//! Configuration schema definitions.

use crate::error::{Error, Result};
use crate::rules::AllowRule;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Root configuration structure.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    /// Agent configuration.
    #[serde(default)]
    pub agent: AgentConfig,

    /// Monitoring configuration.
    #[serde(default)]
    pub monitoring: MonitoringConfig,

    /// Enforcement configuration.
    #[serde(default)]
    pub enforcement: EnforcementConfig,

    /// Protected file definitions.
    #[serde(default)]
    pub protected_files: Vec<ProtectedFile>,

    /// Global exclusions that apply to all protected files.
    #[serde(default)]
    pub global_exclusions: Vec<GlobalExclusion>,

    /// Pre-configured exceptions.
    #[serde(default)]
    pub exceptions: Vec<ExceptionConfig>,

    /// File patterns that should never be protected (e.g., public keys).
    #[serde(default)]
    pub excluded_patterns: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            agent: AgentConfig::default(),
            monitoring: MonitoringConfig::default(),
            enforcement: EnforcementConfig::default(),
            protected_files: default_protected_files(),
            global_exclusions: Vec::new(),
            exceptions: Vec::new(),
            excluded_patterns: default_excluded_patterns(),
        }
    }
}

impl Config {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<()> {
        // Ensure socket path parent exists or can be created
        if let Some(parent) = self.agent.socket_path.parent() {
            let var_run = std::path::Path::new("/var/run");
            if !parent.exists() && parent != var_run && !parent.starts_with(var_run) {
                return Err(Error::config(format!(
                    "Socket path parent directory does not exist: {}",
                    parent.display()
                )));
            }
        }

        // Validate enforcement mode
        let valid_modes = ["monitor", "block"];
        if !valid_modes.contains(&self.enforcement.mode.as_str()) {
            return Err(Error::config(format!(
                "Invalid enforcement mode '{}'. Must be one of: {:?}",
                self.enforcement.mode, valid_modes
            )));
        }

        // Validate protected files have IDs, patterns, and valid allow rules
        for pf in &self.protected_files {
            if pf.id.is_empty() {
                return Err(Error::config("Protected file rule must have an 'id'"));
            }
            if pf.patterns.is_empty() {
                return Err(Error::config(format!(
                    "Protected file rule '{}' must have at least one pattern",
                    pf.id
                )));
            }
            // Validate each allow rule has at least one condition
            for (idx, rule) in pf.allow.iter().enumerate() {
                if let Err(msg) = rule.validate() {
                    return Err(Error::config(format!(
                        "Protected file '{}' allow rule #{}: {}",
                        pf.id,
                        idx + 1,
                        msg
                    )));
                }
            }
        }

        // Validate global exclusions have at least one condition
        for (idx, ge) in self.global_exclusions.iter().enumerate() {
            let rule: AllowRule = ge.clone().into();
            if let Err(msg) = rule.validate() {
                return Err(Error::config(format!(
                    "Global exclusion #{}: {}",
                    idx + 1,
                    msg
                )));
            }
        }

        Ok(())
    }

    /// Check if a file path is in the excluded patterns list.
    pub fn is_excluded(&self, path: &str) -> bool {
        for pattern in &self.excluded_patterns {
            if crate::rules::matches_pattern(pattern, path) {
                return true;
            }
        }
        false
    }

    /// Merge another config into this one.
    /// The other config's values override this one's for scalar fields,
    /// while arrays are appended.
    pub fn merge(&mut self, other: Config) {
        // Override scalar agent settings if they differ from defaults
        if other.agent.log_level != default_log_level() {
            self.agent.log_level = other.agent.log_level;
        }

        // Override enforcement mode if set
        if other.enforcement.mode != "block" {
            self.enforcement.mode = other.enforcement.mode;
        }

        // Append arrays (avoiding duplicates by ID for protected_files)
        for pf in other.protected_files {
            if !self.protected_files.iter().any(|p| p.id == pf.id) {
                self.protected_files.push(pf);
            }
        }

        // Append global exclusions
        self.global_exclusions.extend(other.global_exclusions);

        // Append exceptions
        self.exceptions.extend(other.exceptions);

        // Append excluded patterns (deduplicate)
        for pattern in other.excluded_patterns {
            if !self.excluded_patterns.contains(&pattern) {
                self.excluded_patterns.push(pattern);
            }
        }
    }
}

/// Agent-level configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentConfig {
    /// Log level (trace, debug, info, warn, error).
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Unix socket path for IPC.
    #[serde(default = "super::default_socket_path")]
    pub socket_path: PathBuf,

    /// SQLite database path for violation history.
    #[serde(default = "super::default_database_path")]
    pub database_path: PathBuf,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            log_level: default_log_level(),
            socket_path: super::default_socket_path(),
            database_path: super::default_database_path(),
        }
    }
}

fn default_log_level() -> String {
    "info".to_string()
}

/// Monitoring configuration.
///
/// # Mechanism Selection
///
/// The `mechanism` field controls how file access is monitored:
///
/// ## macOS
///
/// - **`esf`** (PRODUCTION): Direct Endpoint Security Framework integration.
///   Requires a System Extension entitlement from Apple. Provides true pre-access
///   blocking via ES_AUTH_OPEN events. This is the only mechanism suitable for
///   production deployments on macOS.
///
/// - **`eslogger`** (DEVELOPMENT ONLY): Uses Apple's eslogger CLI tool.
///   ⚠️ **WARNING: Unstable and NOT suitable for production.**
///   - Cannot block file access, only detect it after the fact
///   - Relies on parsing JSON from an external process
///   - May miss events under load or if eslogger crashes
///   - Use only for development/testing without entitlements
///
/// ## Linux
///
/// - **`fanotify`**: Uses fanotify with FAN_OPEN_PERM for true pre-access blocking.
///
/// ## FreeBSD
///
/// - **`dtrace`**: Uses DTrace for monitoring (notification only, no blocking).
///
/// ## Auto Selection
///
/// - **`auto`**: Selects the best available mechanism for the platform.
///   On macOS, defaults to `eslogger` since `esf` requires entitlements.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MonitoringConfig {
    /// Monitoring mechanism: "auto", "esf" (macOS production), "eslogger" (macOS dev only),
    /// "fanotify" (Linux), or "dtrace" (FreeBSD).
    #[serde(default = "default_mechanism")]
    pub mechanism: String,

    /// Event buffer size.
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,

    /// Maximum events per second (rate limiting).
    #[serde(default = "default_max_events_per_sec")]
    pub max_events_per_sec: u32,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            mechanism: default_mechanism(),
            buffer_size: default_buffer_size(),
            max_events_per_sec: default_max_events_per_sec(),
        }
    }
}

fn default_mechanism() -> String {
    "auto".to_string()
}

fn default_buffer_size() -> usize {
    1000
}

fn default_max_events_per_sec() -> u32 {
    1900
}

/// Enforcement configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EnforcementConfig {
    /// Enforcement mode: "monitor" or "block".
    #[serde(default = "default_mode")]
    pub mode: String,

    /// Whether to suspend the parent process on violation.
    #[serde(default)]
    pub suspend_parent: bool,

    /// How many days to retain violation history.
    #[serde(default = "default_retention_days")]
    pub history_retention_days: u32,
}

impl Default for EnforcementConfig {
    fn default() -> Self {
        Self {
            mode: default_mode(),
            suspend_parent: false,
            history_retention_days: default_retention_days(),
        }
    }
}

fn default_mode() -> String {
    "block".to_string()
}

fn default_retention_days() -> u32 {
    30
}

/// A protected file definition.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProtectedFile {
    /// Unique identifier for this rule (e.g., "ssh_keys", "aws_creds").
    pub id: String,

    /// File patterns to protect (glob patterns, ~ is expanded).
    pub patterns: Vec<String>,

    /// Allow rules for this protected file.
    #[serde(default)]
    pub allow: Vec<AllowRule>,
}

/// Global exclusion rule.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GlobalExclusion {
    /// Process path pattern.
    #[serde(default)]
    pub path: Option<String>,

    /// Process basename pattern.
    #[serde(default)]
    pub base: Option<String>,

    /// Team ID.
    #[serde(default)]
    pub team_id: Option<String>,

    /// Whether this must be a platform binary.
    #[serde(default)]
    pub platform_binary: Option<bool>,

    /// Required parent PID.
    #[serde(default)]
    pub ppid: Option<u32>,
}

impl From<GlobalExclusion> for AllowRule {
    fn from(ge: GlobalExclusion) -> Self {
        AllowRule {
            path: ge.path,
            base: ge.base,
            team_id: ge.team_id,
            platform_binary: ge.platform_binary,
            ppid: ge.ppid,
            ..Default::default()
        }
    }
}

/// Pre-configured exception in config file.
///
/// Exceptions allow specific processes to access protected files. You can identify
/// processes by path, code signature, or both. At least one identifier is required.
///
/// # Code Signature Types
///
/// macOS apps can be identified by their code signature in three ways:
///
/// - **`team_id`**: Apple Developer Team ID (e.g., "EQHXZ8M8AV" for Google).
///   Use this for third-party apps from identified developers. This is the most
///   secure option as Team IDs are verified by Apple and cannot be forged.
///
/// - **`signing_id`**: Code signing identifier (e.g., "com.apple.bluetoothd").
///   Use this for Apple platform binaries and system daemons that don't have
///   a Team ID but are signed by Apple. Format is typically reverse-DNS.
///
/// - **`platform_binary`**: Set to `true` to only match Apple platform binaries.
///   These are binaries shipped with macOS and signed by Apple's platform key.
///
/// # Examples
///
/// ```toml
/// # Allow Google Drive to access Keychain (third-party app with Team ID)
/// [[exceptions]]
/// team_id = "EQHXZ8M8AV"
/// file_pattern = "/Library/Keychains/*"
/// comment = "Google Drive needs Keychain for credentials"
///
/// # Allow Bluetooth daemon to access Keychain (Apple system daemon)
/// [[exceptions]]
/// signing_id = "com.apple.bluetoothd"
/// file_pattern = "/Library/Keychains/*"
/// comment = "Bluetooth needs Keychain for device pairing"
///
/// # Allow any Apple platform binary to access SSH keys
/// [[exceptions]]
/// platform_binary = true
/// file_pattern = "~/.ssh/*"
/// comment = "Trust all Apple system binaries"
///
/// # Allow a specific tool by path
/// [[exceptions]]
/// process_path = "/usr/local/bin/my-deploy-tool"
/// file_pattern = "~/.ssh/id_*"
/// comment = "Deployment automation"
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExceptionConfig {
    /// Process path pattern (glob supported, e.g., "/usr/local/bin/*").
    /// Use this when the process location is known and stable.
    #[serde(default)]
    pub process_path: Option<String>,

    /// Apple Developer Team ID (e.g., "EQHXZ8M8AV" for Google, "UBF8T346G9" for Microsoft).
    /// This is the most secure way to identify third-party applications.
    /// Find an app's Team ID with: codesign -dv /path/to/App.app 2>&1 | grep TeamIdentifier
    #[serde(default)]
    pub team_id: Option<String>,

    /// Code signing identifier (e.g., "com.apple.bluetoothd", "com.apple.Safari").
    /// Use this for Apple platform binaries that don't have a Team ID.
    /// Find with: codesign -dv /path/to/binary 2>&1 | grep Identifier
    #[serde(default)]
    pub signing_id: Option<String>,

    /// Only match Apple platform binaries (shipped with macOS, signed by Apple).
    /// Set to true to trust all Apple system binaries for the given file pattern.
    #[serde(default)]
    pub platform_binary: Option<bool>,

    /// File pattern this exception applies to (glob supported).
    /// Examples: "~/.ssh/*", "/Library/Keychains/*", "~/.aws/credentials"
    pub file_pattern: String,

    /// When this exception expires (ISO 8601 format, e.g., "2024-12-31T23:59:59Z").
    /// Omit for permanent exceptions.
    #[serde(default)]
    pub expires_at: Option<String>,

    /// Human-readable explanation for why this exception exists.
    /// Good comments help with security audits.
    #[serde(default)]
    pub comment: Option<String>,
}

/// Default protected files for common credentials.
fn default_protected_files() -> Vec<ProtectedFile> {
    vec![
        ProtectedFile {
            id: "ssh_keys".to_string(),
            patterns: vec!["~/.ssh/id_*".to_string(), "~/.ssh/*_key".to_string()],
            allow: vec![
                AllowRule {
                    base: Some("ssh".to_string()),
                    ..Default::default()
                },
                AllowRule {
                    base: Some("ssh-agent".to_string()),
                    ..Default::default()
                },
                AllowRule {
                    base: Some("ssh-add".to_string()),
                    ..Default::default()
                },
                AllowRule {
                    base: Some("git".to_string()),
                    ..Default::default()
                },
                AllowRule {
                    base: Some("scp".to_string()),
                    ..Default::default()
                },
                AllowRule {
                    base: Some("sftp".to_string()),
                    ..Default::default()
                },
            ],
        },
        ProtectedFile {
            id: "aws_credentials".to_string(),
            patterns: vec![
                "~/.aws/credentials".to_string(),
                "~/.aws/config".to_string(),
            ],
            allow: vec![
                AllowRule {
                    base: Some("aws".to_string()),
                    ..Default::default()
                },
                AllowRule {
                    base: Some("terraform".to_string()),
                    ..Default::default()
                },
                AllowRule {
                    base: Some("pulumi".to_string()),
                    ..Default::default()
                },
            ],
        },
        ProtectedFile {
            id: "gcloud_credentials".to_string(),
            patterns: vec![
                "~/.config/gcloud/**/credentials.db".to_string(),
                "~/.config/gcloud/application_default_credentials.json".to_string(),
            ],
            allow: vec![AllowRule {
                base: Some("gcloud".to_string()),
                ..Default::default()
            }],
        },
        ProtectedFile {
            id: "kube_config".to_string(),
            patterns: vec!["~/.kube/config".to_string()],
            allow: vec![
                AllowRule {
                    base: Some("kubectl".to_string()),
                    ..Default::default()
                },
                AllowRule {
                    base: Some("helm".to_string()),
                    ..Default::default()
                },
                AllowRule {
                    base: Some("k9s".to_string()),
                    ..Default::default()
                },
            ],
        },
        ProtectedFile {
            id: "docker_config".to_string(),
            patterns: vec!["~/.docker/config.json".to_string()],
            allow: vec![
                AllowRule {
                    base: Some("docker".to_string()),
                    ..Default::default()
                },
                AllowRule {
                    base: Some("docker-credential-*".to_string()),
                    ..Default::default()
                },
            ],
        },
        ProtectedFile {
            id: "gpg_keys".to_string(),
            patterns: vec![
                "~/.gnupg/private-keys-v1.d/*".to_string(),
                "~/.gnupg/secring.gpg".to_string(),
            ],
            allow: vec![
                AllowRule {
                    base: Some("gpg".to_string()),
                    ..Default::default()
                },
                AllowRule {
                    base: Some("gpg2".to_string()),
                    ..Default::default()
                },
                AllowRule {
                    base: Some("gpg-agent".to_string()),
                    ..Default::default()
                },
            ],
        },
        ProtectedFile {
            id: "npm_token".to_string(),
            patterns: vec!["~/.npmrc".to_string()],
            allow: vec![
                AllowRule {
                    base: Some("npm".to_string()),
                    ..Default::default()
                },
                AllowRule {
                    base: Some("yarn".to_string()),
                    ..Default::default()
                },
                AllowRule {
                    base: Some("pnpm".to_string()),
                    ..Default::default()
                },
            ],
        },
        ProtectedFile {
            id: "pypi_token".to_string(),
            patterns: vec!["~/.pypirc".to_string()],
            allow: vec![
                AllowRule {
                    base: Some("pip".to_string()),
                    ..Default::default()
                },
                AllowRule {
                    base: Some("pip3".to_string()),
                    ..Default::default()
                },
                AllowRule {
                    base: Some("twine".to_string()),
                    ..Default::default()
                },
            ],
        },
        ProtectedFile {
            id: "cargo_credentials".to_string(),
            patterns: vec!["~/.cargo/credentials.toml".to_string()],
            allow: vec![AllowRule {
                base: Some("cargo".to_string()),
                ..Default::default()
            }],
        },
    ]
}

/// Default excluded patterns (files that should never be protected).
fn default_excluded_patterns() -> Vec<String> {
    vec![
        "~/.ssh/*.pub".to_string(),
        "~/.ssh/known_hosts".to_string(),
        "~/.ssh/config".to_string(),
        "~/.ssh/authorized_keys".to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.validate().is_ok());
        assert!(!config.protected_files.is_empty());
    }

    #[test]
    fn test_parse_minimal_config() {
        let toml = r#"
[agent]
log_level = "debug"

[enforcement]
mode = "monitor"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.agent.log_level, "debug");
        assert_eq!(config.enforcement.mode, "monitor");
    }

    #[test]
    fn test_parse_full_config() {
        let toml = r#"
[agent]
log_level = "info"
socket_path = "/tmp/test.sock"
database_path = "/tmp/test.db"

[monitoring]
mechanism = "eslogger"
buffer_size = 500

[enforcement]
mode = "block"
history_retention_days = 7

[[protected_files]]
id = "custom_secrets"
patterns = ["~/secrets/*.key"]

[[protected_files.allow]]
base = "myapp"

[[global_exclusions]]
team_id = "TRUSTED123"

[[exceptions]]
process_path = "/usr/local/bin/tool"
file_pattern = "~/.ssh/*"
comment = "Deployment tool"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.validate().is_ok());
        assert_eq!(config.protected_files.len(), 1);
        assert_eq!(config.global_exclusions.len(), 1);
        assert_eq!(config.exceptions.len(), 1);
    }

    #[test]
    fn test_excluded_patterns() {
        let config = Config::default();
        assert!(config.is_excluded("~/.ssh/id_rsa.pub"));
        assert!(config.is_excluded("~/.ssh/known_hosts"));
        assert!(!config.is_excluded("~/.ssh/id_rsa"));
    }

    #[test]
    fn test_validate_invalid_enforcement_mode() {
        let mut config = Config::default();
        config.enforcement.mode = "invalid".to_string();
        let result = config.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid enforcement mode"));
    }

    #[test]
    fn test_validate_empty_protected_file_id() {
        let mut config = Config::default();
        config.protected_files.push(ProtectedFile {
            id: "".to_string(),
            patterns: vec!["~/.test/*".to_string()],
            allow: vec![],
        });
        let result = config.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must have an 'id'"));
    }

    #[test]
    fn test_validate_empty_protected_file_patterns() {
        let mut config = Config::default();
        config.protected_files.push(ProtectedFile {
            id: "test".to_string(),
            patterns: vec![],
            allow: vec![],
        });
        let result = config.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("at least one pattern"));
    }

    #[test]
    fn test_validate_empty_global_exclusion() {
        let mut config = Config::default();
        config.global_exclusions.push(GlobalExclusion {
            path: None,
            base: None,
            team_id: None,
            platform_binary: None,
            ppid: None,
        });
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no conditions"));
    }

    #[test]
    fn test_global_exclusion_into_allow_rule() {
        let exclusion = GlobalExclusion {
            path: Some("/usr/bin/*".to_string()),
            base: Some("ssh".to_string()),
            team_id: Some("APPLE".to_string()),
            platform_binary: Some(true),
            ppid: Some(1),
        };
        let rule: AllowRule = exclusion.into();
        assert_eq!(rule.path, Some("/usr/bin/*".to_string()));
        assert_eq!(rule.base, Some("ssh".to_string()));
        assert_eq!(rule.team_id, Some("APPLE".to_string()));
        assert_eq!(rule.platform_binary, Some(true));
        assert_eq!(rule.ppid, Some(1));
    }

    #[test]
    fn test_defaults() {
        let config = Config::default();
        assert_eq!(config.agent.log_level, "info");
        assert_eq!(config.monitoring.mechanism, "auto");
        assert_eq!(config.monitoring.buffer_size, 1000);
        assert_eq!(config.monitoring.max_events_per_sec, 1900);
        assert_eq!(config.enforcement.mode, "block");
        assert!(!config.enforcement.suspend_parent);
        assert_eq!(config.enforcement.history_retention_days, 30);
    }

    #[test]
    fn test_exception_with_team_id() {
        let toml = r#"
[[exceptions]]
team_id = "EQHXZ8M8AV"
file_pattern = "/Library/Keychains/*"
comment = "Google Drive needs Keychain for credentials"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.exceptions.len(), 1);
        assert_eq!(config.exceptions[0].team_id, Some("EQHXZ8M8AV".to_string()));
        assert_eq!(
            config.exceptions[0].file_pattern,
            "/Library/Keychains/*".to_string()
        );
    }

    #[test]
    fn test_exception_with_signing_id() {
        let toml = r#"
[[exceptions]]
signing_id = "com.apple.bluetoothd"
file_pattern = "/Library/Keychains/*"
comment = "Bluetooth needs Keychain for device pairing"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.exceptions.len(), 1);
        assert_eq!(
            config.exceptions[0].signing_id,
            Some("com.apple.bluetoothd".to_string())
        );
    }

    #[test]
    fn test_exception_with_platform_binary() {
        let toml = r#"
[[exceptions]]
platform_binary = true
file_pattern = "~/.ssh/*"
comment = "Trust all Apple system binaries"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.exceptions.len(), 1);
        assert_eq!(config.exceptions[0].platform_binary, Some(true));
    }

    #[test]
    fn test_exception_with_process_path() {
        let toml = r#"
[[exceptions]]
process_path = "/usr/local/bin/my-deploy-tool"
file_pattern = "~/.ssh/id_*"
comment = "Deployment automation"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.exceptions.len(), 1);
        assert_eq!(
            config.exceptions[0].process_path,
            Some("/usr/local/bin/my-deploy-tool".to_string())
        );
    }

    #[test]
    fn test_exception_with_expiration() {
        let toml = r#"
[[exceptions]]
team_id = "ABC123"
file_pattern = "~/.aws/credentials"
expires_at = "2024-12-31T23:59:59Z"
comment = "Temporary access for contractor"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.exceptions.len(), 1);
        assert_eq!(
            config.exceptions[0].expires_at,
            Some("2024-12-31T23:59:59Z".to_string())
        );
    }

    #[test]
    fn test_multiple_exceptions() {
        let toml = r#"
# Third-party app by Team ID
[[exceptions]]
team_id = "EQHXZ8M8AV"
file_pattern = "/Library/Keychains/*"
comment = "Google Drive"

# Apple system daemon by signing ID
[[exceptions]]
signing_id = "com.apple.bluetoothd"
file_pattern = "/Library/Keychains/*"
comment = "Bluetooth"

# All Apple platform binaries
[[exceptions]]
platform_binary = true
file_pattern = "~/.ssh/*"
comment = "Trust Apple binaries"

# Specific tool by path
[[exceptions]]
process_path = "/opt/tools/backup"
file_pattern = "~/.ssh/*"
comment = "Backup tool"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.exceptions.len(), 4);

        // Verify each exception type
        assert!(config.exceptions[0].team_id.is_some());
        assert!(config.exceptions[1].signing_id.is_some());
        assert_eq!(config.exceptions[2].platform_binary, Some(true));
        assert!(config.exceptions[3].process_path.is_some());
    }
}
