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
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MonitoringConfig {
    /// Monitoring mechanism to use (auto, eslogger, esf, fanotify, dtrace).
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
    100
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
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExceptionConfig {
    /// Process path pattern.
    #[serde(default)]
    pub process_path: Option<String>,

    /// Code signer (team_id).
    #[serde(default)]
    pub code_signer: Option<String>,

    /// File pattern this exception applies to.
    pub file_pattern: String,

    /// When this exception expires (ISO 8601 format).
    #[serde(default)]
    pub expires_at: Option<String>,

    /// Comment explaining this exception.
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
        assert_eq!(config.monitoring.max_events_per_sec, 100);
        assert_eq!(config.enforcement.mode, "block");
        assert!(!config.enforcement.suspend_parent);
        assert_eq!(config.enforcement.history_retention_days, 30);
    }
}
