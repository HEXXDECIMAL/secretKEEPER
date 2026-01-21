//! Configuration loading and validation.

mod schema;

#[allow(unused_imports)]
pub use schema::{
    AgentConfig, Config, EnforcementConfig, ExceptionConfig, GlobalExclusion,
    MonitoringConfig, ProtectedFile,
};

use crate::error::{Error, Result};
use std::path::Path;

/// Load configuration from a TOML file.
/// This first loads default.toml from the same directory, then merges
/// the platform-specific config on top.
pub fn load_config(path: &Path) -> Result<Config> {
    // Start with hardcoded defaults (includes SSH keys, AWS creds, etc.)
    let mut config = Config::default();

    // Try to load default.toml from the same directory
    if let Some(parent) = path.parent() {
        let default_path = parent.join("default.toml");
        if default_path.exists() {
            let contents = std::fs::read_to_string(&default_path)?;
            let default_config: Config =
                toml::from_str(&contents).map_err(|e| Error::ConfigParse {
                    path: default_path.clone(),
                    source: e,
                })?;
            config.merge(default_config);
            tracing::debug!("Loaded default config from {}", default_path.display());
        }
    }

    // Load the platform-specific config and merge
    let contents = std::fs::read_to_string(path)?;
    let platform_config: Config = toml::from_str(&contents).map_err(|e| Error::ConfigParse {
        path: path.to_path_buf(),
        source: e,
    })?;
    config.merge(platform_config);
    tracing::debug!("Loaded platform config from {}", path.display());

    config.validate()?;
    Ok(config)
}

/// Load configuration from a string.
#[allow(dead_code)]
pub fn load_config_str(contents: &str) -> Result<Config> {
    let config: Config = toml::from_str(contents).map_err(|e| Error::ConfigParse {
        path: std::path::PathBuf::from("<string>"),
        source: e,
    })?;
    config.validate()?;
    Ok(config)
}

/// Get the default configuration path for the current platform.
pub fn default_config_path() -> std::path::PathBuf {
    #[cfg(target_os = "macos")]
    {
        std::path::PathBuf::from("/Library/Application Support/SecretKeeper/config.toml")
    }

    #[cfg(target_os = "linux")]
    {
        std::path::PathBuf::from("/etc/secretkeeper/config.toml")
    }

    #[cfg(target_os = "freebsd")]
    {
        std::path::PathBuf::from("/usr/local/etc/secretkeeper/config.toml")
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "freebsd")))]
    {
        std::path::PathBuf::from("config.toml")
    }
}

/// Get the default socket path for the current platform.
pub fn default_socket_path() -> std::path::PathBuf {
    #[cfg(target_os = "macos")]
    {
        std::path::PathBuf::from("/var/run/secretkeeper.sock")
    }

    #[cfg(target_os = "linux")]
    {
        std::path::PathBuf::from("/var/run/secretkeeper.sock")
    }

    #[cfg(target_os = "freebsd")]
    {
        std::path::PathBuf::from("/var/run/secretkeeper.sock")
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "freebsd")))]
    {
        std::path::PathBuf::from("secretkeeper.sock")
    }
}

/// Get the default database path for the current platform.
pub fn default_database_path() -> std::path::PathBuf {
    #[cfg(target_os = "macos")]
    {
        std::path::PathBuf::from("/var/lib/secretkeeper/violations.db")
    }

    #[cfg(target_os = "linux")]
    {
        std::path::PathBuf::from("/var/lib/secretkeeper/violations.db")
    }

    #[cfg(target_os = "freebsd")]
    {
        std::path::PathBuf::from("/var/db/secretkeeper/violations.db")
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "freebsd")))]
    {
        std::path::PathBuf::from("violations.db")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_load_config_from_file() {
        let config_content = r#"
[agent]
log_level = "debug"

[[protected_files]]
id = "test"
patterns = ["~/.test/*"]

[[protected_files.allow]]
path = "/usr/bin/test"
"#;
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(config_content.as_bytes()).unwrap();
        file.flush().unwrap();

        let config = load_config(file.path()).unwrap();
        assert_eq!(config.agent.log_level, "debug");
        // Config merges with defaults, so we have default protected files + "test"
        assert!(config.protected_files.iter().any(|p| p.id == "test"));
        assert!(config.protected_files.iter().any(|p| p.id == "ssh_keys")); // From defaults
    }

    #[test]
    fn test_load_config_str() {
        let config_content = r#"
[agent]
log_level = "info"

[[protected_files]]
id = "ssh_keys"
patterns = ["~/.ssh/id_*"]

[[protected_files.allow]]
path = "/usr/bin/ssh"
"#;
        let config = load_config_str(config_content).unwrap();
        assert_eq!(config.agent.log_level, "info");
        assert_eq!(config.protected_files.len(), 1);
    }

    #[test]
    fn test_load_config_invalid_toml() {
        let config_content = "this is not valid toml {{{";
        let result = load_config_str(config_content);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("failed to parse config file"));
    }

    #[test]
    fn test_load_config_file_not_found() {
        let result = load_config(Path::new("/nonexistent/path/config.toml"));
        assert!(result.is_err());
    }

    #[test]
    fn test_load_config_empty_allow_rule_rejected() {
        let config_content = r#"
[[protected_files]]
id = "test"
patterns = ["~/.test/*"]

[[protected_files.allow]]
# Empty allow rule - no conditions
"#;
        let result = load_config_str(config_content);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("no conditions"));
    }

    #[test]
    fn test_default_config_path() {
        let path = default_config_path();
        #[cfg(target_os = "macos")]
        assert!(path.to_string_lossy().contains("SecretKeeper"));
        #[cfg(target_os = "linux")]
        assert!(path.to_string_lossy().contains("/etc/"));
    }

    #[test]
    fn test_default_socket_path() {
        let path = default_socket_path();
        assert!(path.to_string_lossy().contains("secretkeeper.sock"));
    }

    #[test]
    fn test_default_database_path() {
        let path = default_database_path();
        assert!(path.to_string_lossy().contains("violations.db"));
    }
}
