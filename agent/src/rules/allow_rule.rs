//! Process allow rules for fine-grained access control.

use crate::process::ProcessContext;
use serde::{Deserialize, Deserializer, Serialize};

/// A single allow rule with AND logic between conditions.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct AllowRule {
    /// Process basename (e.g., "firefox", "chrome"). Supports glob patterns.
    #[serde(default)]
    pub base: Option<String>,

    /// Full path pattern (e.g., "/Applications/*/*.app/Contents/MacOS/*").
    #[serde(default, alias = "path_pattern")]
    pub path: Option<String>,

    /// Parent process ID (e.g., 1 for launchd).
    #[serde(default)]
    pub ppid: Option<u32>,

    /// Apple Team ID (secure, assigned by Apple).
    #[serde(default)]
    pub team_id: Option<String>,

    /// App ID / Bundle ID (can be set by developer, less secure).
    #[serde(default)]
    pub app_id: Option<String>,

    /// Code signing identifier.
    #[serde(default)]
    pub signing_id: Option<String>,

    /// Command line arguments pattern (matches across all args joined).
    #[serde(default)]
    pub args_pattern: Option<String>,

    /// Specific argument that must be present (e.g., "-l" for login shell).
    #[serde(default)]
    pub arg: Option<String>,

    /// User ID (for system processes).
    #[serde(default)]
    pub uid: Option<u32>,

    /// Effective User ID - can be a single value or range (e.g., "501-599").
    #[serde(default, deserialize_with = "deserialize_euid")]
    pub euid: Option<(u32, u32)>,

    /// Whether this is an Apple platform binary.
    #[serde(default)]
    pub platform_binary: Option<bool>,

    // =========================================================================
    // Package-based identification (Linux, FreeBSD, Homebrew)
    // =========================================================================
    /// Package name pattern (e.g., "openssh-*", "coreutils"). Supports glob patterns.
    /// Analogous to `signing_id` for macOS code signing.
    #[serde(default)]
    pub package: Option<String>,

    /// Package vendor/maintainer pattern (e.g., "Red Hat*", "homebrew/core").
    /// Analogous to `team_id` for macOS code signing.
    #[serde(default)]
    pub package_vendor: Option<String>,

    /// Require cryptographic verification of the package (RPM GPG, FreeBSD fingerprint).
    /// Analogous to `platform_binary` for macOS.
    #[serde(default)]
    pub package_verified: Option<bool>,
}

#[allow(dead_code)]
impl AllowRule {
    /// Check if this rule has no conditions (would match everything).
    /// Empty rules are a security risk and should be rejected.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.base.is_none()
            && self.path.is_none()
            && self.ppid.is_none()
            && self.team_id.is_none()
            && self.app_id.is_none()
            && self.signing_id.is_none()
            && self.args_pattern.is_none()
            && self.arg.is_none()
            && self.uid.is_none()
            && self.euid.is_none()
            && self.platform_binary.is_none()
            && self.package.is_none()
            && self.package_vendor.is_none()
            && self.package_verified.is_none()
    }

    /// Validate the rule. Returns an error message if invalid.
    pub fn validate(&self) -> Result<(), String> {
        if self.is_empty() {
            return Err("AllowRule has no conditions - would match all processes".to_string());
        }
        Ok(())
    }

    /// Check if this rule matches the given process context.
    #[must_use]
    pub fn matches(&self, context: &ProcessContext) -> bool {
        self.matches_with_debug(context, false)
    }

    /// Check if this rule matches with optional debug logging.
    #[must_use]
    pub fn matches_with_debug(&self, context: &ProcessContext, debug: bool) -> bool {
        // All specified conditions must match (AND logic)

        // Check basename (supports wildcards)
        if let Some(ref expected_basename) = self.base {
            let actual_basename = context.basename();
            if !matches_pattern(expected_basename, actual_basename) {
                if debug {
                    tracing::debug!(
                        "Rule failed: basename '{}' doesn't match pattern '{}'",
                        actual_basename,
                        expected_basename
                    );
                }
                return false;
            }
        }

        // Check path pattern
        if let Some(ref pattern) = self.path {
            let path_str = context.path.to_string_lossy();
            if !matches_pattern(pattern, &path_str) {
                if debug {
                    tracing::debug!(
                        "Rule failed: path '{}' doesn't match pattern '{}'",
                        path_str,
                        pattern
                    );
                }
                return false;
            }
        }

        // Check ppid
        if let Some(expected_ppid) = self.ppid {
            if context.ppid != Some(expected_ppid) {
                if debug {
                    tracing::debug!(
                        "Rule failed: ppid {:?} != expected {}",
                        context.ppid,
                        expected_ppid
                    );
                }
                return false;
            }
        }

        // Check team_id (secure)
        if let Some(ref expected_team_id) = self.team_id {
            match &context.team_id {
                Some(actual_team_id) => {
                    if !matches_pattern(expected_team_id, actual_team_id) {
                        if debug {
                            tracing::debug!(
                                "Rule failed: team_id '{}' doesn't match pattern '{}'",
                                actual_team_id,
                                expected_team_id
                            );
                        }
                        return false;
                    }
                }
                None => {
                    if debug {
                        tracing::debug!(
                            "Rule failed: expected team_id '{}' but none provided",
                            expected_team_id
                        );
                    }
                    return false;
                }
            }
        }

        // Check app_id
        if let Some(ref expected_app_id) = self.app_id {
            match &context.app_id {
                Some(actual_app_id) => {
                    if !matches_pattern(expected_app_id, actual_app_id) {
                        if debug {
                            tracing::debug!(
                                "Rule failed: app_id '{}' doesn't match pattern '{}'",
                                actual_app_id,
                                expected_app_id
                            );
                        }
                        return false;
                    }
                }
                None => {
                    if debug {
                        tracing::debug!(
                            "Rule failed: expected app_id '{}' but none provided",
                            expected_app_id
                        );
                    }
                    return false;
                }
            }
        }

        // Check signing_id
        if let Some(ref expected_signing_id) = self.signing_id {
            match &context.signing_id {
                Some(actual_signing_id) => {
                    if !matches_pattern(expected_signing_id, actual_signing_id) {
                        if debug {
                            tracing::debug!(
                                "Rule failed: signing_id '{}' doesn't match pattern '{}'",
                                actual_signing_id,
                                expected_signing_id
                            );
                        }
                        return false;
                    }
                }
                None => {
                    if debug {
                        tracing::debug!(
                            "Rule failed: expected signing_id '{}' but none provided",
                            expected_signing_id
                        );
                    }
                    return false;
                }
            }
        }

        // Check args pattern
        if let Some(ref pattern) = self.args_pattern {
            match &context.args {
                Some(actual_args) => {
                    let args_str = actual_args.join(" ");
                    if !matches_pattern(pattern, &args_str) {
                        if debug {
                            tracing::debug!(
                                "Rule failed: args '{}' doesn't match pattern '{}'",
                                args_str,
                                pattern
                            );
                        }
                        return false;
                    }
                }
                None => {
                    if debug {
                        tracing::debug!(
                            "Rule failed: expected args pattern '{}' but no args provided",
                            pattern
                        );
                    }
                    return false;
                }
            }
        }

        // Check for specific arg
        if let Some(ref expected_arg) = self.arg {
            match &context.args {
                Some(actual_args) => {
                    if !actual_args.contains(expected_arg) {
                        if debug {
                            tracing::debug!(
                                "Rule failed: required arg '{}' not found in {:?}",
                                expected_arg,
                                actual_args
                            );
                        }
                        return false;
                    }
                }
                None => {
                    if debug {
                        tracing::debug!(
                            "Rule failed: expected arg '{}' but no args provided",
                            expected_arg
                        );
                    }
                    return false;
                }
            }
        }

        // Check uid
        if let Some(expected_uid) = self.uid {
            if context.uid != Some(expected_uid) {
                if debug {
                    tracing::debug!(
                        "Rule failed: uid {:?} != expected {}",
                        context.uid,
                        expected_uid
                    );
                }
                return false;
            }
        }

        // Check euid range
        if let Some((min_euid, max_euid)) = self.euid {
            match context.euid {
                Some(actual_euid) => {
                    if actual_euid < min_euid || actual_euid > max_euid {
                        if debug {
                            tracing::debug!(
                                "Rule failed: euid {} not in range {}-{}",
                                actual_euid,
                                min_euid,
                                max_euid
                            );
                        }
                        return false;
                    }
                }
                None => {
                    if debug {
                        tracing::debug!(
                            "Rule failed: expected euid in range {}-{} but none provided",
                            min_euid,
                            max_euid
                        );
                    }
                    return false;
                }
            }
        }

        // Check platform_binary
        if let Some(expected_platform) = self.platform_binary {
            match context.platform_binary {
                Some(actual_platform) => {
                    if actual_platform != expected_platform {
                        if debug {
                            tracing::debug!(
                                "Rule failed: platform_binary {} != expected {}",
                                actual_platform,
                                expected_platform
                            );
                        }
                        return false;
                    }
                }
                None => {
                    if debug {
                        tracing::debug!(
                            "Rule failed: expected platform_binary {} but none provided",
                            expected_platform
                        );
                    }
                    return false;
                }
            }
        }

        // Check package name pattern
        if let Some(ref expected_package) = self.package {
            match &context.package {
                Some(pkg_info) => {
                    if !matches_pattern(expected_package, &pkg_info.name) {
                        if debug {
                            tracing::debug!(
                                "Rule failed: package '{}' doesn't match pattern '{}'",
                                pkg_info.name,
                                expected_package
                            );
                        }
                        return false;
                    }
                }
                None => {
                    if debug {
                        tracing::debug!(
                            "Rule failed: expected package '{}' but process has no package info",
                            expected_package
                        );
                    }
                    return false;
                }
            }
        }

        // Check package vendor pattern
        if let Some(ref expected_vendor) = self.package_vendor {
            match &context.package {
                Some(pkg_info) => match &pkg_info.vendor {
                    Some(actual_vendor) => {
                        if !matches_pattern(expected_vendor, actual_vendor) {
                            if debug {
                                tracing::debug!(
                                    "Rule failed: package_vendor '{}' doesn't match pattern '{}'",
                                    actual_vendor,
                                    expected_vendor
                                );
                            }
                            return false;
                        }
                    }
                    None => {
                        if debug {
                            tracing::debug!(
                                    "Rule failed: expected package_vendor '{}' but package has no vendor",
                                    expected_vendor
                                );
                        }
                        return false;
                    }
                },
                None => {
                    if debug {
                        tracing::debug!(
                            "Rule failed: expected package_vendor '{}' but process has no package info",
                            expected_vendor
                        );
                    }
                    return false;
                }
            }
        }

        // Check package verification status.
        // SECURITY: Verification is REQUIRED by default when using package-based rules.
        // If someone specifies `package` or `package_vendor`, we verify the package
        // hasn't been tampered with. Set `package_verified = false` to explicitly
        // skip verification (not recommended).
        // If only `package_verified = true` is set (without package/package_vendor),
        // it acts as a filter: "allow any verified package".
        let uses_package_rules = self.package.is_some() || self.package_vendor.is_some();
        let require_verified = self.package_verified.unwrap_or(uses_package_rules);

        if require_verified {
            match &context.package {
                Some(pkg_info) => {
                    if !pkg_info.is_verified() {
                        if debug {
                            tracing::debug!(
                                "Rule failed: package verification required but package '{}' is {:?}",
                                pkg_info.name,
                                pkg_info.verified
                            );
                        }
                        return false;
                    }
                }
                None => {
                    if debug {
                        tracing::debug!(
                            "Rule failed: package verification required but process has no package info"
                        );
                    }
                    return false;
                }
            }
        }

        // All specified conditions matched
        true
    }
}

/// Performs glob-like pattern matching with * wildcard support.
#[must_use]
pub fn matches_pattern(pattern: &str, text: &str) -> bool {
    glob_match(pattern, text)
}

/// Implements glob pattern matching with * wildcard support.
/// Uses a two-pointer algorithm with backtracking.
fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern_chars: Vec<char> = pattern.chars().collect();
    let text_chars: Vec<char> = text.chars().collect();

    let mut p = 0;
    let mut t = 0;
    let mut star_idx = None;
    let mut star_match = 0;

    while t < text_chars.len() {
        if p < pattern_chars.len() && pattern_chars[p] == text_chars[t] {
            p += 1;
            t += 1;
        } else if p < pattern_chars.len() && pattern_chars[p] == '*' {
            star_idx = Some(p);
            star_match = t;
            p += 1;
        } else if let Some(star_p) = star_idx {
            p = star_p + 1;
            star_match += 1;
            t = star_match;
        } else {
            return false;
        }
    }

    // Consume any trailing * in pattern
    while p < pattern_chars.len() && pattern_chars[p] == '*' {
        p += 1;
    }

    p == pattern_chars.len()
}

/// Deserialize EUID from either a single value or a range string.
fn deserialize_euid<'de, D>(deserializer: D) -> Result<Option<(u32, u32)>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::{self, Visitor};
    use std::fmt;

    struct EuidRangeVisitor;

    impl<'de> Visitor<'de> for EuidRangeVisitor {
        type Value = Option<(u32, u32)>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a number or a range like '501-599'")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let val = value as u32;
            Ok(Some((val, val)))
        }

        fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if value < 0 {
                return Err(E::custom("EUID must be non-negative"));
            }
            let val = value as u32;
            Ok(Some((val, val)))
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if value.is_empty() {
                return Ok(None);
            }

            if let Some(dash_pos) = value.find('-') {
                let start = value[..dash_pos].trim().parse::<u32>().map_err(|_| {
                    E::custom(format!("Invalid range start: {}", &value[..dash_pos]))
                })?;
                let end = value[dash_pos + 1..].trim().parse::<u32>().map_err(|_| {
                    E::custom(format!("Invalid range end: {}", &value[dash_pos + 1..]))
                })?;

                if start > end {
                    return Err(E::custom(format!("Invalid range: {} > {}", start, end)));
                }

                Ok(Some((start, end)))
            } else {
                let val = value
                    .trim()
                    .parse::<u32>()
                    .map_err(|_| E::custom(format!("Invalid EUID value: {}", value)))?;
                Ok(Some((val, val)))
            }
        }
    }

    deserializer.deserialize_any(EuidRangeVisitor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_pattern_matching() {
        assert!(matches_pattern("*.app", "Firefox.app"));
        assert!(matches_pattern("com.apple.*", "com.apple.security"));
        assert!(!matches_pattern("com.apple.*", "com.google.chrome"));
        assert!(matches_pattern("firefox", "firefox"));
        assert!(!matches_pattern("firefox", "chrome"));
        assert!(matches_pattern(
            "docker-credential-*",
            "docker-credential-desktop"
        ));
        assert!(matches_pattern("python*", "python3.11"));
        assert!(!matches_pattern("python*", "ruby"));
    }

    #[test]
    fn test_pattern_matching_edge_cases() {
        // Empty patterns
        assert!(matches_pattern("", ""));
        assert!(!matches_pattern("", "something"));
        assert!(matches_pattern("*", ""));
        assert!(matches_pattern("*", "anything"));

        // Multiple wildcards
        assert!(matches_pattern("*foo*", "foo"));
        assert!(matches_pattern("*foo*", "barfoo"));
        assert!(matches_pattern("*foo*", "foobar"));
        assert!(matches_pattern("*foo*", "barfoobar"));
        assert!(!matches_pattern("*foo*", "bar"));

        // Complex patterns
        assert!(matches_pattern("/usr/*/bin/*", "/usr/local/bin/test"));
        assert!(!matches_pattern("/usr/*/bin/*", "/var/local/bin/test"));

        // Patterns with ~ for home directories
        assert!(matches_pattern("~/.ssh/*", "~/.ssh/id_rsa"));
        assert!(!matches_pattern("~/.ssh/*", "~/.config/test"));

        // Leading/trailing wildcards
        assert!(matches_pattern("*test", "mytest"));
        assert!(matches_pattern("test*", "testing"));
        assert!(!matches_pattern("*test", "testing"));

        // Single char matches
        assert!(matches_pattern("a", "a"));
        assert!(!matches_pattern("a", "b"));
    }

    #[test]
    fn test_rule_matching_base() {
        let rule = AllowRule {
            base: Some("ssh".to_string()),
            ..Default::default()
        };

        let ctx = ProcessContext::new(PathBuf::from("/usr/bin/ssh"));
        assert!(rule.matches(&ctx));

        let ctx2 = ProcessContext::new(PathBuf::from("/usr/bin/scp"));
        assert!(!rule.matches(&ctx2));
    }

    #[test]
    fn test_rule_matching_base_wildcard() {
        let rule = AllowRule {
            base: Some("docker-credential-*".to_string()),
            ..Default::default()
        };

        let ctx = ProcessContext::new(PathBuf::from("/usr/local/bin/docker-credential-desktop"));
        assert!(rule.matches(&ctx));

        let ctx2 = ProcessContext::new(PathBuf::from("/usr/bin/docker"));
        assert!(!rule.matches(&ctx2));
    }

    #[test]
    fn test_rule_matching_path_pattern() {
        let rule = AllowRule {
            path: Some("/Applications/*.app/Contents/MacOS/*".to_string()),
            ..Default::default()
        };

        let ctx = ProcessContext::new(PathBuf::from(
            "/Applications/Firefox.app/Contents/MacOS/firefox",
        ));
        assert!(rule.matches(&ctx));

        let ctx2 = ProcessContext::new(PathBuf::from("/usr/bin/firefox"));
        assert!(!rule.matches(&ctx2));
    }

    #[test]
    fn test_rule_matching_euid_range() {
        let rule = AllowRule {
            base: Some("ssh".to_string()),
            euid: Some((501, 599)),
            ..Default::default()
        };

        let ctx = ProcessContext::new(PathBuf::from("/usr/bin/ssh")).with_euid(501);
        assert!(rule.matches(&ctx));

        let ctx2 = ProcessContext::new(PathBuf::from("/usr/bin/ssh")).with_euid(0);
        assert!(!rule.matches(&ctx2));
    }

    #[test]
    fn test_rule_matching_euid_single_value() {
        let rule = AllowRule {
            euid: Some((0, 0)),
            ..Default::default()
        };

        let ctx = ProcessContext::new(PathBuf::from("/usr/bin/test")).with_euid(0);
        assert!(rule.matches(&ctx));

        let ctx2 = ProcessContext::new(PathBuf::from("/usr/bin/test")).with_euid(501);
        assert!(!rule.matches(&ctx2));
    }

    #[test]
    fn test_rule_matching_team_id() {
        let rule = AllowRule {
            team_id: Some("ABCD1234".to_string()),
            ..Default::default()
        };

        let ctx = ProcessContext::new(PathBuf::from("/usr/bin/test")).with_team_id("ABCD1234");
        assert!(rule.matches(&ctx));

        let ctx2 = ProcessContext::new(PathBuf::from("/usr/bin/test")).with_team_id("XXXX9999");
        assert!(!rule.matches(&ctx2));

        let ctx3 = ProcessContext::new(PathBuf::from("/usr/bin/test"));
        assert!(!rule.matches(&ctx3));
    }

    #[test]
    fn test_rule_matching_team_id_wildcard() {
        let rule = AllowRule {
            team_id: Some("APPLE*".to_string()),
            ..Default::default()
        };

        let ctx = ProcessContext::new(PathBuf::from("/usr/bin/test")).with_team_id("APPLE12345");
        assert!(rule.matches(&ctx));

        let ctx2 = ProcessContext::new(PathBuf::from("/usr/bin/test")).with_team_id("GOOGLE123");
        assert!(!rule.matches(&ctx2));
    }

    #[test]
    fn test_rule_matching_signing_id() {
        let rule = AllowRule {
            signing_id: Some("com.apple.*".to_string()),
            ..Default::default()
        };

        let ctx =
            ProcessContext::new(PathBuf::from("/usr/bin/test")).with_signing_id("com.apple.ssh");
        assert!(rule.matches(&ctx));

        let ctx2 = ProcessContext::new(PathBuf::from("/usr/bin/test"))
            .with_signing_id("com.google.chrome");
        assert!(!rule.matches(&ctx2));
    }

    #[test]
    fn test_rule_matching_platform_binary() {
        let rule = AllowRule {
            platform_binary: Some(true),
            ..Default::default()
        };

        let ctx = ProcessContext::new(PathBuf::from("/usr/bin/ssh")).with_platform_binary(true);
        assert!(rule.matches(&ctx));

        let ctx2 = ProcessContext::new(PathBuf::from("/usr/bin/ssh")).with_platform_binary(false);
        assert!(!rule.matches(&ctx2));

        // No platform_binary set
        let ctx3 = ProcessContext::new(PathBuf::from("/usr/bin/ssh"));
        assert!(!rule.matches(&ctx3));
    }

    #[test]
    fn test_rule_matching_ppid() {
        let rule = AllowRule {
            ppid: Some(1),
            ..Default::default()
        };

        let ctx = ProcessContext::new(PathBuf::from("/usr/bin/test")).with_ppid(1);
        assert!(rule.matches(&ctx));

        let ctx2 = ProcessContext::new(PathBuf::from("/usr/bin/test")).with_ppid(1234);
        assert!(!rule.matches(&ctx2));
    }

    #[test]
    fn test_rule_matching_multiple_conditions() {
        let rule = AllowRule {
            base: Some("ssh".to_string()),
            team_id: Some("APPLE12345".to_string()),
            platform_binary: Some(true),
            ..Default::default()
        };

        // All conditions match
        let ctx = ProcessContext::new(PathBuf::from("/usr/bin/ssh"))
            .with_team_id("APPLE12345")
            .with_platform_binary(true);
        assert!(rule.matches(&ctx));

        // Missing team_id
        let ctx2 = ProcessContext::new(PathBuf::from("/usr/bin/ssh")).with_platform_binary(true);
        assert!(!rule.matches(&ctx2));

        // Wrong base
        let ctx3 = ProcessContext::new(PathBuf::from("/usr/bin/scp"))
            .with_team_id("APPLE12345")
            .with_platform_binary(true);
        assert!(!rule.matches(&ctx3));

        // Wrong platform_binary
        let ctx4 = ProcessContext::new(PathBuf::from("/usr/bin/ssh"))
            .with_team_id("APPLE12345")
            .with_platform_binary(false);
        assert!(!rule.matches(&ctx4));
    }

    #[test]
    fn test_empty_rule_matches_all() {
        let rule = AllowRule::default();

        let ctx = ProcessContext::new(PathBuf::from("/usr/bin/any"));
        assert!(rule.matches(&ctx));

        let ctx2 = ProcessContext::new(PathBuf::from("/malicious/binary"))
            .with_euid(0)
            .with_team_id("UNKNOWN");
        assert!(rule.matches(&ctx2));
    }

    #[test]
    fn test_euid_deserialize() {
        // Test single value as number
        let toml_str = r#"
            euid = 501
        "#;
        let rule: AllowRule = toml::from_str(toml_str).unwrap();
        assert_eq!(rule.euid, Some((501, 501)));

        // Test range as string
        let toml_str = r#"
            euid = "501-599"
        "#;
        let rule: AllowRule = toml::from_str(toml_str).unwrap();
        assert_eq!(rule.euid, Some((501, 599)));

        // Test single value as string
        let toml_str = r#"
            euid = "0"
        "#;
        let rule: AllowRule = toml::from_str(toml_str).unwrap();
        assert_eq!(rule.euid, Some((0, 0)));
    }

    #[test]
    fn test_is_empty() {
        let empty = AllowRule::default();
        assert!(empty.is_empty());

        let with_base = AllowRule {
            base: Some("ssh".to_string()),
            ..Default::default()
        };
        assert!(!with_base.is_empty());

        let with_path = AllowRule {
            path: Some("/usr/bin/*".to_string()),
            ..Default::default()
        };
        assert!(!with_path.is_empty());

        let with_ppid = AllowRule {
            ppid: Some(1),
            ..Default::default()
        };
        assert!(!with_ppid.is_empty());

        let with_uid = AllowRule {
            uid: Some(0),
            ..Default::default()
        };
        assert!(!with_uid.is_empty());
    }

    #[test]
    fn test_validate() {
        let empty = AllowRule::default();
        assert!(empty.validate().is_err());
        assert!(empty.validate().unwrap_err().contains("no conditions"));

        let with_base = AllowRule {
            base: Some("ssh".to_string()),
            ..Default::default()
        };
        assert!(with_base.validate().is_ok());
    }

    #[test]
    fn test_rule_matching_app_id() {
        let rule = AllowRule {
            app_id: Some("com.apple.Terminal".to_string()),
            ..Default::default()
        };

        let ctx =
            ProcessContext::new(PathBuf::from("/usr/bin/test")).with_app_id("com.apple.Terminal");
        assert!(rule.matches(&ctx));

        let ctx2 =
            ProcessContext::new(PathBuf::from("/usr/bin/test")).with_app_id("com.google.chrome");
        assert!(!rule.matches(&ctx2));

        // No app_id set
        let ctx3 = ProcessContext::new(PathBuf::from("/usr/bin/test"));
        assert!(!rule.matches(&ctx3));
    }

    #[test]
    fn test_rule_matching_app_id_wildcard() {
        let rule = AllowRule {
            app_id: Some("com.apple.*".to_string()),
            ..Default::default()
        };

        let ctx =
            ProcessContext::new(PathBuf::from("/usr/bin/test")).with_app_id("com.apple.Safari");
        assert!(rule.matches(&ctx));

        let ctx2 =
            ProcessContext::new(PathBuf::from("/usr/bin/test")).with_app_id("org.mozilla.firefox");
        assert!(!rule.matches(&ctx2));
    }

    #[test]
    fn test_rule_matching_args_pattern() {
        let rule = AllowRule {
            args_pattern: Some("*--config*".to_string()),
            ..Default::default()
        };

        let ctx = ProcessContext::new(PathBuf::from("/usr/bin/app")).with_args(vec![
            "app".to_string(),
            "--config".to_string(),
            "/etc/app.conf".to_string(),
        ]);
        assert!(rule.matches(&ctx));

        let ctx2 = ProcessContext::new(PathBuf::from("/usr/bin/app"))
            .with_args(vec!["app".to_string(), "--help".to_string()]);
        assert!(!rule.matches(&ctx2));

        // No args set
        let ctx3 = ProcessContext::new(PathBuf::from("/usr/bin/app"));
        assert!(!rule.matches(&ctx3));
    }

    #[test]
    fn test_rule_matching_specific_arg() {
        let rule = AllowRule {
            arg: Some("-l".to_string()),
            ..Default::default()
        };

        let ctx = ProcessContext::new(PathBuf::from("/usr/bin/ssh")).with_args(vec![
            "ssh".to_string(),
            "-l".to_string(),
            "user".to_string(),
        ]);
        assert!(rule.matches(&ctx));

        let ctx2 = ProcessContext::new(PathBuf::from("/usr/bin/ssh")).with_args(vec![
            "ssh".to_string(),
            "-i".to_string(),
            "key".to_string(),
        ]);
        assert!(!rule.matches(&ctx2));

        // No args
        let ctx3 = ProcessContext::new(PathBuf::from("/usr/bin/ssh"));
        assert!(!rule.matches(&ctx3));
    }

    #[test]
    fn test_rule_matching_uid() {
        let rule = AllowRule {
            uid: Some(0),
            ..Default::default()
        };

        let ctx = ProcessContext::new(PathBuf::from("/usr/bin/test")).with_uid(0);
        assert!(rule.matches(&ctx));

        let ctx2 = ProcessContext::new(PathBuf::from("/usr/bin/test")).with_uid(501);
        assert!(!rule.matches(&ctx2));

        // No uid set
        let ctx3 = ProcessContext::new(PathBuf::from("/usr/bin/test"));
        assert!(!rule.matches(&ctx3));
    }

    #[test]
    fn test_rule_matching_euid_no_context_euid() {
        let rule = AllowRule {
            euid: Some((500, 600)),
            ..Default::default()
        };

        // No euid in context
        let ctx = ProcessContext::new(PathBuf::from("/usr/bin/test"));
        assert!(!rule.matches(&ctx));
    }

    #[test]
    fn test_rule_matches_with_debug() {
        let rule = AllowRule {
            base: Some("ssh".to_string()),
            ..Default::default()
        };

        let ctx = ProcessContext::new(PathBuf::from("/usr/bin/ssh"));
        assert!(rule.matches_with_debug(&ctx, true));
        assert!(rule.matches_with_debug(&ctx, false));

        let ctx2 = ProcessContext::new(PathBuf::from("/usr/bin/cat"));
        assert!(!rule.matches_with_debug(&ctx2, true));
        assert!(!rule.matches_with_debug(&ctx2, false));
    }

    #[test]
    fn test_euid_deserialize_empty_string() {
        // Empty string should be None
        let toml_str = r#"
            euid = ""
        "#;
        let rule: AllowRule = toml::from_str(toml_str).unwrap();
        assert!(rule.euid.is_none());
    }

    #[test]
    fn test_euid_deserialize_invalid_range() {
        // Invalid range (start > end)
        let toml_str = r#"
            euid = "600-500"
        "#;
        let result: Result<AllowRule, _> = toml::from_str(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_euid_deserialize_invalid_start() {
        let toml_str = r#"
            euid = "abc-500"
        "#;
        let result: Result<AllowRule, _> = toml::from_str(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_euid_deserialize_invalid_end() {
        let toml_str = r#"
            euid = "500-abc"
        "#;
        let result: Result<AllowRule, _> = toml::from_str(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_euid_deserialize_invalid_single() {
        let toml_str = r#"
            euid = "notanumber"
        "#;
        let result: Result<AllowRule, _> = toml::from_str(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_rule_with_all_conditions() {
        let rule = AllowRule {
            base: Some("myapp".to_string()),
            path: Some("/opt/mycompany/*".to_string()),
            ppid: Some(1),
            team_id: Some("TEAM123".to_string()),
            app_id: Some("com.mycompany.myapp".to_string()),
            signing_id: Some("com.mycompany.myapp".to_string()),
            args_pattern: Some("*--safe*".to_string()),
            arg: Some("--safe".to_string()),
            uid: Some(0),
            euid: Some((0, 0)),
            platform_binary: Some(false),
            package: None,
            package_vendor: None,
            package_verified: None,
        };

        // All conditions match
        let ctx = ProcessContext::new(PathBuf::from("/opt/mycompany/bin/myapp"))
            .with_ppid(1)
            .with_team_id("TEAM123")
            .with_app_id("com.mycompany.myapp")
            .with_signing_id("com.mycompany.myapp")
            .with_args(vec!["myapp".to_string(), "--safe".to_string()])
            .with_uid(0)
            .with_euid(0)
            .with_platform_binary(false);
        assert!(rule.matches(&ctx));

        // Just one condition fails (platform_binary)
        let ctx2 = ProcessContext::new(PathBuf::from("/opt/mycompany/bin/myapp"))
            .with_ppid(1)
            .with_team_id("TEAM123")
            .with_app_id("com.mycompany.myapp")
            .with_signing_id("com.mycompany.myapp")
            .with_args(vec!["myapp".to_string(), "--safe".to_string()])
            .with_uid(0)
            .with_euid(0)
            .with_platform_binary(true);
        assert!(!rule.matches(&ctx2));
    }

    #[test]
    fn test_signing_id_no_context_signing_id() {
        let rule = AllowRule {
            signing_id: Some("com.example.*".to_string()),
            ..Default::default()
        };

        // No signing_id in context
        let ctx = ProcessContext::new(PathBuf::from("/usr/bin/test"));
        assert!(!rule.matches(&ctx));
    }

    // =========================================================================
    // Package-based matching tests
    // =========================================================================

    use crate::process::{PackageInfo, PackageManager, VerificationStatus};

    fn make_package_info(
        name: &str,
        vendor: Option<&str>,
        verified: VerificationStatus,
    ) -> PackageInfo {
        PackageInfo {
            manager: PackageManager::Rpm,
            name: name.to_string(),
            version: Some("1.0.0".to_string()),
            vendor: vendor.map(String::from),
            verified,
        }
    }

    #[test]
    fn test_rule_matching_package() {
        let rule = AllowRule {
            package: Some("openssh-*".to_string()),
            ..Default::default()
        };

        // Package matches pattern AND is verified (verification is default)
        let ctx =
            ProcessContext::new(PathBuf::from("/usr/bin/ssh")).with_package(make_package_info(
                "openssh-client",
                Some("Debian"),
                VerificationStatus::Verified,
            ));
        assert!(rule.matches(&ctx));

        // Package matches but NOT verified - should FAIL (verification is default)
        let ctx_unverified =
            ProcessContext::new(PathBuf::from("/usr/bin/ssh")).with_package(make_package_info(
                "openssh-client",
                Some("Debian"),
                VerificationStatus::NotChecked,
            ));
        assert!(!rule.matches(&ctx_unverified));

        // Package doesn't match pattern
        let ctx2 = ProcessContext::new(PathBuf::from("/usr/bin/curl")).with_package(
            make_package_info("curl", Some("Debian"), VerificationStatus::Verified),
        );
        assert!(!rule.matches(&ctx2));

        // No package info
        let ctx3 = ProcessContext::new(PathBuf::from("/usr/bin/ssh"));
        assert!(!rule.matches(&ctx3));
    }

    #[test]
    fn test_rule_matching_package_explicit_no_verify() {
        // Explicitly disable verification (not recommended but supported)
        let rule = AllowRule {
            package: Some("openssh-*".to_string()),
            package_verified: Some(false),
            ..Default::default()
        };

        // Package matches pattern, not verified, but verification disabled
        let ctx =
            ProcessContext::new(PathBuf::from("/usr/bin/ssh")).with_package(make_package_info(
                "openssh-client",
                Some("Debian"),
                VerificationStatus::NotChecked,
            ));
        assert!(rule.matches(&ctx));
    }

    #[test]
    fn test_rule_matching_package_vendor() {
        let rule = AllowRule {
            package_vendor: Some("Red Hat*".to_string()),
            ..Default::default()
        };

        // Vendor matches AND verified (verification is default)
        let ctx =
            ProcessContext::new(PathBuf::from("/usr/bin/ssh")).with_package(make_package_info(
                "openssh",
                Some("Red Hat, Inc."),
                VerificationStatus::Verified,
            ));
        assert!(rule.matches(&ctx));

        // Vendor matches but NOT verified - should FAIL
        let ctx_unverified =
            ProcessContext::new(PathBuf::from("/usr/bin/ssh")).with_package(make_package_info(
                "openssh",
                Some("Red Hat, Inc."),
                VerificationStatus::NotChecked,
            ));
        assert!(!rule.matches(&ctx_unverified));

        // Vendor doesn't match
        let ctx2 =
            ProcessContext::new(PathBuf::from("/usr/bin/ssh")).with_package(make_package_info(
                "openssh",
                Some("Fedora Project"),
                VerificationStatus::Verified,
            ));
        assert!(!rule.matches(&ctx2));

        // No vendor in package
        let ctx3 = ProcessContext::new(PathBuf::from("/usr/bin/ssh")).with_package(
            make_package_info("openssh", None, VerificationStatus::Verified),
        );
        assert!(!rule.matches(&ctx3));

        // No package info
        let ctx4 = ProcessContext::new(PathBuf::from("/usr/bin/ssh"));
        assert!(!rule.matches(&ctx4));
    }

    #[test]
    fn test_rule_matching_package_verified() {
        let rule = AllowRule {
            package_verified: Some(true),
            ..Default::default()
        };

        // Package is cryptographically verified
        let ctx = ProcessContext::new(PathBuf::from("/usr/bin/ssh")).with_package(
            make_package_info("openssh", Some("Red Hat"), VerificationStatus::Verified),
        );
        assert!(rule.matches(&ctx));

        // Package is checksum verified (weaker, but still verified)
        let ctx2 = ProcessContext::new(PathBuf::from("/usr/bin/ssh")).with_package(
            make_package_info("openssh", Some("Debian"), VerificationStatus::ChecksumOnly),
        );
        assert!(rule.matches(&ctx2));

        // Package verification not checked
        let ctx3 = ProcessContext::new(PathBuf::from("/usr/bin/ssh")).with_package(
            make_package_info("openssh", Some("Red Hat"), VerificationStatus::NotChecked),
        );
        assert!(!rule.matches(&ctx3));

        // Package verification failed
        let ctx4 = ProcessContext::new(PathBuf::from("/usr/bin/ssh")).with_package(
            make_package_info("openssh", Some("Red Hat"), VerificationStatus::Failed),
        );
        assert!(!rule.matches(&ctx4));

        // No package info
        let ctx5 = ProcessContext::new(PathBuf::from("/usr/bin/ssh"));
        assert!(!rule.matches(&ctx5));
    }

    #[test]
    fn test_rule_matching_package_combined() {
        // Real-world example: Trust all verified Red Hat packages
        let rule = AllowRule {
            package_vendor: Some("Red Hat*".to_string()),
            package_verified: Some(true),
            ..Default::default()
        };

        // Matches: Red Hat vendor + verified
        let ctx =
            ProcessContext::new(PathBuf::from("/usr/bin/ssh")).with_package(make_package_info(
                "openssh",
                Some("Red Hat, Inc."),
                VerificationStatus::Verified,
            ));
        assert!(rule.matches(&ctx));

        // Fails: Red Hat vendor but not verified
        let ctx2 =
            ProcessContext::new(PathBuf::from("/usr/bin/ssh")).with_package(make_package_info(
                "openssh",
                Some("Red Hat, Inc."),
                VerificationStatus::NotChecked,
            ));
        assert!(!rule.matches(&ctx2));

        // Fails: Verified but wrong vendor
        let ctx3 =
            ProcessContext::new(PathBuf::from("/usr/bin/ssh")).with_package(make_package_info(
                "openssh",
                Some("Fedora Project"),
                VerificationStatus::Verified,
            ));
        assert!(!rule.matches(&ctx3));
    }

    #[test]
    fn test_rule_matching_homebrew() {
        // Trust homebrew/core tap - explicitly disable verification since
        // Homebrew doesn't have per-package signatures (trusts tap name only)
        let rule = AllowRule {
            package_vendor: Some("homebrew/core".to_string()),
            package_verified: Some(false), // Homebrew uses tap trust, not signatures
            ..Default::default()
        };

        let mut pkg =
            make_package_info("git", Some("homebrew/core"), VerificationStatus::NotChecked);
        pkg.manager = PackageManager::Homebrew;

        let ctx = ProcessContext::new(PathBuf::from("/opt/homebrew/bin/git")).with_package(pkg);
        assert!(rule.matches(&ctx));

        // Third-party tap
        let mut pkg2 = make_package_info(
            "custom-tool",
            Some("user/custom-tap"),
            VerificationStatus::NotChecked,
        );
        pkg2.manager = PackageManager::Homebrew;

        let ctx2 =
            ProcessContext::new(PathBuf::from("/opt/homebrew/bin/custom-tool")).with_package(pkg2);
        assert!(!rule.matches(&ctx2));
    }

    #[test]
    fn test_package_toml_deserialization() {
        let toml_str = r#"
            package = "openssh-*"
            package_vendor = "Red Hat*"
            package_verified = true
        "#;
        let rule: AllowRule = toml::from_str(toml_str).unwrap();
        assert_eq!(rule.package, Some("openssh-*".to_string()));
        assert_eq!(rule.package_vendor, Some("Red Hat*".to_string()));
        assert_eq!(rule.package_verified, Some(true));
    }

    #[test]
    fn test_is_empty_with_package_fields() {
        // Empty rule
        let empty = AllowRule::default();
        assert!(empty.is_empty());

        // Rule with only package field
        let with_package = AllowRule {
            package: Some("openssh-*".to_string()),
            ..Default::default()
        };
        assert!(!with_package.is_empty());

        // Rule with only package_vendor
        let with_vendor = AllowRule {
            package_vendor: Some("Red Hat*".to_string()),
            ..Default::default()
        };
        assert!(!with_vendor.is_empty());

        // Rule with only package_verified
        let with_verified = AllowRule {
            package_verified: Some(true),
            ..Default::default()
        };
        assert!(!with_verified.is_empty());
    }
}
