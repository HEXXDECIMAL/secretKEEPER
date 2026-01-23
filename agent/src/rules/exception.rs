//! Runtime exceptions for temporary or permanent process allowlisting.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

/// The type of code signature to match against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerType {
    /// Match against team_id (third-party properly signed apps).
    TeamId,
    /// Match against signing_id (platform binaries, some system processes).
    SigningId,
    /// Adhoc signed (has signing_id but no verified identity).
    Adhoc,
    /// Unsigned binary (no code signature at all).
    Unsigned,
}

impl fmt::Display for SignerType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignerType::TeamId => write!(f, "team_id"),
            SignerType::SigningId => write!(f, "signing_id"),
            SignerType::Adhoc => write!(f, "adhoc"),
            SignerType::Unsigned => write!(f, "unsigned"),
        }
    }
}

impl std::str::FromStr for SignerType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "team_id" | "teamid" => Ok(SignerType::TeamId),
            "signing_id" | "signingid" => Ok(SignerType::SigningId),
            "adhoc" | "ad_hoc" | "ad-hoc" => Ok(SignerType::Adhoc),
            "unsigned" => Ok(SignerType::Unsigned),
            _ => Err(format!("unknown signer type: {}", s)),
        }
    }
}

/// A runtime exception that allows a process to access protected files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Exception {
    /// Unique identifier for this exception.
    pub id: i64,
    /// Process path pattern (glob supported).
    pub process_path: Option<String>,
    /// Type of signer to match (None = no signer requirement).
    pub signer_type: Option<SignerType>,
    /// Team ID to match when signer_type is TeamId.
    pub team_id: Option<String>,
    /// Signing ID to match when signer_type is SigningId or Adhoc.
    pub signing_id: Option<String>,
    /// File pattern this exception applies to.
    pub file_pattern: String,
    /// Whether file_pattern is a glob pattern.
    pub is_glob: bool,
    /// When this exception expires (None = permanent).
    pub expires_at: Option<DateTime<Utc>>,
    /// Who added this exception ("user", "ui", "config").
    pub added_by: String,
    /// Optional comment explaining why this exception exists.
    pub comment: Option<String>,
    /// When this exception was created.
    pub created_at: DateTime<Utc>,
}

impl Exception {
    /// Check if this exception is still valid (not expired).
    #[must_use]
    pub fn is_valid(&self) -> bool {
        match self.expires_at {
            Some(expires) => Utc::now() < expires,
            None => true,
        }
    }

    /// Check if this exception matches the given process and file.
    ///
    /// Signer matching is explicit based on signer_type:
    /// - TeamId: matches against process team_id
    /// - SigningId: matches against process signing_id
    /// - Adhoc: matches against process signing_id (adhoc apps have signing IDs)
    /// - Unsigned: matches if process has no team_id and no signing_id
    /// - None: no signer requirement (matches any)
    #[must_use]
    pub fn matches(
        &self,
        process_path: &str,
        process_team_id: Option<&str>,
        process_signing_id: Option<&str>,
        is_adhoc: bool,
        file_path: &str,
    ) -> bool {
        if !self.is_valid() {
            return false;
        }

        // Check process path pattern
        let process_matches = match &self.process_path {
            Some(pattern) => super::matches_pattern(pattern, process_path),
            None => true,
        };

        // Check signer based on explicit signer_type
        let signer_matches = match self.signer_type {
            Some(SignerType::TeamId) => {
                // Must match team_id
                match (&self.team_id, process_team_id) {
                    (Some(expected), Some(actual)) => expected == actual,
                    _ => false,
                }
            }
            Some(SignerType::SigningId) => {
                // Must match signing_id
                match (&self.signing_id, process_signing_id) {
                    (Some(expected), Some(actual)) => expected == actual,
                    _ => false,
                }
            }
            Some(SignerType::Adhoc) => {
                // Process must be adhoc signed and optionally match signing_id
                if !is_adhoc {
                    return false;
                }
                match (&self.signing_id, process_signing_id) {
                    (Some(expected), Some(actual)) => expected == actual,
                    (None, _) => true, // No specific signing_id required, just adhoc
                    _ => false,
                }
            }
            Some(SignerType::Unsigned) => {
                // Process must have no signature
                process_team_id.is_none() && process_signing_id.is_none() && !is_adhoc
            }
            None => true, // No signer requirement
        };

        // Check file pattern
        let file_matches = if self.is_glob {
            super::matches_pattern(&self.file_pattern, file_path)
        } else {
            self.file_pattern == file_path
        };

        process_matches && signer_matches && file_matches
    }
}

/// Builder for creating new exceptions.
#[allow(dead_code)]
pub struct ExceptionBuilder {
    process_path: Option<String>,
    signer_type: Option<SignerType>,
    team_id: Option<String>,
    signing_id: Option<String>,
    file_pattern: String,
    is_glob: bool,
    expires_at: Option<DateTime<Utc>>,
    added_by: String,
    comment: Option<String>,
}

#[allow(dead_code)]
impl ExceptionBuilder {
    #[must_use]
    pub fn new(file_pattern: impl Into<String>, added_by: impl Into<String>) -> Self {
        Self {
            process_path: None,
            signer_type: None,
            team_id: None,
            signing_id: None,
            file_pattern: file_pattern.into(),
            is_glob: false,
            expires_at: None,
            added_by: added_by.into(),
            comment: None,
        }
    }

    #[must_use]
    pub fn process_path(mut self, path: impl Into<String>) -> Self {
        self.process_path = Some(path.into());
        self
    }

    #[must_use]
    pub fn signer_type(mut self, signer_type: SignerType) -> Self {
        self.signer_type = Some(signer_type);
        self
    }

    #[must_use]
    pub fn team_id(mut self, team_id: impl Into<String>) -> Self {
        self.team_id = Some(team_id.into());
        self.signer_type = Some(SignerType::TeamId);
        self
    }

    #[must_use]
    pub fn signing_id(mut self, signing_id: impl Into<String>) -> Self {
        self.signing_id = Some(signing_id.into());
        // Don't auto-set signer_type here - caller should set it explicitly
        self
    }

    #[must_use]
    pub fn glob(mut self, is_glob: bool) -> Self {
        self.is_glob = is_glob;
        self
    }

    #[must_use]
    pub fn expires_at(mut self, expires: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires);
        self
    }

    #[must_use]
    pub fn comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// Build the exception. Note: id and created_at are set by the database.
    #[must_use]
    pub fn build(self) -> Exception {
        Exception {
            id: 0, // Set by database
            process_path: self.process_path,
            signer_type: self.signer_type,
            team_id: self.team_id,
            signing_id: self.signing_id,
            file_pattern: self.file_pattern,
            is_glob: self.is_glob,
            expires_at: self.expires_at,
            added_by: self.added_by,
            comment: self.comment,
            created_at: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    /// Helper to create a basic exception with no signer requirement
    fn make_exception(file_pattern: &str, is_glob: bool) -> Exception {
        Exception {
            id: 1,
            process_path: None,
            signer_type: None,
            team_id: None,
            signing_id: None,
            file_pattern: file_pattern.to_string(),
            is_glob,
            expires_at: None,
            added_by: "test".to_string(),
            comment: None,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn test_exception_validity() {
        let permanent = make_exception("~/.ssh/*", true);
        assert!(permanent.is_valid());

        let mut future = make_exception("~/.ssh/*", true);
        future.expires_at = Some(Utc::now() + Duration::hours(1));
        assert!(future.is_valid());

        let mut expired = make_exception("~/.ssh/*", true);
        expired.expires_at = Some(Utc::now() - Duration::hours(1));
        assert!(!expired.is_valid());
    }

    #[test]
    fn test_exception_matching() {
        let mut exception = make_exception("~/.ssh/*", true);
        exception.process_path = Some("/usr/local/bin/*".to_string());

        // is_adhoc=false for all these tests
        assert!(exception.matches("/usr/local/bin/mytool", None, None, false, "~/.ssh/id_rsa"));
        assert!(!exception.matches("/usr/bin/cat", None, None, false, "~/.ssh/id_rsa"));
        assert!(!exception.matches(
            "/usr/local/bin/mytool",
            None,
            None,
            false,
            "~/.aws/credentials"
        ));
    }

    #[test]
    fn test_exception_team_id_matching() {
        let exception = Exception {
            id: 1,
            process_path: None,
            signer_type: Some(SignerType::TeamId),
            team_id: Some("TEAMID123".to_string()),
            signing_id: None,
            file_pattern: "~/.ssh/*".to_string(),
            is_glob: true,
            expires_at: None,
            added_by: "test".to_string(),
            comment: None,
            created_at: Utc::now(),
        };

        // Matching team_id
        assert!(exception.matches("/any/path", Some("TEAMID123"), None, false, "~/.ssh/id_rsa"));
        // Wrong team_id
        assert!(!exception.matches("/any/path", Some("WRONGID"), None, false, "~/.ssh/id_rsa"));
        // No team_id provided
        assert!(!exception.matches(
            "/any/path",
            None,
            Some("com.example.app"),
            false,
            "~/.ssh/id_rsa"
        ));
        // No identifiers at all
        assert!(!exception.matches("/any/path", None, None, false, "~/.ssh/id_rsa"));
    }

    #[test]
    fn test_exception_signing_id_matching() {
        // For platform binaries that only have signing_id (no team_id)
        let exception = Exception {
            id: 1,
            process_path: None,
            signer_type: Some(SignerType::SigningId),
            team_id: None,
            signing_id: Some("com.apple.bluetoothd".to_string()),
            file_pattern: "/Library/Keychains/*".to_string(),
            is_glob: true,
            expires_at: None,
            added_by: "test".to_string(),
            comment: None,
            created_at: Utc::now(),
        };

        // Matching signing_id (platform binary case)
        assert!(exception.matches(
            "/any/path",
            None,
            Some("com.apple.bluetoothd"),
            false,
            "/Library/Keychains/foo"
        ));
        // Wrong signing_id
        assert!(!exception.matches(
            "/any/path",
            None,
            Some("com.apple.other"),
            false,
            "/Library/Keychains/foo"
        ));
        // Has team_id but we need signing_id match
        assert!(!exception.matches(
            "/any/path",
            Some("SOMETEAM"),
            None,
            false,
            "/Library/Keychains/foo"
        ));
    }

    #[test]
    fn test_exception_adhoc_matching() {
        // Adhoc exception with specific signing_id
        let exception = Exception {
            id: 1,
            process_path: None,
            signer_type: Some(SignerType::Adhoc),
            team_id: None,
            signing_id: Some("adhoc-app-id".to_string()),
            file_pattern: "~/.ssh/*".to_string(),
            is_glob: true,
            expires_at: None,
            added_by: "test".to_string(),
            comment: None,
            created_at: Utc::now(),
        };

        // Adhoc with matching signing_id
        assert!(exception.matches(
            "/any/path",
            None,
            Some("adhoc-app-id"),
            true,
            "~/.ssh/id_rsa"
        ));
        // Not adhoc - should not match even with matching signing_id
        assert!(!exception.matches(
            "/any/path",
            None,
            Some("adhoc-app-id"),
            false,
            "~/.ssh/id_rsa"
        ));
        // Adhoc but wrong signing_id
        assert!(!exception.matches("/any/path", None, Some("wrong-id"), true, "~/.ssh/id_rsa"));
    }

    #[test]
    fn test_exception_adhoc_any_signing_id() {
        // Adhoc exception without specific signing_id (matches any adhoc)
        let exception = Exception {
            id: 1,
            process_path: None,
            signer_type: Some(SignerType::Adhoc),
            team_id: None,
            signing_id: None, // No specific signing_id required
            file_pattern: "~/.ssh/*".to_string(),
            is_glob: true,
            expires_at: None,
            added_by: "test".to_string(),
            comment: None,
            created_at: Utc::now(),
        };

        // Any adhoc process matches
        assert!(exception.matches(
            "/any/path",
            None,
            Some("any-adhoc-id"),
            true,
            "~/.ssh/id_rsa"
        ));
        // Not adhoc - should not match
        assert!(!exception.matches("/any/path", None, Some("any-id"), false, "~/.ssh/id_rsa"));
    }

    #[test]
    fn test_exception_unsigned_matching() {
        let exception = Exception {
            id: 1,
            process_path: None,
            signer_type: Some(SignerType::Unsigned),
            team_id: None,
            signing_id: None,
            file_pattern: "~/.ssh/*".to_string(),
            is_glob: true,
            expires_at: None,
            added_by: "test".to_string(),
            comment: None,
            created_at: Utc::now(),
        };

        // Unsigned process (no team_id, no signing_id, not adhoc)
        assert!(exception.matches("/any/path", None, None, false, "~/.ssh/id_rsa"));
        // Has team_id - not unsigned
        assert!(!exception.matches("/any/path", Some("TEAM"), None, false, "~/.ssh/id_rsa"));
        // Has signing_id - not unsigned
        assert!(!exception.matches(
            "/any/path",
            None,
            Some("com.example"),
            false,
            "~/.ssh/id_rsa"
        ));
        // Adhoc - not unsigned
        assert!(!exception.matches("/any/path", None, Some("adhoc-id"), true, "~/.ssh/id_rsa"));
    }

    #[test]
    fn test_exception_no_process_path_matches_all() {
        let exception = make_exception("~/.ssh/*", true);

        // Any process should match
        assert!(exception.matches("/usr/bin/cat", None, None, false, "~/.ssh/id_rsa"));
        assert!(exception.matches("/opt/custom/tool", None, None, false, "~/.ssh/id_rsa"));
    }

    #[test]
    fn test_exception_exact_file_match() {
        let exception = make_exception("~/.ssh/id_rsa", false);

        assert!(exception.matches("/any/path", None, None, false, "~/.ssh/id_rsa"));
        assert!(!exception.matches("/any/path", None, None, false, "~/.ssh/id_ed25519"));
    }

    #[test]
    fn test_exception_expired_does_not_match() {
        let mut exception = make_exception("~/.ssh/*", true);
        exception.expires_at = Some(Utc::now() - Duration::hours(1));

        // Should not match because it's expired
        assert!(!exception.matches("/any/path", None, None, false, "~/.ssh/id_rsa"));
    }

    #[test]
    fn test_exception_builder_basic() {
        let exception = ExceptionBuilder::new("~/.ssh/*", "user").glob(true).build();

        assert_eq!(exception.file_pattern, "~/.ssh/*");
        assert!(exception.is_glob);
        assert_eq!(exception.added_by, "user");
        assert!(exception.process_path.is_none());
        assert!(exception.signer_type.is_none());
        assert!(exception.team_id.is_none());
        assert!(exception.signing_id.is_none());
        assert!(exception.expires_at.is_none());
        assert!(exception.comment.is_none());
    }

    #[test]
    fn test_exception_builder_with_team_id() {
        let expires = Utc::now() + Duration::days(7);
        let exception = ExceptionBuilder::new("~/.ssh/id_rsa", "ui")
            .process_path("/usr/bin/ssh")
            .team_id("APPLE123")
            .expires_at(expires)
            .comment("Allow ssh access")
            .build();

        assert_eq!(exception.file_pattern, "~/.ssh/id_rsa");
        assert!(!exception.is_glob);
        assert_eq!(exception.added_by, "ui");
        assert_eq!(exception.process_path, Some("/usr/bin/ssh".to_string()));
        assert_eq!(exception.signer_type, Some(SignerType::TeamId));
        assert_eq!(exception.team_id, Some("APPLE123".to_string()));
        assert!(exception.signing_id.is_none());
        assert_eq!(exception.expires_at, Some(expires));
        assert_eq!(exception.comment, Some("Allow ssh access".to_string()));
    }

    #[test]
    fn test_exception_builder_with_signing_id() {
        let exception = ExceptionBuilder::new("/Library/Keychains/*", "ui")
            .signer_type(SignerType::SigningId)
            .signing_id("com.apple.bluetoothd")
            .glob(true)
            .build();

        assert_eq!(exception.signer_type, Some(SignerType::SigningId));
        assert_eq!(
            exception.signing_id,
            Some("com.apple.bluetoothd".to_string())
        );
        assert!(exception.team_id.is_none());
    }

    #[test]
    fn test_exception_combined_filters() {
        let exception = Exception {
            id: 1,
            process_path: Some("/usr/bin/ssh".to_string()),
            signer_type: Some(SignerType::TeamId),
            team_id: Some("APPLE".to_string()),
            signing_id: None,
            file_pattern: "~/.ssh/*".to_string(),
            is_glob: true,
            expires_at: None,
            added_by: "test".to_string(),
            comment: None,
            created_at: Utc::now(),
        };

        // All conditions must match
        assert!(exception.matches("/usr/bin/ssh", Some("APPLE"), None, false, "~/.ssh/id_rsa"));
        // Wrong process
        assert!(!exception.matches("/usr/bin/cat", Some("APPLE"), None, false, "~/.ssh/id_rsa"));
        // Wrong signer
        assert!(!exception.matches("/usr/bin/ssh", Some("OTHER"), None, false, "~/.ssh/id_rsa"));
        // Wrong file
        assert!(!exception.matches("/usr/bin/ssh", Some("APPLE"), None, false, "~/.aws/creds"));
    }

    #[test]
    fn test_exception_no_signer_requirement_matches_any() {
        let exception = make_exception("~/.ssh/*", true);

        // Should match regardless of team_id or signing_id
        assert!(exception.matches("/any/path", Some("ANY_TEAM"), None, false, "~/.ssh/id_rsa"));
        assert!(exception.matches(
            "/any/path",
            None,
            Some("com.example.app"),
            false,
            "~/.ssh/id_rsa"
        ));
        assert!(exception.matches("/any/path", None, None, false, "~/.ssh/id_rsa"));
        assert!(exception.matches("/any/path", None, Some("adhoc"), true, "~/.ssh/id_rsa"));
    }

    #[test]
    fn test_exception_expiration_durations() {
        // Test 1 hour expiration
        let mut one_hour = make_exception("~/.ssh/*", true);
        one_hour.expires_at = Some(Utc::now() + Duration::hours(1));
        assert!(one_hour.is_valid());
        assert!(one_hour.matches("/any/path", None, None, false, "~/.ssh/id_rsa"));

        // Test 24 hour expiration
        let mut one_day = make_exception("~/.ssh/*", true);
        one_day.expires_at = Some(Utc::now() + Duration::hours(24));
        assert!(one_day.is_valid());

        // Test 1 week expiration
        let mut one_week = make_exception("~/.ssh/*", true);
        one_week.expires_at = Some(Utc::now() + Duration::hours(168));
        assert!(one_week.is_valid());
    }

    #[test]
    fn test_exception_just_expired() {
        let mut just_expired = make_exception("~/.ssh/*", true);
        just_expired.expires_at = Some(Utc::now() - Duration::seconds(1));
        just_expired.created_at = Utc::now() - Duration::hours(1);

        assert!(!just_expired.is_valid());
        assert!(!just_expired.matches("/any/path", None, None, false, "~/.ssh/id_rsa"));
    }

    #[test]
    fn test_exception_about_to_expire() {
        let mut about_to_expire = make_exception("~/.ssh/*", true);
        about_to_expire.expires_at = Some(Utc::now() + Duration::seconds(1));

        assert!(about_to_expire.is_valid());
        assert!(about_to_expire.matches("/any/path", None, None, false, "~/.ssh/id_rsa"));
    }

    #[test]
    fn test_signer_type_from_str() {
        assert_eq!("team_id".parse::<SignerType>().unwrap(), SignerType::TeamId);
        assert_eq!("teamid".parse::<SignerType>().unwrap(), SignerType::TeamId);
        assert_eq!(
            "signing_id".parse::<SignerType>().unwrap(),
            SignerType::SigningId
        );
        assert_eq!("adhoc".parse::<SignerType>().unwrap(), SignerType::Adhoc);
        assert_eq!("ad-hoc".parse::<SignerType>().unwrap(), SignerType::Adhoc);
        assert_eq!(
            "unsigned".parse::<SignerType>().unwrap(),
            SignerType::Unsigned
        );
        assert!("invalid".parse::<SignerType>().is_err());
    }

    #[test]
    fn test_signer_type_display() {
        assert_eq!(SignerType::TeamId.to_string(), "team_id");
        assert_eq!(SignerType::SigningId.to_string(), "signing_id");
        assert_eq!(SignerType::Adhoc.to_string(), "adhoc");
        assert_eq!(SignerType::Unsigned.to_string(), "unsigned");
    }

    // Edge case tests for reliability

    #[test]
    fn test_team_id_exception_without_team_id_value_does_not_match() {
        // Invalid state: signer_type=TeamId but no team_id value
        // Should never match anything
        let exception = Exception {
            id: 1,
            process_path: None,
            signer_type: Some(SignerType::TeamId),
            team_id: None, // Missing!
            signing_id: None,
            file_pattern: "~/.ssh/*".to_string(),
            is_glob: true,
            expires_at: None,
            added_by: "test".to_string(),
            comment: None,
            created_at: Utc::now(),
        };

        // Should not match even if process has a team_id
        assert!(!exception.matches("/any/path", Some("ANY_TEAM"), None, false, "~/.ssh/id_rsa"));
        // Should not match unsigned either
        assert!(!exception.matches("/any/path", None, None, false, "~/.ssh/id_rsa"));
    }

    #[test]
    fn test_signing_id_exception_without_signing_id_value_does_not_match() {
        // Invalid state: signer_type=SigningId but no signing_id value
        let exception = Exception {
            id: 1,
            process_path: None,
            signer_type: Some(SignerType::SigningId),
            team_id: None,
            signing_id: None, // Missing!
            file_pattern: "~/.ssh/*".to_string(),
            is_glob: true,
            expires_at: None,
            added_by: "test".to_string(),
            comment: None,
            created_at: Utc::now(),
        };

        // Should not match even if process has a signing_id
        assert!(!exception.matches(
            "/any/path",
            None,
            Some("com.example.app"),
            false,
            "~/.ssh/id_rsa"
        ));
        // Should not match platform binary
        assert!(!exception.matches(
            "/any/path",
            None,
            Some("com.apple.bluetoothd"),
            false,
            "~/.ssh/id_rsa"
        ));
    }

    #[test]
    fn test_signing_id_exception_matches_process_with_both_team_and_signing_id() {
        // A process can have both team_id (developer signed) and signing_id
        // A SigningId exception should still match if signing_id matches
        let exception = Exception {
            id: 1,
            process_path: None,
            signer_type: Some(SignerType::SigningId),
            team_id: None,
            signing_id: Some("com.example.myapp".to_string()),
            file_pattern: "~/.ssh/*".to_string(),
            is_glob: true,
            expires_at: None,
            added_by: "test".to_string(),
            comment: None,
            created_at: Utc::now(),
        };

        // Process has both team_id and signing_id - should match on signing_id
        assert!(exception.matches(
            "/Applications/MyApp.app/Contents/MacOS/MyApp",
            Some("TEAM123"), // Has team_id too
            Some("com.example.myapp"),
            false,
            "~/.ssh/id_rsa"
        ));

        // Wrong signing_id should not match even with team_id
        assert!(!exception.matches(
            "/Applications/MyApp.app/Contents/MacOS/MyApp",
            Some("TEAM123"),
            Some("com.example.otherapp"),
            false,
            "~/.ssh/id_rsa"
        ));
    }

    #[test]
    fn test_team_id_exception_does_not_match_process_with_only_signing_id() {
        // TeamId exception requires team_id, not just signing_id
        let exception = Exception {
            id: 1,
            process_path: None,
            signer_type: Some(SignerType::TeamId),
            team_id: Some("TEAM123".to_string()),
            signing_id: None,
            file_pattern: "~/.ssh/*".to_string(),
            is_glob: true,
            expires_at: None,
            added_by: "test".to_string(),
            comment: None,
            created_at: Utc::now(),
        };

        // Platform binary with signing_id but no team_id should NOT match
        assert!(!exception.matches(
            "/usr/libexec/something",
            None,
            Some("com.apple.something"),
            false,
            "~/.ssh/id_rsa"
        ));

        // Adhoc with signing_id but no team_id should NOT match
        assert!(!exception.matches(
            "/usr/local/bin/adhoc-tool",
            None,
            Some("adhoc-tool-id"),
            true,
            "~/.ssh/id_rsa"
        ));
    }

    #[test]
    fn test_adhoc_exception_does_not_match_platform_binary() {
        // Adhoc exception should only match is_adhoc=true processes
        // Platform binaries have is_adhoc=false
        let exception = Exception {
            id: 1,
            process_path: None,
            signer_type: Some(SignerType::Adhoc),
            team_id: None,
            signing_id: Some("com.apple.bluetoothd".to_string()),
            file_pattern: "~/.ssh/*".to_string(),
            is_glob: true,
            expires_at: None,
            added_by: "test".to_string(),
            comment: None,
            created_at: Utc::now(),
        };

        // Platform binary (is_adhoc=false) should NOT match adhoc exception
        assert!(!exception.matches(
            "/usr/sbin/bluetoothd",
            None,
            Some("com.apple.bluetoothd"),
            false, // NOT adhoc - it's a platform binary
            "~/.ssh/id_rsa"
        ));

        // Actual adhoc process should match
        assert!(exception.matches(
            "/usr/local/bin/adhoc-tool",
            None,
            Some("com.apple.bluetoothd"), // Same signing_id
            true,                         // IS adhoc
            "~/.ssh/id_rsa"
        ));
    }

    #[test]
    fn test_unsigned_exception_does_not_match_adhoc() {
        // Unsigned means truly unsigned (no signature at all)
        // Adhoc processes have signatures, just not verified
        let exception = Exception {
            id: 1,
            process_path: None,
            signer_type: Some(SignerType::Unsigned),
            team_id: None,
            signing_id: None,
            file_pattern: "~/.ssh/*".to_string(),
            is_glob: true,
            expires_at: None,
            added_by: "test".to_string(),
            comment: None,
            created_at: Utc::now(),
        };

        // Adhoc process (has signing_id) should NOT match unsigned exception
        assert!(!exception.matches(
            "/usr/local/bin/adhoc-tool",
            None,
            Some("adhoc-signing-id"),
            true, // is_adhoc=true
            "~/.ssh/id_rsa"
        ));

        // Truly unsigned (no signing_id, not adhoc) should match
        assert!(exception.matches(
            "/usr/local/bin/unsigned-tool",
            None,
            None,
            false,
            "~/.ssh/id_rsa"
        ));
    }

    #[test]
    fn test_exception_process_path_glob_matching() {
        // Test that process_path supports glob patterns
        let exception = Exception {
            id: 1,
            process_path: Some("/usr/local/bin/*".to_string()),
            signer_type: None,
            team_id: None,
            signing_id: None,
            file_pattern: "~/.ssh/*".to_string(),
            is_glob: true,
            expires_at: None,
            added_by: "test".to_string(),
            comment: None,
            created_at: Utc::now(),
        };

        // Should match any process under /usr/local/bin/
        assert!(exception.matches("/usr/local/bin/my-tool", None, None, false, "~/.ssh/id_rsa"));
        assert!(exception.matches("/usr/local/bin/other", None, None, false, "~/.ssh/id_rsa"));

        // Should NOT match other paths
        assert!(!exception.matches("/usr/bin/cat", None, None, false, "~/.ssh/id_rsa"));
        assert!(!exception.matches("/opt/bin/tool", None, None, false, "~/.ssh/id_rsa"));
    }

    #[test]
    fn test_exception_file_pattern_exact_vs_glob() {
        // Test that is_glob flag is respected
        let glob_exception = Exception {
            id: 1,
            process_path: None,
            signer_type: None,
            team_id: None,
            signing_id: None,
            file_pattern: "~/.ssh/*".to_string(),
            is_glob: true,
            expires_at: None,
            added_by: "test".to_string(),
            comment: None,
            created_at: Utc::now(),
        };

        let exact_exception = Exception {
            id: 2,
            process_path: None,
            signer_type: None,
            team_id: None,
            signing_id: None,
            file_pattern: "~/.ssh/*".to_string(), // Same pattern but treated as literal
            is_glob: false,
            expires_at: None,
            added_by: "test".to_string(),
            comment: None,
            created_at: Utc::now(),
        };

        // Glob should match files under ~/.ssh/
        assert!(glob_exception.matches("/any", None, None, false, "~/.ssh/id_rsa"));
        assert!(glob_exception.matches("/any", None, None, false, "~/.ssh/config"));

        // Exact should only match the literal string "~/.ssh/*"
        assert!(!exact_exception.matches("/any", None, None, false, "~/.ssh/id_rsa"));
        assert!(exact_exception.matches("/any", None, None, false, "~/.ssh/*"));
        // Literal match
    }

    #[test]
    fn test_exception_all_conditions_must_match() {
        // If all conditions are specified, ALL must match
        let exception = Exception {
            id: 1,
            process_path: Some("/usr/bin/ssh".to_string()),
            signer_type: Some(SignerType::TeamId),
            team_id: Some("APPLE".to_string()),
            signing_id: None,
            file_pattern: "~/.ssh/id_rsa".to_string(),
            is_glob: false,
            expires_at: None,
            added_by: "test".to_string(),
            comment: None,
            created_at: Utc::now(),
        };

        // All match - should pass
        assert!(exception.matches("/usr/bin/ssh", Some("APPLE"), None, false, "~/.ssh/id_rsa"));

        // Process path mismatch
        assert!(!exception.matches("/usr/bin/cat", Some("APPLE"), None, false, "~/.ssh/id_rsa"));

        // Team ID mismatch
        assert!(!exception.matches("/usr/bin/ssh", Some("OTHER"), None, false, "~/.ssh/id_rsa"));

        // File mismatch
        assert!(!exception.matches(
            "/usr/bin/ssh",
            Some("APPLE"),
            None,
            false,
            "~/.ssh/id_ed25519"
        ));

        // No team_id at all
        assert!(!exception.matches("/usr/bin/ssh", None, None, false, "~/.ssh/id_rsa"));
    }

    #[test]
    fn test_case_sensitive_matching() {
        // Team IDs and signing IDs should be case-sensitive
        let exception = Exception {
            id: 1,
            process_path: None,
            signer_type: Some(SignerType::TeamId),
            team_id: Some("APPLE123".to_string()),
            signing_id: None,
            file_pattern: "~/.ssh/*".to_string(),
            is_glob: true,
            expires_at: None,
            added_by: "test".to_string(),
            comment: None,
            created_at: Utc::now(),
        };

        // Exact case matches
        assert!(exception.matches("/any", Some("APPLE123"), None, false, "~/.ssh/id_rsa"));

        // Different case should NOT match
        assert!(!exception.matches("/any", Some("apple123"), None, false, "~/.ssh/id_rsa"));
        assert!(!exception.matches("/any", Some("Apple123"), None, false, "~/.ssh/id_rsa"));
    }
}
