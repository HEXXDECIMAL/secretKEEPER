//! Runtime exceptions for temporary or permanent process allowlisting.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A runtime exception that allows a process to access protected files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Exception {
    /// Unique identifier for this exception.
    pub id: i64,
    /// Process path pattern (glob supported).
    pub process_path: Option<String>,
    /// Code signer (team_id) to allow.
    pub code_signer: Option<String>,
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
    pub fn is_valid(&self) -> bool {
        match self.expires_at {
            Some(expires) => Utc::now() < expires,
            None => true,
        }
    }

    /// Check if this exception matches the given process and file.
    pub fn matches(&self, process_path: &str, team_id: Option<&str>, file_path: &str) -> bool {
        if !self.is_valid() {
            return false;
        }

        // Check process path pattern
        let process_matches = match &self.process_path {
            Some(pattern) => super::matches_pattern(pattern, process_path),
            None => true,
        };

        // Check code signer
        let signer_matches = match (&self.code_signer, team_id) {
            (Some(expected), Some(actual)) => expected == actual,
            (Some(_), None) => false,
            (None, _) => true,
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
    code_signer: Option<String>,
    file_pattern: String,
    is_glob: bool,
    expires_at: Option<DateTime<Utc>>,
    added_by: String,
    comment: Option<String>,
}

#[allow(dead_code)]
impl ExceptionBuilder {
    pub fn new(file_pattern: impl Into<String>, added_by: impl Into<String>) -> Self {
        Self {
            process_path: None,
            code_signer: None,
            file_pattern: file_pattern.into(),
            is_glob: false,
            expires_at: None,
            added_by: added_by.into(),
            comment: None,
        }
    }

    pub fn process_path(mut self, path: impl Into<String>) -> Self {
        self.process_path = Some(path.into());
        self
    }

    pub fn code_signer(mut self, signer: impl Into<String>) -> Self {
        self.code_signer = Some(signer.into());
        self
    }

    pub fn glob(mut self, is_glob: bool) -> Self {
        self.is_glob = is_glob;
        self
    }

    pub fn expires_at(mut self, expires: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires);
        self
    }

    pub fn comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// Build the exception. Note: id and created_at are set by the database.
    pub fn build(self) -> Exception {
        Exception {
            id: 0, // Set by database
            process_path: self.process_path,
            code_signer: self.code_signer,
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

    #[test]
    fn test_exception_validity() {
        let permanent = Exception {
            id: 1,
            process_path: None,
            code_signer: None,
            file_pattern: "~/.ssh/*".to_string(),
            is_glob: true,
            expires_at: None,
            added_by: "test".to_string(),
            comment: None,
            created_at: Utc::now(),
        };
        assert!(permanent.is_valid());

        let future = Exception {
            id: 2,
            process_path: None,
            code_signer: None,
            file_pattern: "~/.ssh/*".to_string(),
            is_glob: true,
            expires_at: Some(Utc::now() + Duration::hours(1)),
            added_by: "test".to_string(),
            comment: None,
            created_at: Utc::now(),
        };
        assert!(future.is_valid());

        let expired = Exception {
            id: 3,
            process_path: None,
            code_signer: None,
            file_pattern: "~/.ssh/*".to_string(),
            is_glob: true,
            expires_at: Some(Utc::now() - Duration::hours(1)),
            added_by: "test".to_string(),
            comment: None,
            created_at: Utc::now(),
        };
        assert!(!expired.is_valid());
    }

    #[test]
    fn test_exception_matching() {
        let exception = Exception {
            id: 1,
            process_path: Some("/usr/local/bin/*".to_string()),
            code_signer: None,
            file_pattern: "~/.ssh/*".to_string(),
            is_glob: true,
            expires_at: None,
            added_by: "test".to_string(),
            comment: None,
            created_at: Utc::now(),
        };

        assert!(exception.matches("/usr/local/bin/mytool", None, "~/.ssh/id_rsa"));
        assert!(!exception.matches("/usr/bin/cat", None, "~/.ssh/id_rsa"));
        assert!(!exception.matches("/usr/local/bin/mytool", None, "~/.aws/credentials"));
    }

    #[test]
    fn test_exception_code_signer_matching() {
        let exception = Exception {
            id: 1,
            process_path: None,
            code_signer: Some("TEAMID123".to_string()),
            file_pattern: "~/.ssh/*".to_string(),
            is_glob: true,
            expires_at: None,
            added_by: "test".to_string(),
            comment: None,
            created_at: Utc::now(),
        };

        // Matching team_id
        assert!(exception.matches("/any/path", Some("TEAMID123"), "~/.ssh/id_rsa"));
        // Wrong team_id
        assert!(!exception.matches("/any/path", Some("WRONGID"), "~/.ssh/id_rsa"));
        // No team_id when required
        assert!(!exception.matches("/any/path", None, "~/.ssh/id_rsa"));
    }

    #[test]
    fn test_exception_no_process_path_matches_all() {
        let exception = Exception {
            id: 1,
            process_path: None,
            code_signer: None,
            file_pattern: "~/.ssh/*".to_string(),
            is_glob: true,
            expires_at: None,
            added_by: "test".to_string(),
            comment: None,
            created_at: Utc::now(),
        };

        // Any process should match
        assert!(exception.matches("/usr/bin/cat", None, "~/.ssh/id_rsa"));
        assert!(exception.matches("/opt/custom/tool", None, "~/.ssh/id_rsa"));
    }

    #[test]
    fn test_exception_exact_file_match() {
        let exception = Exception {
            id: 1,
            process_path: None,
            code_signer: None,
            file_pattern: "~/.ssh/id_rsa".to_string(),
            is_glob: false, // Exact match, not glob
            expires_at: None,
            added_by: "test".to_string(),
            comment: None,
            created_at: Utc::now(),
        };

        assert!(exception.matches("/any/path", None, "~/.ssh/id_rsa"));
        assert!(!exception.matches("/any/path", None, "~/.ssh/id_ed25519"));
    }

    #[test]
    fn test_exception_expired_does_not_match() {
        let exception = Exception {
            id: 1,
            process_path: None,
            code_signer: None,
            file_pattern: "~/.ssh/*".to_string(),
            is_glob: true,
            expires_at: Some(Utc::now() - Duration::hours(1)), // Expired
            added_by: "test".to_string(),
            comment: None,
            created_at: Utc::now(),
        };

        // Should not match because it's expired
        assert!(!exception.matches("/any/path", None, "~/.ssh/id_rsa"));
    }

    #[test]
    fn test_exception_builder_basic() {
        let exception = ExceptionBuilder::new("~/.ssh/*", "user").glob(true).build();

        assert_eq!(exception.file_pattern, "~/.ssh/*");
        assert!(exception.is_glob);
        assert_eq!(exception.added_by, "user");
        assert!(exception.process_path.is_none());
        assert!(exception.code_signer.is_none());
        assert!(exception.expires_at.is_none());
        assert!(exception.comment.is_none());
    }

    #[test]
    fn test_exception_builder_full() {
        let expires = Utc::now() + Duration::days(7);
        let exception = ExceptionBuilder::new("~/.ssh/id_rsa", "ui")
            .process_path("/usr/bin/ssh")
            .code_signer("APPLE123")
            .expires_at(expires)
            .comment("Allow ssh access")
            .build();

        assert_eq!(exception.file_pattern, "~/.ssh/id_rsa");
        assert!(!exception.is_glob);
        assert_eq!(exception.added_by, "ui");
        assert_eq!(exception.process_path, Some("/usr/bin/ssh".to_string()));
        assert_eq!(exception.code_signer, Some("APPLE123".to_string()));
        assert_eq!(exception.expires_at, Some(expires));
        assert_eq!(exception.comment, Some("Allow ssh access".to_string()));
    }

    #[test]
    fn test_exception_combined_filters() {
        let exception = Exception {
            id: 1,
            process_path: Some("/usr/bin/ssh".to_string()),
            code_signer: Some("APPLE".to_string()),
            file_pattern: "~/.ssh/*".to_string(),
            is_glob: true,
            expires_at: None,
            added_by: "test".to_string(),
            comment: None,
            created_at: Utc::now(),
        };

        // All conditions must match
        assert!(exception.matches("/usr/bin/ssh", Some("APPLE"), "~/.ssh/id_rsa"));
        // Wrong process
        assert!(!exception.matches("/usr/bin/cat", Some("APPLE"), "~/.ssh/id_rsa"));
        // Wrong signer
        assert!(!exception.matches("/usr/bin/ssh", Some("OTHER"), "~/.ssh/id_rsa"));
        // Wrong file
        assert!(!exception.matches("/usr/bin/ssh", Some("APPLE"), "~/.aws/creds"));
    }

    #[test]
    fn test_exception_no_signer_requirement_matches_any() {
        let exception = Exception {
            id: 1,
            process_path: None,
            code_signer: None, // No signer requirement
            file_pattern: "~/.ssh/*".to_string(),
            is_glob: true,
            expires_at: None,
            added_by: "test".to_string(),
            comment: None,
            created_at: Utc::now(),
        };

        // Should match regardless of team_id
        assert!(exception.matches("/any/path", Some("ANY_TEAM"), "~/.ssh/id_rsa"));
        assert!(exception.matches("/any/path", None, "~/.ssh/id_rsa"));
    }
}
