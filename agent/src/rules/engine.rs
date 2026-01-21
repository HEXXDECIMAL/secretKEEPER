//! Rule engine for making access control decisions.

use super::{AllowRule, Exception};
use crate::config::ProtectedFile;
use crate::process::ProcessContext;

/// The result of evaluating access rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Access is allowed by a rule.
    Allow,
    /// Access is denied (no matching allow rule).
    Deny,
    /// File is not protected.
    NotProtected,
}

/// The rule engine evaluates process access against configured rules.
pub struct RuleEngine {
    protected_files: Vec<ProtectedFile>,
    global_exclusions: Vec<AllowRule>,
    exceptions: Vec<Exception>,
}

impl RuleEngine {
    pub fn new(
        protected_files: Vec<ProtectedFile>,
        global_exclusions: Vec<AllowRule>,
    ) -> Self {
        Self {
            protected_files,
            global_exclusions,
            exceptions: Vec::new(),
        }
    }

    /// Set runtime exceptions.
    pub fn set_exceptions(&mut self, exceptions: Vec<Exception>) {
        self.exceptions = exceptions;
    }

    /// Add a single exception.
    #[allow(dead_code)]
    pub fn add_exception(&mut self, exception: Exception) {
        self.exceptions.push(exception);
    }

    /// Remove an exception by ID.
    #[allow(dead_code)]
    pub fn remove_exception(&mut self, id: i64) -> bool {
        let initial_len = self.exceptions.len();
        self.exceptions.retain(|e| e.id != id);
        self.exceptions.len() < initial_len
    }

    /// Evaluate whether a process should be allowed to access a file.
    pub fn evaluate(&self, context: &ProcessContext, file_path: &str) -> Decision {
        self.evaluate_with_debug(context, file_path, false)
    }

    /// Evaluate with optional debug logging.
    pub fn evaluate_with_debug(
        &self,
        context: &ProcessContext,
        file_path: &str,
        debug: bool,
    ) -> Decision {
        // First check if the file is protected
        let protected_file = match self.find_protected_file(file_path) {
            Some(pf) => pf,
            None => {
                if debug {
                    tracing::debug!("File '{}' is not protected", file_path);
                }
                return Decision::NotProtected;
            }
        };

        if debug {
            tracing::debug!(
                "File '{}' matches protected rule '{}'",
                file_path,
                protected_file.id
            );
        }

        // Check global exclusions first
        for rule in &self.global_exclusions {
            if rule.matches_with_debug(context, debug) {
                if debug {
                    tracing::debug!(
                        "Process '{}' allowed by global exclusion",
                        context.path.display()
                    );
                }
                return Decision::Allow;
            }
        }

        // Check runtime exceptions
        let team_id = context.team_id.as_deref();
        let process_path = context.path.to_string_lossy();
        for exception in &self.exceptions {
            if exception.matches(&process_path, team_id, file_path) {
                if debug {
                    tracing::debug!(
                        "Process '{}' allowed by exception {}",
                        process_path,
                        exception.id
                    );
                }
                return Decision::Allow;
            }
        }

        // Check file-specific allow rules
        for rule in &protected_file.allow {
            if rule.matches_with_debug(context, debug) {
                if debug {
                    tracing::debug!(
                        "Process '{}' allowed by rule for '{}'",
                        context.path.display(),
                        protected_file.id
                    );
                }
                return Decision::Allow;
            }
        }

        if debug {
            tracing::debug!(
                "Process '{}' DENIED access to '{}'",
                context.path.display(),
                file_path
            );
        }

        Decision::Deny
    }

    /// Find the protected file rule that matches the given path.
    fn find_protected_file(&self, file_path: &str) -> Option<&ProtectedFile> {
        for pf in &self.protected_files {
            for pattern in &pf.patterns {
                if super::matches_pattern(pattern, file_path) {
                    return Some(pf);
                }
            }
        }
        None
    }

    /// Check if a file path is protected by any rule.
    #[allow(dead_code)]
    pub fn is_protected(&self, file_path: &str) -> bool {
        self.find_protected_file(file_path).is_some()
    }

    /// Get the rule ID for a protected file, if any.
    pub fn get_rule_id(&self, file_path: &str) -> Option<&str> {
        self.find_protected_file(file_path).map(|pf| pf.id.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use std::path::PathBuf;

    fn make_protected_files() -> Vec<ProtectedFile> {
        vec![
            ProtectedFile {
                id: "ssh_keys".to_string(),
                patterns: vec!["~/.ssh/id_*".to_string(), "~/.ssh/*_key".to_string()],
                allow: vec![AllowRule {
                    base: Some("ssh".to_string()),
                    ..Default::default()
                }],
            },
            ProtectedFile {
                id: "aws_creds".to_string(),
                patterns: vec!["~/.aws/credentials".to_string()],
                allow: vec![AllowRule {
                    base: Some("aws".to_string()),
                    ..Default::default()
                }],
            },
        ]
    }

    #[test]
    fn test_not_protected() {
        let engine = RuleEngine::new(make_protected_files(), vec![]);
        let ctx = ProcessContext::new(PathBuf::from("/usr/bin/cat"));

        assert_eq!(
            engine.evaluate(&ctx, "/etc/passwd"),
            Decision::NotProtected
        );
    }

    #[test]
    fn test_allowed_by_rule() {
        let engine = RuleEngine::new(make_protected_files(), vec![]);
        let ctx = ProcessContext::new(PathBuf::from("/usr/bin/ssh"));

        assert_eq!(engine.evaluate(&ctx, "~/.ssh/id_rsa"), Decision::Allow);
    }

    #[test]
    fn test_denied() {
        let engine = RuleEngine::new(make_protected_files(), vec![]);
        let ctx = ProcessContext::new(PathBuf::from("/usr/bin/cat"));

        assert_eq!(engine.evaluate(&ctx, "~/.ssh/id_rsa"), Decision::Deny);
    }

    #[test]
    fn test_global_exclusion() {
        let exclusions = vec![AllowRule {
            team_id: Some("TRUSTED123".to_string()),
            ..Default::default()
        }];

        let engine = RuleEngine::new(make_protected_files(), exclusions);
        let ctx =
            ProcessContext::new(PathBuf::from("/usr/bin/cat")).with_team_id("TRUSTED123");

        assert_eq!(engine.evaluate(&ctx, "~/.ssh/id_rsa"), Decision::Allow);
    }

    #[test]
    fn test_exception_allows_access() {
        let mut engine = RuleEngine::new(make_protected_files(), vec![]);

        // Add an exception for a specific process
        let exception = Exception {
            id: 1,
            process_path: Some("/usr/bin/cat".to_string()),
            code_signer: None,
            file_pattern: "~/.ssh/*".to_string(),
            is_glob: true,
            expires_at: None,
            added_by: "test".to_string(),
            comment: None,
            created_at: Utc::now(),
        };
        engine.set_exceptions(vec![exception]);

        let ctx = ProcessContext::new(PathBuf::from("/usr/bin/cat"));
        assert_eq!(engine.evaluate(&ctx, "~/.ssh/id_rsa"), Decision::Allow);
    }

    #[test]
    fn test_expired_exception_does_not_allow() {
        let mut engine = RuleEngine::new(make_protected_files(), vec![]);

        // Add an expired exception
        let exception = Exception {
            id: 1,
            process_path: Some("/usr/bin/cat".to_string()),
            code_signer: None,
            file_pattern: "~/.ssh/*".to_string(),
            is_glob: true,
            expires_at: Some(Utc::now() - Duration::hours(1)),
            added_by: "test".to_string(),
            comment: None,
            created_at: Utc::now() - Duration::hours(2),
        };
        engine.set_exceptions(vec![exception]);

        let ctx = ProcessContext::new(PathBuf::from("/usr/bin/cat"));
        assert_eq!(engine.evaluate(&ctx, "~/.ssh/id_rsa"), Decision::Deny);
    }

    #[test]
    fn test_exception_by_code_signer() {
        let mut engine = RuleEngine::new(make_protected_files(), vec![]);

        // Add an exception by code signer
        let exception = Exception {
            id: 1,
            process_path: None,
            code_signer: Some("TRUSTED_TEAM_ID".to_string()),
            file_pattern: "~/.ssh/*".to_string(),
            is_glob: true,
            expires_at: None,
            added_by: "test".to_string(),
            comment: None,
            created_at: Utc::now(),
        };
        engine.set_exceptions(vec![exception]);

        let ctx =
            ProcessContext::new(PathBuf::from("/usr/bin/mytool")).with_team_id("TRUSTED_TEAM_ID");
        assert_eq!(engine.evaluate(&ctx, "~/.ssh/id_rsa"), Decision::Allow);

        // Different team_id should be denied
        let ctx2 =
            ProcessContext::new(PathBuf::from("/usr/bin/mytool")).with_team_id("DIFFERENT_TEAM");
        assert_eq!(engine.evaluate(&ctx2, "~/.ssh/id_rsa"), Decision::Deny);
    }

    #[test]
    fn test_add_remove_exception() {
        let mut engine = RuleEngine::new(make_protected_files(), vec![]);

        let exception = Exception {
            id: 42,
            process_path: Some("/usr/bin/cat".to_string()),
            code_signer: None,
            file_pattern: "~/.ssh/*".to_string(),
            is_glob: true,
            expires_at: None,
            added_by: "test".to_string(),
            comment: None,
            created_at: Utc::now(),
        };
        engine.add_exception(exception);

        let ctx = ProcessContext::new(PathBuf::from("/usr/bin/cat"));
        assert_eq!(engine.evaluate(&ctx, "~/.ssh/id_rsa"), Decision::Allow);

        // Remove the exception
        assert!(engine.remove_exception(42));
        assert_eq!(engine.evaluate(&ctx, "~/.ssh/id_rsa"), Decision::Deny);

        // Remove non-existent exception
        assert!(!engine.remove_exception(999));
    }

    #[test]
    fn test_is_protected() {
        let engine = RuleEngine::new(make_protected_files(), vec![]);

        assert!(engine.is_protected("~/.ssh/id_rsa"));
        assert!(engine.is_protected("~/.ssh/id_ed25519"));
        assert!(engine.is_protected("~/.ssh/my_key"));
        assert!(engine.is_protected("~/.aws/credentials"));
        assert!(!engine.is_protected("/etc/passwd"));
        assert!(!engine.is_protected("~/.config/something"));
    }

    #[test]
    fn test_get_rule_id() {
        let engine = RuleEngine::new(make_protected_files(), vec![]);

        assert_eq!(engine.get_rule_id("~/.ssh/id_rsa"), Some("ssh_keys"));
        assert_eq!(engine.get_rule_id("~/.aws/credentials"), Some("aws_creds"));
        assert_eq!(engine.get_rule_id("/etc/passwd"), None);
    }

    #[test]
    fn test_multiple_allow_rules() {
        let protected = vec![ProtectedFile {
            id: "ssh_keys".to_string(),
            patterns: vec!["~/.ssh/id_*".to_string()],
            allow: vec![
                AllowRule {
                    base: Some("ssh".to_string()),
                    ..Default::default()
                },
                AllowRule {
                    base: Some("scp".to_string()),
                    ..Default::default()
                },
                AllowRule {
                    base: Some("git-remote-*".to_string()),
                    ..Default::default()
                },
            ],
        }];

        let engine = RuleEngine::new(protected, vec![]);

        // ssh allowed
        let ctx = ProcessContext::new(PathBuf::from("/usr/bin/ssh"));
        assert_eq!(engine.evaluate(&ctx, "~/.ssh/id_rsa"), Decision::Allow);

        // scp allowed
        let ctx = ProcessContext::new(PathBuf::from("/usr/bin/scp"));
        assert_eq!(engine.evaluate(&ctx, "~/.ssh/id_rsa"), Decision::Allow);

        // git-remote-ssh allowed
        let ctx = ProcessContext::new(PathBuf::from("/usr/libexec/git-core/git-remote-ssh"));
        assert_eq!(engine.evaluate(&ctx, "~/.ssh/id_rsa"), Decision::Allow);

        // cat denied
        let ctx = ProcessContext::new(PathBuf::from("/usr/bin/cat"));
        assert_eq!(engine.evaluate(&ctx, "~/.ssh/id_rsa"), Decision::Deny);
    }

    #[test]
    fn test_global_exclusion_takes_precedence() {
        let protected = vec![ProtectedFile {
            id: "ssh_keys".to_string(),
            patterns: vec!["~/.ssh/id_*".to_string()],
            allow: vec![], // No specific allow rules
        }];

        let exclusions = vec![AllowRule {
            platform_binary: Some(true),
            ..Default::default()
        }];

        let engine = RuleEngine::new(protected, exclusions);

        // Platform binary is allowed even without specific rule
        let ctx = ProcessContext::new(PathBuf::from("/usr/bin/anything"))
            .with_platform_binary(true);
        assert_eq!(engine.evaluate(&ctx, "~/.ssh/id_rsa"), Decision::Allow);

        // Non-platform binary is denied
        let ctx = ProcessContext::new(PathBuf::from("/usr/bin/anything"))
            .with_platform_binary(false);
        assert_eq!(engine.evaluate(&ctx, "~/.ssh/id_rsa"), Decision::Deny);
    }

    #[test]
    fn test_exception_exact_file_match() {
        let mut engine = RuleEngine::new(make_protected_files(), vec![]);

        // Exception for exact file (not glob)
        let exception = Exception {
            id: 1,
            process_path: Some("/usr/bin/cat".to_string()),
            code_signer: None,
            file_pattern: "~/.ssh/id_rsa".to_string(),
            is_glob: false,
            expires_at: None,
            added_by: "test".to_string(),
            comment: None,
            created_at: Utc::now(),
        };
        engine.set_exceptions(vec![exception]);

        let ctx = ProcessContext::new(PathBuf::from("/usr/bin/cat"));

        // Exact match allowed
        assert_eq!(engine.evaluate(&ctx, "~/.ssh/id_rsa"), Decision::Allow);

        // Different file denied
        assert_eq!(engine.evaluate(&ctx, "~/.ssh/id_ed25519"), Decision::Deny);
    }
}
