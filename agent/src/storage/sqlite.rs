//! SQLite storage for violations and exceptions.

use crate::error::{Error, Result};
use crate::process::ProcessTreeEntry;
use crate::rules::Exception;
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

/// Persistent storage backed by SQLite.
pub struct Storage {
    conn: Mutex<Connection>,
}

impl Storage {
    /// Acquire the database lock, recovering from poison if necessary.
    /// Poisoned mutexes indicate a previous panic - we log and continue.
    fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|poisoned| {
            tracing::warn!("Database mutex was poisoned, recovering");
            poisoned.into_inner()
        })
    }
}

impl Storage {
    /// Open or create a database at the given path.
    pub fn open(path: &Path) -> Result<Self> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(path)?;
        let storage = Self {
            conn: Mutex::new(conn),
        };
        storage.initialize()?;
        Ok(storage)
    }

    /// Open an in-memory database (for testing).
    #[allow(dead_code)]
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let storage = Self {
            conn: Mutex::new(conn),
        };
        storage.initialize()?;
        Ok(storage)
    }

    fn initialize(&self) -> Result<()> {
        let conn = self.lock();

        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS violations (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                rule_id TEXT,
                file_path TEXT NOT NULL,
                process_path TEXT NOT NULL,
                process_pid INTEGER NOT NULL,
                process_ppid INTEGER,
                process_euid INTEGER,
                process_cmdline TEXT,
                team_id TEXT,
                signing_id TEXT,
                action TEXT NOT NULL,
                process_tree_json TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_violations_timestamp ON violations(timestamp);
            CREATE INDEX IF NOT EXISTS idx_violations_file_path ON violations(file_path);
            CREATE INDEX IF NOT EXISTS idx_violations_process_path ON violations(process_path);

            CREATE TABLE IF NOT EXISTS exceptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                process_path TEXT,
                code_signer TEXT,
                file_pattern TEXT NOT NULL,
                is_glob INTEGER DEFAULT 0,
                expires_at TEXT,
                added_by TEXT NOT NULL,
                comment TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                CONSTRAINT chk_identifier CHECK (process_path IS NOT NULL OR code_signer IS NOT NULL)
            );

            CREATE INDEX IF NOT EXISTS idx_exceptions_process ON exceptions(process_path);
            CREATE INDEX IF NOT EXISTS idx_exceptions_signer ON exceptions(code_signer);

            CREATE TABLE IF NOT EXISTS agent_state (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            "#,
        )?;

        Ok(())
    }

    /// Record a violation.
    pub fn record_violation(&self, violation: &Violation) -> Result<()> {
        let conn = self.lock();
        let process_tree_json = serde_json::to_string(&violation.process_tree)?;

        conn.execute(
            r#"
            INSERT INTO violations (
                id, timestamp, rule_id, file_path, process_path, process_pid,
                process_ppid, process_euid, process_cmdline, team_id, signing_id,
                action, process_tree_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
            "#,
            params![
                violation.id,
                violation.timestamp.to_rfc3339(),
                violation.rule_id,
                violation.file_path,
                violation.process_path,
                violation.process_pid,
                violation.process_ppid,
                violation.process_euid,
                violation.process_cmdline,
                violation.team_id,
                violation.signing_id,
                violation.action,
                process_tree_json,
            ],
        )?;

        Ok(())
    }

    /// Get a violation by ID.
    pub fn get_violation(&self, id: &str) -> Result<Option<Violation>> {
        let conn = self.lock();

        conn.query_row(
            "SELECT * FROM violations WHERE id = ?1",
            params![id],
            |row| {
                let process_tree_json: String = row.get("process_tree_json")?;
                let timestamp_str: String = row.get("timestamp")?;

                Ok(Violation {
                    id: row.get("id")?,
                    timestamp: DateTime::parse_from_rfc3339(&timestamp_str)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                    rule_id: row.get("rule_id")?,
                    file_path: row.get("file_path")?,
                    process_path: row.get("process_path")?,
                    process_pid: row.get("process_pid")?,
                    process_ppid: row.get("process_ppid")?,
                    process_euid: row.get("process_euid")?,
                    process_cmdline: row.get("process_cmdline")?,
                    team_id: row.get("team_id")?,
                    signing_id: row.get("signing_id")?,
                    action: row.get("action")?,
                    process_tree: serde_json::from_str(&process_tree_json).unwrap_or_default(),
                })
            },
        )
        .optional()
        .map_err(Error::from)
    }

    /// Get recent violations.
    pub fn get_violations(
        &self,
        limit: usize,
        since: Option<DateTime<Utc>>,
    ) -> Result<Vec<Violation>> {
        let conn = self.lock();
        let mut violations = Vec::new();

        let query = match since {
            Some(_) => {
                "SELECT * FROM violations WHERE timestamp >= ?1 ORDER BY timestamp DESC LIMIT ?2"
            }
            None => "SELECT * FROM violations ORDER BY timestamp DESC LIMIT ?1",
        };

        let mut stmt = conn.prepare(query)?;

        let rows = match since {
            Some(ts) => stmt.query(params![ts.to_rfc3339(), limit])?,
            None => stmt.query(params![limit])?,
        };

        let mut rows = rows;
        while let Some(row) = rows.next()? {
            let process_tree_json: String = row.get("process_tree_json")?;
            let timestamp_str: String = row.get("timestamp")?;

            violations.push(Violation {
                id: row.get("id")?,
                timestamp: DateTime::parse_from_rfc3339(&timestamp_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                rule_id: row.get("rule_id")?,
                file_path: row.get("file_path")?,
                process_path: row.get("process_path")?,
                process_pid: row.get("process_pid")?,
                process_ppid: row.get("process_ppid")?,
                process_euid: row.get("process_euid")?,
                process_cmdline: row.get("process_cmdline")?,
                team_id: row.get("team_id")?,
                signing_id: row.get("signing_id")?,
                action: row.get("action")?,
                process_tree: serde_json::from_str(&process_tree_json).unwrap_or_default(),
            });
        }

        Ok(violations)
    }

    /// Delete violations older than the specified number of days.
    #[allow(dead_code)]
    pub fn cleanup_old_violations(&self, retention_days: u32) -> Result<usize> {
        let conn = self.lock();
        let cutoff = Utc::now() - chrono::Duration::days(retention_days as i64);

        let deleted = conn.execute(
            "DELETE FROM violations WHERE timestamp < ?1",
            params![cutoff.to_rfc3339()],
        )?;

        Ok(deleted)
    }

    /// Add an exception.
    pub fn add_exception(&self, exception: &Exception) -> Result<i64> {
        let conn = self.lock();

        conn.execute(
            r#"
            INSERT INTO exceptions (
                process_path, code_signer, file_pattern, is_glob,
                expires_at, added_by, comment
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
            params![
                exception.process_path,
                exception.code_signer,
                exception.file_pattern,
                exception.is_glob as i32,
                exception.expires_at.map(|dt| dt.to_rfc3339()),
                exception.added_by,
                exception.comment,
            ],
        )?;

        Ok(conn.last_insert_rowid())
    }

    /// Get all valid (non-expired) exceptions.
    pub fn get_exceptions(&self) -> Result<Vec<Exception>> {
        let conn = self.lock();
        let mut exceptions = Vec::new();

        let mut stmt =
            conn.prepare("SELECT * FROM exceptions WHERE expires_at IS NULL OR expires_at > ?1")?;

        let now = Utc::now().to_rfc3339();
        let rows = stmt.query(params![now])?;

        let mut rows = rows;
        while let Some(row) = rows.next()? {
            let expires_at_str: Option<String> = row.get("expires_at")?;
            let created_at_str: String = row.get("created_at")?;

            exceptions.push(Exception {
                id: row.get("id")?,
                process_path: row.get("process_path")?,
                code_signer: row.get("code_signer")?,
                file_pattern: row.get("file_pattern")?,
                is_glob: row.get::<_, i32>("is_glob")? != 0,
                expires_at: expires_at_str.and_then(|s| {
                    DateTime::parse_from_rfc3339(&s)
                        .map(|dt| dt.with_timezone(&Utc))
                        .ok()
                }),
                added_by: row.get("added_by")?,
                comment: row.get("comment")?,
                created_at: DateTime::parse_from_rfc3339(&created_at_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            });
        }

        Ok(exceptions)
    }

    /// Remove an exception by ID.
    pub fn remove_exception(&self, id: i64) -> Result<bool> {
        let conn = self.lock();
        let deleted = conn.execute("DELETE FROM exceptions WHERE id = ?1", params![id])?;
        Ok(deleted > 0)
    }

    /// Get a state value.
    #[allow(dead_code)]
    pub fn get_state(&self, key: &str) -> Result<Option<String>> {
        let conn = self.lock();
        conn.query_row(
            "SELECT value FROM agent_state WHERE key = ?1",
            params![key],
            |row| row.get(0),
        )
        .optional()
        .map_err(Error::from)
    }

    /// Set a state value.
    pub fn set_state(&self, key: &str, value: &str) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            r#"
            INSERT INTO agent_state (key, value, updated_at)
            VALUES (?1, ?2, CURRENT_TIMESTAMP)
            ON CONFLICT(key) DO UPDATE SET value = ?2, updated_at = CURRENT_TIMESTAMP
            "#,
            params![key, value],
        )?;
        Ok(())
    }

    /// Count total violations.
    pub fn count_violations(&self) -> Result<u64> {
        let conn = self.lock();
        conn.query_row("SELECT COUNT(*) FROM violations", [], |row| row.get(0))
            .map_err(Error::from)
    }
}

/// A recorded violation.
#[derive(Debug, Clone)]
pub struct Violation {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub rule_id: Option<String>,
    pub file_path: String,
    pub process_path: String,
    pub process_pid: u32,
    pub process_ppid: Option<u32>,
    pub process_euid: Option<u32>,
    pub process_cmdline: Option<String>,
    pub team_id: Option<String>,
    pub signing_id: Option<String>,
    pub action: String,
    pub process_tree: Vec<ProcessTreeEntry>,
}

#[allow(dead_code)]
impl Violation {
    pub fn new(
        file_path: impl Into<String>,
        process_path: impl Into<String>,
        process_pid: u32,
        action: impl Into<String>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            rule_id: None,
            file_path: file_path.into(),
            process_path: process_path.into(),
            process_pid,
            process_ppid: None,
            process_euid: None,
            process_cmdline: None,
            team_id: None,
            signing_id: None,
            action: action.into(),
            process_tree: Vec::new(),
        }
    }

    pub fn with_rule_id(mut self, rule_id: impl Into<String>) -> Self {
        self.rule_id = Some(rule_id.into());
        self
    }

    pub fn with_ppid(mut self, ppid: u32) -> Self {
        self.process_ppid = Some(ppid);
        self
    }

    pub fn with_euid(mut self, euid: u32) -> Self {
        self.process_euid = Some(euid);
        self
    }

    pub fn with_cmdline(mut self, cmdline: impl Into<String>) -> Self {
        self.process_cmdline = Some(cmdline.into());
        self
    }

    pub fn with_team_id(mut self, team_id: impl Into<String>) -> Self {
        self.team_id = Some(team_id.into());
        self
    }

    pub fn with_signing_id(mut self, signing_id: impl Into<String>) -> Self {
        self.signing_id = Some(signing_id.into());
        self
    }

    pub fn with_process_tree(mut self, tree: Vec<ProcessTreeEntry>) -> Self {
        self.process_tree = tree;
        self
    }

    /// Set ppid from Option value.
    pub fn with_ppid_opt(mut self, ppid: Option<u32>) -> Self {
        self.process_ppid = ppid;
        self
    }

    /// Set euid from Option value.
    pub fn with_euid_opt(mut self, euid: Option<u32>) -> Self {
        self.process_euid = euid;
        self
    }

    /// Set cmdline from Option value.
    pub fn with_cmdline_opt(mut self, cmdline: Option<String>) -> Self {
        self.process_cmdline = cmdline;
        self
    }

    /// Set team_id from Option value.
    pub fn with_team_id_opt(mut self, team_id: Option<String>) -> Self {
        self.team_id = team_id;
        self
    }

    /// Set signing_id from Option value.
    pub fn with_signing_id_opt(mut self, signing_id: Option<String>) -> Self {
        self.signing_id = signing_id;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_storage_violations() {
        let storage = Storage::in_memory().unwrap();

        let violation = Violation::new("~/.ssh/id_rsa", "/usr/bin/cat", 1234, "blocked")
            .with_rule_id("ssh_keys")
            .with_euid(501);

        storage.record_violation(&violation).unwrap();

        let retrieved = storage.get_violation(&violation.id).unwrap().unwrap();
        assert_eq!(retrieved.file_path, "~/.ssh/id_rsa");
        assert_eq!(retrieved.process_path, "/usr/bin/cat");
        assert_eq!(retrieved.process_pid, 1234);
        assert_eq!(retrieved.action, "blocked");

        let violations = storage.get_violations(10, None).unwrap();
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn test_storage_exceptions() {
        let storage = Storage::in_memory().unwrap();

        let exception = Exception {
            id: 0,
            process_path: Some("/usr/local/bin/tool".to_string()),
            code_signer: None,
            file_pattern: "~/.ssh/*".to_string(),
            is_glob: true,
            expires_at: None,
            added_by: "test".to_string(),
            comment: Some("Test exception".to_string()),
            created_at: Utc::now(),
        };

        let id = storage.add_exception(&exception).unwrap();
        assert!(id > 0);

        let exceptions = storage.get_exceptions().unwrap();
        assert_eq!(exceptions.len(), 1);
        assert_eq!(exceptions[0].file_pattern, "~/.ssh/*");

        storage.remove_exception(id).unwrap();
        let exceptions = storage.get_exceptions().unwrap();
        assert!(exceptions.is_empty());
    }

    #[test]
    fn test_storage_state() {
        let storage = Storage::in_memory().unwrap();

        storage.set_state("mode", "block").unwrap();
        assert_eq!(
            storage.get_state("mode").unwrap(),
            Some("block".to_string())
        );

        storage.set_state("mode", "monitor").unwrap();
        assert_eq!(
            storage.get_state("mode").unwrap(),
            Some("monitor".to_string())
        );
    }

    #[test]
    fn test_multiple_violations() {
        let storage = Storage::in_memory().unwrap();

        // Add multiple violations
        for i in 0..5 {
            let violation = Violation::new(
                format!("~/.ssh/key_{}", i),
                "/usr/bin/cat",
                1000 + i,
                "blocked",
            );
            storage.record_violation(&violation).unwrap();
        }

        // Test count
        assert_eq!(storage.count_violations().unwrap(), 5);

        // Test limit
        let violations = storage.get_violations(3, None).unwrap();
        assert_eq!(violations.len(), 3);

        // Get all
        let all_violations = storage.get_violations(100, None).unwrap();
        assert_eq!(all_violations.len(), 5);
    }

    #[test]
    fn test_violation_with_all_fields() {
        let storage = Storage::in_memory().unwrap();

        let process_tree = vec![ProcessTreeEntry {
            pid: 1234,
            ppid: Some(1),
            name: "cat".to_string(),
            path: "/usr/bin/cat".to_string(),
            cwd: Some("/home/user".to_string()),
            cmdline: Some("cat ~/.ssh/id_rsa".to_string()),
            uid: Some(501),
            euid: Some(501),
            team_id: None,
            signing_id: Some("com.apple.cat".to_string()),
            is_platform_binary: true,
            is_stopped: false,
        }];

        let violation = Violation::new("~/.ssh/id_rsa", "/usr/bin/cat", 1234, "blocked")
            .with_rule_id("ssh_keys")
            .with_ppid(1)
            .with_euid(501)
            .with_cmdline("cat ~/.ssh/id_rsa")
            .with_team_id("APPLE123")
            .with_signing_id("com.apple.cat")
            .with_process_tree(process_tree);

        storage.record_violation(&violation).unwrap();

        let retrieved = storage.get_violation(&violation.id).unwrap().unwrap();
        assert_eq!(retrieved.rule_id, Some("ssh_keys".to_string()));
        assert_eq!(retrieved.process_ppid, Some(1));
        assert_eq!(retrieved.process_euid, Some(501));
        assert_eq!(
            retrieved.process_cmdline,
            Some("cat ~/.ssh/id_rsa".to_string())
        );
        assert_eq!(retrieved.team_id, Some("APPLE123".to_string()));
        assert_eq!(retrieved.signing_id, Some("com.apple.cat".to_string()));
        assert_eq!(retrieved.process_tree.len(), 1);
        assert_eq!(retrieved.process_tree[0].name, "cat");
    }

    #[test]
    fn test_expired_exceptions_filtered() {
        let storage = Storage::in_memory().unwrap();

        // Add a non-expired exception
        let valid_exception = Exception {
            id: 0,
            process_path: Some("/usr/bin/valid".to_string()),
            code_signer: None,
            file_pattern: "~/.ssh/*".to_string(),
            is_glob: true,
            expires_at: Some(Utc::now() + Duration::hours(1)),
            added_by: "test".to_string(),
            comment: None,
            created_at: Utc::now(),
        };
        storage.add_exception(&valid_exception).unwrap();

        // Add an expired exception
        let expired_exception = Exception {
            id: 0,
            process_path: Some("/usr/bin/expired".to_string()),
            code_signer: None,
            file_pattern: "~/.aws/*".to_string(),
            is_glob: true,
            expires_at: Some(Utc::now() - Duration::hours(1)),
            added_by: "test".to_string(),
            comment: None,
            created_at: Utc::now() - Duration::hours(2),
        };
        storage.add_exception(&expired_exception).unwrap();

        // Only non-expired should be returned
        let exceptions = storage.get_exceptions().unwrap();
        assert_eq!(exceptions.len(), 1);
        assert_eq!(exceptions[0].file_pattern, "~/.ssh/*");
    }

    #[test]
    fn test_exception_with_code_signer() {
        let storage = Storage::in_memory().unwrap();

        let exception = Exception {
            id: 0,
            process_path: None,
            code_signer: Some("APPLE_TEAM_123".to_string()),
            file_pattern: "~/.ssh/*".to_string(),
            is_glob: true,
            expires_at: None,
            added_by: "test".to_string(),
            comment: Some("Allow all Apple-signed apps".to_string()),
            created_at: Utc::now(),
        };

        let id = storage.add_exception(&exception).unwrap();
        let exceptions = storage.get_exceptions().unwrap();

        assert_eq!(exceptions.len(), 1);
        assert_eq!(exceptions[0].id, id);
        assert!(exceptions[0].process_path.is_none());
        assert_eq!(
            exceptions[0].code_signer,
            Some("APPLE_TEAM_123".to_string())
        );
    }

    #[test]
    fn test_remove_nonexistent_exception() {
        let storage = Storage::in_memory().unwrap();

        let result = storage.remove_exception(999).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_get_nonexistent_violation() {
        let storage = Storage::in_memory().unwrap();

        let result = storage.get_violation("nonexistent-id").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_get_nonexistent_state() {
        let storage = Storage::in_memory().unwrap();

        let result = storage.get_state("nonexistent-key").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_cleanup_old_violations() {
        let storage = Storage::in_memory().unwrap();

        // Add a recent violation
        let recent = Violation::new("~/.ssh/id_rsa", "/usr/bin/cat", 1234, "blocked");
        storage.record_violation(&recent).unwrap();

        // We can't easily add old violations in the test because timestamp is set on creation
        // But we can verify the cleanup doesn't delete recent ones
        let deleted = storage.cleanup_old_violations(30).unwrap();
        assert_eq!(deleted, 0);

        // Verify violation still exists
        assert_eq!(storage.count_violations().unwrap(), 1);
    }

    #[test]
    fn test_get_violations_with_since() {
        let storage = Storage::in_memory().unwrap();

        // Add a few violations
        for i in 0..3 {
            let violation = Violation::new(
                format!("~/.ssh/key_{}", i),
                "/usr/bin/cat",
                1000 + i,
                "blocked",
            );
            storage.record_violation(&violation).unwrap();
        }

        // Get violations since now (should be empty because all are in the past)
        let future = Utc::now() + Duration::hours(1);
        let violations = storage.get_violations(10, Some(future)).unwrap();
        assert!(violations.is_empty());

        // Get violations since an hour ago (should get all)
        let past = Utc::now() - Duration::hours(1);
        let violations = storage.get_violations(10, Some(past)).unwrap();
        assert_eq!(violations.len(), 3);
    }

    #[test]
    fn test_permanent_exception() {
        let storage = Storage::in_memory().unwrap();

        // Add a permanent exception (no expiry)
        let exception = Exception {
            id: 0,
            process_path: Some("/usr/bin/ssh".to_string()),
            code_signer: None,
            file_pattern: "~/.ssh/*".to_string(),
            is_glob: true,
            expires_at: None, // Permanent
            added_by: "test".to_string(),
            comment: None,
            created_at: Utc::now(),
        };
        storage.add_exception(&exception).unwrap();

        // Should be returned
        let exceptions = storage.get_exceptions().unwrap();
        assert_eq!(exceptions.len(), 1);
        assert!(exceptions[0].expires_at.is_none());
    }

    #[test]
    fn test_violation_builder_methods() {
        let violation = Violation::new("~/.ssh/id_rsa", "/usr/bin/cat", 1234, "blocked")
            .with_ppid_opt(Some(1))
            .with_euid_opt(Some(501))
            .with_cmdline_opt(Some("cat ~/.ssh/id_rsa".to_string()))
            .with_team_id_opt(Some("APPLE123".to_string()))
            .with_signing_id_opt(Some("com.apple.cat".to_string()));

        assert_eq!(violation.process_ppid, Some(1));
        assert_eq!(violation.process_euid, Some(501));
        assert_eq!(
            violation.process_cmdline,
            Some("cat ~/.ssh/id_rsa".to_string())
        );
        assert_eq!(violation.team_id, Some("APPLE123".to_string()));
        assert_eq!(violation.signing_id, Some("com.apple.cat".to_string()));
    }

    #[test]
    fn test_violation_builder_methods_none_sets_none() {
        let violation = Violation::new("~/.ssh/id_rsa", "/usr/bin/cat", 1234, "blocked")
            .with_ppid_opt(None)
            .with_euid_opt(None)
            .with_cmdline_opt(None)
            .with_team_id_opt(None)
            .with_signing_id_opt(None);

        assert!(violation.process_ppid.is_none());
        assert!(violation.process_euid.is_none());
        assert!(violation.process_cmdline.is_none());
        assert!(violation.team_id.is_none());
        assert!(violation.signing_id.is_none());
    }

    #[test]
    fn test_storage_open_creates_tables() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let db_path = temp_dir.path().join("new.db");

        // File doesn't exist yet
        assert!(!db_path.exists());

        // Opening should create it
        let storage = Storage::open(&db_path).unwrap();
        assert!(db_path.exists());

        // Tables should be created - try to use them
        let violations = storage.get_violations(10, None).unwrap();
        assert!(violations.is_empty());

        let exceptions = storage.get_exceptions().unwrap();
        assert!(exceptions.is_empty());
    }
}
