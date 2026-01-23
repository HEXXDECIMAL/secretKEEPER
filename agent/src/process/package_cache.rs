//! High-performance cache for package ownership queries.
//!
//! Uses a combination of file metadata (inode, mtime, ctime, btime) as cache keys
//! to detect file modifications without re-querying the package manager.
//!
//! Note: This cache is not yet wired into the main monitoring loop.
//! It will be integrated when package-based rules are enabled at runtime.

#![allow(dead_code)]

use super::package::{verify_package, PackageInfo, VerificationStatus};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::{Instant, SystemTime};

/// Maximum number of entries in the cache.
const MAX_CACHE_ENTRIES: usize = 10_000;

/// How often to check if the package database has changed (seconds).
const PKG_DB_CHECK_INTERVAL_SECS: u64 = 60;

/// Cache key based on file identity and modification times.
/// All fields must match for a cache hit.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct FileCacheKey {
    /// Canonical file path
    pub path: PathBuf,
    /// Inode number (catches file replacement)
    pub inode: u64,
    /// Modification time in seconds since epoch
    pub mtime_secs: i64,
    /// Modification time nanoseconds component
    pub mtime_nsecs: u32,
    /// Inode change time in seconds since epoch
    pub ctime_secs: i64,
    /// Inode change time nanoseconds component
    pub ctime_nsecs: u32,
    /// Birth time in seconds (if available)
    pub btime_secs: Option<i64>,
}

impl FileCacheKey {
    /// Build a cache key from a file path.
    /// Returns None if the file doesn't exist or metadata can't be read.
    #[must_use]
    pub fn from_path(path: &Path) -> Option<Self> {
        // Canonicalize to resolve symlinks
        let canonical = std::fs::canonicalize(path).ok()?;
        let metadata = std::fs::metadata(&canonical).ok()?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            let inode = metadata.ino();
            let mtime_secs = metadata.mtime();
            let mtime_nsecs = metadata.mtime_nsec() as u32;
            let ctime_secs = metadata.ctime();
            let ctime_nsecs = metadata.ctime_nsec() as u32;

            // Birth time - platform specific
            #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "netbsd"))]
            let btime_secs = {
                // macOS, FreeBSD, and NetBSD support birth time
                metadata.created().ok().and_then(|t| {
                    t.duration_since(SystemTime::UNIX_EPOCH)
                        .ok()
                        .map(|d| d.as_secs() as i64)
                })
            };

            #[cfg(target_os = "linux")]
            let btime_secs = {
                // Linux statx supports birth time on some filesystems
                metadata.created().ok().and_then(|t| {
                    t.duration_since(SystemTime::UNIX_EPOCH)
                        .ok()
                        .map(|d| d.as_secs() as i64)
                })
            };

            #[cfg(not(any(
                target_os = "macos",
                target_os = "freebsd",
                target_os = "netbsd",
                target_os = "linux"
            )))]
            let btime_secs: Option<i64> = None;

            Some(Self {
                path: canonical,
                inode,
                mtime_secs,
                mtime_nsecs,
                ctime_secs,
                ctime_nsecs,
                btime_secs,
            })
        }

        #[cfg(not(unix))]
        {
            let _ = metadata;
            let _ = canonical;
            None
        }
    }
}

/// Cached package information with additional metadata.
#[derive(Debug, Clone)]
struct CacheEntry {
    /// Package info (None if file is not part of any package)
    info: Option<PackageInfo>,
    /// When this entry was created (for future TTL-based eviction)
    #[allow(dead_code)]
    cached_at: Instant,
}

/// Thread-safe package cache with automatic invalidation.
pub struct PackageCache {
    /// Main cache: file identity -> package info
    cache: RwLock<HashMap<FileCacheKey, CacheEntry>>,
    /// Last time we checked the package database modification time
    last_pkg_db_check: RwLock<Instant>,
    /// Cached package database modification time
    pkg_db_mtime: RwLock<Option<SystemTime>>,
}

impl Default for PackageCache {
    fn default() -> Self {
        Self::new()
    }
}

impl PackageCache {
    /// Create a new package cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::with_capacity(1000)),
            last_pkg_db_check: RwLock::new(Instant::now()),
            pkg_db_mtime: RwLock::new(None),
        }
    }

    /// Look up package info for a file path.
    /// Returns cached result if available and valid, otherwise queries the package manager.
    pub fn lookup(&self, path: &Path) -> Option<PackageInfo> {
        // Check if package database has changed (invalidates entire cache)
        if self.should_check_pkg_db() {
            self.check_pkg_db_and_invalidate();
        }

        // Build cache key
        let key = FileCacheKey::from_path(path)?;

        // Try cache first (read lock)
        {
            let cache = self.cache.read().ok()?;
            if let Some(entry) = cache.get(&key) {
                return entry.info.clone();
            }
        }

        // Cache miss - query package manager
        let info = super::package::query_package(&key.path);

        // Insert into cache (write lock)
        self.insert(key, info.clone());

        info
    }

    /// Look up package info and verify if requested.
    /// Verification is cached along with the package info.
    pub fn lookup_and_verify(
        &self,
        path: &Path,
        require_verification: bool,
    ) -> Option<PackageInfo> {
        // Check if package database has changed
        if self.should_check_pkg_db() {
            self.check_pkg_db_and_invalidate();
        }

        let key = FileCacheKey::from_path(path)?;

        // Try cache first
        {
            let cache = self.cache.read().ok()?;
            if let Some(entry) = cache.get(&key) {
                if let Some(ref info) = entry.info {
                    // If verification is required and not yet done, we need to verify
                    if require_verification && info.verified == VerificationStatus::NotChecked {
                        // Fall through to verification
                    } else {
                        return entry.info.clone();
                    }
                } else {
                    return None;
                }
            }
        }

        // Cache miss or verification needed
        let mut info = super::package::query_package(&key.path);

        if let Some(ref mut pkg_info) = info {
            if require_verification && pkg_info.verified == VerificationStatus::NotChecked {
                verify_package(pkg_info);
            }
        }

        self.insert(key, info.clone());
        info
    }

    /// Insert an entry into the cache, evicting old entries if necessary.
    fn insert(&self, key: FileCacheKey, info: Option<PackageInfo>) {
        let mut cache = match self.cache.write() {
            Ok(c) => c,
            Err(_) => return, // Lock poisoned, skip caching
        };

        // Evict if cache is full (simple random eviction)
        if cache.len() >= MAX_CACHE_ENTRIES {
            // Remove ~10% of entries
            let to_remove: Vec<_> = cache.keys().take(MAX_CACHE_ENTRIES / 10).cloned().collect();
            for k in to_remove {
                cache.remove(&k);
            }
        }

        cache.insert(
            key,
            CacheEntry {
                info,
                cached_at: Instant::now(),
            },
        );
    }

    /// Check if we should check the package database for changes.
    fn should_check_pkg_db(&self) -> bool {
        let last_check = match self.last_pkg_db_check.read() {
            Ok(t) => *t,
            Err(_) => return true,
        };
        last_check.elapsed().as_secs() >= PKG_DB_CHECK_INTERVAL_SECS
    }

    /// Check if the package database has changed and invalidate cache if so.
    fn check_pkg_db_and_invalidate(&self) {
        // Update last check time
        if let Ok(mut last) = self.last_pkg_db_check.write() {
            *last = Instant::now();
        }

        let db_paths = package_db_paths();
        let mut current_mtime: Option<SystemTime> = None;

        // Get the most recent modification time of any package database
        for db_path in db_paths {
            if let Ok(meta) = std::fs::metadata(&db_path) {
                if let Ok(mtime) = meta.modified() {
                    current_mtime = Some(match current_mtime {
                        Some(existing) => existing.max(mtime),
                        None => mtime,
                    });
                }
            }
        }

        // Compare with cached mtime
        let should_invalidate = {
            let cached = self.pkg_db_mtime.read().ok();
            match (cached.as_deref(), &current_mtime) {
                (Some(Some(cached_time)), Some(current_time)) => cached_time != current_time,
                (Some(None), Some(_)) => true, // First time seeing a DB
                _ => false,
            }
        };

        // Update cached mtime
        if let Ok(mut cached) = self.pkg_db_mtime.write() {
            *cached = current_mtime;
        }

        // Invalidate cache if database changed
        if should_invalidate {
            tracing::info!("Package database changed, invalidating cache");
            if let Ok(mut cache) = self.cache.write() {
                cache.clear();
            }
        }
    }

    /// Get cache statistics for debugging/monitoring.
    #[must_use]
    pub fn stats(&self) -> CacheStats {
        let entries = self.cache.read().map(|c| c.len()).unwrap_or(0);
        CacheStats {
            entries,
            max_entries: MAX_CACHE_ENTRIES,
        }
    }

    /// Clear the entire cache.
    pub fn clear(&self) {
        if let Ok(mut cache) = self.cache.write() {
            cache.clear();
        }
    }
}

/// Cache statistics for monitoring.
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Current number of entries
    pub entries: usize,
    /// Maximum allowed entries
    pub max_entries: usize,
}

/// Get paths to package database files that should be monitored for changes.
fn package_db_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // RPM database locations (new SQLite and old BDB)
        paths.push(PathBuf::from("/var/lib/rpm/rpmdb.sqlite"));
        paths.push(PathBuf::from("/var/lib/rpm/Packages"));
        paths.push(PathBuf::from("/var/lib/rpm/Packages.db"));

        // Debian/Ubuntu dpkg database
        paths.push(PathBuf::from("/var/lib/dpkg/status"));

        // Arch Linux pacman database
        paths.push(PathBuf::from("/var/lib/pacman/local"));
    }

    #[cfg(target_os = "freebsd")]
    {
        // FreeBSD pkg database
        paths.push(PathBuf::from("/var/db/pkg/local.sqlite"));
    }

    #[cfg(target_os = "netbsd")]
    {
        // NetBSD pkgsrc database
        paths.push(PathBuf::from("/var/db/pkg/pkgdb.byfile.db"));
        paths.push(PathBuf::from("/var/db/pkg"));
    }

    #[cfg(target_os = "macos")]
    {
        // Homebrew Cellar directory - monitor for formula changes
        paths.push(PathBuf::from("/opt/homebrew/Cellar"));
        paths.push(PathBuf::from("/usr/local/Cellar"));
    }

    paths
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_cache_key_from_existing_file() {
        // Use a file that definitely exists
        let key = FileCacheKey::from_path(Path::new("/bin/sh"));

        #[cfg(unix)]
        {
            // On Unix systems /bin/sh should exist
            if Path::new("/bin/sh").exists() {
                assert!(key.is_some());
                let key = key.unwrap();
                assert!(key.inode > 0);
            }
        }
    }

    #[test]
    fn test_cache_key_from_nonexistent_file() {
        let key = FileCacheKey::from_path(Path::new("/nonexistent/path/to/file"));
        assert!(key.is_none());
    }

    #[test]
    fn test_package_cache_new() {
        let cache = PackageCache::new();
        let stats = cache.stats();
        assert_eq!(stats.entries, 0);
        assert_eq!(stats.max_entries, MAX_CACHE_ENTRIES);
    }

    #[test]
    fn test_package_cache_clear() {
        let cache = PackageCache::new();

        // Insert a dummy entry directly
        if let Some(key) = FileCacheKey::from_path(Path::new("/bin/sh")) {
            cache.insert(key, None);
        }

        let stats_before = cache.stats();

        cache.clear();

        let stats_after = cache.stats();
        assert_eq!(stats_after.entries, 0);
        assert!(stats_before.entries >= stats_after.entries);
    }

    #[test]
    fn test_file_cache_key_equality() {
        let key1 = FileCacheKey {
            path: PathBuf::from("/test"),
            inode: 12345,
            mtime_secs: 1000,
            mtime_nsecs: 500,
            ctime_secs: 1000,
            ctime_nsecs: 500,
            btime_secs: Some(900),
        };

        let key2 = FileCacheKey {
            path: PathBuf::from("/test"),
            inode: 12345,
            mtime_secs: 1000,
            mtime_nsecs: 500,
            ctime_secs: 1000,
            ctime_nsecs: 500,
            btime_secs: Some(900),
        };

        let key3 = FileCacheKey {
            path: PathBuf::from("/test"),
            inode: 12345,
            mtime_secs: 1001, // Different mtime
            mtime_nsecs: 500,
            ctime_secs: 1000,
            ctime_nsecs: 500,
            btime_secs: Some(900),
        };

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_file_cache_key_different_inode() {
        let key1 = FileCacheKey {
            path: PathBuf::from("/test"),
            inode: 12345,
            mtime_secs: 1000,
            mtime_nsecs: 0,
            ctime_secs: 1000,
            ctime_nsecs: 0,
            btime_secs: None,
        };

        let key2 = FileCacheKey {
            path: PathBuf::from("/test"),
            inode: 99999, // Different inode (file was replaced)
            mtime_secs: 1000,
            mtime_nsecs: 0,
            ctime_secs: 1000,
            ctime_nsecs: 0,
            btime_secs: None,
        };

        assert_ne!(key1, key2);
    }
}
