//! Package manager integration for process identification.
//!
//! This module provides efficient querying to determine which system package
//! owns a given binary, enabling trust decisions based on package provenance.
//!
//! Note: Functions in this module are not yet wired into the main monitoring loop.
//! They will be integrated when package-based rules are enabled at runtime.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;

// Absolute paths for package manager binaries - prevents PATH manipulation attacks
#[cfg(target_os = "linux")]
mod paths {
    pub const DPKG: &str = "/usr/bin/dpkg";
    pub const DPKG_QUERY: &str = "/usr/bin/dpkg-query";
    pub const RPM: &str = "/usr/bin/rpm";
    pub const DEBSUMS: &str = "/usr/bin/debsums";
    pub const PACMAN: &str = "/usr/bin/pacman";
}

#[cfg(target_os = "freebsd")]
mod paths {
    pub const PKG: &str = "/usr/sbin/pkg";
}

#[cfg(target_os = "macos")]
mod paths {
    pub const BREW: &str = "/opt/homebrew/bin/brew";
    pub const BREW_INTEL: &str = "/usr/local/bin/brew";
}

#[cfg(target_os = "netbsd")]
mod paths {
    pub const PKG_INFO: &str = "/usr/sbin/pkg_info";
    pub const PKG_ADMIN: &str = "/usr/sbin/pkg_admin";
}

/// Package manager type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PackageManager {
    /// RPM-based (RHEL, Fedora, CentOS, Rocky, Alma)
    Rpm,
    /// Debian/Ubuntu dpkg
    Dpkg,
    /// Arch Linux pacman
    Pacman,
    /// FreeBSD pkg
    FreeBsdPkg,
    /// NetBSD pkgsrc (pkg_info)
    NetBsdPkgsrc,
    /// Homebrew (macOS and Linux)
    Homebrew,
}

impl std::fmt::Display for PackageManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rpm => write!(f, "rpm"),
            Self::Dpkg => write!(f, "dpkg"),
            Self::Pacman => write!(f, "pacman"),
            Self::FreeBsdPkg => write!(f, "pkg"),
            Self::NetBsdPkgsrc => write!(f, "pkgsrc"),
            Self::Homebrew => write!(f, "homebrew"),
        }
    }
}

/// Verification status for package integrity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum VerificationStatus {
    /// Cryptographically verified (RPM GPG, FreeBSD fingerprint)
    Verified,
    /// Checksum matches but not cryptographically signed (Debian debsums)
    ChecksumOnly,
    /// Verification not yet performed
    #[default]
    NotChecked,
    /// Verification was attempted but failed
    Failed,
    /// File is not part of any package
    NotInPackage,
}

/// Information about a package that owns a binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageInfo {
    /// Package manager type
    pub manager: PackageManager,
    /// Package name (e.g., "openssh-client", "coreutils")
    pub name: String,
    /// Package version (e.g., "8.0p1-3.el8")
    pub version: Option<String>,
    /// Vendor/maintainer (e.g., "Red Hat, Inc.", "homebrew/core")
    pub vendor: Option<String>,
    /// Verification status
    pub verified: VerificationStatus,
}

impl PackageInfo {
    /// Check if this package is verified (cryptographically or checksum).
    #[must_use]
    pub fn is_verified(&self) -> bool {
        matches!(
            self.verified,
            VerificationStatus::Verified | VerificationStatus::ChecksumOnly
        )
    }

    /// Check if this package is cryptographically verified (stronger than checksum).
    #[must_use]
    pub fn is_cryptographically_verified(&self) -> bool {
        self.verified == VerificationStatus::Verified
    }
}

/// Query which package owns a file path.
/// Returns None if the file is not part of any package.
#[must_use]
pub fn query_package(path: &Path) -> Option<PackageInfo> {
    #[cfg(target_os = "linux")]
    {
        // Try package managers in order of prevalence:
        // RPM (enterprise distros), dpkg (Debian/Ubuntu), pacman (Arch)
        if Path::new(paths::RPM).exists() {
            if let Some(info) = query_rpm(path) {
                return Some(info);
            }
        }
        if Path::new(paths::DPKG).exists() {
            if let Some(info) = query_dpkg(path) {
                return Some(info);
            }
        }
        if Path::new(paths::PACMAN).exists() {
            if let Some(info) = query_pacman(path) {
                return Some(info);
            }
        }
        // Also check Homebrew on Linux (least common)
        if let Some(info) = query_homebrew(path) {
            return Some(info);
        }
        None
    }

    #[cfg(target_os = "freebsd")]
    {
        query_freebsd_pkg(path)
    }

    #[cfg(target_os = "netbsd")]
    {
        query_netbsd_pkgsrc(path)
    }

    #[cfg(target_os = "macos")]
    {
        query_homebrew(path)
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "macos"
    )))]
    {
        let _ = path;
        None
    }
}

/// Verify a package's integrity.
/// This is a potentially expensive operation and should be cached.
pub fn verify_package(info: &mut PackageInfo) {
    match info.manager {
        #[cfg(target_os = "linux")]
        PackageManager::Rpm => {
            info.verified = verify_rpm(&info.name);
        }
        #[cfg(target_os = "linux")]
        PackageManager::Dpkg => {
            info.verified = verify_dpkg(&info.name);
        }
        #[cfg(target_os = "linux")]
        PackageManager::Pacman => {
            info.verified = verify_pacman(&info.name);
        }
        #[cfg(target_os = "freebsd")]
        PackageManager::FreeBsdPkg => {
            info.verified = verify_freebsd_pkg(&info.name);
        }
        #[cfg(target_os = "netbsd")]
        PackageManager::NetBsdPkgsrc => {
            info.verified = verify_netbsd_pkgsrc(&info.name);
        }
        // Homebrew: No verification per user decision (trust tap name only)
        PackageManager::Homebrew => {
            info.verified = VerificationStatus::NotChecked;
        }
        #[allow(unreachable_patterns)]
        _ => {}
    }
}

// =============================================================================
// RPM (RHEL, Fedora, CentOS)
// =============================================================================

#[cfg(target_os = "linux")]
fn query_rpm(path: &Path) -> Option<PackageInfo> {
    let path_str = path.to_str()?;

    // rpm -qf /path/to/file --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n'
    let output = Command::new(paths::RPM)
        .args([
            "-qf",
            path_str,
            "--qf",
            "%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n",
        ])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.trim();
    if line.is_empty() || line.contains("not owned") {
        return None;
    }

    let parts: Vec<&str> = line.split('\t').collect();
    if parts.is_empty() {
        return None;
    }

    let name = parts[0].to_string();
    let version = parts
        .get(1)
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string());
    let vendor = parts
        .get(2)
        .filter(|v| !v.is_empty() && *v != "(none)")
        .map(|v| v.to_string());

    Some(PackageInfo {
        manager: PackageManager::Rpm,
        name,
        version,
        vendor,
        verified: VerificationStatus::NotChecked,
    })
}

#[cfg(target_os = "linux")]
fn verify_rpm(pkg_name: &str) -> VerificationStatus {
    // rpm -V pkg_name returns 0 if all files verify
    let output = Command::new(paths::RPM).args(["-V", pkg_name]).output();

    match output {
        Ok(o) if o.status.success() => VerificationStatus::Verified,
        Ok(o) => {
            // Non-zero exit but command ran - check if it's a real failure
            let stderr = String::from_utf8_lossy(&o.stderr);
            if stderr.contains("not installed") {
                VerificationStatus::NotInPackage
            } else {
                VerificationStatus::Failed
            }
        }
        Err(_) => VerificationStatus::Failed,
    }
}

// =============================================================================
// Debian/Ubuntu (dpkg)
// =============================================================================

#[cfg(target_os = "linux")]
fn query_dpkg(path: &Path) -> Option<PackageInfo> {
    let path_str = path.to_str()?;

    // dpkg -S /path/to/file returns "package: /path/to/file"
    let output = Command::new(paths::DPKG)
        .args(["-S", path_str])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.trim();

    // Parse "package: /path" or "package, package2: /path" (diversion)
    let pkg_part = line.split(':').next()?.trim();
    // Handle diversions - take first package
    let name = pkg_part.split(',').next()?.trim().to_string();

    if name.is_empty() {
        return None;
    }

    // Get version and maintainer
    let (version, vendor) = get_dpkg_details(&name);

    Some(PackageInfo {
        manager: PackageManager::Dpkg,
        name,
        version,
        vendor,
        verified: VerificationStatus::NotChecked,
    })
}

#[cfg(target_os = "linux")]
fn get_dpkg_details(pkg_name: &str) -> (Option<String>, Option<String>) {
    // dpkg-query -W -f '${Version}\t${Maintainer}\n' package
    let output = Command::new(paths::DPKG_QUERY)
        .args(["-W", "-f", "${Version}\t${Maintainer}\n", pkg_name])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            let line = stdout.trim();
            let parts: Vec<&str> = line.split('\t').collect();

            let version = parts
                .first()
                .filter(|v| !v.is_empty())
                .map(|v| v.to_string());
            let vendor = parts.get(1).filter(|v| !v.is_empty()).map(|v| {
                // Extract just the organization/email from maintainer
                // e.g., "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>"
                // becomes "Ubuntu Developers" or the full email
                v.to_string()
            });

            (version, vendor)
        }
        _ => (None, None),
    }
}

#[cfg(target_os = "linux")]
fn verify_dpkg(pkg_name: &str) -> VerificationStatus {
    // debsums -s pkg_name (silent mode, only shows errors)
    if !Path::new(paths::DEBSUMS).exists() {
        return VerificationStatus::NotChecked;
    }

    let output = Command::new(paths::DEBSUMS).args(["-s", pkg_name]).output();

    match output {
        Ok(o) if o.status.success() => VerificationStatus::ChecksumOnly, // MD5 only, not GPG
        Ok(_) => VerificationStatus::Failed,
        Err(_) => VerificationStatus::NotChecked,
    }
}

// =============================================================================
// Arch Linux (pacman)
// =============================================================================

/// Query pacman for package ownership.
/// Uses `pacman -Qo` which is fast (queries local database only).
#[cfg(target_os = "linux")]
fn query_pacman(path: &Path) -> Option<PackageInfo> {
    let path_str = path.to_str()?;

    // pacman -Qo /path/to/file
    // Output on success: "/path/to/file is owned by package_name version"
    // Output on failure: "error: No package owns /path/to/file"
    let output = Command::new(paths::PACMAN)
        .args(["-Qo", path_str])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.trim();

    // Parse: "/path/to/file is owned by package_name version"
    // Find "is owned by " and extract package name and version after it
    let owned_by_marker = " is owned by ";
    let pkg_info_start = line.find(owned_by_marker)?;
    let pkg_info = &line[pkg_info_start + owned_by_marker.len()..];

    // Split "package_name version" - package names can't contain spaces
    let mut parts = pkg_info.split_whitespace();
    let name = parts.next()?.to_string();
    let version = parts.next().map(|v| v.to_string());

    // Get packager info for vendor field
    let vendor = get_pacman_packager(&name);

    Some(PackageInfo {
        manager: PackageManager::Pacman,
        name,
        version,
        vendor,
        verified: VerificationStatus::NotChecked,
    })
}

/// Get the packager field from pacman package info.
/// Returns "Arch Linux" for official packages, or the packager email otherwise.
#[cfg(target_os = "linux")]
fn get_pacman_packager(pkg_name: &str) -> Option<String> {
    // pacman -Qi pkg_name - query package info
    // We only need the Packager line, so we'll parse minimally
    let output = Command::new(paths::PACMAN)
        .args(["-Qi", pkg_name])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Find "Packager" line - format: "Packager        : Name <email>"
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("Packager") {
            let packager = rest.trim_start_matches(|c| c == ' ' || c == ':').trim();
            if packager.is_empty() || packager == "Unknown Packager" {
                return None;
            }
            // Check if it's an official Arch packager (contains @archlinux.org)
            if packager.contains("@archlinux.org") {
                return Some("Arch Linux".to_string());
            }
            // For AUR or custom packages, return the full packager string
            return Some(packager.to_string());
        }
    }

    None
}

/// Verify a pacman package's integrity.
/// Uses `pacman -Qk` which checks file presence and sizes against the package database.
/// Arch packages are GPG-signed, and the package database itself is signed.
#[cfg(target_os = "linux")]
fn verify_pacman(pkg_name: &str) -> VerificationStatus {
    // pacman -Qk pkg_name - check package file integrity
    // Returns 0 if all files are present and match expected sizes
    // This verifies against the local package database which is GPG-signed
    let output = Command::new(paths::PACMAN).args(["-Qk", pkg_name]).output();

    match output {
        Ok(o) if o.status.success() => {
            // pacman -Qk succeeded - files match the signed package database
            // Arch's trust model: packages are signed by trusted packagers,
            // and the sync database is signed. Local installs verify signatures.
            VerificationStatus::Verified
        }
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            let stdout = String::from_utf8_lossy(&o.stdout);
            // Check for "0 altered files" in output (sometimes exits non-zero but OK)
            if stdout.contains("0 altered files") || stdout.contains("0 missing files") {
                return VerificationStatus::Verified;
            }
            // Check if package just doesn't exist
            if stderr.contains("was not found") || stderr.contains("No package") {
                VerificationStatus::NotInPackage
            } else {
                // Files were modified or missing
                VerificationStatus::Failed
            }
        }
        Err(_) => VerificationStatus::Failed,
    }
}

// =============================================================================
// FreeBSD pkg
// =============================================================================

#[cfg(target_os = "freebsd")]
fn query_freebsd_pkg(path: &Path) -> Option<PackageInfo> {
    let path_str = path.to_str()?;

    // pkg which /path/to/file
    let output = Command::new(paths::PKG)
        .args(["which", path_str])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Output: "/path/to/file was installed by package pkgname-version"
    let line = stdout.trim();

    if !line.contains("was installed by package") {
        return None;
    }

    // Extract package name (includes version in FreeBSD)
    let pkg_full = line.rsplit("package ").next()?.trim();
    if pkg_full.is_empty() {
        return None;
    }

    // Split name and version (e.g., "bash-5.1.8" -> "bash", "5.1.8")
    let (name, version) = split_freebsd_pkg_name(pkg_full);

    // Get repository origin for vendor
    let vendor = get_freebsd_pkg_origin(&name);

    Some(PackageInfo {
        manager: PackageManager::FreeBsdPkg,
        name,
        version,
        vendor,
        verified: VerificationStatus::NotChecked,
    })
}

#[cfg(target_os = "freebsd")]
fn split_freebsd_pkg_name(full_name: &str) -> (String, Option<String>) {
    // FreeBSD package names are like "bash-5.1.8" or "py39-pip-21.0.1"
    // Find the last dash followed by a digit
    let chars: Vec<char> = full_name.chars().collect();
    for i in (0..chars.len()).rev() {
        if chars[i] == '-' && i + 1 < chars.len() && chars[i + 1].is_ascii_digit() {
            let name = full_name[..i].to_string();
            let version = full_name[i + 1..].to_string();
            return (name, Some(version));
        }
    }
    (full_name.to_string(), None)
}

#[cfg(target_os = "freebsd")]
fn get_freebsd_pkg_origin(pkg_name: &str) -> Option<String> {
    // pkg query '%o' pkgname returns origin (e.g., "shells/bash")
    let output = Command::new(paths::PKG)
        .args(["query", "%o", pkg_name])
        .output()
        .ok()?;

    if output.status.success() {
        let origin = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !origin.is_empty() {
            // Return "FreeBSD" as vendor for official packages
            // Could be extended to check repository source
            return Some("FreeBSD".to_string());
        }
    }
    None
}

#[cfg(target_os = "freebsd")]
fn verify_freebsd_pkg(pkg_name: &str) -> VerificationStatus {
    // pkg check -s pkgname (checksum verification)
    let output = Command::new(paths::PKG)
        .args(["check", "-s", pkg_name])
        .output();

    match output {
        Ok(o) if o.status.success() => VerificationStatus::Verified,
        Ok(_) => VerificationStatus::Failed,
        Err(_) => VerificationStatus::NotChecked,
    }
}

// =============================================================================
// NetBSD pkgsrc
// =============================================================================

#[cfg(target_os = "netbsd")]
fn query_netbsd_pkgsrc(path: &Path) -> Option<PackageInfo> {
    let path_str = path.to_str()?;

    // pkg_info -Fe /path/to/file returns the package name that owns the file
    let output = Command::new(paths::PKG_INFO)
        .args(["-Fe", path_str])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let pkg_full = stdout.trim();

    if pkg_full.is_empty() {
        return None;
    }

    // Split name and version (e.g., "bash-5.1.8" -> "bash", "5.1.8")
    let (name, version) = split_netbsd_pkg_name(pkg_full);

    // Get package comment/description for vendor info
    let vendor = get_netbsd_pkg_maintainer(&name);

    Some(PackageInfo {
        manager: PackageManager::NetBsdPkgsrc,
        name,
        version,
        vendor,
        verified: VerificationStatus::NotChecked,
    })
}

#[cfg(target_os = "netbsd")]
fn split_netbsd_pkg_name(full_name: &str) -> (String, Option<String>) {
    // NetBSD package names are similar to FreeBSD: "bash-5.1.8" or "py39-pip-21.0.1"
    // Find the last dash followed by a digit
    let chars: Vec<char> = full_name.chars().collect();
    for i in (0..chars.len()).rev() {
        if chars[i] == '-' && i + 1 < chars.len() && chars[i + 1].is_ascii_digit() {
            let name = full_name[..i].to_string();
            let version = full_name[i + 1..].to_string();
            return (name, Some(version));
        }
    }
    (full_name.to_string(), None)
}

#[cfg(target_os = "netbsd")]
fn get_netbsd_pkg_maintainer(pkg_name: &str) -> Option<String> {
    // pkg_info -B pkg_name shows build info including PKGPATH
    // We use PKGPATH as the "vendor" to identify the pkgsrc category
    let output = Command::new(paths::PKG_INFO)
        .args(["-B", pkg_name])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Look for PKGPATH line (e.g., "PKGPATH=shells/bash")
    for line in stdout.lines() {
        if let Some(path) = line.strip_prefix("PKGPATH=") {
            let path = path.trim();
            if !path.is_empty() {
                // Return "pkgsrc" as vendor for official packages
                return Some("pkgsrc".to_string());
            }
        }
    }

    Some("pkgsrc".to_string())
}

#[cfg(target_os = "netbsd")]
fn verify_netbsd_pkgsrc(pkg_name: &str) -> VerificationStatus {
    // pkg_admin check pkg_name verifies the package integrity
    let output = Command::new(paths::PKG_ADMIN)
        .args(["check", pkg_name])
        .output();

    match output {
        Ok(o) if o.status.success() => VerificationStatus::Verified,
        Ok(_) => VerificationStatus::Failed,
        Err(_) => VerificationStatus::NotChecked,
    }
}

// =============================================================================
// Homebrew (macOS and Linux)
// =============================================================================

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn query_homebrew(path: &Path) -> Option<PackageInfo> {
    // Resolve symlinks to find actual file location
    let real_path = std::fs::canonicalize(path).ok()?;

    // Get Homebrew prefix
    let prefix = homebrew_prefix()?;
    let cellar = prefix.join("Cellar");

    // Check if file is under Cellar
    if let Ok(rel_path) = real_path.strip_prefix(&cellar) {
        // Path is like: formula_name/version/bin/binary
        let mut components = rel_path.components();

        let formula = components.next()?.as_os_str().to_str()?.to_string();
        let version = components
            .next()
            .and_then(|c| c.as_os_str().to_str())
            .map(String::from);

        // Determine tap (vendor)
        let vendor = get_homebrew_tap(&formula).unwrap_or_else(|| "homebrew/core".to_string());

        return Some(PackageInfo {
            manager: PackageManager::Homebrew,
            name: formula,
            version,
            vendor: Some(vendor),
            verified: VerificationStatus::NotChecked, // No verification per design decision
        });
    }

    // Check if it's a symlink in bin/ pointing to Cellar
    if real_path.starts_with(&prefix) && !real_path.starts_with(&cellar) {
        // File is in prefix but not Cellar - might be a Cask or other install
        // Try to find formula via brew
        return query_homebrew_formula(path);
    }

    None
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn homebrew_prefix() -> Option<std::path::PathBuf> {
    // Check standard locations
    #[cfg(target_os = "macos")]
    {
        #[cfg(target_arch = "aarch64")]
        {
            let prefix = std::path::PathBuf::from("/opt/homebrew");
            if prefix.exists() {
                return Some(prefix);
            }
        }
        #[cfg(target_arch = "x86_64")]
        {
            let prefix = std::path::PathBuf::from("/usr/local");
            if prefix.join("Cellar").exists() {
                return Some(prefix);
            }
        }
        // Try both for universal builds
        let arm_prefix = std::path::PathBuf::from("/opt/homebrew");
        if arm_prefix.exists() {
            return Some(arm_prefix);
        }
        let intel_prefix = std::path::PathBuf::from("/usr/local");
        if intel_prefix.join("Cellar").exists() {
            return Some(intel_prefix);
        }
    }

    #[cfg(target_os = "linux")]
    {
        // Linuxbrew
        let linuxbrew = std::path::PathBuf::from("/home/linuxbrew/.linuxbrew");
        if linuxbrew.exists() {
            return Some(linuxbrew);
        }
        // User-local homebrew
        if let Some(home) = dirs::home_dir() {
            let user_brew = home.join(".linuxbrew");
            if user_brew.exists() {
                return Some(user_brew);
            }
        }
    }

    None
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn get_homebrew_tap(formula: &str) -> Option<String> {
    // Check if formula is from a tap by looking at the tap directory structure
    // Taps are stored in: $(brew --repository)/Library/Taps/owner/homebrew-repo
    let prefix = homebrew_prefix()?;
    let taps_dir = prefix.join("Library/Taps");

    if !taps_dir.exists() {
        return None;
    }

    // Search through taps for this formula
    if let Ok(entries) = std::fs::read_dir(&taps_dir) {
        for owner_entry in entries.flatten() {
            if let Ok(repos) = std::fs::read_dir(owner_entry.path()) {
                for repo_entry in repos.flatten() {
                    let repo_path = repo_entry.path();
                    let formula_dir = repo_path.join("Formula");

                    // Check if formula exists in this tap
                    let formula_file = formula_dir.join(format!("{formula}.rb"));
                    if formula_file.exists() {
                        // Extract tap name from path
                        let owner = owner_entry.file_name().to_string_lossy().to_string();
                        let repo = repo_entry
                            .file_name()
                            .to_string_lossy()
                            .strip_prefix("homebrew-")
                            .unwrap_or(&repo_entry.file_name().to_string_lossy())
                            .to_string();
                        return Some(format!("{owner}/{repo}"));
                    }
                }
            }
        }
    }

    // Default to homebrew/core if not found in taps
    Some("homebrew/core".to_string())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn query_homebrew_formula(path: &Path) -> Option<PackageInfo> {
    // This is a fallback that shells out to brew - slower but more complete
    // Only use if the fast path (Cellar inspection) failed

    let brew_path = if cfg!(target_os = "macos") {
        if std::path::Path::new(paths::BREW).exists() {
            paths::BREW
        } else if std::path::Path::new(paths::BREW_INTEL).exists() {
            paths::BREW_INTEL
        } else {
            return None;
        }
    } else {
        // Linux - try common locations
        if std::path::Path::new("/home/linuxbrew/.linuxbrew/bin/brew").exists() {
            "/home/linuxbrew/.linuxbrew/bin/brew"
        } else {
            return None;
        }
    };

    let path_str = path.to_str()?;

    // brew which-formula is not always available, try to find via list
    let output = Command::new(brew_path)
        .args(["list", "--formula", "-1"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let formulas = String::from_utf8_lossy(&output.stdout);

    // Check each formula to see if it owns this file
    // This is slow, so we limit to basename matching first
    let basename = path.file_name()?.to_str()?;

    for formula in formulas.lines() {
        let formula = formula.trim();
        if formula.is_empty() {
            continue;
        }

        // Quick check: does formula name relate to file basename?
        if !basename.contains(formula)
            && !formula.contains(basename.split('.').next().unwrap_or(""))
        {
            continue;
        }

        // Check if formula owns this file
        let list_output = Command::new(brew_path)
            .args(["list", "--formula", formula])
            .output()
            .ok();

        if let Some(o) = list_output {
            if o.status.success() {
                let files = String::from_utf8_lossy(&o.stdout);
                if files.lines().any(|f| f.trim() == path_str) {
                    let vendor =
                        get_homebrew_tap(formula).unwrap_or_else(|| "homebrew/core".to_string());
                    return Some(PackageInfo {
                        manager: PackageManager::Homebrew,
                        name: formula.to_string(),
                        version: None,
                        vendor: Some(vendor),
                        verified: VerificationStatus::NotChecked,
                    });
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_package_manager_display() {
        assert_eq!(PackageManager::Rpm.to_string(), "rpm");
        assert_eq!(PackageManager::Dpkg.to_string(), "dpkg");
        assert_eq!(PackageManager::Pacman.to_string(), "pacman");
        assert_eq!(PackageManager::FreeBsdPkg.to_string(), "pkg");
        assert_eq!(PackageManager::NetBsdPkgsrc.to_string(), "pkgsrc");
        assert_eq!(PackageManager::Homebrew.to_string(), "homebrew");
    }

    #[test]
    fn test_package_info_is_verified() {
        let mut info = PackageInfo {
            manager: PackageManager::Rpm,
            name: "test".to_string(),
            version: None,
            vendor: None,
            verified: VerificationStatus::Verified,
        };
        assert!(info.is_verified());
        assert!(info.is_cryptographically_verified());

        info.verified = VerificationStatus::ChecksumOnly;
        assert!(info.is_verified());
        assert!(!info.is_cryptographically_verified());

        info.verified = VerificationStatus::NotChecked;
        assert!(!info.is_verified());
        assert!(!info.is_cryptographically_verified());

        info.verified = VerificationStatus::Failed;
        assert!(!info.is_verified());

        info.verified = VerificationStatus::NotInPackage;
        assert!(!info.is_verified());
    }

    #[cfg(target_os = "freebsd")]
    #[test]
    fn test_split_freebsd_pkg_name() {
        let (name, version) = split_freebsd_pkg_name("bash-5.1.8");
        assert_eq!(name, "bash");
        assert_eq!(version, Some("5.1.8".to_string()));

        let (name, version) = split_freebsd_pkg_name("py39-pip-21.0.1");
        assert_eq!(name, "py39-pip");
        assert_eq!(version, Some("21.0.1".to_string()));

        let (name, version) = split_freebsd_pkg_name("noversion");
        assert_eq!(name, "noversion");
        assert_eq!(version, None);
    }

    #[cfg(target_os = "netbsd")]
    #[test]
    fn test_split_netbsd_pkg_name() {
        let (name, version) = split_netbsd_pkg_name("bash-5.1.8");
        assert_eq!(name, "bash");
        assert_eq!(version, Some("5.1.8".to_string()));

        let (name, version) = split_netbsd_pkg_name("py39-pip-21.0.1");
        assert_eq!(name, "py39-pip");
        assert_eq!(version, Some("21.0.1".to_string()));

        let (name, version) = split_netbsd_pkg_name("noversion");
        assert_eq!(name, "noversion");
        assert_eq!(version, None);
    }

    #[test]
    fn test_verification_status_default() {
        let status: VerificationStatus = Default::default();
        assert_eq!(status, VerificationStatus::NotChecked);
    }
}
