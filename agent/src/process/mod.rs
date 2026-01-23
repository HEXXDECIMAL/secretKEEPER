//! Process information and tree building.

pub mod context;
pub mod package;
pub mod package_cache;
pub mod tree;

pub use context::{get_home_for_uid, ProcessContext};
// Package-based identification (re-export types used in ProcessContext and AllowRule)
// These are used by ProcessContext.package field and AllowRule matching, but the
// runtime integration is not yet complete.
#[allow(unused_imports)]
pub use package::{PackageInfo, PackageManager, VerificationStatus};
pub use tree::{build_process_tree, is_process_stopped, ProcessTreeEntry};
