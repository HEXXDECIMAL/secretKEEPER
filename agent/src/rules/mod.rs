//! Rule engine for access control decisions.

pub mod allow_rule;
pub mod engine;
pub mod exception;

pub use allow_rule::{matches_pattern, AllowRule};
pub use engine::{Decision, RuleEngine};
pub use exception::{Exception, SignerType};
