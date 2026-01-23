//! Rule engine for access control decisions.

pub mod allow_rule;
pub mod engine;
pub mod exception;
pub mod learning;

pub use allow_rule::{matches_pattern, AllowRule};
pub use engine::{Decision, RuleEngine};
pub use exception::{Exception, ExceptionSource, SignerType};
#[allow(unused_imports)]
pub use learning::{LearningController, LearningState, LearningStats};
