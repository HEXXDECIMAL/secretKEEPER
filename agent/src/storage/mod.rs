//! Persistent storage for violations and exceptions.

mod sqlite;

pub use sqlite::{Storage, Violation};
