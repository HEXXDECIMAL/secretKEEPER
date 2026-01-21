//! SecretKeeper Agent library.

pub mod config;
pub mod error;
pub mod ipc;
pub mod monitor;
pub mod process;
pub mod rules;
pub mod storage;

pub use error::{Error, Result};
