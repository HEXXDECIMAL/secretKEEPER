//! IPC server and protocol for client communication.

mod handlers;
mod protocol;
mod server;

#[allow(unused_imports)]
pub use protocol::{EventFilter, Request, Response, ViolationEvent};
pub use server::IpcServer;
