//! Call TCP protocol: wire bodies, client send path, server handler.

pub mod bodies;
pub mod client;
pub mod server;

pub use crate::operative::tasks::engine_session::session_pool::error::exec_call_in_pool_error::ExecCallInPoolError;
pub use bodies::{CallRequestBody, CallResponseBody, CallResponseError, CallSuccessBody};
