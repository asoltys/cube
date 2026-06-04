/// Errors associated with executing a `Call` entry in the `SessionPool`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ExecCallInPoolError {
    SessionInactiveError,
    SessionSuspendedError,
    SessionBreakError,
    PoolOverloadedError,
    BatchInfoNotFoundError,
    CallBLSVerifyError(String),
    CallValidateRootAccountError(String),
    CallValidateTargetError {
        targeted_at_batch_height: u64,
        execution_batch_height: u64,
    },
    CallExecutionError(String),
    EntryIdDerivationError,
}
