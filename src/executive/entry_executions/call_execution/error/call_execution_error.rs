use crate::constructive::entity::account::root_account::registered_and_configured_root_account::ext::sync_with_registery::sync_with_registery_error::RegisteredAndConfiguredRootAccountSyncWithRegisteryError;
use crate::constructive::entity::account::root_account::registered_but_unconfigured_root_account::ext::sync_with_registery::sync_with_registery_error::RegisteredButUnconfiguredRootAccountSyncWithRegisteryError;
use crate::executive::vm::program_execution::exec_error::ExecutionError;
use crate::inscriptive::coin_manager::errors::balance_update_errors::CMAccountBalanceDownError;

/// Errors associated with executing a `Call` entry.
#[derive(Debug, Clone)]
pub enum CallExecutionError {
    UnexpectedUnregisteredRootAccountError,
    RegisteredButUnconfiguredRootAccountValidateBLSKeyError,
    RegisteredButUnconfiguredRootAccountInvalidAuthorizationSignatureError,
    RegisteredButUnconfiguredRootAccountSyncWithRegisteryError(
        RegisteredButUnconfiguredRootAccountSyncWithRegisteryError,
    ),
    RegisteredAndConfiguredRootAccountSyncWithRegisteryError(
        RegisteredAndConfiguredRootAccountSyncWithRegisteryError,
    ),
    CoinManagerAccountBalanceDownError(CMAccountBalanceDownError),
    FailedToApplyFeesSubsidy,
    CallFeeOverflow,
    VMExecutionError(ExecutionError),
}
