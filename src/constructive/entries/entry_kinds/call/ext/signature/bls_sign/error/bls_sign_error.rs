use crate::constructive::entries::entry_kinds::call::ext::signature::sighash::error::sighash_error::CallSighashError;

/// Errors associated with BLS-signing a `Call`.
#[derive(Debug, Clone)]
pub enum CallBLSSignError {
    SighashError(CallSighashError),
}
