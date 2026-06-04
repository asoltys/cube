use crate::constructive::entries::entry_kinds::call::ext::signature::sighash::error::sighash_error::CallSighashError;

/// Errors associated with verifying a BLS signature over a `Call`.
#[derive(Debug, Clone)]
pub enum CallBLSVerifyError {
    SighashError(CallSighashError),
    InvalidBLSSignatureError,
}
