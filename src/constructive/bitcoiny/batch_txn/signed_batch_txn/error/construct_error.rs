use crate::constructive::bitcoiny::batch_txn::unsigned_batch_txn::error::construct_error::UnsignedBatchTxnConstructError;
use crate::constructive::txo::lift::lift_versions::liftv1::liftv1::LiftV1;
use crate::constructive::txo::lift::lift_versions::liftv2::liftv2::LiftV2;

#[derive(Debug, Clone)]
/// Errors associated with constructing a signed batch transaction.
pub enum SignedBatchTxnConstructError {
    PrevProjectorsNotSupportedError,
    PayloadLocationNotFoundError,
    ProjectorLocationNotFoundError,
    UnsignedBatchTxnConstructError(UnsignedBatchTxnConstructError),
    PrevPayloadTaprootSighashConstructionError,
    PrevPayloadTaprootSignError,
    PrevLiftV1TaprootSighashConstructionError(LiftV1),
    PrevLiftV1TaprootSignError(LiftV1),
    LiftV2NotSupportedError(LiftV2),
    /// No account+engine MuSig2 cosignature was provided for this LiftV2 key-path spend.
    LiftV2CosignMissingError(LiftV2),
    /// Could not compute the key-path sighash for this LiftV2 input.
    LiftV2TaprootSighashConstructionError(LiftV2),
    /// The provided cosignature is not a valid key-path spend of this LiftV2 deposit.
    LiftV2CosignInvalidError(LiftV2),
    UnknownLiftNotSupportedError,
    SwapoutPinlessSelfCalculatedScriptpubkeyError,
}
