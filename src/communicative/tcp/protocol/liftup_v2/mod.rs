//! Liftup v2 (trustless, MuSig2-cosigned) TCP: two-round deposit cosign.
//!
//! Round 1 (`LiftupV2RegisterProtocol`): the depositor admits its `Liftup` and
//! commits its public nonces. Round 2 (`LiftupV2CosignProtocol`): once the batch
//! freezes, the depositor fetches the engine's cosign material and submits its
//! partial signature, completing the account+engine key-path witness.

pub mod bodies;
pub mod client;
pub mod server;

pub use bodies::{
    LiftupV2CosignRequestBody, LiftupV2CosignResponseBody, LiftupV2CosignResponseError,
    LiftupV2Nonce, LiftupV2RegisterRequestBody, LiftupV2RegisterResponseBody,
    LiftupV2RegisterResponseError, LiftupV2RegisterSuccessBody,
};
