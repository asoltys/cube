//! Engine-side handler for a Liftup v2 cosign request (round 2).
//!
//! `Fetch` returns the engine's cosign material (key-path sighash + engine
//! public nonces) once the batch has frozen, or `NotReady` while the deposit is
//! still in the waiting window. `Submit` aggregates the depositor's partial
//! signature into the account+engine key-path cosignature recorded for the batch.

use crate::communicative::tcp::package::{PackageKind, TCPPackage};
use crate::communicative::tcp::protocol::liftup_v2::bodies::{
    LiftupV2CosignRequestBody, LiftupV2CosignResponseBody, LiftupV2CosignResponseError,
};
use crate::operative::tasks::engine_session::session_pool::session_pool::SESSION_POOL;
use secp::Scalar;

fn package(timestamp: i64, body: LiftupV2CosignResponseBody) -> Option<TCPPackage> {
    let bytes = body.serialize().unwrap_or_default();
    Some(TCPPackage::new(
        PackageKind::LiftupV2CosignProtocol,
        timestamp,
        &bytes,
    ))
}

pub async fn handle_liftup_v2_cosign_request(
    timestamp: i64,
    payload: &[u8],
    session_pool: &SESSION_POOL,
) -> Option<TCPPackage> {
    // 1 Deserialize the request body.
    let request = match LiftupV2CosignRequestBody::deserialize(payload) {
        Some(req) => req,
        None => {
            return package(
                timestamp,
                LiftupV2CosignResponseBody::Err(
                    LiftupV2CosignResponseError::DeserializeRequestError,
                ),
            )
        }
    };

    match request {
        // 2 Fetch: return the engine's cosign material, or NotReady / Unknown.
        LiftupV2CosignRequestBody::Fetch { outpoint } => {
            let _session_pool = session_pool.lock().await;
            if !_session_pool.pending_liftv2.contains_key(&outpoint) {
                return package(
                    timestamp,
                    LiftupV2CosignResponseBody::Err(
                        LiftupV2CosignResponseError::UnknownOutpointError,
                    ),
                );
            }
            match _session_pool.liftv2_cosign_material(&outpoint) {
                Some((sighash, engine_hiding, engine_binding)) => package(
                    timestamp,
                    LiftupV2CosignResponseBody::Material {
                        sighash,
                        engine_hiding_nonce: engine_hiding.serialize().to_vec(),
                        engine_binding_nonce: engine_binding.serialize().to_vec(),
                    },
                ),
                None => package(timestamp, LiftupV2CosignResponseBody::NotReady),
            }
        }

        // 3 Submit: aggregate the depositor's partial signature.
        LiftupV2CosignRequestBody::Submit {
            outpoint,
            client_partial_sig,
        } => {
            let client_partial = match Scalar::from_slice(&client_partial_sig) {
                Ok(s) => s,
                Err(_) => {
                    return package(
                        timestamp,
                        LiftupV2CosignResponseBody::Err(
                            LiftupV2CosignResponseError::InvalidPartialSigError,
                        ),
                    )
                }
            };

            let mut _session_pool = session_pool.lock().await;
            if !_session_pool.pending_liftv2.contains_key(&outpoint) {
                return package(
                    timestamp,
                    LiftupV2CosignResponseBody::Err(
                        LiftupV2CosignResponseError::UnknownOutpointError,
                    ),
                );
            }
            if _session_pool.submit_liftv2_partial_sig(outpoint, client_partial) {
                package(timestamp, LiftupV2CosignResponseBody::Submitted)
            } else {
                package(
                    timestamp,
                    LiftupV2CosignResponseBody::Err(
                        LiftupV2CosignResponseError::InvalidPartialSigError,
                    ),
                )
            }
        }
    }
}
