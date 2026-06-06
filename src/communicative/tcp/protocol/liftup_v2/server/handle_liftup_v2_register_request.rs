//! Engine-side handler for a Liftup v2 register request (round 1).
//!
//! Admits the depositor's `Liftup` (carrying one or more trustless `LiftV2`
//! inputs) into the session pool and records, per V2 outpoint, the depositor's
//! committed public MuSig2 nonces so the key-path cosign can be completed in
//! round 2 once the batch freezes.

use std::collections::HashMap;
use std::time::Duration;

use crate::communicative::tcp::package::{PackageKind, TCPPackage};
use crate::communicative::tcp::protocol::liftup_v2::bodies::{
    LiftupV2RegisterRequestBody, LiftupV2RegisterResponseBody, LiftupV2RegisterResponseError,
};
use crate::constructive::txo::lift::lift::Lift;
use crate::operative::tasks::engine_session::session_pool::error::exec_liftup_in_pool_error::ExecLiftupInPoolError;
use crate::operative::tasks::engine_session::session_pool::session_pool::SESSION_POOL;
use secp::Point;
use tokio::time::sleep;

/// Backoff when the session is not ready yet; lock is dropped before sleeping.
const SESSION_SETTLE_MS: u64 = 500;

/// Total `exec_liftup_in_pool` attempts on session-settle errors.
const MAX_EXEC_ATTEMPTS: u32 = 4;

fn err_package(timestamp: i64, e: LiftupV2RegisterResponseError) -> Option<TCPPackage> {
    let bytes = LiftupV2RegisterResponseBody::err(e)
        .serialize()
        .unwrap_or_default();
    Some(TCPPackage::new(
        PackageKind::LiftupV2RegisterProtocol,
        timestamp,
        &bytes,
    ))
}

pub async fn handle_liftup_v2_register_request(
    timestamp: i64,
    payload: &[u8],
    session_pool: &SESSION_POOL,
) -> Option<TCPPackage> {
    // 1 Deserialize the request body.
    let LiftupV2RegisterRequestBody {
        liftup,
        liftup_bls_signature,
        nonces,
    } = match LiftupV2RegisterRequestBody::deserialize(payload) {
        Some(req) => req,
        None => {
            return err_package(timestamp, LiftupV2RegisterResponseError::DeserializeRequestError)
        }
    };

    // 2 Index the committed nonces by outpoint and decode them to secp points.
    let mut nonce_by_outpoint: HashMap<bitcoin::OutPoint, (Point, Point)> = HashMap::new();
    for n in nonces.iter() {
        let hiding = match Point::from_slice(&n.client_hiding_nonce) {
            Ok(p) => p,
            Err(_) => return err_package(timestamp, LiftupV2RegisterResponseError::InvalidNonceError),
        };
        let binding = match Point::from_slice(&n.client_binding_nonce) {
            Ok(p) => p,
            Err(_) => return err_package(timestamp, LiftupV2RegisterResponseError::InvalidNonceError),
        };
        nonce_by_outpoint.insert(n.outpoint, (hiding, binding));
    }

    // 3 Collect the LiftV2 inputs and ensure each has a committed nonce pair.
    let mut v2_inputs: Vec<(bitcoin::OutPoint, [u8; 32], [u8; 32], Point, Point)> = Vec::new();
    for lift in liftup.lift_tx_inputs.iter() {
        if let Lift::LiftV2(liftv2) = lift {
            match nonce_by_outpoint.get(&liftv2.outpoint) {
                Some((hiding, binding)) => v2_inputs.push((
                    liftv2.outpoint,
                    liftv2.account_key,
                    liftv2.engine_key,
                    *hiding,
                    *binding,
                )),
                None => {
                    return err_package(timestamp, LiftupV2RegisterResponseError::MissingNonceError)
                }
            }
        }
    }
    if v2_inputs.is_empty() {
        // A v2 register with no trustless inputs is malformed (use liftup v1).
        return err_package(timestamp, LiftupV2RegisterResponseError::MissingNonceError);
    }

    // 4 Admit the liftup into the session pool (retry on session-settle errors).
    let mut admit: Option<Result<([u8; 32], crate::constructive::entry::entry::entry::Entry, u64, u64), ExecLiftupInPoolError>> = None;
    for attempt in 1..=MAX_EXEC_ATTEMPTS {
        let attempt_result = {
            let mut _session_pool = session_pool.lock().await;
            _session_pool
                .exec_liftup_in_pool(&liftup, liftup_bls_signature)
                .await
        };

        match attempt_result {
            Ok(v) => {
                admit = Some(Ok(v));
                break;
            }
            Err(err) => {
                let retry_after_settle = matches!(
                    err,
                    ExecLiftupInPoolError::SessionInactiveError
                        | ExecLiftupInPoolError::SessionBreakError
                );
                if retry_after_settle && attempt < MAX_EXEC_ATTEMPTS {
                    sleep(Duration::from_millis(SESSION_SETTLE_MS)).await;
                    continue;
                }
                admit = Some(Err(err));
                break;
            }
        }
    }

    let (entry_id, entry, batch_height, batch_timestamp) = match admit.expect("loop sets admit") {
        Ok(v) => v,
        Err(err) => {
            return err_package(
                timestamp,
                LiftupV2RegisterResponseError::ExecLiftupInPoolError(err),
            )
        }
    };

    // 5 Register the depositor's committed nonces for each V2 input (round 1 of
    //   the key-path cosign).
    {
        let mut _session_pool = session_pool.lock().await;
        for (outpoint, account_key, engine_key, hiding, binding) in v2_inputs.into_iter() {
            _session_pool.register_liftv2_nonces(outpoint, account_key, engine_key, hiding, binding);
        }
    }

    // 6 Respond with the admitted entry.
    let body =
        LiftupV2RegisterResponseBody::ok(entry_id, batch_height, batch_timestamp, entry);
    let bytes = body.serialize().unwrap_or_default();
    Some(TCPPackage::new(
        PackageKind::LiftupV2RegisterProtocol,
        timestamp,
        &bytes,
    ))
}
