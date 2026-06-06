use crate::communicative::peer::peer::PEER;
use crate::communicative::tcp::client::{
    LiftupV1ResponseBody, LiftupV2CosignResponseBody, LiftupV2Nonce, LiftupV2RegisterResponseBody,
    TCPClient,
};
use crate::constructive::core_types::target::target::Target;
use crate::constructive::txo::lift::lift_versions::liftv2::cosign::ClientCosigner;
use crate::constructive::{
    entity::account::root_account::root_account::RootAccount,
    entry::entry_kinds::liftup::liftup::Liftup, txo::lift::lift::Lift,
};
use crate::inscriptive::registery::registery::REGISTERY;
use crate::inscriptive::sync_manager::sync_manager::SYNC_MANAGER;
use crate::inscriptive::utxo_set::utxo_set::UTXO_SET;
use crate::transmutative::key::KeyHolder;
use crate::transmutative::secp::into::IntoScalar;
use bitcoin::OutPoint;
use colored::Colorize;
use rand::rngs::OsRng;
use rand::RngCore;
use secp::{Point, Scalar};
use serde_json::to_string_pretty;
use std::collections::HashMap;

/// Polls per LiftV2 deposit for the engine's cosign material (which becomes
/// available once the batch freezes), then submits the depositor's partial sig.
const LIFTV2_COSIGN_FETCH_ATTEMPTS: u32 = 240;
const LIFTV2_COSIGN_FETCH_BACKOFF_MS: u64 = 500;

/// A fresh, single-use, cryptographically-random secret nonce scalar.
fn random_nonce_scalar() -> Scalar {
    let mut rng = OsRng;
    loop {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        if let Ok(scalar) = bytes.into_scalar() {
            return scalar;
        }
    }
}

// liftup
pub async fn liftup_command(
    engine_key: [u8; 32],
    self_account_key: [u8; 32],
    v2_lift_enabled: bool,
    key_holder: &KeyHolder,
    sync_manager: &SYNC_MANAGER,
    utxo_set: &UTXO_SET,
    registery: &REGISTERY,
    engine_peer: &PEER,
) {
    // 1 Scan the UTXO set and collect the self owned lifts.
    let self_owned_lifts: Vec<Lift> = {
        let _utxo_set = utxo_set.lock().await;
        _utxo_set.scan_and_return_self_owned_lifts(&engine_key, &self_account_key, v2_lift_enabled)
    };

    // 2 If there are no self owned lifts, print an error message.
    if self_owned_lifts.is_empty() {
        println!("{}", "No lift UTXOs found to liftup.".red());
        return;
    }

    // 3 Construct the Root Account.
    let root_account = RootAccount::self_root_account_from_registery(key_holder, registery).await;

    // 4 Get the current cube batch height tip from the sync manager.
    let batch_height_tip: u64 = {
        let _sync_manager = sync_manager.lock().await;
        _sync_manager.cube_batch_sync_height_tip()
    };

    // 5 The current execution batch height is the batch height tip plus one.
    let current_execution_batch_height = batch_height_tip + 1;

    // 6 Construct the target.
    let target = Target::new(current_execution_batch_height);

    // 7 Are any of these lifts trustless (LiftV2)? If so, take the cosign path.
    let has_v2 = self_owned_lifts
        .iter()
        .any(|lift| matches!(lift, Lift::LiftV2(_)));

    // 8 Construct the Liftup.
    let liftup = Liftup::new(root_account, target, self_owned_lifts.clone());

    // 9 Get the BLS signature of the Liftup.
    let liftup_bls_signature: [u8; 96] = match liftup.bls_sign(key_holder) {
        Ok(signature) => signature,
        Err(error) => {
            println!("{}", format!("Error BLS signing liftup: {:?}", error).red());
            return;
        }
    };

    // 10 Route trustless lifts through the MuSig2 cosign flow.
    if has_v2 {
        liftup_v2_flow(
            &liftup,
            liftup_bls_signature,
            &self_owned_lifts,
            key_holder,
            engine_peer,
        )
        .await;
        return;
    }

    // 11 Otherwise, the legacy v1 path.
    let (liftup_v1_response_body, duration) = match engine_peer
        .request_liftup_v1(&liftup, liftup_bls_signature)
        .await
    {
        Ok((liftup_v1_response_body, duration)) => (liftup_v1_response_body, duration),
        Err(error) => {
            println!("{}", format!("Error requesting liftup: {:?}", error).red());
            return;
        }
    };

    match liftup_v1_response_body {
        LiftupV1ResponseBody::Ok(success_body) => {
            println!(
                "{}",
                format!(
                    "Liftup entry successfully executed ({} ms): {}",
                    duration.as_millis(),
                    to_string_pretty(&success_body.json())
                        .expect("serde_json::Value should serialize")
                )
                .green()
            );
        }
        LiftupV1ResponseBody::Err(error) => {
            println!(
                "{}",
                format!(
                    "Error executing liftup: {}",
                    to_string_pretty(&error.json()).expect("serde_json::Value should serialize")
                )
                .red()
            );
        }
    }
}

/// The trustless (LiftV2) two-round cosign: register + nonce commit, then fetch
/// the engine's cosign material and submit the depositor's partial signature for
/// each V2 deposit. The engine aggregates account+engine into the key-path
/// witness used to lift the deposit into the batch.
async fn liftup_v2_flow(
    liftup: &Liftup,
    liftup_bls_signature: [u8; 96],
    self_owned_lifts: &[Lift],
    key_holder: &KeyHolder,
    engine_peer: &PEER,
) {
    // 1 Normalize the account secret to the even-Y point used in the deposit keyagg.
    let account_scalar = match key_holder.secp_secret_key_bytes().into_scalar() {
        Ok(s) => s,
        Err(error) => {
            println!("{}", format!("Error loading account secret: {:?}", error).red());
            return;
        }
    };
    let account_secret_even = account_scalar.negate_if(account_scalar.base_point_mul().parity());

    // 2 Build a ClientCosigner (fresh random nonces) per V2 deposit, and collect
    //   the public nonces to commit in round 1.
    let mut cosigners: HashMap<OutPoint, (ClientCosigner, [u8; 32], [u8; 32])> = HashMap::new();
    let mut nonces: Vec<LiftupV2Nonce> = Vec::new();
    for lift in self_owned_lifts.iter() {
        if let Lift::LiftV2(liftv2) = lift {
            let hiding_secret = random_nonce_scalar();
            let binding_secret = random_nonce_scalar();
            let cosigner = ClientCosigner::new(account_secret_even, hiding_secret, binding_secret);
            let (ch, cb) = cosigner.public_nonces();
            nonces.push(LiftupV2Nonce {
                outpoint: liftv2.outpoint,
                client_hiding_nonce: ch.serialize().to_vec(),
                client_binding_nonce: cb.serialize().to_vec(),
            });
            cosigners.insert(
                liftv2.outpoint,
                (cosigner, liftv2.account_key, liftv2.engine_key),
            );
        }
    }

    // 3 Round 1: register the liftup and commit the public nonces.
    let (register_response, duration) = match engine_peer
        .request_liftup_v2_register(liftup, liftup_bls_signature, nonces)
        .await
    {
        Ok(v) => v,
        Err(error) => {
            println!("{}", format!("Error requesting liftup v2 register: {:?}", error).red());
            return;
        }
    };

    match register_response {
        LiftupV2RegisterResponseBody::Ok(success_body) => {
            println!(
                "{}",
                format!(
                    "Liftup v2 registered ({} ms): {}",
                    duration.as_millis(),
                    to_string_pretty(&success_body.json())
                        .expect("serde_json::Value should serialize")
                )
                .green()
            );
        }
        LiftupV2RegisterResponseBody::Err(error) => {
            println!(
                "{}",
                format!(
                    "Error registering liftup v2: {}",
                    to_string_pretty(&error.json()).expect("serde_json::Value should serialize")
                )
                .red()
            );
            return;
        }
    }

    // 4 Round 2: for each deposit, poll for the engine's cosign material, then
    //   partial-sign and submit.
    for (outpoint, (cosigner, account_key, engine_key)) in cosigners.into_iter() {
        let mut submitted = false;

        'poll: for _ in 0..LIFTV2_COSIGN_FETCH_ATTEMPTS {
            let (material_response, _) = match engine_peer
                .request_liftup_v2_cosign_fetch(outpoint)
                .await
            {
                Ok(v) => v,
                Err(error) => {
                    println!("{}", format!("Error fetching cosign material for {outpoint}: {error:?}").red());
                    break 'poll;
                }
            };

            match material_response {
                LiftupV2CosignResponseBody::Material {
                    sighash,
                    engine_hiding_nonce,
                    engine_binding_nonce,
                } => {
                    let eh = match Point::from_slice(&engine_hiding_nonce) {
                        Ok(p) => p,
                        Err(_) => {
                            println!("{}", format!("Invalid engine hiding nonce for {outpoint}").red());
                            break 'poll;
                        }
                    };
                    let eb = match Point::from_slice(&engine_binding_nonce) {
                        Ok(p) => p,
                        Err(_) => {
                            println!("{}", format!("Invalid engine binding nonce for {outpoint}").red());
                            break 'poll;
                        }
                    };

                    let partial = match cosigner.partial_sign(account_key, engine_key, eh, eb, sighash) {
                        Some(s) => s,
                        None => {
                            println!("{}", format!("Failed to partial-sign cosign for {outpoint}").red());
                            break 'poll;
                        }
                    };

                    let (submit_response, _) = match engine_peer
                        .request_liftup_v2_cosign_submit(outpoint, partial.serialize())
                        .await
                    {
                        Ok(v) => v,
                        Err(error) => {
                            println!("{}", format!("Error submitting cosign for {outpoint}: {error:?}").red());
                            break 'poll;
                        }
                    };

                    match submit_response {
                        LiftupV2CosignResponseBody::Submitted => {
                            println!("{}", format!("Cosign submitted for deposit {outpoint}.").green());
                            submitted = true;
                        }
                        other => {
                            println!(
                                "{}",
                                format!(
                                    "Cosign submit rejected for {outpoint}: {}",
                                    to_string_pretty(&other.json()).unwrap_or_default()
                                )
                                .red()
                            );
                        }
                    }
                    break 'poll;
                }
                LiftupV2CosignResponseBody::NotReady => {
                    tokio::time::sleep(std::time::Duration::from_millis(
                        LIFTV2_COSIGN_FETCH_BACKOFF_MS,
                    ))
                    .await;
                    continue 'poll;
                }
                other => {
                    println!(
                        "{}",
                        format!(
                            "Cosign fetch error for {outpoint}: {}",
                            to_string_pretty(&other.json()).unwrap_or_default()
                        )
                        .red()
                    );
                    break 'poll;
                }
            }
        }

        if !submitted {
            println!("{}", format!("Did not complete cosign for deposit {outpoint}.").red());
        }
    }
}
