use crate::communicative::rpc::bitcoin_rpc::bitcoin_rpc::broadcast_raw_transaction;
use crate::communicative::rpc::bitcoin_rpc::bitcoin_rpc::get_mempool_min_fee_rate;
use crate::communicative::rpc::bitcoin_rpc::bitcoin_rpc_holder::BitcoinRPCHolder;
use crate::executive::exec_ctx::exec_ctx::ExecCtx;
use crate::inscriptive::archival_manager::archival_manager::ARCHIVAL_MANAGER;
use crate::inscriptive::coin_manager::coin_manager::COIN_MANAGER;
use crate::inscriptive::flame_manager::flame_manager::FLAME_MANAGER;
use crate::inscriptive::graveyard::graveyard::GRAVEYARD;
use crate::inscriptive::params_manager::params_manager::PARAMS_MANAGER;
use crate::inscriptive::privileges_manager::privileges_manager::PRIVILEGES_MANAGER;
use crate::inscriptive::registery::registery::REGISTERY;
use crate::inscriptive::state_manager::state_manager::STATE_MANAGER;
use crate::inscriptive::sync_manager::sync_manager::SYNC_MANAGER;
use crate::inscriptive::utxo_set::utxo_set::UTXO_SET;
use crate::operative::tasks::engine_session::session_pool::session_pool::SESSION_POOL;
use crate::transmutative::key::KeyHolder;
use chrono::Utc;
use serde_json::to_string_pretty;
use std::sync::Arc;

/// The waiting window period in seconds.
const WAITING_WINDOW_PERIOD_SECONDS: u64 = 60;

/// How long, after the batch freezes, the engine waits for LiftV2 depositors to
/// submit their MuSig2 key-path partial signatures before giving up on the
/// uncosigned deposits.
const LIFTV2_COSIGN_TIMEOUT_SECONDS: u64 = 30;

/// Poll interval while waiting for LiftV2 cosignatures to arrive.
const LIFTV2_COSIGN_POLL_MS: u64 = 250;

pub async fn engine_batch_builder_background_task(
    session_pool: &SESSION_POOL,
    sync_manager: &SYNC_MANAGER,
    rpc_holder: &BitcoinRPCHolder,
    engine_keyholder: &KeyHolder,
    // Exec ctx params
    engine_key: [u8; 32],
    utxo_set: &UTXO_SET,
    registery: &REGISTERY,
    graveyard: &GRAVEYARD,
    coin_manager: &COIN_MANAGER,
    flame_manager: &FLAME_MANAGER,
    state_manager: &STATE_MANAGER,
    privileges_manager: &PRIVILEGES_MANAGER,
    params_manager: &PARAMS_MANAGER,
    archival_manager: &Option<ARCHIVAL_MANAGER>,
) {
    if archival_manager.is_none() {
        panic!("Archival manager is required for engine batch builder background task.");
    }

    loop {
        //
        // BEGINNING OF THE SESSION.
        //

        // 1 Get the latest batch height.
        let latest_batch_height = {
            let _sync_manager = sync_manager.lock().await;
            _sync_manager.cube_batch_sync_height_tip()
        };

        // 2 Current execution batch height is latest_batch_height plus one.
        let current_execution_batch_height = latest_batch_height + 1;

        // 3 Get current timestamp.
        let current_execution_timestamp = Utc::now().timestamp() as u64 + 60;

        println!(
            "BATCH BUILDER SESSION BEGINNING: height: #{}, timestamp: {}",
            current_execution_batch_height, current_execution_timestamp
        );

        // 4 Retrieve mempool minimum fee rate (sat/vbyte).
        let bitcoin_transaction_feerate = match get_mempool_min_fee_rate(rpc_holder) {
            Ok(feerate) => feerate,
            Err(error) => {
                eprintln!(
                    "Failed to retrieve mempool minimum feerate: {}. Retrying in 5 seconds.",
                    error
                );
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
        };

        println!(
            "Mempool minimum feerate: {} sat/vbyte",
            bitcoin_transaction_feerate
        );

        // 5 Begin the session.
        {
            // 5.1 Lock the session pool.
            let mut _session_pool = session_pool.lock().await;

            // 5.2 Begin the session.
            _session_pool.begin_session(
                current_execution_batch_height,
                current_execution_timestamp,
                bitcoin_transaction_feerate,
            );
        }

        // 6 Wait for the waiting window period.
        tokio::time::sleep(std::time::Duration::from_secs(
            WAITING_WINDOW_PERIOD_SECONDS,
        ))
        .await;

        // 7 Take a break from the session.
        {
            let mut _session_pool = session_pool.lock().await;
            _session_pool.take_a_break_session();
        }

        // 7.5 Collect LiftV2 key-path cosignatures (the trustless deposit Lift Path).
        //
        // The batch is now frozen, so each pending LiftV2 deposit has a stable
        // key-path sighash. We prepare the engine's half of every MuSig2 cosign,
        // then wait for depositors to fetch that material and submit their partial
        // signatures over the LiftupV2Cosign transport. A LiftV2 input cannot be
        // spent into the batch without this account+engine key-path signature, so
        // if a depositor never completes its cosign we abort the batch (its deposit
        // simply retries next session) rather than build a batch with a missing
        // witness.
        {
            // 7.5.1 Is there any LiftV2 deposit awaiting cosign this batch?
            let has_pending_liftv2 = {
                let _session_pool = session_pool.lock().await;
                !_session_pool.pending_liftv2.is_empty()
            };

            if has_pending_liftv2 {
                // 7.5.2 Engine partial-signs each pending deposit (deterministic
                // nonces from the engine secret + the frozen sighash).
                let prepare_result = {
                    let mut _session_pool = session_pool.lock().await;
                    _session_pool
                        .prepare_liftv2_cosigns(engine_keyholder.secp_secret_key_bytes())
                        .await
                };

                if let Err(error) = prepare_result {
                    eprintln!(
                        "Failed to prepare LiftV2 cosigns: {:?} at batch height #{}. Ending session.",
                        error, current_execution_batch_height
                    );
                    let mut _session_pool = session_pool.lock().await;
                    _session_pool.end_session().await;
                    continue;
                }

                // 7.5.3 Wait for depositors to submit their partial signatures.
                let deadline = std::time::Instant::now()
                    + std::time::Duration::from_secs(LIFTV2_COSIGN_TIMEOUT_SECONDS);
                loop {
                    let all_cosigned = {
                        let _session_pool = session_pool.lock().await;
                        _session_pool.all_liftv2_cosigned()
                    };
                    if all_cosigned {
                        break;
                    }
                    if std::time::Instant::now() >= deadline {
                        eprintln!(
                            "LiftV2 cosign window timed out at batch height #{}; aborting batch (uncosigned deposits retry next session).",
                            current_execution_batch_height
                        );
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(LIFTV2_COSIGN_POLL_MS))
                        .await;
                }

                // 7.5.4 If any deposit is still uncosigned, abort this batch.
                let fully_cosigned = {
                    let _session_pool = session_pool.lock().await;
                    _session_pool.all_liftv2_cosigned()
                };
                if !fully_cosigned {
                    let mut _session_pool = session_pool.lock().await;
                    _session_pool.end_session().await;
                    continue;
                }
            }
        }

        // 8 Get the number of entries in the session pool.
        let number_of_entries = {
            let _session_pool = session_pool.lock().await;
            _session_pool.added_entries.len()
        };

        // 8 If the number of entries is zero, end the session and go to the next iteration.
        if number_of_entries == 0 {
            // 8.1 End the session.
            {
                let mut _session_pool = session_pool.lock().await;
                _session_pool.end_session().await;
            }

            // 8.2 Go to the next iteration.
            continue;
        }

        // 9 Get the batch container.
        let batch_container = {
            // 9.1 Try to get the batch container.
            let batch_container_result = {
                let mut _session_pool = session_pool.lock().await;
                _session_pool.into_batch_container(&engine_keyholder).await
            };

            // 9.2 Match the batch container result.
            match batch_container_result {
                Ok(batch_container) => batch_container,
                Err(error) => {
                    eprintln!("Failed to get the batch container during batch builder background task: {:?} at batch height: #{}, timestamp: {}, and bitcoin transaction feerate: {}.", error, current_execution_batch_height, current_execution_timestamp, bitcoin_transaction_feerate);

                    // End the session.
                    {
                        let mut _session_pool = session_pool.lock().await;
                        _session_pool.end_session().await;
                    }

                    continue;
                }
            }
        };

        // 10 End the session pool.
        {
            let mut _session_pool = session_pool.lock().await;
            _session_pool.end_session().await;
        }

        // 11 Broadcast raw transaction.
        {
            // 11.1 Encode the signed batch transaction bytes as a hex string.
            let raw_transaction_hex =
                hex::encode(batch_container.signed_batch_txn.serialize_bytes());

            // 11.2 Broadcast the raw transaction.
            match broadcast_raw_transaction(rpc_holder, &raw_transaction_hex) {
                Ok(_) => (),
                Err(error) => {
                    eprintln!("Failed to broadcast batch transaction: {:?}", error);
                    continue;
                }
            }
        }

        // 12 Construct ExecCtx.
        let exec_ctx = ExecCtx::construct(
            engine_key,
            Arc::clone(sync_manager),
            Arc::clone(utxo_set),
            Arc::clone(registery),
            Arc::clone(graveyard),
            Arc::clone(coin_manager),
            Arc::clone(flame_manager),
            Arc::clone(state_manager),
            Arc::clone(privileges_manager),
            Arc::clone(params_manager),
            archival_manager.clone(),
        );

        // 13 Try to execute the batch container.
        let execute_batch_result = {
            let mut _exec_ctx = exec_ctx.lock().await;
            _exec_ctx.execute_batch(&batch_container).await
        };

        // 14 Match the execute batch result.
        match execute_batch_result {
            Ok(batch_record) => {
                println!(
                    "New batch record: {}",
                    to_string_pretty(&batch_record.json())
                        .expect("serde_json::Value should serialize")
                );
            }
            Err(error) => {
                eprintln!("Failed to execute the batch container during batch builder background task: {:?} at batch height: #{}, timestamp: {}, and bitcoin transaction feerate: {}.", error, current_execution_batch_height, current_execution_timestamp, bitcoin_transaction_feerate);
                continue;
            }
        }

        //
        // END OF THE SESSION.
        //
    }
}
