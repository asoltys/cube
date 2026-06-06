// Drives the LiftV2 trustless-deposit TCP transport through its REAL server
// handlers (the same functions the connection dispatcher calls), with real
// serialized wire bodies, end to end in-process:
//
//   R1  -> handle_liftup_v2_register_request(register body)  // admit + commit nonces
//   freeze -> prepare_liftv2_cosigns(engine_secret)          // engine loop step
//   R2a -> handle_liftup_v2_cosign_request(Fetch)            // engine cosign material
//   R2b -> handle_liftup_v2_cosign_request(Submit partial)   // aggregate cosig
//   -> into_batch_container                                   // build with cosigned input
//
// This validates the wire payloads + handler logic; the only surface it doesn't
// touch is the OS socket framing, which is byte-identical to the working liftup
// v1 path. It also asserts the Fetch handler returns NotReady before freeze and
// rejects an unknown outpoint.

#[cfg(test)]
mod liftv2_transport_handlers {
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, OutPoint, ScriptBuf, TxOut, Txid};

    use cube::communicative::tcp::protocol::liftup_v2::bodies::{
        LiftupV2CosignRequestBody, LiftupV2CosignResponseBody, LiftupV2Nonce,
        LiftupV2RegisterRequestBody, LiftupV2RegisterResponseBody,
    };
    use cube::communicative::tcp::protocol::liftup_v2::server::{
        handle_liftup_v2_cosign_request, handle_liftup_v2_register_request,
    };
    use cube::constructive::bitcoiny::batch_container::batch_container::BatchContainer;
    use cube::constructive::core_types::entities::account::root_account::root_account::RootAccount;
    use cube::constructive::core_types::target::target::Target;
    use cube::constructive::entries::entry_kinds::liftup::liftup::Liftup;
    use cube::constructive::txo::lift::lift::Lift;
    use cube::constructive::txo::lift::lift_versions::liftv2::cosign::ClientCosigner;
    use cube::constructive::txo::lift::lift_versions::liftv2::liftv2::return_liftv2_scriptpubkey;
    use cube::inscriptive::archival_manager::archival_manager::{
        erase_archival_manager, ArchivalManager, ARCHIVAL_MANAGER,
    };
    use cube::inscriptive::coin_manager::coin_manager::{erase_coin_manager, CoinManager, COIN_MANAGER};
    use cube::inscriptive::flame_manager::flame_manager::{erase_flame_manager, FlameManager, FLAME_MANAGER};
    use cube::inscriptive::graveyard::graveyard::{erase_graveyard, Graveyard, GRAVEYARD};
    use cube::inscriptive::params_manager::params_manager::{erase_params_manager, ParamsManager, PARAMS_MANAGER};
    use cube::inscriptive::privileges_manager::privileges_manager::{erase_privileges_manager, PrivilegesManager, PRIVILEGES_MANAGER};
    use cube::inscriptive::registery::registery::{erase_registery, Registery, REGISTERY};
    use cube::inscriptive::state_manager::state_manager::{erase_state_manager, StateManager, STATE_MANAGER};
    use cube::inscriptive::sync_manager::sync_manager::{erase_sync_manager, SyncManager, SYNC_MANAGER};
    use cube::inscriptive::utxo_set::utxo_set::{erase_utxo_set, UTXOSet, UTXO_SET};
    use cube::operative::run_args::chain::Chain;
    use cube::operative::tasks::engine_session::session_pool::session_pool::{SessionPool, SESSION_POOL};
    use cube::transmutative::key::KeyHolder;
    use secp::{Point, Scalar};
    use std::sync::Arc;

    const ACCOUNT_SK: &str = "1cc5906ab936b1e29db24fffe9f87b33a4c64f2d3b59aed6c3c4faeb8fcba6da";
    const ENGINE_SK: &str = "4882eef979baa5c88fd9e62c698de201f0a991af65877becf683e988f3024b0f";
    const A_HN_SK: &str = "e2d64e2bd20d5843d03a47199f059aebdf2a9904616a01fe961ee875a7748199";
    const A_BN_SK: &str = "4b978d3aac4135213f536194522f68fbb2ca4321a49d95560ae9726cd9d6a55d";

    fn sk(h: &str) -> [u8; 32] {
        hex::decode(h).unwrap().try_into().unwrap()
    }

    #[tokio::test]
    async fn transport_handlers_lift_in_a_v2_deposit() {
        let chain = Chain::Testbed;
        let feerate = 1u64;

        erase_sync_manager(chain);
        let sync_manager: SYNC_MANAGER = SyncManager::new(chain).expect("sync");
        erase_utxo_set(chain);
        let utxo_set: UTXO_SET = UTXOSet::new(chain).expect("utxo");
        erase_registery(chain);
        let registery: REGISTERY = Registery::new(chain).expect("registery");
        erase_graveyard(chain);
        let graveyard: GRAVEYARD = Graveyard::new(chain).expect("graveyard");
        erase_coin_manager(chain);
        let coin_manager: COIN_MANAGER = CoinManager::new(chain).expect("coin");
        erase_flame_manager(chain);
        let flame_manager: FLAME_MANAGER = FlameManager::new(chain).expect("flame");
        erase_state_manager(chain);
        let state_manager: STATE_MANAGER = StateManager::new(chain).expect("state");
        erase_privileges_manager(chain);
        let privileges_manager: PRIVILEGES_MANAGER = PrivilegesManager::new(chain).expect("priv");
        erase_params_manager(chain);
        let params_manager: PARAMS_MANAGER = ParamsManager::new(chain).expect("params");
        erase_archival_manager(chain);
        let archival_manager: ARCHIVAL_MANAGER = ArchivalManager::new(chain).expect("archival");

        let account_kh = KeyHolder::new(sk(ACCOUNT_SK)).expect("account kh");
        let engine_kh = KeyHolder::new(sk(ENGINE_SK)).expect("engine kh");
        let account_key = account_kh.secp_public_key_bytes();
        let engine_key = engine_kh.secp_public_key_bytes();

        let session_pool: SESSION_POOL = SessionPool::construct(
            engine_key,
            &sync_manager,
            &utxo_set,
            &registery,
            &graveyard,
            &coin_manager,
            &flame_manager,
            &state_manager,
            &privileges_manager,
            &params_manager,
            Some(Arc::clone(&archival_manager)),
        );

        // A confirmed LiftV2 deposit owned by account+engine.
        let lift_spk = ScriptBuf::from(return_liftv2_scriptpubkey(account_key, engine_key).unwrap());
        let lift_outpoint = OutPoint::new(Txid::from_byte_array([0x00u8; 32]), 0);
        let lift_txout = TxOut { value: Amount::from_sat(100_000), script_pubkey: lift_spk };
        utxo_set.lock().await.insert_utxo(&lift_outpoint, &lift_txout);
        let lift = Lift::new_liftv2(account_key, engine_key, lift_outpoint, lift_txout);

        let root = RootAccount::self_root_account_from_registery(&account_kh, &registery).await;
        let liftup = Liftup::new(root, Target::new(1), vec![lift]);
        let sig = liftup.bls_sign(&account_kh).expect("liftup sign");

        // Depositor's committed nonces (round 1).
        let client = ClientCosigner::new(
            Scalar::from_hex(ACCOUNT_SK).unwrap(),
            Scalar::from_hex(A_HN_SK).unwrap(),
            Scalar::from_hex(A_BN_SK).unwrap(),
        );
        let (ch, cb) = client.public_nonces();

        // Session must be active for the register handler to admit the liftup.
        session_pool.lock().await.begin_session(1, 1_776_000_001, feerate);

        // ---- R1: register over the real handler with a serialized wire body. ----
        let register_body = LiftupV2RegisterRequestBody::new(
            liftup.clone(),
            sig,
            vec![LiftupV2Nonce {
                outpoint: lift_outpoint,
                client_hiding_nonce: ch.serialize().to_vec(),
                client_binding_nonce: cb.serialize().to_vec(),
            }],
        );
        let register_payload = register_body.serialize().expect("serialize register");
        let register_pkg = handle_liftup_v2_register_request(1, &register_payload, &session_pool)
            .await
            .expect("register handler returns a package");
        let register_response =
            LiftupV2RegisterResponseBody::deserialize(&register_pkg.payload()).expect("register resp");
        assert!(
            matches!(register_response, LiftupV2RegisterResponseBody::Ok(_)),
            "register handler admits the liftup and commits the nonces"
        );

        // ---- Fetch BEFORE freeze: the engine has no cosign material yet. ----
        let fetch_body = LiftupV2CosignRequestBody::fetch(lift_outpoint);
        let fetch_payload = fetch_body.serialize().expect("serialize fetch");
        let pre_pkg = handle_liftup_v2_cosign_request(1, &fetch_payload, &session_pool)
            .await
            .expect("cosign handler returns a package");
        let pre_resp = LiftupV2CosignResponseBody::deserialize(&pre_pkg.payload()).expect("pre resp");
        assert!(
            matches!(pre_resp, LiftupV2CosignResponseBody::NotReady),
            "before freeze the engine returns NotReady"
        );

        // ---- Fetch an UNKNOWN outpoint: rejected. ----
        let unknown_op = OutPoint::new(Txid::from_byte_array([0x99u8; 32]), 7);
        let unknown_payload = LiftupV2CosignRequestBody::fetch(unknown_op).serialize().unwrap();
        let unknown_pkg = handle_liftup_v2_cosign_request(1, &unknown_payload, &session_pool)
            .await
            .expect("cosign handler returns a package");
        let unknown_resp =
            LiftupV2CosignResponseBody::deserialize(&unknown_pkg.payload()).expect("unknown resp");
        assert!(
            matches!(unknown_resp, LiftupV2CosignResponseBody::Err(_)),
            "an unknown outpoint is rejected"
        );

        // ---- freeze: the engine prepares its cosign material (engine loop step). ----
        session_pool
            .lock()
            .await
            .prepare_liftv2_cosigns(sk(ENGINE_SK))
            .await
            .expect("prepare cosigns");

        // ---- R2a: Fetch the engine cosign material over the handler. ----
        let mat_pkg = handle_liftup_v2_cosign_request(1, &fetch_payload, &session_pool)
            .await
            .expect("cosign handler returns a package");
        let (sighash, eh, eb) =
            match LiftupV2CosignResponseBody::deserialize(&mat_pkg.payload()).expect("material resp") {
                LiftupV2CosignResponseBody::Material {
                    sighash,
                    engine_hiding_nonce,
                    engine_binding_nonce,
                } => (
                    sighash,
                    Point::from_slice(&engine_hiding_nonce).expect("eh point"),
                    Point::from_slice(&engine_binding_nonce).expect("eb point"),
                ),
                other => panic!("expected Material, got {:?}", other.json()),
            };

        // Depositor partial-signs (round 2) from the fetched material.
        let client_partial = client
            .partial_sign(account_key, engine_key, eh, eb, sighash)
            .expect("client partial");

        // ---- R2b: Submit the partial over the handler. ----
        let submit_payload = LiftupV2CosignRequestBody::submit(lift_outpoint, client_partial.serialize())
            .serialize()
            .expect("serialize submit");
        let submit_pkg = handle_liftup_v2_cosign_request(1, &submit_payload, &session_pool)
            .await
            .expect("cosign handler returns a package");
        let submit_resp =
            LiftupV2CosignResponseBody::deserialize(&submit_pkg.payload()).expect("submit resp");
        assert!(
            matches!(submit_resp, LiftupV2CosignResponseBody::Submitted),
            "submit handler aggregates the cosignature"
        );

        assert!(
            session_pool.lock().await.all_liftv2_cosigned(),
            "all V2 lifts cosigned after the transport round trips"
        );

        // ---- Build the batch — succeeds only if the cosig is a valid key-path spend. ----
        let bc: BatchContainer = session_pool
            .lock()
            .await
            .into_batch_container(&engine_kh)
            .await
            .expect("batch build with the transport-cosigned V2 deposit");
        session_pool.lock().await.end_session().await;

        let (op, _txout, witness) = &bc.signed_batch_txn.tx_inputs[1];
        assert_eq!(*op, lift_outpoint);
        assert_eq!(witness.len(), 1);
        assert_eq!(witness[0].len(), 64);

        println!("LiftV2 TRANSPORT HANDLERS PROVEN: register -> (NotReady/unknown rejected) -> prepare -> Fetch material -> Submit partial -> into_batch_container lifts a V2 deposit in, all through the real TCP handler functions with serialized wire bodies.");
    }
}
