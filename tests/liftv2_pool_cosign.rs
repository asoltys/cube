// Drives the real SessionPool LiftV2 cosign state machine end to end, in-process
// (no sockets): register a V2 lift + depositor nonces, freeze, prepare the engine
// cosign, have the depositor partial-sign via the cosign module, submit, and build
// the batch — which only succeeds if the collected cosignature is a valid key-path
// spend of the deposit. This exercises register_liftv2_nonces ->
// prepare_liftv2_cosigns -> submit_liftv2_partial_sig -> into_batch_container.

#[cfg(test)]
mod liftv2_pool_cosign {
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, OutPoint, ScriptBuf, TxOut, Txid};

    use cube::constructive::bitcoiny::batch_container::batch_container::BatchContainer;
    use cube::constructive::core_types::entities::account::root_account::root_account::RootAccount;
    use cube::constructive::core_types::target::target::Target;
    use cube::constructive::entries::entry_kinds::liftup::liftup::Liftup;
    use cube::constructive::txo::lift::lift::Lift;
    use cube::constructive::txo::lift::lift_versions::liftv2::cosign::ClientCosigner;
    use cube::constructive::txo::lift::lift_versions::liftv2::liftv2::return_liftv2_scriptpubkey;
    use cube::inscriptive::archival_manager::archival_manager::{erase_archival_manager, ArchivalManager, ARCHIVAL_MANAGER};
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
    use secp::Scalar;
    use std::sync::Arc;

    // account = musig signer_1, engine = musig signer_2 (both even-Y), + nonces.
    const ACCOUNT_SK: &str = "1cc5906ab936b1e29db24fffe9f87b33a4c64f2d3b59aed6c3c4faeb8fcba6da";
    const ENGINE_SK: &str = "4882eef979baa5c88fd9e62c698de201f0a991af65877becf683e988f3024b0f";
    const A_HN_SK: &str = "e2d64e2bd20d5843d03a47199f059aebdf2a9904616a01fe961ee875a7748199";
    const A_BN_SK: &str = "4b978d3aac4135213f536194522f68fbb2ca4321a49d95560ae9726cd9d6a55d";

    fn sk(h: &str) -> [u8; 32] {
        hex::decode(h).unwrap().try_into().unwrap()
    }

    #[tokio::test]
    async fn pool_cosign_state_machine_lifts_in_a_v2_deposit() {
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

        // depositor's committed nonces (round 1).
        let client = ClientCosigner::new(
            Scalar::from_hex(ACCOUNT_SK).unwrap(),
            Scalar::from_hex(A_HN_SK).unwrap(),
            Scalar::from_hex(A_BN_SK).unwrap(),
        );
        let (ch, cb) = client.public_nonces();

        // begin -> register entry -> register nonces.
        session_pool.lock().await.begin_session(1, 1_776_000_001, feerate);
        session_pool
            .lock()
            .await
            .exec_liftup_in_pool(&liftup, sig)
            .await
            .expect("liftup in pool");
        session_pool
            .lock()
            .await
            .register_liftv2_nonces(lift_outpoint, account_key, engine_key, ch, cb);

        // freeze: engine prepares the cosign and returns the round-2 material.
        let material = session_pool
            .lock()
            .await
            .prepare_liftv2_cosigns(sk(ENGINE_SK))
            .await
            .expect("prepare cosigns");
        let (sighash, eh, eb) = *material.get(&lift_outpoint).expect("cosign material for the deposit");

        // depositor partial-signs (round 2), engine aggregates on submit.
        let client_partial = client
            .partial_sign(account_key, engine_key, eh, eb, sighash)
            .expect("client partial");
        assert!(
            session_pool
                .lock()
                .await
                .submit_liftv2_partial_sig(lift_outpoint, client_partial),
            "submit must aggregate the cosignature"
        );
        assert!(session_pool.lock().await.all_liftv2_cosigned(), "all V2 lifts cosigned");

        // build the batch — succeeds only if the collected cosig is a valid
        // key-path spend of the deposit.
        let bc: BatchContainer = session_pool
            .lock()
            .await
            .into_batch_container(&engine_kh)
            .await
            .expect("batch build with the cosigned V2 deposit");
        session_pool.lock().await.end_session().await;

        // the V2 lift input (index 1) carries the 64-byte key-path cosignature.
        let (op, _txout, witness) = &bc.signed_batch_txn.tx_inputs[1];
        assert_eq!(*op, lift_outpoint);
        assert_eq!(witness.len(), 1);
        assert_eq!(witness[0].len(), 64);

        println!("LiftV2 POOL COSIGN STATE MACHINE PROVEN: register -> prepare -> submit -> into_batch_container lifts a V2 deposit in.");
    }
}
