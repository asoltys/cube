// The ENGINE-LEVEL non-custodial cycle, end to end through the SessionPool with
// EMIT_EXIT_TREE_PROJECTORS on:
//   batch 1: the engine derives a contract's exit tree from live shadow state and
//            EMITS its covenant (Projector) output; we persist it as the tip.
//   batch 2: the prev projector is fed back; the engine exposes the refresh
//            sighash, the participants + engine N-of-N co-sign it (in-process
//            here; the live wire is the per-batch cosign transport), the cosig is
//            handed to the pool, and into_batch_container spends the prev covenant
//            (auto-refresh) AND emits the next covenant.
// This proves the orchestration the engine loop performs. The only piece not
// exercised is the OS-socket transport that collects the cosigns from clients.

#[cfg(test)]
mod projector_engine_cycle {
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Txid, TxOut};

    use cube::constructive::bitcoiny::batch_container::batch_container::BatchContainer;
    use cube::constructive::core_types::entities::account::root_account::root_account::RootAccount;
    use cube::constructive::core_types::target::target::Target;
    use cube::constructive::entries::entry_kinds::liftup::liftup::Liftup;
    use cube::constructive::txo::lift::lift::Lift;
    use cube::constructive::txo::lift::lift_versions::liftv1::liftv1::return_liftv1_scriptpubkey;
    use cube::constructive::txout_types::timeout_tree::refresh::{
        engine_projected_pubkey, engine_projected_secret, participant_projected_pubkey,
        participant_projected_secret, refresh_keyagg,
    };
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
    use cube::transmutative::musig::session::MusigSessionCtx;
    use secp::{Point, Scalar};
    use std::sync::Arc;

    const ALICE_SK: &str = "1cc5906ab936b1e29db24fffe9f87b33a4c64f2d3b59aed6c3c4faeb8fcba6da";
    const ALICE_PK: &str = "02cb70281face51a77d51400612196032bb12422d4c07fa42997a0ab39c2431455";
    const BOB_SK: &str = "4882eef979baa5c88fd9e62c698de201f0a991af65877becf683e988f3024b0f";
    const BOB_PK: &str = "0251deb9fcf4d16b0f82c75cf71e1ffb7879beb0c6bf733b0778a81b777406574f";
    const ENGINE_SK: &str = "2c71bfbd0389b96e292b37c2272ea846655cfb48578b06600c0ffd991f6f7e29";
    const ENGINE_PK: &str = "029611bc66d526fa3194d0f525dce21e782dcf90cc72529ec2d5486da838d83770";
    const A_HN: &str = "e2d64e2bd20d5843d03a47199f059aebdf2a9904616a01fe961ee875a7748199";
    const A_BN: &str = "4b978d3aac4135213f536194522f68fbb2ca4321a49d95560ae9726cd9d6a55d";
    const B_HN: &str = "d3b9f2f01f7caa9b0fe2e932ae752f71da9f8f1a652ec895504091333b97d007";
    const B_BN: &str = "961a4d128a1f3cb5c41e71bc86fdc9e81050b7471f05112a6a5360a2240ff3cf";
    const S_HN: &str = "cf2087a05db9aad43ae97aba584f8d8cb9d61fb84c39f372ea72bdd1d272ab81";
    const S_BN: &str = "4025f894ab8712c244e38af85094043e025824a0d021cd6fb9709fc9ef739e45";

    fn sc(h: &str) -> Scalar { Scalar::from_hex(h).unwrap() }
    fn pt(h: &str) -> Point { Point::from_hex(h).unwrap() }
    fn xkey(pk: &str) -> [u8; 32] { hex::decode(&pk[2..]).unwrap().try_into().unwrap() }

    // Mirror the engine's EXIT_TREE_EXPIRY_WINDOW with bitcoin tip 0 (fresh testbed).
    const EXPIRY: u32 = 12_960;

    // N-of-N refresh cosign over `sighash` for `allocations` (sorted by account
    // key, exactly as the engine enumerates them). Participants carry (secret, hn,
    // bn) keyed by account key; engine signs last (index = allocations.len()).
    fn n_of_n_refresh_cosig(
        engine: [u8; 32],
        engine_secret: &str,
        allocations: &[([u8; 32], u64)],
        participant_material: &[([u8; 32], &str, &str, &str)], // key, secret, hn, bn
        sighash: [u8; 32],
    ) -> [u8; 64] {
        let keyagg = refresh_keyagg(engine, allocations, EXPIRY).unwrap();
        let mut session = MusigSessionCtx::new(&keyagg, sighash).unwrap();
        // participants in allocation order
        let mut pubs: Vec<Point> = Vec::new();
        let mut secs: Vec<(Scalar, Scalar, Scalar)> = Vec::new();
        for (i, (acct, value)) in allocations.iter().enumerate() {
            let (_, secret, hn, bn) = participant_material.iter().find(|(k, ..)| k == acct).unwrap();
            let base = Point::from_slice(&{
                // even-Y base point from the x-only account key
                let mut v = vec![0x02u8]; v.extend_from_slice(acct); v
            }).unwrap();
            let pp = participant_projected_pubkey(base, *value, i as u32).unwrap();
            session.insert_nonce(pp, sc(hn).base_point_mul(), sc(bn).base_point_mul());
            pubs.push(pp);
            secs.push((participant_projected_secret(sc(secret), *value, i as u32).unwrap(), sc(hn), sc(bn)));
        }
        let e_pub = engine_projected_pubkey(pt(ENGINE_PK), allocations).unwrap();
        session.insert_nonce(e_pub, sc(S_HN).base_point_mul(), sc(S_BN).base_point_mul());
        for (i, pp) in pubs.iter().enumerate() {
            let (s, hn, bn) = &secs[i];
            let partial = session.partial_sign(*s, *hn, *bn).unwrap();
            assert!(session.insert_partial_sig(*pp, partial));
        }
        let e_partial = session
            .partial_sign(engine_projected_secret(sc(engine_secret), allocations).unwrap(), sc(S_HN), sc(S_BN))
            .unwrap();
        assert!(session.insert_partial_sig(e_pub, e_partial));
        session.full_agg_sig().unwrap()
    }

    #[tokio::test]
    async fn engine_emits_and_refreshes_a_contract_covenant() {
        std::env::set_var("CUBE_EMIT_EXIT_TREE_PROJECTORS", "1");
        let chain = Chain::Testbed;

        erase_sync_manager(chain); let sync_manager: SYNC_MANAGER = SyncManager::new(chain).unwrap();
        erase_utxo_set(chain); let utxo_set: UTXO_SET = UTXOSet::new(chain).unwrap();
        erase_registery(chain); let registery: REGISTERY = Registery::new(chain).unwrap();
        erase_graveyard(chain); let graveyard: GRAVEYARD = Graveyard::new(chain).unwrap();
        erase_coin_manager(chain); let coin_manager: COIN_MANAGER = CoinManager::new(chain).unwrap();
        erase_flame_manager(chain); let flame_manager: FLAME_MANAGER = FlameManager::new(chain).unwrap();
        erase_state_manager(chain); let state_manager: STATE_MANAGER = StateManager::new(chain).unwrap();
        erase_privileges_manager(chain); let privileges_manager: PRIVILEGES_MANAGER = PrivilegesManager::new(chain).unwrap();
        erase_params_manager(chain); let params_manager: PARAMS_MANAGER = ParamsManager::new(chain).unwrap();
        erase_archival_manager(chain); let archival_manager: ARCHIVAL_MANAGER = ArchivalManager::new(chain).unwrap();

        let engine_kh = KeyHolder::new(hex::decode(ENGINE_SK).unwrap().try_into().unwrap()).unwrap();
        let engine_key = engine_kh.secp_public_key_bytes();
        assert_eq!(engine_key, xkey(ENGINE_PK));

        let alice = xkey(ALICE_PK); let bob = xkey(BOB_PK);
        // A contract with shadow claims (the pot). Small so it fits the genesis payload value.
        let cid = [0xc0u8; 32];
        {
            let mut c = coin_manager.lock().await;
            c.register_contract(cid, 5_000).unwrap();
            c.register_account(alice, 0).unwrap();
            c.register_account(bob, 0).unwrap();
            c.apply_changes().unwrap();
            c.contract_shadow_alloc_account(cid, alice).unwrap();
            c.shadow_up(cid, alice, 3_000).unwrap();
            c.contract_shadow_alloc_account(cid, bob).unwrap();
            c.shadow_up(cid, bob, 2_000).unwrap();
            c.apply_changes().unwrap();
        }
        // allocations as the engine enumerates them (sorted by account key).
        let allocations = coin_manager.lock().await.get_contract_shadow_allocations_in_satoshis(cid).unwrap();
        assert_eq!(allocations.iter().map(|(_, v)| v).sum::<u64>(), 5_000);

        let session_pool: SESSION_POOL = SessionPool::construct(
            engine_key, &sync_manager, &utxo_set, &registery, &graveyard, &coin_manager,
            &flame_manager, &state_manager, &privileges_manager, &params_manager,
            Some(Arc::clone(&archival_manager)),
        );

        // A batch needs >=1 entry (the engine never builds an empty batch; the BLS
        // aggregate is over the entries). Add a LiftV1 deposit + liftup by a fresh
        // depositor (not a contract participant, so no registration collision).
        let dep_kh = KeyHolder::new([0x33u8; 32]).unwrap();
        let dep = dep_kh.secp_public_key_bytes();
        let lift_spk = ScriptBuf::from(return_liftv1_scriptpubkey(dep, engine_key).unwrap());
        let lift_outpoint = OutPoint::new(Txid::from_byte_array([0x5a; 32]), 0);
        let lift_txout = TxOut { value: Amount::from_sat(50_000), script_pubkey: lift_spk };
        utxo_set.lock().await.insert_utxo(&lift_outpoint, &lift_txout);
        let lift = Lift::new_liftv1(dep, engine_key, lift_outpoint, lift_txout);
        let root = RootAccount::self_root_account_from_registery(&dep_kh, &registery).await;
        let liftup = Liftup::new(root, Target::new(1), vec![lift]);
        let liftup_sig = liftup.bls_sign(&dep_kh).expect("liftup sign");

        // ---- BATCH 1: emit the contract's covenant (alongside the liftup entry). ----
        session_pool.lock().await.begin_session(1, 1_777_000_000, 1);
        session_pool.lock().await.exec_liftup_in_pool(&liftup, liftup_sig).await.expect("liftup in pool");
        let bc1: BatchContainer = session_pool.lock().await.into_batch_container(&engine_kh).await
            .expect("batch 1 emits the covenant");
        let emitted = session_pool.lock().await.locate_emitted_projectors(&bc1);
        assert_eq!(emitted.len(), 1, "one covenant emitted for the allocated contract");
        assert_eq!(emitted[0].satoshi_amount, 5_000, "covenant carries the pot");
        let prev_projector = emitted[0].clone();
        let prev_outpoint = prev_projector.location.as_ref().unwrap().0;
        session_pool.lock().await.end_session().await;
        // persist the emitted covenant as the tip the next batch must refresh.
        sync_manager.lock().await.set_projector_tips(vec![prev_projector]);

        // ---- BATCH 2: refresh (spend) the prev covenant + emit the next. ----
        // second liftup entry (batch needs >=1 entry).
        let lift2_outpoint = OutPoint::new(Txid::from_byte_array([0x5b; 32]), 0);
        let lift2_txout = TxOut { value: Amount::from_sat(50_000), script_pubkey: ScriptBuf::from(return_liftv1_scriptpubkey(dep, engine_key).unwrap()) };
        utxo_set.lock().await.insert_utxo(&lift2_outpoint, &lift2_txout);
        let lift2 = Lift::new_liftv1(dep, engine_key, lift2_outpoint, lift2_txout);
        let root2 = RootAccount::self_root_account_from_registery(&dep_kh, &registery).await;
        let liftup2 = Liftup::new(root2, Target::new(2), vec![lift2]);
        let liftup2_sig = liftup2.bls_sign(&dep_kh).expect("liftup2 sign");

        session_pool.lock().await.begin_session(2, 1_777_000_060, 1);
        session_pool.lock().await.exec_liftup_in_pool(&liftup2, liftup2_sig).await.expect("liftup2 in pool");
        let sighashes = session_pool.lock().await.projector_refresh_keypath_sighashes().await
            .expect("refresh sighashes");
        let sighash = *sighashes.get(&prev_outpoint).expect("sighash for the prev covenant");

        let cosig = n_of_n_refresh_cosig(
            engine_key, ENGINE_SK, &allocations,
            &[(alice, ALICE_SK, A_HN, A_BN), (bob, BOB_SK, B_HN, B_BN)],
            sighash,
        );
        session_pool.lock().await.insert_projector_refresh_cosig(prev_outpoint, cosig);

        let bc2: BatchContainer = session_pool.lock().await.into_batch_container(&engine_kh).await
            .expect("batch 2 spends the prev covenant via the N-of-N refresh + emits the next");
        // the prev covenant is spent as an input with the 64-byte refresh witness.
        let spent: Vec<&OutPoint> = bc2.signed_batch_txn.tx_inputs.iter().map(|(op, _, _)| op).collect();
        assert!(spent.contains(&&prev_outpoint), "batch 2 spends (refreshes) the prev covenant");
        let (_op, _txout, witness) = bc2.signed_batch_txn.tx_inputs.iter().find(|(op, _, _)| *op == prev_outpoint).unwrap();
        assert_eq!(witness.len(), 1, "key-path refresh: one witness element");
        assert_eq!(witness[0].len(), 64, "the 64-byte N-of-N refresh signature");
        // and batch 2 emits the next covenant.
        let emitted2 = session_pool.lock().await.locate_emitted_projectors(&bc2);
        assert_eq!(emitted2.len(), 1, "batch 2 emits the refreshed covenant");
        session_pool.lock().await.end_session().await;

        std::env::remove_var("CUBE_EMIT_EXIT_TREE_PROJECTORS");
        println!("ENGINE CYCLE PROVEN: SessionPool emits a contract's exit-tree covenant (batch 1), persists it, then spends it via an N-of-N refresh cosig AND emits the next covenant (batch 2). The full auto-refresh orchestration end to end through the engine; only the OS-socket cosign transport remains for a live multi-party run.");
    }
}
