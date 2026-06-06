// The engine derives non-custodial exit trees from LIVE shadow state.
//
// Proves SessionPool::derive_contract_exit_trees (the method wired into the batch
// builder's assemble_batch_args) turns a contract's on-ledger Shadowing claims
// into a TimeoutTree of per-participant, unilaterally-exitable VTXOs — straight
// from the coin manager the running engine uses.

#[cfg(test)]
mod engine_exit_trees {
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, OutPoint, ScriptBuf, TxOut, Txid};

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
    use std::sync::Arc;

    const ENGINE_SK: &str = "4882eef979baa5c88fd9e62c698de201f0a991af65877becf683e988f3024b0f";
    const ALICE_PK: &str = "02cb70281face51a77d51400612196032bb12422d4c07fa42997a0ab39c2431455";
    const BOB_PK: &str = "0251deb9fcf4d16b0f82c75cf71e1ffb7879beb0c6bf733b0778a81b777406574f";

    fn sk(h: &str) -> [u8; 32] { hex::decode(h).unwrap().try_into().unwrap() }
    fn x(pk: &str) -> [u8; 32] { hex::decode(&pk[2..]).unwrap().try_into().unwrap() }

    #[tokio::test]
    async fn engine_derives_exit_trees_from_live_shadow_state() {
        let chain = Chain::Testbed;

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

        let engine_kh = KeyHolder::new(sk(ENGINE_SK)).expect("engine kh");
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

        // No contracts yet -> no exit trees.
        {
            let trees = session_pool.lock().await.derive_contract_exit_trees(800_000, 144).await;
            assert!(trees.is_empty(), "no contracts -> no exit trees");
        }

        // Populate two contracts with shadow allocations on the engine's coin manager.
        let alice = x(ALICE_PK);
        let bob = x(BOB_PK);
        let cid_a = [0xa0u8; 32];
        let cid_b = [0xb0u8; 32];
        {
            let mut c = coin_manager.lock().await;
            c.register_contract(cid_a, 50_000).expect("rc a");
            c.register_contract(cid_b, 12_000).expect("rc b");
            c.register_account(alice, 0).expect("ra alice");
            c.register_account(bob, 0).expect("ra bob");
            c.apply_changes().expect("ap");
            c.contract_shadow_alloc_account(cid_a, alice).expect("alloc a-alice");
            c.shadow_up(cid_a, alice, 30_000).expect("up a-alice");
            c.contract_shadow_alloc_account(cid_a, bob).expect("alloc a-bob");
            c.shadow_up(cid_a, bob, 20_000).expect("up a-bob");
            c.contract_shadow_alloc_account(cid_b, alice).expect("alloc b-alice");
            c.shadow_up(cid_b, alice, 12_000).expect("up b-alice");
            c.apply_changes().expect("ap2");
        }
        // touch the utxo_set so the unused warning is moot and managers are live
        utxo_set.lock().await.insert_utxo(
            &OutPoint::new(Txid::from_byte_array([0x01u8; 32]), 0),
            &TxOut { value: Amount::from_sat(1), script_pubkey: ScriptBuf::new() },
        );

        // The engine derives a tree per contract, straight from live shadow state.
        let trees = session_pool.lock().await.derive_contract_exit_trees(800_000, 144).await;
        assert_eq!(trees.len(), 2, "one exit tree per contract with allocations");

        let by_id: std::collections::HashMap<[u8; 32], &cube::constructive::txout_types::timeout_tree::TimeoutTree> =
            trees.iter().map(|(id, t)| (*id, t)).collect();

        let tree_a = by_id.get(&cid_a).expect("tree for contract A");
        assert_eq!(tree_a.leaves.len(), 2, "A has 2 participants");
        assert_eq!(tree_a.leaves_value_sum(), 50_000, "A: Σ VTXOs == pot");
        assert_eq!(tree_a.total_value_in_satoshis, 50_000);
        assert!(tree_a.funding_scriptpubkey().is_some());
        // each leaf is unilaterally exitable (CSV exit elements present).
        for leaf in tree_a.leaves.iter() {
            assert!(leaf.exit_spend_elements().is_some(), "VTXO has a unilateral exit path");
        }

        let tree_b = by_id.get(&cid_b).expect("tree for contract B");
        assert_eq!(tree_b.leaves.len(), 1, "B has 1 participant");
        assert_eq!(tree_b.leaves_value_sum(), 12_000, "B: Σ VTXOs == pot");

        // contract id enumeration sees both.
        let ids = coin_manager.lock().await.get_all_contract_ids();
        assert!(ids.contains(&cid_a) && ids.contains(&cid_b));

        println!("ENGINE EXIT-TREE DERIVATION PROVEN: SessionPool::derive_contract_exit_trees turns live shadow allocations (2 contracts) into TimeoutTrees of unilaterally-exitable VTXOs — the per-batch non-custodial rendering wired into assemble_batch_args.");
    }
}
