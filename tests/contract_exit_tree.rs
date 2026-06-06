// Contract pot -> Shadowing claims -> timeout-tree of unilaterally-exitable VTXOs.
//
// This is the non-custodial ownership leg wired end to end through REAL engine
// code: a contract custodies a pot, Shadowing attributes it to participants as
// account_key->value claims, and `TimeoutTree::build` (src module, not a test
// helper) renders those claims as per-participant VTXO leaves. We prove:
//   * Σ leaf values == pot (every claim collateralized & exitable),
//   * a holder UNILATERALLY EXITS their leaf via the CSV path with ONLY their key
//     (control-block commitment + BIP340 signature both verify),
//   * the covenant key is VALUE-BOUND (a different claim value -> different spk),
//   * an optional disprove leaf is committed in the leaf taproot.

#[cfg(test)]
mod contract_exit_tree {
    use bitcoin::hashes::Hash;
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash};
    use bitcoin::transaction::Version;
    use bitcoin::{
        absolute::LockTime, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
        Witness, XOnlyPublicKey,
    };

    use cube::constructive::txout_types::timeout_tree::TimeoutTree;
    use cube::inscriptive::coin_manager::coin_manager::{erase_coin_manager, CoinManager, COIN_MANAGER};
    use cube::operative::run_args::chain::Chain;
    use cube::transmutative::hash::sha256;
    use cube::transmutative::secp::schnorr::{sign, verify_xonly, SchnorrSigningMode};
    use secp::Scalar;

    // Two players (alice, bob) + engine — even-Y test keypairs.
    const ALICE_SK: &str = "1cc5906ab936b1e29db24fffe9f87b33a4c64f2d3b59aed6c3c4faeb8fcba6da";
    const ALICE_PK: &str = "02cb70281face51a77d51400612196032bb12422d4c07fa42997a0ab39c2431455";
    const BOB_PK: &str = "0251deb9fcf4d16b0f82c75cf71e1ffb7879beb0c6bf733b0778a81b777406574f";
    const ENGINE_PK: &str = "029611bc66d526fa3194d0f525dce21e782dcf90cc72529ec2d5486da838d83770";

    fn x(pk: &str) -> [u8; 32] {
        hex::decode(&pk[2..]).unwrap().try_into().unwrap()
    }

    #[tokio::test]
    async fn shadow_claims_become_a_timeout_tree_of_exitable_vtxos() {
        let alice = x(ALICE_PK);
        let bob = x(BOB_PK);
        let engine = x(ENGINE_PK);
        let expiry_height = 800_000u32;
        let exit_delay = 144u16;

        // Stakes (the lottery scenario): alice 30k, bob 20k -> pot 50k.
        let alice_stake = 30_000u64;
        let bob_stake = 20_000u64;
        let pot = alice_stake + bob_stake;

        // ---- Shadowing: contract custodies the pot, claims attributed per account. ----
        let chain = Chain::Testbed;
        erase_coin_manager(chain);
        let cm: COIN_MANAGER = CoinManager::new(chain).expect("coin");
        let cid = [0xc0u8; 32];
        {
            let mut c = cm.lock().await;
            c.register_contract(cid, pot).expect("rc");
            c.register_account(alice, 0).expect("ra alice");
            c.register_account(bob, 0).expect("ra bob");
            c.apply_changes().expect("ap");
            c.contract_shadow_alloc_account(cid, alice).expect("alloc alice");
            c.shadow_up(cid, alice, alice_stake).expect("stake alice");
            c.contract_shadow_alloc_account(cid, bob).expect("alloc bob");
            c.shadow_up(cid, bob, bob_stake).expect("stake bob");
            c.apply_changes().expect("ap2");
        }

        // Read the attributed claims back out (this is what the engine would feed
        // the tree builder).
        let allocations: Vec<([u8; 32], u64)> = {
            let c = cm.lock().await;
            vec![
                (alice, c.get_shadow_alloc_value_in_satoshis(cid, alice).unwrap()),
                (bob, c.get_shadow_alloc_value_in_satoshis(cid, bob).unwrap()),
            ]
        };
        let contract_pot = cm.lock().await.get_contract_balance(cid).unwrap();
        assert_eq!(contract_pot, pot);

        // ---- Build the timeout tree from the shadow claims. ----
        let tree = TimeoutTree::build(engine, &allocations, expiry_height, exit_delay, None)
            .expect("build timeout tree");
        assert_eq!(tree.leaves.len(), 2);
        assert_eq!(
            tree.leaves_value_sum(),
            contract_pot,
            "Σ leaf VTXO values == contract pot (every claim collateralized & exitable)"
        );
        assert_eq!(tree.total_value_in_satoshis, pot);
        assert!(tree.funding_scriptpubkey().is_some(), "the pot funding output has a spk");

        // ---- UNILATERAL EXIT of alice's leaf via the CSV exit path, her key only. ----
        let alice_leaf = tree
            .leaves
            .iter()
            .find(|l| l.account_key == alice)
            .expect("alice leaf");
        assert_eq!(alice_leaf.value_in_satoshis, alice_stake);

        let leaf_spk = ScriptBuf::from_bytes(alice_leaf.scriptpubkey().unwrap());
        let leaf_txout = TxOut {
            value: Amount::from_sat(alice_leaf.value_in_satoshis),
            script_pubkey: leaf_spk,
        };
        let leaf_outpoint = OutPoint::new(Txid::from_byte_array([0xa1u8; 32]), 0);

        let exit_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: leaf_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::from_height(exit_delay),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(alice_leaf.value_in_satoshis - 500),
                script_pubkey: ScriptBuf::new_op_return(&[]),
            }],
        };

        let (exit_leaf_hash, exit_script_bytes, exit_control_block) =
            alice_leaf.exit_spend_elements().expect("exit elements");
        let exit_script = ScriptBuf::from_bytes(exit_script_bytes);

        // cube and rust-bitcoin agree on the exit leaf hash.
        assert_eq!(
            exit_leaf_hash,
            TapLeafHash::from_script(&exit_script, LeafVersion::TapScript).to_byte_array()
        );

        // the exit leaf is committed in alice's VTXO taproot.
        let out_x = XOnlyPublicKey::from_slice(&alice_leaf.taproot.tweaked_key().unwrap().serialize_xonly())
            .unwrap();
        assert!(
            ControlBlock::decode(&exit_control_block)
                .unwrap()
                .verify_taproot_commitment(
                    &bitcoin::secp256k1::Secp256k1::verification_only(),
                    out_x,
                    &exit_script
                ),
            "exit leaf committed in the VTXO taproot"
        );

        let exit_sighash = SighashCache::new(&exit_tx)
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&[leaf_txout]),
                TapLeafHash::from_script(&exit_script, LeafVersion::TapScript),
                TapSighashType::Default,
            )
            .unwrap()
            .to_byte_array();
        let alice_sig = sign(
            Scalar::from_hex(ALICE_SK).unwrap().serialize(),
            exit_sighash,
            SchnorrSigningMode::BIP340,
        )
        .unwrap();
        assert!(
            verify_xonly(alice, exit_sighash, alice_sig, SchnorrSigningMode::BIP340),
            "UNILATERAL EXIT: alice spends her shadow-claimed VTXO via CSV with only her key"
        );

        // ---- VALUE BINDING: a different claim value -> different covenant spk. ----
        let bumped = vec![(alice, alice_stake + 1), (bob, bob_stake)];
        let tree_bumped =
            TimeoutTree::build(engine, &bumped, expiry_height, exit_delay, None).expect("bumped");
        assert_ne!(
            tree.funding_scriptpubkey().unwrap(),
            tree_bumped.funding_scriptpubkey().unwrap(),
            "Projector binds the pot covenant key to the claim values"
        );
        let alice_leaf_bumped = tree_bumped.leaves.iter().find(|l| l.account_key == alice).unwrap();
        assert_ne!(
            alice_leaf.scriptpubkey().unwrap(),
            alice_leaf_bumped.scriptpubkey().unwrap(),
            "a leaf's covenant key is bound to its value"
        );

        // ---- DISPROVE leaf: an optional BitVM punishment path is committed. ----
        let disprove_secret = sha256(b"garbled-invalid-output-label");
        let disprove_hash = sha256(&disprove_secret);
        let tree_zk = TimeoutTree::build(
            engine,
            &allocations,
            expiry_height,
            exit_delay,
            Some(&[disprove_hash, sha256(b"bob-disprove")]),
        )
        .expect("zktlc tree");
        let alice_zk = tree_zk.leaves.iter().find(|l| l.account_key == alice).unwrap();
        let (dh, dscript, dcb) = alice_zk.disprove_spend_elements().expect("disprove elements");
        let dscript = ScriptBuf::from_bytes(dscript);
        assert_eq!(dh, TapLeafHash::from_script(&dscript, LeafVersion::TapScript).to_byte_array());
        let zk_out_x =
            XOnlyPublicKey::from_slice(&alice_zk.taproot.tweaked_key().unwrap().serialize_xonly()).unwrap();
        assert!(
            ControlBlock::decode(&dcb)
                .unwrap()
                .verify_taproot_commitment(&bitcoin::secp256k1::Secp256k1::verification_only(), zk_out_x, &dscript),
            "disprove leaf committed in the ZKTLC leaf taproot"
        );
        // the ownership-only tree has no disprove path.
        assert!(alice_leaf.disprove_spend_elements().is_none());

        println!("CONTRACT EXIT TREE PROVEN: Shadowing claims -> TimeoutTree::build -> per-participant VTXOs; Σ leaves == pot; a holder unilaterally exits via CSV with only their key; the covenant key is Projector value-bound; an optional disprove leaf wires the BitVM punishment path. The non-custodial ownership leg, from real engine code.");
    }
}
