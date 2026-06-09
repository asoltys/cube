// WINNER-SWEEP — the BitVM3 settle-enforced reattribution leg. On an HONEST
// settle the garbled winner-verifier's VALID output label is derivable by anyone
// evaluating the circuit on the true public draw; each LOSER leaf carries a
// winner-sweep path `OP_HASH160 <ripemd160(valid_hash)> EQUALVERIFY <winner>
// CHECKSIG`, so the proven winner sweeps the whole pot with NO cooperation from
// the losers. It is the exact mirror of the disprove path (which opens only on a
// WRONG settle, letting a defrauded holder reclaim their OWN leaf). The two are
// mutually exclusive: for a given draw exactly one of {valid, invalid} is ever
// derivable, so a sweep can never coexist with a disprove.
//
// This test drives the REAL garble (`WinnerVerifier`) and the REAL leaf
// (`TimeoutTree::build_with_sweep`) and proves, cryptographically:
//   1) the winner's OWN leaf has no winner-sweep path,
//   2) HONEST settle: the valid label opens a loser leaf's winner-sweep hashlock,
//      the winner's CHECKSIG verifies, and the control block commits the leaf,
//   3) WRONG settle: the invalid label opens the SAME loser leaf's disprove path
//      (leaf owner reclaims), and the valid label is NOT derivable,
//   4) cross-use is impossible: the valid label never opens disprove, the invalid
//      label never opens winner-sweep.

#[cfg(test)]
mod winner_sweep {
    use bitcoin::hashes::{ripemd160, Hash as _};
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash};
    use bitcoin::transaction::Version;
    use bitcoin::{absolute::LockTime, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, XOnlyPublicKey};

    use cube::constructive::txout_types::timeout_tree::TimeoutTree;
    use cube::transmutative::garble::WinnerVerifier;
    use cube::transmutative::hash::sha256;
    use cube::transmutative::secp::schnorr::{sign, verify_xonly, SchnorrSigningMode};

    // even-Y test keypairs (shared with tests/timeout_tree.rs).
    const ALICE_SK: &str = "1cc5906ab936b1e29db24fffe9f87b33a4c64f2d3b59aed6c3c4faeb8fcba6da";
    const ALICE_PK: &str = "02cb70281face51a77d51400612196032bb12422d4c07fa42997a0ab39c2431455";
    const BOB_SK: &str = "4882eef979baa5c88fd9e62c698de201f0a991af65877becf683e988f3024b0f";
    const BOB_PK: &str = "0251deb9fcf4d16b0f82c75cf71e1ffb7879beb0c6bf733b0778a81b777406574f";
    const ENGINE_PK: &str = "029611bc66d526fa3194d0f525dce21e782dcf90cc72529ec2d5486da838d83770";

    fn xb(pk: &str) -> [u8; 32] { hex::decode(&pk[2..]).unwrap().try_into().unwrap() }
    fn skb(h: &str) -> [u8; 32] { hex::decode(h).unwrap().try_into().unwrap() }
    fn hash160(b: &[u8]) -> [u8; 20] { ripemd160::Hash::hash(b).to_byte_array() }

    // Spend `prev` via the given tapscript leaf; return the BIP341 script-path
    // sighash so we can sign + verify it. Also asserts cube's reported tapleaf hash
    // matches rust-bitcoin's, so the witness leaf is exactly the committed one.
    fn script_path_sighash(prev: &TxOut, script: &ScriptBuf, cube_leaf_hash: [u8; 32]) -> [u8; 32] {
        let lh = TapLeafHash::from_script(script, LeafVersion::TapScript);
        assert_eq!(lh.to_byte_array(), cube_leaf_hash, "cube and rust-bitcoin agree on the tapleaf hash");
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: Txid::from_byte_array([0x77; 32]), vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut { value: Amount::from_sat(prev.value.to_sat() - 500), script_pubkey: ScriptBuf::new_op_return(&[]) }],
        };
        SighashCache::new(&tx)
            .taproot_script_spend_signature_hash(0, &Prevouts::All(&[prev.clone()]), lh, TapSighashType::Default)
            .unwrap()
            .to_byte_array()
    }

    #[test]
    fn winner_sweeps_losers_honestly_disprove_only_on_fraud() {
        // ---- a 2-entry round: alice stakes 1000, bob stakes 2000; bob wins. ----
        let engine = xb(ENGINE_PK);
        // allocations MUST be in the same (account-sorted) order the engine uses to
        // build the bands and the tree, so the winner INDEX lines up with the leaf.
        let mut allocs: Vec<([u8; 32], u64)> = vec![(xb(ALICE_PK), 1000), (xb(BOB_PK), 2000)];
        allocs.sort_by(|a, b| a.0.cmp(&b.0));
        let (mut lo, mut hi, mut acc) = (Vec::new(), Vec::new(), 0u64);
        for (_, v) in &allocs { lo.push(acc); acc += v; hi.push(acc); }

        let winner_idx = allocs.iter().position(|(k, _)| *k == xb(BOB_PK)).unwrap();
        let loser_idx = 1 - winner_idx;
        let winner_key = allocs[winner_idx].0; // bob
        let true_rg = lo[winner_idx]; // a draw position inside bob's band

        // ---- garble the real winner-verifier; derive the two output-label hashes.
        let v = WinnerVerifier::new(&lo, &hi);
        let wires = v.wires(0xC0FFEE);
        let tables = v.garble(&wires);
        let valid_hash = v.valid_hash(&wires);
        let disprove_hash = v.disprove_hash(&wires);
        assert_ne!(valid_hash, disprove_hash);

        // ---- build the SETTLE tree: every leaf disprove-locked to this round, and
        // every LOSER leaf additionally winner-sweep-locked to bob + valid_hash.
        let expiry = 800_000u32;
        let delay = 144u16;
        let dh = vec![disprove_hash; allocs.len()];
        let tree = TimeoutTree::build_with_sweep(
            engine, &allocs, expiry, delay, Some(&dh), Some((valid_hash, winner_key)),
        )
        .expect("settle tree");

        let winner_leaf = &tree.leaves[winner_idx];
        let loser_leaf = &tree.leaves[loser_idx];

        // (1) the winner's OWN leaf has no winner-sweep path; the loser's does.
        assert!(winner_leaf.winner_sweep_spend_elements().is_none(), "winner leaf must not be sweepable");
        assert!(loser_leaf.winner_sweep_spend_elements().is_some(), "loser leaf must be sweepable");
        // both leaves still carry the defensive disprove path.
        assert!(winner_leaf.disprove_spend_elements().is_some());
        assert!(loser_leaf.disprove_spend_elements().is_some());

        let loser_txout = TxOut {
            value: Amount::from_sat(loser_leaf.value_in_satoshis),
            script_pubkey: ScriptBuf::from_bytes(loser_leaf.scriptpubkey().unwrap()),
        };
        let loser_out_x = XOnlyPublicKey::from_slice(&loser_leaf.taproot.tweaked_key().unwrap().serialize_xonly()).unwrap();
        let secp = bitcoin::secp256k1::Secp256k1::verification_only();

        // ================= HONEST SETTLE =================
        let honest = v.assert_settle(&wires, &tables, true_rg, winner_idx as u32);
        // the winner derives the VALID label by evaluating the circuit on the draw.
        let valid_label = WinnerVerifier::winner_label(&honest, true_rg).unwrap().expect("honest -> valid label");
        // no disprove secret is available on an honest settle.
        assert!(WinnerVerifier::challenge(&honest, true_rg).unwrap().is_none(), "honest settle yields no disprove secret");

        // (2) the valid label opens the loser leaf's winner-sweep hashlock...
        let (sweep_lh, sweep_script, sweep_cb) = loser_leaf.winner_sweep_spend_elements().unwrap();
        // OP_HASH160(valid_label) == ripemd160(valid_hash), the value baked in the script.
        assert_eq!(hash160(&sha256(&valid_label)), hash160(&valid_hash), "valid label opens the winner-sweep lock");
        // ...and only with the WINNER's signature.
        let sweep_buf = ScriptBuf::from_bytes(sweep_script.clone());
        assert!(ControlBlock::decode(&sweep_cb).unwrap()
            .verify_taproot_commitment(&secp, loser_out_x, &sweep_buf), "winner-sweep leaf is committed in the loser VTXO");
        let sweep_sighash = script_path_sighash(&loser_txout, &sweep_buf, sweep_lh);
        let winner_sig = sign(skb(BOB_SK), sweep_sighash, SchnorrSigningMode::BIP340).unwrap();
        assert!(verify_xonly(winner_key, sweep_sighash, winner_sig, SchnorrSigningMode::BIP340),
            "WINNER-SWEEP: bob spends the loser's leaf with the valid label + his key — no loser cooperation");
        // the on-chain witness the winner broadcasts:
        let _sweep_witness = vec![winner_sig.to_vec(), valid_label.to_vec(), sweep_script.clone(), sweep_cb.clone()];

        // (4a) the valid label must NOT open the disprove path.
        assert_ne!(hash160(&sha256(&valid_label)), hash160(&disprove_hash), "valid label can never disprove");

        // ================= WRONG SETTLE (fraud) =================
        // the engine claims the LOSER won; a challenger derives the disprove secret.
        let wrong = v.assert_settle(&wires, &tables, true_rg, loser_idx as u32);
        let invalid_label = WinnerVerifier::challenge(&wrong, true_rg).unwrap().expect("fraud -> disprove secret");
        // no valid (sweep) label is available on a fraudulent settle.
        assert!(WinnerVerifier::winner_label(&wrong, true_rg).unwrap().is_none(), "fraud yields no winner-sweep secret");

        // (3) the invalid label opens the loser leaf's DISPROVE path (owner reclaim).
        let (dis_lh, dis_script, dis_cb) = loser_leaf.disprove_spend_elements().unwrap();
        assert_eq!(hash160(&sha256(&invalid_label)), hash160(&disprove_hash), "invalid label opens the disprove lock");
        let dis_buf = ScriptBuf::from_bytes(dis_script.clone());
        assert!(ControlBlock::decode(&dis_cb).unwrap()
            .verify_taproot_commitment(&secp, loser_out_x, &dis_buf), "disprove leaf is committed in the loser VTXO");
        let dis_sighash = script_path_sighash(&loser_txout, &dis_buf, dis_lh);
        // the disprove path is keyed to the LEAF OWNER (the loser, alice).
        let loser_key = allocs[loser_idx].0;
        let loser_sig = sign(skb(ALICE_SK), dis_sighash, SchnorrSigningMode::BIP340).unwrap();
        assert!(verify_xonly(loser_key, dis_sighash, loser_sig, SchnorrSigningMode::BIP340),
            "DISPROVE: on fraud the loser reclaims their OWN leaf with the invalid label + their key");

        // (4b) the invalid label must NOT open the winner-sweep path.
        assert_ne!(hash160(&sha256(&invalid_label)), hash160(&valid_hash), "invalid label can never sweep");

        println!("WINNER-SWEEP proven: honest settle -> the proven winner sweeps every loser leaf with the garbled VALID label (no loser cooperation); a wrong settle exposes the INVALID label instead, letting each loser reclaim their own leaf via disprove. The two paths are mutually exclusive by construction.");
    }
}
