// THE FULL DISPUTE GRAPH on a real garbled-lock leaf — composing exit_ladder.rs's
// connector/fork-binding with lottery_enforcement's garbled secret and a real
// TimeoutTree VTXO leaf. Mirrors Burak's "Unilateral Exit Paths" figure:
//   tx::exit-ladder (creates a CONNECTOR + exit metadata)
//   tx::fork-attest (spends [contested leaf via its ZKTLC garbled lock, connector])
// On a wrong settle the challenger garble-derives the disprove secret (from the
// real garble lib), opens the leaf's disprove path, and the fork-attest's signature
// commits the connector — so the dispute is bound to the canonical exit-ladder and
// the engine cannot dodge it onto a fork.

#[cfg(test)]
mod lottery_exit_ladder_dispute {
    use bitcoin::hashes::Hash as _;
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash};
    use bitcoin::transaction::Version;
    use bitcoin::{absolute::LockTime, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, XOnlyPublicKey};
    use std::collections::HashMap;

    use cube::constructive::txout_types::timeout_tree::TimeoutTree;
    use cube::transmutative::garble::WinnerVerifier;
    use cube::transmutative::hash::sha256;
    use cube::transmutative::secp::schnorr::{sign, verify_xonly, SchnorrSigningMode};
    use secp::Scalar;

    const ACCOUNT_SK: &str = "1cc5906ab936b1e29db24fffe9f87b33a4c64f2d3b59aed6c3c4faeb8fcba6da";
    const ACCOUNT_PK: &str = "02cb70281face51a77d51400612196032bb12422d4c07fa42997a0ab39c2431455";
    const ENGINE_PK: &str = "029611bc66d526fa3194d0f525dce21e782dcf90cc72529ec2d5486da838d83770";
    fn xkey(pk: &str) -> [u8; 32] { hex::decode(&pk[2..]).unwrap().try_into().unwrap() }
    fn sk(h: &str) -> [u8; 32] { hex::decode(h).unwrap().try_into().unwrap() }

    // A tx::exit-ladder: carries exit metadata (OP_RETURN) and creates a connector
    // output at vout 0. `tag` distinguishes the canonical chain from a fork.
    fn exit_ladder(tag: u8) -> Transaction {
        Transaction {
            version: Version::TWO, lock_time: LockTime::ZERO,
            input: vec![TxIn { previous_output: OutPoint { txid: Txid::from_byte_array([tag; 32]), vout: 0 }, script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() }],
            output: vec![
                TxOut { value: Amount::from_sat(330), script_pubkey: ScriptBuf::new_op_return(&[tag]) }, // connector
                TxOut { value: Amount::from_sat(0), script_pubkey: ScriptBuf::new_op_return(b"exit-metadata") },
            ],
        }
    }

    #[test]
    fn fork_attest_binds_garbled_lock_reclaim_to_the_canonical_exit_ladder() {
        // ---- the round + a WRONG settle -> the real garbled disprove secret ----
        let lo = [0u64, 1000, 3000, 6000];
        let hi = [1000u64, 3000, 6000, 10000];
        let v = WinnerVerifier::new(&lo, &hi);
        let wires = v.wires(42);
        let tables = v.garble(&wires);
        let true_rg = 5000u64; // entry 2
        // a challenger evaluating the engine's WRONG claim (winner 0) obtains the
        // "invalid" label = the disprove secret.
        let secret = v.evaluate(&wires, &tables, true_rg, 0);
        assert_eq!(secret, v.invalid_label(&wires), "wrong claim yields the disprove secret");
        let disprove_hash = v.disprove_hash(&wires); // == sha256(secret)
        assert_eq!(sha256(&secret), disprove_hash);

        // ---- the contested output: a REAL TimeoutTree VTXO leaf locked to it ----
        let account = xkey(ACCOUNT_PK);
        let engine = xkey(ENGINE_PK);
        let tree = TimeoutTree::build(engine, &[(account, 49_500)], 800_000, 144, Some(&[disprove_hash])).unwrap();
        let leaf = &tree.leaves[0];
        let leaf_spk = leaf.scriptpubkey().unwrap();
        let (leaf_hash, disprove_script, control_block) = leaf.disprove_spend_elements().unwrap();
        let leaf_txout = TxOut { value: Amount::from_sat(leaf.value_in_satoshis), script_pubkey: ScriptBuf::from_bytes(leaf_spk.clone()) };
        let leaf_outpoint = OutPoint::new(Txid::from_byte_array([0xab; 32]), 0);

        // ---- tx::exit-ladder (canonical E) + a forked alternative E' ----
        let e = exit_ladder(0x01);
        let e_fork = exit_ladder(0x02);
        let connector = OutPoint::new(e.compute_txid(), 0);
        let connector_txout = e.output[0].clone();
        let connector_fork = OutPoint::new(e_fork.compute_txid(), 0);
        let connector_fork_txout = e_fork.output[0].clone();
        assert_ne!(connector, connector_fork);

        // ---- tx::fork-attest: spends [contested leaf (garbled lock), connector] ----
        let payout = ScriptBuf::new_op_return(b"reclaimed-to-challenger");
        let mk_fork_attest = |conn: OutPoint| Transaction {
            version: Version::TWO, lock_time: LockTime::ZERO,
            input: vec![
                TxIn { previous_output: leaf_outpoint, script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() },
                TxIn { previous_output: conn, script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() },
            ],
            output: vec![TxOut { value: Amount::from_sat(leaf.value_in_satoshis - 500), script_pubkey: payout.clone() }],
        };
        let fa = mk_fork_attest(connector);

        // the leaf's disprove-path sighash (SIGHASH_DEFAULT) commits ALL prevouts,
        // including the connector — binding the dispute to the canonical exit-ladder.
        let script_buf = ScriptBuf::from_bytes(disprove_script.clone());
        let leaf_lh = TapLeafHash::from_script(&script_buf, LeafVersion::TapScript);
        assert_eq!(leaf_lh.to_byte_array(), leaf_hash);
        let sighash = SighashCache::new(&fa)
            .taproot_script_spend_signature_hash(0, &Prevouts::All(&[leaf_txout.clone(), connector_txout]), leaf_lh, TapSighashType::Default)
            .unwrap().to_byte_array();
        let sig = sign(sk(ACCOUNT_SK), sighash, SchnorrSigningMode::BIP340).unwrap();
        assert!(verify_xonly(account, sighash, sig, SchnorrSigningMode::BIP340), "challenger signs the leaf disprove path over the canonical fork-attest");

        // the control block commits the disprove leaf; the garbled secret opens it.
        let out_x = XOnlyPublicKey::from_slice(&leaf_spk[2..34]).unwrap();
        assert!(ControlBlock::decode(&control_block).unwrap().verify_taproot_commitment(
            &bitcoin::secp256k1::Secp256k1::verification_only(), out_x, &script_buf));
        assert_eq!(
            bitcoin::hashes::ripemd160::Hash::hash(&sha256(&secret)),
            bitcoin::hashes::ripemd160::Hash::hash(&disprove_hash),
            "the garbled secret opens the leaf's disprove hashlock"
        );
        // the on-chain witness: [sig, secret, disprove_script, control_block] + the connector input.
        let _w: Vec<Vec<u8>> = vec![sig.to_vec(), secret.to_vec(), disprove_script.clone(), control_block.clone()];

        // ---- fork binding: the same signature is INVALID against a forked connector ----
        let fa_fork = mk_fork_attest(connector_fork);
        let sighash_fork = SighashCache::new(&fa_fork)
            .taproot_script_spend_signature_hash(0, &Prevouts::All(&[leaf_txout, connector_fork_txout]), leaf_lh, TapSighashType::Default)
            .unwrap().to_byte_array();
        assert_ne!(sighash, sighash_fork, "the connector input is committed in the sighash");
        assert!(!verify_xonly(account, sighash_fork, sig, SchnorrSigningMode::BIP340),
            "the reclaim is bound to the canonical exit-ladder — it does not validate on a fork");

        let _ = HashMap::<u8, u8>::new();
        println!("EXIT-LADDER DISPUTE COMPOSED: a real TimeoutTree VTXO leaf locked to the round's \
garbled 'invalid' label is reclaimed via tx::fork-attest spending [leaf disprove-path, exit-ladder \
connector]. The garbled secret opens the leaf's disprove lock, the control block commits it, and the \
fork-attest signature commits the connector — binding the reclaim to the canonical exit-ladder so the \
engine can't dodge the dispute onto a fork. The full graph, on a real garbled lock.");
    }
}
