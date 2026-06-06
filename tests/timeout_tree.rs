// Exploring TIMEOUT TREES — the ownership/unilateral-exit primitive beneath a
// ZKTLC (Ark's design, per bark's lib/src/tree). A pre-signed transaction tree
// lets many virtual outputs (VTXOs) share one on-chain settlement while each
// holder keeps a unilateral path to Bitcoin.
//
// Structure of each node output (taproot):
//   * key path  = MuSig2 aggregate of all cosigners — the cooperative/refresh path
//   * script path "expiry"  = <height> CLTV DROP <server> CHECKSIG  (server
//     reclaims unrefreshed funds after expiry — anti-griefing / recycle)
//   * leaf also has script path "exit" = <delay> CSV DROP <user> CHECKSIG  (the
//     VTXO holder spends unilaterally after a delay once the leaf is on-chain)
//
// We build a 1-root -> 2-leaf tree with cube's TapRoot + MuSig2 and prove the
// three spend paths cryptographically:
//   1) the round COSIGN (3-party MuSig key-path spend of the funding output that
//      creates the tree tx) — this fixes the pre-signed tree,
//   2) a leaf holder's UNILATERAL EXIT (CSV script path, user key only),
//   3) the server EXPIRY reclaim (CLTV script path, server key only).

#[cfg(test)]
mod timeout_tree {
    use bitcoin::hashes::Hash;
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CSV, OP_CLTV, OP_DROP};
    use bitcoin::script::Builder;
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash};
    use bitcoin::transaction::Version;
    use bitcoin::{absolute::LockTime, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, XOnlyPublicKey};

    use cube::constructive::taproot::{TapLeaf, TapRoot};
    use cube::transmutative::musig::keyagg::MusigKeyAggCtx;
    use cube::transmutative::musig::session::MusigSessionCtx;
    use cube::transmutative::secp::into::IntoPoint;
    use cube::transmutative::secp::schnorr::{sign, verify_xonly, SchnorrSigningMode};
    use secp::{Point, Scalar};

    // alice, bob (leaf holders), server — even-Y keypairs + nonces from tests/musig.rs.
    const ALICE_SK: &str = "1cc5906ab936b1e29db24fffe9f87b33a4c64f2d3b59aed6c3c4faeb8fcba6da";
    const ALICE_PK: &str = "02cb70281face51a77d51400612196032bb12422d4c07fa42997a0ab39c2431455";
    const BOB_PK: &str = "0251deb9fcf4d16b0f82c75cf71e1ffb7879beb0c6bf733b0778a81b777406574f";
    const SERVER_PK: &str = "029611bc66d526fa3194d0f525dce21e782dcf90cc72529ec2d5486da838d83770";
    // per-party nonce secrets (hiding, binding) for the 3-party cosign
    const A_HN: &str = "e2d64e2bd20d5843d03a47199f059aebdf2a9904616a01fe961ee875a7748199";
    const A_BN: &str = "4b978d3aac4135213f536194522f68fbb2ca4321a49d95560ae9726cd9d6a55d";
    const B_SK: &str = "4882eef979baa5c88fd9e62c698de201f0a991af65877becf683e988f3024b0f";
    const B_HN: &str = "d3b9f2f01f7caa9b0fe2e932ae752f71da9f8f1a652ec895504091333b97d007";
    const B_BN: &str = "961a4d128a1f3cb5c41e71bc86fdc9e81050b7471f05112a6a5360a2240ff3cf";
    const S_SK: &str = "2c71bfbd0389b96e292b37c2272ea846655cfb48578b06600c0ffd991f6f7e29";
    const S_HN: &str = "cf2087a05db9aad43ae97aba584f8d8cb9d61fb84c39f372ea72bdd1d272ab81";
    const S_BN: &str = "4025f894ab8712c244e38af85094043e025824a0d021cd6fb9709fc9ef739e45";

    fn pt(h: &str) -> Point { Point::from_hex(h).unwrap() }
    fn sc(h: &str) -> Scalar { Scalar::from_hex(h).unwrap() }
    fn xonly(h: &str) -> XOnlyPublicKey { XOnlyPublicKey::from_slice(&hex::decode(&h[2..]).unwrap()).unwrap() }

    // Ark's expiry clause: <height> OP_CLTV OP_DROP <pk> OP_CHECKSIG.
    fn timelock_sign(height: u32, pk: &XOnlyPublicKey) -> ScriptBuf {
        Builder::new()
            .push_int(LockTime::from_height(height).unwrap().to_consensus_u32() as i64)
            .push_opcode(OP_CLTV).push_opcode(OP_DROP)
            .push_x_only_key(pk).push_opcode(OP_CHECKSIG)
            .into_script()
    }
    // Ark's exit clause: <delay> OP_CSV OP_DROP <pk> OP_CHECKSIG.
    fn delayed_sign(delay: u16, pk: &XOnlyPublicKey) -> ScriptBuf {
        Builder::new()
            .push_int(Sequence::from_height(delay).to_consensus_u32() as i64)
            .push_opcode(OP_CSV).push_opcode(OP_DROP)
            .push_x_only_key(pk).push_opcode(OP_CHECKSIG)
            .into_script()
    }

    fn leaf(script: &ScriptBuf) -> TapLeaf { TapLeaf::new(script.to_bytes()) }

    #[test]
    fn timeout_tree_cosign_unilateral_exit_and_expiry() {
        let alice = pt(ALICE_PK);
        let bob = pt(BOB_PK);
        let server = pt(SERVER_PK);
        let server_x = xonly(SERVER_PK);
        let alice_x = xonly(ALICE_PK);
        let expiry_height = 700_000u32;
        let exit_delay = 144u16; // ~1 day of blocks

        // ---- 1) ROUND COSIGN: the funding output is key-path = MuSig(all 3) with
        // a server expiry script path; the round cosigns the tree tx that spends it. ----
        let funding_inner = MusigKeyAggCtx::new(&vec![alice, bob, server], None).unwrap().agg_inner_key();
        let funding_expiry = timelock_sign(expiry_height, &server_x);
        let funding_taproot = TapRoot::key_and_script_path_single(funding_inner, leaf(&funding_expiry));
        let funding_spk = ScriptBuf::from_bytes(funding_taproot.spk().unwrap());
        let funding_txout = TxOut { value: Amount::from_sat(100_000), script_pubkey: funding_spk };
        let funding_outpoint = OutPoint { txid: Txid::from_byte_array([0xf0; 32]), vout: 0 };

        // two leaf VTXO outputs (one per holder).
        let leaf_spk = |user: Point, user_x: &XOnlyPublicKey| -> ScriptBuf {
            let inner = MusigKeyAggCtx::new(&vec![user, server], None).unwrap().agg_inner_key();
            let tr = TapRoot::key_and_script_path_multi(
                inner,
                vec![leaf(&timelock_sign(expiry_height, &server_x)), leaf(&delayed_sign(exit_delay, user_x))],
            );
            ScriptBuf::from_bytes(tr.spk().unwrap())
        };
        let tree_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn { previous_output: funding_outpoint, script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() }],
            output: vec![
                TxOut { value: Amount::from_sat(49_500), script_pubkey: leaf_spk(alice, &alice_x) },
                TxOut { value: Amount::from_sat(49_500), script_pubkey: leaf_spk(bob, &xonly(BOB_PK)) },
            ],
        };
        // key-path sighash of the tree tx + 3-party MuSig cosign (with the taproot tweak).
        let tree_sighash = SighashCache::new(&tree_tx)
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&[funding_txout]), TapSighashType::Default)
            .unwrap().to_byte_array();
        let tweak = Scalar::from_slice(&funding_taproot.tap_tweak()).unwrap();
        let keyagg = MusigKeyAggCtx::new(&vec![alice, bob, server], Some(tweak)).unwrap();
        let mut s = MusigSessionCtx::new(&keyagg, tree_sighash).unwrap();
        assert!(s.insert_nonce(alice, sc(A_HN).base_point_mul(), sc(A_BN).base_point_mul()));
        assert!(s.insert_nonce(bob, sc(B_HN).base_point_mul(), sc(B_BN).base_point_mul()));
        assert!(s.insert_nonce(server, sc(S_HN).base_point_mul(), sc(S_BN).base_point_mul()));
        let pa = s.partial_sign(sc(ALICE_SK), sc(A_HN), sc(A_BN)).unwrap();
        let pb = s.partial_sign(sc(B_SK), sc(B_HN), sc(B_BN)).unwrap();
        let ps = s.partial_sign(sc(S_SK), sc(S_HN), sc(S_BN)).unwrap();
        assert!(s.insert_partial_sig(alice, pa));
        assert!(s.insert_partial_sig(bob, pb));
        assert!(s.insert_partial_sig(server, ps));
        let tree_cosig = s.full_agg_sig().unwrap();
        assert!(verify_xonly(keyagg.agg_key().serialize_xonly(), tree_sighash, tree_cosig, SchnorrSigningMode::BIP340),
            "round cosign: 3-party MuSig key-path spend of the funding output is valid (fixes the pre-signed tree)");

        // ---- 2) UNILATERAL EXIT: alice's leaf is on-chain (after broadcasting the
        // pre-signed tree tx); she spends it via the CSV exit clause with ONLY her key. ----
        let alice_inner = MusigKeyAggCtx::new(&vec![alice, server], None).unwrap().agg_inner_key();
        let exit_script = delayed_sign(exit_delay, &alice_x);
        let leaf_taproot = TapRoot::key_and_script_path_multi(
            alice_inner,
            vec![leaf(&timelock_sign(expiry_height, &server_x)), leaf(&exit_script)],
        );
        let alice_leaf_txout = TxOut { value: Amount::from_sat(49_500), script_pubkey: ScriptBuf::from_bytes(leaf_taproot.spk().unwrap()) };
        let alice_leaf_outpoint = OutPoint { txid: Txid::from_byte_array([0xa1; 32]), vout: 0 };
        let exit_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn { previous_output: alice_leaf_outpoint, script_sig: ScriptBuf::new(), sequence: Sequence::from_height(exit_delay), witness: Witness::new() }],
            output: vec![TxOut { value: Amount::from_sat(49_000), script_pubkey: bitcoin::ScriptBuf::new_op_return(&[]) }],
        };
        // exit clause is leaf index 1 in the taproot tree.
        let exit_script_buf = ScriptBuf::from_bytes(exit_script.to_bytes());
        let exit_leaf_hash = TapLeafHash::from_script(&exit_script_buf, LeafVersion::TapScript);
        // cube and rust-bitcoin agree on the leaf hash:
        let (cube_leaf_hash, _ts, control_block_bytes) = {
            let tree = leaf_taproot.tree().unwrap();
            let l = &tree.leaves()[1];
            (l.tapleaf_hash(), l.tap_script(), leaf_taproot.control_block(1).unwrap().to_vec())
        };
        assert_eq!(cube_leaf_hash, exit_leaf_hash.to_byte_array());
        let output_x = XOnlyPublicKey::from_slice(&leaf_taproot.tweaked_key().unwrap().serialize_xonly()).unwrap();
        assert!(ControlBlock::decode(&control_block_bytes).unwrap()
            .verify_taproot_commitment(&bitcoin::secp256k1::Secp256k1::verification_only(), output_x, &exit_script_buf),
            "exit leaf is committed in alice's VTXO taproot");
        let exit_sighash = SighashCache::new(&exit_tx)
            .taproot_script_spend_signature_hash(0, &Prevouts::All(&[alice_leaf_txout.clone()]), exit_leaf_hash, TapSighashType::Default)
            .unwrap().to_byte_array();
        let alice_sig = sign(sc(ALICE_SK).serialize(), exit_sighash, SchnorrSigningMode::BIP340).unwrap();
        assert!(verify_xonly(alice_x.serialize(), exit_sighash, alice_sig, SchnorrSigningMode::BIP340),
            "UNILATERAL EXIT: alice spends her VTXO via CSV with only her key — no server, no other holders");

        // ---- 3) SERVER EXPIRY reclaim: server spends the same leaf via the CLTV
        // expiry clause (leaf index 0) after expiry_height, with only its key. ----
        let expiry_script = ScriptBuf::from_bytes(timelock_sign(expiry_height, &server_x).to_bytes());
        let expiry_leaf_hash = TapLeafHash::from_script(&expiry_script, LeafVersion::TapScript);
        let reclaim_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::from_height(expiry_height).unwrap(),
            input: vec![TxIn { previous_output: alice_leaf_outpoint, script_sig: ScriptBuf::new(), sequence: Sequence::ENABLE_LOCKTIME_NO_RBF, witness: Witness::new() }],
            output: vec![TxOut { value: Amount::from_sat(49_000), script_pubkey: bitcoin::ScriptBuf::new_op_return(&[]) }],
        };
        let reclaim_sighash = SighashCache::new(&reclaim_tx)
            .taproot_script_spend_signature_hash(0, &Prevouts::All(&[alice_leaf_txout]), expiry_leaf_hash, TapSighashType::Default)
            .unwrap().to_byte_array();
        let server_sig = sign(sc(S_SK).serialize(), reclaim_sighash, SchnorrSigningMode::BIP340).unwrap();
        assert!(verify_xonly(server_x.serialize(), reclaim_sighash, server_sig, SchnorrSigningMode::BIP340),
            "SERVER EXPIRY: server reclaims an unrefreshed VTXO via CLTV after expiry (anti-griefing)");

        println!("TIMEOUT TREE EXPLORED: round 3-party cosign fixes the pre-signed tree; a leaf holder exits unilaterally via CSV (no server); the server reclaims via CLTV after expiry. This is the ownership/exit leg of a ZKTLC.");
    }
}
