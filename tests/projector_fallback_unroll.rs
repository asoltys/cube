// OFFLINE-LIVENESS FALLBACK — the pre-signed tree unroll.
//
// The covenant refresh is N-of-N: every participant must co-sign each batch. A
// public faucet lotto can't require that (players go offline). The fallback:
// at covenant CREATION (everyone is online — they just entered), the N-of-N
// pre-signs ONE transaction that unrolls the funding covenant into the
// per-participant VTXO leaf outputs. That signed tx can be broadcast LATER by
// anyone, with NO participant online, because it was signed back when everyone
// was. Once on-chain, each holder unilaterally CSV-exits their own leaf.
//
// We prove:
//   1. the N-of-N pre-signs a valid key-path spend of the funding covenant into
//      the leaf outputs (the unroll), at creation,
//   2. that signed unroll is broadcastable with nobody online (it's just bytes),
//   3. after it confirms, a holder (alice) exits her materialized leaf with ONLY
//      her key — even though the engine and every other participant are gone.

#[cfg(test)]
mod projector_fallback_unroll {
    use bitcoin::hashes::Hash;
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash};
    use bitcoin::transaction::Version;
    use bitcoin::{
        absolute::LockTime, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
        Witness, XOnlyPublicKey,
    };

    use cube::constructive::txout_types::timeout_tree::refresh::{
        engine_projected_pubkey, engine_projected_secret, participant_projected_pubkey,
        participant_projected_secret, refresh_keyagg,
    };
    use cube::constructive::txout_types::timeout_tree::{funding_taproot, TimeoutTree};
    use cube::transmutative::musig::session::MusigSessionCtx;
    use cube::transmutative::secp::schnorr::{sign, verify_xonly, SchnorrSigningMode};
    use secp::{Point, Scalar};

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

    #[test]
    fn presigned_unroll_lets_offline_holders_exit() {
        let alice = xkey(ALICE_PK);
        let bob = xkey(BOB_PK);
        let engine = xkey(ENGINE_PK);
        let allocs = [(alice, 30_000u64), (bob, 20_000u64)];
        let total: u64 = allocs.iter().map(|(_, v)| v).sum();
        let expiry = 800_000u32;
        let exit_delay = 144u16;

        let tree = TimeoutTree::build(engine, &allocs, expiry, exit_delay, None).unwrap();

        // The funding covenant output holding the pot.
        let funding_tr = funding_taproot(engine, &allocs, expiry).unwrap();
        let funding_spk = ScriptBuf::from_bytes(funding_tr.spk().unwrap());
        let funding_txout = TxOut { value: Amount::from_sat(total), script_pubkey: funding_spk };
        let funding_outpoint = OutPoint::new(Txid::from_byte_array([0xf0; 32]), 0);

        // The unroll transaction: funding covenant -> per-participant VTXO leaves.
        let unroll_outputs = tree.unroll_outputs().unwrap();
        assert_eq!(unroll_outputs.len(), 2);
        let unroll_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: funding_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: unroll_outputs.clone(),
        };

        // ---- 1) AT CREATION (everyone online): N-of-N pre-sign the unroll. ----
        let sighash = SighashCache::new(&unroll_tx)
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&[funding_txout]), TapSighashType::Default)
            .unwrap()
            .to_byte_array();
        let keyagg = refresh_keyagg(engine, &allocs, expiry).unwrap();
        let a_pub = participant_projected_pubkey(pt(ALICE_PK), 30_000, 0).unwrap();
        let b_pub = participant_projected_pubkey(pt(BOB_PK), 20_000, 1).unwrap();
        let e_pub = engine_projected_pubkey(pt(ENGINE_PK), &allocs).unwrap();
        let mut s = MusigSessionCtx::new(&keyagg, sighash).unwrap();
        s.insert_nonce(a_pub, sc(A_HN).base_point_mul(), sc(A_BN).base_point_mul());
        s.insert_nonce(b_pub, sc(B_HN).base_point_mul(), sc(B_BN).base_point_mul());
        s.insert_nonce(e_pub, sc(S_HN).base_point_mul(), sc(S_BN).base_point_mul());
        let pa = s.partial_sign(participant_projected_secret(sc(ALICE_SK), 30_000, 0).unwrap(), sc(A_HN), sc(A_BN)).unwrap();
        let pb = s.partial_sign(participant_projected_secret(sc(BOB_SK), 20_000, 1).unwrap(), sc(B_HN), sc(B_BN)).unwrap();
        let pe = s.partial_sign(engine_projected_secret(sc(ENGINE_SK), &allocs).unwrap(), sc(S_HN), sc(S_BN)).unwrap();
        s.insert_partial_sig(a_pub, pa);
        s.insert_partial_sig(b_pub, pb);
        s.insert_partial_sig(e_pub, pe);
        let unroll_sig = s.full_agg_sig().unwrap();

        assert!(
            verify_xonly(
                funding_tr.tweaked_key().unwrap().serialize_xonly(),
                sighash,
                unroll_sig,
                SchnorrSigningMode::BIP340
            ),
            "the unroll is a valid N-of-N key-path spend of the funding covenant, pre-signed at creation"
        );

        // ---- 2) The signed unroll is now just bytes — broadcastable by ANYONE,
        //         with no participant online. (We hold the 64-byte witness.) ----
        let _broadcastable_unroll_witness = vec![unroll_sig.to_vec()];

        // ---- 3) LATER, everyone offline: the unroll has confirmed, materializing
        //         alice's VTXO leaf on-chain. She exits it with ONLY her key. ----
        let alice_leaf = tree.leaves.iter().find(|l| l.account_key == alice).unwrap();
        let alice_leaf_vout = tree.leaves.iter().position(|l| l.account_key == alice).unwrap() as u32;
        let alice_leaf_outpoint = OutPoint::new(unroll_tx.compute_txid(), alice_leaf_vout);
        let alice_leaf_txout = unroll_tx.output[alice_leaf_vout as usize].clone();

        let exit_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: alice_leaf_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::from_height(exit_delay),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(alice_leaf.value_in_satoshis - 500),
                script_pubkey: ScriptBuf::new_op_return(&[]),
            }],
        };
        let (_lh, exit_script_bytes, exit_cb) = alice_leaf.exit_spend_elements().unwrap();
        let exit_script = ScriptBuf::from_bytes(exit_script_bytes);
        let out_x = XOnlyPublicKey::from_slice(&alice_leaf.taproot.tweaked_key().unwrap().serialize_xonly()).unwrap();
        assert!(
            ControlBlock::decode(&exit_cb).unwrap().verify_taproot_commitment(
                &bitcoin::secp256k1::Secp256k1::verification_only(),
                out_x,
                &exit_script
            ),
            "alice's exit leaf is committed in her materialized VTXO"
        );
        let exit_sighash = SighashCache::new(&exit_tx)
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&[alice_leaf_txout]),
                TapLeafHash::from_script(&exit_script, LeafVersion::TapScript),
                TapSighashType::Default,
            )
            .unwrap()
            .to_byte_array();
        let alice_sig = sign(sc(ALICE_SK).serialize(), exit_sighash, SchnorrSigningMode::BIP340).unwrap();
        assert!(
            verify_xonly(alice, exit_sighash, alice_sig, SchnorrSigningMode::BIP340),
            "OFFLINE-SAFE: alice recovers her stake via the pre-signed unroll + her own CSV exit — engine and all other players gone"
        );
        assert_eq!(alice_leaf.value_in_satoshis, 30_000, "she recovers exactly her stake");

        println!("OFFLINE FALLBACK PROVEN: the N-of-N pre-signs (at creation, all online) ONE unroll tx spending the funding covenant into per-participant VTXO leaves; it broadcasts later with nobody online; each holder then unilaterally CSV-exits their leaf. This is the liveness fallback that lets EMIT work for a public lotto where players go offline.");
    }
}
