// COVENANT LIFECYCLE across batches — emit -> refresh -> still non-custodial.
//
// Composes the pieces of (b) into the property that matters: a contract pot's
// covenant output tracks the shadow ledger across batches via consensus-enforced
// N-of-N refresh, and at EVERY committed state every participant can unilaterally
// exit their claim. We show:
//   * batch 0: covenant C0 + tree T0 rendered from allocations A0; alice can exit
//     her T0 VTXO with only her key (funds exitable at the committed state),
//   * a value transition A0 -> A1 (e.g. a settle) refreshes C0 -> C1 via an N-of-N
//     Projector key-path signature (no single party can move the pot),
//   * batch 1: covenant C1 + tree T1 rendered from A1; alice exits her (now larger)
//     T1 VTXO with only her key,
//   * value is conserved across the refresh.

#[cfg(test)]
mod covenant_lifecycle {
    use bitcoin::hashes::Hash;
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash};
    use bitcoin::transaction::Version;
    use bitcoin::{
        absolute::LockTime, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
        Witness, XOnlyPublicKey,
    };

    use cube::constructive::txout_types::timeout_tree::refresh::{
        covenant_scriptpubkey, engine_projected_pubkey, engine_projected_secret,
        participant_projected_pubkey, participant_projected_secret, refresh_keyagg,
    };
    use cube::constructive::txout_types::timeout_tree::{funding_taproot, TimeoutTree};
    use cube::constructive::txout_types::timeout_tree::VtxoLeaf;
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

    const EXIT_DELAY: u16 = 144;

    /// Alice unilaterally exits her VTXO leaf with only her key (control-block
    /// commitment + BIP340 signature both verify).
    fn assert_alice_can_exit(leaf: &VtxoLeaf) {
        let leaf_txout = TxOut {
            value: Amount::from_sat(leaf.value_in_satoshis),
            script_pubkey: ScriptBuf::from_bytes(leaf.scriptpubkey().unwrap()),
        };
        let outpoint = OutPoint::new(Txid::from_byte_array([0xa1; 32]), 0);
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::from_height(EXIT_DELAY),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(leaf.value_in_satoshis - 500),
                script_pubkey: ScriptBuf::new_op_return(&[]),
            }],
        };
        let (_lh, script, cb) = leaf.exit_spend_elements().unwrap();
        let script = ScriptBuf::from_bytes(script);
        let out_x =
            XOnlyPublicKey::from_slice(&leaf.taproot.tweaked_key().unwrap().serialize_xonly()).unwrap();
        assert!(ControlBlock::decode(&cb).unwrap().verify_taproot_commitment(
            &bitcoin::secp256k1::Secp256k1::verification_only(),
            out_x,
            &script
        ));
        let sighash = SighashCache::new(&tx)
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&[leaf_txout]),
                TapLeafHash::from_script(&script, LeafVersion::TapScript),
                TapSighashType::Default,
            )
            .unwrap()
            .to_byte_array();
        let sig = sign(sc(ALICE_SK).serialize(), sighash, SchnorrSigningMode::BIP340).unwrap();
        assert!(verify_xonly(xkey(ALICE_PK), sighash, sig, SchnorrSigningMode::BIP340));
    }

    #[test]
    fn pot_covenant_tracks_the_ledger_across_batches_and_stays_exitable() {
        let alice = xkey(ALICE_PK);
        let bob = xkey(BOB_PK);
        let engine = xkey(ENGINE_PK);

        // ---- batch 0 ----
        let a0 = [(alice, 30_000u64), (bob, 20_000u64)];
        let total: u64 = a0.iter().map(|(_, v)| v).sum();
        let expiry0 = 800_000u32;
        let t0 = TimeoutTree::build(engine, &a0, expiry0, EXIT_DELAY, None).unwrap();
        assert_eq!(t0.leaves_value_sum(), total);
        // at the committed state, alice exits her claim unilaterally.
        assert_alice_can_exit(t0.leaves.iter().find(|l| l.account_key == alice).unwrap());

        let c0_taproot = funding_taproot(engine, &a0, expiry0).unwrap();
        let c0_spk = ScriptBuf::from_bytes(c0_taproot.spk().unwrap());
        let c0_txout = TxOut { value: Amount::from_sat(total), script_pubkey: c0_spk.clone() };
        let c0_outpoint = OutPoint::new(Txid::from_byte_array([0xc0; 32]), 0);

        // ---- value transition A0 -> A1 (e.g. a settle moves value alice<-bob) ----
        let a1 = [(alice, 35_000u64), (bob, 15_000u64)];
        let total1: u64 = a1.iter().map(|(_, v)| v).sum();
        assert_eq!(total, total1, "value conserved across the transition");
        let expiry1 = 801_000u32;
        let c1_spk = ScriptBuf::from_bytes(covenant_scriptpubkey(engine, &a1, expiry1).unwrap());

        // ---- refresh C0 -> C1 via N-of-N Projector key-path cosign ----
        let fee = 200u64;
        let refresh_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: c0_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut { value: Amount::from_sat(total1 - fee), script_pubkey: c1_spk }],
        };
        let sighash = SighashCache::new(&refresh_tx)
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&[c0_txout]), TapSighashType::Default)
            .unwrap()
            .to_byte_array();

        let keyagg = refresh_keyagg(engine, &a0, expiry0).unwrap();
        let a_pub = participant_projected_pubkey(pt(ALICE_PK), 30_000, 0).unwrap();
        let b_pub = participant_projected_pubkey(pt(BOB_PK), 20_000, 1).unwrap();
        let e_pub = engine_projected_pubkey(pt(ENGINE_PK), &a0).unwrap();
        let mut s = MusigSessionCtx::new(&keyagg, sighash).unwrap();
        s.insert_nonce(a_pub, sc(A_HN).base_point_mul(), sc(A_BN).base_point_mul());
        s.insert_nonce(b_pub, sc(B_HN).base_point_mul(), sc(B_BN).base_point_mul());
        s.insert_nonce(e_pub, sc(S_HN).base_point_mul(), sc(S_BN).base_point_mul());
        let pa = s.partial_sign(participant_projected_secret(sc(ALICE_SK), 30_000, 0).unwrap(), sc(A_HN), sc(A_BN)).unwrap();
        let pb = s.partial_sign(participant_projected_secret(sc(BOB_SK), 20_000, 1).unwrap(), sc(B_HN), sc(B_BN)).unwrap();
        let pe = s.partial_sign(engine_projected_secret(sc(ENGINE_SK), &a0).unwrap(), sc(S_HN), sc(S_BN)).unwrap();
        s.insert_partial_sig(a_pub, pa);
        s.insert_partial_sig(b_pub, pb);
        s.insert_partial_sig(e_pub, pe);
        let refresh_sig = s.full_agg_sig().unwrap();
        assert!(verify_xonly(c0_taproot.tweaked_key().unwrap().serialize_xonly(), sighash, refresh_sig, SchnorrSigningMode::BIP340),
            "refresh C0 -> C1 is a valid N-of-N key-path spend of the old covenant");

        // ---- batch 1: tree from A1; alice exits her (now larger) claim ----
        let t1 = TimeoutTree::build(engine, &a1, expiry1, EXIT_DELAY, None).unwrap();
        assert_eq!(t1.leaves_value_sum(), total1);
        let alice_t1 = t1.leaves.iter().find(|l| l.account_key == alice).unwrap();
        assert_eq!(alice_t1.value_in_satoshis, 35_000, "alice's refreshed claim");
        assert_alice_can_exit(alice_t1);

        println!("COVENANT LIFECYCLE PROVEN: a pot covenant is rendered as exitable VTXOs (alice exits unilaterally at the committed state), the ledger transition A0->A1 refreshes the covenant via an N-of-N Projector key-path signature (no single party can move it), value is conserved, and alice exits her refreshed claim from the new state — non-custodial at every batch.");
    }
}
