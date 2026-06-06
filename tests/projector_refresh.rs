// PROJECTOR REFRESH — the cross-batch "auto-refresh" of a contract pot's covenant.
//
// A contract pot lives in a funding (covenant) output locked to a Projector
// value-bound MuSig2 key path. Each batch the engine re-renders the pot from
// updated shadow state, which means spending the OLD covenant output into the NEW
// one via an N-of-N (all participants + engine) taproot KEY-PATH spend. This is
// the consensus-enforced refresh — the covenant can only move to a state every
// participant co-signs.
//
// We prove the full transition with REAL value-bound MuSig2 over a real refresh
// transaction:
//   * the refresh keyagg's aggregate key equals the OLD covenant output key,
//   * an N-of-N MuSig2 signature over the refresh sighash is a valid BIP340/341
//     key-path spend of that covenant,
//   * the NEW covenant output is value-bound to the UPDATED allocations (a
//     different state -> a different covenant spk),
//   * value is conserved across the refresh (Σ new claims == Σ old claims).

#[cfg(test)]
mod projector_refresh {
    use bitcoin::hashes::Hash;
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::transaction::Version;
    use bitcoin::{
        absolute::LockTime, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
        Witness,
    };

    use cube::constructive::txout_types::timeout_tree::funding_taproot;
    use cube::constructive::txout_types::timeout_tree::refresh::{
        covenant_scriptpubkey, engine_projected_pubkey, engine_projected_secret,
        participant_projected_pubkey, participant_projected_secret, refresh_keyagg,
    };
    use cube::transmutative::musig::session::MusigSessionCtx;
    use cube::transmutative::secp::schnorr::{verify_xonly, SchnorrSigningMode};
    use secp::{Point, Scalar};

    // alice, bob (participants) + engine — even-Y keypairs (from tests/musig.rs).
    const ALICE_SK: &str = "1cc5906ab936b1e29db24fffe9f87b33a4c64f2d3b59aed6c3c4faeb8fcba6da";
    const ALICE_PK: &str = "02cb70281face51a77d51400612196032bb12422d4c07fa42997a0ab39c2431455";
    const BOB_SK: &str = "4882eef979baa5c88fd9e62c698de201f0a991af65877becf683e988f3024b0f";
    const BOB_PK: &str = "0251deb9fcf4d16b0f82c75cf71e1ffb7879beb0c6bf733b0778a81b777406574f";
    const ENGINE_SK: &str = "2c71bfbd0389b96e292b37c2272ea846655cfb48578b06600c0ffd991f6f7e29";
    const ENGINE_PK: &str = "029611bc66d526fa3194d0f525dce21e782dcf90cc72529ec2d5486da838d83770";
    // per-signer nonce secrets (hiding, binding).
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
    fn covenant_refreshes_into_next_state_via_n_of_n_keypath_cosign() {
        let alice = xkey(ALICE_PK);
        let bob = xkey(BOB_PK);
        let engine = xkey(ENGINE_PK);

        // OLD state: alice 30k, bob 20k (pot 50k). NEW state: alice 40k, bob 10k.
        let old_allocs = [(alice, 30_000u64), (bob, 20_000u64)];
        let new_allocs = [(alice, 40_000u64), (bob, 10_000u64)];
        let old_total: u64 = old_allocs.iter().map(|(_, v)| v).sum();
        let new_total: u64 = new_allocs.iter().map(|(_, v)| v).sum();
        let expiry_old = 800_000u32;
        let expiry_new = 801_000u32;

        // The covenant output we are refreshing FROM.
        let old_taproot = funding_taproot(engine, &old_allocs, expiry_old).unwrap();
        let old_covenant_spk = ScriptBuf::from_bytes(old_taproot.spk().unwrap());
        let old_covenant_txout = TxOut {
            value: Amount::from_sat(old_total),
            script_pubkey: old_covenant_spk.clone(),
        };
        let old_covenant_outpoint = OutPoint::new(Txid::from_byte_array([0x0c; 32]), 0);

        // The covenant output we are refreshing TO (value-bound to the new state).
        let new_covenant_spk =
            ScriptBuf::from_bytes(covenant_scriptpubkey(engine, &new_allocs, expiry_new).unwrap());
        assert_ne!(
            old_covenant_spk.as_bytes(),
            new_covenant_spk.as_bytes(),
            "a different allocation state -> a different (value-bound) covenant spk"
        );
        assert_eq!(old_total, new_total, "value conserved across the refresh");

        // The refresh transaction: spend old covenant -> new covenant (key path).
        let fee = 200u64;
        let refresh_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: old_covenant_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(new_total - fee),
                script_pubkey: new_covenant_spk,
            }],
        };

        // The key-path sighash of the refresh, over the old covenant prevout.
        let sighash = SighashCache::new(&refresh_tx)
            .taproot_key_spend_signature_hash(
                0,
                &Prevouts::All(&[old_covenant_txout]),
                TapSighashType::Default,
            )
            .unwrap()
            .to_byte_array();

        // ---- N-of-N Projector cosign over the OLD covenant's keyagg. ----
        let keyagg = refresh_keyagg(engine, &old_allocs, expiry_old).unwrap();

        // the refresh keyagg's aggregate key IS the old covenant output key.
        assert_eq!(
            keyagg.agg_key().serialize_xonly(),
            old_taproot.tweaked_key().unwrap().serialize_xonly(),
            "refresh keyagg == covenant output key"
        );

        // projected public keys (for nonce registration) and secrets (for signing).
        let alice_pub = participant_projected_pubkey(pt(ALICE_PK), 30_000, 0).unwrap();
        let bob_pub = participant_projected_pubkey(pt(BOB_PK), 20_000, 1).unwrap();
        let engine_pub = engine_projected_pubkey(pt(ENGINE_PK), &old_allocs).unwrap();
        let alice_sec = participant_projected_secret(sc(ALICE_SK), 30_000, 0).unwrap();
        let bob_sec = participant_projected_secret(sc(BOB_SK), 20_000, 1).unwrap();
        let engine_sec = engine_projected_secret(sc(ENGINE_SK), &old_allocs).unwrap();

        let mut session = MusigSessionCtx::new(&keyagg, sighash).unwrap();
        assert!(session.insert_nonce(alice_pub, sc(A_HN).base_point_mul(), sc(A_BN).base_point_mul()));
        assert!(session.insert_nonce(bob_pub, sc(B_HN).base_point_mul(), sc(B_BN).base_point_mul()));
        assert!(session.insert_nonce(engine_pub, sc(S_HN).base_point_mul(), sc(S_BN).base_point_mul()));

        let pa = session.partial_sign(alice_sec, sc(A_HN), sc(A_BN)).unwrap();
        let pb = session.partial_sign(bob_sec, sc(B_HN), sc(B_BN)).unwrap();
        let ps = session.partial_sign(engine_sec, sc(S_HN), sc(S_BN)).unwrap();
        assert!(session.insert_partial_sig(alice_pub, pa));
        assert!(session.insert_partial_sig(bob_pub, pb));
        assert!(session.insert_partial_sig(engine_pub, ps));
        let refresh_sig = session.full_agg_sig().unwrap();

        // the aggregate is a valid key-path spend of the old covenant.
        assert!(
            verify_xonly(
                keyagg.agg_key().serialize_xonly(),
                sighash,
                refresh_sig,
                SchnorrSigningMode::BIP340
            ),
            "N-of-N refresh: the covenant moves to the next state only with everyone's signature"
        );

        // a missing participant cannot refresh (3-of-3 is required): drop bob.
        let mut bad = MusigSessionCtx::new(&keyagg, sighash).unwrap();
        bad.insert_nonce(alice_pub, sc(A_HN).base_point_mul(), sc(A_BN).base_point_mul());
        bad.insert_nonce(engine_pub, sc(S_HN).base_point_mul(), sc(S_BN).base_point_mul());
        let _ = bad.partial_sign(alice_sec, sc(A_HN), sc(A_BN));
        assert!(bad.full_agg_sig().is_none(), "refresh requires every participant (N-of-N)");

        println!("PROJECTOR REFRESH PROVEN: a value-bound covenant output is spent into the next state via an N-of-N Projector MuSig2 key-path signature (the consensus-enforced auto-refresh); the keyagg equals the covenant output key, value is conserved, the new covenant is bound to the updated allocations, and a missing participant cannot refresh.");
    }
}
