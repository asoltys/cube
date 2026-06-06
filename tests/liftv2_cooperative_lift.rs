// Probe of the OTHER half of LiftV2's trust model: the cooperative "lift-in".
//
// A LiftV2 deposit is locked to a P2TR whose key path is MuSig2(account, engine)
// (taproot-tweaked) and whose script path is the account-only 3-month sweep. For
// the engine to lift the deposit INTO the rollup it must spend the key path,
// which requires BOTH the account and the engine to co-sign (MuSig2). This is
// what makes the deposit trustless: the engine cannot take the deposit
// unilaterally, and if it refuses to cooperate the account sweeps after 3 months
// (proven in liftv2_unilateral_exit / liftv2_regtest_sweep).
//
// This test proves, with cube's own MuSig2, that:
//   1. the MuSig2 aggregate (with the taproot tweak) equals the deposit output key,
//   2. account + engine co-signing yields a valid BIP341 key-path spend signature,
//   3. the engine ALONE cannot produce that signature.

#[cfg(test)]
mod liftv2_cooperative_lift {
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::transaction::Version;
    use bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    };

    use cube::constructive::txo::lift::lift_versions::liftv2::liftv2::{
        return_liftv2_scriptpubkey, return_liftv2_taproot,
    };
    use cube::transmutative::musig::keyagg::MusigKeyAggCtx;
    use cube::transmutative::musig::session::MusigSessionCtx;
    use cube::transmutative::secp::schnorr::{verify_xonly, SchnorrSigningMode};
    use secp::{Point, Scalar};

    // Known even-Y keypairs + nonces (from tests/musig.rs): account and engine.
    fn account() -> (Scalar, Point) {
        (
            Scalar::from_hex("1cc5906ab936b1e29db24fffe9f87b33a4c64f2d3b59aed6c3c4faeb8fcba6da").unwrap(),
            Point::from_hex("02cb70281face51a77d51400612196032bb12422d4c07fa42997a0ab39c2431455").unwrap(),
        )
    }
    fn engine() -> (Scalar, Point) {
        (
            Scalar::from_hex("4882eef979baa5c88fd9e62c698de201f0a991af65877becf683e988f3024b0f").unwrap(),
            Point::from_hex("0251deb9fcf4d16b0f82c75cf71e1ffb7879beb0c6bf733b0778a81b777406574f").unwrap(),
        )
    }
    // (hiding_sk, hiding_pk, binding_sk, binding_pk)
    fn account_nonces() -> (Scalar, Point, Scalar, Point) {
        (
            Scalar::from_hex("e2d64e2bd20d5843d03a47199f059aebdf2a9904616a01fe961ee875a7748199").unwrap(),
            Point::from_hex("020f8eb9edf13c5cbca406d616d9441311906d72ea405bcb7e22b99f7e892f0d20").unwrap(),
            Scalar::from_hex("4b978d3aac4135213f536194522f68fbb2ca4321a49d95560ae9726cd9d6a55d").unwrap(),
            Point::from_hex("031451a7f53decf60829622152e16f92b9fb7b72b4521e03510eba2469a742643f").unwrap(),
        )
    }
    fn engine_nonces() -> (Scalar, Point, Scalar, Point) {
        (
            Scalar::from_hex("d3b9f2f01f7caa9b0fe2e932ae752f71da9f8f1a652ec895504091333b97d007").unwrap(),
            Point::from_hex("024cb6badc87cfcad700eb028e1203f2cc0fd63a919d7c199a63b7891afd300e7c").unwrap(),
            Scalar::from_hex("961a4d128a1f3cb5c41e71bc86fdc9e81050b7471f05112a6a5360a2240ff3cf").unwrap(),
            Point::from_hex("02f963d471e593d7574451d73a748ed06edae936f62cda9b4b62aa9cdd280c1d99").unwrap(),
        )
    }

    #[test]
    fn account_and_engine_cosign_lift_in_engine_alone_cannot() {
        let (account_sk, account_pk) = account();
        let (engine_sk, engine_pk) = engine();
        let account_key = account_pk.serialize_xonly();
        let engine_key = engine_pk.serialize_xonly();

        // The LiftV2 deposit output.
        let taproot = return_liftv2_taproot(account_key, engine_key).unwrap();
        let spk = ScriptBuf::from_bytes(return_liftv2_scriptpubkey(account_key, engine_key).unwrap());

        // 1) MuSig2 aggregate (with the taproot tweak) == the deposit output key.
        let tweak = Scalar::from_slice(&taproot.tap_tweak()).unwrap();
        let keyagg = MusigKeyAggCtx::new(&vec![account_pk, engine_pk], Some(tweak)).unwrap();
        assert_eq!(
            keyagg.agg_key(),
            taproot.tweaked_key().unwrap(),
            "MuSig2 agg key (tweaked) must equal the LiftV2 deposit output key"
        );

        // A lift-in spend tx: the engine spends the deposit (key path) into the rollup.
        let deposit = OutPoint { txid: Txid::from_byte_array([0x07; 32]), vout: 0 };
        let prevout = TxOut { value: Amount::from_sat(100_000), script_pubkey: spk.clone() };
        let spend = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: deposit,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut { value: Amount::from_sat(99_000), script_pubkey: spk.clone() }],
        };
        // BIP341 KEY-path sighash (no leaf).
        let msg = SighashCache::new(&spend)
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&[prevout]), TapSighashType::Default)
            .unwrap()
            .to_byte_array();

        // 2) account + engine co-sign -> valid key-path spend signature.
        let (a_h_sk, a_h_pk, a_b_sk, a_b_pk) = account_nonces();
        let (e_h_sk, e_h_pk, e_b_sk, e_b_pk) = engine_nonces();
        let mut session = MusigSessionCtx::new(&keyagg, msg).unwrap();
        assert!(session.insert_nonce(account_pk, a_h_pk, a_b_pk));
        assert!(session.insert_nonce(engine_pk, e_h_pk, e_b_pk));
        assert!(session.ready());
        let a_sig = session.partial_sign(account_sk, a_h_sk, a_b_sk).expect("account partial sig");
        let e_sig = session.partial_sign(engine_sk, e_h_sk, e_b_sk).expect("engine partial sig");
        assert!(session.insert_partial_sig(account_pk, a_sig));
        assert!(session.insert_partial_sig(engine_pk, e_sig));
        let agg_sig = session.full_agg_sig().expect("aggregate signature");
        assert!(
            verify_xonly(keyagg.agg_key().serialize_xonly(), msg, agg_sig, SchnorrSigningMode::BIP340),
            "co-signed signature must be a valid key-path spend of the deposit (a node would accept witness=[sig])"
        );

        // 3) the engine ALONE cannot lift the deposit (no account participation).
        let mut solo = MusigSessionCtx::new(&keyagg, msg).unwrap();
        assert!(solo.insert_nonce(engine_pk, e_h_pk, e_b_pk));
        assert!(!solo.ready(), "session is not complete without the account's nonce");
        assert!(
            solo.full_agg_sig().is_none(),
            "engine alone must NOT be able to produce the lift-in signature"
        );

        println!("LiftV2 cooperative lift-in PROVEN: account+engine MuSig2 yields a valid key-path spend; engine alone cannot.");
    }
}
