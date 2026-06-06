// Engine-side integration of trustless LiftV2 deposits: the batch builder lifts a
// LiftV2 deposit INTO the rollup via a key-path spend that is co-signed by the
// account and the engine (MuSig2). This is the missing engine half — previously
// the batch builder hard-errored on LiftV2 (LiftV2NotSupportedError).
//
// Here the cosignature is produced in-process (the test plays both account and
// engine), which is exactly what the interactive cosigning session will deliver
// to the engine at batch-finalization time. We assert the batch builder accepts
// the V2 lift, verifies the cosignature against the deposit output key, and emits
// the correct key-path witness (a single 64-byte aggregated signature).

#[cfg(test)]
mod liftv2_batch_lift {
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, OutPoint, ScriptBuf, TxOut, Txid};

    use cube::constructive::bitcoiny::batch_txn::signed_batch_txn::signed_batch_txn::SignedBatchTxn;
    use cube::constructive::bitcoiny::batch_txn::unsigned_batch_txn::unsigned_batch_txn::UnsignedBatchTxn;
    use cube::constructive::core_types::target::target::Target;
    use cube::constructive::entity::account::root_account::root_account::RootAccount;
    use cube::constructive::entry::entry::entry::Entry;
    use cube::constructive::entry::entry_kinds::liftup::liftup::Liftup;
    use cube::constructive::txo::lift::lift::Lift;
    use cube::constructive::txo::lift::lift_versions::liftv2::liftv2::{
        return_liftv2_scriptpubkey, return_liftv2_taproot,
    };
    use cube::constructive::txout_types::payload::payload::Payload;
    use cube::inscriptive::registery::registery::{erase_registery, Registery, REGISTERY};
    use cube::operative::run_args::chain::Chain;
    use cube::transmutative::key::KeyHolder;
    use cube::transmutative::musig::keyagg::MusigKeyAggCtx;
    use cube::transmutative::musig::session::MusigSessionCtx;

    use secp::{Point, Scalar};
    use std::collections::HashMap;

    // account = musig signer_1, engine = musig signer_2 (even-Y), with their nonces.
    const ACCOUNT_SK: &str = "1cc5906ab936b1e29db24fffe9f87b33a4c64f2d3b59aed6c3c4faeb8fcba6da";
    const ACCOUNT_PK: &str = "02cb70281face51a77d51400612196032bb12422d4c07fa42997a0ab39c2431455";
    const ENGINE_SK: &str = "4882eef979baa5c88fd9e62c698de201f0a991af65877becf683e988f3024b0f";
    const ENGINE_PK: &str = "0251deb9fcf4d16b0f82c75cf71e1ffb7879beb0c6bf733b0778a81b777406574f";
    const A_HN_SK: &str = "e2d64e2bd20d5843d03a47199f059aebdf2a9904616a01fe961ee875a7748199";
    const A_HN_PK: &str = "020f8eb9edf13c5cbca406d616d9441311906d72ea405bcb7e22b99f7e892f0d20";
    const A_BN_SK: &str = "4b978d3aac4135213f536194522f68fbb2ca4321a49d95560ae9726cd9d6a55d";
    const A_BN_PK: &str = "031451a7f53decf60829622152e16f92b9fb7b72b4521e03510eba2469a742643f";
    const E_HN_SK: &str = "d3b9f2f01f7caa9b0fe2e932ae752f71da9f8f1a652ec895504091333b97d007";
    const E_HN_PK: &str = "024cb6badc87cfcad700eb028e1203f2cc0fd63a919d7c199a63b7891afd300e7c";
    const E_BN_SK: &str = "961a4d128a1f3cb5c41e71bc86fdc9e81050b7471f05112a6a5360a2240ff3cf";
    const E_BN_PK: &str = "02f963d471e593d7574451d73a748ed06edae936f62cda9b4b62aa9cdd280c1d99";

    fn bytes32(h: &str) -> [u8; 32] {
        hex::decode(h).unwrap().try_into().unwrap()
    }

    #[tokio::test]
    async fn batch_builder_lifts_in_a_cosigned_liftv2_deposit() {
        let chain = Chain::Testbed;
        erase_registery(chain);
        let registery: REGISTERY = Registery::new(chain).expect("registery");

        // Engine + account (user) keyholders.
        let engine_kh = KeyHolder::new(bytes32(ENGINE_SK)).expect("engine kh");
        let user_kh = KeyHolder::new(bytes32(ACCOUNT_SK)).expect("user kh");
        let engine_key = engine_kh.secp_public_key_bytes();
        let account_key = user_kh.secp_public_key_bytes();
        assert_eq!(engine_key, bytes32(&ENGINE_PK[2..]), "engine xonly");
        assert_eq!(account_key, bytes32(&ACCOUNT_PK[2..]), "account xonly");

        // Prev payload as a confirmed UTXO (synthetic), spendable by the engine.
        let payload_bytes = vec![0xde, 0xad, 0xbe, 0xef];
        let payload_spk = Payload::new(engine_key, payload_bytes.clone(), None)
            .calculated_scriptpubkey()
            .expect("payload spk");
        let prev_payload = Payload::new(
            engine_key,
            payload_bytes,
            Some((
                OutPoint { txid: Txid::from_byte_array([0x11; 32]), vout: 0 },
                TxOut { value: Amount::from_sat(5_000), script_pubkey: ScriptBuf::from(payload_spk) },
            )),
        );

        // A confirmed LiftV2 deposit owned by account+engine.
        let lift_outpoint = OutPoint { txid: Txid::from_byte_array([0x22; 32]), vout: 0 };
        let lift_spk = ScriptBuf::from(return_liftv2_scriptpubkey(account_key, engine_key).unwrap());
        let lift_txout = TxOut { value: Amount::from_sat(100_000), script_pubkey: lift_spk };
        let lift = Lift::new_liftv2(account_key, engine_key, lift_outpoint, lift_txout.clone());

        // Liftup entry carrying the V2 lift.
        let liftup = {
            let root_account =
                RootAccount::self_root_account_from_registery(&user_kh, &registery).await;
            Liftup::new(root_account, Target::new(0), vec![lift.clone()])
        };
        let new_payload = Payload::new(engine_key, vec![0xca, 0xfe], None);
        let new_payload_txout = TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from(new_payload.calculated_scriptpubkey().unwrap()),
        };

        // Reproduce the batch's unsigned tx to get the V2 input's key-path sighash.
        // Input order: prev_payload(0), projectors(none), lifts(1).
        let unsigned = UnsignedBatchTxn::construct(
            prev_payload.location().unwrap(),
            vec![],
            vec![(lift.outpoint(), lift.txout())],
            new_payload_txout,
            None,
            vec![],
            1,
        )
        .expect("unsigned batch");
        let keypath_sighash = unsigned.taproot_sighash(1, None).expect("v2 key-path sighash");

        // --- in-process account+engine MuSig2 cosign over the key-path sighash ---
        let taproot = return_liftv2_taproot(account_key, engine_key).unwrap();
        let tweak = Scalar::from_slice(&taproot.tap_tweak()).unwrap();
        let account_pt = Point::from_hex(ACCOUNT_PK).unwrap();
        let engine_pt = Point::from_hex(ENGINE_PK).unwrap();
        let keyagg = MusigKeyAggCtx::new(&vec![account_pt, engine_pt], Some(tweak)).unwrap();

        let mut session = MusigSessionCtx::new(&keyagg, keypath_sighash).unwrap();
        assert!(session.insert_nonce(account_pt, Point::from_hex(A_HN_PK).unwrap(), Point::from_hex(A_BN_PK).unwrap()));
        assert!(session.insert_nonce(engine_pt, Point::from_hex(E_HN_PK).unwrap(), Point::from_hex(E_BN_PK).unwrap()));
        let a_sig = session
            .partial_sign(Scalar::from_hex(ACCOUNT_SK).unwrap(), Scalar::from_hex(A_HN_SK).unwrap(), Scalar::from_hex(A_BN_SK).unwrap())
            .unwrap();
        let e_sig = session
            .partial_sign(Scalar::from_hex(ENGINE_SK).unwrap(), Scalar::from_hex(E_HN_SK).unwrap(), Scalar::from_hex(E_BN_SK).unwrap())
            .unwrap();
        assert!(session.insert_partial_sig(account_pt, a_sig));
        assert!(session.insert_partial_sig(engine_pt, e_sig));
        let cosig = session.full_agg_sig().expect("aggregated cosig");

        let mut sigs = HashMap::new();
        sigs.insert(lift_outpoint, cosig);

        // --- the engine builds the batch, lifting in the V2 deposit ---
        let signed = SignedBatchTxn::construct(
            prev_payload,
            vec![],
            vec![Entry::Liftup(liftup)],
            new_payload,
            None,
            1,
            &engine_kh,
            &sigs,
        )
        .expect("batch builder must accept the cosigned LiftV2 deposit");

        // The V2 lift is input index 1; its witness is the single key-path signature.
        let (outpoint, _txout, witness) = &signed.tx_inputs[1];
        assert_eq!(*outpoint, lift_outpoint, "input 1 is the V2 lift");
        assert_eq!(witness.len(), 1, "key-path witness is a single item");
        assert_eq!(witness[0].len(), 64, "key-path witness is a 64-byte schnorr sig");
        assert_eq!(witness[0], cosig.to_vec(), "witness carries the cosignature");

        // Negative: the same batch with NO cosignature must be rejected.
        let payload_spk2 = Payload::new(engine_key, vec![0xde, 0xad, 0xbe, 0xef], None)
            .calculated_scriptpubkey()
            .unwrap();
        let prev_payload2 = Payload::new(
            engine_key,
            vec![0xde, 0xad, 0xbe, 0xef],
            Some((
                OutPoint { txid: Txid::from_byte_array([0x11; 32]), vout: 0 },
                TxOut { value: Amount::from_sat(5_000), script_pubkey: ScriptBuf::from(payload_spk2) },
            )),
        );
        let liftup2 = Liftup::new(
            RootAccount::self_root_account_from_registery(&user_kh, &registery).await,
            Target::new(0),
            vec![lift],
        );
        let bad = SignedBatchTxn::construct(
            prev_payload2,
            vec![],
            vec![Entry::Liftup(liftup2)],
            Payload::new(engine_key, vec![0xca, 0xfe], None),
            None,
            1,
            &engine_kh,
            &HashMap::new(), // no cosig provided
        );
        assert!(bad.is_err(), "batch builder must reject a LiftV2 without a cosignature");

        println!("LiftV2 BATCH LIFT-IN PROVEN: engine batch builder lifts a cosigned V2 deposit via key-path; missing cosig rejected.");
    }
}
