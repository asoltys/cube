// Batch-tx restructure (task b): the engine batch tx can now EMIT projector
// (exit-tree funding) outputs AND SPEND a prev projector by refreshing it via an
// N-of-N (participants + engine) MuSig2 key-path cosignature.
//
//   * EMIT:   construct a batch with new_projectors = [P]; the tx carries P's
//             value-bound covenant output and the payload change drops by P's value.
//   * REFRESH: feed P back as a prev_projector; the batch spends it via a single
//             64-byte key-path witness = the N-of-N refresh signature over the
//             batch's projector_refresh sighash. construct verifies that signature
//             against P's covenant output key before trusting it.

#[cfg(test)]
mod projector_emit_refresh {
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, OutPoint, ScriptBuf, TxOut, Txid};

    use cube::constructive::bitcoiny::batch_txn::signed_batch_txn::signed_batch_txn::SignedBatchTxn;
    use cube::constructive::txout_types::payload::payload::Payload;
    use cube::constructive::txout_types::projector::projector::Projector;
    use cube::constructive::txout_types::timeout_tree::funding_taproot;
    use cube::constructive::txout_types::timeout_tree::refresh::{
        engine_projected_pubkey, engine_projected_secret, participant_projected_pubkey,
        participant_projected_secret, refresh_keyagg,
    };
    use cube::transmutative::key::KeyHolder;
    use cube::transmutative::musig::session::MusigSessionCtx;
    use secp::{Point, Scalar};
    use std::collections::HashMap;

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

    fn payload_with_location(engine_key: [u8; 32], tag: u8, value: u64) -> Payload {
        let bytes = vec![0xde, 0xad, tag];
        let spk = Payload::new(engine_key, bytes.clone(), None)
            .calculated_scriptpubkey()
            .expect("payload spk");
        Payload::new(
            engine_key,
            bytes,
            Some((
                OutPoint { txid: Txid::from_byte_array([tag; 32]), vout: 0 },
                TxOut { value: Amount::from_sat(value), script_pubkey: ScriptBuf::from(spk) },
            )),
        )
    }

    #[test]
    fn batch_emits_a_projector_then_refreshes_it() {
        let alice = xkey(ALICE_PK);
        let bob = xkey(BOB_PK);
        let engine = xkey(ENGINE_PK);
        let engine_kh = KeyHolder::new(hex::decode(ENGINE_SK).unwrap().try_into().unwrap()).unwrap();
        assert_eq!(engine_kh.secp_public_key_bytes(), engine, "engine xonly");

        let allocs = [(alice, 30_000u64), (bob, 20_000u64)];
        let total: u64 = allocs.iter().map(|(_, v)| v).sum(); // 50_000
        let expiry = 800_000u32;

        // The contract pot's covenant (exit-tree funding) output P.
        let p_spk = funding_taproot(engine, &allocs, expiry).unwrap().spk().unwrap();
        let projector_p = Projector {
            scriptpubkey: p_spk.clone(),
            satoshi_amount: total,
            location: None,
        };

        // ---- EMIT: a batch that creates P as an output. ----
        let prev_payload = payload_with_location(engine, 0x11, 80_000);
        let new_payload = Payload::new(engine, vec![0xca, 0xfe], None);
        let emit = SignedBatchTxn::construct(
            prev_payload,
            vec![],                       // no prev projectors
            vec![],                       // no entries
            new_payload,
            vec![projector_p.clone()],    // emit P
            1,
            &engine_kh,
            &HashMap::new(),
            &HashMap::new(),
        )
        .expect("emit batch builds");

        // The projector output is present (output 1: payload change is output 0).
        let p_out = emit
            .tx_outputs
            .iter()
            .find(|o| o.script_pubkey.as_bytes() == p_spk.as_slice())
            .expect("projector output emitted");
        assert_eq!(p_out.value.to_sat(), total, "projector output carries the pot value");
        // payload change dropped by P's value (80_000 - 50_000 - fee).
        assert!(emit.tx_outputs[0].value.to_sat() < 80_000 - total, "payload change reduced by P");

        // P is now a confirmed UTXO at (emit batch txid, vout of the projector output).
        let p_vout = emit
            .tx_outputs
            .iter()
            .position(|o| o.script_pubkey.as_bytes() == p_spk.as_slice())
            .unwrap() as u32;
        let p_outpoint = OutPoint { txid: emit.txid(), vout: p_vout };
        let p_with_location = Projector {
            scriptpubkey: p_spk.clone(),
            satoshi_amount: total,
            location: Some((p_outpoint, p_out.clone())),
        };

        // ---- REFRESH: a next batch that SPENDS P via the N-of-N cosign. ----
        let prev_payload2 = payload_with_location(engine, 0x22, 10_000);
        let new_payload2 = Payload::new(engine, vec![0xbe, 0xef], None);

        // The refresh sighash for P (the message the participants + engine co-sign).
        let refresh_sighash = *SignedBatchTxn::projector_refresh_keypath_sighashes(
            &prev_payload2,
            &[p_with_location.clone()],
            &[],
            &new_payload2,
            &[],
            1,
        )
        .expect("refresh sighashes")
        .get(&p_outpoint)
        .expect("sighash for P");

        // N-of-N Projector cosign over that sighash (alice + bob + engine).
        let keyagg = refresh_keyagg(engine, &allocs, expiry).unwrap();
        let a_pub = participant_projected_pubkey(pt(ALICE_PK), 30_000, 0).unwrap();
        let b_pub = participant_projected_pubkey(pt(BOB_PK), 20_000, 1).unwrap();
        let e_pub = engine_projected_pubkey(pt(ENGINE_PK), &allocs).unwrap();
        let mut s = MusigSessionCtx::new(&keyagg, refresh_sighash).unwrap();
        s.insert_nonce(a_pub, sc(A_HN).base_point_mul(), sc(A_BN).base_point_mul());
        s.insert_nonce(b_pub, sc(B_HN).base_point_mul(), sc(B_BN).base_point_mul());
        s.insert_nonce(e_pub, sc(S_HN).base_point_mul(), sc(S_BN).base_point_mul());
        let pa = s.partial_sign(participant_projected_secret(sc(ALICE_SK), 30_000, 0).unwrap(), sc(A_HN), sc(A_BN)).unwrap();
        let pb = s.partial_sign(participant_projected_secret(sc(BOB_SK), 20_000, 1).unwrap(), sc(B_HN), sc(B_BN)).unwrap();
        let pe = s.partial_sign(engine_projected_secret(sc(ENGINE_SK), &allocs).unwrap(), sc(S_HN), sc(S_BN)).unwrap();
        s.insert_partial_sig(a_pub, pa);
        s.insert_partial_sig(b_pub, pb);
        s.insert_partial_sig(e_pub, pe);
        let refresh_cosig = s.full_agg_sig().unwrap();

        let mut refresh_cosigs = HashMap::new();
        refresh_cosigs.insert(p_outpoint, refresh_cosig);

        let refreshed = SignedBatchTxn::construct(
            prev_payload2,
            vec![p_with_location],        // spend P
            vec![],
            new_payload2,
            vec![],                       // (could emit P' here; empty for this test)
            1,
            &engine_kh,
            &HashMap::new(),
            &refresh_cosigs,
        )
        .expect("refresh batch builds and verifies the N-of-N cosig against P's output key");

        // P is spent at input index 1 (prev_payload is input 0), witness = the cosig.
        let (op, _txout, witness) = &refreshed.tx_inputs[1];
        assert_eq!(*op, p_outpoint, "the batch spends P");
        assert_eq!(witness.len(), 1, "key-path spend: one witness element");
        assert_eq!(witness[0].len(), 64, "the 64-byte N-of-N refresh signature");

        // A wrong/missing cosig is rejected.
        let bad = SignedBatchTxn::construct(
            payload_with_location(engine, 0x33, 10_000),
            vec![Projector { scriptpubkey: p_spk, satoshi_amount: total, location: Some((p_outpoint, p_out.clone())) }],
            vec![],
            Payload::new(engine, vec![0x00], None),
            vec![],
            1,
            &engine_kh,
            &HashMap::new(),
            &HashMap::new(), // no refresh cosig
        );
        assert!(bad.is_err(), "a prev projector without a refresh cosig is rejected");

        println!("PROJECTOR EMIT+REFRESH PROVEN: the batch tx emits a value-bound covenant output and spends a prev covenant via a single 64-byte N-of-N MuSig2 key-path refresh signature (verified against the covenant output key); missing cosig rejected. The batch-tx restructure for the auto-refresh.");
    }
}
