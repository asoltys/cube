// Full engine-side data path for a trustless LiftV2 deposit, end to end:
//   SignedBatchTxn::liftv2_keypath_sighashes  (what the engine exposes to clients)
//        -> ClientCosigner / EngineCosigner    (the staged 2-round cosign module)
//             -> SignedBatchTxn::construct      (the batch builder, with the cosig)
// proving the sighash the engine hands out is exactly the one the builder verifies
// against, so a depositor's cosignature actually authorizes the lift-in.
//
// (The session-pool methods assemble_batch_args / liftv2_keypath_sighashes /
// into_batch_container are thin wrappers over these same functions.)

#[cfg(test)]
mod liftv2_engine_path {
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, OutPoint, ScriptBuf, TxOut, Txid};

    use cube::constructive::bitcoiny::batch_txn::signed_batch_txn::signed_batch_txn::SignedBatchTxn;
    use cube::constructive::core_types::target::target::Target;
    use cube::constructive::entity::account::root_account::root_account::RootAccount;
    use cube::constructive::entry::entry::entry::Entry;
    use cube::constructive::entry::entry_kinds::liftup::liftup::Liftup;
    use cube::constructive::txo::lift::lift::Lift;
    use cube::constructive::txo::lift::lift_versions::liftv2::cosign::{
        ClientCosigner, EngineCosigner,
    };
    use cube::constructive::txo::lift::lift_versions::liftv2::liftv2::return_liftv2_scriptpubkey;
    use cube::constructive::txout_types::payload::payload::Payload;
    use cube::inscriptive::registery::registery::{erase_registery, Registery, REGISTERY};
    use cube::operative::run_args::chain::Chain;
    use cube::transmutative::key::KeyHolder;

    use secp::Scalar;
    use std::collections::HashMap;

    const ACCOUNT_SK: &str = "1cc5906ab936b1e29db24fffe9f87b33a4c64f2d3b59aed6c3c4faeb8fcba6da";
    const ACCOUNT_PK: &str = "02cb70281face51a77d51400612196032bb12422d4c07fa42997a0ab39c2431455";
    const ENGINE_SK: &str = "4882eef979baa5c88fd9e62c698de201f0a991af65877becf683e988f3024b0f";
    const ENGINE_PK: &str = "0251deb9fcf4d16b0f82c75cf71e1ffb7879beb0c6bf733b0778a81b777406574f";
    const A_HN_SK: &str = "e2d64e2bd20d5843d03a47199f059aebdf2a9904616a01fe961ee875a7748199";
    const A_BN_SK: &str = "4b978d3aac4135213f536194522f68fbb2ca4321a49d95560ae9726cd9d6a55d";
    const E_HN_SK: &str = "d3b9f2f01f7caa9b0fe2e932ae752f71da9f8f1a652ec895504091333b97d007";
    const E_BN_SK: &str = "961a4d128a1f3cb5c41e71bc86fdc9e81050b7471f05112a6a5360a2240ff3cf";

    fn xonly(pk_hex: &str) -> [u8; 32] {
        hex::decode(&pk_hex[2..]).unwrap().try_into().unwrap()
    }

    #[tokio::test]
    async fn engine_exposed_sighash_drives_a_valid_lift_in() {
        let chain = Chain::Testbed;
        erase_registery(chain);
        let registery: REGISTERY = Registery::new(chain).expect("registery");

        let engine_kh = KeyHolder::new(hex::decode(ENGINE_SK).unwrap().try_into().unwrap()).unwrap();
        let user_kh = KeyHolder::new(hex::decode(ACCOUNT_SK).unwrap().try_into().unwrap()).unwrap();
        let engine_key = engine_kh.secp_public_key_bytes();
        let account_key = user_kh.secp_public_key_bytes();
        assert_eq!(account_key, xonly(ACCOUNT_PK));
        assert_eq!(engine_key, xonly(ENGINE_PK));

        // prev payload (synthetic confirmed UTXO) + V2 deposit + liftup entry.
        let payload_spk = Payload::new(engine_key, vec![0xde, 0xad], None)
            .calculated_scriptpubkey()
            .unwrap();
        let prev_payload = Payload::new(
            engine_key,
            vec![0xde, 0xad],
            Some((
                OutPoint { txid: Txid::from_byte_array([0x11; 32]), vout: 0 },
                TxOut { value: Amount::from_sat(5_000), script_pubkey: ScriptBuf::from(payload_spk) },
            )),
        );
        let lift_outpoint = OutPoint { txid: Txid::from_byte_array([0x22; 32]), vout: 0 };
        let lift_spk = ScriptBuf::from(return_liftv2_scriptpubkey(account_key, engine_key).unwrap());
        let lift = Lift::new_liftv2(
            account_key,
            engine_key,
            lift_outpoint,
            TxOut { value: Amount::from_sat(100_000), script_pubkey: lift_spk },
        );
        let liftup = Liftup::new(
            RootAccount::self_root_account_from_registery(&user_kh, &registery).await,
            Target::new(0),
            vec![lift],
        );
        let entries = vec![Entry::Liftup(liftup)];
        let new_payload = Payload::new(engine_key, vec![0xca, 0xfe], None);

        // 1) The engine computes + exposes the V2 key-path sighash(es).
        let sighashes = SignedBatchTxn::liftv2_keypath_sighashes(
            &prev_payload,
            &[],
            &entries,
            &new_payload,
            &None,
            1,
        )
        .expect("liftv2 sighashes");
        let sighash = *sighashes.get(&lift_outpoint).expect("sighash for the V2 deposit");

        // 2) The staged cosign over that sighash (client commits nonces, engine
        //    begins at freeze, client partial-signs, engine aggregates).
        let client = ClientCosigner::new(
            Scalar::from_hex(ACCOUNT_SK).unwrap(),
            Scalar::from_hex(A_HN_SK).unwrap(),
            Scalar::from_hex(A_BN_SK).unwrap(),
        );
        let (ch, cb) = client.public_nonces();
        let engine = EngineCosigner::begin(
            account_key,
            engine_key,
            Scalar::from_hex(ENGINE_SK).unwrap(),
            Scalar::from_hex(E_HN_SK).unwrap(),
            Scalar::from_hex(E_BN_SK).unwrap(),
            ch,
            cb,
            sighash,
        )
        .expect("engine begin");
        let (eh, eb) = engine.engine_public_nonces();
        let client_partial = client
            .partial_sign(account_key, engine_key, eh, eb, sighash)
            .expect("client partial");
        let cosig = engine.complete(client_partial).expect("aggregate");

        // 3) The batch builder accepts the cosignature and lifts the deposit in.
        let mut cosigs = HashMap::new();
        cosigs.insert(lift_outpoint, cosig);
        let signed = SignedBatchTxn::construct(
            prev_payload,
            vec![],
            entries,
            new_payload,
            None,
            1,
            &engine_kh,
            &cosigs,
        )
        .expect("the exposed sighash must be exactly what construct verifies against");

        let (op, _txout, witness) = &signed.tx_inputs[1];
        assert_eq!(*op, lift_outpoint);
        assert_eq!(witness, &vec![cosig.to_vec()], "V2 key-path witness is the cosignature");

        println!("LiftV2 ENGINE PATH PROVEN: exposed key-path sighash -> staged cosign -> batch builder lift-in, end to end.");
    }
}
