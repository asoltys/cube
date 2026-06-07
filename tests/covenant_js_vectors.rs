// Ground-truth vectors for CLIENT-SIDE tx verification in the browser. Before
// signing a refresh, the player's browser must (1) rebuild the next covenant spk
// from the new allocations and confirm the tx pays it out, and (2) recompute the
// BIP341 key-path sighash from the tx itself instead of trusting the server's
// message. This emits the covenant-spk internals + a full refresh tx and its
// key-path sighash so the JS port (covenant.mjs / sighash.mjs) matches cube
// byte-for-byte.
//
// Run: cargo test --test covenant_js_vectors -- --nocapture --test-threads=1

#[cfg(test)]
mod covenant_js_vectors {
    use bitcoin::hashes::Hash as _;
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::transaction::Version;
    use bitcoin::{
        absolute::LockTime, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
        Witness,
    };

    use cube::constructive::txout_types::timeout_tree::funding_taproot;
    use cube::constructive::txout_types::timeout_tree::refresh::covenant_scriptpubkey;
    use cube::transmutative::musig::projector::key_projector_agg;
    use cube::constructive::txout_types::timeout_tree::funding_keys_and_values;

    fn x(pk: &str) -> [u8; 32] { hex::decode(&pk[2..]).unwrap().try_into().unwrap() }
    fn hx(b: &[u8]) -> String { hex::encode(b) }

    const ALICE_PK: &str = "02cb70281face51a77d51400612196032bb12422d4c07fa42997a0ab39c2431455";
    const BOB_PK: &str = "0251deb9fcf4d16b0f82c75cf71e1ffb7879beb0c6bf733b0778a81b777406574f";
    const ENGINE_PK: &str = "029611bc66d526fa3194d0f525dce21e782dcf90cc72529ec2d5486da838d83770";

    #[test]
    fn covenant_and_sighash_vector() {
        let alice = x(ALICE_PK);
        let bob = x(BOB_PK);
        let engine = x(ENGINE_PK);

        // allocation order is canonical = sorted by account key (matches the arcade).
        let mut a0 = vec![(alice, 30_000u64), (bob, 20_000u64)];
        a0.sort_by(|p, q| p.0.cmp(&q.0));
        let expiry0 = 800_000u32;

        let c0 = funding_taproot(engine, &a0, expiry0).unwrap();
        let agg_inner = key_projector_agg(&funding_keys_and_values(engine, &a0).unwrap(), None)
            .unwrap()
            .agg_inner_key();
        let leaf = c0.tree().unwrap().leaves()[0].clone();

        println!("=== COVENANT SPK VECTOR ===");
        println!("ENGINE={}", ENGINE_PK);
        println!("ALLOC0={}", a0.iter().map(|(k, v)| format!("{}:{}", hx(k), v)).collect::<Vec<_>>().join(","));
        println!("EXPIRY0={}", expiry0);
        println!("AGG_INNER={}", hx(&agg_inner.serialize()));
        println!("EXPIRY_TAPSCRIPT={}", hx(&leaf.tap_script()));
        println!("TAPLEAF_HASH={}", hx(&leaf.tapleaf_hash()));
        println!("TAP_TWEAK={}", hx(&c0.tap_tweak()));
        println!("OUTPUT_KEY={}", hx(&c0.tweaked_key().unwrap().serialize_xonly()));
        println!("COVENANT_SPK={}", hx(&c0.spk().unwrap()));

        // ---- a concrete refresh tx (C0 -> C1) and its key-path sighash ----
        let total0: u64 = a0.iter().map(|(_, v)| v).sum();
        let mut a1 = vec![(alice, 35_000u64), (bob, 15_000u64)];
        a1.sort_by(|p, q| p.0.cmp(&q.0));
        let expiry1 = 801_000u32;
        let fee = 200u64;
        let total1: u64 = a1.iter().map(|(_, v)| v).sum();
        let c1_spk = covenant_scriptpubkey(engine, &a1, expiry1).unwrap();

        let prev_txid: [u8; 32] = [0xc0; 32];
        let prev_vout = 0u32;
        let prev_value = total0;
        let c0_txout = TxOut {
            value: Amount::from_sat(prev_value),
            script_pubkey: ScriptBuf::from_bytes(c0.spk().unwrap()),
        };
        let refresh_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array(prev_txid), prev_vout),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(total1 - fee),
                script_pubkey: ScriptBuf::from_bytes(c1_spk.clone()),
            }],
        };
        let sighash = SighashCache::new(&refresh_tx)
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&[c0_txout]), TapSighashType::Default)
            .unwrap()
            .to_byte_array();

        println!("=== REFRESH SIGHASH VECTOR ===");
        println!("ALLOC1={}", a1.iter().map(|(k, v)| format!("{}:{}", hx(k), v)).collect::<Vec<_>>().join(","));
        println!("EXPIRY1={}", expiry1);
        println!("FEE={}", fee);
        println!("PREV_TXID={}", hx(&prev_txid));
        println!("PREV_VOUT={}", prev_vout);
        println!("PREV_VALUE={}", prev_value);
        println!("C1_SPK={}", hx(&c1_spk));
        println!("OUT_VALUE={}", total1 - fee);
        println!("KEYPATH_SIGHASH={}", hx(&sighash));
        println!("=== END ===");
    }
}
