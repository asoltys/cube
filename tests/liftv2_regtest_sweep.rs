// Real-network proof of LiftV2's unilateral exit on a regtest node. NO Cube
// engine runs at any point — only bitcoind and the depositor's account key.
//
//   deposit BTC -> LiftV2 address
//   try to sweep early           -> rejected (CSV not matured)
//   mine past the 12,960-block relative timelock
//   sweep with the ACCOUNT KEY ONLY -> accepted + confirms
//
// Gated on env so it's skipped unless a regtest node is provided:
//   CUBE_REGTEST_URL  (e.g. http://127.0.0.1:18450/wallet/sweep)
//   CUBE_REGTEST_USER CUBE_REGTEST_PASS
// Run: CUBE_REGTEST_URL=... CUBE_REGTEST_USER=user CUBE_REGTEST_PASS=password \
//   cargo test --test liftv2_regtest_sweep -- --nocapture --ignored

#[cfg(test)]
mod liftv2_regtest_sweep {
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::key::TweakedPublicKey;
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::taproot::{LeafVersion, TapLeafHash};
    use bitcoin::transaction::Version;
    use bitcoin::{
        Address, Amount, KnownHrp, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    };
    use bitcoincore_rpc::{jsonrpc, Client, RpcApi};
    use std::time::Duration;

    use cube::constructive::txo::lift::lift_versions::liftv2::liftv2::{
        return_liftv2_scriptpubkey, return_liftv2_taproot, LiftV2,
    };
    use cube::transmutative::secp::schnorr::{sign, SchnorrSigningMode};

    const CSV_BLOCKS: u16 = 12_960; // CSVFlag::CSVThreeMonths

    fn xonly(secp: &Secp256k1<bitcoin::secp256k1::All>, sk: [u8; 32]) -> [u8; 32] {
        let kp = Keypair::from_secret_key(secp, &SecretKey::from_slice(&sk).unwrap());
        XOnlyPublicKey::from_keypair(&kp).0.serialize()
    }

    #[test]
    #[ignore] // requires a regtest node (see header); run explicitly with --ignored
    fn unilateral_sweep_on_regtest() {
        let (url, user, pass) = match (
            std::env::var("CUBE_REGTEST_URL"),
            std::env::var("CUBE_REGTEST_USER"),
            std::env::var("CUBE_REGTEST_PASS"),
        ) {
            (Ok(u), Ok(us), Ok(pw)) => (u, us, pw),
            _ => {
                println!("SKIP: set CUBE_REGTEST_URL/USER/PASS to run this test");
                return;
            }
        };
        // Long timeout so bulk block generation (disk flushes) doesn't trip the
        // default ~15s socket read timeout.
        let transport = jsonrpc::simple_http::SimpleHttpTransport::builder()
            .url(&url)
            .expect("rpc url")
            .auth(user, Some(pass))
            .timeout(Duration::from_secs(300))
            .build();
        let rpc = Client::from_jsonrpc(jsonrpc::Client::with_transport(transport));
        let secp = Secp256k1::new();

        // Depositor (account) and engine keys. The engine secret is NEVER used.
        let account_secret = [0x42u8; 32];
        let engine_secret = [0x99u8; 32];
        let account_key = xonly(&secp, account_secret);
        let engine_key = xonly(&secp, engine_secret);

        // LiftV2 deposit address (P2TR with the account/engine MuSig key-path + the
        // account-only CSV sweep leaf).
        let taproot = return_liftv2_taproot(account_key, engine_key).unwrap();
        let out_xonly = XOnlyPublicKey::from_slice(&taproot.tweaked_key().unwrap().serialize_xonly()).unwrap();
        let deposit_addr =
            Address::p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(out_xonly), KnownHrp::Regtest);
        let spk = ScriptBuf::from_bytes(return_liftv2_scriptpubkey(account_key, engine_key).unwrap());
        assert_eq!(deposit_addr.script_pubkey(), spk, "address must match the LiftV2 spk");

        let mine_addr = rpc.get_new_address(None, None).unwrap().assume_checked();
        let deposit_amount = Amount::from_sat(100_000);

        // 1) Fund the LiftV2 deposit and confirm it.
        let fund_txid = rpc
            .send_to_address(&deposit_addr, deposit_amount, None, None, None, None, None, None)
            .expect("fund deposit");
        let fund_tx = rpc.get_raw_transaction(&fund_txid, None).expect("get fund tx");
        let vout = fund_tx
            .output
            .iter()
            .position(|o| o.script_pubkey == spk)
            .expect("deposit vout") as u32;
        rpc.generate_to_address(1, &mine_addr).unwrap();
        println!("deposit {}:{} funded with {} sat", fund_txid, vout, deposit_amount.to_sat());

        // Validate the on-chain output really is a well-formed LiftV2.
        let lift = LiftV2::new(
            account_key,
            engine_key,
            OutPoint { txid: fund_txid, vout },
            TxOut { value: deposit_amount, script_pubkey: spk.clone() },
        );
        assert!(lift.validate_scriptpubkey());
        let (cube_leaf_hash, tapscript, control_block) = lift.sweep_script_path_spend_elements();
        let script = ScriptBuf::from_bytes(tapscript);
        let leaf_hash = TapLeafHash::from_script(&script, LeafVersion::TapScript);
        assert_eq!(leaf_hash.to_byte_array(), cube_leaf_hash);

        // 2) Build the account-only sweep tx (deposit -> account-owned p2tr).
        let acct_dest = Address::p2tr(&secp, XOnlyPublicKey::from_slice(&account_key).unwrap(), None, KnownHrp::Regtest);
        let prevout = TxOut { value: deposit_amount, script_pubkey: spk.clone() };
        let mut sweep = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: fund_txid, vout },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::from_height(CSV_BLOCKS),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(99_000), // 1000 sat fee
                script_pubkey: acct_dest.script_pubkey(),
            }],
        };
        let sighash = SighashCache::new(&sweep)
            .taproot_script_spend_signature_hash(0, &Prevouts::All(&[prevout]), leaf_hash, TapSighashType::Default)
            .unwrap()
            .to_byte_array();
        let sig = sign(account_secret, sighash, SchnorrSigningMode::BIP340).expect("account sign");
        let mut witness = Witness::new();
        witness.push(sig.to_vec());
        witness.push(script.to_bytes());
        witness.push(control_block);
        sweep.input[0].witness = witness;

        // 3) Early broadcast must FAIL — the 12,960-block CSV hasn't matured (1 conf).
        let early = rpc.send_raw_transaction(&sweep);
        assert!(early.is_err(), "sweep must be rejected before CSV maturity");
        println!("pre-maturity broadcast correctly rejected: {}", early.unwrap_err());

        // 4) Mine until the deposit has 12,960 confirmations, then sweep succeeds.
        // Mine in chunks so a single large RPC call doesn't hit the socket timeout.
        let mut remaining = (CSV_BLOCKS as u64) - 1;
        while remaining > 0 {
            let n = remaining.min(1000);
            rpc.generate_to_address(n, &mine_addr).unwrap();
            remaining -= n;
        }
        let sweep_txid = match rpc.send_raw_transaction(&sweep) {
            Ok(t) => t,
            Err(e) => {
                println!("post-maturity attempt #1 failed ({}); mining +1 and retrying", e);
                rpc.generate_to_address(1, &mine_addr).unwrap();
                rpc.send_raw_transaction(&sweep).expect("sweep must be accepted after maturity")
            }
        };
        rpc.generate_to_address(1, &mine_addr).unwrap();
        let confirmed = rpc.get_raw_transaction_info(&sweep_txid, None).unwrap();
        assert!(confirmed.confirmations.unwrap_or(0) >= 1, "sweep must confirm");

        println!(
            "LiftV2 UNILATERAL EXIT PROVEN ON REGTEST: deposit recovered by account key alone in {} (engine never ran).",
            sweep_txid
        );
    }
}
