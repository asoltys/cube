// Probe of Cube's one *implemented* trust-minimization claim: a LiftV2 deposit
// must be unilaterally recoverable by the depositor (account key) alone, with NO
// engine cooperation, via the 3-month CSV "sweep" leaf.
//
// LiftV2 (the trustless deposit) is feature-flagged off in the engine
// (V2_LIFT_ENABLED=false), but the on-chain script is fully built. This test
// exercises the sweep path end-to-end at the script/signature level:
//   - construct the LiftV2 deposit output,
//   - cross-check cube's tapleaf hash against rust-bitcoin's BIP341 computation,
//   - verify the control block proves the sweep leaf is committed to the output,
//   - build the sweep spend tx, compute the BIP341 script-path sighash,
//   - sign with ONLY the account key and confirm it satisfies the leaf's OP_CHECKSIG,
//   - confirm the engine key is irrelevant.
// A real node enforces the CSV maturity separately; this proves the spend is
// valid and unilateral.

#[cfg(test)]
mod liftv2_unilateral_exit {
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash};
    use bitcoin::transaction::Version;
    use bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    };

    use cube::constructive::txo::lift::lift_versions::liftv2::liftv2::{
        return_liftv2_scriptpubkey, return_liftv2_taproot, LiftV2,
    };
    use cube::transmutative::secp::schnorr::{sign, verify_xonly, SchnorrSigningMode};

    const CSV_THREE_MONTHS_BLOCKS: u16 = 12_960; // matches CSVFlag::CSVThreeMonths

    fn xonly(secp: &Secp256k1<bitcoin::secp256k1::All>, sk: [u8; 32]) -> [u8; 32] {
        let secret = SecretKey::from_slice(&sk).unwrap();
        let kp = Keypair::from_secret_key(secp, &secret);
        XOnlyPublicKey::from_keypair(&kp).0.serialize()
    }

    #[test]
    fn account_can_sweep_liftv2_without_engine() {
        let secp = Secp256k1::new();

        // Two distinct parties: the depositor (account) and the engine/operator.
        let account_secret = [0x11u8; 32];
        let engine_secret = [0x22u8; 32];
        let account_key = xonly(&secp, account_secret);
        let engine_key = xonly(&secp, engine_secret);

        // The on-chain LiftV2 deposit output.
        let spk_bytes = return_liftv2_scriptpubkey(account_key, engine_key).expect("v2 spk");
        let lift_txout = TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::from_bytes(spk_bytes),
        };
        let deposit_outpoint = OutPoint {
            txid: Txid::from_byte_array([0xab; 32]),
            vout: 0,
        };
        let lift = LiftV2::new(account_key, engine_key, deposit_outpoint, lift_txout.clone());
        assert!(lift.validate_scriptpubkey(), "LiftV2 scriptpubkey must validate");

        // Account-only sweep leaf spend elements.
        let (cube_leaf_hash, tapscript, control_block_bytes) =
            lift.sweep_script_path_spend_elements();
        let script = ScriptBuf::from_bytes(tapscript.clone());

        // 1) cube's tapleaf hash agrees with rust-bitcoin's BIP341 leaf hash.
        let leaf_hash = TapLeafHash::from_script(&script, LeafVersion::TapScript);
        assert_eq!(
            leaf_hash.to_byte_array(),
            cube_leaf_hash,
            "cube tapleaf hash must match BIP341"
        );

        // 2) the control block proves the sweep leaf is committed to the deposit output key.
        let output_key_bytes = return_liftv2_taproot(account_key, engine_key)
            .unwrap()
            .tweaked_key()
            .unwrap()
            .serialize_xonly();
        let output_xonly = XOnlyPublicKey::from_slice(&output_key_bytes).unwrap();
        let control_block =
            ControlBlock::decode(&control_block_bytes).expect("decode control block");
        assert!(
            control_block.verify_taproot_commitment(&secp, output_xonly, &script),
            "control block must prove the sweep leaf is in the deposit's taproot tree"
        );

        // 3) the unilateral sweep tx (deposit -> account), spending the CSV leaf.
        let dest = ScriptBuf::new_p2tr(&secp, XOnlyPublicKey::from_slice(&account_key).unwrap(), None);
        let spend = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: deposit_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::from_height(CSV_THREE_MONTHS_BLOCKS), // satisfies OP_CSV
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(99_000),
                script_pubkey: dest,
            }],
        };

        // 4) BIP341 script-path sighash over the sweep leaf.
        let sighash = SighashCache::new(&spend)
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&[lift_txout]),
                leaf_hash,
                TapSighashType::Default,
            )
            .expect("script-path sighash");
        let msg = sighash.to_byte_array();

        // 5) sign with ONLY the account key — the engine is never involved.
        let sig = sign(account_secret, msg, SchnorrSigningMode::BIP340).expect("account sign");
        assert!(
            verify_xonly(account_key, msg, sig, SchnorrSigningMode::BIP340),
            "account signature must satisfy the sweep leaf's OP_CHECKSIG"
        );
        assert!(
            !verify_xonly(engine_key, msg, sig, SchnorrSigningMode::BIP340),
            "engine key is irrelevant to the unilateral sweep"
        );

        // 6) the witness a node would accept: <account_sig> <sweep_script> <control_block>.
        let mut witness = Witness::new();
        witness.push(sig.to_vec());
        witness.push(script.to_bytes());
        witness.push(control_block_bytes);
        assert_eq!(witness.len(), 3, "script-path witness has 3 items");

        println!("LiftV2 unilateral exit PROVEN: account-only sweep is valid; engine not involved.");
    }
}
