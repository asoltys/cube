// Exploring the EXIT-LADDER + FORK-ATTEST connector mechanism — how Cube turns
// "I hold the disprove secret" into an on-chain dispute that the Engine cannot
// dodge by pretending it happened on a different fork.
//
// The challenger broadcasts tx::exit-ladder (carrying the refused Entry's metadata
// and creating a CONNECTOR output). The dispute's tx::fork-attest must SPEND that
// connector, so it only exists on a chain where the exit-ladder was mined. Two
// sighash tricks make this work (per the Cube paper):
//   (a) the Engine pre-signs its input with SIGHASH_ALL|ANYONECANPAY, which
//       commits to all OUTPUTS but only its OWN input — so the challenger can
//       attach the connector input later without invalidating the pre-signature;
//   (b) a SIGHASH_ALL signature pins ALL inputs (including the connector outpoint),
//       so the pre-signature is invalid against any fork-attest using a different
//       connector (a different/forked exit-ladder) — that's the fork attestation.
//
// We build a canonical exit-ladder E and a forked one E', and show the
// SIGHASH_ALL signature binds the dispute to E's connector, while the
// ANYONECANPAY signature is robust to the challenger adding the connector input.

#[cfg(test)]
mod exit_ladder {
    use bitcoin::hashes::Hash;
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::transaction::Version;
    use bitcoin::{absolute::LockTime, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};

    use cube::transmutative::secp::schnorr::{sign, verify_xonly, SchnorrSigningMode};

    const ENGINE_SK: &str = "1cc5906ab936b1e29db24fffe9f87b33a4c64f2d3b59aed6c3c4faeb8fcba6da";
    const ENGINE_PK_X: &str = "cb70281face51a77d51400612196032bb12422d4c07fa42997a0ab39c2431455";

    fn engine_sk() -> [u8; 32] { hex::decode(ENGINE_SK).unwrap().try_into().unwrap() }
    fn engine_x() -> [u8; 32] { hex::decode(ENGINE_PK_X).unwrap().try_into().unwrap() }

    // An exit-ladder tx: carries refused-Entry metadata (OP_RETURN) and creates a
    // connector output at vout 0. `tag` distinguishes the canonical chain from a fork.
    fn exit_ladder(tag: u8) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: Txid::from_byte_array([tag; 32]), vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![
                // vout 0: the connector (dust anchor the dispute must spend)
                TxOut { value: Amount::from_sat(330), script_pubkey: ScriptBuf::new_op_return(&[tag]) },
                // vout 1: APE-encoded refused Entry metadata (illustrative)
                TxOut { value: Amount::from_sat(0), script_pubkey: ScriptBuf::new_op_return(b"refused-entry-metadata") },
            ],
        }
    }

    // tx::fork-attest spending [bonded engine funds, connector].
    fn fork_attest(bond: OutPoint, connector: OutPoint) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![
                TxIn { previous_output: bond, script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() },
                TxIn { previous_output: connector, script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() },
            ],
            output: vec![TxOut { value: Amount::from_sat(99_000), script_pubkey: ScriptBuf::new_op_return(b"punishment-payout") }],
        }
    }

    #[test]
    fn fork_attest_binds_the_dispute_to_the_canonical_exit_ladder() {
        // The engine's bonded output (what the dispute punishes).
        let bond_outpoint = OutPoint { txid: Txid::from_byte_array([0xbb; 32]), vout: 0 };
        let bond_txout = TxOut { value: Amount::from_sat(100_000), script_pubkey: ScriptBuf::new_op_return(b"engine-bond") };

        // Canonical exit-ladder E and a forked alternative E' (different connector).
        let e = exit_ladder(0x01);
        let e_fork = exit_ladder(0x02);
        let connector = OutPoint { txid: e.compute_txid(), vout: 0 };
        let connector_txout = e.output[0].clone();
        let connector_fork = OutPoint { txid: e_fork.compute_txid(), vout: 0 };
        let connector_fork_txout = e_fork.output[0].clone();
        assert_ne!(connector, connector_fork, "fork has a different connector outpoint");

        let f = fork_attest(bond_outpoint, connector);
        let f_fork = fork_attest(bond_outpoint, connector_fork);

        // --- (b) SIGHASH_ALL pins ALL inputs incl. the connector -> fork binding ---
        let sighash_all_f = SighashCache::new(&f)
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&[bond_txout.clone(), connector_txout.clone()]), TapSighashType::All)
            .unwrap().to_byte_array();
        let sig_all = sign(engine_sk(), sighash_all_f, SchnorrSigningMode::BIP340).unwrap();
        assert!(verify_xonly(engine_x(), sighash_all_f, sig_all, SchnorrSigningMode::BIP340),
            "engine's SIGHASH_ALL presig is valid for the dispute over the canonical connector");

        // The same pre-signature must NOT validate for a fork-attest using the forked
        // connector — the Engine can't move the dispute to a chain lacking E.
        let sighash_all_fork = SighashCache::new(&f_fork)
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&[bond_txout.clone(), connector_fork_txout]), TapSighashType::All)
            .unwrap().to_byte_array();
        assert_ne!(sighash_all_f, sighash_all_fork, "SIGHASH_ALL commits to the connector input");
        assert!(!verify_xonly(engine_x(), sighash_all_fork, sig_all, SchnorrSigningMode::BIP340),
            "fork attestation: the presig does not validate against a different/forked connector");

        // --- (a) SIGHASH_ALL|ANYONECANPAY lets the challenger ATTACH the connector ---
        // The ANYONECANPAY sighash over the engine's input is the SAME whether or not
        // the challenger has added the connector input yet (it commits only the
        // engine's own prevout + all outputs), so the engine can pre-sign early.
        let mut f_without_connector = f.clone();
        f_without_connector.input.truncate(1); // before the challenger attaches the connector
        let acp = TapSighashType::AllPlusAnyoneCanPay;
        let sighash_acp_pre = SighashCache::new(&f_without_connector)
            .taproot_key_spend_signature_hash(0, &Prevouts::One(0, bond_txout.clone()), acp)
            .unwrap().to_byte_array();
        let sighash_acp_post = SighashCache::new(&f)
            .taproot_key_spend_signature_hash(0, &Prevouts::One(0, bond_txout.clone()), acp)
            .unwrap().to_byte_array();
        assert_eq!(sighash_acp_pre, sighash_acp_post,
            "ANYONECANPAY: engine's presig survives the challenger attaching the connector input");
        let sig_acp = sign(engine_sk(), sighash_acp_pre, SchnorrSigningMode::BIP340).unwrap();
        assert!(verify_xonly(engine_x(), sighash_acp_post, sig_acp, SchnorrSigningMode::BIP340));

        println!("EXIT-LADDER / FORK-ATTEST EXPLORED: the connector outpoint binds the dispute to the canonical exit-ladder (SIGHASH_ALL presig fails on a forked connector), while SIGHASH_ALL|ANYONECANPAY lets the engine pre-sign before the challenger attaches that connector. No fork-selection escape.");
    }
}
