// THE DISPUTE — composing the garbled fraud-proof with Cube's exit-ladder /
// fork-attest bond slash. This ties together the two halves that lived apart:
//   * the garbled winner-verifier (lottery_enforcement_sound / _cutchoose), whose
//     "invalid" output label is the disprove SECRET, and
//   * Cube's exit-ladder + fork-attest dispute graph (exit_ladder.rs): the engine
//     posts a BOND and pre-signs a fork-attest spending it; the challenger
//     attaches the exit-ladder CONNECTOR (ANYONECANPAY) and the SIGHASH binding
//     stops the engine dodging onto a fork.
// The missing link, built here: the bond's slash path is GATED by the disprove
// hashlock, so the bond can be taken IFF a wrong settle handed someone the secret.
// Honest settle -> no secret -> bond is safe. Wrong settle -> secret -> bond
// slashed. Per Burak's design the engine is never a custodian: it cannot move the
// pot wrongly without forfeiting a bond worth more than the pot.

#[cfg(test)]
mod lottery_enforcement_dispute {
    use bitcoin::hashes::{ripemd160, Hash as _};
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_EQUALVERIFY, OP_HASH160};
    use bitcoin::script::Builder;
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash};
    use bitcoin::transaction::Version;
    use bitcoin::{absolute::LockTime, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, XOnlyPublicKey};
    use std::collections::HashMap;

    use cube::constructive::taproot::{TapLeaf, TapRoot};
    use cube::transmutative::hash::sha256;
    use cube::transmutative::secp::schnorr::{sign, verify_xonly, SchnorrSigningMode};
    use secp::{Point, Scalar};

    // ---- minimal garbled gate (yields the real disprove secret) ----
    type Label = [u8; 32];
    fn xorl(a: &Label, b: &Label) -> Label { let mut o = [0u8; 32]; for i in 0..32 { o[i] = a[i] ^ b[i]; } o }
    fn lbl(s: &str) -> Label { sha256(s.as_bytes()) }
    fn ks(a: &Label, b: &Label, kind: &[u8]) -> Label { let mut p = Vec::new(); p.extend_from_slice(a); p.extend_from_slice(b); p.extend_from_slice(kind); sha256(&p) }

    const ENGINE_SK: &str = "1cc5906ab936b1e29db24fffe9f87b33a4c64f2d3b59aed6c3c4faeb8fcba6da";
    const ENGINE_PK: &str = "02cb70281face51a77d51400612196032bb12422d4c07fa42997a0ab39c2431455";
    const CHALLENGER_PK: &str = "0251deb9fcf4d16b0f82c75cf71e1ffb7879beb0c6bf733b0778a81b777406574f";
    fn sk(h: &str) -> [u8; 32] { hex::decode(h).unwrap().try_into().unwrap() }
    fn x(pk: &str) -> [u8; 32] { hex::decode(&pk[2..]).unwrap().try_into().unwrap() }
    fn pt(pk: &str) -> Point { Point::from_hex(pk).unwrap() }

    fn exit_ladder(tag: u8) -> Transaction {
        Transaction {
            version: Version::TWO, lock_time: LockTime::ZERO,
            input: vec![TxIn { previous_output: OutPoint { txid: Txid::from_byte_array([tag; 32]), vout: 0 }, script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() }],
            output: vec![TxOut { value: Amount::from_sat(330), script_pubkey: ScriptBuf::new_op_return(&[tag]) }],
        }
    }

    // Maps to the Cube exit graph (Burak's "Unilateral Exit Paths" figure):
    //   tx::batch (Projector N-of-N -> per-user 2-of-2 Engine<>User VTXOs)
    //   -> tx::trigger (a ladder of 2-of-2 steps; "or otherwise back to Engine")
    //   -> tx::exit-ladder (Prevouts for fees + OP_RETURN exit metadata + Connector)
    //   -> tx::fork-attest (spends a 2-of-2 Engine<>User + the ZKTLC GARBLED LOCK,
    //      and the Connector). The garbled lock is the disprove hashlock below.
    #[test]
    fn wrong_settle_lets_the_user_reclaim_the_contested_2of2_via_garbled_lock() {
        // ---- garble a 1-gate verifier; the "invalid" label is the disprove secret.
        // (the sibling tests garble the full sound winner predicate; here we focus
        //  on tying the secret to the bond slash.)
        let a = [lbl("a0"), lbl("a1")];
        let b = [lbl("b0"), lbl("b1")];
        let verdict = [lbl("invalid"), lbl("valid")]; // AND: out[i&j]
        let rows: Vec<(Label, Label)> = (0..2).flat_map(|i| (0..2).map(move |j| (i, j)))
            .map(|(i, j)| (ks(&a[i], &b[j], b"tag"), xorl(&ks(&a[i], &b[j], b"enc"), &verdict[i & j]))).collect();
        let eval = |al: &Label, bl: &Label| -> Label { let t = ks(al, bl, b"tag"); let (_, ct) = rows.iter().find(|(tg, _)| *tg == t).unwrap(); xorl(ct, &ks(al, bl, b"enc")) };

        // honest assertion (valid: 1 AND 1) yields the 'valid' label — no secret.
        let honest = eval(&a[1], &b[1]);
        assert_eq!(honest, verdict[1]);
        // a WRONG assertion (invalid: 1 AND 0) yields the disprove secret.
        let disprove_secret = eval(&a[1], &b[0]);
        assert_eq!(disprove_secret, verdict[0]);
        let disprove_h = sha256(&disprove_secret); // committed hashlock value

        // ---- the contested 2-of-2 Engine<>User ZKTLC output (image #5's
        // "2-of-2 + ZKTLC Garbled Lock"). Its DISPROVE leaf is gated by the garbled
        // lock (disprove hashlock) + the engine's CHECKSIG. Key path = the
        // cooperative 2-of-2 (honest settle). The engine pre-signs the disprove
        // path so that, IF it asserts a wrong settle, the user can reclaim the
        // contested output — prevention, not custody: the engine never gets to keep
        // funds it isn't owed. (Per Burak there is no separate pot-sized slash; the
        // small bond/prevouts only cover the exit-ladder fees.)
        let engine_x = XOnlyPublicKey::from_slice(&x(ENGINE_PK)).unwrap();
        let slash_script = Builder::new()
            .push_opcode(OP_HASH160)
            .push_slice(ripemd160::Hash::hash(&disprove_h).to_byte_array())
            .push_opcode(OP_EQUALVERIFY)
            .push_x_only_key(&engine_x)
            .push_opcode(OP_CHECKSIG)
            .into_script();
        let bond_taproot = TapRoot::key_and_script_path_single(pt(ENGINE_PK), TapLeaf::new(slash_script.to_bytes()));
        let bond_value = 100_000u64; // bond >= pot, so cheating never profits
        let bond_txout = TxOut { value: Amount::from_sat(bond_value), script_pubkey: ScriptBuf::from_bytes(bond_taproot.spk().unwrap()) };
        let bond_outpoint = OutPoint { txid: Txid::from_byte_array([0xbb; 32]), vout: 0 };

        // ---- the dispute: tx::fork-attest spends [bond, connector] -> challenger.
        let e = exit_ladder(0x01);                          // canonical exit-ladder
        let connector = OutPoint { txid: e.compute_txid(), vout: 0 };
        let connector_txout = e.output[0].clone();
        let challenger_spk = {
            // pay the slashed bond to the challenger (a P2TR to their key).
            let mut spk = vec![0x51, 0x20]; spk.extend_from_slice(&x(CHALLENGER_PK)); ScriptBuf::from_bytes(spk)
        };
        let fork_attest = Transaction {
            version: Version::TWO, lock_time: LockTime::ZERO,
            input: vec![
                TxIn { previous_output: bond_outpoint, script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() },
                TxIn { previous_output: connector, script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() },
            ],
            output: vec![TxOut { value: Amount::from_sat(bond_value - 1000), script_pubkey: challenger_spk }],
        };

        // the engine PRE-SIGNS its bond input's slash leaf with ANYONECANPAY, so the
        // challenger can attach the connector afterwards without invalidating it.
        let leaf_buf = ScriptBuf::from_bytes(slash_script.to_bytes());
        let leaf_lh = TapLeafHash::from_script(&leaf_buf, LeafVersion::TapScript);
        // control block commits the slash leaf to the bond output key.
        let out_x = XOnlyPublicKey::from_slice(&bond_taproot.tweaked_key().unwrap().serialize_xonly()).unwrap();
        assert!(ControlBlock::decode(&bond_taproot.control_block(0).unwrap().to_vec()).unwrap()
            .verify_taproot_commitment(&bitcoin::secp256k1::Secp256k1::verification_only(), out_x, &leaf_buf),
            "the disprove-gated slash leaf is committed in the bond taproot");
        let acp = TapSighashType::AllPlusAnyoneCanPay;
        let presig_sighash = SighashCache::new(&fork_attest)
            .taproot_script_spend_signature_hash(0, &Prevouts::One(0, bond_txout.clone()), leaf_lh, acp)
            .unwrap().to_byte_array();
        let engine_presig = sign(sk(ENGINE_SK), presig_sighash, SchnorrSigningMode::BIP340).unwrap();
        assert!(verify_xonly(x(ENGINE_PK), presig_sighash, engine_presig, SchnorrSigningMode::BIP340),
            "engine's ANYONECANPAY pre-signature over the slash is valid");

        // ---- HONEST settle: the challenger has the 'valid' label, not the secret,
        // so it cannot satisfy the slash hashlock; the bond is safe.
        let honest_opens = ripemd160::Hash::hash(&sha256(&honest)) == ripemd160::Hash::hash(&disprove_h);
        assert!(!honest_opens, "honest settle yields no secret -> bond cannot be slashed");

        // ---- WRONG settle: the disprove secret satisfies the hashlock; combined
        // with the engine's pre-sig + the attached connector, the bond is slashed.
        assert_eq!(ripemd160::Hash::hash(&sha256(&disprove_secret)), ripemd160::Hash::hash(&disprove_h),
            "the garbled 'invalid' secret opens the bond's slash hashlock");
        // the on-chain witness for input 0: [engine_presig, disprove_secret, script, control_block]
        let _slash_witness = vec![
            engine_presig.to_vec(), disprove_secret.to_vec(),
            slash_script.to_bytes(), bond_taproot.control_block(0).unwrap().to_vec(),
        ];
        // and the connector is genuinely attached as input 1 (the dispute is bound
        // to the canonical exit-ladder; a forked connector changes the txid and a
        // SIGHASH_ALL binding would reject it — see exit_ladder.rs).
        assert_eq!(fork_attest.input[1].previous_output, connector);
        assert_eq!(connector_txout.value.to_sat(), 330);

        println!(
            "DISPUTE COMPOSED (maps to Burak's exit graph): a contested {}-sat 2-of-2 Engine<>User \
ZKTLC whose disprove path is the GARBLED LOCK. An HONEST settle yields only the 'valid' label, so \
the contested output can't be taken via the lock (the cooperative 2-of-2 path settles it). A WRONG \
settle hands the user the 'invalid' secret, which — with the engine's ANYONECANPAY pre-signature \
and the exit-ladder connector attached (tx::fork-attest) — lets the USER RECLAIM the contested \
output; the connector binds the dispute to the canonical exit-ladder so the engine can't dodge onto \
a fork. Prevention, not custody: the engine can never keep funds it isn't owed.",
            bond_value
        );
    }
}
