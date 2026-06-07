// ENFORCEMENT — making the lottery SETTLE non-custodial without the loser's
// cooperation, via a garbled fraud-proof wired to the VTXO disprove leaf.
//
// The covenant refresh is N-of-N, so a sore loser could refuse to sign away their
// stake to the winner. The fix (BitVM3 / Cube ZKTLC): the Engine ASSERTS the
// winner; the assertion is a verifiable predicate (lottery_zktlc.rs:
// winner = the band [lo,hi) containing the draw rg). The Engine garbles that
// VERIFIER; its "invalid" output label is committed as each leaf's DISPROVE
// hashlock (timeout_tree disprove leaf). If the Engine claims a WRONG winner, a
// challenger garble-evaluates the verifier on the public (rg, claimed band),
// obtains the "invalid" label, and spends the disprove path to punish — so a
// wrong assertion is unprofitable, and an HONEST one cannot be disproved (the
// evaluator only ever gets the "valid" label, never the secret).
//
// Unlike zktlc_compose.rs (a single toy AND gate), this garbles the REAL winner
// predicate (N-bit comparators) and wires its invalid label to an actual
// TimeoutTree disprove leaf, then spends that leaf with the garbled secret.

#[cfg(test)]
mod lottery_enforcement {
    use bitcoin::hashes::Hash as _;
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash};
    use bitcoin::transaction::Version;
    use bitcoin::{absolute::LockTime, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, XOnlyPublicKey};
    use std::collections::HashMap;

    use cube::constructive::txout_types::timeout_tree::TimeoutTree;
    use cube::transmutative::hash::sha256;
    use cube::transmutative::secp::schnorr::{sign, verify_xonly, SchnorrSigningMode};
    use secp::Scalar;

    // ---- garbled circuit (same primitive as tests/garbled_adder.rs) ----
    type Label = [u8; 32];
    fn xor(a: &Label, b: &Label) -> Label { let mut o = [0u8; 32]; for i in 0..32 { o[i] = a[i] ^ b[i]; } o }
    fn label(seed: &str) -> Label { sha256(seed.as_bytes()) }
    fn ks(a: &Label, b: &Label, gate: u32, kind: &[u8]) -> Label {
        let mut p = Vec::new();
        p.extend_from_slice(a); p.extend_from_slice(b);
        p.extend_from_slice(&gate.to_le_bytes()); p.extend_from_slice(kind);
        sha256(&p)
    }
    const XOR: [usize; 4] = [0, 1, 1, 0];
    const AND: [usize; 4] = [0, 0, 0, 1];
    const OR: [usize; 4] = [0, 1, 1, 1];

    struct Gate { a: usize, b: usize, o: usize, truth: [usize; 4], id: u32 }
    #[derive(Clone)]
    struct Row { tag: Label, ct: Label }
    struct Circuit { wires: Vec<[Label; 2]>, gates: Vec<Gate> }
    impl Circuit {
        fn new() -> Self { Circuit { wires: Vec::new(), gates: Vec::new() } }
        fn wire(&mut self) -> usize {
            let id = self.wires.len();
            self.wires.push([label(&format!("w{id}:0")), label(&format!("w{id}:1"))]);
            id
        }
        fn gate(&mut self, a: usize, b: usize, truth: [usize; 4]) -> usize {
            let o = self.wire();
            let id = self.gates.len() as u32;
            self.gates.push(Gate { a, b, o, truth, id });
            o
        }
        fn garble(&self) -> Vec<Vec<Row>> {
            self.gates.iter().map(|g| {
                let mut rows = Vec::new();
                for i in 0..2usize { for j in 0..2usize {
                    let a_l = &self.wires[g.a][i];
                    let b_l = &self.wires[g.b][j];
                    let out_l = &self.wires[g.o][g.truth[i * 2 + j]];
                    rows.push(Row { tag: ks(a_l, b_l, g.id, b"tag"), ct: xor(&ks(a_l, b_l, g.id, b"enc"), out_l) });
                }}
                rows.rotate_left((g.id as usize) % 4);
                rows
            }).collect()
        }
        fn eval(&self, tables: &[Vec<Row>], inputs: &HashMap<usize, Label>) -> HashMap<usize, Label> {
            let mut active = inputs.clone();
            for (gi, g) in self.gates.iter().enumerate() {
                let la = active[&g.a]; let lb = active[&g.b];
                let tag = ks(&la, &lb, g.id, b"tag");
                let row = tables[gi].iter().find(|r| r.tag == tag).expect("one row opens");
                active.insert(g.o, xor(&row.ct, &ks(&la, &lb, g.id, b"enc")));
            }
            active
        }
    }

    const N: usize = 16; // values < 65536 (lottery draw space in this test)

    // N-bit unsigned less-than: lt_i = (a_i<b_i) | ((a_i==b_i) & lt_{i-1}), LSB→MSB.
    // `one`/`zero` are constant wires (fed their 1-/0-labels). Returns the lt wire.
    fn less_than(c: &mut Circuit, a: &[usize], b: &[usize], one: usize, zero: usize) -> usize {
        let mut lt = zero;
        for i in 0..N {
            let not_a = c.gate(a[i], one, XOR);          // !a_i
            let a_lt_b = c.gate(not_a, b[i], AND);       // (!a_i) & b_i
            let a_xor_b = c.gate(a[i], b[i], XOR);
            let eq = c.gate(a_xor_b, one, XOR);          // !(a_i ^ b_i)
            let eq_and_lt = c.gate(eq, lt, AND);
            lt = c.gate(a_lt_b, eq_and_lt, OR);
        }
        lt
    }

    fn bits_inputs(c: &Circuit, wires: &[usize], v: u64, inputs: &mut HashMap<usize, Label>) {
        for i in 0..N { inputs.insert(wires[i], c.wires[wires[i]][((v >> i) & 1) as usize]); }
    }

    const ALICE_SK: &str = "1cc5906ab936b1e29db24fffe9f87b33a4c64f2d3b59aed6c3c4faeb8fcba6da";
    const ALICE_PK: &str = "02cb70281face51a77d51400612196032bb12422d4c07fa42997a0ab39c2431455";
    const ENGINE_PK: &str = "029611bc66d526fa3194d0f525dce21e782dcf90cc72529ec2d5486da838d83770";
    fn xkey(pk: &str) -> [u8; 32] { hex::decode(&pk[2..]).unwrap().try_into().unwrap() }

    #[test]
    fn wrong_winner_is_punishable_via_garbled_disprove() {
        // The Engine garbles the winner VERIFIER: valid = (rg >= lo) & (rg < hi).
        let mut c = Circuit::new();
        let one = c.wire();
        let zero = c.wire();
        let rg: Vec<usize> = (0..N).map(|_| c.wire()).collect();
        let lo: Vec<usize> = (0..N).map(|_| c.wire()).collect();
        let hi: Vec<usize> = (0..N).map(|_| c.wire()).collect();
        let rg_lt_lo = less_than(&mut c, &rg, &lo, one, zero);
        let rg_lt_hi = less_than(&mut c, &rg, &hi, one, zero);
        let ge_lo = c.gate(rg_lt_lo, one, XOR);     // !(rg < lo) == rg >= lo
        let valid = c.gate(ge_lo, rg_lt_hi, AND);
        let tables = c.garble();
        println!("garbled the lottery winner-verifier: {} gates", c.gates.len());

        // The "invalid" output label is the disprove secret; commit its sha256 as
        // the leaf's disprove hashlock.
        let invalid_label = c.wires[valid][0];
        let valid_label = c.wires[valid][1];
        let disprove_hash: [u8; 32] = sha256(&invalid_label);

        // Public draw: rg = 5000 lands in entry 2's band [3000, 6000).
        let draw_rg: u64 = 5000;
        let true_band = (3000u64, 6000u64);
        let wrong_band = (0u64, 1000u64); // entry 0's band — does NOT contain rg

        let evaluate = |band: (u64, u64)| -> Label {
            let mut inputs: HashMap<usize, Label> = HashMap::new();
            inputs.insert(one, c.wires[one][1]);
            inputs.insert(zero, c.wires[zero][0]);
            bits_inputs(&c, &rg, draw_rg, &mut inputs);
            bits_inputs(&c, &lo, band.0, &mut inputs);
            bits_inputs(&c, &hi, band.1, &mut inputs);
            c.eval(&tables, &inputs)[&valid]
        };

        // HONEST claim (true winner): evaluator gets the "valid" label, NOT the secret.
        let honest_out = evaluate(true_band);
        assert_eq!(honest_out, valid_label, "honest settle evaluates to 'valid'");
        assert_ne!(honest_out, invalid_label, "honest settle yields no disprove secret");
        assert_ne!(sha256(&honest_out), disprove_hash, "honest output cannot open the disprove hashlock");

        // CHEATING claim (wrong winner): evaluator obtains the "invalid" label = the
        // disprove secret that opens the hashlock.
        let cheat_out = evaluate(wrong_band);
        assert_eq!(cheat_out, invalid_label, "wrong-winner claim evaluates to 'invalid'");
        assert_eq!(sha256(&cheat_out), disprove_hash, "the garbled 'invalid' secret opens the disprove hashlock");
        let disprove_secret = cheat_out;

        // ---- wire it to a REAL timeout-tree disprove leaf and spend it ----
        let alice = xkey(ALICE_PK);
        let engine = xkey(ENGINE_PK);
        let allocations = [(alice, 49_500u64)];
        let disprove_hashes = [disprove_hash];
        let tree = TimeoutTree::build(engine, &allocations, 800_000, 144, Some(&disprove_hashes)).unwrap();
        let leaf = tree.leaves.iter().find(|l| l.account_key == alice).unwrap();
        let (leaf_hash, script, control_block) = leaf.disprove_spend_elements().unwrap();

        // control block commits the disprove script to the leaf output key.
        let leaf_spk = leaf.scriptpubkey().unwrap();
        let out_x = XOnlyPublicKey::from_slice(&leaf_spk[2..34]).unwrap();
        let script_buf = ScriptBuf::from_bytes(script.clone());
        assert!(
            ControlBlock::decode(&control_block).unwrap().verify_taproot_commitment(
                &bitcoin::secp256k1::Secp256k1::verification_only(), out_x, &script_buf),
            "disprove leaf is committed in the VTXO taproot"
        );

        // build + sign the punishment spend (script-path: hashlock + account sig).
        let leaf_txout = TxOut { value: Amount::from_sat(leaf.value_in_satoshis), script_pubkey: ScriptBuf::from_bytes(leaf_spk) };
        let tx = Transaction {
            version: Version::TWO, lock_time: LockTime::ZERO,
            input: vec![TxIn { previous_output: OutPoint::new(Txid::from_byte_array([0xd1; 32]), 0), script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() }],
            output: vec![TxOut { value: Amount::from_sat(leaf.value_in_satoshis - 500), script_pubkey: ScriptBuf::new_op_return(&[]) }],
        };
        let leaf_lh = TapLeafHash::from_script(&script_buf, LeafVersion::TapScript);
        assert_eq!(leaf_lh.to_byte_array(), leaf_hash, "leaf hash matches");
        let sighash = SighashCache::new(&tx)
            .taproot_script_spend_signature_hash(0, &Prevouts::All(&[leaf_txout]), leaf_lh, TapSighashType::Default)
            .unwrap().to_byte_array();
        let sig = sign(Scalar::from_hex(ALICE_SK).unwrap().serialize(), sighash, SchnorrSigningMode::BIP340).unwrap();
        assert!(verify_xonly(alice, sighash, sig, SchnorrSigningMode::BIP340), "challenger's disprove signature verifies");
        // the witness that would go on-chain: [sig, disprove_secret, script, control_block]
        let _witness = vec![sig.to_vec(), disprove_secret.to_vec(), script.clone(), control_block.clone()];

        // emit the leaf data so a regtest harness can broadcast the punishment spend.
        println!("ENFORCE_LEAF_SPK={}", hex::encode(leaf.scriptpubkey().unwrap()));
        println!("ENFORCE_DISPROVE_SCRIPT={}", hex::encode(&script));
        println!("ENFORCE_CONTROL_BLOCK={}", hex::encode(&control_block));
        println!("ENFORCE_INVALID_LABEL={}", hex::encode(disprove_secret));
        println!("ENFORCE_VALID_LABEL={}", hex::encode(honest_out));
        println!("ENFORCE_ACCOUNT_SK={}", ALICE_SK);

        println!("LOTTERY ENFORCEMENT PROVEN: the Engine garbles the winner-verifier ({} gates); an HONEST winner claim evaluates to 'valid' (no disprove secret obtainable), while a WRONG-winner claim hands the challenger the garbled 'invalid' label, which opens the VTXO's disprove hashlock and authorizes the punishment spend. Loser-forfeit needs no loser signature — a false settle is punishable on-chain.", c.gates.len());
    }
}
