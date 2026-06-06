// Exploring "disprovable computation" — the core idea behind BitVM3 and Cube's
// ZKTLC, built from scratch (no deps beyond cube's sha256).
//
// A GARBLED CIRCUIT lets one party (the "garbler" — in Cube, the Engine) encrypt
// a boolean circuit so another party (the "evaluator" — the challenger) can run
// it on specific inputs and learn ONLY the output, nothing else. Each wire gets
// two random 32-byte LABELS, one meaning 0 and one meaning 1. A gate is a 4-row
// table where each row encrypts the output-wire label under the two input-wire
// labels of that truth-table row. With one input label per wire, the evaluator
// decrypts exactly one row -> one output label.
//
// Why Bitcoin cares: commit hash(output_label_for_0) and hash(output_label_for_1)
// as on-chain hashlocks. The circuit here is a VERIFIER: output 1 = "the Engine's
// asserted state transition is valid", output 0 = "invalid". If the Engine lies,
// the evaluator garble-evaluates the verifier, obtains the output-0 label, and
// thereby learns the preimage to the DISPROVE hashlock — unlocking the punitive
// path on Bitcoin. (BitVM3 garbles a Groth16 *verifier* circuit this way; "valid
// proof -> output 1". This demo uses a single AND gate to show the mechanism.)

#[cfg(test)]
mod garbled_circuit_demo {
    use cube::transmutative::hash::sha256;

    type Label = [u8; 32];

    fn xor(a: &Label, b: &Label) -> Label {
        let mut o = [0u8; 32];
        for i in 0..32 {
            o[i] = a[i] ^ b[i];
        }
        o
    }

    // Deterministic "random" label from a seed (a real garbler uses a CSPRNG;
    // determinism here just makes the test reproducible).
    fn label(seed: &str) -> Label {
        sha256(seed.as_bytes())
    }

    // Per-row keystream / tag derived from the two input labels (+ a gate id).
    // The tag lets the evaluator find the one row it can open without revealing
    // which inputs the other rows correspond to.
    fn row_keystream(a: &Label, b: &Label, gate: u8) -> Label {
        let mut pre = Vec::new();
        pre.extend_from_slice(a);
        pre.extend_from_slice(b);
        pre.push(gate);
        pre.extend_from_slice(b"enc");
        sha256(&pre)
    }
    fn row_tag(a: &Label, b: &Label, gate: u8) -> Label {
        let mut pre = Vec::new();
        pre.extend_from_slice(a);
        pre.extend_from_slice(b);
        pre.push(gate);
        pre.extend_from_slice(b"tag");
        sha256(&pre)
    }

    #[derive(Clone)]
    struct GarbledRow {
        tag: Label,         // = row_tag(in_a_label, in_b_label, gate)
        ciphertext: Label,  // = row_keystream(...) XOR output_label
    }

    /// Garble an AND gate. Returns (rows, [out0, out1]).
    fn garble_and(a: [Label; 2], b: [Label; 2], out: [Label; 2], gate: u8) -> Vec<GarbledRow> {
        let mut rows = Vec::new();
        for i in 0..2usize {
            for j in 0..2usize {
                let result = i & j; // AND truth table
                rows.push(GarbledRow {
                    tag: row_tag(&a[i], &b[j], gate),
                    ciphertext: xor(&row_keystream(&a[i], &b[j], gate), &out[result]),
                });
            }
        }
        // Permute so row position doesn't leak the inputs (deterministic shuffle).
        rows.reverse();
        rows.rotate_left(1);
        rows
    }

    /// Evaluate: given ONE label per input wire, recover the single output label.
    fn evaluate(rows: &[GarbledRow], a_label: &Label, b_label: &Label, gate: u8) -> Option<Label> {
        let my_tag = row_tag(a_label, b_label, gate);
        for row in rows {
            if row.tag == my_tag {
                return Some(xor(&row.ciphertext, &row_keystream(a_label, b_label, gate)));
            }
        }
        None
    }

    #[test]
    fn garbled_and_gate_reveals_only_the_evaluated_output_and_a_disprove_secret() {
        let gate = 0x01;
        // Garbler picks two labels per wire (0-label, 1-label).
        let a = [label("a:0"), label("a:1")];
        let b = [label("b:0"), label("b:1")];
        // The OUTPUT wire of our "verifier": out[1] = valid, out[0] = invalid.
        let out = [label("verdict:invalid"), label("verdict:valid")];

        let rows = garble_and(a, b, out, gate);

        // On-chain commitments (hashlocks): the preimage of DISPROVE_HASH is the
        // output-0 ("invalid") label. Whoever produces it can take the punishment.
        let disprove_hash = sha256(&out[0]); // commit hash(invalid-label)
        let valid_hash = sha256(&out[1]);

        // --- Case 1: honest/valid computation (a=1, b=1 -> AND=1 -> "valid") ---
        let got_valid = evaluate(&rows, &a[1], &b[1], gate).expect("decrypt one row");
        assert_eq!(got_valid, out[1], "1 AND 1 -> valid label");
        assert_eq!(sha256(&got_valid), valid_hash);
        assert_ne!(sha256(&got_valid), disprove_hash, "no disprove secret leaked on valid");

        // --- Case 2: the verifier rejects (a=1, b=0 -> AND=0 -> "invalid") ---
        // The evaluator (challenger) obtains the INVALID label = the disprove
        // preimage, and can now unlock the punitive Bitcoin path.
        let got_invalid = evaluate(&rows, &a[1], &b[0], gate).expect("decrypt one row");
        assert_eq!(got_invalid, out[0], "1 AND 0 -> invalid label");
        assert_eq!(
            sha256(&got_invalid),
            disprove_hash,
            "invalid evaluation reveals the on-chain DISPROVE preimage"
        );

        // --- Key secrecy property: evaluating one input combo reveals ONLY that
        // output label; the evaluator cannot derive the other output label (so it
        // can't forge the 'valid' verdict when the real verdict is 'invalid'). ---
        assert_ne!(got_invalid, out[1]);
        // It also can't open a different row (no matching tag for inputs it lacks
        // labels for) — it only ever holds one label per wire.
        assert!(evaluate(&rows, &a[0], &b[1], gate).is_some()); // could, IF it had a[0]
        // but in a real run the garbler delivers only the labels for the actual
        // inputs (via oblivious transfer), so the evaluator holds exactly one per wire.

        println!("GARBLED CIRCUIT EXPLORED: evaluate -> one output label; an 'invalid' verdict yields the Bitcoin DISPROVE preimage (this is the BitVM3/ZKTLC punishment mechanism). A full ZKTLC garbles a Groth16 verifier circuit the same way.");
    }
}
