// Part 2 of the garbled-circuit exploration: COMPOSITION.
//
// A single garbled gate (see garbled_circuit_demo.rs) only gets you one boolean
// op. Real disprovable computation — e.g. BitVM3 garbling a *Groth16 verifier* —
// is millions of gates wired together. The trick that makes this work: a gate's
// output-wire labels ARE the input-wire labels of the next gate. So the evaluator
// decrypts gate 1 to get an intermediate wire label, then feeds that very label
// straight into gate 2, and so on, learning only the labels along the actual
// execution path and ultimately one final output label ("proof valid?" = 1/0).
//
// Here we build f(a,b,c) = (a AND b) OR c from two chained garbled gates and
// check it computes correctly for all 8 inputs while only ever revealing the
// labels on the evaluated path.

#[cfg(test)]
mod garbled_circuit_compose {
    use cube::transmutative::hash::sha256;

    type Label = [u8; 32];

    fn xor(a: &Label, b: &Label) -> Label {
        let mut o = [0u8; 32];
        for i in 0..32 {
            o[i] = a[i] ^ b[i];
        }
        o
    }
    fn label(seed: &str) -> Label {
        sha256(seed.as_bytes())
    }
    fn ks(a: &Label, b: &Label, gate: u8, kind: &[u8]) -> Label {
        let mut p = Vec::new();
        p.extend_from_slice(a);
        p.extend_from_slice(b);
        p.push(gate);
        p.extend_from_slice(kind);
        sha256(&p)
    }

    #[derive(Clone)]
    struct Row {
        tag: Label,
        ct: Label,
    }

    /// Garble any 2-input boolean gate given its truth-table function.
    fn garble(in1: [Label; 2], in2: [Label; 2], out: [Label; 2], gate: u8, f: impl Fn(usize, usize) -> usize) -> Vec<Row> {
        let mut rows = Vec::new();
        for i in 0..2usize {
            for j in 0..2usize {
                rows.push(Row {
                    tag: ks(&in1[i], &in2[j], gate, b"tag"),
                    ct: xor(&ks(&in1[i], &in2[j], gate, b"enc"), &out[f(i, j)]),
                });
            }
        }
        rows.rotate_left(3); // permute
        rows
    }

    fn eval(rows: &[Row], l1: &Label, l2: &Label, gate: u8) -> Option<Label> {
        let t = ks(l1, l2, gate, b"tag");
        rows.iter()
            .find(|r| r.tag == t)
            .map(|r| xor(&r.ct, &ks(l1, l2, gate, b"enc")))
    }

    #[test]
    fn two_chained_gates_compute_a_and_b_or_c() {
        // Wires: a, b, c (inputs), w (= a AND b, intermediate), out (= w OR c).
        let a = [label("a0"), label("a1")];
        let b = [label("b0"), label("b1")];
        let c = [label("c0"), label("c1")];
        let w = [label("w0"), label("w1")];
        let out = [label("out0"), label("out1")];

        // Garbler builds both gates. gate2's FIRST input wire reuses w's labels —
        // that's the wiring: gate1's output labels == gate2's input labels.
        let gate1 = garble(a, b, w, 0x01, |i, j| i & j); // AND
        let gate2 = garble(w, c, out, 0x02, |i, j| i | j); // OR

        for abit in 0..2usize {
            for bbit in 0..2usize {
                for cbit in 0..2usize {
                    // Evaluator holds one label per input wire (delivered via OT in
                    // a real run). It evaluates gate1, then feeds the recovered w
                    // label directly into gate2.
                    let w_label = eval(&gate1, &a[abit], &b[bbit], 0x01).expect("gate1");
                    let out_label = eval(&gate2, &w_label, &c[cbit], 0x02).expect("gate2");

                    let expected = (abit & bbit) | cbit;
                    let got_bit = if out_label == out[1] {
                        1
                    } else if out_label == out[0] {
                        0
                    } else {
                        panic!("output label matched neither 0 nor 1");
                    };
                    assert_eq!(got_bit, expected, "f({abit},{bbit},{cbit})");

                    // Secrecy along the path: the recovered intermediate label is
                    // exactly one of w's two labels and nothing more.
                    assert!(w_label == w[0] || w_label == w[1]);
                }
            }
        }

        println!("GARBLED COMPOSITION EXPLORED: gate1's output label feeds gate2's input; f=(a AND b) OR c verified for all 8 inputs. Scale this to millions of gates and the final output bit is 'Groth16 proof valid?' — that is a ZKTLC.");
    }
}
