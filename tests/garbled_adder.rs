// A "real" garbled circuit: an 8-bit ripple-carry ADDER built from garbled gates.
//
// This is the same primitive as the garbled_circuit_* demos, but assembled into a
// genuine arithmetic circuit (8 chained full-adders = 40 gates). It shows how
// useful computation decomposes into thousands of garbled boolean gates — the
// same way a Groth16 verifier's field arithmetic does. The garbler garbles the
// whole circuit once; the evaluator, given one label per input bit, propagates
// labels gate-by-gate and reads the output labels as the sum bits. It only ever
// learns the labels on the actual execution path.

#[cfg(test)]
mod garbled_adder {
    use cube::transmutative::hash::sha256;
    use std::collections::HashMap;

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
    fn ks(a: &Label, b: &Label, gate: u32, kind: &[u8]) -> Label {
        let mut p = Vec::new();
        p.extend_from_slice(a);
        p.extend_from_slice(b);
        p.extend_from_slice(&gate.to_le_bytes());
        p.extend_from_slice(kind);
        sha256(&p)
    }

    // Truth tables indexed by (i*2 + j).
    const XOR: [usize; 4] = [0, 1, 1, 0];
    const AND: [usize; 4] = [0, 0, 0, 1];
    const OR: [usize; 4] = [0, 1, 1, 1];

    struct Gate {
        a: usize,
        b: usize,
        o: usize,
        truth: [usize; 4],
        id: u32,
    }
    #[derive(Clone)]
    struct Row {
        tag: Label,
        ct: Label,
    }

    struct Circuit {
        wires: Vec<[Label; 2]>, // per-wire (0-label, 1-label)
        gates: Vec<Gate>,
    }
    impl Circuit {
        fn new() -> Self {
            Circuit { wires: Vec::new(), gates: Vec::new() }
        }
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
        /// Garble every gate into a 4-row table (rows permuted).
        fn garble(&self) -> Vec<Vec<Row>> {
            self.gates
                .iter()
                .map(|g| {
                    let mut rows = Vec::new();
                    for i in 0..2usize {
                        for j in 0..2usize {
                            let a_l = &self.wires[g.a][i];
                            let b_l = &self.wires[g.b][j];
                            let out_l = &self.wires[g.o][g.truth[i * 2 + j]];
                            rows.push(Row {
                                tag: ks(a_l, b_l, g.id, b"tag"),
                                ct: xor(&ks(a_l, b_l, g.id, b"enc"), out_l),
                            });
                        }
                    }
                    rows.rotate_left((g.id as usize) % 4); // permute
                    rows
                })
                .collect()
        }
        /// Evaluate with one active label per input wire; returns active labels.
        fn eval(&self, tables: &[Vec<Row>], inputs: &HashMap<usize, Label>) -> HashMap<usize, Label> {
            let mut active = inputs.clone();
            for (gi, g) in self.gates.iter().enumerate() {
                let la = active[&g.a];
                let lb = active[&g.b];
                let my_tag = ks(&la, &lb, g.id, b"tag");
                let row = tables[gi].iter().find(|r| r.tag == my_tag).expect("one row opens");
                active.insert(g.o, xor(&row.ct, &ks(&la, &lb, g.id, b"enc")));
            }
            active
        }
    }

    #[test]
    fn garbled_8bit_adder_computes_real_sums() {
        const N: usize = 8;
        let mut c = Circuit::new();

        // input wires: a[0..N], b[0..N] (bit 0 = LSB), and a constant-0 carry-in wire.
        let a_in: Vec<usize> = (0..N).map(|_| c.wire()).collect();
        let b_in: Vec<usize> = (0..N).map(|_| c.wire()).collect();
        let zero = c.wire(); // carry-in for bit 0 (always fed its 0-label)

        // Ripple-carry: full adder per bit. sum = a^b^cin; carry = (a&b)|(cin&(a^b)).
        let mut carry = zero;
        let mut sum_wires = Vec::new();
        for i in 0..N {
            let axb = c.gate(a_in[i], b_in[i], XOR);
            let sum = c.gate(axb, carry, XOR);
            let ab = c.gate(a_in[i], b_in[i], AND);
            let cx = c.gate(carry, axb, AND);
            let cout = c.gate(ab, cx, OR);
            sum_wires.push(sum);
            carry = cout;
        }
        let carry_out = carry;

        // Garble once.
        let tables = c.garble();
        println!("garbled an {}-bit adder: {} gates", N, c.gates.len());

        // Evaluate for several (a, b) pairs; check it matches real addition.
        for (av, bv) in [(5u16, 3u16), (200, 100), (255, 1), (0, 0), (123, 45)] {
            let mut inputs: HashMap<usize, Label> = HashMap::new();
            for i in 0..N {
                inputs.insert(a_in[i], c.wires[a_in[i]][((av >> i) & 1) as usize]);
                inputs.insert(b_in[i], c.wires[b_in[i]][((bv >> i) & 1) as usize]);
            }
            inputs.insert(zero, c.wires[zero][0]); // carry-in = 0

            let active = c.eval(&tables, &inputs);

            // Decode output labels -> bits.
            let mut result: u16 = 0;
            for i in 0..N {
                let l = active[&sum_wires[i]];
                let bit = if l == c.wires[sum_wires[i]][1] { 1 } else if l == c.wires[sum_wires[i]][0] { 0 } else { panic!("bad sum label") };
                result |= (bit as u16) << i;
            }
            let cout_label = active[&carry_out];
            let cout_bit = if cout_label == c.wires[carry_out][1] { 1u16 } else { 0 };
            result |= cout_bit << N;

            assert_eq!(result, av + bv, "garbled adder: {av} + {bv}");
        }

        println!("GARBLED ADDER EXPLORED: an 8-bit adder ({} gates) garbled once, evaluates real sums (incl. carry/overflow) purely by decrypting one row per gate along the path.", c.gates.len());
    }
}
