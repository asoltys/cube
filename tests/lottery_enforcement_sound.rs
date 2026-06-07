// SOUND enforcement — closes the two holes in lottery_enforcement.rs:
//   (c) the engine can't feed a FAKE band: the per-entry bands are CONSTANTS baked
//       into the (publicly-verifiable) verifier circuit, and the engine only
//       supplies the claimed winner INDEX W. Claiming a wrong index muxes the
//       wrong constant band -> the draw isn't inside it -> "invalid".
//   (b) the engine can't feed a FAKE draw rg: each rg input bit is committed up
//       front as (H(label0), H(label1)); the challenger accepts a revealed label
//       only if it hashes to the commitment for the TRUE public bit, so the engine
//       is forced to evaluate on the real rg.
//
// Verifier: valid = (lo_W <= rg) & (rg < hi_W), where (lo_W,hi_W) = mux of the
// constant bands by W. Honest claim -> "valid" (no secret). Wrong winner OR faked
// rg -> the challenger obtains the "invalid" label = the disprove secret.

#[cfg(test)]
mod lottery_enforcement_sound {
    use cube::transmutative::hash::sha256;
    use std::collections::HashMap;

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
                    let a_l = &self.wires[g.a][i]; let b_l = &self.wires[g.b][j];
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

    const N: usize = 24; // bits for rg / band values (covers the draw space)

    // N-bit unsigned less-than (LSB→MSB): lt = (a_i<b_i) | ((a_i==b_i)&lt).
    fn less_than(c: &mut Circuit, a: &[usize], b: &[usize], one: usize, zero: usize) -> usize {
        let mut lt = zero;
        for i in 0..N {
            let not_a = c.gate(a[i], one, XOR);
            let a_lt_b = c.gate(not_a, b[i], AND);
            let a_xor_b = c.gate(a[i], b[i], XOR);
            let eq = c.gate(a_xor_b, one, XOR);
            let eq_and_lt = c.gate(eq, lt, AND);
            lt = c.gate(a_lt_b, eq_and_lt, OR);
        }
        lt
    }

    // selW_i = (W == i) for a 2-bit claimed index W and constant i.
    fn eq_const2(c: &mut Circuit, w: &[usize; 2], i: usize, one: usize) -> usize {
        let t0 = if i & 1 == 1 { w[0] } else { c.gate(w[0], one, XOR) };
        let t1 = if (i >> 1) & 1 == 1 { w[1] } else { c.gate(w[1], one, XOR) };
        c.gate(t0, t1, AND)
    }

    // Mux constant band values by W: out[k] = OR over {i : const_i bit k set} selW_i.
    // (Exactly one selW_i is 1, so out = the selected constant.)
    fn mux_const(c: &mut Circuit, sel: &[usize; 4], consts: &[u64; 4], zero: usize) -> Vec<usize> {
        (0..N).map(|k| {
            let active: Vec<usize> = (0..4).filter(|&i| (consts[i] >> k) & 1 == 1).map(|i| sel[i]).collect();
            if active.is_empty() { return zero; }
            let mut acc = active[0];
            for &w in &active[1..] { acc = c.gate(acc, w, OR); }
            acc
        }).collect()
    }

    fn put_bits(c: &Circuit, wires: &[usize], v: u64, inputs: &mut HashMap<usize, Label>) {
        for k in 0..N { inputs.insert(wires[k], c.wires[wires[k]][((v >> k) & 1) as usize]); }
    }

    #[test]
    fn sound_winner_verifier_resists_wrong_index_and_faked_draw() {
        // Round (public): 4 entries; cumulative bands baked as CONSTANTS.
        let contribs = [1000u64, 2000, 3000, 4000];
        let b0 = 0u64;
        let mut cum = Vec::new();
        let mut acc = b0;
        for c in contribs { acc += c; cum.push(acc); } // [1000,3000,6000,10000]
        let lo_consts: [u64; 4] = [b0, cum[0], cum[1], cum[2]];   // [0,1000,3000,6000]
        let hi_consts: [u64; 4] = [cum[0], cum[1], cum[2], cum[3]]; // [1000,3000,6000,10000]
        let true_rg = 5000u64; // -> entry 2's band [3000,6000)

        // Build the verifier: inputs = rg[N] (committed), W[2] (claimed index).
        let mut c = Circuit::new();
        let one = c.wire();
        let zero = c.wire();
        let rg: Vec<usize> = (0..N).map(|_| c.wire()).collect();
        let w: [usize; 2] = [c.wire(), c.wire()];
        let sel = [
            eq_const2(&mut c, &w, 0, one), eq_const2(&mut c, &w, 1, one),
            eq_const2(&mut c, &w, 2, one), eq_const2(&mut c, &w, 3, one),
        ];
        let lo_w = mux_const(&mut c, &sel, &lo_consts, zero);
        let hi_w = mux_const(&mut c, &sel, &hi_consts, zero);
        let rg_lt_lo = less_than(&mut c, &rg, &lo_w, one, zero);
        let rg_lt_hi = less_than(&mut c, &rg, &hi_w, one, zero);
        let ge_lo = c.gate(rg_lt_lo, one, XOR);
        let valid = c.gate(ge_lo, rg_lt_hi, AND);
        let tables = c.garble();

        let invalid_label = c.wires[valid][0];
        let valid_label = c.wires[valid][1];
        let disprove_hash = sha256(&invalid_label);

        // (b) per-rg-bit label commitments, fixed BEFORE the draw is revealed.
        let rg_commit: Vec<(Label, Label)> = (0..N)
            .map(|k| (sha256(&c.wires[rg[k]][0]), sha256(&c.wires[rg[k]][1])))
            .collect();
        // The challenger accepts a revealed rg only if every bit's label hashes to
        // the commitment for the TRUE public bit of `true_rg`.
        let rg_labels_verify = |revealed: &HashMap<usize, Label>| -> bool {
            (0..N).all(|k| {
                let bit = ((true_rg >> k) & 1) as usize;
                sha256(&revealed[&rg[k]]) == (if bit == 0 { rg_commit[k].0 } else { rg_commit[k].1 })
            })
        };

        let eval_claim = |claim_w: u64, rg_value: u64| -> (HashMap<usize, Label>, Label) {
            let mut inputs: HashMap<usize, Label> = HashMap::new();
            inputs.insert(one, c.wires[one][1]);
            inputs.insert(zero, c.wires[zero][0]);
            put_bits(&c, &rg, rg_value, &mut inputs);
            inputs.insert(w[0], c.wires[w[0]][(claim_w & 1) as usize]);
            inputs.insert(w[1], c.wires[w[1]][((claim_w >> 1) & 1) as usize]);
            let out = c.eval(&tables, &inputs)[&valid];
            (inputs, out)
        };

        // HONEST: claim W=2 with the true rg -> labels verify, output is "valid".
        let (honest_in, honest_out) = eval_claim(2, true_rg);
        assert!(rg_labels_verify(&honest_in), "honest rg labels match the commitments");
        assert_eq!(honest_out, valid_label, "honest winner claim evaluates to 'valid'");
        assert_ne!(sha256(&honest_out), disprove_hash, "honest output can't open the disprove lock");

        // CHEAT 1 — WRONG INDEX: claim W=0 with the true rg -> "invalid" (disprovable).
        let (cheat_in, cheat_out) = eval_claim(0, true_rg);
        assert!(rg_labels_verify(&cheat_in), "rg still the true draw");
        assert_eq!(cheat_out, invalid_label, "wrong winner index -> 'invalid'");
        assert_eq!(sha256(&cheat_out), disprove_hash, "the 'invalid' secret opens the disprove lock");

        // CHEAT 2 — FAKED DRAW: claim W=0 but feed a fake rg=500 (inside [0,1000)).
        // The circuit would say "valid", BUT the rg label commitments reject it:
        let (fake_in, fake_out) = eval_claim(0, 500);
        assert_eq!(fake_out, valid_label, "on the faked rg the circuit would accept...");
        assert!(!rg_labels_verify(&fake_in), "...but the rg commitments expose the faked draw — rejected");

        println!(
            "SOUND ENFORCEMENT: winner-verifier ({} gates) with bands baked as constants and rg \
label-committed. Honest claim -> 'valid'; a WRONG winner index -> 'invalid' (disprovable); a FAKED \
draw is caught by the rg commitments (can't even be evaluated). The engine can neither fake the \
band nor the draw — only an honest settle survives.",
            c.gates.len()
        );
    }
}
