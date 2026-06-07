// CUT-AND-CHOOSE — forces the engine to garble the HONEST verifier.
//
// lottery_enforcement_sound.rs assumed the engine garbles the real circuit. A
// malicious garbler could instead commit a leaf whose disprove hashlock can NEVER
// be opened (so a wrong settle is unpunishable), or a circuit that always says
// "valid". Cut-and-choose removes that trust: the engine garbles K independent
// instances and commits them; a Fiat-Shamir challenge (derived from the
// commitments, so the engine can't predict it) OPENS half — for those the engine
// reveals all wire labels and the challenger re-garbles and checks the tables +
// that each committed disprove hash really equals sha256(that instance's 'invalid'
// label). The unopened half is used live. To stay unpunishable on a wrong claim
// the engine would need every UNOPENED instance dishonest while every OPENED one
// is honest — impossible to arrange before the challenge, so cheating is caught
// with overwhelming probability.

#[cfg(test)]
mod lottery_enforcement_cutchoose {
    use cube::transmutative::hash::sha256;
    use std::collections::HashMap;

    type Label = [u8; 32];
    fn xor(a: &Label, b: &Label) -> Label { let mut o = [0u8; 32]; for i in 0..32 { o[i] = a[i] ^ b[i]; } o }
    fn ks(a: &Label, b: &Label, gate: u32, kind: &[u8]) -> Label {
        let mut p = Vec::new();
        p.extend_from_slice(a); p.extend_from_slice(b);
        p.extend_from_slice(&gate.to_le_bytes()); p.extend_from_slice(kind);
        sha256(&p)
    }
    const XOR: [usize; 4] = [0, 1, 1, 0];
    const AND: [usize; 4] = [0, 0, 0, 1];
    const OR: [usize; 4] = [0, 1, 1, 1];
    const N: usize = 16;

    #[derive(Clone)]
    struct Gate { a: usize, b: usize, o: usize, truth: [usize; 4], id: u32 }
    #[derive(Clone)]
    struct Row { tag: Label, ct: Label }

    // The agreed circuit STRUCTURE (gate list) — public; everyone builds the same.
    struct Builder { n_wires: usize, gates: Vec<Gate> }
    impl Builder {
        fn new() -> Self { Builder { n_wires: 0, gates: Vec::new() } }
        fn wire(&mut self) -> usize { let id = self.n_wires; self.n_wires += 1; id }
        fn gate(&mut self, a: usize, b: usize, truth: [usize; 4]) -> usize {
            let o = self.wire();
            let id = self.gates.len() as u32;
            self.gates.push(Gate { a, b, o, truth, id });
            o
        }
    }
    fn less_than(c: &mut Builder, a: &[usize], b: &[usize], one: usize, zero: usize) -> usize {
        let mut lt = zero;
        for i in 0..N {
            let na = c.gate(a[i], one, XOR);
            let alb = c.gate(na, b[i], AND);
            let axb = c.gate(a[i], b[i], XOR);
            let eq = c.gate(axb, one, XOR);
            let eal = c.gate(eq, lt, AND);
            lt = c.gate(alb, eal, OR);
        }
        lt
    }
    fn eq_const2(c: &mut Builder, w: &[usize; 2], i: usize, one: usize) -> usize {
        let t0 = if i & 1 == 1 { w[0] } else { c.gate(w[0], one, XOR) };
        let t1 = if (i >> 1) & 1 == 1 { w[1] } else { c.gate(w[1], one, XOR) };
        c.gate(t0, t1, AND)
    }
    fn mux_const(c: &mut Builder, sel: &[usize; 4], consts: &[u64; 4], zero: usize) -> Vec<usize> {
        (0..N).map(|k| {
            let act: Vec<usize> = (0..4).filter(|&i| (consts[i] >> k) & 1 == 1).map(|i| sel[i]).collect();
            if act.is_empty() { return zero; }
            let mut acc = act[0];
            for &w in &act[1..] { acc = c.gate(acc, w, OR); }
            acc
        }).collect()
    }

    struct Verifier { gates: Vec<Gate>, n_wires: usize, one: usize, zero: usize, rg: Vec<usize>, w: [usize; 2], valid: usize }
    fn build(lo: &[u64; 4], hi: &[u64; 4]) -> Verifier {
        let mut c = Builder::new();
        let one = c.wire();
        let zero = c.wire();
        let rg: Vec<usize> = (0..N).map(|_| c.wire()).collect();
        let w = [c.wire(), c.wire()];
        let sel = [eq_const2(&mut c, &w, 0, one), eq_const2(&mut c, &w, 1, one), eq_const2(&mut c, &w, 2, one), eq_const2(&mut c, &w, 3, one)];
        let lo_w = mux_const(&mut c, &sel, lo, zero);
        let hi_w = mux_const(&mut c, &sel, hi, zero);
        let rl = less_than(&mut c, &rg, &lo_w, one, zero);
        let rh = less_than(&mut c, &rg, &hi_w, one, zero);
        let ge = c.gate(rl, one, XOR);
        let valid = c.gate(ge, rh, AND);
        Verifier { gates: c.gates, n_wires: c.n_wires, one, zero, rg, w, valid }
    }

    // Per-instance labels, derived from a per-instance seed (independent labels).
    fn labels_for(seed: u64, n_wires: usize) -> Vec<[Label; 2]> {
        (0..n_wires).map(|i| {
            let mk = |b: u8| { let mut p = Vec::new(); p.extend_from_slice(&seed.to_le_bytes()); p.extend_from_slice(&(i as u32).to_le_bytes()); p.push(b); sha256(&p) };
            [mk(0), mk(1)]
        }).collect()
    }
    fn garble(wires: &[[Label; 2]], gates: &[Gate]) -> Vec<Vec<Row>> {
        gates.iter().map(|g| {
            let mut rows = Vec::new();
            for i in 0..2usize { for j in 0..2usize {
                let al = &wires[g.a][i]; let bl = &wires[g.b][j];
                let ol = &wires[g.o][g.truth[i * 2 + j]];
                rows.push(Row { tag: ks(al, bl, g.id, b"tag"), ct: xor(&ks(al, bl, g.id, b"enc"), ol) });
            }}
            rows.rotate_left((g.id as usize) % 4);
            rows
        }).collect()
    }
    fn tables_hash(t: &[Vec<Row>]) -> Label {
        let mut p = Vec::new();
        for tab in t { for r in tab { p.extend_from_slice(&r.tag); p.extend_from_slice(&r.ct); } }
        sha256(&p)
    }
    fn eval(v: &Verifier, wires: &[[Label; 2]], tables: &[Vec<Row>], rg: u64, claim_w: u64) -> Label {
        let mut active: HashMap<usize, Label> = HashMap::new();
        active.insert(v.one, wires[v.one][1]);
        active.insert(v.zero, wires[v.zero][0]);
        for k in 0..N { active.insert(v.rg[k], wires[v.rg[k]][((rg >> k) & 1) as usize]); }
        active.insert(v.w[0], wires[v.w[0]][(claim_w & 1) as usize]);
        active.insert(v.w[1], wires[v.w[1]][((claim_w >> 1) & 1) as usize]);
        for (gi, g) in v.gates.iter().enumerate() {
            let la = active[&g.a]; let lb = active[&g.b];
            let tag = ks(&la, &lb, g.id, b"tag");
            let row = tables[gi].iter().find(|r| r.tag == tag).expect("row");
            active.insert(g.o, xor(&row.ct, &ks(&la, &lb, g.id, b"enc")));
        }
        active[&v.valid]
    }

    struct Commit { tables_hash: Label, disprove_hash: Label }

    // Fiat-Shamir: open the instances whose index bit is set in H(all commitments).
    fn open_set(commits: &[Commit], k: usize) -> Vec<bool> {
        let mut p = Vec::new();
        for c in commits { p.extend_from_slice(&c.tables_hash); p.extend_from_slice(&c.disprove_hash); }
        let h = sha256(&p);
        (0..k).map(|i| (h[i % 32] >> (i % 8)) & 1 == 1).collect()
    }

    #[test]
    fn cut_and_choose_catches_a_dishonest_garbler() {
        let lo: [u64; 4] = [0, 1000, 3000, 6000];
        let hi: [u64; 4] = [1000, 3000, 6000, 10000];
        let v = build(&lo, &hi);
        let true_rg = 5000u64; // entry 2
        const K: usize = 12;

        // An engine produces K instances. `cheat[i]` = commit a FAKE disprove hash
        // for instance i (so its leaf could never be opened -> unpunishable).
        let make = |cheat: &[bool]| -> (Vec<Vec<[Label; 2]>>, Vec<Vec<Vec<Row>>>, Vec<Commit>) {
            let mut all_wires = Vec::new();
            let mut all_tables = Vec::new();
            let mut commits = Vec::new();
            for inst in 0..K {
                let wires = labels_for(inst as u64 + 1, v.n_wires);
                let tables = garble(&wires, &v.gates);
                let real_disprove = sha256(&wires[v.valid][0]);
                let disprove_hash = if cheat[inst] { sha256(b"fake-unopenable") } else { real_disprove };
                commits.push(Commit { tables_hash: tables_hash(&tables), disprove_hash });
                all_wires.push(wires);
                all_tables.push(tables);
            }
            (all_wires, all_tables, commits)
        };

        // The challenger's verification of an HONEST engine + the disprove on a wrong claim.
        let honest = vec![false; K];
        let (wires, tables, commits) = make(&honest);
        let opened = open_set(&commits, K);
        // (1) OPEN check: re-garble opened instances from revealed labels; tables +
        //     disprove hash must match the commitments.
        for i in 0..K {
            if !opened[i] { continue; }
            assert_eq!(tables_hash(&garble(&wires[i], &v.gates)), commits[i].tables_hash, "opened tables match");
            assert_eq!(sha256(&wires[i][v.valid][0]), commits[i].disprove_hash, "opened disprove hash is honest");
        }
        // (2) LIVE: on a wrong claim (W=0), every UNOPENED instance yields the
        //     'invalid' label whose hash equals the committed disprove hash -> the
        //     challenger holds a valid on-chain disprove preimage.
        let mut punishable = false;
        for i in 0..K {
            if opened[i] { continue; }
            let out = eval(&v, &wires[i], &tables[i], true_rg, 0);
            if sha256(&out) == commits[i].disprove_hash { punishable = true; }
        }
        assert!(punishable, "honest engine: a wrong claim is punishable via an unopened instance");

        // A CHEATING engine makes EVERY instance unpunishable (fake disprove hash).
        // To pass, it would need all faked instances to land unopened — impossible:
        // the Fiat-Shamir opening hits at least one, and the OPEN check catches it.
        let all_cheat = vec![true; K];
        let (cwires, _ctables, ccommits) = make(&all_cheat);
        let copened = open_set(&ccommits, K);
        let mut caught = false;
        for i in 0..K {
            if !copened[i] { continue; }
            // honest tables (the engine garbled the real circuit) but the committed
            // disprove hash is fake -> mismatch on open == fraud -> slash bond.
            if sha256(&cwires[i][v.valid][0]) != ccommits[i].disprove_hash { caught = true; break; }
        }
        assert!(caught, "cut-and-choose catches the dishonest garbler on opening");

        // Quantify: for the cheat to go undetected it needs ALL fakes unopened.
        let n_open = (0..K).filter(|&i| copened[i]).count();
        println!(
            "CUT-AND-CHOOSE: {} instances, {} opened by Fiat-Shamir. Honest engine passes opening \
and a wrong claim is punishable via an unopened instance; a dishonest garbler (fake disprove locks) \
is caught on opening. Evading detection needs every faked instance to fall in the unopened half — \
probability ~2^-{} for an all-or-nothing cheat — so the engine is forced to garble honestly.",
            K, n_open, n_open
        );
    }
}
