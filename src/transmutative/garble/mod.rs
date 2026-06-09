//! Garbled disprovable computation — the BitVM3 / Cube ZKTLC enforcement
//! primitive, promoted from exploration tests into a reusable library.
//!
//! The Engine garbles a VERIFIER of a state transition; its single output wire
//! has a "valid" label and an "invalid" label. The challenger evaluates the
//! garbled circuit on public inputs and learns exactly one output label — the
//! "invalid" label only when the Engine's asserted transition is wrong. That
//! label (the DISPROVE SECRET) opens an on-chain hashlock (the ZKTLC garbled
//! lock), letting the wronged party reclaim the contested output. Honesty is
//! enforced with cut-and-choose; the public inputs are pinned with per-bit label
//! commitments. See `tests/lottery_enforcement*.rs` for the soundness arguments.
//!
//! The concrete circuit here is the lottery winner predicate
//! `valid = lo_W <= rg < hi_W`, with the per-entry bands baked as CONSTANTS
//! (so the Engine can only choose the winner INDEX W, never fabricate a band) and
//! `rg` (the public draw position) a label-committed input.

use crate::transmutative::hash::sha256;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub type Label = [u8; 32];

fn xor(a: &Label, b: &Label) -> Label {
    let mut o = [0u8; 32];
    for i in 0..32 {
        o[i] = a[i] ^ b[i];
    }
    o
}
fn ks(a: &Label, b: &Label, gate: u32, kind: &[u8]) -> Label {
    let mut p = Vec::with_capacity(72);
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

#[derive(Clone)]
struct Gate {
    a: usize,
    b: usize,
    o: usize,
    truth: [usize; 4],
    id: u32,
}

/// One garbled gate's 4 permuted rows.
#[derive(Clone, Serialize, Deserialize)]
pub struct Row {
    pub tag: Label,
    pub ct: Label,
}

/// What the Engine publishes to assert a settle: enough for an independent
/// challenger to rebuild the public circuit, pin the public draw, and evaluate —
/// learning the disprove secret iff the asserted winner is wrong.
#[derive(Clone, Serialize, Deserialize)]
pub struct SettleAssertion {
    pub lo: Vec<u64>,
    pub hi: Vec<u64>,
    pub rg: u64,
    pub claimed_winner: u32,
    pub tables: Vec<Vec<Row>>,
    /// active input labels the Engine reveals for (rg, claimed_winner): (wire, label)
    pub revealed: Vec<(usize, Label)>,
    /// per-rg-bit (H(label0), H(label1)) commitments, in rg-bit (LSB→MSB) order.
    pub rg_commitments: Vec<(Label, Label)>,
    pub disprove_hash: [u8; 32],
    /// The WINNER-SWEEP hashlock: sha256(valid label). On an HONEST settle the
    /// winner derives the valid label by evaluating the circuit on the true draw
    /// (see [`WinnerVerifier::winner_label`]) and opens this lock to sweep losers'
    /// leaves — the mirror image of `disprove_hash` (which opens only on fraud).
    pub valid_hash: [u8; 32],
}

/// Value bit-width for `rg` and the band constants — 64 bits covers the full draw
/// space (round_total × house multiplier) for any realistic pot.
pub const VALUE_BITS: usize = 64;

fn bits_for(n: usize) -> usize {
    let mut b = 1;
    while (1usize << b) < n {
        b += 1;
    }
    b
}

/// The lottery winner-verifier circuit STRUCTURE (gate list + wire indices),
/// independent of garbling labels. Public — everyone builds the same circuit for
/// the round's bands, which is what cut-and-choose checks.
pub struct WinnerVerifier {
    gates: Vec<Gate>,
    n_wires: usize,
    one: usize,
    zero: usize,
    rg: Vec<usize>,
    w: Vec<usize>,
    valid: usize,
    w_bits: usize,
    lo: Vec<u64>,
    hi: Vec<u64>,
}

impl WinnerVerifier {
    /// Build the verifier for a round whose entries have cumulative bands
    /// `[lo[i], hi[i])`. `lo` and `hi` must be equal length (the entry count).
    pub fn new(lo: &[u64], hi: &[u64]) -> WinnerVerifier {
        assert_eq!(lo.len(), hi.len());
        let n = lo.len().max(1);
        let w_bits = bits_for(n);

        struct B {
            nw: usize,
            gates: Vec<Gate>,
        }
        impl B {
            fn wire(&mut self) -> usize {
                let id = self.nw;
                self.nw += 1;
                id
            }
            fn gate(&mut self, a: usize, b: usize, truth: [usize; 4]) -> usize {
                let o = self.wire();
                let id = self.gates.len() as u32;
                self.gates.push(Gate { a, b, o, truth, id });
                o
            }
            fn less_than(&mut self, a: &[usize], b: &[usize], one: usize, zero: usize) -> usize {
                let mut lt = zero;
                for i in 0..VALUE_BITS {
                    let na = self.gate(a[i], one, XOR);
                    let alb = self.gate(na, b[i], AND);
                    let axb = self.gate(a[i], b[i], XOR);
                    let eq = self.gate(axb, one, XOR);
                    let eal = self.gate(eq, lt, AND);
                    lt = self.gate(alb, eal, OR);
                }
                lt
            }
        }

        let mut b = B { nw: 0, gates: Vec::new() };
        let one = b.wire();
        let zero = b.wire();
        let rg: Vec<usize> = (0..VALUE_BITS).map(|_| b.wire()).collect();
        let w: Vec<usize> = (0..w_bits).map(|_| b.wire()).collect();

        // selW_i = (W == i): AND of (w_bit == i_bit) over the index bits.
        let mut sel: Vec<usize> = Vec::with_capacity(n);
        for i in 0..n {
            let mut term: Option<usize> = None;
            for (bit_idx, &wbit) in w.iter().enumerate() {
                let want1 = (i >> bit_idx) & 1 == 1;
                let lit = if want1 { wbit } else { b.gate(wbit, one, XOR) };
                term = Some(match term {
                    None => lit,
                    Some(t) => b.gate(t, lit, AND),
                });
            }
            sel.push(term.expect("w_bits >= 1"));
        }

        // mux constant band values by W: out[k] = OR over {i: const_i bit k} sel_i.
        let mux = |b: &mut B, consts: &[u64]| -> Vec<usize> {
            (0..VALUE_BITS)
                .map(|k| {
                    let act: Vec<usize> = (0..n).filter(|&i| (consts[i] >> k) & 1 == 1).map(|i| sel[i]).collect();
                    if act.is_empty() {
                        return zero;
                    }
                    let mut acc = act[0];
                    for &x in &act[1..] {
                        acc = b.gate(acc, x, OR);
                    }
                    acc
                })
                .collect()
        };
        let lo_w = mux(&mut b, lo);
        let hi_w = mux(&mut b, hi);
        let rg_lt_lo = b.less_than(&rg, &lo_w, one, zero);
        let rg_lt_hi = b.less_than(&rg, &hi_w, one, zero);
        let ge_lo = b.gate(rg_lt_lo, one, XOR);
        let valid = b.gate(ge_lo, rg_lt_hi, AND);

        WinnerVerifier { gates: b.gates, n_wires: b.nw, one, zero, rg, w, valid, w_bits, lo: lo.to_vec(), hi: hi.to_vec() }
    }

    pub fn gate_count(&self) -> usize {
        self.gates.len()
    }

    /// Deterministically derive this instance's wire labels from `seed`.
    pub fn wires(&self, seed: u64) -> Vec<[Label; 2]> {
        (0..self.n_wires)
            .map(|i| {
                let mk = |b: u8| {
                    let mut p = Vec::with_capacity(13);
                    p.extend_from_slice(&seed.to_le_bytes());
                    p.extend_from_slice(&(i as u32).to_le_bytes());
                    p.push(b);
                    sha256(&p)
                };
                [mk(0), mk(1)]
            })
            .collect()
    }

    /// Garble all gates into permuted 4-row tables.
    pub fn garble(&self, wires: &[[Label; 2]]) -> Vec<Vec<Row>> {
        self.gates
            .iter()
            .map(|g| {
                let mut rows = Vec::with_capacity(4);
                for i in 0..2usize {
                    for j in 0..2usize {
                        let al = &wires[g.a][i];
                        let bl = &wires[g.b][j];
                        let ol = &wires[g.o][g.truth[i * 2 + j]];
                        rows.push(Row { tag: ks(al, bl, g.id, b"tag"), ct: xor(&ks(al, bl, g.id, b"enc"), ol) });
                    }
                }
                rows.rotate_left((g.id as usize) % 4);
                rows
            })
            .collect()
    }

    /// The active input labels the Engine reveals for an asserted (rg, winner).
    pub fn reveal_active(&self, wires: &[[Label; 2]], rg: u64, w: u64) -> Vec<(usize, Label)> {
        let mut out = Vec::new();
        out.push((self.one, wires[self.one][1]));
        out.push((self.zero, wires[self.zero][0]));
        for k in 0..VALUE_BITS {
            out.push((self.rg[k], wires[self.rg[k]][((rg >> k) & 1) as usize]));
        }
        for k in 0..self.w_bits {
            out.push((self.w[k], wires[self.w[k]][((w >> k) & 1) as usize]));
        }
        out
    }

    /// Propagate active labels gate-by-gate through the garbled tables (no wire
    /// secrets) and return the output label — what a challenger computes.
    pub fn eval_active(&self, tables: &[Vec<Row>], active_in: &HashMap<usize, Label>) -> Label {
        let mut active = active_in.clone();
        for (gi, g) in self.gates.iter().enumerate() {
            let la = active[&g.a];
            let lb = active[&g.b];
            let tag = ks(&la, &lb, g.id, b"tag");
            let row = tables[gi].iter().find(|r| r.tag == tag).expect("a row opens");
            active.insert(g.o, xor(&row.ct, &ks(&la, &lb, g.id, b"enc")));
        }
        active[&self.valid]
    }

    /// Evaluate on public `rg` + claimed winner `w` (engine-side convenience).
    pub fn evaluate(&self, wires: &[[Label; 2]], tables: &[Vec<Row>], rg: u64, w: u64) -> Label {
        let active: HashMap<usize, Label> = self.reveal_active(wires, rg, w).into_iter().collect();
        self.eval_active(tables, &active)
    }

    /// Engine: build the publishable assertion for (rg, claimed_winner).
    pub fn assert_settle(&self, wires: &[[Label; 2]], tables: &[Vec<Row>], rg: u64, w: u32) -> SettleAssertion {
        SettleAssertion {
            lo: self.lo.clone(),
            hi: self.hi.clone(),
            rg,
            claimed_winner: w,
            tables: tables.to_vec(),
            revealed: self.reveal_active(wires, rg, w as u64),
            rg_commitments: self.rg_commitments(wires),
            disprove_hash: self.disprove_hash(wires),
            valid_hash: self.valid_hash(wires),
        }
    }

    /// Challenger: rebuild the public circuit, pin the public draw via the rg
    /// commitments, evaluate, and return the disprove SECRET iff the asserted
    /// winner is wrong (the engine cheated). `Ok(None)` = honest settle.
    pub fn challenge(a: &SettleAssertion, true_rg: u64) -> Result<Option<Label>, String> {
        let v = WinnerVerifier::new(&a.lo, &a.hi);
        let active: HashMap<usize, Label> = a.revealed.iter().cloned().collect();
        // (b) the revealed rg labels must match the commitments for the TRUE draw.
        for (k, &wire) in v.rg.iter().enumerate() {
            let lab = active.get(&wire).ok_or("missing rg label")?;
            let bit = ((true_rg >> k) & 1) as usize;
            let want = if bit == 0 { a.rg_commitments[k].0 } else { a.rg_commitments[k].1 };
            if sha256(lab) != want {
                return Err("revealed rg does not match the true public draw".into());
            }
        }
        let out = v.eval_active(&a.tables, &active);
        if sha256(&out) == a.disprove_hash {
            Ok(Some(out)) // disprove secret — the settle is wrong
        } else {
            Ok(None) // honest settle
        }
    }

    /// Winner/challenger: the MIRROR of [`challenge`]. On an HONEST settle the
    /// evaluated output IS the valid label — returned here as the WINNER-SWEEP
    /// secret so the proven winner can open each loser leaf's winner-sweep lock.
    /// Returns:
    ///   `Ok(Some(valid_label))` — honest settle; the winner sweeps,
    ///   `Ok(None)`              — the settle is WRONG (no sweep; losers disprove instead),
    ///   `Err(..)`               — the revealed draw doesn't match the true public draw.
    /// Pins the public draw with the same rg-commitment check as `challenge`, so a
    /// faked `rg` in the assertion is rejected.
    pub fn winner_label(a: &SettleAssertion, true_rg: u64) -> Result<Option<Label>, String> {
        let v = WinnerVerifier::new(&a.lo, &a.hi);
        let active: HashMap<usize, Label> = a.revealed.iter().cloned().collect();
        for (k, &wire) in v.rg.iter().enumerate() {
            let lab = active.get(&wire).ok_or("missing rg label")?;
            let bit = ((true_rg >> k) & 1) as usize;
            let want = if bit == 0 { a.rg_commitments[k].0 } else { a.rg_commitments[k].1 };
            if sha256(lab) != want {
                return Err("revealed rg does not match the true public draw".into());
            }
        }
        let out = v.eval_active(&a.tables, &active);
        if sha256(&out) == a.valid_hash {
            Ok(Some(out)) // valid label — honest settle, the winner-sweep secret
        } else {
            Ok(None) // not the honest claim (wrong winner) — no winner-sweep
        }
    }

    pub fn valid_label(&self, wires: &[[Label; 2]]) -> Label {
        wires[self.valid][1]
    }
    /// The disprove SECRET — revealed to a challenger only on a wrong claim.
    pub fn invalid_label(&self, wires: &[[Label; 2]]) -> Label {
        wires[self.valid][0]
    }
    /// The on-chain disprove hashlock value: sha256(invalid label).
    pub fn disprove_hash(&self, wires: &[[Label; 2]]) -> [u8; 32] {
        sha256(&self.invalid_label(wires))
    }
    /// The on-chain WINNER-SWEEP hashlock value: sha256(valid label). Opened by
    /// the honest winner (who derives the valid label via [`Self::winner_label`])
    /// to sweep losers' leaves. The mirror of [`Self::disprove_hash`].
    pub fn valid_hash(&self, wires: &[[Label; 2]]) -> [u8; 32] {
        sha256(&self.valid_label(wires))
    }
    /// Per-`rg`-bit label commitments (H(label0), H(label1)) — pin the public draw.
    pub fn rg_commitments(&self, wires: &[[Label; 2]]) -> Vec<(Label, Label)> {
        self.rg.iter().map(|&k| (sha256(&wires[k][0]), sha256(&wires[k][1]))).collect()
    }
    /// Commitment to the garbled tables (for cut-and-choose).
    pub fn tables_commit(&self, tables: &[Vec<Row>]) -> Label {
        let mut p = Vec::new();
        for tab in tables {
            for r in tab {
                p.extend_from_slice(&r.tag);
                p.extend_from_slice(&r.ct);
            }
        }
        sha256(&p)
    }
}

/// A per-instance commitment in a cut-and-choose run.
pub struct InstanceCommit {
    pub tables_commit: Label,
    pub disprove_hash: [u8; 32],
    /// sha256(valid label) for this instance — committed up front so that opening
    /// an instance verifies its winner-sweep lock too (same integrity the
    /// cut-and-choose already gives `disprove_hash`). A garbler that fakes this to
    /// grief the winner's sweep is caught with the same probability.
    pub valid_hash: [u8; 32],
}

/// Fiat-Shamir: which of `k` instances to OPEN (verify) — derived from the
/// commitments so the engine can't predict the choice before committing.
pub fn fiat_shamir_open(commits: &[InstanceCommit], k: usize) -> Vec<bool> {
    let mut p = Vec::new();
    for c in commits {
        p.extend_from_slice(&c.tables_commit);
        p.extend_from_slice(&c.disprove_hash);
    }
    let h = sha256(&p);
    (0..k).map(|i| (h[i % 32] >> (i % 8)) & 1 == 1).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn winner_verifier_valid_and_invalid() {
        // bands: [0,1000),[1000,3000),[3000,6000),[6000,10000)
        let lo = [0u64, 1000, 3000, 6000];
        let hi = [1000u64, 3000, 6000, 10000];
        let v = WinnerVerifier::new(&lo, &hi);
        let wires = v.wires(7);
        let tables = v.garble(&wires);
        let rg = 5000u64; // entry 2
        // honest claim
        assert_eq!(v.evaluate(&wires, &tables, rg, 2), v.valid_label(&wires));
        // wrong claim -> invalid (disprove secret)
        let out = v.evaluate(&wires, &tables, rg, 0);
        assert_eq!(out, v.invalid_label(&wires));
        assert_eq!(sha256(&out), v.disprove_hash(&wires));
    }

    #[test]
    fn assert_then_challenge_roundtrip() {
        let lo = [0u64, 1000, 3000, 6000];
        let hi = [1000u64, 3000, 6000, 10000];
        let v = WinnerVerifier::new(&lo, &hi);
        let wires = v.wires(11);
        let tables = v.garble(&wires);
        let true_rg = 5000u64; // entry 2

        // honest assertion -> challenger finds no secret.
        let honest = v.assert_settle(&wires, &tables, true_rg, 2);
        assert!(WinnerVerifier::challenge(&honest, true_rg).unwrap().is_none());

        // wrong-winner assertion -> challenger derives the disprove secret.
        let wrong = v.assert_settle(&wires, &tables, true_rg, 0);
        let secret = WinnerVerifier::challenge(&wrong, true_rg).unwrap();
        assert!(secret.is_some());
        assert_eq!(sha256(&secret.unwrap()), wrong.disprove_hash);

        // a faked draw in the assertion is rejected by the rg commitments.
        let faked = v.assert_settle(&wires, &tables, 500, 0); // engine asserts rg=500
        assert!(WinnerVerifier::challenge(&faked, true_rg).is_err());
    }

    #[test]
    fn winner_sweep_label_gating() {
        // The valid label gates the winner-sweep exactly as the invalid label gates
        // disprove: on an honest claim the evaluated output IS the valid label
        // (sha256 == valid_hash, != disprove_hash); on a wrong claim it's the
        // invalid label (the opposite). The two are mutually exclusive.
        let lo = [0u64, 1000, 3000, 6000];
        let hi = [1000u64, 3000, 6000, 10000];
        let v = WinnerVerifier::new(&lo, &hi);
        let wires = v.wires(23);
        let tables = v.garble(&wires);
        let true_rg = 5000u64; // entry 2 wins

        // honest evaluation yields the valid label, NOT the disprove secret.
        let out = v.evaluate(&wires, &tables, true_rg, 2);
        assert_eq!(out, v.valid_label(&wires));
        assert_eq!(sha256(&out), v.valid_hash(&wires));
        assert_ne!(sha256(&out), v.disprove_hash(&wires));
        // and the two labels are distinct, so a sweep secret can never disprove.
        assert_ne!(v.valid_label(&wires), v.invalid_label(&wires));
        assert_ne!(v.valid_hash(&wires), v.disprove_hash(&wires));
    }

    #[test]
    fn winner_label_roundtrip() {
        let lo = [0u64, 1000, 3000, 6000];
        let hi = [1000u64, 3000, 6000, 10000];
        let v = WinnerVerifier::new(&lo, &hi);
        let wires = v.wires(29);
        let tables = v.garble(&wires);
        let true_rg = 5000u64; // entry 2

        // HONEST settle: winner_label yields the valid (sweep) label; challenge None.
        let honest = v.assert_settle(&wires, &tables, true_rg, 2);
        let sweep = WinnerVerifier::winner_label(&honest, true_rg).unwrap();
        assert!(sweep.is_some(), "honest settle exposes the winner-sweep secret");
        assert_eq!(sha256(&sweep.unwrap()), honest.valid_hash);
        assert!(WinnerVerifier::challenge(&honest, true_rg).unwrap().is_none());

        // WRONG settle: winner_label None (no sweep), challenge yields disprove secret.
        let wrong = v.assert_settle(&wires, &tables, true_rg, 0);
        assert!(WinnerVerifier::winner_label(&wrong, true_rg).unwrap().is_none(), "fraud exposes no sweep secret");
        assert!(WinnerVerifier::challenge(&wrong, true_rg).unwrap().is_some());

        // a faked draw is rejected by the rg commitments on the sweep path too.
        let faked = v.assert_settle(&wires, &tables, 500, 2);
        assert!(WinnerVerifier::winner_label(&faked, true_rg).is_err());
    }

    #[test]
    fn cut_and_choose_opening_is_unpredictable() {
        let lo = [0u64, 1000, 3000, 6000];
        let hi = [1000u64, 3000, 6000, 10000];
        let v = WinnerVerifier::new(&lo, &hi);
        let commits: Vec<InstanceCommit> = (0..8u64)
            .map(|s| {
                let w = v.wires(s + 1);
                let t = v.garble(&w);
                InstanceCommit { tables_commit: v.tables_commit(&t), disprove_hash: v.disprove_hash(&w), valid_hash: v.valid_hash(&w) }
            })
            .collect();
        let open = fiat_shamir_open(&commits, 8);
        assert_eq!(open.len(), 8);
        assert!(open.iter().any(|&b| b) && open.iter().any(|&b| !b), "some opened, some live");
    }
}
