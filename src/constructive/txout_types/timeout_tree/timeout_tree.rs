//! Timeout-tree / ZKTLC exit tree — the ownership & unilateral-exit primitive
//! for non-custodial contract balances.
//!
//! A contract holds a pot of BTC. Shadowing attributes that pot to participants
//! as `account_key -> value` claims (invariant: pot >= Σ claims). To make those
//! claims unilaterally exitable on Bitcoin (the core non-custodial guarantee),
//! the engine renders them as a pre-signed timeout tree: a funding output (the
//! pot, held under a value-bound MuSig2 covenant key) that fans out into one
//! VTXO leaf per participant. Each leaf is a taproot with:
//!
//!   * KEY PATH  — the Projector-bound MuSig2 aggregate of (account, engine),
//!     committed to that leaf's value (cooperative spend / refresh),
//!   * EXIT      — `<delay> CSV DROP <account> CHECKSIG`: the holder spends
//!     unilaterally after a relative delay once the leaf is on-chain,
//!   * EXPIRY    — `<height> CLTV DROP <engine> CHECKSIG`: the engine reclaims an
//!     unrefreshed leaf after expiry (anti-griefing / recycle),
//!   * DISPROVE  — (optional) `OP_HASH160 <h> EQUALVERIFY <account> CHECKSIG`:
//!     the BitVM3/garbled-verifier punishment path, opened by the "invalid"
//!     output label of the garbled state-transition verifier.
//!
//! This is the ownership leg of a ZKTLC. Value binding (Projector) ensures a leaf
//! cannot be re-bound to a different amount; the disprove leaf (when set) ties in
//! the computation-enforcement leg.

use crate::constructive::taproot::{TapLeaf, TapRoot};
use crate::transmutative::musig::projector::key_projector_agg;
use crate::transmutative::secp::into::IntoPoint;
use bitcoin::hashes::{ripemd160, Hash as _};
use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CLTV, OP_CSV, OP_DROP, OP_EQUALVERIFY, OP_HASH160};
use bitcoin::script::Builder;
use bitcoin::{absolute::LockTime, ScriptBuf, Sequence, XOnlyPublicKey};

type Bytes = Vec<u8>;

/// The expiry clause: `<height> OP_CLTV OP_DROP <pk> OP_CHECKSIG`.
fn expiry_script(height: u32, pk: &XOnlyPublicKey) -> ScriptBuf {
    Builder::new()
        .push_int(LockTime::from_height(height).expect("valid height").to_consensus_u32() as i64)
        .push_opcode(OP_CLTV)
        .push_opcode(OP_DROP)
        .push_x_only_key(pk)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// The unilateral-exit clause: `<delay> OP_CSV OP_DROP <pk> OP_CHECKSIG`.
fn exit_script(delay: u16, pk: &XOnlyPublicKey) -> ScriptBuf {
    Builder::new()
        .push_int(Sequence::from_height(delay).to_consensus_u32() as i64)
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_x_only_key(pk)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// The disprove clause: `OP_HASH160 <ripemd160(disprove_hash)> OP_EQUALVERIFY <pk> OP_CHECKSIG`.
fn disprove_script(disprove_hash: &[u8; 32], pk: &XOnlyPublicKey) -> ScriptBuf {
    Builder::new()
        .push_opcode(OP_HASH160)
        .push_slice(ripemd160::Hash::hash(disprove_hash).to_byte_array())
        .push_opcode(OP_EQUALVERIFY)
        .push_x_only_key(pk)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

fn xonly(key: &[u8; 32]) -> Option<XOnlyPublicKey> {
    XOnlyPublicKey::from_slice(key).ok()
}

/// The Projector key set for a contract pot's funding (covenant) output: every
/// participant projected by their value, plus the engine projected by the total.
/// Shared by [`TimeoutTree`] and the cross-batch refresh so the covenant key is
/// computed identically on both sides.
pub fn funding_keys_and_values(
    engine_key: [u8; 32],
    allocations: &[([u8; 32], u64)],
) -> Option<Vec<(secp::Point, u64)>> {
    let total_value_in_satoshis: u64 = allocations.iter().map(|(_, v)| *v).sum();
    let mut keys_and_values: Vec<(secp::Point, u64)> = Vec::with_capacity(allocations.len() + 1);
    for (account_key, value) in allocations.iter() {
        keys_and_values.push((account_key.into_point().ok()?, *value));
    }
    keys_and_values.push((engine_key.into_point().ok()?, total_value_in_satoshis));
    Some(keys_and_values)
}

/// The funding (pot) covenant taproot: a Projector value-bound MuSig2 key path
/// plus a server-expiry (`<height> CLTV DROP <engine> CHECKSIG`) script path.
pub fn funding_taproot(
    engine_key: [u8; 32],
    allocations: &[([u8; 32], u64)],
    expiry_height: u32,
) -> Option<TapRoot> {
    let engine_x = xonly(&engine_key)?;
    let keys_and_values = funding_keys_and_values(engine_key, allocations)?;
    let funding_inner = key_projector_agg(&keys_and_values, None)?.agg_inner_key();
    Some(TapRoot::key_and_script_path_single(
        funding_inner,
        TapLeaf::new(expiry_script(expiry_height, &engine_x).to_bytes()),
    ))
}

/// A single participant's VTXO leaf in the timeout tree.
pub struct VtxoLeaf {
    pub account_key: [u8; 32],
    pub engine_key: [u8; 32],
    pub value_in_satoshis: u64,
    pub expiry_height: u32,
    pub exit_delay: u16,
    pub disprove_hash: Option<[u8; 32]>,
    pub taproot: TapRoot,
}

impl VtxoLeaf {
    /// Leaf script order: [expiry (0), exit (1), disprove (2, if present)].
    fn build(
        account_key: [u8; 32],
        engine_key: [u8; 32],
        value_in_satoshis: u64,
        expiry_height: u32,
        exit_delay: u16,
        disprove_hash: Option<[u8; 32]>,
    ) -> Option<Self> {
        let account_pt = account_key.into_point().ok()?;
        let engine_pt = engine_key.into_point().ok()?;
        let account_x = xonly(&account_key)?;
        let engine_x = xonly(&engine_key)?;

        // Value-bound key path: both keys projected by this leaf's value, so a
        // different value yields a different covenant key (no re-binding).
        let inner_key = key_projector_agg(
            &[(account_pt, value_in_satoshis), (engine_pt, value_in_satoshis)],
            None,
        )?
        .agg_inner_key();

        let mut leaves = vec![
            TapLeaf::new(expiry_script(expiry_height, &engine_x).to_bytes()),
            TapLeaf::new(exit_script(exit_delay, &account_x).to_bytes()),
        ];
        if let Some(ref h) = disprove_hash {
            leaves.push(TapLeaf::new(disprove_script(h, &account_x).to_bytes()));
        }

        let taproot = TapRoot::key_and_script_path_multi(inner_key, leaves);

        Some(VtxoLeaf {
            account_key,
            engine_key,
            value_in_satoshis,
            expiry_height,
            exit_delay,
            disprove_hash,
            taproot,
        })
    }

    /// The VTXO output scriptpubkey.
    pub fn scriptpubkey(&self) -> Option<Bytes> {
        self.taproot.spk()
    }

    /// `(tapleaf_hash, tapscript, control_block)` for the unilateral-exit leaf
    /// (index 1) — what the holder spends with ONLY the account key after the
    /// relative delay, once the leaf is on-chain.
    pub fn exit_spend_elements(&self) -> Option<([u8; 32], Bytes, Bytes)> {
        self.script_path_elements(1)
    }

    /// `(tapleaf_hash, tapscript, control_block)` for the expiry leaf (index 0).
    pub fn expiry_spend_elements(&self) -> Option<([u8; 32], Bytes, Bytes)> {
        self.script_path_elements(0)
    }

    /// `(tapleaf_hash, tapscript, control_block)` for the disprove leaf (index 2),
    /// if this leaf has a disprove path.
    pub fn disprove_spend_elements(&self) -> Option<([u8; 32], Bytes, Bytes)> {
        self.disprove_hash?;
        self.script_path_elements(2)
    }

    fn script_path_elements(&self, index: usize) -> Option<([u8; 32], Bytes, Bytes)> {
        let tree = self.taproot.tree()?;
        let leaves = tree.leaves();
        let leaf = leaves.get(index)?;
        let control_block = self.taproot.control_block(index)?.to_vec();
        Some((leaf.tapleaf_hash(), leaf.tap_script(), control_block))
    }
}

/// A pre-signed timeout tree rendering a contract pot as per-participant VTXOs.
pub struct TimeoutTree {
    pub engine_key: [u8; 32],
    pub expiry_height: u32,
    pub exit_delay: u16,
    /// Funding output: the pot held under the value-bound covenant key path plus
    /// a server-expiry script path (so an abandoned pot can be reclaimed).
    pub funding_taproot: TapRoot,
    pub leaves: Vec<VtxoLeaf>,
    pub total_value_in_satoshis: u64,
}

impl TimeoutTree {
    /// Build the tree from `(account_key, value)` shadow allocations (a contract's
    /// attributed pot). `disprove_hashes`, when supplied, must align by index with
    /// `allocations` and attaches each leaf's BitVM disprove path.
    pub fn build(
        engine_key: [u8; 32],
        allocations: &[([u8; 32], u64)],
        expiry_height: u32,
        exit_delay: u16,
        disprove_hashes: Option<&[[u8; 32]]>,
    ) -> Option<Self> {
        if allocations.is_empty() {
            return None;
        }
        if let Some(hashes) = disprove_hashes {
            if hashes.len() != allocations.len() {
                return None;
            }
        }

        // Funding (pot) covenant: value-bound over the whole pot (shared helper).
        let total_value_in_satoshis: u64 = allocations.iter().map(|(_, v)| *v).sum();
        let funding_taproot = funding_taproot(engine_key, allocations, expiry_height)?;

        // One VTXO leaf per participant.
        let mut leaves = Vec::with_capacity(allocations.len());
        for (i, (account_key, value)) in allocations.iter().enumerate() {
            let disprove_hash = disprove_hashes.map(|h| h[i]);
            leaves.push(VtxoLeaf::build(
                *account_key,
                engine_key,
                *value,
                expiry_height,
                exit_delay,
                disprove_hash,
            )?);
        }

        Some(TimeoutTree {
            engine_key,
            expiry_height,
            exit_delay,
            funding_taproot,
            leaves,
            total_value_in_satoshis,
        })
    }

    /// The funding (pot) output scriptpubkey.
    pub fn funding_scriptpubkey(&self) -> Option<Bytes> {
        self.funding_taproot.spk()
    }

    /// Σ of the leaf VTXO values — must equal the funding pot value (every claim
    /// is collateralized and exitable).
    pub fn leaves_value_sum(&self) -> u64 {
        self.leaves.iter().map(|l| l.value_in_satoshis).sum()
    }
}
