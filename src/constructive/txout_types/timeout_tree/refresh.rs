//! Projector REFRESH — the cross-batch "auto-refresh" of a contract pot's
//! covenant output.
//!
//! A contract pot lives in a funding (covenant) output locked to a Projector
//! value-bound MuSig2 key path (see [`super::timeout_tree::funding_taproot`]).
//! Every batch the engine re-renders the pot from updated shadow state, which
//! means spending the OLD covenant output into the NEW one. That spend is a
//! taproot KEY-PATH spend of an N-of-N (all participants + engine) Projector
//! aggregate — the consensus-enforced refresh: the covenant can only move to a
//! state every participant co-signs.
//!
//! This module provides the crypto core of that spend: the key-aggregation
//! context whose aggregate key equals the covenant output key, and the projected
//! secret each participant signs with. The refresh transaction itself (input =
//! old covenant outpoint, outputs = new covenant + the rest of the batch) is
//! assembled by the batch builder; the MuSig2 session is driven exactly like the
//! LiftV2 deposit cosign (commit nonces → sighash known at freeze → partial-sign
//! → aggregate into the 64-byte key-path witness).

use super::timeout_tree::{funding_keys_and_values, funding_taproot};
use crate::transmutative::musig::keyagg::MusigKeyAggCtx;
use crate::transmutative::musig::projector::{key_projector_agg, project_public_key, project_secret_key};
use secp::{Point, Scalar};

type Bytes = Vec<u8>;

/// The MuSig2 key-aggregation context for a KEY-PATH (refresh) spend of a contract
/// pot's funding covenant: the Projector value-bound aggregate of all participants
/// + engine, with the funding taproot tweak applied. Its `agg_key()` equals the
/// covenant output key, so a full MuSig2 signature over the refresh sighash is a
/// valid BIP340/341 key-path spend.
pub fn refresh_keyagg(
    engine_key: [u8; 32],
    allocations: &[([u8; 32], u64)],
    expiry_height: u32,
) -> Option<MusigKeyAggCtx> {
    let taproot = funding_taproot(engine_key, allocations, expiry_height)?;
    let tweak = Scalar::from_slice(&taproot.tap_tweak()).ok()?;
    let keys_and_values = funding_keys_and_values(engine_key, allocations)?;
    key_projector_agg(&keys_and_values, Some(tweak))
}

/// The covenant output scriptpubkey for a given allocation state (the spk a refresh
/// spends FROM, and the spk the next refresh creates).
pub fn covenant_scriptpubkey(
    engine_key: [u8; 32],
    allocations: &[([u8; 32], u64)],
    expiry_height: u32,
) -> Option<Bytes> {
    funding_taproot(engine_key, allocations, expiry_height)?.spk()
}

/// The signer index convention for [`participant_projected_secret`] /
/// [`engine_projected_secret`]: participants occupy `0..allocations.len()` in
/// allocation order; the engine is `allocations.len()`.
pub fn engine_signer_index(allocations: &[([u8; 32], u64)]) -> u32 {
    allocations.len() as u32
}

/// The projected PUBLIC key for participant `index` (used to register their nonce
/// in the MuSig2 session). `base` is the participant's even-Y account point.
pub fn participant_projected_pubkey(base: Point, value: u64, index: u32) -> Option<Point> {
    project_public_key(base, value, index)
}

/// The projected SECRET a participant at `index` signs the refresh with:
/// `sk' = sk + H_tag("CubeProjector", value‖index)`. `base_secret` is the
/// participant's even-Y account secret.
pub fn participant_projected_secret(base_secret: Scalar, value: u64, index: u32) -> Option<Scalar> {
    project_secret_key(base_secret, value, index)
}

/// The engine's projected key/secret for the refresh: projected by the pot TOTAL
/// at index `allocations.len()`.
pub fn engine_projected_pubkey(
    engine_base: Point,
    allocations: &[([u8; 32], u64)],
) -> Option<Point> {
    let total: u64 = allocations.iter().map(|(_, v)| *v).sum();
    project_public_key(engine_base, total, engine_signer_index(allocations))
}

pub fn engine_projected_secret(
    engine_base_secret: Scalar,
    allocations: &[([u8; 32], u64)],
) -> Option<Scalar> {
    let total: u64 = allocations.iter().map(|(_, v)| *v).sum();
    project_secret_key(engine_base_secret, total, engine_signer_index(allocations))
}
