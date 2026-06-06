//! Projector — value-bound MuSig2 for covenant emulation (Cube's stand-in for
//! native Bitcoin covenants).
//!
//! Plain MuSig2 aggregation commits only to signer identities, so a lightweight
//! co-signer ("Hosted Box") that doesn't fully understand what it's signing could
//! be tricked into authorizing alternative covenant states. Projector fixes this
//! by binding the aggregate key to explicit per-signer VALUE commitments: before
//! the BIP-327 `KeyAgg`, each key is projected
//!
//!     pk_i' = pk_i + t_i·G,    t_i = H_tag("CubeProjector", val_i ‖ i)
//!
//! and each secret correspondingly `sk_i' = sk_i + t_i`. The remaining MuSig2
//! flow is unchanged. The resulting aggregate "Projector Key" therefore changes
//! whenever the committed value configuration changes — so the covenant
//! scriptpubkey (derived from it) is intrinsically tied to a specific value
//! state, and a co-signer cannot have its signature reused across other states.

use super::keyagg::MusigKeyAggCtx;
use crate::transmutative::hash::{Hash, HashTag};
use crate::transmutative::secp::into::IntoScalar;
use secp::{MaybePoint, MaybeScalar, Point, Scalar};

/// The projection tweak `t_i = H_tag("CubeProjector", val_i(8B BE) ‖ i(4B BE))`.
pub fn projection_tweak(value_in_satoshis: u64, index: u32) -> Option<Scalar> {
    let mut preimage = Vec::with_capacity(12);
    preimage.extend_from_slice(&value_in_satoshis.to_be_bytes());
    preimage.extend_from_slice(&index.to_be_bytes());
    preimage
        .hash(Some(HashTag::CustomString("CubeProjector".to_string())))
        .into_reduced_scalar()
        .ok()
}

/// Projects a public key: `pk' = pk + t_i·G`.
pub fn project_public_key(public_key: Point, value_in_satoshis: u64, index: u32) -> Option<Point> {
    let tweak = projection_tweak(value_in_satoshis, index)?;
    match public_key + tweak.base_point_mul() {
        MaybePoint::Valid(point) => Some(point),
        MaybePoint::Infinity => None,
    }
}

/// Projects a secret key: `sk' = sk + t_i` (for signing under the projected key).
pub fn project_secret_key(secret_key: Scalar, value_in_satoshis: u64, index: u32) -> Option<Scalar> {
    let tweak = projection_tweak(value_in_satoshis, index)?;
    match secret_key + tweak {
        MaybeScalar::Valid(scalar) => Some(scalar),
        MaybeScalar::Zero => None,
    }
}

/// `KeyProjectorAgg`: project each `(public_key, value)` by its index, then run
/// BIP-327 key aggregation. `taproot_tweak` is the optional final taproot tweak
/// (as in [`MusigKeyAggCtx::new`]). The returned context's `agg_key()` is the
/// value-bound Projector Key.
pub fn key_projector_agg(
    keys_and_values: &[(Point, u64)],
    taproot_tweak: Option<Scalar>,
) -> Option<MusigKeyAggCtx> {
    let projected_keys: Vec<Point> = keys_and_values
        .iter()
        .enumerate()
        .map(|(index, (public_key, value))| {
            project_public_key(*public_key, *value, index as u32)
        })
        .collect::<Option<Vec<Point>>>()?;

    MusigKeyAggCtx::new(&projected_keys, taproot_tweak)
}
