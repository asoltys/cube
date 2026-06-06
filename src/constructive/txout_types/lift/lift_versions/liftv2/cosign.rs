//! Interactive cosign for lifting a LiftV2 deposit INTO the rollup.
//!
//! A LiftV2 deposit is locked to a P2TR whose key path is the taproot-tweaked
//! MuSig2 aggregate of the depositor's account key and the engine key. To lift
//! the deposit in, the engine spends that key path — which it cannot do alone;
//! the depositor must co-sign. The signed message is the batch's key-path
//! sighash, which is only known once the batch is frozen at the end of the
//! waiting window. MuSig2 nonces, however, are message-independent, so the flow
//! is:
//!
//!   Round 1 (pre-freeze): the depositor submits the lift and COMMITS two public
//!   nonces ([`ClientCosigner::public_nonces`]).
//!   At freeze: the engine combines those with its own fresh nonces, partial-
//!   signs, and returns its public nonces + the key-path sighash
//!   ([`EngineCosigner::begin`]).
//!   Round 2 (post-freeze): the depositor partial-signs over the sighash
//!   ([`ClientCosigner::partial_sign`]) and returns its partial signature; the
//!   engine aggregates ([`EngineCosigner::complete`]) into the 64-byte key-path
//!   signature used as the lift input witness.
//!
//! Both sides recompute the taproot tweak from the deposit keys, so the MuSig2
//! aggregate key equals the deposit output key. The aggregate signature is a
//! standard BIP340/BIP341 key-path spend signature.
//!
//! NOTE: nonces are taken as inputs here for determinism/testability; callers
//! MUST supply fresh, single-use, cryptographically-random secret nonces per
//! cosigning session in production (nonce reuse leaks the secret key).

use crate::constructive::txout_types::lift::lift_versions::liftv2::liftv2::return_liftv2_taproot;
use crate::transmutative::musig::keyagg::MusigKeyAggCtx;
use crate::transmutative::musig::session::MusigSessionCtx;
use crate::transmutative::secp::into::IntoPoint;
use secp::{Point, Scalar};

/// Recompute the MuSig2 key-aggregation context for a LiftV2 deposit, including
/// the taproot tweak so the aggregate key equals the deposit output key.
fn liftv2_keyagg(account_key: [u8; 32], engine_key: [u8; 32]) -> Option<MusigKeyAggCtx> {
    let account_pt = account_key.into_point().ok()?;
    let engine_pt = engine_key.into_point().ok()?;
    let taproot = return_liftv2_taproot(account_key, engine_key)?;
    let tweak = Scalar::from_slice(&taproot.tap_tweak()).ok()?;
    MusigKeyAggCtx::new(&vec![account_pt, engine_pt], Some(tweak))
}

/// Depositor (account) side of the cosign.
pub struct ClientCosigner {
    account_secret: Scalar,
    hiding_secret: Scalar,
    binding_secret: Scalar,
}

impl ClientCosigner {
    /// `account_secret` must correspond to the even-Y account point used in the
    /// deposit. `hiding_secret`/`binding_secret` are this session's secret nonces.
    pub fn new(account_secret: Scalar, hiding_secret: Scalar, binding_secret: Scalar) -> Self {
        ClientCosigner {
            account_secret,
            hiding_secret,
            binding_secret,
        }
    }

    /// Round 1: the public nonces to commit to the engine (before the batch and
    /// thus the sighash are known).
    pub fn public_nonces(&self) -> (Point, Point) {
        (
            self.hiding_secret.base_point_mul(),
            self.binding_secret.base_point_mul(),
        )
    }

    /// Round 2: partial-sign the batch key-path sighash, given the engine's
    /// public nonces (received in the engine's round-2 response).
    pub fn partial_sign(
        &self,
        account_key: [u8; 32],
        engine_key: [u8; 32],
        engine_hiding_nonce: Point,
        engine_binding_nonce: Point,
        keypath_sighash: [u8; 32],
    ) -> Option<Scalar> {
        let keyagg = liftv2_keyagg(account_key, engine_key)?;
        let account_pt = account_key.into_point().ok()?;
        let engine_pt = engine_key.into_point().ok()?;

        let mut session = MusigSessionCtx::new(&keyagg, keypath_sighash)?;
        let (ch, cb) = self.public_nonces();
        if !session.insert_nonce(account_pt, ch, cb) {
            return None;
        }
        if !session.insert_nonce(engine_pt, engine_hiding_nonce, engine_binding_nonce) {
            return None;
        }
        session.partial_sign(self.account_secret, self.hiding_secret, self.binding_secret)
    }
}

/// Engine side of the cosign, built at batch freeze once the sighash is known.
pub struct EngineCosigner {
    session: MusigSessionCtx,
    account_pt: Point,
    engine_hiding_nonce: Point,
    engine_binding_nonce: Point,
}

impl EngineCosigner {
    /// At freeze: combine the depositor's committed nonces with the engine's own
    /// fresh nonces, partial-sign with the engine key, and stage the session.
    pub fn begin(
        account_key: [u8; 32],
        engine_key: [u8; 32],
        engine_secret: Scalar,
        engine_hiding_secret: Scalar,
        engine_binding_secret: Scalar,
        client_hiding_nonce: Point,
        client_binding_nonce: Point,
        keypath_sighash: [u8; 32],
    ) -> Option<Self> {
        let keyagg = liftv2_keyagg(account_key, engine_key)?;
        let account_pt = account_key.into_point().ok()?;
        let engine_pt = engine_key.into_point().ok()?;

        let engine_hiding_nonce = engine_hiding_secret.base_point_mul();
        let engine_binding_nonce = engine_binding_secret.base_point_mul();

        let mut session = MusigSessionCtx::new(&keyagg, keypath_sighash)?;
        if !session.insert_nonce(account_pt, client_hiding_nonce, client_binding_nonce) {
            return None;
        }
        if !session.insert_nonce(engine_pt, engine_hiding_nonce, engine_binding_nonce) {
            return None;
        }
        let engine_partial =
            session.partial_sign(engine_secret, engine_hiding_secret, engine_binding_secret)?;
        if !session.insert_partial_sig(engine_pt, engine_partial) {
            return None;
        }

        Some(EngineCosigner {
            session,
            account_pt,
            engine_hiding_nonce,
            engine_binding_nonce,
        })
    }

    /// The engine's public nonces, sent to the depositor for round 2.
    pub fn engine_public_nonces(&self) -> (Point, Point) {
        (self.engine_hiding_nonce, self.engine_binding_nonce)
    }

    /// Round 2: insert the depositor's partial signature and aggregate into the
    /// 64-byte key-path spend signature (the lift input witness).
    pub fn complete(mut self, client_partial: Scalar) -> Option<[u8; 64]> {
        if !self.session.insert_partial_sig(self.account_pt, client_partial) {
            return None;
        }
        self.session.full_agg_sig()
    }
}
