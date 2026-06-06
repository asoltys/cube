// Exploring the Projector: value-bound MuSig2 covenant emulation.
//
// We build a Projector Key over two participants, each committing a satoshi value,
// then show:
//   1) cooperative signing with PROJECTED secrets yields a valid signature under
//      the Projector Key,
//   2) changing any committed value changes the Projector Key (hence the covenant
//      scriptpubkey) — the value-binding property,
//   3) a signature valid for one value-configuration does NOT verify under another
//      configuration's key, so a co-signer's authority can't be replayed across
//      alternative covenant states.

#[cfg(test)]
mod projector {
    use cube::transmutative::musig::projector::{key_projector_agg, project_secret_key};
    use cube::transmutative::musig::session::MusigSessionCtx;
    use cube::transmutative::secp::schnorr::{verify_xonly, SchnorrSigningMode};
    use secp::{Point, Scalar};

    // Two participants (even-Y keypairs from tests/musig.rs) + their nonces.
    const A_SK: &str = "1cc5906ab936b1e29db24fffe9f87b33a4c64f2d3b59aed6c3c4faeb8fcba6da";
    const A_PK: &str = "02cb70281face51a77d51400612196032bb12422d4c07fa42997a0ab39c2431455";
    const B_SK: &str = "4882eef979baa5c88fd9e62c698de201f0a991af65877becf683e988f3024b0f";
    const B_PK: &str = "0251deb9fcf4d16b0f82c75cf71e1ffb7879beb0c6bf733b0778a81b777406574f";
    const A_HN: &str = "e2d64e2bd20d5843d03a47199f059aebdf2a9904616a01fe961ee875a7748199";
    const A_BN: &str = "4b978d3aac4135213f536194522f68fbb2ca4321a49d95560ae9726cd9d6a55d";
    const B_HN: &str = "d3b9f2f01f7caa9b0fe2e932ae752f71da9f8f1a652ec895504091333b97d007";
    const B_BN: &str = "961a4d128a1f3cb5c41e71bc86fdc9e81050b7471f05112a6a5360a2240ff3cf";

    fn s(h: &str) -> Scalar {
        Scalar::from_hex(h).unwrap()
    }
    fn p(h: &str) -> Point {
        Point::from_hex(h).unwrap()
    }

    /// Cooperatively sign `msg` under the Projector Key for the given value config.
    fn projector_sign(val_a: u64, val_b: u64, msg: [u8; 32]) -> ([u8; 64], Point) {
        let keyagg = key_projector_agg(&[(p(A_PK), val_a), (p(B_PK), val_b)], None).unwrap();

        // Each participant signs with their PROJECTED secret; its point is the
        // projected public key the keyagg used.
        let a_sk = project_secret_key(s(A_SK), val_a, 0).unwrap();
        let b_sk = project_secret_key(s(B_SK), val_b, 1).unwrap();
        let a_pk = a_sk.base_point_mul();
        let b_pk = b_sk.base_point_mul();

        let mut session = MusigSessionCtx::new(&keyagg, msg).unwrap();
        assert!(session.insert_nonce(a_pk, s(A_HN).base_point_mul(), s(A_BN).base_point_mul()));
        assert!(session.insert_nonce(b_pk, s(B_HN).base_point_mul(), s(B_BN).base_point_mul()));
        let a_ps = session.partial_sign(a_sk, s(A_HN), s(A_BN)).unwrap();
        let b_ps = session.partial_sign(b_sk, s(B_HN), s(B_BN)).unwrap();
        assert!(session.insert_partial_sig(a_pk, a_ps));
        assert!(session.insert_partial_sig(b_pk, b_ps));
        (session.full_agg_sig().unwrap(), keyagg.agg_key())
    }

    #[test]
    fn projector_is_value_bound() {
        let msg = [0x7cu8; 32];

        // 1) cooperative signing under value config {a:6000, b:2000} verifies.
        let (sig_v1, key_v1) = projector_sign(6000, 2000, msg);
        assert!(
            verify_xonly(key_v1.serialize_xonly(), msg, sig_v1, SchnorrSigningMode::BIP340),
            "projector cosignature must verify under its Projector Key"
        );

        // 2) value-binding: bump bob's committed value by 1 sat -> different key.
        let key_v2 = key_projector_agg(&[(p(A_PK), 6000), (p(B_PK), 2001)], None)
            .unwrap()
            .agg_key();
        assert_ne!(
            key_v1.serialize_xonly(),
            key_v2.serialize_xonly(),
            "changing a committed value must change the Projector Key (and thus the covenant spk)"
        );

        // 3) the v1 signature does NOT verify under the v2 key — authority can't be
        //    replayed across alternative covenant value-states.
        assert!(
            !verify_xonly(key_v2.serialize_xonly(), msg, sig_v1, SchnorrSigningMode::BIP340),
            "a signature for one value config must not validate under another"
        );

        // sanity: signing under v2's config does verify under v2's key.
        let (sig_v2, key_v2b) = projector_sign(6000, 2001, msg);
        assert_eq!(key_v2.serialize_xonly(), key_v2b.serialize_xonly());
        assert!(verify_xonly(key_v2b.serialize_xonly(), msg, sig_v2, SchnorrSigningMode::BIP340));

        println!("PROJECTOR EXPLORED: value-bound MuSig2 — cosignature verifies under the Projector Key; changing a committed value changes the key; a signature can't be replayed across value-states (covenant emulation).");
    }
}
