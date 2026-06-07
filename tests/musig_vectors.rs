// Ground-truth MuSig2 test vectors for the BROWSER cosign port. cube uses standard
// BIP327 (tags "KeyAgg list" / "KeyAgg coefficient" / "MuSig/noncecoef", BIP340
// tagged hashes), so a standard JS MuSig2 implementation must reproduce these
// byte-for-byte. This emits a full projector-REFRESH cosign scenario (the exact
// thing a player's browser will sign): the Projector value-bound keyagg over
// (participants + engine) with the funding taproot tweak, fixed nonces, and one
// participant's expected partial signature + the final aggregate.
//
// Run: cargo test --test musig_vectors -- --nocapture --test-threads=1

#[cfg(test)]
mod musig_vectors {
    use cube::constructive::txout_types::timeout_tree::funding_taproot;
    use cube::constructive::txout_types::timeout_tree::refresh::{
        engine_projected_pubkey, engine_projected_secret, participant_projected_pubkey,
        participant_projected_secret, refresh_keyagg,
    };
    use cube::transmutative::musig::session::MusigSessionCtx;
    use cube::transmutative::secp::schnorr::{verify_xonly, SchnorrSigningMode};
    use secp::{Point, Scalar};

    const ALICE_SK: &str = "1cc5906ab936b1e29db24fffe9f87b33a4c64f2d3b59aed6c3c4faeb8fcba6da";
    const ALICE_PK: &str = "02cb70281face51a77d51400612196032bb12422d4c07fa42997a0ab39c2431455";
    const BOB_SK: &str = "4882eef979baa5c88fd9e62c698de201f0a991af65877becf683e988f3024b0f";
    const BOB_PK: &str = "0251deb9fcf4d16b0f82c75cf71e1ffb7879beb0c6bf733b0778a81b777406574f";
    const ENGINE_SK: &str = "2c71bfbd0389b96e292b37c2272ea846655cfb48578b06600c0ffd991f6f7e29";
    const ENGINE_PK: &str = "029611bc66d526fa3194d0f525dce21e782dcf90cc72529ec2d5486da838d83770";
    const A_HN: &str = "e2d64e2bd20d5843d03a47199f059aebdf2a9904616a01fe961ee875a7748199";
    const A_BN: &str = "4b978d3aac4135213f536194522f68fbb2ca4321a49d95560ae9726cd9d6a55d";
    const B_HN: &str = "d3b9f2f01f7caa9b0fe2e932ae752f71da9f8f1a652ec895504091333b97d007";
    const B_BN: &str = "961a4d128a1f3cb5c41e71bc86fdc9e81050b7471f05112a6a5360a2240ff3cf";
    const S_HN: &str = "cf2087a05db9aad43ae97aba584f8d8cb9d61fb84c39f372ea72bdd1d272ab81";
    const S_BN: &str = "4025f894ab8712c244e38af85094043e025824a0d021cd6fb9709fc9ef739e45";

    fn sc(h: &str) -> Scalar { Scalar::from_hex(h).unwrap() }
    fn pt(h: &str) -> Point { Point::from_hex(h).unwrap() }
    fn x(pk: &str) -> [u8; 32] { hex::decode(&pk[2..]).unwrap().try_into().unwrap() }
    fn hx(b: &[u8]) -> String { hex::encode(b) }

    #[test]
    fn refresh_cosign_vector() {
        let alice = x(ALICE_PK);
        let bob = x(BOB_PK);
        let engine = x(ENGINE_PK);
        // allocations as the engine enumerates them (sorted by account key):
        // bob (0251..) < alice (02cb..), so bob=index0, alice=index1, engine=index2.
        let allocs = [(bob, 20_000u64), (alice, 30_000u64)];
        let expiry = 800_000u32;

        // A fixed message (stand-in for the refresh key-path sighash).
        let msg = [0x5au8; 32];

        let keyagg = refresh_keyagg(engine, &allocs, expiry).unwrap();
        let funding = funding_taproot(engine, &allocs, expiry).unwrap();

        // projected pubkeys (what the engine broadcasts to clients as the keyagg set)
        let bob_pub = participant_projected_pubkey(pt(BOB_PK), 20_000, 0).unwrap();
        let alice_pub = participant_projected_pubkey(pt(ALICE_PK), 30_000, 1).unwrap();
        let engine_pub = engine_projected_pubkey(pt(ENGINE_PK), &allocs).unwrap();

        let mut s = MusigSessionCtx::new(&keyagg, msg).unwrap();
        s.insert_nonce(bob_pub, sc(B_HN).base_point_mul(), sc(B_BN).base_point_mul());
        s.insert_nonce(alice_pub, sc(A_HN).base_point_mul(), sc(A_BN).base_point_mul());
        s.insert_nonce(engine_pub, sc(S_HN).base_point_mul(), sc(S_BN).base_point_mul());

        // ALICE's partial — the thing her browser must reproduce.
        let alice_proj_sec = participant_projected_secret(sc(ALICE_SK), 30_000, 1).unwrap();
        let alice_partial = s.partial_sign(alice_proj_sec, sc(A_HN), sc(A_BN)).unwrap();

        // complete + aggregate (engine side) for the full-signature vector.
        let bob_partial = s.partial_sign(participant_projected_secret(sc(BOB_SK), 20_000, 0).unwrap(), sc(B_HN), sc(B_BN)).unwrap();
        let engine_partial = s.partial_sign(engine_projected_secret(sc(ENGINE_SK), &allocs).unwrap(), sc(S_HN), sc(S_BN)).unwrap();
        assert!(s.insert_partial_sig(bob_pub, bob_partial));
        assert!(s.insert_partial_sig(alice_pub, alice_partial));
        assert!(s.insert_partial_sig(engine_pub, engine_partial));
        let agg = s.full_agg_sig().unwrap();
        assert!(verify_xonly(funding.tweaked_key().unwrap().serialize_xonly(), msg, agg, SchnorrSigningMode::BIP340));

        // --- emit the vector (the JS browser cosign must reproduce ALICE_PARTIAL) ---
        println!("=== MUSIG2 REFRESH COSIGN VECTOR (BIP327; browser must match) ===");
        println!("MESSAGE={}", hx(&msg));
        println!("FUNDING_OUTPUT_KEY={}", hx(&funding.tweaked_key().unwrap().serialize_xonly()));
        println!("TAPROOT_TWEAK={}", hx(&funding.tap_tweak()));
        println!("AGG_KEY={}", hx(&keyagg.agg_key().serialize_xonly()));
        // keyagg set (projected pubkeys, sorted by the keyagg internally):
        println!("BOB_PROJ_PUB={}", hx(&bob_pub.serialize()));
        println!("ALICE_PROJ_PUB={}", hx(&alice_pub.serialize()));
        println!("ENGINE_PROJ_PUB={}", hx(&engine_pub.serialize()));
        // alice's signing inputs:
        println!("ALICE_BASE_SK={}", ALICE_SK);
        println!("ALICE_VALUE=30000 ALICE_INDEX=1");
        println!("ALICE_PROJ_SK={}", hx(&alice_proj_sec.serialize()));
        println!("ALICE_HIDING_SK={} ALICE_BINDING_SK={}", A_HN, A_BN);
        println!("ALICE_HIDING_PUB={}", hx(&sc(A_HN).base_point_mul().serialize()));
        println!("ALICE_BINDING_PUB={}", hx(&sc(A_BN).base_point_mul().serialize()));
        // public nonces of the other signers (the browser needs all to aggregate):
        println!("BOB_HIDING_PUB={} BOB_BINDING_PUB={}", hx(&sc(B_HN).base_point_mul().serialize()), hx(&sc(B_BN).base_point_mul().serialize()));
        println!("ENGINE_HIDING_PUB={} ENGINE_BINDING_PUB={}", hx(&sc(S_HN).base_point_mul().serialize()), hx(&sc(S_BN).base_point_mul().serialize()));
        // EXPECTED outputs:
        println!("EXPECTED_ALICE_PARTIAL={}", hx(&alice_partial.serialize()));
        println!("EXPECTED_AGG_SIG={}", hx(&agg));
        println!("=== END VECTOR ===");
    }

    // ODD-Y base key: a browser secret whose point has odd Y. The registered
    // account key is the x-only (even-Y) pubkey, and the keyagg lifts it to even-Y
    // — so the player's browser must NEGATE its raw secret before projecting/signing.
    // Half of all real browser keys land here, so the JS even-Y normalization must
    // reproduce this partial byte-for-byte.
    #[test]
    fn refresh_cosign_vector_odd_y_base() {
        use cube::transmutative::secp::schnorr::LiftScalar;
        // Forge a raw secret with an ODD-Y point: lift to even, then negate once.
        let odd_parity = pt(ALICE_PK.replace("02", "03").as_str() /*any odd point*/).parity();
        let alice_raw_odd = sc(ALICE_SK).lift().negate_if(odd_parity);
        assert_eq!(alice_raw_odd.base_point_mul().serialize()[0], 0x03, "raw base must be odd-Y");
        // The even-Y account point (what the keyagg uses) + its x-only account key.
        let alice_even_pt = alice_raw_odd.base_point_mul().negate_if(odd_parity); // back to even
        let alice = alice_even_pt.serialize_xonly();
        let bob = x(BOB_PK);
        let engine = x(ENGINE_PK);
        // bob (0251..) vs alice (02cb..): bob=index0, alice=index1, engine=index2.
        let allocs = [(bob, 20_000u64), (alice, 30_000u64)];
        let expiry = 800_000u32;
        let msg = [0x5au8; 32];

        let keyagg = refresh_keyagg(engine, &allocs, expiry).unwrap();
        let bob_pub = participant_projected_pubkey(pt(BOB_PK), 20_000, 0).unwrap();
        let alice_pub = participant_projected_pubkey(alice_even_pt, 30_000, 1).unwrap();
        let engine_pub = engine_projected_pubkey(pt(ENGINE_PK), &allocs).unwrap();

        let mut s = MusigSessionCtx::new(&keyagg, msg).unwrap();
        s.insert_nonce(bob_pub, sc(B_HN).base_point_mul(), sc(B_BN).base_point_mul());
        s.insert_nonce(alice_pub, sc(A_HN).base_point_mul(), sc(A_BN).base_point_mul());
        s.insert_nonce(engine_pub, sc(S_HN).base_point_mul(), sc(S_BN).base_point_mul());

        // sign with the EVEN-Y projected secret (what lift() yields from the raw odd key).
        let alice_proj_sec = participant_projected_secret(alice_raw_odd.lift(), 30_000, 1).unwrap();
        let alice_partial = s.partial_sign(alice_proj_sec, sc(A_HN), sc(A_BN)).unwrap();

        println!("=== MUSIG2 ODD-Y BASE VECTOR (browser must normalize) ===");
        println!("ALICE_BASE_SK_RAW_ODD={}", hx(&alice_raw_odd.serialize()));
        println!("ALICE_ACCOUNT_XONLY=02{}", hx(&alice));
        println!("ALICE_PROJ_PUB={}", hx(&alice_pub.serialize()));
        println!("BOB_PROJ_PUB={}", hx(&bob_pub.serialize()));
        println!("ENGINE_PROJ_PUB={}", hx(&engine_pub.serialize()));
        println!("AGG_KEY={}", hx(&keyagg.agg_key().serialize_xonly()));
        println!("EXPECTED_ALICE_PARTIAL_ODD={}", hx(&alice_partial.serialize()));
        println!("=== END ODD-Y VECTOR ===");
    }
}
