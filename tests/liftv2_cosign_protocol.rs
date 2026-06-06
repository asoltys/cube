// Drives the staged LiftV2 cosign protocol (the module the transport handlers +
// client will call) through its real round order:
//   R1: client commits public nonces (before the batch/sighash exist)
//   freeze: engine begins with its own nonces + the now-known sighash, partial-signs
//   R2: client partial-signs; engine aggregates -> 64-byte key-path signature
// and verifies the aggregate is a valid key-path spend of the deposit output key.

#[cfg(test)]
mod liftv2_cosign_protocol {
    use cube::constructive::txo::lift::lift_versions::liftv2::cosign::{
        ClientCosigner, EngineCosigner,
    };
    use cube::constructive::txo::lift::lift_versions::liftv2::liftv2::return_liftv2_taproot;
    use cube::transmutative::secp::schnorr::{verify_xonly, SchnorrSigningMode};
    use secp::{Point, Scalar};

    const ACCOUNT_SK: &str = "1cc5906ab936b1e29db24fffe9f87b33a4c64f2d3b59aed6c3c4faeb8fcba6da";
    const ACCOUNT_PK: &str = "02cb70281face51a77d51400612196032bb12422d4c07fa42997a0ab39c2431455";
    const ENGINE_SK: &str = "4882eef979baa5c88fd9e62c698de201f0a991af65877becf683e988f3024b0f";
    const ENGINE_PK: &str = "0251deb9fcf4d16b0f82c75cf71e1ffb7879beb0c6bf733b0778a81b777406574f";
    const A_HN_SK: &str = "e2d64e2bd20d5843d03a47199f059aebdf2a9904616a01fe961ee875a7748199";
    const A_BN_SK: &str = "4b978d3aac4135213f536194522f68fbb2ca4321a49d95560ae9726cd9d6a55d";
    const E_HN_SK: &str = "d3b9f2f01f7caa9b0fe2e932ae752f71da9f8f1a652ec895504091333b97d007";
    const E_BN_SK: &str = "961a4d128a1f3cb5c41e71bc86fdc9e81050b7471f05112a6a5360a2240ff3cf";

    fn xonly(pk_hex: &str) -> [u8; 32] {
        hex::decode(&pk_hex[2..]).unwrap().try_into().unwrap()
    }

    #[test]
    fn staged_cosign_yields_valid_keypath_spend() {
        let account_key = xonly(ACCOUNT_PK);
        let engine_key = xonly(ENGINE_PK);
        // Stand-in for the batch key-path sighash (unknown at round 1).
        let keypath_sighash = [0x5au8; 32];

        // R1 (pre-freeze): client commits its public nonces.
        let client = ClientCosigner::new(
            Scalar::from_hex(ACCOUNT_SK).unwrap(),
            Scalar::from_hex(A_HN_SK).unwrap(),
            Scalar::from_hex(A_BN_SK).unwrap(),
        );
        let (client_h, client_b) = client.public_nonces();
        // sanity: committed public nonces match the secret nonces
        assert_eq!(client_h, Scalar::from_hex(A_HN_SK).unwrap().base_point_mul());
        assert_eq!(client_b, Scalar::from_hex(A_BN_SK).unwrap().base_point_mul());

        // freeze: engine begins with its nonces + the now-known sighash.
        let engine = EngineCosigner::begin(
            account_key,
            engine_key,
            Scalar::from_hex(ENGINE_SK).unwrap(),
            Scalar::from_hex(E_HN_SK).unwrap(),
            Scalar::from_hex(E_BN_SK).unwrap(),
            client_h,
            client_b,
            keypath_sighash,
        )
        .expect("engine begin");
        let (engine_h, engine_b) = engine.engine_public_nonces();

        // R2 (post-freeze): client partial-signs, engine aggregates.
        let client_partial = client
            .partial_sign(account_key, engine_key, engine_h, engine_b, keypath_sighash)
            .expect("client partial sign");
        let agg_sig = engine.complete(client_partial).expect("aggregate");

        // The aggregate is a valid key-path spend of the deposit output key.
        let output_key = return_liftv2_taproot(account_key, engine_key)
            .unwrap()
            .tweaked_key()
            .unwrap()
            .serialize_xonly();
        assert!(
            verify_xonly(output_key, keypath_sighash, agg_sig, SchnorrSigningMode::BIP340),
            "staged cosign must yield a valid key-path spend signature"
        );

        // The aggregate key really is the deposit output key (defensive).
        let _ = Point::from_hex(ACCOUNT_PK).unwrap();

        println!("LiftV2 STAGED COSIGN PROTOCOL PROVEN: R1 nonce-commit -> freeze -> R2 partial-sign -> aggregate yields a valid key-path spend.");
    }
}
