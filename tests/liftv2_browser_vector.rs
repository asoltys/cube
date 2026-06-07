// Ground-truth vector for the BROWSER doing the DEPOSITOR half of a LiftV2
// lift-in cosign (2-of-2 account+engine taproot key-path spend). The deposit
// keyagg is plain MuSig2(account, engine) + taproot tweak — NO Projector
// projection — so the browser signs with its even-Y account secret directly.
// The JS port (musig.mjs partialSign with evenYSecret) must reproduce the
// client partial that cube's ClientCosigner produces, byte-for-byte.
//
// Run: cargo test --test liftv2_browser_vector -- --nocapture --test-threads=1

#[cfg(test)]
mod liftv2_browser_vector {
    use cube::constructive::txout_types::lift::lift_versions::liftv2::cosign::{
        ClientCosigner, EngineCosigner,
    };
    use cube::constructive::txout_types::lift::lift_versions::liftv2::liftv2::return_liftv2_taproot;
    use cube::transmutative::secp::schnorr::{verify_xonly, SchnorrSigningMode};
    use secp::Scalar;

    const ACCOUNT_SK: &str = "1cc5906ab936b1e29db24fffe9f87b33a4c64f2d3b59aed6c3c4faeb8fcba6da";
    const ACCOUNT_PK: &str = "02cb70281face51a77d51400612196032bb12422d4c07fa42997a0ab39c2431455";
    const ENGINE_SK: &str = "4882eef979baa5c88fd9e62c698de201f0a991af65877becf683e988f3024b0f";
    const ENGINE_PK: &str = "0251deb9fcf4d16b0f82c75cf71e1ffb7879beb0c6bf733b0778a81b777406574f";
    const A_HN: &str = "e2d64e2bd20d5843d03a47199f059aebdf2a9904616a01fe961ee875a7748199";
    const A_BN: &str = "4b978d3aac4135213f536194522f68fbb2ca4321a49d95560ae9726cd9d6a55d";
    const E_HN: &str = "d3b9f2f01f7caa9b0fe2e932ae752f71da9f8f1a652ec895504091333b97d007";
    const E_BN: &str = "961a4d128a1f3cb5c41e71bc86fdc9e81050b7471f05112a6a5360a2240ff3cf";

    fn sc(h: &str) -> Scalar { Scalar::from_hex(h).unwrap() }
    fn x(pk: &str) -> [u8; 32] { hex::decode(&pk[2..]).unwrap().try_into().unwrap() }
    fn hx(b: &[u8]) -> String { hex::encode(b) }

    #[test]
    fn liftin_client_partial_vector() {
        let account_key = x(ACCOUNT_PK);
        let engine_key = x(ENGINE_PK);
        let sighash = [0x5au8; 32]; // stand-in for the lift-in key-path sighash

        let client = ClientCosigner::new(sc(ACCOUNT_SK), sc(A_HN), sc(A_BN));
        let (client_h, client_b) = client.public_nonces();
        let engine = EngineCosigner::begin(
            account_key, engine_key, sc(ENGINE_SK), sc(E_HN), sc(E_BN),
            client_h, client_b, sighash,
        ).unwrap();
        let (engine_h, engine_b) = engine.engine_public_nonces();
        let client_partial = client
            .partial_sign(account_key, engine_key, engine_h, engine_b, sighash)
            .unwrap();
        let agg = engine.complete(client_partial).unwrap();

        let taproot = return_liftv2_taproot(account_key, engine_key).unwrap();
        let output_key = taproot.tweaked_key().unwrap().serialize_xonly();
        assert!(verify_xonly(output_key, sighash, agg, SchnorrSigningMode::BIP340));

        println!("=== LIFTV2 LIFT-IN CLIENT PARTIAL VECTOR (browser must match) ===");
        println!("MESSAGE={}", hx(&sighash));
        println!("ACCOUNT_PK={}", ACCOUNT_PK);
        println!("ENGINE_PK={}", ENGINE_PK);
        println!("TWEAK={}", hx(&taproot.tap_tweak()));
        println!("OUTPUT_KEY={}", hx(&output_key));
        println!("ACCOUNT_SK={}", ACCOUNT_SK);
        println!("ACCOUNT_HIDING_PUB={}", hx(&client_h.serialize()));
        println!("ACCOUNT_BINDING_PUB={}", hx(&client_b.serialize()));
        println!("ENGINE_HIDING_PUB={}", hx(&engine_h.serialize()));
        println!("ENGINE_BINDING_PUB={}", hx(&engine_b.serialize()));
        println!("ACCOUNT_HIDING_SK={} ACCOUNT_BINDING_SK={}", A_HN, A_BN);
        println!("EXPECTED_CLIENT_PARTIAL={}", hx(&client_partial.serialize()));
        println!("=== END VECTOR ===");
    }
}
