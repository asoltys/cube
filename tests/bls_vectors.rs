// Throwaway: prints BLS + tagged-hash test vectors so the browser JS port
// (noble bls12-381) can be verified byte-for-byte against the Rust implementation.

#[cfg(test)]
mod bls_vectors {
    use cube::transmutative::bls::key::{
        bls_secret_key_bytes_to_bls_secret_key, bls_secret_key_to_bls_public_key,
        secp_secret_key_bytes_to_bls_secret_key_bytes,
    };
    use cube::transmutative::bls::sign::bls_sign;
    use cube::transmutative::bls::verify::bls_verify;
    use cube::transmutative::hash::{Hash, HashTag};

    #[test]
    fn print_vectors() {
        // Fixed secp secret key for reproducibility.
        let secp_secret = [0x42u8; 32];

        // BLS secret (48 bytes) -> scalar (Fr, Copy) -> public key (48 bytes).
        let bls_sk_bytes = secp_secret_key_bytes_to_bls_secret_key_bytes(&secp_secret);
        let bls_sk = bls_secret_key_bytes_to_bls_secret_key(bls_sk_bytes);
        let bls_pk: Vec<u8> = bls_secret_key_to_bls_public_key(bls_sk).unwrap();

        // Sign a fixed 32-byte message.
        let msg = [0x01u8; 32];
        let sig = bls_sign(bls_sk, msg);

        // Tagged-hash vector (the CallEntrySighash tag over a known preimage).
        let tagged = b"hello cube".to_vec().hash(Some(HashTag::CallEntrySighash));

        println!("SECP_SECRET={}", hex::encode(secp_secret));
        println!("BLS_SK={}", hex::encode(bls_sk_bytes));
        println!("BLS_PK={}", hex::encode(&bls_pk));
        println!("MSG={}", hex::encode(msg));
        println!("SIG={}", hex::encode(&sig));
        println!("TAGGED_HASH_INPUT=hello cube");
        println!("TAGGED_HASH={}", hex::encode(tagged));

        // Sanity: Rust verifies its own signature.
        let pk48: [u8; 48] = bls_pk.try_into().unwrap();
        assert!(bls_verify(&pk48, msg, sig), "rust self-verify failed");
    }

    #[test]
    fn print_call_vector() {
        use cube::constructive::core_types::calldata::calldata_elements::calldata_element::CalldataElement;
        use cube::constructive::entity::account::root_account::registered_and_configured_root_account::registered_and_configured_root_account::RegisteredAndConfiguredRootAccount;
        use cube::constructive::entity::account::root_account::root_account::RootAccount;
        use cube::constructive::entity::contract::contract::Contract;
        use cube::constructive::core_types::method_index::method_index::MethodIndex;
        use cube::constructive::core_types::ops_budget::ops_budget::OpsBudget;
        use cube::constructive::core_types::ops_price::ops_price::OpsPrice;
        use cube::constructive::core_types::target::target::Target;
        use cube::constructive::entry::entry_kinds::call::call::Call;

        // Known field values (registered+configured account; BLS key from secp 0x42*32).
        let secp_secret = [0x42u8; 32];
        let bls_sk_bytes = secp_secret_key_bytes_to_bls_secret_key_bytes(&secp_secret);
        let bls_sk = bls_secret_key_bytes_to_bls_secret_key(bls_sk_bytes);
        let bls_pk: Vec<u8> = bls_secret_key_to_bls_public_key(bls_sk).unwrap();
        let bls_pk48: [u8; 48] = bls_pk.clone().try_into().unwrap();

        let account_key = [0x11u8; 32];
        let registery_index = 7u64;
        let account = RootAccount::RegisteredAndConfiguredRootAccount(
            RegisteredAndConfiguredRootAccount::new(account_key, registery_index, bls_pk48),
        );
        let contract = Contract::new([0x22u8; 32], 2);
        let calldata = vec![CalldataElement::Payable(10_000)];
        let call = Call::new(
            account,
            contract,
            MethodIndex::new(0),
            calldata,
            OpsBudget::new(None),
            OpsPrice::new(100),
            Target::new(5),
        );

        let sbe = call.encode_sbe().unwrap();
        let sighash = call.sighash().unwrap();
        let sig = bls_sign(bls_sk, sighash);

        println!("CALL_SBE={}", hex::encode(&sbe));
        println!("CALL_SIGHASH={}", hex::encode(sighash));
        println!("CALL_SIG={}", hex::encode(&sig));
        assert!(bls_verify(&bls_pk48, sighash, sig), "call self-verify failed");
    }
}
