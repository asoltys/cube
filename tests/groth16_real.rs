// Real Groth16 zk-SNARK on BLS12-381 (arkworks) — the proof system whose VERIFIER
// is what BitVM3/Cube garbles into a ZKTLC.
//
// We define a tiny circuit (knowledge of a, b such that a*b == c, with c public),
// run the full Groth16 flow — circuit-specific setup -> prove -> verify — on the
// same BLS12-381 curve cube already uses (via bls_on_arkworks), and confirm a
// tampered public input is rejected. The proof is 3 group elements (A in G1,
// B in G2, C in G1): ~192 bytes regardless of circuit size. In Cube, "a*b==c"
// would instead be "this state transition obeyed CubeVM + Bitcoin rules", and the
// verifier below is the boolean circuit that gets garbled (millions of the gates
// from the garbled_circuit_* demos), whose single output bit is "proof valid?".

#[cfg(test)]
mod groth16_real {
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_groth16::Groth16;
    use ark_relations::{
        lc,
        r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
    };
    use ark_serialize::{CanonicalSerialize, Compress};
    use ark_snark::SNARK;
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    /// Circuit: prove knowledge of private a, b with a * b == c (c is public).
    #[derive(Clone)]
    struct MulCircuit {
        a: Option<Fr>,
        b: Option<Fr>,
    }

    impl ConstraintSynthesizer<Fr> for MulCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            // private witnesses a, b
            let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
            let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
            // public input c
            let c_val = match (self.a, self.b) {
                (Some(a), Some(b)) => Some(a * b),
                _ => None,
            };
            let c = cs.new_input_variable(|| c_val.ok_or(SynthesisError::AssignmentMissing))?;
            // the one R1CS constraint: a * b = c
            cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
            Ok(())
        }
    }

    #[test]
    fn groth16_prove_and_verify_on_bls12_381() {
        let mut rng = StdRng::seed_from_u64(42);

        let a = Fr::from(3u64);
        let b = Fr::from(11u64);
        let c = a * b; // 33 — the public statement "I know factors of 33"

        let circuit = MulCircuit { a: Some(a), b: Some(b) };

        // Trusted setup (per-circuit). In a ZKTLC this is the participant-scoped
        // ceremony done with the Engine; toxic waste stays with the participant.
        let (pk, vk) =
            Groth16::<Bls12_381>::circuit_specific_setup(circuit.clone(), &mut rng).expect("setup");

        // Prove.
        let proof = Groth16::<Bls12_381>::prove(&pk, circuit, &mut rng).expect("prove");

        // The famously tiny proof: 3 group elements, constant size.
        let proof_size = proof.serialized_size(Compress::Yes);
        println!("Groth16 proof size: {} bytes (A in G1, B in G2, C in G1)", proof_size);
        assert!(proof_size <= 200, "Groth16 proof is constant ~192 bytes");

        // Verify: valid proof against the correct public input c = 33.
        let pvk = Groth16::<Bls12_381>::process_vk(&vk).expect("process vk");
        assert!(
            Groth16::<Bls12_381>::verify_with_processed_vk(&pvk, &[c], &proof).expect("verify"),
            "a valid proof must verify"
        );

        // A wrong public statement (c = 34) is rejected — the verifier is sound.
        assert!(
            !Groth16::<Bls12_381>::verify_with_processed_vk(&pvk, &[c + Fr::from(1u64)], &proof)
                .expect("verify"),
            "a wrong public input must be rejected"
        );

        println!("REAL GROTH16 EXPLORED: setup -> prove -> verify on BLS12-381; valid proof accepted, tampered public input rejected. This verifier circuit is exactly what a ZKTLC garbles.");
    }
}
