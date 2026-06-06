// THE NON-CUSTODIAL LOTTERY — the whole lifecycle through real engine code.
//
// Everything we built composes here into the goal we've been working toward: a
// lottery whose pot nobody custodies, where stakes and winnings are unilaterally
// exitable and the draw is a publicly-verifiable, disprovable state transition.
//
//   1. STAKE      players stake into a lottery contract; each stake is a Shadowing
//                 claim, and the engine renders the pot as a TimeoutTree so every
//                 player can unilaterally exit their stake (collateralized pot).
//   2. SETTLE     from a public seed the winner is the band containing
//                 (seed mod space); the settle is a deterministic transition over
//                 public data (winner band, 1% rake, rollover in the house zone)
//                 that anyone can recompute — honest settles verify, a wrong
//                 winner / skim / false rollover are disprovable.
//   3. ENFORCE    the settle predicate is what a garbled Groth16 verifier checks;
//                 its "invalid" output label is the disprove secret wired into the
//                 winner VTXO's disprove leaf (BitVM punishment path).
//   4. PAYOUT     the engine applies the verified settle to the shadow state
//                 (losers -> 0, winner -> pot-rake, operator -> rake), then
//                 re-renders the TimeoutTree; the winner unilaterally exits the
//                 whole jackpot with only their key.
//
// The only test-local parts are the settle arithmetic (mirrors lottery_v3) and the
// 1-gate garbled verifier (stands in for the BitVM3 garbled Groth16) — every
// custody/exit/value-binding step runs through real engine modules (CoinManager
// Shadowing, Projector, TimeoutTree).

#[cfg(test)]
mod non_custodial_lottery {
    use bitcoin::hashes::Hash;
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash};
    use bitcoin::transaction::Version;
    use bitcoin::{
        absolute::LockTime, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
        Witness, XOnlyPublicKey,
    };

    use cube::constructive::txout_types::timeout_tree::TimeoutTree;
    use cube::inscriptive::coin_manager::coin_manager::{erase_coin_manager, CoinManager, COIN_MANAGER};
    use cube::operative::run_args::chain::Chain;
    use cube::transmutative::hash::sha256;
    use cube::transmutative::secp::schnorr::{sign, verify_xonly, SchnorrSigningMode};
    use secp::Scalar;

    const ODDS_DENOM: u64 = 475;
    const RAKE_PERCENT: u64 = 1;

    // Two players (alice, bob) + engine — even-Y test keypairs.
    const ALICE_SK: &str = "1cc5906ab936b1e29db24fffe9f87b33a4c64f2d3b59aed6c3c4faeb8fcba6da";
    const ALICE_PK: &str = "02cb70281face51a77d51400612196032bb12422d4c07fa42997a0ab39c2431455";
    const BOB_PK: &str = "0251deb9fcf4d16b0f82c75cf71e1ffb7879beb0c6bf733b0778a81b777406574f";
    const ENGINE_PK: &str = "029611bc66d526fa3194d0f525dce21e782dcf90cc72529ec2d5486da838d83770";

    fn x(pk: &str) -> [u8; 32] {
        hex::decode(&pk[2..]).unwrap().try_into().unwrap()
    }

    // ---- The verifiable settle (mirrors lottery_v3 / tests/lottery_zktlc). ----
    #[derive(Debug, PartialEq, Eq, Clone)]
    enum Settlement {
        Rollover,
        Winner { entry_index: usize, payout: u64, rake: u64 },
    }
    fn seed_mod(seed: &[u8; 32], space: u64) -> u64 {
        let mut r: u128 = 0;
        for &byte in seed.iter().rev() {
            r = (r * 256 + byte as u128) % space as u128;
        }
        r as u64
    }
    fn compute_settlement(contribs: &[u64], b: u64, seed: &[u8; 32]) -> Settlement {
        let round_total: u64 = contribs.iter().sum();
        let house = round_total * ODDS_DENOM;
        let space = (round_total + house).max(1);
        let total = b + round_total;
        let rg = seed_mod(seed, space) + b;
        if rg >= total {
            return Settlement::Rollover;
        }
        let mut cum = b;
        for (i, c) in contribs.iter().enumerate() {
            let lo = cum;
            cum += c;
            if lo <= rg && rg < cum {
                let pot = total;
                let rake = pot * RAKE_PERCENT / 100;
                return Settlement::Winner { entry_index: i, payout: pot - rake, rake };
            }
        }
        unreachable!()
    }
    fn settle_is_valid(contribs: &[u64], b: u64, seed: &[u8; 32], claimed: &Settlement) -> bool {
        &compute_settlement(contribs, b, seed) == claimed
    }

    // ---- 1-gate garbled AND verifier: output-0 label = "invalid" disprove secret. ----
    type Label = [u8; 32];
    fn xorl(a: &Label, b: &Label) -> Label {
        let mut o = [0u8; 32];
        for i in 0..32 {
            o[i] = a[i] ^ b[i];
        }
        o
    }
    fn ks(a: &Label, b: &Label, kind: &[u8]) -> Label {
        let mut p = Vec::new();
        p.extend_from_slice(a);
        p.extend_from_slice(b);
        p.extend_from_slice(kind);
        sha256(&p)
    }
    /// Returns the disprove secret obtained by garble-evaluating an INVALID
    /// transition (the "valid?" gate outputting 0).
    fn garbled_invalid_secret() -> Label {
        let a = [sha256(b"a0"), sha256(b"a1")];
        let b = [sha256(b"b0"), sha256(b"b1")];
        let verdict = [sha256(b"invalid"), sha256(b"valid")]; // [out0, out1]
        let rows: Vec<(Label, Label)> = (0..2)
            .flat_map(|i| (0..2).map(move |j| (i, j)))
            .map(|(i, j)| (ks(&a[i], &b[j], b"tag"), xorl(&ks(&a[i], &b[j], b"enc"), &verdict[i & j])))
            .collect();
        let eval = |al: &Label, bl: &Label| -> Label {
            let t = ks(al, bl, b"tag");
            let (_, ct) = rows.iter().find(|(tag, _)| *tag == t).unwrap();
            xorl(ct, &ks(al, bl, b"enc"))
        };
        // an invalid transition (1 AND 0 -> 0) yields verdict[0] = "invalid".
        let secret = eval(&a[1], &b[0]);
        assert_eq!(secret, verdict[0]);
        secret
    }

    #[tokio::test]
    async fn non_custodial_lottery_full_lifecycle() {
        let alice = x(ALICE_PK);
        let bob = x(BOB_PK);
        let engine = x(ENGINE_PK);
        let house = {
            // a valid even-Y operator (house/rake) account key, no secret needed.
            let s = Scalar::from_slice(&sha256(b"cube-lottery-house")).unwrap();
            let s = s.negate_if(s.base_point_mul().parity());
            s.base_point_mul().serialize_xonly()
        };
        let expiry_height = 800_000u32;
        let exit_delay = 144u16;

        // ---- 1. STAKE: players stake into the lottery contract (shadow claims). ----
        let alice_stake = 30_000u64;
        let bob_stake = 20_000u64;
        let pot = alice_stake + bob_stake;
        let contribs = [alice_stake, bob_stake];

        let chain = Chain::Testbed;
        erase_coin_manager(chain);
        let cm: COIN_MANAGER = CoinManager::new(chain).expect("coin");
        let cid = [0xc0u8; 32];
        {
            let mut c = cm.lock().await;
            c.register_contract(cid, pot).expect("rc");
            c.register_account(alice, 0).expect("ra alice");
            c.register_account(bob, 0).expect("ra bob");
            c.register_account(house, 0).expect("ra house");
            c.apply_changes().expect("ap");
            c.contract_shadow_alloc_account(cid, alice).expect("alloc alice");
            c.shadow_up(cid, alice, alice_stake).expect("stake alice");
            c.contract_shadow_alloc_account(cid, bob).expect("alloc bob");
            c.shadow_up(cid, bob, bob_stake).expect("stake bob");
            c.apply_changes().expect("ap2");
        }

        // engine renders the staked pot as a timeout tree -> both players exitable.
        let pre = {
            let c = cm.lock().await;
            c.get_contract_shadow_allocations_in_satoshis(cid).unwrap()
        };
        let pre_tree = TimeoutTree::build(engine, &pre, expiry_height, exit_delay, None).unwrap();
        assert_eq!(pre_tree.leaves_value_sum(), pot, "pre-draw: every stake collateralized & exitable");

        // ---- 2. SETTLE: pick the winner from a public seed (verifiable). ----
        let mut seed = [0u8; 32];
        seed[0] = 0x64; // 100 -> r=100 in [0, 30000) -> alice (entry 0) wins.
        let settlement = compute_settlement(&contribs, 0, &seed);
        let (winner_index, payout, rake) = match settlement {
            Settlement::Winner { entry_index, payout, rake } => (entry_index, payout, rake),
            Settlement::Rollover => panic!("seed chosen to produce a winner"),
        };
        assert_eq!(winner_index, 0, "alice wins");
        assert_eq!(payout, 49_500);
        assert_eq!(rake, 500);
        // honest settle verifies; the disprovable cases do not.
        assert!(settle_is_valid(&contribs, 0, &seed, &Settlement::Winner { entry_index: 0, payout, rake }));
        assert!(!settle_is_valid(&contribs, 0, &seed, &Settlement::Winner { entry_index: 1, payout, rake }), "wrong winner disprovable");
        assert!(!settle_is_valid(&contribs, 0, &seed, &Settlement::Rollover), "false rollover disprovable");

        // ---- 3. ENFORCE: the garbled verifier's "invalid" secret arms the disprove leaf. ----
        let disprove_secret = garbled_invalid_secret();
        let winner_disprove_hash = sha256(&disprove_secret);

        // ---- 4. PAYOUT: apply the verified settle to shadow state, re-render tree. ----
        {
            let mut c = cm.lock().await;
            // losers -> 0
            c.shadow_down(cid, bob, bob_stake).expect("zero loser bob");
            // winner -> payout
            c.shadow_up(cid, alice, payout - alice_stake).expect("pay winner");
            // operator -> rake
            c.contract_shadow_alloc_account(cid, house).expect("alloc house");
            c.shadow_up(cid, house, rake).expect("rake to house");
            c.apply_changes().expect("ap settle");
        }

        let post = {
            let c = cm.lock().await;
            c.get_contract_shadow_allocations_in_satoshis(cid).unwrap()
        };
        // post-settle claims: winner=payout, house=rake, bob gone.
        let post_map: std::collections::HashMap<[u8; 32], u64> = post.iter().cloned().collect();
        assert_eq!(post_map.get(&alice).copied(), Some(payout), "winner claims the jackpot");
        assert_eq!(post_map.get(&house).copied(), Some(rake), "operator claims the rake");
        assert_eq!(post_map.get(&bob), None, "loser has no claim");
        let post_sum: u64 = post.iter().map(|(_, v)| v).sum();
        assert_eq!(post_sum, pot, "post-settle claims still fully collateralize the pot");

        // re-render the tree, arming alice's winner VTXO with the disprove leaf.
        let disprove_hashes: Vec<[u8; 32]> = post
            .iter()
            .map(|(k, _)| if *k == alice { winner_disprove_hash } else { sha256(k) })
            .collect();
        let post_tree =
            TimeoutTree::build(engine, &post, expiry_height, exit_delay, Some(&disprove_hashes)).unwrap();
        assert_eq!(post_tree.leaves_value_sum(), pot);

        let winner_leaf = post_tree.leaves.iter().find(|l| l.account_key == alice).unwrap();
        assert_eq!(winner_leaf.value_in_satoshis, payout);

        // the winner VTXO's disprove leaf is committed & opens to the garbled secret's hash.
        let (_dh, dscript, dcb) = winner_leaf.disprove_spend_elements().expect("disprove leaf");
        let dscript = ScriptBuf::from_bytes(dscript);
        let winner_x =
            XOnlyPublicKey::from_slice(&winner_leaf.taproot.tweaked_key().unwrap().serialize_xonly()).unwrap();
        assert!(
            ControlBlock::decode(&dcb).unwrap().verify_taproot_commitment(
                &bitcoin::secp256k1::Secp256k1::verification_only(),
                winner_x,
                &dscript
            ),
            "disprove leaf committed in the winner VTXO"
        );

        // ---- the winner UNILATERALLY EXITS the whole jackpot with only her key. ----
        let leaf_txout = TxOut {
            value: Amount::from_sat(winner_leaf.value_in_satoshis),
            script_pubkey: ScriptBuf::from_bytes(winner_leaf.scriptpubkey().unwrap()),
        };
        let leaf_outpoint = OutPoint::new(Txid::from_byte_array([0xa1u8; 32]), 0);
        let exit_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: leaf_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::from_height(exit_delay),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(winner_leaf.value_in_satoshis - 500),
                script_pubkey: ScriptBuf::new_op_return(&[]),
            }],
        };
        let (_eh, exit_script_bytes, exit_cb) = winner_leaf.exit_spend_elements().unwrap();
        let exit_script = ScriptBuf::from_bytes(exit_script_bytes);
        assert!(
            ControlBlock::decode(&exit_cb).unwrap().verify_taproot_commitment(
                &bitcoin::secp256k1::Secp256k1::verification_only(),
                winner_x,
                &exit_script
            ),
            "exit leaf committed in the winner VTXO"
        );
        let exit_sighash = SighashCache::new(&exit_tx)
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&[leaf_txout]),
                TapLeafHash::from_script(&exit_script, LeafVersion::TapScript),
                TapSighashType::Default,
            )
            .unwrap()
            .to_byte_array();
        let winner_sig = sign(
            Scalar::from_hex(ALICE_SK).unwrap().serialize(),
            exit_sighash,
            SchnorrSigningMode::BIP340,
        )
        .unwrap();
        assert!(
            verify_xonly(alice, exit_sighash, winner_sig, SchnorrSigningMode::BIP340),
            "the winner unilaterally exits the jackpot VTXO with only her key — no engine, no custody"
        );

        println!("NON-CUSTODIAL LOTTERY PROVEN END-TO-END: stake (shadow claims, exitable VTXO tree) -> verifiable settle (winner band, 1% rake; wrong winner/rollover disprovable) -> garbled 'invalid' secret arms the disprove leaf -> payout updates shadow state -> winner unilaterally exits the jackpot. Pot stays fully collateralized at every step; nobody custodies it.");
    }
}
