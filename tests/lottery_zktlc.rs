// #2 — The lottery as a ZKTLC: the SETTLE rule as a verifiable state transition,
// plus stakes/winnings as shadow-attributed claims.
//
// For the lottery to be non-custodial, the Engine's settle must be a statement
// anyone can check from public data (the seed + the entry bands) — i.e. the
// predicate a garbled Groth16 verifier would enforce. If the Engine settles to
// the wrong winner, the predicate fails and a challenger disproves it. This file
// implements that predicate (matching lottery_v3: house = round_total*475, win
// region is the cumulative bands, 1% rake) and shows:
//   * a correct settle satisfies the predicate,
//   * a wrong winner / wrong rollover is rejected (the disprovable case),
//   * stakes are shadow allocations fully collateralized by the pot.

#[cfg(test)]
mod lottery_zktlc {
    use cube::inscriptive::coin_manager::coin_manager::{erase_coin_manager, CoinManager, COIN_MANAGER};
    use cube::operative::run_args::chain::Chain;

    const ODDS_DENOM: u64 = 475; // house = round_total * 475  (≈ 0.21% per-round win)
    const RAKE_PERCENT: u64 = 1;

    #[derive(Debug, PartialEq, Eq, Clone)]
    enum Settlement {
        Rollover,
        Winner { entry_index: usize, payout: u64, rake: u64 },
    }

    /// LE 256-bit `seed` reduced mod `space` (matches StackUint::from_little_endian).
    fn seed_mod(seed: &[u8; 32], space: u64) -> u64 {
        let mut r: u128 = 0;
        for &byte in seed.iter().rev() {
            r = (r * 256 + byte as u128) % space as u128;
        }
        r as u64
    }

    /// The deterministic settle of a round from PUBLIC data — the verifiable
    /// transition. `contribs` are the per-entry contributions in order; `b` is the
    /// cumulative total before this round.
    fn compute_settlement(contribs: &[u64], b: u64, seed: &[u8; 32]) -> Settlement {
        let round_total: u64 = contribs.iter().sum();
        let house = round_total * ODDS_DENOM;
        let space = (round_total + house).max(1);
        let total = b + round_total;

        let r = seed_mod(seed, space);
        let rg = r + b;

        if rg >= total {
            return Settlement::Rollover;
        }
        // winner = the entry whose cumulative band [lo, hi) contains rg.
        let mut cum = b;
        for (i, c) in contribs.iter().enumerate() {
            let lo = cum;
            cum += c;
            if lo <= rg && rg < cum {
                let pot = total; // whole jackpot (b carried + this round)
                let rake = pot * RAKE_PERCENT / 100;
                return Settlement::Winner { entry_index: i, payout: pot - rake, rake };
            }
        }
        unreachable!("rg < total guarantees a winning band")
    }

    /// What the garbled verifier checks: does the Engine's claimed settle match the
    /// deterministic computation from public data?
    fn settle_is_valid(contribs: &[u64], b: u64, seed: &[u8; 32], claimed: &Settlement) -> bool {
        &compute_settlement(contribs, b, seed) == claimed
    }

    #[tokio::test]
    async fn lottery_settle_is_a_verifiable_transition_over_shadow_claims() {
        // A round: 5 entries, cumulative bands 1000,3000,6000,10000,15000.
        let contribs = [1000u64, 2000, 3000, 4000, 5000];
        let b = 0u64;
        let round_total: u64 = contribs.iter().sum(); // 15000

        // --- WIN case: seed=5000 -> r=5000 in [3000,6000) -> entry 2 (player 0x33).
        let mut seed = [0u8; 32];
        seed[0] = 0x88;
        seed[1] = 0x13; // 0x1388 = 5000 LE
        let correct = compute_settlement(&contribs, b, &seed);
        assert_eq!(
            correct,
            Settlement::Winner { entry_index: 2, payout: 14850, rake: 150 },
            "winner = band containing r; 1% rake"
        );
        assert!(settle_is_valid(&contribs, b, &seed, &correct), "honest settle verifies");

        // The disprovable cases: a lying Engine is caught by the predicate.
        let wrong_winner = Settlement::Winner { entry_index: 0, payout: 14850, rake: 150 };
        assert!(!settle_is_valid(&contribs, b, &seed, &wrong_winner), "wrong winner is disprovable");
        assert!(!settle_is_valid(&contribs, b, &seed, &Settlement::Rollover), "false rollover is disprovable");
        let skim = Settlement::Winner { entry_index: 2, payout: 14000, rake: 1000 };
        assert!(!settle_is_valid(&contribs, b, &seed, &skim), "skimming the payout is disprovable");

        // --- ROLLOVER case: a seed landing in the house zone (rg >= total).
        let mut roll = [0u8; 32];
        roll[0] = 0x20;
        roll[1] = 0x4e; // 0x4e20 = 20000 >= total(15000) -> rollover
        assert_eq!(compute_settlement(&contribs, b, &roll), Settlement::Rollover);
        assert!(settle_is_valid(&contribs, b, &roll, &Settlement::Rollover));
        assert!(!settle_is_valid(&contribs, b, &roll, &Settlement::Winner { entry_index: 2, payout: 14850, rake: 150 }),
            "claiming a winner on a rollover round is disprovable");

        // --- Stakes as shadow claims, fully collateralized by the pot. ---
        let chain = Chain::Testbed;
        erase_coin_manager(chain);
        let cm: COIN_MANAGER = CoinManager::new(chain).expect("coin");
        let cid = [0x10u8; 32];
        let players: [[u8; 32]; 5] = [[0x11; 32], [0x22; 32], [0x33; 32], [0x44; 32], [0x55; 32]];
        {
            let mut c = cm.lock().await;
            c.register_contract(cid, round_total).expect("rc"); // pot custodies all stakes
            for p in players.iter() {
                c.register_account(*p, 0).expect("ra");
            }
            c.apply_changes().expect("ap");
            // each player's stake = a shadow claim on the pot
            for (i, p) in players.iter().enumerate() {
                c.contract_shadow_alloc_account(cid, *p).expect("alloc");
                c.shadow_up(cid, *p, contribs[i]).expect("stake");
            }
            c.apply_changes().expect("ap2");
        }
        {
            let c = cm.lock().await;
            let pot = c.get_contract_balance(cid).unwrap();
            let staked: u64 = players.iter().map(|p| c.get_shadow_alloc_value_in_satoshis(cid, *p).unwrap()).sum();
            assert_eq!(pot, round_total);
            assert_eq!(staked, pot, "Σ stake claims == pot (fully collateralized; everyone can exit their stake)");
        }

        println!("LOTTERY-AS-ZKTLC EXPLORED: the settle (winner = band containing seed mod space; 1% rake; rollover in the house zone) is a verifiable transition over public data — honest settles verify, wrong winner / false rollover / skimming are disprovable. Stakes are shadow claims fully collateralized by the pot.");
    }
}
