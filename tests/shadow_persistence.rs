// Reproduces the live symptom: after a restart, a contract's BALANCE persists but
// its shadow ALLOCATIONS load as 0 (custody gap). Drives the real CoinManager
// persist -> drop -> reload (sled on disk) roundtrip.

#[cfg(test)]
mod shadow_persistence {
    use cube::inscriptive::coin_manager::coin_manager::{erase_coin_manager, CoinManager, COIN_MANAGER};
    use cube::operative::run_args::chain::Chain;

    #[tokio::test]
    async fn shadow_allocs_survive_restart() {
        let chain = Chain::Testbed;
        erase_coin_manager(chain);
        let cid = [0x7c; 32];
        let acct = [0x11; 32];

        // Session 1: register + shadow_up + apply (commit to disk).
        {
            let cm: COIN_MANAGER = CoinManager::new(chain).expect("coin1");
            let mut c = cm.lock().await;
            c.register_contract(cid, 10_000).expect("rc");
            c.register_account(acct, 0).expect("ra");
            c.apply_changes().expect("ap1");
            c.contract_shadow_alloc_account(cid, acct).expect("alloc");
            c.shadow_up(cid, acct, 5_000).expect("up");
            c.apply_changes().expect("ap2");
            assert_eq!(c.get_shadow_alloc_value_in_satoshis(cid, acct).unwrap(), 5_000, "in-process claim");
            assert_eq!(c.get_contract_balance(cid).unwrap(), 10_000, "in-process balance");
        }

        // Session 2: reload from disk (simulates an engine restart). DO NOT erase.
        {
            let cm: COIN_MANAGER = CoinManager::new(chain).expect("coin2");
            let c = cm.lock().await;
            let balance = c.get_contract_balance(cid).unwrap_or(0);
            let claim = c.get_shadow_alloc_value_in_satoshis(cid, acct).unwrap_or(0);
            let enumerated: u64 = c
                .get_contract_shadow_allocations_in_satoshis(cid)
                .unwrap_or_default()
                .iter()
                .map(|(_, v)| v)
                .sum();
            println!("AFTER RELOAD: balance={} claim={} Σenumerated={}", balance, claim, enumerated);
            assert_eq!(balance, 10_000, "balance persists across restart");
            assert_eq!(claim, 5_000, "shadow claim must persist across restart (no custody gap)");
            assert_eq!(enumerated, 5_000, "enumeration must find the persisted claim");
        }
    }
}
