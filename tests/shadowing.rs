// Exploring Cube "Shadowing" — the bridge between logic-held contract funds and
// Bitcoin-native, per-account, unilaterally-exitable claims.
//
// A contract holds BTC under its own logic, but projects participant-attributable
// "shadow allocations" so each account's redeemable balance = native + Σ shadow
// across contracts, always fully collateralized (Contract Balance ≥ Σ shadow).
//
// This test drives a tiny vault contract through the real shadow opcodes:
//   deposit(payable E): OP_SHADOW_ALLOC(caller) + OP_SHADOW_UP(caller, E)  (1:1 claim)
//   reward(payable R):  OP_SHADOW_UP_ALL(R)   (proportional yield, AMM-style)
//   overdraw():         OP_SHADOW_UP(caller, big)  with no new deposit -> rejected
// and verifies the projected balances + the collateralization invariant.

#[cfg(test)]
mod shadowing {
    use cube::constructive::calldata::element_type::CalldataElementType;
    use cube::executive::executable::executable::{Executable, Program};
    use cube::executive::executable::method::method_type::MethodType;
    use cube::executive::executable::method::program_method::ProgramMethod;
    use cube::executive::opcode::opcode::Opcode;
    use cube::executive::opcode::opcodes::callinfo::op_caller::OP_CALLER;
    use cube::executive::opcode::opcodes::flow::op_returnall::OP_RETURNALL;
    use cube::executive::opcode::opcodes::push::op_pushdata::OP_PUSHDATA;
    use cube::executive::opcode::opcodes::shadowing::op_shadow_alloc::OP_SHADOW_ALLOC;
    use cube::executive::opcode::opcodes::shadowing::op_shadow_up::OP_SHADOW_UP;
    use cube::executive::opcode::opcodes::shadowing::op_shadow_up_all::OP_SHADOW_UP_ALL;
    use cube::executive::opcode::opcodes::stack::op_drop::OP_DROP;
    use cube::executive::opcode::opcodes::stack::op_dup::OP_DUP;
    use cube::executive::stack::stack_item::StackItem;
    use cube::executive::stack::stack_uint::{StackItemUintExt, StackUint};
    use cube::executive::vm::program_execution::caller::Caller;
    use cube::executive::vm::program_execution::exec::execute;
    use cube::inscriptive::coin_manager::coin_manager::{erase_coin_manager, CoinManager, COIN_MANAGER};
    use cube::inscriptive::registery::registery::{erase_registery, Registery, REGISTERY};
    use cube::inscriptive::state_manager::state_manager::{erase_state_manager, StateManager, STATE_MANAGER};
    use cube::operative::run_args::chain::Chain;

    fn push_u64(n: u64) -> Opcode {
        Opcode::OP_PUSHDATA(OP_PUSHDATA(
            StackItem::from_stack_uint(StackUint::from(n)).bytes().to_vec(),
        ))
    }

    fn vault_program() -> Program {
        // deposit(payable E): project a 1:1 shadow claim to the depositor.
        //   stack starts [E]; OP_CALLER -> [E, caller, false]; DROP -> [E, caller];
        //   DUP -> [E, caller, caller]; SHADOW_ALLOC pops caller -> [E, caller];
        //   SHADOW_UP pops caller then E -> [].
        let deposit = ProgramMethod::new(
            "deposit".to_string(),
            MethodType::Callable,
            vec![CalldataElementType::Payable],
            vec![
                Opcode::OP_CALLER(OP_CALLER),
                Opcode::OP_DROP(OP_DROP),
                Opcode::OP_DUP(OP_DUP),
                Opcode::OP_SHADOW_ALLOC(OP_SHADOW_ALLOC),
                Opcode::OP_SHADOW_UP(OP_SHADOW_UP),
                Opcode::OP_RETURNALL(OP_RETURNALL),
            ],
        )
        .expect("deposit");

        // reward(payable R): distribute R across all shadow allocations pro-rata.
        //   stack [R]; SHADOW_UP_ALL pops R -> [].
        let reward = ProgramMethod::new(
            "reward".to_string(),
            MethodType::Callable,
            vec![CalldataElementType::Payable],
            vec![
                // pad to the 4-opcode method minimum; DUP+DROP is a no-op on [R].
                Opcode::OP_DUP(OP_DUP),
                Opcode::OP_DROP(OP_DROP),
                Opcode::OP_SHADOW_UP_ALL(OP_SHADOW_UP_ALL),
                Opcode::OP_RETURNALL(OP_RETURNALL),
            ],
        )
        .expect("reward");

        // overdraw(): try to inflate the caller's claim by 1000 with NO new deposit.
        //   push 1000; OP_CALLER; DROP -> [1000, caller]; SHADOW_UP -> would push
        //   allocs_sum past the contract balance -> rejected by the VM.
        let overdraw = ProgramMethod::new(
            "overdraw".to_string(),
            MethodType::Callable,
            vec![],
            vec![
                push_u64(1000),
                Opcode::OP_CALLER(OP_CALLER),
                Opcode::OP_DROP(OP_DROP),
                Opcode::OP_SHADOW_UP(OP_SHADOW_UP),
                Opcode::OP_RETURNALL(OP_RETURNALL),
            ],
        )
        .expect("overdraw");

        Executable::new("shadow vault".to_string(), None, vec![deposit, reward, overdraw])
            .expect("program")
    }

    #[tokio::test]
    async fn shadowing_bridges_contract_funds_to_per_account_claims() {
        let chain = Chain::Testbed;
        erase_registery(chain);
        let registery: REGISTERY = Registery::new(chain).expect("reg");
        erase_coin_manager(chain);
        let coin_manager: COIN_MANAGER = CoinManager::new(chain).expect("coin");
        erase_state_manager(chain);
        let state_manager: STATE_MANAGER = StateManager::new(chain).expect("state");

        let program = vault_program();
        let cid = program.contract_id();
        let ts = 1_800_000_000u64;
        let alice = [0xa1u8; 32];
        let bob = [0xb0u8; 32];

        {
            let mut r = registery.lock().await;
            r.register_contract(cid, ts, program.clone()).expect("rc");
            r.register_account(alice, ts, None, None, None, None).expect("ra");
            r.register_account(bob, ts, None, None, None, None).expect("rb");
            r.apply_changes().expect("rap");
        }
        {
            let mut c = coin_manager.lock().await;
            c.register_contract(cid, 0).expect("crc");
            c.register_account(alice, 1_000_000).expect("cra");
            c.register_account(bob, 1_000_000).expect("crb");
            c.apply_changes().expect("cap");
        }
        {
            let mut s = state_manager.lock().await;
            s.register_contract(cid).expect("src");
            s.apply_changes().expect("sap");
        }

        // Helper to run a method and commit.
        async fn call(
            sm: &STATE_MANAGER, cm: &COIN_MANAGER, reg: &REGISTERY,
            caller: [u8; 32], cid: [u8; 32], method: u16, payable: Option<u64>, ts: u64,
        ) -> Result<(), String> {
            let args = match payable {
                Some(v) => vec![StackItem::from_stack_uint(StackUint::from(v))],
                None => vec![],
            };
            let r = execute(false, Caller::Account(caller), cid, method, args, ts, [0u8; 32], 1_000_000, 0, 0, 0, sm, cm, reg).await;
            if r.is_ok() {
                cm.lock().await.apply_changes().expect("cap");
                sm.lock().await.apply_changes().expect("sap");
            }
            r.map(|_| ()).map_err(|e| format!("{:?}", e))
        }

        // 1) Deposits project 1:1 shadow claims; contract custody = Σ claims.
        call(&state_manager, &coin_manager, &registery, alice, cid, 0, Some(6000), ts).await.expect("alice deposit");
        call(&state_manager, &coin_manager, &registery, bob, cid, 0, Some(2000), ts + 1).await.expect("bob deposit");
        {
            let c = coin_manager.lock().await;
            assert_eq!(c.get_contract_balance(cid).unwrap(), 8000, "contract holds all deposits");
            assert_eq!(c.get_shadow_alloc_value_in_satoshis(cid, alice).unwrap(), 6000, "alice 1:1 claim");
            assert_eq!(c.get_shadow_alloc_value_in_satoshis(cid, bob).unwrap(), 2000, "bob 1:1 claim");
            // The headline property: redeemable = native + Σ shadow across contracts.
            assert_eq!(c.get_account_global_shadow_allocs_sum_in_satoshis(alice).unwrap(), 6000);
        }

        // 2) reward() distributes new BTC pro-rata (AMM-style yield) via SHADOW_UP_ALL.
        //    +8000 over {alice:6000, bob:2000} -> alice +6000, bob +2000.
        call(&state_manager, &coin_manager, &registery, alice, cid, 1, Some(8000), ts + 2).await.expect("reward");
        {
            let c = coin_manager.lock().await;
            assert_eq!(c.get_contract_balance(cid).unwrap(), 16000);
            assert_eq!(c.get_shadow_alloc_value_in_satoshis(cid, alice).unwrap(), 12000, "alice 75% share");
            assert_eq!(c.get_shadow_alloc_value_in_satoshis(cid, bob).unwrap(), 4000, "bob 25% share");
        }

        // 3) The collateralization invariant: over-allocating beyond contract funds is rejected.
        let overdraw = call(&state_manager, &coin_manager, &registery, alice, cid, 2, None, ts + 3).await;
        assert!(overdraw.is_err(), "VM must reject shadow allocs exceeding contract balance");

        println!("SHADOWING EXPLORED: deposits -> 1:1 claims; reward -> pro-rata yield; over-allocation rejected (Contract Balance >= Sum shadow).");
    }
}
