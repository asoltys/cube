// Reproduces the engine's batch-finalization path for a Call entry.
//
// Chains three batches on the Testbed chain, each via the real
// begin_session -> exec_*_in_pool -> into_batch_container -> execute_batch path:
//   batch 1: liftup   (registers + funds the account)
//   batch 2: deploy   (registers the doubling contract)
//   batch 3: call     (invokes `double` with a payable -> OP_TRANSFER 2x)
//
// The live engine's execute_batch failed on batch 3; this pins it down.

#[cfg(test)]
mod call_simulation {
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, OutPoint, ScriptBuf, TxOut, Txid};
    use cube::constructive::bitcoiny::batch_container::batch_container::BatchContainer;
    use cube::constructive::calldata::element_type::CalldataElementType;
    use cube::constructive::core_types::calldata::calldata_elements::calldata_element::CalldataElement;
    use cube::constructive::core_types::entities::account::root_account::root_account::RootAccount;
    use cube::constructive::core_types::entities::contract::contract::Contract;
    use cube::constructive::core_types::method_index::method_index::MethodIndex;
    use cube::constructive::core_types::ops_budget::ops_budget::OpsBudget;
    use cube::constructive::core_types::ops_price::ops_price::OpsPrice;
    use cube::constructive::core_types::target::target::Target;
    use cube::constructive::entries::entry_kinds::call::call::Call;
    use cube::constructive::entries::entry_kinds::deploy::deploy::Deploy;
    use cube::constructive::entries::entry_kinds::liftup::liftup::Liftup;
    use cube::constructive::txo::lift::lift::Lift;
    use cube::constructive::txo::lift::lift_versions::liftv1::liftv1::return_liftv1_scriptpubkey;
    use cube::executive::exec_ctx::exec_ctx::{ExecCtx, EXEC_CTX};
    use cube::executive::executable::compiler::compiler::ProgramCompiler;
    use cube::executive::executable::executable::{Executable, Program};
    use cube::executive::executable::method::method_type::MethodType;
    use cube::executive::executable::method::program_method::ProgramMethod;
    use cube::executive::opcode::opcode::Opcode;
    use cube::executive::opcode::opcodes::arithmetic::op_2mul::OP_2MUL;
    use cube::executive::opcode::opcodes::arithmetic::op_within::OP_WITHIN;
    use cube::executive::opcode::opcodes::callinfo::op_caller::OP_CALLER;
    use cube::executive::opcode::opcodes::coin::op_transfer::OP_TRANSFER;
    use cube::executive::opcode::opcodes::flow::op_returnall::OP_RETURNALL;
    use cube::executive::opcode::opcodes::flow::op_verify::OP_VERIFY;
    use cube::executive::opcode::opcodes::push::op_pushdata::OP_PUSHDATA;
    use cube::executive::opcode::opcodes::push::op_true::OP_TRUE;
    use cube::executive::opcode::opcodes::stack::op_dup::OP_DUP;
    use cube::executive::stack::stack_item::StackItem;
    use cube::executive::stack::stack_uint::{StackItemUintExt, StackUint};
    use cube::inscriptive::archival_manager::archival_manager::{
        erase_archival_manager, ArchivalManager, ARCHIVAL_MANAGER,
    };
    use cube::inscriptive::coin_manager::coin_manager::{
        erase_coin_manager, CoinManager, COIN_MANAGER,
    };
    use cube::inscriptive::flame_manager::flame_manager::{
        erase_flame_manager, FlameManager, FLAME_MANAGER,
    };
    use cube::inscriptive::graveyard::graveyard::{erase_graveyard, Graveyard, GRAVEYARD};
    use cube::inscriptive::params_manager::params_manager::{
        erase_params_manager, ParamsManager, PARAMS_MANAGER,
    };
    use cube::inscriptive::privileges_manager::privileges_manager::{
        erase_privileges_manager, PrivilegesManager, PRIVILEGES_MANAGER,
    };
    use cube::inscriptive::registery::registery::{erase_registery, Registery, REGISTERY};
    use cube::inscriptive::state_manager::state_manager::{
        erase_state_manager, StateManager, STATE_MANAGER,
    };
    use cube::inscriptive::sync_manager::sync_manager::{erase_sync_manager, SyncManager, SYNC_MANAGER};
    use cube::inscriptive::utxo_set::utxo_set::{erase_utxo_set, UTXOSet, UTXO_SET};
    use cube::operative::run_args::chain::Chain;
    use cube::operative::tasks::engine_session::session_pool::session_pool::{
        SessionPool, SESSION_POOL,
    };
    use cube::transmutative::key::KeyHolder;
    use std::sync::Arc;

    fn double_program() -> Program {
        let cap = StackItem::from_stack_uint(StackUint::from(5000u64));
        let script = vec![
            Opcode::OP_DUP(OP_DUP),
            Opcode::OP_TRUE(OP_TRUE),
            Opcode::OP_PUSHDATA(OP_PUSHDATA(cap.bytes().to_vec())),
            Opcode::OP_WITHIN(OP_WITHIN),
            Opcode::OP_VERIFY(OP_VERIFY),
            Opcode::OP_2MUL(OP_2MUL),
            Opcode::OP_VERIFY(OP_VERIFY),
            Opcode::OP_CALLER(OP_CALLER),
            Opcode::OP_TRANSFER(OP_TRANSFER),
            Opcode::OP_RETURNALL(OP_RETURNALL),
        ];
        let method = ProgramMethod::new(
            "double".to_string(),
            MethodType::Callable,
            vec![CalldataElementType::Payable],
            script,
        )
        .expect("method");
        Executable::new("Double your money contract".to_string(), None, vec![method])
            .expect("program")
    }

    #[tokio::test]
    async fn call_through_execute_batch() -> Result<(), String> {
        let engine_key: [u8; 32] = [
            0xa3, 0x08, 0xf8, 0x7d, 0x88, 0x7d, 0x78, 0x34, 0x19, 0xb8, 0x4b, 0x97, 0x65, 0x1f,
            0xd8, 0xa5, 0xf8, 0x8f, 0x6d, 0xb6, 0x41, 0x4a, 0xe6, 0xeb, 0x19, 0x84, 0xcc, 0x67,
            0x42, 0xee, 0xf0, 0x9e,
        ];
        let secret_key: [u8; 32] =
            hex::decode("2795044ce0f83f718bc79c5f2add1e52521978df91ce9b7f82c9097191d33602")
                .unwrap()
                .try_into()
                .unwrap();
        let public_key: [u8; 32] =
            hex::decode("d0ea35e4a5d654109aef6b175672ea98099212a42d028fcf8bd4e38c137ff15a")
                .unwrap()
                .try_into()
                .unwrap();
        let key_holder = KeyHolder::new(secret_key).expect("key holder");
        assert_eq!(key_holder.secp_public_key_bytes(), public_key);

        let chain = Chain::Testbed;
        let feerate = 1u64;

        erase_sync_manager(chain);
        let sync_manager: SYNC_MANAGER = SyncManager::new(chain).expect("sync");
        erase_utxo_set(chain);
        let utxo_set: UTXO_SET = UTXOSet::new(chain).expect("utxo");
        erase_registery(chain);
        let registery: REGISTERY = Registery::new(chain).expect("registery");
        erase_graveyard(chain);
        let graveyard: GRAVEYARD = Graveyard::new(chain).expect("graveyard");
        erase_coin_manager(chain);
        let coin_manager: COIN_MANAGER = CoinManager::new(chain).expect("coin");
        erase_flame_manager(chain);
        let flame_manager: FLAME_MANAGER = FlameManager::new(chain).expect("flame");
        erase_state_manager(chain);
        let state_manager: STATE_MANAGER = StateManager::new(chain).expect("state");
        erase_privileges_manager(chain);
        let privileges_manager: PRIVILEGES_MANAGER = PrivilegesManager::new(chain).expect("priv");
        erase_params_manager(chain);
        let params_manager: PARAMS_MANAGER = ParamsManager::new(chain).expect("params");
        erase_archival_manager(chain);
        let archival_manager: ARCHIVAL_MANAGER = ArchivalManager::new(chain).expect("archival");

        let new_session = || {
            SessionPool::construct(
                engine_key,
                &sync_manager,
                &utxo_set,
                &registery,
                &graveyard,
                &coin_manager,
                &flame_manager,
                &state_manager,
                &privileges_manager,
                &params_manager,
                Some(Arc::clone(&archival_manager)),
            )
        };
        let new_exec_ctx = || {
            ExecCtx::construct(
                engine_key,
                Arc::clone(&sync_manager),
                Arc::clone(&utxo_set),
                Arc::clone(&registery),
                Arc::clone(&graveyard),
                Arc::clone(&coin_manager),
                Arc::clone(&flame_manager),
                Arc::clone(&state_manager),
                Arc::clone(&privileges_manager),
                Arc::clone(&params_manager),
                None,
            )
        };

        // ---- batch 1: liftup (fund + register the account) ----
        {
            let lift: Lift = {
                let spk = return_liftv1_scriptpubkey(public_key, engine_key).expect("lift spk");
                let outpoint = OutPoint::new(Txid::from_byte_array([0x00u8; 32]), 0);
                let txout = TxOut {
                    value: Amount::from_sat(100_000),
                    script_pubkey: ScriptBuf::from(spk),
                };
                utxo_set.lock().await.insert_utxo(&outpoint, &txout);
                Lift::new_liftv1(public_key, engine_key, outpoint, txout)
            };
            let root = RootAccount::self_root_account_from_registery(&key_holder, &registery).await;
            let liftup = Liftup::new(root, Target::new(1), vec![lift]);
            let sig = liftup.bls_sign(&key_holder).expect("liftup sign");

            let session_pool: SESSION_POOL = new_session();
            session_pool.lock().await.begin_session(1, 1_776_000_001, feerate);
            session_pool
                .lock()
                .await
                .exec_liftup_in_pool(&liftup, sig)
                .await
                .map_err(|e| format!("liftup pool: {:?}", e))?;
            let bc: BatchContainer = session_pool
                .lock()
                .await
                .into_batch_container(&key_holder)
                .await
                .map_err(|e| format!("liftup into_batch_container: {:?}", e))?;
            session_pool.lock().await.end_session().await;
            drop(session_pool);
            new_exec_ctx()
                .lock()
                .await
                .execute_batch(&bc)
                .await
                .map_err(|e| format!("liftup execute_batch: {:?}", e))?;
        }

        // ---- batch 2: deploy the doubling contract ----
        let program = double_program();
        let contract_id = program.contract_id();
        {
            let root = RootAccount::self_root_account_from_registery(&key_holder, &registery).await;
            let deploy = Deploy::new(root, program.clone(), 40_000, Target::new(2));
            let sig = deploy.bls_sign(&key_holder).expect("deploy sign");

            let session_pool: SESSION_POOL = new_session();
            session_pool.lock().await.begin_session(2, 1_776_000_002, feerate);
            session_pool
                .lock()
                .await
                .exec_deploy_in_pool(&deploy, sig)
                .await
                .map_err(|e| format!("deploy pool: {:?}", e))?;
            let bc: BatchContainer = session_pool
                .lock()
                .await
                .into_batch_container(&key_holder)
                .await
                .map_err(|e| format!("deploy into_batch_container: {:?}", e))?;
            session_pool.lock().await.end_session().await;
            drop(session_pool);
            new_exec_ctx()
                .lock()
                .await
                .execute_batch(&bc)
                .await
                .map_err(|e| format!("deploy execute_batch: {:?}", e))?;
        }

        // ---- batch 3: call double(5000) -> the path that failed live ----
        {
            let root = RootAccount::self_root_account_from_registery(&key_holder, &registery).await;
            let contract = {
                let r = registery.lock().await;
                r.get_contract_by_contract_id(contract_id)
                    .unwrap_or_else(|| Contract::new(contract_id, 0))
            };
            let call = Call::new(
                root,
                contract,
                MethodIndex::new(0),
                vec![CalldataElement::Payable(5000)],
                OpsBudget::new(None),
                OpsPrice::new(100),
                Target::new(3),
            );
            // Regression: the call must survive the APE encode->decode round-trip
            // unchanged. The engine recomputes the sighash from the decoded call during
            // batch finalization, so any lossy field breaks aggregate-BLS verification.
            {
                let bits = call
                    .encode_ape(3, &registery, false, false, 100)
                    .await
                    .expect("call ape encode");
                let mut iter = bits.iter();
                let decoded = Call::decode_ape(&mut iter, 3, 100, false, false, &registery)
                    .await
                    .expect("call ape decode");
                assert_eq!(
                    call.sighash().expect("orig sighash"),
                    decoded.sighash().expect("decoded sighash"),
                    "call must survive APE round-trip (sighash stable)"
                );
            }

            let sig = call.bls_sign(&key_holder).expect("call sign");

            let session_pool: SESSION_POOL = new_session();
            session_pool.lock().await.begin_session(3, 1_776_000_003, feerate);
            session_pool
                .lock()
                .await
                .exec_call_in_pool(&call, sig)
                .await
                .map_err(|e| format!("call pool: {:?}", e))?;
            let bc: BatchContainer = session_pool
                .lock()
                .await
                .into_batch_container(&key_holder)
                .await
                .map_err(|e| format!("call into_batch_container: {:?}", e))?;
            session_pool.lock().await.end_session().await;
            drop(session_pool);
            new_exec_ctx()
                .lock()
                .await
                .execute_batch(&bc)
                .await
                .map_err(|e| format!("call execute_batch: {:?}", e))?;
        }

        // If we got here, the call survived execute_batch. Verify the 2x payout.
        let cm = coin_manager.lock().await;
        let contract_bal = cm.get_contract_balance(contract_id).unwrap_or(0);
        println!("caller balance: {:?}", cm.get_account_balance(public_key));
        println!("contract balance: {}", contract_bal);
        assert_eq!(contract_bal, 30_000, "contract should have paid out 2x (10k)");
        Ok(())
    }
}
