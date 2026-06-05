// A perpetual, block-hash-fair on-VM lottery.
//
// Two methods share per-contract storage:
//   "n"      = total entries ever
//   "s" + i  = entrant at global index i
//   "a"      = 1 while a filled round is awaiting its draw
//   "r"      = round_start index of the pending draw
//   "c"      = OP_BLOCKHASH at the moment the round filled (the "close" block)
//
//   enter()  [Callable, Payable]: require payable == ENTRY (10_000); record the
//            caller at slot[n]; n += 1. When the round fills (n % ROUND == 0),
//            arm the draw: store round_start, set armed = 1, and remember the
//            close block hash.
//
//   draw()   [Callable]: require armed; read OP_BLOCKHASH H; require H differs
//            from the close block (so the entropy comes from a *later* block the
//            entrants could not have known); winner = slot[round_start + H % ROUND];
//            pay the winner PAYOUT (27_000 = 90% of the 30k pot, 3k fee stays);
//            disarm.
//
// Because 256 ≡ 1 (mod 3), a 32-byte hash's value mod 3 equals the sum of its
// bytes mod 3 — which lets the test pick a draw-block hash that selects a known
// winner without depending on stack-uint endianness.
//
// Trust model: this is *fairer* than OP_TIMESTAMP (which the engine sets freely)
// because the draw block is committed-to only after entries close. It is not
// fully trustless — whoever produces/sequences the draw block still has some
// grinding leverage. A production design would commit to a future block *height*
// and/or layer commit-reveal on top.

#[cfg(test)]
mod lottery {
    use cube::constructive::calldata::element_type::CalldataElementType;
    use cube::executive::executable::executable::{Executable, Program};
    use cube::executive::executable::method::method_type::MethodType;
    use cube::executive::executable::method::program_method::ProgramMethod;
    use cube::executive::opcode::opcode::Opcode;
    use cube::executive::opcode::opcodes::arithmetic::op_add::OP_ADD;
    use cube::executive::opcode::opcodes::arithmetic::op_div::OP_DIV;
    use cube::executive::opcode::opcodes::arithmetic::op_not::OP_NOT;
    use cube::executive::opcode::opcodes::arithmetic::op_sub::OP_SUB;
    use cube::executive::opcode::opcodes::bitwise::op_equal::OP_EQUAL;
    use cube::executive::opcode::opcodes::bitwise::op_equalverify::OP_EQUALVERIFY;
    use cube::executive::opcode::opcodes::callinfo::op_blockhash::OP_BLOCKHASH;
    use cube::executive::opcode::opcodes::callinfo::op_caller::OP_CALLER;
    use cube::executive::opcode::opcodes::coin::op_transfer::OP_TRANSFER;
    use cube::executive::opcode::opcodes::flow::op_else::OP_ELSE;
    use cube::executive::opcode::opcodes::flow::op_endif::OP_ENDIF;
    use cube::executive::opcode::opcodes::flow::op_notif::OP_NOTIF;
    use cube::executive::opcode::opcodes::flow::op_returnall::OP_RETURNALL;
    use cube::executive::opcode::opcodes::flow::op_verify::OP_VERIFY;
    use cube::executive::opcode::opcodes::push::op_2::OP_2;
    use cube::executive::opcode::opcodes::push::op_3::OP_3;
    use cube::executive::opcode::opcodes::push::op_false::OP_FALSE;
    use cube::executive::opcode::opcodes::push::op_pushdata::OP_PUSHDATA;
    use cube::executive::opcode::opcodes::push::op_true::OP_TRUE;
    use cube::executive::opcode::opcodes::splice::op_cat::OP_CAT;
    use cube::executive::opcode::opcodes::stack::op_dup::OP_DUP;
    use cube::executive::opcode::opcodes::stack::op_swap::OP_SWAP;
    use cube::executive::stack::stack_item::StackItem;
    use cube::executive::stack::stack_uint::{StackItemUintExt, StackUint};
    use cube::executive::vm::program_execution::caller::Caller;
    use cube::executive::vm::program_execution::exec::execute;
    use cube::inscriptive::coin_manager::coin_manager::{
        erase_coin_manager, CoinManager, COIN_MANAGER,
    };
    use cube::inscriptive::registery::registery::{erase_registery, Registery, REGISTERY};
    use cube::inscriptive::state_manager::state_manager::{
        erase_state_manager, StateManager, STATE_MANAGER,
    };
    use cube::operative::run_args::chain::Chain;

    const ENTRY_LE: [u8; 2] = [0x10, 0x27]; // 10_000
    const PAYOUT_LE: [u8; 2] = [0x78, 0x69]; // 27_000
    const KEY_N: u8 = 0x6e; // "n"
    const KEY_S: u8 = 0x73; // "s"
    const KEY_A: u8 = 0x61; // "a"
    const KEY_C: u8 = 0x63; // "c"
    const KEY_R: u8 = 0x72; // "r"

    // Shorthands for the noisy fully-qualified opcode constructors.
    fn sread() -> Opcode {
        Opcode::OP_SREAD(cube::executive::opcode::opcodes::storage::op_sread::OP_SREAD)
    }
    fn swrite() -> Opcode {
        Opcode::OP_SWRITE(cube::executive::opcode::opcodes::storage::op_swrite::OP_SWRITE)
    }
    fn push(bytes: Vec<u8>) -> Opcode {
        Opcode::OP_PUSHDATA(OP_PUSHDATA(bytes))
    }

    // enter(): record the caller and arm the draw when the round fills.
    fn enter_script() -> Vec<Opcode> {
        vec![
            // require payable E == ENTRY
            push(ENTRY_LE.to_vec()),
            Opcode::OP_EQUALVERIFY(OP_EQUALVERIFY),
            // slot[n] = caller   (key = "s" ++ n)
            push(vec![KEY_N]),
            sread(), // [n]
            Opcode::OP_DUP(OP_DUP),
            push(vec![KEY_S]),
            Opcode::OP_SWAP(OP_SWAP),
            Opcode::OP_CAT(OP_CAT), // [n, key]
            Opcode::OP_CALLER(OP_CALLER),
            Opcode::OP_DROP(cube::executive::opcode::opcodes::stack::op_drop::OP_DROP), // [n, key, caller]
            Opcode::OP_SWAP(OP_SWAP), // [n, caller, key]
            swrite(),                 // [n]
            // newn = n + 1 ; SWRITE("n", newn)
            Opcode::OP_TRUE(OP_TRUE),
            Opcode::OP_ADD(OP_ADD),
            Opcode::OP_VERIFY(OP_VERIFY), // [newn]
            Opcode::OP_DUP(OP_DUP),
            push(vec![KEY_N]),
            swrite(), // [newn]
            // modulo = newn % ROUND
            Opcode::OP_DUP(OP_DUP),
            Opcode::OP_3(OP_3),
            Opcode::OP_SWAP(OP_SWAP),
            Opcode::OP_DIV(OP_DIV),
            Opcode::OP_VERIFY(OP_VERIFY),
            Opcode::OP_DROP(cube::executive::opcode::opcodes::stack::op_drop::OP_DROP), // [newn, modulo]
            Opcode::OP_NOTIF(OP_NOTIF), // modulo == 0 -> arm the draw; [newn]
            // round_start = newn - ROUND ; store (round_start + 1) since storage
            // rejects empty values and round_start can be 0.
            Opcode::OP_3(OP_3),
            Opcode::OP_SWAP(OP_SWAP),
            Opcode::OP_SUB(OP_SUB),
            Opcode::OP_VERIFY(OP_VERIFY), // [rs]
            Opcode::OP_TRUE(OP_TRUE),
            Opcode::OP_ADD(OP_ADD),
            Opcode::OP_VERIFY(OP_VERIFY), // [rs + 1]
            push(vec![KEY_R]),
            swrite(), // []  r = rs + 1
            // armed = 1
            Opcode::OP_TRUE(OP_TRUE),
            push(vec![KEY_A]),
            swrite(), // []  a = 1
            // close block hash = OP_BLOCKHASH
            Opcode::OP_BLOCKHASH(OP_BLOCKHASH),
            push(vec![KEY_C]),
            swrite(), // []  c = close block hash
            Opcode::OP_ELSE(OP_ELSE),
            Opcode::OP_DROP(cube::executive::opcode::opcodes::stack::op_drop::OP_DROP), // drop newn -> []
            Opcode::OP_ENDIF(OP_ENDIF),
            Opcode::OP_RETURNALL(OP_RETURNALL),
        ]
    }

    // draw(): pick + pay the winner using the (later) draw block's hash.
    fn draw_script() -> Vec<Opcode> {
        vec![
            // require armed (a == 1; becomes 2 once drawn)
            push(vec![KEY_A]),
            sread(),
            Opcode::OP_TRUE(OP_TRUE),
            Opcode::OP_EQUALVERIFY(OP_EQUALVERIFY), // []  require a == 1
            // H = draw block hash ; require H != close block hash
            Opcode::OP_BLOCKHASH(OP_BLOCKHASH), // [H]
            Opcode::OP_DUP(OP_DUP),             // [H, H]
            push(vec![KEY_C]),
            sread(),                       // [H, H, c]
            Opcode::OP_EQUAL(OP_EQUAL),    // [H, (H == c)]
            Opcode::OP_NOT(OP_NOT),        // [H, (H != c)]
            Opcode::OP_VERIFY(OP_VERIFY),  // [H]  require draw block != close block
            // modulo = H % ROUND
            Opcode::OP_3(OP_3),
            Opcode::OP_SWAP(OP_SWAP),
            Opcode::OP_DIV(OP_DIV),
            Opcode::OP_VERIFY(OP_VERIFY),
            Opcode::OP_DROP(cube::executive::opcode::opcodes::stack::op_drop::OP_DROP), // [modulo]
            // sum = modulo + (round_start + 1)
            push(vec![KEY_R]),
            sread(), // [modulo, r_stored]
            Opcode::OP_ADD(OP_ADD),
            Opcode::OP_VERIFY(OP_VERIFY), // [sum]
            // widx = sum - 1  (undo the +1 offset stored in "r")
            Opcode::OP_TRUE(OP_TRUE),
            Opcode::OP_SWAP(OP_SWAP),
            Opcode::OP_SUB(OP_SUB),
            Opcode::OP_VERIFY(OP_VERIFY), // [widx]
            // winner = SREAD("s" ++ widx)
            push(vec![KEY_S]),
            Opcode::OP_SWAP(OP_SWAP),
            Opcode::OP_CAT(OP_CAT),
            sread(), // [winner]
            // pay PAYOUT to winner (account)
            push(PAYOUT_LE.to_vec()),
            Opcode::OP_SWAP(OP_SWAP),
            Opcode::OP_FALSE(OP_FALSE),
            Opcode::OP_TRANSFER(OP_TRANSFER), // []
            // disarm: a = 2 (drawn; storage rejects empty so we can't clear it)
            Opcode::OP_2(OP_2),
            push(vec![KEY_A]),
            swrite(), // []
            Opcode::OP_RETURNALL(OP_RETURNALL),
        ]
    }

    fn lottery_program() -> Program {
        let enter = ProgramMethod::new(
            "enter".to_string(),
            MethodType::Callable,
            vec![CalldataElementType::Payable],
            enter_script(),
        )
        .expect("enter method");
        let draw = ProgramMethod::new(
            "draw".to_string(),
            MethodType::Callable,
            vec![],
            draw_script(),
        )
        .expect("draw method");
        Executable::new("perpetual lottery".to_string(), None, vec![enter, draw])
            .expect("program")
    }

    #[test]
    fn print_lottery_bytes() {
        use cube::executive::executable::compiler::compiler::ProgramCompiler;
        let program = lottery_program();
        let bytes = program.compile().expect("compile");
        println!("LOTTERY_PROGRAM_BYTES=0x{}", hex::encode(&bytes));
        println!("LOTTERY_CONTRACT_ID=0x{}", hex::encode(program.contract_id()));
    }

    #[tokio::test]
    async fn lottery_draws_on_a_future_block() {
        let chain = Chain::Testbed;
        erase_registery(chain);
        let registery: REGISTERY = Registery::new(chain).expect("registery");
        erase_coin_manager(chain);
        let coin_manager: COIN_MANAGER = CoinManager::new(chain).expect("coin");
        erase_state_manager(chain);
        let state_manager: STATE_MANAGER = StateManager::new(chain).expect("state");

        let program = lottery_program();
        let contract_id = program.contract_id();
        let ts = 1_776_000_000u64;

        // Register + fund: contract (treasury 0) and three players (10_000 each).
        let players: [[u8; 32]; 3] = [[0x11; 32], [0x22; 32], [0x33; 32]];
        {
            let mut r = registery.lock().await;
            r.register_contract(contract_id, ts, program.clone()).expect("reg contract");
            for p in players.iter() {
                r.register_account(*p, ts, None, None, None, None).expect("reg acct");
            }
            r.apply_changes().expect("reg apply");
        }
        {
            let mut c = coin_manager.lock().await;
            c.register_contract(contract_id, 0).expect("coin reg contract");
            for p in players.iter() {
                c.register_account(*p, 10_000).expect("coin reg acct");
            }
            c.apply_changes().expect("coin apply");
        }
        {
            let mut s = state_manager.lock().await;
            s.register_contract(contract_id).expect("state reg contract");
            s.apply_changes().expect("state apply");
        }

        // Block hashes for the three entry blocks (the 3rd becomes the close block).
        let entry_block_hashes: [[u8; 32]; 3] = [[0xa1; 32], [0xa2; 32], [0xa3; 32]];

        // The draw runs in a *later* block. Its byte-sum mod 3 selects the winner:
        // sum == 2 (mod 3) -> round_start(0) + 2 -> slot 2 -> player 2.
        let mut draw_block_hash = [0u8; 32];
        draw_block_hash[0] = 0x02; // value % 3 == 2

        // Three entries fill the round and arm the draw.
        for (i, p) in players.iter().enumerate() {
            let args = vec![StackItem::from_stack_uint(StackUint::from(10_000u64))];
            execute(
                false,
                Caller::Account(*p),
                contract_id,
                0, // enter
                args,
                ts + 1 + i as u64,
                entry_block_hashes[i],
                1_000_000,
                0,
                0,
                0,
                &state_manager,
                &coin_manager,
                &registery,
            )
            .await
            .unwrap_or_else(|e| panic!("enter {} failed: {:?}", i, e));
            coin_manager.lock().await.apply_changes().expect("coin apply");
            state_manager.lock().await.apply_changes().expect("state apply");
        }

        // Anyone can trigger the draw; it pays the block-hash-selected winner.
        execute(
            false,
            Caller::Account(players[0]),
            contract_id,
            1, // draw
            vec![],
            ts + 10,
            draw_block_hash,
            1_000_000,
            0,
            0,
            0,
            &state_manager,
            &coin_manager,
            &registery,
        )
        .await
        .unwrap_or_else(|e| panic!("draw failed: {:?}", e));
        coin_manager.lock().await.apply_changes().expect("coin apply");
        state_manager.lock().await.apply_changes().expect("state apply");

        let cm = coin_manager.lock().await;
        let p0 = cm.get_account_balance(players[0]).unwrap_or(0);
        let p1 = cm.get_account_balance(players[1]).unwrap_or(0);
        let p2 = cm.get_account_balance(players[2]).unwrap_or(0);
        let treasury = cm.get_contract_balance(contract_id).unwrap_or(0);
        println!("p0={} p1={} p2={} treasury={}", p0, p1, p2, treasury);
        // Draw block hash selects player 2: paid 10000 in, receives 27000 -> 27000.
        assert_eq!(p0, 0, "player 0 paid in, did not win");
        assert_eq!(p1, 0, "player 1 paid in, did not win");
        assert_eq!(p2, 27_000, "player 2 is the block-hash-selected winner");
        assert_eq!(treasury, 3_000, "treasury keeps the 10% fee");
    }
}
