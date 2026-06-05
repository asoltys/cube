// Lottery v2 — unlimited participants, variable contributions, proportional
// odds, time-based settlement with a minimum-participant gate, a ~25% no-winner
// rollover (growing jackpot), and a guaranteed-winner final round after 3
// rollovers.
//
// Storage model (all values kept non-empty; rounds advance by moving markers
// forward rather than zeroing keys, which storage forbids):
//   "T"            running total contributed across ALL entries ever (cumsum base)
//   "B"            running total at the START of the current round (cum-before)
//   "g"            global entry count (monotonic; never reset)
//   "r"            global index where the current round started (absent => 0)
//   "c"+le(i)      running total *after* global entry i  (for O(1) odds verify)
//   "p"+le(i)      participant key at global entry i
//   "d"            completed-round count (absent => 0)
//   "w"            round number of the last WIN (absent => 0)  [streak = d - w]
//   "t"            timestamp the current round opened (absent => 0)
//   "k"            round number that has been closed (closed iff k == d+1)
//   "s"            seed (OP_BLOCKHASH) snapshotted at close
//
// Methods: enter(payable) [0], close() [1], settle(u32 idx) [2].

#[cfg(test)]
mod lottery_v2 {
    use cube::constructive::calldata::element_type::CalldataElementType;
    use cube::executive::executable::executable::{Executable, Program};
    use cube::executive::executable::method::method_type::MethodType;
    use cube::executive::executable::method::program_method::ProgramMethod;
    use cube::executive::opcode::opcode::Opcode;
    use cube::executive::opcode::opcodes::arithmetic::op_add::OP_ADD;
    use cube::executive::opcode::opcodes::arithmetic::op_greaterthanorequal::OP_GREATERTHANOREQUAL;
    use cube::executive::opcode::opcodes::callinfo::op_blockhash::OP_BLOCKHASH;
    use cube::executive::opcode::opcodes::callinfo::op_caller::OP_CALLER;
    use cube::executive::opcode::opcodes::callinfo::op_timestamp::OP_TIMESTAMP;
    use cube::executive::opcode::opcodes::bitwise::op_equal::OP_EQUAL;
    use cube::executive::opcode::opcodes::arithmetic::op_not::OP_NOT;
    use cube::executive::opcode::opcodes::flow::op_returnall::OP_RETURNALL;
    use cube::executive::opcode::opcodes::flow::op_verify::OP_VERIFY;
    use cube::executive::opcode::opcodes::push::op_pushdata::OP_PUSHDATA;
    use cube::executive::opcode::opcodes::push::op_true::OP_TRUE;
    use cube::executive::opcode::opcodes::splice::op_cat::OP_CAT;
    use cube::executive::opcode::opcodes::stack::op_drop::OP_DROP;
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

    const KEY_TOTAL: u8 = 0x54; // "T"
    const KEY_B: u8 = 0x42; // "B"
    const KEY_G: u8 = 0x67; // "g"
    const KEY_RS: u8 = 0x72; // "r"
    const KEY_C: u8 = 0x63; // "c"
    const KEY_P: u8 = 0x70; // "p"
    const KEY_TIME: u8 = 0x74; // "t"
    const KEY_K: u8 = 0x6b; // "k"
    const KEY_SEED: u8 = 0x73; // "s"
    const KEY_D: u8 = 0x64; // "d"
    const KEY_W: u8 = 0x77; // "w"
    const DURATION: u8 = 60;

    fn sread() -> Opcode {
        Opcode::OP_SREAD(cube::executive::opcode::opcodes::storage::op_sread::OP_SREAD)
    }
    fn swrite() -> Opcode {
        Opcode::OP_SWRITE(cube::executive::opcode::opcodes::storage::op_swrite::OP_SWRITE)
    }
    fn push(bytes: Vec<u8>) -> Opcode {
        Opcode::OP_PUSHDATA(OP_PUSHDATA(bytes))
    }
    fn k(b: u8) -> Opcode {
        push(vec![b])
    }

    // enter(payable E): record the contribution, its running cumulative sum, and
    // the contributor, all indexed by the monotonic global entry number.
    fn enter_script() -> Vec<Opcode> {
        vec![
            // newT = T + E            [E]
            k(KEY_TOTAL), sread(),      // [E, T]
            Opcode::OP_ADD(OP_ADD), Opcode::OP_VERIFY(OP_VERIFY), // [newT]
            // "T" = newT (keep a copy for the cumsum)
            Opcode::OP_DUP(OP_DUP),     // [newT, newT]
            k(KEY_TOTAL), swrite(),     // [newT]
            // "c"+le(g) = newT
            k(KEY_C), k(KEY_G), sread(), Opcode::OP_CAT(OP_CAT), // [newT, "c"++g]
            swrite(),                   // []
            // "p"+le(g) = caller
            k(KEY_P), k(KEY_G), sread(), Opcode::OP_CAT(OP_CAT), // ["p"++g]
            Opcode::OP_CALLER(OP_CALLER),
            Opcode::OP_DROP(OP_DROP),   // ["p"++g, caller]
            Opcode::OP_SWAP(OP_SWAP),   // [caller, "p"++g]
            swrite(),                   // []
            // "g" = g + 1
            k(KEY_G), sread(), Opcode::OP_TRUE(OP_TRUE), Opcode::OP_ADD(OP_ADD),
            Opcode::OP_VERIFY(OP_VERIFY), // [newg]
            k(KEY_G), swrite(),         // []
            Opcode::OP_RETURNALL(OP_RETURNALL),
        ]
    }

    // close(): gate by time + minimum participants, then snapshot the seed.
    fn close_script() -> Vec<Opcode> {
        vec![
            // require count = (g - r... using totals is simpler: require g - rs >= 5)
            // count = g - rs ; rs absent => 0, so count = g - rs.
            // push g, push rs, SUB -> but SUB is top-second; want g - rs.
            // [] -> read g, read rs => [g, rs]; need g - rs: item_1=top=rs? no.
            // Build [rs, g] then SUB(top=g, second=rs) = g - rs.
            k(KEY_RS), sread(),         // [rs]
            k(KEY_G), sread(),          // [rs, g]
            Opcode::OP_SUB(cube::executive::opcode::opcodes::arithmetic::op_sub::OP_SUB),
            Opcode::OP_VERIFY(OP_VERIFY), // [count]
            Opcode::OP_TRUE(OP_TRUE),    // [count, 1]  (require >= 1 participant)
            Opcode::OP_GREATERTHANOREQUAL(OP_GREATERTHANOREQUAL), // [count>=1]
            Opcode::OP_VERIFY(OP_VERIFY), // []
            // require now >= t + DURATION
            Opcode::OP_TIMESTAMP(OP_TIMESTAMP), // [now]
            k(KEY_TIME), sread(),       // [now, t]
            push(vec![DURATION]),       // [now, t, 60]
            Opcode::OP_ADD(OP_ADD), Opcode::OP_VERIFY(OP_VERIFY), // [now, t+60]
            Opcode::OP_GREATERTHANOREQUAL(OP_GREATERTHANOREQUAL), // [now >= t+60]
            Opcode::OP_VERIFY(OP_VERIFY), // []
            // "s" = OP_BLOCKHASH
            Opcode::OP_BLOCKHASH(OP_BLOCKHASH), k(KEY_SEED), swrite(), // []
            // "k" = d + 1  (mark this round closed)
            k(KEY_D), sread(), Opcode::OP_TRUE(OP_TRUE), Opcode::OP_ADD(OP_ADD),
            Opcode::OP_VERIFY(OP_VERIFY), // [d+1]
            k(KEY_K), swrite(), // []
            Opcode::OP_RETURNALL(OP_RETURNALL),
        ]
    }

    // Opcode shorthands for settle.
    fn op(o: Opcode) -> Opcode { o }
    use cube::executive::opcode::opcodes::arithmetic::op_div::OP_DIV;
    use cube::executive::opcode::opcodes::arithmetic::op_sub::OP_SUB;
    use cube::executive::opcode::opcodes::push::op_3::OP_3;
    use cube::executive::opcode::opcodes::push::op_false::OP_FALSE;
    use cube::executive::opcode::opcodes::flow::op_if::OP_IF;
    use cube::executive::opcode::opcodes::flow::op_else::OP_ELSE;
    use cube::executive::opcode::opcodes::flow::op_endif::OP_ENDIF;
    use cube::executive::opcode::opcodes::altstack::op_toaltstack::OP_TOALTSTACK;
    use cube::executive::opcode::opcodes::altstack::op_fromaltstack::OP_FROMALTSTACK;
    use cube::executive::opcode::opcodes::arithmetic::op_within::OP_WITHIN;
    use cube::executive::opcode::opcodes::coin::op_self_balance::OP_SELF_BALANCE;
    use cube::executive::opcode::opcodes::coin::op_transfer::OP_TRANSFER;

    // Common round-advance opcodes: d=d+1, B=T, rs=g, t=now.
    fn advance() -> Vec<Opcode> {
        vec![
            k(KEY_D), sread(), op(Opcode::OP_TRUE(OP_TRUE)), op(Opcode::OP_ADD(OP_ADD)),
            op(Opcode::OP_VERIFY(OP_VERIFY)), k(KEY_D), swrite(),
            k(KEY_TOTAL), sread(), k(KEY_B), swrite(),
            k(KEY_G), sread(), k(KEY_RS), swrite(),
            op(Opcode::OP_TIMESTAMP(OP_TIMESTAMP)), k(KEY_TIME), swrite(),
        ]
    }

    // settle(u32 idx): pick + pay the proportional winner, or roll over.
    fn settle_script() -> Vec<Opcode> {
        let mut s: Vec<Opcode> = Vec::new();
        let e = |v: &mut Vec<Opcode>, o: Opcode| v.push(o);
        // stash idx
        e(&mut s, Opcode::OP_TOALTSTACK(OP_TOALTSTACK)); // [] alt=[idx]
        // require closed: k == d+1
        s.push(k(KEY_K)); s.push(sread());
        s.push(k(KEY_D)); s.push(sread());
        e(&mut s, Opcode::OP_TRUE(OP_TRUE)); e(&mut s, Opcode::OP_ADD(OP_ADD)); e(&mut s, Opcode::OP_VERIFY(OP_VERIFY));
        e(&mut s, Opcode::OP_EQUAL(OP_EQUAL)); e(&mut s, Opcode::OP_VERIFY(OP_VERIFY)); // []
        // rt = T - B
        s.push(k(KEY_B)); s.push(sread());
        s.push(k(KEY_TOTAL)); s.push(sread());
        e(&mut s, Opcode::OP_SUB(OP_SUB)); e(&mut s, Opcode::OP_VERIFY(OP_VERIFY)); // [rt]
        // house = (d - w >= 3) ? 0 : rt/3
        e(&mut s, Opcode::OP_DUP(OP_DUP)); // [rt, rt]
        s.push(k(KEY_D)); s.push(sread());
        s.push(k(KEY_W)); s.push(sread());
        e(&mut s, Opcode::OP_SWAP(OP_SWAP)); e(&mut s, Opcode::OP_SUB(OP_SUB)); e(&mut s, Opcode::OP_VERIFY(OP_VERIFY)); // [rt,rt,streak]
        e(&mut s, Opcode::OP_3(OP_3)); e(&mut s, Opcode::OP_GREATERTHANOREQUAL(OP_GREATERTHANOREQUAL)); // [rt,rt,final]
        e(&mut s, Opcode::OP_IF(OP_IF));
        e(&mut s, Opcode::OP_DROP(OP_DROP)); e(&mut s, Opcode::OP_FALSE(OP_FALSE)); // [rt, 0]
        e(&mut s, Opcode::OP_ELSE(OP_ELSE));
        e(&mut s, Opcode::OP_3(OP_3)); e(&mut s, Opcode::OP_SWAP(OP_SWAP)); e(&mut s, Opcode::OP_DIV(OP_DIV));
        e(&mut s, Opcode::OP_VERIFY(OP_VERIFY)); e(&mut s, Opcode::OP_SWAP(OP_SWAP)); e(&mut s, Opcode::OP_DROP(OP_DROP)); // [rt, rt/3]
        e(&mut s, Opcode::OP_ENDIF(OP_ENDIF)); // [rt, house]
        // space = rt + house
        e(&mut s, Opcode::OP_ADD(OP_ADD)); e(&mut s, Opcode::OP_VERIFY(OP_VERIFY)); // [space]
        // r = seed % space
        s.push(k(KEY_SEED)); s.push(sread()); // [space, seed]
        e(&mut s, Opcode::OP_DIV(OP_DIV)); e(&mut s, Opcode::OP_VERIFY(OP_VERIFY)); e(&mut s, Opcode::OP_DROP(OP_DROP)); // [r]
        // r_global = r + B
        s.push(k(KEY_B)); s.push(sread()); e(&mut s, Opcode::OP_ADD(OP_ADD)); e(&mut s, Opcode::OP_VERIFY(OP_VERIFY)); // [rg]
        // branch: rg >= T  -> rollover
        e(&mut s, Opcode::OP_DUP(OP_DUP)); s.push(k(KEY_TOTAL)); s.push(sread());
        e(&mut s, Opcode::OP_GREATERTHANOREQUAL(OP_GREATERTHANOREQUAL)); // [rg, rollover]
        e(&mut s, Opcode::OP_IF(OP_IF));
        // ---- ROLLOVER ----
        e(&mut s, Opcode::OP_DROP(OP_DROP)); // []
        for o in advance() { s.push(o); }
        e(&mut s, Opcode::OP_ELSE(OP_ELSE));
        // ---- WIN ---- [rg]
        e(&mut s, Opcode::OP_FROMALTSTACK(OP_FROMALTSTACK)); // [rg, idx]
        e(&mut s, Opcode::OP_FALSE(OP_FALSE)); e(&mut s, Opcode::OP_ADD(OP_ADD)); e(&mut s, Opcode::OP_VERIFY(OP_VERIFY)); // [rg, idxn] (normalized)
        e(&mut s, Opcode::OP_DUP(OP_DUP)); e(&mut s, Opcode::OP_TOALTSTACK(OP_TOALTSTACK)); // [rg, idxn] alt=[idxn] (keep for payout)
        // upper = cum[idx] = read "c"++idxn
        e(&mut s, Opcode::OP_DUP(OP_DUP)); // [rg, idxn, idxn]
        s.push(k(KEY_C)); e(&mut s, Opcode::OP_SWAP(OP_SWAP)); e(&mut s, Opcode::OP_CAT(OP_CAT)); s.push(sread()); // [rg, idxn, upper]
        // lower = (idxn==0) ? 0 : cum[idxn-1]
        e(&mut s, Opcode::OP_SWAP(OP_SWAP)); // [rg, upper, idxn]
        e(&mut s, Opcode::OP_DUP(OP_DUP)); e(&mut s, Opcode::OP_FALSE(OP_FALSE)); e(&mut s, Opcode::OP_EQUAL(OP_EQUAL)); // [rg, upper, idxn, idxn==0]
        e(&mut s, Opcode::OP_IF(OP_IF));
        e(&mut s, Opcode::OP_DROP(OP_DROP)); e(&mut s, Opcode::OP_FALSE(OP_FALSE)); // [rg, upper, 0]
        e(&mut s, Opcode::OP_ELSE(OP_ELSE));
        // idxn-1 = idxn - 1
        e(&mut s, Opcode::OP_TRUE(OP_TRUE)); e(&mut s, Opcode::OP_SWAP(OP_SWAP)); e(&mut s, Opcode::OP_SUB(OP_SUB)); e(&mut s, Opcode::OP_VERIFY(OP_VERIFY)); // [rg, upper, idxn-1]
        s.push(k(KEY_C)); e(&mut s, Opcode::OP_SWAP(OP_SWAP)); e(&mut s, Opcode::OP_CAT(OP_CAT)); s.push(sread()); // [rg, upper, lower]
        e(&mut s, Opcode::OP_ENDIF(OP_ENDIF)); // [rg, upper, lower]
        e(&mut s, Opcode::OP_SWAP(OP_SWAP)); // [rg, lower, upper]
        e(&mut s, Opcode::OP_WITHIN(OP_WITHIN)); e(&mut s, Opcode::OP_VERIFY(OP_VERIFY)); // []  (lower<=rg<upper)
        // winner = p[idx]
        e(&mut s, Opcode::OP_FROMALTSTACK(OP_FROMALTSTACK)); // [idxn]
        s.push(k(KEY_P)); e(&mut s, Opcode::OP_SWAP(OP_SWAP)); e(&mut s, Opcode::OP_CAT(OP_CAT)); s.push(sread()); // [winner]
        // pay full treasury to winner: amount = OP_SELF_BALANCE
        e(&mut s, Opcode::OP_SELF_BALANCE(OP_SELF_BALANCE)); // [winner, balance]
        e(&mut s, Opcode::OP_SWAP(OP_SWAP)); e(&mut s, Opcode::OP_FALSE(OP_FALSE)); // [balance, winner, false(kind=account)]
        e(&mut s, Opcode::OP_TRANSFER(OP_TRANSFER)); // []
        for o in advance() { s.push(o); }
        // w = d (the just-incremented round number that won)
        s.push(k(KEY_D)); s.push(sread()); s.push(k(KEY_W)); s.push(swrite());
        e(&mut s, Opcode::OP_ENDIF(OP_ENDIF));
        e(&mut s, Opcode::OP_RETURNALL(OP_RETURNALL));
        s
    }

    fn lottery_v2_program() -> Program {
        let enter = ProgramMethod::new(
            "enter".to_string(),
            MethodType::Callable,
            vec![CalldataElementType::Payable],
            enter_script(),
        )
        .expect("enter");
        let close = ProgramMethod::new(
            "close".to_string(),
            MethodType::Callable,
            vec![],
            close_script(),
        )
        .expect("close");
        let settle = ProgramMethod::new(
            "settle".to_string(),
            MethodType::Callable,
            vec![CalldataElementType::U32],
            settle_script(),
        )
        .expect("settle");
        Executable::new("perpetual jackpot".to_string(), None, vec![enter, close, settle])
            .expect("program")
    }

    fn le_uint(b: &[u8]) -> u64 {
        let mut x = 0u64;
        for (i, &c) in b.iter().take(8).enumerate() {
            x |= (c as u64) << (8 * i);
        }
        x
    }

    #[test]
    fn print_v2_bytes() {
        use cube::executive::executable::compiler::compiler::ProgramCompiler;
        let program = lottery_v2_program();
        let bytes = program.compile().expect("compile");
        let rt = { let mut s = bytes.clone().into_iter(); Program::decompile(&mut s).expect("decompile") };
        assert_eq!(rt, program, "round-trip");
        println!("V2_BYTES=0x{}", hex::encode(&bytes));
        println!("V2_CONTRACT_ID=0x{}", hex::encode(program.contract_id()));
    }

    #[tokio::test]
    async fn enter_and_close() {
        let chain = Chain::Testbed;
        erase_registery(chain);
        let registery: REGISTERY = Registery::new(chain).expect("reg");
        erase_coin_manager(chain);
        let coin_manager: COIN_MANAGER = CoinManager::new(chain).expect("coin");
        erase_state_manager(chain);
        let state_manager: STATE_MANAGER = StateManager::new(chain).expect("state");

        let program = lottery_v2_program();
        let cid = program.contract_id();
        let ts = 1_800_000_000u64;
        let players: [[u8; 32]; 5] = [[0x11; 32], [0x22; 32], [0x33; 32], [0x44; 32], [0x55; 32]];
        let amounts: [u64; 5] = [1000, 2000, 3000, 4000, 5000];

        {
            let mut r = registery.lock().await;
            r.register_contract(cid, ts, program.clone()).expect("rc");
            for p in players.iter() {
                r.register_account(*p, ts, None, None, None, None).expect("ra");
            }
            r.apply_changes().expect("rap");
        }
        {
            let mut c = coin_manager.lock().await;
            c.register_contract(cid, 0).expect("crc");
            for p in players.iter() {
                c.register_account(*p, 1_000_000).expect("cra");
            }
            c.apply_changes().expect("cap");
        }
        {
            let mut s = state_manager.lock().await;
            s.register_contract(cid).expect("src");
            s.apply_changes().expect("sap");
        }

        for (i, p) in players.iter().enumerate() {
            let args = vec![StackItem::from_stack_uint(StackUint::from(amounts[i]))];
            execute(
                false, Caller::Account(*p), cid, 0, args,
                ts + i as u64, [0xaa; 32], 1_000_000, 0, 0, 0,
                &state_manager, &coin_manager, &registery,
            )
            .await
            .unwrap_or_else(|e| panic!("enter {} failed: {:?}", i, e));
            coin_manager.lock().await.apply_changes().expect("cap");
            state_manager.lock().await.apply_changes().expect("sap");
        }

        // Verify recorded state.
        {
            let s = state_manager.lock().await;
            let g = le_uint(&s.get_state_value(cid, &vec![KEY_G]).unwrap_or_default());
            let total = le_uint(&s.get_state_value(cid, &vec![KEY_TOTAL]).unwrap_or_default());
            let c0 = le_uint(&s.get_state_value(cid, &vec![KEY_C]).unwrap_or_default());
            let c4 = le_uint(&s.get_state_value(cid, &vec![KEY_C, 0x04]).unwrap_or_default());
            println!("g={} total={} c0={} c4={}", g, total, c0, c4);
            assert_eq!(g, 5, "5 entries");
            assert_eq!(total, 15000, "running total");
            assert_eq!(c0, 1000, "cumsum after entry 0");
            assert_eq!(c4, 15000, "cumsum after entry 4");
        }
        let treasury = coin_manager.lock().await.get_contract_balance(cid).unwrap_or(0);
        assert_eq!(treasury, 15000, "treasury holds all contributions");

        // close() after the duration elapses.
        execute(
            false, Caller::Account(players[0]), cid, 1, vec![],
            ts + DURATION as u64 + 1, [0xbb; 32], 1_000_000, 0, 0, 0,
            &state_manager, &coin_manager, &registery,
        )
        .await
        .unwrap_or_else(|e| panic!("close failed: {:?}", e));
        coin_manager.lock().await.apply_changes().expect("cap");
        state_manager.lock().await.apply_changes().expect("sap");
        {
            let s = state_manager.lock().await;
            let seed = s.get_state_value(cid, &vec![KEY_SEED]).unwrap_or_default();
            let closed = le_uint(&s.get_state_value(cid, &vec![KEY_K]).unwrap_or_default());
            println!("seed={} closed={}", hex::encode(&seed), closed);
            assert_eq!(seed, vec![0xbb; 32], "seed snapshotted from blockhash");
        }
    }

    // Helper: register + fund + run a full round, return managers.
    async fn setup() -> (REGISTERY, COIN_MANAGER, STATE_MANAGER, [u8; 32], [[u8; 32]; 5], u64) {
        let chain = Chain::Testbed;
        erase_registery(chain);
        let registery: REGISTERY = Registery::new(chain).expect("reg");
        erase_coin_manager(chain);
        let coin_manager: COIN_MANAGER = CoinManager::new(chain).expect("coin");
        erase_state_manager(chain);
        let state_manager: STATE_MANAGER = StateManager::new(chain).expect("state");
        let program = lottery_v2_program();
        let cid = program.contract_id();
        let ts = 1_800_000_000u64;
        let players: [[u8; 32]; 5] = [[0x11; 32], [0x22; 32], [0x33; 32], [0x44; 32], [0x55; 32]];
        {
            let mut r = registery.lock().await;
            r.register_contract(cid, ts, program.clone()).expect("rc");
            for p in players.iter() { r.register_account(*p, ts, None, None, None, None).expect("ra"); }
            r.apply_changes().expect("rap");
        }
        {
            let mut c = coin_manager.lock().await;
            c.register_contract(cid, 0).expect("crc");
            for p in players.iter() { c.register_account(*p, 1_000_000).expect("cra"); }
            c.apply_changes().expect("cap");
        }
        {
            let mut s = state_manager.lock().await;
            s.register_contract(cid).expect("src");
            s.apply_changes().expect("sap");
        }
        (registery, coin_manager, state_manager, cid, players, ts)
    }

    async fn enter(reg: &REGISTERY, cm: &COIN_MANAGER, sm: &STATE_MANAGER, cid: [u8;32], p: [u8;32], amount: u64, ts: u64) {
        let args = vec![StackItem::from_stack_uint(StackUint::from(amount))];
        execute(false, Caller::Account(p), cid, 0, args, ts, [0xaa; 32], 1_000_000, 0, 0, 0, sm, cm, reg)
            .await.unwrap_or_else(|e| panic!("enter failed: {:?}", e));
        cm.lock().await.apply_changes().expect("cap");
        sm.lock().await.apply_changes().expect("sap");
    }

    #[tokio::test]
    async fn settle_pays_proportional_winner() {
        let (reg, cm, sm, cid, players, ts) = setup().await;
        let amounts: [u64; 5] = [1000, 2000, 3000, 4000, 5000]; // cumsums 1000,3000,6000,10000,15000
        for (i, p) in players.iter().enumerate() {
            enter(&reg, &cm, &sm, cid, *p, amounts[i], ts + i as u64).await;
        }
        // close with a controlled seed. total=15000, house=rt/3=5000, space=20000.
        // seed value 5000 (LE) -> r = 5000 % 20000 = 5000 -> in [3000,6000) -> idx 2 (player 0x33).
        let mut seed = [0u8; 32]; seed[0] = 0x88; seed[1] = 0x13; // 0x1388 = 5000 LE
        execute(false, Caller::Account(players[0]), cid, 1, vec![], ts + DURATION as u64 + 1, seed, 1_000_000, 0, 0, 0, &sm, &cm, &reg)
            .await.unwrap_or_else(|e| panic!("close failed: {:?}", e));
        cm.lock().await.apply_changes().expect("cap");
        sm.lock().await.apply_changes().expect("sap");

        let bal_before = cm.lock().await.get_account_balance(players[2]).unwrap_or(0);
        // settle(idx=2)
        let args = vec![StackItem::from_stack_uint(StackUint::from(2u64))];
        execute(false, Caller::Account(players[0]), cid, 2, args, ts + DURATION as u64 + 2, seed, 1_000_000, 0, 0, 0, &sm, &cm, &reg)
            .await.unwrap_or_else(|e| panic!("settle failed: {:?}", e));
        cm.lock().await.apply_changes().expect("cap");
        sm.lock().await.apply_changes().expect("sap");

        let bal_after = cm.lock().await.get_account_balance(players[2]).unwrap_or(0);
        let treasury = cm.lock().await.get_contract_balance(cid).unwrap_or(0);
        println!("winner(player2) before={} after={} gained={} treasury={}", bal_before, bal_after, bal_after - bal_before, treasury);
        assert_eq!(bal_after - bal_before, 15000, "winner gets the full pot");
        assert_eq!(treasury, 0, "pot emptied");
    }

    #[tokio::test]
    async fn rollovers_grow_jackpot_then_final_round_pays() {
        let (reg, cm, sm, cid, players, ts) = setup().await;
        let amounts: [u64; 5] = [1000, 2000, 3000, 4000, 5000]; // 15000 / round
        // Seed that rolls over in a normal round (r = 17000, round_total 15000, house 5000, space 20000).
        let mut roll_seed = [0u8; 32]; roll_seed[0] = 0x68; roll_seed[1] = 0x42; // 0x4268 = 17000
        let mut now = ts;

        // Rounds 1-3: all roll over; jackpot accumulates.
        for round in 0..3 {
            for (i, p) in players.iter().enumerate() {
                enter(&reg, &cm, &sm, cid, *p, amounts[i], now).await; now += 1;
            }
            now += 100;
            execute(false, Caller::Account(players[0]), cid, 1, vec![], now, roll_seed, 1_000_000, 0, 0, 0, &sm, &cm, &reg)
                .await.unwrap_or_else(|e| panic!("close r{} failed: {:?}", round, e));
            cm.lock().await.apply_changes().unwrap(); sm.lock().await.apply_changes().unwrap();
            now += 1;
            let args = vec![StackItem::from_stack_uint(StackUint::from(0u64))]; // idx ignored on rollover
            execute(false, Caller::Account(players[0]), cid, 2, args, now, roll_seed, 1_000_000, 0, 0, 0, &sm, &cm, &reg)
                .await.unwrap_or_else(|e| panic!("settle r{} failed: {:?}", round, e));
            cm.lock().await.apply_changes().unwrap(); sm.lock().await.apply_changes().unwrap();
            let treasury = cm.lock().await.get_contract_balance(cid).unwrap_or(0);
            println!("after round {}: treasury(jackpot)={}", round + 1, treasury);
            assert_eq!(treasury, 15000 * (round as u64 + 1), "jackpot grows on rollover");
            now += 200;
        }

        // Round 4: streak == 3 -> final round (house = 0) -> guaranteed winner even with the roll seed.
        for (i, p) in players.iter().enumerate() {
            enter(&reg, &cm, &sm, cid, *p, amounts[i], now).await; now += 1;
        }
        now += 100;
        execute(false, Caller::Account(players[0]), cid, 1, vec![], now, roll_seed, 1_000_000, 0, 0, 0, &sm, &cm, &reg)
            .await.unwrap_or_else(|e| panic!("final close failed: {:?}", e));
        cm.lock().await.apply_changes().unwrap(); sm.lock().await.apply_changes().unwrap();
        now += 1;
        // total now 60000, B=45000, round_total=15000, house=0, space=15000, r=17000%15000=2000,
        // rg=2000+45000=47000 in [cum[15]=46000, cum[16]=48000) -> global idx 16 = player1.
        let winner_idx = 16u64;
        let bal_before = cm.lock().await.get_account_balance(players[1]).unwrap_or(0);
        let args = vec![StackItem::from_stack_uint(StackUint::from(winner_idx))];
        execute(false, Caller::Account(players[0]), cid, 2, args, now, roll_seed, 1_000_000, 0, 0, 0, &sm, &cm, &reg)
            .await.unwrap_or_else(|e| panic!("final settle failed: {:?}", e));
        cm.lock().await.apply_changes().unwrap(); sm.lock().await.apply_changes().unwrap();
        let bal_after = cm.lock().await.get_account_balance(players[1]).unwrap_or(0);
        let treasury = cm.lock().await.get_contract_balance(cid).unwrap_or(0);
        println!("FINAL: player1 gained={} treasury={}", bal_after - bal_before, treasury);
        assert_eq!(bal_after - bal_before, 60000, "final-round winner takes the whole accumulated jackpot");
        assert_eq!(treasury, 0, "jackpot fully paid out");
    }
}
