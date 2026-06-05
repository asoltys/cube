// Lottery v3 — identical to v2 (unlimited participants, proportional odds,
// time-based settle, ~25% rollover, guaranteed-winner final round) but with a
// 1% operator rake: on a winning settle, 1% of the paid-out pot is transferred
// to a fixed operator account before the winner is paid the remainder. Rollover
// rounds pay nothing and take no rake.
//
// Storage model and methods are unchanged from v2 (enter[0], close[1], settle[2]).

#[cfg(test)]
mod lottery_v3 {
    use cube::constructive::calldata::element_type::CalldataElementType;
    use cube::executive::executable::executable::{Executable, Program};
    use cube::executive::executable::method::method_type::MethodType;
    use cube::executive::executable::method::program_method::ProgramMethod;
    use cube::executive::opcode::opcode::Opcode;
    use cube::executive::opcode::opcodes::arithmetic::op_add::OP_ADD;
    use cube::executive::opcode::opcodes::arithmetic::op_greaterthanorequal::OP_GREATERTHANOREQUAL;
    use cube::executive::opcode::opcodes::callinfo::op_blockhash::OP_BLOCKHASH;
    use cube::executive::opcode::opcodes::callinfo::op_timestamp::OP_TIMESTAMP;
    use cube::executive::opcode::opcodes::bitwise::op_equal::OP_EQUAL;
    use cube::executive::opcode::opcodes::flow::op_returnall::OP_RETURNALL;
    use cube::executive::opcode::opcodes::flow::op_verify::OP_VERIFY;
    use cube::executive::opcode::opcodes::push::op_pushdata::OP_PUSHDATA;
    use cube::executive::opcode::opcodes::splice::op_cat::OP_CAT;
    use cube::executive::opcode::opcodes::stack::op_drop::OP_DROP;
    use cube::executive::opcode::opcodes::stack::op_dup::OP_DUP;
    use cube::executive::opcode::opcodes::stack::op_swap::OP_SWAP;
    use cube::executive::opcode::opcodes::push::op_true::OP_TRUE;
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
    const DURATION: u8 = 120; // 2-minute rounds (timer starts at the first entry)
    const ODDS_DENOM: u64 = 475; // house = rt * 475 -> win region rt is 1/476 of space (~0.21%)

    // Operator account that accrues the 1% rake (baked into the contract).
    const OPERATOR_HEX: &str = "a55068222783355b755993fe7e1ac0b190d29fa2689a9ebc041ff7252617dd04";
    fn operator_key() -> Vec<u8> {
        hex::decode(OPERATOR_HEX).expect("operator hex")
    }

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
    // Minimal little-endian encoding of n (at least one byte), matching how the
    // VM reads pushed numbers.
    fn le_bytes(mut n: u64) -> Vec<u8> {
        let mut out = Vec::new();
        while n > 0 { out.push((n & 0xff) as u8); n >>= 8; }
        if out.is_empty() { out.push(0); }
        out
    }

    // enter(payable E): record the contribution, its running cumulative sum, and
    // the contributor, all indexed by the monotonic global entry number.
    fn enter_script() -> Vec<Opcode> {
        vec![
            // First entry of the round starts the 2-minute timer: if g == rs
            // (no entries yet this round) then t = now. This way a lone early
            // joiner gives others a full window instead of an already-elapsed one.
            k(KEY_G), sread(), k(KEY_RS), sread(),
            Opcode::OP_EQUAL(OP_EQUAL),
            Opcode::OP_IF(OP_IF),
            Opcode::OP_TIMESTAMP(OP_TIMESTAMP), k(KEY_TIME), swrite(),
            Opcode::OP_ENDIF(OP_ENDIF),
            // newT = T + E
            k(KEY_TOTAL), sread(),
            Opcode::OP_ADD(OP_ADD), Opcode::OP_VERIFY(OP_VERIFY),
            Opcode::OP_DUP(OP_DUP),
            k(KEY_TOTAL), swrite(),
            k(KEY_C), k(KEY_G), sread(), Opcode::OP_CAT(OP_CAT),
            swrite(),
            k(KEY_P), k(KEY_G), sread(), Opcode::OP_CAT(OP_CAT),
            Opcode::OP_CALLER(cube::executive::opcode::opcodes::callinfo::op_caller::OP_CALLER),
            Opcode::OP_DROP(OP_DROP),
            Opcode::OP_SWAP(OP_SWAP),
            swrite(),
            k(KEY_G), sread(), Opcode::OP_TRUE(OP_TRUE), Opcode::OP_ADD(OP_ADD),
            Opcode::OP_VERIFY(OP_VERIFY),
            k(KEY_G), swrite(),
            Opcode::OP_RETURNALL(OP_RETURNALL),
        ]
    }

    // close(): gate by time + minimum participants, then snapshot the seed.
    fn close_script() -> Vec<Opcode> {
        vec![
            k(KEY_RS), sread(),
            k(KEY_G), sread(),
            Opcode::OP_SUB(cube::executive::opcode::opcodes::arithmetic::op_sub::OP_SUB),
            Opcode::OP_VERIFY(OP_VERIFY),
            Opcode::OP_TRUE(OP_TRUE),
            Opcode::OP_GREATERTHANOREQUAL(OP_GREATERTHANOREQUAL),
            Opcode::OP_VERIFY(OP_VERIFY),
            Opcode::OP_TIMESTAMP(OP_TIMESTAMP),
            k(KEY_TIME), sread(),
            push(vec![DURATION]),
            Opcode::OP_ADD(OP_ADD), Opcode::OP_VERIFY(OP_VERIFY),
            Opcode::OP_GREATERTHANOREQUAL(OP_GREATERTHANOREQUAL),
            Opcode::OP_VERIFY(OP_VERIFY),
            Opcode::OP_BLOCKHASH(OP_BLOCKHASH), k(KEY_SEED), swrite(),
            k(KEY_D), sread(), Opcode::OP_TRUE(OP_TRUE), Opcode::OP_ADD(OP_ADD),
            Opcode::OP_VERIFY(OP_VERIFY),
            k(KEY_K), swrite(),
            Opcode::OP_RETURNALL(OP_RETURNALL),
        ]
    }

    fn op(o: Opcode) -> Opcode { o }
    use cube::executive::opcode::opcodes::arithmetic::op_div::OP_DIV;
    use cube::executive::opcode::opcodes::arithmetic::op_mul::OP_MUL;
    use cube::executive::opcode::opcodes::arithmetic::op_sub::OP_SUB;
    use cube::executive::opcode::opcodes::push::op_false::OP_FALSE;
    use cube::executive::opcode::opcodes::flow::op_if::OP_IF;
    use cube::executive::opcode::opcodes::flow::op_else::OP_ELSE;
    use cube::executive::opcode::opcodes::flow::op_endif::OP_ENDIF;
    use cube::executive::opcode::opcodes::altstack::op_toaltstack::OP_TOALTSTACK;
    use cube::executive::opcode::opcodes::altstack::op_fromaltstack::OP_FROMALTSTACK;
    use cube::executive::opcode::opcodes::arithmetic::op_within::OP_WITHIN;
    use cube::executive::opcode::opcodes::coin::op_self_balance::OP_SELF_BALANCE;
    use cube::executive::opcode::opcodes::coin::op_transfer::OP_TRANSFER;

    fn advance() -> Vec<Opcode> {
        vec![
            k(KEY_D), sread(), op(Opcode::OP_TRUE(OP_TRUE)), op(Opcode::OP_ADD(OP_ADD)),
            op(Opcode::OP_VERIFY(OP_VERIFY)), k(KEY_D), swrite(),
            k(KEY_TOTAL), sread(), k(KEY_B), swrite(),
            k(KEY_G), sread(), k(KEY_RS), swrite(),
            op(Opcode::OP_TIMESTAMP(OP_TIMESTAMP)), k(KEY_TIME), swrite(),
        ]
    }

    // settle(u32 idx): pick + pay the proportional winner (minus 1% operator
    // rake), or roll over.
    fn settle_script() -> Vec<Opcode> {
        let mut s: Vec<Opcode> = Vec::new();
        let e = |v: &mut Vec<Opcode>, o: Opcode| v.push(o);
        e(&mut s, Opcode::OP_TOALTSTACK(OP_TOALTSTACK));
        s.push(k(KEY_K)); s.push(sread());
        s.push(k(KEY_D)); s.push(sread());
        e(&mut s, Opcode::OP_TRUE(OP_TRUE)); e(&mut s, Opcode::OP_ADD(OP_ADD)); e(&mut s, Opcode::OP_VERIFY(OP_VERIFY));
        e(&mut s, Opcode::OP_EQUAL(OP_EQUAL)); e(&mut s, Opcode::OP_VERIFY(OP_VERIFY));
        s.push(k(KEY_B)); s.push(sread());
        s.push(k(KEY_TOTAL)); s.push(sread());
        e(&mut s, Opcode::OP_SUB(OP_SUB)); e(&mut s, Opcode::OP_VERIFY(OP_VERIFY)); // [rt]
        // house = rt * ODDS_DENOM  (win region rt is 1/(ODDS_DENOM+1) of space)
        e(&mut s, Opcode::OP_DUP(OP_DUP)); // [rt, rt]
        s.push(push(le_bytes(ODDS_DENOM))); e(&mut s, Opcode::OP_MUL(OP_MUL)); e(&mut s, Opcode::OP_VERIFY(OP_VERIFY)); // [rt, rt*475]
        e(&mut s, Opcode::OP_ADD(OP_ADD)); e(&mut s, Opcode::OP_VERIFY(OP_VERIFY)); // [space = rt*476]
        s.push(k(KEY_SEED)); s.push(sread());
        e(&mut s, Opcode::OP_DIV(OP_DIV)); e(&mut s, Opcode::OP_VERIFY(OP_VERIFY)); e(&mut s, Opcode::OP_DROP(OP_DROP)); // [r]
        s.push(k(KEY_B)); s.push(sread()); e(&mut s, Opcode::OP_ADD(OP_ADD)); e(&mut s, Opcode::OP_VERIFY(OP_VERIFY)); // [rg]
        e(&mut s, Opcode::OP_DUP(OP_DUP)); s.push(k(KEY_TOTAL)); s.push(sread());
        e(&mut s, Opcode::OP_GREATERTHANOREQUAL(OP_GREATERTHANOREQUAL)); // [rg, rollover]
        e(&mut s, Opcode::OP_IF(OP_IF));
        // ---- ROLLOVER ---- (no payout, no rake)
        e(&mut s, Opcode::OP_DROP(OP_DROP));
        for o in advance() { s.push(o); }
        e(&mut s, Opcode::OP_ELSE(OP_ELSE));
        // ---- WIN ---- [rg]
        e(&mut s, Opcode::OP_FROMALTSTACK(OP_FROMALTSTACK));
        e(&mut s, Opcode::OP_FALSE(OP_FALSE)); e(&mut s, Opcode::OP_ADD(OP_ADD)); e(&mut s, Opcode::OP_VERIFY(OP_VERIFY));
        e(&mut s, Opcode::OP_DUP(OP_DUP)); e(&mut s, Opcode::OP_TOALTSTACK(OP_TOALTSTACK));
        e(&mut s, Opcode::OP_DUP(OP_DUP));
        s.push(k(KEY_C)); e(&mut s, Opcode::OP_SWAP(OP_SWAP)); e(&mut s, Opcode::OP_CAT(OP_CAT)); s.push(sread());
        e(&mut s, Opcode::OP_SWAP(OP_SWAP));
        e(&mut s, Opcode::OP_DUP(OP_DUP)); e(&mut s, Opcode::OP_FALSE(OP_FALSE)); e(&mut s, Opcode::OP_EQUAL(OP_EQUAL));
        e(&mut s, Opcode::OP_IF(OP_IF));
        e(&mut s, Opcode::OP_DROP(OP_DROP)); e(&mut s, Opcode::OP_FALSE(OP_FALSE));
        e(&mut s, Opcode::OP_ELSE(OP_ELSE));
        e(&mut s, Opcode::OP_TRUE(OP_TRUE)); e(&mut s, Opcode::OP_SWAP(OP_SWAP)); e(&mut s, Opcode::OP_SUB(OP_SUB)); e(&mut s, Opcode::OP_VERIFY(OP_VERIFY));
        s.push(k(KEY_C)); e(&mut s, Opcode::OP_SWAP(OP_SWAP)); e(&mut s, Opcode::OP_CAT(OP_CAT)); s.push(sread());
        e(&mut s, Opcode::OP_ENDIF(OP_ENDIF));
        e(&mut s, Opcode::OP_SWAP(OP_SWAP));
        e(&mut s, Opcode::OP_WITHIN(OP_WITHIN)); e(&mut s, Opcode::OP_VERIFY(OP_VERIFY)); // [] (lower<=rg<upper)
        // ---- 1% operator rake (wins only) ----
        // rake = floor(balance / 100)
        s.push(push(vec![100u8]));              // [100]
        e(&mut s, Opcode::OP_SELF_BALANCE(OP_SELF_BALANCE)); // [100, balance]
        e(&mut s, Opcode::OP_DIV(OP_DIV)); e(&mut s, Opcode::OP_VERIFY(OP_VERIFY)); // [remainder, quotient]
        e(&mut s, Opcode::OP_SWAP(OP_SWAP)); e(&mut s, Opcode::OP_DROP(OP_DROP)); // [rake]
        // if rake != 0 -> transfer to operator account, else drop
        e(&mut s, Opcode::OP_DUP(OP_DUP)); e(&mut s, Opcode::OP_FALSE(OP_FALSE)); e(&mut s, Opcode::OP_EQUAL(OP_EQUAL)); // [rake, rake==0]
        e(&mut s, Opcode::OP_IF(OP_IF));
        e(&mut s, Opcode::OP_DROP(OP_DROP)); // []
        e(&mut s, Opcode::OP_ELSE(OP_ELSE));
        s.push(push(operator_key()));           // [rake, operator]
        e(&mut s, Opcode::OP_FALSE(OP_FALSE));   // [rake, operator, account]
        e(&mut s, Opcode::OP_TRANSFER(OP_TRANSFER)); // []
        e(&mut s, Opcode::OP_ENDIF(OP_ENDIF));
        // ---- pay the winner the remaining treasury ----
        e(&mut s, Opcode::OP_FROMALTSTACK(OP_FROMALTSTACK)); // [idxn]
        s.push(k(KEY_P)); e(&mut s, Opcode::OP_SWAP(OP_SWAP)); e(&mut s, Opcode::OP_CAT(OP_CAT)); s.push(sread()); // [winner]
        e(&mut s, Opcode::OP_SELF_BALANCE(OP_SELF_BALANCE)); // [winner, balance-rake]
        e(&mut s, Opcode::OP_SWAP(OP_SWAP)); e(&mut s, Opcode::OP_FALSE(OP_FALSE)); // [balance, winner, account]
        e(&mut s, Opcode::OP_TRANSFER(OP_TRANSFER)); // []
        for o in advance() { s.push(o); }
        s.push(k(KEY_D)); s.push(sread()); s.push(k(KEY_W)); s.push(swrite()); // w = d
        e(&mut s, Opcode::OP_ENDIF(OP_ENDIF));
        e(&mut s, Opcode::OP_RETURNALL(OP_RETURNALL));
        s
    }

    fn lottery_v3_program() -> Program {
        let enter = ProgramMethod::new(
            "enter".to_string(), MethodType::Callable,
            vec![CalldataElementType::Payable], enter_script(),
        ).expect("enter");
        let close = ProgramMethod::new(
            "close".to_string(), MethodType::Callable, vec![], close_script(),
        ).expect("close");
        let settle = ProgramMethod::new(
            "settle".to_string(), MethodType::Callable,
            vec![CalldataElementType::U32], settle_script(),
        ).expect("settle");
        Executable::new("perpetual jackpot v3".to_string(), None, vec![enter, close, settle])
            .expect("program")
    }

    fn le_uint(b: &[u8]) -> u64 {
        let mut x = 0u64;
        for (i, &c) in b.iter().take(8).enumerate() { x |= (c as u64) << (8 * i); }
        x
    }

    #[test]
    fn print_v3_bytes() {
        use cube::executive::executable::compiler::compiler::ProgramCompiler;
        let program = lottery_v3_program();
        let bytes = program.compile().expect("compile");
        let rt = { let mut s = bytes.clone().into_iter(); Program::decompile(&mut s).expect("decompile") };
        assert_eq!(rt, program, "round-trip");
        println!("V3_BYTES=0x{}", hex::encode(&bytes));
        println!("V3_CONTRACT_ID=0x{}", hex::encode(program.contract_id()));
    }

    async fn setup() -> (REGISTERY, COIN_MANAGER, STATE_MANAGER, [u8; 32], [[u8; 32]; 5], [u8; 32], u64) {
        let chain = Chain::Testbed;
        erase_registery(chain);
        let registery: REGISTERY = Registery::new(chain).expect("reg");
        erase_coin_manager(chain);
        let coin_manager: COIN_MANAGER = CoinManager::new(chain).expect("coin");
        erase_state_manager(chain);
        let state_manager: STATE_MANAGER = StateManager::new(chain).expect("state");
        let program = lottery_v3_program();
        let cid = program.contract_id();
        let ts = 1_800_000_000u64;
        let players: [[u8; 32]; 5] = [[0x11; 32], [0x22; 32], [0x33; 32], [0x44; 32], [0x55; 32]];
        let operator: [u8; 32] = operator_key().try_into().unwrap();
        {
            let mut r = registery.lock().await;
            r.register_contract(cid, ts, program.clone()).expect("rc");
            for p in players.iter() { r.register_account(*p, ts, None, None, None, None).expect("ra"); }
            r.register_account(operator, ts, None, None, None, None).expect("rao");
            r.apply_changes().expect("rap");
        }
        {
            let mut c = coin_manager.lock().await;
            c.register_contract(cid, 0).expect("crc");
            for p in players.iter() { c.register_account(*p, 1_000_000).expect("cra"); }
            c.register_account(operator, 0).expect("crao");
            c.apply_changes().expect("cap");
        }
        {
            let mut s = state_manager.lock().await;
            s.register_contract(cid).expect("src");
            s.apply_changes().expect("sap");
        }
        (registery, coin_manager, state_manager, cid, players, operator, ts)
    }

    async fn enter(reg: &REGISTERY, cm: &COIN_MANAGER, sm: &STATE_MANAGER, cid: [u8;32], p: [u8;32], amount: u64, ts: u64) {
        let args = vec![StackItem::from_stack_uint(StackUint::from(amount))];
        execute(false, Caller::Account(p), cid, 0, args, ts, [0xaa; 32], 1_000_000, 0, 0, 0, sm, cm, reg)
            .await.unwrap_or_else(|e| panic!("enter failed: {:?}", e));
        cm.lock().await.apply_changes().expect("cap");
        sm.lock().await.apply_changes().expect("sap");
    }

    #[tokio::test]
    async fn settle_rakes_one_percent_to_operator() {
        let (reg, cm, sm, cid, players, operator, ts) = setup().await;
        let amounts: [u64; 5] = [1000, 2000, 3000, 4000, 5000]; // cumsums 1000,3000,6000,10000,15000
        for (i, p) in players.iter().enumerate() {
            enter(&reg, &cm, &sm, cid, *p, amounts[i], ts + i as u64).await;
        }
        // total=15000, house=rt*475, space=rt*476=7_140_000. seed 5000 -> r=5000,
        // which is in the win region [0,15000) -> band [3000,6000) -> idx 2 (0x33).
        let mut seed = [0u8; 32]; seed[0] = 0x88; seed[1] = 0x13; // 0x1388 = 5000 LE
        execute(false, Caller::Account(players[0]), cid, 1, vec![], ts + DURATION as u64 + 1, seed, 1_000_000, 0, 0, 0, &sm, &cm, &reg)
            .await.unwrap_or_else(|e| panic!("close failed: {:?}", e));
        cm.lock().await.apply_changes().unwrap(); sm.lock().await.apply_changes().unwrap();

        let win_before = cm.lock().await.get_account_balance(players[2]).unwrap_or(0);
        let op_before = cm.lock().await.get_account_balance(operator).unwrap_or(0);
        let args = vec![StackItem::from_stack_uint(StackUint::from(2u64))];
        execute(false, Caller::Account(players[0]), cid, 2, args, ts + DURATION as u64 + 2, seed, 1_000_000, 0, 0, 0, &sm, &cm, &reg)
            .await.unwrap_or_else(|e| panic!("settle failed: {:?}", e));
        cm.lock().await.apply_changes().unwrap(); sm.lock().await.apply_changes().unwrap();

        let win_gain = cm.lock().await.get_account_balance(players[2]).unwrap_or(0) - win_before;
        let op_gain = cm.lock().await.get_account_balance(operator).unwrap_or(0) - op_before;
        let treasury = cm.lock().await.get_contract_balance(cid).unwrap_or(0);
        println!("winner gained={} operator gained={} treasury={}", win_gain, op_gain, treasury);
        assert_eq!(op_gain, 150, "operator takes 1% of the 15000 pot");
        assert_eq!(win_gain, 14850, "winner takes the remaining 99%");
        assert_eq!(treasury, 0, "pot fully distributed");
    }

    // Run one full round (enter all players, close, settle) at the given open
    // time with the given seed + winner idx arg.
    async fn round(reg: &REGISTERY, cm: &COIN_MANAGER, sm: &STATE_MANAGER, cid: [u8; 32], players: &[[u8; 32]; 5], amounts: &[u64; 5], open: u64, seed: [u8; 32], idx: u64) -> u64 {
        for (i, p) in players.iter().enumerate() { enter(reg, cm, sm, cid, *p, amounts[i], open + i as u64).await; }
        let close = open + DURATION as u64 + 1;
        execute(false, Caller::Account(players[0]), cid, 1, vec![], close, seed, 1_000_000, 0, 0, 0, sm, cm, reg)
            .await.unwrap_or_else(|e| panic!("close failed: {:?}", e));
        cm.lock().await.apply_changes().unwrap(); sm.lock().await.apply_changes().unwrap();
        let settle = close + 1;
        execute(false, Caller::Account(players[0]), cid, 2, vec![StackItem::from_stack_uint(StackUint::from(idx))], settle, seed, 1_000_000, 0, 0, 0, sm, cm, reg)
            .await.unwrap_or_else(|e| panic!("settle failed: {:?}", e));
        cm.lock().await.apply_changes().unwrap(); sm.lock().await.apply_changes().unwrap();
        settle
    }

    #[tokio::test]
    async fn second_round_rolls_over_at_one_percent() {
        let (reg, cm, sm, cid, players, operator, ts) = setup().await;
        let amounts: [u64; 5] = [1000, 2000, 3000, 4000, 5000];
        // Round 1 is guaranteed (no prior win) -> pays out, stamps last-win time.
        let mut win = [0u8; 32]; win[0] = 0x88; win[1] = 0x13; // r=5000 -> idx 2
        let settle1 = round(&reg, &cm, &sm, cid, &players, &amounts, ts, win, 2).await;
        // Round 2 happens <1 day later -> NOT guaranteed -> house = rt*99,
        // space = rt*100. rt=15000, B=15000, total=30000. r must be >= 15000 to
        // roll over (rg = r + B >= total). seed 20000 -> r=20000 -> rollover.
        let mut roll = [0u8; 32]; roll[0] = 0x20; roll[1] = 0x4e; // 0x4e20 = 20000
        let open2 = settle1 + 10;
        for (i, p) in players.iter().enumerate() { enter(&reg, &cm, &sm, cid, *p, amounts[i], open2 + i as u64).await; }
        let close2 = open2 + DURATION as u64 + 1;
        execute(false, Caller::Account(players[0]), cid, 1, vec![], close2, roll, 1_000_000, 0, 0, 0, &sm, &cm, &reg)
            .await.unwrap_or_else(|e| panic!("close2 failed: {:?}", e));
        cm.lock().await.apply_changes().unwrap(); sm.lock().await.apply_changes().unwrap();
        let op_before = cm.lock().await.get_account_balance(operator).unwrap_or(0);
        execute(false, Caller::Account(players[0]), cid, 2, vec![StackItem::from_stack_uint(StackUint::from(0u64))], close2 + 1, roll, 1_000_000, 0, 0, 0, &sm, &cm, &reg)
            .await.unwrap_or_else(|e| panic!("settle2 failed: {:?}", e));
        cm.lock().await.apply_changes().unwrap(); sm.lock().await.apply_changes().unwrap();
        let op_gain = cm.lock().await.get_account_balance(operator).unwrap_or(0) - op_before;
        let treasury = cm.lock().await.get_contract_balance(cid).unwrap_or(0);
        println!("1% regime rollover: operator gained={} treasury={}", op_gain, treasury);
        assert_eq!(op_gain, 0, "no rake on rollover");
        assert_eq!(treasury, 15000, "round-2 pot rolls over into the jackpot");
    }

    #[tokio::test]
    async fn timer_starts_at_first_entry_not_round_open() {
        let (reg, cm, sm, cid, players, _op, ts) = setup().await;
        let amounts: [u64; 5] = [1000, 2000, 3000, 4000, 5000];
        let mut win = [0u8; 32]; win[0] = 0x88; win[1] = 0x13;
        let settle1 = round(&reg, &cm, &sm, cid, &players, &amounts, ts, win, 2).await;
        // Round 2 opened at advance(settle1) with t=settle1, but nobody joins for
        // a long while. The first joiner should reset the 2-minute timer to now.
        let join = settle1 + 5000;
        enter(&reg, &cm, &sm, cid, players[0], 1000, join).await;
        let t = le_uint(&sm.lock().await.get_state_value(cid, &vec![KEY_TIME]).unwrap_or_default());
        assert_eq!(t, join, "timer resets to the first entry's timestamp");
        // Closing before join + DURATION must fail (window not elapsed yet).
        let early = execute(false, Caller::Account(players[0]), cid, 1, vec![], join + 60, win, 1_000_000, 0, 0, 0, &sm, &cm, &reg).await;
        assert!(early.is_err(), "cannot close until 2 minutes after the first entry");
        // Closing after the window succeeds.
        execute(false, Caller::Account(players[0]), cid, 1, vec![], join + DURATION as u64 + 1, win, 1_000_000, 0, 0, 0, &sm, &cm, &reg)
            .await.unwrap_or_else(|e| panic!("close after window failed: {:?}", e));
    }

    #[tokio::test]
    async fn second_round_win_in_one_percent_regime_pays_rake() {
        let (reg, cm, sm, cid, players, operator, ts) = setup().await;
        let amounts: [u64; 5] = [1000, 2000, 3000, 4000, 5000];
        let mut win = [0u8; 32]; win[0] = 0x88; win[1] = 0x13; // round 1: r=5000 -> idx 2
        let settle1 = round(&reg, &cm, &sm, cid, &players, &amounts, ts, win, 2).await;
        // Round 2 (<1 day) in the 1% regime, but with a seed that lands in the win
        // region. rt=15000, B=15000, total=30000, space=1_500_000. seed 5000 ->
        // r=5000, rg=20000 in global [18000,21000) -> idx 7 (player 0x33).
        let open2 = settle1 + 10;
        for (i, p) in players.iter().enumerate() { enter(&reg, &cm, &sm, cid, *p, amounts[i], open2 + i as u64).await; }
        let close2 = open2 + DURATION as u64 + 1;
        execute(false, Caller::Account(players[0]), cid, 1, vec![], close2, win, 1_000_000, 0, 0, 0, &sm, &cm, &reg)
            .await.unwrap_or_else(|e| panic!("close2 failed: {:?}", e));
        cm.lock().await.apply_changes().unwrap(); sm.lock().await.apply_changes().unwrap();
        let win_before = cm.lock().await.get_account_balance(players[2]).unwrap_or(0);
        let op_before = cm.lock().await.get_account_balance(operator).unwrap_or(0);
        execute(false, Caller::Account(players[0]), cid, 2, vec![StackItem::from_stack_uint(StackUint::from(7u64))], close2 + 1, win, 1_000_000, 0, 0, 0, &sm, &cm, &reg)
            .await.unwrap_or_else(|e| panic!("settle2 failed: {:?}", e));
        cm.lock().await.apply_changes().unwrap(); sm.lock().await.apply_changes().unwrap();
        let win_gain = cm.lock().await.get_account_balance(players[2]).unwrap_or(0) - win_before;
        let op_gain = cm.lock().await.get_account_balance(operator).unwrap_or(0) - op_before;
        let treasury = cm.lock().await.get_contract_balance(cid).unwrap_or(0);
        println!("1% regime win: winner gained={} operator gained={} treasury={}", win_gain, op_gain, treasury);
        assert_eq!(op_gain, 150, "operator takes 1% of the 15000 pot");
        assert_eq!(win_gain, 14850, "winner takes the remaining 99%");
        assert_eq!(treasury, 0, "pot fully distributed");
    }
}
