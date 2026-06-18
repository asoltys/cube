// Lottery v5 — the NON-CUSTODIAL JACKPOT with an accumulating prize.
//
// Mechanics (vs v4's 20%-win / 80%-rollover):
//   * EVERY round has a winner. The winner is drawn proportionally to stake from
//     the round pot (seed mod rt), so there's no rollover — the round always pays.
//   * Of the round pot rt: RAKE_PCT% (1%) -> operator, JACKPOT_PCT% (4%) is
//     RETAINED in the contract balance (the accumulating jackpot), and the rest
//     (95%) -> the round winner's native (exitable) account.
//   * Independently, the round winner ALSO wins the WHOLE accumulated jackpot with
//     probability STRIKE_NUM/STRIKE_DENOM = 0.21%. The strike draw is a second,
//     independent digit of the same block-hash seed: q = seed div rt, strike if
//     (q mod STRIKE_DENOM) < STRIKE_NUM. On a strike the entire contract balance
//     (the accumulator) is transferred to the winner.
//
// The accumulating jackpot is the contract balance BETWEEN rounds — unattributed
// to any player (it belongs to whoever strikes it). During a live round the
// balance = jackpot + Σ stake-claims; only the stake-claims are shadow allocations
// (exitable VTXOs). Stakes are shadow_up'd on enter and shadow_down_all'd before
// payout so the balance can move without violating (balance >= Σ allocs).

#[cfg(test)]
mod lottery_v5 {
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
    use cube::executive::opcode::opcodes::shadowing::op_shadow_up::OP_SHADOW_UP;
    use cube::executive::opcode::opcodes::shadowing::op_shadow_allocs_sum::OP_SHADOW_ALLOCS_SUM;
    use cube::executive::opcode::opcodes::shadowing::op_shadow_down_all::OP_SHADOW_DOWN_ALL;
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

    const KEY_TOTAL: u8 = 0x54;
    const KEY_B: u8 = 0x42;
    const KEY_G: u8 = 0x67;
    const KEY_RS: u8 = 0x72;
    const KEY_C: u8 = 0x63;
    const KEY_P: u8 = 0x70;
    const KEY_TIME: u8 = 0x74;
    const KEY_K: u8 = 0x6b;
    const KEY_SEED: u8 = 0x73;
    const KEY_D: u8 = 0x64;
    const KEY_W: u8 = 0x77;
    // v5 settle scratch keys (uppercase -> distinct from the lowercase state keys;
    // each > 0x10 so a single-byte data push is minimal/accepted by the compiler).
    const KEY_RT: u8 = 0x52; // round pot rt = TOTAL - B
    const KEY_RK: u8 = 0x51; // rake (RAKE_PCT% of rt)
    const KEY_PO: u8 = 0x50; // round payout to the winner
    const KEY_WK: u8 = 0x4f; // winner account key (32 bytes)
    const DURATION: u8 = 120;
    const RAKE_PCT: u64 = 1;
    const JACKPOT_PCT: u64 = 4;
    const STRIKE_NUM: u64 = 21;     // 0.21% jackpot-strike chance ...
    const STRIKE_DENOM: u64 = 10000; // ... = STRIKE_NUM / STRIKE_DENOM

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
    fn le_bytes(mut n: u64) -> Vec<u8> {
        let mut out = Vec::new();
        while n > 0 { out.push((n & 0xff) as u8); n >>= 8; }
        if out.is_empty() { out.push(0); }
        out
    }
    // Minimal numeric push: 0->OP_FALSE, 1..=16->OP_N, else a data push. Required
    // because small ints (1..16) must use their OP_N opcode (a data push is
    // non-minimal and rejected at script validation).
    fn pushnum(n: u64) -> Opcode {
        use cube::executive::opcode::opcodes::push::{
            op_false::OP_FALSE, op_true::OP_TRUE,
            op_2::OP_2, op_3::OP_3, op_4::OP_4, op_5::OP_5, op_6::OP_6, op_7::OP_7, op_8::OP_8,
            op_9::OP_9, op_10::OP_10, op_11::OP_11, op_12::OP_12, op_13::OP_13, op_14::OP_14,
            op_15::OP_15, op_16::OP_16,
        };
        match n {
            0 => Opcode::OP_FALSE(OP_FALSE),
            1 => Opcode::OP_TRUE(OP_TRUE),
            2 => Opcode::OP_2(OP_2), 3 => Opcode::OP_3(OP_3), 4 => Opcode::OP_4(OP_4),
            5 => Opcode::OP_5(OP_5), 6 => Opcode::OP_6(OP_6), 7 => Opcode::OP_7(OP_7),
            8 => Opcode::OP_8(OP_8), 9 => Opcode::OP_9(OP_9), 10 => Opcode::OP_10(OP_10),
            11 => Opcode::OP_11(OP_11), 12 => Opcode::OP_12(OP_12), 13 => Opcode::OP_13(OP_13),
            14 => Opcode::OP_14(OP_14), 15 => Opcode::OP_15(OP_15), 16 => Opcode::OP_16(OP_16),
            _ => push(le_bytes(n)),
        }
    }

    // enter(payable E): NON-CUSTODIAL attribution — shadow_up the caller's claim
    // by E (caller must already be allocated in the contract shadow space), then
    // the v3 entry bookkeeping for the draw.
    fn enter_script() -> Vec<Opcode> {
        let mut v: Vec<Opcode> = vec![
            // --- shadow-attribute the stake: shadow_up(amount=E, account=caller) ---
            Opcode::OP_DUP(OP_DUP),                                                   // [E, E]
            Opcode::OP_CALLER(cube::executive::opcode::opcodes::callinfo::op_caller::OP_CALLER), // [E, E, caller, kind]
            Opcode::OP_DROP(OP_DROP),                                                 // [E, E, caller]
            Opcode::OP_SHADOW_UP(OP_SHADOW_UP),                                       // [E]
        ];
        v.extend(vec![
            // First entry of the round starts the 2-minute timer.
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
        ]);
        v
    }

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
    use cube::executive::opcode::opcodes::arithmetic::op_lessthan::OP_LESSTHAN;
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

    // settle(winner_idx): EVERY round has a winner. Verify the asserted entrant
    // band contains the seed draw, pay 95% to the winner / 1% rake / retain 4% as
    // the jackpot, then (0.21%) maybe pay the winner the whole accumulated jackpot.
    fn settle_script() -> Vec<Opcode> {
        let mut s: Vec<Opcode> = Vec::new();
        let e = |v: &mut Vec<Opcode>, o: Opcode| v.push(o);
        e(&mut s, Opcode::OP_TOALTSTACK(OP_TOALTSTACK)); // alt=[idx]
        // verify the round is closed: K == D + 1
        s.push(k(KEY_K)); s.push(sread());
        s.push(k(KEY_D)); s.push(sread());
        e(&mut s, Opcode::OP_TRUE(OP_TRUE)); e(&mut s, Opcode::OP_ADD(OP_ADD)); e(&mut s, Opcode::OP_VERIFY(OP_VERIFY));
        e(&mut s, Opcode::OP_EQUAL(OP_EQUAL)); e(&mut s, Opcode::OP_VERIFY(OP_VERIFY));
        // rt = TOTAL - B  -> KEY_RT
        s.push(k(KEY_B)); s.push(sread());
        s.push(k(KEY_TOTAL)); s.push(sread());
        e(&mut s, Opcode::OP_SUB(OP_SUB)); e(&mut s, Opcode::OP_VERIFY(OP_VERIFY)); // [rt]
        s.push(k(KEY_RT)); s.push(swrite()); // []
        // winner draw: r = seed mod rt ; rg = r + B  (always lands in [B, TOTAL))
        s.push(k(KEY_RT)); s.push(sread());      // [rt]
        s.push(k(KEY_SEED)); s.push(sread());    // [rt, seed]
        e(&mut s, Opcode::OP_DIV(OP_DIV)); e(&mut s, Opcode::OP_VERIFY(OP_VERIFY)); e(&mut s, Opcode::OP_DROP(OP_DROP)); // [r] (keep modulo)
        s.push(k(KEY_B)); s.push(sread()); e(&mut s, Opcode::OP_ADD(OP_ADD)); e(&mut s, Opcode::OP_VERIFY(OP_VERIFY)); // [rg]
        // ---- verify the asserted winner_idx band [C[idx-1], C[idx]) contains rg ----
        e(&mut s, Opcode::OP_FROMALTSTACK(OP_FROMALTSTACK)); // [rg, idx]
        e(&mut s, Opcode::OP_FALSE(OP_FALSE)); e(&mut s, Opcode::OP_ADD(OP_ADD)); e(&mut s, Opcode::OP_VERIFY(OP_VERIFY)); // coerce idx -> uint
        e(&mut s, Opcode::OP_DUP(OP_DUP)); e(&mut s, Opcode::OP_TOALTSTACK(OP_TOALTSTACK)); // re-stash idx; [rg, idx]
        e(&mut s, Opcode::OP_DUP(OP_DUP)); // [rg, idx, idx]
        s.push(k(KEY_C)); e(&mut s, Opcode::OP_SWAP(OP_SWAP)); e(&mut s, Opcode::OP_CAT(OP_CAT)); s.push(sread()); // [rg, idx, upper]
        e(&mut s, Opcode::OP_SWAP(OP_SWAP)); // [rg, upper, idx]
        e(&mut s, Opcode::OP_DUP(OP_DUP)); e(&mut s, Opcode::OP_FALSE(OP_FALSE)); e(&mut s, Opcode::OP_EQUAL(OP_EQUAL));
        e(&mut s, Opcode::OP_IF(OP_IF)); // idx == 0 -> lower = 0
        e(&mut s, Opcode::OP_DROP(OP_DROP)); e(&mut s, Opcode::OP_FALSE(OP_FALSE));
        e(&mut s, Opcode::OP_ELSE(OP_ELSE));
        e(&mut s, Opcode::OP_TRUE(OP_TRUE)); e(&mut s, Opcode::OP_SWAP(OP_SWAP)); e(&mut s, Opcode::OP_SUB(OP_SUB)); e(&mut s, Opcode::OP_VERIFY(OP_VERIFY));
        s.push(k(KEY_C)); e(&mut s, Opcode::OP_SWAP(OP_SWAP)); e(&mut s, Opcode::OP_CAT(OP_CAT)); s.push(sread()); // lower = C[idx-1]
        e(&mut s, Opcode::OP_ENDIF(OP_ENDIF));
        e(&mut s, Opcode::OP_SWAP(OP_SWAP)); // [rg, lower, upper]
        e(&mut s, Opcode::OP_WITHIN(OP_WITHIN)); e(&mut s, Opcode::OP_VERIFY(OP_VERIFY)); // [] winner verified; alt=[idx]
        // winner_key = read(KEY_P ++ idx) -> KEY_WK
        e(&mut s, Opcode::OP_FROMALTSTACK(OP_FROMALTSTACK)); // [idx]
        s.push(k(KEY_P)); e(&mut s, Opcode::OP_SWAP(OP_SWAP)); e(&mut s, Opcode::OP_CAT(OP_CAT)); s.push(sread()); // [winner_key]
        s.push(k(KEY_WK)); s.push(swrite()); // []
        // ---- zero every stake-claim before moving the balance ----
        e(&mut s, Opcode::OP_SHADOW_ALLOCS_SUM(OP_SHADOW_ALLOCS_SUM));
        e(&mut s, Opcode::OP_SHADOW_DOWN_ALL(OP_SHADOW_DOWN_ALL)); // []
        // rake = rt / 100  -> KEY_RK
        s.push(push(vec![100u8])); s.push(k(KEY_RT)); s.push(sread()); // [100, rt]
        e(&mut s, Opcode::OP_DIV(OP_DIV)); e(&mut s, Opcode::OP_VERIFY(OP_VERIFY)); e(&mut s, Opcode::OP_SWAP(OP_SWAP)); e(&mut s, Opcode::OP_DROP(OP_DROP)); // [rake] (quotient)
        s.push(k(KEY_RK)); s.push(swrite()); // []
        // round_payout = rt - rake - jackpot_cut, where jackpot_cut = rt*JACKPOT_PCT/100  -> KEY_PO
        s.push(k(KEY_RT)); s.push(sread()); // [rt]
        s.push(k(KEY_RK)); s.push(sread()); // [rt, rake]
        s.push(push(vec![100u8])); s.push(pushnum(JACKPOT_PCT)); s.push(k(KEY_RT)); s.push(sread()); // [rt, rake, 100, PCT, rt]
        e(&mut s, Opcode::OP_MUL(OP_MUL)); e(&mut s, Opcode::OP_VERIFY(OP_VERIFY)); // [rt, rake, 100, rt*PCT]
        e(&mut s, Opcode::OP_DIV(OP_DIV)); e(&mut s, Opcode::OP_VERIFY(OP_VERIFY)); e(&mut s, Opcode::OP_SWAP(OP_SWAP)); e(&mut s, Opcode::OP_DROP(OP_DROP)); // [rt, rake, jc]
        e(&mut s, Opcode::OP_ADD(OP_ADD)); e(&mut s, Opcode::OP_VERIFY(OP_VERIFY)); // [rt, rake+jc]
        e(&mut s, Opcode::OP_SWAP(OP_SWAP)); e(&mut s, Opcode::OP_SUB(OP_SUB)); e(&mut s, Opcode::OP_VERIFY(OP_VERIFY)); // [round_payout = rt-(rake+jc)]
        s.push(k(KEY_PO)); s.push(swrite()); // []
        // transfer rake -> operator (skip if 0)
        s.push(k(KEY_RK)); s.push(sread());
        e(&mut s, Opcode::OP_DUP(OP_DUP)); e(&mut s, Opcode::OP_FALSE(OP_FALSE)); e(&mut s, Opcode::OP_EQUAL(OP_EQUAL));
        e(&mut s, Opcode::OP_IF(OP_IF)); e(&mut s, Opcode::OP_DROP(OP_DROP));
        e(&mut s, Opcode::OP_ELSE(OP_ELSE));
        s.push(push(operator_key())); e(&mut s, Opcode::OP_FALSE(OP_FALSE)); e(&mut s, Opcode::OP_TRANSFER(OP_TRANSFER));
        e(&mut s, Opcode::OP_ENDIF(OP_ENDIF)); // []
        // transfer round_payout -> winner (skip if 0)
        s.push(k(KEY_PO)); s.push(sread());
        e(&mut s, Opcode::OP_DUP(OP_DUP)); e(&mut s, Opcode::OP_FALSE(OP_FALSE)); e(&mut s, Opcode::OP_EQUAL(OP_EQUAL));
        e(&mut s, Opcode::OP_IF(OP_IF)); e(&mut s, Opcode::OP_DROP(OP_DROP));
        e(&mut s, Opcode::OP_ELSE(OP_ELSE));
        s.push(k(KEY_WK)); s.push(sread()); e(&mut s, Opcode::OP_FALSE(OP_FALSE)); e(&mut s, Opcode::OP_TRANSFER(OP_TRANSFER));
        e(&mut s, Opcode::OP_ENDIF(OP_ENDIF)); // []  (remaining balance == accumulated jackpot)
        // ---- jackpot strike: q = seed div rt ; strike if (q mod STRIKE_DENOM) < STRIKE_NUM ----
        s.push(k(KEY_RT)); s.push(sread()); s.push(k(KEY_SEED)); s.push(sread()); // [rt, seed]
        e(&mut s, Opcode::OP_DIV(OP_DIV)); e(&mut s, Opcode::OP_VERIFY(OP_VERIFY)); e(&mut s, Opcode::OP_SWAP(OP_SWAP)); e(&mut s, Opcode::OP_DROP(OP_DROP)); // [q] (quotient)
        s.push(push(le_bytes(STRIKE_DENOM))); e(&mut s, Opcode::OP_SWAP(OP_SWAP)); // [DENOM, q]
        e(&mut s, Opcode::OP_DIV(OP_DIV)); e(&mut s, Opcode::OP_VERIFY(OP_VERIFY)); e(&mut s, Opcode::OP_DROP(OP_DROP)); // [qm = q mod DENOM]
        s.push(push(le_bytes(STRIKE_NUM))); // [qm, NUM]
        e(&mut s, Opcode::OP_LESSTHAN(OP_LESSTHAN)); // [strike]
        e(&mut s, Opcode::OP_IF(OP_IF));
        // pay the whole remaining balance (the accumulated jackpot) to the winner (skip if 0)
        e(&mut s, Opcode::OP_SELF_BALANCE(OP_SELF_BALANCE));
        e(&mut s, Opcode::OP_DUP(OP_DUP)); e(&mut s, Opcode::OP_FALSE(OP_FALSE)); e(&mut s, Opcode::OP_EQUAL(OP_EQUAL));
        e(&mut s, Opcode::OP_IF(OP_IF)); e(&mut s, Opcode::OP_DROP(OP_DROP));
        e(&mut s, Opcode::OP_ELSE(OP_ELSE));
        s.push(k(KEY_WK)); s.push(sread()); e(&mut s, Opcode::OP_FALSE(OP_FALSE)); e(&mut s, Opcode::OP_TRANSFER(OP_TRANSFER));
        e(&mut s, Opcode::OP_ENDIF(OP_ENDIF));
        e(&mut s, Opcode::OP_ENDIF(OP_ENDIF)); // end strike
        // advance to the next round + record the winning round number
        for o in advance() { s.push(o); }
        s.push(k(KEY_D)); s.push(sread()); s.push(k(KEY_W)); s.push(swrite());
        e(&mut s, Opcode::OP_RETURNALL(OP_RETURNALL));
        s
    }

    fn lottery_v5_program() -> Program {
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
        Executable::new("perpetual jackpot v5 (accumulating)".to_string(), None, vec![enter, close, settle])
            .expect("program")
    }

    #[test]
    fn print_v5_bytes() {
        use cube::executive::executable::compiler::compiler::ProgramCompiler;
        let program = lottery_v5_program();
        let bytes = program.compile().expect("compile");
        let rt = { let mut s = bytes.clone().into_iter(); Program::decompile(&mut s).expect("decompile") };
        assert_eq!(rt, program, "round-trip");
        println!("V5_BYTES=0x{}", hex::encode(&bytes));
        println!("V5_CONTRACT_ID=0x{}", hex::encode(program.contract_id()));
    }

    async fn setup() -> (REGISTERY, COIN_MANAGER, STATE_MANAGER, [u8; 32], [[u8; 32]; 5], [u8; 32], u64) {
        let chain = Chain::Testbed;
        erase_registery(chain);
        let registery: REGISTERY = Registery::new(chain).expect("reg");
        erase_coin_manager(chain);
        let coin_manager: COIN_MANAGER = CoinManager::new(chain).expect("coin");
        erase_state_manager(chain);
        let state_manager: STATE_MANAGER = StateManager::new(chain).expect("state");
        let program = lottery_v5_program();
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
            // The arcade allocates each player + the operator in the contract
            // shadow space once (at faucet time). enter only shadow_ups.
            for p in players.iter() { c.contract_shadow_alloc_account(cid, *p).expect("alloc"); }
            c.contract_shadow_alloc_account(cid, operator).expect("alloc op");
            c.apply_changes().expect("cap2");
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

    fn seed_of(v: u64) -> [u8; 32] {
        let mut s = [0u8; 32];
        s[..8].copy_from_slice(&v.to_le_bytes());
        s
    }

    async fn close_and_settle(reg: &REGISTERY, cm: &COIN_MANAGER, sm: &STATE_MANAGER, cid: [u8;32], caller: [u8;32], winner_idx: u64, seed: [u8;32], ts: u64) {
        execute(false, Caller::Account(caller), cid, 1, vec![], ts + DURATION as u64 + 1, seed, 1_000_000, 0, 0, 0, sm, cm, reg)
            .await.unwrap_or_else(|e| panic!("close failed: {:?}", e));
        cm.lock().await.apply_changes().unwrap(); sm.lock().await.apply_changes().unwrap();
        let args = vec![StackItem::from_stack_uint(StackUint::from(winner_idx))];
        execute(false, Caller::Account(caller), cid, 2, args, ts + DURATION as u64 + 2, seed, 1_000_000, 0, 0, 0, sm, cm, reg)
            .await.unwrap_or_else(|e| panic!("settle failed: {:?}", e));
        cm.lock().await.apply_changes().unwrap(); sm.lock().await.apply_changes().unwrap();
    }

    #[tokio::test]
    async fn every_round_has_a_winner_with_95_4_1_split() {
        let (reg, cm, sm, cid, players, operator, ts) = setup().await;
        let amounts: [u64; 5] = [1000, 2000, 3000, 4000, 5000]; // pot rt = 15000
        for (i, p) in players.iter().enumerate() {
            enter(&reg, &cm, &sm, cid, *p, amounts[i], ts + i as u64).await;
        }
        // stakes are exitable shadow claims while the round is live; Σ == pot.
        {
            let c = cm.lock().await;
            assert_eq!(c.get_contract_balance(cid).unwrap(), 15000);
            let claimed: u64 = players.iter().map(|p| c.get_shadow_alloc_value_in_satoshis(cid, *p).unwrap_or(0)).sum();
            assert_eq!(claimed, 15000, "Σ exitable claims == pot");
        }
        // seed 1_505_000: r = 1505000 mod 15000 = 5000 -> rg 5000 in [3000,6000) -> idx 2;
        // q = 1505000 / 15000 = 100, qm = 100 >= 21 -> NO strike.
        let win_before = cm.lock().await.get_account_balance(players[2]).unwrap_or(0);
        let op_before = cm.lock().await.get_account_balance(operator).unwrap_or(0);
        close_and_settle(&reg, &cm, &sm, cid, players[0], 2, seed_of(1_505_000), ts).await;

        let c = cm.lock().await;
        // rake = 150 (1%), jackpot_cut = 600 (4%, RETAINED), round_payout = 14250 (95%).
        assert_eq!(c.get_account_balance(players[2]).unwrap_or(0) - win_before, 14250, "winner takes 95% of the round pot");
        assert_eq!(c.get_account_balance(operator).unwrap_or(0) - op_before, 150, "operator 1% rake");
        assert_eq!(c.get_contract_balance(cid).unwrap_or(0), 600, "4% retained as the accumulating jackpot");
        let leftover: u64 = players.iter().map(|p| c.get_shadow_alloc_value_in_satoshis(cid, *p).unwrap_or(0)).sum();
        assert_eq!(leftover, 0, "all stake-claims zeroed on settle (invariant preserved)");
        println!("v5: every round pays a winner 95% / operator 1% / jackpot 4% retained ({}); claims zeroed.", 600);
    }

    #[tokio::test]
    async fn jackpot_accumulates_then_strike_pays_it() {
        let (reg, cm, sm, cid, players, _operator, ts) = setup().await;
        let amounts: [u64; 5] = [1000, 2000, 3000, 4000, 5000]; // rt = 15000

        // ---- round 1: no strike -> 600 retained in the jackpot ----
        for (i, p) in players.iter().enumerate() { enter(&reg, &cm, &sm, cid, *p, amounts[i], ts + i as u64).await; }
        close_and_settle(&reg, &cm, &sm, cid, players[0], 2, seed_of(1_505_000), ts).await;
        assert_eq!(cm.lock().await.get_contract_balance(cid).unwrap_or(0), 600, "jackpot holds 4% after round 1");

        // ---- round 2: a STRIKE seed -> winner takes round pot AND the jackpot ----
        let ts2 = ts + 1000;
        for (i, p) in players.iter().enumerate() { enter(&reg, &cm, &sm, cid, *p, amounts[i], ts2 + i as u64).await; }
        // balance now = 600 (jackpot) + 15000 (round 2 stakes).
        assert_eq!(cm.lock().await.get_contract_balance(cid).unwrap_or(0), 15600);
        // round 2 entries are global indices 5..9: C = [16000,18000,21000,25000,30000], B=15000.
        // seed 5000: r = 5000 mod 15000 = 5000 -> rg = 20000 in [18000,21000) -> idx 7 (players[2]);
        // q = 5000 / 15000 = 0, qm = 0 < 21 -> STRIKE.
        let win_before = cm.lock().await.get_account_balance(players[2]).unwrap_or(0);
        close_and_settle(&reg, &cm, &sm, cid, players[0], 7, seed_of(5000), ts2).await;

        let c = cm.lock().await;
        // round 2: rake 150, jc 600, round_payout 14250; pre-strike balance = 600+15000-150-14250 = 1200
        // (= prior jackpot 600 + this round's 600). STRIKE pays that whole 1200 to the winner.
        assert_eq!(c.get_account_balance(players[2]).unwrap_or(0) - win_before, 14250 + 1200, "winner takes round pot + the whole accumulated jackpot");
        assert_eq!(c.get_contract_balance(cid).unwrap_or(0), 0, "jackpot emptied by the strike");
        let leftover: u64 = players.iter().map(|p| c.get_shadow_alloc_value_in_satoshis(cid, *p).unwrap_or(0)).sum();
        assert_eq!(leftover, 0, "claims zeroed");
        println!("v5: jackpot accumulated to 1200 then a 0.21% STRIKE paid it (plus the 14250 round pot) to the winner; jackpot reset to 0.");
    }
}
