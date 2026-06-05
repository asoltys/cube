use crate::executive::stack::{
    stack_error::StackError, stack_holder::StackHolder, stack_item::StackItem,
};
use serde::{Deserialize, Serialize};

/// Push the 32-byte hash anchoring this execution's batch to Bitcoin.
///
/// This exposes block-derived entropy to contracts (e.g. for fair lotteries).
/// The value is supplied by the engine at execution time and is the same for
/// every opcode within a single batch execution. Contracts that need
/// unpredictable randomness should draw against a *later* batch's hash than the
/// one in which entries were committed (see the lottery example), since the
/// sequencer/miner can influence the value of any single block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub struct OP_BLOCKHASH;

/// The number of ops for the `OP_BLOCKHASH` opcode.
pub const BLOCKHASH_OPS: u32 = 1;

impl OP_BLOCKHASH {
    pub fn execute(stack_holder: &mut StackHolder) -> Result<(), StackError> {
        // If this is not the active execution, return immediately.
        if !stack_holder.active_execution() {
            return Ok(());
        }

        // Get the block hash anchoring this execution.
        let block_hash = stack_holder.block_hash();

        // Push the 32-byte hash to the main stack.
        stack_holder.push(StackItem::new(block_hash.to_vec()))?;

        // Increment the ops counter.
        stack_holder.increment_ops(BLOCKHASH_OPS)?;

        Ok(())
    }

    /// Returns the bytecode for the `OP_BLOCKHASH` opcode (0xd3).
    pub fn bytecode() -> Vec<u8> {
        vec![0xd3]
    }
}
