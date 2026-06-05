use crate::executive::{
    opcode::ops::OP_SWAP_OPS,
    stack::{stack_error::StackError, stack_holder::StackHolder},
};
use serde::{Deserialize, Serialize};

/// The top two items on the stack are swapped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub struct OP_SWAP;

impl OP_SWAP {
    pub fn execute(stack_holder: &mut StackHolder) -> Result<(), StackError> {
        // If this is not the active execution, return immediately.
        if !stack_holder.active_execution() {
            return Ok(());
        }

        // Swap the top two items. Note: `push`/`pop` operate on the end of the
        // backing vec (the top), whereas `item_by_depth`/`remove_item_by_depth`
        // index from the front (the bottom). Popping both and pushing them back
        // in reverse order swaps the true top two regardless of that convention.
        let top_item = stack_holder.pop()?;
        let second_to_top_item = stack_holder.pop()?;
        stack_holder.push(top_item)?;
        stack_holder.push(second_to_top_item)?;

        // Increment the ops counter.
        stack_holder.increment_ops(OP_SWAP_OPS)?;

        Ok(())
    }

    /// Returns the bytecode for the `OP_SWAP` opcode (0x7c).
    pub fn bytecode() -> Vec<u8> {
        vec![0x7c]
    }
}
