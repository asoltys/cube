//! Timeout-tree / ZKTLC exit tree: a contract pot rendered as per-participant,
//! unilaterally-exitable VTXO leaves (the ownership leg of a ZKTLC).

pub mod timeout_tree;

pub use timeout_tree::{TimeoutTree, VtxoLeaf};
