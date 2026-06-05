//! Generic post-init engine hook.
//!
//! After the engine constructs its in-memory managers, it invokes an optional
//! registered hook with handles to them. This lets a downstream crate attach
//! in-process services (e.g. an application web server) without cube having to
//! depend on, or know anything about, that application.

use crate::inscriptive::archival_manager::archival_manager::ARCHIVAL_MANAGER;
use crate::inscriptive::coin_manager::coin_manager::COIN_MANAGER;
use crate::inscriptive::flame_manager::flame_manager::FLAME_MANAGER;
use crate::inscriptive::graveyard::graveyard::GRAVEYARD;
use crate::inscriptive::params_manager::params_manager::PARAMS_MANAGER;
use crate::inscriptive::privileges_manager::privileges_manager::PRIVILEGES_MANAGER;
use crate::inscriptive::registery::registery::REGISTERY;
use crate::inscriptive::state_manager::state_manager::STATE_MANAGER;
use crate::inscriptive::sync_manager::sync_manager::SYNC_MANAGER;
use crate::inscriptive::utxo_set::utxo_set::UTXO_SET;
use crate::operative::run_args::chain::Chain;
use std::sync::OnceLock;

/// Handles to a running engine's managers, handed to the post-init hook.
pub struct EngineHandles {
    pub chain: Chain,
    pub engine_key: [u8; 32],
    pub registery: REGISTERY,
    pub coin_manager: COIN_MANAGER,
    pub state_manager: STATE_MANAGER,
    pub flame_manager: FLAME_MANAGER,
    pub sync_manager: SYNC_MANAGER,
    pub utxo_set: UTXO_SET,
    pub params_manager: PARAMS_MANAGER,
    pub privileges_manager: PRIVILEGES_MANAGER,
    pub graveyard: GRAVEYARD,
    pub archival_manager: Option<ARCHIVAL_MANAGER>,
    pub rpc_url: String,
    pub rpc_user: String,
    pub rpc_pass: String,
}

type Hook = Box<dyn Fn(EngineHandles) + Send + Sync>;
static ENGINE_HOOK: OnceLock<Hook> = OnceLock::new();

/// Register a hook to be invoked once, after the engine's managers are built.
/// Call this before `runner::run`.
pub fn set_engine_hook(hook: Hook) {
    let _ = ENGINE_HOOK.set(hook);
}

/// The registered hook, if any.
pub fn engine_hook() -> Option<&'static Hook> {
    ENGINE_HOOK.get()
}
