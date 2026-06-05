// Cube Lottery arcade: a small web server (served on localhost) that lets people
// play the on-VM lottery from a browser. Keys are generated and calls are
// BLS-signed entirely in the browser; this server only verifies the signature,
// executes the call directly on the engine's VM (instant, no batch wait), and
// runs a faucet so each browser tab can be a funded player.

use crate::constructive::core_types::calldata::calldata_elements::calldata_element::CalldataElement;
use crate::constructive::entity::account::root_account::registered_and_configured_root_account::registered_and_configured_root_account::RegisteredAndConfiguredRootAccount;
use crate::constructive::entity::account::root_account::root_account::RootAccount;
use crate::constructive::entity::contract::contract::Contract;
use crate::constructive::core_types::method_index::method_index::MethodIndex;
use crate::constructive::core_types::ops_budget::ops_budget::OpsBudget;
use crate::constructive::core_types::ops_price::ops_price::OpsPrice;
use crate::constructive::core_types::target::target::Target;
use crate::constructive::entry::entry_kinds::call::call::Call;
use crate::executive::exec_ctx::exec_ctx::{ExecCtx, EXEC_CTX};
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
use axum::extract::{Query, State};
use axum::http::header;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use bitcoin::hashes::Hash as _;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

const INDEX_HTML: &str = include_str!("arcade_assets/index.html");
const BUNDLE_JS: &str = include_str!("arcade_assets/bundle.js");

// Lottery contract constants (mirror tests/lottery.rs).
const KEY_N: u8 = 0x6e;
const KEY_S: u8 = 0x73;
const KEY_A: u8 = 0x61;
const KEY_R: u8 = 0x72;
const ROUND: u64 = 3;
const ENTRY_COST: u64 = 10_000;
const PAYOUT: u64 = 27_000;
const FAUCET_TOPUP_TO: u64 = 100_000;
const FAUCET_TOPUP_BELOW: u64 = 30_000;

#[derive(Clone)]
struct ArcadeState {
    engine_key: [u8; 32],
    contract_id: [u8; 32],
    registery: REGISTERY,
    coin_manager: COIN_MANAGER,
    state_manager: STATE_MANAGER,
    flame_manager: FLAME_MANAGER,
    sync_manager: SYNC_MANAGER,
    utxo_set: UTXO_SET,
    params_manager: PARAMS_MANAGER,
    privileges_manager: PRIVILEGES_MANAGER,
    graveyard: GRAVEYARD,
    archival_manager: Option<ARCHIVAL_MANAGER>,
    rpc_url: String,
    rpc_user: String,
    rpc_pass: String,
    mine_address: String,
    last_winner: Arc<tokio::sync::Mutex<Option<String>>>,
}

impl ArcadeState {
    fn exec_ctx(&self) -> EXEC_CTX {
        ExecCtx::construct(
            self.engine_key,
            Arc::clone(&self.sync_manager),
            Arc::clone(&self.utxo_set),
            Arc::clone(&self.registery),
            Arc::clone(&self.graveyard),
            Arc::clone(&self.coin_manager),
            Arc::clone(&self.flame_manager),
            Arc::clone(&self.state_manager),
            Arc::clone(&self.privileges_manager),
            Arc::clone(&self.params_manager),
            self.archival_manager.clone(),
        )
    }
    fn rpc(&self) -> Option<Client> {
        Client::new(
            &self.rpc_url,
            Auth::UserPass(self.rpc_user.clone(), self.rpc_pass.clone()),
        )
        .ok()
    }
    fn best_block_hash(&self) -> [u8; 32] {
        self.rpc()
            .and_then(|c| c.get_best_block_hash().ok())
            .map(|h| h.to_byte_array())
            .unwrap_or([0u8; 32])
    }
    fn mine(&self, n: u64) {
        if let (Some(rpc), Ok(addr)) = (self.rpc(), bitcoin::Address::from_str(&self.mine_address)) {
            let addr = addr.assume_checked();
            let _ = rpc.generate_to_address(n, &addr);
        }
    }
}

// ---------- helpers ----------
fn parse_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    let v = hex::decode(s.trim_start_matches("0x")).ok()?;
    v.try_into().ok()
}
fn le_uint(bytes: &[u8]) -> u64 {
    let mut x = 0u64;
    for (i, &b) in bytes.iter().take(8).enumerate() {
        x |= (b as u64) << (8 * i);
    }
    x
}
fn minimal_le(mut n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    while n > 0 {
        out.push((n & 0xff) as u8);
        n >>= 8;
    }
    out
}

async fn read_state_uint(s: &ArcadeState, key: u8) -> u64 {
    let sm = s.state_manager.lock().await;
    sm.get_state_value(s.contract_id, &vec![key])
        .map(|v| le_uint(&v))
        .unwrap_or(0)
}

// ---------- handlers ----------
// Serve embedded assets, or live from CUBE_ARCADE_ASSETS dir if set (for UI iteration).
fn asset(name: &str, embedded: &'static str) -> String {
    if let Ok(dir) = std::env::var("CUBE_ARCADE_ASSETS") {
        if let Ok(s) = std::fs::read_to_string(format!("{}/{}", dir, name)) {
            return s;
        }
    }
    embedded.to_string()
}
async fn serve_index() -> Html<String> {
    Html(asset("index.html", INDEX_HTML))
}
async fn serve_bundle() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        asset("bundle.js", BUNDLE_JS),
    )
}

async fn contract_registery_index(s: &ArcadeState) -> u64 {
    let reg = s.registery.lock().await;
    reg.get_contract_by_contract_id(s.contract_id)
        .map(|c| c.registery_index)
        .unwrap_or(0)
}

async fn get_state(
    State(s): State<ArcadeState>,
    Query(params): Query<HashMap<String, String>>,
) -> Json<Value> {
    let n = read_state_uint(&s, KEY_N).await;
    let armed = read_state_uint(&s, KEY_A).await;
    let treasury = {
        let cm = s.coin_manager.lock().await;
        cm.get_contract_balance(s.contract_id).unwrap_or(0)
    };
    let batch_height_tip = {
        let sm = s.sync_manager.lock().await;
        sm.cube_batch_sync_height_tip()
    };
    let mut out = json!({
        "contract_id": hex::encode(s.contract_id),
        "contract_registery_index": contract_registery_index(&s).await,
        "batch_height_tip": batch_height_tip,
        "n": n,
        "treasury": treasury,
        "armed": armed,
        "round_size": ROUND,
        "entry_cost": ENTRY_COST,
        "payout": PAYOUT,
        "last_winner": s.last_winner.lock().await.clone(),
    });
    if let Some(acct_hex) = params.get("account") {
        if let Some(account_key) = parse_hex::<32>(acct_hex) {
            let (registered, reg_index) = {
                let reg = s.registery.lock().await;
                match reg.get_account_info_by_account_key(account_key) {
                    Some((_, _, idx, _)) => (true, idx),
                    None => (false, 0),
                }
            };
            let balance = {
                let cm = s.coin_manager.lock().await;
                cm.get_account_balance(account_key).unwrap_or(0)
            };
            out["account"] = json!({ "registered": registered, "registery_index": reg_index, "balance": balance });
        }
    }
    Json(out)
}

#[derive(Deserialize)]
struct FaucetReq {
    account_key: String,
    bls_key: String,
}

async fn post_faucet(State(s): State<ArcadeState>, Json(body): Json<FaucetReq>) -> Json<Value> {
    let (account_key, bls_key) = match (parse_hex::<32>(&body.account_key), parse_hex::<48>(&body.bls_key)) {
        (Some(a), Some(b)) => (a, b),
        _ => return Json(json!({ "error": "bad keys" })),
    };
    let now = Utc::now().timestamp() as u64;

    // Register the account (configured with its BLS key) if not already.
    let already = {
        let reg = s.registery.lock().await;
        reg.get_account_info_by_account_key(account_key).is_some()
    };
    if !already {
        let mut reg = s.registery.lock().await;
        let _ = reg.register_account(account_key, now, Some(bls_key), None, None, None);
        let _ = reg.apply_changes();
    }

    // Grant / top up balance.
    {
        let mut cm = s.coin_manager.lock().await;
        match cm.get_account_balance(account_key) {
            None => {
                let _ = cm.register_account(account_key, FAUCET_TOPUP_TO);
            }
            Some(bal) if bal < FAUCET_TOPUP_BELOW => {
                let _ = cm.account_balance_up(account_key, FAUCET_TOPUP_TO - bal);
            }
            Some(_) => {}
        }
        let _ = cm.apply_changes();
    }

    let reg_index = {
        let reg = s.registery.lock().await;
        reg.get_account_info_by_account_key(account_key)
            .map(|(_, _, idx, _)| idx)
            .unwrap_or(0)
    };
    let balance = {
        let cm = s.coin_manager.lock().await;
        cm.get_account_balance(account_key).unwrap_or(0)
    };
    Json(json!({ "registery_index": reg_index, "balance": balance }))
}

#[derive(Deserialize)]
struct CalldataEl {
    #[serde(rename = "type")]
    kind: String,
    value: u64,
}
#[derive(Deserialize)]
struct CallReq {
    account_key: String,
    registery_index: u64,
    bls_key: String,
    method_index: u16,
    calldata: Vec<CalldataEl>,
    ops_price: u64,
    target: u64,
    bls_signature: String,
}

async fn post_call(State(s): State<ArcadeState>, Json(body): Json<CallReq>) -> Json<Value> {
    let account_key = match parse_hex::<32>(&body.account_key) {
        Some(a) => a,
        None => return Json(json!({ "ok": false, "error": "bad account key" })),
    };
    let bls_key = match parse_hex::<48>(&body.bls_key) {
        Some(b) => b,
        None => return Json(json!({ "ok": false, "error": "bad bls key" })),
    };
    let signature = match parse_hex::<96>(&body.bls_signature) {
        Some(sig) => sig,
        None => return Json(json!({ "ok": false, "error": "bad signature" })),
    };

    // Reconstruct the Call exactly as the browser signed it.
    let account = RootAccount::RegisteredAndConfiguredRootAccount(
        RegisteredAndConfiguredRootAccount::new(account_key, body.registery_index, bls_key),
    );
    let contract = {
        let reg = s.registery.lock().await;
        reg.get_contract_by_contract_id(s.contract_id)
            .unwrap_or_else(|| Contract::new(s.contract_id, 0))
    };
    let calldata: Vec<CalldataElement> = body
        .calldata
        .iter()
        .filter(|e| e.kind == "payable")
        .map(|e| CalldataElement::Payable(e.value as u32))
        .collect();
    let call = Call::new(
        account,
        contract,
        MethodIndex::new(body.method_index),
        calldata,
        OpsBudget::new(None),
        OpsPrice::new(body.ops_price),
        Target::new(body.target),
    );

    // Verify the browser's BLS signature over the sighash.
    if call.bls_verify(signature).is_err() {
        return Json(json!({ "ok": false, "error": "signature verification failed" }));
    }

    let balance_before = {
        let cm = s.coin_manager.lock().await;
        cm.get_account_balance(account_key).unwrap_or(0)
    };

    // Execute directly on the VM. OP_BLOCKHASH = current Bitcoin tip hash.
    let block_hash = s.best_block_hash();
    let now = Utc::now().timestamp() as u64;
    let exec_ctx = s.exec_ctx();
    {
        let mut ctx = exec_ctx.lock().await;
        ctx.pre_execution().await;
    }
    let result = {
        let mut ctx = exec_ctx.lock().await;
        ctx.execute_call(&call, now, block_hash).await
    };
    drop(exec_ctx);

    match result {
        Err(e) => {
            // Discard the partial delta on failure.
            s.exec_ctx().lock().await.flush().await;
            Json(json!({ "ok": false, "error": format!("{:?}", e) }))
        }
        Ok(_) => {
            // Commit the execution delta to permanent storage.
            let _ = s.coin_manager.lock().await.apply_changes();
            let _ = s.state_manager.lock().await.apply_changes();
            let _ = s.registery.lock().await.apply_changes();
            let _ = s.graveyard.lock().await.apply_changes();
            let _ = s.privileges_manager.lock().await.apply_changes();
            // Advance the chain tip so a subsequent draw uses a *different* block hash.
            s.mine(1);

            let balance_after = {
                let cm = s.coin_manager.lock().await;
                cm.get_account_balance(account_key).unwrap_or(0)
            };
            let treasury = {
                let cm = s.coin_manager.lock().await;
                cm.get_contract_balance(s.contract_id).unwrap_or(0)
            };

            // If this was a draw (method 1), compute + record the winner for display.
            let mut winner_hex: Option<String> = None;
            if body.method_index == 1 {
                let r_stored = read_state_uint(&s, KEY_R).await;
                let round_start = r_stored.saturating_sub(1);
                let modv: u64 = block_hash.iter().map(|&b| b as u64).sum::<u64>() % ROUND;
                let widx = round_start + modv;
                let mut slot_key = vec![KEY_S];
                slot_key.extend(minimal_le(widx));
                let w = {
                    let sm = s.state_manager.lock().await;
                    sm.get_state_value(s.contract_id, &slot_key)
                };
                if let Some(w) = w {
                    let wh = hex::encode(&w);
                    winner_hex = Some(wh.clone());
                    *s.last_winner.lock().await = Some(wh);
                }
            }

            Json(json!({
                "ok": true,
                "balance": balance_after,
                "won": balance_after > balance_before,
                "payout": PAYOUT,
                "treasury": treasury,
                "winner": winner_hex,
            }))
        }
    }
}

#[derive(Deserialize)]
struct MineReq {
    n: Option<u64>,
}
async fn post_mine(State(s): State<ArcadeState>, Json(body): Json<MineReq>) -> Json<Value> {
    s.mine(body.n.unwrap_or(1));
    Json(json!({ "ok": true, "tip": hex::encode(s.best_block_hash()) }))
}

/// Spawns the arcade web server as a background task.
pub async fn run_arcade(
    _chain: Chain,
    port: u16,
    engine_key: [u8; 32],
    contract_id: [u8; 32],
    registery: &REGISTERY,
    coin_manager: &COIN_MANAGER,
    state_manager: &STATE_MANAGER,
    flame_manager: &FLAME_MANAGER,
    sync_manager: &SYNC_MANAGER,
    utxo_set: &UTXO_SET,
    params_manager: &PARAMS_MANAGER,
    privileges_manager: &PRIVILEGES_MANAGER,
    graveyard: &GRAVEYARD,
    archival_manager: Option<&ARCHIVAL_MANAGER>,
    rpc_url: String,
    rpc_user: String,
    rpc_pass: String,
    mine_address: String,
) {
    let state = ArcadeState {
        engine_key,
        contract_id,
        registery: Arc::clone(registery),
        coin_manager: Arc::clone(coin_manager),
        state_manager: Arc::clone(state_manager),
        flame_manager: Arc::clone(flame_manager),
        sync_manager: Arc::clone(sync_manager),
        utxo_set: Arc::clone(utxo_set),
        params_manager: Arc::clone(params_manager),
        privileges_manager: Arc::clone(privileges_manager),
        graveyard: Arc::clone(graveyard),
        archival_manager: archival_manager.map(Arc::clone),
        rpc_url,
        rpc_user,
        rpc_pass,
        mine_address,
        last_winner: Arc::new(tokio::sync::Mutex::new(None)),
    };

    let app = Router::new()
        .route("/", get(serve_index))
        .route("/bundle.js", get(serve_bundle))
        .route("/api/state", get(get_state))
        .route("/api/faucet", post(post_faucet))
        .route("/api/call", post(post_call))
        .route("/api/mine", post(post_mine))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("arcade: failed to bind {}: {}", addr, e);
            return;
        }
    };
    println!("🎲 Cube Lottery arcade on http://127.0.0.1:{}/", port);
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
}
