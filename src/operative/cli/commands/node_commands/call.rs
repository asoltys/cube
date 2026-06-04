use crate::communicative::peer::peer::PEER;
use crate::communicative::tcp::client::TCPClient;
use crate::communicative::tcp::protocol::call::CallResponseBody;
use crate::constructive::core_types::calldata::calldata_elements::calldata_element::CalldataElement;
use crate::constructive::core_types::entities::account::root_account::root_account::RootAccount;
use crate::constructive::core_types::entities::contract::contract::Contract;
use crate::constructive::core_types::method_index::method_index::MethodIndex;
use crate::constructive::core_types::ops_budget::ops_budget::OpsBudget;
use crate::constructive::core_types::ops_price::ops_price::OpsPrice;
use crate::constructive::core_types::target::target::Target;
use crate::constructive::entry::entry_kinds::call::call::Call;
use crate::inscriptive::registery::registery::REGISTERY;
use crate::inscriptive::sync_manager::sync_manager::SYNC_MANAGER;
use crate::transmutative::key::KeyHolder;
use colored::Colorize;
use serde_json::to_string_pretty;

/// call <contract_id_hex> <method_index> [<type> <value> ...]
pub async fn call_command(
    contract_id: [u8; 32],
    method_index: u16,
    calldata_elements: Vec<CalldataElement>,
    key_holder: &KeyHolder,
    sync_manager: &SYNC_MANAGER,
    registery: &REGISTERY,
    engine_peer: &PEER,
) {
    // 1 Build the caller's root account from the registery.
    let root_account = RootAccount::self_root_account_from_registery(key_holder, registery).await;

    // 2 Resolve the contract's registery index (rank).
    let registery_index = {
        let _registery = registery.lock().await;
        _registery.get_rank_by_contract_id(contract_id).unwrap_or(0)
    };
    let contract = Contract::new(contract_id, registery_index);

    // 3 Target the next execution batch height.
    let batch_height_tip: u64 = {
        let _sync_manager = sync_manager.lock().await;
        _sync_manager.cube_batch_sync_height_tip()
    };
    let target = Target::new(batch_height_tip + 1);

    // 4 Construct the call (default ops budget/price).
    let call = Call::new(
        root_account,
        contract,
        MethodIndex::new(method_index),
        calldata_elements,
        OpsBudget::new(None),
        OpsPrice::new(0),
        target,
    );

    // 5 BLS-sign the call.
    let call_bls_signature: [u8; 96] = match call.bls_sign(key_holder) {
        Ok(signature) => signature,
        Err(error) => {
            println!("{}", format!("Error BLS signing call: {:?}", error).red());
            return;
        }
    };

    // 6 Send the call to the engine.
    let (call_response_body, duration) = match engine_peer
        .request_call(&call, call_bls_signature)
        .await
    {
        Ok((call_response_body, duration)) => (call_response_body, duration),
        Err(error) => {
            println!("{}", format!("Error requesting call: {:?}", error).red());
            return;
        }
    };

    // 7 Print the result.
    match call_response_body {
        CallResponseBody::Ok(success_body) => {
            println!(
                "{}",
                format!(
                    "Call entry successfully executed ({} ms): {}",
                    duration.as_millis(),
                    to_string_pretty(&success_body.json())
                        .expect("serde_json::Value should serialize")
                )
                .green()
            );
        }
        CallResponseBody::Err(error) => {
            println!(
                "{}",
                format!(
                    "Error executing call: {}",
                    to_string_pretty(&error.json()).expect("serde_json::Value should serialize")
                )
                .red()
            );
        }
    }
}
