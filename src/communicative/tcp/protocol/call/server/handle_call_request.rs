use std::time::Duration;

use crate::communicative::tcp::package::{PackageKind, TCPPackage};
use crate::communicative::tcp::protocol::call::{
    CallRequestBody, CallResponseBody, CallResponseError,
};
use crate::operative::tasks::engine_session::session_pool::error::exec_call_in_pool_error::ExecCallInPoolError;
use crate::operative::tasks::engine_session::session_pool::session_pool::SESSION_POOL;
use tokio::time::sleep;

const SESSION_SETTLE_MS: u64 = 500;
const MAX_EXEC_ATTEMPTS: u32 = 4;

pub async fn handle_call_request(
    timestamp: i64,
    payload: &[u8],
    session_pool: &SESSION_POOL,
) -> Option<TCPPackage> {
    let CallRequestBody {
        call,
        call_bls_signature,
    } = match CallRequestBody::deserialize(payload) {
        Some(req) => req,
        None => {
            let body = CallResponseBody::err(CallResponseError::DeserializeCallRequestError);
            let bytes = body.serialize().unwrap_or_default();
            return Some(TCPPackage::new(PackageKind::CallProtocol, timestamp, &bytes));
        }
    };

    let mut response: Option<CallResponseBody> = None;
    for attempt in 1..=MAX_EXEC_ATTEMPTS {
        let attempt_result = {
            let mut _session_pool = session_pool.lock().await;
            _session_pool
                .exec_call_in_pool(&call, call_bls_signature)
                .await
        };

        match attempt_result {
            Ok((entry_id, entry, batch_height, batch_timestamp)) => {
                response = Some(CallResponseBody::ok(
                    entry_id,
                    batch_height,
                    batch_timestamp,
                    entry,
                ));
                break;
            }
            Err(err) => {
                let retry_after_settle = matches!(
                    err,
                    ExecCallInPoolError::SessionInactiveError
                        | ExecCallInPoolError::SessionBreakError
                );

                if retry_after_settle && attempt < MAX_EXEC_ATTEMPTS {
                    sleep(Duration::from_millis(SESSION_SETTLE_MS)).await;
                    continue;
                }

                response = Some(CallResponseBody::err(
                    CallResponseError::ExecCallInPoolError(err),
                ));
                break;
            }
        }
    }

    let response_bytes = response
        .expect("This can never be None after the loop.")
        .serialize()
        .unwrap_or_default();

    let response_package = TCPPackage::new(PackageKind::CallProtocol, timestamp, &response_bytes);

    Some(response_package)
}
