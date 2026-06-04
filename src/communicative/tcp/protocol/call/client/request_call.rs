//! Send helper for Call TCP requests.

use crate::communicative::peer::peer::{PeerConnection, PEER, SOCKET};
use crate::communicative::tcp::package::{PackageKind, TCPPackage};
use crate::communicative::tcp::protocol::call::{CallRequestBody, CallResponseBody};
use crate::communicative::tcp::request_error::RequestError;
use crate::communicative::tcp::tcp::{self, TCPError};
use crate::constructive::entry::entry_kinds::call::call::Call;
use chrono::Utc;
use std::time::Duration;

const CALL_REQUEST_TIMEOUT_MS: u64 = 5_000;

pub async fn request_call(
    peer: &PEER,
    call: &Call,
    call_bls_signature: [u8; 96],
) -> Result<(CallResponseBody, Duration), RequestError> {
    let request_body = CallRequestBody::new(call.clone(), call_bls_signature);

    let payload = request_body
        .serialize()
        .ok_or(RequestError::RequestSerializationError)?;

    let request_package =
        TCPPackage::new(PackageKind::CallProtocol, Utc::now().timestamp(), &payload);

    let socket: SOCKET = peer
        .socket()
        .await
        .ok_or(RequestError::TCPErr(TCPError::ConnErr))?;

    let timeout = Duration::from_millis(CALL_REQUEST_TIMEOUT_MS);

    let (response_package, duration) = tcp::request(&socket, request_package, Some(timeout))
        .await
        .map_err(RequestError::TCPErr)?;

    let response_payload = match response_package.payload_len() {
        0 => return Err(RequestError::EmptyResponse),
        _ => response_package.payload(),
    };

    CallResponseBody::deserialize(&response_payload)
        .ok_or(RequestError::ResponseDeserializationError)
        .map(|r| (r, duration))
}
