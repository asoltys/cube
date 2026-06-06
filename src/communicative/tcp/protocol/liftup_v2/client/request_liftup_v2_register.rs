//! Send helper for Liftup v2 register requests (round 1).

use crate::communicative::peer::peer::{PeerConnection, PEER, SOCKET};
use crate::communicative::tcp::package::{PackageKind, TCPPackage};
use crate::communicative::tcp::protocol::liftup_v2::bodies::{
    LiftupV2Nonce, LiftupV2RegisterRequestBody, LiftupV2RegisterResponseBody,
};
use crate::communicative::tcp::request_error::RequestError;
use crate::communicative::tcp::tcp::{self, TCPError};
use crate::constructive::entry::entry_kinds::liftup::liftup::Liftup;
use chrono::Utc;
use std::time::Duration;

/// Timeout for Liftup v2 register requests.
const LIFTUP_V2_REGISTER_TIMEOUT_MS: u64 = 5_000;

/// Sends a Liftup v2 register request over the peer's TCP connection.
pub async fn request_liftup_v2_register(
    peer: &PEER,
    liftup: &Liftup,
    liftup_bls_signature: [u8; 96],
    nonces: Vec<LiftupV2Nonce>,
) -> Result<(LiftupV2RegisterResponseBody, Duration), RequestError> {
    // 1 Construct the request body.
    let request_body =
        LiftupV2RegisterRequestBody::new(liftup.clone(), liftup_bls_signature, nonces);

    // 2 Serialize the request body.
    let payload = request_body
        .serialize()
        .ok_or(RequestError::RequestSerializationError)?;

    // 3 Construct the request package.
    let request_package = TCPPackage::new(
        PackageKind::LiftupV2RegisterProtocol,
        Utc::now().timestamp(),
        &payload,
    );

    // 4 Acquire the socket.
    let socket: SOCKET = peer
        .socket()
        .await
        .ok_or(RequestError::TCPErr(TCPError::ConnErr))?;

    // 5 Set the timeout.
    let timeout = Duration::from_millis(LIFTUP_V2_REGISTER_TIMEOUT_MS);

    // 6 Send the request package and get the response package.
    let (response_package, duration) = tcp::request(&socket, request_package, Some(timeout))
        .await
        .map_err(RequestError::TCPErr)?;

    // 7 Deserialize the response payload.
    let response_payload = match response_package.payload_len() {
        0 => return Err(RequestError::EmptyResponse),
        _ => response_package.payload(),
    };

    // 8 Return the response body.
    LiftupV2RegisterResponseBody::deserialize(&response_payload)
        .ok_or(RequestError::ResponseDeserializationError)
        .map(|r| (r, duration))
}
