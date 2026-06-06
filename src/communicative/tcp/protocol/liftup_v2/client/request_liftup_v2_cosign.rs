//! Send helper for Liftup v2 cosign requests (round 2): fetch + submit.

use crate::communicative::peer::peer::{PeerConnection, PEER, SOCKET};
use crate::communicative::tcp::package::{PackageKind, TCPPackage};
use crate::communicative::tcp::protocol::liftup_v2::bodies::{
    LiftupV2CosignRequestBody, LiftupV2CosignResponseBody,
};
use crate::communicative::tcp::request_error::RequestError;
use crate::communicative::tcp::tcp::{self, TCPError};
use bitcoin::OutPoint;
use chrono::Utc;
use std::time::Duration;

/// Timeout for Liftup v2 cosign requests.
const LIFTUP_V2_COSIGN_TIMEOUT_MS: u64 = 5_000;

async fn request_cosign(
    peer: &PEER,
    request_body: LiftupV2CosignRequestBody,
) -> Result<(LiftupV2CosignResponseBody, Duration), RequestError> {
    // 1 Serialize the request body.
    let payload = request_body
        .serialize()
        .ok_or(RequestError::RequestSerializationError)?;

    // 2 Construct the request package.
    let request_package = TCPPackage::new(
        PackageKind::LiftupV2CosignProtocol,
        Utc::now().timestamp(),
        &payload,
    );

    // 3 Acquire the socket.
    let socket: SOCKET = peer
        .socket()
        .await
        .ok_or(RequestError::TCPErr(TCPError::ConnErr))?;

    // 4 Send the request package and get the response package.
    let timeout = Duration::from_millis(LIFTUP_V2_COSIGN_TIMEOUT_MS);
    let (response_package, duration) = tcp::request(&socket, request_package, Some(timeout))
        .await
        .map_err(RequestError::TCPErr)?;

    // 5 Deserialize the response payload.
    let response_payload = match response_package.payload_len() {
        0 => return Err(RequestError::EmptyResponse),
        _ => response_package.payload(),
    };

    LiftupV2CosignResponseBody::deserialize(&response_payload)
        .ok_or(RequestError::ResponseDeserializationError)
        .map(|r| (r, duration))
}

/// Fetch the engine's cosign material for `outpoint`.
pub async fn request_liftup_v2_cosign_fetch(
    peer: &PEER,
    outpoint: OutPoint,
) -> Result<(LiftupV2CosignResponseBody, Duration), RequestError> {
    request_cosign(peer, LiftupV2CosignRequestBody::fetch(outpoint)).await
}

/// Submit the depositor's partial signature for `outpoint`.
pub async fn request_liftup_v2_cosign_submit(
    peer: &PEER,
    outpoint: OutPoint,
    client_partial_sig: [u8; 32],
) -> Result<(LiftupV2CosignResponseBody, Duration), RequestError> {
    request_cosign(
        peer,
        LiftupV2CosignRequestBody::submit(outpoint, client_partial_sig),
    )
    .await
}
