//! Liftup v2 (trustless) cosign TCP bodies — round 2 of the deposit cosign.
//!
//! After the batch freezes the engine partial-signs each pending LiftV2 deposit.
//! The depositor first FETCHes the engine's cosign material (key-path sighash +
//! engine public nonces), computes its own partial signature, then SUBMITs it.
//! The engine aggregates account+engine into the key-path witness for the batch.

use bitcoin::OutPoint;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LiftupV2CosignRequestBody {
    /// Fetch the engine's cosign material for `outpoint`.
    Fetch { outpoint: OutPoint },
    /// Submit the depositor's 32-byte MuSig2 partial signature for `outpoint`.
    Submit {
        outpoint: OutPoint,
        client_partial_sig: [u8; 32],
    },
}

impl LiftupV2CosignRequestBody {
    pub fn fetch(outpoint: OutPoint) -> Self {
        Self::Fetch { outpoint }
    }

    pub fn submit(outpoint: OutPoint, client_partial_sig: [u8; 32]) -> Self {
        Self::Submit {
            outpoint,
            client_partial_sig,
        }
    }

    pub fn serialize(&self) -> Option<Vec<u8>> {
        bincode::serde::encode_to_vec(self, bincode::config::standard()).ok()
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        bincode::serde::decode_from_slice::<Self, _>(bytes, bincode::config::standard())
            .ok()
            .map(|(r, _)| r)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub enum LiftupV2CosignResponseError {
    DeserializeRequestError,
    /// No pending LiftV2 deposit for this outpoint in the current batch.
    UnknownOutpointError,
    /// The submitted partial signature did not aggregate into a valid cosignature.
    InvalidPartialSigError,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LiftupV2CosignResponseBody {
    /// The engine's cosign material: key-path sighash + engine public nonces
    /// (33-byte compressed points).
    Material {
        sighash: [u8; 32],
        engine_hiding_nonce: Vec<u8>,
        engine_binding_nonce: Vec<u8>,
    },
    /// The deposit exists but the engine has not prepared its cosign yet (the
    /// batch has not frozen). The depositor should retry shortly.
    NotReady,
    /// The depositor's partial signature was accepted and aggregated.
    Submitted,
    Err(LiftupV2CosignResponseError),
}

impl LiftupV2CosignResponseBody {
    pub fn serialize(&self) -> Option<Vec<u8>> {
        bincode::serde::encode_to_vec(self, bincode::config::standard()).ok()
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        bincode::serde::decode_from_slice::<Self, _>(bytes, bincode::config::standard())
            .ok()
            .map(|(r, _)| r)
    }

    pub fn json(&self) -> Value {
        let mut obj = Map::new();
        match self {
            LiftupV2CosignResponseBody::Material {
                sighash,
                engine_hiding_nonce,
                engine_binding_nonce,
            } => {
                obj.insert("status".to_string(), Value::String("material".to_string()));
                obj.insert("sighash".to_string(), Value::String(hex::encode(sighash)));
                obj.insert(
                    "engine_hiding_nonce".to_string(),
                    Value::String(hex::encode(engine_hiding_nonce)),
                );
                obj.insert(
                    "engine_binding_nonce".to_string(),
                    Value::String(hex::encode(engine_binding_nonce)),
                );
            }
            LiftupV2CosignResponseBody::NotReady => {
                obj.insert("status".to_string(), Value::String("not_ready".to_string()));
            }
            LiftupV2CosignResponseBody::Submitted => {
                obj.insert("status".to_string(), Value::String("submitted".to_string()));
            }
            LiftupV2CosignResponseBody::Err(e) => {
                obj.insert("status".to_string(), Value::String("err".to_string()));
                obj.insert("error".to_string(), Value::String(format!("{e:?}")));
            }
        }
        Value::Object(obj)
    }
}
