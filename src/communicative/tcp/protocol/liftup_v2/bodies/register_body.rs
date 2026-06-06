//! Liftup v2 (trustless) register TCP bodies — round 1 of the deposit cosign.
//!
//! The depositor admits its `Liftup` (which carries one or more `LiftV2` inputs)
//! AND commits, per V2 deposit outpoint, the public MuSig2 nonces it will later
//! partial-sign the key-path spend with. Compressed points (33 bytes) travel as
//! `Vec<u8>` since serde's built-in array impls stop at 32.

use crate::constructive::entry::entry::entry::Entry;
use crate::constructive::entry::entry_kinds::liftup::liftup::Liftup;
use crate::operative::tasks::engine_session::session_pool::error::exec_liftup_in_pool_error::ExecLiftupInPoolError;
use bitcoin::OutPoint;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

mod bls_signature_96 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(bytes: &[u8; 96], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let (a, rest) = bytes.split_at(32);
        let (b, c) = rest.split_at(32);
        let parts = (
            <[u8; 32]>::try_from(a).expect("split_at(32)"),
            <[u8; 32]>::try_from(b).expect("split_at(32)"),
            <[u8; 32]>::try_from(c).expect("split_at(32)"),
        );
        parts.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 96], D::Error>
    where
        D: Deserializer<'de>,
    {
        let (a, b, c) = <([u8; 32], [u8; 32], [u8; 32])>::deserialize(deserializer)?;
        let mut out = [0u8; 96];
        out[0..32].copy_from_slice(&a);
        out[32..64].copy_from_slice(&b);
        out[64..96].copy_from_slice(&c);
        Ok(out)
    }
}

/// A depositor's committed public nonces for one LiftV2 deposit (round 1).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiftupV2Nonce {
    pub outpoint: OutPoint,
    /// 33-byte compressed secp point.
    pub client_hiding_nonce: Vec<u8>,
    /// 33-byte compressed secp point.
    pub client_binding_nonce: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiftupV2RegisterRequestBody {
    pub liftup: Liftup,
    #[serde(with = "bls_signature_96")]
    pub liftup_bls_signature: [u8; 96],
    /// One entry per LiftV2 input in `liftup`, carrying its public nonces.
    pub nonces: Vec<LiftupV2Nonce>,
}

impl LiftupV2RegisterRequestBody {
    pub fn new(liftup: Liftup, liftup_bls_signature: [u8; 96], nonces: Vec<LiftupV2Nonce>) -> Self {
        Self {
            liftup,
            liftup_bls_signature,
            nonces,
        }
    }

    pub fn serialize(&self) -> Option<Vec<u8>> {
        bincode::serde::encode_to_vec(self, bincode::config::standard()).ok()
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        bincode::serde::decode_from_slice::<Self, _>(bytes, bincode::config::standard())
            .ok()
            .map(|(req, _)| req)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiftupV2RegisterSuccessBody {
    pub entry_id: [u8; 32],
    pub batch_height: u64,
    pub batch_timestamp: u64,
    pub entry: Entry,
}

impl LiftupV2RegisterSuccessBody {
    pub fn json(&self) -> Value {
        let mut obj = Map::new();
        obj.insert("entry_id".to_string(), Value::String(hex::encode(self.entry_id)));
        obj.insert("batch_height".to_string(), Value::Number(self.batch_height.into()));
        obj.insert("batch_timestamp".to_string(), Value::Number(self.batch_timestamp.into()));
        obj.insert("entry".to_string(), self.entry.json());
        Value::Object(obj)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub enum LiftupV2RegisterResponseError {
    DeserializeRequestError,
    /// The request carried no nonce for a LiftV2 input (or no LiftV2 inputs).
    MissingNonceError,
    /// A nonce point did not decode as a valid compressed secp point.
    InvalidNonceError,
    ExecLiftupInPoolError(ExecLiftupInPoolError),
}

impl LiftupV2RegisterResponseError {
    pub fn json(&self) -> Value {
        let mut obj = Map::new();
        match self {
            LiftupV2RegisterResponseError::DeserializeRequestError => {
                obj.insert("kind".to_string(), Value::String("deserialize_request_error".to_string()));
            }
            LiftupV2RegisterResponseError::MissingNonceError => {
                obj.insert("kind".to_string(), Value::String("missing_nonce_error".to_string()));
            }
            LiftupV2RegisterResponseError::InvalidNonceError => {
                obj.insert("kind".to_string(), Value::String("invalid_nonce_error".to_string()));
            }
            LiftupV2RegisterResponseError::ExecLiftupInPoolError(e) => {
                obj.insert("kind".to_string(), Value::String("exec_liftup_in_pool_error".to_string()));
                obj.insert(
                    "error".to_string(),
                    serde_json::to_value(e).unwrap_or_else(|_| Value::String(format!("{e:?}"))),
                );
            }
        }
        Value::Object(obj)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LiftupV2RegisterResponseBody {
    Ok(LiftupV2RegisterSuccessBody),
    Err(LiftupV2RegisterResponseError),
}

impl LiftupV2RegisterResponseBody {
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
            LiftupV2RegisterResponseBody::Ok(body) => {
                obj.insert("status".to_string(), Value::String("ok".to_string()));
                obj.insert("result".to_string(), body.json());
            }
            LiftupV2RegisterResponseBody::Err(e) => {
                obj.insert("status".to_string(), Value::String("err".to_string()));
                obj.insert("error".to_string(), e.json());
            }
        }
        Value::Object(obj)
    }

    pub fn ok(entry_id: [u8; 32], batch_height: u64, batch_timestamp: u64, entry: Entry) -> Self {
        Self::Ok(LiftupV2RegisterSuccessBody {
            entry_id,
            batch_height,
            batch_timestamp,
            entry,
        })
    }

    pub fn err(e: LiftupV2RegisterResponseError) -> Self {
        Self::Err(e)
    }
}
