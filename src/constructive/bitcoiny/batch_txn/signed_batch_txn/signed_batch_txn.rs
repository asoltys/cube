use crate::constructive::bitcoiny::batch_txn::{
    signed_batch_txn::error::construct_error::SignedBatchTxnConstructError,
    unsigned_batch_txn::error::construct_error::UnsignedBatchTxnConstructError,
    unsigned_batch_txn::unsigned_batch_txn::UnsignedBatchTxn,
};
use crate::constructive::entry::entry::entry::Entry;
use crate::constructive::txout_types::lift::lift::Lift;
use crate::constructive::txout_types::lift::lift_versions::liftv2::liftv2::return_liftv2_taproot;
use crate::constructive::txout_types::payload::payload::Payload;
use crate::constructive::txout_types::projector::projector::Projector;
use crate::transmutative::codec::varint::encode_varint;
use crate::transmutative::hash::sha256;
use crate::transmutative::key::KeyHolder;
use crate::transmutative::secp::schnorr::{self, SchnorrSigningMode};
use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint, ScriptBuf, TxOut, Txid};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Bare transaction fields:
const N_VERSION: [u8; 4] = [0x02, 0x00, 0x00, 0x00];
const N_LOCKTIME: [u8; 4] = [0x00, 0x00, 0x00, 0x00];
const N_SEQUENCE_MAX: [u8; 4] = [0xff, 0xff, 0xff, 0xff];

/// BIP141 witness serialization marker and flag.
const SEGWIT_MARKER: u8 = 0x00;
const SEGWIT_FLAG: u8 = 0x01;

type Bytes = Vec<u8>;

type Witness = Vec<Bytes>;

/// Represents a signed batch transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedBatchTxn {
    /// The Bitcoin transaction inputs of the batch.
    pub tx_inputs: Vec<(OutPoint, TxOut, Witness)>,

    /// The Bitcoin transaction outputs of the batch.
    pub tx_outputs: Vec<TxOut>,
}

impl SignedBatchTxn {
    /// Constructs a signed batch transaction.
    pub fn construct(
        // Tx inputs
        prev_payload: Payload,
        prev_projectors: Vec<Projector>,
        // Entries
        entries: Vec<Entry>,
        // Tx outputs
        new_payload: Payload,
        new_projectors: Vec<Projector>,
        // Tx feerate (sats per vbyte)
        bitcoin_transaction_feerate: u64,
        // Engine key
        engine_keyholder: &KeyHolder,
        // Account+engine MuSig2 key-path cosignatures for each LiftV2 deposit,
        // keyed by the deposit outpoint. The engine cannot produce these alone;
        // they come from the interactive cosigning session with each depositor.
        liftv2_keypath_sigs: &HashMap<OutPoint, [u8; 64]>,
        // N-of-N (all participants + engine) MuSig2 key-path cosignatures for each
        // prev projector being refreshed (spent) into this batch, keyed by the
        // projector outpoint. The consensus-enforced auto-refresh.
        projector_refresh_keypath_sigs: &HashMap<OutPoint, [u8; 64]>,
    ) -> Result<SignedBatchTxn, SignedBatchTxnConstructError> {
        // Assemble the unsigned batch transaction (shared with the LiftV2
        // key-path sighash computation so the two never diverge).
        let unsigned_batch_txn = Self::assemble_unsigned_batch_txn(
            &prev_payload,
            &prev_projectors,
            &entries,
            &new_payload,
            &new_projectors,
            bitcoin_transaction_feerate,
        )?;

        // Initialize the tx input witnesses.
        let mut tx_input_witnesses = Vec::<Witness>::new();

        let mut tx_input_index_iterator = 0;

        // Fill tx input witnesses

        // Fill prev payload witness
        {
            let (prev_payload_tapleaf_hash, prev_payload_tapscript, prev_payload_control_block) =
                prev_payload.p2tr_script_path_spend_elements();

            let prev_payload_taproot_sighash: [u8; 32] = unsigned_batch_txn
                .taproot_sighash(tx_input_index_iterator, Some(prev_payload_tapleaf_hash))
                .ok_or(SignedBatchTxnConstructError::PrevPayloadTaprootSighashConstructionError)?;

            let prev_payload_taproot_signature: [u8; 64] = schnorr::sign(
                engine_keyholder.secp_secret_key_bytes(),
                prev_payload_taproot_sighash,
                SchnorrSigningMode::BIP340,
            )
            .ok_or(SignedBatchTxnConstructError::PrevPayloadTaprootSignError)?;

            // BIP342 script-path witness stack:
            // <sig> <engine-branch selector=1> <tapscript> <control block>
            let prev_payload_witness: Vec<Bytes> = vec![
                prev_payload_taproot_signature.to_vec(),
                vec![0x01],
                prev_payload_tapscript,
                prev_payload_control_block,
            ];

            tx_input_witnesses.push(prev_payload_witness);
            tx_input_index_iterator += 1;
        }

        // Fill prev projectors witnesses (the auto-refresh): each prev projector is
        // spent via a KEY-PATH spend of its value-bound N-of-N MuSig2 output. The
        // engine cannot sign alone; the aggregated refresh signature is supplied
        // here (keyed by projector outpoint), exactly like a LiftV2 cosign.
        {
            for projector in &prev_projectors {
                let outpoint = projector
                    .location
                    .as_ref()
                    .map(|(outpoint, _)| *outpoint)
                    .ok_or(SignedBatchTxnConstructError::ProjectorLocationNotFoundError)?;

                let cosig = projector_refresh_keypath_sigs
                    .get(&outpoint)
                    .copied()
                    .ok_or(SignedBatchTxnConstructError::ProjectorRefreshCosignMissingError(
                        outpoint,
                    ))?;

                // Key-path sighash for this input (no leaf).
                let refresh_sighash: [u8; 32] = unsigned_batch_txn
                    .taproot_sighash(tx_input_index_iterator, None)
                    .ok_or(SignedBatchTxnConstructError::ProjectorRefreshSighashConstructionError(
                        outpoint,
                    ))?;

                // The covenant output key is the P2TR output key in the projector
                // scriptpubkey (OP_1 <32-byte key>). Verify the refresh cosig
                // against it before trusting it in the batch.
                let spk = &projector.scriptpubkey;
                if spk.len() != 34 || spk[0] != 0x51 || spk[1] != 0x20 {
                    return Err(SignedBatchTxnConstructError::ProjectorRefreshCosignInvalidError(
                        outpoint,
                    ));
                }
                let mut output_key = [0u8; 32];
                output_key.copy_from_slice(&spk[2..34]);

                if !schnorr::verify_xonly(
                    output_key,
                    refresh_sighash,
                    cosig,
                    SchnorrSigningMode::BIP340,
                ) {
                    return Err(SignedBatchTxnConstructError::ProjectorRefreshCosignInvalidError(
                        outpoint,
                    ));
                }

                // Key-path witness is just the aggregated refresh signature.
                tx_input_witnesses.push(vec![cosig.to_vec()]);
                tx_input_index_iterator += 1;
            }
        }

        // Fill LiftV1 witnesses
        {
            for entry in &entries {
                if let Entry::Liftup(liftup) = entry {
                    for lift in &liftup.lift_tx_inputs {
                        // Error if its Liftv2
                        match lift {
                            Lift::LiftV1(liftv1) => {
                                // Get the tapleaf hash, tapscript, and control block
                                let (
                                    prev_liftv1_tapleaf_hash,
                                    prev_liftv1_tapscript,
                                    prev_liftv1_control_block,
                                ) = liftv1.p2tr_script_path_spend_elements();

                                // Get the taproot sighash
                                let prev_liftv1_taproot_sighash: [u8; 32] = unsigned_batch_txn
                                    .taproot_sighash(tx_input_index_iterator, Some(prev_liftv1_tapleaf_hash))
                                    .ok_or(SignedBatchTxnConstructError::PrevLiftV1TaprootSighashConstructionError(liftv1.clone()))?;

                                // Get the taproot signature
                                let prev_liftv1_taproot_signature: [u8; 64] = schnorr::sign(
                                    engine_keyholder.secp_secret_key_bytes(),
                                    prev_liftv1_taproot_sighash,
                                    SchnorrSigningMode::BIP340,
                                )
                                .ok_or(SignedBatchTxnConstructError::PrevLiftV1TaprootSignError(
                                    liftv1.clone(),
                                ))?;

                                let prev_liftv1_witness = vec![
                                    prev_liftv1_taproot_signature.to_vec(),
                                    prev_liftv1_tapscript,
                                    prev_liftv1_control_block,
                                ];

                                tx_input_witnesses.push(prev_liftv1_witness);
                                tx_input_index_iterator += 1;
                            }
                            Lift::LiftV2(liftv2) => {
                                // LiftV2 is lifted in via a KEY-PATH spend of the
                                // account+engine MuSig2 output. The engine cannot
                                // sign this alone; it must be co-signed with the
                                // depositor, so the aggregated signature is supplied
                                // here (keyed by outpoint).
                                let cosig = liftv2_keypath_sigs
                                    .get(&liftv2.outpoint)
                                    .copied()
                                    .ok_or(SignedBatchTxnConstructError::LiftV2CosignMissingError(
                                        liftv2.clone(),
                                    ))?;

                                // Key-path sighash for this input (no leaf).
                                let liftv2_keypath_sighash: [u8; 32] = unsigned_batch_txn
                                    .taproot_sighash(tx_input_index_iterator, None)
                                    .ok_or(SignedBatchTxnConstructError::LiftV2TaprootSighashConstructionError(
                                        liftv2.clone(),
                                    ))?;

                                // Verify the cosignature against the deposit output key
                                // before trusting it in the batch.
                                let output_key: [u8; 32] = return_liftv2_taproot(
                                    liftv2.account_key,
                                    liftv2.engine_key,
                                )
                                .and_then(|taproot| taproot.tweaked_key())
                                .ok_or(SignedBatchTxnConstructError::LiftV2CosignInvalidError(
                                    liftv2.clone(),
                                ))?
                                .serialize_xonly();

                                if !schnorr::verify_xonly(
                                    output_key,
                                    liftv2_keypath_sighash,
                                    cosig,
                                    SchnorrSigningMode::BIP340,
                                ) {
                                    return Err(
                                        SignedBatchTxnConstructError::LiftV2CosignInvalidError(
                                            liftv2.clone(),
                                        ),
                                    );
                                }

                                // Key-path witness is just the aggregated signature.
                                let prev_liftv2_witness = vec![cosig.to_vec()];

                                tx_input_witnesses.push(prev_liftv2_witness);
                                tx_input_index_iterator += 1;
                            }
                            Lift::Unknown { .. } => {
                                return Err(
                                    SignedBatchTxnConstructError::UnknownLiftNotSupportedError,
                                );
                            }
                        }
                    }
                }
            }
        }

        let tx_inputs: Vec<(OutPoint, TxOut, Witness)> = unsigned_batch_txn
            .tx_inputs
            .into_iter()
            .zip(tx_input_witnesses.into_iter())
            .map(|((outpoint, txout), witness)| (outpoint, txout, witness))
            .collect();

        Ok(SignedBatchTxn {
            tx_inputs,
            tx_outputs: unsigned_batch_txn.tx_outputs,
        })
    }

    /// Assembles the unsigned batch transaction from the batch inputs/outputs.
    /// Shared by `construct` and `liftv2_keypath_sighashes` so the inputs (and
    /// thus the sighashes) are identical.
    fn assemble_unsigned_batch_txn(
        prev_payload: &Payload,
        prev_projectors: &[Projector],
        entries: &[Entry],
        new_payload: &Payload,
        new_projectors: &[Projector],
        bitcoin_transaction_feerate: u64,
    ) -> Result<UnsignedBatchTxn, SignedBatchTxnConstructError> {
        let prev_payload_tx_input: (OutPoint, TxOut) = match prev_payload.location() {
            Some((outpoint, txout)) => (outpoint, txout),
            None => return Err(SignedBatchTxnConstructError::PayloadLocationNotFoundError),
        };

        let projector_tx_inputs: Vec<(OutPoint, TxOut)> = prev_projectors
            .iter()
            .map(|projector| {
                projector
                    .location
                    .as_ref()
                    .map(|(outpoint, txout)| (outpoint.clone(), txout.clone()))
                    .ok_or(SignedBatchTxnConstructError::ProjectorLocationNotFoundError)
            })
            .collect::<Result<Vec<_>, _>>()?;

        let lift_tx_inputs: Vec<(OutPoint, TxOut)> = {
            let mut lift_tx_inputs = Vec::new();
            for entry in entries {
                if let Entry::Liftup(liftup) = entry {
                    for lift in &liftup.lift_tx_inputs {
                        lift_tx_inputs.push((lift.outpoint(), lift.txout()));
                    }
                }
            }
            lift_tx_inputs
        };

        let swapout_tx_outputs: Vec<TxOut> = {
            let mut swapout_tx_outputs = Vec::new();
            for entry in entries {
                if let Entry::Swapout(swapout) = entry {
                    let scriptpubkey = swapout
                        .pinless_self
                        .calculated_scriptpubkey()
                        .ok_or(
                            SignedBatchTxnConstructError::SwapoutPinlessSelfCalculatedScriptpubkeyError,
                        )?;
                    swapout_tx_outputs.push(TxOut {
                        value: Amount::from_sat(u64::from(swapout.amount)),
                        script_pubkey: ScriptBuf::from(scriptpubkey),
                    });
                }
            }
            swapout_tx_outputs
        };

        let new_payload_scriptpubkey = new_payload.calculated_scriptpubkey().ok_or(
            SignedBatchTxnConstructError::UnsignedBatchTxnConstructError(
                UnsignedBatchTxnConstructError::NewPayloadScriptpubkeyError,
            ),
        )?;
        let new_payload_txout = TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from(new_payload_scriptpubkey),
        };

        let new_projector_txouts: Vec<TxOut> = new_projectors
            .iter()
            .map(|projector| TxOut {
                value: Amount::from_sat(projector.satoshi_amount),
                script_pubkey: ScriptBuf::from(projector.scriptpubkey.clone()),
            })
            .collect();

        UnsignedBatchTxn::construct(
            prev_payload_tx_input,
            projector_tx_inputs,
            lift_tx_inputs,
            new_payload_txout,
            new_projector_txouts,
            swapout_tx_outputs,
            bitcoin_transaction_feerate,
        )
        .map_err(SignedBatchTxnConstructError::UnsignedBatchTxnConstructError)
    }

    /// Computes the BIP341 key-path sighash for each LiftV2 deposit spent in this
    /// batch, keyed by deposit outpoint. These are the messages the depositor and
    /// the engine co-sign (MuSig2) to authorize lifting each deposit in.
    pub fn liftv2_keypath_sighashes(
        prev_payload: &Payload,
        prev_projectors: &[Projector],
        entries: &[Entry],
        new_payload: &Payload,
        new_projectors: &[Projector],
        bitcoin_transaction_feerate: u64,
    ) -> Result<HashMap<OutPoint, [u8; 32]>, SignedBatchTxnConstructError> {
        let unsigned = Self::assemble_unsigned_batch_txn(
            prev_payload,
            prev_projectors,
            entries,
            new_payload,
            new_projectors,
            bitcoin_transaction_feerate,
        )?;

        // Input order matches assemble: prev_payload(0), projectors, then lifts.
        let mut index: u32 = 1 + prev_projectors.len() as u32;
        let mut sighashes = HashMap::new();
        for entry in entries {
            if let Entry::Liftup(liftup) = entry {
                for lift in &liftup.lift_tx_inputs {
                    if let Lift::LiftV2(liftv2) = lift {
                        let sighash = unsigned.taproot_sighash(index, None).ok_or(
                            SignedBatchTxnConstructError::LiftV2TaprootSighashConstructionError(
                                liftv2.clone(),
                            ),
                        )?;
                        sighashes.insert(liftv2.outpoint, sighash);
                    }
                    index += 1;
                }
            }
        }
        Ok(sighashes)
    }

    /// Computes the BIP341 KEY-PATH sighash for each prev projector being refreshed
    /// (spent) in this batch, keyed by projector outpoint. These are the messages
    /// the participants + engine N-of-N co-sign to authorize the auto-refresh.
    /// Projector inputs occupy indices 1..1+prev_projectors.len() (right after the
    /// prev payload), matching `assemble_unsigned_batch_txn`.
    pub fn projector_refresh_keypath_sighashes(
        prev_payload: &Payload,
        prev_projectors: &[Projector],
        entries: &[Entry],
        new_payload: &Payload,
        new_projectors: &[Projector],
        bitcoin_transaction_feerate: u64,
    ) -> Result<HashMap<OutPoint, [u8; 32]>, SignedBatchTxnConstructError> {
        let unsigned = Self::assemble_unsigned_batch_txn(
            prev_payload,
            prev_projectors,
            entries,
            new_payload,
            new_projectors,
            bitcoin_transaction_feerate,
        )?;

        let mut sighashes = HashMap::new();
        for (i, projector) in prev_projectors.iter().enumerate() {
            let outpoint = projector
                .location
                .as_ref()
                .map(|(outpoint, _)| *outpoint)
                .ok_or(SignedBatchTxnConstructError::ProjectorLocationNotFoundError)?;
            let index = 1 + i as u32; // prev_payload is input 0
            let sighash = unsigned.taproot_sighash(index, None).ok_or(
                SignedBatchTxnConstructError::ProjectorRefreshSighashConstructionError(outpoint),
            )?;
            sighashes.insert(outpoint, sighash);
        }
        Ok(sighashes)
    }

    /// Returns the transaction input outpoints.
    pub fn tx_input_outpoints(&self) -> Vec<OutPoint> {
        self.tx_inputs
            .iter()
            .map(|(outpoint, _, _)| outpoint.clone())
            .collect()
    }

    /// Returns the transaction outputs.
    pub fn tx_outputs(&self) -> Vec<TxOut> {
        self.tx_outputs.clone()
    }

    /// Serializes this value with bincode.
    pub fn serialize(&self) -> Option<Vec<u8>> {
        bincode::serde::encode_to_vec(self, bincode::config::standard()).ok()
    }

    /// Deserializes a signed batch transaction from bincode bytes.
    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        bincode::serde::decode_from_slice::<Self, _>(bytes, bincode::config::standard())
            .ok()
            .map(|(signed_batch_txn, _)| signed_batch_txn)
    }

    /// Serializes the Bitcoin transaction.
    pub fn serialize_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&N_VERSION);
        buf.push(SEGWIT_MARKER);
        buf.push(SEGWIT_FLAG);

        buf.extend_from_slice(&encode_varint(self.tx_inputs.len() as u64));
        for (outpoint, _, _) in &self.tx_inputs {
            push_legacy_txin(&mut buf, outpoint);
        }

        buf.extend_from_slice(&encode_varint(self.tx_outputs.len() as u64));
        for txout in &self.tx_outputs {
            push_txout(&mut buf, txout);
        }

        for (_, _, w) in &self.tx_inputs {
            push_witness(&mut buf, w);
        }

        buf.extend_from_slice(&N_LOCKTIME);
        buf
    }

    /// Serializes the transaction for txid.
    pub fn serialize_bytes_for_txid(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&N_VERSION);

        buf.extend_from_slice(&encode_varint(self.tx_inputs.len() as u64));
        for (outpoint, _, _) in &self.tx_inputs {
            push_legacy_txin(&mut buf, outpoint);
        }

        buf.extend_from_slice(&encode_varint(self.tx_outputs.len() as u64));
        for txout in &self.tx_outputs {
            push_txout(&mut buf, txout);
        }

        buf.extend_from_slice(&N_LOCKTIME);
        buf
    }

    /// Returns the transaction id.
    pub fn txid(&self) -> Txid {
        let preimage = self.serialize_bytes_for_txid();
        let first = sha256(&preimage);
        Txid::from_byte_array(sha256(&first))
    }
}

fn push_outpoint(buf: &mut Vec<u8>, outpoint: &OutPoint) {
    buf.extend_from_slice(&outpoint.txid.to_byte_array());
    buf.extend_from_slice(&outpoint.vout.to_le_bytes());
}

fn push_legacy_txin(buf: &mut Vec<u8>, outpoint: &OutPoint) {
    push_outpoint(buf, outpoint);
    buf.push(0x00); // empty scriptSig
    buf.extend_from_slice(&N_SEQUENCE_MAX);
}

fn push_txout(buf: &mut Vec<u8>, txout: &TxOut) {
    buf.extend_from_slice(&txout.value.to_sat().to_le_bytes());
    let spk = txout.script_pubkey.as_bytes();
    buf.extend_from_slice(&encode_varint(spk.len() as u64));
    buf.extend_from_slice(spk);
}

/// One input’s witness stack (BIP141): stack item count, then each item length-prefixed.
fn push_witness(buf: &mut Vec<u8>, witness: &Witness) {
    buf.extend_from_slice(&encode_varint(witness.len() as u64));
    for item in witness {
        buf.extend_from_slice(&encode_varint(item.len() as u64));
        buf.extend_from_slice(item);
    }
}
