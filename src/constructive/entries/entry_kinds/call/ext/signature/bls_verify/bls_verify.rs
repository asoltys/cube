use crate::constructive::entries::entry_kinds::call::call::Call;
use crate::constructive::entries::entry_kinds::call::ext::signature::bls_verify::error::bls_verify_error::CallBLSVerifyError;
use crate::transmutative::bls::verify::bls_verify as bls_verify_message;

impl Call {
    /// Verifies a BLS signature over this `Call`'s signature message (sighash).
    pub fn bls_verify(&self, bls_signature: [u8; 96]) -> Result<(), CallBLSVerifyError> {
        let sighash = self.sighash().map_err(CallBLSVerifyError::SighashError)?;
        let bls_public_key = self.account.bls_key();
        match bls_verify_message(&bls_public_key, sighash, bls_signature) {
            true => Ok(()),
            false => Err(CallBLSVerifyError::InvalidBLSSignatureError),
        }
    }
}
