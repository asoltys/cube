use crate::constructive::entries::entry_kinds::call::call::Call;
use crate::constructive::entries::entry_kinds::call::ext::signature::bls_sign::error::bls_sign_error::CallBLSSignError;
use crate::transmutative::bls::sign::bls_sign as bls_sign_message;
use crate::transmutative::key::KeyHolder;

impl Call {
    /// Signs the `Call` signature message (sighash) with the BLS secret key.
    pub fn bls_sign(&self, keyholder: &KeyHolder) -> Result<[u8; 96], CallBLSSignError> {
        let sighash = self.sighash().map_err(CallBLSSignError::SighashError)?;
        let bls_secret_key = keyholder.bls_secret_key();
        Ok(bls_sign_message(bls_secret_key, sighash))
    }
}
