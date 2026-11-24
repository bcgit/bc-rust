//! The provided decrypting finals zeroize the caller's buffer on an error even when the
//! implementor's `finish_` method left data in it.

use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{
    AEADCipherDecryptor, Algorithm, FinishToken, SymmetricCipherDecryptor,
};

const LEN: usize = 8;

/// Fills the final buffer with junk and fails, against the trait's contract.
struct Leaky;

impl Algorithm for Leaky {
    const ALG_NAME: &'static str = "leaky-toy";
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::None;
}

impl SymmetricCipherDecryptor<LEN, LEN> for Leaky {
    fn do_decrypt_out_len(&self, _input_len: usize) -> usize {
        0
    }
    fn do_decrypt_out(&mut self, _: &[u8], _: &mut [u8]) -> Result<usize, SymmetricCipherError> {
        Ok(0)
    }
    fn finish_decrypt_into(
        &mut self,
        _token: &FinishToken,
        out: &mut [u8; LEN],
    ) -> Result<usize, SymmetricCipherError> {
        out.fill(0x5A);
        Err(SymmetricCipherError::DecryptionFailed)
    }
    fn decrypt_out_len(ciphertext_len: usize) -> usize {
        ciphertext_len
    }
}

impl AEADCipherDecryptor<LEN, LEN, LEN> for Leaky {
    fn do_update_aad(&mut self, _aad: &[u8]) -> Result<(), SymmetricCipherError> {
        Ok(())
    }
    fn finish_decrypt_detached_into(
        &mut self,
        _token: &FinishToken,
        _tag: &[u8; LEN],
        plaintext: &mut [u8; LEN],
    ) -> Result<usize, SymmetricCipherError> {
        plaintext.fill(0x5A);
        Err(SymmetricCipherError::AEADTagCheckFailed)
    }
}

#[test]
fn a_failed_final_leaves_the_buffer_zeroed_whatever_the_implementor_wrote() {
    let mut out = [0xEEu8; LEN];
    assert!(Leaky.do_decrypt_final_out(&mut out).is_err());
    assert_eq!(out, [0u8; LEN], "do_decrypt_final_out");

    let mut out = [0xEEu8; LEN];
    assert!(Leaky.do_decrypt_final_detached_out(&[0u8; LEN], &mut out).is_err());
    assert_eq!(out, [0u8; LEN], "do_decrypt_final_detached_out");
}

#[cfg(feature = "alloc")]
#[test]
fn a_failed_boxed_final_leaves_the_buffer_zeroed_whatever_the_implementor_wrote() {
    let boxed: Box<dyn SymmetricCipherDecryptor<LEN, LEN>> = Box::new(Leaky);
    let mut out = [0xEEu8; LEN];
    assert!(boxed.do_decrypt_final_out_boxed(&mut out).is_err());
    assert_eq!(out, [0u8; LEN], "do_decrypt_final_out_boxed");

    let boxed: Box<dyn AEADCipherDecryptor<LEN, LEN, LEN>> = Box::new(Leaky);
    let mut out = [0xEEu8; LEN];
    assert!(boxed.do_decrypt_final_detached_out_boxed(&[0u8; LEN], &mut out).is_err());
    assert_eq!(out, [0u8; LEN], "do_decrypt_final_detached_out_boxed");
}
