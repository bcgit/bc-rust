//! Initialization-vector generation, shared by the modes that need one.

use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::traits::RNG;

/// Generates a random initialization vector.
///
/// NIST SP 800-38A Appendix C gives two recommended methods for producing the unpredictable IVs
/// that CBC and CFB require. This is the second one verbatim: "to generate a random data block
/// using a FIPS-approved random number generator".
///
/// The first method -- applying the forward cipher function to a nonce under the same key -- is not
/// implemented, because it needs a nonce the caller has to guarantee unique, and the API
/// deliberately does not accept caller-supplied initialization data at all.
///
/// Appendix C also notes the IV "need not be secret", so this is not wrapped in a `Secret`: it is
/// returned to the caller to transmit alongside the ciphertext. Its *integrity* is a different
/// matter -- see the `cbc` module docs on Appendix D.
pub(crate) fn random_iv<const N: usize>(
    rng: &mut dyn RNG,
) -> Result<[u8; N], SymmetricCipherError> {
    let mut iv = [0u8; N];
    // `RNGError` converts into `SymmetricCipherError` via the `From` impl in core::errors.
    rng.next_bytes_out(&mut iv)?;
    Ok(iv)
}
