//! The roles of key transport: a public key that encrypts a key the sender already holds to
//! its owner, and the private key that recovers it. This is the other way to establish a key
//! with a public-key encryption scheme; a KEM ([`crate::kem_key`]) generates the key itself.
//!
//! As with the KEM roles, the algorithm's parameters are the role's type parameter, so the
//! argument selects the algorithm a key runs: `pk.transport(&mut rng, params, &key)`.

use crate::errors::KeyTransportError;
use crate::key_material::{KeyMaterial, KeyMaterialTrait};
use crate::traits::{Algorithm, RNG};

/// Marks an [`Algorithm`] as a key-transport scheme: what the roles name.
pub trait KeyTransportAlgorithm: Algorithm {}

/// A public key that transports keys to its owner under `Params`, as `CT_LEN`-byte
/// ciphertexts.
pub trait KeyTransportEncryptingKey<Params, const CT_LEN: usize> {
    /// The algorithm the key runs under these parameters.
    type Algorithm: KeyTransportAlgorithm;

    /// The longest key, in bytes, that `params` let this key carry.
    fn max_key_len(&self, params: Params) -> usize;

    /// Encrypts `key` to the owner of this public key into `ct`, which is zeroized first and
    /// left so on an error, and returns the number of bytes written, always `CT_LEN`.
    ///
    /// # Errors
    /// * [`KeyTransportError::KeyTooLong`] if `key` is longer than
    ///   [`max_key_len`](Self::max_key_len).
    /// * [`KeyTransportError::KeyMaterialError`] if `key` is zeroized.
    /// * [`KeyTransportError::RNGError`] if the RNG is weaker than the algorithm or fails.
    fn transport_out(
        &self,
        rng: &mut dyn RNG,
        params: Params,
        key: &dyn KeyMaterialTrait,
        ct: &mut [u8; CT_LEN],
    ) -> Result<usize, KeyTransportError>;

    /// [`transport_out`](Self::transport_out) returning the ciphertext.
    ///
    /// # Errors
    /// As [`transport_out`](Self::transport_out).
    fn transport(
        &self,
        rng: &mut dyn RNG,
        params: Params,
        key: &dyn KeyMaterialTrait,
    ) -> Result<[u8; CT_LEN], KeyTransportError> {
        let mut ct = [0u8; CT_LEN];
        self.transport_out(rng, params, key, &mut ct)?;
        Ok(ct)
    }
}

/// A private key that recovers the keys transported to it under `Params`.
pub trait KeyTransportDecryptingKey<Params, const CT_LEN: usize> {
    /// The algorithm the key runs under these parameters.
    type Algorithm: KeyTransportAlgorithm;

    /// Recovers the key in `ct` into `key`, which is zeroized first and left so on an error,
    /// and returns its length in bytes. The key comes back as
    /// [`KeyType::CryptographicRandom`](crate::key_material::KeyType) at the lesser of the
    /// algorithm's strength and what its length carries: the scheme transports bytes, not their
    /// type, and does not say who sent them.
    ///
    /// # Errors
    /// [`KeyTransportError::DecryptionFailed`] if `ct` is not a ciphertext for this key under
    /// `params`, or holds a key longer than `N` bytes; the causes are not distinguished.
    fn recover_out<const N: usize>(
        &self,
        ct: &[u8; CT_LEN],
        params: Params,
        key: &mut KeyMaterial<N>,
    ) -> Result<usize, KeyTransportError>;
}
