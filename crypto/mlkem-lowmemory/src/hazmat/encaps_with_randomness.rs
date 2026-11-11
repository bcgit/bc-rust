//! [`EncapsWithRandomness`]: ML-KEM.Encaps_internal with the randomness supplied by the caller.

use crate::mlkem::{MLKEM, MLKEM_RND_LEN, MLKEM_SS_LEN};
use crate::mlkem_keys::MLKEMPublicKey;
use crate::params::{CiphertextLen, MLKEMParams};

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_core::kem_key::EncapsulatingKey;
#[allow(unused_imports)]
use bouncycastle_core::key_material::KeyMaterial;
// end of imports needed for docs

/// FIPS 203 Algorithm 17, ML-KEM.Encaps_internal(ek, m), with `m` supplied by the caller.
///
/// # 🚨 Security Considerations 🚨
/// `m` is the encapsulation randomness, the message the underlying PKE encrypts. It must be 32
/// bytes of fresh, uniformly random, secret data for every call: any deterministic KEM, like any
/// deterministic encryption, fails every indistinguishability notion (IND-CPA, IND-CCA2), and a
/// predictable `m` hands an attacker the shared secret. [`EncapsulatingKey::encaps`] draws `m`
/// from the DRBG and is the method to use; this exists for known-answer tests and for
/// environments that must supply their own randomness.
///
/// The shared secret comes back as raw bytes rather than wrapped in a [`KeyMaterial`] with its
/// type and security strength set; handling it is up to the caller.
///
/// A trait rather than an inherent method so that the operation is only reachable with this
/// module's path in scope; see [`bouncycastle_core::hazmat`].
pub trait EncapsWithRandomness<const CT_LEN: usize> {
    /// Encapsulates to this key using `m` as the randomness, returning the shared secret and the
    /// ciphertext.
    fn encaps_with_randomness(&self, m: [u8; MLKEM_RND_LEN]) -> ([u8; MLKEM_SS_LEN], [u8; CT_LEN]);
}

impl<P: MLKEMParams + CiphertextLen<CT_LEN>, const CT_LEN: usize> EncapsWithRandomness<CT_LEN>
    for MLKEMPublicKey<P>
{
    fn encaps_with_randomness(&self, m: [u8; MLKEM_RND_LEN]) -> ([u8; MLKEM_SS_LEN], [u8; CT_LEN]) {
        // The public contract returns `K` by value; the internal path keeps it in a `Secret`.
        let (K, ct) = MLKEM::<P>::encaps_internal::<CT_LEN>(self, &m);
        (*K, ct)
    }
}
