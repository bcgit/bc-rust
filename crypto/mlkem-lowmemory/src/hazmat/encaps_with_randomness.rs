//! [`EncapsWithRandomness`]: ML-KEM.Encaps_internal with the randomness supplied by the caller.

use crate::mlkem::{MLKEM, MLKEM_RND_LEN, MLKEM_SS_LEN};
use crate::mlkem_keys::{
    MLKEMPrivateKeyInternalTrait, MLKEMPrivateKeyTrait, MLKEMPublicKeyInternalTrait,
    MLKEMPublicKeyTrait,
};
use crate::params::MLKEMParams;

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_core::key_material::KeyMaterial;
#[allow(unused_imports)]
use bouncycastle_core::traits::KEMEncapsulator;
// end of imports needed for docs

/// FIPS 203 Algorithm 17, ML-KEM.Encaps_internal(ek, m), with `m` supplied by the caller.
///
/// # 🚨 Security Considerations 🚨
/// `m` is the encapsulation randomness, the message the underlying PKE encrypts. It must be 32
/// bytes of fresh, uniformly random, secret data for every call: any deterministic KEM, like any
/// deterministic encryption, fails every indistinguishability notion (IND-CPA, IND-CCA2), and a
/// predictable `m` hands an attacker the shared secret. [`KEMEncapsulator::encaps`] draws `m` from
/// the DRBG and is the function to use; this exists for known-answer tests and for environments
/// that must supply their own randomness.
///
/// The shared secret comes back as raw bytes rather than wrapped in a [`KeyMaterial`] with its
/// type and security strength set; handling it is up to the caller.
///
/// A trait rather than an inherent method so that the operation is only reachable with this
/// module's path in scope; see [`bouncycastle_core::hazmat`].
pub trait EncapsWithRandomness<PK, const CT_LEN: usize> {
    /// Encapsulates to `ek` using `m` as the randomness, returning the shared secret and the
    /// ciphertext.
    fn encaps_with_randomness(
        ek: &PK,
        m: [u8; MLKEM_RND_LEN],
    ) -> ([u8; MLKEM_SS_LEN], [u8; CT_LEN]);
}

impl<
    P: MLKEMParams,
    PK: MLKEMPublicKeyTrait<P, PK_LEN> + MLKEMPublicKeyInternalTrait<P, PK_LEN>,
    SK: MLKEMPrivateKeyTrait<P, SK_LEN, FULL_SK_LEN, PK_LEN>
        + MLKEMPrivateKeyInternalTrait<P, SK_LEN, PK_LEN>,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const FULL_SK_LEN: usize,
    const CT_LEN: usize,
    const SS_LEN: usize,
> EncapsWithRandomness<PK, CT_LEN>
    for MLKEM<P, PK, SK, PK_LEN, SK_LEN, FULL_SK_LEN, CT_LEN, SS_LEN>
{
    fn encaps_with_randomness(
        ek: &PK,
        m: [u8; MLKEM_RND_LEN],
    ) -> ([u8; MLKEM_SS_LEN], [u8; CT_LEN]) {
        Self::encaps_internal(ek, m)
    }
}
