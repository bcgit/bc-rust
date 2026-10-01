//! [`EncapsWithRandomness`]: ML-KEM.Encaps_internal with the randomness supplied by the caller.

use crate::mlkem::{MLKEM, MLKEM_RND_LEN, MLKEM_SS_LEN};
use crate::mlkem_keys::{
    MLKEMPrivateKeyInternalTrait, MLKEMPrivateKeyTrait, MLKEMPublicKeyInternalTrait,
    MLKEMPublicKeyTrait,
};
use crate::params::MLKEMParams;

// Imports needed for docs
#[allow(unused_imports)]
use crate::MLKEMPublicKeyExpanded;
#[allow(unused_imports)]
use bouncycastle_core::key_material::KeyMaterial;
#[allow(unused_imports)]
use bouncycastle_core::traits::KEMEncapsulator;
// end of imports needed for docs

/// FIPS 203 Algorithm 17, ML-KEM.Encaps_internal(ek, m), with `m` supplied by the caller.
///
/// # 🚨 Security 🚨
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
    /// The expanded public matrix `A_hat`; see [`MLKEMPublicKeyTrait::A_hat`].
    type MatrixA;

    /// Encapsulates to `ek` using `m` as the randomness, returning the shared secret and the
    /// ciphertext.
    ///
    /// `A_hat` is the public matrix expanded from `ek`, as [`MLKEMPublicKeyExpanded`] holds it;
    /// pass it when the same key is used for many encapsulations, or `None` to have it computed.
    fn encaps_with_randomness(
        ek: &PK,
        A_hat: Option<&Self::MatrixA>,
        m: [u8; MLKEM_RND_LEN],
    ) -> ([u8; MLKEM_SS_LEN], [u8; CT_LEN]);
}

impl<
    P: MLKEMParams,
    PK: MLKEMPublicKeyTrait<P, PK_LEN> + MLKEMPublicKeyInternalTrait<P, PK_LEN>,
    SK: MLKEMPrivateKeyTrait<P, PK, SK_LEN, PK_LEN>
        + MLKEMPrivateKeyInternalTrait<P, PK, SK_LEN, PK_LEN>,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const CT_LEN: usize,
    const SS_LEN: usize,
> EncapsWithRandomness<PK, CT_LEN> for MLKEM<P, PK, SK, PK_LEN, SK_LEN, CT_LEN, SS_LEN>
{
    type MatrixA = P::MatrixA;

    fn encaps_with_randomness(
        ek: &PK,
        A_hat: Option<&P::MatrixA>,
        m: [u8; MLKEM_RND_LEN],
    ) -> ([u8; MLKEM_SS_LEN], [u8; CT_LEN]) {
        Self::encaps_internal(ek, A_hat, m)
    }
}
