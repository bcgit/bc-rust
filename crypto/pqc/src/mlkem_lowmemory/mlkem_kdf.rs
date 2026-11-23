//! The KEM roles of this module's keys over [`KdfParams`]: ML-KEM with its shared secret derived
//! through a KDF, the algorithms [`MLKEM512_HKDF_SHA256`], [`MLKEM768_HKDF_SHA512`] and
//! [`MLKEM1024_HKDF_SHA512`] of `bouncycastle_pqc::mlkem_common::kdf`, which says what is derived
//! and why the ciphertext is not part of the info. A worker, which that module defines for both
//! ML-KEM modules, borrows the key, seed or expanded, as the plain ML-KEM workers do, runs the
//! key's plain ML-KEM operation and derives from its 𝐾 through the parameter set's
//! [`MLKEMKdfPairing`] with the KDF of the parameters; a key is paired with one KDF, so the
//! parameter type selects the algorithm and names the derived key's length, and a KDF the key is
//! not paired with is a compile error.

use crate::mlkem_common::kdf::{
    MLKEMKdfDecapsulator, MLKEMKdfPairing, PairedKdf, PlainDecaps, PlainEncaps,
};
use crate::mlkem_lowmemory::mlkem::{MLKEM, MLKEM_SS_LEN};
use crate::mlkem_lowmemory::mlkem_keys::{
    MLKEMPublicKey, MLKEMSeedPrivateKey, MLKEMSeedPrivateKeyExpanded,
};
use crate::mlkem_lowmemory::params::{CiphertextLen, MLKEMParams};
use bouncycastle_core::errors::KEMError;
use bouncycastle_core::kdf_params::{KdfDescription, KdfParams};
use bouncycastle_core::kem_key::{DecapsulatingKey, EncapsulatingKey};
use bouncycastle_core::key_material::KeyMaterial;
use bouncycastle_core::traits::RNG;

// Imports needed for docs
#[allow(unused_imports)]
use crate::mlkem_common::kdf::{MLKEM512_HKDF_SHA256, MLKEM768_HKDF_SHA512, MLKEM1024_HKDF_SHA512};
// End imports needed for docs

/// The encapsulator an ML-KEM public key hands out through [`EncapsulatingKey`] over
/// [`KdfParams`]: it borrows the key, holds the parameters, and derives the pairing's key from
/// each encapsulation's 𝐾.
pub type MLKEMKdfEncapsulator<'k, 'p, P, D, const SS_LEN: usize> =
    crate::mlkem_common::kdf::MLKEMKdfEncapsulator<'k, 'p, P, D, MLKEMPublicKey<P>, SS_LEN>;

impl<P: MLKEMParams + CiphertextLen<CT_LEN>, const CT_LEN: usize> PlainEncaps<CT_LEN>
    for MLKEMPublicKey<P>
{
    // Inlined so that the encapsulation's frames merge into the worker's one-shot instead of
    // stacking under it; the KDF rows of the ML-KEM stack harness show the difference.
    #[inline(always)]
    fn encaps_K(
        &self,
        rng: &mut dyn RNG,
        ct: &mut [u8; CT_LEN],
    ) -> Result<(KeyMaterial<MLKEM_SS_LEN>, usize), KEMError> {
        MLKEM::<P>::encaps_with_rng(self, rng, ct)
    }
}

impl<P: MLKEMParams + CiphertextLen<CT_LEN>, const CT_LEN: usize> PlainDecaps<CT_LEN>
    for MLKEMSeedPrivateKey<P>
{
    fn decaps_K(&self, ct: &[u8; CT_LEN]) -> Result<KeyMaterial<MLKEM_SS_LEN>, KEMError> {
        MLKEM::<P>::decaps_checked(self, ct)
    }
}

impl<P: MLKEMParams + CiphertextLen<CT_LEN>, const CT_LEN: usize> PlainDecaps<CT_LEN>
    for MLKEMSeedPrivateKeyExpanded<P>
{
    fn decaps_K(&self, ct: &[u8; CT_LEN]) -> Result<KeyMaterial<MLKEM_SS_LEN>, KEMError> {
        MLKEM::<P>::decaps_checked(self, ct)
    }
}

impl<'p, P, D, const CT_LEN: usize, const SS_LEN: usize>
    EncapsulatingKey<KdfParams<'p, D, SS_LEN>, CT_LEN, SS_LEN> for MLKEMPublicKey<P>
where
    P: MLKEMParams + CiphertextLen<CT_LEN> + MLKEMKdfPairing<D, SS_LEN>,
    D: KdfDescription + PairedKdf + ?Sized,
{
    type Algorithm = <P as MLKEMKdfPairing<D, SS_LEN>>::Algorithm;
    type Encapsulator<'k>
        = MLKEMKdfEncapsulator<'k, 'p, P, D, SS_LEN>
    where
        P: 'k;

    /// The length is checked at compile time; a KDF validated what it was made from, and
    /// refuses at the derivation an instance that has since absorbed input.
    fn create_encapsulator<'k>(
        &'k self,
        params: KdfParams<'p, D, SS_LEN>,
    ) -> Result<Self::Encapsulator<'k>, KEMError> {
        Ok(MLKEMKdfEncapsulator::new(self, params))
    }
}

impl<'p, P, D, const CT_LEN: usize, const SS_LEN: usize>
    DecapsulatingKey<KdfParams<'p, D, SS_LEN>, CT_LEN, SS_LEN> for MLKEMSeedPrivateKey<P>
where
    P: MLKEMParams + CiphertextLen<CT_LEN> + MLKEMKdfPairing<D, SS_LEN>,
    D: KdfDescription + PairedKdf + ?Sized,
{
    type Algorithm = <P as MLKEMKdfPairing<D, SS_LEN>>::Algorithm;
    type Decapsulator<'k>
        = MLKEMKdfDecapsulator<'k, 'p, P, D, Self, SS_LEN>
    where
        P: 'k;

    /// The length is checked at compile time; a KDF validated what it was made from, and
    /// refuses at the derivation an instance that has since absorbed input.
    fn create_decapsulator<'k>(
        &'k self,
        params: KdfParams<'p, D, SS_LEN>,
    ) -> Result<Self::Decapsulator<'k>, KEMError> {
        Ok(MLKEMKdfDecapsulator::new(self, params))
    }
}

impl<'p, P, D, const CT_LEN: usize, const SS_LEN: usize>
    DecapsulatingKey<KdfParams<'p, D, SS_LEN>, CT_LEN, SS_LEN> for MLKEMSeedPrivateKeyExpanded<P>
where
    P: MLKEMParams + CiphertextLen<CT_LEN> + MLKEMKdfPairing<D, SS_LEN>,
    D: KdfDescription + PairedKdf + ?Sized,
{
    type Algorithm = <P as MLKEMKdfPairing<D, SS_LEN>>::Algorithm;
    type Decapsulator<'k>
        = MLKEMKdfDecapsulator<'k, 'p, P, D, Self, SS_LEN>
    where
        P: 'k;

    /// The length is checked at compile time; a KDF validated what it was made from, and
    /// refuses at the derivation an instance that has since absorbed input.
    fn create_decapsulator<'k>(
        &'k self,
        params: KdfParams<'p, D, SS_LEN>,
    ) -> Result<Self::Decapsulator<'k>, KEMError> {
        Ok(MLKEMKdfDecapsulator::new(self, params))
    }
}
