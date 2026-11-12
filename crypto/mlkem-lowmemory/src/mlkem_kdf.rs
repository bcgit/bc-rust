//! The KEM roles of this crate's keys over [`KdfParams`]: ML-KEM with its shared secret derived
//! through a KDF, the algorithms [`MLKEM512_HKDF_SHA256`], [`MLKEM768_HKDF_SHA512`] and
//! [`MLKEM1024_HKDF_SHA512`] of `bouncycastle_mlkem_common::kdf`, which says what is derived
//! and why the ciphertext is not part of the info. A worker borrows the key, seed or expanded,
//! as the plain ML-KEM workers do, runs the plain ML-KEM operation and derives from its 𝐾
//! through the parameter set's [`MLKEMKdfPairing`] with the KDF of the parameters; a key is
//! paired with one KDF, so the parameter type selects the algorithm and names the derived key's
//! length, and a KDF the key is not paired with is a compile error.

use crate::mlkem::MLKEM;
use crate::mlkem_keys::{
    MLKEMPrivateKeyInternalTrait, MLKEMPublicKey, MLKEMSeedPrivateKey, MLKEMSeedPrivateKeyExpanded,
};
use crate::params::{CiphertextLen, MLKEMParams};
use bouncycastle_core::errors::KEMError;
use bouncycastle_core::kdf_params::{KdfDescription, KdfParams};
use bouncycastle_core::kem_key::{DecapsulatingKey, EncapsulatingKey};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, KEMDecapsulator, KEMEncapsulator, RNG};
use bouncycastle_mlkem_common::kdf::{MLKEMKdfPairing, PairedKdf};
use core::marker::PhantomData;

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_mlkem_common::kdf::{
    MLKEM512_HKDF_SHA256, MLKEM768_HKDF_SHA512, MLKEM1024_HKDF_SHA512,
};
// End imports needed for docs

/// The encapsulator an ML-KEM public key hands out through [`EncapsulatingKey`] over
/// [`KdfParams`]: it borrows the key, holds the parameters, and derives the pairing's key from
/// each encapsulation's 𝐾.
pub struct MLKEMKdfEncapsulator<
    'k,
    'p,
    P: MLKEMParams,
    D: KdfDescription + PairedKdf + ?Sized,
    const SS_LEN: usize,
> {
    ek: &'k MLKEMPublicKey<P>,
    params: KdfParams<'p, D, SS_LEN>,
}

impl<
    P: MLKEMParams + MLKEMKdfPairing<D, SS_LEN>,
    D: KdfDescription + PairedKdf + ?Sized,
    const SS_LEN: usize,
> Algorithm for MLKEMKdfEncapsulator<'_, '_, P, D, SS_LEN>
{
    const ALG_NAME: &'static str = <P as MLKEMKdfPairing<D, SS_LEN>>::Algorithm::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength =
        <P as MLKEMKdfPairing<D, SS_LEN>>::Algorithm::MAX_SECURITY_STRENGTH;
}

impl<
    P: MLKEMParams + CiphertextLen<CT_LEN> + MLKEMKdfPairing<D, SS_LEN>,
    D: KdfDescription + PairedKdf + ?Sized,
    const CT_LEN: usize,
    const SS_LEN: usize,
> KEMEncapsulator<CT_LEN, SS_LEN> for MLKEMKdfEncapsulator<'_, '_, P, D, SS_LEN>
{
    /// Algorithm 20 ML-KEM.Encaps(ek) for 𝐾 and the ciphertext, then the pairing's KDF over 𝐾.
    fn encaps_out(
        &self,
        rng: &mut dyn RNG,
        ct: &mut [u8; CT_LEN],
        ss: &mut KeyMaterial<SS_LEN>,
    ) -> Result<usize, KEMError> {
        ss.zeroize();
        let (K, written) = MLKEM::<P>::encaps_with_rng(self.ek, rng, ct)?;
        // A ciphertext for a secret the caller never gets is not left in the buffer; `derive`
        // leaves `ss` zeroized on its errors.
        if let Err(e) = P::derive(self.params, &K, ss) {
            ct.fill(0);
            return Err(e);
        }
        Ok(written)
    }
}

/// The decapsulator an ML-KEM private key hands out through [`DecapsulatingKey`] over
/// [`KdfParams`]: it borrows the key, seed or expanded, holds the parameters, and derives the
/// pairing's key from the 𝐾 of each decapsulation.
pub struct MLKEMKdfDecapsulator<
    'k,
    'p,
    P: MLKEMParams,
    D: KdfDescription + PairedKdf + ?Sized,
    DK: MLKEMPrivateKeyInternalTrait<P>,
    const SS_LEN: usize,
> {
    dk: &'k DK,
    params: KdfParams<'p, D, SS_LEN>,
    _phantom: PhantomData<P>,
}

impl<
    P: MLKEMParams + MLKEMKdfPairing<D, SS_LEN>,
    D: KdfDescription + PairedKdf + ?Sized,
    DK: MLKEMPrivateKeyInternalTrait<P>,
    const SS_LEN: usize,
> Algorithm for MLKEMKdfDecapsulator<'_, '_, P, D, DK, SS_LEN>
{
    const ALG_NAME: &'static str = <P as MLKEMKdfPairing<D, SS_LEN>>::Algorithm::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength =
        <P as MLKEMKdfPairing<D, SS_LEN>>::Algorithm::MAX_SECURITY_STRENGTH;
}

impl<
    P: MLKEMParams + CiphertextLen<CT_LEN> + MLKEMKdfPairing<D, SS_LEN>,
    D: KdfDescription + PairedKdf + ?Sized,
    DK: MLKEMPrivateKeyInternalTrait<P>,
    const CT_LEN: usize,
    const SS_LEN: usize,
> KEMDecapsulator<CT_LEN, SS_LEN> for MLKEMKdfDecapsulator<'_, '_, P, D, DK, SS_LEN>
{
    /// Algorithm 21 ML-KEM.Decaps(dk, 𝑐) for 𝐾, then the pairing's KDF over it. ML-KEM rejects
    /// implicitly, so a damaged ciphertext yields a different key, not an error.
    fn decaps_out(
        &self,
        ct: &[u8; CT_LEN],
        ss: &mut KeyMaterial<SS_LEN>,
    ) -> Result<usize, KEMError> {
        ss.zeroize();
        let K = MLKEM::<P>::decaps_checked(self.dk, ct)?;
        P::derive(self.params, &K, ss)?;
        Ok(SS_LEN)
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
        const { P::LEN_CHECK };
        Ok(MLKEMKdfEncapsulator { ek: self, params })
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
        const { P::LEN_CHECK };
        Ok(MLKEMKdfDecapsulator { dk: self, params, _phantom: PhantomData })
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
        const { P::LEN_CHECK };
        Ok(MLKEMKdfDecapsulator { dk: self, params, _phantom: PhantomData })
    }
}
