//! The KEM roles of this crate's keys over [`HkdfParams`]: ML-KEM with its shared secret derived
//! through HKDF, the algorithms [`MLKEM512_HKDF_SHA256`], [`MLKEM768_HKDF_SHA512`] and
//! [`MLKEM1024_HKDF_SHA512`] of `bouncycastle_mlkem_common::hkdf`, which says what is derived
//! and why the ciphertext is not part of the info. A worker borrows the key, plain or expanded,
//! as the plain ML-KEM workers do, runs the plain ML-KEM operation and derives from its 𝐾
//! through the parameter set's [`MLKEMHkdfPairing`] with the hash of the parameters; a key is
//! paired with one hash, so the parameter type selects the algorithm and a hash the key is not
//! paired with is a compile error.

use crate::mlkem::MLKEM;
use crate::mlkem_keys::{
    MLKEMPrivateKey, MLKEMPrivateKeyExpanded, MLKEMPrivateKeyInternalTrait, MLKEMPublicKey,
    MLKEMPublicKeyExpanded, MLKEMPublicKeyInternalTrait,
};
use crate::params::{CiphertextLen, MLKEMParams};
use bouncycastle_core::errors::KEMError;
use bouncycastle_core::kem_key::{DecapsulatingKey, EncapsulatingKey};
use bouncycastle_core::key_material::KeyMaterial;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, KEMDecapsulator, KEMEncapsulator, RNG};
use bouncycastle_hkdf::HkdfParams;
use bouncycastle_hmac::HMACParams;
use bouncycastle_mlkem_common::hkdf::{MLKEMHkdfPairing, check_salt};
use core::marker::PhantomData;

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_mlkem_common::hkdf::{
    MLKEM512_HKDF_SHA256, MLKEM768_HKDF_SHA512, MLKEM1024_HKDF_SHA512,
};
// End imports needed for docs

/// The encapsulator an ML-KEM public key hands out through [`EncapsulatingKey`] over
/// [`HkdfParams`]: it borrows the key, plain or expanded, holds the parameters, and derives the
/// pairing's key from each encapsulation's 𝐾.
pub struct MLKEMHkdfEncapsulator<
    'k,
    'p,
    P: MLKEMParams,
    H: HMACParams,
    EK: MLKEMPublicKeyInternalTrait<P>,
    const SS_LEN: usize,
> {
    ek: &'k EK,
    params: HkdfParams<'p, H>,
    _phantom: PhantomData<P>,
}

impl<
    P: MLKEMParams + MLKEMHkdfPairing<H, SS_LEN>,
    H: HMACParams,
    EK: MLKEMPublicKeyInternalTrait<P>,
    const SS_LEN: usize,
> Algorithm for MLKEMHkdfEncapsulator<'_, '_, P, H, EK, SS_LEN>
{
    const ALG_NAME: &'static str = <P as MLKEMHkdfPairing<H, SS_LEN>>::Algorithm::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength =
        <P as MLKEMHkdfPairing<H, SS_LEN>>::Algorithm::MAX_SECURITY_STRENGTH;
}

impl<
    P: MLKEMParams + CiphertextLen<CT_LEN> + MLKEMHkdfPairing<H, SS_LEN>,
    H: HMACParams,
    EK: MLKEMPublicKeyInternalTrait<P>,
    const CT_LEN: usize,
    const SS_LEN: usize,
> KEMEncapsulator<CT_LEN, SS_LEN> for MLKEMHkdfEncapsulator<'_, '_, P, H, EK, SS_LEN>
{
    /// Algorithm 20 ML-KEM.Encaps(ek) for 𝐾 and the ciphertext, then the pairing's HKDF over 𝐾.
    fn encaps_out(
        &self,
        rng: &mut dyn RNG,
        ct: &mut [u8; CT_LEN],
    ) -> Result<(KeyMaterial<SS_LEN>, usize), KEMError> {
        let (K, written) = MLKEM::<P>::encaps_with_rng(self.ek, rng, ct)?;
        Ok((P::derive(self.params, &K)?, written))
    }
}

/// The decapsulator an ML-KEM private key hands out through [`DecapsulatingKey`] over
/// [`HkdfParams`]: it borrows the key, plain or expanded, holds the parameters, and derives the
/// pairing's key from the 𝐾 of each decapsulation.
pub struct MLKEMHkdfDecapsulator<
    'k,
    'p,
    P: MLKEMParams,
    H: HMACParams,
    DK: MLKEMPrivateKeyInternalTrait<P>,
    const SS_LEN: usize,
> {
    dk: &'k DK,
    params: HkdfParams<'p, H>,
    _phantom: PhantomData<P>,
}

impl<
    P: MLKEMParams + MLKEMHkdfPairing<H, SS_LEN>,
    H: HMACParams,
    DK: MLKEMPrivateKeyInternalTrait<P>,
    const SS_LEN: usize,
> Algorithm for MLKEMHkdfDecapsulator<'_, '_, P, H, DK, SS_LEN>
{
    const ALG_NAME: &'static str = <P as MLKEMHkdfPairing<H, SS_LEN>>::Algorithm::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength =
        <P as MLKEMHkdfPairing<H, SS_LEN>>::Algorithm::MAX_SECURITY_STRENGTH;
}

impl<
    P: MLKEMParams + CiphertextLen<CT_LEN> + MLKEMHkdfPairing<H, SS_LEN>,
    H: HMACParams,
    DK: MLKEMPrivateKeyInternalTrait<P>,
    const CT_LEN: usize,
    const SS_LEN: usize,
> KEMDecapsulator<CT_LEN, SS_LEN> for MLKEMHkdfDecapsulator<'_, '_, P, H, DK, SS_LEN>
{
    /// Algorithm 21 ML-KEM.Decaps(dk, 𝑐) for 𝐾, then the pairing's HKDF over it. ML-KEM rejects
    /// implicitly, so a damaged ciphertext yields a different key, not an error.
    fn decaps(&self, ct: &[u8; CT_LEN]) -> Result<KeyMaterial<SS_LEN>, KEMError> {
        let K = MLKEM::<P>::decaps_checked(self.dk, ct)?;
        P::derive(self.params, &K)
    }
}

impl<'p, P, H, const CT_LEN: usize, const SS_LEN: usize>
    EncapsulatingKey<HkdfParams<'p, H>, CT_LEN, SS_LEN> for MLKEMPublicKey<P>
where
    P: MLKEMParams + CiphertextLen<CT_LEN> + MLKEMHkdfPairing<H, SS_LEN>,
    H: HMACParams,
{
    type Algorithm = <P as MLKEMHkdfPairing<H, SS_LEN>>::Algorithm;
    type Encapsulator<'k>
        = MLKEMHkdfEncapsulator<'k, 'p, P, H, Self, SS_LEN>
    where
        P: 'k;

    /// Refuses a salt typed `Unknown` here, once, rather than at every encapsulation.
    fn create_encapsulator<'k>(
        &'k self,
        params: HkdfParams<'p, H>,
    ) -> Result<Self::Encapsulator<'k>, KEMError> {
        check_salt(&params)?;
        Ok(MLKEMHkdfEncapsulator { ek: self, params, _phantom: PhantomData })
    }
}

impl<'p, P, H, const CT_LEN: usize, const SS_LEN: usize>
    EncapsulatingKey<HkdfParams<'p, H>, CT_LEN, SS_LEN> for MLKEMPublicKeyExpanded<P>
where
    P: MLKEMParams + CiphertextLen<CT_LEN> + MLKEMHkdfPairing<H, SS_LEN>,
    H: HMACParams,
{
    type Algorithm = <P as MLKEMHkdfPairing<H, SS_LEN>>::Algorithm;
    type Encapsulator<'k>
        = MLKEMHkdfEncapsulator<'k, 'p, P, H, Self, SS_LEN>
    where
        P: 'k;

    /// Refuses a salt typed `Unknown` here, once, rather than at every encapsulation.
    fn create_encapsulator<'k>(
        &'k self,
        params: HkdfParams<'p, H>,
    ) -> Result<Self::Encapsulator<'k>, KEMError> {
        check_salt(&params)?;
        Ok(MLKEMHkdfEncapsulator { ek: self, params, _phantom: PhantomData })
    }
}

impl<'p, P, H, const CT_LEN: usize, const SS_LEN: usize>
    DecapsulatingKey<HkdfParams<'p, H>, CT_LEN, SS_LEN> for MLKEMPrivateKey<P>
where
    P: MLKEMParams + CiphertextLen<CT_LEN> + MLKEMHkdfPairing<H, SS_LEN>,
    H: HMACParams,
{
    type Algorithm = <P as MLKEMHkdfPairing<H, SS_LEN>>::Algorithm;
    type Decapsulator<'k>
        = MLKEMHkdfDecapsulator<'k, 'p, P, H, Self, SS_LEN>
    where
        P: 'k;

    /// Refuses a salt typed `Unknown` here, once, rather than at every decapsulation.
    fn create_decapsulator<'k>(
        &'k self,
        params: HkdfParams<'p, H>,
    ) -> Result<Self::Decapsulator<'k>, KEMError> {
        check_salt(&params)?;
        Ok(MLKEMHkdfDecapsulator { dk: self, params, _phantom: PhantomData })
    }
}

impl<'p, P, H, const CT_LEN: usize, const SS_LEN: usize>
    DecapsulatingKey<HkdfParams<'p, H>, CT_LEN, SS_LEN> for MLKEMPrivateKeyExpanded<P>
where
    P: MLKEMParams + CiphertextLen<CT_LEN> + MLKEMHkdfPairing<H, SS_LEN>,
    H: HMACParams,
{
    type Algorithm = <P as MLKEMHkdfPairing<H, SS_LEN>>::Algorithm;
    type Decapsulator<'k>
        = MLKEMHkdfDecapsulator<'k, 'p, P, H, Self, SS_LEN>
    where
        P: 'k;

    /// Refuses a salt typed `Unknown` here, once, rather than at every decapsulation.
    fn create_decapsulator<'k>(
        &'k self,
        params: HkdfParams<'p, H>,
    ) -> Result<Self::Decapsulator<'k>, KEMError> {
        check_salt(&params)?;
        Ok(MLKEMHkdfDecapsulator { dk: self, params, _phantom: PhantomData })
    }
}
