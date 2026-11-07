//! ECC CDH with a KDF over `Z`: SP 800-56A Rev. 3 Section 5.8's derivation, and SEC 1 Section
//! 6.1's ECDH scheme for the X9.63 KDF, as the pairing of a curve with a KDF that each curve's
//! keys implement the agreement role over, with
//! [`KdfParams`] as the parameters: a borrowed KDF
//! instance and the fixed info (RFC 5869's info, SEC 1's `SharedInfo`). The derived key is
//! KDF(Z, info), one hash output long, at the curve's strength, which the KDF caps at.
//!
//! The pairings are one `impl KdfPairing<KDF, SS_LEN> for Curve` each, in the curve's module:
//! the X9.63 KDF over the hash matched to the curve on every curve, and HKDF-SHA256 on P-256.
//! A key under a KDF its curve is not paired with has no role, so the wrong KDF is a compile
//! error; a further pairing is one marker and one impl.

use bouncycastle_core::agreement_key::KeyAgreementAlgorithm;
use bouncycastle_core::errors::KeyAgreementError;
use bouncycastle_core::kdf_params::KdfParams;
use bouncycastle_core::key_material::KeyMaterial;
use bouncycastle_core::traits::KDF;

/// A curve paired with a KDF: `Curve: KdfPairing<D, SS_LEN>` has one solution per curve and KDF,
/// so the curve's role impl, generic over `D` and `SS_LEN` and bound on it, infers both from the
/// parameter type. Sealed: the pairings are the library's.
pub trait KdfPairing<D: KDF + ?Sized, const SS_LEN: usize>:
    KeyAgreementAlgorithm + sealed::Sealed
{
    /// The algorithm the pairing is.
    type Algorithm: KeyAgreementAlgorithm;
}

/// KDF(Z, info) into a key of `SS_LEN` bytes: `Z` is typed `SharedSecret`, which the KDF credits.
pub(crate) fn derive<D: KDF + ?Sized, const Z_LEN: usize, const SS_LEN: usize>(
    params: KdfParams<'_, D>,
    z: &KeyMaterial<Z_LEN>,
) -> Result<KeyMaterial<SS_LEN>, KeyAgreementError> {
    let mut okm = KeyMaterial::new();
    params
        .kdf()
        .derive_key_out(z, params.info(), SS_LEN, &mut okm)
        .map_err(|_| KeyAgreementError::GenericError("the KDF over Z failed"))?;
    Ok(okm)
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for crate::eccdh_p256::ECCDHP256 {}
    impl Sealed for crate::eccdh_p384::ECCDHP384 {}
    impl Sealed for crate::eccdh_p521::ECCDHP521 {}
    impl Sealed for crate::eccdh_p256k1::ECCDHSecp256K1 {}
    impl Sealed for crate::eccdh_bp256r1::ECCDHBp256r1 {}
    impl Sealed for crate::eccdh_bp384r1::ECCDHBp384r1 {}
    impl Sealed for crate::eccdh_bp512r1::ECCDHBp512r1 {}
}
