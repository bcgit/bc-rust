//! ECC CDH with a KDF over `Z`: SP 800-56A Rev. 3 Section 5.8's derivation, and SEC 1 Section
//! 6.1's ECDH scheme for the X9.63 KDF, as the pairing of a curve with a KDF that each curve's
//! keys implement the agreement role over, with
//! [`KdfParams`] as the parameters: a borrowed KDF
//! instance, the fixed info (RFC 5869's info, SEC 1's `SharedInfo`) and the length. The derived
//! key is KDF(Z, info), of the length the parameters name, at the curve's strength, which the
//! KDF caps at.
//!
//! The pairings are one `impl KdfPairing<KDF, SS_LEN> for Curve` each, in the curve's module:
//! the X9.63 KDF over the hash matched to the curve on every curve, and HKDF-SHA256 on P-256.
//! A key under a KDF its curve is not paired with has no role, so the wrong KDF is a compile
//! error; a further pairing is one marker and one impl.

use bouncycastle_core::agreement_key::KeyAgreementAlgorithm;
use bouncycastle_core::errors::KeyAgreementError;
use bouncycastle_core::kdf_params::KdfParams;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait};
use bouncycastle_core::traits::{HashAlgParams, KDF};
use bouncycastle_sha2::SHA256;
use bouncycastle_sha2::hkdf::HKDF_SHA256;
use bouncycastle_x963kdf::{X963KDF, X963KDFParams};

/// A KDF the library pairs a curve with: HKDF-SHA256 and the X9.63 KDFs. Sealed, so that the
/// pairing trait, generic over the KDF, cannot be implemented outside this crate under a name
/// and strength of a downstream crate's choosing.
pub trait PairedKdf: sealed::Sealed {
    /// The most bytes one derivation produces: 255 hash outputs for HKDF (RFC 5869 Section
    /// 2.3); below `hashlen * (2^32 - 1)` for the X9.63 KDF (SEC 1 v2 Section 3.6.1 step 2).
    const MAX_LEN: usize;
}

impl PairedKdf for HKDF_SHA256 {
    const MAX_LEN: usize = 255 * SHA256::OUTPUT_LEN;
}

impl<H: X963KDFParams> PairedKdf for X963KDF<H> {
    const MAX_LEN: usize = x963_max_len(H::OUTPUT_LEN);
}

/// `hashlen * (2^32 - 1) - 1`, or `usize::MAX` where that does not fit.
const fn x963_max_len(hash_len: usize) -> usize {
    let max = hash_len as u128 * 0xFFFF_FFFF - 1;
    if max > usize::MAX as u128 { usize::MAX } else { max as usize }
}

/// A curve paired with a KDF: `Curve: KdfPairing<D, SS_LEN>` has one solution per curve, KDF
/// and length, so the curve's role impl, generic over `D` and `SS_LEN` and bound on it, takes
/// both from the parameter type, `KdfParams<'p, D, SS_LEN>`. The length is the caller's, from
/// one byte to the KDF's [`PairedKdf::MAX_LEN`], checked when the role is instantiated. Sealed
/// on both sides: the pairings are the library's.
pub trait KdfPairing<D: KDF + PairedKdf + ?Sized, const SS_LEN: usize>:
    KeyAgreementAlgorithm + sealed::Sealed
{
    /// The algorithm the pairing is.
    type Algorithm: KeyAgreementAlgorithm;
}

/// KDF(Z, info) into `out`, zeroized first, a key of `SS_LEN` bytes: `Z` is typed
/// `SharedSecret`, which the KDF credits. The caller's buffer is where the key lives.
///
/// # Errors
/// [`KeyAgreementError::GenericError`] if the KDF refuses the derivation or writes anything but
/// `SS_LEN` bytes; `out` is left zeroized.
pub(crate) fn derive<D: KDF + PairedKdf + ?Sized, const Z_LEN: usize, const SS_LEN: usize>(
    params: KdfParams<'_, D, SS_LEN>,
    z: &KeyMaterial<Z_LEN>,
    out: &mut KeyMaterial<SS_LEN>,
) -> Result<(), KeyAgreementError> {
    const {
        assert!(
            SS_LEN > 0 && SS_LEN <= D::MAX_LEN,
            "the derived key is from one byte to the KDF's MAX_LEN long"
        )
    };
    // `derive_key_out` zeroizes `out` first and leaves it so on its errors.
    let written = params
        .kdf()
        .derive_key_out(z, params.info(), SS_LEN, out)
        .map_err(|_| KeyAgreementError::GenericError("the KDF over Z failed"))?;
    if written != SS_LEN || out.key_len() != SS_LEN {
        out.zeroize();
        return Err(KeyAgreementError::GenericError("the KDF derived a key of the wrong length"));
    }
    Ok(())
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for bouncycastle_sha2::hkdf::HKDF_SHA256 {}
    impl<H: bouncycastle_x963kdf::X963KDFParams> Sealed for bouncycastle_x963kdf::X963KDF<H> {}
    impl Sealed for crate::eccdh_p256::ECCDHP256 {}
    impl Sealed for crate::eccdh_p384::ECCDHP384 {}
    impl Sealed for crate::eccdh_p521::ECCDHP521 {}
    impl Sealed for crate::eccdh_p256k1::ECCDHSecp256K1 {}
    impl Sealed for crate::eccdh_bp256r1::ECCDHBp256r1 {}
    impl Sealed for crate::eccdh_bp384r1::ECCDHBp384r1 {}
    impl Sealed for crate::eccdh_bp512r1::ECCDHBp512r1 {}
}
