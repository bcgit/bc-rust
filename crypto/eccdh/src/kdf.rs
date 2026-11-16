//! ECC CDH with a KDF over `Z`: SP 800-56A Rev. 3 Section 5.8's derivation, and SEC 1 Section
//! 6.1's ECDH scheme for the X9.63 KDF, as the pairing of a curve with a KDF that each curve's
//! keys implement the agreement role over, with
//! [`KdfParams`] as the parameters: a borrowed KDF
//! instance, the fixed info (RFC 5869's info, SEC 1's `SharedInfo`) and the length. The derived
//! key is KDF(Z, info), of the length the parameters name, at the curve's strength, which the
//! KDF caps at. The length is part of the protocol's agreement as the info is, and it does not
//! separate keys: under one info the key at one length is a prefix of the key at a longer one
//! (RFC 5869 Section 2.3's OKM is the first L octets of T; SEC 1 v2 Section 3.6.1 step 5's K
//! the leftmost keydatalen octets of K1 || K2 || ..), so a protocol that wants two keys from
//! one agreement gives them two infos, not two lengths (SP 800-56C Rev. 2 Section 4.1 puts `L`
//! in `FixedInfo` for that reason).
//!
//! The pairings are `impl KdfPairing<KDF, SS_LEN> for ECCDH<C>` in [`crate::eccdh`]: the X9.63
//! KDF and the NIST concatenation KDF over the hash matched to the curve
//! ([`MatchedHash`](crate::eccdh::MatchedHash)) on every curve, and HKDF-SHA256 on P-256.
//! A key under a KDF its curve is not paired with has no role, so the wrong KDF is a compile
//! error; a further pairing is one marker and one impl.
//!
//! The derived key is typed by the KDF's accounting ([`KDF`]'s docs): `CryptographicRandom` at
//! the least of the curve's strength, the KDF's and the length's, so a key shorter than 14
//! bytes carries no strength although the algorithm's `MAX_SECURITY_STRENGTH` is the curve's.
//! An all-zero `Z` (`x_P = 0`, on the curve for P-256, P-384 and P-521 and not arrangeable
//! without `d`) reaches the KDF typed `Zeroized` and credits nothing: the X9.63 and
//! concatenation roles, and HKDF with an empty salt, return a key typed `Unknown` with no
//! strength, while HKDF with a `MACKey` salt credits the salt and returns `CryptographicRandom`
//! (a salt of any other type is credited nothing, as HKDF's docs say).
//! None of that is an error.
//!
//! The length is checked when a role is instantiated, in codegen rather than type checking, so
//! `cargo check` passes what `cargo build` refuses: a zero length,
//!
//! ```compile_fail
//! use bouncycastle_core::agreement_key::AgreementKey;
//! use bouncycastle_core::kdf_params::{KdfParams, KeyLen};
//! use bouncycastle_ec::P256;
//! use bouncycastle_eccdh::keys::keygen;
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_x963kdf::X963KDF_SHA256;
//!
//! let (pk, sk) = keygen::<P256>(&mut HashDRBG_SHA512::new_from_os()).unwrap();
//! let kdf = X963KDF_SHA256::new();
//! let _ = sk.agree(&pk, KdfParams::new(&kdf, b"", KeyLen::<0>));
//! ```
//!
//! and one past the KDF's [`PairedKdf::MAX_LEN`], 255 hash outputs for HKDF-SHA256:
//!
//! ```compile_fail
//! use bouncycastle_core::agreement_key::AgreementKey;
//! use bouncycastle_core::kdf_params::{KdfParams, KeyLen};
//! use bouncycastle_ec::P256;
//! use bouncycastle_eccdh::keys::keygen;
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_hkdf::HkdfDescription;
//!
//! let (pk, sk) = keygen::<P256>(&mut HashDRBG_SHA512::new_from_os()).unwrap();
//! let hkdf = HKDF_SHA256::new();
//! let _ = sk.agree(&pk, KdfParams::new(&hkdf, b"", KeyLen::<8161>));
//! ```

use bouncycastle_concatkdf::{ConcatKDF, ConcatKDFParams};
use bouncycastle_core::agreement_key::KeyAgreementAlgorithm;
use bouncycastle_core::errors::KeyAgreementError;
use bouncycastle_core::kdf_params::{KdfDescription, KdfParams};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait};
use bouncycastle_core::traits::{HashAlgParams, KDF};
use bouncycastle_hkdf::HkdfDescription;
use bouncycastle_sha2::SHA256;
use bouncycastle_x963kdf::{X963KDF, X963KDFParams};

/// A KDF the library pairs a curve with, by its description: HKDF-SHA256, the X9.63 KDFs and the
/// concatenation KDFs. Sealed, so that the
/// pairing trait, generic over the KDF, cannot be implemented outside this crate under a name
/// and strength of a downstream crate's choosing.
pub trait PairedKdf: sealed::Sealed {
    /// The most bytes one derivation produces: 255 hash outputs for HKDF (RFC 5869 Section
    /// 2.3); below `hashlen * (2^32 - 1)` for the X9.63 KDF (SEC 1 v2 Section 3.6.1 step 2); at
    /// most `2^32 - 1` hash outputs for the concatenation KDF (SP 800-56C Rev. 2 Section 4.1
    /// step 2).
    const MAX_LEN: usize;
}

impl PairedKdf for HkdfDescription<'_, SHA256> {
    const MAX_LEN: usize = 255 * SHA256::OUTPUT_LEN;
}

impl<H: X963KDFParams> PairedKdf for X963KDF<H> {
    const MAX_LEN: usize = x963_max_len(H::OUTPUT_LEN);
}

impl<H: ConcatKDFParams> PairedKdf for ConcatKDF<H> {
    const MAX_LEN: usize = ConcatKDF::<H>::MAX_LEN;
}

/// `hashlen * (2^32 - 1) - 1`, or `usize::MAX` where that does not fit.
const fn x963_max_len(hash_len: usize) -> usize {
    let max = hash_len as u128 * 0xFFFF_FFFF - 1;
    if max > usize::MAX as u128 { usize::MAX } else { max as usize }
}

/// A curve paired with a KDF: `ECCDH<C>: KdfPairing<D, SS_LEN>` has one solution per curve, KDF
/// and length, so the role impl, generic over `D` and `SS_LEN` and bound on it, takes
/// both from the parameter type, `KdfParams<'p, D, SS_LEN>`. The length is the caller's, from
/// one byte to the KDF's [`PairedKdf::MAX_LEN`], checked when the role is instantiated. Sealed
/// on both sides: the pairings are the library's.
pub trait KdfPairing<D: KdfDescription + PairedKdf + ?Sized, const SS_LEN: usize>:
    KeyAgreementAlgorithm + sealed::Sealed
{
    /// The algorithm the pairing is.
    type Algorithm: KeyAgreementAlgorithm;
}

/// KDF(Z, info) into `out`, zeroized first, a key of `SS_LEN` bytes: `Z` is typed
/// `SharedSecret`, which the KDF credits. The caller's buffer is where the key lives.
///
/// # Errors
/// [`KeyAgreementError::KDFError`] with the KDF's own error if it refuses to be built from the
/// description or refuses the derivation, and
/// [`KeyAgreementError::GenericError`] if it writes anything but `SS_LEN` bytes; `out` is left
/// zeroized.
pub(crate) fn derive<
    D: KdfDescription + PairedKdf + ?Sized,
    const Z_LEN: usize,
    const SS_LEN: usize,
>(
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
    out.zeroize();
    // The engine is built from the description for this derivation: for HKDF, an instance keyed
    // with the salt. `derive_key_out` zeroizes `out` first and leaves it so on its errors.
    let kdf = params.kdf().engine()?;
    let written = kdf.derive_key_out(z, params.info(), SS_LEN, out)?;
    if written != SS_LEN || out.key_len() != SS_LEN {
        out.zeroize();
        return Err(KeyAgreementError::GenericError("the KDF derived a key of the wrong length"));
    }
    Ok(())
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for bouncycastle_hkdf::HkdfDescription<'_, bouncycastle_sha2::SHA256> {}
    impl<H: bouncycastle_x963kdf::X963KDFParams> Sealed for bouncycastle_x963kdf::X963KDF<H> {}
    impl<H: bouncycastle_concatkdf::ConcatKDFParams> Sealed for bouncycastle_concatkdf::ConcatKDF<H> {}
    impl<C: bouncycastle_ec::curve::Curve> Sealed for crate::eccdh::ECCDH<C> {}
}
