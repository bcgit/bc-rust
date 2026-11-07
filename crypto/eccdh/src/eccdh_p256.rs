//! The ECC CDH primitive over P-256 (SP 800-56A Rev. 3 Section 5.7.1.2) on the key-agreement
//! roles of [`bouncycastle_core::agreement_key`]: the marker [`ECCDHP256`], the worker a private
//! key hands out, and the role impl over `()`. The same keys implement the
//! role a second time over [`HkdfParams<'p, SHA256>`] as [`ECCDHP256_HKDF_SHA256`]: `Z` through
//! HKDF-SHA256, the two-step key-derivation method of SP 800-56C Rev. 2 Section 5.1, with the
//! caller's salt and info; the hash on the parameter type selects the algorithm at the call.

use crate::keys_p256::{ECCDHP256PrivateKey, ECCDHP256PublicKey};
use bouncycastle_core::agreement_key::{AgreementKey, KeyAgreementAlgorithm};
use bouncycastle_core::errors::{KeyAgreementError, KeyMaterialError};
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, KeyAgreement};
use bouncycastle_ec::hazmat::p256::P256FieldElement;
use bouncycastle_ec::hazmat::p256_mul::multiply_point;
use bouncycastle_ec::hazmat::p256_point::P256JacobianPoint;
use bouncycastle_ec::hazmat::p256_sec1;
use bouncycastle_hkdf::HkdfParams;
use bouncycastle_sha2::SHA256;
use bouncycastle_sha2::hkdf::HKDF_SHA256;
use bouncycastle_utils::secret::Secret;

/// Length of the shared secret `Z`: Appendix C.2's field-element-to-byte-string conversion of
/// `x_P`, `ceil(log2 p / 8)` = 32 bytes.
pub const SS_LEN: usize = 32;

/// ECC CDH over P-256: the algorithm a [`ECCDHP256PrivateKey`] runs when made into a worker from
/// `()`. The cofactor is 1 (SP 800-186 Section 3.2.1.3 (P-256; Section 3.2.1: "For pseudorandom curves, the cofactor h = 1")), so `Z` is the same value plain ECDH gives; what the name says
/// is that the peer key was fully validated and the identity checked, as Section 5.7.1.2 asks.
pub struct ECCDHP256;

impl Algorithm for ECCDHP256 {
    const ALG_NAME: &'static str = "ECC-CDH-P256";
    /// SP 800-57 Part 1 Rev. 5 Table 2: a 256-bit curve order gives 128 bits.
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

impl KeyAgreementAlgorithm for ECCDHP256 {}

/// The worker [`AgreementKey::create_agreement`] hands out: the own key, borrowed. Reusable
/// against any number of peers, as a static key is in SP 800-56A Rev. 3 Section 6.2's schemes.
pub struct ECCDHP256Agreement<'k> {
    sk: &'k ECCDHP256PrivateKey,
}

impl Algorithm for ECCDHP256Agreement<'_> {
    const ALG_NAME: &'static str = ECCDHP256::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = ECCDHP256::MAX_SECURITY_STRENGTH;
}

/// `x * z^-2`, branch-free: the affine x of a Jacobian point without
/// [`P256JacobianPoint::to_affine`]'s branch on the identity, which the caller tests separately.
fn x_affine(point: &P256JacobianPoint) -> P256FieldElement {
    let mut z_inv = point.z.invert();
    let x = point.x.mul(&z_inv.mul(&z_inv));
    z_inv.zeroize();
    x
}

/// SP 800-56A Rev. 3 Section 5.7.1.2, the ECC CDH primitive, with `d` this worker's key and `Q`
/// the peer's. Returns `Z` typed [`KeyType::SharedSecret`] at the curve's strength: keying
/// material for a KDF (Section 5.8), which nothing else accepts as a key.
#[allow(non_snake_case)] // `z` and `Z` are Section 5.7.1.2's names for x_P and its byte string
pub(crate) fn agree(
    sk: &ECCDHP256PrivateKey,
    peer_pk: &ECCDHP256PublicKey,
) -> Result<KeyMaterial<SS_LEN>, KeyAgreementError> {
    // 1. Compute the point P = h d_A Q_B. The cofactor h is 1 (SP 800-186 Section 3.2.1.3 (P-256; Section 3.2.1: "For pseudorandom curves, the cofactor h = 1")), so this is [d]Q, in
    //    constant time in d; Q passed full validation when the key was decoded.
    let q = P256JacobianPoint::from_affine(peer_pk.x, peer_pk.y);
    let mut p = multiply_point(sk.scalar(), &q);

    // 2. If P = O, destroy all intermediate values ... and output an error indicator. [d]Q is
    //    the identity only for a Q of order dividing d, which a validated point of prime order n
    //    never is; the test is kept, on a condition no valid input reaches, and acted on after
    //    the zeroizing below so that the error path destroys the intermediates too.
    let p_is_infinity = p.is_infinity();

    // 3. Set z = x_P and convert z to Z (Appendix C.2, the field-element-to-byte-string
    //    conversion: big-endian, SS_LEN bytes, which is SEC 1's form).
    let mut z = x_affine(&p);
    let mut Z = Secret::<[u8; SS_LEN]>::new();
    *Z = p256_sec1::be_bytes_from_limbs(&z.to_limbs());

    // 4. Destroy the results of all intermediate calculations (including P and z).
    p.zeroize();
    z.zeroize();
    if p_is_infinity.to_bool() {
        return Err(KeyAgreementError::AgreementFailed);
    }

    // 5. Output Z, typed so that a KDF credits it and nothing else accepts it as a key, at the
    //    curve's strength rather than the length-derived default. An all-zero Z (x_P = 0, a valid
    //    field element, probability about 2^-256) comes back typed Zeroized and takes no
    //    strength; that is not an error.
    let mut shared = KeyMaterial::<SS_LEN>::from_bytes_as_type(&*Z, KeyType::SharedSecret)?;
    if shared.key_type() == KeyType::SharedSecret {
        do_hazardous_operations(&mut shared, |shared| {
            shared.set_security_strength(ECCDHP256::MAX_SECURITY_STRENGTH)
        })?;
    }
    Ok(shared)
}

impl KeyAgreement<ECCDHP256PublicKey, SS_LEN> for ECCDHP256Agreement<'_> {
    fn agree(
        &self,
        peer_pk: &ECCDHP256PublicKey,
    ) -> Result<KeyMaterial<SS_LEN>, KeyAgreementError> {
        agree(self.sk, peer_pk)
    }
}

impl AgreementKey<(), SS_LEN> for ECCDHP256PrivateKey {
    type Algorithm = ECCDHP256;
    type PublicKey = ECCDHP256PublicKey;
    type Agreement<'k> = ECCDHP256Agreement<'k>;

    /// The raw primitive takes nothing beyond the key, so this never fails.
    fn create_agreement<'k>(
        &'k self,
        _params: (),
    ) -> Result<Self::Agreement<'k>, KeyAgreementError> {
        Ok(ECCDHP256Agreement { sk: self })
    }
}

/*** The same keys under a KDF: ECC CDH with HKDF-SHA256 ***/

/// Length of the key ECC-CDH-P256-HKDF-SHA256 derives: one SHA-256 output.
pub const HKDF_SHA256_SS_LEN: usize = 32;

/// ECC CDH over P-256 with the shared secret derived through HKDF-SHA256: the algorithm an
/// [`ECCDHP256PrivateKey`] runs when made into a worker from `HkdfParams<'p, SHA256>`. The key is
/// HKDF-SHA256(salt, Z, info) over the primitive's `Z`, one hash output long, at 128 bits: the
/// curve's strength, which HKDF-SHA256 also caps at.
#[allow(non_camel_case_types)]
pub struct ECCDHP256_HKDF_SHA256;

impl Algorithm for ECCDHP256_HKDF_SHA256 {
    const ALG_NAME: &'static str = "ECC-CDH-P256-HKDF-SHA256";
    const MAX_SECURITY_STRENGTH: SecurityStrength = ECCDHP256::MAX_SECURITY_STRENGTH;
}

impl KeyAgreementAlgorithm for ECCDHP256_HKDF_SHA256 {}

/// The worker [`AgreementKey::create_agreement`] hands out over [`HkdfParams`]: the own key and
/// the HKDF configuration, borrowed separately. Reusable against any number of peers.
pub struct ECCDHP256HkdfAgreement<'k, 'p> {
    sk: &'k ECCDHP256PrivateKey,
    params: HkdfParams<'p, SHA256>,
}

impl Algorithm for ECCDHP256HkdfAgreement<'_, '_> {
    const ALG_NAME: &'static str = ECCDHP256_HKDF_SHA256::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = ECCDHP256_HKDF_SHA256::MAX_SECURITY_STRENGTH;
}

impl KeyAgreement<ECCDHP256PublicKey, HKDF_SHA256_SS_LEN> for ECCDHP256HkdfAgreement<'_, '_> {
    /// `Z` from the primitive, then the KDF (SP 800-56A Rev. 3 Section 5.8): `Z` is typed
    /// `SharedSecret`, which HKDF credits as keying material, and it never leaves this call.
    fn agree(
        &self,
        peer_pk: &ECCDHP256PublicKey,
    ) -> Result<KeyMaterial<HKDF_SHA256_SS_LEN>, KeyAgreementError> {
        let z = agree(self.sk, peer_pk)?;
        let mut okm = KeyMaterial::<HKDF_SHA256_SS_LEN>::new();
        HKDF_SHA256::extract_and_expand_out(
            self.params.salt(),
            &z,
            self.params.info(),
            HKDF_SHA256_SS_LEN,
            &mut okm,
        )
        .map_err(|_| KeyAgreementError::GenericError("HKDF-SHA256 over Z failed"))?;
        Ok(okm)
    }
}

impl<'p> AgreementKey<HkdfParams<'p, SHA256>, HKDF_SHA256_SS_LEN> for ECCDHP256PrivateKey {
    type Algorithm = ECCDHP256_HKDF_SHA256;
    type PublicKey = ECCDHP256PublicKey;
    type Agreement<'k> = ECCDHP256HkdfAgreement<'k, 'p>;

    /// Refuses a salt typed [`KeyType::Unknown`] here, once, rather than at every agreement:
    /// HKDF does not promote bytes of unknown provenance to a key.
    fn create_agreement<'k>(
        &'k self,
        params: HkdfParams<'p, SHA256>,
    ) -> Result<Self::Agreement<'k>, KeyAgreementError> {
        if params.salt().key_type() == KeyType::Unknown {
            return Err(KeyMaterialError::InvalidKeyType(
                "the HKDF salt must not be KeyType::Unknown",
            )
            .into());
        }
        Ok(ECCDHP256HkdfAgreement { sk: self, params })
    }
}
