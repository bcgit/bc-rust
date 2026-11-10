//! The ECC CDH primitive over P-256 (SP 800-56A Rev. 3 Section 5.7.1.2) on the key-agreement
//! roles of [`bouncycastle_core::agreement_key`]: the marker [`ECCDHP256`], the worker a private
//! key hands out, the role impl over `()`, and the same keys under the ANSI X9.63 KDF as
//! [`ECCDHP256_X963KDF_SHA256`], and under the NIST concatenation KDF as [`ECCDHP256_ConcatKDF_SHA256`]. The same keys run
//! HKDF-SHA256, the two-step key-derivation method of SP 800-56C Rev. 2 Section 5.1, as
//! [`ECCDHP256_HKDF_SHA256`]; the KDF type on the parameters selects the algorithm at the call,
//! and the pairings are in [`crate::kdf`].

use crate::kdf::{KdfPairing, PairedKdf, derive};
use crate::keys_p256::{ECCDHP256PrivateKey, ECCDHP256PublicKey};
use bouncycastle_concatkdf::ConcatKDF_SHA256;
use bouncycastle_core::agreement_key::{AgreementKey, KeyAgreementAlgorithm};
use bouncycastle_core::errors::{KeyAgreementError, KeyMaterialError};
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::kdf_params::KdfParams;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, KDF, KeyAgreement};
use bouncycastle_ec::hazmat::p256::P256FieldElement;
use bouncycastle_ec::hazmat::p256_mul::multiply_point;
use bouncycastle_ec::hazmat::p256_point::P256JacobianPoint;
use bouncycastle_ec::hazmat::p256_sec1;
use bouncycastle_sha2::hkdf::HKDF_SHA256;
use bouncycastle_utils::secret::Secret;
use bouncycastle_x963kdf::X963KDF_SHA256;

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
/// The inverse and its square are scrubbed here; the inversion's own intermediates are not.
fn x_affine(point: &P256JacobianPoint) -> P256FieldElement {
    let mut z_inv = point.z.invert();
    let mut z_inv_sq = z_inv.mul(&z_inv);
    let x = point.x.mul(&z_inv_sq);
    z_inv.zeroize();
    z_inv_sq.zeroize();
    x
}

/// SP 800-56A Rev. 3 Section 5.7.1.2, the ECC CDH primitive, with `d` this worker's key and `Q`
/// the peer's: `Z` into `ss`, zeroized first, typed [`KeyType::SharedSecret`] at the curve's
/// strength, keying material for a KDF (Section 5.8), which nothing else accepts as a key. Into
/// the caller's buffer rather than returned, so that no copy of `Z` is staged in a return slot.
pub(crate) fn agree_out(
    sk: &ECCDHP256PrivateKey,
    peer_pk: &ECCDHP256PublicKey,
    ss: &mut KeyMaterial<SS_LEN>,
) -> Result<(), KeyAgreementError> {
    // 1. Compute the point P = h d_A Q_B. The cofactor h is 1 (SP 800-186 Section 3.2.1.3 (P-256; Section 3.2.1: "For pseudorandom curves, the cofactor h = 1")), so this is [d]Q, in
    //    constant time in d; Q passed full validation when the key was decoded.
    let q = P256JacobianPoint::from_affine(peer_pk.x, peer_pk.y);
    let mut p = multiply_point(sk.scalar(), &q);
    z_from_product(&mut p, ss)
}

/// Steps 2 to 5 of Section 5.7.1.2 from `P = [d]Q`, which is destroyed here, into `ss`,
/// zeroized first and left so on the error path. Apart from the multiplication so that step 2's
/// identity path, which no validated key reaches, has a test.
#[allow(non_snake_case)] // `z` and `Z` are Section 5.7.1.2's names for x_P and its byte string
fn z_from_product(
    p: &mut P256JacobianPoint,
    ss: &mut KeyMaterial<SS_LEN>,
) -> Result<(), KeyAgreementError> {
    ss.zeroize();

    // 2. If P = O, destroy all intermediate values ... and output an error indicator. [d]Q is
    //    the identity only for a Q of order dividing d, which a validated point of prime order n
    //    never is; the test is kept, on a condition no valid input reaches, and acted on after
    //    the zeroizing below so that the error path destroys the intermediates too.
    let p_is_infinity = p.is_infinity();

    // 3. Set z = x_P and convert z to Z (Appendix C.2, the field-element-to-byte-string
    //    conversion: big-endian, SS_LEN bytes, which is SEC 1's form). The limbs and the bytes
    //    are held in `Secret`s, scrubbed on return.
    let mut z = x_affine(p);
    let mut z_limbs = Secret::<[u64; 4]>::new();
    *z_limbs = z.to_limbs();
    let mut Z = Secret::<[u8; SS_LEN]>::new();
    *Z = p256_sec1::be_bytes_from_limbs(&z_limbs);

    // 4. Destroy the results of all intermediate calculations (including P and z): those this
    //    function holds; the arithmetic's own intermediates are `bouncycastle_ec`'s.
    p.zeroize();
    z.zeroize();
    if p_is_infinity.to_bool() {
        return Err(KeyAgreementError::AgreementFailed);
    }

    // 5. Output Z into the caller's buffer, typed so that a KDF credits it and nothing else
    //    accepts it as a key, at the curve's strength rather than the length-derived default. An
    //    all-zero Z (x_P = 0, a valid field element) is typed Zeroized by the buffer, which says
    //    so through its courtesy error, and takes no strength; that is not an error.
    //    Neither error below is reachable (the buffer is SS_LEN bytes and SharedSecret takes a
    //    strength), but each leaves the buffer zeroized, as the doc above says.
    match ss.set_bytes_as_type(&*Z, KeyType::SharedSecret) {
        Ok(()) | Err(KeyMaterialError::ActingOnZeroizedKey) => {}
        Err(e) => {
            ss.zeroize();
            return Err(KeyAgreementError::KeyMaterialError(e));
        }
    }
    if ss.key_type() == KeyType::SharedSecret
        && let Err(e) = do_hazardous_operations(ss, |ss| {
            ss.set_security_strength(ECCDHP256::MAX_SECURITY_STRENGTH)
        })
    {
        ss.zeroize();
        return Err(KeyAgreementError::KeyMaterialError(e));
    }
    Ok(())
}

impl KeyAgreement<ECCDHP256PublicKey, SS_LEN> for ECCDHP256Agreement<'_> {
    fn agree_out(
        &self,
        peer_pk: &ECCDHP256PublicKey,
        ss: &mut KeyMaterial<SS_LEN>,
    ) -> Result<usize, KeyAgreementError> {
        agree_out(self.sk, peer_pk, ss)?;
        Ok(SS_LEN)
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

/*** The same keys under a KDF: the pairings, and one role impl over them ***/

/// The length the tests derive for ECC-CDH-P256-HKDF-SHA256, one SHA-256 output; the parameters name any.
pub const HKDF_SHA256_SS_LEN: usize = 32;

/// ECC CDH over P-256 with the shared secret derived through HKDF-SHA256: the algorithm an
/// [`ECCDHP256PrivateKey`] runs when made into a worker from `KdfParams<'p, HKDF_SHA256, LEN>`. The
/// key is HKDF-SHA256(salt, Z, info) over the primitive's `Z`, the salt the instance's, one hash
/// output long unless the parameters say otherwise, at 128 bits: the curve's strength, which
/// HKDF-SHA256 also caps at.
#[allow(non_camel_case_types)]
pub struct ECCDHP256_HKDF_SHA256;

impl Algorithm for ECCDHP256_HKDF_SHA256 {
    const ALG_NAME: &'static str = "ECC-CDH-P256-HKDF-SHA256";
    const MAX_SECURITY_STRENGTH: SecurityStrength = ECCDHP256::MAX_SECURITY_STRENGTH;
}

impl KeyAgreementAlgorithm for ECCDHP256_HKDF_SHA256 {}

/// The length the tests derive for ECC-CDH-P256-X963KDF-SHA256, one SHA-256 output; the parameters name any.
pub const X963KDF_SHA256_SS_LEN: usize = 32;

/// ECC CDH over P-256 with the keying data derived through the ANSI X9.63 KDF over
/// SHA-256 (SEC 1 v2 Sections 3.6.1 and 6.1): the algorithm a [`ECCDHP256PrivateKey`] runs when made
/// into a worker from `KdfParams<'p, X963KDF_SHA256, LEN>`. The key is `KDF(Z, SharedInfo)` with
/// `keydatalen` one hash output, at the curve's strength.
#[allow(non_camel_case_types)]
pub struct ECCDHP256_X963KDF_SHA256;

impl Algorithm for ECCDHP256_X963KDF_SHA256 {
    const ALG_NAME: &'static str = "ECC-CDH-P256-X963KDF-SHA256";
    const MAX_SECURITY_STRENGTH: SecurityStrength = ECCDHP256::MAX_SECURITY_STRENGTH;
}

impl KeyAgreementAlgorithm for ECCDHP256_X963KDF_SHA256 {}

impl<const SS_LEN: usize> KdfPairing<HKDF_SHA256, SS_LEN> for ECCDHP256 {
    type Algorithm = ECCDHP256_HKDF_SHA256;
}

impl<const SS_LEN: usize> KdfPairing<X963KDF_SHA256, SS_LEN> for ECCDHP256 {
    type Algorithm = ECCDHP256_X963KDF_SHA256;
}

/// The length the tests derive for ECC-CDH-P256-ConcatKDF-SHA256, one SHA-256 output; the parameters name any.
pub const CONCAT_KDF_SHA256_SS_LEN: usize = 32;

/// ECC CDH over P256 with the keying material derived through the NIST concatenation KDF over
/// SHA-256 (SP 800-56C Rev. 2 Section 4.1, Option 1, as SP 800-56A Rev. 3 Section 5.8 calls for):
/// the algorithm a [`ECCDHP256PrivateKey`] runs when made into a worker from
/// `KdfParams<'p, ConcatKDF_SHA256, LEN>`. The key is `KDM(Z, OtherInput)` with `FixedInfo` the
/// parameters' fixed info and `L` their length, at the curve's strength.
#[allow(non_camel_case_types)]
pub struct ECCDHP256_ConcatKDF_SHA256;

impl Algorithm for ECCDHP256_ConcatKDF_SHA256 {
    const ALG_NAME: &'static str = "ECC-CDH-P256-ConcatKDF-SHA256";
    const MAX_SECURITY_STRENGTH: SecurityStrength = ECCDHP256::MAX_SECURITY_STRENGTH;
}

impl KeyAgreementAlgorithm for ECCDHP256_ConcatKDF_SHA256 {}

impl<const SS_LEN: usize> KdfPairing<ConcatKDF_SHA256, SS_LEN> for ECCDHP256 {
    type Algorithm = ECCDHP256_ConcatKDF_SHA256;
}

/// The worker [`AgreementKey::create_agreement`] hands out over [`KdfParams`]: the own key and
/// the KDF's parameters, borrowed separately. Reusable against any number of peers.
pub struct ECCDHP256KdfAgreement<'k, 'p, D: KDF + PairedKdf + ?Sized, const SS_LEN: usize> {
    sk: &'k ECCDHP256PrivateKey,
    params: KdfParams<'p, D, SS_LEN>,
}

impl<D: KDF + PairedKdf + ?Sized, const SS_LEN: usize> Algorithm
    for ECCDHP256KdfAgreement<'_, '_, D, SS_LEN>
where
    ECCDHP256: KdfPairing<D, SS_LEN>,
{
    const ALG_NAME: &'static str = <ECCDHP256 as KdfPairing<D, SS_LEN>>::Algorithm::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength =
        <ECCDHP256 as KdfPairing<D, SS_LEN>>::Algorithm::MAX_SECURITY_STRENGTH;
}

impl<D: KDF + PairedKdf + ?Sized, const SS_LEN: usize> KeyAgreement<ECCDHP256PublicKey, SS_LEN>
    for ECCDHP256KdfAgreement<'_, '_, D, SS_LEN>
where
    ECCDHP256: KdfPairing<D, SS_LEN>,
{
    /// `Z` from the primitive, then the KDF into the caller's buffer (SP 800-56A Rev. 3 Section
    /// 5.8; SEC 1 Section 6.1's steps for the X9.63 KDF): `Z` is typed `SharedSecret`, which the
    /// KDF credits; this crate's frames hold it in one local, wiped when it drops.
    fn agree_out(
        &self,
        peer_pk: &ECCDHP256PublicKey,
        ss: &mut KeyMaterial<SS_LEN>,
    ) -> Result<usize, KeyAgreementError> {
        ss.zeroize();
        // Z lives in this local, zeroized when it drops, and is written into it rather than
        // returned, so this crate stages no copy of it on the way to the KDF. The copy the KDF's
        // hash leaves when it finalises by value is the crate docs' subject, not this frame's.
        let mut z = KeyMaterial::<{ crate::eccdh_p256::SS_LEN }>::new();
        agree_out(self.sk, peer_pk, &mut z)?;
        derive(self.params, &z, ss)?;
        Ok(SS_LEN)
    }
}

impl<'p, D: KDF + PairedKdf + ?Sized, const SS_LEN: usize>
    AgreementKey<KdfParams<'p, D, SS_LEN>, SS_LEN> for ECCDHP256PrivateKey
where
    ECCDHP256: KdfPairing<D, SS_LEN>,
{
    type Algorithm = <ECCDHP256 as KdfPairing<D, SS_LEN>>::Algorithm;
    type PublicKey = ECCDHP256PublicKey;
    type Agreement<'k> = ECCDHP256KdfAgreement<'k, 'p, D, SS_LEN>;

    /// Cannot fail: the KDF validated what it was made from when it was made.
    fn create_agreement<'k>(
        &'k self,
        params: KdfParams<'p, D, SS_LEN>,
    ) -> Result<Self::Agreement<'k>, KeyAgreementError> {
        Ok(ECCDHP256KdfAgreement { sk: self, params })
    }
}

// Section 5.7.1.2 step 2's identity check is on a condition no validated peer key and in-range d
// can reach ([d]Q = O needs a Q of order dividing d, and every point here has prime order n), so
// no integration test can drive it; it is pinned here on the product directly.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_identity_product_is_an_error_and_leaves_the_buffer_zeroized() {
        let mut o = P256JacobianPoint::INFINITY;
        let mut ss =
            KeyMaterial::<SS_LEN>::from_bytes_as_type(&[0xFF; SS_LEN], KeyType::Seed).unwrap();
        assert!(matches!(z_from_product(&mut o, &mut ss), Err(KeyAgreementError::AgreementFailed)));
        assert_eq!(ss.key_type(), KeyType::Zeroized);
        assert_eq!(ss.key_len(), 0);
    }
}
