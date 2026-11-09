//! The ECC CDH primitive over brainpoolP256r1 (SP 800-56A Rev. 3 Section 5.7.1.2) on the key-agreement
//! roles of [`bouncycastle_core::agreement_key`]: the marker [`ECCDHBp256r1`], the worker a private
//! key hands out, the role impl over `()`, and the same keys under the ANSI X9.63 KDF as
//! [`ECCDHBp256r1_X963KDF_SHA256`], and under the NIST concatenation KDF as [`ECCDHBp256r1_ConcatKDF_SHA256`].

use crate::kdf::{KdfPairing, PairedKdf, derive};
use crate::keys_bp256r1::{ECCDHBp256r1PrivateKey, ECCDHBp256r1PublicKey};
use bouncycastle_concatkdf::ConcatKDF_SHA256;
use bouncycastle_core::agreement_key::{AgreementKey, KeyAgreementAlgorithm};
use bouncycastle_core::errors::KeyAgreementError;
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::kdf_params::KdfParams;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, KDF, KeyAgreement};
use bouncycastle_ec::hazmat::bp256r1::Bp256r1FieldElement;
use bouncycastle_ec::hazmat::bp256r1_mul::multiply_point;
use bouncycastle_ec::hazmat::bp256r1_point::Bp256r1JacobianPoint;
use bouncycastle_ec::hazmat::bp256r1_sec1;
use bouncycastle_utils::secret::Secret;
use bouncycastle_x963kdf::X963KDF_SHA256;

/// Length of the shared secret `Z`: Appendix C.2's field-element-to-byte-string conversion of
/// `x_P`, `ceil(log2 p / 8)` = 32 bytes.
pub const SS_LEN: usize = 32;

/// ECC CDH over brainpoolP256r1: the algorithm a [`ECCDHBp256r1PrivateKey`] runs when made into a worker from
/// `()`. The cofactor is 1 (RFC 5639 Section 3.4 (h = 1)), so `Z` is the same value plain ECDH gives; what the name says
/// is that the peer key was fully validated and the identity checked, as Section 5.7.1.2 asks.
pub struct ECCDHBp256r1;

impl Algorithm for ECCDHBp256r1 {
    const ALG_NAME: &'static str = "ECC-CDH-brainpoolP256r1";
    /// SP 800-57 Part 1 Rev. 5 Table 2: a 256-bit curve order gives 128 bits.
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

impl KeyAgreementAlgorithm for ECCDHBp256r1 {}

/// The worker [`AgreementKey::create_agreement`] hands out: the own key, borrowed. Reusable
/// against any number of peers, as a static key is in SP 800-56A Rev. 3 Section 6.2's schemes.
pub struct ECCDHBp256r1Agreement<'k> {
    sk: &'k ECCDHBp256r1PrivateKey,
}

impl Algorithm for ECCDHBp256r1Agreement<'_> {
    const ALG_NAME: &'static str = ECCDHBp256r1::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = ECCDHBp256r1::MAX_SECURITY_STRENGTH;
}

/// `x * z^-2`, branch-free: the affine x of a Jacobian point without
/// [`Bp256r1JacobianPoint::to_affine`]'s branch on the identity, which the caller tests separately.
fn x_affine(point: &Bp256r1JacobianPoint) -> Bp256r1FieldElement {
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
    sk: &ECCDHBp256r1PrivateKey,
    peer_pk: &ECCDHBp256r1PublicKey,
) -> Result<KeyMaterial<SS_LEN>, KeyAgreementError> {
    // 1. Compute the point P = h d_A Q_B. The cofactor h is 1 (RFC 5639 Section 3.4 (h = 1)), so this is [d]Q, in
    //    constant time in d; Q passed full validation when the key was decoded.
    let q = Bp256r1JacobianPoint::from_affine(peer_pk.x, peer_pk.y);
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
    *Z = bp256r1_sec1::be_bytes_from_limbs(&z.to_limbs());

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
            shared.set_security_strength(ECCDHBp256r1::MAX_SECURITY_STRENGTH)
        })?;
    }
    Ok(shared)
}

impl KeyAgreement<ECCDHBp256r1PublicKey, SS_LEN> for ECCDHBp256r1Agreement<'_> {
    fn agree_out(
        &self,
        peer_pk: &ECCDHBp256r1PublicKey,
        ss: &mut KeyMaterial<SS_LEN>,
    ) -> Result<usize, KeyAgreementError> {
        ss.zeroize();
        *ss = agree(self.sk, peer_pk)?;
        Ok(SS_LEN)
    }
}

impl AgreementKey<(), SS_LEN> for ECCDHBp256r1PrivateKey {
    type Algorithm = ECCDHBp256r1;
    type PublicKey = ECCDHBp256r1PublicKey;
    type Agreement<'k> = ECCDHBp256r1Agreement<'k>;

    /// The raw primitive takes nothing beyond the key, so this never fails.
    fn create_agreement<'k>(
        &'k self,
        _params: (),
    ) -> Result<Self::Agreement<'k>, KeyAgreementError> {
        Ok(ECCDHBp256r1Agreement { sk: self })
    }
}

/*** The same keys under a KDF: the pairings, and one role impl over them ***/

/// The length the tests derive for ECC-CDH-brainpoolP256r1-X963KDF-SHA-256, one SHA-256 output; the parameters name any.
pub const X963KDF_SHA256_SS_LEN: usize = 32;

/// ECC CDH over brainpoolP256r1 with the keying data derived through the ANSI X9.63 KDF over
/// SHA-256 (SEC 1 v2 Sections 3.6.1 and 6.1): the algorithm a [`ECCDHBp256r1PrivateKey`] runs when made
/// into a worker from `KdfParams<'p, X963KDF_SHA256, LEN>`. The key is `KDF(Z, SharedInfo)` with
/// `keydatalen` one hash output, at the curve's strength.
#[allow(non_camel_case_types)]
pub struct ECCDHBp256r1_X963KDF_SHA256;

impl Algorithm for ECCDHBp256r1_X963KDF_SHA256 {
    const ALG_NAME: &'static str = "ECC-CDH-brainpoolP256r1-X963KDF-SHA-256";
    const MAX_SECURITY_STRENGTH: SecurityStrength = ECCDHBp256r1::MAX_SECURITY_STRENGTH;
}

impl KeyAgreementAlgorithm for ECCDHBp256r1_X963KDF_SHA256 {}

impl<const SS_LEN: usize> KdfPairing<X963KDF_SHA256, SS_LEN> for ECCDHBp256r1 {
    type Algorithm = ECCDHBp256r1_X963KDF_SHA256;
}

/// The length the tests derive for ECC-CDH-brainpoolP256r1-ConcatKDF-SHA-256, one SHA-256 output; the parameters name any.
pub const CONCAT_KDF_SHA256_SS_LEN: usize = 32;

/// ECC CDH over brainpoolP256r1 with the keying material derived through the NIST concatenation KDF over
/// SHA-256 (SP 800-56C Rev. 2 Section 4.1, Option 1, as SP 800-56A Rev. 3 Section 5.8 calls for):
/// the algorithm a [`ECCDHBp256r1PrivateKey`] runs when made into a worker from
/// `KdfParams<'p, ConcatKDF_SHA256, LEN>`. The key is `KDM(Z, OtherInput)` with `FixedInfo` the
/// parameters' fixed info and `L` their length, at the curve's strength.
#[allow(non_camel_case_types)]
pub struct ECCDHBp256r1_ConcatKDF_SHA256;

impl Algorithm for ECCDHBp256r1_ConcatKDF_SHA256 {
    const ALG_NAME: &'static str = "ECC-CDH-brainpoolP256r1-ConcatKDF-SHA-256";
    const MAX_SECURITY_STRENGTH: SecurityStrength = ECCDHBp256r1::MAX_SECURITY_STRENGTH;
}

impl KeyAgreementAlgorithm for ECCDHBp256r1_ConcatKDF_SHA256 {}

impl<const SS_LEN: usize> KdfPairing<ConcatKDF_SHA256, SS_LEN> for ECCDHBp256r1 {
    type Algorithm = ECCDHBp256r1_ConcatKDF_SHA256;
}

/// The worker [`AgreementKey::create_agreement`] hands out over [`KdfParams`]: the own key and
/// the KDF's parameters, borrowed separately. Reusable against any number of peers.
pub struct ECCDHBp256r1KdfAgreement<'k, 'p, D: KDF + PairedKdf + ?Sized, const SS_LEN: usize> {
    sk: &'k ECCDHBp256r1PrivateKey,
    params: KdfParams<'p, D, SS_LEN>,
}

impl<D: KDF + PairedKdf + ?Sized, const SS_LEN: usize> Algorithm
    for ECCDHBp256r1KdfAgreement<'_, '_, D, SS_LEN>
where
    ECCDHBp256r1: KdfPairing<D, SS_LEN>,
{
    const ALG_NAME: &'static str = <ECCDHBp256r1 as KdfPairing<D, SS_LEN>>::Algorithm::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength =
        <ECCDHBp256r1 as KdfPairing<D, SS_LEN>>::Algorithm::MAX_SECURITY_STRENGTH;
}

impl<D: KDF + PairedKdf + ?Sized, const SS_LEN: usize> KeyAgreement<ECCDHBp256r1PublicKey, SS_LEN>
    for ECCDHBp256r1KdfAgreement<'_, '_, D, SS_LEN>
where
    ECCDHBp256r1: KdfPairing<D, SS_LEN>,
{
    /// `Z` from the primitive, then the KDF into the caller's buffer (SP 800-56A Rev. 3 Section
    /// 5.8; SEC 1 Section 6.1's steps for the X9.63 KDF): `Z` is typed `SharedSecret`, which the
    /// KDF credits, and it never leaves this call.
    fn agree_out(
        &self,
        peer_pk: &ECCDHBp256r1PublicKey,
        ss: &mut KeyMaterial<SS_LEN>,
    ) -> Result<usize, KeyAgreementError> {
        ss.zeroize();
        let z = agree(self.sk, peer_pk)?;
        derive(self.params, &z, ss)?;
        Ok(SS_LEN)
    }
}

impl<'p, D: KDF + PairedKdf + ?Sized, const SS_LEN: usize>
    AgreementKey<KdfParams<'p, D, SS_LEN>, SS_LEN> for ECCDHBp256r1PrivateKey
where
    ECCDHBp256r1: KdfPairing<D, SS_LEN>,
{
    type Algorithm = <ECCDHBp256r1 as KdfPairing<D, SS_LEN>>::Algorithm;
    type PublicKey = ECCDHBp256r1PublicKey;
    type Agreement<'k> = ECCDHBp256r1KdfAgreement<'k, 'p, D, SS_LEN>;

    /// Cannot fail: the KDF validated what it was made from when it was made.
    fn create_agreement<'k>(
        &'k self,
        params: KdfParams<'p, D, SS_LEN>,
    ) -> Result<Self::Agreement<'k>, KeyAgreementError> {
        Ok(ECCDHBp256r1KdfAgreement { sk: self, params })
    }
}
