//! The ECC CDH primitive over P-384 (SP 800-56A Rev. 3 Section 5.7.1.2) on the key-agreement
//! roles of [`bouncycastle_core::agreement_key`]: the marker [`ECCDHP384`], the worker a private
//! key hands out, the role impl over `()`, and the same keys under the ANSI X9.63 KDF as
//! [`ECCDHP384_X963KDF_SHA384`].

use crate::kdf::{KdfPairing, PairedKdf, derive};
use crate::keys_p384::{ECCDHP384PrivateKey, ECCDHP384PublicKey};
use bouncycastle_core::agreement_key::{AgreementKey, KeyAgreementAlgorithm};
use bouncycastle_core::errors::KeyAgreementError;
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::kdf_params::KdfParams;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, KDF, KeyAgreement};
use bouncycastle_ec::hazmat::p384::P384FieldElement;
use bouncycastle_ec::hazmat::p384_mul::multiply_point;
use bouncycastle_ec::hazmat::p384_point::P384JacobianPoint;
use bouncycastle_ec::hazmat::p384_sec1;
use bouncycastle_utils::secret::Secret;
use bouncycastle_x963kdf::X963KDF_SHA384;

/// Length of the shared secret `Z`: Appendix C.2's field-element-to-byte-string conversion of
/// `x_P`, `ceil(log2 p / 8)` = 48 bytes.
pub const SS_LEN: usize = 48;

/// ECC CDH over P-384: the algorithm a [`ECCDHP384PrivateKey`] runs when made into a worker from
/// `()`. The cofactor is 1 (SP 800-186 Section 3.2.1.4 (P-384; Section 3.2.1: "For pseudorandom curves, the cofactor h = 1")), so `Z` is the same value plain ECDH gives; what the name says
/// is that the peer key was fully validated and the identity checked, as Section 5.7.1.2 asks.
pub struct ECCDHP384;

impl Algorithm for ECCDHP384 {
    const ALG_NAME: &'static str = "ECC-CDH-P384";
    /// SP 800-57 Part 1 Rev. 5 Table 2: a 384-bit curve order gives 192 bits.
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_192bit;
}

impl KeyAgreementAlgorithm for ECCDHP384 {}

/// The worker [`AgreementKey::create_agreement`] hands out: the own key, borrowed. Reusable
/// against any number of peers, as a static key is in SP 800-56A Rev. 3 Section 6.2's schemes.
pub struct ECCDHP384Agreement<'k> {
    sk: &'k ECCDHP384PrivateKey,
}

impl Algorithm for ECCDHP384Agreement<'_> {
    const ALG_NAME: &'static str = ECCDHP384::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = ECCDHP384::MAX_SECURITY_STRENGTH;
}

/// `x * z^-2`, branch-free: the affine x of a Jacobian point without
/// [`P384JacobianPoint::to_affine`]'s branch on the identity, which the caller tests separately.
fn x_affine(point: &P384JacobianPoint) -> P384FieldElement {
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
    sk: &ECCDHP384PrivateKey,
    peer_pk: &ECCDHP384PublicKey,
) -> Result<KeyMaterial<SS_LEN>, KeyAgreementError> {
    // 1. Compute the point P = h d_A Q_B. The cofactor h is 1 (SP 800-186 Section 3.2.1.4 (P-384; Section 3.2.1: "For pseudorandom curves, the cofactor h = 1")), so this is [d]Q, in
    //    constant time in d; Q passed full validation when the key was decoded.
    let q = P384JacobianPoint::from_affine(peer_pk.x, peer_pk.y);
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
    *Z = p384_sec1::be_bytes_from_limbs(&z.to_limbs());

    // 4. Destroy the results of all intermediate calculations (including P and z).
    p.zeroize();
    z.zeroize();
    if p_is_infinity.to_bool() {
        return Err(KeyAgreementError::AgreementFailed);
    }

    // 5. Output Z, typed so that a KDF credits it and nothing else accepts it as a key, at the
    //    curve's strength rather than the length-derived default. An all-zero Z (x_P = 0, a valid
    //    field element, probability about 2^-384) comes back typed Zeroized and takes no
    //    strength; that is not an error.
    let mut shared = KeyMaterial::<SS_LEN>::from_bytes_as_type(&*Z, KeyType::SharedSecret)?;
    if shared.key_type() == KeyType::SharedSecret {
        do_hazardous_operations(&mut shared, |shared| {
            shared.set_security_strength(ECCDHP384::MAX_SECURITY_STRENGTH)
        })?;
    }
    Ok(shared)
}

impl KeyAgreement<ECCDHP384PublicKey, SS_LEN> for ECCDHP384Agreement<'_> {
    fn agree(
        &self,
        peer_pk: &ECCDHP384PublicKey,
    ) -> Result<KeyMaterial<SS_LEN>, KeyAgreementError> {
        agree(self.sk, peer_pk)
    }
}

impl AgreementKey<(), SS_LEN> for ECCDHP384PrivateKey {
    type Algorithm = ECCDHP384;
    type PublicKey = ECCDHP384PublicKey;
    type Agreement<'k> = ECCDHP384Agreement<'k>;

    /// The raw primitive takes nothing beyond the key, so this never fails.
    fn create_agreement<'k>(
        &'k self,
        _params: (),
    ) -> Result<Self::Agreement<'k>, KeyAgreementError> {
        Ok(ECCDHP384Agreement { sk: self })
    }
}

/*** The same keys under a KDF: the pairings, and one role impl over them ***/

/// The length the tests derive for ECC-CDH-P-384-X963KDF-SHA-384, one SHA-384 output; the parameters name any.
pub const X963KDF_SHA384_SS_LEN: usize = 48;

/// ECC CDH over P-384 with the keying data derived through the ANSI X9.63 KDF over
/// SHA-384 (SEC 1 v2 Sections 3.6.1 and 6.1): the algorithm a [`ECCDHP384PrivateKey`] runs when made
/// into a worker from `KdfParams<'p, X963KDF_SHA384, LEN>`. The key is `KDF(Z, SharedInfo)` with
/// `keydatalen` one hash output, at the curve's strength.
#[allow(non_camel_case_types)]
pub struct ECCDHP384_X963KDF_SHA384;

impl Algorithm for ECCDHP384_X963KDF_SHA384 {
    const ALG_NAME: &'static str = "ECC-CDH-P384-X963KDF-SHA-384";
    const MAX_SECURITY_STRENGTH: SecurityStrength = ECCDHP384::MAX_SECURITY_STRENGTH;
}

impl KeyAgreementAlgorithm for ECCDHP384_X963KDF_SHA384 {}

impl<const SS_LEN: usize> KdfPairing<X963KDF_SHA384, SS_LEN> for ECCDHP384 {
    type Algorithm = ECCDHP384_X963KDF_SHA384;
}

/// The worker [`AgreementKey::create_agreement`] hands out over [`KdfParams`]: the own key and
/// the KDF's parameters, borrowed separately. Reusable against any number of peers.
pub struct ECCDHP384KdfAgreement<'k, 'p, D: KDF + PairedKdf + ?Sized, const SS_LEN: usize> {
    sk: &'k ECCDHP384PrivateKey,
    params: KdfParams<'p, D, SS_LEN>,
}

impl<D: KDF + PairedKdf + ?Sized, const SS_LEN: usize> Algorithm
    for ECCDHP384KdfAgreement<'_, '_, D, SS_LEN>
where
    ECCDHP384: KdfPairing<D, SS_LEN>,
{
    const ALG_NAME: &'static str = <ECCDHP384 as KdfPairing<D, SS_LEN>>::Algorithm::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength =
        <ECCDHP384 as KdfPairing<D, SS_LEN>>::Algorithm::MAX_SECURITY_STRENGTH;
}

impl<D: KDF + PairedKdf + ?Sized, const SS_LEN: usize> KeyAgreement<ECCDHP384PublicKey, SS_LEN>
    for ECCDHP384KdfAgreement<'_, '_, D, SS_LEN>
where
    ECCDHP384: KdfPairing<D, SS_LEN>,
{
    /// `Z` from the primitive, then the KDF (SP 800-56A Rev. 3 Section 5.8; SEC 1 Section 6.1's
    /// steps for the X9.63 KDF): `Z` is typed `SharedSecret`, which the KDF credits, and it never
    /// leaves this call.
    fn agree(
        &self,
        peer_pk: &ECCDHP384PublicKey,
    ) -> Result<KeyMaterial<SS_LEN>, KeyAgreementError> {
        let z = agree(self.sk, peer_pk)?;
        derive(self.params, &z)
    }
}

impl<'p, D: KDF + PairedKdf + ?Sized, const SS_LEN: usize>
    AgreementKey<KdfParams<'p, D, SS_LEN>, SS_LEN> for ECCDHP384PrivateKey
where
    ECCDHP384: KdfPairing<D, SS_LEN>,
{
    type Algorithm = <ECCDHP384 as KdfPairing<D, SS_LEN>>::Algorithm;
    type PublicKey = ECCDHP384PublicKey;
    type Agreement<'k> = ECCDHP384KdfAgreement<'k, 'p, D, SS_LEN>;

    /// Cannot fail: the KDF validated what it was made from when it was made.
    fn create_agreement<'k>(
        &'k self,
        params: KdfParams<'p, D, SS_LEN>,
    ) -> Result<Self::Agreement<'k>, KeyAgreementError> {
        Ok(ECCDHP384KdfAgreement { sk: self, params })
    }
}
