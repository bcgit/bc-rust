//! The ECC CDH primitive over brainpoolP384r1 (SP 800-56A Rev. 3 Section 5.7.1.2) on the key-agreement
//! roles of [`bouncycastle_core::agreement_key`]: the marker [`ECCDHBp384r1`], the worker a private
//! key hands out, and the role impl over `()`.

use crate::keys_bp384r1::{ECCDHBp384r1PrivateKey, ECCDHBp384r1PublicKey};
use bouncycastle_core::agreement_key::{AgreementKey, KeyAgreementAlgorithm};
use bouncycastle_core::errors::KeyAgreementError;
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, KeyAgreement};
use bouncycastle_ec::hazmat::bp384r1::Bp384r1FieldElement;
use bouncycastle_ec::hazmat::bp384r1_mul::multiply_point;
use bouncycastle_ec::hazmat::bp384r1_point::Bp384r1JacobianPoint;
use bouncycastle_ec::hazmat::bp384r1_sec1;
use bouncycastle_utils::secret::Secret;

/// Length of the shared secret `Z`: Appendix C.2's field-element-to-byte-string conversion of
/// `x_P`, `ceil(log2 p / 8)` = 48 bytes.
pub const SS_LEN: usize = 48;

/// ECC CDH over brainpoolP384r1: the algorithm a [`ECCDHBp384r1PrivateKey`] runs when made into a worker from
/// `()`. The cofactor is 1 (RFC 5639 Section 3.6 (h = 1)), so `Z` is the same value plain ECDH gives; what the name says
/// is that the peer key was fully validated and the identity checked, as Section 5.7.1.2 asks.
pub struct ECCDHBp384r1;

impl Algorithm for ECCDHBp384r1 {
    const ALG_NAME: &'static str = "ECC-CDH-brainpoolP384r1";
    /// SP 800-57 Part 1 Rev. 5 Table 2: a 384-bit curve order gives 192 bits.
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_192bit;
}

impl KeyAgreementAlgorithm for ECCDHBp384r1 {}

/// The worker [`AgreementKey::create_agreement`] hands out: the own key, borrowed. Reusable
/// against any number of peers, as a static key is in SP 800-56A Rev. 3 Section 6.2's schemes.
pub struct ECCDHBp384r1Agreement<'k> {
    sk: &'k ECCDHBp384r1PrivateKey,
}

impl Algorithm for ECCDHBp384r1Agreement<'_> {
    const ALG_NAME: &'static str = ECCDHBp384r1::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = ECCDHBp384r1::MAX_SECURITY_STRENGTH;
}

/// `x * z^-2`, branch-free: the affine x of a Jacobian point without
/// [`Bp384r1JacobianPoint::to_affine`]'s branch on the identity, which the caller tests separately.
fn x_affine(point: &Bp384r1JacobianPoint) -> Bp384r1FieldElement {
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
    sk: &ECCDHBp384r1PrivateKey,
    peer_pk: &ECCDHBp384r1PublicKey,
) -> Result<KeyMaterial<SS_LEN>, KeyAgreementError> {
    // 1. Compute the point P = h d_A Q_B. The cofactor h is 1 (RFC 5639 Section 3.6 (h = 1)), so this is [d]Q, in
    //    constant time in d; Q passed full validation when the key was decoded.
    let q = Bp384r1JacobianPoint::from_affine(peer_pk.x, peer_pk.y);
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
    *Z = bp384r1_sec1::be_bytes_from_limbs(&z.to_limbs());

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
            shared.set_security_strength(ECCDHBp384r1::MAX_SECURITY_STRENGTH)
        })?;
    }
    Ok(shared)
}

impl KeyAgreement<ECCDHBp384r1PublicKey, SS_LEN> for ECCDHBp384r1Agreement<'_> {
    fn agree(
        &self,
        peer_pk: &ECCDHBp384r1PublicKey,
    ) -> Result<KeyMaterial<SS_LEN>, KeyAgreementError> {
        agree(self.sk, peer_pk)
    }
}

impl AgreementKey<(), SS_LEN> for ECCDHBp384r1PrivateKey {
    type Algorithm = ECCDHBp384r1;
    type PublicKey = ECCDHBp384r1PublicKey;
    type Agreement<'k> = ECCDHBp384r1Agreement<'k>;

    /// The raw primitive takes nothing beyond the key, so this never fails.
    fn create_agreement<'k>(
        &'k self,
        _params: (),
    ) -> Result<Self::Agreement<'k>, KeyAgreementError> {
        Ok(ECCDHBp384r1Agreement { sk: self })
    }
}
