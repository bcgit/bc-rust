//! The ECC CDH primitive over secp256k1 (SP 800-56A Rev. 3 Section 5.7.1.2) on the key-agreement
//! roles of [`bouncycastle_core::agreement_key`]: the marker [`ECCDHSecp256K1`], the worker a private
//! key hands out, the role impl over `()`, and the same keys under the ANSI X9.63 KDF as
//! [`ECCDHSecp256K1_X963KDF_SHA256`].

use crate::keys_p256k1::{ECCDHSecp256K1PrivateKey, ECCDHSecp256K1PublicKey};
use bouncycastle_core::agreement_key::{AgreementKey, KeyAgreementAlgorithm};
use bouncycastle_core::errors::KeyAgreementError;
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, KeyAgreement};
use bouncycastle_ec::hazmat::p256k1::P256K1FieldElement;
use bouncycastle_ec::hazmat::p256k1_mul::multiply_point;
use bouncycastle_ec::hazmat::p256k1_point::P256K1JacobianPoint;
use bouncycastle_ec::hazmat::p256k1_sec1;
use bouncycastle_sha2::SHA256;
use bouncycastle_utils::secret::Secret;
use bouncycastle_x963kdf::{X963KDF_SHA256, X963KdfParams};

/// Length of the shared secret `Z`: Appendix C.2's field-element-to-byte-string conversion of
/// `x_P`, `ceil(log2 p / 8)` = 32 bytes.
pub const SS_LEN: usize = 32;

/// ECC CDH over secp256k1: the algorithm a [`ECCDHSecp256K1PrivateKey`] runs when made into a worker from
/// `()`. The cofactor is 1 (SEC 2 v2 Section 2.4.1 (h = 01)), so `Z` is the same value plain ECDH gives; what the name says
/// is that the peer key was fully validated and the identity checked, as Section 5.7.1.2 asks.
pub struct ECCDHSecp256K1;

impl Algorithm for ECCDHSecp256K1 {
    const ALG_NAME: &'static str = "ECC-CDH-secp256k1";
    /// SP 800-57 Part 1 Rev. 5 Table 2: a 256-bit curve order gives 128 bits.
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

impl KeyAgreementAlgorithm for ECCDHSecp256K1 {}

/// The worker [`AgreementKey::create_agreement`] hands out: the own key, borrowed. Reusable
/// against any number of peers, as a static key is in SP 800-56A Rev. 3 Section 6.2's schemes.
pub struct ECCDHSecp256K1Agreement<'k> {
    sk: &'k ECCDHSecp256K1PrivateKey,
}

impl Algorithm for ECCDHSecp256K1Agreement<'_> {
    const ALG_NAME: &'static str = ECCDHSecp256K1::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = ECCDHSecp256K1::MAX_SECURITY_STRENGTH;
}

/// `x * z^-2`, branch-free: the affine x of a Jacobian point without
/// [`P256K1JacobianPoint::to_affine`]'s branch on the identity, which the caller tests separately.
fn x_affine(point: &P256K1JacobianPoint) -> P256K1FieldElement {
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
    sk: &ECCDHSecp256K1PrivateKey,
    peer_pk: &ECCDHSecp256K1PublicKey,
) -> Result<KeyMaterial<SS_LEN>, KeyAgreementError> {
    // 1. Compute the point P = h d_A Q_B. The cofactor h is 1 (SEC 2 v2 Section 2.4.1 (h = 01)), so this is [d]Q, in
    //    constant time in d; Q passed full validation when the key was decoded.
    let q = P256K1JacobianPoint::from_affine(peer_pk.x, peer_pk.y);
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
    *Z = p256k1_sec1::be_bytes_from_limbs(&z.to_limbs());

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
            shared.set_security_strength(ECCDHSecp256K1::MAX_SECURITY_STRENGTH)
        })?;
    }
    Ok(shared)
}

impl KeyAgreement<ECCDHSecp256K1PublicKey, SS_LEN> for ECCDHSecp256K1Agreement<'_> {
    fn agree(
        &self,
        peer_pk: &ECCDHSecp256K1PublicKey,
    ) -> Result<KeyMaterial<SS_LEN>, KeyAgreementError> {
        agree(self.sk, peer_pk)
    }
}

impl AgreementKey<(), SS_LEN> for ECCDHSecp256K1PrivateKey {
    type Algorithm = ECCDHSecp256K1;
    type PublicKey = ECCDHSecp256K1PublicKey;
    type Agreement<'k> = ECCDHSecp256K1Agreement<'k>;

    /// The raw primitive takes nothing beyond the key, so this never fails.
    fn create_agreement<'k>(
        &'k self,
        _params: (),
    ) -> Result<Self::Agreement<'k>, KeyAgreementError> {
        Ok(ECCDHSecp256K1Agreement { sk: self })
    }
}

/*** The same keys under the ANSI X9.63 KDF: SEC 1 Section 6.1's ECDH scheme ***/

/// Length of the keying data ECC-CDH-secp256k1-X963KDF-SHA-256 derives: one SHA-256 output.
pub const X963KDF_SHA256_SS_LEN: usize = 32;

/// ECC CDH over secp256k1 with the keying data derived through the ANSI X9.63 KDF over
/// SHA-256 (SEC 1 v2 Sections 3.6.1 and 6.1): the algorithm a [`ECCDHSecp256K1PrivateKey`] runs when made
/// into a worker from `X963KdfParams<'p, SHA256>`. The key is `KDF(Z, SharedInfo)` with
/// `keydatalen` one hash output, at the curve's strength.
#[allow(non_camel_case_types)]
pub struct ECCDHSecp256K1_X963KDF_SHA256;

impl Algorithm for ECCDHSecp256K1_X963KDF_SHA256 {
    const ALG_NAME: &'static str = "ECC-CDH-secp256k1-X963KDF-SHA-256";
    const MAX_SECURITY_STRENGTH: SecurityStrength = ECCDHSecp256K1::MAX_SECURITY_STRENGTH;
}

impl KeyAgreementAlgorithm for ECCDHSecp256K1_X963KDF_SHA256 {}

/// The worker [`AgreementKey::create_agreement`] hands out over [`X963KdfParams`]: the own key
/// and the `SharedInfo`, borrowed separately. Reusable against any number of peers.
pub struct ECCDHSecp256K1X963KdfAgreement<'k, 'p> {
    sk: &'k ECCDHSecp256K1PrivateKey,
    params: X963KdfParams<'p, SHA256>,
}

impl Algorithm for ECCDHSecp256K1X963KdfAgreement<'_, '_> {
    const ALG_NAME: &'static str = ECCDHSecp256K1_X963KDF_SHA256::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength =
        ECCDHSecp256K1_X963KDF_SHA256::MAX_SECURITY_STRENGTH;
}

impl KeyAgreement<ECCDHSecp256K1PublicKey, X963KDF_SHA256_SS_LEN>
    for ECCDHSecp256K1X963KdfAgreement<'_, '_>
{
    /// SEC 1 Section 6.1 steps: `Z` from the primitive, then `KDF(Z, SharedInfo)`; `Z` is typed
    /// `SharedSecret`, which the KDF credits, and it never leaves this call.
    fn agree(
        &self,
        peer_pk: &ECCDHSecp256K1PublicKey,
    ) -> Result<KeyMaterial<X963KDF_SHA256_SS_LEN>, KeyAgreementError> {
        let z = agree(self.sk, peer_pk)?;
        let mut okm = KeyMaterial::<X963KDF_SHA256_SS_LEN>::new();
        X963KDF_SHA256::derive_out(&z, self.params.shared_info(), X963KDF_SHA256_SS_LEN, &mut okm)
            .map_err(|_| KeyAgreementError::GenericError("X9.63 KDF over Z failed"))?;
        Ok(okm)
    }
}

impl<'p> AgreementKey<X963KdfParams<'p, SHA256>, X963KDF_SHA256_SS_LEN>
    for ECCDHSecp256K1PrivateKey
{
    type Algorithm = ECCDHSecp256K1_X963KDF_SHA256;
    type PublicKey = ECCDHSecp256K1PublicKey;
    type Agreement<'k> = ECCDHSecp256K1X963KdfAgreement<'k, 'p>;

    /// The KDF takes no parameter it can refuse, so this never fails.
    fn create_agreement<'k>(
        &'k self,
        params: X963KdfParams<'p, SHA256>,
    ) -> Result<Self::Agreement<'k>, KeyAgreementError> {
        Ok(ECCDHSecp256K1X963KdfAgreement { sk: self, params })
    }
}
