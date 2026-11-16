//! The ECC CDH primitive (SP 800-56A Rev. 3 Section 5.7.1.2) over any [`Curve`], on the
//! key-agreement roles of [`bouncycastle_core::agreement_key`]: the marker [`ECCDH<C>`], the
//! worker a private key hands out, the role impl over `()`, and the same keys under the ANSI
//! X9.63 KDF ([`ECCDH_X963KDF`]) and the NIST concatenation KDF ([`ECCDH_ConcatKDF`]) over the
//! hash matched to the curve's strength ([`MatchedHash`]), and on P-256 under HKDF-SHA256
//! ([`ECCDH_HKDF_SHA256`]), the two-step key-derivation method of SP 800-56C Rev. 2 Section 5.1.
//! The KDF type on the parameters selects the algorithm at the call; the pairing trait is in
//! [`crate::kdf`].

use crate::kdf::{KdfPairing, PairedKdf, derive};
use crate::keys::{ECCDHPrivateKey, ECCDHPublicKey};
use bouncycastle_concatkdf::{ConcatKDF, ConcatKDFParams};
use bouncycastle_core::agreement_key::{AgreementKey, KeyAgreementAlgorithm};
use bouncycastle_core::errors::{KeyAgreementError, KeyMaterialError};
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::kdf_params::{KdfDescription, KdfParams};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, KeyAgreement};
use bouncycastle_ec::curve::{Curve, FieldElement, JacobianPoint};
use bouncycastle_ec::{Bp256r1, Bp384r1, Bp512r1, P256, P384, P521, Secp256K1};
use bouncycastle_hkdf::HkdfDescription;
use bouncycastle_sha2::{SHA256, SHA384, SHA512};
use bouncycastle_utils::const_str::ConstStr;
use bouncycastle_utils::secret::Secret;
use bouncycastle_x963kdf::{X963KDF, X963KDFParams};
use core::marker::PhantomData;

/// ECC CDH over the curve `C`: the algorithm an [`ECCDHPrivateKey<C>`] runs when made into a
/// worker from `()`. Every curve here has cofactor 1 (see the crate docs), so `Z` is the same
/// value plain ECDH gives; what the name says is that the peer key was fully validated and the
/// identity checked, as Section 5.7.1.2 asks. Named `ECC-CDH-<curve>`, at the curve's strength.
/// The shared secret `Z` is `C::FE_LEN` bytes, Appendix C.2's field-element-to-byte-string
/// conversion of `x_P`.
pub struct ECCDH<C: Curve>(PhantomData<C>);

impl<C: Curve> ECCDH<C> {
    const NAME: ConstStr<40> = ConstStr::concat(&["ECC-CDH-", C::NAME]);
}

impl<C: Curve> Algorithm for ECCDH<C> {
    const ALG_NAME: &'static str = Self::NAME.as_str();
    /// SP 800-57 Part 1 Rev. 5 Table 2, from the order's bit length.
    const MAX_SECURITY_STRENGTH: SecurityStrength = C::STRENGTH;
}

impl<C: Curve> KeyAgreementAlgorithm for ECCDH<C> {}

/// The worker [`AgreementKey::create_agreement`] hands out: the own key, borrowed. Reusable
/// against any number of peers, as a static key is in SP 800-56A Rev. 3 Section 6.2's schemes.
pub struct ECCDHAgreement<'k, C: Curve> {
    sk: &'k ECCDHPrivateKey<C>,
}

impl<C: Curve> Algorithm for ECCDHAgreement<'_, C> {
    const ALG_NAME: &'static str = ECCDH::<C>::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = ECCDH::<C>::MAX_SECURITY_STRENGTH;
}

/// SP 800-56A Rev. 3 Section 5.7.1.2, the ECC CDH primitive, with `d` this worker's key and `Q`
/// the peer's: `Z` into `ss`, zeroized first, typed [`KeyType::SharedSecret`] at the curve's
/// strength, keying material for a KDF (Section 5.8), which nothing else accepts as a key. Into
/// the caller's buffer rather than returned, so that no copy of `Z` is staged in a return slot.
pub(crate) fn agree_out<C, const SS_LEN: usize>(
    sk: &ECCDHPrivateKey<C>,
    peer_pk: &ECCDHPublicKey<C>,
    ss: &mut KeyMaterial<SS_LEN>,
) -> Result<(), KeyAgreementError>
where
    C: Curve<FeBytes = [u8; SS_LEN]>,
{
    // 1. Compute the point P = h d_A Q_B. The cofactor h is 1 (the crate docs), so this is [d]Q, in
    //    constant time in d; Q passed full validation when the key was decoded.
    let q = C::Point::from_affine(peer_pk.x, peer_pk.y);
    let mut p = C::multiply_point(sk.scalar(), &q);
    z_from_product::<C, SS_LEN>(&mut p, ss)
}

/// Steps 2 to 5 of Section 5.7.1.2 from `P = [d]Q`, which is destroyed here, into `ss`,
/// zeroized first and left so on the error path. Apart from the multiplication so that step 2's
/// identity path, which no validated key reaches, has a test.
#[allow(non_snake_case)] // `z` and `Z` are Section 5.7.1.2's names for x_P and its byte string
fn z_from_product<C, const SS_LEN: usize>(
    p: &mut C::Point,
    ss: &mut KeyMaterial<SS_LEN>,
) -> Result<(), KeyAgreementError>
where
    C: Curve<FeBytes = [u8; SS_LEN]>,
{
    ss.zeroize();

    // 2. If P = O, destroy all intermediate values ... and output an error indicator. [d]Q is
    //    the identity only for a Q of order dividing d, which a validated point of prime order n
    //    never is; the test is kept, on a condition no valid input reaches, and acted on after
    //    the zeroizing below so that the error path destroys the intermediates too.
    let p_is_infinity = p.is_infinity();

    // 3. Set z = x_P and convert z to Z (Appendix C.2, the field-element-to-byte-string
    //    conversion: big-endian, SS_LEN bytes, which is SEC 1's form). The affine x is computed
    //    without `to_affine`'s identity branch, since P came from the secret d; the limbs and
    //    the bytes are held in `Secret`s, scrubbed on return.
    let mut z = p.affine_x_of_nonidentity();
    let mut z_limbs = Secret::<C::Limbs>::new();
    z.to_limbs_into(&mut z_limbs);
    let mut Z = Secret::<[u8; SS_LEN]>::new();
    C::fe_be_bytes_from_limbs_into(&z_limbs, &mut Z);

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
    //    so through its courtesy error, and takes no strength; that is not an error. The buffer
    //    skips that zero test while the caller's hazardous window is open, so an open buffer
    //    gets an all-zero Z typed SharedSecret: closing the window is the caller's side of it.
    //    Neither error below is reachable (the buffer is SS_LEN bytes and SharedSecret takes a
    //    strength), but each leaves the buffer zeroized, as the doc above says.
    match ss.set_bytes_as_type(&*Z, KeyType::SharedSecret) {
        Ok(()) | Err(KeyMaterialError::ActingOnZeroizedKey) => {}
        Err(e) => {
            ss.zeroize();
            return Err(e.into());
        }
    }
    if ss.key_type() == KeyType::SharedSecret
        && let Err(e) = do_hazardous_operations(ss, |ss| ss.set_security_strength(C::STRENGTH))
    {
        ss.zeroize();
        return Err(e.into());
    }
    Ok(())
}

impl<C, const SS_LEN: usize> KeyAgreement<ECCDHPublicKey<C>, SS_LEN> for ECCDHAgreement<'_, C>
where
    C: Curve<FeBytes = [u8; SS_LEN]>,
{
    fn agree_out(
        &self,
        peer_pk: &ECCDHPublicKey<C>,
        ss: &mut KeyMaterial<SS_LEN>,
    ) -> Result<usize, KeyAgreementError> {
        agree_out::<C, SS_LEN>(self.sk, peer_pk, ss)?;
        Ok(SS_LEN)
    }
}

impl<C, const SS_LEN: usize> AgreementKey<(), SS_LEN> for ECCDHPrivateKey<C>
where
    C: Curve<FeBytes = [u8; SS_LEN]>,
{
    type Algorithm = ECCDH<C>;
    type PublicKey = ECCDHPublicKey<C>;
    type Agreement<'k>
        = ECCDHAgreement<'k, C>
    where
        Self: 'k;

    /// The raw primitive takes nothing beyond the key, so this never fails.
    fn create_agreement<'k>(
        &'k self,
        _params: (),
    ) -> Result<Self::Agreement<'k>, KeyAgreementError> {
        Ok(ECCDHAgreement { sk: self })
    }
}

/*** The same keys under a KDF: the pairings, and one role impl over them ***/

/// The hash a curve's X9.63 and concatenation KDF pairings run over: the SHA-2 at the curve's
/// strength (SHA-256 for the 256-bit curves, SHA-384 for the 384-bit ones, SHA-512 for P-521
/// and brainpoolP512r1), which is what the library pairs; a KDF over another hash is reached
/// by hand from the raw `Z`.
pub trait MatchedHash: Curve {
    /// The hash.
    type Hash: X963KDFParams + ConcatKDFParams;
}

impl MatchedHash for P256 {
    type Hash = SHA256;
}
impl MatchedHash for P384 {
    type Hash = SHA384;
}
impl MatchedHash for P521 {
    type Hash = SHA512;
}
impl MatchedHash for Secp256K1 {
    type Hash = SHA256;
}
impl MatchedHash for Bp256r1 {
    type Hash = SHA256;
}
impl MatchedHash for Bp384r1 {
    type Hash = SHA384;
}
impl MatchedHash for Bp512r1 {
    type Hash = SHA512;
}

/// ECC CDH over `C` with the shared secret derived through HKDF-SHA256: the algorithm an
/// [`ECCDHPrivateKey<C>`] runs when made into a worker from
/// `KdfParams<'p, HkdfDescription<'s, SHA256>, LEN>`. The key is HKDF-SHA256(salt, Z, info) over
/// the primitive's `Z`, the salt the description's, of
/// the length the parameters name, at the curve's strength, which HKDF-SHA256 caps at 128 bits;
/// paired on P-256, whose strength that is. Named `ECC-CDH-<curve>-HKDF-SHA256`.
#[allow(non_camel_case_types)]
pub struct ECCDH_HKDF_SHA256<C: Curve>(PhantomData<C>);

impl<C: Curve> ECCDH_HKDF_SHA256<C> {
    const NAME: ConstStr<48> = ConstStr::concat(&["ECC-CDH-", C::NAME, "-HKDF-SHA256"]);
}

impl<C: Curve> Algorithm for ECCDH_HKDF_SHA256<C> {
    const ALG_NAME: &'static str = Self::NAME.as_str();
    const MAX_SECURITY_STRENGTH: SecurityStrength = C::STRENGTH;
}

impl<C: Curve> KeyAgreementAlgorithm for ECCDH_HKDF_SHA256<C> {}

impl<const SS_LEN: usize> KdfPairing<HkdfDescription<'_, SHA256>, SS_LEN> for ECCDH<P256> {
    type Algorithm = ECCDH_HKDF_SHA256<P256>;
}

/// ECC CDH over `C` with the keying data derived through the ANSI X9.63 KDF over `H` (SEC 1 v2
/// Sections 3.6.1 and 6.1): the algorithm an [`ECCDHPrivateKey<C>`] runs when made into a worker
/// from `KdfParams<'p, X963KDF<H>, LEN>`, `H` the curve's [`MatchedHash`]. The key is
/// `KDF(Z, SharedInfo)` with `keydatalen` the parameters' length, at the curve's strength. Named
/// `ECC-CDH-<curve>-X963KDF-<hash>`.
#[allow(non_camel_case_types)]
pub struct ECCDH_X963KDF<C: Curve, H: X963KDFParams>(PhantomData<(C, H)>);

impl<C: Curve, H: X963KDFParams> ECCDH_X963KDF<C, H> {
    const NAME: ConstStr<48> = ConstStr::concat(&["ECC-CDH-", C::NAME, "-", H::X963KDF_ALG_NAME]);
}

impl<C: Curve, H: X963KDFParams> Algorithm for ECCDH_X963KDF<C, H> {
    const ALG_NAME: &'static str = Self::NAME.as_str();
    const MAX_SECURITY_STRENGTH: SecurityStrength = C::STRENGTH;
}

impl<C: Curve, H: X963KDFParams> KeyAgreementAlgorithm for ECCDH_X963KDF<C, H> {}

impl<C: MatchedHash, const SS_LEN: usize> KdfPairing<X963KDF<C::Hash>, SS_LEN> for ECCDH<C> {
    type Algorithm = ECCDH_X963KDF<C, C::Hash>;
}

/// ECC CDH over `C` with the keying material derived through the NIST concatenation KDF over
/// `H` (SP 800-56C Rev. 2 Section 4.1, Option 1, as SP 800-56A Rev. 3 Section 5.8 calls for):
/// the algorithm an [`ECCDHPrivateKey<C>`] runs when made into a worker from
/// `KdfParams<'p, ConcatKDF<H>, LEN>`, `H` the curve's [`MatchedHash`]. The key is
/// `KDM(Z, OtherInput)` with `FixedInfo` the parameters' fixed info and `L` their length, at the
/// curve's strength. Named `ECC-CDH-<curve>-ConcatKDF-<hash>`.
#[allow(non_camel_case_types)]
pub struct ECCDH_ConcatKDF<C: Curve, H: ConcatKDFParams>(PhantomData<(C, H)>);

impl<C: Curve, H: ConcatKDFParams> ECCDH_ConcatKDF<C, H> {
    const NAME: ConstStr<48> =
        ConstStr::concat(&["ECC-CDH-", C::NAME, "-", H::CONCAT_KDF_ALG_NAME]);
}

impl<C: Curve, H: ConcatKDFParams> Algorithm for ECCDH_ConcatKDF<C, H> {
    const ALG_NAME: &'static str = Self::NAME.as_str();
    const MAX_SECURITY_STRENGTH: SecurityStrength = C::STRENGTH;
}

impl<C: Curve, H: ConcatKDFParams> KeyAgreementAlgorithm for ECCDH_ConcatKDF<C, H> {}

impl<C: MatchedHash, const SS_LEN: usize> KdfPairing<ConcatKDF<C::Hash>, SS_LEN> for ECCDH<C> {
    type Algorithm = ECCDH_ConcatKDF<C, C::Hash>;
}

/// The worker [`AgreementKey::create_agreement`] hands out over [`KdfParams`]: the own key and
/// the KDF's parameters, borrowed separately. Reusable against any number of peers.
pub struct ECCDHKdfAgreement<
    'k,
    'p,
    C: Curve,
    D: KdfDescription + PairedKdf + ?Sized,
    const SS_LEN: usize,
> {
    sk: &'k ECCDHPrivateKey<C>,
    params: KdfParams<'p, D, SS_LEN>,
}

impl<C: Curve, D: KdfDescription + PairedKdf + ?Sized, const SS_LEN: usize> Algorithm
    for ECCDHKdfAgreement<'_, '_, C, D, SS_LEN>
where
    ECCDH<C>: KdfPairing<D, SS_LEN>,
{
    const ALG_NAME: &'static str = <ECCDH<C> as KdfPairing<D, SS_LEN>>::Algorithm::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength =
        <ECCDH<C> as KdfPairing<D, SS_LEN>>::Algorithm::MAX_SECURITY_STRENGTH;
}

impl<C, D: KdfDescription + PairedKdf + ?Sized, const Z_LEN: usize, const SS_LEN: usize>
    KeyAgreement<ECCDHPublicKey<C>, SS_LEN> for ECCDHKdfAgreement<'_, '_, C, D, SS_LEN>
where
    C: Curve<FeBytes = [u8; Z_LEN]>,
    ECCDH<C>: KdfPairing<D, SS_LEN>,
{
    /// `Z` from the primitive, then the KDF into the caller's buffer (SP 800-56A Rev. 3 Section
    /// 5.8; SEC 1 Section 6.1's steps for the X9.63 KDF): `Z` is typed `SharedSecret`, which the
    /// KDF credits; this crate's frames hold it in one local, wiped when it drops.
    fn agree_out(
        &self,
        peer_pk: &ECCDHPublicKey<C>,
        ss: &mut KeyMaterial<SS_LEN>,
    ) -> Result<usize, KeyAgreementError> {
        ss.zeroize();
        // Z lives in this local, zeroized when it drops, and is written into it rather than
        // returned, so this crate stages no copy of it on the way to the KDF. The copy the KDF's
        // hash leaves when it finalises by value is the crate docs' subject, not this frame's.
        let mut z = KeyMaterial::<Z_LEN>::new();
        agree_out::<C, Z_LEN>(self.sk, peer_pk, &mut z)?;
        derive(self.params, &z, ss)?;
        Ok(SS_LEN)
    }
}

impl<'p, C, D: KdfDescription + PairedKdf + ?Sized, const Z_LEN: usize, const SS_LEN: usize>
    AgreementKey<KdfParams<'p, D, SS_LEN>, SS_LEN> for ECCDHPrivateKey<C>
where
    C: Curve<FeBytes = [u8; Z_LEN]>,
    ECCDH<C>: KdfPairing<D, SS_LEN>,
{
    type Algorithm = <ECCDH<C> as KdfPairing<D, SS_LEN>>::Algorithm;
    type PublicKey = ECCDHPublicKey<C>;
    type Agreement<'k>
        = ECCDHKdfAgreement<'k, 'p, C, D, SS_LEN>
    where
        Self: 'k;

    /// Cannot fail: the KDF validated what it was made from when it was made.
    fn create_agreement<'k>(
        &'k self,
        params: KdfParams<'p, D, SS_LEN>,
    ) -> Result<Self::Agreement<'k>, KeyAgreementError> {
        Ok(ECCDHKdfAgreement { sk: self, params })
    }
}

// Section 5.7.1.2 step 2's identity check is on a condition no validated peer key and in-range d
// can reach ([d]Q = O needs a Q of order dividing d, and every point here has prime order n), so
// no integration test can drive it; it is pinned here on the product directly, on P-256.
#[cfg(test)]
mod tests {
    use super::*;
    use bouncycastle_ec::hazmat::p256_domain::{G_X_LIMBS, G_Y_LIMBS};

    type Fe = <P256 as Curve>::Fe;
    type Point = <P256 as Curve>::Point;
    const SS_LEN: usize = P256::FE_LEN;

    #[test]
    fn the_identity_product_is_an_error_and_leaves_the_buffer_zeroized() {
        let mut o = Point::INFINITY;
        let mut ss =
            KeyMaterial::<SS_LEN>::from_bytes_as_type(&[0xFF; SS_LEN], KeyType::Seed).unwrap();
        assert!(matches!(
            z_from_product::<P256, SS_LEN>(&mut o, &mut ss),
            Err(KeyAgreementError::AgreementFailed)
        ));
        assert_eq!(ss.key_type(), KeyType::Zeroized);
        assert_eq!(ss.key_len(), 0);
    }

    /// Step 5's typing on a real product (G, so Z is G's x), and step 4's destruction of P, which
    /// no integration test can see.
    #[test]
    fn a_real_product_types_z_at_the_curve_strength_and_zeroizes_the_point() {
        let mut p = Point::from_affine(Fe::from_limbs(G_X_LIMBS), Fe::from_limbs(G_Y_LIMBS));
        let mut ss =
            KeyMaterial::<SS_LEN>::from_bytes_as_type(&[0xFF; SS_LEN], KeyType::Seed).unwrap();
        assert_eq!(z_from_product::<P256, SS_LEN>(&mut p, &mut ss), Ok(()));
        assert_eq!(ss.key_type(), KeyType::SharedSecret);
        assert_eq!(ss.security_strength(), ECCDH::<P256>::MAX_SECURITY_STRENGTH);
        assert_eq!(ss.ref_to_bytes(), &P256::fe_be_bytes_from_limbs(&G_X_LIMBS)[..]);
        assert_eq!([p.x().to_limbs(), p.y().to_limbs(), p.z().to_limbs()], [[0u64; 4]; 3]);
    }
}
