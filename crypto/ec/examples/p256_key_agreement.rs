//! ECC CDH over P-256 (SP 800-56A Rev. 3 Section 5.7.1.2) on the key-agreement roles of
//! `bouncycastle_core::agreement_key`, built from this crate's hazmat arithmetic: what the
//! `bouncycastle-ecdh` crate will hold, in one file, checked against RFC 5903 Section 8.1.
//!
//! The raw primitive is the role impl over `()`. The same keys implement the role a second
//! time over an HKDF configuration, `HkdfParams`, deriving a key from `Z` with HKDF-SHA256 as
//! the two-step key-derivation method of SP 800-56C does; the parameter type picks between the
//! two at the call. The derived key reports 128 bits, HKDF-SHA256's cap, which is also the
//! curve's strength.
//!
//! Run with `cargo run -p bouncycastle-ec --example p256_key_agreement`.

use bouncycastle_core::agreement_key::{AgreementKey, KeyAgreementAlgorithm};
use bouncycastle_core::errors::{KeyAgreementError, RNGError};
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{
    Algorithm, KeyAgreement, KeyAgreementPrivateKey, KeyAgreementPublicKey, RNG,
};
use bouncycastle_ec::hazmat::p256::P256FieldElement;
use bouncycastle_ec::hazmat::p256_comb::comb_multiply_base_point;
use bouncycastle_ec::hazmat::p256_extra_bits::reduce_wide_bits_mod_n_minus_1;
use bouncycastle_ec::hazmat::p256_mul::multiply_point;
use bouncycastle_ec::hazmat::p256_point::P256JacobianPoint;
use bouncycastle_ec::hazmat::p256_scalar::P256Scalar;
use bouncycastle_ec::hazmat::p256_sec1;
use bouncycastle_hex as hex;
use bouncycastle_rng::HashDRBG_SHA512;
use bouncycastle_sha2::hkdf::HKDF_SHA256;
use bouncycastle_utils::secret::Secret;
use core::fmt;

/// SEC 1 Section 2.3.7 integer-to-octet-string of `d`: 32 bytes.
const SK_LEN: usize = 32;
/// SEC 1 Section 2.3.3 uncompressed `04 || X || Y`: 65 bytes.
const PK_LEN: usize = 65;
/// `Z` is the x-coordinate of the computed point (Section 5.7.1.2 step 3): a field element.
const SS_LEN: usize = 32;

/// The algorithm marker. Raw ECC CDH takes no parameters, so the role impl is over `()`; a
/// one-step KDF form (SP 800-56C) would be a second impl on these same keys over the
/// configured KDF, naming its own marker.
#[allow(non_camel_case_types)]
struct ECCDH_P256;

impl Algorithm for ECCDH_P256 {
    const ALG_NAME: &'static str = "ECC-CDH-P256";
    /// SP 800-57 Part 1 Rev. 5 Table 2: a 256-bit curve order gives 128 bits.
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

impl KeyAgreementAlgorithm for ECCDH_P256 {}

/// `d` in `[1, n-1]`, held in `Secret` through `P256Scalar`.
#[derive(Clone, PartialEq, Eq)]
struct P256PrivateKey(P256Scalar);

/// `Q = [d]G`, as the affine pair the SEC 1 codec validated.
#[derive(Clone, PartialEq, Eq, Debug)]
struct P256PublicKey {
    x: P256FieldElement,
    y: P256FieldElement,
}

impl fmt::Display for P256PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "P256PublicKey {{ {} }}", hex::encode(self.encode()))
    }
}

impl KeyAgreementPrivateKey<SK_LEN> for P256PrivateKey {
    fn encode(&self) -> [u8; SK_LEN] {
        self.0.to_be_bytes()
    }
    fn encode_out(&self, out: &mut [u8; SK_LEN]) -> usize {
        out.fill(0);
        *out = self.encode();
        SK_LEN
    }
    fn from_bytes(bytes: &[u8]) -> Result<Self, KeyAgreementError> {
        let bytes: [u8; SK_LEN] = bytes
            .try_into()
            .map_err(|_| KeyAgreementError::DecodingError("a P-256 private key is 32 bytes"))?;
        // `from_be_bytes` reduces mod n; a zero scalar is not a key (FIPS 186-5 Section 6.2.1).
        let d = P256Scalar::from_be_bytes(&bytes);
        if d.to_be_bytes() == [0u8; SK_LEN] {
            return Err(KeyAgreementError::DecodingError("d must be in [1, n-1]"));
        }
        Ok(Self(d))
    }
}

impl KeyAgreementPublicKey<PK_LEN> for P256PublicKey {
    fn encode(&self) -> [u8; PK_LEN] {
        p256_sec1::encode_uncompressed(&self.x, &self.y)
    }
    fn encode_out(&self, out: &mut [u8; PK_LEN]) -> usize {
        out.fill(0);
        *out = self.encode();
        PK_LEN
    }
    /// Full public-key validation (SP 800-186 Appendix D.1.1.1) happens here, in the SEC 1
    /// decoder, so a key that exists is on the curve and the agreement needs no further check.
    fn from_bytes(bytes: &[u8]) -> Result<Self, KeyAgreementError> {
        let (x, y) = p256_sec1::decode(bytes).ok_or(KeyAgreementError::DecodingError(
            "invalid or out-of-range SEC 1 P-256 point encoding",
        ))?;
        Ok(Self { x, y })
    }
}

/// FIPS 186-5 Appendix A.2.1 key-pair generation by extra random bits, as the ECDSA crate does
/// it: 352 bits from a DRBG of at least 128-bit strength, reduced into `[1, n-1]`.
fn keygen(rng: &mut dyn RNG) -> Result<(P256PublicKey, P256PrivateKey), KeyAgreementError> {
    if rng.security_strength() < ECCDH_P256::MAX_SECURITY_STRENGTH {
        return Err(RNGError::SecurityStrengthInsufficientForAlgorithm.into());
    }
    let mut extra_bits = Secret::<[u8; 44]>::new();
    rng.next_bytes_out(&mut *extra_bits)?;
    let d = reduce_wide_bits_mod_n_minus_1(&*extra_bits);

    let mut q = comb_multiply_base_point(&d);
    // d is in [1, n-1] and G has prime order n, so [d]G is never the identity.
    let (x, y) = q.to_affine().expect("[d]G is never infinity for d in [1, n-1]");
    q.zeroize();
    Ok((P256PublicKey { x, y }, P256PrivateKey(d)))
}

/// The worker: the own key, borrowed. Reusable against any number of peers.
struct P256Agreement<'k> {
    d: &'k P256PrivateKey,
}

impl Algorithm for P256Agreement<'_> {
    const ALG_NAME: &'static str = ECCDH_P256::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = ECCDH_P256::MAX_SECURITY_STRENGTH;
}

impl KeyAgreement<P256PublicKey, SS_LEN> for P256Agreement<'_> {
    /// SP 800-56A Rev. 3 Section 5.7.1.2, the ECC CDH primitive.
    fn agree(&self, peer_pk: &P256PublicKey) -> Result<KeyMaterial<SS_LEN>, KeyAgreementError> {
        // 1. Compute the point P = h d_A Q_B. P-256's cofactor h is 1 (SP 800-186 Section
        //    3.2.1.3), so this is [d]Q, in constant time in d; Q passed the decoder's on-curve
        //    check when the key was made.
        let q = P256JacobianPoint::from_affine(peer_pk.x, peer_pk.y);
        let mut p = multiply_point(&self.d.0, &q);

        // 2. If P = O, destroy all intermediate values ... and output an error indicator.
        //    [d]Q is the identity only for Q of order dividing d, which a validated point of
        //    prime order n never is; the branch reveals nothing about d.
        let Some((mut x_p, mut y_p)) = p.to_affine() else {
            p.zeroize();
            return Err(KeyAgreementError::AgreementFailed);
        };

        // 3. Set z = x_P and convert z to Z (Appendix C.2, the field-element-to-byte-string
        //    conversion, which is SEC 1's big-endian form).
        let mut z = Secret::<[u8; SS_LEN]>::new();
        *z = p256_sec1::be_bytes_from_limbs(&x_p.to_limbs());

        // 4. Destroy the results of all intermediate calculations (including P and z).
        p.zeroize();
        x_p.zeroize();
        y_p.zeroize();

        // 5. Output Z: keying material for a KDF (Section 5.8), typed so that a KDF credits it
        //    and nothing else accepts it as a key, at the curve's strength.
        let mut shared = KeyMaterial::<SS_LEN>::from_bytes_as_type(&*z, KeyType::SharedSecret)?;
        do_hazardous_operations(&mut shared, |shared| {
            shared.set_security_strength(ECCDH_P256::MAX_SECURITY_STRENGTH)
        })?;
        Ok(shared)
    }
}

impl AgreementKey<(), SS_LEN> for P256PrivateKey {
    type Algorithm = ECCDH_P256;
    type PublicKey = P256PublicKey;
    type Agreement<'k> = P256Agreement<'k>;

    fn create_agreement<'k>(
        &'k self,
        _params: (),
    ) -> Result<Self::Agreement<'k>, KeyAgreementError> {
        Ok(P256Agreement { d: self })
    }
}

/*** The same keys under a KDF: ECC CDH with HKDF-SHA256 ***/

/// The length of the derived key.
const DERIVED_LEN: usize = 32;

/// The HKDF configuration a worker is made from: RFC 5869's salt and info, borrowed from the
/// caller for `'p`. `Copy` so that the one value serves every construction.
#[derive(Clone, Copy)]
struct HkdfParams<'p> {
    salt: &'p KeyMaterial<32>,
    info: &'p [u8],
}

/// The marker: ECC CDH over P-256 whose output is HKDF-SHA256(salt, Z, info).
#[allow(non_camel_case_types)]
struct ECCDH_P256_HKDF_SHA256;

impl Algorithm for ECCDH_P256_HKDF_SHA256 {
    const ALG_NAME: &'static str = "ECC-CDH-P256-HKDF-SHA256";
    const MAX_SECURITY_STRENGTH: SecurityStrength = ECCDH_P256::MAX_SECURITY_STRENGTH;
}

impl KeyAgreementAlgorithm for ECCDH_P256_HKDF_SHA256 {}

/// The worker: the raw primitive's worker and the HKDF configuration, borrowed separately.
struct P256HkdfAgreement<'k, 'p> {
    inner: P256Agreement<'k>,
    params: HkdfParams<'p>,
}

impl Algorithm for P256HkdfAgreement<'_, '_> {
    const ALG_NAME: &'static str = ECCDH_P256_HKDF_SHA256::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = ECCDH_P256_HKDF_SHA256::MAX_SECURITY_STRENGTH;
}

impl KeyAgreement<P256PublicKey, DERIVED_LEN> for P256HkdfAgreement<'_, '_> {
    /// `Z` from the raw primitive, then the KDF (SP 800-56A Rev. 3 Section 5.8): `Z` is typed
    /// `SharedSecret`, which HKDF credits as keying material, and it never leaves this call.
    fn agree(
        &self,
        peer_pk: &P256PublicKey,
    ) -> Result<KeyMaterial<DERIVED_LEN>, KeyAgreementError> {
        let z = self.inner.agree(peer_pk)?;
        let mut okm = KeyMaterial::<DERIVED_LEN>::new();
        HKDF_SHA256::extract_and_expand_out(
            self.params.salt, &z, self.params.info, DERIVED_LEN, &mut okm,
        )
        .map_err(|_| KeyAgreementError::GenericError("HKDF failed"))?;
        Ok(okm)
    }
}

impl<'p> AgreementKey<HkdfParams<'p>, DERIVED_LEN> for P256PrivateKey {
    type Algorithm = ECCDH_P256_HKDF_SHA256;
    type PublicKey = P256PublicKey;
    type Agreement<'k> = P256HkdfAgreement<'k, 'p>;

    fn create_agreement<'k>(
        &'k self,
        params: HkdfParams<'p>,
    ) -> Result<Self::Agreement<'k>, KeyAgreementError> {
        // Where a KDF-bearing agreement validates its parameters, once, before any agreement.
        if params.salt.key_type() == KeyType::Unknown {
            return Err(KeyAgreementError::GenericError(
                "the HKDF salt must be typed key material",
            ));
        }
        Ok(P256HkdfAgreement { inner: P256Agreement { d: self }, params })
    }
}

fn main() {
    // RFC 5903 Section 8.1, the 256-bit random ECP group: the initiator's and responder's
    // private keys, their public keys and the shared secret (girx).
    let i = P256PrivateKey::from_bytes(
        &hex::decode("C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433").unwrap(),
    )
    .unwrap();
    let r = P256PrivateKey::from_bytes(
        &hex::decode("C6EF9C5D78AE012A011164ACB397CE2088685D8F06BF9BE0B283AB46476BEE53").unwrap(),
    )
    .unwrap();
    let gi = P256PublicKey::from_bytes(
        &hex::decode(
            "04DAD0B65394221CF9B051E1FECA5787D098DFE637FC90B9EF945D0C3772581180\
               5271A0461CDB8252D61F1C456FA3E59AB1F45B33ACCF5F58389E0577B8990BB3",
        )
        .unwrap(),
    )
    .unwrap();
    let gr = P256PublicKey::from_bytes(
        &hex::decode(
            "04D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF63\
               56FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB",
        )
        .unwrap(),
    )
    .unwrap();
    let girx =
        hex::decode("D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE").unwrap();

    // Each side's public key derives from its private key.
    let derive_pk = |sk: &P256PrivateKey| {
        let (x, y) = comb_multiply_base_point(&sk.0).to_affine().unwrap();
        P256PublicKey { x, y }
    };
    assert_eq!(derive_pk(&i), gi);
    assert_eq!(derive_pk(&r), gr);

    // The agreement, one-shot and through a worker, matches the vector from both sides.
    let z_i = i.agree((), &gr).unwrap();
    let z_r = r.create_agreement(()).unwrap().agree(&gi).unwrap();
    assert_eq!(z_i.ref_to_bytes(), girx.as_slice());
    assert!(z_i.equals(&z_r));
    println!("RFC 5903 8.1: Z = {}", hex::encode(z_i.ref_to_bytes()));
    println!("typed: {z_i}");

    // A fresh pair, as a protocol would make them.
    let mut rng = HashDRBG_SHA512::new_from_os();
    let (pk_a, sk_a) = keygen(&mut rng).unwrap();
    let (pk_b, sk_b) = keygen(&mut rng).unwrap();
    let agreement_a = sk_a.create_agreement(()).unwrap();
    assert!(agreement_a.agree(&pk_b).unwrap().equals(&sk_b.agree((), &pk_a).unwrap()));

    // The peer key is validated when decoded: a point off the curve never reaches `agree`.
    let mut off_curve = pk_b.encode();
    off_curve[64] ^= 1;
    assert!(matches!(
        P256PublicKey::from_bytes(&off_curve),
        Err(KeyAgreementError::DecodingError(_))
    ));
    println!("fresh pair agreed; off-curve peer key refused at decode");

    // The same keys under HKDF-SHA256: the parameter type selects the algorithm.
    let salt = KeyMaterial::<32>::from_rng(&mut rng).unwrap();
    let params = HkdfParams { salt: &salt, info: b"example protocol v1" };
    let key_a = sk_a.agree(params, &pk_b).unwrap();
    let key_b = sk_b.agree(params, &pk_a).unwrap();
    assert!(key_a.equals(&key_b));
    assert!(!key_a.equals(&sk_a.agree((), &pk_b).unwrap()), "derived key is not the raw Z");
    let other = HkdfParams { salt: &salt, info: b"example protocol v2" };
    assert!(
        !sk_b.agree(other, &pk_a).unwrap().equals(&key_a),
        "a different context, a different key"
    );
    let agreement = sk_a.create_agreement(params).unwrap(); // a static key's worker, params fixed once
    assert!(agreement.agree(&pk_b).unwrap().equals(&key_a));
    println!("HKDF-SHA256 over Z: {key_a}");
}
