//! `ECDSABp256r1` and `ECDetDSABp256r1`: FIPS 186-5 §6.4.1 (signature generation, with `k` drawn at
//! random for `ECDSABp256r1` per §6.3.1 or derived from `d` and the hash for `ECDetDSABp256r1` per
//! §6.3.2, as [`crate::ecdsa_p256`] lays out) and §6.4.2 (verification), fixed to SHA-256 (the
//! pairing wycheproof's `ecdsa_brainpoolP256r1_sha256_*` vector files use). Identical in shape to
//! [`crate::ecdsa_p256`] -- see that module's docs for the full reasoning (`e = bits2int(H)` needs
//! no truncation since `len(n) == hashlen == 256`; `x_affine_of_signing_point`'s
//! branch-free-on-a-secret-value argument; both hold unchanged here) -- with brainpoolP256r1's
//! types, [`crate::keys_bp256r1`], [`crate::extra_bits_bp256r1`], and [`crate::rfc6979_bp256r1`]
//! substituted.

use crate::extra_bits_bp256r1::reduce_wide_bits_mod_n_minus_1;
use crate::keys_bp256r1::{ECDSABp256r1PrivateKey, ECDSABp256r1PublicKey, PK_LEN, SK_LEN};
use crate::rfc6979_bp256r1;
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{Hash, RNG, SignatureVerifier, Signer};
use bouncycastle_ec::bp256r1::Bp256r1FieldElement;
use bouncycastle_ec::bp256r1_comb::comb_multiply_base_point;
use bouncycastle_ec::bp256r1_point::Bp256r1JacobianPoint;
use bouncycastle_ec::bp256r1_scalar::{
    Bp256r1PublicScalar, Bp256r1Scalar, Bp256r1ScalarField, N_LIMBS,
};
use bouncycastle_ec::bp256r1_sec1;
use bouncycastle_ec::bp256r1_wnaf::shamir_multiply;
use bouncycastle_ec::nat;
use bouncycastle_rng::DefaultRNG;
use bouncycastle_sha2::SHA256;
use bouncycastle_utils::secret::Secret;

/// Raw `r || s` signature length: two 32-byte field-width integers, the default encoding.
/// [`ECDSABp256r1::sign_der`]/[`ECDSABp256r1::verify_der`] offer the RFC 3279
/// §2.2.3 DER `SEQUENCE { r, s }` alternative via [`crate::der`], for interop that needs it.
pub const SIG_LEN: usize = 64;

/// Upper bound on a DER-encoded brainpoolP256r1 signature (`r`, `s` each 32 bytes); see
/// [`crate::der::max_len`].
pub const DER_SIG_MAX_LEN: usize = crate::der::max_len(32);

/// ECDSA over brainpoolP256r1 with a random per-message secret (FIPS 186-5 §6.3.1, Appendix A.3.1);
/// see [`crate::ecdsa_p256::ECDSAP256`]'s docs. Streaming state for both the [`Signer`] and
/// [`SignatureVerifier`] impls. [`ECDetDSABp256r1`] is the deterministic variant.
pub struct ECDSABp256r1 {
    hash: SHA256,
    sk: Option<ECDSABp256r1PrivateKey>,
    pk: Option<ECDSABp256r1PublicKey>,
}

/// Deterministic ECDSA over brainpoolP256r1 (FIPS 186-5 §6.3.2, Appendix A.3.3, RFC 6979); see
/// [`crate::ecdsa_p256::ECDetDSAP256`]'s docs. Streaming state as for [`ECDSABp256r1`].
pub struct ECDetDSABp256r1 {
    hash: SHA256,
    sk: Option<ECDSABp256r1PrivateKey>,
    pk: Option<ECDSABp256r1PublicKey>,
}

/// `x * z^-2`, branch-free -- see [`crate::ecdsa_p256`]'s module docs for why this isn't
/// [`Bp256r1JacobianPoint::to_affine`].
fn x_affine_of_signing_point(point: &Bp256r1JacobianPoint) -> Bp256r1FieldElement {
    let z_inv = point.z.invert();
    point.x.mul(&z_inv.mul(&z_inv))
}

/// FIPS 186-5 §6.4.1 steps 4-12, given `k` already generated (step 3) by one of Appendix A.3's
/// methods. Returns `Err` only for step 11's negligible-probability `r = 0` or `s = 0` case.
fn sign_with_k(
    sk: &ECDSABp256r1PrivateKey,
    e: &Bp256r1ScalarField,
    k: Bp256r1Scalar,
) -> Result<[u8; SIG_LEN], SignatureError> {
    let mut k_field = Bp256r1ScalarField::from_secret(&k);
    let mut k_inv = k_field.invert(); // step 4

    let r_point = comb_multiply_base_point(&k); // step 5
    let x_r = x_affine_of_signing_point(&r_point); // steps 6-7
    let r = Bp256r1ScalarField::from_limbs(x_r.to_limbs()); // step 8

    let mut d_field = Bp256r1ScalarField::from_secret(sk.scalar());
    let s = k_inv.mul(&e.add(&r.mul(&d_field))); // step 9

    // `k_field`, `k_inv` and `d_field` hold `k`, `k^-1` and `d`. Nothing below needs them, so they
    // are overwritten here rather than left legible on the stack after this returns -- placed
    // before step 11's check so that both ways out of the function are covered. `k` itself is a
    // `Secret` and scrubs when it drops; `e`, `r` and `s` are public by construction.
    k_field.zeroize();
    k_inv.zeroize();
    d_field.zeroize();

    // step 11: astronomically unlikely (r, s range over ~2^256 values each); this comparison is
    // FIPS 186-5's own mandated success/failure branch on the just-computed public output, not a
    // constant-time violation -- see this module's docs on x_affine_of_signing_point for the one
    // secret-derived branch this function does avoid.
    if r_or_s_is_zero(&r, &s) {
        return Err(SignatureError::GenericError(
            "ECDSA signature generation produced r = 0 or s = 0; regenerate k and retry",
        ));
    }

    let mut sig = [0u8; SIG_LEN];
    sig[..32].copy_from_slice(&bp256r1_sec1::be_bytes_from_limbs(&r.to_limbs()));
    sig[32..].copy_from_slice(&bp256r1_sec1::be_bytes_from_limbs(&s.to_limbs()));
    Ok(sig)
}

/// FIPS 186-5 §6.4.1 step 3 by Appendix A.3.1, reduced into `[1, n-1]` by
/// `reduce_wide_bits_mod_n_minus_1`; the one place [`ECDSABp256r1`]'s signing paths draw `k`.
fn random_k(rng: &mut dyn RNG) -> Result<Bp256r1Scalar, SignatureError> {
    // Raw DRBG output, reduced below into the per-message secret: held in `Secret` so it is
    // scrubbed when this function returns rather than left on the stack.
    let mut extra_bits = Secret::<[u8; crate::keys_bp256r1::EXTRA_BITS_DRBG_OUTPUT_LEN]>::new();
    rng.next_bytes_out(&mut *extra_bits).map_err(SignatureError::RNGError)?;
    Ok(reduce_wide_bits_mod_n_minus_1(&*extra_bits))
}

/// `e` from a 32-byte message hash: FIPS 186-5 §6.4.1 step 2 / §6.4.2 step 3, `E = H` (no
/// truncation needed -- see the module docs) then Appendix B.2.1's big-endian conversion.
fn e_from_hash(h: &[u8; 32]) -> Bp256r1ScalarField {
    Bp256r1ScalarField::from_limbs(bp256r1_sec1::limbs_from_be_bytes(h))
}

/// FIPS 186-5 §6.4.1 step 11's `r = 0` or `s = 0` check, named so it has something to unit test
/// directly: reaching either branch through `sign_with_k` needs an `r`/`s` value that is
/// astronomically unlikely for any real `k`/`d`/message (see [`sign_with_k`]'s call site).
fn r_or_s_is_zero(r: &Bp256r1ScalarField, s: &Bp256r1ScalarField) -> bool {
    *r == Bp256r1ScalarField::ZERO || *s == Bp256r1ScalarField::ZERO
}

/// FIPS 186-5 §6.4.2 on the finished message hash; both signer types' `do_verify_final` are
/// this one function. See `crate::ecdsa_p256`'s `verify_final`.
fn verify_final(
    hash: SHA256,
    pk: &ECDSABp256r1PublicKey,
    sig: &[u8],
) -> Result<(), SignatureError> {
    // Exactly SIG_LEN, not "at least": the raw encoding is two fixed-width integers and
    // nothing else, so trailing bytes make this a different, malformed encoding rather than a
    // valid signature in a roomy buffer. Accepting them would let anyone turn one valid
    // signature into unlimited distinct byte strings that all verify -- malleability that
    // breaks any caller treating the signature as an opaque, comparable blob. This matches how
    // `SignaturePublicKey`/`SignaturePrivateKey::from_bytes` already reject an over-long
    // encoding here (see `core-test-framework`'s own `test_boundary_conditions`).
    if sig.len() != SIG_LEN {
        return Err(SignatureError::SignatureVerificationFailed);
    }

    // step 1: r, s in [1, n-1], rejected (not reduced) if out of range.
    let r_limbs = bp256r1_sec1::limbs_from_be_bytes(&sig[..32].try_into().unwrap());
    let s_limbs = bp256r1_sec1::limbs_from_be_bytes(&sig[32..64].try_into().unwrap());
    if !in_range(&r_limbs) || !in_range(&s_limbs) {
        return Err(SignatureError::SignatureVerificationFailed);
    }
    let r = Bp256r1ScalarField::from_limbs(r_limbs);

    let mut h = [0u8; 32];
    hash.do_final_out(&mut h);
    let e = e_from_hash(&h); // steps 2-3

    // `s` is part of the signature, so its inverse is taken in variable time on the public
    // scalar type; the constant-time `invert` is for the signer's `k`.
    let s_inv = Bp256r1PublicScalar::from_limbs(s_limbs).invert_vartime(); // step 4
    let u = e.mul(&s_inv); // step 5
    let v = r.mul(&s_inv);

    let q = Bp256r1JacobianPoint::from_affine(pk.x, pk.y);
    let u_pub = Bp256r1PublicScalar::from_limbs(u.to_limbs());
    let v_pub = Bp256r1PublicScalar::from_limbs(v.to_limbs());
    let r1_point = shamir_multiply(&u_pub, &v_pub, &q); // step 6

    if r1_point.is_infinity().to_bool() {
        return Err(SignatureError::SignatureVerificationFailed);
    }
    let (x_r1, _) =
        r1_point.to_affine().expect("just checked r1_point is not the point at infinity");
    let r1 = Bp256r1ScalarField::from_limbs(x_r1.to_limbs()); // steps 7-8

    if r1 == r { Ok(()) } else { Err(SignatureError::SignatureVerificationFailed) } // step 9
}

/// RFC 3279 §2.2.3 `Ecdsa-Sig-Value` from raw `r || s`, with the encoded length; see
/// `crate::ecdsa_p256`'s `der_encode`.
fn der_encode(raw: &[u8; SIG_LEN]) -> ([u8; DER_SIG_MAX_LEN], usize) {
    let mut out = [0u8; DER_SIG_MAX_LEN];
    let len = crate::der::encode(&raw[..32], &raw[32..], &mut out);
    (out, len)
}

/// Raw `r || s` from a DER `Ecdsa-Sig-Value`; a malformed encoding is a verification failure.
fn der_decode(sig: &[u8]) -> Result<[u8; SIG_LEN], SignatureError> {
    let mut raw = [0u8; SIG_LEN];
    let (r_out, s_out) = raw.split_at_mut(32);
    crate::der::decode(sig, r_out, s_out).ok_or(SignatureError::SignatureVerificationFailed)?;
    Ok(raw)
}

impl ECDSABp256r1 {
    /// As [`Signer::sign`], with `k` drawn from `rng` instead of the library's default RNG.
    pub fn sign_rng(
        sk: &ECDSABp256r1PrivateKey,
        msg: &[u8],
        ctx: Option<&[u8]>,
        rng: &mut dyn RNG,
    ) -> Result<[u8; SIG_LEN], SignatureError> {
        let mut s = Self::do_sign_init(sk, ctx)?;
        s.do_sign_update(msg);
        s.do_sign_final_rng(rng)
    }

    /// As [`Signer::do_sign_final`], with `k` drawn from `rng` instead of the library's default
    /// RNG.
    pub fn do_sign_final_rng(self, rng: &mut dyn RNG) -> Result<[u8; SIG_LEN], SignatureError> {
        let sk = self.sk.ok_or(SignatureError::GenericError(
            "do_sign_final called on a verify-initialized ECDSABp256r1; call do_verify_final instead",
        ))?;
        let mut h = [0u8; 32];
        self.hash.do_final_out(&mut h);
        let k = random_k(rng)?;
        sign_with_k(&sk, &e_from_hash(&h), k)
    }

    /// As [`Signer::sign`], but DER-encoded; see [`crate::ecdsa_p256::ECDSAP256::sign_der`].
    pub fn sign_der(
        sk: &ECDSABp256r1PrivateKey,
        msg: &[u8],
        ctx: Option<&[u8]>,
    ) -> Result<([u8; DER_SIG_MAX_LEN], usize), SignatureError> {
        Ok(der_encode(&Self::sign(sk, msg, ctx)?))
    }

    /// As [`SignatureVerifier::verify`], but for a DER-encoded signature; see
    /// [`crate::ecdsa_p256::ECDSAP256::verify_der`].
    pub fn verify_der(
        pk: &ECDSABp256r1PublicKey,
        msg: &[u8],
        ctx: Option<&[u8]>,
        sig: &[u8],
    ) -> Result<(), SignatureError> {
        Self::verify(pk, msg, ctx, &der_decode(sig)?)
    }
}

impl ECDetDSABp256r1 {
    /// As [`Signer::sign`], but DER-encoded; see [`crate::ecdsa_p256::ECDSAP256::sign_der`].
    pub fn sign_der(
        sk: &ECDSABp256r1PrivateKey,
        msg: &[u8],
        ctx: Option<&[u8]>,
    ) -> Result<([u8; DER_SIG_MAX_LEN], usize), SignatureError> {
        Ok(der_encode(&Self::sign(sk, msg, ctx)?))
    }

    /// As [`SignatureVerifier::verify`], but for a DER-encoded signature; see
    /// [`crate::ecdsa_p256::ECDSAP256::verify_der`].
    pub fn verify_der(
        pk: &ECDSABp256r1PublicKey,
        msg: &[u8],
        ctx: Option<&[u8]>,
        sig: &[u8],
    ) -> Result<(), SignatureError> {
        Self::verify(pk, msg, ctx, &der_decode(sig)?)
    }
}

impl Signer<ECDSABp256r1PrivateKey, SK_LEN, SIG_LEN> for ECDSABp256r1 {
    fn sign(
        sk: &ECDSABp256r1PrivateKey,
        msg: &[u8],
        ctx: Option<&[u8]>,
    ) -> Result<[u8; SIG_LEN], SignatureError> {
        let mut s = Self::do_sign_init(sk, ctx)?;
        s.do_sign_update(msg);
        s.do_sign_final()
    }

    fn sign_out(
        sk: &ECDSABp256r1PrivateKey,
        msg: &[u8],
        ctx: Option<&[u8]>,
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError> {
        output.fill(0);
        *output = Self::sign(sk, msg, ctx)?;
        Ok(SIG_LEN)
    }

    fn do_sign_init(
        sk: &ECDSABp256r1PrivateKey,
        _ctx: Option<&[u8]>,
    ) -> Result<Self, SignatureError> {
        Ok(Self { hash: SHA256::default(), sk: Some(sk.clone()), pk: None })
    }

    fn do_sign_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn do_sign_final(self) -> Result<[u8; SIG_LEN], SignatureError> {
        self.do_sign_final_rng(&mut DefaultRNG::default())
    }

    fn do_sign_final_out(self, output: &mut [u8; SIG_LEN]) -> Result<usize, SignatureError> {
        output.fill(0);
        *output = self.do_sign_final()?;
        Ok(SIG_LEN)
    }
}

impl Signer<ECDSABp256r1PrivateKey, SK_LEN, SIG_LEN> for ECDetDSABp256r1 {
    fn sign(
        sk: &ECDSABp256r1PrivateKey,
        msg: &[u8],
        ctx: Option<&[u8]>,
    ) -> Result<[u8; SIG_LEN], SignatureError> {
        let mut s = Self::do_sign_init(sk, ctx)?;
        s.do_sign_update(msg);
        s.do_sign_final()
    }

    fn sign_out(
        sk: &ECDSABp256r1PrivateKey,
        msg: &[u8],
        ctx: Option<&[u8]>,
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError> {
        output.fill(0);
        *output = Self::sign(sk, msg, ctx)?;
        Ok(SIG_LEN)
    }

    fn do_sign_init(
        sk: &ECDSABp256r1PrivateKey,
        _ctx: Option<&[u8]>,
    ) -> Result<Self, SignatureError> {
        Ok(Self { hash: SHA256::default(), sk: Some(sk.clone()), pk: None })
    }

    fn do_sign_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn do_sign_final(self) -> Result<[u8; SIG_LEN], SignatureError> {
        let sk = self.sk.ok_or(SignatureError::GenericError(
            "do_sign_final on a verify-initialized ECDetDSABp256r1; call do_verify_final",
        ))?;
        let mut h = [0u8; 32];
        self.hash.do_final_out(&mut h);
        let k = rfc6979_bp256r1::generate_k(sk.scalar(), &h); // step 3, Appendix A.3.3
        sign_with_k(&sk, &e_from_hash(&h), k)
    }

    fn do_sign_final_out(self, output: &mut [u8; SIG_LEN]) -> Result<usize, SignatureError> {
        output.fill(0);
        *output = self.do_sign_final()?;
        Ok(SIG_LEN)
    }
}

impl SignatureVerifier<ECDSABp256r1PublicKey, PK_LEN, SIG_LEN> for ECDSABp256r1 {
    fn verify(
        pk: &ECDSABp256r1PublicKey,
        msg: &[u8],
        ctx: Option<&[u8]>,
        sig: &[u8],
    ) -> Result<(), SignatureError> {
        let mut v = Self::do_verify_init(pk, ctx)?;
        v.do_verify_update(msg);
        v.do_verify_final(sig)
    }

    fn do_verify_init(
        pk: &ECDSABp256r1PublicKey,
        _ctx: Option<&[u8]>,
    ) -> Result<Self, SignatureError> {
        Ok(Self { hash: SHA256::default(), sk: None, pk: Some(*pk) })
    }

    fn do_verify_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn do_verify_final(self, sig: &[u8]) -> Result<(), SignatureError> {
        let pk = self.pk.ok_or(SignatureError::GenericError(
            "do_verify_final called on a sign-initialized ECDSABp256r1; call do_sign_final instead",
        ))?;
        verify_final(self.hash, &pk, sig)
    }
}

impl SignatureVerifier<ECDSABp256r1PublicKey, PK_LEN, SIG_LEN> for ECDetDSABp256r1 {
    fn verify(
        pk: &ECDSABp256r1PublicKey,
        msg: &[u8],
        ctx: Option<&[u8]>,
        sig: &[u8],
    ) -> Result<(), SignatureError> {
        let mut v = Self::do_verify_init(pk, ctx)?;
        v.do_verify_update(msg);
        v.do_verify_final(sig)
    }

    fn do_verify_init(
        pk: &ECDSABp256r1PublicKey,
        _ctx: Option<&[u8]>,
    ) -> Result<Self, SignatureError> {
        Ok(Self { hash: SHA256::default(), sk: None, pk: Some(*pk) })
    }

    fn do_verify_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn do_verify_final(self, sig: &[u8]) -> Result<(), SignatureError> {
        let pk = self.pk.ok_or(SignatureError::GenericError(
            "do_verify_final on a sign-initialized ECDetDSABp256r1; call do_sign_final",
        ))?;
        verify_final(self.hash, &pk, sig)
    }
}

/// `true` iff `limbs`, read as a big-endian-decoded integer, is in `[1, n-1]` -- FIPS 186-5 §6.4.2
/// step 1's range check on `r` and `s`. On public signature data, so plain (not branch-free).
fn in_range(limbs: &[u64; 4]) -> bool {
    if *limbs == [0, 0, 0, 0] {
        return false;
    }
    let (_, borrow) = nat::sub(limbs, &N_LIMBS);
    borrow == 1
}

// `r_or_s_is_zero` is private and, through `sign_with_k`, only ever reached with an `r`/`s` value
// that is astronomically unlikely for any real input (see its own doc comment), so no realistic
// integration test exercises either disjunct -- the QUALITY_AND_STYLE.md private-function
// exception applies.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r_or_s_is_zero_requires_only_one_to_be_zero() {
        let zero = Bp256r1ScalarField::ZERO;
        let one = Bp256r1ScalarField::ONE;
        assert!(!r_or_s_is_zero(&one, &one));
        assert!(r_or_s_is_zero(&zero, &one));
        assert!(r_or_s_is_zero(&one, &zero));
        assert!(r_or_s_is_zero(&zero, &zero));
    }
}
