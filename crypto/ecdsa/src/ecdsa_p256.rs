//! ECDSA over P-256: FIPS 186-5 §6.4.1 (signature generation) and §6.4.2 (verification), fixed
//! to SHA-256. [`ECDSAP256`] is the algorithm marker; [`ECDSAP256PrivateKey`] signs through
//! [`SigningKey`] (a random per-message `k`, §6.3.1 / Appendix A.3.1) and
//! [`DeterministicSigningKey`] (`k` from `d` and the message hash, §6.3.2 / Appendix A.3.3,
//! RFC 6979), and [`ECDSAP256PublicKey`] verifies through [`VerifyingKey`]. §6 says the choice of
//! `k` "does not impact the signature verification process", so there is one verifier and a
//! signature from either signer verifies under it.
//!
//! # `r`, `s` and `e`
//!
//! SP 800-186 Appendix F.1 (field element -> integer) is the identity for a prime field, so
//! extracting `r`'s raw value from `R`'s affine `x`-coordinate is just reading that coordinate's
//! canonical `[0, p)` representative. `e` (§6.4.1 step 2 / §6.4.2 step 3) needs no truncation
//! because `len(n) == hashlen == 256` for P-256/SHA-256, so `E = H` and `e = bits2int(H)` directly
//! (Appendix B.2.1). Both `r1` (from `x_R`) and `e` can exceed `n` as raw 256-bit values;
//! [`P256ScalarField::from_limbs`] reduces any such value with a single conditional subtraction
//! (documented on that function), which is exactly steps 6-8's "convert, then `mod n`".
//!
//! # Extracting `x_R` from a secret-derived `R`
//!
//! `R = [k]G` is Jacobian-coordinate output of a secret scalar multiplication, so converting it to
//! affine cannot use [`P256JacobianPoint::to_affine`] -- that function's own docs say it branches
//! on infinity and is "not for use on a secret intermediate value". [`x_affine_of_signing_point`]
//! instead always computes `X * Z^-2`, branch-free, exactly mirroring what `to_affine` does in its
//! non-infinity case; `Z` is never `0` here since `k` is in `[1, n-1]` (RFC 6979 or Appendix A.3.1,
//! both of which produce a `k` in that range by construction) and `G` has prime order `n` (SP
//! 800-186 §3.2.1.3's cofactor `h = 1`), so `[k]G` is never the identity for any valid `k` -- this
//! holds unconditionally, so skipping the infinity branch leaks nothing about which `k` was drawn.

use crate::keys_p256::{ECDSAP256PrivateKey, ECDSAP256PublicKey, EXTRA_BITS_DRBG_OUTPUT_LEN};
use crate::rfc6979_p256;
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::signature_key::{
    DeterministicSigningKey, SignatureAlgorithm, SigningKey, VerifyingKey,
};
use bouncycastle_core::traits::{
    Algorithm, AlgorithmInfo, Hash, RNG, SignatureSigner, SignatureVerifier,
};
use bouncycastle_ec::hazmat::p256::P256FieldElement;
use bouncycastle_ec::hazmat::p256_comb::comb_multiply_base_point;
use bouncycastle_ec::hazmat::p256_extra_bits::reduce_wide_bits_mod_n_minus_1;
use bouncycastle_ec::hazmat::p256_point::P256JacobianPoint;
use bouncycastle_ec::hazmat::p256_scalar::{
    N_LIMBS, P256PublicScalar, P256Scalar, P256ScalarField,
};
use bouncycastle_ec::hazmat::p256_sec1;
use bouncycastle_ec::hazmat::p256_wnaf::shamir_multiply;
use bouncycastle_ec::nat;
use bouncycastle_sha2::SHA256;
use bouncycastle_utils::secret::Secret;

/// Raw `r || s` signature length: two 32-byte field-width integers, the default encoding.
/// `sign_der`/`verify_der` on the keys offer the RFC 3279 §2.2.3
/// DER `SEQUENCE { r, s }` alternative via [`crate::der`], for interop that needs it.
pub const SIG_LEN: usize = 64;

/// Upper bound on a DER-encoded P-256 signature (`r`, `s` each 32 bytes); see [`crate::der::max_len`].
pub const DER_SIG_MAX_LEN: usize = crate::der::max_len(32);

/// ECDSA over P-256: FIPS 186-5 §6.4.1 (signature generation) and §6.4.2 (verification), fixed
/// to SHA-256. The algorithm marker the key role traits are implemented over:
/// [`ECDSAP256PrivateKey`] signs with it through [`SigningKey`] (a random per-message `k`,
/// §6.3.1 / Appendix A.3.1) and [`DeterministicSigningKey`] (`k` from `d` and the message hash,
/// §6.3.2 / Appendix A.3.3, RFC 6979); [`ECDSAP256PublicKey`] verifies through [`VerifyingKey`].
/// §6 says the choice of `k` "does not impact the signature verification process", so there is
/// one verifier and a signature from either signer verifies under it.
///
/// Neither signer uses `ctx`: ECDSA has no context string, and the argument is accepted and
/// ignored so that the key traits read the same across algorithms.
pub struct ECDSAP256;

impl Algorithm for ECDSAP256 {
    const ALG_NAME: &'static str = "ECDSA-P256";
    /// SP 800-57 Part 1 Rev. 5, Table 2: a 256-bit curve order gives 128 bits.
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

impl SignatureAlgorithm for ECDSAP256 {}

/// What [`ECDetDSAP256Signer`] reports as its algorithm name. The algorithm marker is still
/// [`ECDSAP256`]; this names the RFC 6979 way of choosing `k`.
pub const ECDETDSA_P256_NAME: &str = "ECDetDSA-P256";

/// The signer [`SigningKey::create_signer`] hands out: ECDSA with a random `k`.
///
/// `k` is drawn from the caller's RNG when the signer is created (Appendix A.3.1, "extra random
/// bits"), since it does not depend on the message; the signer then only hashes. Two signatures
/// of one message under one key differ.
pub struct ECDSAP256Signer<'k> {
    sk: &'k ECDSAP256PrivateKey,
    hash: SHA256,
    k: P256Scalar,
}

/// The signer [`DeterministicSigningKey::create_signer_deterministic`] hands out: Deterministic
/// ECDSA, `k` from `d` and the message hash by RFC 6979, so the same key and message always give
/// the same signature and signing draws no randomness. Reports [`ECDETDSA_P256_NAME`].
pub struct ECDetDSAP256Signer<'k> {
    sk: &'k ECDSAP256PrivateKey,
    hash: SHA256,
}

/// The verifier [`VerifyingKey::create_verifier`] hands out; FIPS 186-5 §6.4.2.
pub struct ECDSAP256Verifier<'k> {
    pk: &'k ECDSAP256PublicKey,
    hash: SHA256,
}

/// `x * z^-2`, branch-free -- see the module docs for why this isn't [`P256JacobianPoint::to_affine`].
fn x_affine_of_signing_point(point: &P256JacobianPoint) -> P256FieldElement {
    let mut z_inv = point.z.invert();
    let x = point.x.mul(&z_inv.mul(&z_inv));
    z_inv.zeroize();
    x
}

/// FIPS 186-5 §6.4.1 steps 4-12, given `k` already generated (step 3) by one of Appendix A.3's
/// methods.
/// Returns `None` for step 11's `r = 0` or `s = 0` case; each caller acts on it as step 11
/// directs for its way of generating `k`.
fn sign_with_k(
    sk: &ECDSAP256PrivateKey,
    e: &P256ScalarField,
    k: P256Scalar,
) -> Option<[u8; SIG_LEN]> {
    let mut k_field = P256ScalarField::from_secret(&k);
    let mut k_inv = k_field.invert(); // step 4

    let mut r_point = comb_multiply_base_point(&k); // step 5
    let x_r = x_affine_of_signing_point(&r_point); // steps 6-7
    let r = P256ScalarField::from_limbs(x_r.to_limbs()); // step 8

    let mut d_field = P256ScalarField::from_secret(sk.scalar());
    let s = k_inv.mul(&e.add(&r.mul(&d_field))); // step 9

    // `k_field`, `k_inv` and `d_field` hold `k`, `k^-1` and `d`, and `r_point`'s projective
    // coordinates are a function of `k`'s bits even though its affine `x` is the public `r`.
    // Nothing below needs them, so they are overwritten here rather than left legible on the
    // stack after this returns -- placed before step 11's check so that both ways out of the
    // function are covered. `k` itself is a `Secret` and scrubs when it drops; `e`, `r` and `s`
    // are public by construction.
    k_field.zeroize();
    k_inv.zeroize();
    d_field.zeroize();
    r_point.zeroize();

    // step 11: astronomically unlikely (r, s range over ~2^256 values each); this comparison is
    // FIPS 186-5's own mandated success/failure branch on the just-computed public output, not a
    // constant-time violation -- see this module's docs on x_affine_of_signing_point for the one
    // secret-derived branch this function does avoid.
    if r_or_s_is_zero(&r, &s) {
        return None;
    }

    let mut sig = [0u8; SIG_LEN];
    sig[..32].copy_from_slice(&p256_sec1::be_bytes_from_limbs(&r.to_limbs()));
    sig[32..].copy_from_slice(&p256_sec1::be_bytes_from_limbs(&s.to_limbs()));
    Some(sig)
}

/// FIPS 186-5 §6.4.1 step 3 by Appendix A.3.1: `N + 64` bits from `rng`, reduced into `[1, n-1]`
/// by `reduce_wide_bits_mod_n_minus_1`. The one place [`ECDSAP256`]'s signing paths draw `k`.
fn random_k(rng: &mut dyn RNG) -> Result<P256Scalar, SignatureError> {
    // Raw DRBG output, reduced below into the per-message secret: held in `Secret` so it is
    // scrubbed when this function returns rather than left on the stack.
    let mut extra_bits = Secret::<[u8; EXTRA_BITS_DRBG_OUTPUT_LEN]>::new();
    rng.next_bytes_out(&mut *extra_bits).map_err(SignatureError::RNGError)?;
    Ok(reduce_wide_bits_mod_n_minus_1(&*extra_bits))
}

/// `e` from a 32-byte message hash: FIPS 186-5 §6.4.1 step 2 / §6.4.2 step 3, `E = H` (no
/// truncation needed -- see the module docs) then Appendix B.2.1's big-endian conversion.
fn e_from_hash(h: &[u8; 32]) -> P256ScalarField {
    P256ScalarField::from_limbs(p256_sec1::limbs_from_be_bytes(h))
}

/// FIPS 186-5 §6.4.1 step 11's `r = 0` or `s = 0` check, named so it has something to unit test
/// directly: reaching either branch through `sign_with_k` needs an `r`/`s` value that is
/// astronomically unlikely for any real `k`/`d`/message (see [`sign_with_k`]'s call site).
fn r_or_s_is_zero(r: &P256ScalarField, s: &P256ScalarField) -> bool {
    *r == P256ScalarField::ZERO || *s == P256ScalarField::ZERO
}

/// FIPS 186-5 §6.4.2 on the finished message hash: step 1's range check, then steps 3-9 (step 2
/// is the hashing the caller has done). Both signer types' `do_verify_final` are this one
/// function, since how `k` was generated does not enter verification.
fn verify_final(hash: SHA256, pk: &ECDSAP256PublicKey, sig: &[u8]) -> Result<(), SignatureError> {
    // Exactly SIG_LEN, not "at least": the raw encoding is two fixed-width integers and
    // nothing else, so trailing bytes make this a different, malformed encoding rather than a
    // valid signature in a roomy buffer. Accepting them would let anyone turn one valid
    // signature into unlimited distinct byte strings that all verify -- malleability that
    // breaks any caller treating the signature as an opaque, comparable blob. This matches how
    // `SignaturePublicKey`/`SignaturePrivateKey::from_bytes` already reject an over-long
    // encoding here (see `core-test-framework`'s own `test_boundary_conditions`).
    if sig.len() != SIG_LEN {
        return Err(SignatureError::LengthError("ECDSA P-256 signature must be exactly 64 bytes"));
    }

    // step 1: r, s in [1, n-1], rejected (not reduced) if out of range.
    let r_limbs = p256_sec1::limbs_from_be_bytes(&sig[..32].try_into().unwrap());
    let s_limbs = p256_sec1::limbs_from_be_bytes(&sig[32..64].try_into().unwrap());
    if !in_range(&r_limbs) || !in_range(&s_limbs) {
        return Err(SignatureError::SignatureVerificationFailed);
    }
    let r = P256ScalarField::from_limbs(r_limbs);

    let mut h = [0u8; 32];
    hash.do_final_out(&mut h);
    let e = e_from_hash(&h); // steps 2-3

    // `s` is part of the signature, so its inverse is taken in variable time on the public
    // scalar type; the constant-time `invert` is for the signer's `k`.
    let s_inv = P256PublicScalar::from_limbs(s_limbs).invert_vartime(); // step 4
    let u = e.mul(&s_inv); // step 5
    let v = r.mul(&s_inv);

    let q = P256JacobianPoint::from_affine(pk.x, pk.y);
    let u_pub = P256PublicScalar::from_limbs(u.to_limbs());
    let v_pub = P256PublicScalar::from_limbs(v.to_limbs());
    let r1_point = shamir_multiply(&u_pub, &v_pub, &q); // step 6

    if r1_point.is_infinity().to_bool() {
        return Err(SignatureError::SignatureVerificationFailed);
    }
    let (x_r1, _) =
        r1_point.to_affine().expect("just checked r1_point is not the point at infinity");
    let r1 = P256ScalarField::from_limbs(x_r1.to_limbs()); // steps 7-8

    if r1 == r { Ok(()) } else { Err(SignatureError::SignatureVerificationFailed) } // step 9
}

/// RFC 3279 §2.2.3 `Ecdsa-Sig-Value` from raw `r || s`, with the encoded length; unused trailing
/// bytes of the fixed-size buffer are left as written by [`crate::der::encode`] (zeroed only up
/// to that length).
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

impl ECDSAP256PrivateKey {
    /// [`SigningKey::sign`] with the signature DER-encoded as RFC 3279 §2.2.3's
    /// `SEQUENCE { r, s }` (see [`crate::der`]); returns the buffer and the encoded length.
    pub fn sign_der(
        &self,
        rng: &mut dyn RNG,
        msg: &[u8],
        ctx: Option<&[u8]>,
    ) -> Result<([u8; DER_SIG_MAX_LEN], usize), SignatureError> {
        Ok(der_encode(&self.sign(rng, msg, ctx)?))
    }

    /// [`DeterministicSigningKey::sign_deterministic`], DER-encoded as [`Self::sign_der`].
    pub fn sign_der_deterministic(
        &self,
        msg: &[u8],
        ctx: Option<&[u8]>,
    ) -> Result<([u8; DER_SIG_MAX_LEN], usize), SignatureError> {
        Ok(der_encode(&self.sign_deterministic(msg, ctx)?))
    }
}

impl ECDSAP256PublicKey {
    /// [`VerifyingKey::verify`] of a DER-encoded signature (RFC 3279 §2.2.3); a malformed
    /// encoding is a verification failure.
    pub fn verify_der(
        &self,
        msg: &[u8],
        ctx: Option<&[u8]>,
        sig: &[u8],
    ) -> Result<(), SignatureError> {
        self.verify(msg, ctx, &der_decode(sig)?)
    }
}

impl SigningKey<ECDSAP256, SIG_LEN> for ECDSAP256PrivateKey {
    type Signer<'k>
        = ECDSAP256Signer<'k>
    where
        Self: 'k;

    fn create_signer<'k>(
        &'k self,
        rng: &mut dyn RNG,
        _ctx: Option<&[u8]>,
    ) -> Result<Self::Signer<'k>, SignatureError> {
        Ok(ECDSAP256Signer { sk: self, hash: SHA256::default(), k: random_k(rng)? })
    }
}

impl DeterministicSigningKey<ECDSAP256, SIG_LEN> for ECDSAP256PrivateKey {
    type Signer<'k>
        = ECDetDSAP256Signer<'k>
    where
        Self: 'k;

    fn create_signer_deterministic<'k>(
        &'k self,
        _ctx: Option<&[u8]>,
    ) -> Result<Self::Signer<'k>, SignatureError> {
        Ok(ECDetDSAP256Signer { sk: self, hash: SHA256::default() })
    }
}

impl VerifyingKey<ECDSAP256, SIG_LEN> for ECDSAP256PublicKey {
    type Verifier<'k>
        = ECDSAP256Verifier<'k>
    where
        Self: 'k;

    fn create_verifier<'k>(
        &'k self,
        _ctx: Option<&[u8]>,
    ) -> Result<Self::Verifier<'k>, SignatureError> {
        Ok(ECDSAP256Verifier { pk: self, hash: SHA256::default() })
    }
}

impl AlgorithmInfo for ECDSAP256Signer<'_> {
    fn alg_name(&self) -> &'static str {
        ECDSAP256::ALG_NAME
    }

    fn max_security_strength(&self) -> SecurityStrength {
        ECDSAP256::MAX_SECURITY_STRENGTH
    }
}

impl SignatureSigner<SIG_LEN> for ECDSAP256Signer<'_> {
    fn do_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn do_final(self) -> Result<[u8; SIG_LEN], SignatureError> {
        let mut h = [0u8; 32];
        self.hash.do_final_out(&mut h);
        // FIPS 186-5 §6.4.1 step 11: with a random `k`, `r = 0` or `s = 0` goes back to step 3.
        // `k` was drawn when this signer was created and there is no RNG here to draw another
        // from, so the failure is reported instead; it has probability about 2^-255.
        sign_with_k(self.sk, &e_from_hash(&h), self.k).ok_or(SignatureError::GenericError(
            "ECDSA produced r = 0 or s = 0; create a fresh signer and sign again",
        ))
    }

    fn do_final_out(self, output: &mut [u8; SIG_LEN]) -> Result<usize, SignatureError> {
        output.fill(0);
        *output = self.do_final()?;
        Ok(SIG_LEN)
    }
}

impl AlgorithmInfo for ECDetDSAP256Signer<'_> {
    fn alg_name(&self) -> &'static str {
        ECDETDSA_P256_NAME
    }

    fn max_security_strength(&self) -> SecurityStrength {
        ECDSAP256::MAX_SECURITY_STRENGTH
    }
}

impl SignatureSigner<SIG_LEN> for ECDetDSAP256Signer<'_> {
    fn do_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn do_final(self) -> Result<[u8; SIG_LEN], SignatureError> {
        let mut h = [0u8; 32];
        self.hash.do_final_out(&mut h);
        let k = rfc6979_p256::generate_k(self.sk.scalar(), &h); // step 3, Appendix A.3.3
        // FIPS 186-5 §6.4.1 step 11: with a deterministic `k`, `r = 0` or `s = 0` outputs failure.
        sign_with_k(self.sk, &e_from_hash(&h), k).ok_or(SignatureError::GenericError(
            "deterministic ECDSA produced r = 0 or s = 0; FIPS 186-5 §6.4.1 step 11: output failure",
        ))
    }

    fn do_final_out(self, output: &mut [u8; SIG_LEN]) -> Result<usize, SignatureError> {
        output.fill(0);
        *output = self.do_final()?;
        Ok(SIG_LEN)
    }
}

impl AlgorithmInfo for ECDSAP256Verifier<'_> {
    fn alg_name(&self) -> &'static str {
        ECDSAP256::ALG_NAME
    }

    fn max_security_strength(&self) -> SecurityStrength {
        ECDSAP256::MAX_SECURITY_STRENGTH
    }
}

impl SignatureVerifier for ECDSAP256Verifier<'_> {
    fn do_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn do_verify_final(self, sig: &[u8]) -> Result<(), SignatureError> {
        verify_final(self.hash, self.pk, sig)
    }
}

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
        let zero = P256ScalarField::ZERO;
        let one = P256ScalarField::ONE;
        assert!(!r_or_s_is_zero(&one, &one));
        assert!(r_or_s_is_zero(&zero, &one));
        assert!(r_or_s_is_zero(&one, &zero));
        assert!(r_or_s_is_zero(&zero, &zero));
    }
}
