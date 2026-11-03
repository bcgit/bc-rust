//! ECDSA over P-384: FIPS 186-5 §6.4.1 (signature generation) and §6.4.2 (verification),
//! fixed to SHA-384. [`ECDSAP384`] is the algorithm marker; [`ECDSAP384PrivateKey`] signs
//! through [`SigningKey`] (random `k`, §6.3.1) and [`DeterministicSigningKey`] (`k` by RFC 6979,
//! §6.3.2), [`ECDSAP384PublicKey`] verifies through [`VerifyingKey`], as [`crate::ecdsa_p256`]
//! lays out. Fixed to SHA-384.
//! Identical in shape to [`crate::ecdsa_p256`] -- see that module's docs for the full reasoning
//! (why `e` needs no truncation, why `x_affine_of_signing_point` exists, the `ctx`/ignore-it
//! stance) -- with P-384's types and SHA-384 substituted.

use crate::keys_p384::{ECDSAP384PrivateKey, ECDSAP384PublicKey, EXTRA_BITS_DRBG_OUTPUT_LEN};
use crate::rfc6979_p384;
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::signature_key::{
    DeterministicSigningKey, SignatureAlgorithm, SigningKey, VerifyingKey,
};
use bouncycastle_core::traits::{
    Algorithm, AlgorithmInfo, Hash, RNG, SignatureSigner, SignatureVerifier,
};
use bouncycastle_ec::nat;
use bouncycastle_ec::p384::P384FieldElement;
use bouncycastle_ec::p384_comb::comb_multiply_base_point;
use bouncycastle_ec::p384_extra_bits::reduce_wide_bits_mod_n_minus_1;
use bouncycastle_ec::p384_point::P384JacobianPoint;
use bouncycastle_ec::p384_scalar::{N_LIMBS, P384PublicScalar, P384Scalar, P384ScalarField};
use bouncycastle_ec::p384_sec1;
use bouncycastle_ec::p384_wnaf::shamir_multiply;
use bouncycastle_sha2::SHA384;
use bouncycastle_utils::secret::Secret;

/// Raw `r || s` signature length: two 48-byte field-width integers.
pub const SIG_LEN: usize = 96;

/// Upper bound on a DER-encoded P-384 signature (`r`, `s` each 48 bytes); see [`crate::der::max_len`].
pub const DER_SIG_MAX_LEN: usize = crate::der::max_len(48);

/// ECDSA over P-384: FIPS 186-5 §6.4.1 (signature generation) and §6.4.2 (verification), fixed
/// to SHA-384. The algorithm marker the key role traits are implemented over:
/// [`ECDSAP384PrivateKey`] signs with it through [`SigningKey`] (a random per-message `k`,
/// §6.3.1 / Appendix A.3.1) and [`DeterministicSigningKey`] (`k` from `d` and the message hash,
/// §6.3.2 / Appendix A.3.3, RFC 6979); [`ECDSAP384PublicKey`] verifies through [`VerifyingKey`].
/// §6 says the choice of `k` "does not impact the signature verification process", so there is
/// one verifier and a signature from either signer verifies under it.
///
/// Neither signer uses `ctx`: ECDSA has no context string, and the argument is accepted and
/// ignored so that the key traits read the same across algorithms.
pub struct ECDSAP384;

impl Algorithm for ECDSAP384 {
    const ALG_NAME: &'static str = "ECDSA-P384";
    /// SP 800-57 Part 1 Rev. 5, Table 2: a 384-bit curve order gives 192 bits.
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_192bit;
}

impl SignatureAlgorithm for ECDSAP384 {}

/// What [`ECDetDSAP384Signer`] reports as its algorithm name. The algorithm marker is still
/// [`ECDSAP384`]; this names the RFC 6979 way of choosing `k`.
pub const ECDETDSA_P384_NAME: &str = "ECDetDSA-P384";

/// The signer [`SigningKey::create_signer`] hands out: ECDSA with a random `k`.
///
/// `k` is drawn from the caller's RNG when the signer is created (Appendix A.3.1, "extra random
/// bits"), since it does not depend on the message; the signer then only hashes. Two signatures
/// of one message under one key differ.
pub struct ECDSAP384Signer<'k> {
    sk: &'k ECDSAP384PrivateKey,
    hash: SHA384,
    k: P384Scalar,
}

/// The signer [`DeterministicSigningKey::create_signer_deterministic`] hands out: Deterministic
/// ECDSA, `k` from `d` and the message hash by RFC 6979, so the same key and message always give
/// the same signature and signing draws no randomness. Reports [`ECDETDSA_P384_NAME`].
pub struct ECDetDSAP384Signer<'k> {
    sk: &'k ECDSAP384PrivateKey,
    hash: SHA384,
}

/// The verifier [`VerifyingKey::create_verifier`] hands out; FIPS 186-5 §6.4.2.
pub struct ECDSAP384Verifier<'k> {
    pk: &'k ECDSAP384PublicKey,
    hash: SHA384,
}

/// `x * z^-2`, branch-free. See [`crate::ecdsa_p256::x_affine_of_signing_point`]'s docs.
fn x_affine_of_signing_point(point: &P384JacobianPoint) -> P384FieldElement {
    let z_inv = point.z.invert();
    point.x.mul(&z_inv.mul(&z_inv))
}

/// FIPS 186-5 §6.4.1 steps 4-12, given `k` already generated (step 3).
/// Returns `None` for step 11's `r = 0` or `s = 0` case; each caller acts on it as step 11
/// directs for its way of generating `k`.
fn sign_with_k(
    sk: &ECDSAP384PrivateKey,
    e: &P384ScalarField,
    k: P384Scalar,
) -> Option<[u8; SIG_LEN]> {
    let mut k_field = P384ScalarField::from_secret(&k);
    let mut k_inv = k_field.invert(); // step 4

    let r_point = comb_multiply_base_point(&k); // step 5
    let x_r = x_affine_of_signing_point(&r_point); // steps 6-7
    let r = P384ScalarField::from_limbs(x_r.to_limbs()); // step 8

    let mut d_field = P384ScalarField::from_secret(sk.scalar());
    let s = k_inv.mul(&e.add(&r.mul(&d_field))); // step 9

    // `k_field`, `k_inv` and `d_field` hold `k`, `k^-1` and `d`. Nothing below needs them, so they
    // are overwritten here rather than left legible on the stack after this returns -- placed
    // before step 11's check so that both ways out of the function are covered. `k` itself is a
    // `Secret` and scrubs when it drops; `e`, `r` and `s` are public by construction.
    k_field.zeroize();
    k_inv.zeroize();
    d_field.zeroize();

    if r_or_s_is_zero(&r, &s) {
        return None;
    }

    let mut sig = [0u8; SIG_LEN];
    sig[..48].copy_from_slice(&p384_sec1::be_bytes_from_limbs(&r.to_limbs()));
    sig[48..].copy_from_slice(&p384_sec1::be_bytes_from_limbs(&s.to_limbs()));
    Some(sig)
}

/// FIPS 186-5 §6.4.1 step 3 by Appendix A.3.1, reduced into `[1, n-1]` by
/// `reduce_wide_bits_mod_n_minus_1`; the one place [`ECDSAP384`]'s signing paths draw `k`. Draws
/// A.3.1 step 3's `N + t` bits with `t = 64` (see [`bouncycastle_ec::p384_extra_bits`]'s docs for why that is
/// required here even though P-384's `n` would need none for bias alone).
fn random_k(rng: &mut dyn RNG) -> Result<P384Scalar, SignatureError> {
    // Raw DRBG output, reduced below into the per-message secret: held in `Secret` so it is
    // scrubbed when this function returns rather than left on the stack.
    let mut extra_bits = Secret::<[u8; EXTRA_BITS_DRBG_OUTPUT_LEN]>::new();
    rng.next_bytes_out(&mut *extra_bits).map_err(SignatureError::RNGError)?;
    Ok(reduce_wide_bits_mod_n_minus_1(&*extra_bits))
}

/// `e` from a 48-byte message hash: `E = H` (no truncation needed, `len(n) == hashlen`), then
/// Appendix B.2.1's big-endian conversion.
fn e_from_hash(h: &[u8; 48]) -> P384ScalarField {
    P384ScalarField::from_limbs(p384_sec1::limbs_from_be_bytes(h))
}

/// FIPS 186-5 §6.4.1 step 11's `r = 0` or `s = 0` check. See
/// [`crate::ecdsa_p256::r_or_s_is_zero`]'s docs.
fn r_or_s_is_zero(r: &P384ScalarField, s: &P384ScalarField) -> bool {
    *r == P384ScalarField::ZERO || *s == P384ScalarField::ZERO
}

/// FIPS 186-5 §6.4.2 on the finished message hash; the verifier's `do_verify_final` is
/// this one function. See `crate::ecdsa_p256`'s `verify_final`.
fn verify_final(hash: SHA384, pk: &ECDSAP384PublicKey, sig: &[u8]) -> Result<(), SignatureError> {
    // Exactly SIG_LEN, not "at least": the raw encoding is two fixed-width integers and
    // nothing else, so trailing bytes make this a different, malformed encoding rather than a
    // valid signature in a roomy buffer. Accepting them would let anyone turn one valid
    // signature into unlimited distinct byte strings that all verify -- malleability that
    // breaks any caller treating the signature as an opaque, comparable blob. This matches how
    // `SignaturePublicKey`/`SignaturePrivateKey::from_bytes` already reject an over-long
    // encoding here (see `core-test-framework`'s own `test_boundary_conditions`).
    if sig.len() != SIG_LEN {
        return Err(SignatureError::LengthError("ECDSA P-384 signature must be exactly 96 bytes"));
    }

    let r_limbs = p384_sec1::limbs_from_be_bytes(&sig[..48].try_into().unwrap());
    let s_limbs = p384_sec1::limbs_from_be_bytes(&sig[48..96].try_into().unwrap());
    if !in_range(&r_limbs) || !in_range(&s_limbs) {
        return Err(SignatureError::SignatureVerificationFailed);
    }
    let r = P384ScalarField::from_limbs(r_limbs);

    let mut h = [0u8; 48];
    hash.do_final_out(&mut h);
    let e = e_from_hash(&h);

    // `s` is part of the signature, so its inverse is taken in variable time on the public
    // scalar type; the constant-time `invert` is for the signer's `k`.
    let s_inv = P384PublicScalar::from_limbs(s_limbs).invert_vartime();
    let u = e.mul(&s_inv);
    let v = r.mul(&s_inv);

    let q = P384JacobianPoint::from_affine(pk.x, pk.y);
    let u_pub = P384PublicScalar::from_limbs(u.to_limbs());
    let v_pub = P384PublicScalar::from_limbs(v.to_limbs());
    let r1_point = shamir_multiply(&u_pub, &v_pub, &q);

    if r1_point.is_infinity().to_bool() {
        return Err(SignatureError::SignatureVerificationFailed);
    }
    let (x_r1, _) =
        r1_point.to_affine().expect("just checked r1_point is not the point at infinity");
    let r1 = P384ScalarField::from_limbs(x_r1.to_limbs());

    if r1 == r { Ok(()) } else { Err(SignatureError::SignatureVerificationFailed) }
}

/// RFC 3279 §2.2.3 `Ecdsa-Sig-Value` from raw `r || s`, with the encoded length; see
/// `crate::ecdsa_p256`'s `der_encode`.
fn der_encode(raw: &[u8; SIG_LEN]) -> ([u8; DER_SIG_MAX_LEN], usize) {
    let mut out = [0u8; DER_SIG_MAX_LEN];
    let len = crate::der::encode(&raw[..48], &raw[48..], &mut out);
    (out, len)
}

/// Raw `r || s` from a DER `Ecdsa-Sig-Value`; a malformed encoding is a verification failure.
fn der_decode(sig: &[u8]) -> Result<[u8; SIG_LEN], SignatureError> {
    let mut raw = [0u8; SIG_LEN];
    let (r_out, s_out) = raw.split_at_mut(48);
    crate::der::decode(sig, r_out, s_out).ok_or(SignatureError::SignatureVerificationFailed)?;
    Ok(raw)
}

impl ECDSAP384PrivateKey {
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

impl ECDSAP384PublicKey {
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

impl SigningKey<ECDSAP384, SIG_LEN> for ECDSAP384PrivateKey {
    type Signer<'k>
        = ECDSAP384Signer<'k>
    where
        Self: 'k;

    fn create_signer<'k>(
        &'k self,
        rng: &mut dyn RNG,
        _ctx: Option<&[u8]>,
    ) -> Result<Self::Signer<'k>, SignatureError> {
        Ok(ECDSAP384Signer { sk: self, hash: SHA384::default(), k: random_k(rng)? })
    }
}

impl DeterministicSigningKey<ECDSAP384, SIG_LEN> for ECDSAP384PrivateKey {
    type Signer<'k>
        = ECDetDSAP384Signer<'k>
    where
        Self: 'k;

    fn create_signer_deterministic<'k>(
        &'k self,
        _ctx: Option<&[u8]>,
    ) -> Result<Self::Signer<'k>, SignatureError> {
        Ok(ECDetDSAP384Signer { sk: self, hash: SHA384::default() })
    }
}

impl VerifyingKey<ECDSAP384, SIG_LEN> for ECDSAP384PublicKey {
    type Verifier<'k>
        = ECDSAP384Verifier<'k>
    where
        Self: 'k;

    fn create_verifier<'k>(
        &'k self,
        _ctx: Option<&[u8]>,
    ) -> Result<Self::Verifier<'k>, SignatureError> {
        Ok(ECDSAP384Verifier { pk: self, hash: SHA384::default() })
    }
}

impl AlgorithmInfo for ECDSAP384Signer<'_> {
    fn alg_name(&self) -> &'static str {
        ECDSAP384::ALG_NAME
    }

    fn max_security_strength(&self) -> SecurityStrength {
        ECDSAP384::MAX_SECURITY_STRENGTH
    }
}

impl SignatureSigner<SIG_LEN> for ECDSAP384Signer<'_> {
    fn do_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn do_final(self) -> Result<[u8; SIG_LEN], SignatureError> {
        let mut h = [0u8; 48];
        self.hash.do_final_out(&mut h);
        // FIPS 186-5 §6.4.1 step 11: with a random `k`, `r = 0` or `s = 0` goes back to step 3.
        // `k` was drawn when this signer was created and there is no RNG here to draw another
        // from, so the failure is reported instead; it has probability about 2^-383.
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

impl AlgorithmInfo for ECDetDSAP384Signer<'_> {
    fn alg_name(&self) -> &'static str {
        ECDETDSA_P384_NAME
    }

    fn max_security_strength(&self) -> SecurityStrength {
        ECDSAP384::MAX_SECURITY_STRENGTH
    }
}

impl SignatureSigner<SIG_LEN> for ECDetDSAP384Signer<'_> {
    fn do_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn do_final(self) -> Result<[u8; SIG_LEN], SignatureError> {
        let mut h = [0u8; 48];
        self.hash.do_final_out(&mut h);
        let k = rfc6979_p384::generate_k(self.sk.scalar(), &h); // step 3, Appendix A.3.3
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

impl AlgorithmInfo for ECDSAP384Verifier<'_> {
    fn alg_name(&self) -> &'static str {
        ECDSAP384::ALG_NAME
    }

    fn max_security_strength(&self) -> SecurityStrength {
        ECDSAP384::MAX_SECURITY_STRENGTH
    }
}

impl SignatureVerifier for ECDSAP384Verifier<'_> {
    fn do_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn do_verify_final(self, sig: &[u8]) -> Result<(), SignatureError> {
        verify_final(self.hash, self.pk, sig)
    }
}

fn in_range(limbs: &[u64; 6]) -> bool {
    if *limbs == [0, 0, 0, 0, 0, 0] {
        return false;
    }
    let (_, borrow) = nat::sub(limbs, &N_LIMBS);
    borrow == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r_or_s_is_zero_requires_only_one_to_be_zero() {
        let zero = P384ScalarField::ZERO;
        let one = P384ScalarField::ONE;
        assert!(!r_or_s_is_zero(&one, &one));
        assert!(r_or_s_is_zero(&zero, &one));
        assert!(r_or_s_is_zero(&one, &zero));
        assert!(r_or_s_is_zero(&zero, &zero));
    }
}
