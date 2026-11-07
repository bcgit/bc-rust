//! ECDSA over brainpoolP384r1: FIPS 186-5 §6.4.1 (signature generation) and §6.4.2 (verification),
//! fixed to SHA-384. [`ECDSABp384r1`] is the algorithm marker; [`ECDSABp384r1PrivateKey`] signs
//! through [`SigningKey`] (random `k`, §6.3.1) and [`DeterministicSigningKey`] (`k` by RFC 6979,
//! §6.3.2), [`ECDSABp384r1PublicKey`] verifies through [`VerifyingKey`], as [`crate::ecdsa_p256`]
//! lays out. Fixed to SHA-384 (the pairing wycheproof's `ecdsa_brainpoolP384r1_sha384_*` vector
//! files use). Identical in shape to [`crate::ecdsa_p256`] -- see that module's docs for the full
//! reasoning (`e = bits2int(H)` needs no truncation since `len(n) == hashlen == 384`;
//! `x_affine_of_signing_point`'s branch-free-on-a-secret-value argument; both hold unchanged here)
//! -- with brainpoolP384r1's types, [`crate::keys_bp384r1`],
//! [`bouncycastle_ec::hazmat::bp384r1_extra_bits`], and `crate::rfc6979_bp384r1` substituted.

use crate::keys_bp384r1::{ECDSABp384r1PrivateKey, ECDSABp384r1PublicKey};
use crate::rfc6979_bp384r1;
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::signature_key::{
    DeterministicSigningKey, SignatureAlgorithm, SigningKey, VerifyingKey,
};
use bouncycastle_core::traits::{
    Algorithm, AlgorithmInfo, Hash, RNG, SignatureSigner, SignatureVerifier,
};
use bouncycastle_ec::hazmat::bp384r1::Bp384r1FieldElement;
use bouncycastle_ec::hazmat::bp384r1_comb::comb_multiply_base_point;
use bouncycastle_ec::hazmat::bp384r1_extra_bits::reduce_wide_bits_mod_n_minus_1;
use bouncycastle_ec::hazmat::bp384r1_point::Bp384r1JacobianPoint;
use bouncycastle_ec::hazmat::bp384r1_scalar::{
    Bp384r1PublicScalar, Bp384r1Scalar, Bp384r1ScalarField, N_LIMBS,
};
use bouncycastle_ec::hazmat::bp384r1_sec1;
use bouncycastle_ec::hazmat::bp384r1_wnaf::shamir_multiply;
use bouncycastle_ec::nat;
use bouncycastle_sha2::SHA384;
use bouncycastle_utils::secret::Secret;

/// Raw `r || s` signature length: two 48-byte field-width integers, the default encoding.
/// [`crate::der`] offers the RFC 3279 §2.2.3 DER `SEQUENCE { r, s }` alternative, for interop that
/// needs it.
pub const SIG_LEN: usize = 96;

/// ECDSA over brainpoolP384r1: FIPS 186-5 §6.4.1 (signature generation) and §6.4.2 (verification), fixed
/// to SHA-384. The algorithm marker the key role traits are implemented over:
/// [`ECDSABp384r1PrivateKey`] signs with it through [`SigningKey`] (a random per-message `k`,
/// §6.3.1 / Appendix A.3.1) and [`DeterministicSigningKey`] (`k` from `d` and the message hash,
/// §6.3.2 / Appendix A.3.3, RFC 6979); [`ECDSABp384r1PublicKey`] verifies through [`VerifyingKey`].
/// §6 says the choice of `k` "does not impact the signature verification process", so there is
/// one verifier and a signature from either signer verifies under it.
///
/// Neither signer uses `ctx`: ECDSA has no context string, and the argument is accepted and
/// ignored so that the key traits read the same across algorithms.
pub struct ECDSABp384r1;

impl Algorithm for ECDSABp384r1 {
    const ALG_NAME: &'static str = "ECDSA-brainpoolP384r1";
    /// SP 800-57 Part 1 Rev. 5, Table 2: a 384-bit curve order gives 192 bits.
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_192bit;
}

impl SignatureAlgorithm for ECDSABp384r1 {}

/// What [`ECDetDSABp384r1Signer`] reports as its algorithm name. The algorithm marker is still
/// [`ECDSABp384r1`]; this names the RFC 6979 way of choosing `k`.
const ECDETDSA_BP384R1_NAME: &str = "ECDetDSA-brainpoolP384r1";

/// The signer [`SigningKey::create_signer`] hands out: ECDSA with a random `k`.
///
/// `k` is drawn from the caller's RNG when the signer is created (Appendix A.3.1, "extra random
/// bits"), since it does not depend on the message; the signer then only hashes. Two signatures
/// of one message under one key differ.
pub struct ECDSABp384r1Signer<'k> {
    sk: &'k ECDSABp384r1PrivateKey,
    hash: SHA384,
    k: Bp384r1Scalar,
}

/// The signer [`DeterministicSigningKey::create_signer_deterministic`] hands out: Deterministic
/// ECDSA, `k` from `d` and the message hash by RFC 6979, so the same key and message always give
/// the same signature and signing draws no randomness. Reports `ECDetDSA-brainpoolP384r1`.
pub struct ECDetDSABp384r1Signer<'k> {
    sk: &'k ECDSABp384r1PrivateKey,
    hash: SHA384,
}

/// The verifier [`VerifyingKey::create_verifier`] hands out; FIPS 186-5 §6.4.2.
pub struct ECDSABp384r1Verifier<'k> {
    pk: &'k ECDSABp384r1PublicKey,
    hash: SHA384,
}

/// `x * z^-2`, branch-free -- see [`crate::ecdsa_p256`]'s module docs for why this isn't
/// [`Bp384r1JacobianPoint::to_affine`].
fn x_affine_of_signing_point(point: &Bp384r1JacobianPoint) -> Bp384r1FieldElement {
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
    sk: &ECDSABp384r1PrivateKey,
    e: &Bp384r1ScalarField,
    k: Bp384r1Scalar,
) -> Option<[u8; SIG_LEN]> {
    let mut k_field = Bp384r1ScalarField::from_secret(&k);
    let mut k_inv = k_field.invert(); // step 4

    let mut r_point = comb_multiply_base_point(&k); // step 5
    let x_r = x_affine_of_signing_point(&r_point); // steps 6-7
    let r = Bp384r1ScalarField::from_limbs(x_r.to_limbs()); // step 8

    let mut d_field = Bp384r1ScalarField::from_secret(sk.scalar());
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

    // step 11: astronomically unlikely (r, s range over ~2^384 values each); this comparison is
    // FIPS 186-5's own mandated success/failure branch on the just-computed public output, not a
    // constant-time violation -- see this module's docs on x_affine_of_signing_point for the one
    // secret-derived branch this function does avoid.
    if r_or_s_is_zero(&r, &s) {
        return None;
    }

    let mut sig = [0u8; SIG_LEN];
    sig[..48].copy_from_slice(&bp384r1_sec1::be_bytes_from_limbs(&r.to_limbs()));
    sig[48..].copy_from_slice(&bp384r1_sec1::be_bytes_from_limbs(&s.to_limbs()));
    Some(sig)
}

/// FIPS 186-5 §6.4.1 step 3 by Appendix A.3.1, reduced into `[1, n-1]` by
/// `reduce_wide_bits_mod_n_minus_1`; the one place [`ECDSABp384r1`]'s signing paths draw `k`.
fn random_k(rng: &mut dyn RNG) -> Result<Bp384r1Scalar, SignatureError> {
    // Raw DRBG output, reduced below into the per-message secret: held in `Secret` so it is
    // scrubbed when this function returns rather than left on the stack.
    let mut extra_bits = Secret::<[u8; crate::keys_bp384r1::EXTRA_BITS_DRBG_OUTPUT_LEN]>::new();
    rng.next_bytes_out(&mut *extra_bits).map_err(SignatureError::RNGError)?;
    Ok(reduce_wide_bits_mod_n_minus_1(&*extra_bits))
}

/// `e` from a 48-byte message hash: FIPS 186-5 §6.4.1 step 2 / §6.4.2 step 3, `E = H` (no
/// truncation needed -- see the module docs) then Appendix B.2.1's big-endian conversion.
fn e_from_hash(h: &[u8; 48]) -> Bp384r1ScalarField {
    Bp384r1ScalarField::from_limbs(bp384r1_sec1::limbs_from_be_bytes(h))
}

/// FIPS 186-5 §6.4.1 step 11's `r = 0` or `s = 0` check, named so it has something to unit test
/// directly: reaching either branch through `sign_with_k` needs an `r`/`s` value that is
/// astronomically unlikely for any real `k`/`d`/message (see [`sign_with_k`]'s call site).
fn r_or_s_is_zero(r: &Bp384r1ScalarField, s: &Bp384r1ScalarField) -> bool {
    *r == Bp384r1ScalarField::ZERO || *s == Bp384r1ScalarField::ZERO
}

/// FIPS 186-5 §6.4.2 on the finished message hash; the verifier's `do_verify_final` is
/// this one function. See `crate::ecdsa_p256`'s `verify_final`.
fn verify_final(
    hash: SHA384,
    pk: &ECDSABp384r1PublicKey,
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
        return Err(SignatureError::LengthError(
            "ECDSA brainpoolP384r1 signature must be exactly 96 bytes",
        ));
    }

    // step 1: r, s in [1, n-1], rejected (not reduced) if out of range.
    let r_limbs = bp384r1_sec1::limbs_from_be_bytes(&sig[..48].try_into().unwrap());
    let s_limbs = bp384r1_sec1::limbs_from_be_bytes(&sig[48..96].try_into().unwrap());
    if !in_range(&r_limbs) || !in_range(&s_limbs) {
        return Err(SignatureError::SignatureVerificationFailed);
    }
    let r = Bp384r1ScalarField::from_limbs(r_limbs);

    let mut h = [0u8; 48];
    hash.do_final_out(&mut h);
    let e = e_from_hash(&h); // steps 2-3

    // `s` is part of the signature, so its inverse is taken in variable time on the public
    // scalar type; the constant-time `invert` is for the signer's `k`.
    let s_inv = Bp384r1PublicScalar::from_limbs(s_limbs).invert_vartime(); // step 4
    let u = e.mul(&s_inv); // step 5
    let v = r.mul(&s_inv);

    let q = Bp384r1JacobianPoint::from_affine(pk.x, pk.y);
    let u_pub = Bp384r1PublicScalar::from_limbs(u.to_limbs());
    let v_pub = Bp384r1PublicScalar::from_limbs(v.to_limbs());
    let r1_point = shamir_multiply(&u_pub, &v_pub, &q); // step 6

    if r1_point.is_infinity().to_bool() {
        return Err(SignatureError::SignatureVerificationFailed);
    }
    let (x_r1, _) =
        r1_point.to_affine().expect("just checked r1_point is not the point at infinity");
    let r1 = Bp384r1ScalarField::from_limbs(x_r1.to_limbs()); // steps 7-8

    if r1 == r { Ok(()) } else { Err(SignatureError::SignatureVerificationFailed) } // step 9
}

impl SigningKey<ECDSABp384r1, SIG_LEN> for ECDSABp384r1PrivateKey {
    type Signer<'k>
        = ECDSABp384r1Signer<'k>
    where
        Self: 'k;

    fn create_signer<'k>(
        &'k self,
        rng: &mut dyn RNG,
        _ctx: Option<&[u8]>,
    ) -> Result<Self::Signer<'k>, SignatureError> {
        Ok(ECDSABp384r1Signer { sk: self, hash: SHA384::default(), k: random_k(rng)? })
    }
}

impl DeterministicSigningKey<ECDSABp384r1, SIG_LEN> for ECDSABp384r1PrivateKey {
    type Signer<'k>
        = ECDetDSABp384r1Signer<'k>
    where
        Self: 'k;

    fn create_signer_deterministic<'k>(
        &'k self,
        _ctx: Option<&[u8]>,
    ) -> Result<Self::Signer<'k>, SignatureError> {
        Ok(ECDetDSABp384r1Signer { sk: self, hash: SHA384::default() })
    }
}

impl VerifyingKey<ECDSABp384r1, SIG_LEN> for ECDSABp384r1PublicKey {
    type Verifier<'k>
        = ECDSABp384r1Verifier<'k>
    where
        Self: 'k;

    fn create_verifier<'k>(
        &'k self,
        _ctx: Option<&[u8]>,
    ) -> Result<Self::Verifier<'k>, SignatureError> {
        Ok(ECDSABp384r1Verifier { pk: self, hash: SHA384::default() })
    }
}

impl AlgorithmInfo for ECDSABp384r1Signer<'_> {
    fn alg_name(&self) -> &'static str {
        ECDSABp384r1::ALG_NAME
    }

    fn max_security_strength(&self) -> SecurityStrength {
        ECDSABp384r1::MAX_SECURITY_STRENGTH
    }
}

impl SignatureSigner<SIG_LEN> for ECDSABp384r1Signer<'_> {
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

impl AlgorithmInfo for ECDetDSABp384r1Signer<'_> {
    fn alg_name(&self) -> &'static str {
        ECDETDSA_BP384R1_NAME
    }

    fn max_security_strength(&self) -> SecurityStrength {
        ECDSABp384r1::MAX_SECURITY_STRENGTH
    }
}

impl SignatureSigner<SIG_LEN> for ECDetDSABp384r1Signer<'_> {
    fn do_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn do_final(self) -> Result<[u8; SIG_LEN], SignatureError> {
        let mut h = [0u8; 48];
        self.hash.do_final_out(&mut h);
        let k = rfc6979_bp384r1::generate_k(self.sk.scalar(), &h); // step 3, Appendix A.3.3
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

impl AlgorithmInfo for ECDSABp384r1Verifier<'_> {
    fn alg_name(&self) -> &'static str {
        ECDSABp384r1::ALG_NAME
    }

    fn max_security_strength(&self) -> SecurityStrength {
        ECDSABp384r1::MAX_SECURITY_STRENGTH
    }
}

impl SignatureVerifier for ECDSABp384r1Verifier<'_> {
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

// `r_or_s_is_zero` is private and, through `sign_with_k`, only ever reached with an `r`/`s` value
// that is astronomically unlikely for any real input (see its own doc comment), so no realistic
// integration test exercises either disjunct -- the QUALITY_AND_STYLE.md private-function
// exception applies.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r_or_s_is_zero_requires_only_one_to_be_zero() {
        let zero = Bp384r1ScalarField::ZERO;
        let one = Bp384r1ScalarField::ONE;
        assert!(!r_or_s_is_zero(&one, &one));
        assert!(r_or_s_is_zero(&zero, &one));
        assert!(r_or_s_is_zero(&one, &zero));
        assert!(r_or_s_is_zero(&zero, &zero));
    }
}
