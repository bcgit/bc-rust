//! `ECDSABp384r1`: FIPS 186-5 §6.4.1 (signature generation, deterministic per §6.3.2/Appendix
//! A.3.3 by default) and §6.4.2 (verification), fixed to SHA-384 (the pairing wycheproof's
//! `ecdsa_brainpoolP384r1_sha384_*` vector files use). Identical in shape to [`crate::ecdsa_p256`]
//! -- see that module's docs for the full reasoning (`e = bits2int(H)` needs no truncation since
//! `len(n) == hashlen == 384`; `x_affine_of_signing_point`'s branch-free-on-a-secret-value
//! argument; both hold unchanged here) -- with brainpoolP384r1's types, [`crate::keys_bp384r1`],
//! [`crate::extra_bits_bp384r1`], and [`crate::rfc6979_bp384r1`] substituted.

use crate::extra_bits_bp384r1::reduce_wide_bits_mod_n_minus_1;
use crate::keys_bp384r1::{ECDSABp384r1PrivateKey, ECDSABp384r1PublicKey, PK_LEN, SK_LEN};
use crate::rfc6979_bp384r1;
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{Hash, RNG, SignatureVerifier, Signer};
use bouncycastle_ec::bp384r1::Bp384r1FieldElement;
use bouncycastle_ec::bp384r1_comb::comb_multiply_base_point;
use bouncycastle_ec::bp384r1_point::Bp384r1JacobianPoint;
use bouncycastle_ec::bp384r1_scalar::{
    Bp384r1PublicScalar, Bp384r1Scalar, Bp384r1ScalarField, N_LIMBS,
};
use bouncycastle_ec::bp384r1_sec1;
use bouncycastle_ec::bp384r1_wnaf::shamir_multiply;
use bouncycastle_ec::nat;
use bouncycastle_sha2::SHA384;
use bouncycastle_utils::secret::Secret;

/// Raw `r || s` signature length: two 48-byte field-width integers (the plan's §6.4 choice of
/// default encoding). [`ECDSABp384r1::sign_der`]/[`ECDSABp384r1::verify_der`] offer the RFC 3279
/// §2.2.3 DER `SEQUENCE { r, s }` alternative via [`crate::der`], for interop that needs it.
pub const SIG_LEN: usize = 96;

/// Upper bound on a DER-encoded brainpoolP384r1 signature (`r`, `s` each 48 bytes); see
/// [`crate::der::max_len`].
pub const DER_SIG_MAX_LEN: usize = crate::der::max_len(48);

/// Streaming state for both `ECDSABp384r1`'s [`Signer`] and [`SignatureVerifier`] impls, mirroring
/// [`crate::ecdsa_p256::ECDSAP256`]'s shape.
pub struct ECDSABp384r1 {
    hash: SHA384,
    sk: Option<ECDSABp384r1PrivateKey>,
    pk: Option<ECDSABp384r1PublicKey>,
}

/// `x * z^-2`, branch-free -- see [`crate::ecdsa_p256`]'s module docs for why this isn't
/// [`Bp384r1JacobianPoint::to_affine`].
fn x_affine_of_signing_point(point: &Bp384r1JacobianPoint) -> Bp384r1FieldElement {
    let z_inv = point.z.invert();
    point.x.mul(&z_inv.mul(&z_inv))
}

/// FIPS 186-5 §6.4.1 steps 4-12, given `k` already generated (step 3) by one of Appendix A.3's
/// methods. Returns `Err` only for step 11's negligible-probability `r = 0` or `s = 0` case.
fn sign_with_k(
    sk: &ECDSABp384r1PrivateKey,
    e: &Bp384r1ScalarField,
    k: Bp384r1Scalar,
) -> Result<[u8; SIG_LEN], SignatureError> {
    let mut k_field = Bp384r1ScalarField::from_secret(&k);
    let mut k_inv = k_field.invert(); // step 4

    let r_point = comb_multiply_base_point(&k); // step 5
    let x_r = x_affine_of_signing_point(&r_point); // steps 6-7
    let r = Bp384r1ScalarField::from_limbs(x_r.to_limbs()); // step 8

    let mut d_field = Bp384r1ScalarField::from_secret(sk.scalar());
    let s = k_inv.mul(&e.add(&r.mul(&d_field))); // step 9

    // `k_field`, `k_inv` and `d_field` hold `k`, `k^-1` and `d`. Nothing below needs them, so they
    // are overwritten here rather than left legible on the stack after this returns -- placed
    // before step 11's check so that both ways out of the function are covered. `k` itself is a
    // `Secret` and scrubs when it drops; `e`, `r` and `s` are public by construction.
    k_field.zeroize();
    k_inv.zeroize();
    d_field.zeroize();

    // step 11: astronomically unlikely (r, s range over ~2^384 values each); this comparison is
    // FIPS 186-5's own mandated success/failure branch on the just-computed public output, not a
    // constant-time violation -- see this module's docs on x_affine_of_signing_point for the one
    // secret-derived branch this function does avoid.
    if r_or_s_is_zero(&r, &s) {
        return Err(SignatureError::GenericError(
            "ECDSA signature generation produced r = 0 or s = 0; regenerate k and retry",
        ));
    }

    let mut sig = [0u8; SIG_LEN];
    sig[..48].copy_from_slice(&bp384r1_sec1::be_bytes_from_limbs(&r.to_limbs()));
    sig[48..].copy_from_slice(&bp384r1_sec1::be_bytes_from_limbs(&s.to_limbs()));
    Ok(sig)
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

impl ECDSABp384r1 {
    /// FIPS 186-5 §6.4.1 with `k` generated by Appendix A.3.1 ("extra random bits") instead of the
    /// deterministic default -- an additional capability alongside [`Signer::sign`]. See
    /// [`crate::ecdsa_p256::ECDSAP256::sign_randomized`]'s docs for the full reasoning.
    pub fn sign_randomized(
        sk: &ECDSABp384r1PrivateKey,
        msg: &[u8],
        rng: &mut dyn RNG,
    ) -> Result<[u8; SIG_LEN], SignatureError> {
        let h: [u8; 48] = SHA384::default().hash(msg)[..48].try_into().unwrap();
        let e = e_from_hash(&h);

        // Raw DRBG output, reduced below into the private key / per-message secret: held in
        // `Secret` so it is scrubbed when this function returns rather than left on the stack.
        let mut extra_bits = Secret::<[u8; crate::keys_bp384r1::EXTRA_BITS_DRBG_OUTPUT_LEN]>::new();
        rng.next_bytes_out(&mut *extra_bits).map_err(SignatureError::RNGError)?;
        let k = reduce_wide_bits_mod_n_minus_1(&*extra_bits);

        sign_with_k(sk, &e, k)
    }

    /// As [`Signer::sign`], but DER-encodes the result (RFC 3279 §2.2.3 `Ecdsa-Sig-Value`) instead
    /// of raw `r || s`. Returns the encoded length; unused trailing bytes of the fixed-size buffer
    /// are left as written by [`crate::der::encode`] (zeroed only up to that length).
    pub fn sign_der(
        sk: &ECDSABp384r1PrivateKey,
        msg: &[u8],
        ctx: Option<&[u8]>,
    ) -> Result<([u8; DER_SIG_MAX_LEN], usize), SignatureError> {
        let raw = Self::sign(sk, msg, ctx)?;
        let mut out = [0u8; DER_SIG_MAX_LEN];
        let len = crate::der::encode(&raw[..48], &raw[48..], &mut out);
        Ok((out, len))
    }

    /// As [`SignatureVerifier::verify`], but expects a DER-encoded signature (see [`Self::sign_der`])
    /// instead of raw `r || s`.
    pub fn verify_der(
        pk: &ECDSABp384r1PublicKey,
        msg: &[u8],
        ctx: Option<&[u8]>,
        sig: &[u8],
    ) -> Result<(), SignatureError> {
        let mut raw = [0u8; SIG_LEN];
        let (r_out, s_out) = raw.split_at_mut(48);
        crate::der::decode(sig, r_out, s_out).ok_or(SignatureError::SignatureVerificationFailed)?;
        Self::verify(pk, msg, ctx, &raw)
    }
}

impl Signer<ECDSABp384r1PrivateKey, SK_LEN, SIG_LEN> for ECDSABp384r1 {
    fn sign(
        sk: &ECDSABp384r1PrivateKey,
        msg: &[u8],
        ctx: Option<&[u8]>,
    ) -> Result<[u8; SIG_LEN], SignatureError> {
        let mut s = Self::sign_init(sk, ctx)?;
        s.sign_update(msg);
        s.sign_final()
    }

    fn sign_out(
        sk: &ECDSABp384r1PrivateKey,
        msg: &[u8],
        ctx: Option<&[u8]>,
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError> {
        output.fill(0);
        *output = Self::sign(sk, msg, ctx)?;
        Ok(SIG_LEN)
    }

    fn sign_init(sk: &ECDSABp384r1PrivateKey, _ctx: Option<&[u8]>) -> Result<Self, SignatureError> {
        // ctx ignored -- see this crate's docs.
        Ok(Self { hash: SHA384::default(), sk: Some(sk.clone()), pk: None })
    }

    fn sign_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn sign_final(self) -> Result<[u8; SIG_LEN], SignatureError> {
        let sk = self.sk.ok_or(SignatureError::GenericError(
            "sign_final called on a verify-initialized ECDSABp384r1; call verify_final instead",
        ))?;
        let mut h = [0u8; 48];
        self.hash.do_final_out(&mut h);
        let e = e_from_hash(&h);
        let k = rfc6979_bp384r1::generate_k(sk.scalar(), &h);
        sign_with_k(&sk, &e, k)
    }

    fn sign_final_out(self, output: &mut [u8; SIG_LEN]) -> Result<usize, SignatureError> {
        output.fill(0);
        *output = self.sign_final()?;
        Ok(SIG_LEN)
    }
}

impl SignatureVerifier<ECDSABp384r1PublicKey, PK_LEN, SIG_LEN> for ECDSABp384r1 {
    fn verify(
        pk: &ECDSABp384r1PublicKey,
        msg: &[u8],
        ctx: Option<&[u8]>,
        sig: &[u8],
    ) -> Result<(), SignatureError> {
        let mut v = Self::verify_init(pk, ctx)?;
        v.verify_update(msg);
        v.verify_final(sig)
    }

    fn verify_init(
        pk: &ECDSABp384r1PublicKey,
        _ctx: Option<&[u8]>,
    ) -> Result<Self, SignatureError> {
        Ok(Self { hash: SHA384::default(), sk: None, pk: Some(*pk) })
    }

    fn verify_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn verify_final(self, sig: &[u8]) -> Result<(), SignatureError> {
        let pk = self.pk.ok_or(SignatureError::GenericError(
            "verify_final called on a sign-initialized ECDSABp384r1; call sign_final instead",
        ))?;
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
        let r_limbs = bp384r1_sec1::limbs_from_be_bytes(&sig[..48].try_into().unwrap());
        let s_limbs = bp384r1_sec1::limbs_from_be_bytes(&sig[48..96].try_into().unwrap());
        if !in_range(&r_limbs) || !in_range(&s_limbs) {
            return Err(SignatureError::SignatureVerificationFailed);
        }
        let r = Bp384r1ScalarField::from_limbs(r_limbs);
        let s = Bp384r1ScalarField::from_limbs(s_limbs);

        let mut h = [0u8; 48];
        self.hash.do_final_out(&mut h);
        let e = e_from_hash(&h); // steps 2-3

        let s_inv = s.invert(); // step 4
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
}

/// `true` iff `limbs`, read as a big-endian-decoded integer, is in `[1, n-1]` -- FIPS 186-5 §6.4.2
/// step 1's range check on `r` and `s`. On public signature data, so plain (not branch-free).
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
