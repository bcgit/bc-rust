//! `SM2`: GB/T 32918.2-2016 §6.1 (signature generation) and §7.1 (verification), the draft's §5.2
//! and §5.3 -- the actual SM2 Digital Signature Algorithm, distinct from ECDSA despite both being
//! built on Weierstrass elliptic-curve arithmetic: SM2's signing equation `s = (1+dA)^-1 * (k -
//! r*dA) mod n` and its identity-binding `ZA` digest (see [`crate::za`]) have no ECDSA
//! equivalent. Fixed to SM3: GB/T 32918.2-2016 §5.4.2 (the draft's §5.1.4.2) admits any approved
//! hash "such as SM3", but SM3 is what the standard's own Appendix A example, the draft's, and
//! every deployed implementation use, so no other hash is offered.
//!
//! # `ctx` carries the signer's identity `IDA`
//!
//! Every operation here (`ZA` is prepended to the message in §6.1 step A1 / §7.1 step B3) needs
//! `IDA`, the signer's identity octet string (§5.5), to compute `ZA`. The key traits' `ctx`
//! parameter is the natural place for a per-signature binding value, so this crate treats
//! `ctx: Option<&[u8]>` as literally `IDA`, and [`SigningKey::create_signer`] /
//! [`VerifyingKey::create_verifier`] return [`SignatureError::GenericError`] if `ctx` is `None` --
//! there is no default identity in the draft to fall back to, and inventing one unverified would
//! be worse than requiring the caller supply it explicitly.
//!
//! # Randomness, not determinism
//!
//! GB/T 32918.2-2016 §6.1 step A3 says only to produce `k` in `[1, n-1]` with a random number
//! generator (the draft's §5.2.1: "pick a random number `k`... using a random number
//! generator"); there is no SM2 analogue of RFC 6979 in either, so (unlike every curve in
//! `bouncycastle-ecdsa`) there is no [`DeterministicSigningKey`] impl here. `k` is drawn from the
//! RNG handed to [`SigningKey::create_signer`], once per signer, before the message is seen.
//!
//! # Retry
//!
//! Steps A5 (`r = 0` or `r + k = n`) and A6 (`s = 0`) each ask the signer to go back to step A3 and
//! draw a new `k`. The signer has no RNG at `do_final` to draw from, so it reports the failure
//! and the caller creates a fresh signer, as `bouncycastle-ecdsa`'s random-`k` signers do for
//! FIPS 186-5 §6.4.1 step 11; each case has probability about `2^-256`.
//!
//! # No DER encoding
//!
//! GB/T 32918.2-2016 has no ASN.1/DER encoding for `(r, s)`; [`SIG_LEN`] is raw `r || s`, 64 bytes, each a
//! 32-byte big-endian integer -- the same convention `bouncycastle-ecdsa` uses as its own default.
//!
//! # Extracting `x1` from a secret-derived `[k]G`
//!
//! `[k]G` (§6.1 step A4) is Jacobian-coordinate output of a *secret* scalar multiplication, so
//! converting it to affine cannot use [`Sm2JacobianPoint::to_affine`] -- that function's own docs
//! say it branches on infinity and is "not for use on a secret intermediate value".
//! [`x_affine_of_signing_point`] instead always computes `X * Z^-2`, branch-free; see its docs for
//! why `Z` is never zero here. This mirrors what every curve in `bouncycastle-ecdsa` does for the
//! same step, and is what makes this crate's "never handled in variable time" claim for `k` (see
//! [`crate`]'s Security Considerations) true of the signing path as a whole.

use crate::extra_bits::reduce_wide_bits_mod_n_minus_1;
use crate::keys::{EXTRA_BITS_DRBG_OUTPUT_LEN, SM2PrivateKey, SM2PublicKey};
use crate::za;
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::security_strength::SecurityStrength;
#[allow(unused_imports)] // for the docs
use bouncycastle_core::signature_key::DeterministicSigningKey;
use bouncycastle_core::signature_key::{SignatureAlgorithm, SigningKey, VerifyingKey};
use bouncycastle_core::traits::{
    Algorithm, AlgorithmInfo, Hash, RNG, SignatureSigner, SignatureVerifier,
};
use bouncycastle_ec::hazmat::sm2::Sm2FieldElement;
use bouncycastle_ec::hazmat::sm2_comb::comb_multiply_base_point;
use bouncycastle_ec::hazmat::sm2_point::Sm2JacobianPoint;
use bouncycastle_ec::hazmat::sm2_scalar::{N_LIMBS, Sm2PublicScalar, Sm2Scalar, Sm2ScalarField};
use bouncycastle_ec::hazmat::sm2_sec1;
use bouncycastle_ec::hazmat::sm2_wnaf::shamir_multiply;
use bouncycastle_ec::nat;
use bouncycastle_sm3::SM3;
use bouncycastle_utils::secret::Secret;

/// Raw `r || s` signature length: two 32-byte field-width integers. See the module docs on why
/// there is no DER alternative here.
pub const SIG_LEN: usize = 64;

/// SM2 digital signature (GB/T 32918.2-2016): the algorithm marker. [`SM2PrivateKey`] signs
/// through [`SigningKey`], [`SM2PublicKey`] verifies through [`VerifyingKey`]. `ctx` must carry
/// the signer's identity `IDA` (S5.5): `ZA` binds it into every signature, so a missing `ctx` is
/// an error rather than a default identity.
pub struct SM2;

impl Algorithm for SM2 {
    const ALG_NAME: &'static str = "SM2";
    /// SP 800-57 Part 1 Rev. 5, Table 2: a 256-bit curve order gives 128 bits.
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

impl SignatureAlgorithm for SM2 {}

/// The signer [`SigningKey::create_signer`] hands out. `ZA` is absorbed when it is created, and
/// the per-message secret `k` (step A3) is drawn from the caller's RNG then too, since it does
/// not depend on the message; the signer then only hashes.
pub struct SM2Signer<'k> {
    sk: &'k SM2PrivateKey,
    hash: SM3,
    k: Sm2Scalar,
}

/// The verifier [`VerifyingKey::create_verifier`] hands out; `ZA` is absorbed when it is created.
pub struct SM2Verifier<'k> {
    pk: &'k SM2PublicKey,
    hash: SM3,
}

/// `e` from the (already `ZA`-prefixed) running hash, per §6.1 step A2 / §7.1 step B4.
fn e_from_hash(hash: SM3) -> Sm2ScalarField {
    let mut e_bytes = [0u8; 32];
    hash.do_final_out(&mut e_bytes);
    Sm2ScalarField::from_limbs(sm2_sec1::limbs_from_be_bytes(&e_bytes))
}

/// `x * z^-2`, branch-free -- the affine `x1` of a point that came out of a *secret* scalar
/// multiplication, mirroring `bouncycastle_ecdsa::ecdsa_p256`'s helper of the same name.
///
/// [`Sm2JacobianPoint::to_affine`] cannot be used here: its own docs say it branches on infinity
/// and is "not for use on a secret intermediate value", and `[k]G` is exactly that. This always
/// computes `X * Z^-2` instead, which is what `to_affine` does in its non-infinity case. `Z` is
/// never `0` here, since `k` is in `[1, n-1]` by construction and `G` has prime order `n` (SM2's
/// cofactor is `h = 1`), so `[k]G` is never the identity for any valid `k` -- that holds
/// unconditionally, so skipping the infinity branch leaks nothing about which `k` was drawn. It
/// also skips computing `y1`, which step A5 never uses.
fn x_affine_of_signing_point(point: &Sm2JacobianPoint) -> Sm2FieldElement {
    let z_inv = point.z.invert();
    point.x.mul(&z_inv.mul(&z_inv))
}

/// §6.1 steps A4-A7, given `k` already generated (step A3) by one of `SM2`'s randomised methods.
/// Returns `None` for step A5's `r = 0`/`r + k = n` or step A6's `s = 0`, on which
/// [`sign_with_random_k`] goes back to step A3.
fn sign_with_k(sk: &SM2PrivateKey, e: &Sm2ScalarField, k: Sm2Scalar) -> Option<[u8; SIG_LEN]> {
    let mut k_field = Sm2ScalarField::from_secret(&k);

    let r_point = comb_multiply_base_point(&k); // step A4
    let x1 = x_affine_of_signing_point(&r_point); // step A4's x1
    let x1_field = Sm2ScalarField::from_limbs(x1.to_limbs());
    let r = e.add(&x1_field); // step A5

    // `r + k` is as sensitive as `k`: `r` is published in the signature, so anyone holding both
    // recovers `k` by subtraction. It is scrubbed on both ways out of the check below.
    let mut r_plus_k = r.add(&k_field);
    // Step A5's check. Both disjuncts are compared in constant time (`PartialEq` on the field
    // type is), and the branch below is one of the two data-dependent branches on the signing
    // path (step A6's `s = 0` is the other). `r = 0` is a condition on the public output;
    // `(r + k) mod n = 0`, i.e. `r + k = n` for `k` in `[1, n-1]` and `r` in `[0, n-1]`, is a
    // function of `k`, but a taken branch discards that `k`, so it reveals nothing about a `k`
    // that is used. Each disjunct is taken with probability about `2^-256` per signature.
    let r_out_of_range = r_is_zero_or_r_plus_k_is_zero(&r, &r_plus_k);
    r_plus_k.zeroize();
    if r_out_of_range {
        k_field.zeroize();
        return None;
    }

    let mut d_field = Sm2ScalarField::from_secret(sk.scalar());
    // (1 + dA)^-1 is cached on the key (see SM2PrivateKey's docs): it depends only on dA, and
    // recomputing it here was a constant-time inversion per signature.
    let mut one_plus_d_inv = Sm2ScalarField::from_secret(sk.one_plus_d_inv());
    let s = one_plus_d_inv.mul(&k_field.sub(&r.mul(&d_field))); // step A6

    // `k_field`, `d_field` and `(1 + dA)^-1` all reveal `k` or `dA`; nothing below needs them, and
    // scrubbing here covers both the error return and the success return. `k` itself is a `Secret`
    // and scrubs when it drops; `e`, `r` and `s` are public by construction.
    k_field.zeroize();
    d_field.zeroize();
    one_plus_d_inv.zeroize();

    if s == Sm2ScalarField::ZERO {
        return None;
    }

    let mut sig = [0u8; SIG_LEN];
    sig[..32].copy_from_slice(&sm2_sec1::be_bytes_from_limbs(&r.to_limbs()));
    sig[32..].copy_from_slice(&sm2_sec1::be_bytes_from_limbs(&s.to_limbs()));
    Some(sig) // step A7
}

/// Step A3: `k` from the caller's RNG, by the extra-random-bits reduction of
/// [`reduce_wide_bits_mod_n_minus_1`].
fn random_k(rng: &mut dyn RNG) -> Result<Sm2Scalar, SignatureError> {
    // Raw DRBG output, reduced below into the per-message secret: held in `Secret` so it is
    // scrubbed rather than left on the stack.
    let mut extra_bits = Secret::<[u8; EXTRA_BITS_DRBG_OUTPUT_LEN]>::new();
    rng.next_bytes_out(&mut *extra_bits).map_err(SignatureError::RNGError)?;
    Ok(reduce_wide_bits_mod_n_minus_1(&*extra_bits))
}

/// §6.1 step A5's `r = 0` or `r + k = n` check, named so it has something to unit test directly:
/// reaching either branch through `sign_with_k` needs an `r`/`r + k` value that is astronomically
/// unlikely for any real `k`/`e` (see `sign_with_k`'s call site).
fn r_is_zero_or_r_plus_k_is_zero(r: &Sm2ScalarField, r_plus_k: &Sm2ScalarField) -> bool {
    *r == Sm2ScalarField::ZERO || *r_plus_k == Sm2ScalarField::ZERO
}

/// `SM3` with `ZA = H256(ENTL || IDA || a || b || xG || yG || xA || yA)` absorbed (S5.5), the
/// state both the signer and the verifier start from. `ctx` is `IDA`.
fn za_hash(
    ctx: Option<&[u8]>,
    x: &Sm2FieldElement,
    y: &Sm2FieldElement,
) -> Result<SM3, SignatureError> {
    let id = ctx.ok_or(SignatureError::GenericError(
        "SM2 requires ctx to carry the signer's identity IDA (GB/T 32918.2-2016 S5.5); see \
         bouncycastle-sm2's crate docs",
    ))?;
    let za = za::compute(id, x, y)?;
    let mut hash = SM3::new();
    hash.do_update(&za);
    Ok(hash)
}

impl SigningKey<SM2, SIG_LEN> for SM2PrivateKey {
    type Signer<'k>
        = SM2Signer<'k>
    where
        Self: 'k;

    fn create_signer<'k>(
        &'k self,
        rng: &mut dyn RNG,
        ctx: Option<&[u8]>,
    ) -> Result<Self::Signer<'k>, SignatureError> {
        // PA is carried by the key, not recomputed: see SM2PrivateKey's docs.
        let (x, y) = self.derive_pk().affine();
        Ok(SM2Signer { sk: self, hash: za_hash(ctx, &x, &y)?, k: random_k(rng)? })
    }
}

impl VerifyingKey<SM2, SIG_LEN> for SM2PublicKey {
    type Verifier<'k>
        = SM2Verifier<'k>
    where
        Self: 'k;

    fn create_verifier<'k>(
        &'k self,
        ctx: Option<&[u8]>,
    ) -> Result<Self::Verifier<'k>, SignatureError> {
        let (x, y) = self.affine();
        Ok(SM2Verifier { pk: self, hash: za_hash(ctx, &x, &y)? })
    }
}

impl AlgorithmInfo for SM2Signer<'_> {
    fn alg_name(&self) -> &'static str {
        SM2::ALG_NAME
    }

    fn max_security_strength(&self) -> SecurityStrength {
        SM2::MAX_SECURITY_STRENGTH
    }
}

impl SignatureSigner<SIG_LEN> for SM2Signer<'_> {
    fn do_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn do_final(self) -> Result<[u8; SIG_LEN], SignatureError> {
        let e = e_from_hash(self.hash);
        // Steps A5 and A6 send `r = 0`, `r + k = n` and `s = 0` back to step A3 for a new `k`.
        // `k` was drawn when this signer was created and there is no RNG here to draw another
        // from, so the failure is reported instead; each case has probability about 2^-256.
        sign_with_k(self.sk, &e, self.k).ok_or(SignatureError::GenericError(
            "SM2 produced r = 0, r + k = n or s = 0; create a fresh signer and sign again",
        ))
    }

    fn do_final_out(self, output: &mut [u8; SIG_LEN]) -> Result<usize, SignatureError> {
        output.fill(0);
        *output = self.do_final()?;
        Ok(SIG_LEN)
    }
}

impl AlgorithmInfo for SM2Verifier<'_> {
    fn alg_name(&self) -> &'static str {
        SM2::ALG_NAME
    }

    fn max_security_strength(&self) -> SecurityStrength {
        SM2::MAX_SECURITY_STRENGTH
    }
}

impl SignatureVerifier for SM2Verifier<'_> {
    fn do_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn do_verify_final(self, sig: &[u8]) -> Result<(), SignatureError> {
        verify_final(self.hash, self.pk, sig)
    }
}

/// Steps B1-B7 of the verification, given the `ZA`-primed hash with the message absorbed.
fn verify_final(hash: SM3, pk: &SM2PublicKey, sig: &[u8]) -> Result<(), SignatureError> {
    // Exactly SIG_LEN, not "at least": the raw encoding is two fixed-width integers and
    // nothing else, so trailing bytes make this a different, malformed encoding rather than a
    // valid signature in a roomy buffer. Accepting them would let anyone turn one valid
    // signature into unlimited distinct byte strings that all verify -- malleability that
    // breaks any caller treating the signature as an opaque, comparable blob. This matches how
    // `SignaturePublicKey`/`SignaturePrivateKey::from_bytes` already reject an over-long
    // encoding here (see `core-test-framework`'s own `test_boundary_conditions`).
    if sig.len() != SIG_LEN {
        return Err(SignatureError::LengthError("SM2 signature must be exactly 64 bytes"));
    }

    // steps B1-B2: r', s' in [1, n-1], rejected (not reduced) if out of range.
    let r_limbs = sm2_sec1::limbs_from_be_bytes(&sig[..32].try_into().unwrap());
    let s_limbs = sm2_sec1::limbs_from_be_bytes(&sig[32..64].try_into().unwrap());
    if either_out_of_range(&r_limbs, &s_limbs) {
        return Err(SignatureError::SignatureVerificationFailed);
    }
    let r = Sm2ScalarField::from_limbs(r_limbs);
    let s = Sm2ScalarField::from_limbs(s_limbs);

    let e = e_from_hash(hash); // steps B3-B4

    let t = r.add(&s); // step B5
    if t == Sm2ScalarField::ZERO {
        return Err(SignatureError::SignatureVerificationFailed);
    }

    let q = Sm2JacobianPoint::from_affine(pk.x, pk.y);
    let s_pub = Sm2PublicScalar::from_limbs(s.to_limbs());
    let t_pub = Sm2PublicScalar::from_limbs(t.to_limbs());
    let point = shamir_multiply(&s_pub, &t_pub, &q); // step B6

    if point.is_infinity().to_bool() {
        return Err(SignatureError::SignatureVerificationFailed);
    }
    let (x1, _) = point.to_affine().expect("just checked point is not the point at infinity");
    let r1 = e.add(&Sm2ScalarField::from_limbs(x1.to_limbs())); // step B7's R

    if r1 == r { Ok(()) } else { Err(SignatureError::SignatureVerificationFailed) } // step B7
}

fn in_range(limbs: &[u64; 4]) -> bool {
    if *limbs == [0, 0, 0, 0] {
        return false;
    }
    let (_, borrow) = nat::sub(limbs, &N_LIMBS);
    borrow == 1
}

/// `true` iff either `r'` or `s'` is outside `[1, n-1]` -- §7.1 steps B1-B2's range check, named so
/// the OR-of-two-checks combination has something to unit test directly (mirroring
/// `bouncycastle_ec::hazmat::sm2_sec1::either_out_of_range`'s own naming and reasoning).
fn either_out_of_range(r_limbs: &[u64; 4], s_limbs: &[u64; 4]) -> bool {
    !in_range(r_limbs) || !in_range(s_limbs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_range_boundary_cases() {
        assert!(!in_range(&[0, 0, 0, 0]));
        assert!(in_range(&[1, 0, 0, 0]));
        let n_minus_1 = [N_LIMBS[0] - 1, N_LIMBS[1], N_LIMBS[2], N_LIMBS[3]];
        assert!(in_range(&n_minus_1));
        assert!(!in_range(&N_LIMBS));
        assert!(!in_range(&[u64::MAX; 4]));
    }

    // r_is_zero_or_r_plus_k_is_zero is private and, through sign_with_k, only ever reached with an
    // r/r+k value that is astronomically unlikely for any real k/e (see its own doc comment), so no
    // realistic integration test exercises either disjunct -- the QUALITY_AND_STYLE.md
    // private-function exception applies (the same one bouncycastle-ecdsa's own
    // r_or_s_is_zero_requires_only_one_to_be_zero test relies on).
    #[test]
    fn r_is_zero_or_r_plus_k_is_zero_requires_only_one_to_be_zero() {
        let zero = Sm2ScalarField::ZERO;
        let one = Sm2ScalarField::ONE;
        assert!(!r_is_zero_or_r_plus_k_is_zero(&one, &one));
        assert!(r_is_zero_or_r_plus_k_is_zero(&zero, &one));
        assert!(r_is_zero_or_r_plus_k_is_zero(&one, &zero));
        assert!(r_is_zero_or_r_plus_k_is_zero(&zero, &zero));
    }

    #[test]
    fn either_out_of_range_requires_only_one_to_be_out_of_range() {
        let in_range = [1, 0, 0, 0];
        let out_of_range = N_LIMBS;
        assert!(!either_out_of_range(&in_range, &in_range));
        assert!(either_out_of_range(&out_of_range, &in_range));
        assert!(either_out_of_range(&in_range, &out_of_range));
        assert!(either_out_of_range(&out_of_range, &out_of_range));
    }
}
