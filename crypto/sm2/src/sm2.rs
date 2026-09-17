//! `SM2`: `draft-shen-sm2-ecdsa-02` §5.1 (signature generation) and §5.2 (verification), the actual
//! SM2 Digital Signature Algorithm -- distinct from ECDSA, despite both being built on Weierstrass
//! elliptic-curve arithmetic: SM2's signing equation `s = (1+dA)^-1 * (k - r*dA) mod n` and its
//! identity-binding `ZA` digest (see [`crate::za`]) have no ECDSA equivalent. Fixed to SM3 (the
//! draft's own hash, §5's worked example and every citation of "the cryptographic hash function"
//! throughout use SM3; `draft-shen-sm2-ecdsa-02` does not sanction substituting another hash).
//!
//! # `ctx` carries the signer's identity `IDA`
//!
//! Every operation here (§5.1 step 1 / §5.2 step 1) needs `IDA`, the signer's identity octet
//! string, to compute `ZA`. [`bouncycastle_core::traits::Signer::sign`]'s own documentation sanctions using
//! `ctx` "in a non-standard way" when a primitive doesn't natively support a context-binding value
//! the way the trait envisions: this crate treats `ctx: Option<&[u8]>` as literally `IDA`, and
//! returns [`SignatureError::GenericError`] if `ctx` is `None` -- there is no default identity in
//! the draft to fall back to, and inventing one unverified would be worse than requiring the caller
//! supply it explicitly.
//!
//! # Randomness, not determinism
//!
//! The draft's §5.1.3 step A3 says only to "pick a random number `k`... using a random number
//! generator"; there is no SM2 analogue of RFC 6979 in this draft, so (unlike every curve in
//! `bouncycastle-ecdsa`) there is no deterministic default here. [`bouncycastle_core::traits::Signer`]'s
//! own docs say its trait is "assumed to source all its randomness from bouncycastle's default
//! os-backed RNG", so [`Signer::sign`]/[`Signer::sign_final`] do exactly that (via [`bouncycastle_rng::DefaultRNG`]);
//! [`SM2::sign_randomized`] is offered alongside for a caller-supplied RNG, the same "additional
//! capability" shape `bouncycastle-ecdsa`'s curves offer for their own randomised alternative to
//! RFC 6979.
//!
//! # Retry convention
//!
//! Steps A5 (`r = 0` or `r + k = n`) and A6 (`s = 0`) each ask the signer to go back to step A3 and
//! draw a new `k`. Matching every curve's `sign_with_k` in `bouncycastle-ecdsa` (which returns `Err`
//! with a "regenerate k and retry" message rather than looping internally), this crate does the
//! same rather than retrying in a loop -- a deliberate consistency choice with this workspace's
//! established pattern, not mandated by the draft itself.
//!
//! # No DER encoding
//!
//! The draft has no ASN.1/DER encoding for `(r, s)`; [`SIG_LEN`] is raw `r || s`, 64 bytes, each a
//! 32-byte big-endian integer -- the same convention `bouncycastle-ecdsa` uses as its own default.
//!
//! # Extracting `x1` from a secret-derived `[k]G`
//!
//! `[k]G` (§5.1.3 step A4) is Jacobian-coordinate output of a *secret* scalar multiplication, so
//! converting it to affine cannot use [`Sm2JacobianPoint::to_affine`] -- that function's own docs
//! say it branches on infinity and is "not for use on a secret intermediate value".
//! [`x_affine_of_signing_point`] instead always computes `X * Z^-2`, branch-free; see its docs for
//! why `Z` is never zero here. This mirrors what every curve in `bouncycastle-ecdsa` does for the
//! same step, and is what makes this crate's "never handled in variable time" claim for `k` (see
//! [`crate`]'s Security Considerations) true of the signing path as a whole.

use crate::extra_bits::reduce_wide_bits_mod_n_minus_1;
use crate::keys::{EXTRA_BITS_DRBG_OUTPUT_LEN, PK_LEN, SK_LEN, SM2PrivateKey, SM2PublicKey};
use crate::za;
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{Hash, RNG, SignatureVerifier, Signer};
use bouncycastle_ec::nat;
use bouncycastle_ec::sm2::Sm2FieldElement;
use bouncycastle_ec::sm2_comb::comb_multiply_base_point;
use bouncycastle_ec::sm2_point::Sm2JacobianPoint;
use bouncycastle_ec::sm2_scalar::{N_LIMBS, Sm2PublicScalar, Sm2Scalar, Sm2ScalarField};
use bouncycastle_ec::sm2_sec1;
use bouncycastle_ec::sm2_wnaf::shamir_multiply;
use bouncycastle_rng::DefaultRNG;
use bouncycastle_sm3::SM3;
use bouncycastle_utils::secret::Secret;

/// Raw `r || s` signature length: two 32-byte field-width integers. See the module docs on why
/// there is no DER alternative here.
pub const SIG_LEN: usize = 64;

/// Streaming state for both `SM2`'s [`Signer`] and [`SignatureVerifier`] impls. Unlike
/// `bouncycastle-ecdsa`'s curves, the hash absorbed here already has `ZA` prepended by
/// [`Signer::sign_init`]/[`SignatureVerifier::verify_init`], so a later [`Signer::sign_final`]/
/// [`SignatureVerifier::verify_final`] need only finish hashing `M` to get `e = SM3(ZA || M)`
/// (`draft-shen-sm2-ecdsa-02` §5.1.3 step 1 / §5.2.3 step 1).
pub struct SM2 {
    hash: SM3,
    sk: Option<SM2PrivateKey>,
    pk: Option<SM2PublicKey>,
}

/// `e` from the (already `ZA`-prefixed) running hash, per §5.1.3 step 1 / §5.2.3 step 1.
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

/// §5.1.3 steps A4-A7, given `k` already generated (step A3) by one of `SM2`'s randomised methods.
/// Returns `Err` for step A5's `r = 0`/`r + k = n` or step A6's `s = 0` -- see the module docs on
/// this crate's retry convention.
fn sign_with_k(
    sk: &SM2PrivateKey,
    e: &Sm2ScalarField,
    k: Sm2Scalar,
) -> Result<[u8; SIG_LEN], SignatureError> {
    let k_field = Sm2ScalarField::from_secret(&k);

    let r_point = comb_multiply_base_point(&k); // step A4
    let x1 = x_affine_of_signing_point(&r_point); // step A4's x1
    let x1_field = Sm2ScalarField::from_limbs(x1.to_limbs());
    let r = e.add(&x1_field); // step A5

    let r_plus_k = r.add(&k_field);
    // Astronomically unlikely for any real k/e (r, r+k range over ~2^256 values each); this
    // comparison is the draft's own mandated success/failure branch on the just-computed public
    // output r, not a constant-time violation on a secret intermediate.
    if r_is_zero_or_r_plus_k_is_zero(&r, &r_plus_k) {
        return Err(SignatureError::GenericError(
            "SM2 signature generation produced r = 0 or r + k = n; regenerate k and retry",
        ));
    }

    let d_field = Sm2ScalarField::from_secret(sk.scalar());
    let one_plus_d_inv = Sm2ScalarField::ONE.add(&d_field).invert();
    let s = one_plus_d_inv.mul(&k_field.sub(&r.mul(&d_field))); // step A6

    if s == Sm2ScalarField::ZERO {
        return Err(SignatureError::GenericError(
            "SM2 signature generation produced s = 0; regenerate k and retry",
        ));
    }

    let mut sig = [0u8; SIG_LEN];
    sig[..32].copy_from_slice(&sm2_sec1::be_bytes_from_limbs(&r.to_limbs()));
    sig[32..].copy_from_slice(&sm2_sec1::be_bytes_from_limbs(&s.to_limbs()));
    Ok(sig) // step A7
}

/// §5.1.3 step A5's `r = 0` or `r + k = n` check, named so it has something to unit test directly:
/// reaching either branch through `sign_with_k` needs an `r`/`r + k` value that is astronomically
/// unlikely for any real `k`/`e` (see `sign_with_k`'s call site).
fn r_is_zero_or_r_plus_k_is_zero(r: &Sm2ScalarField, r_plus_k: &Sm2ScalarField) -> bool {
    *r == Sm2ScalarField::ZERO || *r_plus_k == Sm2ScalarField::ZERO
}

impl SM2 {
    /// §5.1 with `k` drawn from the caller-provided RNG -- an additional capability alongside
    /// [`Signer::sign`] (which sources `k` from the library's default RNG instead). See the module
    /// docs for why there is no deterministic alternative to offer here, unlike
    /// `bouncycastle-ecdsa`'s curves.
    pub fn sign_randomized(
        sk: &SM2PrivateKey,
        msg: &[u8],
        id: &[u8],
        rng: &mut dyn RNG,
    ) -> Result<[u8; SIG_LEN], SignatureError> {
        // PA is carried by the key, not recomputed: see SM2PrivateKey's docs on why deriving it
        // here would double the cost of signing.
        let (x, y) = sk.derive_pk().affine();
        let za = za::compute(id, &x, &y)?;

        let mut hash = SM3::new();
        hash.do_update(&za);
        hash.do_update(msg);
        let e = e_from_hash(hash);

        // Raw DRBG output, reduced below into the private key / per-message secret: held in
        // `Secret` so it is scrubbed when this function returns rather than left on the stack.
        let mut extra_bits = Secret::<[u8; EXTRA_BITS_DRBG_OUTPUT_LEN]>::new();
        rng.next_bytes_out(&mut *extra_bits).map_err(SignatureError::RNGError)?;
        let k = reduce_wide_bits_mod_n_minus_1(&*extra_bits);

        sign_with_k(sk, &e, k)
    }
}

impl Signer<SM2PrivateKey, SK_LEN, SIG_LEN> for SM2 {
    fn sign(
        sk: &SM2PrivateKey,
        msg: &[u8],
        ctx: Option<&[u8]>,
    ) -> Result<[u8; SIG_LEN], SignatureError> {
        let mut s = Self::sign_init(sk, ctx)?;
        s.sign_update(msg);
        s.sign_final()
    }

    fn sign_out(
        sk: &SM2PrivateKey,
        msg: &[u8],
        ctx: Option<&[u8]>,
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError> {
        output.fill(0);
        *output = Self::sign(sk, msg, ctx)?;
        Ok(SIG_LEN)
    }

    fn sign_init(sk: &SM2PrivateKey, ctx: Option<&[u8]>) -> Result<Self, SignatureError> {
        let id = ctx.ok_or(SignatureError::GenericError(
            "SM2 requires ctx to carry the signer's identity IDA (draft-shen-sm2-ecdsa-02 S5.1.2); \
             see bouncycastle-sm2's crate docs",
        ))?;
        // PA is carried by the key, not recomputed: see SM2PrivateKey's docs.
        let (x, y) = sk.derive_pk().affine();
        let za = za::compute(id, &x, &y)?;

        let mut hash = SM3::new();
        hash.do_update(&za);
        Ok(Self { hash, sk: Some(sk.clone()), pk: None })
    }

    fn sign_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn sign_final(self) -> Result<[u8; SIG_LEN], SignatureError> {
        let sk = self.sk.ok_or(SignatureError::GenericError(
            "sign_final called on a verify-initialized SM2; call verify_final instead",
        ))?;
        let e = e_from_hash(self.hash);

        let mut rng = DefaultRNG::default();
        // Raw DRBG output, reduced below into the private key / per-message secret: held in
        // `Secret` so it is scrubbed when this function returns rather than left on the stack.
        let mut extra_bits = Secret::<[u8; EXTRA_BITS_DRBG_OUTPUT_LEN]>::new();
        rng.next_bytes_out(&mut *extra_bits).map_err(SignatureError::RNGError)?;
        let k = reduce_wide_bits_mod_n_minus_1(&*extra_bits);

        sign_with_k(&sk, &e, k)
    }

    fn sign_final_out(self, output: &mut [u8; SIG_LEN]) -> Result<usize, SignatureError> {
        output.fill(0);
        *output = self.sign_final()?;
        Ok(SIG_LEN)
    }
}

impl SignatureVerifier<SM2PublicKey, PK_LEN, SIG_LEN> for SM2 {
    fn verify(
        pk: &SM2PublicKey,
        msg: &[u8],
        ctx: Option<&[u8]>,
        sig: &[u8],
    ) -> Result<(), SignatureError> {
        let mut v = Self::verify_init(pk, ctx)?;
        v.verify_update(msg);
        v.verify_final(sig)
    }

    fn verify_init(pk: &SM2PublicKey, ctx: Option<&[u8]>) -> Result<Self, SignatureError> {
        let id = ctx.ok_or(SignatureError::GenericError(
            "SM2 requires ctx to carry the signer's identity IDA (draft-shen-sm2-ecdsa-02 S5.2.2); \
             see bouncycastle-sm2's crate docs",
        ))?;
        let (x, y) = pk.affine();
        let za = za::compute(id, &x, &y)?;

        let mut hash = SM3::new();
        hash.do_update(&za);
        Ok(Self { hash, sk: None, pk: Some(*pk) })
    }

    fn verify_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn verify_final(self, sig: &[u8]) -> Result<(), SignatureError> {
        let pk = self.pk.ok_or(SignatureError::GenericError(
            "verify_final called on a sign-initialized SM2; call sign_final instead",
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

        // step B1: r', s' in [1, n-1], rejected (not reduced) if out of range.
        let r_limbs = sm2_sec1::limbs_from_be_bytes(&sig[..32].try_into().unwrap());
        let s_limbs = sm2_sec1::limbs_from_be_bytes(&sig[32..64].try_into().unwrap());
        if either_out_of_range(&r_limbs, &s_limbs) {
            return Err(SignatureError::SignatureVerificationFailed);
        }
        let r = Sm2ScalarField::from_limbs(r_limbs);
        let s = Sm2ScalarField::from_limbs(s_limbs);

        let e = e_from_hash(self.hash); // steps B2-B3

        let t = r.add(&s); // step B4
        if t == Sm2ScalarField::ZERO {
            return Err(SignatureError::SignatureVerificationFailed);
        }

        let q = Sm2JacobianPoint::from_affine(pk.x, pk.y);
        let s_pub = Sm2PublicScalar::from_limbs(s.to_limbs());
        let t_pub = Sm2PublicScalar::from_limbs(t.to_limbs());
        let point = shamir_multiply(&s_pub, &t_pub, &q); // step B5

        if point.is_infinity().to_bool() {
            return Err(SignatureError::SignatureVerificationFailed);
        }
        let (x1, _) = point.to_affine().expect("just checked point is not the point at infinity");
        let r1 = e.add(&Sm2ScalarField::from_limbs(x1.to_limbs())); // step B6

        if r1 == r { Ok(()) } else { Err(SignatureError::SignatureVerificationFailed) } // step B7
    }
}

/// `true` iff `limbs`, read as a big-endian-decoded integer, is in `[1, n-1]` -- §5.2.2 step B1's
/// range check on `r'` and `s'`. On public signature data, so plain (not branch-free).
fn in_range(limbs: &[u64; 4]) -> bool {
    if *limbs == [0, 0, 0, 0] {
        return false;
    }
    let (_, borrow) = nat::sub(limbs, &N_LIMBS);
    borrow == 1
}

/// `true` iff either `r'` or `s'` is outside `[1, n-1]` -- §5.2.2 step B1's range check, named so
/// the OR-of-two-checks combination has something to unit test directly (mirroring
/// `bouncycastle_ec::sm2_sec1::either_out_of_range`'s own naming and reasoning).
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
