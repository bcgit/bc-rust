//! ECDSA over any [`Curve`] with any hash: FIPS 186-5 Section 6.4.1 (signature generation) and
//! Section 6.4.2 (verification). [`ECDSA<C, H>`] is the algorithm marker;
//! [`ECDSAPrivateKey<C, H>`] signs through [`SigningKey`] (a random per-message `k`, Section 6.3.1
//! / Appendix A.3.1) and [`DeterministicSigningKey`] (`k` from `d` and the message hash, Section
//! 6.3.2 / Appendix A.3.3, RFC 6979), and [`ECDSAPublicKey<C, H>`] verifies through
//! [`VerifyingKey`]. Section 6 says the choice of `k` "does not impact the signature
//! verification process", so there is one verifier and a signature from either signer verifies
//! under it. The conventional pairings have aliases, [`ECDSAP256`] and its siblings.
//!
//! # `r`, `s` and `e`
//!
//! SP 800-186 Appendix F.1 (field element to integer) is the identity for a prime field, so `r1`
//! is `R`'s affine `x` read as its canonical `[0, p)` representative. `e` is Section 6.4.1 step 2
//! / Section 6.4.2 step 3: `E = H` when `len(n) >= hashlen`, else the leftmost `len(n)` bits of
//! `H`, then Appendix B.2.1's big-endian conversion; byte-aligned on every curve here, which
//! `check_hash_fits` pins. Both `r1` and `e` can exceed `n` as raw values below `2^len(n)`, and
//! `2n > 2^len(n)`, so the scalar field's load reduces either with one conditional subtraction,
//! which is steps 7-8's "convert, then `mod n`".
//!
//! # Extracting `x_R` from a secret-derived `R`
//!
//! `R = [k]G` is Jacobian output of a secret scalar multiplication, so its affine `x` is taken
//! through [`JacobianPoint::affine_x_of_nonidentity`], branch-free, rather than `to_affine`,
//! which branches on the identity. `R` is never the identity: `k` is in `[1, n-1]` (RFC 6979 or
//! Appendix A.3.1, both by construction) and `G` has prime order `n` (cofactor 1 on every curve
//! here), so skipping the branch leaks nothing about which `k` was drawn.

use crate::keys::{ECDSAPrivateKey, ECDSAPublicKey};
use crate::rfc6979;
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::signature_key::{
    DeterministicSigningKey, SignatureAlgorithm, SigningKey, VerifyingKey,
};
use bouncycastle_core::traits::{
    Algorithm, AlgorithmInfo, HashAlgParams, RNG, SignatureSigner, SignatureVerifier,
};
use bouncycastle_ec::curve::{
    Curve, FieldElement, JacobianPoint, PublicScalar, ScalarFieldElement,
};
use bouncycastle_ec::{Bp256r1, Bp384r1, Bp512r1, P256, P384, P521, Secp256K1};
use bouncycastle_hmac::HMACParams;
use bouncycastle_sha2::{SHA256, SHA384, SHA512};
use bouncycastle_utils::const_str::ConstStr;
use bouncycastle_utils::secret::{Secret, ZeroizablePrimitive};
use core::marker::PhantomData;

/// The largest hash output the signers size their buffers for: SHA-512 and SHA3-512.
pub(crate) const MAX_HASH_LEN: usize = 64;

/// What a curve and hash pairing must satisfy for this crate's byte-wise handling of `E`
/// (Section 6.4.1 step 2) and of RFC 6979's `bits2int`: the hash fits the buffers, its output
/// is either no longer than the order (`E = H`, zero-extended) or the order's length is a whole
/// number of bytes (the leftmost `len(n)` bits are the first `len(n) / 8` bytes), and RFC 6979
/// step h.2 needs no more rounds than the buffer holds. Evaluated as a `const` in every
/// instantiation, so a pairing outside those conditions does not compile.
pub(crate) const fn check_hash_fits<C: Curve, H: HashAlgParams>() {
    assert!(H::OUTPUT_LEN <= MAX_HASH_LEN, "the hash output fits MAX_HASH_LEN");
    assert!(
        C::ORDER_BITS % 8 == 0 || 8 * H::OUTPUT_LEN <= C::ORDER_BITS,
        "the leftmost len(n) bits of the hash are whole bytes"
    );
    assert!(
        C::ORDER_BITS.div_ceil(8 * H::OUTPUT_LEN) <= rfc6979::MAX_ROUNDS,
        "RFC 6979 step h.2 fits MAX_ROUNDS"
    );
}

/// `E` of FIPS 186-5 Section 6.4.1 step 2 / Section 6.4.2 step 3 as limbs: `H` itself when
/// `len(n) >= hashlen`, else its leftmost `len(n)` bits (whole bytes here, see
/// [`check_hash_fits`]), zero-extended on the left to the scalar width and converted as Appendix
/// B.2.1 says (big-endian). Also RFC 6979 Section 2.3.2's `bits2int(h1)`, which is the same rule.
pub(crate) fn hash_to_limbs<C: Curve, H: HashAlgParams>(h: &[u8]) -> C::Limbs {
    let take = if 8 * h.len() <= C::ORDER_BITS { h.len() } else { C::ORDER_BITS / 8 };
    let mut bytes = C::ScalarBytes::ZEROED;
    let width = bytes.as_ref().len();
    bytes.as_mut()[width - take..].copy_from_slice(&h[..take]);
    C::limbs_from_be_bytes(&bytes)
}

/// The lesser of two strengths.
const fn min_strength(a: SecurityStrength, b: SecurityStrength) -> SecurityStrength {
    if (a as u8) <= (b as u8) { a } else { b }
}

/// ECDSA over the curve `C` with the hash `H`: the algorithm marker the key role traits are
/// implemented over. [`ECDSAPrivateKey<C, H>`] signs with it through [`SigningKey`] (a random
/// per-message `k`, Section 6.3.1 / Appendix A.3.1) and [`DeterministicSigningKey`] (`k` from `d`
/// and the message hash, Section 6.3.2 / Appendix A.3.3, RFC 6979); [`ECDSAPublicKey<C, H>`]
/// verifies through [`VerifyingKey`]. Named `ECDSA-<curve>-<hash>` (`ECDSA-P256-SHA256`), with
/// the deterministic signer reporting `ECDetDSA-<curve>-<hash>`; the strength is the lesser of
/// the curve's and the hash's. FIPS 186-5 Section 6.4.1 asks the hash's strength to be at least
/// the key pair's; a pairing below that is accepted here, at the hash's strength, for verifying
/// what was signed that way.
///
/// Raw `r || s`, `C::SIG_LEN` bytes, is the signature encoding; [`crate::der`] offers the RFC
/// 3279 Section 2.2.3 DER `SEQUENCE { r, s }` for interop that needs it. Neither signer uses
/// `ctx`: ECDSA has no context string, and the argument is accepted and ignored so that the key
/// traits read the same across algorithms.
pub struct ECDSA<C: Curve, H: EcdsaHash>(PhantomData<(C, H)>);

impl<C: Curve, H: EcdsaHash> ECDSA<C, H> {
    const NAME: ConstStr<48> = ConstStr::concat(&["ECDSA-", C::NAME, "-", H::ALG_NAME]);
    const DET_NAME: ConstStr<48> = ConstStr::concat(&["ECDetDSA-", C::NAME, "-", H::ALG_NAME]);
    /// What the deterministic signer reports as its algorithm name: the algorithm is still this
    /// one, and the name says how `k` was chosen.
    pub const DETERMINISTIC_ALG_NAME: &'static str = Self::DET_NAME.as_str();
}

impl<C: Curve, H: EcdsaHash> Algorithm for ECDSA<C, H> {
    const ALG_NAME: &'static str = Self::NAME.as_str();
    const MAX_SECURITY_STRENGTH: SecurityStrength =
        min_strength(C::STRENGTH, H::MAX_SECURITY_STRENGTH);
}

impl<C: Curve, H: EcdsaHash> SignatureAlgorithm for ECDSA<C, H> {}

/// A hash ECDSA signs with: any [`HMACParams`] hash, because the deterministic signer keys RFC
/// 6979's HMAC on it. Implemented for every such hash, so the bound is a name for "a hash", not
/// a restriction.
pub trait EcdsaHash: HMACParams {}

impl<H: HMACParams> EcdsaHash for H {}

/// ECDSA-P256-SHA256, the pairing FIPS 186-5 and TLS 1.3 use.
pub type ECDSAP256 = ECDSA<P256, SHA256>;
/// ECDSA-P384-SHA384.
pub type ECDSAP384 = ECDSA<P384, SHA384>;
/// ECDSA-P521-SHA512.
pub type ECDSAP521 = ECDSA<P521, SHA512>;
/// ECDSA-secp256k1-SHA256.
pub type ECDSASecp256K1 = ECDSA<Secp256K1, SHA256>;
/// ECDSA-brainpoolP256r1-SHA256.
pub type ECDSABp256r1 = ECDSA<Bp256r1, SHA256>;
/// ECDSA-brainpoolP384r1-SHA384.
pub type ECDSABp384r1 = ECDSA<Bp384r1, SHA384>;
/// ECDSA-brainpoolP512r1-SHA512.
pub type ECDSABp512r1 = ECDSA<Bp512r1, SHA512>;

/// The signer [`SigningKey::create_signer`] hands out: ECDSA with a random `k`.
///
/// `k` is drawn from the caller's RNG when the signer is created (Appendix A.3.1, "extra random
/// bits"), since it does not depend on the message; the signer then only hashes. Two signatures
/// of one message under one key differ.
pub struct ECDSASigner<'k, C: Curve, H: EcdsaHash> {
    sk: &'k ECDSAPrivateKey<C, H>,
    hash: H,
    k: C::Scalar,
}

/// The signer [`DeterministicSigningKey::create_signer_deterministic`] hands out: Deterministic
/// ECDSA, `k` from `d` and the message hash by RFC 6979, so the same key and message always give
/// the same signature and signing draws no randomness. Reports `ECDetDSA-<curve>-<hash>`.
pub struct ECDetDSASigner<'k, C: Curve, H: EcdsaHash> {
    sk: &'k ECDSAPrivateKey<C, H>,
    hash: H,
}

/// The verifier [`VerifyingKey::create_verifier`] hands out; FIPS 186-5 Section 6.4.2.
pub struct ECDSAVerifier<'k, C: Curve, H: EcdsaHash> {
    pk: &'k ECDSAPublicKey<C, H>,
    hash: H,
}

/// FIPS 186-5 Section 6.4.1 steps 4-12, given `k` already generated (step 3) by one of Appendix
/// A.3's methods. Returns `None` for step 11's `r = 0` or `s = 0` case; each caller acts on it
/// as step 11 directs for its way of generating `k`.
fn sign_with_k<C: Curve, H: EcdsaHash>(
    sk: &ECDSAPrivateKey<C, H>,
    e: &C::ScalarField,
    k: C::Scalar,
) -> Option<C::Signature> {
    let mut k_field = C::ScalarField::from_secret(&k);
    let mut k_inv = k_field.invert(); // step 4

    let mut r_point = C::multiply_base_point(&k); // step 5
    let x_r = r_point.affine_x_of_nonidentity(); // steps 6-7, see the module docs
    let r = C::ScalarField::from_limbs(x_r.to_limbs()); // step 8

    let mut d_field = C::ScalarField::from_secret(sk.scalar());
    let s = k_inv.mul(&e.add(&r.mul(&d_field))); // step 9

    // step 10: `k_field`, `k_inv` and `d_field` hold `k`, `k^-1` and `d`, and `r_point`'s
    // projective coordinates are a function of `k`'s bits even though its affine `x` is the
    // public `r`. Overwritten here, before step 11's check, so both ways out of the function are
    // covered. `k` itself is a `Secret` and scrubs when it drops; `e`, `r` and `s` are public.
    k_field.zeroize();
    k_inv.zeroize();
    d_field.zeroize();
    r_point.zeroize();

    // step 11: astronomically unlikely (r and s range over about 2^len(n) values each); this is
    // FIPS 186-5's own success/failure branch on the just-computed public output, not a
    // constant-time violation -- see the module docs for the one secret-derived branch avoided.
    if r_or_s_is_zero::<C>(&r, &s) {
        return None;
    }

    // step 12: r || s, each int2octets to the scalar width
    let mut sig = C::Signature::ZEROED;
    let half = C::SCALAR_LEN;
    sig.as_mut()[..half].copy_from_slice(C::be_bytes_from_limbs(&r.to_limbs()).as_ref());
    sig.as_mut()[half..].copy_from_slice(C::be_bytes_from_limbs(&s.to_limbs()).as_ref());
    Some(sig)
}

/// FIPS 186-5 Section 6.4.1 step 3 by Appendix A.3.1: the curve's extra-bits draw from `rng`
/// (at least `N + 64` bits, step 3's `t >= 64`), reduced into `[1, n-1]` by the curve's
/// `reduce_wide_bits_mod_n_minus_1`. The one place the random signer draws `k`.
fn random_k<C: Curve>(rng: &mut dyn RNG) -> Result<C::Scalar, SignatureError> {
    // Raw DRBG output, reduced below into the per-message secret: held in a Secret so it is
    // scrubbed when this function returns rather than left on the stack.
    let mut extra_bits = Secret::<C::ExtraBitsDraw>::new();
    rng.next_bytes_out(extra_bits.as_mut()).map_err(SignatureError::RNGError)?;
    Ok(C::reduce_wide_bits_mod_n_minus_1((*extra_bits).as_ref()))
}

/// `e` from the message hash, [`hash_to_limbs`] reduced mod `n` by the scalar field's load.
fn e_from_hash<C: Curve, H: HashAlgParams>(h: &[u8]) -> C::ScalarField {
    C::ScalarField::from_limbs(hash_to_limbs::<C, H>(h))
}

/// FIPS 186-5 Section 6.4.1 step 11's `r = 0` or `s = 0` check, named so it has something to
/// unit test directly: reaching either branch through `sign_with_k` needs an `r`/`s` value that
/// is astronomically unlikely for any real `k`/`d`/message.
fn r_or_s_is_zero<C: Curve>(r: &C::ScalarField, s: &C::ScalarField) -> bool {
    *r == C::ScalarField::ZERO || *s == C::ScalarField::ZERO
}

/// The finished message hash, `H::OUTPUT_LEN` bytes of a `MAX_HASH_LEN` buffer.
fn finish_hash<H: EcdsaHash>(hash: H) -> [u8; MAX_HASH_LEN] {
    let mut h = [0u8; MAX_HASH_LEN];
    hash.do_final_out(&mut h[..H::OUTPUT_LEN]);
    h
}

/// FIPS 186-5 Section 6.4.2 on the finished message hash: step 1's range check, then steps 3-9
/// (step 2 is the hashing the caller has done). Both signer types' `do_verify_final` are this
/// one function, since how `k` was generated does not enter verification.
fn verify_final<C: Curve, H: EcdsaHash>(
    hash: H,
    pk: &ECDSAPublicKey<C, H>,
    sig: &[u8],
) -> Result<(), SignatureError> {
    // Exactly SIG_LEN, not "at least": the raw encoding is two fixed-width integers and nothing
    // else, so trailing bytes make this a different, malformed encoding rather than a valid
    // signature in a roomy buffer. Accepting them would let anyone turn one valid signature into
    // unlimited distinct byte strings that all verify, malleability that breaks any caller
    // treating the signature as an opaque, comparable blob.
    if sig.len() != C::SIG_LEN {
        return Err(SignatureError::LengthError(
            "an ECDSA signature is exactly twice the curve's scalar length",
        ));
    }
    let half = C::SCALAR_LEN;
    let mut r_bytes = C::ScalarBytes::ZEROED;
    r_bytes.as_mut().copy_from_slice(&sig[..half]);
    let mut s_bytes = C::ScalarBytes::ZEROED;
    s_bytes.as_mut().copy_from_slice(&sig[half..]);

    // step 1: r, s in [1, n-1], rejected (not reduced) if out of range.
    let r_limbs = C::limbs_from_be_bytes(&r_bytes);
    let s_limbs = C::limbs_from_be_bytes(&s_bytes);
    if !(C::scalar_in_range(&r_limbs) & C::scalar_in_range(&s_limbs)).to_bool() {
        return Err(SignatureError::SignatureVerificationFailed);
    }
    let r = C::ScalarField::from_limbs(r_limbs);

    let h = finish_hash(hash);
    let e = e_from_hash::<C, H>(&h[..H::OUTPUT_LEN]); // steps 2-3

    // `s` is part of the signature, so its inverse is taken in variable time on the public
    // scalar type; the constant-time `invert` is for the signer's `k`.
    let s_inv = C::PublicScalar::from_limbs(s_limbs).invert_vartime(); // step 4
    let u = e.mul(&s_inv); // step 5
    let v = r.mul(&s_inv);

    let q = C::Point::from_affine(pk.x, pk.y);
    let u_pub = C::PublicScalar::from_limbs(u.to_limbs());
    let v_pub = C::PublicScalar::from_limbs(v.to_limbs());
    let r1_point = C::shamir_multiply(&u_pub, &v_pub, &q); // step 6

    if r1_point.is_infinity().to_bool() {
        return Err(SignatureError::SignatureVerificationFailed);
    }
    let (x_r1, _) =
        r1_point.to_affine().expect("just checked r1_point is not the point at infinity");
    let r1 = C::ScalarField::from_limbs(x_r1.to_limbs()); // steps 7-8

    if r1 == r { Ok(()) } else { Err(SignatureError::SignatureVerificationFailed) } // step 9
}

impl<C, H: EcdsaHash, const SIG_LEN: usize> SigningKey<ECDSA<C, H>, SIG_LEN>
    for ECDSAPrivateKey<C, H>
where
    C: Curve<Signature = [u8; SIG_LEN]>,
{
    type Signer<'k>
        = ECDSASigner<'k, C, H>
    where
        Self: 'k;

    fn create_signer<'k>(
        &'k self,
        rng: &mut dyn RNG,
        _ctx: Option<&[u8]>,
    ) -> Result<Self::Signer<'k>, SignatureError> {
        const { check_hash_fits::<C, H>() };
        Ok(ECDSASigner { sk: self, hash: H::default(), k: random_k::<C>(rng)? })
    }
}

impl<C, H: EcdsaHash, const SIG_LEN: usize> DeterministicSigningKey<ECDSA<C, H>, SIG_LEN>
    for ECDSAPrivateKey<C, H>
where
    C: Curve<Signature = [u8; SIG_LEN]>,
{
    type Signer<'k>
        = ECDetDSASigner<'k, C, H>
    where
        Self: 'k;

    fn create_signer_deterministic<'k>(
        &'k self,
        _ctx: Option<&[u8]>,
    ) -> Result<Self::Signer<'k>, SignatureError> {
        const { check_hash_fits::<C, H>() };
        Ok(ECDetDSASigner { sk: self, hash: H::default() })
    }
}

impl<C, H: EcdsaHash, const SIG_LEN: usize> VerifyingKey<ECDSA<C, H>, SIG_LEN>
    for ECDSAPublicKey<C, H>
where
    C: Curve<Signature = [u8; SIG_LEN]>,
{
    type Verifier<'k>
        = ECDSAVerifier<'k, C, H>
    where
        Self: 'k;

    fn create_verifier<'k>(
        &'k self,
        _ctx: Option<&[u8]>,
    ) -> Result<Self::Verifier<'k>, SignatureError> {
        const { check_hash_fits::<C, H>() };
        Ok(ECDSAVerifier { pk: self, hash: H::default() })
    }
}

impl<C: Curve, H: EcdsaHash> AlgorithmInfo for ECDSASigner<'_, C, H> {
    fn alg_name(&self) -> &'static str {
        ECDSA::<C, H>::ALG_NAME
    }

    fn max_security_strength(&self) -> SecurityStrength {
        ECDSA::<C, H>::MAX_SECURITY_STRENGTH
    }
}

impl<C, H: EcdsaHash, const SIG_LEN: usize> SignatureSigner<SIG_LEN> for ECDSASigner<'_, C, H>
where
    C: Curve<Signature = [u8; SIG_LEN]>,
{
    fn do_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn do_final(self) -> Result<[u8; SIG_LEN], SignatureError> {
        let h = finish_hash(self.hash);
        // FIPS 186-5 Section 6.4.1 step 11: with a random `k`, `r = 0` or `s = 0` goes back to
        // step 3. `k` was drawn when this signer was created and there is no RNG here to draw
        // another from, so the failure is reported instead; it has probability about 2^-(len(n)-1).
        sign_with_k::<C, H>(self.sk, &e_from_hash::<C, H>(&h[..H::OUTPUT_LEN]), self.k).ok_or(
            SignatureError::GenericError(
                "ECDSA produced r = 0 or s = 0; create a fresh signer and sign again",
            ),
        )
    }

    fn do_final_out(self, output: &mut [u8; SIG_LEN]) -> Result<usize, SignatureError> {
        output.fill(0);
        *output = self.do_final()?;
        Ok(SIG_LEN)
    }
}

impl<C: Curve, H: EcdsaHash> AlgorithmInfo for ECDetDSASigner<'_, C, H> {
    fn alg_name(&self) -> &'static str {
        ECDSA::<C, H>::DETERMINISTIC_ALG_NAME
    }

    fn max_security_strength(&self) -> SecurityStrength {
        ECDSA::<C, H>::MAX_SECURITY_STRENGTH
    }
}

impl<C, H: EcdsaHash, const SIG_LEN: usize> SignatureSigner<SIG_LEN> for ECDetDSASigner<'_, C, H>
where
    C: Curve<Signature = [u8; SIG_LEN]>,
{
    fn do_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn do_final(self) -> Result<[u8; SIG_LEN], SignatureError> {
        let h = finish_hash(self.hash);
        let h = &h[..H::OUTPUT_LEN];
        let k = rfc6979::generate_k::<C, H>(self.sk.scalar(), h); // step 3, Appendix A.3.3
        // FIPS 186-5 Section 6.4.1 step 11: with a deterministic `k`, `r = 0` or `s = 0` outputs
        // failure.
        sign_with_k::<C, H>(self.sk, &e_from_hash::<C, H>(h), k).ok_or(SignatureError::GenericError(
            "deterministic ECDSA produced r = 0 or s = 0; FIPS 186-5 Section 6.4.1 step 11: output failure",
        ))
    }

    fn do_final_out(self, output: &mut [u8; SIG_LEN]) -> Result<usize, SignatureError> {
        output.fill(0);
        *output = self.do_final()?;
        Ok(SIG_LEN)
    }
}

impl<C: Curve, H: EcdsaHash> AlgorithmInfo for ECDSAVerifier<'_, C, H> {
    fn alg_name(&self) -> &'static str {
        ECDSA::<C, H>::ALG_NAME
    }

    fn max_security_strength(&self) -> SecurityStrength {
        ECDSA::<C, H>::MAX_SECURITY_STRENGTH
    }
}

impl<C: Curve, H: EcdsaHash> SignatureVerifier for ECDSAVerifier<'_, C, H> {
    fn do_update(&mut self, msg_chunk: &[u8]) {
        self.hash.do_update(msg_chunk);
    }

    fn do_verify_final(self, sig: &[u8]) -> Result<(), SignatureError> {
        verify_final::<C, H>(self.hash, self.pk, sig)
    }
}

// `r_or_s_is_zero` is private and, through `sign_with_k`, only ever reached with an `r`/`s` value
// that is astronomically unlikely for any real input (see its own doc comment), so no realistic
// integration test exercises either disjunct -- the QUALITY_AND_STYLE.md private-function
// exception applies. `hash_to_limbs`'s truncation and extension are reached by the vector suites
// (P-256 under SHA-512, P-521 under SHA-512), so they are not pinned here.
#[cfg(test)]
mod tests {
    use super::*;

    type F = <P256 as Curve>::ScalarField;

    #[test]
    fn r_or_s_is_zero_requires_only_one_to_be_zero() {
        let zero = F::ZERO;
        let one = F::ONE;
        assert!(!r_or_s_is_zero::<P256>(&one, &one));
        assert!(r_or_s_is_zero::<P256>(&zero, &one));
        assert!(r_or_s_is_zero::<P256>(&one, &zero));
        assert!(r_or_s_is_zero::<P256>(&zero, &zero));
    }
}
