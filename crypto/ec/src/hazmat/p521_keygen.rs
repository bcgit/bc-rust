//! Key pair generation over P-521: a private scalar in `[1, n-1]` by the extra random bits
//! method and its public point `[d]G`, for the signature and the key agreement crates alike,
//! each of which wraps the pair in its own key types (one pair does not serve both purposes:
//! SP 800-56A Rev. 3 Section 5.6.3.2 item 5). FIPS 186-5 Appendix A.2.1 and SP 800-56A Rev. 3
//! Section 5.6.1.2.1 are one computation: an RBG of the curve's strength, `N + t` bits of its
//! output with `t >= 64`, `d = (c mod (n - 1)) + 1` through
//! [`reduce_wide_bits_mod_n_minus_1`], and `Q = [d]G`.

use crate::hazmat::p521::P521FieldElement;
use crate::hazmat::p521_comb::comb_multiply_base_point;
use crate::hazmat::p521_extra_bits::reduce_wide_bits_mod_n_minus_1;
use crate::hazmat::p521_scalar::P521Scalar;
use bouncycastle_core::errors::RNGError;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::RNG;
use bouncycastle_utils::secret::Secret;

/// The strength the RNG must offer, SP 800-57 Part 1 Rev. 5 Table 2's 256 bits for this curve's
/// order (FIPS 186-5 Appendix A.2.1 step 3; SP 800-56A Rev. 3 Section 5.6.1.2.1 step 4).
pub const RNG_STRENGTH: SecurityStrength = SecurityStrength::_256bit;

/// The most DRBG output [`keygen`] takes, the reduction's bound. The caller fixes `DRBG_LEN` at
/// or above the `N + 64` bits both specifications require (FIPS 186-5 Table A.2's recommended
/// length for a signature key, `N + 64` for key agreement) and at or below this.
pub const MAX_DRBG_OUTPUT_LEN: usize = 80;

/// A key pair: `d` in `[1, n-1]` from `DRBG_LEN` bytes of `rng`'s output, and `Q = [d]G` in
/// affine form. `d` is held in a `Secret` throughout and the DRBG output is scrubbed when this
/// function returns; the returned pair is moved out, which does not wipe where it was built.
///
/// # Errors
/// [`RNGError::SecurityStrengthInsufficientForAlgorithm`] if the RNG is weaker than
/// [`RNG_STRENGTH`], or the RNG's own error if it fails to deliver.
pub fn keygen<const DRBG_LEN: usize>(
    rng: &mut dyn RNG,
) -> Result<(P521Scalar, (P521FieldElement, P521FieldElement)), RNGError> {
    const {
        assert!(
            DRBG_LEN <= MAX_DRBG_OUTPUT_LEN,
            "the DRBG output must fit the extra-bits reduction"
        )
    };
    if rng.security_strength() < RNG_STRENGTH {
        return Err(RNGError::SecurityStrengthInsufficientForAlgorithm);
    }
    let mut extra_bits = Secret::<[u8; DRBG_LEN]>::new();
    rng.next_bytes_out(&mut *extra_bits)?;
    let d = reduce_wide_bits_mod_n_minus_1(&*extra_bits);
    let q = public_point(&d);
    Ok((d, q))
}

/// `[d]G` in affine form for a `d` in `[1, n-1]`: the public key of a private scalar. `d` is in
/// range by construction wherever a scalar comes from, and `G` has prime order `n` (the cofactor
/// is 1), so `[d]G` is never the identity; that holds for every valid `d`, so the branch on it
/// leaks nothing about `d`.
pub fn public_point(d: &P521Scalar) -> (P521FieldElement, P521FieldElement) {
    let mut q = comb_multiply_base_point(d);
    let affine = q.to_affine().expect("[d]G is never infinity for d in [1, n-1]");
    // Only the affine pair is public; the projective coordinates are a function of `d`'s bits.
    q.zeroize();
    affine
}
