//! FIPS 186-5 Appendix A.4.1, "Conversion of a Bit String to an Integer mod n via Modular
//! Reduction" -- the "extra random bits" method both [`crate::keys`]'s key generation (Appendix
//! A.2.1) and [`crate::ecdsa_p256`]'s randomised per-message secret (Appendix A.3.1) use to turn a
//! DRBG output wider than `n` into a value in `[1, n-1]` with negligible bias.
//!
//! # The algorithm, and why it needs its own reduction
//!
//! Appendix A.4.1's process, for a bit string `X` of length `l` and modulus `n`:
//! 1. `x = bits2int(X)` (§B.2.1, big-endian).
//! 2. `x = x mod (n-1)`.
//! 3. `x = x + 1`.
//!
//! `X` here is 352 bits (44 bytes -- FIPS 186-5 Table A.2's "Recommended" output length for a
//! DRBG feeding a P-256 private key or per-message secret, `l = N + t` with `N = 256` and `t = 96
//! >= 64`), 96 bits wider than the 4-limb (256-bit) width every other value in this workspace's
//! P-256 arithmetic is sized for. `bouncycastle_ec::p256_scalar` reduces mod `n`, not `n-1`, and
//! has no width wider than 4 limbs, so step 2's reduction is implemented here directly, from
//! scratch, rather than reused.
//!
//! # Constant time
//!
//! `X` is DRBG output destined to become a secret `d` or `k` once step 3 adds `1`, so this is
//! exactly the kind of "value derived from a private scalar" this workspace's constant-time rules
//! (see `bouncycastle_ec`'s crate docs) forbid branching on. [`reduce_wide_bits_mod_n_minus_1`]
//! is [`bouncycastle_ec::barrett`]'s constant-time Barrett reduction with `m = n - 1`: two
//! fixed-width multiplications and three masked conditional subtractions, none of which branches
//! or indexes on `X`. (An earlier version reduced `X` one bit at a time with a doubling and a
//! masked subtraction per bit; correct, but 352 rounds of it cost more than a field inversion on
//! every key generation and randomised signature.)
//!
//! `extra_bits_tests.rs` pins known answers computed in Python and cross-checks the reduction
//! against that bit-serial algorithm, kept there as an independent reference, over pseudorandom
//! inputs of every width up to the maximum.

use bouncycastle_ec::barrett;
use bouncycastle_ec::nat;
use bouncycastle_ec::p256_scalar::{N_LIMBS, P256Scalar};

/// `n - 1`, little-endian `u64` limbs. `N_LIMBS[0]` is odd (SP 800-186 §3.2.1.3's `n`), so the
/// subtraction never borrows out of the low limb.
const N_MINUS_1_LIMBS: [u64; 4] = [N_LIMBS[0] - 1, N_LIMBS[1], N_LIMBS[2], N_LIMBS[3]];

/// `floor(2^512 / (n-1)) - 2^256`: the low limbs of Barrett's `mu` for `m = n - 1` (whose top
/// limb is `mu`'s only other bit -- see [`bouncycastle_ec::barrett`]), computed in Python from
/// SP 800-186 §3.2.1.3's `n`.
const MU_LOW_LIMBS: [u64; 4] =
    [0x012ffd85eedf9bff, 0x43190552df1a6c21, 0xfffffffeffffffff, 0x00000000ffffffff];

/// FIPS 186-5 Appendix A.4.1 steps 3-5 for `n` = the curve order: reduces the big-endian bit string
/// `bytes` modulo `n-1` and adds `1`, landing in `[1, n-1]`. `bytes` may be up to `63` bytes
/// -- `2^504 < (n-1) * 2^256`, Barrett's precondition -- which covers the 44-byte DRBG
/// output this crate draws with room to spare; a longer input is a programming error and panics.
pub fn reduce_wide_bits_mod_n_minus_1(bytes: &[u8]) -> P256Scalar {
    assert!(
        bytes.len() < 64,
        "reduce_wide_bits_mod_n_minus_1 given {} bytes, more than 63",
        bytes.len()
    );
    let t = barrett::limbs_from_be_bytes::<8>(bytes);
    let reduced = barrett::reduce::<4, 8, 5>(&t, &N_MINUS_1_LIMBS, &MU_LOW_LIMBS);
    let (plus_one, _) = nat::add(&reduced, &[1, 0, 0, 0]);
    P256Scalar::from_limbs(plus_one)
}
