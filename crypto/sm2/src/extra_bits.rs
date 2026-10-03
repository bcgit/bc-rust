//! "Extra random bits" reduction: turns a DRBG output wider than `n` into a value in `[1, n-1]`
//! with negligible bias, the same technique `bouncycastle-ecdsa`'s `extra_bits` module uses for
//! P-256 (and every brainpool curve on this branch), applied here for the private key `dA` and the
//! per-message secret `k` `draft-shen-sm2-ecdsa-02` §5.1.3/§5.2.1 step A3 both need. The draft
//! itself only says "pick a random number ... via a random number generator" without specifying a
//! DRBG-to-scalar conversion, so this reuses FIPS 186-5 Appendix A.4.1's method (the same
//! bias-bound methodology this workspace already applies to every other curve) rather than a plain
//! modular reduction, which would be measurably biased for a `DRBG output length == n's bit
//! length` request.
//!
//! # Why SM2 needs this at all
//!
//! SM2's `n` sits about `2^225` below `2^256` -- the same distance P-256's `n` keeps from its
//! power of two (about `2^224`), and for the same reason not close enough: a 256-bit DRBG output
//! reduced mod `n - 1` would land in `[0, 2^256 - n)` about twice as often as anywhere else,
//! which is the bias FIPS 186-5's Table A.2 gives P-256 its 288/352-bit entries to dilute. (The
//! brainpool curves need the extra bits for a different reason -- their `n` is nowhere near a
//! power of two -- while P-384, P-521 and secp256k1 need none for bias, their `n` being within a
//! relative `2^-128` or closer of one, and draw them only because FIPS 186-5 Appendix A.3.1
//! requires `t >= 64` for a per-message secret.) FIPS 186-5 Appendix A.4.1 step 2's bias-bound check
//! (`2ρ(1-ρ)(n-1) > ε·N`, `ε = 2^-64`) was evaluated directly (in Python, against `n`'s actual
//! value from `draft-shen-sm2-ecdsa-02` Appendix D) for `N = 2^l` at increasing `l`: `l = 256`
//! (matching `n`'s own bit length) fails the check, and the smallest passing `l` is `319`; this
//! crate uses `l = 320` (40 bytes, byte-aligned) as `crate::keys::EXTRA_BITS_DRBG_OUTPUT_LEN`.
//!
//! The reduction itself is [`bouncycastle_ec::barrett`]'s constant-time Barrett reduction with
//! `m = n - 1` (see `bouncycastle_ecdsa`'s `extra_bits` docs for the constant-time argument); `extra_bits_tests.rs`
//! pins known answers computed in Python and cross-checks it against the bit-serial algorithm this
//! module used to implement, kept there as an independent reference.

use bouncycastle_ec::barrett;
use bouncycastle_ec::nat;
use bouncycastle_ec::sm2_scalar::{N_LIMBS, Sm2Scalar};

/// `n - 1`, little-endian `u64` limbs. `N_LIMBS[0]` is odd (`n` is prime), so the subtraction
/// never borrows out of the low limb.
const N_MINUS_1_LIMBS: [u64; 4] = [N_LIMBS[0] - 1, N_LIMBS[1], N_LIMBS[2], N_LIMBS[3]];

/// `floor(2^512 / (n-1)) - 2^256`: the low limbs of Barrett's `mu` for `m = n - 1` (whose top
/// limb is `mu`'s only other bit -- see [`bouncycastle_ec::barrett`]), computed in Python from
/// draft-shen-sm2-ecdsa-02 Appendix D's `n`.
const MU_LOW_LIMBS: [u64; 4] =
    [0x12ac6361f15149a1, 0x8dfc2096fa323c01, 0x0000000100000001, 0x0000000100000001];

/// FIPS 186-5 Appendix A.4.1 steps 3-5 for `n` = the curve order: reduces the big-endian bit string
/// `bytes` modulo `n-1` and adds `1`, landing in `[1, n-1]`. `bytes` may be up to `63` bytes
/// -- `2^504 < (n-1) * 2^256`, Barrett's precondition -- which covers the 40-byte DRBG
/// output this crate draws with room to spare; a longer input is a programming error and panics.
pub fn reduce_wide_bits_mod_n_minus_1(bytes: &[u8]) -> Sm2Scalar {
    assert!(
        bytes.len() < 64,
        "reduce_wide_bits_mod_n_minus_1 given {} bytes, more than 63",
        bytes.len()
    );
    let t = barrett::limbs_from_be_bytes::<8>(bytes);
    let reduced = barrett::reduce::<4, 8, 5>(&t, &N_MINUS_1_LIMBS, &MU_LOW_LIMBS);
    let (plus_one, _) = nat::add(&reduced, &[1, 0, 0, 0]);
    Sm2Scalar::from_limbs(plus_one)
}
