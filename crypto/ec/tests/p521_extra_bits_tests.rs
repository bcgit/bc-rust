//! Known-answer tests for [`reduce_wide_bits_mod_n_minus_1`] (FIPS 186-5 Appendix A.4.1 steps
//! 3-5) over P-521's `n`. Expected values computed independently in Python via
//! `(int.from_bytes(bytes, 'big') % (n - 1)) + 1` with `n` from SP 800-186 §3.2.1.5, not from this
//! crate's own reduction code; this is exactly what would have caught the wide-reduction bug the
//! module's docs describe, had it existed from the start.

use bouncycastle_ec::nat;
use bouncycastle_ec::p521_extra_bits::reduce_wide_bits_mod_n_minus_1;
use bouncycastle_ec::p521_scalar::{N_LIMBS, P521Scalar};
use bouncycastle_ec::p521_sec1;

/// The width `bouncycastle-ecdsa` draws for P-521: `ceil((521 + 64) / 8)`.
const DRBG_OUTPUT_LEN: usize = 74;
/// SEC 1 octet width of a P-521 scalar.
const N_LEN: usize = 66;

/// `n - 1`, little-endian limbs.
fn n_minus_1_limbs() -> [u64; 9] {
    let (limbs, borrow) = nat::sub(&N_LIMBS, &[1, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(borrow, 0);
    limbs
}

#[test]
fn known_answer_all_ff_at_the_drbg_width() {
    // 74 bytes of 0xff: the width keygen and ECDSAP521 actually draw. Expected value is
    // Python's ((2^592 - 1) % (n - 1)) + 1.
    let input = [0xffu8; DRBG_OUTPUT_LEN];
    let expected: [u64; 9] = [
        0x0000000000000000, 0x482470b763cdfc00, 0x251b23bb31dc28a2, 0x19ff5b847b2d17e2,
        0x3cbc3e206834ca40, 0x00000000000002d7, 0x0000000000000000, 0x0000000000000000,
        0x0000000000000000,
    ];
    assert_eq!(reduce_wide_bits_mod_n_minus_1(&input), P521Scalar::from_limbs(expected));
}

#[test]
fn known_answer_all_ff() {
    let input = [0xffu8; N_LEN];
    let expected: [u64; 9] = [
        0x482470b763cdfc00, 0x251b23bb31dc28a2, 0x19ff5b847b2d17e2, 0x3cbc3e206834ca40,
        0x00000000000002d7, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
        0x0000000000000000,
    ];
    assert_eq!(reduce_wide_bits_mod_n_minus_1(&input), P521Scalar::from_limbs(expected));
}

#[test]
fn known_answer_repeating_pattern() {
    let mut input = [0u8; N_LEN];
    for (i, b) in input.iter_mut().enumerate().take(64) {
        *b = [0x01, 0x02, 0x03, 0x04][i % 4];
    }
    input[64] = 0x05;
    input[65] = 0x06;
    let expected: [u64; 9] = [
        0x0304010203040507, 0x0304010203040102, 0x0304010203040102, 0x0304010203040102,
        0x0304010203040102, 0x0304010203040102, 0x0304010203040102, 0x0304010203040102,
        0x0000000000000102,
    ];
    assert_eq!(reduce_wide_bits_mod_n_minus_1(&input), P521Scalar::from_limbs(expected));
}

#[test]
fn known_answer_at_the_n_minus_1_boundary() {
    // n - 1 is the modulus of Appendix A.4.1 step 4 itself, so it reduces to 0 and step 5
    // makes it 1; n - 2 is the largest residue and comes out as n - 1, the top of the
    // output interval.
    let n_minus_1 = p521_sec1::be_bytes_from_limbs(&n_minus_1_limbs());
    let mut expected_one = [0u64; 9];
    expected_one[0] = 1;
    assert_eq!(reduce_wide_bits_mod_n_minus_1(&n_minus_1), P521Scalar::from_limbs(expected_one));

    let mut n_minus_2 = n_minus_1;
    n_minus_2[N_LEN - 1] -= 1; // n - 1 is even (n is prime), so this never borrows
    assert_eq!(
        reduce_wide_bits_mod_n_minus_1(&n_minus_2),
        P521Scalar::from_limbs(n_minus_1_limbs())
    );
}

#[test]
fn known_answer_all_zero_yields_one() {
    let input = [0u8; N_LEN];
    let mut expected = [0u64; 9];
    expected[0] = 1;
    assert_eq!(reduce_wide_bits_mod_n_minus_1(&input), P521Scalar::from_limbs(expected));
}
