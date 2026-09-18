//! Known-answer tests for [`reduce_wide_bits_mod_n_minus_1`] (FIPS 186-5 Appendix A.4.1 steps
//! 3-5): `x = bits2int(X)`, `x = x mod (n-1)`, `x = x + 1`. Expected values computed independently
//! in Python via `(int.from_bytes(bytes, 'big') % (n - 1)) + 1` with `n` from SP 800-186
//! §3.2.1.4, not derived from this crate's own reduction code -- see `extra_bits_tests.rs`'s docs
//! for why this independent-reference pinning matters. Inputs are the 56 bytes (448 bits)
//! `keys_p384` and `ecdsa_p384` actually draw, except where a shorter input is the point.

use bouncycastle_ec::p384_scalar::N_LIMBS;
use bouncycastle_ec::p384_sec1::be_bytes_from_limbs;
use bouncycastle_ecdsa::extra_bits_p384::reduce_wide_bits_mod_n_minus_1;
use bouncycastle_hex::decode as hex_decode;

fn bytes48(hex: &str) -> [u8; 48] {
    hex_decode(hex).unwrap().try_into().unwrap()
}

#[test]
fn known_answer_repeating_pattern() {
    let input: Vec<u8> = [0x01u8, 0x02, 0x03, 0x04].iter().cloned().cycle().take(56).collect();
    let expected = bytes48(
        "01020304010203040102030401020304013b119a9ccd3619eb1707bbd346539086279eb3ecc7299aa3ee0276b98d073d",
    );
    assert_eq!(reduce_wide_bits_mod_n_minus_1(&input).to_be_bytes(), expected);
}

#[test]
fn known_answer_all_ff() {
    let input = [0xffu8; 56];
    let expected = bytes48(
        "00000000000000000000000000000000389cb27e0bc8d220a7e5f24db74f58851313e695333ad68e0000000000000000",
    );
    assert_eq!(reduce_wide_bits_mod_n_minus_1(&input).to_be_bytes(), expected);
}

#[test]
fn known_answer_all_zero_yields_one() {
    // bits2int(0) = 0; 0 mod (n-1) = 0; +1 = 1 -- the smallest value Appendix A.4.1 can produce.
    let input = [0u8; 56];
    let mut expected = [0u8; 48];
    expected[47] = 1;
    assert_eq!(reduce_wide_bits_mod_n_minus_1(&input).to_be_bytes(), expected);
}

/// An `n`-width input below `n - 1` is its own residue, so the result is `x + 1`: the case the
/// single-subtraction reduction this module replaced was built for, kept as a check that the
/// wide reduction agrees with it on its home ground. `x` is pseudorandom, from Python.
#[test]
fn known_answer_n_width_input_below_n_minus_1() {
    let x = bytes48(
        "0c479ba61fe9eb497e4ef8d29646bba8128fd0fd853321fe2e841ff3542270c0a4afd95a574e5cebe7531273ac31909b",
    );
    let mut x_plus_1 = x;
    x_plus_1[47] += 1;
    assert_eq!(reduce_wide_bits_mod_n_minus_1(&x).to_be_bytes(), x_plus_1);
}

/// The boundaries of Appendix A.4.1's own arithmetic: `n - 1` is the modulus of step 4, so it
/// reduces to `0` and step 5 makes it `1`; `n - 2` is the largest residue, so it comes out as
/// `n - 1`, the top of the output interval; and `n` itself is `1 mod (n-1)`, so `2`.
#[test]
fn known_answer_at_the_n_minus_1_boundary() {
    let n = be_bytes_from_limbs(&N_LIMBS);
    let mut n_minus_1 = n;
    n_minus_1[47] -= 1; // n is odd, so neither subtraction borrows
    let mut n_minus_2 = n;
    n_minus_2[47] -= 2;

    let mut one = [0u8; 48];
    one[47] = 1;
    let mut two = [0u8; 48];
    two[47] = 2;

    let mut input = [0u8; 56];
    input[8..].copy_from_slice(&n_minus_1);
    assert_eq!(reduce_wide_bits_mod_n_minus_1(&input).to_be_bytes(), one, "n - 1 -> 1");
    input[8..].copy_from_slice(&n_minus_2);
    assert_eq!(reduce_wide_bits_mod_n_minus_1(&input).to_be_bytes(), n_minus_1, "n - 2 -> n - 1");
    input[8..].copy_from_slice(&n);
    assert_eq!(reduce_wide_bits_mod_n_minus_1(&input).to_be_bytes(), two, "n -> 2");
}
