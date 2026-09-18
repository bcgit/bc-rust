//! Known-answer tests for [`reduce_wide_bits_mod_n_minus_1`] (FIPS 186-5 Appendix A.4.1 steps
//! 3-5): `x = bits2int(X)`, `x = x mod (n-1)`, `x = x + 1`. Expected values computed independently
//! in Python via `(int.from_bytes(bytes, 'big') % (n - 1)) + 1` with `n` from SP 800-186 §3.2.1.3,
//! not derived from this crate's own reduction code -- existing round-trip tests elsewhere
//! (`keygen`/`sign_randomized`) only ever check that the reduced value is self-consistent with
//! itself, which can't distinguish a correct reduction from a systematically wrong one (this is
//! exactly what a `cargo mutants` run on `reduce_wide_bits_mod_n_minus_1`'s bit-extraction and
//! carry-correction surfaced: several bit-level mutants survived because nothing here pinned the
//! function against an independent reference).

use bouncycastle_ecdsa::extra_bits::reduce_wide_bits_mod_n_minus_1;
use bouncycastle_hex::decode as hex_decode;

fn bytes32(hex: &str) -> [u8; 32] {
    hex_decode(hex).unwrap().try_into().unwrap()
}

#[test]
fn known_answer_repeating_pattern() {
    let input: Vec<u8> = [0x01u8, 0x02, 0x03, 0x04].iter().cloned().cycle().take(44).collect();
    let expected = bytes32("01020303ff419cfdb5fae98dc534e5e6caac2bc95762898fec3558aa95c8f885");
    assert_eq!(reduce_wide_bits_mod_n_minus_1(&input).to_be_bytes(), expected);
}

#[test]
fn known_answer_all_ff() {
    let input = [0xffu8; 44];
    let expected = bytes32("fffffffe431905549c0166cd652e96b789b1054851cc17b9e7739585f8c64aa0");
    assert_eq!(reduce_wide_bits_mod_n_minus_1(&input).to_be_bytes(), expected);
}

#[test]
fn known_answer_all_zero_yields_one() {
    // bits2int(0) = 0; 0 mod (n-1) = 0; +1 = 1 -- the smallest value Appendix A.4.1 can produce.
    let input = [0u8; 44];
    let mut expected = [0u8; 32];
    expected[31] = 1;
    assert_eq!(reduce_wide_bits_mod_n_minus_1(&input).to_be_bytes(), expected);
}

/// The two boundaries of Appendix A.4.1's own arithmetic: `n - 1` is the modulus of step 4, so it
/// reduces to `0` and step 5 makes it `1`; `n - 2` is the largest residue, so it comes out as
/// `n - 1`, the top of the `[1, n-1]` output interval. Both inputs are left-padded to the DRBG
/// output width this module is fed with.
#[test]
fn known_answer_at_the_n_minus_1_boundary() {
    let n = bouncycastle_ec::p256_sec1::be_bytes_from_limbs(&bouncycastle_ec::p256_scalar::N_LIMBS);
    let mut n_minus_1 = n;
    n_minus_1[31] -= 1; // n is odd, so neither of these subtractions borrows
    let mut n_minus_2 = n;
    n_minus_2[31] -= 2;

    let mut input = [0u8; 44];
    input[12..].copy_from_slice(&n_minus_1);
    let mut one = [0u8; 32];
    one[31] = 1;
    assert_eq!(reduce_wide_bits_mod_n_minus_1(&input).to_be_bytes(), one, "n - 1 -> 1");

    input[12..].copy_from_slice(&n_minus_2);
    assert_eq!(reduce_wide_bits_mod_n_minus_1(&input).to_be_bytes(), n_minus_1, "n - 2 -> n - 1");
}
