//! Known-answer tests for [`reduce_wide_bits_mod_n_minus_1`] (FIPS 186-5 Appendix A.4.1 steps
//! 3-5): `x = bits2int(X)`, `x = x mod (n-1)`, `x = x + 1`. Expected values computed independently
//! in Python via `(int.from_bytes(bytes, 'big') % (n - 1)) + 1` with `n` from RFC 5639 §3.4, not
//! derived from this crate's own reduction code -- see `extra_bits_bp256r1_tests.rs`'s docs for why
//! this independent-reference pinning matters (a real test gap `cargo mutants` found on that
//! curve's analogous constant and reduction).

use bouncycastle_ecdsa::extra_bits_bp384r1::reduce_wide_bits_mod_n_minus_1;
use bouncycastle_hex::decode as hex_decode;

fn bytes48(hex: &str) -> [u8; 48] {
    hex_decode(hex).unwrap().try_into().unwrap()
}

#[test]
fn known_answer_repeating_pattern() {
    let input: Vec<u8> = [0x01u8, 0x02, 0x03, 0x04].iter().cloned().cycle().take(56).collect();
    let expected = bytes48(
        "601f5e94713f3101088d9b91ddd7101eef885d40f508b354b55c1848db5b1a0b408636d749e783b059eda819efd1cd29",
    );
    assert_eq!(reduce_wide_bits_mod_n_minus_1(&input).to_be_bytes(), expected);
}

#[test]
fn known_answer_all_ff() {
    let input = [0xffu8; 56];
    let expected = bytes48(
        "8c411bc9d770ff441c959a14f5397a62dbddfd1e9e782eab85d0816fe833a4b180553a48c19d96aa7284dfef4cf3c820",
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

/// The two boundaries of Appendix A.4.1's own arithmetic: `n - 1` is the modulus of step 4, so it
/// reduces to `0` and step 5 makes it `1`; `n - 2` is the largest residue, so it comes out as
/// `n - 1`, the top of the `[1, n-1]` output interval. Both inputs are left-padded to the DRBG
/// output width this module is fed with.
#[test]
fn known_answer_at_the_n_minus_1_boundary() {
    let n = bouncycastle_ec::bp384r1_sec1::be_bytes_from_limbs(
        &bouncycastle_ec::bp384r1_scalar::N_LIMBS,
    );
    let mut n_minus_1 = n;
    n_minus_1[47] -= 1; // n is odd, so neither of these subtractions borrows
    let mut n_minus_2 = n;
    n_minus_2[47] -= 2;

    let mut input = [0u8; 56];
    input[8..].copy_from_slice(&n_minus_1);
    let mut one = [0u8; 48];
    one[47] = 1;
    assert_eq!(reduce_wide_bits_mod_n_minus_1(&input).to_be_bytes(), one, "n - 1 -> 1");

    input[8..].copy_from_slice(&n_minus_2);
    assert_eq!(reduce_wide_bits_mod_n_minus_1(&input).to_be_bytes(), n_minus_1, "n - 2 -> n - 1");
}
