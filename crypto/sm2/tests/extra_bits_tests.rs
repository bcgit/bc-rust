//! Known-answer tests for [`reduce_wide_bits_mod_n_minus_1`] (FIPS 186-5 Appendix A.4.1 steps
//! 3-5): `x = bits2int(X)`, `x = x mod (n-1)`, `x = x + 1`. Expected values computed independently
//! in Python via `(int.from_bytes(bytes, 'big') % (n - 1)) + 1` with `n` from
//! `draft-shen-sm2-ecdsa-02` Appendix D, not derived from this crate's own reduction code --
//! existing round-trip tests elsewhere (`keygen`/`sign_randomized`) only ever check that the
//! reduced value is self-consistent with itself, which can't distinguish a correct reduction from
//! a systematically wrong one. Mirrors `bouncycastle-ecdsa`'s own `extra_bits_bp256r1_tests.rs`,
//! written for the identical reason there: a `cargo mutants` run on this function and its
//! `N_MINUS_1_LIMBS`/`TWO_POW_256_MOD_N_MINUS_1_LIMBS` constants surfaced several bit-level and
//! off-by-one mutants surviving because nothing pinned them against an independent reference.

use bouncycastle_hex::decode as hex_decode;
use bouncycastle_sm2::extra_bits::reduce_wide_bits_mod_n_minus_1;

fn bytes32(hex: &str) -> [u8; 32] {
    hex_decode(hex).unwrap().try_into().unwrap()
}

#[test]
fn known_answer_repeating_pattern() {
    let input: Vec<u8> = [0x01u8, 0x02, 0x03, 0x04].iter().cloned().cycle().take(40).collect();
    let expected = bytes32("0306090c0102030401911cc9047a6deaf6e477a96f45da1d0d752effea492df5");
    assert_eq!(reduce_wide_bits_mod_n_minus_1(&input).to_be_bytes(), expected);
}

#[test]
fn known_answer_all_ff() {
    let input = [0xffu8; 40];
    let expected = bytes32("00000001000000008dfc20956c361b6a187a276050a8c5a9726ecad4c62abede");
    assert_eq!(reduce_wide_bits_mod_n_minus_1(&input).to_be_bytes(), expected);
}

#[test]
fn known_answer_all_zero_yields_one() {
    // bits2int(0) = 0; 0 mod (n-1) = 0; +1 = 1 -- the smallest value Appendix A.4.1 can produce.
    let input = [0u8; 40];
    let mut expected = [0u8; 32];
    expected[31] = 1;
    assert_eq!(reduce_wide_bits_mod_n_minus_1(&input).to_be_bytes(), expected);
}
