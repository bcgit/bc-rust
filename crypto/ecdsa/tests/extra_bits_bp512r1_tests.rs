//! Known-answer tests for [`reduce_wide_bits_mod_n_minus_1`] (FIPS 186-5 Appendix A.4.1 steps
//! 3-5): `x = bits2int(X)`, `x = x mod (n-1)`, `x = x + 1`. Expected values computed independently
//! in Python via `(int.from_bytes(bytes, 'big') % (n - 1)) + 1` with `n` from RFC 5639 §3.4, not
//! derived from this crate's own reduction code -- see `extra_bits_bp256r1_tests.rs`'s docs for why
//! this independent-reference pinning matters (a real test gap `cargo mutants` found on that
//! curve's analogous constant and reduction).

use bouncycastle_ecdsa::extra_bits_bp512r1::reduce_wide_bits_mod_n_minus_1;
use bouncycastle_hex::decode as hex_decode;

fn bytes64(hex: &str) -> [u8; 64] {
    hex_decode(hex).unwrap().try_into().unwrap()
}

#[test]
fn known_answer_repeating_pattern() {
    let input: Vec<u8> = [0x01u8, 0x02, 0x03, 0x04].iter().cloned().cycle().take(72).collect();
    let expected = bytes64(
        "2cba3745dd71ed5c4cc168f9f67d3c7e18f888d946d40f4564a04fd7bfc177c94c477653df36f73070d93ffa1bab888928286601549d218f6b6de368e4089705",
    );
    assert_eq!(reduce_wide_bits_mod_n_minus_1(&input).to_be_bytes(), expected);
}

#[test]
fn known_answer_all_ff() {
    let input = [0xffu8; 72];
    let expected = bytes64(
        "0e92f4a257e37a20a2fb93f3a339141b36cf5e509308f63b090de57b2a66d2e19da0600d96652b67b2e40e271d3a86916d3d726abda6c95cef9691d720f64ff0",
    );
    assert_eq!(reduce_wide_bits_mod_n_minus_1(&input).to_be_bytes(), expected);
}

#[test]
fn known_answer_all_zero_yields_one() {
    // bits2int(0) = 0; 0 mod (n-1) = 0; +1 = 1 -- the smallest value Appendix A.4.1 can produce.
    let input = [0u8; 72];
    let mut expected = [0u8; 64];
    expected[63] = 1;
    assert_eq!(reduce_wide_bits_mod_n_minus_1(&input).to_be_bytes(), expected);
}
