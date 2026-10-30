//! Known-answer tests for [`reduce_wide_bits_mod_n_minus_1`] (FIPS 186-5 Appendix A.4.1 steps
//! 3-5): `x = bits2int(X)`, `x = x mod (n-1)`, `x = x + 1`. Expected values computed independently
//! in Python via `(int.from_bytes(bytes, 'big') % (n - 1)) + 1` with `n` from SEC 2 v2 §2.4.1,
//! not derived from this crate's own reduction code -- see `extra_bits_tests.rs`'s docs for why
//! this independent-reference pinning matters. Inputs are the 40 bytes (320 bits) `keys_p256k1`
//! and `ecdsa_p256k1` actually draw, except where a shorter input is the point.

use bouncycastle_ec::p256k1_scalar::N_LIMBS;
use bouncycastle_ec::p256k1_sec1::be_bytes_from_limbs;
use bouncycastle_ecdsa::extra_bits_p256k1::reduce_wide_bits_mod_n_minus_1;
use bouncycastle_hex::decode as hex_decode;

fn bytes32(hex: &str) -> [u8; 32] {
    hex_decode(hex).unwrap().try_into().unwrap()
}

#[test]
fn known_answer_repeating_pattern() {
    let input: Vec<u8> = [0x01u8, 0x02, 0x03, 0x04].iter().cloned().cycle().take(40).collect();
    let expected = bytes32("01020304010203040249e29e6a7b13c455f8adf82d7885809a9646b25ae53e05");
    assert_eq!(reduce_wide_bits_mod_n_minus_1(&input).to_be_bytes(), expected);
}

#[test]
fn known_answer_all_ff() {
    let input = [0xffu8; 40];
    let expected = bytes32("00000000000000014551231950b75fc4402da1732fc9bec00000000000000000");
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

/// An `n`-width input below `n - 1` is its own residue, so the result is `x + 1`: the case the
/// single-subtraction reduction this module replaced was built for, kept as a check that the
/// wide reduction agrees with it on its home ground. `x` is pseudorandom, from Python.
#[test]
fn known_answer_n_width_input_below_n_minus_1() {
    let x = bytes32("72d50095457ed5710b049ab71dbafb06b0525afa51a26b8a310022084564664a");
    let mut x_plus_1 = x;
    x_plus_1[31] += 1;
    assert_eq!(reduce_wide_bits_mod_n_minus_1(&x).to_be_bytes(), x_plus_1);
}

/// The boundaries of Appendix A.4.1's own arithmetic: `n - 1` is the modulus of step 4, so it
/// reduces to `0` and step 5 makes it `1`; `n - 2` is the largest residue, so it comes out as
/// `n - 1`, the top of the output interval; and `n` itself is `1 mod (n-1)`, so `2`.
#[test]
fn known_answer_at_the_n_minus_1_boundary() {
    let n = be_bytes_from_limbs(&N_LIMBS);
    let mut n_minus_1 = n;
    n_minus_1[31] -= 1; // n is odd, so neither subtraction borrows
    let mut n_minus_2 = n;
    n_minus_2[31] -= 2;

    let mut one = [0u8; 32];
    one[31] = 1;
    let mut two = [0u8; 32];
    two[31] = 2;

    let mut input = [0u8; 40];
    input[8..].copy_from_slice(&n_minus_1);
    assert_eq!(reduce_wide_bits_mod_n_minus_1(&input).to_be_bytes(), one, "n - 1 -> 1");
    input[8..].copy_from_slice(&n_minus_2);
    assert_eq!(reduce_wide_bits_mod_n_minus_1(&input).to_be_bytes(), n_minus_1, "n - 2 -> n - 1");
    input[8..].copy_from_slice(&n);
    assert_eq!(reduce_wide_bits_mod_n_minus_1(&input).to_be_bytes(), two, "n -> 2");
}

/// The bit-serial algorithm this module implemented before switching to Barrett reduction, kept
/// here as an independent reference: Horner's rule over the input bits, doubling the running
/// remainder and subtracting `n - 1` when it is exceeded, with the carry out of the top limb folded
/// back in as `2^256 mod (n-1) = 2^256 - (n-1)`. Slow, obviously correct, and sharing no
/// code with the Barrett path beyond `nat`'s add and sub.
fn reference_bit_serial(bytes: &[u8]) -> [u8; 32] {
    use bouncycastle_ec::nat;
    let n = bouncycastle_ec::p256k1_scalar::N_LIMBS;
    let mut m = n;
    m[0] -= 1; // n is odd
    let two_pow_mod_m = nat::sub(&[0u64; 4], &m).0; // 2^256 - m, wrapping
    let mut acc = [0u64; 4];
    for &byte in bytes {
        for bit_idx in (0..8).rev() {
            let (mut doubled, carry) = nat::add(&acc, &acc);
            doubled[0] |= ((byte >> bit_idx) & 1) as u64;
            if carry == 1 {
                doubled = nat::add(&doubled, &two_pow_mod_m).0;
            }
            let (reduced, borrow) = nat::sub(&doubled, &m);
            acc = if borrow == 1 { doubled } else { reduced };
        }
    }
    let plus_one = nat::add(&acc, &[1u64, 0, 0, 0]).0;
    bouncycastle_ec::p256k1_sec1::be_bytes_from_limbs(&plus_one)
}

/// xorshift64*, fixed seed, as in the `ec` crate's property tests.
struct Xorshift64(u64);

impl Xorshift64 {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

/// Barrett against the bit-serial reference over pseudorandom inputs at every width from one byte
/// up to the 63-byte maximum the function accepts, biased towards the widths actually drawn
/// (40 bytes) and towards values with long runs of set bits, where Barrett's quotient estimate is
/// furthest off and the most conditional subtractions are needed.
#[test]
fn agrees_with_the_bit_serial_reference_over_many_pseudorandom_inputs() {
    let mut rng = Xorshift64(0xBA77E770_0000_0004);
    for i in 0..3000 {
        let len = match i % 4 {
            0 => 40,
            1 => 63,
            _ => 1 + (rng.next_u64() as usize % 63),
        };
        let mut bytes = vec![0u8; len];
        for chunk in bytes.chunks_mut(8) {
            let word = rng.next_u64().to_be_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
        if i % 3 == 0 {
            for b in bytes.iter_mut().take(len / 2) {
                *b = 0xff;
            }
        }
        assert_eq!(
            reduce_wide_bits_mod_n_minus_1(&bytes).to_be_bytes(),
            reference_bit_serial(&bytes),
            "len = {len}, bytes = {bytes:02x?}"
        );
    }
}

#[test]
fn maximum_width_all_ones_input() {
    // 2^504 - 1, the largest input accepted: Barrett's precondition holds with room to spare.
    let bytes = [0xffu8; 63];
    assert_eq!(reduce_wide_bits_mod_n_minus_1(&bytes).to_be_bytes(), reference_bit_serial(&bytes));
}
