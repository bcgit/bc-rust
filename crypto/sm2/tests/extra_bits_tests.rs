//! Known-answer tests for [`reduce_wide_bits_mod_n_minus_1`] (FIPS 186-5 Appendix A.4.1 steps
//! 3-5): `x = bits2int(X)`, `x = x mod (n-1)`, `x = x + 1`, and for
//! [`reduce_wide_bits_mod_n_minus_2`], the same steps with modulus `n - 2`. Expected values
//! computed independently in Python via `(int.from_bytes(bytes, 'big') % m) + 1` with `n` from
//! `draft-shen-sm2-ecdsa-02` Appendix D, not derived from this crate's own reduction code --
//! existing round-trip tests elsewhere (`keygen`/`sign_randomized`) only ever check that the
//! reduced value is self-consistent with itself, which can't distinguish a correct reduction from
//! a systematically wrong one. Mirrors `bouncycastle-ecdsa`'s own `extra_bits_bp256r1_tests.rs`,
//! written for the identical reason there: a `cargo mutants` run on this function and its
//! `N_MINUS_1_LIMBS`/`TWO_POW_256_MOD_N_MINUS_1_LIMBS` constants surfaced several bit-level and
//! off-by-one mutants surviving because nothing pinned them against an independent reference.

use bouncycastle_ec::nat;
use bouncycastle_ec::sm2_scalar::N_LIMBS;
use bouncycastle_ec::sm2_sec1::be_bytes_from_limbs;
use bouncycastle_hex::decode as hex_decode;
use bouncycastle_sm2::extra_bits::{
    reduce_wide_bits_mod_n_minus_1, reduce_wide_bits_mod_n_minus_2,
};

fn bytes32(hex: &str) -> [u8; 32] {
    hex_decode(hex).unwrap().try_into().unwrap()
}

/// `n - 1` and `n - 2` as limbs: `n` is odd and `N_LIMBS[0]` ends `0x23`, so neither borrows.
fn n_minus_1() -> [u64; 4] {
    [N_LIMBS[0] - 1, N_LIMBS[1], N_LIMBS[2], N_LIMBS[3]]
}

fn n_minus_2() -> [u64; 4] {
    [N_LIMBS[0] - 2, N_LIMBS[1], N_LIMBS[2], N_LIMBS[3]]
}

/// `value`, big-endian, left-padded to the 40-byte DRBG output width this module is fed with.
fn padded_to_40(value: &[u64; 4]) -> [u8; 40] {
    let mut input = [0u8; 40];
    input[8..].copy_from_slice(&be_bytes_from_limbs(value));
    input
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

/// The two boundaries of Appendix A.4.1's own arithmetic: `n - 1` is the modulus of step 4, so it
/// reduces to `0` and step 5 makes it `1`; `n - 2` is the largest residue, so it comes out as
/// `n - 1`, the top of the `[1, n-1]` output interval.
#[test]
fn known_answer_at_the_n_minus_1_boundary() {
    let mut one = [0u8; 32];
    one[31] = 1;
    let input = padded_to_40(&n_minus_1());
    assert_eq!(reduce_wide_bits_mod_n_minus_1(&input).to_be_bytes(), one, "n - 1 -> 1");

    let input = padded_to_40(&n_minus_2());
    let n_minus_1 = be_bytes_from_limbs(&n_minus_1());
    assert_eq!(reduce_wide_bits_mod_n_minus_1(&input).to_be_bytes(), n_minus_1, "n - 2 -> n - 1");
}

#[test]
fn known_answer_repeating_pattern_mod_n_minus_2() {
    let input: Vec<u8> = [0x01u8, 0x02, 0x03, 0x04].iter().cloned().cycle().take(40).collect();
    let expected = bytes32("0306090c0102030401911cc9047a6deaf6e477a96f45da1d0e773203ec4d33fd");
    assert_eq!(reduce_wide_bits_mod_n_minus_2(&input).to_be_bytes(), expected);
}

#[test]
fn known_answer_all_ff_mod_n_minus_2() {
    let input = [0xffu8; 40];
    let expected = bytes32("00000001000000008dfc20956c361b6a187a276050a8c5aa726ecad5c62abedf");
    assert_eq!(reduce_wide_bits_mod_n_minus_2(&input).to_be_bytes(), expected);
}

#[test]
fn known_answer_all_zero_yields_one_mod_n_minus_2() {
    let input = [0u8; 40];
    let mut expected = [0u8; 32];
    expected[31] = 1;
    assert_eq!(reduce_wide_bits_mod_n_minus_2(&input).to_be_bytes(), expected);
}

/// The same boundaries one lower: `n - 2` is the modulus, so it reduces to `0` and comes out `1`;
/// `n - 3` is the largest residue and comes out as `n - 2`, the top of the `[1, n-2]` output
/// interval; and `n - 1`, the value the `[1, n-1]` range used to admit as a private key, is `1`
/// above the modulus and comes out `2`.
#[test]
fn known_answer_at_the_n_minus_2_boundary() {
    let mut one = [0u8; 32];
    one[31] = 1;
    let mut two = [0u8; 32];
    two[31] = 2;
    let n_minus_3 = [N_LIMBS[0] - 3, N_LIMBS[1], N_LIMBS[2], N_LIMBS[3]];

    let input = padded_to_40(&n_minus_2());
    assert_eq!(reduce_wide_bits_mod_n_minus_2(&input).to_be_bytes(), one, "n - 2 -> 1");

    let input = padded_to_40(&n_minus_3);
    let n_minus_2 = be_bytes_from_limbs(&n_minus_2());
    assert_eq!(reduce_wide_bits_mod_n_minus_2(&input).to_be_bytes(), n_minus_2, "n - 3 -> n - 2");

    let input = padded_to_40(&n_minus_1());
    assert_eq!(reduce_wide_bits_mod_n_minus_2(&input).to_be_bytes(), two, "n - 1 -> 2");
}

/// The bit-serial algorithm this module implemented before switching to Barrett reduction, kept
/// here as an independent reference: Horner's rule over the input bits, doubling the running
/// remainder and subtracting the modulus `m` when it is exceeded, with the carry out of the top
/// limb folded back in as `2^256 mod m = 2^256 - m`. Slow, obviously correct, and sharing no code
/// with the Barrett path beyond `nat`'s add and sub.
fn reference_bit_serial(bytes: &[u8], m: &[u64; 4]) -> [u8; 32] {
    let two_pow_mod_m = nat::sub(&[0u64; 4], m).0; // 2^256 - m, wrapping
    let mut acc = [0u64; 4];
    for &byte in bytes {
        for bit_idx in (0..8).rev() {
            let (mut doubled, carry) = nat::add(&acc, &acc);
            doubled[0] |= ((byte >> bit_idx) & 1) as u64;
            if carry == 1 {
                doubled = nat::add(&doubled, &two_pow_mod_m).0;
            }
            let (reduced, borrow) = nat::sub(&doubled, m);
            acc = if borrow == 1 { doubled } else { reduced };
        }
    }
    let plus_one = nat::add(&acc, &[1u64, 0, 0, 0]).0;
    be_bytes_from_limbs(&plus_one)
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
/// up to the 63-byte maximum the functions accept, biased towards the widths actually drawn
/// (40 bytes) and towards values with long runs of set bits, where Barrett's quotient estimate is
/// furthest off and the most conditional subtractions are needed. Both moduli, on the same inputs.
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
            reference_bit_serial(&bytes, &n_minus_1()),
            "mod n - 1: len = {len}, bytes = {bytes:02x?}"
        );
        assert_eq!(
            reduce_wide_bits_mod_n_minus_2(&bytes).to_be_bytes(),
            reference_bit_serial(&bytes, &n_minus_2()),
            "mod n - 2: len = {len}, bytes = {bytes:02x?}"
        );
    }
}

/// `2^504 - 1`, the largest input accepted: Barrett's precondition holds with room to spare. The
/// `n - 2` answer is pinned from Python as well as against the reference.
#[test]
fn maximum_width_all_ones_input() {
    let bytes = [0xffu8; 63];
    assert_eq!(
        reduce_wide_bits_mod_n_minus_1(&bytes).to_be_bytes(),
        reference_bit_serial(&bytes, &n_minus_1())
    );
    let expected = bytes32("a21eb5e374a22b3d3d620fc84e3affe07e92c8346dee9756110ae2df3783fc97");
    assert_eq!(reduce_wide_bits_mod_n_minus_2(&bytes).to_be_bytes(), expected);
    assert_eq!(expected, reference_bit_serial(&bytes, &n_minus_2()));
}
