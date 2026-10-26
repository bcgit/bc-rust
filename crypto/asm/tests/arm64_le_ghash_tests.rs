//! The `PMULL` field multiplication against SP 800-38D Sec 6.3 Algorithm 1, computed bit by
//! bit, and `mul4` against four single products.

#![cfg(all(
    target_arch = "aarch64",
    target_endian = "little",
    target_feature = "neon",
    any(
        target_feature = "aes",
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "windows"
    )
))]

mod common;

use bouncycastle_asm::arm64_le::ghash::Element;
use common::Xorshift;

/// `R = 11100001 || 0^120` (Sec 6.3): first byte `0xE1`, the rest zero, in the `[u64; 2]` form.
const R: Element = [0xE100_0000_0000_0000, 0];

/// The spec's `1`: `1 || 0^127`, the multiplicative identity.
const ONE: Element = [0x8000_0000_0000_0000, 0];

/// Algorithm 1 (Sec 6.3), a direct transcription: the oracle, never used outside the tests.
/// Bit `x_0` is the top bit of `x[0]`, `x_127` the bottom bit of `x[1]`; "V >> 1" shifts the
/// 128-bit string right across the pair.
fn mul_reference(x: &Element, y: &Element) -> Element {
    // Step 2: Z_0 = 0^128, V_0 = Y.
    let mut z: Element = [0, 0];
    let mut v: Element = *y;
    // Step 3: for i = 0 to 127.
    for i in 0..128u32 {
        let bit = if i < 64 { (x[0] >> (63 - i)) & 1 } else { (x[1] >> (127 - i)) & 1 };
        // Z_{i+1} = Z_i if x_i = 0, Z_i (+) V_i if x_i = 1.
        let m = 0u64.wrapping_sub(bit);
        z[0] ^= v[0] & m;
        z[1] ^= v[1] & m;
        // V_{i+1} = V_i >> 1 if LSB_1(V_i) = 0, (V_i >> 1) (+) R otherwise.
        let lsb = v[1] & 1;
        let lm = 0u64.wrapping_sub(lsb);
        let carry = v[0] & 1;
        v[0] >>= 1;
        v[1] = (v[1] >> 1) | (carry << 63);
        v[0] ^= R[0] & lm;
        v[1] ^= R[1] & lm;
    }
    // Step 4: return Z_128.
    z
}

#[test]
fn mul_matches_the_reference_on_zero() {
    let Some(cx) = common::cx() else { return };
    let h: Element = [0x1122_3344_5566_7788, 0x99aa_bbcc_ddee_ff00];
    assert_eq!(cx.ghash_mul(&[0, 0], &h), mul_reference(&[0, 0], &h));
    assert_eq!(cx.ghash_mul(&h, &[0, 0]), mul_reference(&h, &[0, 0]));
}

#[test]
fn mul_matches_the_reference_at_every_single_bit_position() {
    let Some(cx) = common::cx() else { return };
    let h: Element = [0xdead_beef_cafe_babe, 0x0123_4567_89ab_cdef];
    for i in 0..128u32 {
        let x: Element = if i < 64 { [1u64 << (63 - i), 0] } else { [0, 1u64 << (127 - i)] };
        assert_eq!(cx.ghash_mul(&x, &h), mul_reference(&x, &h), "bit position {i}");
        assert_eq!(cx.ghash_mul(&h, &x), mul_reference(&h, &x), "bit position {i}, swapped");
    }
}

#[test]
fn mul_matches_the_reference_on_all_ones() {
    let Some(cx) = common::cx() else { return };
    let h: Element = [0xfeed_face_dead_beef, 0x0102_0304_0506_0708];
    let ones: Element = [u64::MAX, u64::MAX];
    assert_eq!(cx.ghash_mul(&ones, &h), mul_reference(&ones, &h));
    assert_eq!(cx.ghash_mul(&h, &ones), mul_reference(&h, &ones));
    assert_eq!(cx.ghash_mul(&ones, &ones), mul_reference(&ones, &ones));
}

#[test]
fn mul_matches_the_reference_on_ten_thousand_random_pairs() {
    let Some(cx) = common::cx() else { return };
    let mut rng = Xorshift(0x2545_f491_4f6c_dd1d);
    for _ in 0..10_000 {
        let x = rng.element();
        let y = rng.element();
        assert_eq!(cx.ghash_mul(&x, &y), mul_reference(&x, &y), "x={x:?} y={y:?}");
    }
}

#[test]
fn mul_by_one_is_the_identity_and_mul_is_commutative() {
    let Some(cx) = common::cx() else { return };
    let mut rng = Xorshift(0x9e37_79b9_7f4a_7c15);
    for _ in 0..256 {
        let x = rng.element();
        let y = rng.element();
        assert_eq!(cx.ghash_mul(&x, &ONE), x);
        assert_eq!(cx.ghash_mul(&ONE, &x), x);
        assert_eq!(cx.ghash_mul(&x, &y), cx.ghash_mul(&y, &x));
    }
    assert_eq!(cx.ghash_mul(&R, &ONE), R);
}

#[test]
fn mul4_is_the_sum_of_four_products() {
    let Some(cx) = common::cx() else { return };
    let mut rng = Xorshift(0xbf58_476d_1ce4_e5b9);
    for _ in 0..1000 {
        let x: [Element; 4] = core::array::from_fn(|_| rng.element());
        let y: [Element; 4] = core::array::from_fn(|_| rng.element());
        let mut expected: Element = [0, 0];
        for i in 0..4 {
            let p = mul_reference(&x[i], &y[i]);
            expected[0] ^= p[0];
            expected[1] ^= p[1];
        }
        assert_eq!(cx.ghash_mul4(&x, &y), expected);
    }
}

/// Sec 6.4, Algorithm 2 folded four blocks at a time: `Y = (Y (+) X1).H^4 (+) X2.H^3 (+)
/// X3.H^2 (+) X4.H` must equal four steps of `Y_i = (Y_{i-1} (+) X_i).H`.
#[test]
fn mul4_folds_four_ghash_steps_at_once() {
    let Some(cx) = common::cx() else { return };
    let mut rng = Xorshift(0x94d0_49bb_1331_11eb);
    for _ in 0..200 {
        let h = rng.element();
        let h2 = cx.ghash_mul(&h, &h);
        let h3 = cx.ghash_mul(&h2, &h);
        let h4 = cx.ghash_mul(&h3, &h);
        let blocks: [Element; 8] = core::array::from_fn(|_| rng.element());

        let mut one_at_a_time: Element = [0, 0];
        for x in &blocks {
            one_at_a_time = mul_reference(&[one_at_a_time[0] ^ x[0], one_at_a_time[1] ^ x[1]], &h);
        }

        let mut four_at_a_time: Element = [0, 0];
        for group in blocks.chunks_exact(4) {
            let first = [four_at_a_time[0] ^ group[0][0], four_at_a_time[1] ^ group[0][1]];
            four_at_a_time =
                cx.ghash_mul4(&[first, group[1], group[2], group[3]], &[h4, h3, h2, h]);
        }
        assert_eq!(four_at_a_time, one_at_a_time);
    }
}
