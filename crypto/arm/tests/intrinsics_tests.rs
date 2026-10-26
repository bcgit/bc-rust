//! Each `V128` wrapper against a scalar model of the instruction it wraps.
//!
//! The AES instructions are pinned by the FIPS 197 and SP 800-38A vectors in `aes_tests.rs`;
//! here they are checked only for the identities that relate them to each other.
//!
//! The wrappers are `#[target_feature]`, so each test body is too, and [`run`] calls it only
//! on a CPU with the instructions.

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

use bouncycastle_arm::intrinsics::V128;
use common::Xorshift;

/// Runs a `#[target_feature(enable = "aes,neon")]` test body, or returns early on a CPU
/// without the instructions.
fn run(body: unsafe fn()) {
    if common::cx().is_some() {
        // SAFETY: `cx()` found the instructions `body`'s `#[target_feature]` names.
        unsafe { body() }
    }
}

/// Carry-less multiplication of two 64-bit values, bit by bit.
fn clmul(a: u64, b: u64) -> u128 {
    let mut r = 0u128;
    for i in 0..64 {
        if (b >> i) & 1 == 1 {
            r ^= (a as u128) << i;
        }
    }
    r
}

fn lanes_u32(b: &[u8; 16]) -> [u32; 4] {
    core::array::from_fn(|i| u32::from_le_bytes(b[4 * i..4 * i + 4].try_into().unwrap()))
}

fn from_lanes_u32(l: &[u32; 4]) -> [u8; 16] {
    let mut b = [0u8; 16];
    for (i, w) in l.iter().enumerate() {
        b[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
    }
    b
}

#[test]
fn bytes_round_trip() {
    run(bytes_round_trip_body);
}

#[target_feature(enable = "aes,neon")]
fn bytes_round_trip_body() {
    let mut rng = Xorshift(1);
    for _ in 0..100 {
        let b = rng.block();
        assert_eq!(V128::from_bytes(&b).to_bytes(), b);
    }
    assert_eq!(V128::zero().to_bytes(), [0u8; 16]);
}

#[test]
fn u64_lanes_are_little_endian_halves() {
    run(u64_lanes_are_little_endian_halves_body);
}

#[target_feature(enable = "aes,neon")]
fn u64_lanes_are_little_endian_halves_body() {
    let (lo, hi) = (0x0123_4567_89ab_cdefu64, 0xfedc_ba98_7654_3210u64);
    let v = V128::from_u64x2(lo, hi);
    let mut expected = [0u8; 16];
    expected[..8].copy_from_slice(&lo.to_le_bytes());
    expected[8..].copy_from_slice(&hi.to_le_bytes());
    assert_eq!(v.to_bytes(), expected);
    assert_eq!(v.lane_u64::<0>(), lo);
    assert_eq!(v.lane_u64::<1>(), hi);
}

#[test]
fn u32_splat_and_lane() {
    run(u32_splat_and_lane_body);
}

#[target_feature(enable = "aes,neon")]
fn u32_splat_and_lane_body() {
    let v = V128::splat_u32(0x1122_3344);
    assert_eq!(lanes_u32(&v.to_bytes()), [0x1122_3344; 4]);
    assert_eq!(v.lane_u32::<0>(), 0x1122_3344);
    assert_eq!(v.lane_u32::<3>(), 0x1122_3344);
    // The word's bytes appear in memory order within each lane.
    assert_eq!(&v.to_bytes()[..4], &[0x44, 0x33, 0x22, 0x11]);
}

#[test]
fn eor_and_orr_are_bytewise() {
    run(eor_and_orr_are_bytewise_body);
}

#[target_feature(enable = "aes,neon")]
fn eor_and_orr_are_bytewise_body() {
    let mut rng = Xorshift(2);
    for _ in 0..100 {
        let (a, b) = (rng.block(), rng.block());
        let (va, vb) = (V128::from_bytes(&a), V128::from_bytes(&b));
        assert_eq!(va.eor(vb).to_bytes(), core::array::from_fn(|i| a[i] ^ b[i]));
        assert_eq!(va.orr(vb).to_bytes(), core::array::from_fn(|i| a[i] | b[i]));
    }
}

#[test]
fn rev64_reverses_each_eight_byte_half() {
    run(rev64_reverses_each_eight_byte_half_body);
}

#[target_feature(enable = "aes,neon")]
fn rev64_reverses_each_eight_byte_half_body() {
    let b: [u8; 16] = core::array::from_fn(|i| i as u8);
    let r = V128::from_bytes(&b).rev64().to_bytes();
    assert_eq!(r, [7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8]);
}

#[test]
fn ext_is_a_window_into_the_concatenation() {
    run(ext_is_a_window_into_the_concatenation_body);
}

#[target_feature(enable = "aes,neon")]
fn ext_is_a_window_into_the_concatenation_body() {
    let a: [u8; 16] = core::array::from_fn(|i| i as u8);
    let b: [u8; 16] = core::array::from_fn(|i| 0x10 + i as u8);
    let mut cat = [0u8; 32];
    cat[..16].copy_from_slice(&a);
    cat[16..].copy_from_slice(&b);
    let (va, vb) = (V128::from_bytes(&a), V128::from_bytes(&b));
    assert_eq!(va.ext::<4>(vb).to_bytes(), cat[4..20]);
    assert_eq!(va.ext::<8>(vb).to_bytes(), cat[8..24]);
    assert_eq!(va.ext::<12>(vb).to_bytes(), cat[12..28]);
    // The two idioms the kernels use: shift down by N, shift up by 16 - N.
    let z = V128::zero();
    assert_eq!(va.ext::<8>(z).to_bytes()[..8], a[8..]);
    assert_eq!(va.ext::<8>(z).to_bytes()[8..], [0u8; 8]);
    assert_eq!(z.ext::<8>(va).to_bytes()[..8], [0u8; 8]);
    assert_eq!(z.ext::<8>(va).to_bytes()[8..], a[..8]);
}

#[test]
fn lane_shifts_match_per_lane_u32_shifts() {
    run(lane_shifts_match_per_lane_u32_shifts_body);
}

#[target_feature(enable = "aes,neon")]
fn lane_shifts_match_per_lane_u32_shifts_body() {
    let mut rng = Xorshift(3);
    for _ in 0..100 {
        let b = rng.block();
        let v = V128::from_bytes(&b);
        let l = lanes_u32(&b);
        assert_eq!(lanes_u32(&v.shr32::<1>().to_bytes()), l.map(|w| w >> 1));
        assert_eq!(lanes_u32(&v.shr32::<2>().to_bytes()), l.map(|w| w >> 2));
        assert_eq!(lanes_u32(&v.shr32::<7>().to_bytes()), l.map(|w| w >> 7));
        assert_eq!(lanes_u32(&v.shr32::<31>().to_bytes()), l.map(|w| w >> 31));
        assert_eq!(lanes_u32(&v.shl32::<1>().to_bytes()), l.map(|w| w << 1));
        assert_eq!(lanes_u32(&v.shl32::<25>().to_bytes()), l.map(|w| w << 25));
        assert_eq!(lanes_u32(&v.shl32::<30>().to_bytes()), l.map(|w| w << 30));
        assert_eq!(lanes_u32(&v.shl32::<31>().to_bytes()), l.map(|w| w << 31));
    }
}

#[test]
fn add32_wraps_within_each_lane() {
    run(add32_wraps_within_each_lane_body);
}

#[target_feature(enable = "aes,neon")]
fn add32_wraps_within_each_lane_body() {
    let mut rng = Xorshift(4);
    for _ in 0..100 {
        let (a, b) = (rng.block(), rng.block());
        let (la, lb) = (lanes_u32(&a), lanes_u32(&b));
        let sum = V128::from_bytes(&a).add32(V128::from_bytes(&b)).to_bytes();
        assert_eq!(lanes_u32(&sum), core::array::from_fn(|i| la[i].wrapping_add(lb[i])));
    }
    // A carry out of one lane must not reach the next.
    let a = from_lanes_u32(&[u32::MAX, 0, u32::MAX, 0]);
    let one = from_lanes_u32(&[1, 0, 1, 0]);
    let sum = V128::from_bytes(&a).add32(V128::from_bytes(&one)).to_bytes();
    assert_eq!(lanes_u32(&sum), [0, 0, 0, 0]);
}

#[test]
fn pmull_variants_match_scalar_carry_less_multiplication() {
    run(pmull_variants_match_scalar_carry_less_multiplication_body);
}

#[target_feature(enable = "aes,neon")]
fn pmull_variants_match_scalar_carry_less_multiplication_body() {
    let mut rng = Xorshift(5);
    for _ in 0..1000 {
        let (a0, a1, b0, b1) = (rng.next_u64(), rng.next_u64(), rng.next_u64(), rng.next_u64());
        let (va, vb) = (V128::from_u64x2(a0, a1), V128::from_u64x2(b0, b1));
        assert_eq!(va.pmull_ll(vb).to_bytes(), clmul(a0, b0).to_le_bytes());
        assert_eq!(va.pmull_hl(vb).to_bytes(), clmul(a1, b0).to_le_bytes());
        assert_eq!(va.pmull_lh(vb).to_bytes(), clmul(a0, b1).to_le_bytes());
        assert_eq!(va.pmull_hh(vb).to_bytes(), clmul(a1, b1).to_le_bytes());
    }
}

/// `AESIMC` inverts `AESMC`, and `AESD` with a zero key inverts the substitution and row
/// shift of `AESE`, leaving only the key addition: `aesd(aese(x, k), 0) == x XOR k`.
#[test]
fn aes_instruction_identities() {
    run(aes_instruction_identities_body);
}

#[target_feature(enable = "aes,neon")]
fn aes_instruction_identities_body() {
    let mut rng = Xorshift(6);
    for _ in 0..100 {
        let (x, k) = (rng.block(), rng.block());
        let (vx, vk) = (V128::from_bytes(&x), V128::from_bytes(&k));
        assert_eq!(vx.aesmc().aesimc().to_bytes(), x);
        assert_eq!(vx.aesimc().aesmc().to_bytes(), x);
        assert_eq!(vx.aese(vk).aesd(V128::zero()).to_bytes(), vx.eor(vk).to_bytes());
        assert_eq!(vx.aesd(vk).aese(V128::zero()).to_bytes(), vx.eor(vk).to_bytes());
    }
}
