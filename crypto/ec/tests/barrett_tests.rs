//! Known-answer tests for [`bouncycastle_ec::barrett`], with `m = n - 1` for P-256 (the modulus
//! `bouncycastle-ecdsa`'s extra-bits reduction passes it). `MU_LOW_LIMBS` is
//! `floor(2^512 / m) - 2^256`, and every expected value is Python's `T % m`, both computed
//! independently of this crate; the inputs are the extremes of the algorithm's bound (`0`, `1`,
//! `m - 1`, `m`, `m + 1`, `2m - 1`, `4m - 1`, `m * 2^256 - 1`, the all-ones values at the widths
//! callers use) plus pseudorandom values (`random.seed(2026)`).

use bouncycastle_ec::barrett::{limbs_from_be_bytes, reduce};
use bouncycastle_ec::p256_scalar::N_LIMBS;

const MU_LOW_LIMBS: [u64; 4] =
    [0x012ffd85eedf9bff, 0x43190552df1a6c21, 0xfffffffeffffffff, 0x00000000ffffffff];

fn n_minus_1() -> [u64; 4] {
    let mut m = N_LIMBS;
    m[0] -= 1;
    m
}

#[test]
fn known_answers_at_the_bounds_extremes_and_pseudorandom_inputs() {
    let m = n_minus_1();
    let cases: [([u64; 8], [u64; 4]); 12] = [
        (
            [
                0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
                0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
            ],
            [0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000],
        ),
        (
            [
                0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
                0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
            ],
            [0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000],
        ),
        (
            [
                0xf3b9cac2fc63254f, 0xbce6faada7179e84, 0xffffffffffffffff, 0xffffffff00000000,
                0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
            ],
            [0xf3b9cac2fc63254f, 0xbce6faada7179e84, 0xffffffffffffffff, 0xffffffff00000000],
        ),
        (
            [
                0xf3b9cac2fc632550, 0xbce6faada7179e84, 0xffffffffffffffff, 0xffffffff00000000,
                0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
            ],
            [0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000],
        ),
        (
            [
                0xf3b9cac2fc632551, 0xbce6faada7179e84, 0xffffffffffffffff, 0xffffffff00000000,
                0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
            ],
            [0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000],
        ),
        (
            [
                0xe7739585f8c64a9f, 0x79cdf55b4e2f3d09, 0xffffffffffffffff, 0xfffffffe00000001,
                0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
            ],
            [0xf3b9cac2fc63254f, 0xbce6faada7179e84, 0xffffffffffffffff, 0xffffffff00000000],
        ),
        (
            [
                0xcee72b0bf18c953f, 0xf39beab69c5e7a13, 0xfffffffffffffffe, 0xfffffffc00000003,
                0x0000000000000003, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
            ],
            [0xf3b9cac2fc63254f, 0xbce6faada7179e84, 0xffffffffffffffff, 0xffffffff00000000],
        ),
        (
            [
                0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
                0xffffffffffffffff, 0x00000000ffffffff, 0x0000000000000000, 0x0000000000000000,
            ],
            [0xe7739585f8c64a9f, 0x89b1054851cc17b9, 0x9c0166cd652e96b7, 0xfffffffe43190554],
        ),
        (
            [
                0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
                0xf3b9cac2fc63254f, 0xbce6faada7179e84, 0xffffffffffffffff, 0xffffffff00000000,
            ],
            [0xf3b9cac2fc63254f, 0xbce6faada7179e84, 0xffffffffffffffff, 0xffffffff00000000],
        ),
        (
            [
                0x51c9bc701e7ea419, 0xf38b2ffc80a4df5a, 0xa5aec7978306d03b, 0xf3f49249dc28ff90,
                0xe255accb1a466884, 0x0000000039292d22, 0x0000000000000000, 0x0000000000000000,
            ],
            [0xdec46b5a9d169069, 0x638e03895206cd65, 0x6f3ad9656a29e7a3, 0xd511cdaaee884747],
        ),
        (
            [
                0x99dd251de5121482, 0x8e7aa6e99f199504, 0xc88b28756bad6be2, 0x8c3d5f169293de8f,
                0xbb049a79d7a7a3cc, 0xc4a334bfc6cd75e9, 0xc0433cbd7dabe929, 0x00096263c5e818fa,
            ],
            [0xa2b4e9170b3fa0c2, 0x9109ae74fd54327f, 0xeac480d056cfea11, 0x7c84c22119b7a494],
        ),
        (
            [
                0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
                0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x00ffffffffffffff,
            ],
            [0xb156ab779217b88f, 0x15f6df373af24723, 0x1e2845b2382b6bec, 0xff66e12c97f3d957],
        ),
    ];
    for (t, expected) in cases {
        assert_eq!(reduce::<4, 8, 5>(&t, &m, &MU_LOW_LIMBS), expected, "t = {t:x?}");
    }
}

#[test]
fn limbs_from_be_bytes_packs_big_endian_input_little_endian_zero_extended() {
    assert_eq!(limbs_from_be_bytes::<2>(&[]), [0, 0]);
    assert_eq!(limbs_from_be_bytes::<2>(&[0x01]), [1, 0]);
    assert_eq!(limbs_from_be_bytes::<2>(&[0x01, 0x02]), [0x0102, 0]);
    assert_eq!(
        limbs_from_be_bytes::<2>(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]),
        [0x0203040506070809, 0x01]
    );
    assert_eq!(limbs_from_be_bytes::<2>(&[0xff; 16]), [u64::MAX, u64::MAX]);
}

#[test]
#[should_panic(expected = "do not fit")]
fn limbs_from_be_bytes_rejects_input_wider_than_the_limbs() {
    let _ = limbs_from_be_bytes::<2>(&[0u8; 17]);
}
