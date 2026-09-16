//! Known-answer tests for SEC 1 §2.3.3/§2.3.4 point encoding and decoding, SM2.
//!
//! `G`'s coordinates are `draft-shen-sm2-ecdsa-02` Appendix D's (already verified independently in
//! `sm2_point_tests.rs`); `2G`'s were computed independently in Python via the standard `a = -3`
//! affine group law, specifically because it has odd `y` where `G`'s is even, so between them both
//! compressed tags (`0x02`/`0x03`) are exercised. The encodings below were derived from those
//! coordinates independently in Python via plain big-endian byte packing.

use bouncycastle_ec::sm2::Sm2FieldElement;
use bouncycastle_ec::sm2_domain::{G_X_LIMBS, G_Y_LIMBS};
use bouncycastle_ec::sm2_sec1::{decode, decode_point, encode_compressed, encode_uncompressed};

const TWO_G_X: [u64; 4] =
    [0x495c2e1da3f2bd52, 0x9c0dfa08c08a7331, 0x0d58ef57fa73ba4d, 0x56cefd60d7c87c00];
const TWO_G_Y: [u64; 4] =
    [0x6f780d3a970a23c3, 0x6de84c182f6c8e71, 0x68535ce0f8eaf1bd, 0x31b7e7e6cc8189f6];

const UNCOMPRESSED_G: [u8; 65] = [
    0x04, 0x32, 0xc4, 0xae, 0x2c, 0x1f, 0x19, 0x81, 0x19, 0x5f, 0x99, 0x04, 0x46, 0x6a, 0x39, 0xc9,
    0x94, 0x8f, 0xe3, 0x0b, 0xbf, 0xf2, 0x66, 0x0b, 0xe1, 0x71, 0x5a, 0x45, 0x89, 0x33, 0x4c, 0x74,
    0xc7, 0xbc, 0x37, 0x36, 0xa2, 0xf4, 0xf6, 0x77, 0x9c, 0x59, 0xbd, 0xce, 0xe3, 0x6b, 0x69, 0x21,
    0x53, 0xd0, 0xa9, 0x87, 0x7c, 0xc6, 0x2a, 0x47, 0x40, 0x02, 0xdf, 0x32, 0xe5, 0x21, 0x39, 0xf0,
    0xa0,
];

const COMPRESSED_G: [u8; 33] = [
    0x02, 0x32, 0xc4, 0xae, 0x2c, 0x1f, 0x19, 0x81, 0x19, 0x5f, 0x99, 0x04, 0x46, 0x6a, 0x39, 0xc9,
    0x94, 0x8f, 0xe3, 0x0b, 0xbf, 0xf2, 0x66, 0x0b, 0xe1, 0x71, 0x5a, 0x45, 0x89, 0x33, 0x4c, 0x74,
    0xc7,
];

const UNCOMPRESSED_TWO_G: [u8; 65] = [
    0x04, 0x56, 0xce, 0xfd, 0x60, 0xd7, 0xc8, 0x7c, 0x00, 0x0d, 0x58, 0xef, 0x57, 0xfa, 0x73, 0xba,
    0x4d, 0x9c, 0x0d, 0xfa, 0x08, 0xc0, 0x8a, 0x73, 0x31, 0x49, 0x5c, 0x2e, 0x1d, 0xa3, 0xf2, 0xbd,
    0x52, 0x31, 0xb7, 0xe7, 0xe6, 0xcc, 0x81, 0x89, 0xf6, 0x68, 0x53, 0x5c, 0xe0, 0xf8, 0xea, 0xf1,
    0xbd, 0x6d, 0xe8, 0x4c, 0x18, 0x2f, 0x6c, 0x8e, 0x71, 0x6f, 0x78, 0x0d, 0x3a, 0x97, 0x0a, 0x23,
    0xc3,
];

const COMPRESSED_TWO_G: [u8; 33] = [
    0x03, 0x56, 0xce, 0xfd, 0x60, 0xd7, 0xc8, 0x7c, 0x00, 0x0d, 0x58, 0xef, 0x57, 0xfa, 0x73, 0xba,
    0x4d, 0x9c, 0x0d, 0xfa, 0x08, 0xc0, 0x8a, 0x73, 0x31, 0x49, 0x5c, 0x2e, 0x1d, 0xa3, 0xf2, 0xbd,
    0x52,
];

fn fe(limbs: [u64; 4]) -> Sm2FieldElement {
    Sm2FieldElement::from_limbs(limbs)
}

#[test]
fn known_answer_encode_uncompressed() {
    assert_eq!(encode_uncompressed(&fe(G_X_LIMBS), &fe(G_Y_LIMBS)), UNCOMPRESSED_G);
    assert_eq!(encode_uncompressed(&fe(TWO_G_X), &fe(TWO_G_Y)), UNCOMPRESSED_TWO_G);
}

#[test]
fn known_answer_encode_compressed() {
    assert_eq!(
        encode_compressed(&fe(G_X_LIMBS), &fe(G_Y_LIMBS)),
        COMPRESSED_G,
        "G has even y -> tag 0x02"
    );
    assert_eq!(
        encode_compressed(&fe(TWO_G_X), &fe(TWO_G_Y)),
        COMPRESSED_TWO_G,
        "2G has odd y -> tag 0x03"
    );
}

#[test]
fn known_answer_decode_uncompressed() {
    let (x, y) = decode(&UNCOMPRESSED_G).expect("valid uncompressed point");
    assert_eq!(x, fe(G_X_LIMBS));
    assert_eq!(y, fe(G_Y_LIMBS));
}

#[test]
fn known_answer_decode_compressed() {
    let (x, y) = decode(&COMPRESSED_G).expect("valid compressed point, tag 0x02");
    assert_eq!(x, fe(G_X_LIMBS));
    assert_eq!(y, fe(G_Y_LIMBS));

    let (x2, y2) = decode(&COMPRESSED_TWO_G).expect("valid compressed point, tag 0x03");
    assert_eq!(x2, fe(TWO_G_X));
    assert_eq!(y2, fe(TWO_G_Y));
}

#[test]
fn round_trip_uncompressed_and_compressed() {
    for (x, y) in [(G_X_LIMBS, G_Y_LIMBS), (TWO_G_X, TWO_G_Y)] {
        let uncompressed = encode_uncompressed(&fe(x), &fe(y));
        assert_eq!(decode(&uncompressed), Some((fe(x), fe(y))));

        let compressed = encode_compressed(&fe(x), &fe(y));
        assert_eq!(decode(&compressed), Some((fe(x), fe(y))));

        assert!(decode_point(&uncompressed).unwrap().to_affine().is_some());
    }
}

#[test]
fn decode_rejects_malformed_input() {
    assert_eq!(decode(&[]), None);
    assert_eq!(decode(&[0x04; 64]), None);
    assert_eq!(decode(&[0x04; 66]), None);
    assert_eq!(decode(&[0x02; 16]), None);

    let mut bad_tag_65 = UNCOMPRESSED_G;
    bad_tag_65[0] = 0x02;
    assert_eq!(decode(&bad_tag_65), None);

    let mut bad_tag_33 = COMPRESSED_G;
    bad_tag_33[0] = 0x04;
    assert_eq!(decode(&bad_tag_33), None);

    assert_eq!(decode(&[0x00]), None);

    let mut x_too_big = COMPRESSED_G;
    x_too_big[1..33].fill(0xff);
    assert_eq!(decode(&x_too_big), None);

    let mut no_root = COMPRESSED_G;
    no_root[1..33].fill(0);
    no_root[32] = 2; // x = 2, confirmed (in the Python derivation) to have no square root
    assert_eq!(decode(&no_root), None);

    let mut not_on_curve = UNCOMPRESSED_G;
    not_on_curve[64] ^= 0x01;
    assert_eq!(decode(&not_on_curve), None);

    let mut y_too_big = UNCOMPRESSED_G;
    y_too_big[33..65].fill(0xff);
    assert_eq!(decode(&y_too_big), None);
}
