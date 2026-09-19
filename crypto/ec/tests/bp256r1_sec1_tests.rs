//! Known-answer tests for SEC 1 §2.3.3/§2.3.4 point encoding and decoding, brainpoolP256r1.
//!
//! `G`'s coordinates are RFC 5639 §3.4's (already verified independently in
//! `bp256r1_point_tests.rs`); `2G`'s were computed independently in Python via the standard
//! general-`a` affine group law, specifically because it has even `y` where `G`'s is odd, so
//! between them both compressed tags (`0x02`/`0x03`) are exercised. The encodings below were
//! derived from those coordinates independently in Python via plain big-endian byte packing.

use bouncycastle_ec::bp256r1::Bp256r1FieldElement;
use bouncycastle_ec::bp256r1_domain::{G_X_LIMBS, G_Y_LIMBS};
use bouncycastle_ec::bp256r1_sec1::{decode, decode_point, encode_compressed, encode_uncompressed};

const TWO_G_X: [u64; 4] =
    [0xd51a14c2ce13ea0e, 0x36ef044166699e37, 0xb55f8aa369593ac4, 0x743cf1b8b5cd4f2e];
const TWO_G_Y: [u64; 4] =
    [0x892ada097eeb7cd4, 0x38df059f69249406, 0x946fe0bb776529da, 0x36ed163337deba9c];

const UNCOMPRESSED_G: [u8; 65] = [
    0x04, 0x8b, 0xd2, 0xae, 0xb9, 0xcb, 0x7e, 0x57, 0xcb, 0x2c, 0x4b, 0x48, 0x2f, 0xfc, 0x81, 0xb7,
    0xaf, 0xb9, 0xde, 0x27, 0xe1, 0xe3, 0xbd, 0x23, 0xc2, 0x3a, 0x44, 0x53, 0xbd, 0x9a, 0xce, 0x32,
    0x62, 0x54, 0x7e, 0xf8, 0x35, 0xc3, 0xda, 0xc4, 0xfd, 0x97, 0xf8, 0x46, 0x1a, 0x14, 0x61, 0x1d,
    0xc9, 0xc2, 0x77, 0x45, 0x13, 0x2d, 0xed, 0x8e, 0x54, 0x5c, 0x1d, 0x54, 0xc7, 0x2f, 0x04, 0x69,
    0x97,
];

const COMPRESSED_G: [u8; 33] = [
    0x03, 0x8b, 0xd2, 0xae, 0xb9, 0xcb, 0x7e, 0x57, 0xcb, 0x2c, 0x4b, 0x48, 0x2f, 0xfc, 0x81, 0xb7,
    0xaf, 0xb9, 0xde, 0x27, 0xe1, 0xe3, 0xbd, 0x23, 0xc2, 0x3a, 0x44, 0x53, 0xbd, 0x9a, 0xce, 0x32,
    0x62,
];

const UNCOMPRESSED_TWO_G: [u8; 65] = [
    0x04, 0x74, 0x3c, 0xf1, 0xb8, 0xb5, 0xcd, 0x4f, 0x2e, 0xb5, 0x5f, 0x8a, 0xa3, 0x69, 0x59, 0x3a,
    0xc4, 0x36, 0xef, 0x04, 0x41, 0x66, 0x69, 0x9e, 0x37, 0xd5, 0x1a, 0x14, 0xc2, 0xce, 0x13, 0xea,
    0x0e, 0x36, 0xed, 0x16, 0x33, 0x37, 0xde, 0xba, 0x9c, 0x94, 0x6f, 0xe0, 0xbb, 0x77, 0x65, 0x29,
    0xda, 0x38, 0xdf, 0x05, 0x9f, 0x69, 0x24, 0x94, 0x06, 0x89, 0x2a, 0xda, 0x09, 0x7e, 0xeb, 0x7c,
    0xd4,
];

const COMPRESSED_TWO_G: [u8; 33] = [
    0x02, 0x74, 0x3c, 0xf1, 0xb8, 0xb5, 0xcd, 0x4f, 0x2e, 0xb5, 0x5f, 0x8a, 0xa3, 0x69, 0x59, 0x3a,
    0xc4, 0x36, 0xef, 0x04, 0x41, 0x66, 0x69, 0x9e, 0x37, 0xd5, 0x1a, 0x14, 0xc2, 0xce, 0x13, 0xea,
    0x0e,
];

fn fe(limbs: [u64; 4]) -> Bp256r1FieldElement {
    Bp256r1FieldElement::from_limbs(limbs)
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
        "G has odd y -> tag 0x03"
    );
    assert_eq!(
        encode_compressed(&fe(TWO_G_X), &fe(TWO_G_Y)),
        COMPRESSED_TWO_G,
        "2G has even y -> tag 0x02"
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
    let (x, y) = decode(&COMPRESSED_G).expect("valid compressed point, tag 0x03");
    assert_eq!(x, fe(G_X_LIMBS));
    assert_eq!(y, fe(G_Y_LIMBS));

    let (x2, y2) = decode(&COMPRESSED_TWO_G).expect("valid compressed point, tag 0x02");
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
    no_root[32] = 4; // x = 4, confirmed (in the Python derivation) to have no square root
    assert_eq!(decode(&no_root), None);

    let mut not_on_curve = UNCOMPRESSED_G;
    not_on_curve[64] ^= 0x01;
    assert_eq!(decode(&not_on_curve), None);

    let mut y_too_big = UNCOMPRESSED_G;
    y_too_big[33..65].fill(0xff);
    assert_eq!(decode(&y_too_big), None);
}
