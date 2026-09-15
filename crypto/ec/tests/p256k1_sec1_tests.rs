//! Known-answer tests for SEC 1 §2.3.3/§2.3.4 point encoding and decoding, secp256k1.
//!
//! `G`'s coordinates are SEC 2 v2 §2.4.1's (already verified independently in
//! `p256k1_point_tests.rs`/`p256k1_comb_tests.rs`); `6G`'s were computed independently in Python via
//! the standard affine group law (`a = 0`) specifically because it has odd `y` where `G`'s is even,
//! so between them both compressed tags (`0x02`/`0x03`) are exercised. The encodings below were
//! derived from those coordinates independently in Python via plain big-endian byte packing.

use bouncycastle_ec::p256k1::P256K1FieldElement;
use bouncycastle_ec::p256k1_domain::{G_X_LIMBS, G_Y_LIMBS};
use bouncycastle_ec::p256k1_sec1::{decode, decode_point, encode_compressed, encode_uncompressed};

const SIX_G_X: [u64; 4] =
    [0x2f057a1460297556, 0x82f6472f8568a18b, 0x20453a14355235d3, 0xfff97bd5755eeea4];
const SIX_G_Y: [u64; 4] =
    [0x3c870c36b075f297, 0xde80f0f6518fe4a0, 0xf3be96017f45c560, 0xae12777aacfbb620];

const UNCOMPRESSED_G: [u8; 65] = [
    0x04, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
    0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17,
    0x98, 0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08,
    0xa8, 0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19, 0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4,
    0xb8,
];

const COMPRESSED_G: [u8; 33] = [
    0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
    0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17,
    0x98,
];

const UNCOMPRESSED_SIX_G: [u8; 65] = [
    0x04, 0xff, 0xf9, 0x7b, 0xd5, 0x75, 0x5e, 0xee, 0xa4, 0x20, 0x45, 0x3a, 0x14, 0x35, 0x52, 0x35,
    0xd3, 0x82, 0xf6, 0x47, 0x2f, 0x85, 0x68, 0xa1, 0x8b, 0x2f, 0x05, 0x7a, 0x14, 0x60, 0x29, 0x75,
    0x56, 0xae, 0x12, 0x77, 0x7a, 0xac, 0xfb, 0xb6, 0x20, 0xf3, 0xbe, 0x96, 0x01, 0x7f, 0x45, 0xc5,
    0x60, 0xde, 0x80, 0xf0, 0xf6, 0x51, 0x8f, 0xe4, 0xa0, 0x3c, 0x87, 0x0c, 0x36, 0xb0, 0x75, 0xf2,
    0x97,
];

const COMPRESSED_SIX_G: [u8; 33] = [
    0x03, 0xff, 0xf9, 0x7b, 0xd5, 0x75, 0x5e, 0xee, 0xa4, 0x20, 0x45, 0x3a, 0x14, 0x35, 0x52, 0x35,
    0xd3, 0x82, 0xf6, 0x47, 0x2f, 0x85, 0x68, 0xa1, 0x8b, 0x2f, 0x05, 0x7a, 0x14, 0x60, 0x29, 0x75,
    0x56,
];

fn fe(limbs: [u64; 4]) -> P256K1FieldElement {
    P256K1FieldElement::from_limbs(limbs)
}

#[test]
fn known_answer_encode_uncompressed() {
    assert_eq!(encode_uncompressed(&fe(G_X_LIMBS), &fe(G_Y_LIMBS)), UNCOMPRESSED_G);
    assert_eq!(encode_uncompressed(&fe(SIX_G_X), &fe(SIX_G_Y)), UNCOMPRESSED_SIX_G);
}

#[test]
fn known_answer_encode_compressed() {
    assert_eq!(
        encode_compressed(&fe(G_X_LIMBS), &fe(G_Y_LIMBS)),
        COMPRESSED_G,
        "G has even y -> tag 0x02"
    );
    assert_eq!(
        encode_compressed(&fe(SIX_G_X), &fe(SIX_G_Y)),
        COMPRESSED_SIX_G,
        "6G has odd y -> tag 0x03"
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

    let (x6, y6) = decode(&COMPRESSED_SIX_G).expect("valid compressed point, tag 0x03");
    assert_eq!(x6, fe(SIX_G_X));
    assert_eq!(y6, fe(SIX_G_Y));
}

#[test]
fn round_trip_uncompressed_and_compressed() {
    for (x, y) in [(G_X_LIMBS, G_Y_LIMBS), (SIX_G_X, SIX_G_Y)] {
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
    no_root[32] = 5; // x = 5, confirmed (in the Python derivation) to have no square root
    assert_eq!(decode(&no_root), None);

    let mut not_on_curve = UNCOMPRESSED_G;
    not_on_curve[64] ^= 0x01;
    assert_eq!(decode(&not_on_curve), None);

    let mut y_too_big = UNCOMPRESSED_G;
    y_too_big[33..65].fill(0xff);
    assert_eq!(decode(&y_too_big), None);
}
