//! Known-answer tests for SEC 1 §2.3.3/§2.3.4 point encoding and decoding, P-384.
//!
//! `G` and `2G`'s coordinates are the same values verified independently in
//! `p384_point_tests.rs`; the encodings below were derived from those coordinates independently
//! in Python via plain big-endian byte packing. `G` has odd `y` (tag `0x03`) and `2G` has even `y`
//! (tag `0x02`), so between them both compressed tags are exercised.

use bouncycastle_ec::p384::P384FieldElement;
use bouncycastle_ec::p384_sec1::{decode, decode_point, encode_compressed, encode_uncompressed};

const G_X: [u64; 6] = [
    0x3a545e3872760ab7, 0x5502f25dbf55296c, 0x59f741e082542a38, 0x6e1d3b628ba79b98,
    0x8eb1c71ef320ad74, 0xaa87ca22be8b0537,
];
const G_Y: [u64; 6] = [
    0x7a431d7c90ea0e5f, 0x0a60b1ce1d7e819d, 0xe9da3113b5f0b8c0, 0xf8f41dbd289a147c,
    0x5d9e98bf9292dc29, 0x3617de4a96262c6f,
];
const TWO_G_X: [u64; 6] = [
    0x5b96a9c75295df61, 0x4fe0e86ebe0e64f8, 0x51d207d19fb96e9e, 0x89025959a6f434d6,
    0x69260045c55b97f0, 0x08d999057ba3d2d9,
];
const TWO_G_Y: [u64; 6] = [
    0x61501e700a940e80, 0x5ffd43e94d39e22d, 0x904e505f256ab425, 0xb275d875bc6cc43e,
    0xb7bfe8dffd6dba74, 0x8e80f1fa5b1b3ced,
];

const UNCOMPRESSED_G: [u8; 97] = [
    0x04, 0xaa, 0x87, 0xca, 0x22, 0xbe, 0x8b, 0x05, 0x37, 0x8e, 0xb1, 0xc7, 0x1e, 0xf3, 0x20, 0xad,
    0x74, 0x6e, 0x1d, 0x3b, 0x62, 0x8b, 0xa7, 0x9b, 0x98, 0x59, 0xf7, 0x41, 0xe0, 0x82, 0x54, 0x2a,
    0x38, 0x55, 0x02, 0xf2, 0x5d, 0xbf, 0x55, 0x29, 0x6c, 0x3a, 0x54, 0x5e, 0x38, 0x72, 0x76, 0x0a,
    0xb7, 0x36, 0x17, 0xde, 0x4a, 0x96, 0x26, 0x2c, 0x6f, 0x5d, 0x9e, 0x98, 0xbf, 0x92, 0x92, 0xdc,
    0x29, 0xf8, 0xf4, 0x1d, 0xbd, 0x28, 0x9a, 0x14, 0x7c, 0xe9, 0xda, 0x31, 0x13, 0xb5, 0xf0, 0xb8,
    0xc0, 0x0a, 0x60, 0xb1, 0xce, 0x1d, 0x7e, 0x81, 0x9d, 0x7a, 0x43, 0x1d, 0x7c, 0x90, 0xea, 0x0e,
    0x5f,
];

const COMPRESSED_G: [u8; 49] = [
    0x03, 0xaa, 0x87, 0xca, 0x22, 0xbe, 0x8b, 0x05, 0x37, 0x8e, 0xb1, 0xc7, 0x1e, 0xf3, 0x20, 0xad,
    0x74, 0x6e, 0x1d, 0x3b, 0x62, 0x8b, 0xa7, 0x9b, 0x98, 0x59, 0xf7, 0x41, 0xe0, 0x82, 0x54, 0x2a,
    0x38, 0x55, 0x02, 0xf2, 0x5d, 0xbf, 0x55, 0x29, 0x6c, 0x3a, 0x54, 0x5e, 0x38, 0x72, 0x76, 0x0a,
    0xb7,
];

const COMPRESSED_2G: [u8; 49] = [
    0x02, 0x08, 0xd9, 0x99, 0x05, 0x7b, 0xa3, 0xd2, 0xd9, 0x69, 0x26, 0x00, 0x45, 0xc5, 0x5b, 0x97,
    0xf0, 0x89, 0x02, 0x59, 0x59, 0xa6, 0xf4, 0x34, 0xd6, 0x51, 0xd2, 0x07, 0xd1, 0x9f, 0xb9, 0x6e,
    0x9e, 0x4f, 0xe0, 0xe8, 0x6e, 0xbe, 0x0e, 0x64, 0xf8, 0x5b, 0x96, 0xa9, 0xc7, 0x52, 0x95, 0xdf,
    0x61,
];

fn fe(limbs: [u64; 6]) -> P384FieldElement {
    P384FieldElement::from_limbs(limbs)
}

#[test]
fn known_answer_encode_uncompressed() {
    assert_eq!(encode_uncompressed(&fe(G_X), &fe(G_Y)), UNCOMPRESSED_G);
}

#[test]
fn known_answer_encode_compressed() {
    assert_eq!(encode_compressed(&fe(G_X), &fe(G_Y)), COMPRESSED_G, "G has odd y -> tag 0x03");
    assert_eq!(
        encode_compressed(&fe(TWO_G_X), &fe(TWO_G_Y)),
        COMPRESSED_2G,
        "2G has even y -> tag 0x02"
    );
}

#[test]
fn known_answer_decode_uncompressed() {
    let (x, y) = decode(&UNCOMPRESSED_G).expect("valid uncompressed point");
    assert_eq!(x, fe(G_X));
    assert_eq!(y, fe(G_Y));
}

#[test]
fn known_answer_decode_compressed() {
    let (x, y) = decode(&COMPRESSED_G).expect("valid compressed point, tag 0x03");
    assert_eq!(x, fe(G_X));
    assert_eq!(y, fe(G_Y));

    let (x2, y2) = decode(&COMPRESSED_2G).expect("valid compressed point, tag 0x02");
    assert_eq!(x2, fe(TWO_G_X));
    assert_eq!(y2, fe(TWO_G_Y));
}

#[test]
fn round_trip_uncompressed_and_compressed() {
    for (x, y) in [(G_X, G_Y), (TWO_G_X, TWO_G_Y)] {
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
    assert_eq!(decode(&[0x04; 96]), None);
    assert_eq!(decode(&[0x04; 98]), None);
    assert_eq!(decode(&[0x02; 32]), None);

    let mut bad_tag_97 = UNCOMPRESSED_G;
    bad_tag_97[0] = 0x02;
    assert_eq!(decode(&bad_tag_97), None);

    let mut bad_tag_49 = COMPRESSED_G;
    bad_tag_49[0] = 0x04;
    assert_eq!(decode(&bad_tag_49), None);

    assert_eq!(decode(&[0x00]), None);

    let mut x_too_big = COMPRESSED_G;
    x_too_big[1..49].fill(0xff);
    assert_eq!(decode(&x_too_big), None);

    let mut no_root = COMPRESSED_G;
    no_root[1..49].fill(0);
    no_root[48] = 4; // x = 4, confirmed (in the Python derivation) to have no square root
    assert_eq!(decode(&no_root), None);

    let mut not_on_curve = UNCOMPRESSED_G;
    not_on_curve[96] ^= 0x01;
    assert_eq!(decode(&not_on_curve), None);

    let mut y_too_big = UNCOMPRESSED_G;
    y_too_big[49..97].fill(0xff);
    assert_eq!(decode(&y_too_big), None);
}
