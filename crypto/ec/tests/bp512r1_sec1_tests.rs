//! Known-answer tests for SEC 1 §2.3.3/§2.3.4 point encoding and decoding, brainpoolP512r1.
//!
//! `G`'s coordinates are RFC 5639 §3.4's (already verified independently in
//! `bp512r1_point_tests.rs`); `2G`'s were computed independently in Python via the standard
//! general-`a` affine group law, specifically because it has odd `y` where `G`'s is even, so
//! between them both compressed tags (`0x02`/`0x03`) are exercised. The encodings below were
//! derived from those coordinates independently in Python via plain big-endian byte packing.

use bouncycastle_ec::hazmat::bp512r1::Bp512r1FieldElement;
use bouncycastle_ec::hazmat::bp512r1_domain::{G_X_LIMBS, G_Y_LIMBS};
use bouncycastle_ec::hazmat::bp512r1_sec1::{
    decode, decode_point, encode_compressed, encode_uncompressed,
};
use bouncycastle_hex::decode as hex_decode;

const TWO_G_X: [u64; 8] = [
    0x080447def02f4850, 0xf698f404089a4cc5, 0x97116e702915a4f4, 0x957877f3a8f0f725,
    0xa30d3035f4cb6581, 0xd18d8141b8a18064, 0x0a63285758f399b3, 0x9f4945f680edf980,
];
const TWO_G_Y: [u64; 8] = [
    0xe269ad21be592e71, 0x63a42e4181fd929c, 0xa5c3b602b0960cbf, 0xfdf99bb1709c700f,
    0x5a2c366b03e5d1b2, 0x149ce1238d3f1e0f, 0x49826b716292f29d, 0x6d6b4b188b699c56,
];

const UNCOMPRESSED_G: [u8; 129] = [
    0x04, 0x81, 0xae, 0xe4, 0xbd, 0xd8, 0x2e, 0xd9, 0x64, 0x5a, 0x21, 0x32, 0x2e, 0x9c, 0x4c, 0x6a,
    0x93, 0x85, 0xed, 0x9f, 0x70, 0xb5, 0xd9, 0x16, 0xc1, 0xb4, 0x3b, 0x62, 0xee, 0xf4, 0xd0, 0x09,
    0x8e, 0xff, 0x3b, 0x1f, 0x78, 0xe2, 0xd0, 0xd4, 0x8d, 0x50, 0xd1, 0x68, 0x7b, 0x93, 0xb9, 0x7d,
    0x5f, 0x7c, 0x6d, 0x50, 0x47, 0x40, 0x6a, 0x5e, 0x68, 0x8b, 0x35, 0x22, 0x09, 0xbc, 0xb9, 0xf8,
    0x22, 0x7d, 0xde, 0x38, 0x5d, 0x56, 0x63, 0x32, 0xec, 0xc0, 0xea, 0xbf, 0xa9, 0xcf, 0x78, 0x22,
    0xfd, 0xf2, 0x09, 0xf7, 0x00, 0x24, 0xa5, 0x7b, 0x1a, 0xa0, 0x00, 0xc5, 0x5b, 0x88, 0x1f, 0x81,
    0x11, 0xb2, 0xdc, 0xde, 0x49, 0x4a, 0x5f, 0x48, 0x5e, 0x5b, 0xca, 0x4b, 0xd8, 0x8a, 0x27, 0x63,
    0xae, 0xd1, 0xca, 0x2b, 0x2f, 0xa8, 0xf0, 0x54, 0x06, 0x78, 0xcd, 0x1e, 0x0f, 0x3a, 0xd8, 0x08,
    0x92,
];

const COMPRESSED_G: [u8; 65] = [
    0x02, 0x81, 0xae, 0xe4, 0xbd, 0xd8, 0x2e, 0xd9, 0x64, 0x5a, 0x21, 0x32, 0x2e, 0x9c, 0x4c, 0x6a,
    0x93, 0x85, 0xed, 0x9f, 0x70, 0xb5, 0xd9, 0x16, 0xc1, 0xb4, 0x3b, 0x62, 0xee, 0xf4, 0xd0, 0x09,
    0x8e, 0xff, 0x3b, 0x1f, 0x78, 0xe2, 0xd0, 0xd4, 0x8d, 0x50, 0xd1, 0x68, 0x7b, 0x93, 0xb9, 0x7d,
    0x5f, 0x7c, 0x6d, 0x50, 0x47, 0x40, 0x6a, 0x5e, 0x68, 0x8b, 0x35, 0x22, 0x09, 0xbc, 0xb9, 0xf8,
    0x22,
];

const UNCOMPRESSED_TWO_G: [u8; 129] = [
    0x04, 0x9f, 0x49, 0x45, 0xf6, 0x80, 0xed, 0xf9, 0x80, 0x0a, 0x63, 0x28, 0x57, 0x58, 0xf3, 0x99,
    0xb3, 0xd1, 0x8d, 0x81, 0x41, 0xb8, 0xa1, 0x80, 0x64, 0xa3, 0x0d, 0x30, 0x35, 0xf4, 0xcb, 0x65,
    0x81, 0x95, 0x78, 0x77, 0xf3, 0xa8, 0xf0, 0xf7, 0x25, 0x97, 0x11, 0x6e, 0x70, 0x29, 0x15, 0xa4,
    0xf4, 0xf6, 0x98, 0xf4, 0x04, 0x08, 0x9a, 0x4c, 0xc5, 0x08, 0x04, 0x47, 0xde, 0xf0, 0x2f, 0x48,
    0x50, 0x6d, 0x6b, 0x4b, 0x18, 0x8b, 0x69, 0x9c, 0x56, 0x49, 0x82, 0x6b, 0x71, 0x62, 0x92, 0xf2,
    0x9d, 0x14, 0x9c, 0xe1, 0x23, 0x8d, 0x3f, 0x1e, 0x0f, 0x5a, 0x2c, 0x36, 0x6b, 0x03, 0xe5, 0xd1,
    0xb2, 0xfd, 0xf9, 0x9b, 0xb1, 0x70, 0x9c, 0x70, 0x0f, 0xa5, 0xc3, 0xb6, 0x02, 0xb0, 0x96, 0x0c,
    0xbf, 0x63, 0xa4, 0x2e, 0x41, 0x81, 0xfd, 0x92, 0x9c, 0xe2, 0x69, 0xad, 0x21, 0xbe, 0x59, 0x2e,
    0x71,
];

const COMPRESSED_TWO_G: [u8; 65] = [
    0x03, 0x9f, 0x49, 0x45, 0xf6, 0x80, 0xed, 0xf9, 0x80, 0x0a, 0x63, 0x28, 0x57, 0x58, 0xf3, 0x99,
    0xb3, 0xd1, 0x8d, 0x81, 0x41, 0xb8, 0xa1, 0x80, 0x64, 0xa3, 0x0d, 0x30, 0x35, 0xf4, 0xcb, 0x65,
    0x81, 0x95, 0x78, 0x77, 0xf3, 0xa8, 0xf0, 0xf7, 0x25, 0x97, 0x11, 0x6e, 0x70, 0x29, 0x15, 0xa4,
    0xf4, 0xf6, 0x98, 0xf4, 0x04, 0x08, 0x9a, 0x4c, 0xc5, 0x08, 0x04, 0x47, 0xde, 0xf0, 0x2f, 0x48,
    0x50,
];

fn fe(limbs: [u64; 8]) -> Bp512r1FieldElement {
    Bp512r1FieldElement::from_limbs(limbs)
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
    assert_eq!(decode(&[0x04; 128]), None);
    assert_eq!(decode(&[0x04; 130]), None);
    assert_eq!(decode(&[0x02; 16]), None);

    let mut bad_tag_129 = UNCOMPRESSED_G;
    bad_tag_129[0] = 0x02;
    assert_eq!(decode(&bad_tag_129), None);

    let mut bad_tag_65 = COMPRESSED_G;
    bad_tag_65[0] = 0x04;
    assert_eq!(decode(&bad_tag_65), None);

    assert_eq!(decode(&[0x00]), None);

    let mut x_too_big = COMPRESSED_G;
    x_too_big[1..65].fill(0xff);
    assert_eq!(decode(&x_too_big), None);

    let mut no_root = COMPRESSED_G;
    no_root[1..65].fill(0);
    no_root[64] = 1; // x = 1, confirmed (in the Python derivation) to have no square root
    assert_eq!(decode(&no_root), None);

    let mut not_on_curve = UNCOMPRESSED_G;
    not_on_curve[128] ^= 0x01;
    assert_eq!(decode(&not_on_curve), None);

    let mut y_too_big = UNCOMPRESSED_G;
    y_too_big[65..129].fill(0xff);
    assert_eq!(decode(&y_too_big), None);
}

/// SP 800-186 Appendix D.1.1.1 step 2 on its own: `(x, y)` is on the curve, so `(x + p, y)` is
/// too once reduced, and only the coordinate range check rejects its encodings. Computed in
/// Python from the curve's `p`, `a` and `b`: the smallest `x` with `x^3 + ax + b` a residue
/// (`x = 3`), `y` its root `(x^3 + ax + b)^((p + 1) / 4)`, and `x + p`, which fits the
/// 64-byte field.
#[test]
fn decode_rejects_a_coordinate_at_or_above_p_that_is_on_the_curve_after_reduction() {
    let point = hex_decode(
        "0400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003045dd3ad1b6a380eff32bccd947957f3acd60d5a6df18ed9a4d676c1924123576c959ae8473de224ca262d456e8d51f6da36eaae8e3dfc0e914afdb1bc552796",
    )
    .unwrap();
    assert!(decode(&point).is_some(), "(x, y) is on the curve");
    let x_plus_p = hex_decode(
        "04aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f6045dd3ad1b6a380eff32bccd947957f3acd60d5a6df18ed9a4d676c1924123576c959ae8473de224ca262d456e8d51f6da36eaae8e3dfc0e914afdb1bc552796",
    )
    .unwrap();
    assert_eq!(decode(&x_plus_p), None, "uncompressed, x + p");
    let compressed = hex_decode(
        "02aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f6",
    )
    .unwrap();
    assert_eq!(decode(&compressed), None, "compressed, x + p");
    let y_plus_p = hex_decode(
        "0400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003af3b7165f753fc9a3f07a37bc84353fb78069b0e21bb60e87b3a138c02742bc8e9e335e8e3044a6778f3ce705530d2dd02b8e9ddbbc0c293b9f55e08148f7089",
    )
    .unwrap();
    assert_eq!(decode(&y_plus_p), None, "uncompressed, y + p");
}
