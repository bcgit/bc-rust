//! Known-answer tests for SEC 1 §2.3.3/§2.3.4 point encoding and decoding.
//!
//! `G` and `3G`'s coordinates come from `p256_comb_tests.rs`'s already-verified values (in turn
//! from the SP 800-186 Appendix A.1.1 affine group law); the encodings below were derived from
//! those coordinates independently in Python via plain big-endian byte packing:
//! `bytes([tag]) + x.to_bytes(32, 'big') + (y.to_bytes(32, 'big') if uncompressed else b'')`.
//! `G` has odd `y` (tag `0x03`) and `3G` has even `y` (tag `0x02`), so between them both
//! compressed tags are exercised.

use bouncycastle_ec::p256::P256FieldElement;
use bouncycastle_ec::p256_sec1::{decode, decode_point, encode_compressed, encode_uncompressed};

const G_X: [u64; 4] =
    [0xf4a13945d898c296, 0x77037d812deb33a0, 0xf8bce6e563a440f2, 0x6b17d1f2e12c4247];
const G_Y: [u64; 4] =
    [0xcbb6406837bf51f5, 0x2bce33576b315ece, 0x8ee7eb4a7c0f9e16, 0x4fe342e2fe1a7f9b];
const P3_X: [u64; 4] =
    [0xfb41661bc6e7fd6c, 0xe6c6b721efada985, 0xc8f7ef951d4bf165, 0x5ecbe4d1a6330a44];
const P3_Y: [u64; 4] =
    [0x9a79b127a27d5032, 0xd82ab036384fb83d, 0x374b06ce1a64a2ec, 0x8734640c4998ff7e];

#[rustfmt::skip]
const UNCOMPRESSED_G: [u8; 65] = [
    0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42,
    0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
    0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33,
    0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2,
    0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f,
    0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e,
    0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e,
    0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51,
    0xf5,
];

#[rustfmt::skip]
const COMPRESSED_G: [u8; 33] = [
    0x03, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42,
    0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
    0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33,
    0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2,
    0x96,
];

#[rustfmt::skip]
const COMPRESSED_3G: [u8; 33] = [
    0x02, 0x5e, 0xcb, 0xe4, 0xd1, 0xa6, 0x33, 0x0a,
    0x44, 0xc8, 0xf7, 0xef, 0x95, 0x1d, 0x4b, 0xf1,
    0x65, 0xe6, 0xc6, 0xb7, 0x21, 0xef, 0xad, 0xa9,
    0x85, 0xfb, 0x41, 0x66, 0x1b, 0xc6, 0xe7, 0xfd,
    0x6c,
];

fn fe(limbs: [u64; 4]) -> P256FieldElement {
    P256FieldElement::from_limbs(limbs)
}

#[test]
fn known_answer_encode_uncompressed() {
    assert_eq!(encode_uncompressed(&fe(G_X), &fe(G_Y)), UNCOMPRESSED_G);
}

#[test]
fn known_answer_encode_compressed() {
    assert_eq!(encode_compressed(&fe(G_X), &fe(G_Y)), COMPRESSED_G, "G has odd y -> tag 0x03");
    assert_eq!(encode_compressed(&fe(P3_X), &fe(P3_Y)), COMPRESSED_3G, "3G has even y -> tag 0x02");
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

    let (x3, y3) = decode(&COMPRESSED_3G).expect("valid compressed point, tag 0x02");
    assert_eq!(x3, fe(P3_X));
    assert_eq!(y3, fe(P3_Y));
}

#[test]
fn round_trip_uncompressed_and_compressed() {
    for (x, y) in [(G_X, G_Y), (P3_X, P3_Y)] {
        let uncompressed = encode_uncompressed(&fe(x), &fe(y));
        assert_eq!(decode(&uncompressed), Some((fe(x), fe(y))));

        let compressed = encode_compressed(&fe(x), &fe(y));
        assert_eq!(decode(&compressed), Some((fe(x), fe(y))));

        assert!(decode_point(&uncompressed).unwrap().to_affine().is_some());
    }
}

#[test]
fn decode_rejects_malformed_input() {
    // wrong length
    assert_eq!(decode(&[]), None);
    assert_eq!(decode(&[0x04; 64]), None);
    assert_eq!(decode(&[0x04; 66]), None);
    assert_eq!(decode(&[0x02; 32]), None);

    // wrong tag for the given length
    let mut bad_tag_65 = UNCOMPRESSED_G;
    bad_tag_65[0] = 0x02;
    assert_eq!(decode(&bad_tag_65), None);

    let mut bad_tag_33 = COMPRESSED_G;
    bad_tag_33[0] = 0x04;
    assert_eq!(decode(&bad_tag_33), None);

    let mut bad_tag_33_other = COMPRESSED_G;
    bad_tag_33_other[0] = 0x01;
    assert_eq!(decode(&bad_tag_33_other), None);

    // the single-byte point-at-infinity encoding is not accepted (see module docs)
    assert_eq!(decode(&[0x00]), None);

    // x out of range [0, p) for the compressed case (all-0xff x, > p)
    let mut x_too_big = COMPRESSED_G;
    x_too_big[1..33].fill(0xff);
    assert_eq!(decode(&x_too_big), None);

    // an x with no square root (curve equation has no solution) must be rejected
    let mut no_root = COMPRESSED_G;
    no_root[1..33].fill(0);
    no_root[32] = 2; // x = 2, confirmed (in the Python derivation) to have no square root
    assert_eq!(decode(&no_root), None);

    // uncompressed point not on the curve (G's x with a tampered y)
    let mut not_on_curve = UNCOMPRESSED_G;
    not_on_curve[64] ^= 0x01;
    assert_eq!(decode(&not_on_curve), None);

    // y out of range [0, p) for the uncompressed case
    let mut y_too_big = UNCOMPRESSED_G;
    y_too_big[33..65].fill(0xff);
    assert_eq!(decode(&y_too_big), None);
}
