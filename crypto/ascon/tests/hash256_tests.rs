//! Ascon-Hash256 tests (NIST SP 800-232 §5.1).
//!
//! Embedded NIST LWC known-answer vectors (always-on; full sweep in `bc_test_data.rs`) plus
//! streaming-equivalence, one-shot/trait-API, metadata, and unsupported-partial-op tests.

use bouncycastle_ascon::ascon_hash256::AsconHash256;
use bouncycastle_core::traits::Hash;
use bouncycastle_hex as hex;

/// Embedded NIST LWC Ascon-Hash256 vectors `(message, digest)` in hex, spanning empty, sub-block,
/// exact-block, and multi-block messages. (Counts 1, 2, 9, 17, 33 of LWC_HASH_KAT_256.txt.)
const HASH_KAT: &[(&str, &str)] = &[
    ("", "0B3BE5850F2F6B98CAF29F8FDEA89B64A1FA70AA249B8F839BD53BAA304D92B2"),
    ("00", "0728621035AF3ED2BCA03BF6FDE900F9456F5330E4B5EE23E7F6A1E70291BC80"),
    ("0001020304050607", "B88E497AE8E6FB641B87EF622EB8F2FCA0ED95383F7FFEBE167ACF1099BA764F"),
    (
        "000102030405060708090A0B0C0D0E0F",
        "3158C1940A2FBADBD68AB661777859B94A689E4EFC375911467ADDD641835C38",
    ),
    (
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        "BD9D3D60A66B53868EAB2A5C74539A518A1F60F01EB176C60E43DEE81680B33E",
    ),
];

fn dh(s: &str) -> Vec<u8> {
    let s = s.trim();
    if s.is_empty() { Vec::new() } else { hex::decode(s).expect("valid hex") }
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(7).wrapping_add(1)).collect()
}

#[test]
fn hash256_embedded_kat() {
    for (msg_hex, md_hex) in HASH_KAT {
        let msg = dh(msg_hex);
        let expected = dh(md_hex);
        assert_eq!(AsconHash256::digest(&msg).as_slice(), expected.as_slice(), "msg={msg_hex}");
    }
}

#[test]
fn hash256_streaming_matches_one_shot() {
    let msg = pattern(100);
    let expected = AsconHash256::digest(&msg);

    // One-shot APIs agree.
    assert_eq!(AsconHash256::new().hash(&msg), expected.to_vec());
    let mut buf = [0u8; 32];
    let mut h = AsconHash256::new();
    h.update_bytes(&msg);
    h.do_final_into(&mut buf);
    assert_eq!(buf, expected);

    // Chunked update_bytes agrees for a range of chunk sizes.
    for chunk in [1usize, 7, 8, 9, 16, 33] {
        let mut hasher = AsconHash256::new();
        for piece in msg.chunks(chunk) {
            hasher.update_bytes(piece);
        }
        let mut got = [0u8; 32];
        hasher.do_final_into(&mut got);
        assert_eq!(got, expected, "chunked hash mismatch (chunk={chunk})");
    }

    // Byte-at-a-time update() agrees.
    let mut hasher = AsconHash256::new();
    for &b in &msg {
        hasher.update(b);
    }
    let mut got = [0u8; 32];
    hasher.do_final_into(&mut got);
    assert_eq!(got, expected, "byte-at-a-time hash mismatch");
}

#[test]
fn hash256_metadata_accessors() {
    assert_eq!(AsconHash256::digest_size(), 32);
    let h = AsconHash256::new();
    assert_eq!(h.output_len(), 32);
    assert_eq!(h.block_bitlen(), 64);
}

#[test]
fn hash256_trait_wrappers_match_inherent() {
    let msg = pattern(50);
    let expected = AsconHash256::digest(&msg);

    assert_eq!(AsconHash256::new().hash(&msg), expected.to_vec());

    let mut h = AsconHash256::new();
    h.do_update(&msg);
    assert_eq!(h.do_final(), expected.to_vec());

    let mut h = AsconHash256::new();
    h.do_update(&msg);
    let mut o = [0u8; 32];
    assert_eq!(h.do_final_out(&mut o), 32);
    assert_eq!(o, expected);

    let mut o2 = [0u8; 32];
    assert_eq!(AsconHash256::new().hash_out(&msg, &mut o2), 32);
    assert_eq!(o2, expected);
}

#[test]
fn hash256_unsupported_partial_ops_return_err() {
    assert!(AsconHash256::new().do_final_partial_bits(0, 3).is_err());
    let mut o = [0u8; 32];
    assert!(AsconHash256::new().do_final_partial_bits_out(0, 3, &mut o).is_err());
}
