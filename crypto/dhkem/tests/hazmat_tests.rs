//! The labelled KDF's buffer contracts. Its values are pinned by the DHKEM and HPKE vector
//! suites; these are the rules a direct caller meets.

use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_dhkem::hazmat::{MAX_NH, labeled_expand, labeled_extract_out, salt_key};
use bouncycastle_sha2::SHA256;

/// `labeled_extract_out` writes Nh bytes and leaves the rest of a stale buffer zero.
#[test]
fn labeled_extract_out_clears_the_buffer_past_the_prk() {
    let mut out = [0xFFu8; MAX_NH];
    let nh = labeled_extract_out::<SHA256>(
        b"KEM\x00\x20",
        &salt_key(&[]),
        b"label",
        &[b"ikm"],
        &mut out,
    );
    assert_eq!(nh, 32);
    assert_ne!(out[..32], [0xFFu8; 32]);
    assert_eq!(out[32..], [0u8; 32]);
    // The input keying material is the concatenation of its parts.
    let mut joined = [0xFFu8; MAX_NH];
    labeled_extract_out::<SHA256>(
        b"KEM\x00\x20",
        &salt_key(&[]),
        b"label",
        &[b"ik", b"m"],
        &mut joined,
    );
    assert_eq!(out, joined);
}

fn prk() -> KeyMaterial<MAX_NH> {
    KeyMaterial::<MAX_NH>::from_bytes_as_type(&[0x5A; 32], KeyType::MACKey).unwrap()
}

/// The longest output HKDF-SHA256 gives, 255 blocks, is produced.
#[test]
fn labeled_expand_takes_255_blocks() {
    let mut out = vec![0u8; 255 * 32];
    labeled_expand::<SHA256>(b"KEM\x00\x20", &prk(), b"label", &[], &mut out);
    assert_ne!(out[..32], out[32..64]);
    assert_ne!(out[254 * 32..], [0u8; 32]);
}

/// One byte more would wrap the block counter, so it is a panic and not a wrong answer.
#[test]
#[should_panic(expected = "L is too long")]
fn labeled_expand_refuses_more_than_255_blocks() {
    let mut out = vec![0u8; 255 * 32 + 1];
    labeled_expand::<SHA256>(b"KEM\x00\x20", &prk(), b"label", &[], &mut out);
}
