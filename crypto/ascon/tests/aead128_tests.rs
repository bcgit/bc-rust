//! Ascon-AEAD128 tests (NIST SP 800-232).
//!
//! - A small embedded set of NIST LWC known-answer vectors (always-on correctness, no external
//!   repo required). The full sweep lives in `bc_test_data.rs`.
//! - Behavioral / contract tests (round-trips, streaming chunk-boundary equivalence, authentication
//!   failures, determinism, output-size predictors), and the shared `AeadCipher` conformance
//!   framework.

use bouncycastle_ascon::ascon_aead128::AsconAead128;
use bouncycastle_core::errors::AeadError;
use bouncycastle_core::traits::AeadCipher;
use bouncycastle_core_test_framework::aead::TestFrameworkAead;
use bouncycastle_hex as hex;

// All embedded vectors use this fixed key/nonce (the NIST LWC KAT convention).
const KEY: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
];
const NONCE: [u8; 16] = [
    0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
];

const PT_SIZES: [usize; 10] = [0, 1, 15, 16, 17, 31, 32, 33, 64, 100];
const CHUNK_SIZES: [usize; 6] = [1, 3, 7, 13, 16, 17];

/// Embedded NIST LWC Ascon-AEAD128 vectors `(plaintext, associated_data, ciphertext||tag)` in hex.
/// Key = Nonce = 000102…0F. Spans empty input, AD-only (incl. a full 32-byte AD block), partial PT
/// with AD, and a multi-block plaintext. (Counts 1, 2, 5, 33, 68, 69, 153, 1057 of
/// LWC_AEAD_KAT_128_128.txt.)
const AEAD_KAT: &[(&str, &str, &str)] = &[
    ("", "", "4427D64B8E1E1451FC445960F0839BB0"),
    ("", "00", "103AB79D913A0321287715A979BB8585"),
    ("", "00010203", "C6FF3CF70575B144B955820D9BC7685E"),
    (
        "",
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        "22133A313FBF0B38029A45870AADC542",
    ),
    ("0001", "00", "25FB41D2732019820A0F8BAB4248B35E7B0B"),
    ("0001", "0001", "49E57017A30E8073D1FA284AC8346110F89F"),
    (
        "00010203",
        "000102030405060708090A0B0C0D0E0F10111213",
        "C305EB0E9A9A7833C5F6FB36BD82F1C78C322678",
    ),
    (
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        "",
        "E770D289D2A44AEE7CD0A48ECE5274E381BAD7E163DCC4970F7873610DEBBEB1A28657F6E82FE53D08B09EFF9330BD2B",
    ),
];

fn dh(s: &str) -> Vec<u8> {
    let s = s.trim();
    if s.is_empty() { Vec::new() } else { hex::decode(s).expect("valid hex") }
}

fn ad_opt(ad: &[u8]) -> Option<&[u8]> {
    if ad.is_empty() { None } else { Some(ad) }
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(7).wrapping_add(1)).collect()
}

fn enc_oneshot(key: &[u8; 16], nonce: &[u8; 16], ad: &[u8], pt: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; pt.len() + 16];
    let n = AsconAead128::encrypt(key, nonce, ad_opt(ad), pt, &mut out);
    out.truncate(n);
    out
}

fn dec_oneshot(
    key: &[u8; 16],
    nonce: &[u8; 16],
    ad: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let mut out = vec![0u8; ct.len()];
    let n = AsconAead128::decrypt(key, nonce, ad_opt(ad), ct, &mut out)?;
    out.truncate(n);
    Ok(out)
}

fn enc_chunked(key: &[u8; 16], nonce: &[u8; 16], ad: &[u8], pt: &[u8], chunk: usize) -> Vec<u8> {
    let mut cipher = AsconAead128::new(key, nonce, ad_opt(ad), true);
    let mut out = vec![0u8; pt.len() + 16];
    let mut off = 0;
    for ch in pt.chunks(chunk.max(1)) {
        off += cipher.encrypt_update(ch, &mut out[off..]);
    }
    off += cipher.encrypt_finalize(&mut out[off..]);
    out.truncate(off);
    out
}

fn dec_chunked(
    key: &[u8; 16],
    nonce: &[u8; 16],
    ad: &[u8],
    ct: &[u8],
    chunk: usize,
) -> Result<Vec<u8>, AeadError> {
    let mut cipher = AsconAead128::new(key, nonce, ad_opt(ad), false);
    let mut out = vec![0u8; ct.len()];
    let mut off = 0;
    for ch in ct.chunks(chunk.max(1)) {
        off += cipher.decrypt_update(ch, &mut out[off..]);
    }
    off += cipher.decrypt_finalize(&mut out[off..])?;
    out.truncate(off);
    Ok(out)
}

/* -------------------------------------------------------------------------- */
/* Embedded known-answer vectors                                              */
/* -------------------------------------------------------------------------- */

#[test]
fn aead128_embedded_kat() {
    // The NIST LWC AEAD KAT convention uses Key == Nonce == 000102…0F (i.e. KEY for both).
    let kat_nonce = KEY;
    for (pt_hex, ad_hex, ct_hex) in AEAD_KAT {
        let pt = dh(pt_hex);
        let ad = dh(ad_hex);
        let expected_ct = dh(ct_hex);

        let got_ct = enc_oneshot(&KEY, &kat_nonce, &ad, &pt);
        assert_eq!(got_ct, expected_ct, "encrypt mismatch for PT={pt_hex} AD={ad_hex}");

        let got_pt =
            dec_oneshot(&KEY, &kat_nonce, &ad, &expected_ct).expect("decrypt should succeed");
        assert_eq!(got_pt, pt, "decrypt mismatch for CT={ct_hex}");
    }
}

/* -------------------------------------------------------------------------- */
/* Round-trips and AAD handling                                               */
/* -------------------------------------------------------------------------- */

#[test]
fn aead_round_trip_sizes_and_ad() {
    for &pt_len in PT_SIZES.iter() {
        let pt = pattern(pt_len);
        for ad in [Vec::new(), b"associated-data".to_vec(), pattern(40)] {
            let ct = enc_oneshot(&KEY, &NONCE, &ad, &pt);
            assert_eq!(ct.len(), pt_len + 16, "ciphertext = plaintext || 16-byte tag");
            let recovered = dec_oneshot(&KEY, &NONCE, &ad, &ct).expect("decrypt should succeed");
            assert_eq!(recovered, pt, "round-trip mismatch (pt_len={pt_len}, ad_len={})", ad.len());
        }
    }
}

#[test]
fn aead_aad_only_round_trip() {
    // Empty plaintext, non-empty AD: ciphertext is just the 16-byte tag.
    let ad = b"only-associated-data";
    let ct = enc_oneshot(&KEY, &NONCE, ad, b"");
    assert_eq!(ct.len(), 16);
    let recovered = dec_oneshot(&KEY, &NONCE, ad, &ct).expect("decrypt should succeed");
    assert!(recovered.is_empty());
}

/* -------------------------------------------------------------------------- */
/* Streaming chunk-boundary equivalence                                       */
/* -------------------------------------------------------------------------- */

#[test]
fn aead_streaming_matches_one_shot() {
    for &pt_len in PT_SIZES.iter() {
        let pt = pattern(pt_len);
        let ad = pattern(20);
        let ct_ref = enc_oneshot(&KEY, &NONCE, &ad, &pt);

        for &chunk in CHUNK_SIZES.iter() {
            let ct = enc_chunked(&KEY, &NONCE, &ad, &pt, chunk);
            assert_eq!(ct, ct_ref, "chunked encrypt mismatch (pt_len={pt_len}, chunk={chunk})");

            let pt_back = dec_chunked(&KEY, &NONCE, &ad, &ct_ref, chunk)
                .expect("chunked decrypt should pass");
            assert_eq!(pt_back, pt, "chunked decrypt mismatch (pt_len={pt_len}, chunk={chunk})");
        }
    }
}

#[test]
fn aead_chunked_aad_matches_one_shot() {
    let pt = pattern(30);
    let ad = pattern(40);
    let ct_ref = enc_oneshot(&KEY, &NONCE, &ad, &pt);

    for &chunk in CHUNK_SIZES.iter() {
        let mut e = AsconAead128::new(&KEY, &NONCE, None, true);
        for piece in ad.chunks(chunk) {
            e.process_aad_bytes(piece);
        }
        let mut out = vec![0u8; pt.len() + 16];
        let n = e.encrypt_update(&pt, &mut out);
        let m = e.encrypt_finalize(&mut out[n..]);
        out.truncate(n + m);
        assert_eq!(out, ct_ref, "chunked AAD mismatch (chunk={chunk})");
    }
}

/* -------------------------------------------------------------------------- */
/* Authentication failures                                                    */
/* -------------------------------------------------------------------------- */

fn assert_auth_failed(result: Result<Vec<u8>, AeadError>, ctx: &str) {
    match result {
        Err(AeadError::AuthenticationFailed) => {}
        other => panic!("{ctx}: expected AuthenticationFailed, got {other:?}"),
    }
}

#[test]
fn aead_rejects_tampering() {
    let pt = pattern(50);
    let ad = b"the-aad";
    let ct = enc_oneshot(&KEY, &NONCE, ad, &pt);

    // Wrong key.
    let mut bad_key = KEY;
    bad_key[0] ^= 0x01;
    assert_auth_failed(dec_oneshot(&bad_key, &NONCE, ad, &ct), "wrong key");

    // Wrong nonce.
    let mut bad_nonce = NONCE;
    bad_nonce[3] ^= 0x80;
    assert_auth_failed(dec_oneshot(&KEY, &bad_nonce, ad, &ct), "wrong nonce");

    // Modified associated data.
    assert_auth_failed(dec_oneshot(&KEY, &NONCE, b"the-AAD", &ct), "modified ad");

    // Flipped tag byte (last byte).
    let mut tag_flip = ct.clone();
    let last = tag_flip.len() - 1;
    tag_flip[last] ^= 0x01;
    assert_auth_failed(dec_oneshot(&KEY, &NONCE, ad, &tag_flip), "flipped tag");

    // Flipped ciphertext body byte.
    let mut body_flip = ct.clone();
    body_flip[0] ^= 0x01;
    assert_auth_failed(dec_oneshot(&KEY, &NONCE, ad, &body_flip), "flipped body");
}

#[test]
fn aead_short_ciphertext_is_length_error() {
    let short = [0u8; 8]; // shorter than the 16-byte tag
    let mut out = [0u8; 16];
    match AsconAead128::decrypt(&KEY, &NONCE, None, &short, &mut out) {
        Err(AeadError::InvalidLength(_)) => {}
        other => panic!("expected InvalidLength, got {other:?}"),
    }
}

/* -------------------------------------------------------------------------- */
/* Determinism / nonce sensitivity / size predictors / get_mac / Debug mask   */
/* -------------------------------------------------------------------------- */

#[test]
fn aead_is_deterministic_and_nonce_sensitive() {
    let pt = pattern(40);
    let ad = b"ctx";
    let a = enc_oneshot(&KEY, &NONCE, ad, &pt);
    let b = enc_oneshot(&KEY, &NONCE, ad, &pt);
    assert_eq!(a, b, "same (key,nonce,ad,pt) must yield identical (ct,tag)");

    let mut other_nonce = NONCE;
    other_nonce[0] ^= 0x01;
    let c = enc_oneshot(&KEY, &other_nonce, ad, &pt);
    assert_ne!(a, c, "changing the nonce must change the ciphertext (SP 800-232 R3)");
}

#[test]
fn aead_output_size_predictors() {
    for &pt_len in PT_SIZES.iter() {
        let enc = AsconAead128::new(&KEY, &NONCE, None, true);
        assert_eq!(enc.get_output_size(pt_len), pt_len + 16);
        assert_eq!(enc.get_update_output_size(pt_len), (pt_len / 16) * 16);

        let dec = AsconAead128::new(&KEY, &NONCE, None, false);
        assert_eq!(dec.get_output_size(pt_len + 16), pt_len);
    }
}

#[test]
fn aead_update_output_size_both_directions() {
    // Encryption branch: whole 16-byte blocks only, accounting for buffered bytes.
    let mut e = AsconAead128::new(&KEY, &NONCE, None, true);
    assert_eq!(e.get_update_output_size(0), 0);
    assert_eq!(e.get_update_output_size(16), 16);
    assert_eq!(e.get_update_output_size(17), 16);
    assert_eq!(e.get_update_output_size(40), 32);
    // After buffering 5 bytes (no full block emitted yet), buf_pos == 5.
    let mut out = [0u8; 64];
    assert_eq!(e.process_bytes(&[0u8; 5], &mut out), 0);
    assert_eq!(e.get_update_output_size(11), 16); // 5 + 11 = 16 -> one block
    assert_eq!(e.get_update_output_size(10), 0); //  5 + 10 = 15 -> none

    // Decryption branch: (buffered + len - tag) whole blocks, once the total reaches 32.
    let d = AsconAead128::new(&KEY, &NONCE, None, false);
    assert_eq!(d.get_update_output_size(0), 0);
    assert_eq!(d.get_update_output_size(31), 0); // < 32 -> nothing emitted yet
    assert_eq!(d.get_update_output_size(32), 16); // (32 - 16)/16 * 16
    assert_eq!(d.get_update_output_size(48), 32); // (48 - 16)/16 * 16
}

#[test]
fn aead_get_mac_returns_tag() {
    let pt = pattern(20);
    let mut e = AsconAead128::new(&KEY, &NONCE, None, true);
    let mut out = vec![0u8; pt.len() + 16];
    let n = e.encrypt_update(&pt, &mut out);
    let m = e.encrypt_finalize(&mut out[n..]);
    let total = n + m;
    let tag = AeadCipher::get_mac(&e);
    assert_ne!(tag, [0u8; 16]);
    assert_eq!(&tag[..], &out[total - 16..total], "get_mac must equal the appended tag");
}

#[test]
fn aead_debug_display_are_masked() {
    let e = AsconAead128::new(&KEY, &NONCE, None, true);
    assert!(format!("{e:?}").contains("masked"));
    assert!(format!("{e}").contains("masked"));
}

#[test]
fn aead_aad_via_trait_methods() {
    // Drive AAD through the AeadCipher *trait* methods (the inherent process_aad_bytes otherwise
    // shadows them), covering the process_aad_byte / process_aad_bytes delegators.
    let pt = pattern(24);
    let ad = pattern(20);
    let ct_ref = enc_oneshot(&KEY, &NONCE, &ad, &pt);

    // Whole AAD via the trait method.
    let mut e = AsconAead128::new(&KEY, &NONCE, None, true);
    AeadCipher::process_aad_bytes(&mut e, &ad);
    let mut out = vec![0u8; pt.len() + 16];
    let n = AeadCipher::process_bytes(&mut e, &pt, &mut out);
    let m = AeadCipher::do_final(e, &mut out[n..]).unwrap();
    out.truncate(n + m);
    assert_eq!(out, ct_ref, "AAD via trait process_aad_bytes");

    // Byte-at-a-time AAD via the trait method (crosses the 16-byte AAD block boundary).
    let mut e = AsconAead128::new(&KEY, &NONCE, None, true);
    for &b in &ad {
        AeadCipher::process_aad_byte(&mut e, b);
    }
    let mut out = vec![0u8; pt.len() + 16];
    let n = AeadCipher::process_bytes(&mut e, &pt, &mut out);
    let m = AeadCipher::do_final(e, &mut out[n..]).unwrap();
    out.truncate(n + m);
    assert_eq!(out, ct_ref, "AAD via trait process_aad_byte");
}

/* -------------------------------------------------------------------------- */
/* AeadCipher trait conformance (shared core-test-framework)                  */
/* -------------------------------------------------------------------------- */

#[test]
fn aead128_trait_framework() {
    let ad = b"framework-associated-data";
    let fw = TestFrameworkAead::new();

    for &pt_len in PT_SIZES.iter() {
        let pt: Vec<u8> = (0..pt_len).map(|i| i as u8).collect();

        fw.test_aead(
            || AsconAead128::new(&KEY, &NONCE, Some(ad), true),
            || AsconAead128::new(&KEY, &NONCE, Some(ad), false),
            &pt,
        );

        fw.test_aead(
            || AsconAead128::new(&KEY, &NONCE, None, true),
            || AsconAead128::new(&KEY, &NONCE, None, false),
            &pt,
        );
    }
}
