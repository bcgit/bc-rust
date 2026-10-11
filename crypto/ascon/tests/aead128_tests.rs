//! Ascon-AEAD128 tests (NIST SP 800-232).
//!
//! - A small embedded set of NIST LWC known-answer vectors (always-on correctness, no external
//!   repo required). The full sweep lives in `bc_test_data.rs`.
//! - Behavioral / contract tests (round-trips, streaming chunk-boundary equivalence, authentication
//!   failures, determinism). The vectors fix the nonce, and the API only ever generates one, so
//!   every encryption here goes through a `*_rng` entry point with a `FixedSeedRNG` that yields
//!   the vector's nonce.
//! - The shared conformance frameworks (`core-test-framework`), which exercise the
//!   `AEADCipherEncryptor`/`AEADCipherDecryptor` pair in both the detached-tag and the inline
//!   `ciphertext || tag` layouts -- the latter also through the
//!   `SymmetricCipherEncryptor`/`SymmetricCipherDecryptor` traits they extend.

use bouncycastle_ascon::Ascon_AEAD128;
use bouncycastle_ascon::ascon_aead128::SUSPENDED_ASCON_AEAD128_STATE_LEN;
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::errors::{SuspendableError, SymmetricCipherError};
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, SuspendableKeyed, SymmetricCipherDecryptor,
    SymmetricCipherEncryptor,
};
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_core_test_framework::aead::{
    TestFrameworkAEADCipher, TestFrameworkAEADTaggedLayout,
};
use bouncycastle_core_test_framework::suspendable_state::TestFrameworkSuspendableKeyedState;
use bouncycastle_hex as hex;

type Enc = Ascon_AEAD128<Encrypting>;
type Dec = Ascon_AEAD128<Decrypting>;

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

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(7).wrapping_add(1)).collect()
}

/// Build a `KeyMaterial<16>` suitable for `Ascon_AEAD128`. The NIST LWC KAT vectors include an
/// all-zero key (Count=1), which `KeyMaterial::from_bytes_as_type` would otherwise tag
/// `KeyType::Zeroized` / `SecurityStrength::None`; force the type/strength the way a caller who
/// knows the provenance of the key would (see `cli/src/helpers.rs::parse_seed`).
fn key_material(key: &[u8; 16]) -> KeyMaterial<16> {
    let mut km = KeyMaterial::<16>::from_bytes_as_type(key, KeyType::SymmetricCipherKey).unwrap();
    do_hazardous_operations(&mut km, |k| {
        k.set_key_type(KeyType::SymmetricCipherKey)?;
        k.set_security_strength(SecurityStrength::_128bit)
    })
    .unwrap();
    km
}

/// An RNG whose first 16 bytes are `nonce`, so an encryption through the trait API runs under
/// the vector's nonce rather than a fresh one.
fn rng_for(nonce: &[u8; 16]) -> FixedSeedRNG<16> {
    FixedSeedRNG::<16>::new(*nonce)
}

/// One-shot encryption into the inline `ciphertext || tag` layout under `nonce`.
fn enc_oneshot(key: &[u8; 16], nonce: &[u8; 16], ad: &[u8], pt: &[u8]) -> Vec<u8> {
    let km = key_material(key);
    let mut out = vec![0u8; Enc::encrypt_out_len(pt.len())];
    let (got_nonce, n) =
        Enc::encrypt_with_aad_rng_out(&km, &mut rng_for(nonce), ad, pt, &mut out).unwrap();
    assert_eq!(&got_nonce, nonce, "the fixed RNG must supply the nonce verbatim");
    out.truncate(n);
    out
}

/// One-shot decryption of the inline layout.
fn dec_oneshot(
    key: &[u8; 16],
    nonce: &[u8; 16],
    ad: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>, SymmetricCipherError> {
    Dec::decrypt_with_aad(&key_material(key), nonce, ad, ct)
}

/// Streaming encryption in `chunk`-byte pieces, the tag taken detached and appended, so the
/// result is comparable with [`enc_oneshot`].
fn enc_chunked(key: &[u8; 16], nonce: &[u8; 16], ad: &[u8], pt: &[u8], chunk: usize) -> Vec<u8> {
    let km = key_material(key);
    let (mut e, _) = Enc::do_encrypt_init_rng(&km, &mut rng_for(nonce)).unwrap();
    e.do_update_aad(ad).unwrap();
    let mut out = Vec::with_capacity(pt.len() + 16);
    for piece in pt.chunks(chunk.max(1)) {
        let mut buf = vec![0u8; e.do_encrypt_out_len(piece.len())];
        let n = e.do_encrypt_out(piece, &mut buf).unwrap();
        out.extend_from_slice(&buf[..n]);
    }
    let (last, last_len, tag) = e.do_encrypt_final_detachedtag().unwrap();
    out.extend_from_slice(&last[..last_len]);
    out.extend_from_slice(&tag);
    out
}

/// Streaming decryption of the inline layout in `chunk`-byte pieces: the decryptor holds the
/// possible tag back itself and checks it at `do_decrypt_final`.
fn dec_chunked(
    key: &[u8; 16],
    nonce: &[u8; 16],
    ad: &[u8],
    ct: &[u8],
    chunk: usize,
) -> Result<Vec<u8>, SymmetricCipherError> {
    let mut d = Dec::do_decrypt_init(&key_material(key), nonce)?;
    d.do_update_aad(ad)?;
    let mut out = Vec::with_capacity(ct.len());
    for piece in ct.chunks(chunk.max(1)) {
        let mut buf = vec![0u8; d.do_decrypt_out_len(piece.len())];
        let n = d.do_decrypt_out(piece, &mut buf)?;
        out.extend_from_slice(&buf[..n]);
    }
    let (last, last_len) = d.do_decrypt_final()?;
    out.extend_from_slice(&last[..last_len]);
    Ok(out)
}

/// Streaming decryption with the tag detached: `ct` is ciphertext only, and the held-back bytes
/// come out of `do_decrypt_final_detachedtag_out`.
fn dec_chunked_detached(
    key: &[u8; 16],
    nonce: &[u8; 16],
    ad: &[u8],
    ct: &[u8],
    tag: &[u8; 16],
    chunk: usize,
) -> Result<Vec<u8>, SymmetricCipherError> {
    let mut d = Dec::do_decrypt_init(&key_material(key), nonce)?;
    d.do_update_aad(ad)?;
    let mut out = Vec::with_capacity(ct.len());
    for piece in ct.chunks(chunk.max(1)) {
        let mut buf = vec![0u8; d.do_decrypt_out_len(piece.len())];
        let n = d.do_decrypt_out(piece, &mut buf)?;
        out.extend_from_slice(&buf[..n]);
    }
    let mut last = [0u8; 16];
    let last_len = d.do_decrypt_final_detachedtag_out(tag, &mut last)?;
    out.extend_from_slice(&last[..last_len]);
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
    let km = key_material(&KEY);

    for &chunk in CHUNK_SIZES.iter() {
        let (mut e, _) = Enc::do_encrypt_init_rng(&km, &mut rng_for(&NONCE)).unwrap();
        for piece in ad.chunks(chunk) {
            e.do_update_aad(piece).unwrap();
        }
        let mut out = vec![0u8; Enc::encrypt_out_len(pt.len())];
        let written = e.do_encrypt_out(&pt, &mut out).unwrap();
        let mut last = [0u8; 16];
        let last_len = e.do_encrypt_final_out(&mut last).unwrap();
        out[written..written + last_len].copy_from_slice(&last[..last_len]);
        assert_eq!(out, ct_ref, "chunked AAD mismatch (chunk={chunk})");
    }
}

/* -------------------------------------------------------------------------- */
/* Streaming chunk sweep                                                      */
/* -------------------------------------------------------------------------- */

/// Every (plaintext length, AAD length, chunking) combination streams to the one-shot's bytes,
/// and streams back through both finalizations: inline, and with the tag detached.
#[test]
fn aead_streaming_chunk_sweep() {
    for pt_len in 0..=40 {
        let pt = pattern(pt_len);
        for ad_len in [0, 1, 15, 16, 17, 33] {
            let ad = pattern(ad_len);
            let ct_ref = enc_oneshot(&KEY, &NONCE, &ad, &pt);
            let (body, tag) = ct_ref.split_at(pt_len);
            let tag: [u8; 16] = tag.try_into().unwrap();

            for &chunk in [1, 2, 7, 15, 16, 17, 31, 32, 1024].iter() {
                let ctx = format!("pt_len={pt_len} ad_len={ad_len} chunk={chunk}");
                assert_eq!(enc_chunked(&KEY, &NONCE, &ad, &pt, chunk), ct_ref, "{ctx}");
                assert_eq!(dec_chunked(&KEY, &NONCE, &ad, &ct_ref, chunk).unwrap(), pt, "{ctx}");
                assert_eq!(
                    dec_chunked_detached(&KEY, &NONCE, &ad, body, &tag, chunk).unwrap(),
                    pt,
                    "{ctx}"
                );
            }
        }
    }
}

#[test]
fn detached_final_rejects_wrong_tag_and_zeroizes_its_buffer() {
    let km = key_material(&KEY);
    let pt = pattern(20);
    let mut d = Dec::do_decrypt_init(&km, &NONCE).unwrap();
    let mut released = [0u8; 20];
    // 4 of the 20 bytes come out now, 16 are held back as the possible tag.
    assert_eq!(d.do_decrypt_out(&pt, &mut released).unwrap(), 4);
    let mut last = [0xAAu8; 16];
    assert!(matches!(
        d.do_decrypt_final_detachedtag_out(&[0xFFu8; 16], &mut last),
        Err(SymmetricCipherError::AEADTagCheckFailed)
    ));
    assert_eq!(last, [0u8; 16], "the held-back bytes must not be released on a bad tag");
}

/* -------------------------------------------------------------------------- */
/* Authentication failures                                                    */
/* -------------------------------------------------------------------------- */

fn assert_auth_failed(result: Result<Vec<u8>, SymmetricCipherError>, ctx: &str) {
    match result {
        Err(SymmetricCipherError::AEADTagCheckFailed) => {}
        other => panic!("{ctx}: expected AEADTagCheckFailed, got {other:?}"),
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
fn aead_tamper_leaves_no_plaintext_in_output_buffer() {
    let pt = pattern(20);
    let ad = b"ctx";
    let ct = enc_oneshot(&KEY, &NONCE, ad, &pt);
    let mut tampered = ct.clone();
    tampered[0] ^= 0x01;

    let km = key_material(&KEY);
    let mut out = vec![0xAAu8; pt.len()];
    let n = Dec::decrypt_with_aad_out(&km, &NONCE, ad, &tampered, &mut out);
    assert!(matches!(n, Err(SymmetricCipherError::AEADTagCheckFailed)));
    assert!(out.iter().all(|&b| b == 0), "output buffer must be zeroized on tag failure");
}

#[test]
fn aead_short_ciphertext_is_error() {
    let short = [0u8; 8]; // shorter than the 16-byte tag
    let km = key_material(&KEY);
    let mut out = [0u8; 16];
    match Dec::decrypt_with_aad_out(&km, &NONCE, &[], &short, &mut out) {
        Err(SymmetricCipherError::DecryptionFailed) => {}
        other => panic!("expected DecryptionFailed for short ciphertext, got {other:?}"),
    }

    // A ciphertext of exactly 16 bytes -- an empty plaintext plus its tag -- is the boundary case
    // and must decrypt, not be rejected as shorter than the tag.
    let empty_ct = enc_oneshot(&KEY, &NONCE, &[], &[]);
    assert_eq!(empty_ct.len(), 16);
    let mut empty_pt_buf = [0u8; 0];
    assert_eq!(
        Dec::decrypt_with_aad_out(&km, &NONCE, &[], &empty_ct, &mut empty_pt_buf).unwrap(),
        0
    );
}

/* -------------------------------------------------------------------------- */
/* Determinism / nonce sensitivity / Debug mask                               */
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
fn aead_debug_display_are_masked() {
    let km = key_material(&KEY);
    let (e, _) = Enc::do_encrypt_init(&km).unwrap();
    assert!(format!("{e:?}").contains("masked"));
    assert!(format!("{e}").contains("masked"));
    let d = Dec::do_decrypt_init(&km, &NONCE).unwrap();
    assert!(format!("{d:?}").contains("masked"));
    assert!(format!("{d}").contains("masked"));
}

/* -------------------------------------------------------------------------- */
/* Trait conformance (shared core-test-framework)                             */
/* -------------------------------------------------------------------------- */

/// The whole AEAD contract -- `update_out_len` correctness, chunking-independence of both AAD and
/// data, the AAD-after-data `StateError`, tamper detection, the key-type and strength policy --
/// against the generic conformance suite rather than hand-written here.
#[test]
fn aead128_encryptor_decryptor_trait_framework() {
    TestFrameworkAEADCipher::new().test_encryptor_decryptor::<16, 16, 16, 16, Enc, Dec>();
}

/// The inline `ciphertext || tag` layout -- where the tag lands, what the decryptor holds back,
/// and how an input shorter than the tag is refused -- at every length across a few multiples of
/// the tag and under every chunking.
#[test]
fn aead128_inline_tag_layout_conforms_at_every_edge() {
    TestFrameworkAEADTaggedLayout::new().test::<16, 16, 16, 16, Enc, Dec>();
}

/// The two tag layouts must agree byte for byte: `direct_ciphertext || direct_tag`, produced by
/// streaming and taking the tag from `do_encrypt_final_detachedtag_out`, must equal what the
/// inline layout produces for the same key, nonce (driven by the same RNG stream), AAD and
/// message -- through both `encrypt_with_aad_out` and the inherited `do_encrypt_final` -- and
/// either must decrypt back to the original plaintext.
#[test]
fn aead128_tagged_and_direct_layouts_agree() {
    let km = key_material(&KEY);
    let aad = b"tagged-layout-aad";
    for pt_len in [0usize, 1, 15, 16, 17, 40] {
        let pt = pattern(pt_len);
        let pinned = [0x11u8; 16];

        // detached tag, streamed
        let (mut direct_enc, direct_nonce) =
            Enc::do_encrypt_init_rng(&km, &mut rng_for(&pinned)).unwrap();
        direct_enc.do_update_aad(aad).unwrap();
        let mut direct_ct = vec![0u8; pt.len()];
        direct_enc.do_encrypt_out(&pt, &mut direct_ct).unwrap();
        let mut unused = [0u8; 16];
        let (flushed, direct_tag) =
            direct_enc.do_encrypt_final_detachedtag_out(&mut unused).unwrap();
        assert_eq!(flushed, 0, "Ascon-AEAD128 holds nothing back to flush");
        let mut direct_inline = direct_ct.clone();
        direct_inline.extend_from_slice(&direct_tag);

        // inline tag, streamed
        let (mut tagged_enc, tagged_nonce) =
            Enc::do_encrypt_init_rng(&km, &mut rng_for(&pinned)).unwrap();
        tagged_enc.do_update_aad(aad).unwrap();
        let mut tagged_out = vec![0u8; Enc::encrypt_out_len(pt.len())];
        let written = tagged_enc.do_encrypt_out(&pt, &mut tagged_out).unwrap();
        let mut last = [0u8; 16];
        let last_len = tagged_enc.do_encrypt_final_out(&mut last).unwrap();
        tagged_out[written..written + last_len].copy_from_slice(&last[..last_len]);
        tagged_out.truncate(written + last_len);

        assert_eq!(direct_nonce, tagged_nonce, "pt_len {pt_len}: same RNG stream, same nonce");
        assert_eq!(direct_inline, tagged_out, "pt_len {pt_len}: inline layout must agree");

        // inline tag, one-shot: its own generated nonce, so what must match is the round trip
        // and the length, not the bytes.
        let mut one_shot = vec![0u8; Enc::encrypt_out_len(pt.len())];
        let (one_nonce, one_len) = Enc::encrypt_with_aad_out(&km, aad, &pt, &mut one_shot).unwrap();
        assert_eq!(one_len, tagged_out.len(), "pt_len {pt_len}: one-shot writes the same length");
        let mut one_back = vec![0u8; Dec::decrypt_out_len(one_len)];
        let one_n =
            Dec::decrypt_with_aad_out(&km, &one_nonce, aad, &one_shot[..one_len], &mut one_back)
                .unwrap();
        assert_eq!(&one_back[..one_n], &pt[..], "pt_len {pt_len}: one-shot round trip");

        // ...and all of it decrypts back, each through its own view. The decryptor holds the
        // last 16 bytes back either way; detached, `do_decrypt_final_detachedtag_out` releases
        // them.
        let mut direct_dec = Dec::do_decrypt_init(&km, &direct_nonce).unwrap();
        direct_dec.do_update_aad(aad).unwrap();
        let mut direct_pt = vec![0u8; direct_ct.len()];
        let got = direct_dec.do_decrypt_out(&direct_ct, &mut direct_pt).unwrap();
        assert_eq!(got, pt_len.saturating_sub(16), "pt_len {pt_len}: the last 16 bytes are held");
        let mut last = [0u8; 16];
        let last_len = direct_dec.do_decrypt_final_detachedtag_out(&direct_tag, &mut last).unwrap();
        assert_eq!(got + last_len, pt_len, "pt_len {pt_len}: detached final releases the rest");
        direct_pt[got..].copy_from_slice(&last[..last_len]);
        assert_eq!(direct_pt, pt, "pt_len {pt_len}: direct decrypt round trip");

        let mut tagged_dec = Dec::do_decrypt_init(&km, &tagged_nonce).unwrap();
        tagged_dec.do_update_aad(aad).unwrap();
        let mut tagged_pt = vec![0u8; tagged_out.len()];
        let got = tagged_dec.do_decrypt_out(&tagged_out, &mut tagged_pt).unwrap();
        assert_eq!(got, pt_len, "pt_len {pt_len}: all but the tag is released");
        let (_, data_len) = tagged_dec.do_decrypt_final().unwrap();
        assert_eq!(data_len, 0, "pt_len {pt_len}: nothing but the tag was held back");
        assert_eq!(&tagged_pt[..got], &pt[..], "pt_len {pt_len}: tagged decrypt round trip");

        let mut one_pt = vec![0u8; Dec::decrypt_out_len(tagged_out.len())];
        let n =
            Dec::decrypt_with_aad_out(&km, &tagged_nonce, aad, &tagged_out, &mut one_pt).unwrap();
        assert_eq!(&one_pt[..n], &pt[..], "pt_len {pt_len}: streamed ciphertext, one-shot decrypt");
    }
}

/// With no associated data, the pair used purely as a [`SymmetricCipherEncryptor`] /
/// [`SymmetricCipherDecryptor`] -- nonce driven to the KAT's by a fixed RNG -- reproduces the
/// embedded NIST LWC vectors' `ciphertext || tag`, and decrypts them back.
#[test]
fn aead128_symmetric_cipher_view_matches_kat() {
    let km = key_material(&KEY);
    // The NIST LWC AEAD KAT convention uses Key == Nonce == 000102…0F (i.e. KEY for both).
    let kat_nonce = KEY;
    let mut tested = 0;
    for (pt_hex, ad_hex, ct_hex) in AEAD_KAT.iter().filter(|(_, ad, _)| ad.is_empty()) {
        let pt = dh(pt_hex);
        let expected = dh(ct_hex);
        assert!(dh(ad_hex).is_empty());

        let mut ct = vec![0u8; Enc::encrypt_out_len(pt.len())];
        let (nonce, n) = Enc::encrypt_rng_out(&km, &mut rng_for(&kat_nonce), &pt, &mut ct).unwrap();
        assert_eq!(nonce, kat_nonce);
        assert_eq!(&ct[..n], &expected[..], "pt {pt_hex}: SymmetricCipherEncryptor view vs KAT");

        let recovered = Dec::decrypt(&km, &kat_nonce, &expected).unwrap();
        assert_eq!(recovered, pt, "pt {pt_hex}: SymmetricCipherDecryptor view vs KAT");
        tested += 1;
    }
    assert!(tested >= 2, "the embedded KATs must include no-AD vectors");
}

/* -------------------------------------------------------------------------- */
/* Suspend / resume                                                           */
/* -------------------------------------------------------------------------- */

// Byte offsets into the serialized state, after the 3-byte library version prefix: see the
// layout on `SUSPENDED_ASCON_AEAD128_STATE_LEN`.
const STATE_TAG_AT: usize = 3;
const POS_AT: usize = STATE_TAG_AT + 1 + 40;
const PHASE_AT: usize = POS_AT + 1;
const TAIL_LEN_AT: usize = SUSPENDED_ASCON_AEAD128_STATE_LEN - 1;

/// Encrypt part of the plaintext, suspend, resume with the re-supplied key, finish, and confirm
/// the output matches a one-shot encryption. The key is never part of the serialized state.
#[test]
fn aead128_encryptor_suspends_and_resumes() {
    let pt = pattern(40);
    let ad = b"suspend-ad";
    let ct_ref = enc_oneshot(&KEY, &NONCE, ad, &pt);
    let km = key_material(&KEY);

    let (mut e, _) = Enc::do_encrypt_init_rng(&km, &mut rng_for(&NONCE)).unwrap();
    e.do_update_aad(ad).unwrap();
    let mut out = vec![0u8; Enc::encrypt_out_len(pt.len())];
    e.do_encrypt_out(&pt[..18], &mut out[..18]).unwrap();

    TestFrameworkSuspendableKeyedState::new().test(&e, &km);

    let serialized = e.suspend();
    let mut resumed = Enc::from_suspended(serialized, &km).unwrap();
    resumed.do_encrypt_out(&pt[18..], &mut out[18..pt.len()]).unwrap();
    let mut last = [0u8; 16];
    let last_len = resumed.do_encrypt_final_out(&mut last).unwrap();
    out[pt.len()..].copy_from_slice(&last[..last_len]);
    assert_eq!(out, ct_ref, "resumed AEAD ciphertext must match one-shot encryption");

    // A corrupted state tag must be rejected.
    let mut busted = serialized;
    busted[STATE_TAG_AT] ^= 0xFF;
    assert!(matches!(Enc::from_suspended(busted, &km), Err(SuspendableError::InvalidData)));

    // An unknown phase discriminant must be rejected.
    let mut bad_phase = serialized;
    bad_phase[PHASE_AT] = 200;
    assert!(matches!(Enc::from_suspended(bad_phase, &km), Err(SuspendableError::InvalidData)));

    // A nonzero byte position (18 bytes in, pos = 2) while claiming the Init phase must be
    // rejected.
    let mut inconsistent = serialized;
    assert_eq!(inconsistent[POS_AT], 2);
    inconsistent[PHASE_AT] = 0;
    assert!(matches!(Enc::from_suspended(inconsistent, &km), Err(SuspendableError::InvalidData)));

    // pos >= RATE (16) must be rejected.
    let mut bad_pos = serialized;
    bad_pos[POS_AT] = 16;
    assert!(matches!(Enc::from_suspended(bad_pos, &km), Err(SuspendableError::InvalidData)));

    // A tail longer than the tag must be rejected, as must a tail outside the Data phase.
    let mut long_tail = serialized;
    long_tail[TAIL_LEN_AT] = 17;
    assert!(matches!(Enc::from_suspended(long_tail, &km), Err(SuspendableError::InvalidData)));
    let mut early_tail = serialized;
    early_tail[PHASE_AT] = 1;
    early_tail[TAIL_LEN_AT] = 1;
    assert!(matches!(Enc::from_suspended(early_tail, &km), Err(SuspendableError::InvalidData)));
}

/// The decryptor's suspended state carries the bytes it is holding back as a possible tag:
/// suspend after a partial stream, resume, finish, and confirm the plaintext.
#[test]
fn aead128_decryptor_suspends_and_resumes_with_its_tail() {
    let pt = pattern(40);
    let ad = b"suspend-ad";
    let ct = enc_oneshot(&KEY, &NONCE, ad, &pt);
    let km = key_material(&KEY);

    let mut d = Dec::do_decrypt_init(&km, &NONCE).unwrap();
    d.do_update_aad(ad).unwrap();
    let mut out = Vec::with_capacity(pt.len());
    let mut buf = vec![0u8; d.do_decrypt_out_len(18)];
    let n = d.do_decrypt_out(&ct[..18], &mut buf).unwrap();
    assert_eq!(n, 2, "18 bytes in: 2 released, 16 held back");
    out.extend_from_slice(&buf[..n]);

    TestFrameworkSuspendableKeyedState::new().test(&d, &km);

    let serialized = d.suspend();
    assert_eq!(serialized[TAIL_LEN_AT], 16, "the held-back tail is in the state");
    let mut resumed = Dec::from_suspended(serialized, &km).unwrap();
    let mut buf = vec![0u8; resumed.do_decrypt_out_len(ct.len() - 18)];
    let n = resumed.do_decrypt_out(&ct[18..], &mut buf).unwrap();
    out.extend_from_slice(&buf[..n]);
    let (last, last_len) = resumed.do_decrypt_final().unwrap();
    out.extend_from_slice(&last[..last_len]);
    assert_eq!(out, pt, "resumed decryption must recover the plaintext");
}
