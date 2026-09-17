//! Ascon-AEAD128 tests (NIST SP 800-232).
//!
//! - A small embedded set of NIST LWC known-answer vectors (always-on correctness, no external
//!   repo required). The full sweep lives in `bc_test_data.rs`.
//! - Behavioral / contract tests (round-trips, streaming chunk-boundary equivalence, authentication
//!   failures, determinism), driven through the inherent explicit-nonce API.
//! - The shared `AEADCipher` conformance framework (`core-test-framework`), which exercises the
//!   generic `SymmetricCipher` / `AEADCipher` trait surface with internally-generated nonces.

use bouncycastle_ascon::ascon_aead128::AsconAead128;
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::key_material::{
    KeyMaterial, KeyMaterialTrait, KeyType, do_hazardous_operations,
};
use bouncycastle_core::traits::SecurityStrength;
use bouncycastle_core_test_framework::symmetric_ciphers::TestFrameworkAEADCipher;
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

/// Build a `KeyMaterial<16>` suitable for `AsconAead128`. The NIST LWC KAT vectors include an
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

fn enc_oneshot(key: &[u8; 16], nonce: &[u8; 16], ad: &[u8], pt: &[u8]) -> Vec<u8> {
    let km = key_material(key);
    let mut out = vec![0u8; pt.len() + 16];
    let n = AsconAead128::encrypt(&km, nonce, ad_opt(ad), pt, &mut out).unwrap();
    out.truncate(n);
    out
}

fn dec_oneshot(
    key: &[u8; 16],
    nonce: &[u8; 16],
    ad: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>, SymmetricCipherError> {
    let km = key_material(key);
    let mut out = vec![0u8; ct.len()];
    let n = AsconAead128::decrypt(&km, nonce, ad_opt(ad), ct, &mut out)?;
    out.truncate(n);
    Ok(out)
}

fn enc_chunked(key: &[u8; 16], nonce: &[u8; 16], ad: &[u8], pt: &[u8], chunk: usize) -> Vec<u8> {
    let km = key_material(key);
    let mut cipher = AsconAead128::new(&km, nonce, ad_opt(ad), true).unwrap();
    let mut out = vec![0u8; pt.len() + 16];
    out[..pt.len()].copy_from_slice(pt);

    let chunk = chunk.max(1);
    let mut off = 0;
    while off < pt.len() {
        let end = (off + chunk).min(pt.len());
        cipher.do_encrypt_update(&mut out[off..end]);
        off = end;
    }
    let tag = cipher.do_encrypt_final();
    out[pt.len()..].copy_from_slice(&tag);
    out
}

fn dec_chunked(
    key: &[u8; 16],
    nonce: &[u8; 16],
    ad: &[u8],
    ct: &[u8],
    chunk: usize,
) -> Result<Vec<u8>, SymmetricCipherError> {
    let km = key_material(key);
    let mut cipher = AsconAead128::new(&km, nonce, ad_opt(ad), false).unwrap();
    let pt_len = ct.len() - 16;
    let mut out = vec![0u8; pt_len];
    out.copy_from_slice(&ct[..pt_len]);

    let chunk = chunk.max(1);
    let mut off = 0;
    while off < pt_len {
        let end = (off + chunk).min(pt_len);
        cipher.do_decrypt_update(&mut out[off..end]);
        off = end;
    }
    // infallible: ct.len() - pt_len == 16 by construction above.
    let tag: [u8; 16] = ct[pt_len..].try_into().unwrap();
    cipher.do_decrypt_final(&tag)?;
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
        let mut e = AsconAead128::new(&km, &NONCE, None, true).unwrap();
        for piece in ad.chunks(chunk) {
            e.do_update_aad(piece);
        }
        let mut out = vec![0u8; pt.len() + 16];
        out[..pt.len()].copy_from_slice(&pt);
        e.do_encrypt_update(&mut out[..pt.len()]);
        let tag = e.do_encrypt_final();
        out[pt.len()..].copy_from_slice(&tag);
        assert_eq!(out, ct_ref, "chunked AAD mismatch (chunk={chunk})");
    }
}

/* -------------------------------------------------------------------------- */
/* Trait-driven streaming sweep (this is what would have caught F1/F2)        */
/* -------------------------------------------------------------------------- */

#[test]
fn aead_trait_streaming_sweep() {
    use bouncycastle_core::traits::AEADCipher;

    let km = key_material(&KEY);
    for pt_len in 0..=40 {
        let pt = pattern(pt_len);
        for ad_len in [0, 1, 15, 16, 17, 33] {
            let ad = pattern(ad_len);
            let ad_opt_ = ad_opt(&ad);
            let ct_ref = enc_oneshot(&KEY, &NONCE, &ad, &pt);
            let (ct_ref_body, tag_ref) = ct_ref.split_at(pt_len);

            for &chunk in [1, 2, 7, 15, 16, 17, 31, 32, 1024].iter() {
                let mut e = AsconAead128::new(&km, &NONCE, ad_opt_, true).unwrap();
                let mut out = pt.clone();
                let chunk = chunk.max(1);
                let mut off = 0;
                while off < out.len() {
                    let end = (off + chunk).min(out.len());
                    e.do_encrypt_update(&mut out[off..end]);
                    off = end;
                }
                let tag = e.do_aead_encrypt_final().unwrap();
                assert_eq!(out, ct_ref_body, "pt_len={pt_len} ad_len={ad_len} chunk={chunk}");
                assert_eq!(tag, tag_ref, "pt_len={pt_len} ad_len={ad_len} chunk={chunk}");

                let mut d = AsconAead128::new(&km, &NONCE, ad_opt_, false).unwrap();
                let mut back = ct_ref_body.to_vec();
                let mut off = 0;
                while off < back.len() {
                    let end = (off + chunk).min(back.len());
                    d.do_decrypt_update(&mut back[off..end]);
                    off = end;
                }
                let tag_arr: [u8; 16] = tag_ref.try_into().unwrap();
                d.do_aead_decrypt_final(&tag_arr).unwrap();
                assert_eq!(back, pt, "pt_len={pt_len} ad_len={ad_len} chunk={chunk}");
            }
        }
    }
}

#[test]
fn do_aead_decrypt_final_rejects_wrong_tag() {
    use bouncycastle_core::traits::AEADCipher;

    let km = key_material(&KEY);
    let pt = pattern(20);
    let mut d = AsconAead128::new(&km, &NONCE, None, false).unwrap();
    let mut buf = pt.clone();
    d.do_decrypt_update(&mut buf);
    let wrong_tag = [0xFFu8; 16];
    assert!(matches!(
        d.do_aead_decrypt_final(&wrong_tag),
        Err(SymmetricCipherError::AEADTagCheckFailed)
    ));
}

/* -------------------------------------------------------------------------- */
/* std-only Vec-returning trait wrappers                                      */
/* -------------------------------------------------------------------------- */

// `TestFrameworkSymmetricCipher`/`TestFrameworkAEADCipher` only exercise the `_out` (buffer-based)
// entry points, so the `#[cfg(feature = "std")]` `Vec`-returning wrappers (`encrypt`, `decrypt`,
// `aead_encrypt`, `aead_decrypt`) are otherwise never called by any test.
#[test]
fn aead128_std_vec_wrappers_round_trip() {
    use bouncycastle_core::traits::{AEADCipher, SymmetricCipher};

    let km = key_material(&KEY);
    let msg = pattern(40);

    let (nonce, ct) = <AsconAead128 as SymmetricCipher<16, 16>>::encrypt(&km, &msg).unwrap();
    assert_eq!(ct.len(), msg.len() + 16);
    let pt = <AsconAead128 as SymmetricCipher<16, 16>>::decrypt(&km, nonce, &ct).unwrap();
    assert_eq!(pt, msg);

    let (nonce, ct, tag) =
        <AsconAead128 as AEADCipher<16, 16, 16>>::aead_encrypt(&km, b"aad", &msg).unwrap();
    assert_eq!(ct.len(), msg.len());
    let pt = <AsconAead128 as AEADCipher<16, 16, 16>>::aead_decrypt(&km, &nonce, b"aad", &ct, &tag)
        .unwrap();
    assert_eq!(pt, msg);

    // Tampering must still be rejected through these entry points too.
    assert!(
        <AsconAead128 as AEADCipher<16, 16, 16>>::aead_decrypt(
            &km, &nonce, b"wrong-aad", &ct, &tag
        )
        .is_err()
    );
}

// None of the length checks in the `SymmetricCipher`/`AEADCipher` `_out` entry points are ever
// triggered by `TestFrameworkSymmetricCipher`/`TestFrameworkAEADCipher` (which always pass a
// generously-sized fixed buffer), nor by the inherent one-shot `encrypt`/`decrypt` tests above
// (which always size their own buffer correctly). Exercise every one directly.
#[test]
fn aead128_undersized_buffers_are_rejected() {
    use bouncycastle_core::traits::{AEADCipher, SymmetricCipher};

    let km = key_material(&KEY);
    let msg = pattern(40);

    // SymmetricCipher::encrypt_out: ciphertext buffer shorter than plaintext.len() + 16.
    let mut too_small = vec![0u8; msg.len() + 15];
    match <AsconAead128 as SymmetricCipher<16, 16>>::encrypt_out(&km, &msg, &mut too_small) {
        Err(SymmetricCipherError::IncorrectOutputBufferLength(_, needed)) => {
            assert_eq!(needed, msg.len() + 16);
        }
        other => panic!("expected IncorrectOutputBufferLength, got {other:?}"),
    }

    // SymmetricCipher::decrypt / decrypt_out: ciphertext shorter than the 16-byte tag.
    let short = [0u8; 8];
    match <AsconAead128 as SymmetricCipher<16, 16>>::decrypt(&km, NONCE, &short) {
        Err(SymmetricCipherError::GenericError(_)) => {}
        other => panic!("expected GenericError, got {other:?}"),
    }
    let mut pt_buf = [0u8; 8];
    match <AsconAead128 as SymmetricCipher<16, 16>>::decrypt_out(&km, NONCE, &short, &mut pt_buf) {
        Err(SymmetricCipherError::GenericError(_)) => {}
        other => panic!("expected GenericError, got {other:?}"),
    }

    // SymmetricCipher::decrypt_out: valid-length ciphertext, but undersized plaintext buffer.
    let ct = enc_oneshot(&KEY, &NONCE, &[], &msg);
    let mut too_small_pt = vec![0u8; msg.len() - 1];
    match <AsconAead128 as SymmetricCipher<16, 16>>::decrypt_out(&km, NONCE, &ct, &mut too_small_pt)
    {
        Err(SymmetricCipherError::IncorrectOutputBufferLength(_, needed)) => {
            assert_eq!(needed, msg.len());
        }
        other => panic!("expected IncorrectOutputBufferLength, got {other:?}"),
    }

    // decrypt / decrypt_out: ciphertext of exactly 16 bytes (an empty plaintext plus the tag) is
    // the boundary case and must NOT be rejected as "too short".
    let empty_ct = enc_oneshot(&KEY, &NONCE, &[], &[]);
    assert_eq!(empty_ct.len(), 16);
    assert_eq!(
        <AsconAead128 as SymmetricCipher<16, 16>>::decrypt(&km, NONCE, &empty_ct).unwrap(),
        Vec::<u8>::new()
    );
    let mut empty_pt_buf = [0u8; 0];
    assert_eq!(
        <AsconAead128 as SymmetricCipher<16, 16>>::decrypt_out(
            &km, NONCE, &empty_ct, &mut empty_pt_buf
        )
        .unwrap(),
        0
    );

    // decrypt_out: a plaintext buffer *larger* than needed must succeed, not be rejected.
    let mut oversized_pt = vec![0xAAu8; msg.len() + 5];
    let n =
        <AsconAead128 as SymmetricCipher<16, 16>>::decrypt_out(&km, NONCE, &ct, &mut oversized_pt)
            .unwrap();
    assert_eq!(n, msg.len());
    assert_eq!(&oversized_pt[..n], &msg[..]);

    // AEADCipher::aead_encrypt_out: ciphertext buffer shorter than the plaintext.
    let mut too_small = vec![0u8; msg.len() - 1];
    match <AsconAead128 as AEADCipher<16, 16, 16>>::aead_encrypt_out(
        &km, b"aad", &msg, &mut too_small,
    ) {
        Err(SymmetricCipherError::IncorrectOutputBufferLength(_, needed)) => {
            assert_eq!(needed, msg.len());
        }
        other => panic!("expected IncorrectOutputBufferLength, got {other:?}"),
    }

    // AEADCipher::aead_decrypt_out: plaintext buffer shorter than the ciphertext.
    let (nonce, ct, tag) =
        <AsconAead128 as AEADCipher<16, 16, 16>>::aead_encrypt(&km, b"aad", &msg).unwrap();
    let mut too_small_pt = vec![0u8; ct.len() - 1];
    match <AsconAead128 as AEADCipher<16, 16, 16>>::aead_decrypt_out(
        &km, &nonce, b"aad", &ct, &tag, &mut too_small_pt,
    ) {
        Err(SymmetricCipherError::IncorrectOutputBufferLength(_, needed)) => {
            assert_eq!(needed, ct.len());
        }
        other => panic!("expected IncorrectOutputBufferLength, got {other:?}"),
    }
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
    let n = AsconAead128::decrypt(&km, &NONCE, ad_opt(ad), &tampered, &mut out);
    assert!(matches!(n, Err(SymmetricCipherError::AEADTagCheckFailed)));
    assert!(out.iter().all(|&b| b == 0), "output buffer must be zeroized on tag failure");
}

#[test]
fn aead_short_ciphertext_is_error() {
    let short = [0u8; 8]; // shorter than the 16-byte tag
    let km = key_material(&KEY);
    let mut out = [0u8; 16];
    match AsconAead128::decrypt(&km, &NONCE, None, &short, &mut out) {
        Err(SymmetricCipherError::GenericError(_)) => {}
        other => panic!("expected GenericError for short ciphertext, got {other:?}"),
    }
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
    let e = AsconAead128::new(&km, &NONCE, None, true).unwrap();
    assert!(format!("{e:?}").contains("masked"));
    assert!(format!("{e}").contains("masked"));
}

/* -------------------------------------------------------------------------- */
/* Direction-misuse guards                                                    */
/* -------------------------------------------------------------------------- */

#[test]
#[should_panic(expected = "decryptor")]
fn do_encrypt_update_on_decryptor_panics() {
    let km = key_material(&KEY);
    let mut d = AsconAead128::new(&km, &NONCE, None, false).unwrap();
    let mut buf = [0u8; 4];
    d.do_encrypt_update(&mut buf);
}

#[test]
#[should_panic(expected = "encryptor")]
fn do_decrypt_update_on_encryptor_panics() {
    let km = key_material(&KEY);
    let mut e = AsconAead128::new(&km, &NONCE, None, true).unwrap();
    let mut buf = [0u8; 4];
    e.do_decrypt_update(&mut buf);
}

/* -------------------------------------------------------------------------- */
/* AEADCipher trait conformance (shared core-test-framework)                  */
/* -------------------------------------------------------------------------- */

#[test]
fn aead128_trait_framework() {
    // Exercises the generic SymmetricCipher<16,16> + AEADCipher<16,16,16> surface: internally
    // generated (random, distinct) nonces, key-type / key-strength enforcement, and the AEAD
    // tamper-detection contract (modified ciphertext / AAD / tag must fail the tag check, and
    // must never leave plaintext in the output buffer).
    TestFrameworkAEADCipher::new().test::<16, 16, 16, AsconAead128>();
}

#[test]
fn aead128_suspendable_keyed_state() {
    use bouncycastle_core::errors::SuspendableError;
    use bouncycastle_core::traits::SuspendableKeyed;
    use bouncycastle_core_test_framework::suspendable_state::TestFrameworkSuspendableKeyedState;

    let pt = pattern(40);
    let ad = b"suspend-ad";
    let ct_ref = enc_oneshot(&KEY, &NONCE, ad, &pt);
    let km = key_material(&KEY);

    // Encrypt part of the plaintext, suspend, resume with the re-supplied key, finish, and confirm
    // the output matches a one-shot encryption. The key is never part of the serialized state.
    let mut e = AsconAead128::new(&km, &NONCE, Some(ad), true).unwrap();
    let mut out = vec![0u8; pt.len() + 16];
    out[..pt.len()].copy_from_slice(&pt);
    e.do_encrypt_update(&mut out[..18]);

    TestFrameworkSuspendableKeyedState::new().test(&e, &km);

    let serialized = e.clone().suspend();
    let mut resumed = AsconAead128::from_suspended(serialized, &km).unwrap();
    resumed.do_encrypt_update(&mut out[18..pt.len()]);
    let tag = resumed.do_encrypt_final();
    out[pt.len()..].copy_from_slice(&tag);
    assert_eq!(out, ct_ref, "resumed AEAD ciphertext must match one-shot encryption");

    // A corrupted state tag must be rejected (the tag is the byte after the 3-byte version prefix).
    let mut busted = serialized;
    busted[3] ^= 0xFF;
    assert!(matches!(
        AsconAead128::from_suspended(busted, &km),
        Err(SuspendableError::InvalidData)
    ));

    // An unknown call-state discriminant must be rejected.
    let last = serialized.len() - 1;
    let pos_offset = serialized.len() - 2;
    let mut bad_state = serialized;
    bad_state[last] = 200;
    assert!(matches!(
        AsconAead128::from_suspended(bad_state, &km),
        Err(SuspendableError::InvalidData)
    ));

    // A nonzero byte position while still in an *Init state must be rejected.
    let mut inconsistent = serialized;
    inconsistent[pos_offset] = 3; // pos = 3
    inconsistent[last] = 0; // EncInit
    assert!(matches!(
        AsconAead128::from_suspended(inconsistent, &km),
        Err(SuspendableError::InvalidData)
    ));

    // pos >= RATE (16) must be rejected.
    let mut bad_pos = serialized;
    bad_pos[pos_offset] = 16;
    assert!(matches!(
        AsconAead128::from_suspended(bad_pos, &km),
        Err(SuspendableError::InvalidData)
    ));
}
