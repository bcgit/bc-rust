//! Behavioral / contract tests that the KAT vectors do not exercise:
//! AEAD negative cases, streaming chunk-boundary equivalence, determinism, output-size predictors,
//! hash/XOF streaming equivalence, the XOF prefix property, CXOF domain separation, and misuse
//! guards.

use bouncycastle_ascon::ascon_aead128::AsconAead128;
use bouncycastle_ascon::ascon_cxof128::AsconCXof128;
use bouncycastle_ascon::ascon_hash256::AsconHash256;
use bouncycastle_ascon::ascon_xof128::AsconXof128;
use bouncycastle_core::errors::AeadError;
use bouncycastle_core::traits::{AeadCipher, Hash, XOF};

const KEY: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
];
const NONCE: [u8; 16] = [
    0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
];

const PT_SIZES: [usize; 10] = [0, 1, 15, 16, 17, 31, 32, 33, 64, 100];
const CHUNK_SIZES: [usize; 6] = [1, 3, 7, 13, 16, 17];

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(7).wrapping_add(1)).collect()
}

fn ad_opt(ad: &[u8]) -> Option<&[u8]> {
    if ad.is_empty() { None } else { Some(ad) }
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
/* AEAD round-trips and AAD handling                                          */
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
/* AEAD streaming chunk-boundary equivalence                                  */
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

/* -------------------------------------------------------------------------- */
/* AEAD authentication failures                                               */
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
/* AEAD determinism / nonce sensitivity / size predictors                     */
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
        assert_eq!(
            enc.get_output_size(pt_len),
            pt_len + 16,
            "encrypt get_output_size should be pt_len + tag"
        );
        assert_eq!(
            enc.get_update_output_size(pt_len),
            (pt_len / 16) * 16,
            "encrypt get_update_output_size should be whole blocks only"
        );

        let dec = AsconAead128::new(&KEY, &NONCE, None, false);
        let ct_len = pt_len + 16;
        assert_eq!(
            dec.get_output_size(ct_len),
            pt_len,
            "decrypt get_output_size should be ct_len - tag"
        );
    }
}

/* -------------------------------------------------------------------------- */
/* Hash256 streaming equivalence                                              */
/* -------------------------------------------------------------------------- */

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

/* -------------------------------------------------------------------------- */
/* XOF128 / CXOF128 prefix property, streaming, domain separation             */
/* -------------------------------------------------------------------------- */

#[test]
fn xof128_prefix_property_and_streaming() {
    let msg = pattern(70);
    let full = AsconXof128::new().hash_xof(&msg, 100);

    // Squeezing in several calls yields the same stream (prefix property).
    let mut x = AsconXof128::new();
    x.absorb(&msg);
    let mut piecewise = Vec::new();
    for n in [30usize, 40, 30] {
        let mut part = vec![0u8; n];
        x.squeeze_into(&mut part);
        piecewise.extend_from_slice(&part);
    }
    assert_eq!(piecewise, full, "incremental squeeze must equal a single squeeze");

    // Absorbing in chunks equals one-shot absorb.
    for chunk in [1usize, 8, 9, 64] {
        let mut xc = AsconXof128::new();
        for piece in msg.chunks(chunk) {
            xc.absorb(piece);
        }
        let mut got = vec![0u8; 100];
        xc.squeeze_into(&mut got);
        assert_eq!(got, full, "chunked absorb mismatch (chunk={chunk})");
    }
}

#[test]
fn cxof128_domain_separation() {
    let msg = pattern(48);

    let out_z1 = AsconCXof128::with_customization(b"context-1").hash_xof(&msg, 64);
    let out_z2 = AsconCXof128::with_customization(b"context-2").hash_xof(&msg, 64);
    assert_ne!(out_z1, out_z2, "different customization strings must give different output");

    // Empty-customization CXOF128 must differ from XOF128 (different IV).
    let cxof_empty = AsconCXof128::new().hash_xof(&msg, 64);
    let xof = AsconXof128::new().hash_xof(&msg, 64);
    assert_ne!(cxof_empty, xof, "CXOF128 (empty Z) must differ from XOF128");
}

/* -------------------------------------------------------------------------- */
/* Misuse guards                                                              */
/* -------------------------------------------------------------------------- */

#[test]
#[should_panic]
fn xof128_absorb_after_squeeze_panics() {
    let mut x = AsconXof128::new();
    x.absorb(b"data");
    let mut out = [0u8; 8];
    x.squeeze_into(&mut out);
    // Absorbing after squeezing has begun is a usage error.
    x.absorb(b"more");
}

#[test]
#[should_panic]
fn cxof128_absorb_after_squeeze_panics() {
    let mut x = AsconCXof128::with_customization(b"z");
    x.absorb(b"data");
    let mut out = [0u8; 8];
    x.squeeze_into(&mut out);
    x.absorb(b"more");
}

/* -------------------------------------------------------------------------- */
/* API-surface coverage (trait wrappers, metadata, unsupported ops)           */
/* -------------------------------------------------------------------------- */

#[test]
fn metadata_accessors() {
    assert_eq!(AsconHash256::digest_size(), 32);
    let h = AsconHash256::new();
    assert_eq!(h.output_len(), 32);
    assert_eq!(h.block_bitlen(), 64);
}

#[test]
fn unsupported_partial_ops_return_err() {
    // Hash256 does not support partial-byte input.
    assert!(AsconHash256::new().do_final_partial_bits(0, 3).is_err());
    let mut o = [0u8; 32];
    assert!(AsconHash256::new().do_final_partial_bits_out(0, 3, &mut o).is_err());

    // XOF128 does not support partial-byte input/output.
    let mut x = AsconXof128::new();
    assert!(x.absorb_last_partial_byte(0, 3).is_err());
    assert!(AsconXof128::new().squeeze_partial_byte_final(3).is_err());
    let mut b = 0u8;
    assert!(AsconXof128::new().squeeze_partial_byte_final_out(3, &mut b).is_err());

    // CXOF128 likewise.
    let mut c = AsconCXof128::new();
    assert!(c.absorb_last_partial_byte(0, 3).is_err());
    assert!(AsconCXof128::new().squeeze_partial_byte_final(3).is_err());
    let mut b2 = 0u8;
    assert!(AsconCXof128::new().squeeze_partial_byte_final_out(3, &mut b2).is_err());
}

#[test]
fn hash_trait_wrappers_match_inherent() {
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
fn xof_trait_wrappers_match_inherent() {
    let msg = pattern(50);

    let xref = AsconXof128::new().hash_xof(&msg, 40);
    let mut x = AsconXof128::new();
    x.absorb(&msg);
    assert_eq!(x.squeeze(40), xref);
    let mut x = AsconXof128::new();
    x.absorb(&msg);
    let mut o = [0u8; 40];
    assert_eq!(x.squeeze_out(&mut o), 40);
    assert_eq!(o.to_vec(), xref);
    let mut o = [0u8; 40];
    assert_eq!(AsconXof128::new().hash_xof_out(&msg, &mut o), 40);
    assert_eq!(o.to_vec(), xref);

    let cref = AsconCXof128::with_customization(b"z").hash_xof(&msg, 40);
    let mut c = AsconCXof128::with_customization(b"z");
    c.absorb(&msg);
    assert_eq!(c.squeeze(40), cref);
    let mut c = AsconCXof128::with_customization(b"z");
    c.absorb(&msg);
    let mut o = [0u8; 40];
    assert_eq!(c.squeeze_out(&mut o), 40);
    assert_eq!(o.to_vec(), cref);
    let mut o = [0u8; 40];
    assert_eq!(AsconCXof128::with_customization(b"z").hash_xof_out(&msg, &mut o), 40);
    assert_eq!(o.to_vec(), cref);
}

#[test]
fn xof_byte_at_a_time_matches_one_shot() {
    let msg = pattern(40); // > 8 bytes so update_byte triggers full-block absorption

    let xref = AsconXof128::new().hash_xof(&msg, 48);
    let mut x = AsconXof128::new();
    for &b in &msg {
        x.update_byte(b);
    }
    let mut o = [0u8; 48];
    x.squeeze_into(&mut o);
    assert_eq!(o.to_vec(), xref, "XOF128 update_byte mismatch");

    let cref = AsconCXof128::with_customization(b"zz").hash_xof(&msg, 48);
    let mut c = AsconCXof128::with_customization(b"zz");
    for &b in &msg {
        c.update_byte(b);
    }
    let mut o = [0u8; 48];
    c.squeeze_into(&mut o);
    assert_eq!(o.to_vec(), cref, "CXOF128 update_byte mismatch");
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

#[test]
fn aead_debug_display_are_masked() {
    let e = AsconAead128::new(&KEY, &NONCE, None, true);
    assert!(format!("{e:?}").contains("masked"));
    assert!(format!("{e}").contains("masked"));
}

#[test]
fn aead_aad_via_trait_methods() {
    // Drive AAD through the AeadCipher *trait* methods (the inherent process_aad_bytes otherwise
    // shadows them), covering process_aad_byte / process_aad_bytes delegators.
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
