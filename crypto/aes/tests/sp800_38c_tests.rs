//! The four AES-CCM example vectors of NIST SP 800-38C Appendix C, and the streaming and
//! error-path properties that go with them.
//!
//! The vectors are transcribed from the errata-updated (07-20-2007) PDF of the recommendation.
//! Appendix C: "four examples are provided for the encryption-generation process of CCM with the
//! formatting and counter generation functions that are specified in Appendix A. The underlying
//! block cipher algorithm is the AES algorithm under a key of 128 bits." All four share one key
//! and differ in every length, which is what makes them worth having all four of: between them
//! they cover `t` of 4, 6, 8 and 14 and `q` of 8, 7, 3 and 2, i.e. both ends of each of A.1's
//! ranges.
//!
//! Appendix C prints `C` as a single string, which is Sec 6.1 step 8's
//! `(P XOR MSB_Plen(S)) || (T XOR MSB_Tlen(S0))` -- the ciphertext with the tag appended. It is
//! split here at `Plen`, and both layouts of the API are checked against the two halves.
//!
//! Appendix C gives no decryption examples ("From each example, a corresponding example of the
//! decryption-verification process of CCM is straightforward to construct"), so the decryption
//! direction is checked by round-tripping each vector's own `C` back to its `P`.

use bouncycastle_aes::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle_cipher::modes::{Ccm, CcmDecryptor, CcmEncryptor};
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, SymmetricCipherDecryptor, SymmetricCipherEncryptor,
};
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_core_test_framework::aead::TestFrameworkAEADCipher;
use bouncycastle_hex as hex;

/// Appendix C's key, the same in all four examples: `40414243 44454647 48494a4b 4c4d4e4f`.
const APPENDIX_C_KEY: &str = "404142434445464748494a4b4c4d4e4f";

fn key<const N: usize>(hex_key: &str) -> KeyMaterial<N> {
    let bytes = hex::decode(hex_key).expect("valid hex key");
    assert_eq!(bytes.len(), N, "key length must match the parameter set");
    KeyMaterial::<N>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey)
        .expect("a symmetric cipher key")
}

fn buffer_len_error<T>(r: Result<T, SymmetricCipherError>) -> Option<usize> {
    match r {
        Err(SymmetricCipherError::OutputBufferTooSmall(needed)) => Some(needed),
        _ => None,
    }
}

/// Drives one Appendix C example through every entry point, in both layouts and both directions.
///
/// `c` is the appendix's whole `C` string; it is split at `plaintext.len()` into the ciphertext and
/// the tag, so a mistake in either half is caught, and so is a mistake in where the split belongs.
fn check_vector<
    const KEY_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    P: bouncycastle_core::hazmat::ElectronicCodeBook<KEY_LEN, 16>,
>(
    name: &str,
    key_hex: &str,
    nonce_hex: &str,
    aad: &[u8],
    plaintext_hex: &str,
    c_hex: &str,
    // Whether to run the chunking sweep as well as the single-pass checks; `appendix_c4` says why
    // it opts out.
    sweep: bool,
) {
    type Enc<P, const K: usize, const N: usize, const T: usize> = Ccm<P, Encrypting, K, 16, N, T>;
    type Dec<P, const K: usize, const N: usize, const T: usize> = Ccm<P, Decrypting, K, 16, N, T>;

    let k = key::<KEY_LEN>(key_hex);
    let nonce_bytes = hex::decode(nonce_hex).expect("valid hex nonce");
    let nonce: [u8; NONCE_LEN] = nonce_bytes.try_into().expect("nonce length matches NONCE_LEN");
    let plaintext = hex::decode(plaintext_hex).expect("valid hex plaintext");
    let c = hex::decode(c_hex).expect("valid hex C");

    assert_eq!(
        c.len(),
        plaintext.len() + TAG_LEN,
        "{name}: the appendix's C must be Plen + Tlen octets"
    );
    let (want_ct, want_tag) = c.split_at(plaintext.len());

    // --- Sec 6.1, detached tag ---
    let mut ct = vec![0u8; plaintext.len()];
    let (written, tag) = Enc::<P, KEY_LEN, NONCE_LEN, TAG_LEN>::encrypt_detached_out(
        &k, &nonce, aad, &plaintext, &mut ct,
    )
    .expect("encryption");
    assert_eq!(written, plaintext.len(), "{name}: CCM never expands the payload");
    assert_eq!(ct, want_ct, "{name}: ciphertext");
    assert_eq!(tag, want_tag, "{name}: tag");

    // --- Sec 6.1, the appendix's own inline `ciphertext || tag` layout ---
    let mut inline = vec![0u8; plaintext.len() + TAG_LEN];
    let n = Enc::<P, KEY_LEN, NONCE_LEN, TAG_LEN>::encrypt_out(
        &k, &nonce, aad, &plaintext, &mut inline,
    )
    .expect("encryption");
    assert_eq!(n, c.len(), "{name}: inline output length");
    assert_eq!(inline, c, "{name}: the whole C string of Appendix C");

    // --- Sec 6.2, both layouts ---
    let mut recovered = vec![0u8; plaintext.len()];
    let n = Dec::<P, KEY_LEN, NONCE_LEN, TAG_LEN>::decrypt_detached_out(
        &k,
        &nonce,
        aad,
        want_ct,
        want_tag.try_into().expect("TAG_LEN bytes"),
        &mut recovered,
    )
    .expect("decryption");
    assert_eq!(n, plaintext.len());
    assert_eq!(recovered, plaintext, "{name}: detached round trip");

    let mut recovered = vec![0u8; plaintext.len()];
    let n = Dec::<P, KEY_LEN, NONCE_LEN, TAG_LEN>::decrypt_out(&k, &nonce, aad, &c, &mut recovered)
        .expect("decryption");
    assert_eq!(n, plaintext.len());
    assert_eq!(recovered, plaintext, "{name}: inline round trip");

    // --- Every ciphertext chunking through the streaming API gives the same answer ---
    if sweep {
        // Sec 3 says CCM is not a streaming mode, and `Ccm` handles that by taking the payload length
        // up front; given that, the chunking must be invisible, exactly as for the other modes.
        for chunk in [1usize, 2, 3, 7, 16, 17] {
            let mut ccm =
                Enc::<P, KEY_LEN, NONCE_LEN, TAG_LEN>::new(&k, &nonce, aad, plaintext.len())
                    .expect("streaming init");
            let mut streamed = plaintext.clone();
            for piece in streamed.chunks_mut(chunk) {
                ccm.do_encrypt(piece).expect("update");
            }
            let streamed_tag = ccm.do_encrypt_final().expect("final");
            assert_eq!(streamed, want_ct, "{name}: ciphertext, streamed in {chunk}-byte chunks");
            assert_eq!(streamed_tag, want_tag, "{name}: tag, streamed in {chunk}-byte chunks");

            let mut ccm =
                Dec::<P, KEY_LEN, NONCE_LEN, TAG_LEN>::new(&k, &nonce, aad, plaintext.len())
                    .expect("streaming init");
            for piece in streamed.chunks_mut(chunk) {
                ccm.do_decrypt_update(piece).expect("update");
            }
            ccm.do_decrypt_final(want_tag.try_into().expect("TAG_LEN bytes")).expect("tag check");
            assert_eq!(streamed, plaintext, "{name}: plaintext, streamed in {chunk}-byte chunks");
        }
    }
}

/// Appendix C.1: `Klen = 128, Tlen = 32, Nlen = 56, Alen = 64, Plen = 32`.
///
/// `n = 7`, so `q = 8`: the widest length field A.1 allows, and the shortest permitted tag.
#[test]
fn appendix_c1() {
    check_vector::<16, 7, 4, AES128Internal>(
        "C.1",
        APPENDIX_C_KEY,
        "10111213141516",
        &hex::decode("0001020304050607").unwrap(),
        "20212223",
        // C: 7162015b 4dac255d
        "7162015b4dac255d",
        true,
    );
}

/// Appendix C.2: `Klen = 128, Tlen = 48, Nlen = 64, Alen = 128, Plen = 128`.
///
/// `n = 8`, so `q = 7`. The payload is exactly one block, which is the case where A.2.3's
/// "minimum number of '0' bits, possibly none" is none.
#[test]
fn appendix_c2() {
    check_vector::<16, 8, 6, AES128Internal>(
        "C.2",
        APPENDIX_C_KEY,
        "1011121314151617",
        &hex::decode("000102030405060708090a0b0c0d0e0f").unwrap(),
        "202122232425262728292a2b2c2d2e2f",
        // C: d2a1f0e0 51ea5f62 081a7792 073d593d 1fc64fbf accd
        "d2a1f0e051ea5f62081a7792073d593d1fc64fbfaccd",
        true,
    );
}

/// Appendix C.3: `Klen = 128, Tlen = 64, Nlen = 96, Alen = 160, Plen = 192`.
///
/// `n = 12`, so `q = 3`. Both the AAD (20 bytes) and the payload (24 bytes) need zero-padding, and
/// the payload spans two counter blocks.
#[test]
fn appendix_c3() {
    check_vector::<16, 12, 8, AES128Internal>(
        "C.3",
        APPENDIX_C_KEY,
        "101112131415161718191a1b",
        &hex::decode("000102030405060708090a0b0c0d0e0f10111213").unwrap(),
        "202122232425262728292a2b2c2d2e2f3031323334353637",
        // C: e3b201a9 f5b71a7a 9b1ceaec cd97e70b
        //    6176aad9 a4428aa5 484392fb c1b09951
        "e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5484392fbc1b09951",
        true,
    );
}

/// Appendix C.4: `Klen = 128, Tlen = 112, Nlen = 104, Alen = 524288, Plen = 256`.
///
/// `n = 13`, so `q = 2`: the narrowest length field A.1 allows. This is the example that exercises
/// A.2.2's **six-octet** AAD length encoding, `0xff || 0xfe || [a]_32` -- `Alen` is 524288 bits,
/// i.e. `a = 65536`, which is past the `2^16 - 2^8` boundary. Nothing else in the appendix does,
/// and neither does the ACVP set, so this test is the only coverage of that branch against an
/// official answer.
///
/// The appendix does not print `A` in full: "the given string of the first sixteen blocks of the
/// associated data string is concatenated with itself repeatedly to form a string of 524288 bits".
/// Those sixteen blocks are `00 01 02 ... ff`, so `A` is that 256-byte run repeated 256 times.
#[test]
fn appendix_c4() {
    let mut aad = Vec::with_capacity(65536);
    for _ in 0..256 {
        aad.extend(0u8..=255u8);
    }
    assert_eq!(aad.len(), 65536, "Alen = 524288 bits");

    check_vector::<16, 13, 14, AES128Internal>(
        "C.4",
        APPENDIX_C_KEY,
        "101112131415161718191a1b1c",
        &aad,
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        // C: 69915dad 1e84c637 6a68c296 7e4dab61
        //    5ae0fd1f aec44cc4 84828529 463ccf72
        //    b4ac6bec 93e8598e 7f0dadbc ea5b
        "69915dad1e84c6376a68c2967e4dab615ae0fd1faec44cc484828529463ccf72\
         b4ac6bec93e8598e7f0dadbcea5b",
        // No chunking sweep here: with a 64 KiB AAD every extra pass through Sec 6.1 or 6.2 is a
        // 4096-block CBC-MAC, and the sweep alone made this the slowest test in the crate. What it
        // pins, chunking invisibility, is pinned on C.1 to C.3 above and exhaustively over the toy
        // in `ccm_tests.rs`; what only C.4 can pin, the six-octet AAD length and `q = 2`, needs one
        // pass.
        false,
    );
}

/// The shared framework, told the one payload length a fixed-frame pair's streaming methods
/// accept, `DATA_LEN`, so that it streams exactly that and checks that anything else is refused.
fn framework(data_len: usize) -> TestFrameworkAEADCipher {
    let mut framework = TestFrameworkAEADCipher::new();
    framework.fixed_message_len = Some(data_len);
    framework
}

/// The whole [`AEADCipherEncryptor`] / [`AEADCipherDecryptor`] contract, through the shared
/// framework, for the fixed-frame [`CcmEncryptor`] / [`CcmDecryptor`] pair.
///
/// `DATA_LEN` is 240, well above the few multiples of the tag the suite's one-shots try, so the
/// one-shots are exercised at every length up to it and the streaming methods at exactly it.
/// `AAD_LEN` is 64, above the suite's 20-byte AAD. `FINAL_LEN` is the tag.
#[test]
fn framework_streaming_contract() {
    framework(240).test_encryptor_decryptor::<
        16,
        12,
        16,
        16,
        CcmEncryptor<AES128Internal, 16, 16, 12, 16, 64, 240>,
        CcmDecryptor<AES128Internal, 16, 16, 12, 16, 64, 240>,
    >();
}

/// The same, for the other two AES key lengths and a short tag, so the framework's error and
/// key-policy checks run against every parameterization the CLI and the aliases expose.
#[test]
fn framework_streaming_contract_other_parameter_sets() {
    framework(240).test_encryptor_decryptor::<
        24,
        12,
        16,
        16,
        CcmEncryptor<AES192Internal, 24, 16, 12, 16, 64, 240>,
        CcmDecryptor<AES192Internal, 24, 16, 12, 16, 64, 240>,
    >();
    framework(240).test_encryptor_decryptor::<
        32,
        12,
        16,
        16,
        CcmEncryptor<AES256Internal, 32, 16, 12, 16, 64, 240>,
        CcmDecryptor<AES256Internal, 32, 16, 12, 16, 64, 240>,
    >();
    // A 13-byte nonce (q = 2) with an 8-byte tag: the parameterization IEEE 802.11 CCMP uses, and
    // the one A.1's narrowest length field applies to.
    framework(240).test_encryptor_decryptor::<
        16,
        13,
        8,
        8,
        CcmEncryptor<AES128Internal, 16, 16, 13, 8, 64, 240>,
        CcmDecryptor<AES128Internal, 16, 16, 13, 8, 64, 240>,
    >();
    // The empty frame: a message that is nothing but its AAD and tag.
    framework(0).test_encryptor_decryptor::<
        16,
        12,
        16,
        16,
        CcmEncryptor<AES128Internal, 16, 16, 12, 16, 64, 0>,
        CcmDecryptor<AES128Internal, 16, 16, 12, 16, 64, 0>,
    >();
}

/// The fixed-frame pair must agree with the run-time-length [`Ccm`] byte for byte -- they are two
/// routes to the same Sec 6.1 -- and it must be driven with a caller-chosen nonce to check that,
/// which is what `do_encrypt_init_rng` and a fixed-output RNG provide. C.3's payload is 24 bytes
/// and its AAD 20, so that is the frame.
#[test]
fn the_fixed_frame_pair_agrees_with_the_direct_api_on_appendix_c3() {
    type Enc = CcmEncryptor<AES128Internal, 16, 16, 12, 8, 20, 24>;
    type Dec = CcmDecryptor<AES128Internal, 16, 16, 12, 8, 20, 24>;

    let k = key::<16>(APPENDIX_C_KEY);
    let nonce_bytes = hex::decode("101112131415161718191a1b").unwrap();
    let aad = hex::decode("000102030405060708090a0b0c0d0e0f10111213").unwrap();
    let plaintext = hex::decode("202122232425262728292a2b2c2d2e2f3031323334353637").unwrap();
    let c =
        hex::decode("e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5484392fbc1b09951").unwrap();
    let (want_ct, want_tag) = c.split_at(plaintext.len());

    // The trait generates the nonce; feed it Appendix C.3's so the answer is comparable, and check
    // it came back, so an implementation that ignored the RNG could not pass silently.
    let nonce_seed: [u8; 12] = nonce_bytes.clone().try_into().expect("12-byte nonce");
    let mut rng = FixedSeedRNG::<12>::new(nonce_seed);
    let (mut enc, nonce) = Enc::do_encrypt_init_rng(&k, &mut rng).expect("init");
    assert_eq!(&nonce[..], &nonce_bytes[..], "the generated nonce must come from the RNG");

    // Chunk both phases, and check `update_out_len`'s promise that every byte is released at once.
    enc.do_update_aad(&aad[..5]).expect("aad 1");
    enc.do_update_aad(&aad[5..]).expect("aad 2");
    let mut ct = Vec::new();
    for piece in plaintext.chunks(7) {
        assert_eq!(enc.do_encrypt_out_len(piece.len()), piece.len(), "nothing is held back");
        let mut buf = vec![0u8; piece.len()];
        assert_eq!(enc.do_encrypt_out(piece, &mut buf).expect("update"), piece.len());
        ct.extend_from_slice(&buf);
    }
    let mut flushed = [0xEEu8; 8];
    let (len, tag) = enc.do_encrypt_final_detachedtag_out(&mut flushed).expect("final");
    assert_eq!(len, 0, "the detached final flushes nothing");
    assert_eq!(flushed, [0u8; 8], "...and leaves the buffer zeroed");
    assert_eq!(&ct[..], want_ct, "C.3 ciphertext via the trait");
    assert_eq!(&tag[..], want_tag, "C.3 tag via the trait");

    let mut dec = Dec::do_decrypt_init(&k, &nonce).expect("init");
    dec.do_update_aad(&aad).expect("aad");
    let mut pt = Vec::new();
    for piece in want_ct.chunks(5) {
        let mut buf = vec![0u8; dec.do_decrypt_out_len(piece.len())];
        assert_eq!(dec.do_decrypt_out(piece, &mut buf).expect("update"), piece.len());
        pt.extend_from_slice(&buf);
    }
    let mut out = [0xEEu8; 8];
    let n = dec
        .do_decrypt_final_detachedtag_out(want_tag.try_into().expect("8 bytes"), &mut out)
        .expect("tag check");
    assert_eq!(n, 0, "the detached final releases nothing");
    assert_eq!(out, [0u8; 8], "...and leaves the buffer zeroed");
    assert_eq!(&pt[..], &plaintext[..], "C.3 plaintext via the trait");

    // The inline layout through the inherited `SymmetricCipher*` methods: C.3's `C` is exactly
    // `ciphertext || tag`, with the tag as the final's output, and the decryptor takes the tag
    // back off its end.
    let mut rng = FixedSeedRNG::<12>::new(nonce_seed);
    let (mut enc, nonce) = Enc::do_encrypt_init_rng(&k, &mut rng).expect("init");
    enc.do_update_aad(&aad).expect("aad");
    let mut inline = vec![0u8; 24];
    enc.do_encrypt_out(&plaintext, &mut inline).expect("update");
    let (last, last_len) = enc.do_encrypt_final().expect("final");
    inline.extend_from_slice(&last[..last_len]);
    assert_eq!(&inline[..], &c[..], "C.3 `C` via the inline do_encrypt_final");
    let mut dec = Dec::do_decrypt_init(&k, &nonce).expect("init");
    dec.do_update_aad(&aad).expect("aad");
    let mut pt = Vec::new();
    for piece in c.chunks(5) {
        let mut buf = vec![0u8; dec.do_decrypt_out_len(piece.len())];
        let n = dec.do_decrypt_out(piece, &mut buf).expect("update");
        pt.extend_from_slice(&buf[..n]);
    }
    let (_, n) = dec.do_decrypt_final().expect("tag check");
    assert_eq!(n, 0, "the inline final releases nothing: the payload already went out");
    assert_eq!(&pt[..], &plaintext[..], "C.3 plaintext via the inline do_decrypt_final");
}

/// More than the declared lengths is refused, and the refusal consumes nothing and writes
/// nothing: a payload past `DATA_LEN` at the update that would cross it, on both sides, and an
/// AAD past `AAD_LEN`.
#[test]
fn the_adapters_refuse_more_than_the_declared_lengths() {
    type Enc = CcmEncryptor<AES128Internal, 16, 16, 12, 16, 32, 32>;
    type Dec = CcmDecryptor<AES128Internal, 16, 16, 12, 16, 32, 32>;
    let k = key::<16>(APPENDIX_C_KEY);

    let (mut enc, _) = Enc::do_encrypt_init(&k).expect("init");
    let mut out = [0xEEu8; 33];
    match enc.do_encrypt_out(&[0u8; 33], &mut out) {
        Err(SymmetricCipherError::StateError(msg)) => assert!(
            msg.contains("DATA_LEN"),
            "the encryptor's refusal must name its bound, got: {msg}"
        ),
        other => panic!("expected StateError, got {other:?}"),
    }
    assert_eq!(out, [0u8; 33], "a refused update must leave the output buffer zeroed");

    // In two calls that together overflow, the first must succeed and the second be refused.
    let (mut enc, _) = Enc::do_encrypt_init(&k).expect("init");
    assert_eq!(enc.do_encrypt_out(&[0u8; 20], &mut out).expect("fits"), 20);
    assert!(matches!(
        enc.do_encrypt_out(&[0u8; 13], &mut out),
        Err(SymmetricCipherError::StateError(_))
    ));

    let (mut enc, _) = Enc::do_encrypt_init(&k).expect("init");
    match enc.do_update_aad(&[0u8; 33]) {
        Err(SymmetricCipherError::GenericError(msg)) => {
            assert!(msg.contains("AAD_LEN"), "the refusal must name AAD_LEN, got: {msg}")
        }
        other => panic!("expected GenericError, got {other:?}"),
    }

    // The decryptor's bound is `DATA_LEN + TAG_LEN`, the frame with an inline tag.
    let nonce = [0x24u8; 12];
    let mut dec = Dec::do_decrypt_init(&k, &nonce).expect("init");
    let mut pt = [0xEEu8; 49];
    match dec.do_decrypt_out(&[0u8; 49], &mut pt) {
        Err(SymmetricCipherError::StateError(msg)) => assert!(
            msg.contains("DATA_LEN + TAG_LEN"),
            "the decryptor's refusal must name its bound, got: {msg}"
        ),
        other => panic!("expected StateError, got {other:?}"),
    }
    assert_eq!(pt, [0u8; 49], "a refused update must leave the output buffer zeroed");
    let mut dec = Dec::do_decrypt_init(&k, &nonce).expect("init");
    assert_eq!(dec.do_decrypt_out(&[0u8; 40], &mut pt).expect("fits"), 32);
    assert!(matches!(
        dec.do_decrypt_out(&[0u8; 9], &mut pt),
        Err(SymmetricCipherError::StateError(_))
    ));
    let mut dec = Dec::do_decrypt_init(&k, &nonce).expect("init");
    assert!(matches!(dec.do_update_aad(&[0u8; 33]), Err(SymmetricCipherError::GenericError(_))));
}

/// An empty `do_update_out` is a no-op and does not close the AAD phase, on either side. The
/// trait makes an empty `aad` a no-op "at any point" so that a generic caller may pass one
/// unconditionally; a caller whose reader hands back an empty first chunk, or that calls
/// `do_update_out(&[])` before deciding on AAD, gets the same treatment here. Only a non-empty
/// call starts the data phase.
#[test]
fn an_empty_update_does_not_close_the_aad_phase() {
    type Enc = CcmEncryptor<AES128Internal, 16, 16, 12, 16, 48, 7>;
    type Dec = CcmDecryptor<AES128Internal, 16, 16, 12, 16, 48, 7>;
    let k = key::<16>(APPENDIX_C_KEY);
    let aad = b"header";
    let message = b"payload";

    let (mut enc, nonce) = Enc::do_encrypt_init(&k).expect("init");
    let mut sealed = [0u8; 7];
    enc.do_encrypt_out(&[], &mut sealed).expect("an empty update is a no-op");
    enc.do_update_aad(aad).expect("the AAD phase is still open after an empty update");
    enc.do_encrypt_out(message, &mut sealed).expect("released");
    assert!(
        matches!(enc.do_update_aad(aad), Err(SymmetricCipherError::StateError(_))),
        "a non-empty update still closes the AAD phase"
    );
    let (tag, tag_len) = enc.do_encrypt_final().expect("final");
    assert_eq!(tag_len, 16);

    // The AAD really was absorbed: the direct API with the same AAD must agree, and the
    // decryptor, given the same empty-then-AAD sequence, must verify it.
    let mut expected = [0u8; 7 + 16];
    let n = Ccm::<AES128Internal, Encrypting, 16, 16, 12, 16>::encrypt_out(
        &k, &nonce, aad, message, &mut expected,
    )
    .expect("direct");
    assert_eq!(n, 23);
    assert_eq!(&sealed[..], &expected[..7]);
    assert_eq!(&tag[..], &expected[7..]);

    let mut dec = Dec::do_decrypt_init(&k, &nonce).expect("init");
    let mut opened = [0u8; 7];
    dec.do_decrypt_out(&[], &mut opened).expect("an empty update is a no-op");
    dec.do_update_aad(aad).expect("the AAD phase is still open after an empty update");
    dec.do_decrypt_out(&expected, &mut opened).expect("the payload and the inline tag");
    assert!(
        matches!(dec.do_update_aad(aad), Err(SymmetricCipherError::StateError(_))),
        "a non-empty update still closes the AAD phase"
    );
    let (_, opened_len) = dec.do_decrypt_final().expect("tag check");
    assert_eq!(opened_len, 0);
    assert_eq!(&opened[..], message);
}

/// Exactly the declared lengths are accepted, in one call and split across two, on both sides:
/// the checks are `>`, so using all of `DATA_LEN` and `AAD_LEN` is legitimate and only one byte
/// more is not. The split for the decryptor straddles the payload/tag boundary, which is where
/// its own bookkeeping goes wrong.
#[test]
fn exact_lengths_are_accepted_whole_and_split() {
    type Enc = CcmEncryptor<AES128Internal, 16, 16, 12, 16, 32, 32>;
    type Dec = CcmDecryptor<AES128Internal, 16, 16, 12, 16, 32, 32>;
    let k = key::<16>(APPENDIX_C_KEY);
    let aad = [0x11u8; 32];
    let message = [0x5Au8; 32];
    let nonce_seed = [0x24u8; 12];

    let (mut enc, nonce) =
        Enc::do_encrypt_init_rng(&k, &mut FixedSeedRNG::<12>::new(nonce_seed)).expect("init");
    enc.do_update_aad(&aad).expect("AAD exactly filling the capacity is accepted");
    let mut sealed = [0u8; 48];
    assert_eq!(enc.do_encrypt_out(&message, &mut sealed).expect("exactly DATA_LEN"), 32);
    let (tag, _) = enc.do_encrypt_final().expect("final");
    sealed[32..].copy_from_slice(&tag);

    let (mut enc, _) =
        Enc::do_encrypt_init_rng(&k, &mut FixedSeedRNG::<12>::new(nonce_seed)).expect("init");
    enc.do_update_aad(&aad[..20]).expect("part");
    enc.do_update_aad(&aad[20..]).expect("exactly fills the remaining capacity");
    let mut split = [0u8; 48];
    assert_eq!(enc.do_encrypt_out(&message[..20], &mut split).expect("fits"), 20);
    assert_eq!(enc.do_encrypt_out(&message[20..], &mut split[20..]).expect("the rest"), 12);
    let (tag, _) = enc.do_encrypt_final().expect("final");
    split[32..].copy_from_slice(&tag);
    assert_eq!(split, sealed, "the chunking must not change the answer");

    let mut dec = Dec::do_decrypt_init(&k, &nonce).expect("init");
    dec.do_update_aad(&aad).expect("aad");
    let mut opened = [0u8; 32];
    assert_eq!(dec.do_decrypt_out(&sealed, &mut opened).expect("the whole frame"), 32);
    dec.do_decrypt_final().expect("tag check");
    assert_eq!(opened, message);

    let mut dec = Dec::do_decrypt_init(&k, &nonce).expect("init");
    dec.do_update_aad(&aad[..20]).expect("part");
    dec.do_update_aad(&aad[20..]).expect("the rest");
    let mut opened = [0u8; 32];
    // 20 bytes of payload, then 12 of payload with 10 of tag, then the last 6 of tag.
    assert_eq!(dec.do_decrypt_out_len(20), 20);
    assert_eq!(dec.do_decrypt_out(&sealed[..20], &mut opened).expect("payload"), 20);
    assert_eq!(dec.do_decrypt_out_len(22), 12, "only the payload part is released");
    assert_eq!(dec.do_decrypt_out(&sealed[20..42], &mut opened[20..]).expect("straddle"), 12);
    assert_eq!(dec.do_decrypt_out_len(6), 0, "the rest is tag");
    assert_eq!(dec.do_decrypt_out(&sealed[42..], &mut []).expect("tag"), 0);
    dec.do_decrypt_final().expect("tag check");
    assert_eq!(opened, message);
}

/// `AAD_LEN` is a capacity and `DATA_LEN` an exact length, and each is enforced on its own: a
/// small AAD capacity next to a larger frame is the shape a packet protocol with a short header
/// wants, and the AAD may fall short of its capacity, including all the way to none.
#[test]
fn the_aad_capacity_and_the_payload_length_are_independent() {
    type Enc = CcmEncryptor<AES128Internal, 16, 16, 12, 16, 8, 64>;
    type Dec = CcmDecryptor<AES128Internal, 16, 16, 12, 16, 8, 64>;
    let k = key::<16>(APPENDIX_C_KEY);

    // AAD past AAD_LEN is refused, although it would fit in DATA_LEN.
    let (mut enc, _) = Enc::do_encrypt_init(&k).expect("init");
    assert!(matches!(enc.do_update_aad(&[0u8; 9]), Err(SymmetricCipherError::GenericError(_))));

    // A full AAD_LEN of AAD and a full DATA_LEN of payload together, far more than AAD_LEN alone,
    // round-trip through both sides; so does a frame with less AAD than the capacity, and with
    // none, each agreeing with the direct API.
    let message = [0x5Au8; 64];
    for aad in [&[0x11u8; 8][..], &[0x11u8; 3][..], &[][..]] {
        let (mut enc, nonce) = Enc::do_encrypt_init(&k).expect("init");
        enc.do_update_aad(aad).expect("within AAD_LEN");
        let mut sealed = [0u8; 64];
        enc.do_encrypt_out(&message, &mut sealed).expect("exactly DATA_LEN");
        let (_, _, tag) = enc.do_encrypt_final_detachedtag().expect("final");

        let mut direct = [0u8; 64];
        let (_, direct_tag) =
            Ccm::<AES128Internal, Encrypting, 16, 16, 12, 16>::encrypt_detached_out(
                &k, &nonce, aad, &message, &mut direct,
            )
            .expect("direct");
        assert_eq!((sealed, tag), (direct, direct_tag), "aad of {} bytes", aad.len());

        let mut dec = Dec::do_decrypt_init(&k, &nonce).expect("init");
        dec.do_update_aad(aad).expect("within AAD_LEN");
        let mut opened = [0u8; 64];
        dec.do_decrypt_out(&sealed, &mut opened).expect("exactly DATA_LEN");
        dec.do_decrypt_final_detachedtag(&tag).expect("tag check");
        assert_eq!(opened, message);
    }
}

/// The decryptor knows where the payload ends, so it releases every payload byte as it arrives
/// and holds back only what follows: the inline tag, if the final says the layout is inline, and
/// excess ciphertext if it says detached. Nothing is released by either final.
#[test]
fn the_decryptor_releases_the_payload_and_holds_back_only_the_tag() {
    type Enc = CcmEncryptor<AES128Internal, 16, 16, 12, 16, 32, 32>;
    type Dec = CcmDecryptor<AES128Internal, 16, 16, 12, 16, 32, 32>;
    let k = key::<16>(APPENDIX_C_KEY);
    let message = [0x5Au8; 32];

    let (mut enc, nonce) = Enc::do_encrypt_init(&k).expect("init");
    let mut inline = [0u8; 48];
    enc.do_encrypt_out(&message, &mut inline).expect("the frame");
    let (tag, _) = enc.do_encrypt_final().expect("final");
    inline[32..].copy_from_slice(&tag);

    // Inline: 40 bytes release the 32 of payload and hold 8 of tag; the last 8 release nothing.
    let mut dec = Dec::do_decrypt_init(&k, &nonce).expect("init");
    let mut out = [0u8; 32];
    assert_eq!(dec.do_decrypt_out_len(40), 32);
    assert_eq!(
        dec.do_decrypt_out(&inline[..40], &mut out).expect("payload and part of the tag"),
        32
    );
    assert_eq!(out, message, "the payload is out before the tag has been seen");
    assert_eq!(dec.do_decrypt_out(&inline[40..], &mut []).expect("the rest of the tag"), 0);
    let (_, n) = dec.do_decrypt_final().expect("tag check");
    assert_eq!(n, 0, "nothing is left to release");

    // One byte past the frame with its tag is refused, and the final still verifies.
    let mut dec = Dec::do_decrypt_init(&k, &nonce).expect("init");
    dec.do_decrypt_out(&inline, &mut out).expect("the whole frame");
    assert!(matches!(
        dec.do_decrypt_out(&[0u8; 1], &mut []),
        Err(SymmetricCipherError::StateError(_))
    ));
    dec.do_decrypt_final().expect("a refused update must not disturb the state");

    // Detached, the 16 bytes held back after the payload have nowhere to go: the frame is
    // exactly DATA_LEN, so this `C` is malformed.
    let mut dec = Dec::do_decrypt_init(&k, &nonce).expect("init");
    dec.do_decrypt_out(&inline, &mut out).expect("the whole frame");
    let mut nothing = [0xEEu8; 16];
    assert!(matches!(
        dec.do_decrypt_final_detachedtag_out(&tag, &mut nothing),
        Err(SymmetricCipherError::DecryptionFailed)
    ));
    assert_eq!(nothing, [0u8; 16], "the detached final only zeroes its buffer");

    // ...and exactly DATA_LEN is the detached frame.
    let mut dec = Dec::do_decrypt_init(&k, &nonce).expect("init");
    let mut out = [0u8; 32];
    dec.do_decrypt_out(&inline[..32], &mut out).expect("the frame");
    assert_eq!(dec.do_decrypt_final_detachedtag_out(&tag, &mut nothing).expect("tag check"), 0);
    assert_eq!(nothing, [0u8; 16], "the detached final only zeroes its buffer");
    assert_eq!(out, message);
}

/// The trait one-shots are the trait's own, provided over the streaming methods, so `DATA_LEN`
/// and `AAD_LEN` bind them exactly as they bind the streaming calls: a frame of the declared
/// length goes through and agrees with the run-time-length [`Ccm`] byte for byte, and anything
/// else is refused with the streaming methods' own errors.
#[test]
fn trait_one_shots_are_bound_by_data_len() {
    type Enc = CcmEncryptor<AES128Internal, 16, 16, 12, 16, 48, 48>;
    type Dec = CcmDecryptor<AES128Internal, 16, 16, 12, 16, 48, 48>;
    let k = key::<16>(APPENDIX_C_KEY);
    let nonce_seed = [0x24u8; 12];
    let aad = [0x3Cu8; 48];
    let frame = [0xA5u8; 48];

    let mut ciphertext = [0u8; 48];
    let (nonce, written, tag) = Enc::encrypt_detached_rng_out(
        &k,
        &mut FixedSeedRNG::<12>::new(nonce_seed),
        &aad,
        &frame,
        &mut ciphertext,
    )
    .expect("exactly DATA_LEN and AAD_LEN");
    assert_eq!(written, 48);
    let mut direct = [0u8; 48];
    let (_, direct_tag) = Ccm::<AES128Internal, Encrypting, 16, 16, 12, 16>::encrypt_detached_out(
        &k, &nonce, &aad, &frame, &mut direct,
    )
    .expect("direct");
    assert_eq!((ciphertext, tag), (direct, direct_tag), "the two routes to Sec 6.1 agree");
    let mut opened = [0u8; 48];
    assert_eq!(
        Dec::decrypt_detached_out(&k, &nonce, &aad, &ciphertext, &tag, &mut opened).expect("open"),
        48
    );
    assert_eq!(opened, frame);

    // One byte either side of the frame is refused, with the streaming methods' own variants.
    let mut out = [0u8; 4096];
    assert!(matches!(
        Enc::encrypt_detached_out(&k, &aad, &[0xA5u8; 47], &mut out),
        Err(SymmetricCipherError::StateError(_))
    ));
    assert!(matches!(
        Enc::encrypt_detached_out(&k, &aad, &[0xA5u8; 49], &mut out),
        Err(SymmetricCipherError::StateError(_))
    ));
    assert!(matches!(
        Enc::encrypt_detached_out(&k, &[0x3Cu8; 49], &frame, &mut out),
        Err(SymmetricCipherError::GenericError(_))
    ));
    assert!(matches!(
        Dec::decrypt_detached_out(&k, &nonce, &aad, &ciphertext[..47], &tag, &mut out),
        Err(SymmetricCipherError::DecryptionFailed)
    ));
    let mut long = [0u8; 49];
    long[..48].copy_from_slice(&ciphertext);
    assert!(matches!(
        Dec::decrypt_detached_out(&k, &nonce, &aad, &long, &tag, &mut out),
        Err(SymmetricCipherError::DecryptionFailed)
    ));
}

/// `B0` commits to `DATA_LEN`, so every final must check that exactly that much payload was
/// supplied before it computes or checks a tag -- a tag over a shorter message would be one no
/// verifier could reproduce, and on the decrypting side a `C` of the wrong length is malformed.
/// Every one of the eight final entry points is asserted on its own, the provided forwarders
/// included, so that a forwarder that dropped the check could not hide behind the one it wraps.
///
/// The encryptor refuses with [`SymmetricCipherError::StateError`], the caller's own sequencing
/// mistake; the decryptor with [`SymmetricCipherError::DecryptionFailed`], since the input is a
/// ciphertext, and a wrong-length one is malformed. Each refusal is paired with the same call
/// succeeding on the right amount, so a matcher that passed for the wrong reason would show.
#[test]
fn every_final_refuses_a_payload_of_the_wrong_length() {
    type Enc = CcmEncryptor<AES128Internal, 16, 16, 12, 16, 16, 8>;
    type Dec = CcmDecryptor<AES128Internal, 16, 16, 12, 16, 16, 8>;
    let k = key::<16>(APPENDIX_C_KEY);
    let aad = b"header";
    let frame = [0x5Au8; 8];
    let nonce_seed = [0x24u8; 12];

    // An encryptor fed `supplied` of the 8 declared bytes.
    let enc = |supplied: usize| {
        let (mut enc, _) =
            Enc::do_encrypt_init_rng(&k, &mut FixedSeedRNG::<12>::new(nonce_seed)).expect("init");
        enc.do_update_aad(aad).expect("aad");
        let mut out = [0u8; 8];
        enc.do_encrypt_out(&frame[..supplied], &mut out).expect("update");
        enc
    };
    for short in [0usize, 4, 7] {
        assert!(
            matches!(enc(short).do_encrypt_final(), Err(SymmetricCipherError::StateError(_))),
            "do_encrypt_final after {short} of 8 bytes"
        );
        let mut buf = [0u8; 16];
        assert!(
            matches!(
                enc(short).do_encrypt_final_out(&mut buf),
                Err(SymmetricCipherError::StateError(_))
            ),
            "do_encrypt_final_out after {short} of 8 bytes"
        );
        assert!(
            matches!(
                enc(short).do_encrypt_final_detachedtag(),
                Err(SymmetricCipherError::StateError(_))
            ),
            "do_encrypt_final_detachedtag after {short} of 8 bytes"
        );
        assert!(
            matches!(
                enc(short).do_encrypt_final_detachedtag_out(&mut buf),
                Err(SymmetricCipherError::StateError(_))
            ),
            "do_encrypt_final_detachedtag_out after {short} of 8 bytes"
        );
    }
    // The positive controls, which also produce the ciphertext for the decrypting side.
    let (tag, n) = enc(8).do_encrypt_final().expect("do_encrypt_final on a whole frame");
    assert_eq!(n, 16);
    let mut buf = [0u8; 16];
    assert_eq!(
        enc(8).do_encrypt_final_out(&mut buf).expect("do_encrypt_final_out on a whole frame"),
        16
    );
    assert_eq!(buf, tag);
    let (_, n, tag2) = enc(8)
        .do_encrypt_final_detachedtag()
        .expect("do_encrypt_final_detachedtag on a whole frame");
    assert_eq!((n, tag2), (0, tag));
    let (n, tag3) = enc(8)
        .do_encrypt_final_detachedtag_out(&mut buf)
        .expect("do_encrypt_final_detachedtag_out on a whole frame");
    assert_eq!((n, tag3), (0, tag));
    let mut ct = [0u8; 8];
    {
        let (mut e, _) =
            Enc::do_encrypt_init_rng(&k, &mut FixedSeedRNG::<12>::new(nonce_seed)).expect("init");
        e.do_update_aad(aad).expect("aad");
        e.do_encrypt_out(&frame, &mut ct).expect("update");
        e.do_encrypt_final().expect("final");
    }
    let mut inline = [0u8; 24];
    inline[..8].copy_from_slice(&ct);
    inline[8..].copy_from_slice(&tag);

    // A decryptor fed the first `supplied` bytes of `inline`.
    let dec = |supplied: usize| {
        let mut dec = Dec::do_decrypt_init(&k, &nonce_seed).expect("init");
        dec.do_update_aad(aad).expect("aad");
        let mut out = [0u8; 8];
        dec.do_decrypt_out(&inline[..supplied], &mut out).expect("update");
        dec
    };
    // Inline: a short payload, and a whole payload with a short tag, are both a short `C`.
    for short in [0usize, 4, 7, 8, 12, 23] {
        assert!(
            matches!(dec(short).do_decrypt_final(), Err(SymmetricCipherError::DecryptionFailed)),
            "do_decrypt_final after {short} of 24 bytes"
        );
        let mut buf = [0u8; 16];
        assert!(
            matches!(
                dec(short).do_decrypt_final_out(&mut buf),
                Err(SymmetricCipherError::DecryptionFailed)
            ),
            "do_decrypt_final_out after {short} of 24 bytes"
        );
    }
    assert_eq!(dec(24).do_decrypt_final().expect("do_decrypt_final on a whole frame").1, 0);
    assert_eq!(
        dec(24).do_decrypt_final_out(&mut buf).expect("do_decrypt_final_out on a whole frame"),
        0
    );
    // Detached: a short payload, and bytes past it that this layout has no place for.
    for wrong in [0usize, 4, 7, 9, 24] {
        assert!(
            matches!(
                dec(wrong).do_decrypt_final_detachedtag(&tag),
                Err(SymmetricCipherError::DecryptionFailed)
            ),
            "do_decrypt_final_detachedtag after {wrong} of 8 bytes"
        );
        let mut buf = [0u8; 16];
        assert!(
            matches!(
                dec(wrong).do_decrypt_final_detachedtag_out(&tag, &mut buf),
                Err(SymmetricCipherError::DecryptionFailed)
            ),
            "do_decrypt_final_detachedtag_out after {wrong} of 8 bytes"
        );
    }
    assert_eq!(
        dec(8)
            .do_decrypt_final_detachedtag(&tag)
            .expect("do_decrypt_final_detachedtag on a whole frame")
            .1,
        0
    );
    assert_eq!(
        dec(8)
            .do_decrypt_final_detachedtag_out(&tag, &mut buf)
            .expect("do_decrypt_final_detachedtag_out on a whole frame"),
        0
    );
    // ...and a whole frame with the wrong tag is the tag check failing, not a length refusal.
    let mut forged = tag;
    forged[0] ^= 0xFF;
    assert!(matches!(
        dec(8).do_decrypt_final_detachedtag(&forged),
        Err(SymmetricCipherError::AEADTagCheckFailed)
    ));
}

/// Sec 6.2 step 1: "If Clen <= Tlen, then return INVALID". The inline layout has to reject a `C`
/// too short to contain a tag before it can split one off.
///
/// A `C` of exactly `TAG_LEN` octets is *not* too short: it is the empty payload of Sec 5.3's
/// footnote, and must authenticate.
///
/// All three inline entry points -- the inherent one-shot, the fixed-frame decryptor's
/// `do_decrypt_final` and its `decrypt_with_aad_out` -- must report the same malformed input with
/// the same variant, [`SymmetricCipherError::DecryptionFailed`], which is what
/// [`SymmetricCipherDecryptor::do_decrypt_final`] specifies for a malformed ciphertext; a caller
/// telling "malformed" from "inauthentic" must not get a different answer depending on which one it
/// used.
#[test]
fn an_inline_ciphertext_shorter_than_the_tag_is_rejected() {
    type Enc = Ccm<AES128Internal, Encrypting, 16, 16, 12, 16>;
    type Dec = Ccm<AES128Internal, Decrypting, 16, 16, 12, 16>;
    // The empty frame, so that every byte of a short `C` is a (missing) tag byte.
    type StreamDec = CcmDecryptor<AES128Internal, 16, 16, 12, 16, 48, 0>;
    let k = key::<16>(APPENDIX_C_KEY);
    let nonce = [0u8; 12];
    let mut out = [0u8; 16];
    let mut nothing = [0u8; 0];

    for len in 0..16 {
        let short = vec![0u8; len];
        assert!(
            matches!(
                Dec::decrypt_out(&k, &nonce, &[], &short, &mut out),
                Err(SymmetricCipherError::DecryptionFailed)
            ),
            "a {len}-byte C cannot carry a 16-byte tag (Ccm::decrypt_out)"
        );
        assert!(
            matches!(
                StreamDec::decrypt_with_aad_out(&k, &nonce, &[], &short, &mut out),
                Err(SymmetricCipherError::DecryptionFailed)
            ),
            "a {len}-byte C cannot carry a 16-byte tag (decrypt_with_aad_out)"
        );
        let mut dec = StreamDec::do_decrypt_init(&k, &nonce).expect("init");
        dec.do_decrypt_out(&short, &mut nothing).expect("held back as a possible tag");
        assert!(
            matches!(dec.do_decrypt_final(), Err(SymmetricCipherError::DecryptionFailed)),
            "a {len}-byte C cannot carry a 16-byte tag (do_decrypt_final)"
        );
    }

    // Exactly TAG_LEN: an empty payload plus its tag, which must verify, on all three.
    let mut inline = [0u8; 16];
    let n = Enc::encrypt_out(&k, &nonce, &[], &[], &mut inline).expect("encryption");
    assert_eq!(n, 16);
    assert_eq!(Dec::decrypt_out(&k, &nonce, &[], &inline, &mut out).expect("decryption"), 0);
    assert_eq!(
        StreamDec::decrypt_with_aad_out(&k, &nonce, &[], &inline, &mut out).expect("decryption"),
        0
    );
    let mut dec = StreamDec::do_decrypt_init(&k, &nonce).expect("init");
    assert_eq!(dec.do_decrypt_out(&inline, &mut nothing).expect("the tag"), 0);
    assert_eq!(dec.do_decrypt_final().expect("an empty frame still verifies").1, 0);
}

/// The same agreement on a frame that is not empty, where the inline entry points can disagree
/// in a way the empty frame hides. `do_decrypt_out` releases the payload as it arrives, up to
/// `DATA_LEN`, and only then holds bytes back as the tag; so a `C` of fewer than
/// `DATA_LEN + TAG_LEN` bytes still asks for a `DATA_LEN`-byte buffer when it is longer than the
/// frame. `decrypt_out_len` is therefore `DATA_LEN` for any such `C`, not `C` less a tag: a
/// one-shot that sizes its buffer by it reaches the final, which reports the short `C` as
/// malformed, rather than refusing the buffer with `OutputBufferTooSmall` first.
#[test]
fn a_short_inline_ciphertext_is_rejected_the_same_way_for_a_non_empty_frame() {
    const DATA_LEN: usize = 32;
    type Enc = CcmEncryptor<AES128Internal, 16, 16, 12, 16, 16, DATA_LEN>;
    type Dec = CcmDecryptor<AES128Internal, 16, 16, 12, 16, 16, DATA_LEN>;
    let k = key::<16>(APPENDIX_C_KEY);
    let frame = [0x5Au8; DATA_LEN];
    let mut sealed = vec![0u8; Enc::encrypt_out_len(DATA_LEN)];
    let (nonce, n) = Enc::encrypt_with_aad_out(&k, b"hdr", &frame, &mut sealed).expect("seal");
    assert_eq!(n, DATA_LEN + 16);

    // The whole frame plus its tag is the one accepted inline length, and the bound is exact.
    assert_eq!(Dec::decrypt_out_len(DATA_LEN + 16), DATA_LEN);
    assert_eq!(Dec::decrypt_out_len(DATA_LEN + 1), DATA_LEN, "the payload is DATA_LEN");
    assert_eq!(Dec::decrypt_out_len(5), 5, "...or all of a C shorter than the frame");

    for len in 0..DATA_LEN + 16 {
        let short = &sealed[..len];
        let mut pt = vec![0u8; Dec::decrypt_out_len(len)];
        assert!(
            matches!(
                Dec::decrypt_with_aad_out(&k, &nonce, b"hdr", short, &mut pt),
                Err(SymmetricCipherError::DecryptionFailed)
            ),
            "a {len}-byte C is not a frame and its tag (decrypt_with_aad_out)"
        );
        let mut pt = vec![0u8; Dec::decrypt_out_len(len)];
        assert!(
            matches!(
                Dec::decrypt_out(&k, &nonce, short, &mut pt),
                Err(SymmetricCipherError::DecryptionFailed)
            ),
            "a {len}-byte C is not a frame and its tag (decrypt_out)"
        );
        let mut dec = Dec::do_decrypt_init(&k, &nonce).expect("init");
        dec.do_update_aad(b"hdr").expect("aad");
        let mut pt = vec![0u8; dec.do_decrypt_out_len(len)];
        dec.do_decrypt_out(short, &mut pt).expect("the payload is released, the rest held");
        assert!(
            matches!(dec.do_decrypt_final(), Err(SymmetricCipherError::DecryptionFailed)),
            "a {len}-byte C is not a frame and its tag (do_decrypt_final)"
        );
    }

    // ...and the accepted length, through the same three, so the loop's bound is not off by one.
    let mut pt = vec![0u8; Dec::decrypt_out_len(sealed.len())];
    assert_eq!(Dec::decrypt_with_aad_out(&k, &nonce, b"hdr", &sealed, &mut pt).expect("open"), 32);
    assert_eq!(&pt[..], &frame[..]);
}

/// An output buffer that is too short is refused with the length required, before any work.
#[test]
fn undersized_output_buffers_are_refused() {
    type Enc = Ccm<AES128Internal, Encrypting, 16, 16, 12, 16>;
    type Dec = Ccm<AES128Internal, Decrypting, 16, 16, 12, 16>;
    let k = key::<16>(APPENDIX_C_KEY);
    let nonce = [0u8; 12];
    let plaintext = [0xAAu8; 24];

    let mut too_small = [0u8; 23];
    assert_eq!(
        buffer_len_error(Enc::encrypt_detached_out(&k, &nonce, &[], &plaintext, &mut too_small)),
        Some(24)
    );

    let mut too_small = [0u8; 39];
    assert_eq!(
        buffer_len_error(Enc::encrypt_out(&k, &nonce, &[], &plaintext, &mut too_small)),
        Some(40)
    );

    let mut ct = [0u8; 40];
    Enc::encrypt_out(&k, &nonce, &[], &plaintext, &mut ct).expect("encryption");
    let mut too_small = [0u8; 23];
    assert_eq!(buffer_len_error(Dec::decrypt_out(&k, &nonce, &[], &ct, &mut too_small)), Some(24));
}

/// A key of the wrong [`KeyType`] is rejected by every entry point, in both directions.
#[test]
fn a_non_cipher_key_is_rejected() {
    type Enc = Ccm<AES128Internal, Encrypting, 16, 16, 12, 16>;
    type Dec = Ccm<AES128Internal, Decrypting, 16, 16, 12, 16>;
    let wrong =
        KeyMaterial::<16>::from_bytes_as_type(&[0x11; 16], KeyType::MACKey).expect("a MAC key");
    let mut out = [0u8; 16];
    assert!(matches!(
        Enc::encrypt_detached_out(&wrong, &[0u8; 12], &[], &[], &mut out),
        Err(SymmetricCipherError::KeyMaterialError(_))
    ));
    assert!(matches!(
        Enc::new(&wrong, &[0u8; 12], &[], 0),
        Err(SymmetricCipherError::KeyMaterialError(_))
    ));
    assert!(matches!(
        Dec::decrypt_out(&wrong, &[0u8; 12], &[], &[0u8; 16], &mut out),
        Err(SymmetricCipherError::KeyMaterialError(_))
    ));
    assert!(matches!(
        Dec::new(&wrong, &[0u8; 12], &[], 0),
        Err(SymmetricCipherError::KeyMaterialError(_))
    ));
}

/// The direction is in the type, so the wrong direction's method is a **compile** error rather
/// than a runtime one. This is what the `Dir` parameter buys over a runtime flag, and without a
/// test the guarantee could quietly regress into an inherent method on the shared impl block.
///
/// Both of these are checked as `compile_fail` doctests on [`Ccm`] itself; this test is the
/// positive half -- that the *right* direction's methods do exist on each -- which a
/// `compile_fail` cannot express.
#[test]
fn each_direction_has_its_own_methods() {
    type Enc = Ccm<AES128Internal, Encrypting, 16, 16, 12, 16>;
    type Dec = Ccm<AES128Internal, Decrypting, 16, 16, 12, 16>;
    let k = key::<16>(APPENDIX_C_KEY);
    let nonce = [0x55u8; 12];

    let mut enc = Enc::new(&k, &nonce, b"aad", 4).expect("encrypt init");
    let mut data = [1u8, 2, 3, 4];
    enc.do_encrypt(&mut data).expect("encrypt update");
    let tag = enc.do_encrypt_final().expect("encrypt final");

    let mut dec = Dec::new(&k, &nonce, b"aad", 4).expect("decrypt init");
    dec.do_decrypt_update(&mut data).expect("decrypt update");
    dec.do_decrypt_final(&tag).expect("decrypt final");
    assert_eq!(data, [1u8, 2, 3, 4]);
}

// ---- memory ------------------------------------------------------------------------------

/// Pins the sizes: `Ccm` is 264/296/328 B for AES-128/192/256, independent of
/// `NONCE_LEN`/`TAG_LEN`, and the fixed-frame pair is `Ccm` plus the `AAD_LEN` buffer and a few
/// words of bookkeeping, independent of `DATA_LEN`.
#[test]
fn sizes_match_the_documented_memory_table() {
    use core::mem::size_of;

    assert_eq!(size_of::<Ccm<AES128Internal, Encrypting, 16, 16, 12, 16>>(), 264);
    assert_eq!(size_of::<Ccm<AES192Internal, Encrypting, 24, 16, 12, 16>>(), 296);
    assert_eq!(size_of::<Ccm<AES256Internal, Encrypting, 32, 16, 12, 16>>(), 328);

    // Independent of NONCE_LEN and TAG_LEN: the nonce lives inside the counter template and the
    // tag is assembled at finalization, not held.
    assert_eq!(
        size_of::<Ccm<AES128Internal, Encrypting, 16, 16, 12, 16>>(),
        size_of::<Ccm<AES128Internal, Encrypting, 16, 16, 7, 4>>()
    );
    assert_eq!(
        size_of::<Ccm<AES128Internal, Encrypting, 16, 16, 12, 16>>(),
        size_of::<Ccm<AES128Internal, Encrypting, 16, 16, 13, 16>>()
    );

    // The direction marker is free, and does not change the layout.
    assert_eq!(
        size_of::<Ccm<AES128Internal, Encrypting, 16, 16, 12, 16>>(),
        size_of::<Ccm<AES128Internal, Decrypting, 16, 16, 12, 16>>()
    );

    // The fixed-frame pair holds no payload: a 4 KiB frame costs exactly what a 16-byte one does.
    let enc_64 = size_of::<CcmEncryptor<AES128Internal, 16, 16, 12, 16, 64, 4096>>();
    assert_eq!(enc_64, size_of::<CcmEncryptor<AES128Internal, 16, 16, 12, 16, 64, 16>>());
    assert_eq!(enc_64, 264 + 64 + 16, "Ccm, the AAD buffer, its length and the phase flag");
    assert_eq!(
        size_of::<CcmEncryptor<AES128Internal, 16, 16, 12, 16, 4096, 4096>>() - enc_64,
        4096 - 64,
        "the value grows by exactly the AAD capacity"
    );
    // The decryptor adds the tag it holds back and that tag's length.
    let dec_64 = size_of::<CcmDecryptor<AES128Internal, 16, 16, 12, 16, 64, 4096>>();
    assert_eq!(dec_64, size_of::<CcmDecryptor<AES128Internal, 16, 16, 12, 16, 64, 16>>());
    assert_eq!(dec_64, enc_64 + 16 + 8);
}

// ---- moved from crypto/cipher/src/modes/ccm.rs's in-file unit tests -----------------------------

/// A.1's `p < 2^8q`. With `n = 13`, `q = 2`, so the limit is 65535 and 65536 must be refused.
///
/// Only the public API is exercised, so this belongs here rather than in `ccm.rs`'s own
/// `#[cfg(test)]` block, which is for the private formatting helpers no public API reaches.
#[test]
fn payload_longer_than_the_q_limit_is_refused() {
    let k = key::<16>(APPENDIX_C_KEY);
    let nonce = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c];
    assert!(
        Ccm::<AES128Internal, Encrypting, 16, 16, 13, 14>::new(&k, &nonce, &[], 65535).is_ok(),
        "2^16 - 1 is the largest payload q = 2 can encode"
    );
    assert!(
        matches!(
            Ccm::<AES128Internal, Encrypting, 16, 16, 13, 14>::new(&k, &nonce, &[], 65536),
            Err(SymmetricCipherError::GenericError(_))
        ),
        "2^16 does not fit [p]_16"
    );
}

// ---- progressive AAD: new_with_lengths + do_update_aad ------------------------------------

/// Runs one Appendix C example through [`Ccm::new_with_lengths`], feeding the AAD in `chunk`-byte
/// pieces, in both directions, and checks the result against the example's `C`.
fn check_progressive_aad<const NONCE_LEN: usize, const TAG_LEN: usize>(
    label: &str,
    nonce: &str,
    aad: &[u8],
    plaintext: &str,
    c: &str,
    chunk: usize,
) {
    let k = key::<16>(APPENDIX_C_KEY);
    let nonce: [u8; NONCE_LEN] = hex::decode(nonce).unwrap().try_into().unwrap();
    let plaintext = hex::decode(plaintext).unwrap();
    let c = hex::decode(c).unwrap();
    let (want_ct, want_tag) = c.split_at(plaintext.len());

    let mut enc = Ccm::<AES128Internal, Encrypting, 16, 16, NONCE_LEN, TAG_LEN>::new_with_lengths(
        &k,
        &nonce,
        aad.len(),
        plaintext.len(),
    )
    .unwrap();
    for piece in aad.chunks(chunk) {
        enc.do_update_aad(piece).unwrap();
    }
    let mut data = plaintext.clone();
    enc.do_encrypt(&mut data).unwrap();
    let tag = enc.do_encrypt_final().unwrap();
    assert_eq!(data, want_ct, "{label}: ciphertext, AAD in {chunk}-byte pieces");
    assert_eq!(&tag[..], want_tag, "{label}: tag, AAD in {chunk}-byte pieces");

    let mut dec = Ccm::<AES128Internal, Decrypting, 16, 16, NONCE_LEN, TAG_LEN>::new_with_lengths(
        &k,
        &nonce,
        aad.len(),
        plaintext.len(),
    )
    .unwrap();
    for piece in aad.chunks(chunk) {
        dec.do_update_aad(piece).unwrap();
    }
    dec.do_decrypt_update(&mut data).unwrap();
    dec.do_decrypt_final(&tag).unwrap();
    assert_eq!(data, plaintext, "{label}: decryption, AAD in {chunk}-byte pieces");
}

/// Supplying the AAD in pieces gives Appendix C's answers, whatever the chunking: C.3's 20-byte
/// AAD, which needs padding, and C.4's 65536-byte one, which takes A.2.2's six-octet length
/// encoding. The chunk sizes straddle the 16-byte block, so pieces end part-way through a block.
#[test]
fn progressive_aad_matches_appendix_c() {
    for chunk in [1, 3, 15, 16, 17, 20] {
        check_progressive_aad::<12, 8>(
            "C.3",
            "101112131415161718191a1b",
            &hex::decode("000102030405060708090a0b0c0d0e0f10111213").unwrap(),
            "202122232425262728292a2b2c2d2e2f3031323334353637",
            "e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5484392fbc1b09951",
            chunk,
        );
    }
    let mut aad = Vec::with_capacity(65536);
    for _ in 0..256 {
        aad.extend(0u8..=255u8);
    }
    for chunk in [1, 7, 256, 1000, 65536] {
        check_progressive_aad::<13, 14>(
            "C.4",
            "101112131415161718191a1b1c",
            &aad,
            "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
            "69915dad1e84c6376a68c2967e4dab615ae0fd1faec44cc484828529463ccf72\
             b4ac6bec93e8598e7f0dadbcea5b",
            chunk,
        );
    }
}

/// The declared AAD length is encoded in front of the AAD, so, as for the payload, any other
/// amount is refused -- more at the update, less at the final -- and the payload may not start
/// until the AAD is complete. A refused call consumes nothing.
#[test]
fn progressive_aad_enforces_the_declared_length_and_order() {
    type Enc = Ccm<AES128Internal, Encrypting, 16, 16, 12, 16>;
    type Dec = Ccm<AES128Internal, Decrypting, 16, 16, 12, 16>;
    let k = key::<16>(APPENDIX_C_KEY);
    let nonce = [0x24u8; 12];
    let aad = b"0123456789";
    let message = *b"payload";

    let reference = {
        let mut ccm = Enc::new(&k, &nonce, aad, message.len()).unwrap();
        let mut data = message;
        ccm.do_encrypt(&mut data).unwrap();
        (data, ccm.do_encrypt_final().unwrap())
    };

    // More than declared: refused, and the refused call absorbs nothing.
    let mut ccm = Enc::new_with_lengths(&k, &nonce, aad.len(), message.len()).unwrap();
    ccm.do_update_aad(&aad[..4]).unwrap();
    assert!(matches!(ccm.do_update_aad(&[0u8; 7]), Err(SymmetricCipherError::StateError(_))));

    // Payload before the AAD is complete: refused, and the data is left untouched.
    let mut data = message;
    assert!(matches!(ccm.do_encrypt(&mut data), Err(SymmetricCipherError::StateError(_))));
    assert_eq!(data, message, "a refused update must not touch the data");
    // An empty payload update is a no-op, not a refusal.
    ccm.do_encrypt(&mut []).expect("an empty update is a no-op");

    // Completing the AAD after both refusals gives the same answer as supplying it whole.
    ccm.do_update_aad(&aad[4..]).unwrap();
    ccm.do_encrypt(&mut data).unwrap();
    assert_eq!((data, ccm.do_encrypt_final().unwrap()), reference);

    // Less than declared: refused at the final, in both directions.
    let mut ccm = Enc::new_with_lengths(&k, &nonce, aad.len(), 0).unwrap();
    ccm.do_update_aad(&aad[..9]).unwrap();
    assert!(matches!(ccm.do_encrypt_final(), Err(SymmetricCipherError::StateError(_))));
    let mut dec = Dec::new_with_lengths(&k, &nonce, aad.len(), 0).unwrap();
    dec.do_update_aad(&aad[..9]).unwrap();
    assert!(matches!(dec.do_decrypt_final(&[0u8; 16]), Err(SymmetricCipherError::StateError(_))));

    // The decryptor refuses payload before the AAD is complete too.
    let mut dec = Dec::new_with_lengths(&k, &nonce, aad.len(), message.len()).unwrap();
    let mut ct = reference.0;
    assert!(matches!(dec.do_decrypt_update(&mut ct), Err(SymmetricCipherError::StateError(_))));
    assert_eq!(ct, reference.0, "a refused update must not touch the data");
    dec.do_update_aad(aad).unwrap();
    dec.do_decrypt_update(&mut ct).unwrap();
    dec.do_decrypt_final(&reference.1).expect("tag check");
    assert_eq!(ct, message);

    // `new` declares exactly the AAD it is given, so any more afterwards is refused.
    let mut ccm = Enc::new(&k, &nonce, aad, message.len()).unwrap();
    assert!(matches!(ccm.do_update_aad(b"x"), Err(SymmetricCipherError::StateError(_))));
    ccm.do_update_aad(&[]).expect("an empty AAD update is always a no-op");

    // A declared AAD length of zero is the no-AAD flow: the payload may start at once.
    let mut ccm = Enc::new_with_lengths(&k, &nonce, 0, message.len()).unwrap();
    let mut data = message;
    ccm.do_encrypt(&mut data).unwrap();
    let no_aad = ccm.do_encrypt_final().unwrap();
    let mut ccm = Enc::new(&k, &nonce, &[], message.len()).unwrap();
    let mut data2 = message;
    ccm.do_encrypt(&mut data2).unwrap();
    assert_eq!((data, no_aad), (data2, ccm.do_encrypt_final().unwrap()));
}
