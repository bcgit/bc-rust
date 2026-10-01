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
use bouncycastle_cipher::modes::{
    CCM_MAX_BUFFER_LEN, Ccm, CcmDecryptor, CcmEncryptor, Decrypting, Encrypting,
};
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
    let (written, tag) = Enc::<P, KEY_LEN, NONCE_LEN, TAG_LEN>::encrypt_out_detached(
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
    let n = Dec::<P, KEY_LEN, NONCE_LEN, TAG_LEN>::decrypt_out_detached(
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

/// The shared framework, told the streaming capacity of a buffering pair, `DATA_LEN`, so that it
/// caps every message it streams at that length.
fn framework(capacity: usize) -> TestFrameworkAEADCipher {
    let mut framework = TestFrameworkAEADCipher::new();
    framework.max_message_len = capacity;
    framework
}

/// The whole [`AEADCipherEncryptor`] / [`AEADCipherDecryptor`] contract, through the shared
/// framework, for the buffering [`CcmEncryptor`] / [`CcmDecryptor`] pair.
///
/// `DATA_LEN` and `AAD_LEN` are 240, comfortably above the
/// longest message the suite tries (`3 * FINAL_LEN + 5` in the symmetric-cipher part, capped by
/// nothing here since its one-shots bypass the buffer, and `3 * TAG_LEN + 5 = 53` in the AEAD
/// part). Everything is flushed at finalization.
#[test]
fn framework_streaming_contract() {
    framework(256 - 16).test_encryptor_decryptor::<
        16,
        12,
        16,
        256,
        CcmEncryptor<AES128Internal, 16, 16, 12, 16, 240, 240, 256>,
        CcmDecryptor<AES128Internal, 16, 16, 12, 16, 240, 240, 256>,
    >();
}

/// The same, for the other two AES key lengths and a short tag, so the framework's error and
/// key-policy checks run against every parameterization the CLI and the aliases expose.
#[test]
fn framework_streaming_contract_other_parameter_sets() {
    framework(256 - 16).test_encryptor_decryptor::<
        24,
        12,
        16,
        256,
        CcmEncryptor<AES192Internal, 24, 16, 12, 16, 240, 240, 256>,
        CcmDecryptor<AES192Internal, 24, 16, 12, 16, 240, 240, 256>,
    >();
    framework(256 - 16).test_encryptor_decryptor::<
        32,
        12,
        16,
        256,
        CcmEncryptor<AES256Internal, 32, 16, 12, 16, 240, 240, 256>,
        CcmDecryptor<AES256Internal, 32, 16, 12, 16, 240, 240, 256>,
    >();
    // A 13-byte nonce (q = 2) with an 8-byte tag: the parameterization IEEE 802.11 CCMP uses, and
    // the one A.1's narrowest length field applies to.
    framework(256 - 8).test_encryptor_decryptor::<
        16,
        13,
        8,
        256,
        CcmEncryptor<AES128Internal, 16, 16, 13, 8, 248, 248, 256>,
        CcmDecryptor<AES128Internal, 16, 16, 13, 8, 248, 248, 256>,
    >();
}

/// The buffering pair must agree with the non-buffering [`Ccm`] byte for byte -- they are two
/// routes to the same Sec 6.1 -- and it must be driven with a caller-chosen nonce to check that,
/// which is what `do_encrypt_init_rng` and a fixed-output RNG provide.
#[test]
fn the_buffering_pair_agrees_with_the_direct_api_on_appendix_c3() {
    type Enc = CcmEncryptor<AES128Internal, 16, 16, 12, 8, 248, 248, 256>;
    type Dec = CcmDecryptor<AES128Internal, 16, 16, 12, 8, 248, 248, 256>;

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

    // Chunk both phases, and check `update_out_len`'s promise that nothing is released early.
    enc.do_update_aad(&aad[..5]).expect("aad 1");
    enc.do_update_aad(&aad[5..]).expect("aad 2");
    let mut nothing = [0u8; 0];
    for piece in plaintext.chunks(7) {
        assert_eq!(enc.do_encrypt_out_len(piece.len()), 0, "CCM releases nothing mid-stream");
        assert_eq!(enc.do_encrypt_out(piece, &mut nothing).expect("update"), 0);
    }
    let mut flushed = [0u8; 256];
    let (len, tag) = enc.do_final_out_detached(&mut flushed).expect("final");
    assert_eq!(len, plaintext.len(), "everything is flushed at finalization");
    assert_eq!(&flushed[..len], want_ct, "C.3 ciphertext via the trait");
    assert_eq!(&tag[..], want_tag, "C.3 tag via the trait");

    let mut dec = Dec::do_decrypt_init(&k, &nonce).expect("init");
    dec.do_update_aad(&aad).expect("aad");
    for piece in want_ct.chunks(5) {
        assert_eq!(dec.do_decrypt_out(piece, &mut nothing).expect("update"), 0);
    }
    let mut out = [0u8; 256];
    let n = dec
        .do_final_out_detached(want_tag.try_into().expect("8 bytes"), &mut out)
        .expect("tag check");
    assert_eq!(&out[..n], &plaintext[..], "C.3 plaintext via the trait");

    // The inline layout through the inherited `SymmetricCipher*` methods: C.3's `C` is exactly
    // `ciphertext || tag`, and the decryptor takes the tag back off its end.
    let mut rng = FixedSeedRNG::<12>::new(nonce_seed);
    let (mut enc, nonce) = Enc::do_encrypt_init_rng(&k, &mut rng).expect("init");
    enc.do_update_aad(&aad).expect("aad");
    enc.do_encrypt_out(&plaintext, &mut nothing).expect("update");
    let (inline, inline_len) = enc.do_final().expect("final");
    assert_eq!(&inline[..inline_len], &c[..], "C.3 `C` via the inline do_final");
    let mut dec = Dec::do_decrypt_init(&k, &nonce).expect("init");
    dec.do_update_aad(&aad).expect("aad");
    for piece in c.chunks(5) {
        assert_eq!(dec.do_decrypt_out(piece, &mut nothing).expect("update"), 0);
    }
    let (out, n) = dec.do_final().expect("tag check");
    assert_eq!(&out[..n], &plaintext[..], "C.3 plaintext via the inline do_final");
}

/// A message longer than the streaming capacity, `DATA_LEN`, is refused rather than
/// silently truncated, and so is an oversized AAD. This is the cost of the trait's length-free `do_encrypt_init`; see
/// [`CcmEncryptor`].
#[test]
fn the_buffering_pair_refuses_a_message_past_its_buffer() {
    // 32-byte AAD and payload capacities; `FINAL_LEN` adds room for the 16-byte inline tag.
    type Enc = CcmEncryptor<AES128Internal, 16, 16, 12, 16, 32, 32, { 32 + 16 }>;
    let k = key::<16>(APPENDIX_C_KEY);
    let mut nothing = [0u8; 0];

    let (mut enc, _) = Enc::do_encrypt_init(&k).expect("init");
    assert!(matches!(
        enc.do_encrypt_out(&[0u8; 33], &mut nothing),
        Err(SymmetricCipherError::GenericError(_))
    ));

    // In two calls that together overflow, the first must succeed and the second be refused.
    let (mut enc, _) = Enc::do_encrypt_init(&k).expect("init");
    assert_eq!(enc.do_encrypt_out(&[0u8; 20], &mut nothing).expect("fits"), 0);
    assert!(matches!(
        enc.do_encrypt_out(&[0u8; 13], &mut nothing),
        Err(SymmetricCipherError::GenericError(_))
    ));

    let (mut enc, _) = Enc::do_encrypt_init(&k).expect("init");
    assert!(matches!(enc.do_update_aad(&[0u8; 33]), Err(SymmetricCipherError::GenericError(_))));

    // The encryptor's bound is `DATA_LEN`, not `FINAL_LEN`, and its message must say so: 33 bytes
    // is refused although it is well inside the 48-byte `FINAL_LEN`.
    let (mut enc, _) = Enc::do_encrypt_init(&k).expect("init");
    match enc.do_encrypt_out(&[0u8; 33], &mut nothing) {
        Err(SymmetricCipherError::GenericError(msg)) => assert!(
            msg.contains("DATA_LEN"),
            "the encryptor's refusal must name its real bound, got: {msg}"
        ),
        other => panic!("expected GenericError, got {other:?}"),
    }
}

/// An empty `do_update_out` is a no-op and does not close the AAD phase, on either side. The
/// trait makes an empty `aad` a no-op "at any point" so that a generic caller may pass one
/// unconditionally; a caller whose reader hands back an empty first chunk, or that calls
/// `do_update_out(&[])` before deciding on AAD, gets the same treatment here. Only a non-empty
/// call starts the data phase.
#[test]
fn an_empty_update_does_not_close_the_aad_phase() {
    type Enc = CcmEncryptor<AES128Internal, 16, 16, 12, 16, 48, 48, 64>;
    type Dec = CcmDecryptor<AES128Internal, 16, 16, 12, 16, 48, 48, 64>;
    let k = key::<16>(APPENDIX_C_KEY);
    let mut nothing = [0u8; 0];
    let aad = b"header";
    let message = b"payload";

    let (mut enc, nonce) = Enc::do_encrypt_init(&k).expect("init");
    enc.do_encrypt_out(&[], &mut nothing).expect("an empty update is a no-op");
    enc.do_update_aad(aad).expect("the AAD phase is still open after an empty update");
    enc.do_encrypt_out(message, &mut nothing).expect("buffered");
    assert!(
        matches!(enc.do_update_aad(aad), Err(SymmetricCipherError::StateError(_))),
        "a non-empty update still closes the AAD phase"
    );
    let (sealed, sealed_len) = enc.do_final().expect("final");

    // The AAD really was absorbed: the direct API with the same AAD must agree, and the
    // decryptor, given the same empty-then-AAD sequence, must verify it.
    let mut expected = [0u8; 64];
    let n = Ccm::<AES128Internal, Encrypting, 16, 16, 12, 16>::encrypt_out(
        &k, &nonce, aad, message, &mut expected,
    )
    .expect("direct");
    assert_eq!(&sealed[..sealed_len], &expected[..n]);

    let mut dec = Dec::do_decrypt_init(&k, &nonce).expect("init");
    dec.do_decrypt_out(&[], &mut nothing).expect("an empty update is a no-op");
    dec.do_update_aad(aad).expect("the AAD phase is still open after an empty update");
    dec.do_decrypt_out(&sealed[..sealed_len], &mut nothing).expect("buffered");
    assert!(
        matches!(dec.do_update_aad(aad), Err(SymmetricCipherError::StateError(_))),
        "a non-empty update still closes the AAD phase"
    );
    let (opened, opened_len) = dec.do_final().expect("tag check");
    assert_eq!(&opened[..opened_len], message);
}

/// Filling the streaming capacity *exactly* must be accepted, not refused: `CcmBuffer::do_update_aad`
/// / `do_update_out` check `end > AAD_LEN` / `end > DATA_LEN`, so using all of it is legitimate and only
/// one byte more is not. Both boundary sides, in one call and split across two.
#[test]
fn the_buffering_pair_accepts_a_message_that_exactly_fills_its_buffer() {
    // 32-byte AAD and payload capacities; `FINAL_LEN` adds room for the 16-byte inline tag.
    type Enc = CcmEncryptor<AES128Internal, 16, 16, 12, 16, 32, 32, { 32 + 16 }>;
    let k = key::<16>(APPENDIX_C_KEY);
    let mut nothing = [0u8; 0];

    let (mut enc, _) = Enc::do_encrypt_init(&k).expect("init");
    assert_eq!(
        enc.do_encrypt_out(&[0u8; 32], &mut nothing).expect("exactly fills the capacity"),
        0
    );

    let (mut enc, _) = Enc::do_encrypt_init(&k).expect("init");
    assert_eq!(enc.do_encrypt_out(&[0u8; 20], &mut nothing).expect("fits"), 0);
    assert_eq!(
        enc.do_encrypt_out(&[0u8; 12], &mut nothing).expect("exactly fills the remaining space"),
        0
    );

    let (mut enc, _) = Enc::do_encrypt_init(&k).expect("init");
    assert!(enc.do_update_aad(&[0u8; 32]).is_ok(), "AAD exactly filling the capacity is accepted");
}

/// `AAD_LEN` and `DATA_LEN` are separate capacities: each is enforced against its own bound, and
/// neither borrows from the other. A small AAD capacity next to a larger payload one is the shape a
/// packet protocol with a short header wants.
#[test]
fn the_aad_and_payload_capacities_are_independent() {
    type Enc = CcmEncryptor<AES128Internal, 16, 16, 12, 16, 8, 64, { 64 + 16 }>;
    type Dec = CcmDecryptor<AES128Internal, 16, 16, 12, 16, 8, 64, { 64 + 16 }>;
    let k = key::<16>(APPENDIX_C_KEY);
    let mut nothing = [0u8; 0];

    // AAD past AAD_LEN is refused, although it would fit in DATA_LEN, and says which bound it hit.
    let (mut enc, _) = Enc::do_encrypt_init(&k).expect("init");
    match enc.do_update_aad(&[0u8; 9]) {
        Err(SymmetricCipherError::GenericError(msg)) => {
            assert!(msg.contains("AAD_LEN"), "the refusal must name AAD_LEN, got: {msg}")
        }
        other => panic!("expected GenericError, got {other:?}"),
    }

    // A full AAD_LEN of AAD and a full DATA_LEN of payload together, far more than AAD_LEN alone,
    // round-trip through both sides.
    let aad = [0x11u8; 8];
    let message = [0x5Au8; 64];
    let (mut enc, nonce) = Enc::do_encrypt_init(&k).expect("init");
    enc.do_update_aad(&aad).expect("exactly AAD_LEN");
    enc.do_encrypt_out(&message, &mut nothing).expect("exactly DATA_LEN");
    let (sealed, sealed_len) = enc.do_final().expect("final");
    assert_eq!(sealed_len, 64 + 16);

    let mut dec = Dec::do_decrypt_init(&k, &nonce).expect("init");
    dec.do_update_aad(&aad).expect("exactly AAD_LEN");
    assert!(
        matches!(dec.do_update_aad(&[0u8; 1]), Err(SymmetricCipherError::GenericError(_))),
        "the decryptor enforces AAD_LEN too"
    );
    dec.do_decrypt_out(&sealed[..sealed_len], &mut nothing).expect("DATA_LEN and the inline tag");
    let (opened, opened_len) = dec.do_final().expect("tag check");
    assert_eq!(&opened[..opened_len], &message[..]);
}

/// The decryptor cannot know until the final call whether the tag is inline, so it buffers up to
/// the full `FINAL_LEN` -- a capacity-filling ciphertext with its tag after it -- and decrypts that
/// through the inline `do_final`. The detached final holds the ciphertext to the same capacity as
/// the encryptor, so the room kept for an inline tag cannot be used to smuggle a longer message
/// past it.
#[test]
fn the_buffering_decryptor_holds_the_inline_tag_but_caps_detached_ciphertext() {
    type Enc = CcmEncryptor<AES128Internal, 16, 16, 12, 16, 32, 32, { 32 + 16 }>;
    type Dec = CcmDecryptor<AES128Internal, 16, 16, 12, 16, 32, 32, { 32 + 16 }>;
    let k = key::<16>(APPENDIX_C_KEY);
    let mut nothing = [0u8; 0];
    let message = [0x5Au8; 32];

    let (mut enc, nonce) = Enc::do_encrypt_init(&k).expect("init");
    enc.do_encrypt_out(&message, &mut nothing).expect("fills the capacity");
    let (inline, inline_len) = enc.do_final().expect("final");
    assert_eq!(inline_len, 48, "32 bytes of ciphertext and the 16-byte tag");

    let mut dec = Dec::do_decrypt_init(&k, &nonce).expect("init");
    dec.do_decrypt_out(&inline[..inline_len], &mut nothing)
        .expect("all of FINAL_LEN may be buffered");
    let (out, n) = dec.do_final().expect("tag check");
    assert_eq!(&out[..n], &message[..]);

    // One byte past FINAL_LEN is refused even though the tag might be inline.
    let mut dec = Dec::do_decrypt_init(&k, &nonce).expect("init");
    assert!(matches!(
        dec.do_decrypt_out(&[0u8; 49], &mut nothing),
        Err(SymmetricCipherError::GenericError(_))
    ));

    // Detached, the 48 buffered bytes would all be ciphertext: more than the capacity.
    let mut dec = Dec::do_decrypt_init(&k, &nonce).expect("init");
    dec.do_decrypt_out(&inline[..inline_len], &mut nothing).expect("buffered");
    let mut out = [0u8; 48];
    assert!(matches!(
        dec.do_final_out_detached(&[0u8; 16], &mut out),
        Err(SymmetricCipherError::GenericError(_))
    ));

    // ...and exactly the capacity is fine.
    let mut detached = [0u8; 32];
    let (_, _, tag) = Enc::encrypt_out_rng_detached(
        &k,
        &mut FixedSeedRNG::<12>::new(nonce),
        &[],
        &message,
        &mut detached,
    )
    .expect("one-shot");
    let mut dec = Dec::do_decrypt_init(&k, &nonce).expect("init");
    dec.do_decrypt_out(&detached, &mut nothing).expect("buffered");
    let n = dec.do_final_out_detached(&tag, &mut out).expect("tag check");
    assert_eq!(&out[..n], &message[..]);
}

/// The trait one-shots know both lengths up front, so they use `Ccm` directly rather than imposing
/// the streaming adapter's fixed buffer on otherwise valid packets.
#[test]
fn trait_one_shots_are_not_capped_by_final_len() {
    type Enc = CcmEncryptor<AES128Internal, 16, 16, 12, 16, 48, 48, 64>;
    type Dec = CcmDecryptor<AES128Internal, 16, 16, 12, 16, 48, 48, 64>;

    let k = key::<16>(APPENDIX_C_KEY);
    let aad = [0x3Cu8; 128];
    let plaintext = [0xA5u8; 4096];
    let mut ciphertext = [0u8; 4096];
    let (nonce, written, tag) = Enc::encrypt_out_rng_detached(
        &k,
        &mut FixedSeedRNG::<12>::new([0x24u8; 12]),
        &aad,
        &plaintext,
        &mut ciphertext,
    )
    .expect("one-shot payload and AAD may exceed FINAL_LEN");
    assert_eq!(written, plaintext.len());

    let mut opened = [0u8; 4096];
    let opened_len =
        Dec::decrypt_out_detached(&k, &nonce, &aad, &ciphertext[..written], &tag, &mut opened)
            .expect("direct one-shot decryption");
    assert_eq!(&opened[..opened_len], &plaintext);
}

/// Sec 6.2 step 1: "If Clen <= Tlen, then return INVALID". The inline layout has to reject a `C`
/// too short to contain a tag before it can split one off.
///
/// A `C` of exactly `TAG_LEN` octets is *not* too short: it is the empty payload of Sec 5.3's
/// footnote, and must authenticate.
///
/// All three inline entry points -- the inherent one-shot, the buffering decryptor's `do_final`
/// and its `decrypt_out_with_aad` -- must report the same malformed input with the same variant,
/// [`SymmetricCipherError::DecryptionFailed`], which is what [`SymmetricCipherDecryptor::do_final`]
/// specifies for a malformed ciphertext; a caller telling "malformed" from "inauthentic" must not
/// get a different answer depending on which one it used.
#[test]
fn an_inline_ciphertext_shorter_than_the_tag_is_rejected() {
    type Enc = Ccm<AES128Internal, Encrypting, 16, 16, 12, 16>;
    type Dec = Ccm<AES128Internal, Decrypting, 16, 16, 12, 16>;
    type StreamDec = CcmDecryptor<AES128Internal, 16, 16, 12, 16, 48, 48, 64>;
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
                StreamDec::decrypt_out_with_aad(&k, &nonce, &[], &short, &mut out),
                Err(SymmetricCipherError::DecryptionFailed)
            ),
            "a {len}-byte C cannot carry a 16-byte tag (decrypt_out_with_aad)"
        );
        let mut dec = StreamDec::do_decrypt_init(&k, &nonce).expect("init");
        dec.do_decrypt_out(&short, &mut nothing).expect("buffered");
        assert!(
            matches!(dec.do_final(), Err(SymmetricCipherError::DecryptionFailed)),
            "a {len}-byte C cannot carry a 16-byte tag (do_final)"
        );
    }

    // Exactly TAG_LEN: an empty payload plus its tag, which must verify.
    let mut inline = [0u8; 16];
    let n = Enc::encrypt_out(&k, &nonce, &[], &[], &mut inline).expect("encryption");
    assert_eq!(n, 16);
    assert_eq!(Dec::decrypt_out(&k, &nonce, &[], &inline, &mut out).expect("decryption"), 0);
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
        buffer_len_error(Enc::encrypt_out_detached(&k, &nonce, &[], &plaintext, &mut too_small)),
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
        Enc::encrypt_out_detached(&wrong, &[0u8; 12], &[], &[], &mut out),
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

/// Pins the "Memory Usage" table in the crate docs: `Ccm` is 264/296/328 B for AES-128/192/256,
/// independent of `NONCE_LEN`/`TAG_LEN`, and the buffering pair is `AAD_LEN + FINAL_LEN`.
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

    // The buffering adapters: AAD_LEN + FINAL_LEN each (an `aad` array and a `data` array), so a
    // small AAD capacity is a small AAD array rather than a second payload-sized one.
    assert_eq!(
        size_of::<CcmEncryptor<AES128Internal, 16, 16, 12, 16, 64, 4096, 4112>>(),
        size_of::<CcmDecryptor<AES128Internal, 16, 16, 12, 16, 64, 4096, 4112>>()
    );
    let small_aad = size_of::<CcmEncryptor<AES128Internal, 16, 16, 12, 16, 64, 4096, 4112>>();
    assert!(small_aad >= 64 + 4112);
    assert!(small_aad < 2 * 4096, "the AAD array is AAD_LEN long, not payload-sized");
    assert_eq!(
        size_of::<CcmEncryptor<AES128Internal, 16, 16, 12, 16, 4096, 4096, 4112>>() - small_aad,
        4096 - 64,
        "the value grows by exactly the AAD capacity"
    );
}

/// The streaming adapters' buffer cap is the 512 KiB [`CCM_MAX_BUFFER_LEN`]'s docs promise. The
/// doctests on [`CcmEncryptor`] check only that the cap compiles and one byte more does not, which
/// holds for any value, so the value itself is pinned here.
#[test]
fn the_buffer_cap_is_512_kib() {
    assert_eq!(CCM_MAX_BUFFER_LEN, 512 * 1024);
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
