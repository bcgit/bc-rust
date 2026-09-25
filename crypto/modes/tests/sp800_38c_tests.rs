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

use bouncycastle_aes::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, SymmetricCipherDecryptor, SymmetricCipherEncryptor,
};
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_core_test_framework::symmetric_ciphers::TestFrameworkAEADCipher;
use bouncycastle_hex as hex;
use bouncycastle_modes::{Ccm, CcmDecryptor, CcmEncryptor, Decrypting, Encrypting};

/// Appendix C's key, the same in all four examples: `40414243 44454647 48494a4b 4c4d4e4f`.
const APPENDIX_C_KEY: &str = "404142434445464748494a4b4c4d4e4f";

fn key<const N: usize>(hex_key: &str) -> KeyMaterial<N> {
    let bytes = hex::decode(hex_key).expect("valid hex key");
    assert_eq!(bytes.len(), N, "key length must match the parameter set");
    KeyMaterial::<N>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey)
        .expect("a symmetric cipher key")
}

/// [`SymmetricCipherError`] is deliberately not `PartialEq` -- it carries `&'static str` detail that
/// tests have no business pinning -- so these two match on the variant instead.
fn is_tag_failure<T>(r: Result<T, SymmetricCipherError>) -> bool {
    matches!(r, Err(SymmetricCipherError::AEADTagCheckFailed))
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
    P: bouncycastle_core::traits::ElectronicCodeBook<KEY_LEN, 16>,
>(
    name: &str,
    key_hex: &str,
    nonce_hex: &str,
    aad: &[u8],
    plaintext_hex: &str,
    c_hex: &str,
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
    let (written, tag) = Enc::<P, KEY_LEN, NONCE_LEN, TAG_LEN>::encrypt_detached(
        &k, &nonce, aad, &plaintext, &mut ct,
    )
    .expect("encryption");
    assert_eq!(written, plaintext.len(), "{name}: CCM never expands the payload");
    assert_eq!(ct, want_ct, "{name}: ciphertext");
    assert_eq!(tag, want_tag, "{name}: tag");

    // --- Sec 6.1, the appendix's own inline `ciphertext || tag` layout ---
    let mut inline = vec![0u8; plaintext.len() + TAG_LEN];
    let n =
        Enc::<P, KEY_LEN, NONCE_LEN, TAG_LEN>::encrypt(&k, &nonce, aad, &plaintext, &mut inline)
            .expect("encryption");
    assert_eq!(n, c.len(), "{name}: inline output length");
    assert_eq!(inline, c, "{name}: the whole C string of Appendix C");

    // --- Sec 6.2, both layouts ---
    let mut recovered = vec![0u8; plaintext.len()];
    let n = Dec::<P, KEY_LEN, NONCE_LEN, TAG_LEN>::decrypt_detached(
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
    let n = Dec::<P, KEY_LEN, NONCE_LEN, TAG_LEN>::decrypt(&k, &nonce, aad, &c, &mut recovered)
        .expect("decryption");
    assert_eq!(n, plaintext.len());
    assert_eq!(recovered, plaintext, "{name}: inline round trip");

    // --- Every ciphertext chunking through the streaming API gives the same answer ---
    // Sec 3 says CCM is not a streaming mode, and `Ccm` handles that by taking the payload length
    // up front; given that, the chunking must be invisible, exactly as for the other modes.
    for chunk in [1usize, 2, 3, 7, 16, 17] {
        let mut ccm = Enc::<P, KEY_LEN, NONCE_LEN, TAG_LEN>::new(&k, &nonce, aad, plaintext.len())
            .expect("streaming init");
        let mut streamed = plaintext.clone();
        for piece in streamed.chunks_mut(chunk) {
            ccm.do_encrypt_update(piece).expect("update");
        }
        let streamed_tag = ccm.do_encrypt_final().expect("final");
        assert_eq!(streamed, want_ct, "{name}: ciphertext, streamed in {chunk}-byte chunks");
        assert_eq!(streamed_tag, want_tag, "{name}: tag, streamed in {chunk}-byte chunks");

        let mut ccm = Dec::<P, KEY_LEN, NONCE_LEN, TAG_LEN>::new(&k, &nonce, aad, plaintext.len())
            .expect("streaming init");
        for piece in streamed.chunks_mut(chunk) {
            ccm.do_decrypt_update(piece).expect("update");
        }
        ccm.do_decrypt_final(want_tag.try_into().expect("TAG_LEN bytes")).expect("tag check");
        assert_eq!(streamed, plaintext, "{name}: plaintext, streamed in {chunk}-byte chunks");
    }

    // --- Every bit of the tag is checked, and so is every byte of the ciphertext and the AAD ---
    let tag_arr: &[u8; TAG_LEN] = want_tag.try_into().expect("TAG_LEN bytes");
    for i in 0..TAG_LEN {
        let mut bad = *tag_arr;
        bad[i] ^= 0x80;
        let mut out = vec![0u8; plaintext.len()];
        assert!(
            is_tag_failure(Dec::<P, KEY_LEN, NONCE_LEN, TAG_LEN>::decrypt_detached(
                &k, &nonce, aad, want_ct, &bad, &mut out
            )),
            "{name}: a flipped bit in tag byte {i} must be caught"
        );
        assert!(
            out.iter().all(|b| *b == 0),
            "{name}: Sec 6.2 -- the payload must not be revealed on INVALID"
        );
    }
    if !want_ct.is_empty() {
        let mut bad_ct = want_ct.to_vec();
        bad_ct[0] ^= 0x01;
        let mut out = vec![0u8; plaintext.len()];
        assert!(
            is_tag_failure(Dec::<P, KEY_LEN, NONCE_LEN, TAG_LEN>::decrypt_detached(
                &k, &nonce, aad, &bad_ct, tag_arr, &mut out
            )),
            "{name}: a modified ciphertext must be caught"
        );
    }
    if !aad.is_empty() {
        let mut bad_aad = aad.to_vec();
        bad_aad[0] ^= 0x01;
        let mut out = vec![0u8; plaintext.len()];
        assert!(
            is_tag_failure(Dec::<P, KEY_LEN, NONCE_LEN, TAG_LEN>::decrypt_detached(
                &k, &nonce, &bad_aad, want_ct, tag_arr, &mut out
            )),
            "{name}: CCM authenticates the AAD as well as the payload"
        );
    }
    // Truncating the AAD by one byte changes `a`, which A.2.2 encodes in front of it, so this must
    // fail even though the remaining bytes are genuine.
    if aad.len() > 1 {
        let mut out = vec![0u8; plaintext.len()];
        assert!(
            is_tag_failure(Dec::<P, KEY_LEN, NONCE_LEN, TAG_LEN>::decrypt_detached(
                &k,
                &nonce,
                &aad[..aad.len() - 1],
                want_ct,
                tag_arr,
                &mut out
            )),
            "{name}: the AAD length is authenticated, not just its contents"
        );
    }
    // A different nonce must fail too: it changes both `B0` and every counter block.
    let mut bad_nonce = nonce;
    bad_nonce[0] ^= 0x01;
    let mut out = vec![0u8; plaintext.len()];
    assert!(
        is_tag_failure(Dec::<P, KEY_LEN, NONCE_LEN, TAG_LEN>::decrypt_detached(
            &k, &bad_nonce, aad, want_ct, tag_arr, &mut out
        )),
        "{name}: the nonce is authenticated"
    );
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
    );
}

/// An empty payload and an empty AAD, which Appendix C never shows but Sec 5.3 explicitly permits:
/// "A may be the empty string", and its footnote, "The payload may also be empty, in which case
/// the specification degenerates to an authentication mode on the associated data".
///
/// With `a = 0` and `p = 0` the formatted string is `B0` alone, so `r = 0` and the MAC is
/// `MSB_Tlen(Y0)`. There is no official vector for it; what is checked here is that all four
/// combinations of empty/non-empty are accepted, give distinct tags, and round-trip.
#[test]
fn empty_payload_and_empty_aad_are_permitted() {
    type Enc = Ccm<AES128Internal, Encrypting, 16, 16, 12, 16>;
    type Dec = Ccm<AES128Internal, Decrypting, 16, 16, 12, 16>;
    let k = key::<16>(APPENDIX_C_KEY);
    let nonce = [0x42u8; 12];
    let aad = b"header";
    let payload = b"payload";

    let mut tags = Vec::new();
    for (a, p) in
        [(&[][..], &[][..]), (&aad[..], &[][..]), (&[][..], &payload[..]), (&aad[..], &payload[..])]
    {
        let mut ct = vec![0u8; p.len()];
        let (written, tag) = Enc::encrypt_detached(&k, &nonce, a, p, &mut ct).expect("encryption");
        assert_eq!(written, p.len());

        let mut back = vec![0u8; p.len()];
        let n = Dec::decrypt_detached(&k, &nonce, a, &ct, &tag, &mut back).expect("decryption");
        assert_eq!(n, p.len());
        assert_eq!(back, p, "round trip with aad {} / payload {}", a.len(), p.len());
        tags.push(tag);
    }

    // An empty AAD must not be treated as the same message as a present one, nor an empty payload
    // as the same as a present one: A.2.1's Adata bit and A.2.1's `Q` respectively make them
    // distinct inputs to the MAC.
    for i in 0..tags.len() {
        for j in i + 1..tags.len() {
            assert_ne!(tags[i], tags[j], "tags {i} and {j} must differ");
        }
    }
}

/// The shared framework, told the streaming capacity of a buffering pair, `FINAL_LEN - TAG_LEN`,
/// so that it caps every message it streams at that length.
fn framework(capacity: usize) -> TestFrameworkAEADCipher {
    let mut framework = TestFrameworkAEADCipher::new();
    framework.max_message_len = capacity;
    framework
}

/// The whole [`AEADCipherEncryptor`] / [`AEADCipherDecryptor`] contract, through the shared
/// framework, for the buffering [`CcmEncryptor`] / [`CcmDecryptor`] pair.
///
/// `FINAL_LEN` is 256, so the streaming capacity `FINAL_LEN - TAG_LEN` is comfortably above the
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
        CcmEncryptor<AES128Internal, 16, 16, 12, 16, 256>,
        CcmDecryptor<AES128Internal, 16, 16, 12, 16, 256>,
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
        CcmEncryptor<AES192Internal, 24, 16, 12, 16, 256>,
        CcmDecryptor<AES192Internal, 24, 16, 12, 16, 256>,
    >();
    framework(256 - 16).test_encryptor_decryptor::<
        32,
        12,
        16,
        256,
        CcmEncryptor<AES256Internal, 32, 16, 12, 16, 256>,
        CcmDecryptor<AES256Internal, 32, 16, 12, 16, 256>,
    >();
    // A 13-byte nonce (q = 2) with an 8-byte tag: the parameterization IEEE 802.11 CCMP uses, and
    // the one A.1's narrowest length field applies to.
    framework(256 - 8).test_encryptor_decryptor::<
        16,
        13,
        8,
        256,
        CcmEncryptor<AES128Internal, 16, 16, 13, 8, 256>,
        CcmDecryptor<AES128Internal, 16, 16, 13, 8, 256>,
    >();
}

/// The buffering pair must agree with the non-buffering [`Ccm`] byte for byte -- they are two
/// routes to the same Sec 6.1 -- and it must be driven with a caller-chosen nonce to check that,
/// which is what `do_encrypt_init_rng` and a fixed-output RNG provide.
#[test]
fn the_buffering_pair_agrees_with_the_direct_api_on_appendix_c3() {
    type Enc = CcmEncryptor<AES128Internal, 16, 16, 12, 8, 256>;
    type Dec = CcmDecryptor<AES128Internal, 16, 16, 12, 8, 256>;

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
        assert_eq!(enc.update_out_len(piece.len()), 0, "CCM releases nothing mid-stream");
        assert_eq!(enc.do_update_out(piece, &mut nothing).expect("update"), 0);
    }
    let mut flushed = [0u8; 256];
    let (len, tag) = enc.do_final_out_detached(&mut flushed).expect("final");
    assert_eq!(len, plaintext.len(), "everything is flushed at finalization");
    assert_eq!(&flushed[..len], want_ct, "C.3 ciphertext via the trait");
    assert_eq!(&tag[..], want_tag, "C.3 tag via the trait");

    let mut dec = Dec::do_decrypt_init(&k, &nonce).expect("init");
    dec.do_update_aad(&aad).expect("aad");
    for piece in want_ct.chunks(5) {
        assert_eq!(dec.do_update_out(piece, &mut nothing).expect("update"), 0);
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
    enc.do_update_out(&plaintext, &mut nothing).expect("update");
    let (inline, inline_len) = enc.do_final().expect("final");
    assert_eq!(&inline[..inline_len], &c[..], "C.3 `C` via the inline do_final");
    let mut dec = Dec::do_decrypt_init(&k, &nonce).expect("init");
    dec.do_update_aad(&aad).expect("aad");
    for piece in c.chunks(5) {
        assert_eq!(dec.do_update_out(piece, &mut nothing).expect("update"), 0);
    }
    let (out, n) = dec.do_final().expect("tag check");
    assert_eq!(&out[..n], &plaintext[..], "C.3 plaintext via the inline do_final");
}

/// A message longer than the streaming capacity, `FINAL_LEN - TAG_LEN`, is refused rather than
/// silently truncated, and so is an oversized AAD. This is the cost of the trait's length-free `do_encrypt_init`; see
/// [`CcmEncryptor`].
#[test]
fn the_buffering_pair_refuses_a_message_past_its_buffer() {
    // A 32-byte capacity: `FINAL_LEN` leaves room for the 16-byte inline tag after it.
    type Enc = CcmEncryptor<AES128Internal, 16, 16, 12, 16, { 32 + 16 }>;
    let k = key::<16>(APPENDIX_C_KEY);
    let mut nothing = [0u8; 0];

    let (mut enc, _) = Enc::do_encrypt_init(&k).expect("init");
    assert!(matches!(
        enc.do_update_out(&[0u8; 33], &mut nothing),
        Err(SymmetricCipherError::GenericError(_))
    ));

    // In two calls that together overflow, the first must succeed and the second be refused.
    let (mut enc, _) = Enc::do_encrypt_init(&k).expect("init");
    assert_eq!(enc.do_update_out(&[0u8; 20], &mut nothing).expect("fits"), 0);
    assert!(matches!(
        enc.do_update_out(&[0u8; 13], &mut nothing),
        Err(SymmetricCipherError::GenericError(_))
    ));

    let (mut enc, _) = Enc::do_encrypt_init(&k).expect("init");
    assert!(matches!(enc.do_update_aad(&[0u8; 33]), Err(SymmetricCipherError::GenericError(_))));
}

/// Filling the streaming capacity *exactly* must be accepted, not refused: `CcmBuffer::do_update_aad`
/// / `do_update_out` check `end > FINAL_LEN - TAG_LEN`, so using all of it is legitimate and only
/// one byte more is not. Both boundary sides, in one call and split across two.
#[test]
fn the_buffering_pair_accepts_a_message_that_exactly_fills_its_buffer() {
    // A 32-byte capacity: `FINAL_LEN` leaves room for the 16-byte inline tag after it.
    type Enc = CcmEncryptor<AES128Internal, 16, 16, 12, 16, { 32 + 16 }>;
    let k = key::<16>(APPENDIX_C_KEY);
    let mut nothing = [0u8; 0];

    let (mut enc, _) = Enc::do_encrypt_init(&k).expect("init");
    assert_eq!(enc.do_update_out(&[0u8; 32], &mut nothing).expect("exactly fills the capacity"), 0);

    let (mut enc, _) = Enc::do_encrypt_init(&k).expect("init");
    assert_eq!(enc.do_update_out(&[0u8; 20], &mut nothing).expect("fits"), 0);
    assert_eq!(
        enc.do_update_out(&[0u8; 12], &mut nothing).expect("exactly fills the remaining space"),
        0
    );

    let (mut enc, _) = Enc::do_encrypt_init(&k).expect("init");
    assert!(enc.do_update_aad(&[0u8; 32]).is_ok(), "AAD exactly filling the capacity is accepted");
}

/// The decryptor cannot know until the final call whether the tag is inline, so it buffers up to
/// the full `FINAL_LEN` -- a capacity-filling ciphertext with its tag after it -- and decrypts that
/// through the inline `do_final`. The detached final holds the ciphertext to the same capacity as
/// the encryptor, so the room kept for an inline tag cannot be used to smuggle a longer message
/// past it.
#[test]
fn the_buffering_decryptor_holds_the_inline_tag_but_caps_detached_ciphertext() {
    type Enc = CcmEncryptor<AES128Internal, 16, 16, 12, 16, { 32 + 16 }>;
    type Dec = CcmDecryptor<AES128Internal, 16, 16, 12, 16, { 32 + 16 }>;
    let k = key::<16>(APPENDIX_C_KEY);
    let mut nothing = [0u8; 0];
    let message = [0x5Au8; 32];

    let (mut enc, nonce) = Enc::do_encrypt_init(&k).expect("init");
    enc.do_update_out(&message, &mut nothing).expect("fills the capacity");
    let (inline, inline_len) = enc.do_final().expect("final");
    assert_eq!(inline_len, 48, "32 bytes of ciphertext and the 16-byte tag");

    let mut dec = Dec::do_decrypt_init(&k, &nonce).expect("init");
    dec.do_update_out(&inline[..inline_len], &mut nothing)
        .expect("all of FINAL_LEN may be buffered");
    let (out, n) = dec.do_final().expect("tag check");
    assert_eq!(&out[..n], &message[..]);

    // One byte past FINAL_LEN is refused even though the tag might be inline.
    let mut dec = Dec::do_decrypt_init(&k, &nonce).expect("init");
    assert!(matches!(
        dec.do_update_out(&[0u8; 49], &mut nothing),
        Err(SymmetricCipherError::GenericError(_))
    ));

    // Detached, the 48 buffered bytes would all be ciphertext: more than the capacity.
    let mut dec = Dec::do_decrypt_init(&k, &nonce).expect("init");
    dec.do_update_out(&inline[..inline_len], &mut nothing).expect("buffered");
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
    dec.do_update_out(&detached, &mut nothing).expect("buffered");
    let n = dec.do_final_out_detached(&tag, &mut out).expect("tag check");
    assert_eq!(&out[..n], &message[..]);
}

/// The trait one-shots know both lengths up front, so they use `Ccm` directly rather than imposing
/// the streaming adapter's fixed buffer on otherwise valid packets.
#[test]
fn trait_one_shots_are_not_capped_by_final_len() {
    type Enc = CcmEncryptor<AES128Internal, 16, 16, 12, 16, 64>;
    type Dec = CcmDecryptor<AES128Internal, 16, 16, 12, 16, 64>;

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

/// Resuming a part-way-open keystream block into the batched fours/pairs path.
///
/// None of the Appendix C vectors are long enough for this: the largest, C.4, is 32 bytes (two
/// blocks), too short for a small opening call to leave enough afterwards to reach
/// `apply_keystream_batch`'s fours/pairs path at all. Every chunking `check_vector` sweeps is also
/// *uniform*, so the only call that can ever see `ks_pos` strictly between `0` and `BLOCK_LEN` on
/// entry is a small final remainder -- never one big enough to batch. A first small,
/// non-block-aligned call followed by one call spanning several whole blocks exercises exactly
/// that: the batched blocks must still line up with the keystream the small call left partway
/// through, not silently skip over it. Checked against a one-shot encryption of the identical
/// plaintext, which does not go anywhere near this split.
#[test]
fn resuming_a_part_way_open_block_agrees_with_a_one_shot() {
    type Enc = Ccm<AES128Internal, Encrypting, 16, 16, 12, 16>;
    let k = key::<16>(APPENDIX_C_KEY);
    let nonce = [0x24u8; 12];
    let aad = b"header";
    // Long enough that, after a several-byte opening call, what remains spans at least one
    // four-block batch and one pair-block batch (4 + 2 = 6 blocks = 96 bytes) plus a short tail.
    let plaintext: Vec<u8> = (0..123u8).collect();

    let mut reference = vec![0u8; plaintext.len()];
    let (_, reference_tag) =
        Enc::encrypt_detached(&k, &nonce, aad, &plaintext, &mut reference).expect("one-shot");

    for first in [1usize, 3, 5, 15] {
        let mut ccm = Enc::new(&k, &nonce, aad, plaintext.len()).expect("streaming init");
        let mut streamed = plaintext.clone();
        let (head, rest) = streamed.split_at_mut(first);
        ccm.do_encrypt_update(head).expect("small first update");
        ccm.do_encrypt_update(rest).expect("large second update");
        let tag = ccm.do_encrypt_final().expect("final");
        assert_eq!(streamed, reference, "ciphertext, resuming a {first}-byte-open block");
        assert_eq!(tag, reference_tag, "tag, resuming a {first}-byte-open block");
    }
}

/// Sec 6.2 step 1: "If Clen <= Tlen, then return INVALID". The inline layout has to reject a `C`
/// too short to contain a tag before it can split one off.
///
/// A `C` of exactly `TAG_LEN` octets is *not* too short: it is the empty payload of Sec 5.3's
/// footnote, and must authenticate.
#[test]
fn an_inline_ciphertext_shorter_than_the_tag_is_rejected() {
    type Enc = Ccm<AES128Internal, Encrypting, 16, 16, 12, 16>;
    type Dec = Ccm<AES128Internal, Decrypting, 16, 16, 12, 16>;
    let k = key::<16>(APPENDIX_C_KEY);
    let nonce = [0u8; 12];
    let mut out = [0u8; 16];

    for len in 0..16 {
        assert!(
            matches!(
                Dec::decrypt(&k, &nonce, &[], &vec![0u8; len], &mut out),
                Err(SymmetricCipherError::GenericError(_))
            ),
            "a {len}-byte C cannot carry a 16-byte tag"
        );
    }

    // Exactly TAG_LEN: an empty payload plus its tag, which must verify.
    let mut inline = [0u8; 16];
    let n = Enc::encrypt(&k, &nonce, &[], &[], &mut inline).expect("encryption");
    assert_eq!(n, 16);
    assert_eq!(Dec::decrypt(&k, &nonce, &[], &inline, &mut out).expect("decryption"), 0);
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
        buffer_len_error(Enc::encrypt_detached(&k, &nonce, &[], &plaintext, &mut too_small)),
        Some(24)
    );

    let mut too_small = [0u8; 39];
    assert_eq!(
        buffer_len_error(Enc::encrypt(&k, &nonce, &[], &plaintext, &mut too_small)),
        Some(40)
    );

    let mut ct = [0u8; 40];
    Enc::encrypt(&k, &nonce, &[], &plaintext, &mut ct).expect("encryption");
    let mut too_small = [0u8; 23];
    assert_eq!(buffer_len_error(Dec::decrypt(&k, &nonce, &[], &ct, &mut too_small)), Some(24));
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
        Enc::encrypt_detached(&wrong, &[0u8; 12], &[], &[], &mut out),
        Err(SymmetricCipherError::KeyMaterialError(_))
    ));
    assert!(matches!(
        Enc::new(&wrong, &[0u8; 12], &[], 0),
        Err(SymmetricCipherError::KeyMaterialError(_))
    ));
    assert!(matches!(
        Dec::decrypt(&wrong, &[0u8; 12], &[], &[0u8; 16], &mut out),
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
    enc.do_encrypt_update(&mut data).expect("encrypt update");
    let tag = enc.do_encrypt_final().expect("encrypt final");

    let mut dec = Dec::new(&k, &nonce, b"aad", 4).expect("decrypt init");
    dec.do_decrypt_update(&mut data).expect("decrypt update");
    dec.do_decrypt_final(&tag).expect("decrypt final");
    assert_eq!(data, [1u8, 2, 3, 4]);
}

// ---- memory ------------------------------------------------------------------------------

/// Pins the "Memory Usage" table in the crate docs: `Ccm` is 256/288/320 B for AES-128/192/256,
/// independent of `NONCE_LEN`/`TAG_LEN`, and the buffering pair is `2 * FINAL_LEN`.
#[test]
fn sizes_match_the_documented_memory_table() {
    use core::mem::size_of;

    assert_eq!(size_of::<Ccm<AES128Internal, Encrypting, 16, 16, 12, 16>>(), 256);
    assert_eq!(size_of::<Ccm<AES192Internal, Encrypting, 24, 16, 12, 16>>(), 288);
    assert_eq!(size_of::<Ccm<AES256Internal, Encrypting, 32, 16, 12, 16>>(), 320);

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

    // The buffering adapters: 2 * FINAL_LEN each (an `aad` array and a `data` array).
    assert_eq!(
        size_of::<CcmEncryptor<AES128Internal, 16, 16, 12, 16, 4096>>(),
        size_of::<CcmDecryptor<AES128Internal, 16, 16, 12, 16, 4096>>()
    );
    assert!(size_of::<CcmEncryptor<AES128Internal, 16, 16, 12, 16, 4096>>() >= 2 * 4096);
}

// ---- moved from crypto/modes/src/ccm.rs's in-file unit tests -----------------------------

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

/// The declared payload length is inside `B0`, so neither direction may be finalized with the
/// wrong amount of data.
#[test]
fn a_short_or_long_payload_is_refused() {
    let k = key::<16>(APPENDIX_C_KEY);
    let nonce = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16];
    let mut ccm = Ccm::<AES128Internal, Encrypting, 16, 16, 7, 4>::new(&k, &nonce, &[], 8).unwrap();
    let mut too_much = [0u8; 9];
    assert!(
        matches!(ccm.do_encrypt_update(&mut too_much), Err(SymmetricCipherError::StateError(_))),
        "9 bytes against a declared 8"
    );
    let mut some = [0u8; 4];
    ccm.do_encrypt_update(&mut some).expect("4 of the 8 declared bytes");
    assert!(
        matches!(ccm.do_encrypt_final(), Err(SymmetricCipherError::StateError(_))),
        "finalizing 4 bytes short"
    );
}
