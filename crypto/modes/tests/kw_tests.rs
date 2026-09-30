//! Known-answer and behaviour tests for KW and KWP over AES.
//!
//! The known answers are the published ones: RFC 3394 Sec 4 (all six KW vectors, covering every
//! AES key length and 128-, 192- and 256-bit key data) and RFC 5649 Sec 6 (both KWP examples, the
//! second of which is the 7-octet case that takes the single-block path of SP 800-38F Algorithm 5
//! step 5 and Algorithm 6 step 3). SP 800-38F itself publishes no vectors; the NIST ACVP sets are
//! in `acvp_kw_tests.rs`.
//!
//! The behaviour tests run the shared `TestFrameworkKeyWrap` -- round trips, determinism, the
//! length helpers, every error condition -- for each AES key length at several payload lengths,
//! and then pin the properties that distinguish the two algorithms from each other and from a
//! plain block encryption.

use bouncycastle_aes::aes_internal::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{ElectronicCodeBook, KeyUnwrapper, KeyWrapper};
use bouncycastle_core_test_framework::key_wrap::TestFrameworkKeyWrap;
use bouncycastle_hex as hex;
use bouncycastle_modes::kw::{
    kw_ciphertext_len_is_valid, kw_plaintext_len_is_valid, kw_wrapped_len,
};
use bouncycastle_modes::kwp::{
    kwp_ciphertext_len_is_valid, kwp_plaintext_len_is_valid, kwp_wrapped_len,
};
use bouncycastle_modes::{Kw, Kwp};

type Aes128Kw = Kw<AES128Internal, 16>;
type Aes192Kw = Kw<AES192Internal, 24>;
type Aes256Kw = Kw<AES256Internal, 32>;
type Aes128Kwp = Kwp<AES128Internal, 16>;
type Aes192Kwp = Kwp<AES192Internal, 24>;
type Aes256Kwp = Kwp<AES256Internal, 32>;

fn bytes<const N: usize>(hex_str: &str) -> [u8; N] {
    hex::decode(hex_str).expect("valid hex").try_into().expect("the expected length")
}

fn kek<const N: usize>(hex_str: &str) -> KeyMaterial<N> {
    KeyMaterial::<N>::from_bytes_as_type(&bytes::<N>(hex_str), KeyType::SymmetricCipherKey)
        .expect("a symmetric cipher key")
}

// ---- RFC 3394 Sec 4: the KW vectors --------------------------------------------------------

/// RFC 3394 Sec 4.1-4.6 all use the same KEK bytes, truncated to the key length, and the same
/// key data, truncated to the data length.
const RFC3394_KEK: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const RFC3394_KEY_DATA: &str = "00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f";

/// Sec 4.1, "Wrap 128 bits of Key Data with a 128-bit KEK".
#[test]
fn rfc3394_4_1_wrap_128_bits_with_a_128_bit_kek() {
    TestFrameworkKeyWrap::new().test_kat::<16, 16, 24, Aes128Kw>(
        &bytes(&RFC3394_KEK[..32]),
        &bytes(&RFC3394_KEY_DATA[..32]),
        &bytes("1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5"),
    );
}

/// Sec 4.2, "Wrap 128 bits of Key Data with a 192-bit KEK".
#[test]
fn rfc3394_4_2_wrap_128_bits_with_a_192_bit_kek() {
    TestFrameworkKeyWrap::new().test_kat::<24, 16, 24, Aes192Kw>(
        &bytes(&RFC3394_KEK[..48]),
        &bytes(&RFC3394_KEY_DATA[..32]),
        &bytes("96778b25ae6ca435f92b5b97c050aed2468ab8a17ad84e5d"),
    );
}

/// Sec 4.3, "Wrap 128 bits of Key Data with a 256-bit KEK".
#[test]
fn rfc3394_4_3_wrap_128_bits_with_a_256_bit_kek() {
    TestFrameworkKeyWrap::new().test_kat::<32, 16, 24, Aes256Kw>(
        &bytes(RFC3394_KEK),
        &bytes(&RFC3394_KEY_DATA[..32]),
        &bytes("64e8c3f9ce0f5ba263e9777905818a2a93c8191e7d6e8ae7"),
    );
}

/// Sec 4.4, "Wrap 192 bits of Key Data with a 192-bit KEK".
#[test]
fn rfc3394_4_4_wrap_192_bits_with_a_192_bit_kek() {
    TestFrameworkKeyWrap::new().test_kat::<24, 24, 32, Aes192Kw>(
        &bytes(&RFC3394_KEK[..48]),
        &bytes(&RFC3394_KEY_DATA[..48]),
        &bytes("031d33264e15d33268f24ec260743edce1c6c7ddee725a936ba814915c6762d2"),
    );
}

/// Sec 4.5, "Wrap 192 bits of Key Data with a 256-bit KEK".
#[test]
fn rfc3394_4_5_wrap_192_bits_with_a_256_bit_kek() {
    TestFrameworkKeyWrap::new().test_kat::<32, 24, 32, Aes256Kw>(
        &bytes(RFC3394_KEK),
        &bytes(&RFC3394_KEY_DATA[..48]),
        &bytes("a8f9bc1612c68b3ff6e6f4fbe30e71e4769c8b80a32cb8958cd5d17d6b254da1"),
    );
}

/// Sec 4.6, "Wrap 256 bits of Key Data with a 256-bit KEK".
#[test]
fn rfc3394_4_6_wrap_256_bits_with_a_256_bit_kek() {
    TestFrameworkKeyWrap::new().test_kat::<32, 32, 40, Aes256Kw>(
        &bytes(RFC3394_KEK),
        &bytes(RFC3394_KEY_DATA),
        &bytes("28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21"),
    );
}

// ---- RFC 5649 Sec 6: the KWP vectors -------------------------------------------------------

const RFC5649_KEK: &str = "5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8";

/// "The first example wraps 20 octets of key data with a 192-bit KEK": 20 bytes pad to 24, and
/// the 32-byte result goes through the wrapping function proper.
#[test]
fn rfc5649_wrap_20_octets_with_a_192_bit_kek() {
    TestFrameworkKeyWrap::new().test_kat::<24, 20, 32, Aes192Kwp>(
        &bytes(RFC5649_KEK),
        &bytes("c37b7e6492584340bed12207808941155068f738"),
        &bytes("138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a"),
    );
}

/// "The second example wraps 7 octets of key data with a 192-bit KEK": header plus data fit one
/// block, so this is the single-block path (SP 800-38F Algorithm 5 step 5 / Algorithm 6 step 3).
#[test]
fn rfc5649_wrap_7_octets_with_a_192_bit_kek() {
    TestFrameworkKeyWrap::new().test_kat::<24, 7, 16, Aes192Kwp>(
        &bytes(RFC5649_KEK),
        &bytes("466f7250617369"),
        &bytes("afbeb0f07dfbf5419200f2ccb50bb24f"),
    );
}

// ---- the shared framework, at several payload lengths ---------------------------------------

#[test]
fn kw_conforms_to_the_framework() {
    let tf = TestFrameworkKeyWrap::new();
    // AES-128 KEK: 128-, 192-, 256-bit keys and a 64-byte payload (n = 9 semiblocks).
    tf.test::<16, 16, 24, Aes128Kw>();
    tf.test::<16, 24, 32, Aes128Kw>();
    tf.test::<16, 32, 40, Aes128Kw>();
    tf.test::<16, 64, 72, Aes128Kw>();
    tf.test::<24, 16, 24, Aes192Kw>();
    tf.test::<24, 32, 40, Aes192Kw>();
    tf.test::<32, 16, 24, Aes256Kw>();
    tf.test::<32, 32, 40, Aes256Kw>();
}

#[test]
fn kwp_conforms_to_the_framework() {
    let tf = TestFrameworkKeyWrap::new();
    // Every padding length from 0 to 7 in the single-block case (1..=8 bytes -> 16), then the
    // boundary into the wrapping function (9 -> 24), unaligned and aligned longer inputs.
    tf.test::<16, 1, 16, Aes128Kwp>();
    tf.test::<16, 2, 16, Aes128Kwp>();
    tf.test::<16, 3, 16, Aes128Kwp>();
    tf.test::<16, 4, 16, Aes128Kwp>();
    tf.test::<16, 5, 16, Aes128Kwp>();
    tf.test::<16, 6, 16, Aes128Kwp>();
    tf.test::<16, 7, 16, Aes128Kwp>();
    tf.test::<16, 8, 16, Aes128Kwp>();
    tf.test::<16, 9, 24, Aes128Kwp>();
    tf.test::<16, 13, 24, Aes128Kwp>();
    tf.test::<16, 16, 24, Aes128Kwp>();
    tf.test::<16, 20, 32, Aes128Kwp>();
    tf.test::<16, 32, 40, Aes128Kwp>();
    tf.test::<16, 100, 112, Aes128Kwp>();
    tf.test::<24, 7, 16, Aes192Kwp>();
    tf.test::<24, 32, 40, Aes192Kwp>();
    tf.test::<32, 7, 16, Aes256Kwp>();
    tf.test::<32, 32, 40, Aes256Kwp>();
}

// ---- properties specific to KW and KWP ------------------------------------------------------

fn test_kek() -> KeyMaterial<16> {
    kek::<16>("000102030405060708090a0b0c0d0e0f")
}

/// The two integrity check values differ, so a ciphertext produced by one algorithm is rejected
/// by the other even though the lengths line up.
#[test]
fn kw_and_kwp_ciphertexts_are_not_interchangeable() {
    let kek = test_kek();
    let data = [0x5Au8; 16];

    let kw_ct: [u8; 24] = Aes128Kw::wrap_key(&kek, &data).unwrap();
    let kwp_ct: [u8; 24] = Aes128Kwp::wrap_key(&kek, &data).unwrap();
    assert_ne!(kw_ct, kwp_ct);

    assert!(matches!(
        Aes128Kwp::unwrap_key::<16, 24>(&kek, &kw_ct),
        Err(SymmetricCipherError::DecryptionFailed)
    ));
    assert!(matches!(
        Aes128Kw::unwrap_key::<16, 24>(&kek, &kwp_ct),
        Err(SymmetricCipherError::DecryptionFailed)
    ));
}

/// SP 800-38F Algorithm 5 step 5: for `len(P) <= 64` bits the ciphertext is `CIPH_K(S)` with
/// `S = ICV2 || [len]32 || P || PAD`, one raw block encryption and nothing else. Pinning that
/// against the permutation directly ties the single-block path to the spec rather than to the
/// RFC vector alone.
#[test]
fn kwp_single_block_path_is_one_raw_block_encryption() {
    let kek = test_kek();
    let data = *b"12345";

    let ct: [u8; 16] = Aes128Kwp::wrap_key(&kek, &data).unwrap();

    let mut s = [0u8; 16];
    s[..4].copy_from_slice(&[0xA6, 0x59, 0x59, 0xA6]);
    s[4..8].copy_from_slice(&(data.len() as u32).to_be_bytes());
    s[8..8 + data.len()].copy_from_slice(&data);
    AES128Internal::new(&kek).unwrap().encrypt_block(&mut s);
    assert_eq!(ct, s);
}

/// A KWP ciphertext length fixes the plaintext length only to within 7 bytes; the exact length is
/// the header field. So a 12-byte wrap unwraps fine as 12, and as any other length that shares
/// its ciphertext length is an authenticity failure, as the trait requires.
#[test]
fn kwp_unwrap_key_rejects_a_recovered_length_other_than_key_len() {
    let kek = test_kek();
    let ct: [u8; 24] = Aes128Kwp::wrap_key(&kek, &[0x33u8; 12]).unwrap();

    assert_eq!(*Aes128Kwp::unwrap_key::<12, 24>(&kek, &ct).unwrap(), [0x33u8; 12]);
    assert!(matches!(
        Aes128Kwp::unwrap_key::<13, 24>(&kek, &ct),
        Err(SymmetricCipherError::DecryptionFailed)
    ));
    assert!(matches!(
        Aes128Kwp::unwrap_key::<9, 24>(&kek, &ct),
        Err(SymmetricCipherError::DecryptionFailed)
    ));
    // ... and the run-time API reports the real length.
    let mut pt = [0u8; 16];
    assert_eq!(Aes128Kwp::unwrap_out(&kek, &ct, &mut pt).unwrap(), 12);
    assert_eq!(pt[..12], [0x33u8; 12]);
    assert_eq!(pt[12..], [0u8; 4], "the padding is left as zeros");
}

/// Algorithm 6 step 8: padding must be zero. A ciphertext whose padding bytes were anything else
/// is a forgery. Constructed by wrapping through the raw block cipher with non-zero padding, since
/// the wrapper itself never produces one.
#[test]
fn kwp_rejects_non_zero_padding() {
    let kek = test_kek();
    let perm = AES128Internal::new(&kek).unwrap();

    let mut s = [0u8; 16];
    s[..4].copy_from_slice(&[0xA6, 0x59, 0x59, 0xA6]);
    s[4..8].copy_from_slice(&5u32.to_be_bytes());
    s[8..13].copy_from_slice(b"12345");
    s[15] = 0x01; // the last pad byte
    perm.encrypt_block(&mut s);

    assert!(matches!(
        Aes128Kwp::unwrap_key::<5, 16>(&kek, &s),
        Err(SymmetricCipherError::DecryptionFailed)
    ));
}

/// Algorithm 6 step 7: `padlen` must be 0 to 7, so a length field that does not fit the
/// ciphertext is a forgery even when the ICV and padding check out. Two cases: a length larger
/// than the padded data, and one that would leave 8 or more bytes of padding.
#[test]
fn kwp_rejects_a_length_field_that_does_not_fit() {
    let kek = test_kek();
    let perm = AES128Internal::new(&kek).unwrap();

    for bad_len in [9u32, 0u32, u32::MAX] {
        let mut s = [0u8; 16];
        s[..4].copy_from_slice(&[0xA6, 0x59, 0x59, 0xA6]);
        s[4..8].copy_from_slice(&bad_len.to_be_bytes());
        perm.encrypt_block(&mut s);

        let mut pt = [0xFFu8; 8];
        assert!(
            matches!(
                Aes128Kwp::unwrap_out(&kek, &s, &mut pt),
                Err(SymmetricCipherError::DecryptionFailed)
            ),
            "a length field of {bad_len} should not fit an 8-byte padded plaintext"
        );
        assert_eq!(pt, [0u8; 8], "the buffer is scrubbed on failure");
    }
}

/// The length predicates and helpers are SP 800-38F Table 1 exactly.
#[test]
fn the_length_helpers_match_table_1() {
    // KW: 2 to 2^54 - 1 semiblocks of plaintext, one more of ciphertext.
    assert!(!kw_plaintext_len_is_valid(0));
    assert!(!kw_plaintext_len_is_valid(8));
    assert!(!kw_plaintext_len_is_valid(12));
    assert!(kw_plaintext_len_is_valid(16));
    assert!(kw_plaintext_len_is_valid(24));
    assert!(!kw_ciphertext_len_is_valid(16));
    assert!(kw_ciphertext_len_is_valid(24));
    assert!(!kw_ciphertext_len_is_valid(25));
    assert_eq!(kw_wrapped_len(16), 24);
    assert_eq!(kw_wrapped_len(usize::MAX), usize::MAX, "saturates rather than overflowing");
    assert_eq!(Aes128Kw::wrap_out_len(32), 40);
    assert_eq!(Aes128Kw::unwrap_out_max_len(40), 32);
    assert_eq!(Aes128Kw::unwrap_out_max_len(0), 0);

    // KWP: 1 to 2^32 - 1 octets of plaintext; 2 to 2^29 semiblocks of ciphertext.
    assert!(!kwp_plaintext_len_is_valid(0));
    assert!(kwp_plaintext_len_is_valid(1));
    assert!(kwp_plaintext_len_is_valid(u32::MAX as usize));
    assert!(!kwp_plaintext_len_is_valid(u32::MAX as usize + 1));
    assert!(!kwp_ciphertext_len_is_valid(8));
    assert!(kwp_ciphertext_len_is_valid(16));
    assert!(!kwp_ciphertext_len_is_valid(20));
    assert!(kwp_ciphertext_len_is_valid(8 << 29));
    assert!(!kwp_ciphertext_len_is_valid((8 << 29) + 8));
    assert_eq!(kwp_wrapped_len(1), 16);
    assert_eq!(kwp_wrapped_len(8), 16);
    assert_eq!(kwp_wrapped_len(9), 24);
    assert_eq!(kwp_wrapped_len(20), 32);
    assert_eq!(kwp_wrapped_len(usize::MAX), usize::MAX, "saturates rather than overflowing");
    assert_eq!(Aes128Kwp::unwrap_out_max_len(32), 24);

    // ... and the run-time API enforces them.
    let kek = test_kek();
    let mut buf = [0u8; 64];
    assert!(matches!(
        Aes128Kw::wrap_out(&kek, &[0u8; 8], &mut buf),
        Err(SymmetricCipherError::InvalidInputLength(_))
    ));
    assert!(matches!(
        Aes128Kw::wrap_out(&kek, &[0u8; 12], &mut buf),
        Err(SymmetricCipherError::InvalidInputLength(_))
    ));
    assert!(matches!(
        Aes128Kw::unwrap_out(&kek, &[0u8; 16], &mut buf),
        Err(SymmetricCipherError::InvalidInputLength(_))
    ));
    assert!(matches!(
        Aes128Kwp::unwrap_out(&kek, &[0u8; 20], &mut buf),
        Err(SymmetricCipherError::InvalidInputLength(_))
    ));
}

/// KW and KWP wrap the same aligned data to different lengths only when it is short enough to
/// fit KWP's single block; otherwise KWP's ciphertext is KW's length, not longer, since the
/// header replaces ICV1 rather than adding to it.
#[test]
fn kwp_costs_nothing_extra_for_aligned_data() {
    assert_eq!(Aes128Kw::wrap_out_len(16), Aes128Kwp::wrap_out_len(16));
    assert_eq!(Aes128Kw::wrap_out_len(32), Aes128Kwp::wrap_out_len(32));
    assert_eq!(Aes128Kwp::wrap_out_len(8), 16, "and 8 bytes need only one block");
}

/// The three key lengths are distinct algorithms: the same data under the "same" KEK bytes gives
/// three different ciphertexts, and each unwraps only under its own.
#[test]
fn the_three_key_lengths_are_not_interchangeable() {
    let data = [0x5Au8; 16];
    let ct128: [u8; 24] = Aes128Kw::wrap_key(&kek::<16>(&RFC3394_KEK[..32]), &data).unwrap();
    let ct192: [u8; 24] = Aes192Kw::wrap_key(&kek::<24>(&RFC3394_KEK[..48]), &data).unwrap();
    let ct256: [u8; 24] = Aes256Kw::wrap_key(&kek::<32>(RFC3394_KEK), &data).unwrap();
    assert_ne!(ct128, ct192);
    assert_ne!(ct192, ct256);
    assert_ne!(ct128, ct256);
}
