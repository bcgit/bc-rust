//! Known-answer tests from NIST SP 800-38A Appendix F.
//!
//! * **F.2.1 - F.2.6**, "CBC Example Vectors": CBC-AES128, CBC-AES192 and CBC-AES256, Encrypt and
//!   Decrypt.
//! * **F.3.13 - F.3.18**, part of "CFB Example Vectors": CFB128-AES128, CFB128-AES192 and
//!   CFB128-AES256, Encrypt and Decrypt. These are the `s = b` subsections, which is the variant
//!   [`Cfb`] implements; the CFB1 (F.3.1 - F.3.6) and CFB8 (F.3.7 - F.3.12) subsections are for
//!   segment sizes this crate does not provide.
//!
//! All twelve share the same IV and the same four plaintext blocks (Appendix F preamble); only the
//! key, the mode and the resulting ciphertext differ. The three keys are the same three used by
//! FIPS 197 Appendix A and SP 800-38A F.1, so these vectors also re-check each AES key expansion
//! through a second construction.
//!
//! Transcribed from the published SP 800-38A PDF (2001 edition).
//!
//! # Driving the IV
//!
//! There is no API for supplying an IV -- see the crate docs. Encryption is therefore driven
//! through [`BlockCipherEncryptor::do_encrypt_init_rng`] with a [`FixedSeedRNG`] whose stream is
//! the vector's IV, and the test asserts the returned init data really is that IV before comparing
//! any ciphertext. Decryption takes the IV directly, as init data.
//!
//! # One set of helpers, both modes
//!
//! `check_encrypt` and `check_decrypt` are generic over the *encryptor* and *decryptor* types
//! rather than over the permutation, so the same code drives `Cbc` and `Cfb`. That is only possible
//! because the two modes present an identical API, which is itself worth pinning.

use bouncycastle_aes_lowmemory::{Aes128, Aes192, Aes256};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{
    BlockCipherDecryptor, BlockCipherEncryptor, BlockPermutation, SecurityStrength,
};
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_hex as hex;
use bouncycastle_modes::{Cbc, Cfb, Decrypting, Encrypting};

const BLOCK_LEN: usize = 16;

/// The IV shared by every Appendix F.2 and F.3 subsection.
const IV: &str = "000102030405060708090a0b0c0d0e0f";

/// The four plaintext blocks shared by every Appendix F subsection (Appendix F preamble).
const PLAINTEXTS: [&str; 4] = [
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710",
];

/// The AES-128 key, shared by F.2.1/F.2.2 and F.3.13/F.3.14.
const KEY_128: &str = "2b7e151628aed2a6abf7158809cf4f3c";
/// The AES-192 key, shared by F.2.3/F.2.4 and F.3.15/F.3.16.
const KEY_192: &str = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
/// The AES-256 key, shared by F.2.5/F.2.6 and F.3.17/F.3.18.
const KEY_256: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";

// ---- CBC, Appendix F.2 -------------------------------------------------------------------

/// F.2.1 CBC-AES128.Encrypt output blocks.
const CBC_CIPHERTEXTS_128: [&str; 4] = [
    "7649abac8119b246cee98e9b12e9197d",
    "5086cb9b507219ee95db113a917678b2",
    "73bed6b8e3c1743b7116e69e22229516",
    "3ff1caa1681fac09120eca307586e1a7",
];

/// F.2.3 CBC-AES192.Encrypt output blocks.
const CBC_CIPHERTEXTS_192: [&str; 4] = [
    "4f021db243bc633d7178183a9fa071e8",
    "b4d9ada9ad7dedf4e5e738763f69145a",
    "571b242012fb7ae07fa9baac3df102e0",
    "08b0e27988598881d920a9e64f5615cd",
];

/// F.2.5 CBC-AES256.Encrypt output blocks.
const CBC_CIPHERTEXTS_256: [&str; 4] = [
    "f58c4c04d6e5f1ba779eabfb5f7bfbd6",
    "9cfc4e967edb808d679f777bc6702c7d",
    "39f23369a9d9bacfa530e26304231461",
    "b2eb05e2c39be9fcda6c19078c6a9d1b",
];

// ---- CFB128, Appendix F.3.13 - F.3.18 ----------------------------------------------------

/// F.3.13 CFB128-AES128.Encrypt ciphertext segments.
const CFB_CIPHERTEXTS_128: [&str; 4] = [
    "3b3fd92eb72dad20333449f8e83cfb4a",
    "c8a64537a0b3a93fcde3cdad9f1ce58b",
    "26751f67a3cbb140b1808cf187a4f4df",
    "c04b05357c5d1c0eeac4c66f9ff7f2e6",
];

/// F.3.15 CFB128-AES192.Encrypt ciphertext segments.
const CFB_CIPHERTEXTS_192: [&str; 4] = [
    "cdc80d6fddf18cab34c25909c99a4174",
    "67ce7f7f81173621961a2b70171d3d7a",
    "2e1e8a1dd59b88b1c8e60fed1efac4c9",
    "c05f9f9ca9834fa042ae8fba584b09ff",
];

/// F.3.17 CFB128-AES256.Encrypt ciphertext segments.
const CFB_CIPHERTEXTS_256: [&str; 4] = [
    "dc7e84bfda79164b7ecd8486985d3860",
    "39ffed143b28b1c832113c6331e5407b",
    "df10132415e54b92a13ed0a8267ae2f9",
    "75a385741ab9cef82031623d55b1e471",
];

/// The "Output Block" column of F.3.13, i.e. `Oj = CIPH_K(Ij)` -- the CFB keystream.
const CFB_OUTPUT_BLOCKS_128: [&str; 4] = [
    "50fe67cc996d32b6da0937e99bafec60",
    "668bcf60beb005a35354a201dab36bda",
    "16bd032100975551547b4de89daea630",
    "36d42170a312871947ef8714799bc5f6",
];

/// The "Output Block" column of F.3.15.
const CFB_OUTPUT_BLOCKS_192: [&str; 4] = [
    "a609b38df3b1133dddff2718ba09565e",
    "c9e3f5289f149abd08ad44dc52b2b32b",
    "1ed6965b76c76ca02d1dcef404f09626",
    "36c0bbd976ccd4b7ef85cec1be273eef",
];

/// The "Output Block" column of F.3.17.
const CFB_OUTPUT_BLOCKS_256: [&str; 4] = [
    "b7bf3a5df43989dd97f0fa97ebce2f4a",
    "97d26743252b1d54aca653cf744ace2a",
    "efd80f62b6b9af8344c511b13c70b016",
    "833ca131c5f655ef8d1a2346b3ddd361",
];

// ---- helpers -----------------------------------------------------------------------------

fn block(hex_str: &str) -> [u8; BLOCK_LEN] {
    hex::decode(hex_str).expect("valid hex").try_into().expect("16 bytes")
}

fn blocks(hex_strs: &[&str; 4]) -> [[u8; BLOCK_LEN]; 4] {
    core::array::from_fn(|i| block(hex_strs[i]))
}

fn key_material<const N: usize>(hex_str: &str) -> KeyMaterial<N> {
    let bytes = hex::decode(hex_str).expect("valid hex");
    assert_eq!(bytes.len(), N, "key length");
    KeyMaterial::<N>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey)
        .expect("a valid symmetric cipher key")
}

/// Runs one Appendix F encrypt subsection, for any mode.
///
/// Checks the whole message in one call, then again one block at a time, then again through the
/// `_out` variant -- the vector should not care how the calls are grouped.
fn check_encrypt<E, const KEY_LEN: usize>(section: &str, key_hex: &str, expected: &[&str; 4])
where
    E: BlockCipherEncryptor<KEY_LEN, BLOCK_LEN, BLOCK_LEN>,
{
    let key = key_material::<KEY_LEN>(key_hex);
    let iv = block(IV);
    let pt = blocks(&PLAINTEXTS);
    let ct = blocks(expected);

    // All four blocks in one call.
    let (mut enc, got_iv) =
        E::do_encrypt_init_rng(&key, &mut FixedSeedRNG::<BLOCK_LEN>::new(iv)).unwrap();
    assert_eq!(got_iv, iv, "{section}: the pinned RNG should produce the vector's IV");
    assert_eq!(enc.do_encrypt_blocks(&pt).unwrap(), ct, "{section}: four blocks in one call");

    // One block at a time.
    let (mut enc, _) =
        E::do_encrypt_init_rng(&key, &mut FixedSeedRNG::<BLOCK_LEN>::new(iv)).unwrap();
    for (i, (p, c)) in pt.iter().zip(ct.iter()).enumerate() {
        let [got] = enc.do_encrypt_blocks(&[*p]).unwrap();
        assert_eq!(&got, c, "{section}: block #{}", i + 1);
    }

    // Through the `_out` variant.
    let (mut enc, _) =
        E::do_encrypt_init_rng(&key, &mut FixedSeedRNG::<BLOCK_LEN>::new(iv)).unwrap();
    let mut out = [[0u8; BLOCK_LEN]; 4];
    let n = enc.do_encrypt_blocks_out(&pt, &mut out).unwrap();
    assert_eq!(n, 4 * BLOCK_LEN);
    assert_eq!(out, ct, "{section}: _out variant");
}

/// Runs one Appendix F decrypt subsection, for any mode.
///
/// Checks one call, one block at a time, and the odd grouping `3 + 1` -- which is the grouping that
/// leaves a one-block remainder after the pair loop in `do_decrypt_blocks_out`.
fn check_decrypt<D, const KEY_LEN: usize>(section: &str, key_hex: &str, ciphertext: &[&str; 4])
where
    D: BlockCipherDecryptor<KEY_LEN, BLOCK_LEN, BLOCK_LEN>,
{
    let key = key_material::<KEY_LEN>(key_hex);
    let iv = block(IV);
    let pt = blocks(&PLAINTEXTS);
    let ct = blocks(ciphertext);

    // All four blocks in one call (two pairs, no remainder).
    let mut dec = D::do_decrypt_init(&key, &iv).unwrap();
    assert_eq!(dec.do_decrypt_blocks(&ct).unwrap(), pt, "{section}: four blocks in one call");

    // One block at a time (never takes the pair path).
    let mut dec = D::do_decrypt_init(&key, &iv).unwrap();
    for (i, (c, p)) in ct.iter().zip(pt.iter()).enumerate() {
        let [got] = dec.do_decrypt_blocks(&[*c]).unwrap();
        assert_eq!(&got, p, "{section}: block #{}", i + 1);
    }

    // 3 + 1: one pair plus a remainder, then a lone block.
    let mut dec = D::do_decrypt_init(&key, &iv).unwrap();
    let three = dec.do_decrypt_blocks(&[ct[0], ct[1], ct[2]]).unwrap();
    let one = dec.do_decrypt_blocks(&[ct[3]]).unwrap();
    assert_eq!(three, [pt[0], pt[1], pt[2]], "{section}: blocks 1-3");
    assert_eq!(one, [pt[3]], "{section}: block 4");

    // Through the `_out` variant.
    let mut dec = D::do_decrypt_init(&key, &iv).unwrap();
    let mut out = [[0u8; BLOCK_LEN]; 4];
    let n = dec.do_decrypt_blocks_out(&ct, &mut out).unwrap();
    assert_eq!(n, 4 * BLOCK_LEN);
    assert_eq!(out, pt, "{section}: _out variant");
}

// ---- F.2: CBC ----------------------------------------------------------------------------

#[test]
fn f_2_1_cbc_aes128_encrypt() {
    check_encrypt::<Cbc<Aes128, Encrypting, 16, BLOCK_LEN>, 16>(
        "F.2.1", KEY_128, &CBC_CIPHERTEXTS_128,
    );
}

#[test]
fn f_2_2_cbc_aes128_decrypt() {
    check_decrypt::<Cbc<Aes128, Decrypting, 16, BLOCK_LEN>, 16>(
        "F.2.2", KEY_128, &CBC_CIPHERTEXTS_128,
    );
}

#[test]
fn f_2_3_cbc_aes192_encrypt() {
    check_encrypt::<Cbc<Aes192, Encrypting, 24, BLOCK_LEN>, 24>(
        "F.2.3", KEY_192, &CBC_CIPHERTEXTS_192,
    );
}

#[test]
fn f_2_4_cbc_aes192_decrypt() {
    check_decrypt::<Cbc<Aes192, Decrypting, 24, BLOCK_LEN>, 24>(
        "F.2.4", KEY_192, &CBC_CIPHERTEXTS_192,
    );
}

#[test]
fn f_2_5_cbc_aes256_encrypt() {
    check_encrypt::<Cbc<Aes256, Encrypting, 32, BLOCK_LEN>, 32>(
        "F.2.5", KEY_256, &CBC_CIPHERTEXTS_256,
    );
}

#[test]
fn f_2_6_cbc_aes256_decrypt() {
    check_decrypt::<Cbc<Aes256, Decrypting, 32, BLOCK_LEN>, 32>(
        "F.2.6", KEY_256, &CBC_CIPHERTEXTS_256,
    );
}

// ---- F.3.13 - F.3.18: CFB128 -------------------------------------------------------------

#[test]
fn f_3_13_cfb128_aes128_encrypt() {
    check_encrypt::<Cfb<Aes128, Encrypting, 16, BLOCK_LEN>, 16>(
        "F.3.13", KEY_128, &CFB_CIPHERTEXTS_128,
    );
}

#[test]
fn f_3_14_cfb128_aes128_decrypt() {
    check_decrypt::<Cfb<Aes128, Decrypting, 16, BLOCK_LEN>, 16>(
        "F.3.14", KEY_128, &CFB_CIPHERTEXTS_128,
    );
}

#[test]
fn f_3_15_cfb128_aes192_encrypt() {
    check_encrypt::<Cfb<Aes192, Encrypting, 24, BLOCK_LEN>, 24>(
        "F.3.15", KEY_192, &CFB_CIPHERTEXTS_192,
    );
}

#[test]
fn f_3_16_cfb128_aes192_decrypt() {
    check_decrypt::<Cfb<Aes192, Decrypting, 24, BLOCK_LEN>, 24>(
        "F.3.16", KEY_192, &CFB_CIPHERTEXTS_192,
    );
}

#[test]
fn f_3_17_cfb128_aes256_encrypt() {
    check_encrypt::<Cfb<Aes256, Encrypting, 32, BLOCK_LEN>, 32>(
        "F.3.17", KEY_256, &CFB_CIPHERTEXTS_256,
    );
}

#[test]
fn f_3_18_cfb128_aes256_decrypt() {
    check_decrypt::<Cfb<Aes256, Decrypting, 32, BLOCK_LEN>, 32>(
        "F.3.18", KEY_256, &CFB_CIPHERTEXTS_256,
    );
}

// ---- the published intermediate values -----------------------------------------------------

/// The F.3 subsections tabulate an "Input Block" and an "Output Block" per segment, not just the
/// ciphertext. Checking those pins the *structure* of the mode rather than only its final answer:
///
/// * `Input Block` for segment `j` is `Ij`, and the tables show it is the IV for `j = 1` and the
///   previous **ciphertext** segment thereafter -- which is the `s = b` collapse of
///   `Ij = LSB_{b-s}(Ij-1) | C#j-1`.
/// * `Output Block` for segment `j` is `Oj = CIPH_K(Ij)`, the keystream, applied by
///   `C#j = P#j XOR MSB_s(Oj)`.
///
/// An implementation that fed back the plaintext, or XOR-ed before the cipher call instead of
/// after, could still match a ciphertext by coincidence in one subsection; it cannot match the
/// keystream column. `Oj` is recovered here as `Cj XOR Pj`, which is what the mode must have used.
#[test]
fn the_published_keystream_blocks_match() {
    for (section, key_hex, cts, obs) in [
        ("F.3.13", KEY_128, &CFB_CIPHERTEXTS_128, &CFB_OUTPUT_BLOCKS_128),
        ("F.3.15", KEY_192, &CFB_CIPHERTEXTS_192, &CFB_OUTPUT_BLOCKS_192),
        ("F.3.17", KEY_256, &CFB_CIPHERTEXTS_256, &CFB_OUTPUT_BLOCKS_256),
    ] {
        let pt = blocks(&PLAINTEXTS);
        let ct = blocks(cts);
        let expected_keystream = blocks(obs);

        // Oj = Cj XOR Pj, from the vector's own two columns.
        for (j, ((c, p), o)) in ct.iter().zip(pt.iter()).zip(expected_keystream.iter()).enumerate()
        {
            let recovered: [u8; BLOCK_LEN] = core::array::from_fn(|i| c[i] ^ p[i]);
            assert_eq!(
                &recovered,
                o,
                "{section} segment #{}: the ciphertext and plaintext columns should differ by \
                 the published Output Block",
                j + 1
            );
        }

        // ...and that keystream really is the forward cipher applied to Ij = (IV, C1, C2, C3).
        let iv = block(IV);
        let inputs = [iv, ct[0], ct[1], ct[2]];
        for (j, (input, o)) in inputs.iter().zip(expected_keystream.iter()).enumerate() {
            let got = forward_cipher(key_hex, input);
            assert_eq!(
                &got,
                o,
                "{section} segment #{}: Oj should be CIPH_K(Ij) with Ij the previous ciphertext",
                j + 1
            );
        }
    }
}

/// Applies the raw forward cipher under a hex key of any of the three AES lengths.
fn forward_cipher(key_hex: &str, input: &[u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
    let mut out = *input;
    match hex::decode(key_hex).expect("valid hex").len() {
        16 => {
            let p = <Aes128 as BlockPermutation<16, BLOCK_LEN>>::new(&key_material::<16>(key_hex))
                .unwrap();
            p.encrypt_block(&mut out);
        }
        24 => {
            let p = <Aes192 as BlockPermutation<24, BLOCK_LEN>>::new(&key_material::<24>(key_hex))
                .unwrap();
            p.encrypt_block(&mut out);
        }
        32 => {
            let p = <Aes256 as BlockPermutation<32, BLOCK_LEN>>::new(&key_material::<32>(key_hex))
                .unwrap();
            p.encrypt_block(&mut out);
        }
        other => panic!("AES keys are 16, 24 or 32 bytes, got {other}"),
    }
    out
}

// ---- cross-mode relationships --------------------------------------------------------------

/// The one-shot API must agree with the vectors too, on the decrypt side where the IV is an input.
#[test]
fn the_one_shot_api_matches_the_vectors() {
    let iv = block(IV);
    let pt = blocks(&PLAINTEXTS);

    assert_eq!(
        Cbc::<Aes128, Decrypting, 16, 16>::decrypt_blocks(
            &key_material::<16>(KEY_128),
            &iv,
            &blocks(&CBC_CIPHERTEXTS_128)
        )
        .unwrap(),
        pt
    );
    assert_eq!(
        Cbc::<Aes192, Decrypting, 24, 16>::decrypt_blocks(
            &key_material::<24>(KEY_192),
            &iv,
            &blocks(&CBC_CIPHERTEXTS_192)
        )
        .unwrap(),
        pt
    );
    assert_eq!(
        Cbc::<Aes256, Decrypting, 32, 16>::decrypt_blocks(
            &key_material::<32>(KEY_256),
            &iv,
            &blocks(&CBC_CIPHERTEXTS_256)
        )
        .unwrap(),
        pt
    );

    assert_eq!(
        Cfb::<Aes128, Decrypting, 16, 16>::decrypt_blocks(
            &key_material::<16>(KEY_128),
            &iv,
            &blocks(&CFB_CIPHERTEXTS_128)
        )
        .unwrap(),
        pt
    );
    assert_eq!(
        Cfb::<Aes192, Decrypting, 24, 16>::decrypt_blocks(
            &key_material::<24>(KEY_192),
            &iv,
            &blocks(&CFB_CIPHERTEXTS_192)
        )
        .unwrap(),
        pt
    );
    assert_eq!(
        Cfb::<Aes256, Decrypting, 32, 16>::decrypt_blocks(
            &key_material::<32>(KEY_256),
            &iv,
            &blocks(&CFB_CIPHERTEXTS_256)
        )
        .unwrap(),
        pt
    );
}

/// The IV really is what distinguishes CBC from ECB here: the same key and plaintext under the
/// F.1 (ECB) conditions gives the F.1 ciphertext, and under F.2 gives a different one.
///
/// F.1.1 block #1 for this key is `3ad77bb40d7a3660a89ecaf32466ef97`; F.2.1 block #1 is
/// `7649abac8119b246cee98e9b12e9197d`. They differ solely because CBC XORs the IV in first.
#[test]
fn cbc_differs_from_ecb_by_the_iv() {
    let key = key_material::<16>(KEY_128);
    let iv = block(IV);

    // The raw permutation on P1 alone is the ECB answer from F.1.1.
    let mut ecb = block(PLAINTEXTS[0]);
    <Aes128 as BlockPermutation<16, 16>>::encrypt_block(
        &<Aes128 as BlockPermutation<16, 16>>::new(&key).unwrap(),
        &mut ecb,
    );
    assert_eq!(ecb, block("3ad77bb40d7a3660a89ecaf32466ef97"), "F.1.1 block #1");

    // CBC's C1 = CIPH_K(P1 XOR IV) is the F.2.1 answer, and differs.
    let (mut enc, _) = Cbc::<Aes128, Encrypting, 16, 16>::do_encrypt_init_rng(
        &key,
        &mut FixedSeedRNG::<16>::new(iv),
    )
    .unwrap();
    let [cbc] = enc.do_encrypt_blocks(&[block(PLAINTEXTS[0])]).unwrap();
    assert_eq!(cbc, block(CBC_CIPHERTEXTS_128[0]), "F.2.1 block #1");
    assert_ne!(cbc, ecb);
}

/// CFB and CBC are genuinely different modes, and the vectors say so: under the same key, IV and
/// plaintext, F.2.1 and F.3.13 give different ciphertext from the first block onwards.
///
/// Cheap to state, but it is the check that would fail if `Cfb` were accidentally wired to the CBC
/// code path (or vice versa) -- a mistake that every round-trip test in the suite would miss.
#[test]
fn cfb_differs_from_cbc_on_the_same_inputs() {
    for (cbc_ct, cfb_ct) in [
        (&CBC_CIPHERTEXTS_128, &CFB_CIPHERTEXTS_128),
        (&CBC_CIPHERTEXTS_192, &CFB_CIPHERTEXTS_192),
        (&CBC_CIPHERTEXTS_256, &CFB_CIPHERTEXTS_256),
    ] {
        assert_ne!(blocks(cbc_ct), blocks(cfb_ct));
        assert_ne!(block(cbc_ct[0]), block(cfb_ct[0]), "they differ from the very first block");
    }
}

/// At `s = b`, CFB and OFB coincide on the **first** block: both compute `O1 = CIPH_K(IV)` and XOR
/// it with `P1`. The spec's own tables confirm it -- F.4.1 (OFB-AES128.Encrypt) block #1 ciphertext
/// is `3b3fd92eb72dad20333449f8e83cfb4a`, the same value as F.3.13 segment #1.
///
/// This is a cross-check on the keystream from a different appendix, and it is the reason CFB's
/// first block must not be special-cased differently from OFB's: they are the same computation. The
/// modes diverge from block 2 (CFB feeds back the ciphertext, OFB the cipher output), which is why
/// only block #1 is compared.
#[test]
fn cfb_and_ofb_agree_on_the_first_block() {
    // F.4.1 OFB-AES128.Encrypt, Block #1 Ciphertext.
    const OFB_AES128_BLOCK_1: &str = "3b3fd92eb72dad20333449f8e83cfb4a";
    assert_eq!(block(CFB_CIPHERTEXTS_128[0]), block(OFB_AES128_BLOCK_1));

    // F.4.3 OFB-AES192 and F.4.5 OFB-AES256, Block #1 Ciphertext -- same story.
    assert_eq!(block(CFB_CIPHERTEXTS_192[0]), block("cdc80d6fddf18cab34c25909c99a4174"));
    assert_eq!(block(CFB_CIPHERTEXTS_256[0]), block("dc7e84bfda79164b7ecd8486985d3860"));

    // ...and block #2 must differ, or the mode would be OFB rather than CFB. F.4.1 block #2 is
    // `7789508d16918f03f53c52dac54ed825`.
    assert_ne!(block(CFB_CIPHERTEXTS_128[1]), block("7789508d16918f03f53c52dac54ed825"));
}

/// A mode does not change the strength of the underlying cipher, for either mode.
#[test]
fn the_security_strength_is_the_ciphers() {
    use bouncycastle_core::traits::BlockCipher;

    assert_eq!(
        <Cfb<Aes128, Encrypting, 16, 16> as BlockCipher>::MAX_SECURITY_STRENGTH,
        SecurityStrength::_128bit
    );
    assert_eq!(
        <Cfb<Aes256, Decrypting, 32, 16> as BlockCipher>::MAX_SECURITY_STRENGTH,
        <Aes256 as BlockCipher>::MAX_SECURITY_STRENGTH
    );
    assert_eq!(
        <Cfb<Aes192, Encrypting, 24, 16> as BlockCipher>::MAX_SECURITY_STRENGTH,
        <Cbc<Aes192, Encrypting, 24, 16> as BlockCipher>::MAX_SECURITY_STRENGTH
    );
}
