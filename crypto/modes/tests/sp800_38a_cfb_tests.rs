//! Known-answer tests from NIST SP 800-38A Appendix F.3, "CFB Example Vectors".
//!
//! Sections **F.3.13 through F.3.18**: CFB128-AES128, CFB128-AES192 and CFB128-AES256, Encrypt and
//! Decrypt. These are the `s = b` subsections, the ones [`Cfb`] implements. The rest of Appendix F.3
//! -- F.3.1-F.3.6 (CFB1) and F.3.7-F.3.12 (CFB8) -- covers segment sizes this crate does not
//! provide, and is deliberately not transcribed; see the [`Cfb`] module docs.
//!
//! All six share the same IV and the same four plaintext blocks (Appendix F preamble: the plaintext
//! is the same for every subsection except the CFB1 and CFB8 ones, which truncate it); only the key
//! and the resulting ciphertext differ. The three keys are the same three used by SP 800-38A F.1
//! (ECB) and F.2 (CBC), so these vectors also re-check each AES key expansion through a third
//! construction.
//!
//! Transcribed from the published SP 800-38A PDF (2001 edition).
//!
//! # The intermediate values are checked too
//!
//! Unlike Appendix F.2, whose "Input Block" is just `Pj XOR Cj-1`, the F.3 subsections tabulate the
//! CFB **output blocks** -- the keystream `Oj` -- alongside the input blocks. Those are the mode's
//! internals, so `the_tabulated_output_blocks_are_the_keystream` checks them against the raw
//! permutation rather than only comparing final ciphertext. A mode that produced the right
//! ciphertext by a different route would still have to match them.
//!
//! # Driving the IV
//!
//! There is no API for supplying an IV -- see the crate docs. Encryption is therefore driven
//! through [`BlockCipherEncryptor::do_encrypt_init_rng`] with a [`FixedSeedRNG`] whose stream is
//! the vector's IV, and the test asserts the returned init data really is that IV before comparing
//! any ciphertext. Decryption takes the IV directly, as init data.

use bouncycastle_aes_lowmemory::{Aes128, Aes192, Aes256};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{BlockCipherDecryptor, BlockCipherEncryptor, BlockPermutation};
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_hex as hex;
use bouncycastle_modes::{Cfb, Decrypting, Encrypting};

const BLOCK_LEN: usize = 16;

/// The IV shared by every Appendix F.3 subsection.
const IV: &str = "000102030405060708090a0b0c0d0e0f";

/// The four plaintext blocks shared by every Appendix F subsection (Appendix F preamble).
const PLAINTEXTS: [&str; 4] = [
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710",
];

/// F.3.13 / F.3.14 key.
const KEY_128: &str = "2b7e151628aed2a6abf7158809cf4f3c";
/// F.3.13 CFB128-AES128.Encrypt ciphertext segments.
const CIPHERTEXTS_128: [&str; 4] = [
    "3b3fd92eb72dad20333449f8e83cfb4a",
    "c8a64537a0b3a93fcde3cdad9f1ce58b",
    "26751f67a3cbb140b1808cf187a4f4df",
    "c04b05357c5d1c0eeac4c66f9ff7f2e6",
];
/// F.3.13 CFB128-AES128.Encrypt output blocks, i.e. the keystream `Oj`.
const OUTPUT_BLOCKS_128: [&str; 4] = [
    "50fe67cc996d32b6da0937e99bafec60",
    "668bcf60beb005a35354a201dab36bda",
    "16bd032100975551547b4de89daea630",
    "36d42170a312871947ef8714799bc5f6",
];

/// F.3.15 / F.3.16 key.
const KEY_192: &str = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
/// F.3.15 CFB128-AES192.Encrypt ciphertext segments.
const CIPHERTEXTS_192: [&str; 4] = [
    "cdc80d6fddf18cab34c25909c99a4174",
    "67ce7f7f81173621961a2b70171d3d7a",
    "2e1e8a1dd59b88b1c8e60fed1efac4c9",
    "c05f9f9ca9834fa042ae8fba584b09ff",
];
/// F.3.15 CFB128-AES192.Encrypt output blocks.
const OUTPUT_BLOCKS_192: [&str; 4] = [
    "a609b38df3b1133dddff2718ba09565e",
    "c9e3f5289f149abd08ad44dc52b2b32b",
    "1ed6965b76c76ca02d1dcef404f09626",
    "36c0bbd976ccd4b7ef85cec1be273eef",
];

/// F.3.17 / F.3.18 key.
const KEY_256: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
/// F.3.17 CFB128-AES256.Encrypt ciphertext segments.
const CIPHERTEXTS_256: [&str; 4] = [
    "dc7e84bfda79164b7ecd8486985d3860",
    "39ffed143b28b1c832113c6331e5407b",
    "df10132415e54b92a13ed0a8267ae2f9",
    "75a385741ab9cef82031623d55b1e471",
];
/// F.3.17 CFB128-AES256.Encrypt output blocks.
const OUTPUT_BLOCKS_256: [&str; 4] = [
    "b7bf3a5df43989dd97f0fa97ebce2f4a",
    "97d26743252b1d54aca653cf744ace2a",
    "efd80f62b6b9af8344c511b13c70b016",
    "833ca131c5f655ef8d1a2346b3ddd361",
];

fn block(hex_str: &str) -> [u8; BLOCK_LEN] {
    hex::decode(hex_str).expect("valid hex").try_into().expect("16 bytes")
}

fn blocks(hex_strs: &[&str; 4]) -> [[u8; BLOCK_LEN]; 4] {
    core::array::from_fn(|i| block(hex_strs[i]))
}

/// The same four blocks as 64 contiguous bytes, for the flat streaming and one-shot methods.
fn flat(hex_strs: &[&str; 4]) -> [u8; 4 * BLOCK_LEN] {
    blocks(hex_strs).as_flattened().try_into().expect("4 blocks = 64 bytes")
}

fn key_material<const N: usize>(hex_str: &str) -> KeyMaterial<N> {
    let bytes = hex::decode(hex_str).expect("valid hex");
    assert_eq!(bytes.len(), N, "key length");
    KeyMaterial::<N>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey)
        .expect("a valid symmetric cipher key")
}

/// Runs one Appendix F.3 encrypt subsection.
///
/// Checks the whole message in one call, then again one segment at a time, then again through the
/// `_out` variant -- the vector should not care how the calls are grouped.
fn check_encrypt<P, const KEY_LEN: usize>(section: &str, key_hex: &str, expected: &[&str; 4])
where
    P: BlockPermutation<KEY_LEN, BLOCK_LEN>,
{
    let key = key_material::<KEY_LEN>(key_hex);
    let iv = block(IV);
    let pt = blocks(&PLAINTEXTS);
    let ct = blocks(expected);

    // All four segments in one call.
    let (mut enc, got_iv) = Cfb::<P, Encrypting, KEY_LEN, BLOCK_LEN>::do_encrypt_init_rng(
        &key,
        &mut FixedSeedRNG::<BLOCK_LEN>::new(iv),
    )
    .unwrap();
    assert_eq!(got_iv, iv, "{section}: the pinned RNG should produce the vector's IV");
    assert_eq!(
        enc.do_encrypt(&flat(&PLAINTEXTS)).unwrap(),
        flat(expected),
        "{section}: four segments in one call"
    );

    // One segment at a time.
    let (mut enc, _) = Cfb::<P, Encrypting, KEY_LEN, BLOCK_LEN>::do_encrypt_init_rng(
        &key,
        &mut FixedSeedRNG::<BLOCK_LEN>::new(iv),
    )
    .unwrap();
    for (i, (p, c)) in pt.iter().zip(ct.iter()).enumerate() {
        let got = enc.do_encrypt(p).unwrap();
        assert_eq!(&got, c, "{section}: segment #{}", i + 1);
    }

    // Through the implementor hook, `do_*_blocks_out`.
    let (mut enc, _) = Cfb::<P, Encrypting, KEY_LEN, BLOCK_LEN>::do_encrypt_init_rng(
        &key,
        &mut FixedSeedRNG::<BLOCK_LEN>::new(iv),
    )
    .unwrap();
    let mut out = [[0u8; BLOCK_LEN]; 4];
    let n = enc.do_encrypt_blocks_out(&pt, &mut out).unwrap();
    assert_eq!(n, 4 * BLOCK_LEN);
    assert_eq!(out, ct, "{section}: _out variant");
}

/// Runs one Appendix F.3 decrypt subsection.
///
/// Checks one call, one segment at a time, and the odd grouping `3 + 1` -- which is the grouping
/// that leaves a one-block remainder after the pair loop in `do_decrypt_blocks_out`.
fn check_decrypt<P, const KEY_LEN: usize>(section: &str, key_hex: &str, ciphertext: &[&str; 4])
where
    P: BlockPermutation<KEY_LEN, BLOCK_LEN>,
{
    let key = key_material::<KEY_LEN>(key_hex);
    let iv = block(IV);
    let pt = blocks(&PLAINTEXTS);
    let ct = blocks(ciphertext);

    type Dec<P, const K: usize> = Cfb<P, Decrypting, K, BLOCK_LEN>;

    // All four segments in one call (two pairs, no remainder).
    let mut dec = Dec::<P, KEY_LEN>::do_decrypt_init(&key, &iv).unwrap();
    assert_eq!(
        dec.do_decrypt(&flat(ciphertext)).unwrap(),
        flat(&PLAINTEXTS),
        "{section}: four segments in one call"
    );

    // One segment at a time (never takes the pair path).
    let mut dec = Dec::<P, KEY_LEN>::do_decrypt_init(&key, &iv).unwrap();
    for (i, (c, p)) in ct.iter().zip(pt.iter()).enumerate() {
        let got = dec.do_decrypt(c).unwrap();
        assert_eq!(&got, p, "{section}: segment #{}", i + 1);
    }

    // 3 + 1: one pair plus a remainder, then a lone block.
    let mut dec = Dec::<P, KEY_LEN>::do_decrypt_init(&key, &iv).unwrap();
    let first_three: [u8; 3 * BLOCK_LEN] = ct[..3].as_flattened().try_into().unwrap();
    let three = dec.do_decrypt(&first_three).unwrap();
    let one = dec.do_decrypt(&ct[3]).unwrap();
    assert_eq!(&three[..], pt[..3].as_flattened(), "{section}: segments 1-3");
    assert_eq!(one, pt[3], "{section}: segment 4");

    // Through the implementor hook, `do_*_blocks_out`.
    let mut dec = Dec::<P, KEY_LEN>::do_decrypt_init(&key, &iv).unwrap();
    let mut out = [[0u8; BLOCK_LEN]; 4];
    let n = dec.do_decrypt_blocks_out(&ct, &mut out).unwrap();
    assert_eq!(n, 4 * BLOCK_LEN);
    assert_eq!(out, pt, "{section}: _out variant");
}

#[test]
fn f_3_13_cfb128_aes128_encrypt() {
    check_encrypt::<Aes128, 16>("F.3.13", KEY_128, &CIPHERTEXTS_128);
}

#[test]
fn f_3_14_cfb128_aes128_decrypt() {
    check_decrypt::<Aes128, 16>("F.3.14", KEY_128, &CIPHERTEXTS_128);
}

#[test]
fn f_3_15_cfb128_aes192_encrypt() {
    check_encrypt::<Aes192, 24>("F.3.15", KEY_192, &CIPHERTEXTS_192);
}

#[test]
fn f_3_16_cfb128_aes192_decrypt() {
    check_decrypt::<Aes192, 24>("F.3.16", KEY_192, &CIPHERTEXTS_192);
}

#[test]
fn f_3_17_cfb128_aes256_encrypt() {
    check_encrypt::<Aes256, 32>("F.3.17", KEY_256, &CIPHERTEXTS_256);
}

#[test]
fn f_3_18_cfb128_aes256_decrypt() {
    check_decrypt::<Aes256, 32>("F.3.18", KEY_256, &CIPHERTEXTS_256);
}

/// The one-shot API must agree with the vectors too, on the decrypt side where the IV is an input.
/// The one-shots take flat arrays, so the four segments are presented as 64 contiguous bytes.
#[test]
fn the_one_shot_api_matches_the_vectors() {
    let iv = block(IV);
    let pt = flat(&PLAINTEXTS);

    assert_eq!(
        Cfb::<Aes128, Decrypting, 16, 16>::decrypt(
            &key_material::<16>(KEY_128),
            &iv,
            &flat(&CIPHERTEXTS_128)
        )
        .unwrap(),
        pt
    );
    assert_eq!(
        Cfb::<Aes192, Decrypting, 24, 16>::decrypt(
            &key_material::<24>(KEY_192),
            &iv,
            &flat(&CIPHERTEXTS_192)
        )
        .unwrap(),
        pt
    );
    assert_eq!(
        Cfb::<Aes256, Decrypting, 32, 16>::decrypt(
            &key_material::<32>(KEY_256),
            &iv,
            &flat(&CIPHERTEXTS_256)
        )
        .unwrap(),
        pt
    );
}

/// The spec's tabulated **Output Blocks** are the CFB keystream, and its **Input Blocks** are the
/// IV followed by the ciphertext segments. Both fall straight out of Sec 6.3 with `s = b`:
///
/// ```text
/// I1 = IV;  Ij = C_{j-1} (j >= 2);  Oj = CIPH_K(Ij);  Cj = Pj XOR Oj
/// ```
///
/// So each `Oj` in the table must equal the raw permutation applied to the previous ciphertext
/// segment (or to the IV, for `j = 1`), and XOR-ing it with the plaintext must give the ciphertext.
/// Checking this pins the mode's internals against the spec, not just its final output -- and in
/// particular it is what distinguishes CFB from a mode that happens to agree on the ciphertext.
///
/// It also confirms the transcription: the ciphertext and output-block columns above are related by
/// an XOR that would not survive a typo in either.
fn check_output_blocks<P, const KEY_LEN: usize>(
    section: &str,
    key_hex: &str,
    ciphertexts: &[&str; 4],
    output_blocks: &[&str; 4],
) where
    P: BlockPermutation<KEY_LEN, BLOCK_LEN>,
{
    let key = key_material::<KEY_LEN>(key_hex);
    let perm = P::new(&key).expect("a valid key");
    let pt = blocks(&PLAINTEXTS);
    let ct = blocks(ciphertexts);
    let o = blocks(output_blocks);

    for j in 0..4 {
        // Ij: the IV for j = 1, otherwise the previous ciphertext segment.
        let input_block = if j == 0 { block(IV) } else { ct[j - 1] };

        // Oj = CIPH_K(Ij) -- the *forward* cipher function, which is all CFB ever uses.
        let mut computed = input_block;
        perm.encrypt_block(&mut computed);
        assert_eq!(
            computed,
            o[j],
            "{section}: tabulated output block #{} should be CIPH_K of input block #{}",
            j + 1,
            j + 1
        );

        // Cj = Pj XOR Oj.
        let xored: [u8; BLOCK_LEN] = core::array::from_fn(|k| pt[j][k] ^ o[j][k]);
        assert_eq!(xored, ct[j], "{section}: Cj = Pj XOR Oj for segment #{}", j + 1);
    }
}

#[test]
fn the_tabulated_output_blocks_are_the_keystream() {
    check_output_blocks::<Aes128, 16>("F.3.13", KEY_128, &CIPHERTEXTS_128, &OUTPUT_BLOCKS_128);
    check_output_blocks::<Aes192, 24>("F.3.15", KEY_192, &CIPHERTEXTS_192, &OUTPUT_BLOCKS_192);
    check_output_blocks::<Aes256, 32>("F.3.17", KEY_256, &CIPHERTEXTS_256, &OUTPUT_BLOCKS_256);
}

/// CFB128 and OFB must agree on the **first** block and on nothing after it.
///
/// Both modes set `I1 = IV` and `O1 = CIPH_K(IV)`, and both then XOR that into the plaintext, so
/// `C1` is necessarily the same. They diverge from the second block, because OFB feeds back the
/// output block `Oj` (Sec 6.4) while CFB feeds back the ciphertext `Cj` (Sec 6.3).
///
/// Appendix F bears this out, and the values below are quoted from **F.4.1 (OFB-AES128.Encrypt)**,
/// a different subsection from the ones this file is testing. Agreement on block 1 is therefore an
/// independent check that the F.3.13 transcription is right; disagreement on block 2 is a check
/// that [`Cfb`] is CFB and not OFB.
#[test]
fn cfb128_agrees_with_ofb_on_the_first_block_only() {
    /// F.4.1 OFB-AES128.Encrypt, Block #1 Output Block. Same key and IV, so the same `O1`.
    const OFB_OUTPUT_BLOCK_1: &str = "50fe67cc996d32b6da0937e99bafec60";
    /// F.4.1 OFB-AES128.Encrypt, Block #1 and Block #2 Ciphertext.
    const OFB_CIPHERTEXT_1: &str = "3b3fd92eb72dad20333449f8e83cfb4a";
    const OFB_CIPHERTEXT_2: &str = "7789508d16918f03f53c52dac54ed825";

    assert_eq!(
        OUTPUT_BLOCKS_128[0], OFB_OUTPUT_BLOCK_1,
        "F.3.13 and F.4.1 must tabulate the same O1 = CIPH_K(IV)"
    );

    let key = key_material::<16>(KEY_128);
    let iv = block(IV);
    let (mut enc, got_iv) = Cfb::<Aes128, Encrypting, 16, 16>::do_encrypt_init_rng(
        &key,
        &mut FixedSeedRNG::<16>::new(iv),
    )
    .unwrap();
    assert_eq!(got_iv, iv);

    let c1 = enc.do_encrypt(&block(PLAINTEXTS[0])).unwrap();
    assert_eq!(c1, block(OFB_CIPHERTEXT_1), "block 1 must match OFB, and F.3.13");

    let c2 = enc.do_encrypt(&block(PLAINTEXTS[1])).unwrap();
    assert_eq!(c2, block(CIPHERTEXTS_128[1]), "block 2 must match F.3.13");
    assert_ne!(c2, block(OFB_CIPHERTEXT_2), "block 2 must NOT match OFB");
}
