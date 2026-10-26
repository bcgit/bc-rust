//! Known-answer tests for the AES kernels from FIPS 197 and NIST SP 800-38A, plus the
//! consistency of the one-, two- and four-block paths.
//!
//! * FIPS 197 Appendix A: every word of all three key expansions.
//! * FIPS 197 Appendix B: the worked AES-128 encryption.
//! * FIPS 197 (2001 edition) Appendix C: the `ik_sch` round keys of the equivalent inverse
//!   cipher for all three key sizes, and its plaintext / ciphertext pairs.
//! * SP 800-38A Appendix F.1: ECB, four blocks, all three key sizes, both directions.
//!
//! All values are transcribed from the published PDFs; the Appendix A words were extracted
//! from the document text mechanically rather than retyped.

#![cfg(all(
    target_arch = "aarch64",
    target_endian = "little",
    target_feature = "neon",
    any(
        target_feature = "aes",
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "windows"
    )
))]

mod common;

use bouncycastle_arm::Aes;
use bouncycastle_arm::aes::{Block, RoundKeys128, RoundKeys192, RoundKeys256};
use bouncycastle_hex as hex;
use common::{Xorshift, hex_block, hex_bytes};

// ---- FIPS 197 Appendix A: key expansion -------------------------------------------------------

/// Appendix A.1 key, also Appendix B's and SP 800-38A F.1.1's.
const KEY_128: &str = "2b7e151628aed2a6abf7158809cf4f3c";
/// Appendix A.2 key, also SP 800-38A F.1.3's.
const KEY_192: &str = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
/// Appendix A.3 key, also SP 800-38A F.1.5's.
const KEY_256: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";

/// Appendix A.1, the `w[i]` column for `i = 4..44`; `w[0..4]` is the key.
const WORDS_128: [&str; 40] = [
    "a0fafe17", "88542cb1", "23a33939", "2a6c7605", "f2c295f2", "7a96b943", "5935807a", "7359f67f",
    "3d80477d", "4716fe3e", "1e237e44", "6d7a883b", "ef44a541", "a8525b7f", "b671253b", "db0bad00",
    "d4d1c6f8", "7c839d87", "caf2b8bc", "11f915bc", "6d88a37a", "110b3efd", "dbf98641", "ca0093fd",
    "4e54f70e", "5f5fc9f3", "84a64fb2", "4ea6dc4f", "ead27321", "b58dbad2", "312bf560", "7f8d292f",
    "ac7766f3", "19fadc21", "28d12941", "575c006e", "d014f9a8", "c9ee2589", "e13f0cc8", "b6630ca6",
];

/// Appendix A.2, `w[i]` for `i = 6..52`.
const WORDS_192: [&str; 46] = [
    "fe0c91f7", "2402f5a5", "ec12068e", "6c827f6b", "0e7a95b9", "5c56fec2", "4db7b4bd", "69b54118",
    "85a74796", "e92538fd", "e75fad44", "bb095386", "485af057", "21efb14f", "a448f6d9", "4d6dce24",
    "aa326360", "113b30e6", "a25e7ed5", "83b1cf9a", "27f93943", "6a94f767", "c0a69407", "d19da4e1",
    "ec1786eb", "6fa64971", "485f7032", "22cb8755", "e26d1352", "33f0b7b3", "40beeb28", "2f18a259",
    "6747d26b", "458c553e", "a7e1466c", "9411f1df", "821f750a", "ad07d753", "ca400538", "8fcc5006",
    "282d166a", "bc3ce7b5", "e98ba06f", "448c773c", "8ecc7204", "01002202",
];

/// Appendix A.3, `w[i]` for `i = 8..60`.
const WORDS_256: [&str; 52] = [
    "9ba35411", "8e6925af", "a51a8b5f", "2067fcde", "a8b09c1a", "93d194cd", "be49846e", "b75d5b9a",
    "d59aecb8", "5bf3c917", "fee94248", "de8ebe96", "b5a9328a", "2678a647", "98312229", "2f6c79b3",
    "812c81ad", "dadf48ba", "24360af2", "fab8b464", "98c5bfc9", "bebd198e", "268c3ba7", "09e04214",
    "68007bac", "b2df3316", "96e939e4", "6c518d80", "c814e204", "76a9fb8a", "5025c02d", "59c58239",
    "de136967", "6ccc5a71", "fa256395", "9674ee15", "5886ca5d", "2e2f31d7", "7e0af1fa", "27cf73c3",
    "749c47ab", "18501dda", "e2757e4f", "7401905a", "cafaaae3", "e4d59b34", "9adf6ace", "bd10190d",
    "fe4890d1", "e6188d0b", "046df344", "706c631e",
];

/// Word `i` of a round-key array, as four hex characters per byte.
fn word<const N: usize>(w: &[Block; N], i: usize) -> String {
    hex::encode(&w[i / 4][4 * (i % 4)..4 * (i % 4) + 4])
}

fn check_expansion<const N: usize>(key_hex: &str, w: &[Block; N], expanded: &[&str]) {
    let nk = key_hex.len() / 8;
    for i in 0..nk {
        assert_eq!(word(w, i), key_hex[8 * i..8 * i + 8], "w[{i}] is the key");
    }
    for (j, expected) in expanded.iter().enumerate() {
        let i = nk + j;
        assert_eq!(word(w, i), *expected, "w[{i}]");
    }
    assert_eq!(nk + expanded.len(), 4 * N, "every word checked");
}

#[test]
fn appendix_a1_expands_the_128_bit_key_word_for_word() {
    let Some(cx) = common::cx() else { return };
    let w = cx.expand_128(&hex_bytes::<16>(KEY_128));
    check_expansion(KEY_128, &w, &WORDS_128);
}

#[test]
fn appendix_a2_expands_the_192_bit_key_word_for_word() {
    let Some(cx) = common::cx() else { return };
    let w = cx.expand_192(&hex_bytes::<24>(KEY_192));
    check_expansion(KEY_192, &w, &WORDS_192);
}

#[test]
fn appendix_a3_expands_the_256_bit_key_word_for_word() {
    let Some(cx) = common::cx() else { return };
    let w = cx.expand_256(&hex_bytes::<32>(KEY_256));
    check_expansion(KEY_256, &w, &WORDS_256);
}

// ---- FIPS 197 Appendix B: the worked encryption -----------------------------------------------

#[test]
fn appendix_b_encrypts_the_documented_block() {
    let Some(cx) = common::cx() else { return };
    // Input = 32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34, Key = Appendix A.1's.
    // The final state printed as "output" reads, column by column:
    //         39 25 84 1d 02 dc 09 fb dc 11 85 97 19 6a 0b 32
    let w = cx.expand_128(&hex_bytes::<16>(KEY_128));
    let mut blocks = [hex_block("3243f6a8885a308d313198a2e0370734")];
    cx.encrypt_blocks(&w, &mut blocks);
    assert_eq!(blocks[0], hex_block("3925841d02dc09fbdc118597196a0b32"));

    let dw = cx.equivalent_inverse_round_keys(&w);
    cx.decrypt_blocks(&dw, &mut blocks);
    assert_eq!(blocks[0], hex_block("3243f6a8885a308d313198a2e0370734"));
}

// ---- SP 800-38A Appendix F.1: ECB ------------------------------------------------------------

/// F.1's four plaintext blocks, shared by every key size.
const F1_PLAINTEXT: [&str; 4] = [
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710",
];

/// F.1.1 / F.1.2 ciphertext.
const F1_CIPHERTEXT_128: [&str; 4] = [
    "3ad77bb40d7a3660a89ecaf32466ef97",
    "f5d3d58503b9699de785895a96fdbaaf",
    "43b1cd7f598ece23881b00e3ed030688",
    "7b0c785e27e8ad3f8223207104725dd4",
];

/// F.1.3 / F.1.4 ciphertext.
const F1_CIPHERTEXT_192: [&str; 4] = [
    "bd334f1d6e45f25ff712a214571fa5cc",
    "974104846d0ad3ad7734ecb3ecee4eef",
    "ef7afd2270e2e60adce0ba2face6444e",
    "9a4b41ba738d6c72fb16691603c18e0e",
];

/// F.1.5 / F.1.6 ciphertext.
const F1_CIPHERTEXT_256: [&str; 4] = [
    "f3eed1bdb5d2a03c064b5a7e3db181f8",
    "591ccb10d410ed26dc5ba74a31362870",
    "b6ed21b99ca6f4f9f153e7b1beafed1d",
    "23304b7a39f9f3ff067d8d8f9e24ecc7",
];

fn blocks4(hex: &[&str; 4]) -> [Block; 4] {
    hex.map(hex_block)
}

/// Encrypts and decrypts F.1's four blocks through the four-block path, then checks that the
/// one- and two-block paths give byte-identical results.
fn check_ecb<const N: usize>(cx: Aes, w: &[Block; N], ciphertext: &[&str; 4]) {
    let plaintext = blocks4(&F1_PLAINTEXT);
    let expected = blocks4(ciphertext);
    let dw = cx.equivalent_inverse_round_keys(w);

    let mut four = plaintext;
    cx.encrypt_blocks(w, &mut four);
    assert_eq!(four, expected, "ECB encrypt, four blocks at once");
    cx.decrypt_blocks(&dw, &mut four);
    assert_eq!(four, plaintext, "ECB decrypt, four blocks at once");

    for (i, block) in plaintext.iter().enumerate() {
        let mut one = [*block];
        cx.encrypt_blocks(w, &mut one);
        assert_eq!(one[0], expected[i], "block {i} alone");
        cx.decrypt_blocks(&dw, &mut one);
        assert_eq!(one[0], *block, "block {i} alone, decrypted");
    }

    let mut pair = [plaintext[0], plaintext[1]];
    cx.encrypt_blocks(w, &mut pair);
    assert_eq!(pair, [expected[0], expected[1]], "first pair");
    let mut pair = [plaintext[2], plaintext[3]];
    cx.encrypt_blocks(w, &mut pair);
    assert_eq!(pair, [expected[2], expected[3]], "second pair");
    cx.decrypt_blocks(&dw, &mut pair);
    assert_eq!(pair, [plaintext[2], plaintext[3]], "second pair, decrypted");
}

#[test]
fn sp800_38a_f1_ecb_aes128() {
    let Some(cx) = common::cx() else { return };
    check_ecb(cx, &cx.expand_128(&hex_bytes::<16>(KEY_128)), &F1_CIPHERTEXT_128);
}

#[test]
fn sp800_38a_f1_ecb_aes192() {
    let Some(cx) = common::cx() else { return };
    check_ecb(cx, &cx.expand_192(&hex_bytes::<24>(KEY_192)), &F1_CIPHERTEXT_192);
}

#[test]
fn sp800_38a_f1_ecb_aes256() {
    let Some(cx) = common::cx() else { return };
    check_ecb(cx, &cx.expand_256(&hex_bytes::<32>(KEY_256)), &F1_CIPHERTEXT_256);
}

// ---- FIPS 197 (2001) Appendix C: the equivalent inverse cipher's round keys --------------------

/// Appendix C's key for each size is `00 01 02 ...`, its plaintext `00 11 22 ... ff`.
const C_PLAINTEXT: &str = "00112233445566778899aabbccddeeff";

/// C.1: `round[0].iinput`, the AES-128 ciphertext, and `round[r].ik_sch` for `r = 0..=10`.
const C1_CIPHERTEXT: &str = "69c4e0d86a7b0430d8cdb78070b4c55a";
const C1_IK_SCH: [&str; 11] = [
    "13111d7fe3944a17f307a78b4d2b30c5",
    "13aa29be9c8faff6f770f58000f7bf03",
    "1362a4638f2586486bff5a76f7874a83",
    "8d82fc749c47222be4dadc3e9c7810f5",
    "72e3098d11c5de5f789dfe1578a2cccb",
    "2ec410276326d7d26958204a003f32de",
    "a8a2f5044de2c7f50a7ef79869671294",
    "c7c6e391e54032f1479c306d6319e50c",
    "a0db02992286d160a2dc029c2485d561",
    "8c56dff0825dd3f9805ad3fc8659d7fd",
    "000102030405060708090a0b0c0d0e0f",
];

/// C.2: the AES-192 ciphertext and `ik_sch` for `r = 0..=12`.
const C2_CIPHERTEXT: &str = "dda97ca4864cdfe06eaf70a0ec0d7191";
const C2_IK_SCH: [&str; 13] = [
    "a4970a331a78dc09c418c271e3a41d5d",
    "d6bebd0dc209ea494db073803e021bb9",
    "8fb999c973b26839c7f9d89d85c68c72",
    "f77d6ec1423f54ef5378317f14b75744",
    "1147659047cf663b9b0ece8dfc0bf1f0",
    "dcc1a8b667053f7dcc5c194ab5423a2e",
    "c6deb0ab791e2364a4055fbe568803ab",
    "dd1b7cdaf28d5c158a49ab1dbbc497cb",
    "78c4f708318d3cd69655b701bfc093cf",
    "60dcef10299524ce62dbef152f9620cf",
    "4b4ecbdb4d4dcfda5752d7c74949cbde",
    "1a1f181d1e1b1c194742c7d74949cbde",
    "000102030405060708090a0b0c0d0e0f",
];

/// C.3: the AES-256 ciphertext and `ik_sch` for `r = 0..=14`.
const C3_CIPHERTEXT: &str = "8ea2b7ca516745bfeafc49904b496089";
const C3_IK_SCH: [&str; 15] = [
    "24fc79ccbf0979e9371ac23c6d68de36",
    "34f1d1ffbfceaa2ffce9e25f2558016e",
    "5e1648eb384c350a7571b746dc80e684",
    "c8a305808b3f7bd043274870d9b1e331",
    "b5708e13665a7de14d3d824ca9f151c2",
    "74da7ba3439c7e50c81833a09a96ab41",
    "3ca69715d32af3f22b67ffade4ccd38e",
    "f85fc4f3374605f38b844df0528e98e1",
    "de69409aef8c64e7f84d0c5fcfab2c23",
    "aed55816cf19c100bcc24803d90ad511",
    "15c668bd31e5247d17c168b837e6207c",
    "7fd7850f61cc991673db890365c89d12",
    "2a2840c924234cc026244cc5202748c4",
    "1a1f181d1e1b1c191217101516131411",
    "000102030405060708090a0b0c0d0e0f",
];

/// Appendix C numbers the inverse cipher's rounds in the order they run, so `ik_sch[r]` is
/// `dw[Nr - r]` in Algorithm 4's indexing.
fn check_appendix_c<const N: usize>(cx: Aes, w: &[Block; N], ik_sch: &[&str; N], ciphertext: &str) {
    let nr = N - 1;
    let dw = cx.equivalent_inverse_round_keys(w);
    for (r, expected) in ik_sch.iter().enumerate() {
        assert_eq!(hex::encode(dw[nr - r]), *expected, "round[{r}].ik_sch");
    }
    let mut block = [hex_block(C_PLAINTEXT)];
    cx.encrypt_blocks(w, &mut block);
    assert_eq!(block[0], hex_block(ciphertext));
    cx.decrypt_blocks(&dw, &mut block);
    assert_eq!(block[0], hex_block(C_PLAINTEXT));
}

#[test]
fn appendix_c1_aes128_inverse_round_keys_and_vectors() {
    let Some(cx) = common::cx() else { return };
    let key: [u8; 16] = core::array::from_fn(|i| i as u8);
    check_appendix_c(cx, &cx.expand_128(&key), &C1_IK_SCH, C1_CIPHERTEXT);
}

#[test]
fn appendix_c2_aes192_inverse_round_keys_and_vectors() {
    let Some(cx) = common::cx() else { return };
    let key: [u8; 24] = core::array::from_fn(|i| i as u8);
    check_appendix_c(cx, &cx.expand_192(&key), &C2_IK_SCH, C2_CIPHERTEXT);
}

#[test]
fn appendix_c3_aes256_inverse_round_keys_and_vectors() {
    let Some(cx) = common::cx() else { return };
    let key: [u8; 32] = core::array::from_fn(|i| i as u8);
    check_appendix_c(cx, &cx.expand_256(&key), &C3_IK_SCH, C3_CIPHERTEXT);
}

// ---- Structure -------------------------------------------------------------------------------

/// Algorithm 5 lines 19-22: only round keys `1..=Nr-1` change.
#[test]
fn equivalent_inverse_schedule_keeps_the_first_and_last_round_keys() {
    let Some(cx) = common::cx() else { return };
    let w: RoundKeys128 = cx.expand_128(&hex_bytes::<16>(KEY_128));
    let dw = cx.equivalent_inverse_round_keys(&w);
    assert_eq!(dw[0], w[0]);
    assert_eq!(dw[10], w[10]);
    for i in 1..10 {
        assert_ne!(dw[i], w[i], "round key {i} is transformed");
    }
    let w: RoundKeys192 = cx.expand_192(&hex_bytes::<24>(KEY_192));
    let dw = cx.equivalent_inverse_round_keys(&w);
    assert_eq!((dw[0], dw[12]), (w[0], w[12]));
    let w: RoundKeys256 = cx.expand_256(&hex_bytes::<32>(KEY_256));
    let dw = cx.equivalent_inverse_round_keys(&w);
    assert_eq!((dw[0], dw[14]), (w[0], w[14]));
}

/// Decryption inverts encryption on random keys and blocks, for every key size and width, and
/// the batched paths agree with the single-block one.
#[test]
fn round_trips_on_random_keys_and_blocks() {
    let Some(cx) = common::cx() else { return };
    let mut rng = Xorshift(0x1234_5678_9abc_def1);
    for _ in 0..50 {
        let mut k128 = [0u8; 16];
        rng.fill(&mut k128);
        let mut k192 = [0u8; 24];
        rng.fill(&mut k192);
        let mut k256 = [0u8; 32];
        rng.fill(&mut k256);
        check_round_trips(cx, &cx.expand_128(&k128), &mut rng);
        check_round_trips(cx, &cx.expand_192(&k192), &mut rng);
        check_round_trips(cx, &cx.expand_256(&k256), &mut rng);
    }
}

fn check_round_trips<const N: usize>(cx: Aes, w: &[Block; N], rng: &mut Xorshift) {
    let dw = cx.equivalent_inverse_round_keys(w);
    let plaintext: [Block; 4] = core::array::from_fn(|_| rng.block());

    let mut four = plaintext;
    cx.encrypt_blocks(w, &mut four);
    let ciphertext = four;
    cx.decrypt_blocks(&dw, &mut four);
    assert_eq!(four, plaintext);

    for i in 0..4 {
        let mut one = [plaintext[i]];
        cx.encrypt_blocks(w, &mut one);
        assert_eq!(one[0], ciphertext[i]);
        cx.decrypt_blocks(&dw, &mut one);
        assert_eq!(one[0], plaintext[i]);
    }
    for i in [0, 2] {
        let mut pair = [plaintext[i], plaintext[i + 1]];
        cx.encrypt_blocks(w, &mut pair);
        assert_eq!(pair, [ciphertext[i], ciphertext[i + 1]]);
        cx.decrypt_blocks(&dw, &mut pair);
        assert_eq!(pair, [plaintext[i], plaintext[i + 1]]);
    }
}
