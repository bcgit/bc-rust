//! Known-answer tests against the NIST CAVP "TDES Multi block Message Test" vectors from the
//! `bc-test-data` repository: `TECBMMT3`, `TCBCMMT3`, `TCFB64MMT3`, `TCFB8MMT3` (three-key, for
//! [`TDES`]) and `TECBMMT2`, `TCBCMMT2`, `TCFB64MMT2`, `TCFB8MMT2` (two-key, for [`TDES2Key`]).
//!
//! Requires `bc-test-data` to be cloned alongside this repository, i.e. at `../bc-test-data`
//! relative to the root of this git project, with the response files from NIST's `tdesmmt.zip`
//! (CAVS 18.0) under `crypto/aes_tdes_vectors/TDES/`. If it is absent the tests print a warning and
//! pass, matching the convention used by the AES ACVP and ML-KEM / ML-DSA suites -- `cargo test`
//! must stay green for someone who has only cloned this repository.
//!
//! Every case is checked in **both** directions regardless of the section it came from:
//! encrypting `PLAINTEXT` must give `CIPHERTEXT` and decrypting `CIPHERTEXT` must give
//! `PLAINTEXT`. The `[DECRYPT]` cases use different keys from the `[ENCRYPT]` ones, so this doubles
//! the coverage rather than repeating it. The two-key files have only a `[DECRYPT]` section --
//! NIST tests two-key TDEA in that direction alone, as this crate does.
//!
//! # How the modes are driven
//!
//! ECB vectors are block-permutation vectors and go through the engine directly, one block at a
//! time, as well as through the four-block path where the message is long enough.
//!
//! The CBC and CFB vectors carry an IV, and `bouncycastle-modes` has no API for a caller-supplied
//! IV. Three-key encryption therefore uses `do_encrypt_init_rng` with a `FixedSeedRNG` that emits
//! the vector's IV, and the returned init data is asserted equal to it before any ciphertext is
//! compared; decryption takes the IV directly. The `TDES_*` aliases are used, so the aliases'
//! parameter choices (a 24-byte key, an 8-byte block, an 8-byte IV) are what is under test.
//!
//! Two-key TDEA is decryption-only -- the encrypting modes do not compile over [`TDES2Key`] -- so
//! its CBC and CFB vectors are checked by decrypting `CIPHERTEXT` through the `TDES2_*` aliases
//! (both sections), and the forward direction is checked on the ECB vectors through the raw
//! permutation, which CFB decryption is built on anyway.
//!
//! The Monte Carlo Test files (`tdesmct_intermediate.zip`) are **not** used: their chained update
//! rule is defined by SP 800-20, and implementing it is a separate piece of work from the engine.

use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{
    BlockCipherDecryptor, BlockCipherEncryptor, ElectronicCodeBook, StreamCipherDecryptor,
    StreamCipherEncryptor,
};
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_hex as hex;
use bouncycastle_modes::{Cbc, Decrypting, Encrypting};
use bouncycastle_tdes::{
    BLOCK_LEN, KEY_LEN, KEY_LEN_2KEY, TDES, TDES_CFB, TDES_CFB8, TDES2_CFB, TDES2_CFB8, TDES2Key,
};
use std::fs;
use std::path::{Path, PathBuf};

/// Candidate locations, covering `cargo test` run from the crate root or from the repo root.
const TEST_DATA_PATHS: [&str; 2] = [
    "../../../bc-test-data/crypto/aes_tdes_vectors/TDES",
    "../bc-test-data/crypto/aes_tdes_vectors/TDES",
];

/// Locates the TDES CAVP directory, or `None` if `bc-test-data` is not checked out.
fn test_data_dir() -> Option<PathBuf> {
    for candidate in TEST_DATA_PATHS {
        let path = Path::new(candidate);
        if path.join("TECBMMT3.rsp").exists() {
            return Some(path.to_path_buf());
        }
    }
    println!(
        "WARNING: bc-test-data not found (looked in {TEST_DATA_PATHS:?}); CAVP TDES MMT tests will \
         be skipped"
    );
    None
}

/// One MMT case. `iv` is empty for ECB.
#[derive(Default, Debug, Clone)]
struct MmtCase {
    section: String,
    count: u32,
    key1: Vec<u8>,
    key2: Vec<u8>,
    key3: Vec<u8>,
    iv: Vec<u8>,
    plaintext: Vec<u8>,
    ciphertext: Vec<u8>,
}

/// Parses a CAVS `.rsp` file: `[SECTION]` headers, `COUNT = n` starting a case, `NAME = hex`
/// fields. Lines may end in CRLF.
fn parse_rsp(text: &str) -> Vec<MmtCase> {
    let mut cases: Vec<MmtCase> = Vec::new();
    let mut section = String::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = name.to_string();
            continue;
        }
        let (name, value) = line.split_once(" = ").expect("`NAME = value` line");
        if name == "COUNT" {
            cases.push(MmtCase {
                section: section.clone(),
                count: value.parse().expect("a decimal COUNT"),
                ..Default::default()
            });
            continue;
        }
        let case = cases.last_mut().expect("a field before any COUNT");
        let bytes = hex::decode(value).expect("hex field");
        match name {
            "KEY1" => case.key1 = bytes,
            "KEY2" => case.key2 = bytes,
            "KEY3" => case.key3 = bytes,
            "IV" => case.iv = bytes,
            "PLAINTEXT" => case.plaintext = bytes,
            "CIPHERTEXT" => case.ciphertext = bytes,
            other => panic!("unexpected field {other}"),
        }
    }
    cases
}

/// Loads a response file, or `None` when the data is absent.
///
/// The three-key files carry ten `[ENCRYPT]` and ten `[DECRYPT]` cases. The two-key files carry
/// ten `[DECRYPT]` cases and **no `[ENCRYPT]` section at all**: CAVP tests two-key TDEA in the
/// decrypt direction only, which is the same policy as [`TDES2Key`].
fn load(file: &str) -> Option<Vec<MmtCase>> {
    let dir = test_data_dir()?;
    let text = fs::read_to_string(dir.join(file)).expect("readable response file");
    let cases = parse_rsp(&text);
    let encrypt = cases.iter().filter(|c| c.section == "ENCRYPT").count();
    let decrypt = cases.iter().filter(|c| c.section == "DECRYPT").count();
    assert_eq!(encrypt + decrypt, cases.len(), "{file}: unexpected section");
    assert_eq!(decrypt, 10, "{file}: ten decrypt cases");
    assert_eq!(encrypt, if file.ends_with("MMT2.rsp") { 0 } else { 10 }, "{file}: encrypt cases");
    println!("{file}: {} cases found at {}", cases.len(), dir.display());
    Some(cases)
}

fn key3(case: &MmtCase) -> KeyMaterial<KEY_LEN> {
    let bytes: Vec<u8> = [&case.key1[..], &case.key2[..], &case.key3[..]].concat();
    assert_eq!(bytes.len(), KEY_LEN);
    KeyMaterial::<KEY_LEN>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey)
        .expect("a valid symmetric cipher key")
}

/// The two-key files carry `KEY3 = KEY1`; the engine takes `KEY1 || KEY2`.
fn key2(case: &MmtCase) -> KeyMaterial<KEY_LEN_2KEY> {
    assert_eq!(case.key1, case.key3, "a two-key vector has KEY3 = KEY1");
    let bytes: Vec<u8> = [&case.key1[..], &case.key2[..]].concat();
    KeyMaterial::<KEY_LEN_2KEY>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey)
        .expect("a valid symmetric cipher key")
}

fn iv(case: &MmtCase) -> [u8; BLOCK_LEN] {
    case.iv.clone().try_into().expect("an 8-byte IV")
}

fn label(file: &str, case: &MmtCase) -> String {
    format!("{file} [{}] COUNT = {}", case.section, case.count)
}

/// ECB through a raw permutation: single blocks, then the four-block path.
fn check_ecb<const KEY_LEN: usize, P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>>(
    file: &str,
    case: &MmtCase,
    perm: &P,
) {
    let name = label(file, case);
    assert_eq!(case.plaintext.len(), case.ciphertext.len());
    assert_eq!(case.plaintext.len() % BLOCK_LEN, 0, "{name}: whole blocks");

    let mut buf = case.plaintext.clone();
    for block in buf.as_chunks_mut::<BLOCK_LEN>().0 {
        perm.encrypt_block(block);
    }
    assert_eq!(buf, case.ciphertext, "{name}: encrypt");
    for block in buf.as_chunks_mut::<BLOCK_LEN>().0 {
        perm.decrypt_block(block);
    }
    assert_eq!(buf, case.plaintext, "{name}: decrypt");

    // The four-block methods must give the same answers; the longer cases (up to ten
    // blocks) exercise them, with the remainder going through single blocks.
    {
        let (blocks, _) = buf.as_chunks_mut::<BLOCK_LEN>();
        let (fours, rest) = blocks.as_chunks_mut::<4>();
        for four in fours {
            perm.encrypt_4blocks(four);
        }
        for block in rest {
            perm.encrypt_block(block);
        }
    }
    assert_eq!(buf, case.ciphertext, "{name}: encrypt_4blocks");
    {
        let (blocks, _) = buf.as_chunks_mut::<BLOCK_LEN>();
        let (fours, rest) = blocks.as_chunks_mut::<4>();
        for four in fours {
            perm.decrypt_4blocks(four);
        }
        for block in rest {
            perm.decrypt_block(block);
        }
    }
    assert_eq!(buf, case.plaintext, "{name}: decrypt_4blocks");
}

#[test]
fn tecbmmt3() {
    let Some(cases) = load("TECBMMT3.rsp") else { return };
    for case in &cases {
        let tdes = TDES::new(&key3(case)).expect("a valid CAVP key bundle");
        check_ecb("TECBMMT3", case, &tdes);
    }
}

#[test]
fn tecbmmt2() {
    let Some(cases) = load("TECBMMT2.rsp") else { return };
    for case in &cases {
        let tdes = TDES2Key::new(&key2(case)).expect("a valid CAVP two-key bundle");
        check_ecb("TECBMMT2", case, &tdes);
    }
}

#[test]
fn tcbcmmt3() {
    type Enc = Cbc<TDES, Encrypting, KEY_LEN, BLOCK_LEN>;
    type Dec = Cbc<TDES, Decrypting, KEY_LEN, BLOCK_LEN>;
    let Some(cases) = load("TCBCMMT3.rsp") else { return };

    for case in &cases {
        let key = key3(case);
        let iv = iv(case);
        let name = label("TCBCMMT3", case);

        let (mut enc, got_iv) = Enc::do_encrypt_init_rng(&key, &mut FixedSeedRNG::new(iv)).unwrap();
        assert_eq!(got_iv, iv, "{name}: the pinned RNG should reproduce the vector's IV");
        let mut buf = case.plaintext.clone();
        for block in buf.as_chunks_mut::<BLOCK_LEN>().0 {
            enc.do_encrypt(block).unwrap();
        }
        assert_eq!(buf, case.ciphertext, "{name}: encrypt");

        let mut dec = Dec::do_decrypt_init(&key, &iv).unwrap();
        for block in buf.as_chunks_mut::<BLOCK_LEN>().0 {
            dec.do_decrypt(block).unwrap();
        }
        assert_eq!(buf, case.plaintext, "{name}: decrypt");
    }
}

#[test]
fn tcbcmmt2_decrypts() {
    type Dec = Cbc<TDES2Key, Decrypting, KEY_LEN_2KEY, BLOCK_LEN>;
    let Some(cases) = load("TCBCMMT2.rsp") else { return };

    for case in &cases {
        let name = label("TCBCMMT2", case);
        let mut dec = Dec::do_decrypt_init(&key2(case), &iv(case)).unwrap();
        let mut buf = case.ciphertext.clone();
        for block in buf.as_chunks_mut::<BLOCK_LEN>().0 {
            dec.do_decrypt(block).unwrap();
        }
        assert_eq!(buf, case.plaintext, "{name}: decrypt");
    }
}

/// CFB64 and CFB8 share a shape: stream cipher, 8-byte IV, any length. Three-key: both directions.
fn check_stream3<E, D>(file: &str)
where
    E: StreamCipherEncryptor<KEY_LEN, BLOCK_LEN>,
    D: StreamCipherDecryptor<KEY_LEN, BLOCK_LEN>,
{
    let Some(cases) = load(file) else { return };
    for case in &cases {
        let key = key3(case);
        let iv = iv(case);
        let name = label(file, case);

        let (mut enc, got_iv) = E::do_encrypt_init_rng(&key, &mut FixedSeedRNG::new(iv)).unwrap();
        assert_eq!(got_iv, iv, "{name}: the pinned RNG should reproduce the vector's IV");
        let mut buf = case.plaintext.clone();
        enc.do_encrypt(&mut buf).unwrap();
        assert_eq!(buf, case.ciphertext, "{name}: encrypt");

        let mut dec = D::do_decrypt_init(&key, &iv).unwrap();
        dec.do_decrypt(&mut buf).unwrap();
        assert_eq!(buf, case.plaintext, "{name}: decrypt");

        // The same message fed one byte at a time must give the same ciphertext.
        let (mut enc, _) = E::do_encrypt_init_rng(&key, &mut FixedSeedRNG::new(iv)).unwrap();
        let mut buf = case.plaintext.clone();
        for byte in buf.iter_mut() {
            enc.do_encrypt(core::slice::from_mut(byte)).unwrap();
        }
        assert_eq!(buf, case.ciphertext, "{name}: encrypt byte by byte");
    }
}

/// Two-key: decryption only, whole and byte by byte.
fn check_stream2<D>(file: &str)
where
    D: StreamCipherDecryptor<KEY_LEN_2KEY, BLOCK_LEN>,
{
    let Some(cases) = load(file) else { return };
    for case in &cases {
        let key = key2(case);
        let iv = iv(case);
        let name = label(file, case);

        let mut dec = D::do_decrypt_init(&key, &iv).unwrap();
        let mut buf = case.ciphertext.clone();
        dec.do_decrypt(&mut buf).unwrap();
        assert_eq!(buf, case.plaintext, "{name}: decrypt");

        let mut dec = D::do_decrypt_init(&key, &iv).unwrap();
        let mut buf = case.ciphertext.clone();
        for byte in buf.iter_mut() {
            dec.do_decrypt(core::slice::from_mut(byte)).unwrap();
        }
        assert_eq!(buf, case.plaintext, "{name}: decrypt byte by byte");
    }
}

#[test]
fn tcfb64mmt3() {
    check_stream3::<TDES_CFB<Encrypting>, TDES_CFB<Decrypting>>("TCFB64MMT3.rsp");
}

#[test]
fn tcfb8mmt3() {
    check_stream3::<TDES_CFB8<Encrypting>, TDES_CFB8<Decrypting>>("TCFB8MMT3.rsp");
}

#[test]
fn tcfb64mmt2_decrypts() {
    check_stream2::<TDES2_CFB>("TCFB64MMT2.rsp");
}

#[test]
fn tcfb8mmt2_decrypts() {
    check_stream2::<TDES2_CFB8>("TCFB8MMT2.rsp");
}

#[test]
fn the_vector_files_have_the_expected_shape() {
    // Messages of one block per COUNT (CFB8: one byte), all keys with odd parity as CAVP generates
    // them, and KEY3 = KEY1 in the two-key files. A damaged copy of the data fails here rather than
    // as a puzzling cipher mismatch. (`load` checks the case counts.)
    let files = [
        ("TECBMMT3.rsp", BLOCK_LEN, false),
        ("TCBCMMT3.rsp", BLOCK_LEN, false),
        ("TCFB64MMT3.rsp", BLOCK_LEN, false),
        ("TCFB8MMT3.rsp", 1, false),
        ("TECBMMT2.rsp", BLOCK_LEN, true),
        ("TCBCMMT2.rsp", BLOCK_LEN, true),
        ("TCFB64MMT2.rsp", BLOCK_LEN, true),
        ("TCFB8MMT2.rsp", 1, true),
    ];
    for (file, unit, two_key) in files {
        let Some(cases) = load(file) else { return };
        for case in &cases {
            for k in [&case.key1, &case.key2, &case.key3] {
                assert_eq!(k.len(), 8, "{file}: key length");
                for &b in k {
                    assert_eq!(b.count_ones() % 2, 1, "{file}: CAVP keys have odd parity");
                }
            }
            assert_eq!(case.key1 == case.key3, two_key, "{file}: KEY3 = KEY1 iff two-key");
            assert_eq!(case.plaintext.len(), unit * (case.count as usize + 1), "{file}");
            assert_eq!(case.ciphertext.len(), case.plaintext.len(), "{file}");
        }
    }
}
