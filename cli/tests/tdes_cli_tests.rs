//! Tests for the `tdes-*` and `tdes2-*` subcommands.
//!
//! They share their key and IV loaders, streaming loops and error paths with the AES commands
//! (`cli/src/helpers/`), and `test_aes_*.sh` cover those exhaustively. This file pins what is
//! specific to TDEA: the 8-byte block and IV, the 6-byte CTR nonce, the 24- and 16-byte bundles,
//! the decrypt-only two-key commands, and the known-answer vectors in both directions.
//!
//! The vectors are `COUNT = 0` of each NIST CAVP Multi-block Message Test file the crate's own
//! suite uses (`TECBMMT3`, `TCBCMMT3`, `TCFB64MMT3`, `TCFB8MMT3` `[ENCRYPT]`, and the two-key
//! `[DECRYPT]` files), read from `../bc-test-data` at test time; without it those tests print a
//! warning and pass, as the crate's suite does. The CBC vectors are unpadded, so under the
//! commands' PKCS7 framing the ciphertext is followed by one block of padding, computed here from
//! the engine.

use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// The path to the binary under test, resolved by cargo.
const BC_RUST: &str = env!("CARGO_BIN_EXE_bc-rust");

/// A three-key bundle of distinct, non-weak components, for the tests that need no vector.
const KEY_3: &str = "0123456789abcdef23456789abcdef01456789abcdef0123";

/// Runs `bc-rust <args...>` with `stdin_bytes` on stdin and returns the completed output.
fn run(args: &[&str], stdin_bytes: &[u8]) -> Output {
    let mut child = Command::new(BC_RUST)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn bc-rust");

    // The error-path tests hand a rejected key to a command that `exit`s before it ever reads
    // stdin, so this write races the child's exit and sometimes loses. That is an expected
    // outcome: `wait_with_output` still returns the exit status and stderr, which is all those
    // tests assert on. Any other write error is a real problem and still panics.
    match child.stdin.as_mut().expect("stdin piped").write_all(stdin_bytes) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::BrokenPipe => {}
        Err(e) => panic!("failed to write to stdin: {e}"),
    }

    child.wait_with_output().expect("failed to wait for bc-rust")
}

/// Runs a command that is expected to succeed, returning stdout.
fn run_ok(args: &[&str], stdin_bytes: &[u8]) -> Vec<u8> {
    let out = run(args, stdin_bytes);
    assert!(
        out.status.success(),
        "expected success from {args:?}, got {:?}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

/// Runs a command that is expected to fail, returning stderr as a string.
fn run_err(args: &[&str], stdin_bytes: &[u8]) -> String {
    let out = run(args, stdin_bytes);
    assert!(
        !out.status.success(),
        "expected failure from {args:?}, but it succeeded\nstdout: {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "hex string must have even length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn tohex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Deterministic pseudo-random bytes, so the tests do not depend on an RNG.
fn pseudo_random(len: usize, seed: u32) -> Vec<u8> {
    let mut state = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            (state >> 24) as u8
        })
        .collect()
}

// ---- the CAVP vectors ------------------------------------------------------------------------

/// `COUNT = 0` of one section of a CAVP MMT response file: key bundle, IV (empty for ECB),
/// plaintext and ciphertext, all as hex.
struct Vector {
    key: String,
    iv: String,
    plaintext: String,
    ciphertext: String,
}

/// Locates the TDES CAVP directory, or `None` if `bc-test-data` is not checked out.
fn cavp_dir() -> Option<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../bc-test-data/crypto/aes_tdes_vectors/TDES");
    if dir.join("TECBMMT3.rsp").exists() {
        return Some(dir);
    }
    println!(
        "WARNING: bc-test-data not found at {}; the CAVP vector tests are skipped",
        dir.display()
    );
    None
}

/// `COUNT = 0` of `[section]` in `file`, or `None` without the data. The key is `KEY1 || KEY2`
/// for a two-key file (whose `KEY3 = KEY1`) and `KEY1 || KEY2 || KEY3` otherwise.
fn vector(file: &str, section: &str) -> Option<Vector> {
    let text = std::fs::read_to_string(cavp_dir()?.join(file)).expect("readable response file");
    let body = text.split(&format!("[{section}]")).nth(1).expect("the section");
    let case = body.split("COUNT = 0").nth(1).expect("COUNT = 0");
    let case = case.split("COUNT = 1").next().expect("one case");
    let field = |name: &str| -> String {
        case.lines()
            .map(str::trim)
            .find_map(|l| l.strip_prefix(&format!("{name} = ")))
            .unwrap_or_default()
            .to_lowercase()
    };
    let (k1, k2, k3) = (field("KEY1"), field("KEY2"), field("KEY3"));
    let key = if file.ends_with("MMT2.rsp") {
        assert_eq!(k1, k3, "a two-key vector has KEY3 = KEY1");
        k1 + &k2
    } else {
        k1 + &k2 + &k3
    };
    Some(Vector {
        key,
        iv: field("IV"),
        plaintext: field("PLAINTEXT"),
        ciphertext: field("CIPHERTEXT"),
    })
}

/// The CBC ciphertext block that a full block of PKCS7 padding (eight `0x08` bytes) encrypts to
/// under `key_hex` after the ciphertext block `prev_hex`: `E_K(prev xor 08..08)`, from the engine
/// of the bundle's length. Appended to an unpadded known-answer ciphertext, it gives the PKCS7
/// ciphertext of the same plaintext, which is how the commands frame it.
fn pkcs7_block(key_hex: &str, prev_hex: &str) -> String {
    use bouncycastle::core::hazmat::{BlockPermutation, ElectronicCodeBook};
    use bouncycastle::core::key_material::{KeyMaterial, KeyType};
    use bouncycastle::tdes::hazmat::{TDES2Internal, TDESInternal};

    fn material<const N: usize>(key_hex: &str) -> KeyMaterial<N> {
        let key_bytes: [u8; N] = unhex(key_hex).try_into().expect("the right key length");
        KeyMaterial::<N>::from_bytes_as_type(&key_bytes, KeyType::SymmetricCipherKey)
            .expect("a valid symmetric cipher key")
    }
    let mut block: [u8; 8] = unhex(prev_hex).try_into().expect("an 8-byte block");
    block.iter_mut().for_each(|b| *b ^= 0x08);
    match key_hex.len() / 2 {
        24 => TDESInternal::new(&material::<24>(key_hex)).unwrap().encrypt_block(&mut block),
        16 => TDES2Internal::new(&material::<16>(key_hex)).unwrap().encrypt_block(&mut block),
        _ => panic!("not a TDEA bundle length"),
    }
    tohex(&block)
}

/// The last 16 hex characters: the final ciphertext block.
fn last_block(ct: &str) -> &str {
    &ct[ct.len() - 16..]
}

/// `tdes-cbc encrypt --iv` reproduces TCBCMMT3 followed by the PKCS7 block, `decrypt --iv` takes
/// it back, and `decrypt` with the IV in band gives the same answer.
#[test]
fn tdes_cbc_matches_the_cavp_vector() {
    let Some(v) = vector("TCBCMMT3.rsp", "ENCRYPT") else { return };
    let want = format!("{}{}", v.ciphertext, pkcs7_block(&v.key, last_block(&v.ciphertext)));

    let out = run_ok(
        &["tdes-cbc", "-d", "encrypt", "--key", &v.key, "--iv", &v.iv],
        &unhex(&v.plaintext),
    );
    assert_eq!(tohex(&out), want, "encrypt --iv");

    let back = run_ok(&["tdes-cbc", "-d", "decrypt", "--key", &v.key, "--iv", &v.iv], &out);
    assert_eq!(tohex(&back), v.plaintext, "decrypt --iv");

    let back =
        run_ok(&["tdes-cbc", "-d", "decrypt", "--key", &v.key], &unhex(&format!("{}{want}", v.iv)));
    assert_eq!(tohex(&back), v.plaintext, "decrypt with the IV in band");
}

/// `tdes-cfb encrypt --iv` and `tdes-cfb8 encrypt --iv` reproduce TCFB64MMT3 and TCFB8MMT3
/// exactly, and `decrypt --iv` takes them back.
#[test]
fn tdes_cfb_and_cfb8_match_the_cavp_vectors() {
    for (cmd, file) in [("tdes-cfb", "TCFB64MMT3.rsp"), ("tdes-cfb8", "TCFB8MMT3.rsp")] {
        let Some(v) = vector(file, "ENCRYPT") else { return };
        let out =
            run_ok(&[cmd, "-d", "encrypt", "--key", &v.key, "--iv", &v.iv], &unhex(&v.plaintext));
        assert_eq!(tohex(&out), v.ciphertext, "{cmd} encrypt --iv");
        let back = run_ok(&[cmd, "-d", "decrypt", "--key", &v.key, "--iv", &v.iv], &out);
        assert_eq!(tohex(&back), v.plaintext, "{cmd} decrypt --iv");
    }
}

/// `tdes-ecb` reproduces TECBMMT3 in both directions; there is no IV and no padding.
#[test]
fn tdes_ecb_matches_the_cavp_vector() {
    let Some(v) = vector("TECBMMT3.rsp", "ENCRYPT") else { return };
    let out = run_ok(&["tdes-ecb", "-d", "encrypt", "--key", &v.key], &unhex(&v.plaintext));
    assert_eq!(tohex(&out), v.ciphertext, "encrypt");
    let back = run_ok(&["tdes-ecb", "-d", "decrypt", "--key", &v.key], &out);
    assert_eq!(tohex(&back), v.plaintext, "decrypt");
}

/// The two-key commands decrypt the `[DECRYPT]` vectors of the two-key files: CBC with the PKCS7
/// block appended, CFB64 and CFB8 exactly, ECB without an IV.
#[test]
fn tdes2_commands_decrypt_the_cavp_vectors() {
    let Some(v) = vector("TCBCMMT2.rsp", "DECRYPT") else { return };
    let padded = format!("{}{}", v.ciphertext, pkcs7_block(&v.key, last_block(&v.ciphertext)));
    let out =
        run_ok(&["tdes2-cbc", "-d", "decrypt", "--key", &v.key, "--iv", &v.iv], &unhex(&padded));
    assert_eq!(tohex(&out), v.plaintext, "tdes2-cbc decrypt --iv");
    let out = run_ok(
        &["tdes2-cbc", "-d", "decrypt", "--key", &v.key],
        &unhex(&format!("{}{padded}", v.iv)),
    );
    assert_eq!(tohex(&out), v.plaintext, "tdes2-cbc decrypt with the IV in band");

    for (cmd, file) in [("tdes2-cfb", "TCFB64MMT2.rsp"), ("tdes2-cfb8", "TCFB8MMT2.rsp")] {
        let Some(v) = vector(file, "DECRYPT") else { return };
        let out =
            run_ok(&[cmd, "-d", "decrypt", "--key", &v.key, "--iv", &v.iv], &unhex(&v.ciphertext));
        assert_eq!(tohex(&out), v.plaintext, "{cmd} decrypt --iv");
    }

    let Some(v) = vector("TECBMMT2.rsp", "DECRYPT") else { return };
    let out = run_ok(&["tdes2-ecb", "-d", "decrypt", "--key", &v.key], &unhex(&v.ciphertext));
    assert_eq!(tohex(&out), v.plaintext, "tdes2-ecb decrypt");
}

// ---- the contract ----------------------------------------------------------------------------

/// `encrypt | decrypt` composes for every three-key mode: the 8-byte IV (6-byte nonce for CTR)
/// rides at the front, CBC pads with PKCS7, the stream modes and ECB do not.
#[test]
fn every_three_key_mode_round_trips() {
    let plaintext = pseudo_random(4096, 0xC0FFEE);
    for (cmd, init_len, padded_len) in [
        ("tdes-cbc", 8, 4096 + 8),
        ("tdes-cfb", 8, 4096),
        ("tdes-cfb8", 8, 4096),
        ("tdes-ctr", 6, 4096),
        ("tdes-ecb", 0, 4096),
    ] {
        let ciphertext = run_ok(&[cmd, "-d", "encrypt", "--key", KEY_3], &plaintext);
        assert_eq!(ciphertext.len(), init_len + padded_len, "{cmd}: init data plus the body");
        assert_ne!(&ciphertext[init_len..init_len + 64], &plaintext[..64], "{cmd}: encrypted");
        let recovered = run_ok(&[cmd, "-d", "decrypt", "--key", KEY_3], &ciphertext);
        assert_eq!(recovered, plaintext, "{cmd}: round trip");
    }
}

/// CBC accepts any length and pads to the next whole 8-byte block; ECB does not pad and rejects
/// unaligned input.
#[test]
fn cbc_pads_and_ecb_does_not() {
    for len in [0usize, 1, 7, 8, 9, 17] {
        let plaintext = vec![0x5Au8; len];
        let ciphertext = run_ok(&["tdes-cbc", "-d", "encrypt", "--key", KEY_3], &plaintext);
        assert_eq!(ciphertext.len(), 8 + (len / 8 + 1) * 8, "len {len}: IV plus padded body");
        let recovered = run_ok(&["tdes-cbc", "-d", "decrypt", "--key", KEY_3], &ciphertext);
        assert_eq!(recovered, plaintext, "len {len}: round trip");
    }
    let err = run_err(&["tdes-ecb", "-d", "encrypt", "--key", KEY_3], &[0u8; 9]);
    assert!(err.contains("whole number of 8-byte blocks"), "stderr was: {err}");
}

/// With `--iv` the output is the ciphertext alone, and it is still CTR over TDEA under that
/// 6-byte nonce: the library's key object decrypts it.
#[test]
fn tdes_ctr_under_a_supplied_nonce_agrees_with_the_library() {
    use bouncycastle::cipher::modes::CTR;
    use bouncycastle::core::key_material::{KeyMaterial, KeyType};
    use bouncycastle::core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey};
    use bouncycastle::tdes::{BLOCK_LEN, CTR_NONCE_LEN, TDES3Key};

    let nonce = "000102030405";
    let plaintext = pseudo_random(37, 5);
    let out = run_ok(&["tdes-ctr", "-d", "encrypt", "--key", KEY_3, "--iv", nonce], &plaintext);
    assert_eq!(out.len(), plaintext.len(), "ciphertext only, no nonce in band");

    let key_bytes: [u8; 24] = unhex(KEY_3).try_into().unwrap();
    let material = KeyMaterial::<24>::from_bytes_as_type(&key_bytes, KeyType::SymmetricCipherKey)
        .expect("a valid symmetric cipher key");
    let key = TDES3Key::<CTR<CTR_NONCE_LEN, BLOCK_LEN>>::from_key_material(&material).unwrap();
    let mut recovered = out.clone();
    let nonce_bytes: [u8; CTR_NONCE_LEN] = unhex(nonce).try_into().unwrap();
    key.decrypt_inplace(&nonce_bytes, &mut recovered).expect("decryption");
    assert_eq!(recovered, plaintext, "the CLI should agree with the library under that nonce");

    let back = run_ok(&["tdes-ctr", "-d", "decrypt", "--key", KEY_3, "--iv", nonce], &out);
    assert_eq!(back, plaintext);
}

/// The same with `-x`: identical answer in hex plus a trailing newline.
#[test]
fn hex_output_matches_binary_output() {
    let plaintext = pseudo_random(32, 3);
    let ciphertext = run_ok(&["tdes-cbc", "-d", "encrypt", "--key", KEY_3], &plaintext);
    let binary = run_ok(&["tdes-cbc", "-d", "decrypt", "--key", KEY_3], &ciphertext);
    let hex_out = run_ok(&["tdes-cbc", "-d", "decrypt", "--key", KEY_3, "-x"], &ciphertext);
    assert_eq!(String::from_utf8_lossy(&hex_out), format!("{}\n", tohex(&binary)));
    assert_eq!(binary, plaintext);
}

/// The two-key commands have no `encrypt`: the parser refuses it, naming the one value.
#[test]
fn two_key_commands_refuse_to_encrypt() {
    let key_2 = &KEY_3[..32];
    for cmd in ["tdes2-cbc", "tdes2-cfb", "tdes2-cfb8", "tdes2-ctr", "tdes2-ecb"] {
        let err = run_err(&[cmd, "-d", "encrypt", "--key", key_2], &[0u8; 16]);
        assert!(
            err.contains("decrypt"),
            "{cmd}: stderr should list the one valid value, was: {err}"
        );
    }
}

/// Each command wants exactly its bundle length, and a bundle that repeats a component or holds
/// a weak DEA key is rejected by the key object.
#[test]
fn bad_bundles_are_rejected() {
    let err = run_err(&["tdes-cbc", "-d", "encrypt", "--key", &KEY_3[..32]], &[0u8; 16]);
    assert!(err.contains("TDES needs a 24-byte key, got 16 bytes"), "stderr was: {err}");
    let err = run_err(&["tdes2-cbc", "-d", "decrypt", "--key", KEY_3], &[0u8; 16]);
    assert!(err.contains("two-key TDES needs a 16-byte key, got 24 bytes"), "stderr was: {err}");

    // Key1 = Key2: two of the three transformations cancel.
    let repeated = "0123456789abcdef0123456789abcdef456789abcdef0123";
    let err = run_err(&["tdes-cbc", "-d", "encrypt", "--key", repeated], &[0u8; 16]);
    assert!(err.contains("WeakKey"), "stderr was: {err}");
    // A weak DEA key as Key1.
    let weak = "010101010101010123456789abcdef01456789abcdef0123";
    let err = run_err(&["tdes-cfb", "-d", "encrypt", "--key", weak], &[0u8; 16]);
    assert!(err.contains("WeakKey"), "stderr was: {err}");
}

/// The harness above must survive a write that loses the race with the child's exit: the key is
/// rejected so the command exits before reading a byte, and the payload cannot fit in a pipe
/// buffer, so the write is certain to get EPIPE.
#[test]
fn a_large_payload_on_an_error_path_does_not_break_the_harness() {
    let err =
        run_err(&["tdes-cbc", "-d", "encrypt", "--key", &KEY_3[..32]], &vec![0u8; 4 * 1024 * 1024]);
    assert!(err.contains("TDES needs a 24-byte key"), "stderr was: {err}");
}

/// The subcommands are discoverable.
#[test]
fn the_subcommands_are_listed_in_help() {
    let out = run_ok(&["--help"], &[]);
    let help = String::from_utf8_lossy(&out);
    for cmd in
        ["tdes-cbc", "tdes-cfb", "tdes-cfb8", "tdes-ctr", "tdes-ecb", "tdes2-cbc", "tdes2-ecb"]
    {
        assert!(help.contains(cmd), "`--help` should list {cmd}");
    }
}
