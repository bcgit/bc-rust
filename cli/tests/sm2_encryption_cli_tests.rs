//! Tests for the `sm2-encryption` subcommand, driving the built `bc-rust` binary as a
//! subprocess with the harness in `common`. The known answers are two of the vectors in
//! `crypto/ec/tests/sm2_sm2_encryption_tests.rs`, whose header says where they come from:
//! GM/T 0003.5-2012 Annex C.2 (`ANNEX_C_*` there) and a ciphertext made by OpenSSL 3.0.13
//! (`OPENSSL_*`).

mod common;
use common::{
    BC_RUST, listed_in_help, pseudo_random, run, run_err, run_err_silent, run_ok, tohex, unhex,
};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

const CMD: &str = "sm2-encryption";

/// `ANNEX_C_DB`, `ANNEX_C_PB`, `ANNEX_C_M`, and `ANNEX_C_C1`, `ANNEX_C_C3` and `ANNEX_C_C2`.
const ANNEX_C_DB: &str = "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8";
const ANNEX_C_PB: &str = concat!(
    "0409f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020",
    "ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13",
);
const ANNEX_C_M: &[u8] = b"encryption standard";
const ANNEX_C_C1: &str = concat!(
    "0404ebfc718e8d1798620432268e77feb6415e2ede0e073c0f4f640ecd2e149a73",
    "e858f9d81e5430a57b36daab8f950a3c64e6ee6a63094d99283aff767e124df0",
);
const ANNEX_C_C3: &str = "59983c18f809e262923c53aec295d30383b54e39d609d160afcb1908d0bd8766";
const ANNEX_C_C2: &str = "21886ca989ca9c7d58087307ca93092d651efa";

/// `OPENSSL_D`, `OPENSSL_M` and `OPENSSL_C1C3C2`.
const OPENSSL_D: &str = "8527f34dbaf88d2f24a10d468b8a85d349f7aea6cb9a3f9066d458b312a334bf";
const OPENSSL_M: &str = "0b6afd74296c688903ff01454bea4f96909dd2";
const OPENSSL_C1C3C2: &str = concat!(
    "04c97d997041439eb58b82e28f35ed14784b6690c4285925b61789f7b609e8c3a8",
    "c9def7d2e74055bb3072a604cfe863b6d8260a9e655686972c38c3a8262344ff",
    "1ba513dba6b6f58adc1ac4af4a3ff722bec07fbea41261412272dbc7267ba79b",
    "de917ab1bfccdf7d7dbdbbb89048b3960621f3",
);

/// The lengths of `C1` and of `C1` and `C3` together.
const C1_LEN: usize = 65;
const OVERHEAD_LEN: usize = 97;

/// A fresh scratch file path holding `bytes`.
fn temp_file(name: &str, bytes: &[u8]) -> String {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path: PathBuf =
        std::env::temp_dir().join(format!("bc-rust-sm2enc-{}-{n}-{name}", std::process::id()));
    std::fs::write(&path, bytes).unwrap();
    path.to_string_lossy().into_owned()
}

/// A generated key pair, as the private and the public key file.
fn key_files() -> (String, String) {
    let sk = run_ok(&[CMD, "keygen"], b"");
    assert_eq!(sk.len(), 32);
    let pk = run_ok(&[CMD, "pk-from-sk"], &sk);
    assert_eq!(pk.len(), 65);
    (temp_file("sk", &sk), temp_file("pk", &pk))
}

fn annex_c_c1c3c2() -> Vec<u8> {
    unhex(&[ANNEX_C_C1, ANNEX_C_C3, ANNEX_C_C2].concat())
}

fn annex_c_c1c2c3() -> Vec<u8> {
    unhex(&[ANNEX_C_C1, ANNEX_C_C2, ANNEX_C_C3].concat())
}

#[test]
fn listed_in_the_help() {
    listed_in_help(&[CMD]);
}

#[test]
fn round_trips_in_both_orders() {
    let (sk, pk) = key_files();
    for len in [1usize, 300, 5000] {
        let message = pseudo_random(len, len as u32);
        for order in [&[][..], &["--c1c2c3"][..]] {
            let ciphertext =
                run_ok(&[&[CMD, "encrypt", "--pkfile", &pk], order].concat(), &message);
            assert_eq!(ciphertext.len(), len + OVERHEAD_LEN);
            assert_eq!(ciphertext[0], 0x04);
            let recovered =
                run_ok(&[&[CMD, "decrypt", "--skfile", &sk], order].concat(), &ciphertext);
            assert_eq!(recovered, message);
        }
    }
}

/// The two orders are the same parts: a default ciphertext rearranged decrypts under
/// `--c1c2c3`, and two encryptions of one message differ.
#[test]
fn the_orders_are_rearrangements_and_each_encryption_is_fresh() {
    let (sk, pk) = key_files();
    let message = pseudo_random(200, 7);
    let a = run_ok(&[CMD, "encrypt", "--pkfile", &pk], &message);
    let b = run_ok(&[CMD, "encrypt", "--pkfile", &pk], &message);
    assert_ne!(a, b);

    let rearranged = [&a[..C1_LEN], &a[OVERHEAD_LEN..], &a[C1_LEN..OVERHEAD_LEN]].concat();
    let recovered = run_ok(&[CMD, "decrypt", "--skfile", &sk, "--c1c2c3"], &rearranged);
    assert_eq!(recovered, message);
}

#[test]
fn decrypt_matches_the_known_answers() {
    let sk = temp_file("annex-sk", &unhex(ANNEX_C_DB));
    assert_eq!(run_ok(&[CMD, "decrypt", "--skfile", &sk], &annex_c_c1c3c2()), ANNEX_C_M);
    assert_eq!(
        run_ok(&[CMD, "decrypt", "--skfile", &sk, "--c1c2c3"], &annex_c_c1c2c3()),
        ANNEX_C_M
    );
    // The annex's public key is the one the command derives.
    assert_eq!(tohex(&run_ok(&[CMD, "pk-from-sk", "--skfile", &sk], b"")), ANNEX_C_PB);

    let sk = temp_file("openssl-sk", &unhex(OPENSSL_D));
    let out = run_ok(&[CMD, "decrypt", "--skfile", &sk, "-x"], &unhex(OPENSSL_C1C3C2));
    assert_eq!(String::from_utf8(out).unwrap(), format!("{OPENSSL_M}\n"));
}

/// `-x` writes hex and a newline, and `--hex-input` reads the key files as hex; stdin is raw
/// in both directions with or without it, as for the `*-ccm` commands.
#[test]
fn hex_output_and_hex_input() {
    let sk = temp_file("hex-sk", ANNEX_C_DB.as_bytes());
    let pk = temp_file("hex-pk", ANNEX_C_PB.as_bytes());
    let hex_ct = run_ok(&["--hex-input", CMD, "encrypt", "--pkfile", &pk, "-x"], b"abc");
    assert_eq!(hex_ct.len(), 2 * (3 + OVERHEAD_LEN) + 1);
    let (digits, newline) = hex_ct.split_at(hex_ct.len() - 1);
    assert_eq!(newline, b"\n");
    let ciphertext = unhex(std::str::from_utf8(digits).unwrap());
    assert_eq!(run_ok(&["--hex-input", CMD, "decrypt", "--skfile", &sk], &ciphertext), b"abc");
    assert_eq!(
        run_ok(&["--hex-input", CMD, "decrypt", "--skfile", &sk, "-x"], &ciphertext),
        b"616263\n"
    );

    // The message is not hex-decoded: these six bytes are the message.
    let hex_ct = run_ok(&["--hex-input", CMD, "encrypt", "--pkfile", &pk], b"616263");
    assert_eq!(hex_ct.len(), 6 + OVERHEAD_LEN);
    // And neither is the ciphertext: as hex text it is not one.
    let known = tohex(&annex_c_c1c3c2());
    assert_eq!(
        run_ok(&["--hex-input", CMD, "decrypt", "--skfile", &sk], &annex_c_c1c3c2()),
        ANNEX_C_M
    );
    let err = run_err_silent(&["--hex-input", CMD, "decrypt", "--skfile", &sk], known.as_bytes());
    assert_eq!(err, "Error: SM2 decryption failed.\n");
}

#[test]
fn a_tampered_ciphertext_fails_and_writes_nothing() {
    let sk = temp_file("annex-sk", &unhex(ANNEX_C_DB));
    let good = annex_c_c1c3c2();
    // A byte of C1, of C3, and the first and last of C2.
    for i in [1, C1_LEN - 1, C1_LEN, OVERHEAD_LEN - 1, OVERHEAD_LEN, good.len() - 1] {
        let mut bad = good.clone();
        bad[i] ^= 0x01;
        let err = run_err_silent(&[CMD, "decrypt", "--skfile", &sk], &bad);
        assert_eq!(err, "Error: SM2 decryption failed.\n", "byte {i}");
    }
    // One byte more or fewer of C2.
    let err = run_err_silent(&[CMD, "decrypt", "--skfile", &sk], &[&good[..], &[0]].concat());
    assert_eq!(err, "Error: SM2 decryption failed.\n");
    let err = run_err_silent(&[CMD, "decrypt", "--skfile", &sk], &good[..good.len() - 1]);
    assert_eq!(err, "Error: SM2 decryption failed.\n");
}

#[test]
fn the_wrong_order_fails() {
    let sk = temp_file("annex-sk", &unhex(ANNEX_C_DB));
    let err = run_err_silent(&[CMD, "decrypt", "--skfile", &sk, "--c1c2c3"], &annex_c_c1c3c2());
    assert_eq!(err, "Error: SM2 decryption failed.\n");
    let err = run_err_silent(&[CMD, "decrypt", "--skfile", &sk], &annex_c_c1c2c3());
    assert_eq!(err, "Error: SM2 decryption failed.\n");
}

#[test]
fn the_wrong_key_fails() {
    let sk = temp_file("openssl-sk", &unhex(OPENSSL_D));
    let err = run_err_silent(&[CMD, "decrypt", "--skfile", &sk], &annex_c_c1c3c2());
    assert_eq!(err, "Error: SM2 decryption failed.\n");
}

#[test]
fn an_empty_message_is_refused() {
    let pk = temp_file("annex-pk", &unhex(ANNEX_C_PB));
    for order in [&[][..], &["--c1c2c3"][..]] {
        let err = run_err_silent(&[&[CMD, "encrypt", "--pkfile", &pk], order].concat(), b"");
        assert!(err.contains("the message is empty"), "{err}");
    }
}

/// Anything of 97 bytes or fewer has no `C2`: it fails as every other ciphertext that does
/// not decrypt, with the same message and nothing on stdout.
#[test]
fn a_truncated_ciphertext_is_refused() {
    let sk = temp_file("annex-sk", &unhex(ANNEX_C_DB));
    let good = annex_c_c1c3c2();
    for len in [0, 1, C1_LEN, OVERHEAD_LEN - 1, OVERHEAD_LEN] {
        for order in [&[][..], &["--c1c2c3"][..]] {
            let err =
                run_err_silent(&[&[CMD, "decrypt", "--skfile", &sk], order].concat(), &good[..len]);
            assert_eq!(err, "Error: SM2 decryption failed.\n", "length {len}");
        }
    }
}

#[test]
fn missing_and_malformed_keys_are_errors() {
    let pk = temp_file("annex-pk", &unhex(ANNEX_C_PB));
    let sk = temp_file("annex-sk", &unhex(ANNEX_C_DB));
    assert!(run_err(&[CMD, "encrypt"], b"m").contains("no pkfile provided"));
    assert!(run_err(&[CMD, "decrypt"], &annex_c_c1c3c2()).contains("no skfile provided"));
    // Each key file given as the other.
    let err = run_err_silent(&[CMD, "encrypt", "--pkfile", &sk], b"m");
    assert!(err.contains("valid SM2 public key"), "{err}");
    let err = run_err_silent(&[CMD, "decrypt", "--skfile", &pk], &annex_c_c1c3c2());
    assert!(err.contains("valid SM2 private key"), "{err}");
    // A private key of zero.
    let out = run(&[CMD, "pk-from-sk"], &[0u8; 32]);
    assert!(!out.status.success() && out.stdout.is_empty());
}

/// `C1` in the hybrid form decrypts as the uncompressed form does: the annex's `y1` is even, so
/// its tag is `06`.
#[test]
fn a_hybrid_c1_decrypts() {
    let sk = temp_file("annex-sk", &unhex(ANNEX_C_DB));
    let mut ciphertext = annex_c_c1c3c2();
    ciphertext[0] = 0x06;
    assert_eq!(run_ok(&[CMD, "decrypt", "--skfile", &sk], &ciphertext), ANNEX_C_M);
    ciphertext[0] = 0x07;
    let err = run_err_silent(&[CMD, "decrypt", "--skfile", &sk], &ciphertext);
    assert_eq!(err, "Error: SM2 decryption failed.\n");
}

/// Where the command's stdout goes in [`run_into`].
enum Sink {
    /// A pipe whose read end is closed before the command writes.
    ClosedPipe,
    /// `/dev/full`, where every write fails with `ENOSPC`.
    Full,
}

/// Runs `bc-rust <args...>` with `stdin_bytes` on stdin and stdout sent to `sink`, and returns
/// the exit status and stderr.
fn run_into(args: &[&str], stdin_bytes: &[u8], sink: Sink) -> (ExitStatus, String) {
    let stdout = match sink {
        Sink::ClosedPipe => Stdio::piped(),
        Sink::Full => {
            Stdio::from(std::fs::OpenOptions::new().write(true).open("/dev/full").unwrap())
        }
    };
    let mut child = Command::new(BC_RUST)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(stdout)
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn bc-rust");
    // Closed before stdin is written, so before a command that reads stdin first writes.
    drop(child.stdout.take());
    match child.stdin.take().expect("stdin piped").write_all(stdin_bytes) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::BrokenPipe => {}
        Err(e) => panic!("failed to write to stdin: {e}"),
    }
    let out = child.wait_with_output().expect("failed to wait for bc-rust");
    (out.status, String::from_utf8_lossy(&out.stderr).into_owned())
}

/// A write to stdout that fails ends `keygen` and `decrypt` as it ends every command: a reader
/// that has gone away is a quiet exit with status 0, and any other failure is reported, with
/// status 255. `decrypt` writes 100,000 bytes, past std's 1 KiB stdout buffer, so its write
/// itself fails; `keygen`'s 32 or 64 bytes stay in that buffer, and it is the flush at the end of
/// the command that fails, which `/dev/full` shows (with no flush it exited 0 and lost the key).
/// The secrets the two commands hold are dropped or wiped before the exit, which no test can see
/// from outside the process.
#[test]
fn a_failed_write_to_stdout_keeps_its_exit_status() {
    let (sk, pk) = key_files();
    let message = pseudo_random(100_000, 7);
    let ciphertext = run_ok(&[CMD, "encrypt", "--pkfile", &pk], &message);

    for hex in [&[][..], &["-x"][..]] {
        let decrypt = [&[CMD, "decrypt", "--skfile", &sk], hex].concat();
        let keygen = [&[CMD, "keygen"], hex].concat();
        for args in [&decrypt, &keygen] {
            let stdin = if args == &decrypt { &ciphertext[..] } else { b"" };
            let (status, err) = run_into(args, stdin, Sink::ClosedPipe);
            assert_eq!((status.code(), err.as_str()), (Some(0), ""), "{args:?}");

            if Path::new("/dev/full").exists() {
                let (status, err) = run_into(args, stdin, Sink::Full);
                assert_eq!(status.code(), Some(255), "{args:?}");
                assert!(err.starts_with("Error: failed to write to stdout: "), "{err}");
            }
        }
    }
}
