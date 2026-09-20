//! Tests for the `rsa-1024` .. `rsa-8192` subcommands, driving the built `bc-rust` binary as a
//! subprocess (the harness is the one `aes_cbc_cli_tests.rs` documents): the behaviour worth
//! testing is the command-line contract -- key/signature file loading, the streamed stdin message,
//! exit codes -- none of which is reachable from the library API. What the library computes is
//! cross-checked by verifying the CLI's signatures with `bouncycastle_rsa`'s own
//! `SignatureVerifier` impls (and, for the deterministic PKCS#1 v1.5 case, comparing bytes).
//!
//! `CARGO_BIN_EXE_bc-rust` is set by cargo for integration tests and points at the binary for the
//! current profile, so there is nothing to build or locate by hand.

use bouncycastle::core::traits::{
    SignaturePrivateKey, SignaturePublicKey, SignatureVerifier, Signer,
};
use bouncycastle::rsa::rsa_2048::{
    PK_LEN, RSASSA_PKCS1_v1_5_SHA256, RSASSA_PSS_SHA256, RSASSA_PSS_SHAKE128, Rsa2048PrivateKey,
    Rsa2048PublicKey, SIG_LEN,
};
use std::io::{ErrorKind, Write};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

/// The path to the binary under test, resolved by cargo.
const BC_RUST: &str = env!("CARGO_BIN_EXE_bc-rust");

/// The genuine RSA-2048 CRT key `bouncycastle_rsa`'s own crate docs use (Wycheproof
/// `rsa_pkcs1_2048_sig_gen_test.json`'s SHA-256 group, factored as `rsa_2048_pkcs1_v1_5_tests.rs`
/// describes), in the CLI's `p || q || dP || dQ || qInv` key-file layout, hex.
const SK_2048_HEX: &str = concat!(
    "dc431050f782e894fb5248247d98cb7d58b8d1e24f3b55d041c56e4de086b0d5",
    "bb028bda42eeb5d234d5681e5809d415e6a289ad4cfbf78f978f6c35814f50ee",
    "bff1c5b80a69f788e81e6bab5ddaa78369d659d143ec6f17e79813a575cfad9c",
    "569156b90113e2e9110ad9e7b48a1c9348a6e653321191290ea36cfb3a5b18f1",
    "bd1a81e7977f9898122273ae3222b598ea5fb19eb4eabc38308a5e32196603b2",
    "e500ffb79f5b886816611debc472fac45544070beb057c941378a6868af3b7a0",
    "3d3f9880ec47d5e089b94fbde542aba9ae8d72c57088d7abf5b131f39098f7bc",
    "160f90536abc9492fd4e06f3ed7299d4b97bb03677207d95669f140cfbc20f25",
    "a94b528b28f291599121d91952ffd1c7f21d7c1479d99d478885fb161870ee12",
    "18bf08472612dbe5497e8d9c650688e09c786961ae3e2c354dc48ae34514759c",
    "4c23c4588488961dc06b414e61c0e1e7fbbd2923d31532fe289f96da220711e5",
    "8c14019808e00414276933bb07e4efb9b4a9b37656917205209f33f09515d7c1",
    "3af0e72a933aef09ff2503df78bafed531c02ff1a2bc437c540cdcbd4ad35435",
    "cf511763596543480629b114ca7f780ff7efa32ea0cb6e000d6d9ea1f2ef71fd",
    "9cf9948422a165557e37e755edfe70d90b920502eb478bc98a63f788ce3a0f85",
    "6d6ede7251a383bfa8fa480a81a925af7b3cc538c4bab8c9f7597ffb68011d8d",
    "2640fbfbcfefb163ee7a87b6483a66ee41f956d90fa8a7939bfc042ee0924b1b",
    "7993d0445f758d51933e85179c0320b0c968b48a91c38b5be923e1097c0c562f",
    "88d42294b6a2759bafa5428a74f1270874e45f6fcc60f21602de5eccd143cf31",
    "241f5921b5ad3983fb54ef17be3b285367e50c999c67247b552fe4bfce945f7b",
);
/// Its public key, `n || e` with `e = 0x10001`.
const PK_2048_HEX: &str = concat!(
    "a2b451a07d0aa5f96e455671513550514a8a5b462ebef717094fa1fee82224e6",
    "37f9746d3f7cafd31878d80325b6ef5a1700f65903b469429e89d6eac8845097",
    "b5ab393189db92512ed8a7711a1253facd20f79c15e8247f3d3e42e46e48c98e",
    "254a2fe9765313a03eff8f17e1a029397a1fa26a8dce26f490ed81299615d981",
    "4c22da610428e09c7d9658594266f5c021d0fceca08d945a12be82de4d1ece6b",
    "4c03145b5d3495d4ed5411eb878daf05fd7afc3e09ada0f1126422f590975a19",
    "69816f48698bcbba1b4d9cae79d460d8f9f85e7975005d9bc22c4e5ac0f7c1a4",
    "5d12569a62807d3b9a02e5a530e773066f453d1f5b4c2e9cf7820283f742b9d5",
    "00010001",
);
/// The RSA-1024 public key from `bouncycastle_rsa`'s crate docs (Wycheproof
/// `rsa_pkcs1_1024_sig_gen_test.json`'s first group), `n || e`.
const PK_1024_HEX: &str = concat!(
    "ac9048a7a4f560af91b4fcaf62a14595cb9ca9ec12000fc845e48572113cab28",
    "90adb011a919575a40760d1f23fe92509c8a5810b6d05990b909dd0f4c6014f2",
    "b31b6abd805bace99816e2eda41fd7b95405db7c5c8f4cf6babb14f550d5d0dd",
    "5179b54951fff6aa9686f30f478db649b7c7044cc202dccad00343468eaacfbf",
    "00010001",
);
/// One of that group's genuine PKCS#1 v1.5/SHA-256 signatures, over twenty zero bytes.
const SIG_1024_HEX: &str = concat!(
    "41339884a9b3940e8488d666bb158063c6a2a2717cae7f564834a876fcbf7098",
    "ecf3acbfabf37d38a8e6127b1e313744f1f896e165efdaea0b2e7673867842b9",
    "e94db0868ed9a92bcdcb370a4e20ff275c82595e4400a8b9e9f12482f014846b",
    "48216f321266ae6ae6338dbcdc41b711e483e6e3e728772e7f9f5ef95c30196b",
);

/// Runs `bc-rust <args...>` with `stdin_bytes` on stdin and returns the completed output. See
/// `aes_cbc_cli_tests.rs`'s `run` for why stdin is written from a thread and `BrokenPipe` ignored.
fn run(args: &[&str], stdin_bytes: &[u8]) -> Output {
    let mut child = Command::new(BC_RUST)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn bc-rust");

    let mut stdin = child.stdin.take().expect("stdin piped");
    let payload = stdin_bytes.to_vec();
    let writer = thread::spawn(move || match stdin.write_all(&payload) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::BrokenPipe => {}
        Err(e) => panic!("failed to write to stdin: {e}"),
    });

    let output = child.wait_with_output().expect("failed to wait for bc-rust");
    writer.join().expect("the stdin writer thread panicked");
    output
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

/// Deterministic pseudo-random bytes, so the tests do not depend on an RNG or on `/dev/urandom`.
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

static NEXT_FILE: AtomicUsize = AtomicUsize::new(0);

/// Writes `contents` to a fresh file under the system temp dir (unique per process and call, so
/// parallel tests never share one) and returns its path as a `String` for `--skfile` and friends.
fn temp_file(tag: &str, contents: &[u8]) -> String {
    let n = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
    let mut path: PathBuf = std::env::temp_dir();
    path.push(format!("bc-rust-rsa-cli-{}-{n}-{tag}", std::process::id()));
    std::fs::write(&path, contents).expect("write temp file");
    path.to_string_lossy().into_owned()
}

fn sk_2048() -> Rsa2048PrivateKey {
    Rsa2048PrivateKey::from_bytes(&unhex(SK_2048_HEX)).expect("the documented key decodes")
}

fn pk_2048() -> Rsa2048PublicKey {
    Rsa2048PublicKey::from_bytes(&unhex(PK_2048_HEX)).expect("the documented key decodes")
}

/// The CLI accepts key and signature files as hex (as written here) or binary.
fn rsa_2048_sign(scheme: &str, hash: &str, msg: &[u8]) -> Vec<u8> {
    let skfile = temp_file("sk", SK_2048_HEX.as_bytes());
    run_ok(&["rsa-2048", "sign", "--scheme", scheme, "--hash", hash, "--skfile", &skfile], msg)
}

fn rsa_2048_verify(scheme: &str, hash: &str, msg: &[u8], sig: &[u8]) -> Output {
    let pkfile = temp_file("pk", PK_2048_HEX.as_bytes());
    let sigfile = temp_file("sig", sig);
    run(
        &[
            "rsa-2048", "verify", "--scheme", scheme, "--hash", hash, "--pkfile", &pkfile,
            "--sigfile", &sigfile,
        ],
        msg,
    )
}

/// Verification-only size, against a genuine Wycheproof signature: the one real known-answer
/// check the CLI can make without a key generator.
#[test]
fn rsa_1024_verifies_a_wycheproof_signature_and_rejects_another_message() {
    let pkfile = temp_file("pk1024", PK_1024_HEX.as_bytes());
    let sigfile = temp_file("sig1024", SIG_1024_HEX.as_bytes());
    let args = [
        "rsa-1024", "--scheme", "pkcs1v15", "--hash", "sha256", "--pkfile", &pkfile, "--sigfile",
        &sigfile,
    ];
    let out = run_ok(&args, &[0u8; 20]);
    assert!(String::from_utf8_lossy(&out).contains("Signature is valid."));

    let err = run_err(&args, b"a message this signature was not made for");
    assert!(err.contains("Signature is invalid."), "stderr: {err}");
}

/// PKCS#1 v1.5 is deterministic, so the CLI's signature must equal the library's byte for byte,
/// and a payload several times the CLI's 1 KB stream buffer proves the message is hashed across
/// chunk boundaries correctly.
#[test]
fn rsa_2048_pkcs1v15_signature_matches_the_library_and_verifies() {
    let msg = pseudo_random(5000, 7);
    let sig = rsa_2048_sign("pkcs1v15", "sha256", &msg);
    let expected = RSASSA_PKCS1_v1_5_SHA256::sign(&sk_2048(), &msg, None).unwrap();
    assert_eq!(sig, expected.to_vec());

    let out = rsa_2048_verify("pkcs1v15", "sha256", &msg, &sig);
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).contains("Signature is valid."));

    // `-x` writes the same signature as hex.
    let skfile = temp_file("sk", SK_2048_HEX.as_bytes());
    let hex = run_ok(
        &[
            "rsa-2048", "sign", "--scheme", "pkcs1v15", "--hash", "sha256", "--skfile", &skfile,
            "-x",
        ],
        &msg,
    );
    assert_eq!(unhex(String::from_utf8_lossy(&hex).trim()), sig);
}

/// One PSS pairing: two CLI signatures of one message differ (a fresh salt each), and both
/// verify -- through the library's `SignatureVerifier` `V` and through the CLI.
fn pss_case<V: SignatureVerifier<Rsa2048PublicKey, PK_LEN, SIG_LEN>>(hash: &str, msg: &[u8]) {
    let pk = pk_2048();
    let sig_a = rsa_2048_sign("pss", hash, msg);
    let sig_b = rsa_2048_sign("pss", hash, msg);
    assert_ne!(sig_a, sig_b, "PSS/{hash}: a fresh salt each time");
    for sig in [&sig_a, &sig_b] {
        V::verify(&pk, msg, None, sig)
            .unwrap_or_else(|e| panic!("PSS/{hash}: library rejected {e:?}"));
        let out = rsa_2048_verify("pss", hash, msg, sig);
        assert!(out.status.success(), "PSS/{hash}: {}", String::from_utf8_lossy(&out.stderr));
    }
}

/// PSS draws a fresh salt per signature: see [`pss_case`], for the MGF1/SHA-256 and the
/// SHAKE128-native pairings.
#[test]
fn rsa_2048_pss_signatures_are_fresh_and_verify_both_ways() {
    let msg = pseudo_random(3000, 11);
    pss_case::<RSASSA_PSS_SHA256>("sha256", &msg);
    pss_case::<RSASSA_PSS_SHAKE128>("shake128", &msg);
}

#[test]
fn rsa_2048_verify_rejects_a_tampered_signature_and_a_truncated_one() {
    let msg = b"tamper me";
    let mut sig = rsa_2048_sign("pkcs1v15", "sha256", msg);
    sig[17] ^= 0x01;
    let out = rsa_2048_verify("pkcs1v15", "sha256", msg, &sig);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("Signature is invalid."));

    // RFC 8017 §8.2.2 step 1: a signature that is not k octets is invalid.
    sig[17] ^= 0x01;
    let out = rsa_2048_verify("pkcs1v15", "sha256", msg, &sig[..255]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("Signature is invalid."));
}

#[test]
fn rsa_2048_rejects_a_wrong_length_key_file() {
    let short_sk = temp_file("shortsk", &unhex(SK_2048_HEX)[..639]);
    let err = run_err(
        &["rsa-2048", "sign", "--scheme", "pkcs1v15", "--hash", "sha256", "--skfile", &short_sk],
        b"msg",
    );
    assert!(err.contains("640 bytes"), "stderr: {err}");

    let short_pk = temp_file("shortpk", &unhex(PK_2048_HEX)[..259]);
    let sigfile = temp_file("sig", &[0u8; 256]);
    let err = run_err(
        &[
            "rsa-2048", "verify", "--scheme", "pkcs1v15", "--hash", "sha256", "--pkfile",
            &short_pk, "--sigfile", &sigfile,
        ],
        b"msg",
    );
    assert!(err.contains("260 bytes"), "stderr: {err}");
}

/// Pairings a size does not offer (PSS at 1024 bits, SHAKE256 at 2048) are refused up front.
#[test]
fn unsupported_pairings_are_refused() {
    let pkfile = temp_file("pk1024", PK_1024_HEX.as_bytes());
    let sigfile = temp_file("sig1024", SIG_1024_HEX.as_bytes());
    let err = run_err(
        &[
            "rsa-1024", "--scheme", "pss", "--hash", "sha256", "--pkfile", &pkfile, "--sigfile",
            &sigfile,
        ],
        &[0u8; 20],
    );
    assert!(err.contains("not supported"), "stderr: {err}");

    let skfile = temp_file("sk", SK_2048_HEX.as_bytes());
    let err = run_err(
        &["rsa-2048", "sign", "--scheme", "pss", "--hash", "shake256", "--skfile", &skfile],
        b"msg",
    );
    assert!(err.contains("not supported"), "stderr: {err}");
}
