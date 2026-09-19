//! CLI wiring for RSA signatures (RFC 8017 §8, RFC 8702 §3.2.1), one command function per modulus
//! size (`rsa_1024_cmd` .. `rsa_8192_cmd`) since modulus size is what fixes the private/public key
//! and signature byte lengths -- the same reason `ecdsa_cmd.rs` picks one command per curve.
//! Scheme (PKCS#1 v1.5 / PSS) and hash (SHA-256/384/512, or SHAKE128/256 for PSS) are
//! `--scheme`/`--hash` flags within a size's command rather than further separate subcommands:
//! unlike curve alone (ECDSA) or hash alone (HMAC) elsewhere in this CLI, RSA varies along three
//! independent axes at once, and multiplying all three out into subcommand names
//! (`RSA_2048_PSS_SHA384`, ...) would mean over thirty near-identical subcommands for what is
//! fundamentally one primitive per modulus size.
//!
//! `bouncycastle_rsa` does not generate keys (see that crate's `keys` module docs), so there is no
//! `Keygen` action here, and no `PkFromSk` either -- a private key's CRT components alone do not
//! determine the public exponent `e`, so there is nothing to derive a public key from. Private and
//! public key files use `RsaPrivateKey::encode`/`RsaPublicKey::encode`'s raw fixed-width layout
//! (documented on those methods): not PEM, not ASN.1 DER -- this crate has no encoder for either
//! -- so a key produced by another RSA implementation cannot be fed to this CLI directly.
//!
//! 1024- and 1536-bit RSA are verification-only in `bouncycastle_rsa` (see its crate docs' `#
//! Scope`), so `rsa_1024_cmd`/`rsa_1536_cmd` take no `action`/`skfile` at all: they only verify.
//!
//! Reads the whole message into memory (`read_all_stdin`) rather than this CLI's usual ~1 KB
//! streaming buffer: RSASSA-PKCS1-v1_5 and RSASSA-PSS both hash the entire message before any
//! signing/verification step can begin, and `bouncycastle_rsa`'s sign/verify functions take the
//! whole message as one slice -- there is no incremental hash state to feed a chunk at a time.

use crate::helpers::{read_from_file, write_bytes_or_hex};
use bouncycastle::core::errors::SignatureError;
use bouncycastle::core::traits::RNG;
use bouncycastle::rng::DefaultRNG;
use bouncycastle::rsa::keys::{RsaPrivateKey, RsaPublicKey};
use clap::ValueEnum;
use std::io;
use std::io::Read;
use std::process::exit;

#[derive(ValueEnum, Clone, Debug, PartialEq, Eq)]
pub(crate) enum RSAAction {
    /// Sign a message read from stdin with a private key file and output the signature.
    Sign,
    /// Verify a message read from stdin with a public key file and a signature file.
    Verify,
}

#[derive(ValueEnum, Clone, Debug)]
pub(crate) enum RSAScheme {
    /// RSASSA-PKCS1-v1_5 (RFC 8017 §8.2).
    Pkcs1v15,
    /// RSASSA-PSS (RFC 8017 §8.1 for SHA-256/384/512 with MGF1; RFC 8702 §3.2.1 for SHAKE128/256
    /// used natively as both the hash and the mask generation function). Salt length is fixed to
    /// the hash's own output length in both cases.
    Pss,
}

#[derive(ValueEnum, Clone, Debug)]
pub(crate) enum RSAHash {
    Sha256,
    Sha384,
    Sha512,
    /// Only valid with `--scheme pss`; RFC 8702 §5 recommends this pairing for a 2048- or
    /// 3072-bit modulus.
    Shake128,
    /// Only valid with `--scheme pss`; RFC 8702 §5 recommends this pairing for a 4096-bit or
    /// larger modulus.
    Shake256,
}

fn require_file(file: &Option<String>, flag_name: &str) -> Vec<u8> {
    match file {
        Some(f) => read_from_file(f),
        None => {
            eprintln!("Error: no {flag_name} provided.");
            exit(-1);
        }
    }
}

/// The message is read raw, never hex-decoded: unlike a key or signature file, arbitrary message
/// bytes that happen to look like hex must still be signed/verified byte-for-byte.
fn read_all_stdin() -> Vec<u8> {
    let mut buf = Vec::new();
    io::stdin().read_to_end(&mut buf).expect("Failed to read from stdin");
    buf
}

fn unsupported(scheme: &RSAScheme, hash: &RSAHash, alg_name: &str) -> ! {
    eprintln!("Error: {scheme:?}/{hash:?} is not supported for {alg_name}.");
    exit(-1);
}

/// A `bouncycastle_rsa::rsa_*::pkcs1_v1_5_sign_*` function.
type PkcsSignFn<const L: usize, const HALF: usize, const SIG_LEN: usize> =
    fn(&RsaPrivateKey<L, HALF>, &[u8]) -> Result<[u8; SIG_LEN], SignatureError>;
/// A `bouncycastle_rsa::rsa_*::pss_sign_*`/`pss_shake*_sign` function.
type PssSignFn<const L: usize, const HALF: usize, const SIG_LEN: usize> =
    fn(&RsaPrivateKey<L, HALF>, &[u8], &mut dyn RNG) -> Result<[u8; SIG_LEN], SignatureError>;
/// A `bouncycastle_rsa::rsa_*::{pkcs1_v1_5,pss,pss_shake*}_verify_*` function -- the same shape
/// for every scheme, since verification never needs an RNG.
type VerifyFn<const L: usize, const SIG_LEN: usize> =
    fn(&RsaPublicKey<L>, &[u8], &[u8; SIG_LEN]) -> Result<(), SignatureError>;

/// See [`RsaPrivateKey::from_bytes`] for the expected layout.
fn parse_sk<const HALF: usize, const L: usize, const HALF_BYTES: usize, const SK_LEN: usize>(
    bytes: &[u8],
    alg_name: &str,
) -> RsaPrivateKey<L, HALF> {
    let Ok(arr): Result<[u8; SK_LEN], _> = bytes.try_into() else {
        eprintln!("Error: {alg_name} private key file must be exactly {SK_LEN} bytes.");
        exit(-1);
    };
    match RsaPrivateKey::<L, HALF>::from_bytes::<HALF_BYTES, SK_LEN>(&arr) {
        Ok(sk) => sk,
        Err(_) => {
            eprintln!("Error: couldn't parse the input as a valid {alg_name} private key.");
            exit(-1);
        }
    }
}

/// See [`RsaPublicKey::from_bytes`] for the expected layout.
fn parse_pk<const L: usize, const N_BYTES: usize, const PK_LEN: usize>(
    bytes: &[u8],
    alg_name: &str,
) -> RsaPublicKey<L> {
    let Ok(arr): Result<[u8; PK_LEN], _> = bytes.try_into() else {
        eprintln!("Error: {alg_name} public key file must be exactly {PK_LEN} bytes.");
        exit(-1);
    };
    match RsaPublicKey::<L>::from_bytes::<N_BYTES, PK_LEN>(&arr) {
        Ok(pk) => pk,
        Err(_) => {
            eprintln!("Error: couldn't parse the input as a valid {alg_name} public key.");
            exit(-1);
        }
    }
}

/// Shared by [`rsa_pkcs1_cmd`] and [`rsa_pss_cmd`]'s `Verify` arm, and called directly by the
/// verify-only sizes (`rsa_1024_cmd`, `rsa_1536_cmd`).
fn do_verify<const L: usize, const N_BYTES: usize, const PK_LEN: usize, const SIG_LEN: usize>(
    verify: VerifyFn<L, SIG_LEN>,
    pkfile: &Option<String>,
    sigfile: &Option<String>,
    alg_name: &str,
) {
    let pk_bytes = require_file(pkfile, "pkfile");
    let pk = parse_pk::<L, N_BYTES, PK_LEN>(&pk_bytes, alg_name);
    let sig_bytes = require_file(sigfile, "sigfile");
    let Ok(sig): Result<[u8; SIG_LEN], _> = sig_bytes.try_into() else {
        eprintln!("Error: signature file must be exactly {SIG_LEN} bytes for {alg_name}.");
        exit(-1);
    };
    let msg = read_all_stdin();
    if verify(&pk, &msg, &sig).is_ok() {
        println!("Signature is valid.");
    } else {
        eprintln!("Signature is invalid.");
        exit(-1);
    }
}

/// RSASSA-PKCS1-v1_5 (deterministic: `sign` takes no RNG). See [`rsa_pss_cmd`] for the PSS
/// counterpart.
#[allow(clippy::too_many_arguments)]
fn rsa_pkcs1_cmd<
    const HALF: usize,
    const L: usize,
    const HALF_BYTES: usize,
    const SK_LEN: usize,
    const N_BYTES: usize,
    const PK_LEN: usize,
    const SIG_LEN: usize,
>(
    action: &RSAAction,
    sign: PkcsSignFn<L, HALF, SIG_LEN>,
    verify: VerifyFn<L, SIG_LEN>,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    sigfile: &Option<String>,
    output_hex: bool,
    alg_name: &str,
) {
    match action {
        RSAAction::Sign => {
            let sk_bytes = require_file(skfile, "skfile");
            let sk = parse_sk::<HALF, L, HALF_BYTES, SK_LEN>(&sk_bytes, alg_name);
            let msg = read_all_stdin();
            let sig = sign(&sk, &msg).unwrap_or_else(|_| {
                eprintln!("Error: signing failed.");
                exit(-1);
            });
            write_bytes_or_hex(&sig, output_hex);
        }
        RSAAction::Verify => {
            do_verify::<L, N_BYTES, PK_LEN, SIG_LEN>(verify, pkfile, sigfile, alg_name)
        }
    }
}

/// RSASSA-PSS (randomized: `sign` draws a fresh salt from a [`DefaultRNG`] each call), covering
/// both the MGF1-based scheme (RFC 8017 §8.1) and the SHAKE-native one (RFC 8702 §3.2.1) -- their
/// `sign`/`verify` function shapes are identical, only the concrete function passed in differs.
#[allow(clippy::too_many_arguments)]
fn rsa_pss_cmd<
    const HALF: usize,
    const L: usize,
    const HALF_BYTES: usize,
    const SK_LEN: usize,
    const N_BYTES: usize,
    const PK_LEN: usize,
    const SIG_LEN: usize,
>(
    action: &RSAAction,
    sign: PssSignFn<L, HALF, SIG_LEN>,
    verify: VerifyFn<L, SIG_LEN>,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    sigfile: &Option<String>,
    output_hex: bool,
    alg_name: &str,
) {
    match action {
        RSAAction::Sign => {
            let sk_bytes = require_file(skfile, "skfile");
            let sk = parse_sk::<HALF, L, HALF_BYTES, SK_LEN>(&sk_bytes, alg_name);
            let msg = read_all_stdin();
            let mut rng = DefaultRNG::default();
            let sig = sign(&sk, &msg, &mut rng).unwrap_or_else(|_| {
                eprintln!("Error: signing failed.");
                exit(-1);
            });
            write_bytes_or_hex(&sig, output_hex);
        }
        RSAAction::Verify => {
            do_verify::<L, N_BYTES, PK_LEN, SIG_LEN>(verify, pkfile, sigfile, alg_name)
        }
    }
}

/// RSA-1024: verification only (see module docs). `L = 16`, `N_BYTES = 128`, `PK_LEN = 132`,
/// `SIG_LEN = 128`. No SHA-512 or PSS group exists in Wycheproof at this size (see
/// `bouncycastle_rsa::rsa_1024`'s own docs), so neither is wired up here either.
pub(crate) fn rsa_1024_cmd(
    scheme: &RSAScheme,
    hash: &RSAHash,
    pkfile: &Option<String>,
    sigfile: &Option<String>,
) {
    use bouncycastle::rsa::rsa_1024::{pkcs1_v1_5_verify_sha256, pkcs1_v1_5_verify_sha384};
    match (scheme, hash) {
        (RSAScheme::Pkcs1v15, RSAHash::Sha256) => do_verify::<16, 128, 132, 128>(
            pkcs1_v1_5_verify_sha256,
            pkfile,
            sigfile,
            "RSA-1024/PKCS#1v1.5/SHA-256",
        ),
        (RSAScheme::Pkcs1v15, RSAHash::Sha384) => do_verify::<16, 128, 132, 128>(
            pkcs1_v1_5_verify_sha384,
            pkfile,
            sigfile,
            "RSA-1024/PKCS#1v1.5/SHA-384",
        ),
        (scheme, hash) => unsupported(scheme, hash, "RSA-1024"),
    }
}

/// RSA-1536: verification only (see module docs). `L = 24`, `N_BYTES = 192`, `PK_LEN = 196`,
/// `SIG_LEN = 192`. No PSS group exists in Wycheproof at this size.
pub(crate) fn rsa_1536_cmd(
    scheme: &RSAScheme,
    hash: &RSAHash,
    pkfile: &Option<String>,
    sigfile: &Option<String>,
) {
    use bouncycastle::rsa::rsa_1536::{
        pkcs1_v1_5_verify_sha256, pkcs1_v1_5_verify_sha384, pkcs1_v1_5_verify_sha512,
    };
    match (scheme, hash) {
        (RSAScheme::Pkcs1v15, RSAHash::Sha256) => do_verify::<24, 192, 196, 192>(
            pkcs1_v1_5_verify_sha256,
            pkfile,
            sigfile,
            "RSA-1536/PKCS#1v1.5/SHA-256",
        ),
        (RSAScheme::Pkcs1v15, RSAHash::Sha384) => do_verify::<24, 192, 196, 192>(
            pkcs1_v1_5_verify_sha384,
            pkfile,
            sigfile,
            "RSA-1536/PKCS#1v1.5/SHA-384",
        ),
        (RSAScheme::Pkcs1v15, RSAHash::Sha512) => do_verify::<24, 192, 196, 192>(
            pkcs1_v1_5_verify_sha512,
            pkfile,
            sigfile,
            "RSA-1536/PKCS#1v1.5/SHA-512",
        ),
        (scheme, hash) => unsupported(scheme, hash, "RSA-1536"),
    }
}

/// RSA-2048: sign and verify. `HALF = 16`, `L = 32`, `HALF_BYTES = 128`, `SK_LEN = 640`, `N_BYTES
/// = 256`, `PK_LEN = 260`, `SIG_LEN = 256`. `--hash shake128` is the only SHAKE choice wired up at
/// this size (RFC 8702 §5 pairs SHAKE128 with 2048/3072-bit RSA, SHAKE256 with 4096-bit or
/// larger).
#[allow(clippy::too_many_arguments)]
pub(crate) fn rsa_2048_cmd(
    action: &RSAAction,
    scheme: &RSAScheme,
    hash: &RSAHash,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    sigfile: &Option<String>,
    output_hex: bool,
) {
    use bouncycastle::rsa::rsa_2048::{
        pkcs1_v1_5_sign_sha256, pkcs1_v1_5_sign_sha384, pkcs1_v1_5_sign_sha512,
        pkcs1_v1_5_verify_sha256, pkcs1_v1_5_verify_sha384, pkcs1_v1_5_verify_sha512,
        pss_shake128_sign, pss_shake128_verify, pss_sign_sha256, pss_sign_sha384, pss_sign_sha512,
        pss_verify_sha256, pss_verify_sha384, pss_verify_sha512,
    };
    match (scheme, hash) {
        (RSAScheme::Pkcs1v15, RSAHash::Sha256) => rsa_pkcs1_cmd::<16, 32, 128, 640, 256, 260, 256>(
            action,
            pkcs1_v1_5_sign_sha256,
            pkcs1_v1_5_verify_sha256,
            skfile,
            pkfile,
            sigfile,
            output_hex,
            "RSA-2048/PKCS#1v1.5/SHA-256",
        ),
        (RSAScheme::Pkcs1v15, RSAHash::Sha384) => rsa_pkcs1_cmd::<16, 32, 128, 640, 256, 260, 256>(
            action,
            pkcs1_v1_5_sign_sha384,
            pkcs1_v1_5_verify_sha384,
            skfile,
            pkfile,
            sigfile,
            output_hex,
            "RSA-2048/PKCS#1v1.5/SHA-384",
        ),
        (RSAScheme::Pkcs1v15, RSAHash::Sha512) => rsa_pkcs1_cmd::<16, 32, 128, 640, 256, 260, 256>(
            action,
            pkcs1_v1_5_sign_sha512,
            pkcs1_v1_5_verify_sha512,
            skfile,
            pkfile,
            sigfile,
            output_hex,
            "RSA-2048/PKCS#1v1.5/SHA-512",
        ),
        (RSAScheme::Pss, RSAHash::Sha256) => rsa_pss_cmd::<16, 32, 128, 640, 256, 260, 256>(
            action, pss_sign_sha256, pss_verify_sha256, skfile, pkfile, sigfile, output_hex,
            "RSA-2048/PSS/SHA-256",
        ),
        (RSAScheme::Pss, RSAHash::Sha384) => rsa_pss_cmd::<16, 32, 128, 640, 256, 260, 256>(
            action, pss_sign_sha384, pss_verify_sha384, skfile, pkfile, sigfile, output_hex,
            "RSA-2048/PSS/SHA-384",
        ),
        (RSAScheme::Pss, RSAHash::Sha512) => rsa_pss_cmd::<16, 32, 128, 640, 256, 260, 256>(
            action, pss_sign_sha512, pss_verify_sha512, skfile, pkfile, sigfile, output_hex,
            "RSA-2048/PSS/SHA-512",
        ),
        (RSAScheme::Pss, RSAHash::Shake128) => rsa_pss_cmd::<16, 32, 128, 640, 256, 260, 256>(
            action, pss_shake128_sign, pss_shake128_verify, skfile, pkfile, sigfile, output_hex,
            "RSA-2048/PSS-SHAKE128",
        ),
        (scheme, hash) => unsupported(scheme, hash, "RSA-2048"),
    }
}

/// RSA-3072: sign and verify. `HALF = 24`, `L = 48`, `HALF_BYTES = 192`, `SK_LEN = 960`, `N_BYTES
/// = 384`, `PK_LEN = 388`, `SIG_LEN = 384`. See [`rsa_2048_cmd`] for the SHAKE128 pairing
/// rationale.
#[allow(clippy::too_many_arguments)]
pub(crate) fn rsa_3072_cmd(
    action: &RSAAction,
    scheme: &RSAScheme,
    hash: &RSAHash,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    sigfile: &Option<String>,
    output_hex: bool,
) {
    use bouncycastle::rsa::rsa_3072::{
        pkcs1_v1_5_sign_sha256, pkcs1_v1_5_sign_sha384, pkcs1_v1_5_sign_sha512,
        pkcs1_v1_5_verify_sha256, pkcs1_v1_5_verify_sha384, pkcs1_v1_5_verify_sha512,
        pss_shake128_sign, pss_shake128_verify, pss_sign_sha256, pss_sign_sha384, pss_sign_sha512,
        pss_verify_sha256, pss_verify_sha384, pss_verify_sha512,
    };
    match (scheme, hash) {
        (RSAScheme::Pkcs1v15, RSAHash::Sha256) => rsa_pkcs1_cmd::<24, 48, 192, 960, 384, 388, 384>(
            action,
            pkcs1_v1_5_sign_sha256,
            pkcs1_v1_5_verify_sha256,
            skfile,
            pkfile,
            sigfile,
            output_hex,
            "RSA-3072/PKCS#1v1.5/SHA-256",
        ),
        (RSAScheme::Pkcs1v15, RSAHash::Sha384) => rsa_pkcs1_cmd::<24, 48, 192, 960, 384, 388, 384>(
            action,
            pkcs1_v1_5_sign_sha384,
            pkcs1_v1_5_verify_sha384,
            skfile,
            pkfile,
            sigfile,
            output_hex,
            "RSA-3072/PKCS#1v1.5/SHA-384",
        ),
        (RSAScheme::Pkcs1v15, RSAHash::Sha512) => rsa_pkcs1_cmd::<24, 48, 192, 960, 384, 388, 384>(
            action,
            pkcs1_v1_5_sign_sha512,
            pkcs1_v1_5_verify_sha512,
            skfile,
            pkfile,
            sigfile,
            output_hex,
            "RSA-3072/PKCS#1v1.5/SHA-512",
        ),
        (RSAScheme::Pss, RSAHash::Sha256) => rsa_pss_cmd::<24, 48, 192, 960, 384, 388, 384>(
            action, pss_sign_sha256, pss_verify_sha256, skfile, pkfile, sigfile, output_hex,
            "RSA-3072/PSS/SHA-256",
        ),
        (RSAScheme::Pss, RSAHash::Sha384) => rsa_pss_cmd::<24, 48, 192, 960, 384, 388, 384>(
            action, pss_sign_sha384, pss_verify_sha384, skfile, pkfile, sigfile, output_hex,
            "RSA-3072/PSS/SHA-384",
        ),
        (RSAScheme::Pss, RSAHash::Sha512) => rsa_pss_cmd::<24, 48, 192, 960, 384, 388, 384>(
            action, pss_sign_sha512, pss_verify_sha512, skfile, pkfile, sigfile, output_hex,
            "RSA-3072/PSS/SHA-512",
        ),
        (RSAScheme::Pss, RSAHash::Shake128) => rsa_pss_cmd::<24, 48, 192, 960, 384, 388, 384>(
            action, pss_shake128_sign, pss_shake128_verify, skfile, pkfile, sigfile, output_hex,
            "RSA-3072/PSS-SHAKE128",
        ),
        (scheme, hash) => unsupported(scheme, hash, "RSA-3072"),
    }
}

/// RSA-4096: sign and verify. `HALF = 32`, `L = 64`, `HALF_BYTES = 256`, `SK_LEN = 1280`, `N_BYTES
/// = 512`, `PK_LEN = 516`, `SIG_LEN = 512`. `--hash shake256` (not shake128) is wired up at this
/// size -- see [`rsa_2048_cmd`] for the pairing rationale.
#[allow(clippy::too_many_arguments)]
pub(crate) fn rsa_4096_cmd(
    action: &RSAAction,
    scheme: &RSAScheme,
    hash: &RSAHash,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    sigfile: &Option<String>,
    output_hex: bool,
) {
    use bouncycastle::rsa::rsa_4096::{
        pkcs1_v1_5_sign_sha256, pkcs1_v1_5_sign_sha384, pkcs1_v1_5_sign_sha512,
        pkcs1_v1_5_verify_sha256, pkcs1_v1_5_verify_sha384, pkcs1_v1_5_verify_sha512,
        pss_shake256_sign, pss_shake256_verify, pss_sign_sha256, pss_sign_sha384, pss_sign_sha512,
        pss_verify_sha256, pss_verify_sha384, pss_verify_sha512,
    };
    match (scheme, hash) {
        (RSAScheme::Pkcs1v15, RSAHash::Sha256) => {
            rsa_pkcs1_cmd::<32, 64, 256, 1280, 512, 516, 512>(
                action,
                pkcs1_v1_5_sign_sha256,
                pkcs1_v1_5_verify_sha256,
                skfile,
                pkfile,
                sigfile,
                output_hex,
                "RSA-4096/PKCS#1v1.5/SHA-256",
            )
        }
        (RSAScheme::Pkcs1v15, RSAHash::Sha384) => {
            rsa_pkcs1_cmd::<32, 64, 256, 1280, 512, 516, 512>(
                action,
                pkcs1_v1_5_sign_sha384,
                pkcs1_v1_5_verify_sha384,
                skfile,
                pkfile,
                sigfile,
                output_hex,
                "RSA-4096/PKCS#1v1.5/SHA-384",
            )
        }
        (RSAScheme::Pkcs1v15, RSAHash::Sha512) => {
            rsa_pkcs1_cmd::<32, 64, 256, 1280, 512, 516, 512>(
                action,
                pkcs1_v1_5_sign_sha512,
                pkcs1_v1_5_verify_sha512,
                skfile,
                pkfile,
                sigfile,
                output_hex,
                "RSA-4096/PKCS#1v1.5/SHA-512",
            )
        }
        (RSAScheme::Pss, RSAHash::Sha256) => rsa_pss_cmd::<32, 64, 256, 1280, 512, 516, 512>(
            action, pss_sign_sha256, pss_verify_sha256, skfile, pkfile, sigfile, output_hex,
            "RSA-4096/PSS/SHA-256",
        ),
        (RSAScheme::Pss, RSAHash::Sha384) => rsa_pss_cmd::<32, 64, 256, 1280, 512, 516, 512>(
            action, pss_sign_sha384, pss_verify_sha384, skfile, pkfile, sigfile, output_hex,
            "RSA-4096/PSS/SHA-384",
        ),
        (RSAScheme::Pss, RSAHash::Sha512) => rsa_pss_cmd::<32, 64, 256, 1280, 512, 516, 512>(
            action, pss_sign_sha512, pss_verify_sha512, skfile, pkfile, sigfile, output_hex,
            "RSA-4096/PSS/SHA-512",
        ),
        (RSAScheme::Pss, RSAHash::Shake256) => rsa_pss_cmd::<32, 64, 256, 1280, 512, 516, 512>(
            action, pss_shake256_sign, pss_shake256_verify, skfile, pkfile, sigfile, output_hex,
            "RSA-4096/PSS-SHAKE256",
        ),
        (scheme, hash) => unsupported(scheme, hash, "RSA-4096"),
    }
}

/// RSA-8192: sign and verify. `HALF = 64`, `L = 128`, `HALF_BYTES = 512`, `SK_LEN = 2560`,
/// `N_BYTES = 1024`, `PK_LEN = 1028`, `SIG_LEN = 1024`. No PSS-SHAKE variant is wired up at this
/// size: no Wycheproof vectors exist for it, and RFC 8702 §5 does not name a pairing beyond
/// "4096-bit or larger" for SHAKE256 -- 4096 already covers that recommendation.
#[allow(clippy::too_many_arguments)]
pub(crate) fn rsa_8192_cmd(
    action: &RSAAction,
    scheme: &RSAScheme,
    hash: &RSAHash,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    sigfile: &Option<String>,
    output_hex: bool,
) {
    use bouncycastle::rsa::rsa_8192::{
        pkcs1_v1_5_sign_sha256, pkcs1_v1_5_sign_sha384, pkcs1_v1_5_sign_sha512,
        pkcs1_v1_5_verify_sha256, pkcs1_v1_5_verify_sha384, pkcs1_v1_5_verify_sha512,
        pss_sign_sha256, pss_sign_sha384, pss_sign_sha512, pss_verify_sha256, pss_verify_sha384,
        pss_verify_sha512,
    };
    match (scheme, hash) {
        (RSAScheme::Pkcs1v15, RSAHash::Sha256) => {
            rsa_pkcs1_cmd::<64, 128, 512, 2560, 1024, 1028, 1024>(
                action,
                pkcs1_v1_5_sign_sha256,
                pkcs1_v1_5_verify_sha256,
                skfile,
                pkfile,
                sigfile,
                output_hex,
                "RSA-8192/PKCS#1v1.5/SHA-256",
            )
        }
        (RSAScheme::Pkcs1v15, RSAHash::Sha384) => {
            rsa_pkcs1_cmd::<64, 128, 512, 2560, 1024, 1028, 1024>(
                action,
                pkcs1_v1_5_sign_sha384,
                pkcs1_v1_5_verify_sha384,
                skfile,
                pkfile,
                sigfile,
                output_hex,
                "RSA-8192/PKCS#1v1.5/SHA-384",
            )
        }
        (RSAScheme::Pkcs1v15, RSAHash::Sha512) => {
            rsa_pkcs1_cmd::<64, 128, 512, 2560, 1024, 1028, 1024>(
                action,
                pkcs1_v1_5_sign_sha512,
                pkcs1_v1_5_verify_sha512,
                skfile,
                pkfile,
                sigfile,
                output_hex,
                "RSA-8192/PKCS#1v1.5/SHA-512",
            )
        }
        (RSAScheme::Pss, RSAHash::Sha256) => rsa_pss_cmd::<64, 128, 512, 2560, 1024, 1028, 1024>(
            action, pss_sign_sha256, pss_verify_sha256, skfile, pkfile, sigfile, output_hex,
            "RSA-8192/PSS/SHA-256",
        ),
        (RSAScheme::Pss, RSAHash::Sha384) => rsa_pss_cmd::<64, 128, 512, 2560, 1024, 1028, 1024>(
            action, pss_sign_sha384, pss_verify_sha384, skfile, pkfile, sigfile, output_hex,
            "RSA-8192/PSS/SHA-384",
        ),
        (RSAScheme::Pss, RSAHash::Sha512) => rsa_pss_cmd::<64, 128, 512, 2560, 1024, 1028, 1024>(
            action, pss_sign_sha512, pss_verify_sha512, skfile, pkfile, sigfile, output_hex,
            "RSA-8192/PSS/SHA-512",
        ),
        (scheme, hash) => unsupported(scheme, hash, "RSA-8192"),
    }
}
