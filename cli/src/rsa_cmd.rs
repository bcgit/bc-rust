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
//! Every (size, scheme, hash) pairing is one of `bouncycastle_rsa`'s `Signer`/`SignatureVerifier`
//! types (`rsa_2048::RSASSA_PKCS1_v1_5_SHA256` and siblings), so, as `ecdsa_cmd.rs` does for its
//! curves, a single generic [`rsa_sign_verify_cmd`] bound over those traits is monomorphised once
//! per pairing below, and the message streams from stdin through the traits' `_update` methods in
//! this CLI's usual ~1 KB chunks rather than being read whole. `ctx` (accepted by the traits for
//! conformance) is not exposed as a flag: RSA has no context-string input, and `bouncycastle_rsa`
//! documents the parameter as ignored, so every call below passes `None`.
//!
//! `keygen` (FIPS 186-5 Appendix A.1.3, `bouncycastle_rsa::rsa_*::keygen`) writes the private key
//! to stdout like the other key-generating commands, and -- unlike them -- also needs `--pkfile`
//! to receive the public key: an RSA private key file (RFC 8017's CRT quintuple) does not carry
//! the public exponent `e`, so there is no `PkFromSk`/`CheckConsistency` here, the public key has
//! to be kept from generation time. Private and public key files use the raw fixed-width layout
//! `RsaPrivateKey`/`RsaPublicKey`'s `SignaturePrivateKey`/`SignaturePublicKey` impls encode
//! (documented under `# Encoding` on those types): not PEM, not ASN.1 DER -- this crate has no
//! encoder for either -- so a key produced by another RSA implementation cannot be fed to this
//! CLI directly.
//!
//! 1024- and 1536-bit RSA are verification-only in `bouncycastle_rsa` (see its crate docs' `#
//! Scope`), so `rsa_1024_cmd`/`rsa_1536_cmd` take no `action`/`skfile` at all: they only verify,
//! through [`do_verify`], which needs only a `SignatureVerifier` -- exactly the trait those sizes'
//! types implement.

use crate::helpers::{read_from_file, write_bytes_or_hex, write_bytes_or_hex_to_file};
use bouncycastle::core::errors::SignatureError;
use bouncycastle::core::traits::{
    SignaturePrivateKey, SignaturePublicKey, SignatureVerifier, Signer,
};
use bouncycastle::rsa::{rsa_1024, rsa_1536, rsa_2048, rsa_3072, rsa_4096, rsa_8192};
use clap::ValueEnum;
use std::io;
use std::io::Read;
use std::process::exit;

#[derive(ValueEnum, Clone, Debug, PartialEq, Eq)]
pub(crate) enum RSAAction {
    /// Generate a key pair: the private key to stdout, the public key to `--pkfile`.
    Keygen,
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
/// bytes that happen to look like hex must still be signed/verified byte-for-byte. Streams stdin
/// through `update` in ~1 KB chunks (the same loop as `ecdsa_cmd.rs`).
fn stream_stdin_into(mut update: impl FnMut(&[u8])) {
    let mut buf = [0u8; 1024];
    let mut bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    while bytes_read > 0 {
        update(&buf[..bytes_read]);
        bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    }
}

fn unsupported(scheme: &RSAScheme, hash: &RSAHash, alg_name: &str) -> ! {
    eprintln!("Error: {scheme:?}/{hash:?} is not supported for {alg_name}.");
    exit(-1);
}

/// See `RsaPrivateKey`'s `# Encoding` docs for the expected layout; a wrong-length file is one of
/// the `DecodingError`s `SignaturePrivateKey::from_bytes` reports.
fn parse_sk<SK: SignaturePrivateKey<SK_LEN>, const SK_LEN: usize>(
    bytes: &[u8],
    alg_name: &str,
) -> SK {
    match SK::from_bytes(bytes) {
        Ok(sk) => sk,
        Err(_) => {
            eprintln!(
                "Error: couldn't parse the input as a valid {alg_name} private key (must be \
                 exactly {SK_LEN} bytes)."
            );
            exit(-1);
        }
    }
}

/// See `RsaPublicKey`'s `# Encoding` docs for the expected layout; a wrong-length file is one of
/// the `DecodingError`s `SignaturePublicKey::from_bytes` reports.
fn parse_pk<PK: SignaturePublicKey<PK_LEN>, const PK_LEN: usize>(
    bytes: &[u8],
    alg_name: &str,
) -> PK {
    match PK::from_bytes(bytes) {
        Ok(pk) => pk,
        Err(_) => {
            eprintln!(
                "Error: couldn't parse the input as a valid {alg_name} public key (must be exactly \
                 {PK_LEN} bytes)."
            );
            exit(-1);
        }
    }
}

/// Verifies stdin against `--pkfile`/`--sigfile` through `V`'s streaming `SignatureVerifier`
/// impl. Shared by [`rsa_sign_verify_cmd`]'s `Verify` arm, and called directly by the verify-only
/// sizes (`rsa_1024_cmd`, `rsa_1536_cmd`). A signature file of the wrong length is simply
/// invalid (RFC 8017 §8.1.2/§8.2.2 step 1), as `verify_final` reports it.
fn do_verify<
    PK: SignaturePublicKey<PK_LEN>,
    V: SignatureVerifier<PK, PK_LEN, SIG_LEN>,
    const PK_LEN: usize,
    const SIG_LEN: usize,
>(
    pkfile: &Option<String>,
    sigfile: &Option<String>,
    alg_name: &str,
) {
    let pk = parse_pk::<PK, PK_LEN>(&require_file(pkfile, "pkfile"), alg_name);
    let sig = require_file(sigfile, "sigfile");

    // `verify_init` is infallible for every `bouncycastle_rsa` verifier (it only stores the key
    // and a fresh hash state), so this unwrap cannot fire.
    let mut verifier = V::verify_init(&pk, None).unwrap();
    stream_stdin_into(|chunk| verifier.verify_update(chunk));

    if verifier.verify_final(&sig).is_ok() {
        println!("Signature is valid.");
    } else {
        eprintln!("Signature is invalid.");
        exit(-1);
    }
}

/// One (size, scheme, hash) pairing `S`, generating a key pair, or signing or verifying stdin,
/// per `action`. PSS pairings draw their salt from the library's default OS-backed RNG inside
/// `S::sign_final`; `keygen` is the size's FIPS 186-5 generator, independent of scheme and hash.
fn rsa_sign_verify_cmd<
    PK: SignaturePublicKey<PK_LEN>,
    SK: SignaturePrivateKey<SK_LEN>,
    S: Signer<SK, SK_LEN, SIG_LEN> + SignatureVerifier<PK, PK_LEN, SIG_LEN>,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const SIG_LEN: usize,
>(
    action: &RSAAction,
    keygen: fn() -> Result<(PK, SK), SignatureError>,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    sigfile: &Option<String>,
    output_hex: bool,
    alg_name: &str,
) {
    match action {
        RSAAction::Keygen => {
            let Some(pkfile) = pkfile else {
                eprintln!(
                    "Error: {alg_name} keygen needs --pkfile to receive the public key (an RSA \
                     private key file does not carry e, so it cannot be derived later)."
                );
                exit(-1);
            };
            let (pk, sk) = keygen().unwrap_or_else(|e| {
                eprintln!("Error: {alg_name} key generation failed: {e:?}");
                exit(-1);
            });
            write_bytes_or_hex_to_file(&pk.encode(), pkfile, output_hex);
            write_bytes_or_hex(&sk.encode(), output_hex);
        }
        RSAAction::Sign => {
            let sk = parse_sk::<SK, SK_LEN>(&require_file(skfile, "skfile"), alg_name);

            // `sign_init` is infallible for every `bouncycastle_rsa` signer (see `do_verify`).
            let mut signer = S::sign_init(&sk, None).unwrap();
            stream_stdin_into(|chunk| signer.sign_update(chunk));
            let sig = signer.sign_final().unwrap_or_else(|_| {
                eprintln!("Error: signing failed.");
                exit(-1);
            });

            write_bytes_or_hex(&sig, output_hex);
        }
        RSAAction::Verify => do_verify::<PK, S, PK_LEN, SIG_LEN>(pkfile, sigfile, alg_name),
    }
}

/// RSA-1024: verification only (see module docs). No SHA-512 or PSS group exists in Wycheproof at
/// this size (see `bouncycastle_rsa::rsa_1024`'s own docs), so neither is wired up here either.
pub(crate) fn rsa_1024_cmd(
    scheme: &RSAScheme,
    hash: &RSAHash,
    pkfile: &Option<String>,
    sigfile: &Option<String>,
) {
    use rsa_1024::{
        PK_LEN, RSA1024PublicKey, RSASSA_PKCS1_v1_5_SHA256, RSASSA_PKCS1_v1_5_SHA384, SIG_LEN,
    };
    match (scheme, hash) {
        (RSAScheme::Pkcs1v15, RSAHash::Sha256) => {
            do_verify::<RSA1024PublicKey, RSASSA_PKCS1_v1_5_SHA256, PK_LEN, SIG_LEN>(
                pkfile,
                sigfile,
                "RSA-1024/PKCS#1v1.5/SHA-256",
            )
        }
        (RSAScheme::Pkcs1v15, RSAHash::Sha384) => {
            do_verify::<RSA1024PublicKey, RSASSA_PKCS1_v1_5_SHA384, PK_LEN, SIG_LEN>(
                pkfile,
                sigfile,
                "RSA-1024/PKCS#1v1.5/SHA-384",
            )
        }
        (scheme, hash) => unsupported(scheme, hash, "RSA-1024"),
    }
}

/// RSA-1536: verification only (see module docs). No PSS group exists in Wycheproof at this size.
pub(crate) fn rsa_1536_cmd(
    scheme: &RSAScheme,
    hash: &RSAHash,
    pkfile: &Option<String>,
    sigfile: &Option<String>,
) {
    use rsa_1536::{
        PK_LEN, RSA1536PublicKey, RSASSA_PKCS1_v1_5_SHA256, RSASSA_PKCS1_v1_5_SHA384,
        RSASSA_PKCS1_v1_5_SHA512, SIG_LEN,
    };
    match (scheme, hash) {
        (RSAScheme::Pkcs1v15, RSAHash::Sha256) => {
            do_verify::<RSA1536PublicKey, RSASSA_PKCS1_v1_5_SHA256, PK_LEN, SIG_LEN>(
                pkfile,
                sigfile,
                "RSA-1536/PKCS#1v1.5/SHA-256",
            )
        }
        (RSAScheme::Pkcs1v15, RSAHash::Sha384) => {
            do_verify::<RSA1536PublicKey, RSASSA_PKCS1_v1_5_SHA384, PK_LEN, SIG_LEN>(
                pkfile,
                sigfile,
                "RSA-1536/PKCS#1v1.5/SHA-384",
            )
        }
        (RSAScheme::Pkcs1v15, RSAHash::Sha512) => {
            do_verify::<RSA1536PublicKey, RSASSA_PKCS1_v1_5_SHA512, PK_LEN, SIG_LEN>(
                pkfile,
                sigfile,
                "RSA-1536/PKCS#1v1.5/SHA-512",
            )
        }
        (scheme, hash) => unsupported(scheme, hash, "RSA-1536"),
    }
}

/// RSA-2048: sign and verify. `--hash shake128` is the only SHAKE choice wired up at this size
/// (RFC 8702 §5 pairs SHAKE128 with 2048/3072-bit RSA, SHAKE256 with 4096-bit or larger).
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
    use rsa_2048::{
        PK_LEN, RSA2048PrivateKey as SK, RSA2048PublicKey as PK, RSASSA_PKCS1_v1_5_SHA256,
        RSASSA_PKCS1_v1_5_SHA384, RSASSA_PKCS1_v1_5_SHA512, RSASSA_PSS_SHA256, RSASSA_PSS_SHA384,
        RSASSA_PSS_SHA512, RSASSA_PSS_SHAKE128, SIG_LEN, SK_LEN,
    };
    let args = (skfile, pkfile, sigfile, output_hex);
    let run = |name: &str,
               f: fn(
        &RSAAction,
        fn() -> Result<(PK, SK), SignatureError>,
        &Option<String>,
        &Option<String>,
        &Option<String>,
        bool,
        &str,
    )| { f(action, rsa_2048::keygen, args.0, args.1, args.2, args.3, name) };
    match (scheme, hash) {
        (RSAScheme::Pkcs1v15, RSAHash::Sha256) => run(
            "RSA-2048/PKCS#1v1.5/SHA-256",
            rsa_sign_verify_cmd::<PK, SK, RSASSA_PKCS1_v1_5_SHA256, PK_LEN, SK_LEN, SIG_LEN>,
        ),
        (RSAScheme::Pkcs1v15, RSAHash::Sha384) => run(
            "RSA-2048/PKCS#1v1.5/SHA-384",
            rsa_sign_verify_cmd::<PK, SK, RSASSA_PKCS1_v1_5_SHA384, PK_LEN, SK_LEN, SIG_LEN>,
        ),
        (RSAScheme::Pkcs1v15, RSAHash::Sha512) => run(
            "RSA-2048/PKCS#1v1.5/SHA-512",
            rsa_sign_verify_cmd::<PK, SK, RSASSA_PKCS1_v1_5_SHA512, PK_LEN, SK_LEN, SIG_LEN>,
        ),
        (RSAScheme::Pss, RSAHash::Sha256) => run(
            "RSA-2048/PSS/SHA-256",
            rsa_sign_verify_cmd::<PK, SK, RSASSA_PSS_SHA256, PK_LEN, SK_LEN, SIG_LEN>,
        ),
        (RSAScheme::Pss, RSAHash::Sha384) => run(
            "RSA-2048/PSS/SHA-384",
            rsa_sign_verify_cmd::<PK, SK, RSASSA_PSS_SHA384, PK_LEN, SK_LEN, SIG_LEN>,
        ),
        (RSAScheme::Pss, RSAHash::Sha512) => run(
            "RSA-2048/PSS/SHA-512",
            rsa_sign_verify_cmd::<PK, SK, RSASSA_PSS_SHA512, PK_LEN, SK_LEN, SIG_LEN>,
        ),
        (RSAScheme::Pss, RSAHash::Shake128) => run(
            "RSA-2048/PSS-SHAKE128",
            rsa_sign_verify_cmd::<PK, SK, RSASSA_PSS_SHAKE128, PK_LEN, SK_LEN, SIG_LEN>,
        ),
        (scheme, hash) => unsupported(scheme, hash, "RSA-2048"),
    }
}

/// RSA-3072: sign and verify. See [`rsa_2048_cmd`] for the SHAKE128 pairing rationale.
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
    use rsa_3072::{
        PK_LEN, RSA3072PrivateKey as SK, RSA3072PublicKey as PK, RSASSA_PKCS1_v1_5_SHA256,
        RSASSA_PKCS1_v1_5_SHA384, RSASSA_PKCS1_v1_5_SHA512, RSASSA_PSS_SHA256, RSASSA_PSS_SHA384,
        RSASSA_PSS_SHA512, RSASSA_PSS_SHAKE128, SIG_LEN, SK_LEN,
    };
    let args = (skfile, pkfile, sigfile, output_hex);
    let run = |name: &str,
               f: fn(
        &RSAAction,
        fn() -> Result<(PK, SK), SignatureError>,
        &Option<String>,
        &Option<String>,
        &Option<String>,
        bool,
        &str,
    )| { f(action, rsa_3072::keygen, args.0, args.1, args.2, args.3, name) };
    match (scheme, hash) {
        (RSAScheme::Pkcs1v15, RSAHash::Sha256) => run(
            "RSA-3072/PKCS#1v1.5/SHA-256",
            rsa_sign_verify_cmd::<PK, SK, RSASSA_PKCS1_v1_5_SHA256, PK_LEN, SK_LEN, SIG_LEN>,
        ),
        (RSAScheme::Pkcs1v15, RSAHash::Sha384) => run(
            "RSA-3072/PKCS#1v1.5/SHA-384",
            rsa_sign_verify_cmd::<PK, SK, RSASSA_PKCS1_v1_5_SHA384, PK_LEN, SK_LEN, SIG_LEN>,
        ),
        (RSAScheme::Pkcs1v15, RSAHash::Sha512) => run(
            "RSA-3072/PKCS#1v1.5/SHA-512",
            rsa_sign_verify_cmd::<PK, SK, RSASSA_PKCS1_v1_5_SHA512, PK_LEN, SK_LEN, SIG_LEN>,
        ),
        (RSAScheme::Pss, RSAHash::Sha256) => run(
            "RSA-3072/PSS/SHA-256",
            rsa_sign_verify_cmd::<PK, SK, RSASSA_PSS_SHA256, PK_LEN, SK_LEN, SIG_LEN>,
        ),
        (RSAScheme::Pss, RSAHash::Sha384) => run(
            "RSA-3072/PSS/SHA-384",
            rsa_sign_verify_cmd::<PK, SK, RSASSA_PSS_SHA384, PK_LEN, SK_LEN, SIG_LEN>,
        ),
        (RSAScheme::Pss, RSAHash::Sha512) => run(
            "RSA-3072/PSS/SHA-512",
            rsa_sign_verify_cmd::<PK, SK, RSASSA_PSS_SHA512, PK_LEN, SK_LEN, SIG_LEN>,
        ),
        (RSAScheme::Pss, RSAHash::Shake128) => run(
            "RSA-3072/PSS-SHAKE128",
            rsa_sign_verify_cmd::<PK, SK, RSASSA_PSS_SHAKE128, PK_LEN, SK_LEN, SIG_LEN>,
        ),
        (scheme, hash) => unsupported(scheme, hash, "RSA-3072"),
    }
}

/// RSA-4096: sign and verify. `--hash shake256` (not shake128) is wired up at this size -- see
/// [`rsa_2048_cmd`] for the pairing rationale.
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
    use rsa_4096::{
        PK_LEN, RSA4096PrivateKey as SK, RSA4096PublicKey as PK, RSASSA_PKCS1_v1_5_SHA256,
        RSASSA_PKCS1_v1_5_SHA384, RSASSA_PKCS1_v1_5_SHA512, RSASSA_PSS_SHA256, RSASSA_PSS_SHA384,
        RSASSA_PSS_SHA512, RSASSA_PSS_SHAKE256, SIG_LEN, SK_LEN,
    };
    let args = (skfile, pkfile, sigfile, output_hex);
    let run = |name: &str,
               f: fn(
        &RSAAction,
        fn() -> Result<(PK, SK), SignatureError>,
        &Option<String>,
        &Option<String>,
        &Option<String>,
        bool,
        &str,
    )| { f(action, rsa_4096::keygen, args.0, args.1, args.2, args.3, name) };
    match (scheme, hash) {
        (RSAScheme::Pkcs1v15, RSAHash::Sha256) => run(
            "RSA-4096/PKCS#1v1.5/SHA-256",
            rsa_sign_verify_cmd::<PK, SK, RSASSA_PKCS1_v1_5_SHA256, PK_LEN, SK_LEN, SIG_LEN>,
        ),
        (RSAScheme::Pkcs1v15, RSAHash::Sha384) => run(
            "RSA-4096/PKCS#1v1.5/SHA-384",
            rsa_sign_verify_cmd::<PK, SK, RSASSA_PKCS1_v1_5_SHA384, PK_LEN, SK_LEN, SIG_LEN>,
        ),
        (RSAScheme::Pkcs1v15, RSAHash::Sha512) => run(
            "RSA-4096/PKCS#1v1.5/SHA-512",
            rsa_sign_verify_cmd::<PK, SK, RSASSA_PKCS1_v1_5_SHA512, PK_LEN, SK_LEN, SIG_LEN>,
        ),
        (RSAScheme::Pss, RSAHash::Sha256) => run(
            "RSA-4096/PSS/SHA-256",
            rsa_sign_verify_cmd::<PK, SK, RSASSA_PSS_SHA256, PK_LEN, SK_LEN, SIG_LEN>,
        ),
        (RSAScheme::Pss, RSAHash::Sha384) => run(
            "RSA-4096/PSS/SHA-384",
            rsa_sign_verify_cmd::<PK, SK, RSASSA_PSS_SHA384, PK_LEN, SK_LEN, SIG_LEN>,
        ),
        (RSAScheme::Pss, RSAHash::Sha512) => run(
            "RSA-4096/PSS/SHA-512",
            rsa_sign_verify_cmd::<PK, SK, RSASSA_PSS_SHA512, PK_LEN, SK_LEN, SIG_LEN>,
        ),
        (RSAScheme::Pss, RSAHash::Shake256) => run(
            "RSA-4096/PSS-SHAKE256",
            rsa_sign_verify_cmd::<PK, SK, RSASSA_PSS_SHAKE256, PK_LEN, SK_LEN, SIG_LEN>,
        ),
        (scheme, hash) => unsupported(scheme, hash, "RSA-4096"),
    }
}

/// RSA-8192: sign and verify. No PSS-SHAKE variant is wired up at this size: no Wycheproof
/// vectors exist for it, and RFC 8702 §5 does not name a pairing beyond "4096-bit or larger" for
/// SHAKE256 -- 4096 already covers that recommendation.
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
    use rsa_8192::{
        PK_LEN, RSA8192PrivateKey as SK, RSA8192PublicKey as PK, RSASSA_PKCS1_v1_5_SHA256,
        RSASSA_PKCS1_v1_5_SHA384, RSASSA_PKCS1_v1_5_SHA512, RSASSA_PSS_SHA256, RSASSA_PSS_SHA384,
        RSASSA_PSS_SHA512, SIG_LEN, SK_LEN,
    };
    let args = (skfile, pkfile, sigfile, output_hex);
    let run = |name: &str,
               f: fn(
        &RSAAction,
        fn() -> Result<(PK, SK), SignatureError>,
        &Option<String>,
        &Option<String>,
        &Option<String>,
        bool,
        &str,
    )| { f(action, rsa_8192::keygen, args.0, args.1, args.2, args.3, name) };
    match (scheme, hash) {
        (RSAScheme::Pkcs1v15, RSAHash::Sha256) => run(
            "RSA-8192/PKCS#1v1.5/SHA-256",
            rsa_sign_verify_cmd::<PK, SK, RSASSA_PKCS1_v1_5_SHA256, PK_LEN, SK_LEN, SIG_LEN>,
        ),
        (RSAScheme::Pkcs1v15, RSAHash::Sha384) => run(
            "RSA-8192/PKCS#1v1.5/SHA-384",
            rsa_sign_verify_cmd::<PK, SK, RSASSA_PKCS1_v1_5_SHA384, PK_LEN, SK_LEN, SIG_LEN>,
        ),
        (RSAScheme::Pkcs1v15, RSAHash::Sha512) => run(
            "RSA-8192/PKCS#1v1.5/SHA-512",
            rsa_sign_verify_cmd::<PK, SK, RSASSA_PKCS1_v1_5_SHA512, PK_LEN, SK_LEN, SIG_LEN>,
        ),
        (RSAScheme::Pss, RSAHash::Sha256) => run(
            "RSA-8192/PSS/SHA-256",
            rsa_sign_verify_cmd::<PK, SK, RSASSA_PSS_SHA256, PK_LEN, SK_LEN, SIG_LEN>,
        ),
        (RSAScheme::Pss, RSAHash::Sha384) => run(
            "RSA-8192/PSS/SHA-384",
            rsa_sign_verify_cmd::<PK, SK, RSASSA_PSS_SHA384, PK_LEN, SK_LEN, SIG_LEN>,
        ),
        (RSAScheme::Pss, RSAHash::Sha512) => run(
            "RSA-8192/PSS/SHA-512",
            rsa_sign_verify_cmd::<PK, SK, RSASSA_PSS_SHA512, PK_LEN, SK_LEN, SIG_LEN>,
        ),
        (scheme, hash) => unsupported(scheme, hash, "RSA-8192"),
    }
}
