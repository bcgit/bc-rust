//! Generic CLI wiring for every ECDSA curve in `bouncycastle-ecdsa`: one instantiation of
//! [`ecdsa_cmd`] per curve, rather than the per-curve match block `mldsa_cmd.rs`/`mlkem_cmd.rs`
//! duplicate seven and three times respectively. That duplication is warranted for them -- each
//! parameter set is its own concrete algorithm with its own quirks (a hash-then-sign variant, a
//! from-seed variant, a bespoke consistency-check API) -- but every ECDSA curve implements the
//! identical `Signer`/`SignatureVerifier`/`SignaturePrivateKey`/`SignaturePublicKey`/
//! `DerivePublicKey` trait shape with no per-curve deviation, so a single generic function bound
//! over those traits, monomorphised once per curve below, covers all seven without repeating the
//! same match block.
//!
//! Each curve has two signer types, `ECDSA*` (random `k`) and `ECDetDSA*` (RFC 6979), identical in
//! trait shape; `--deterministic` picks which one [`ecdsa_cmd`] is instantiated over.
//!
//! `ctx` (accepted by `Signer`/`SignatureVerifier` for trait conformance) is not exposed as a CLI
//! flag here: `bouncycastle_ecdsa`'s own crate docs say ECDSA "accepts but ignores" it (FIPS
//! 186-5/SEC 1 have no context-string input), so a `--ctxfile` flag would silently do nothing --
//! every call below passes `None` directly instead. `SM2` (`sm2_cmd.rs`) is the curve this crate
//! does NOT cover: its `ctx` is mandatory (it carries the signer's identity `IDA`) and its
//! `derive_pk` is a bespoke inherent method rather than an implementation of `DerivePublicKey`, so
//! it needs its own command function and its own `--idfile` flag.

use crate::helpers::{read_from_file, read_from_file_or_stdin, write_bytes_or_hex};
use bouncycastle::core::errors::SignatureError;
use bouncycastle::core::signature_key::{
    DeterministicSigningKey, SignatureAlgorithm, SigningKey, VerifyingKey,
};
use bouncycastle::core::traits::{
    RNG, SignaturePrivateKey, SignaturePublicKey, SignatureSigner, SignatureVerifier,
};
use bouncycastle::ecdsa::keys_common::DerivePublicKey;
use bouncycastle::ecdsa::{
    ecdsa_bp256r1, ecdsa_bp256r1::ECDSABp256r1, ecdsa_bp384r1, ecdsa_bp384r1::ECDSABp384r1,
    ecdsa_bp512r1, ecdsa_bp512r1::ECDSABp512r1, ecdsa_p256, ecdsa_p256::ECDSAP256, ecdsa_p256k1,
    ecdsa_p256k1::ECDSASecp256K1, ecdsa_p384, ecdsa_p384::ECDSAP384, ecdsa_p521,
    ecdsa_p521::ECDSAP521,
};
use bouncycastle::ecdsa::{
    keys_bp256r1, keys_bp384r1, keys_bp512r1, keys_p256, keys_p256k1, keys_p384, keys_p521,
};
use bouncycastle::hex;
use bouncycastle::rng::HashDRBG_SHA512;
use clap::ValueEnum;
use std::io;
use std::io::Read;
use std::process::exit;

#[derive(ValueEnum, Clone, Debug)]
pub(crate) enum ECDSAAction {
    /// Generate and output a new private key.
    Keygen,
    /// Derive and output the public key matching a private key read from stdin.
    /// Accepts either binary or hex.
    PkFromSk,
    /// Accepts a private key (stdin) and a public key (--pkfile), and checks that they match.
    CheckConsistency,
    /// Sign a message read from stdin with a private key file and output the signature.
    /// Accepts the private key as binary or hex.
    Sign,
    /// Verify a message read from stdin with a public key file and a signature file.
    /// Accepts the public key and signature as binary or hex.
    Verify,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn ecdsa_cmd<
    A: SignatureAlgorithm,
    PK: SignaturePublicKey<PK_LEN> + VerifyingKey<A, SIG_LEN>,
    SK: SignaturePrivateKey<SK_LEN>
        + DerivePublicKey<PK, PK_LEN>
        + SigningKey<A, SIG_LEN>
        + DeterministicSigningKey<A, SIG_LEN>,
    const SK_LEN: usize,
    const PK_LEN: usize,
    const SIG_LEN: usize,
>(
    action: &ECDSAAction,
    keygen: fn(&mut dyn RNG) -> Result<(PK, SK), SignatureError>,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    sigfile: &Option<String>,
    output_hex: bool,
    deterministic: bool,
    alg_name: &str,
) {
    match action {
        ECDSAAction::Keygen => {
            let (_pk, sk) = keygen(&mut HashDRBG_SHA512::new_from_os()).unwrap();
            write_bytes_or_hex(&sk.encode(), output_hex);
        }
        ECDSAAction::PkFromSk => {
            let buf = read_from_file_or_stdin(skfile);
            let sk = parse_sk::<SK, SK_LEN>(&buf, alg_name);
            write_bytes_or_hex(&sk.derive_pk().encode(), output_hex);
        }
        ECDSAAction::CheckConsistency => {
            let buf = read_from_file_or_stdin(skfile);
            let sk = parse_sk::<SK, SK_LEN>(&buf, alg_name);

            let pk_bytes = require_file(pkfile, "pkfile");
            let pk = parse_pk::<PK, PK_LEN>(&pk_bytes, alg_name);

            if sk.derive_pk() == pk {
                println!("SUCCESS: pk and sk match.");
            } else {
                eprintln!("FAILURE: pk and sk do not match.");
                exit(-1);
            }
        }
        ECDSAAction::Sign => {
            let sk_bytes = require_file(skfile, "skfile");
            let sk = parse_sk::<SK, SK_LEN>(&sk_bytes, alg_name);

            // stream the message from stdin; ECDSA has no context string
            let sig = if deterministic {
                let mut signer = sk.create_signer_deterministic(None).unwrap();
                stream_stdin_into(|chunk| signer.do_update(chunk));
                signer.do_final().unwrap()
            } else {
                let mut signer =
                    sk.create_signer(&mut HashDRBG_SHA512::new_from_os(), None).unwrap();
                stream_stdin_into(|chunk| signer.do_update(chunk));
                signer.do_final().unwrap()
            };

            write_bytes_or_hex(&sig, output_hex);
        }
        ECDSAAction::Verify => {
            let pk_bytes = require_file(pkfile, "pkfile");
            let pk = parse_pk::<PK, PK_LEN>(&pk_bytes, alg_name);
            let sig = require_file(sigfile, "sigfile");

            // stream the message from stdin
            let mut verifier = pk.create_verifier(None).unwrap();
            stream_stdin_into(|chunk| verifier.do_update(chunk));

            if verifier.do_verify_final(&sig).is_ok() {
                println!("Signature is valid.");
            } else {
                eprintln!("Signature is invalid.");
                exit(-1);
            }
        }
    }
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

fn stream_stdin_into(mut update: impl FnMut(&[u8])) {
    let mut buf = [0u8; 1024];
    let mut bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    update(&buf[..bytes_read]);
    while bytes_read != 0 {
        bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
        update(&buf[..bytes_read]);
    }
}

/// Tries a hex-decoded prefix first, in case `read_from_file`'s own whole-buffer hex decode was
/// defeated by trailing whitespace (e.g. a newline after a hex-encoded file); falls back to the
/// bytes as given (already hex-decoded by `read_from_file` when that whole-buffer decode did
/// succeed, or raw binary otherwise).
fn parse_sk<SK: SignaturePrivateKey<SK_LEN>, const SK_LEN: usize>(
    bytes: &[u8],
    alg_name: &str,
) -> SK {
    if bytes.len() >= 2 * SK_LEN {
        if let Ok(decoded) = hex::decode(&bytes[..2 * SK_LEN]) {
            if let Ok(sk) = SK::from_bytes(&decoded) {
                return sk;
            }
        }
    }
    match SK::from_bytes(bytes) {
        Ok(sk) => sk,
        Err(_) => {
            eprintln!("Error: couldn't parse the input as a valid {alg_name} private key.");
            exit(-1);
        }
    }
}

/// See [`parse_sk`].
fn parse_pk<PK: SignaturePublicKey<PK_LEN>, const PK_LEN: usize>(
    bytes: &[u8],
    alg_name: &str,
) -> PK {
    if bytes.len() >= 2 * PK_LEN {
        if let Ok(decoded) = hex::decode(&bytes[..2 * PK_LEN]) {
            if let Ok(pk) = PK::from_bytes(&decoded) {
                return pk;
            }
        }
    }
    match PK::from_bytes(bytes) {
        Ok(pk) => pk,
        Err(_) => {
            eprintln!("Error: couldn't parse the input as a valid {alg_name} public key.");
            exit(-1);
        }
    }
}

pub(crate) fn ecdsa_p256_cmd(
    action: &ECDSAAction,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    sigfile: &Option<String>,
    output_hex: bool,
    deterministic: bool,
) {
    ecdsa_cmd::<
        ECDSAP256,
        _,
        _,
        { keys_p256::SK_LEN },
        { keys_p256::PK_LEN },
        { ecdsa_p256::SIG_LEN },
    >(
        action, keys_p256::keygen, skfile, pkfile, sigfile, output_hex, deterministic, "ECDSA P-256"
    )
}

pub(crate) fn ecdsa_p384_cmd(
    action: &ECDSAAction,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    sigfile: &Option<String>,
    output_hex: bool,
    deterministic: bool,
) {
    ecdsa_cmd::<
        ECDSAP384,
        _,
        _,
        { keys_p384::SK_LEN },
        { keys_p384::PK_LEN },
        { ecdsa_p384::SIG_LEN },
    >(
        action, keys_p384::keygen, skfile, pkfile, sigfile, output_hex, deterministic, "ECDSA P-384"
    )
}

pub(crate) fn ecdsa_p521_cmd(
    action: &ECDSAAction,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    sigfile: &Option<String>,
    output_hex: bool,
    deterministic: bool,
) {
    ecdsa_cmd::<
        ECDSAP521,
        _,
        _,
        { keys_p521::SK_LEN },
        { keys_p521::PK_LEN },
        { ecdsa_p521::SIG_LEN },
    >(
        action, keys_p521::keygen, skfile, pkfile, sigfile, output_hex, deterministic, "ECDSA P-521"
    )
}

pub(crate) fn ecdsa_secp256k1_cmd(
    action: &ECDSAAction,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    sigfile: &Option<String>,
    output_hex: bool,
    deterministic: bool,
) {
    ecdsa_cmd::<
        ECDSASecp256K1,
        _,
        _,
        { keys_p256k1::SK_LEN },
        { keys_p256k1::PK_LEN },
        { ecdsa_p256k1::SIG_LEN },
    >(
        action,
        keys_p256k1::keygen,
        skfile,
        pkfile,
        sigfile,
        output_hex,
        deterministic,
        "ECDSA secp256k1",
    )
}

pub(crate) fn ecdsa_bp256r1_cmd(
    action: &ECDSAAction,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    sigfile: &Option<String>,
    output_hex: bool,
    deterministic: bool,
) {
    ecdsa_cmd::<
        ECDSABp256r1,
        _,
        _,
        { keys_bp256r1::SK_LEN },
        { keys_bp256r1::PK_LEN },
        { ecdsa_bp256r1::SIG_LEN },
    >(
        action,
        keys_bp256r1::keygen,
        skfile,
        pkfile,
        sigfile,
        output_hex,
        deterministic,
        "ECDSA brainpoolP256r1",
    )
}

pub(crate) fn ecdsa_bp384r1_cmd(
    action: &ECDSAAction,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    sigfile: &Option<String>,
    output_hex: bool,
    deterministic: bool,
) {
    ecdsa_cmd::<
        ECDSABp384r1,
        _,
        _,
        { keys_bp384r1::SK_LEN },
        { keys_bp384r1::PK_LEN },
        { ecdsa_bp384r1::SIG_LEN },
    >(
        action,
        keys_bp384r1::keygen,
        skfile,
        pkfile,
        sigfile,
        output_hex,
        deterministic,
        "ECDSA brainpoolP384r1",
    )
}

pub(crate) fn ecdsa_bp512r1_cmd(
    action: &ECDSAAction,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    sigfile: &Option<String>,
    output_hex: bool,
    deterministic: bool,
) {
    ecdsa_cmd::<
        ECDSABp512r1,
        _,
        _,
        { keys_bp512r1::SK_LEN },
        { keys_bp512r1::PK_LEN },
        { ecdsa_bp512r1::SIG_LEN },
    >(
        action,
        keys_bp512r1::keygen,
        skfile,
        pkfile,
        sigfile,
        output_hex,
        deterministic,
        "ECDSA brainpoolP512r1",
    )
}
