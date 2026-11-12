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

use crate::helpers::{
    println_stdout, read_input_file, read_secret_file, read_secret_file_or_stdin, stream_stdin,
    write_bytes_or_hex,
};
use bouncycastle::core::errors::SignatureError;
use bouncycastle::core::key_material::KeyMaterialTrait;
use bouncycastle::core::signature_key::{
    DeterministicSigningKey, SignatureAlgorithm, SigningKey, VerifyingKey,
};
use bouncycastle::core::traits::{
    RNG, SignaturePrivateKey, SignaturePublicKey, SignatureSigner, SignatureVerifier,
};
use bouncycastle::ec::curve::Curve;
use bouncycastle::ec::{Bp256r1, Bp384r1, Bp512r1, P256, P384, P521, Secp256K1};
use bouncycastle::ecdsa::ecdsa::{
    ECDSABp256r1, ECDSABp384r1, ECDSABp512r1, ECDSAP256, ECDSAP384, ECDSAP521, ECDSASecp256K1,
};
use bouncycastle::ecdsa::keys::{ECDSAPrivateKey, ECDSAPublicKey, keygen};
use bouncycastle::ecdsa::keys_common::DerivePublicKey;
use bouncycastle::rng::HashDRBG_SHA512;
use bouncycastle::sha2::{SHA256, SHA384, SHA512};
use clap::ValueEnum;
use std::process::exit;

#[derive(ValueEnum, Clone, Debug)]
pub(crate) enum ECDSAAction {
    /// Generate and output a new private key.
    Keygen,
    /// Derive and output the public key matching a private key read from stdin (raw bytes, or
    /// hex with --hex-input).
    PkFromSk,
    /// Accepts a private key (stdin) and a public key (--pkfile), and checks that they match.
    CheckConsistency,
    /// Sign a message read from stdin with a private key file and output the signature.
    Sign,
    /// Verify a message read from stdin with a public key file and a signature file.
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
            let sk =
                parse_sk::<SK, SK_LEN>(read_secret_file_or_stdin(skfile).ref_to_bytes(), alg_name);
            write_bytes_or_hex(&sk.derive_pk().encode(), output_hex);
        }
        ECDSAAction::CheckConsistency => {
            let sk =
                parse_sk::<SK, SK_LEN>(read_secret_file_or_stdin(skfile).ref_to_bytes(), alg_name);

            let pk_bytes = require_file(pkfile, "pkfile");
            let pk = parse_pk::<PK, PK_LEN>(&pk_bytes, alg_name);

            if sk.derive_pk() == pk {
                println_stdout("SUCCESS: pk and sk match.");
            } else {
                eprintln!("FAILURE: pk and sk do not match.");
                exit(-1);
            }
        }
        ECDSAAction::Sign => {
            let sk =
                parse_sk::<SK, SK_LEN>(require_secret(skfile, "skfile").ref_to_bytes(), alg_name);

            // stream the message from stdin; ECDSA has no context string
            let sig = if deterministic {
                let mut signer = sk.create_signer_deterministic(None).unwrap();
                stream_stdin(|chunk| signer.do_update(chunk));
                signer.do_final().unwrap()
            } else {
                let mut signer =
                    sk.create_signer(&mut HashDRBG_SHA512::new_from_os(), None).unwrap();
                stream_stdin(|chunk| signer.do_update(chunk));
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
            stream_stdin(|chunk| verifier.do_update(chunk));

            if verifier.do_verify_final(&sig).is_ok() {
                println_stdout("Signature is valid.");
            } else {
                eprintln!("Signature is invalid.");
                exit(-1);
            }
        }
    }
}

/// `--pkfile` and `--sigfile`, which cannot fall back to stdin (that carries the message).
fn require_file(file: &Option<String>, flag_name: &str) -> Vec<u8> {
    match file {
        Some(f) => read_input_file(f),
        None => {
            eprintln!("Error: no {flag_name} provided.");
            exit(-1);
        }
    }
}

/// `--skfile` where signing cannot take the key from stdin.
fn require_secret(file: &Option<String>, flag_name: &str) -> crate::helpers::SecretBytes {
    match file {
        Some(f) => read_secret_file(f),
        None => {
            eprintln!("Error: no {flag_name} provided.");
            exit(-1);
        }
    }
}

/// The key from its encoding; the bytes are what the file held, or its hex decoded under
/// `--hex-input`, with nothing guessed from their shape.
fn parse_sk<SK: SignaturePrivateKey<SK_LEN>, const SK_LEN: usize>(
    bytes: &[u8],
    alg_name: &str,
) -> SK {
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
        ECDSAPublicKey<P256, SHA256>,
        ECDSAPrivateKey<P256, SHA256>,
        { P256::SCALAR_LEN },
        { P256::PK_UNCOMPRESSED_LEN },
        { P256::SIG_LEN },
    >(
        action, keygen::<P256, _>, skfile, pkfile, sigfile, output_hex, deterministic, "ECDSA P-256"
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
        ECDSAPublicKey<P384, SHA384>,
        ECDSAPrivateKey<P384, SHA384>,
        { P384::SCALAR_LEN },
        { P384::PK_UNCOMPRESSED_LEN },
        { P384::SIG_LEN },
    >(
        action, keygen::<P384, _>, skfile, pkfile, sigfile, output_hex, deterministic, "ECDSA P-384"
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
        ECDSAPublicKey<P521, SHA512>,
        ECDSAPrivateKey<P521, SHA512>,
        { P521::SCALAR_LEN },
        { P521::PK_UNCOMPRESSED_LEN },
        { P521::SIG_LEN },
    >(
        action, keygen::<P521, _>, skfile, pkfile, sigfile, output_hex, deterministic, "ECDSA P-521"
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
        ECDSAPublicKey<Secp256K1, SHA256>,
        ECDSAPrivateKey<Secp256K1, SHA256>,
        { Secp256K1::SCALAR_LEN },
        { Secp256K1::PK_UNCOMPRESSED_LEN },
        { Secp256K1::SIG_LEN },
    >(
        action, keygen::<Secp256K1, _>, skfile, pkfile, sigfile, output_hex, deterministic,
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
        ECDSAPublicKey<Bp256r1, SHA256>,
        ECDSAPrivateKey<Bp256r1, SHA256>,
        { Bp256r1::SCALAR_LEN },
        { Bp256r1::PK_UNCOMPRESSED_LEN },
        { Bp256r1::SIG_LEN },
    >(
        action, keygen::<Bp256r1, _>, skfile, pkfile, sigfile, output_hex, deterministic,
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
        ECDSAPublicKey<Bp384r1, SHA384>,
        ECDSAPrivateKey<Bp384r1, SHA384>,
        { Bp384r1::SCALAR_LEN },
        { Bp384r1::PK_UNCOMPRESSED_LEN },
        { Bp384r1::SIG_LEN },
    >(
        action, keygen::<Bp384r1, _>, skfile, pkfile, sigfile, output_hex, deterministic,
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
        ECDSAPublicKey<Bp512r1, SHA512>,
        ECDSAPrivateKey<Bp512r1, SHA512>,
        { Bp512r1::SCALAR_LEN },
        { Bp512r1::PK_UNCOMPRESSED_LEN },
        { Bp512r1::SIG_LEN },
    >(
        action, keygen::<Bp512r1, _>, skfile, pkfile, sigfile, output_hex, deterministic,
        "ECDSA brainpoolP512r1",
    )
}
