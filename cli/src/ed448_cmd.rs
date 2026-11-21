//! The `ed448` and `ed448ph` subcommands: Ed448 and Ed448ph signatures (RFC 8032
//! Section 5.2) on one key pair.
//!
//! Ed448 hashes the message twice, the second time after a value computed from the first
//! (RFC 8032 Section 5.2.6, steps 2 and 4), so `ed448` holds all of stdin before it signs or
//! verifies. Ed448ph signs the 64-octet SHAKE256 digest of the message, so `ed448ph` streams
//! it. Unlike Ed25519, both take a context.

use crate::helpers::{
    CHUNK_LEN, SecretBytes, println_stdout, read_input_file, read_secret_file,
    read_secret_file_or_stdin, read_stdin_all, stream_stdin, write_bytes_or_hex, write_private_key,
};
use bouncycastle::core::errors::SignatureError;
use bouncycastle::core::key_material::KeyMaterialTrait;
use bouncycastle::core::signature_key::{
    DeterministicOneShotSigningKey, DeterministicSigningKey, OneShotVerifyingKey, VerifyingKey,
};
use bouncycastle::core::traits::{PublicKey, SignatureSigner, SignatureVerifier};
use bouncycastle::ed::ed448::{
    CONTEXT_MAX_LEN, Ed448, Ed448PrivateKey, Ed448PublicKey, SIGNATURE_LEN, keygen_out,
    keypair_consistency_check,
};
use bouncycastle::rng::HashDRBG_SHA512;
use clap::ValueEnum;
use std::io::Read;
use std::process::exit;

#[derive(ValueEnum, Clone, Debug)]
pub(crate) enum Ed448Action {
    /// Generate a private key (57 bytes) to stdout.
    Keygen,
    /// Derive the public key from the private key.
    PkFromSk,
    /// Check that a public key matches a private key.
    CheckConsistency,
    /// Sign a message read from stdin with a private key file and output the signature.
    Sign,
    /// Verify a message read from stdin with a public key file and a signature file.
    Verify,
}

/// Which of the two algorithms a subcommand runs.
pub(crate) enum Ed448Variant {
    Pure,
    Prehash,
}

pub(crate) fn ed448_cmd(
    variant: &Ed448Variant,
    action: &Ed448Action,
    ctxfile: &Option<String>,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    sigfile: &Option<String>,
    output_hex: bool,
) {
    // A context is an input to signing and verification alone; accepting one elsewhere would
    // suggest it had been used.
    if ctxfile.is_some() && !matches!(action, Ed448Action::Sign | Ed448Action::Verify) {
        eprintln!("Error: --ctxfile applies to sign and verify only.");
        exit(-1);
    }
    match action {
        Ed448Action::Keygen => {
            // The private key is drawn straight into this key, never moved.
            let mut sk = Ed448PrivateKey::zeroized();
            keygen_out(&mut HashDRBG_SHA512::new_from_os(), &mut sk).unwrap_or_else(|e| {
                eprintln!("Error: key generation failed: {e:?}");
                exit(-1);
            });
            write_private_key(&sk, output_hex);
        }
        Ed448Action::PkFromSk => {
            // The private key is dropped before the write, which ends the process on a closed
            // pipe.
            let pk = {
                let mut sk = Ed448PrivateKey::zeroized();
                load_sk(|| read_secret_file_or_stdin(skfile), &mut sk);
                // A decoded key is filled, so it has a public key.
                sk.pk().unwrap()
            };
            write_bytes_or_hex(&pk.encode(), output_hex);
        }
        Ed448Action::CheckConsistency => {
            let pk = parse_pk(&require_file(pkfile, "pkfile"));
            // `exit` runs no destructors, so the private key is dropped, and so wiped, before
            // either branch exits.
            let matches = {
                let mut sk = Ed448PrivateKey::zeroized();
                load_sk(|| read_secret_file_or_stdin(skfile), &mut sk);
                keypair_consistency_check(&pk, &sk).is_ok()
            };
            if matches {
                println_stdout("SUCCESS: pk and sk match.");
            } else {
                eprintln!("FAILURE: pk and sk do not match.");
                exit(-1);
            }
        }
        Ed448Action::Sign => {
            // The helpers that read a file or all of stdin end the process themselves on a
            // failure, and `exit` runs no destructors: so what they read is read first, while
            // there is no key to leave unwiped.
            let ctx = read_ctx(ctxfile);
            let input = match variant {
                Ed448Variant::Pure => SignInput::Message { ctx, msg: read_stdin_all() },
                Ed448Variant::Prehash => SignInput::Context(ctx),
            };
            // As above: the key is dropped before the result is looked at.
            let sig = {
                let mut sk = Ed448PrivateKey::zeroized();
                load_sk(|| require_secret(skfile, "skfile"), &mut sk);
                sign(&input, &sk)
            };
            let sig = sig.unwrap_or_else(|e| {
                match e {
                    SignFailure::Stdin(e) => eprintln!("Error: failed to read from stdin: {e}"),
                    SignFailure::Signature(e) => eprintln!("Error: signing failed: {e:?}"),
                }
                exit(-1);
            });
            write_bytes_or_hex(&sig, output_hex);
        }
        Ed448Action::Verify => {
            let pk = parse_pk(&require_file(pkfile, "pkfile"));
            let sig = require_file(sigfile, "sigfile");
            let ctx = read_ctx(ctxfile);
            // A context that is too long is the caller's mistake, not a bad signature.
            if ctx.len() > CONTEXT_MAX_LEN {
                eprintln!("Error: the context is at most {CONTEXT_MAX_LEN} bytes.");
                exit(-1);
            }
            if verify(variant, &pk, &ctx, &sig).is_ok() {
                println_stdout("Signature is valid.");
            } else {
                eprintln!("Signature is invalid.");
                exit(-1);
            }
        }
    }
}

/// What signing needs besides the key, read before the key is loaded: the context, and for
/// Ed448 the whole message, that of Ed448ph being streamed.
enum SignInput {
    Message { ctx: Vec<u8>, msg: Vec<u8> },
    Context(Vec<u8>),
}

/// Why [`sign`] gave no signature. Returned, not exited on, so that the caller's key is dropped
/// first.
enum SignFailure {
    Stdin(std::io::Error),
    Signature(SignatureError),
}

/// The signature: over the message already read for Ed448, and over stdin in chunks for
/// Ed448ph. Nothing here ends the process, the private key being alive throughout.
fn sign(input: &SignInput, sk: &Ed448PrivateKey) -> Result<[u8; SIGNATURE_LEN], SignFailure> {
    match input {
        SignInput::Message { ctx, msg } => {
            DeterministicOneShotSigningKey::<Ed448, _>::sign_deterministic(sk, msg, Some(ctx))
                .map_err(SignFailure::Signature)
        }
        SignInput::Context(ctx) => {
            let mut signer =
                sk.create_signer_deterministic(Some(ctx)).map_err(SignFailure::Signature)?;
            let mut stdin = std::io::stdin();
            let mut buf = [0u8; CHUNK_LEN];
            loop {
                match stdin.read(&mut buf).map_err(SignFailure::Stdin)? {
                    0 => break,
                    n => signer.do_update(&buf[..n]),
                }
            }
            signer.do_final().map_err(SignFailure::Signature)
        }
    }
}

/// See [`sign`]. `ctx` is at most [`CONTEXT_MAX_LEN`] bytes.
fn verify(
    variant: &Ed448Variant,
    pk: &Ed448PublicKey,
    ctx: &[u8],
    sig: &[u8],
) -> Result<(), SignatureError> {
    match variant {
        Ed448Variant::Pure => {
            let msg = read_stdin_all();
            OneShotVerifyingKey::<Ed448, _>::verify(pk, &msg, Some(ctx), sig)
        }
        Ed448Variant::Prehash => {
            let mut verifier = pk.create_verifier(Some(ctx))?;
            stream_stdin(|chunk| verifier.do_update(chunk));
            verifier.do_verify_final(sig)
        }
    }
}

/// `--ctxfile`'s bytes, or the empty context (RFC 8032's default) without one.
fn read_ctx(ctxfile: &Option<String>) -> Vec<u8> {
    ctxfile.as_ref().map(|f| read_input_file(f)).unwrap_or_default()
}

/// `--pkfile` and `--sigfile`, which cannot fall back to stdin where that carries the message.
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
fn require_secret(file: &Option<String>, flag_name: &str) -> SecretBytes {
    match file {
        Some(f) => read_secret_file(f),
        None => {
            eprintln!("Error: no {flag_name} provided.");
            exit(-1);
        }
    }
}

/// Decodes the private key that the bytes `read` returns encode into `sk`, the caller's key, so
/// that it is not moved. The bytes go out of scope, and so are wiped, before a failure exits.
fn load_sk(read: impl FnOnce() -> SecretBytes, sk: &mut Ed448PrivateKey) {
    let parsed = {
        let bytes = read();
        Ed448PrivateKey::from_bytes_out(bytes.ref_to_bytes(), sk)
    };
    parsed.unwrap_or_else(|_| {
        eprintln!("Error: couldn't parse the input as a 57-byte Ed448 private key.");
        exit(-1);
    })
}

fn parse_pk(bytes: &[u8]) -> Ed448PublicKey {
    Ed448PublicKey::from_bytes(bytes).unwrap_or_else(|_| {
        eprintln!("Error: couldn't parse the input as a valid Ed448 public key.");
        exit(-1);
    })
}
