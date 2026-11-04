//! CLI wiring for `bouncycastle-sm2`. Bespoke rather than routed through `ecdsa_cmd`'s generic
//! function: every SM2 `Signer`/`SignatureVerifier` call requires `ctx` to carry the signer's
//! identity `IDA` (GB/T 32918.2-2016 §5.5; see `bouncycastle_sm2::sm2`'s docs), whereas every
//! curve `ecdsa_cmd` covers ignores `ctx` entirely -- and `SM2PrivateKey::derive_pk` is a plain
//! inherent method rather than an implementation of `bouncycastle_ecdsa::keys_common::
//! DerivePublicKey` (see that method's own doc comment: SM2 was never going to share a single
//! generic command function with the other seven curves regardless). `--idfile` is mandatory for
//! `Sign`/`Verify`: the crate has no default identity to fall back to when `ctx` is omitted.

use crate::helpers::{
    println_stdout, read_input_file, read_secret_file, read_secret_file_or_stdin, stream_stdin,
    write_bytes_or_hex,
};
use bouncycastle::core::key_material::KeyMaterialTrait;
use bouncycastle::core::signature_key::{SigningKey, VerifyingKey};
use bouncycastle::core::traits::{
    SignaturePrivateKey, SignaturePublicKey, SignatureSigner, SignatureVerifier,
};
use bouncycastle::rng::HashDRBG_SHA512;
use bouncycastle::sm2::keys::{SM2PrivateKey, SM2PublicKey, keygen};
use clap::ValueEnum;
use std::process::exit;

#[derive(ValueEnum, Clone, Debug)]
pub(crate) enum SM2Action {
    /// Generate and output a new private key.
    Keygen,
    /// Derive and output the public key matching a private key read from stdin (raw bytes, or
    /// hex with --hex-input).
    PkFromSk,
    /// Accepts a private key (stdin) and a public key (--pkfile), and checks that they match.
    CheckConsistency,
    /// Sign a message read from stdin with a private key file and output the signature.
    /// Requires --idfile: SM2 signing needs the signer's identity IDA, and this crate has no
    /// default identity to fall back to.
    Sign,
    /// Verify a message read from stdin with a public key file and a signature file.
    /// Requires --idfile: SM2 verification needs the signer's identity IDA, and this crate has no
    /// default identity to fall back to.
    Verify,
}

pub(crate) fn sm2_cmd(
    action: &SM2Action,
    idfile: &Option<String>,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    sigfile: &Option<String>,
    output_hex: bool,
) {
    match action {
        SM2Action::Keygen => {
            let (_pk, sk) = keygen(&mut HashDRBG_SHA512::new_from_os()).unwrap();
            write_bytes_or_hex(&sk.encode(), output_hex);
        }
        SM2Action::PkFromSk => {
            let sk = parse_sk(read_secret_file_or_stdin(skfile).ref_to_bytes());
            write_bytes_or_hex(&sk.derive_pk().encode(), output_hex);
        }
        SM2Action::CheckConsistency => {
            let sk = parse_sk(read_secret_file_or_stdin(skfile).ref_to_bytes());

            let pk_bytes = require_file(pkfile, "pkfile");
            let pk = parse_pk(&pk_bytes);

            if sk.derive_pk() == pk {
                println_stdout("SUCCESS: pk and sk match.");
            } else {
                eprintln!("FAILURE: pk and sk do not match.");
                exit(-1);
            }
        }
        SM2Action::Sign => {
            let sk = parse_sk(require_secret(skfile, "skfile").ref_to_bytes());
            let id = require_id(idfile);

            // stream the message from stdin
            let mut signer =
                sk.create_signer(&mut HashDRBG_SHA512::new_from_os(), Some(&id)).unwrap();
            stream_stdin(|chunk| signer.do_update(chunk));
            let sig = signer.do_final().unwrap();

            write_bytes_or_hex(&sig, output_hex);
        }
        SM2Action::Verify => {
            let pk_bytes = require_file(pkfile, "pkfile");
            let pk = parse_pk(&pk_bytes);
            let sig = require_file(sigfile, "sigfile");
            let id = require_id(idfile);

            // stream the message from stdin
            let mut verifier = pk.create_verifier(Some(&id)).unwrap();
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

fn require_file(file: &Option<String>, flag_name: &str) -> Vec<u8> {
    match file {
        Some(f) => read_input_file(f),
        None => {
            eprintln!("Error: no {flag_name} provided.");
            exit(-1);
        }
    }
}

fn require_id(idfile: &Option<String>) -> Vec<u8> {
    match idfile {
        Some(f) => read_input_file(f),
        None => {
            eprintln!(
                "Error: no idfile provided. SM2 signing and verification require the signer's \
                 identity IDA (GB/T 32918.2-2016 S5.5); this crate has no default identity to \
                 fall back to."
            );
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

/// The key from its encoding: the file's bytes, or their hex under `--hex-input`.
fn parse_sk(bytes: &[u8]) -> SM2PrivateKey {
    match SM2PrivateKey::from_bytes(bytes) {
        Ok(sk) => sk,
        Err(_) => {
            eprintln!("Error: couldn't parse the input as a valid SM2 private key.");
            exit(-1);
        }
    }
}

/// See [`parse_sk`].
fn parse_pk(bytes: &[u8]) -> SM2PublicKey {
    match SM2PublicKey::from_bytes(bytes) {
        Ok(pk) => pk,
        Err(_) => {
            eprintln!("Error: couldn't parse the input as a valid SM2 public key.");
            exit(-1);
        }
    }
}
