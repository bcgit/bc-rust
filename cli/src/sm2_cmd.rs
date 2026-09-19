//! CLI wiring for `bouncycastle-sm2`. Bespoke rather than routed through `ecdsa_cmd`'s generic
//! function: every SM2 `Signer`/`SignatureVerifier` call requires `ctx` to carry the signer's
//! identity `IDA` (`draft-shen-sm2-ecdsa-02` S5; see `bouncycastle_sm2::sm2`'s docs), whereas every
//! curve `ecdsa_cmd` covers ignores `ctx` entirely -- and `SM2PrivateKey::derive_pk` is a plain
//! inherent method rather than an implementation of `bouncycastle_ecdsa::keys_common::
//! DerivePublicKey` (see that method's own doc comment: SM2 was never going to share a single
//! generic command function with the other seven curves regardless). `--idfile` is mandatory for
//! `Sign`/`Verify`: the crate has no default identity to fall back to when `ctx` is omitted.

use crate::helpers::{read_from_file, read_from_file_or_stdin, write_bytes_or_hex};
use bouncycastle::core::traits::{
    SignaturePrivateKey, SignaturePublicKey, SignatureVerifier, Signer,
};
use bouncycastle::hex;
use bouncycastle::sm2::keys::{PK_LEN, SK_LEN, SM2PrivateKey, SM2PublicKey, keygen};
use bouncycastle::sm2::sm2::SM2;
use clap::ValueEnum;
use std::io;
use std::io::Read;
use std::process::exit;

#[derive(ValueEnum, Clone, Debug)]
pub(crate) enum SM2Action {
    /// Generate and output a new private key.
    Keygen,
    /// Derive and output the public key matching a private key read from stdin.
    /// Accepts either binary or hex.
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
            let (_pk, sk) = keygen().unwrap();
            write_bytes_or_hex(&sk.encode(), output_hex);
        }
        SM2Action::PkFromSk => {
            let buf = read_from_file_or_stdin(skfile);
            let sk = parse_sk(&buf);
            write_bytes_or_hex(&sk.derive_pk().encode(), output_hex);
        }
        SM2Action::CheckConsistency => {
            let buf = read_from_file_or_stdin(skfile);
            let sk = parse_sk(&buf);

            let pk_bytes = require_file(pkfile, "pkfile");
            let pk = parse_pk(&pk_bytes);

            if sk.derive_pk() == pk {
                println!("SUCCESS: pk and sk match.");
            } else {
                eprintln!("FAILURE: pk and sk do not match.");
                exit(-1);
            }
        }
        SM2Action::Sign => {
            let sk_bytes = require_file(skfile, "skfile");
            let sk = parse_sk(&sk_bytes);
            let id = require_id(idfile);

            // stream the message from stdin
            let mut signer = SM2::sign_init(&sk, Some(&id)).unwrap();
            stream_stdin_into(|chunk| signer.sign_update(chunk));
            let sig = signer.sign_final().unwrap();

            write_bytes_or_hex(&sig, output_hex);
        }
        SM2Action::Verify => {
            let pk_bytes = require_file(pkfile, "pkfile");
            let pk = parse_pk(&pk_bytes);
            let sig = require_file(sigfile, "sigfile");
            let id = require_id(idfile);

            // stream the message from stdin
            let mut verifier = SM2::verify_init(&pk, Some(&id)).unwrap();
            stream_stdin_into(|chunk| verifier.verify_update(chunk));

            if verifier.verify_final(&sig).is_ok() {
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

fn require_id(idfile: &Option<String>) -> Vec<u8> {
    match idfile {
        Some(f) => read_from_file(f),
        None => {
            eprintln!(
                "Error: no idfile provided. SM2 signing and verification require the signer's \
                 identity IDA (draft-shen-sm2-ecdsa-02 S5); this crate has no default identity to \
                 fall back to."
            );
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

/// See `ecdsa_cmd::parse_sk` for why the hex-decoded-prefix retry is needed even though
/// `read_from_file` already attempts a whole-buffer hex decode.
fn parse_sk(bytes: &[u8]) -> SM2PrivateKey {
    if bytes.len() >= 2 * SK_LEN {
        if let Ok(decoded) = hex::decode(&bytes[..2 * SK_LEN]) {
            if let Ok(sk) = SM2PrivateKey::from_bytes(&decoded) {
                return sk;
            }
        }
    }
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
    if bytes.len() >= 2 * PK_LEN {
        if let Ok(decoded) = hex::decode(&bytes[..2 * PK_LEN]) {
            if let Ok(pk) = SM2PublicKey::from_bytes(&decoded) {
                return pk;
            }
        }
    }
    match SM2PublicKey::from_bytes(bytes) {
        Ok(pk) => pk,
        Err(_) => {
            eprintln!("Error: couldn't parse the input as a valid SM2 public key.");
            exit(-1);
        }
    }
}
