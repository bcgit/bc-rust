//! The `x25519` subcommand: X25519 key agreement (RFC 7748) through the agreement role, and
//! DHKEM(X25519, HKDF-SHA256) (RFC 9180) through the KEM roles, on one key pair. `agree` writes
//! the raw shared secret for a KDF (`hkdf-* --ikm-file` and the others), as `eccdh-*` does.

use crate::helpers::kem_helpers::{decaps_cmd, encaps_cmd};
use crate::helpers::{
    SecretBytes, println_stdout, read_input_file, read_secret_file_or_stdin, write_bytes_or_hex,
    write_private_key, write_secret_bytes_or_hex,
};
use bouncycastle::core::agreement_key::AgreementKey;
use bouncycastle::core::key_material::KeyMaterialTrait;
use bouncycastle::core::traits::{PrivateKey, PublicKey};
use bouncycastle::ec::ed::x25519::{
    POINT_LEN, SCALAR_LEN, X25519PrivateKey, X25519PublicKey, keygen_out,
};
use bouncycastle::rng::HashDRBG_SHA512;
use clap::ValueEnum;
use std::process::exit;

#[derive(ValueEnum, Clone, Debug)]
pub(crate) enum X25519Action {
    /// Generate a private key (32 bytes) to stdout.
    Keygen,
    /// Derive the public key from the private key.
    PkFromSk,
    /// Check that a public key matches a private key.
    CheckConsistency,
    /// The raw X25519 shared secret from the private key and the peer's public key, for a KDF.
    Agree,
    /// DHKEM encapsulation against the public key: the shared secret, and the ciphertext.
    Encaps,
    /// DHKEM decapsulation of the ciphertext with the private key.
    Decaps,
}

pub(crate) fn x25519_cmd(
    action: &X25519Action,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    ctfile: &Option<String>,
    output_hex: bool,
) {
    match action {
        X25519Action::Keygen => {
            // The scalar is drawn straight into this key, never moved.
            let mut sk = X25519PrivateKey::zeroized();
            keygen_out(&mut HashDRBG_SHA512::new_from_os(), &mut sk).unwrap_or_else(|e| {
                eprintln!("Error: key generation failed: {e:?}");
                exit(-1);
            });
            write_private_key(&sk, output_hex);
        }
        X25519Action::PkFromSk => {
            let pk = load_sk(skfile).pk();
            write_bytes_or_hex(&pk.encode(), output_hex);
        }
        X25519Action::CheckConsistency => {
            let pk = parse_pk(&read_pkfile(pkfile));
            // The private key is dropped, and so wiped, before either branch exits.
            let matches = load_sk(skfile).pk() == pk;
            if matches {
                println_stdout("SUCCESS: pk and sk match.");
            } else {
                eprintln!("FAILURE: pk and sk do not match.");
                exit(-1);
            }
        }
        X25519Action::Agree => {
            let pk = parse_pk(&read_pkfile(pkfile));
            // `exit` runs no destructors, so the key is dropped before the result is looked at.
            let z = {
                let sk = load_sk(skfile);
                sk.agree(&pk, ())
            };
            let z = z.unwrap_or_else(|e| {
                eprintln!("Error: key agreement failed: {e:?}");
                exit(-1);
            });
            write_secret_bytes_or_hex(z.ref_to_bytes(), output_hex);
        }
        X25519Action::Encaps => {
            encaps_cmd::<X25519PublicKey, POINT_LEN, POINT_LEN, 32>(
                pkfile, ctfile, output_hex, "X25519",
            );
        }
        X25519Action::Decaps => {
            decaps_cmd::<X25519PrivateKey, SCALAR_LEN, POINT_LEN, 32>(
                skfile, ctfile, output_hex, "X25519",
            );
        }
    }
}

fn read_pkfile(pkfile: &Option<String>) -> Vec<u8> {
    match pkfile {
        Some(f) => read_input_file(f),
        None => {
            eprintln!("Error: no pkfile provided.");
            exit(-1);
        }
    }
}

/// The private key in `--skfile`, or on stdin.
fn load_sk(skfile: &Option<String>) -> X25519PrivateKey {
    parse_sk(|| read_secret_file_or_stdin(skfile))
}

/// The private key that the bytes `read` returns encode. The bytes go out of scope, and so are
/// wiped, before a failure exits.
fn parse_sk(read: impl FnOnce() -> SecretBytes) -> X25519PrivateKey {
    let parsed = {
        let bytes = read();
        X25519PrivateKey::from_bytes(bytes.ref_to_bytes())
    };
    parsed.unwrap_or_else(|_| {
        eprintln!("Error: couldn't parse the input as a 32-byte X25519 private key.");
        exit(-1);
    })
}

fn parse_pk(bytes: &[u8]) -> X25519PublicKey {
    X25519PublicKey::from_bytes(bytes).unwrap_or_else(|_| {
        eprintln!("Error: couldn't parse the input as a 32-byte X25519 public key.");
        exit(-1);
    })
}
