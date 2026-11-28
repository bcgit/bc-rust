//! The `x448` subcommand: X448 key agreement (RFC 7748) through the agreement role, and
//! DHKEM(X448, HKDF-SHA512) (RFC 9180) through the KEM roles, on one key pair. `agree` writes
//! the raw shared secret for a KDF (`hkdf-* --ikm-file` and the others), as `x25519` does.

use crate::helpers::kem_helpers::{decaps_cmd, encaps_cmd};
use crate::helpers::{
    finish_stdout, println_stdout, read_input_file, read_secret_file_or_stdin, write_bytes_or_hex,
    write_private_key, write_secret_bytes_or_hex,
};
use bouncycastle::core::agreement_key::AgreementKey;
use bouncycastle::core::key_material::KeyMaterialTrait;
use bouncycastle::core::traits::PublicKey;
use bouncycastle::ec::ed::x448::{
    DHKEM_SS_LEN, POINT_LEN, SCALAR_LEN, X448PrivateKey, X448PublicKey, keygen_out,
    keypair_consistency_check,
};
use bouncycastle::rng::HashDRBG_SHA512;
use clap::ValueEnum;
use std::process::exit;

#[derive(ValueEnum, Clone, Debug)]
pub(crate) enum X448Action {
    /// Generate a private key (56 bytes) to stdout.
    Keygen,
    /// Derive the public key from the private key.
    PkFromSk,
    /// Check that a public key matches a private key.
    CheckConsistency,
    /// The raw X448 shared secret from the private key and the peer's public key, for a KDF.
    Agree,
    /// DHKEM encapsulation against the public key: the shared secret, and the ciphertext.
    Encaps,
    /// DHKEM decapsulation of the ciphertext with the private key.
    Decaps,
}

pub(crate) fn x448_cmd(
    action: &X448Action,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    ctfile: &Option<String>,
    output_hex: bool,
) {
    match action {
        X448Action::Keygen => {
            // The scalar is drawn straight into this key, never moved.
            let mut sk = X448PrivateKey::zeroized();
            keygen_out(&mut HashDRBG_SHA512::new_from_os(), &mut sk).unwrap_or_else(|e| {
                eprintln!("Error: key generation failed: {e:?}");
                exit(-1);
            });
            let written = write_private_key(&sk, output_hex);
            // `exit` runs no destructors, so the key is dropped before a failed write exits.
            drop(sk);
            finish_stdout(written);
        }
        X448Action::PkFromSk => {
            // The private key is dropped before the write, which ends the process on a closed
            // pipe.
            let pk = {
                let mut sk = X448PrivateKey::zeroized();
                load_sk(skfile, &mut sk);
                // A decoded key is filled, so it has a public key.
                sk.pub_key().unwrap()
            };
            write_bytes_or_hex(&pk.encode(), output_hex);
        }
        X448Action::CheckConsistency => {
            let pk = parse_pk(&read_pkfile(pkfile));
            // The private key is dropped, and so wiped, before either branch exits.
            let matches = {
                let mut sk = X448PrivateKey::zeroized();
                load_sk(skfile, &mut sk);
                keypair_consistency_check(&pk, &sk).is_ok()
            };
            if matches {
                println_stdout("SUCCESS: pk and sk match.");
            } else {
                eprintln!("FAILURE: pk and sk do not match.");
                exit(-1);
            }
        }
        X448Action::Agree => {
            let pk = parse_pk(&read_pkfile(pkfile));
            // `exit` runs no destructors, so the key is dropped before the result is looked at.
            let z = {
                let mut sk = X448PrivateKey::zeroized();
                load_sk(skfile, &mut sk);
                sk.agree(&pk, ())
            };
            let z = z.unwrap_or_else(|e| {
                eprintln!("Error: key agreement failed: {e:?}");
                exit(-1);
            });
            let written = write_secret_bytes_or_hex(z.ref_to_bytes(), output_hex);
            drop(z);
            finish_stdout(written);
        }
        X448Action::Encaps => {
            encaps_cmd::<X448PublicKey, POINT_LEN, POINT_LEN, DHKEM_SS_LEN>(
                pkfile, ctfile, output_hex, "X448",
            );
        }
        X448Action::Decaps => {
            decaps_cmd::<X448PrivateKey, SCALAR_LEN, POINT_LEN, DHKEM_SS_LEN>(
                skfile, ctfile, output_hex, "X448",
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
fn load_sk(skfile: &Option<String>, sk: &mut X448PrivateKey) {
    let parsed = {
        // The bytes go out of scope, and so are wiped, before a failure exits.
        let bytes = read_secret_file_or_stdin(skfile);
        X448PrivateKey::from_bytes_out(bytes.ref_to_bytes(), sk)
    };
    parsed.unwrap_or_else(|_| {
        eprintln!("Error: couldn't parse the input as a 56-byte X448 private key.");
        exit(-1);
    })
}

fn parse_pk(bytes: &[u8]) -> X448PublicKey {
    X448PublicKey::from_bytes(bytes).unwrap_or_else(|_| {
        eprintln!("Error: couldn't parse the input as a 56-byte X448 public key.");
        exit(-1);
    })
}
