//! The `x25519` subcommand: X25519 key agreement (RFC 7748) through the agreement role, and
//! DHKEM(X25519, HKDF-SHA256) (RFC 9180) through the KEM roles, on one key pair. `agree` writes
//! the raw shared secret for a KDF (`hkdf-* --ikm-file` and the others), as `eccdh-*` does.

use crate::helpers::{
    println_stdout, read_input_file, read_input_file_or_stdin, read_secret_file,
    read_secret_file_or_stdin, write_bytes_or_hex, write_bytes_or_hex_to_file, write_stdout,
};
use bouncycastle::core::agreement_key::AgreementKey;
use bouncycastle::core::kem_key::{DecapsulatingKey, EncapsulatingKey};
use bouncycastle::core::key_material::KeyMaterialTrait;
use bouncycastle::core::traits::{KeyAgreementPrivateKey, KeyAgreementPublicKey};
use bouncycastle::ed::x25519::{POINT_LEN, X25519PrivateKey, X25519PublicKey, keygen};
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
            let (_pk, sk) = keygen(&mut HashDRBG_SHA512::new_from_os()).unwrap_or_else(|e| {
                eprintln!("Error: key generation failed: {e:?}");
                exit(-1);
            });
            write_bytes_or_hex(&sk.encode(), output_hex);
        }
        X25519Action::PkFromSk => {
            let sk = parse_sk(read_secret_file_or_stdin(skfile).ref_to_bytes());
            write_bytes_or_hex(&sk.pk().encode(), output_hex);
        }
        X25519Action::CheckConsistency => {
            let sk = parse_sk(read_secret_file_or_stdin(skfile).ref_to_bytes());
            let pk = parse_pk(&read_pkfile(pkfile));
            if sk.pk() == pk {
                println_stdout("SUCCESS: pk and sk match.");
            } else {
                eprintln!("FAILURE: pk and sk do not match.");
                exit(-1);
            }
        }
        X25519Action::Agree => {
            let sk = parse_sk(read_secret_file_or_stdin(skfile).ref_to_bytes());
            let pk = parse_pk(&read_pkfile(pkfile));
            let z = sk.agree(&pk, ()).unwrap_or_else(|e| {
                eprintln!("Error: key agreement failed: {e:?}");
                exit(-1);
            });
            write_bytes_or_hex(z.ref_to_bytes(), output_hex);
        }
        X25519Action::Encaps => {
            let pk = parse_pk(&read_input_file_or_stdin(pkfile));
            let (ss, ct) = pk.encaps(&mut HashDRBG_SHA512::new_from_os(), ()).unwrap_or_else(|e| {
                eprintln!("Error: encapsulation failed: {e:?}");
                exit(-1);
            });
            if let Some(ctfile) = ctfile {
                write_bytes_or_hex_to_file(&ct, ctfile, output_hex);
                write_bytes_or_hex(ss.ref_to_bytes(), output_hex);
            } else {
                write_bytes_or_hex(&ct, true);
                write_stdout(b"\n");
                write_bytes_or_hex(ss.ref_to_bytes(), true);
            }
        }
        X25519Action::Decaps => {
            let sk = match skfile {
                Some(f) => parse_sk(read_secret_file(f).ref_to_bytes()),
                None => {
                    eprintln!("Error: no skfile provided.");
                    exit(-1);
                }
            };
            let ct = read_input_file_or_stdin(ctfile);
            let Ok(ct) = <[u8; POINT_LEN]>::try_from(ct.as_slice()) else {
                eprintln!("Error: ciphertext is not the correct length.");
                exit(-1);
            };
            let ss = sk.decaps(&ct, ()).unwrap_or_else(|e| {
                eprintln!("Error: decapsulation failed: {e:?}");
                exit(-1);
            });
            write_bytes_or_hex(ss.ref_to_bytes(), output_hex);
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

fn parse_sk(bytes: &[u8]) -> X25519PrivateKey {
    X25519PrivateKey::from_bytes(bytes).unwrap_or_else(|_| {
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
