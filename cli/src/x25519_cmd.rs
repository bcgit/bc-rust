use crate::helpers::{
    read_from_file, read_from_file_or_stdin, write_bytes_or_hex, write_bytes_or_hex_to_file,
};
use bouncycastle::core::key_material::KeyMaterialTrait;
use bouncycastle::core::traits::{
    KEMDecapsulator, KEMEncapsulator, KeyAgreement, KeyAgreementPrivateKey, KeyAgreementPublicKey,
};
use bouncycastle::ed::x25519::{POINT_SIZE, X25519, X25519PrivateKey, X25519PublicKey};
use clap::ValueEnum;
use std::process::exit;

#[derive(ValueEnum, Clone, Debug)]
pub(crate) enum X25519Action {
    /// Generate and output a new private key.
    Keygen,
    /// Output the public key of a private key read from skfile or stdin.
    /// Accepts either binary or hex.
    PkFromSk,
    /// Accepts a sk (from skfile or stdin) and a pk (from pkfile), and checks that they match.
    CheckConsistency,
    /// Perform an X25519 key agreement between a private key (from skfile or stdin) and the
    /// peer's public key (from pkfile), and output the shared secret to stdout.
    /// The output is the raw X25519 shared secret: derive keys from it with a KDF, such as the
    /// hkdf-sha256 subcommand, rather than using it as a key directly.
    Agree,
    /// Perform a DHKEM(X25519, HKDF-SHA256) encapsulation (RFC 9180 Sec 4.1) with a public key,
    /// and output the shared secret and the ciphertext (the encapsulated key).
    /// If a ctfile is provided, then the shared secret is output to stdout in either binary or hex
    /// and the ciphertext to file also in binary or hex.
    /// If no ctfile is provided then ct followed by ss are output to stdout in hex, separated by a newline.
    /// The shared secret is always output to stdout to prevent it
    /// staying in a file longer than it should and causing a vulnerability.
    Encaps,
    /// Perform a DHKEM(X25519, HKDF-SHA256) decapsulation with a private key and ciphertext, and
    /// output the shared secret to stdout either in binary or hex.
    /// The private key is read from skfile, and the ciphertext from ctfile or stdin, in binary or hex.
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
            let (_pk, sk) = X25519::keygen().unwrap();
            write_bytes_or_hex(&sk.encode(), output_hex);
        }
        X25519Action::PkFromSk => {
            let sk = parse_sk(&read_from_file_or_stdin(skfile));
            write_bytes_or_hex(&sk.pk().encode(), output_hex);
        }
        X25519Action::CheckConsistency => {
            let sk = parse_sk(&read_from_file_or_stdin(skfile));
            let pk = parse_pk(&read_pkfile(pkfile));

            match X25519::keypair_consistency_check(&pk, &sk) {
                Ok(_) => {
                    crate::helpers::println_stdout("SUCCESS: pk and sk match.");
                }
                Err(_) => {
                    eprintln!("FAILURE: pk and sk do not match.");
                    exit(-1);
                }
            }
        }
        X25519Action::Agree => {
            let sk = parse_sk(&read_from_file_or_stdin(skfile));
            let pk = parse_pk(&read_pkfile(pkfile));

            let ss = match X25519::key_agreement(&pk, &sk) {
                Ok(ss) => ss,
                Err(e) => {
                    eprintln!("Error: {:?}", e);
                    exit(-1);
                }
            };
            write_bytes_or_hex(ss.as_ref(), output_hex);
        }
        X25519Action::Encaps => {
            let pk = parse_pk(&read_from_file_or_stdin(pkfile));

            let (ss, ct) = match X25519::encaps(&pk) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Error: {:?}", e);
                    exit(-1);
                }
            };

            if ctfile.is_some() {
                // write ct to file and ss to stdout
                write_bytes_or_hex_to_file(&ct, ctfile.as_ref().unwrap(), output_hex);
                write_bytes_or_hex(ss.ref_to_bytes(), output_hex);
            } else {
                // write both to stdout in hex, separated by a newline.
                write_bytes_or_hex(&ct, true);
                crate::helpers::write_stdout(b"\n");
                write_bytes_or_hex(ss.ref_to_bytes(), true);
            }
        }
        X25519Action::Decaps => {
            let sk = match skfile {
                Some(f) => parse_sk(&read_from_file(f)),
                None => {
                    eprintln!("Error: no skfile provided.");
                    exit(-1);
                }
            };

            let ct = read_from_file_or_stdin(ctfile);
            if ct.len() != POINT_SIZE {
                eprintln!("Error: ciphertext is not the correct length.");
                exit(-1);
            }

            let ss = match X25519::decaps(&sk, &ct) {
                Ok(ss) => ss,
                Err(e) => {
                    eprintln!("Error: {:?}", e);
                    exit(-1);
                }
            };
            write_bytes_or_hex(ss.ref_to_bytes(), output_hex);
        }
    }
}

fn read_pkfile(pkfile: &Option<String>) -> Vec<u8> {
    match pkfile {
        Some(f) => read_from_file(f),
        None => {
            eprintln!("Error: no pkfile provided.");
            exit(-1);
        }
    }
}

fn parse_sk(bytes: &[u8]) -> X25519PrivateKey {
    match X25519PrivateKey::from_bytes(bytes) {
        Ok(sk) => sk,
        Err(_) => {
            eprintln!("Error: couldn't parse the input as a 32-byte X25519 private key.");
            exit(-1);
        }
    }
}

fn parse_pk(bytes: &[u8]) -> X25519PublicKey {
    match X25519PublicKey::from_bytes(bytes) {
        Ok(pk) => pk,
        Err(_) => {
            eprintln!("Error: couldn't parse the input as a 32-byte X25519 public key.");
            exit(-1);
        }
    }
}
