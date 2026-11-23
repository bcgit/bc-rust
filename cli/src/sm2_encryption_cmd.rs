//! CLI wiring for `bouncycastle_ec::sm2::encryption`: the `sm2-encryption` command. The key
//! files are those of `sm2` (a 32-byte private key, a 65-byte or compressed public key), read
//! here as the encryption key types.
//!
//! # This command does not stream, and cannot
//!
//! Decryption has no plaintext to release until `C3`, a hash over the whole message, has been
//! checked, and encryption computes `C3` from the whole message and writes it ahead of `C2` in
//! the default order. So stdin is read to the end, once, and processed where it lies by the
//! detached in-place methods, with no second buffer the size of the input; `decrypt` writes
//! nothing unless the ciphertext verified. Memory use is proportional to the input.
//!
//! As for the `*-ccm` commands, stdin is raw bytes in both directions whatever `--hex-input`
//! says, which is for the key files, and `-x` writes hex followed by a newline.

use crate::helpers::{
    SecretBytes, read_input_file, read_secret_file, read_secret_file_or_stdin,
    read_secret_stdin_all, read_stdin_all, wipe, write_bytes_or_hex, write_private_key,
    write_secret_bytes_or_hex, write_stdout,
};
use bouncycastle::core::errors::PublicKeyEncryptionError;
use bouncycastle::core::key_material::KeyMaterialTrait;
use bouncycastle::core::traits::{PrivateKey, PublicKey};
use bouncycastle::ec::sm2::encryption::{
    C1_LEN, C3_LEN, SM2EncryptionPrivateKey, SM2EncryptionPublicKey, keygen,
};
use bouncycastle::rng::HashDRBG_SHA512;
use clap::ValueEnum;
use std::process::exit;

#[derive(ValueEnum, Clone, Debug)]
pub(crate) enum SM2EncryptionAction {
    /// Generate and output a new private key.
    Keygen,
    /// Derive and output the public key matching a private key read from --skfile or stdin.
    PkFromSk,
    /// Encrypt the message on stdin (raw bytes, not empty) to the public key in --pkfile.
    Encrypt,
    /// Decrypt the ciphertext on stdin (raw bytes) with the private key in --skfile. Nothing
    /// is written unless the ciphertext verifies.
    Decrypt,
}

pub(crate) fn sm2_encryption_cmd(
    action: &SM2EncryptionAction,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    c1c2c3: bool,
    output_hex: bool,
) {
    match action {
        SM2EncryptionAction::Keygen => {
            let (_pk, sk) = keygen(&mut HashDRBG_SHA512::new_from_os()).unwrap();
            write_private_key(&sk, output_hex);
        }
        SM2EncryptionAction::PkFromSk => {
            // A failed write exits, and `exit` runs no destructors, so the key is dropped first.
            let pk = {
                let sk = parse_sk(read_secret_file_or_stdin(skfile));
                sk.derive_pk()
            };
            write_bytes_or_hex(&pk.encode(), output_hex);
        }
        SM2EncryptionAction::Encrypt => {
            let pk = parse_pk(&read_input_file(required(pkfile, "pkfile")));
            // See the module docs on why this is not a streaming command.
            let mut buf = read_secret_stdin_all();
            match pk.encrypt_detached_inplace(&mut HashDRBG_SHA512::new_from_os(), &mut buf) {
                Ok((c1, c3)) => {
                    // `buf` is C2 now.
                    write_bytes_or_hex(&c1, output_hex);
                    if c1c2c3 {
                        write_bytes_or_hex(&buf, output_hex);
                        write_bytes_or_hex(&c3, output_hex);
                    } else {
                        write_bytes_or_hex(&c3, output_hex);
                        write_bytes_or_hex(&buf, output_hex);
                    }
                    if output_hex {
                        write_stdout(b"\n");
                    }
                }
                Err(e) => {
                    // After an error the buffer holds the message as it was given.
                    wipe(&mut buf);
                    match e {
                        PublicKeyEncryptionError::InvalidInputLength(_) if buf.is_empty() => {
                            eprintln!(
                                "Error: the message is empty; SM2 encrypts at least one byte."
                            )
                        }
                        e => eprintln!("Error: SM2 encryption failed: {e:?}"),
                    }
                    exit(-1);
                }
            }
        }
        SM2EncryptionAction::Decrypt => {
            let skfile = required(skfile, "skfile");
            // See the module docs on why this is not a streaming command. The ciphertext is
            // read before the key is loaded, so that a failed read exits with no key held.
            let mut input = read_stdin_all();
            // An input too short to hold C1, C3 and a byte of C2 is a ciphertext that does not
            // decrypt, and is reported as every other one is.
            let parts = input.split_first_chunk_mut::<C1_LEN>().and_then(|(c1, rest)| {
                let (c3, c2) = if c1c2c3 {
                    let (c2, c3) = rest.split_last_chunk_mut::<C3_LEN>()?;
                    (*c3, c2)
                } else {
                    let (c3, c2) = rest.split_first_chunk_mut::<C3_LEN>()?;
                    (*c3, c2)
                };
                // C1 and C3 are copied out, 97 bytes; C2 is decrypted where it lies.
                Some((*c1, c3, c2))
            });
            // `exit` runs no destructors, so the key is dropped before the result is looked at.
            // The library refuses an empty `c2`, and zeroizes `c2` on any error.
            let message = {
                let sk = parse_sk(read_secret_file(skfile));
                parts.and_then(|(c1, c3, c2)| {
                    sk.decrypt_detached_inplace(&c1, &c3, c2).is_ok().then_some(c2)
                })
            };
            let Some(c2) = message else { decryption_failed() };
            write_secret_bytes_or_hex(c2, output_hex);
            if output_hex {
                write_stdout(b"\n");
            }
            wipe(c2);
        }
    }
}

/// The one message for every ciphertext that does not decrypt, whatever is wrong with it.
fn decryption_failed() -> ! {
    eprintln!("Error: SM2 decryption failed.");
    exit(-1)
}

fn required<'a>(file: &'a Option<String>, flag_name: &str) -> &'a str {
    match file {
        Some(f) => f,
        None => {
            eprintln!("Error: no {flag_name} provided.");
            exit(-1);
        }
    }
}

/// The private key in `bytes`, which are dropped, and so wiped, before a failure exits.
fn parse_sk(bytes: SecretBytes) -> SM2EncryptionPrivateKey {
    let parsed = SM2EncryptionPrivateKey::from_bytes(bytes.ref_to_bytes());
    drop(bytes);
    match parsed {
        Ok(sk) => sk,
        Err(_) => {
            eprintln!("Error: couldn't parse the input as a valid SM2 private key.");
            exit(-1);
        }
    }
}

fn parse_pk(bytes: &[u8]) -> SM2EncryptionPublicKey {
    match SM2EncryptionPublicKey::from_bytes(bytes) {
        Ok(pk) => pk,
        Err(_) => {
            eprintln!("Error: couldn't parse the input as a valid SM2 public key.");
            exit(-1);
        }
    }
}
