//! Yup, this file is as absolutely atrocious mess of duplicate code that could be much improved
//! by using generics or macros. I just, haven't ... yet.

use crate::helpers::{parse_seed, read_from_file, read_from_file_or_stdin, write_bytes_or_hex};
use bouncycastle::core::traits::{SignatureVerifier, Signer, SignaturePrivateKey, SignaturePublicKey};
use bouncycastle::hex;
use bouncycastle::mldsa::{MLDSA_SEED_LEN, MLDSA44, MLDSA44_SK_LEN, MLDSA44PrivateKey, MLDSA87_SK_LEN, MLDSAPrivateKeyTrait, MLDSATrait, MLDSA44PublicKey, MLDSA44_PK_LEN, MLDSA65_SK_LEN, MLDSA65PrivateKey, MLDSA65, MLDSA65PublicKey, MLDSA65_PK_LEN, MLDSA87PrivateKey, MLDSA87, MLDSA87PublicKey, MLDSA87_PK_LEN, HashMLDSA44_with_SHA512, HashMLDSA65_with_SHA512, HashMLDSA87_with_SHA512};
use std::{io};
use std::io::{Read};
use std::process::exit;
use clap::ValueEnum;

#[derive(ValueEnum, Clone, Debug)]
pub(crate) enum MLDSAAction {
    /// Generate and output a new private key
    Keygen,
    /// Generate and output a private key from a seed read from stdin.
    /// Accepts either binary or hex.
    KeygenFromSeed,
    /// Generate and output a new public key from a private key read from stdin.
    /// Accepts either binary or hex.
    PkFromSk,
    /// Accepts a sk and pk, and checks that they match.
    CheckConsistency,
    /// Sign a message read from stdin with a private key file and output the signature.
    /// Accepts private key as full or seed, binary or hex.
    Sign,
    /// Verify a message read from stdin with a public key file and a signature file
    /// Accepts the public key and signature as binary or hex.
    Verify,
}

pub(crate) fn mldsa44_cmd(
    action: &MLDSAAction,
    ctxfile: &Option<String>,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    sigfile: &Option<String>,
    output_hex: bool,
) {
    match action {
        MLDSAAction::Keygen => {
            let (_pk, sk) = MLDSA44::keygen().unwrap();
            write_bytes_or_hex(&sk.encode(), output_hex);
        }
        MLDSAAction::KeygenFromSeed => {
            let buf = read_from_file_or_stdin(skfile);
            let seed = match parse_seed::<MLDSA_SEED_LEN>(&buf) {
                Ok(seed) => seed,
                Err(()) => {
                    eprintln!("Error: input could not be parsed as a {} byte seed in either hex or bin", MLDSA_SEED_LEN);
                    exit(-1);
                }
            };

            let (_pk, sk) = MLDSA44::keygen_from_seed(&seed).unwrap();
            write_bytes_or_hex(&sk.encode(), output_hex);
        }
        MLDSAAction::PkFromSk => {
            let buf = read_from_file_or_stdin(skfile);
            let sk = match parse_mldsa44_sk(&buf) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            write_bytes_or_hex(&sk.derive_pk().encode(), output_hex);
        }
        MLDSAAction::CheckConsistency => {
            let buf = read_from_file_or_stdin(skfile);
            let sk = match parse_mldsa44_sk(&buf) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            // first, read the pk
            let pk_bytes = if pkfile.is_some() {
                read_from_file(pkfile.as_ref().unwrap())
            } else {
                eprintln!("Error: no pkfile provided.");
                exit(-1);
            };
            let pk = match parse_mldsa44_pk(&pk_bytes) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            match MLDSA44::keypair_consistency_check(&pk, &sk) {
                Ok(_) => { println!("SUCCESS: pk and sk match."); }
                Err(_) => {
                    eprintln!("FAILURE: pk and sk do not match.");
                    exit(-1);
                }
            }
        }
        MLDSAAction::Sign => {
            // first, read the sk
            let sk_bytes = if skfile.is_some() {
                read_from_file(skfile.as_ref().unwrap())
            } else {
                eprintln!("Error: no skfile provided.");
                exit(-1);
            };

            // then read ctx
            let ctx = if ctxfile.is_some() {
                read_from_file(ctxfile.as_ref().unwrap())
            } else { vec![0u8;0] };

            // and now sign, streaming the message from stdin
            let sk = match parse_mldsa44_sk(&sk_bytes) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };
            let mut signer = MLDSA44::sign_init(&sk, Some(&ctx)).unwrap();

            let mut buf = [0u8; 1024];
            let mut bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
            signer.sign_update(&buf[..bytes_read]);
            while bytes_read != 0 {
                bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
                signer.sign_update(&buf[..bytes_read]);
            }

            let sig = signer.sign_final().unwrap();

            write_bytes_or_hex(&sig, output_hex);
        }
        MLDSAAction::Verify => {
            // first, read the pk
            let pk_bytes = if pkfile.is_some() {
                read_from_file(pkfile.as_ref().unwrap())
            } else {
                eprintln!("Error: no pkfile provided.");
                exit(-1);
            };
            let pk = match parse_mldsa44_pk(&pk_bytes) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            // then read ctx
            let ctx = if ctxfile.is_some() {
                read_from_file(ctxfile.as_ref().unwrap())
            } else { vec![0u8;0] };

            // then read the sig
            let sig = if sigfile.is_some() {
                read_from_file(sigfile.as_ref().unwrap())
            } else {
                eprintln!("Error: no sigfile provided.");
                exit(-1);
            };

            // and now verify, streaming the message from stdin
            let mut verifier = MLDSA44::verify_init(&pk, Some(&ctx)).unwrap();

            let mut buf = [0u8; 1024];
            let mut bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
            verifier.verify_update(&buf[..bytes_read]);
            while bytes_read != 0 {
                bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
                verifier.verify_update(&buf[..bytes_read]);
            }

            let sig = verifier.verify_final(&sig);

            if sig.is_ok() {
                println!("Signature is valid.");
            } else {
                eprintln!("Signature is invalid.");
                exit(-1);
            }
        },
    }
}

pub(crate) fn mldsa65_cmd(
    action: &MLDSAAction,
    ctxfile: &Option<String>,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    sigfile: &Option<String>,
    output_hex: bool,
) {
    match action {
        MLDSAAction::Keygen => {
            let (_pk, sk) = MLDSA65::keygen().unwrap();
            write_bytes_or_hex(&sk.encode(), output_hex);
        }
        MLDSAAction::KeygenFromSeed => {
            let buf = read_from_file_or_stdin(skfile);
            let seed = parse_seed(&buf).unwrap();

            let (_pk, sk) = MLDSA65::keygen_from_seed(&seed).unwrap();
            write_bytes_or_hex(&sk.encode(), output_hex);
        }
        MLDSAAction::PkFromSk => {
            let buf = read_from_file_or_stdin(skfile);
            let sk = match parse_mldsa65_sk(&buf) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            write_bytes_or_hex(&sk.derive_pk().encode(), output_hex);
        }
        MLDSAAction::CheckConsistency => {
            let buf = read_from_file_or_stdin(skfile);
            let sk = match parse_mldsa65_sk(&buf) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            // first, read the pk
            let pk_bytes = if pkfile.is_some() {
                read_from_file(pkfile.as_ref().unwrap())
            } else {
                eprintln!("Error: no pkfile provided.");
                exit(-1);
            };
            let pk = match parse_mldsa65_pk(&pk_bytes) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            match MLDSA65::keypair_consistency_check(&pk, &sk) {
                Ok(_) => { println!("SUCCESS: pk and sk match."); }
                Err(_) => {
                    eprintln!("FAILURE: pk and sk do not match.");
                    exit(-1);
                }
            }
        }
        MLDSAAction::Sign => {
            // first, read the sk
            let sk_bytes = if skfile.is_some() {
                read_from_file(skfile.as_ref().unwrap())
            } else {
                eprintln!("Error: no skfile provided.");
                exit(-1);
            };

            // then read ctx
            let ctx = if ctxfile.is_some() {
                read_from_file(ctxfile.as_ref().unwrap())
            } else { vec![0u8;0] };

            // and now sign, streaming the message from stdin
            let sk = match parse_mldsa65_sk(&sk_bytes) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };
            let mut signer = MLDSA65::sign_init(&sk, Some(&ctx)).unwrap();

            let mut buf = [0u8; 1024];
            let mut bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
            signer.sign_update(&buf[..bytes_read]);
            while bytes_read != 0 {
                bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
                signer.sign_update(&buf[..bytes_read]);
            }

            let sig = signer.sign_final().unwrap();

            write_bytes_or_hex(&sig, output_hex);
        }
        MLDSAAction::Verify => {
            // first, read the pk
            let pk_bytes = if pkfile.is_some() {
                read_from_file(pkfile.as_ref().unwrap())
            } else {
                eprintln!("Error: no pkfile provided.");
                exit(-1);
            };
            let pk = match parse_mldsa65_pk(&pk_bytes) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            // then read ctx
            let ctx = if ctxfile.is_some() {
                read_from_file(ctxfile.as_ref().unwrap())
            } else { vec![0u8;0] };

            // then read the sig
            let sig = if sigfile.is_some() {
                read_from_file(sigfile.as_ref().unwrap())
            } else {
                eprintln!("Error: no sigfile provided.");
                exit(-1);
            };

            // and now verify, streaming the message from stdin
            let mut verifier = MLDSA65::verify_init(&pk, Some(&ctx)).unwrap();

            let mut buf = [0u8; 1024];
            let mut bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
            verifier.verify_update(&buf[..bytes_read]);
            while bytes_read != 0 {
                bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
                verifier.verify_update(&buf[..bytes_read]);
            }

            let sig = verifier.verify_final(&sig);

            if sig.is_ok() {
                println!("Signature is valid.");
            } else {
                eprintln!("Signature is invalid.");
                exit(-1);
            }
        },
    }
}
pub(crate) fn mldsa87_cmd(
    action: &MLDSAAction,
    ctxfile: &Option<String>,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    sigfile: &Option<String>,
    output_hex: bool,
) {
    match action {
        MLDSAAction::Keygen => {
            let (_pk, sk) = MLDSA87::keygen().unwrap();
            write_bytes_or_hex(&sk.encode(), output_hex);
        }
        MLDSAAction::KeygenFromSeed => {
            let buf = read_from_file_or_stdin(skfile);
            let seed = parse_seed(&buf).unwrap();

            let (_pk, sk) = MLDSA87::keygen_from_seed(&seed).unwrap();
            write_bytes_or_hex(&sk.encode(), output_hex);
        }
        MLDSAAction::PkFromSk => {
            let buf = read_from_file_or_stdin(skfile);
            let sk = match parse_mldsa87_sk(&buf) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            write_bytes_or_hex(&sk.derive_pk().encode(), output_hex);
        }
        MLDSAAction::CheckConsistency => {
            let buf = read_from_file_or_stdin(skfile);
            let sk = match parse_mldsa87_sk(&buf) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };


            // first, read the pk
            let pk_bytes = if pkfile.is_some() {
                read_from_file(pkfile.as_ref().unwrap())
            } else {
                eprintln!("Error: no pkfile provided.");
                exit(-1);
            };
            let pk = match parse_mldsa87_pk(&pk_bytes) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            match MLDSA87::keypair_consistency_check(&pk, &sk) {
                Ok(_) => { println!("SUCCESS: pk and sk match."); }
                Err(_) => {
                    eprintln!("FAILURE: pk and sk do not match.");
                    exit(-1);
                }
            }
        }
        MLDSAAction::Sign => {
            // first, read the sk
            let sk_bytes = if skfile.is_some() {
                read_from_file(skfile.as_ref().unwrap())
            } else {
                eprintln!("Error: no skfile provided.");
                exit(-1);
            };

            // then read ctx
            let ctx = if ctxfile.is_some() {
                read_from_file(ctxfile.as_ref().unwrap())
            } else { vec![0u8;0] };

            // and now sign, streaming the message from stdin
            let sk = match parse_mldsa87_sk(&sk_bytes) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };
            let mut signer = MLDSA87::sign_init(&sk, Some(&ctx)).unwrap();

            let mut buf = [0u8; 1024];
            let mut bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
            signer.sign_update(&buf[..bytes_read]);
            while bytes_read != 0 {
                bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
                signer.sign_update(&buf[..bytes_read]);
            }

            let sig = signer.sign_final().unwrap();

            write_bytes_or_hex(&sig, output_hex);
        }
        MLDSAAction::Verify => {
            // first, read the pk
            let pk_bytes = if pkfile.is_some() {
                read_from_file(pkfile.as_ref().unwrap())
            } else {
                eprintln!("Error: no pkfile provided.");
                exit(-1);
            };
            let pk = match parse_mldsa87_pk(&pk_bytes) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            // then read ctx
            let ctx = if ctxfile.is_some() {
                read_from_file(ctxfile.as_ref().unwrap())
            } else { vec![0u8;0] };

            // then read the sig
            let sig = if sigfile.is_some() {
                read_from_file(sigfile.as_ref().unwrap())
            } else {
                eprintln!("Error: no sigfile provided.");
                exit(-1);
            };

            // and now verify, streaming the message from stdin
            let mut verifier = MLDSA87::verify_init(&pk, Some(&ctx)).unwrap();

            let mut buf = [0u8; 1024];
            let mut bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
            verifier.verify_update(&buf[..bytes_read]);
            while bytes_read != 0 {
                bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
                verifier.verify_update(&buf[..bytes_read]);
            }

            let sig = verifier.verify_final(&sig);

            if sig.is_ok() {
                println!("Signature is valid.");
            } else {
                eprintln!("Signature is invalid.");
                exit(-1);
            }
        },
    }
}

pub(crate) fn hash_mldsa44_sha512_cmd(
    action: &MLDSAAction,
    ctxfile: &Option<String>,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    sigfile: &Option<String>,
    output_hex: bool,
) {
    match action {
        MLDSAAction::Keygen => {
            let (_pk, sk) = HashMLDSA44_with_SHA512::keygen().unwrap();
            write_bytes_or_hex(&sk.encode(), output_hex);
        }
        MLDSAAction::KeygenFromSeed => {
            let buf = read_from_file_or_stdin(skfile);
            let seed = parse_seed(&buf).unwrap();

            let (_pk, sk) = HashMLDSA44_with_SHA512::keygen_from_seed(&seed).unwrap();
            write_bytes_or_hex(&sk.encode(), output_hex);
        }
        MLDSAAction::PkFromSk => {
            let buf = read_from_file_or_stdin(skfile);
            let sk = match parse_mldsa44_sk(&buf) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            write_bytes_or_hex(&sk.derive_pk().encode(), output_hex);
        }
        MLDSAAction::CheckConsistency => {
            let buf = read_from_file_or_stdin(skfile);
            let sk = match parse_mldsa44_sk(&buf) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            // first, read the pk
            let pk_bytes = if pkfile.is_some() {
                read_from_file(pkfile.as_ref().unwrap())
            } else {
                eprintln!("Error: no pkfile provided.");
                exit(-1);
            };
            let pk = match parse_mldsa44_pk(&pk_bytes) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            match MLDSA44::keypair_consistency_check(&pk, &sk) {
                Ok(_) => { println!("SUCCESS: pk and sk match."); }
                Err(_) => {
                    eprintln!("FAILURE: pk and sk do not match.");
                    exit(-1);
                }
            }
        }
        MLDSAAction::Sign => {
            // first, read the sk
            let sk_bytes = if skfile.is_some() {
                read_from_file(skfile.as_ref().unwrap())
            } else {
                eprintln!("Error: no skfile provided.");
                exit(-1);
            };

            // then read ctx
            let ctx = if ctxfile.is_some() {
                read_from_file(ctxfile.as_ref().unwrap())
            } else { vec![0u8;0] };

            // and now sign, streaming the message from stdin
            let sk = match parse_mldsa44_sk(&sk_bytes) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };
            let mut signer = HashMLDSA44_with_SHA512::sign_init(&sk, Some(&ctx)).unwrap();

            let mut buf = [0u8; 1024];
            let mut bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
            signer.sign_update(&buf[..bytes_read]);
            while bytes_read != 0 {
                bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
                signer.sign_update(&buf[..bytes_read]);
            }

            let sig = signer.sign_final().unwrap();

            write_bytes_or_hex(&sig, output_hex);
        }
        MLDSAAction::Verify => {
            // first, read the pk
            let pk_bytes = if pkfile.is_some() {
                read_from_file(pkfile.as_ref().unwrap())
            } else {
                eprintln!("Error: no pkfile provided.");
                exit(-1);
            };
            let pk = match parse_mldsa44_pk(&pk_bytes) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            // then read ctx
            let ctx = if ctxfile.is_some() {
                read_from_file(ctxfile.as_ref().unwrap())
            } else { vec![0u8;0] };

            // then read the sig
            let sig = if sigfile.is_some() {
                read_from_file(sigfile.as_ref().unwrap())
            } else {
                eprintln!("Error: no sigfile provided.");
                exit(-1);
            };

            // and now verify, streaming the message from stdin
            let mut verifier = HashMLDSA44_with_SHA512::verify_init(&pk, Some(&ctx)).unwrap();

            let mut buf = [0u8; 1024];
            let mut bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
            verifier.verify_update(&buf[..bytes_read]);
            while bytes_read != 0 {
                bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
                verifier.verify_update(&buf[..bytes_read]);
            }

            let sig = verifier.verify_final(&sig);

            if sig.is_ok() {
                println!("Signature is valid.");
            } else {
                eprintln!("Signature is invalid.");
                exit(-1);
            }
        },
    }
}

pub(crate) fn hash_mldsa65_sha512_cmd(
    action: &MLDSAAction,
    ctxfile: &Option<String>,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    sigfile: &Option<String>,
    output_hex: bool,
) {
    match action {
        MLDSAAction::Keygen => {
            let (_pk, sk) = MLDSA65::keygen().unwrap();
            write_bytes_or_hex(&sk.encode(), output_hex);
        }
        MLDSAAction::KeygenFromSeed => {
            let buf = read_from_file_or_stdin(skfile);
            let seed = parse_seed(&buf).unwrap();

            let (_pk, sk) = MLDSA65::keygen_from_seed(&seed).unwrap();
            write_bytes_or_hex(&sk.encode(), output_hex);
        }
        MLDSAAction::PkFromSk => {
            let buf = read_from_file_or_stdin(skfile);
            let sk = match parse_mldsa65_sk(&buf) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            write_bytes_or_hex(&sk.derive_pk().encode(), output_hex);
        }
        MLDSAAction::CheckConsistency => {
            let buf = read_from_file_or_stdin(skfile);
            let sk = match parse_mldsa65_sk(&buf) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            // first, read the pk
            let pk_bytes = if pkfile.is_some() {
                read_from_file(pkfile.as_ref().unwrap())
            } else {
                eprintln!("Error: no pkfile provided.");
                exit(-1);
            };
            let pk = match parse_mldsa65_pk(&pk_bytes) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            match MLDSA65::keypair_consistency_check(&pk, &sk) {
                Ok(_) => { println!("SUCCESS: pk and sk match."); }
                Err(_) => {
                    eprintln!("FAILURE: pk and sk do not match.");
                    exit(-1);
                }
            }
        }
        MLDSAAction::Sign => {
            // first, read the sk
            let sk_bytes = if skfile.is_some() {
                read_from_file(skfile.as_ref().unwrap())
            } else {
                eprintln!("Error: no skfile provided.");
                exit(-1);
            };

            // then read ctx
            let ctx = if ctxfile.is_some() {
                read_from_file(ctxfile.as_ref().unwrap())
            } else { vec![0u8;0] };

            // and now sign, streaming the message from stdin
            let sk = match parse_mldsa65_sk(&sk_bytes) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };
            let mut signer = HashMLDSA65_with_SHA512::sign_init(&sk, Some(&ctx)).unwrap();

            let mut buf = [0u8; 1024];
            let mut bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
            signer.sign_update(&buf[..bytes_read]);
            while bytes_read != 0 {
                bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
                signer.sign_update(&buf[..bytes_read]);
            }

            let sig = signer.sign_final().unwrap();

            write_bytes_or_hex(&sig, output_hex);
        }
        MLDSAAction::Verify => {
            // first, read the pk
            let pk_bytes = if pkfile.is_some() {
                read_from_file(pkfile.as_ref().unwrap())
            } else {
                eprintln!("Error: no pkfile provided.");
                exit(-1);
            };
            let pk = match parse_mldsa65_pk(&pk_bytes) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            // then read ctx
            let ctx = if ctxfile.is_some() {
                read_from_file(ctxfile.as_ref().unwrap())
            } else { vec![0u8;0] };

            // then read the sig
            let sig = if sigfile.is_some() {
                read_from_file(sigfile.as_ref().unwrap())
            } else {
                eprintln!("Error: no sigfile provided.");
                exit(-1);
            };

            // and now verify, streaming the message from stdin
            let mut verifier = HashMLDSA65_with_SHA512::verify_init(&pk, Some(&ctx)).unwrap();

            let mut buf = [0u8; 1024];
            let mut bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
            verifier.verify_update(&buf[..bytes_read]);
            while bytes_read != 0 {
                bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
                verifier.verify_update(&buf[..bytes_read]);
            }

            let sig = verifier.verify_final(&sig);

            if sig.is_ok() {
                println!("Signature is valid.");
            } else {
                eprintln!("Signature is invalid.");
                exit(-1);
            }
        },
    }
}
pub(crate) fn hash_mldsa87_sha512_cmd(
    action: &MLDSAAction,
    ctxfile: &Option<String>,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    sigfile: &Option<String>,
    output_hex: bool,
) {
    match action {
        MLDSAAction::Keygen => {
            let (_pk, sk) = MLDSA87::keygen().unwrap();
            write_bytes_or_hex(&sk.encode(), output_hex);
        }
        MLDSAAction::KeygenFromSeed => {
            let buf = read_from_file_or_stdin(skfile);
            let seed = parse_seed(&buf).unwrap();

            let (_pk, sk) = MLDSA87::keygen_from_seed(&seed).unwrap();
            write_bytes_or_hex(&sk.encode(), output_hex);
        }
        MLDSAAction::PkFromSk => {
            let buf = read_from_file_or_stdin(skfile);
            let sk = match parse_mldsa87_sk(&buf) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            write_bytes_or_hex(&sk.derive_pk().encode(), output_hex);
        }
        MLDSAAction::CheckConsistency => {
            let buf = read_from_file_or_stdin(skfile);
            let sk = match parse_mldsa87_sk(&buf) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            // first, read the pk
            let pk_bytes = if pkfile.is_some() {
                read_from_file(pkfile.as_ref().unwrap())
            } else {
                eprintln!("Error: no pkfile provided.");
                exit(-1);
            };
            let pk = match parse_mldsa87_pk(&pk_bytes) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            match MLDSA87::keypair_consistency_check(&pk, &sk) {
                Ok(_) => { println!("SUCCESS: pk and sk match."); }
                Err(_) => {
                    eprintln!("FAILURE: pk and sk do not match.");
                    exit(-1);
                }
            }
        }
        MLDSAAction::Sign => {
            // first, read the sk
            let sk_bytes = if skfile.is_some() {
                read_from_file(skfile.as_ref().unwrap())
            } else {
                eprintln!("Error: no skfile provided.");
                exit(-1);
            };

            // then read ctx
            let ctx = if ctxfile.is_some() {
                read_from_file(ctxfile.as_ref().unwrap())
            } else { vec![0u8;0] };

            // and now sign, streaming the message from stdin
            let sk = match parse_mldsa87_sk(&sk_bytes) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };
            let mut signer = HashMLDSA87_with_SHA512::sign_init(&sk, Some(&ctx)).unwrap();

            let mut buf = [0u8; 1024];
            let mut bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
            signer.sign_update(&buf[..bytes_read]);
            while bytes_read != 0 {
                bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
                signer.sign_update(&buf[..bytes_read]);
            }

            let sig = signer.sign_final().unwrap();

            write_bytes_or_hex(&sig, output_hex);
        }
        MLDSAAction::Verify => {
            // first, read the pk
            let pk_bytes = if pkfile.is_some() {
                read_from_file(pkfile.as_ref().unwrap())
            } else {
                eprintln!("Error: no pkfile provided.");
                exit(-1);
            };
            let pk = match parse_mldsa87_pk(&pk_bytes) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            // then read ctx
            let ctx = if ctxfile.is_some() {
                read_from_file(ctxfile.as_ref().unwrap())
            } else { vec![0u8;0] };

            // then read the sig
            let sig = if sigfile.is_some() {
                read_from_file(sigfile.as_ref().unwrap())
            } else {
                eprintln!("Error: no sigfile provided.");
                exit(-1);
            };

            // and now verify, streaming the message from stdin
            let mut verifier = HashMLDSA87_with_SHA512::verify_init(&pk, Some(&ctx)).unwrap();

            let mut buf = [0u8; 1024];
            let mut bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
            verifier.verify_update(&buf[..bytes_read]);
            while bytes_read != 0 {
                bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
                verifier.verify_update(&buf[..bytes_read]);
            }

            let sig = verifier.verify_final(&sig);

            if sig.is_ok() {
                println!("Signature is valid.");
            } else {
                eprintln!("Signature is invalid.");
                exit(-1);
            }
        },
    }
}

fn parse_mldsa44_sk(bytes: &[u8]) -> Result<MLDSA44PrivateKey, &'static str> {
    // try it in Biggest -> Smallest order

    // try it as a hex'd full key
    if bytes.len() >= 2 * MLDSA44_SK_LEN {
        let maybe_sk = hex::decode(&bytes[..2 * MLDSA44_SK_LEN]);
        if maybe_sk.is_ok() {
            // it was hex
            let sk = MLDSA44PrivateKey::from_bytes(&maybe_sk.unwrap());
            if sk.is_ok() {
                return Ok(sk.unwrap());
            } // else: keep trying things
        }
    }

    // try it as a binary full key
    if bytes.len() == MLDSA44_SK_LEN {
        let sk = MLDSA44PrivateKey::from_bytes(&bytes);
        if sk.is_ok() {
            return Ok(sk.unwrap());
        }
    } // else: keep trying things

    // try it as a seed
    let seed = parse_seed(bytes);
    if seed.is_ok() {
        let maybe_sk = MLDSA44::keygen_from_seed(&seed.unwrap());
        if maybe_sk.is_ok() {
            let (_pk, sk) = maybe_sk.unwrap();
            return Ok(sk);
        } // else: we're out of things to try
    }

    Err("Error: couldn't parse the input as a valid ML-DSA-44 private key or seed.")
}

fn parse_mldsa44_pk(bytes: &[u8]) -> Result<MLDSA44PublicKey, &'static str> {
    // try it in Biggest -> Smallest order

    // try it as a hex'd full key
    if bytes.len() >= 2 * MLDSA44_PK_LEN {
        let maybe_pk = hex::decode(&bytes[..2 * MLDSA44_PK_LEN]);
        if maybe_pk.is_ok() {
            // it was hex
            let pk = MLDSA44PublicKey::from_bytes(&maybe_pk.unwrap());
            if pk.is_ok() {
                return Ok(pk.unwrap());
            } // else: keep trying things
        }
    }

    // try it as a binary full key
    if bytes.len() == MLDSA44_PK_LEN {
        let pk = MLDSA44PublicKey::from_bytes(&bytes);
        if pk.is_ok() {
            return Ok(pk.unwrap());
        }
    } // else: we're out of things to try

    Err("Error: couldn't parse the input as a valid ML-DSA-44 public key.")
}

fn parse_mldsa65_sk(bytes: &[u8]) -> Result<MLDSA65PrivateKey, &'static str> {
    // try it in Biggest -> Smallest order

    // try it as a hex'd full key
    if bytes.len() >= 2 * MLDSA65_SK_LEN {
        let maybe_sk = hex::decode(&bytes[..2 * MLDSA65_SK_LEN]);
        if maybe_sk.is_ok() {
            // it was hex
            let sk = MLDSA65PrivateKey::from_bytes(&maybe_sk.unwrap());
            if sk.is_ok() {
                return Ok(sk.unwrap());
            } // else: keep trying things
        }
    }

    // try it as a binary full key
    if bytes.len() == MLDSA65_SK_LEN {
        let sk = MLDSA65PrivateKey::from_bytes(&bytes);
        if sk.is_ok() {
            return Ok(sk.unwrap());
        }
    } // else: keep trying things

    // try it as a seed
    let seed = parse_seed(bytes);
    if seed.is_ok() {
        let maybe_sk = MLDSA65::keygen_from_seed(&seed.unwrap());
        if maybe_sk.is_ok() {
            let (_pk, sk) = maybe_sk.unwrap();
            return Ok(sk);
        } // else: we're out of things to try
    }

    Err("Error: couldn't parse the input as a valid ML-DSA-65 private key or seed.")
}

fn parse_mldsa65_pk(bytes: &[u8]) -> Result<MLDSA65PublicKey, &'static str> {
    // try it in Biggest -> Smallest order

    // try it as a hex'd full key
    if bytes.len() >= 2 * MLDSA65_PK_LEN {
        let maybe_pk = hex::decode(&bytes[..2 * MLDSA65_PK_LEN]);
        if maybe_pk.is_ok() {
            // it was hex
            let pk = MLDSA65PublicKey::from_bytes(&maybe_pk.unwrap());
            if pk.is_ok() {
                return Ok(pk.unwrap());
            } // else: keep trying things
        }
    }

    // try it as a binary full key
    if bytes.len() == MLDSA65_PK_LEN {
        let pk = MLDSA65PublicKey::from_bytes(&bytes);
        if pk.is_ok() {
            return Ok(pk.unwrap());
        }
    } // else: we're out of things to try

    Err("Error: couldn't parse the input as a valid ML-DSA-65 public key or seed.")
}

fn parse_mldsa87_sk(bytes: &[u8]) -> Result<MLDSA87PrivateKey, &'static str> {
    // try it in Biggest -> Smallest order

    // try it as a hex'd full key
    if bytes.len() >= 2 * MLDSA87_SK_LEN {
        let maybe_sk = hex::decode(&bytes[..2 * MLDSA87_SK_LEN]);
        if maybe_sk.is_ok() {
            // it was hex
            let sk = MLDSA87PrivateKey::from_bytes(&maybe_sk.unwrap());
            if sk.is_ok() {
                return Ok(sk.unwrap());
            } // else: keep trying things
        }
    }

    // try it as a binary full key
    if bytes.len() == MLDSA87_SK_LEN {
        let sk = MLDSA87PrivateKey::from_bytes(&bytes);
        if sk.is_ok() {
            return Ok(sk.unwrap());
        }
    } // else: keep trying things

    // try it as a seed
    let seed = parse_seed(bytes);
    if seed.is_ok() {
        let maybe_sk = MLDSA87::keygen_from_seed(&seed.unwrap());
        if maybe_sk.is_ok() {
            let (_pk, sk) = maybe_sk.unwrap();
            return Ok(sk);
        } // else: we're out of things to try
    }

    Err("Error: couldn't parse the input as a valid ML-DSA-87 private key.")
}

fn parse_mldsa87_pk(bytes: &[u8]) -> Result<MLDSA87PublicKey, &'static str> {
    // try it in Biggest -> Smallest order

    // try it as a hex'd full key
    if bytes.len() >= 2 * MLDSA87_PK_LEN {
        let maybe_pk = hex::decode(&bytes[..2 * MLDSA87_PK_LEN]);
        if maybe_pk.is_ok() {
            // it was hex
            let pk = MLDSA87PublicKey::from_bytes(&maybe_pk.unwrap());
            if pk.is_ok() {
                return Ok(pk.unwrap());
            } // else: keep trying things
        }
    }

    // try it as a binary full key
    if bytes.len() == MLDSA87_PK_LEN {
        let pk = MLDSA87PublicKey::from_bytes(&bytes);
        if pk.is_ok() {
            return Ok(pk.unwrap());
        }
    } // else: we're out of things to try

    Err("Error: couldn't parse the input as a valid ML-DSA-87 public key.")
}