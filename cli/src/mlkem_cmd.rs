//! Yup, this file is as absolutely atrocious mess of duplicate code that could be much improved
//! by using generics or macros. I just, haven't ... yet.

use crate::helpers::{
    parse_seed, read_from_file, read_from_file_or_stdin, write_bytes_or_hex,
    write_bytes_or_hex_to_file,
};
use bouncycastle::core::key_material::KeyMaterialTrait;
use bouncycastle::core::traits::{KEMDecapsulator, KEMEncapsulator, KEMPrivateKey, KEMPublicKey};
use bouncycastle::hex;
use bouncycastle::mlkem::{
    MLKEM512, MLKEM512_CT_LEN, MLKEM512_PK_LEN, MLKEM512_SK_LEN, MLKEM512PrivateKey,
    MLKEM512PublicKey, MLKEM768, MLKEM768_CT_LEN, MLKEM768_PK_LEN, MLKEM768_SK_LEN,
    MLKEM768PrivateKey, MLKEM768PublicKey, MLKEM1024, MLKEM1024_CT_LEN, MLKEM1024_PK_LEN,
    MLKEM1024_SK_LEN, MLKEM1024PrivateKey, MLKEM1024PublicKey, MLKEMPrivateKeyTrait, MLKEMTrait,
};
use clap::ValueEnum;
use std::process::exit;

#[derive(ValueEnum, Clone, Debug)]
pub(crate) enum MLKEMAction {
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
    /// Perform an encapsulation with a public key and output the shared secret key and
    /// the ciphertext.
    /// If a ctfile is provided, then the shared secret key is output to std out in either binary or hex
    /// and the ciphertext to file also in binary or hex.
    /// If no ctfile is provided then ct followed by ss are output to stdout in hex, separated by a newline.
    /// The shared secret is always output to stdout to prevent it
    /// staying in a file longer than it should and causing a vulnerability.
    /// Accepts private key as full or seed, binary or hex.
    Encaps,
    /// Perform a decapsulation with a private key and ciphertext and output the shared secret key to stdout either in
    /// binary or hex.
    /// The ciphertext can be read either from ctfile or stdin, in binary or hex.
    /// Accepts the public key and signature as binary or hex.
    Decaps,
}

pub(crate) fn mlkem512_cmd(
    action: &MLKEMAction,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    ctfile: &Option<String>,
    output_hex: bool,
) {
    match action {
        MLKEMAction::Keygen => {
            let (_pk, sk) = MLKEM512::keygen().unwrap();
            write_bytes_or_hex(&sk.encode(), output_hex);
        }
        MLKEMAction::KeygenFromSeed => {
            let buf = read_from_file_or_stdin(skfile);
            let seed = parse_seed(&buf).unwrap();

            let (_pk, sk) = MLKEM512::keygen_from_seed(&seed).unwrap();
            write_bytes_or_hex(&sk.encode(), output_hex);
        }
        MLKEMAction::PkFromSk => {
            let buf = read_from_file_or_stdin(skfile);
            let sk = match parse_mlkem512_sk(&buf) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            write_bytes_or_hex(&sk.pk().encode(), output_hex);
        }
        MLKEMAction::CheckConsistency => {
            let buf = read_from_file_or_stdin(skfile);
            let sk = match parse_mlkem512_sk(buf.as_slice()) {
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
            let pk = match parse_mlkem512_pk(pk_bytes.as_slice()) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            match MLKEM512::keypair_consistency_check(&pk, &sk) {
                Ok(_) => {
                    println!("SUCCESS: pk and sk match.");
                }
                Err(_) => {
                    eprintln!("FAILURE: pk and sk do not match.");
                    exit(-1);
                }
            }
        }
        MLKEMAction::Encaps => {
            // first, read the pk
            let pk_bytes = read_from_file_or_stdin(pkfile);
            let pk = match parse_mlkem512_pk(pk_bytes.as_slice()) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            let (ss, ct) = MLKEM512::encaps(&pk).unwrap();

            if ctfile.is_some() {
                // write ct to file and ss to stdout
                write_bytes_or_hex_to_file(&ct, ctfile.as_ref().unwrap(), output_hex);
                write_bytes_or_hex(ss.ref_to_bytes(), output_hex);
            } else {
                // write both to stdout in hex, separated by a newline.
                write_bytes_or_hex(&ct, true);
                println!();
                write_bytes_or_hex(ss.ref_to_bytes(), true);
            }
        }
        MLKEMAction::Decaps => {
            // first, read the sk
            let sk_bytes = read_from_file_or_stdin(skfile);

            let sk = match parse_mlkem512_sk(sk_bytes.as_slice()) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            let ct_vec = read_from_file_or_stdin(ctfile);
            if ct_vec.len() != MLKEM512_CT_LEN {
                eprintln!("Error: ciphertexts is not the correct length.");
                exit(-1);
            }

            let ct: [u8; MLKEM512_CT_LEN] = ct_vec.try_into().unwrap();

            let ss = match MLKEM512::decaps(&sk, &ct) {
                Ok(ss) => ss,
                Err(estr) => {
                    eprintln!("{:?}", estr);
                    exit(-1);
                }
            };

            write_bytes_or_hex(ss.ref_to_bytes(), output_hex);
        }
    }
}

pub(crate) fn mlkem768_cmd(
    action: &MLKEMAction,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    ctfile: &Option<String>,
    output_hex: bool,
) {
    match action {
        MLKEMAction::Keygen => {
            let (_pk, sk) = MLKEM768::keygen().unwrap();
            write_bytes_or_hex(&sk.encode(), output_hex);
        }
        MLKEMAction::KeygenFromSeed => {
            let buf = read_from_file_or_stdin(skfile);
            let seed = parse_seed(&buf).unwrap();

            let (_pk, sk) = MLKEM768::keygen_from_seed(&seed).unwrap();
            write_bytes_or_hex(&sk.encode(), output_hex);
        }
        MLKEMAction::PkFromSk => {
            let buf = read_from_file_or_stdin(skfile);
            let sk = match parse_mlkem768_sk(&buf) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            write_bytes_or_hex(&sk.pk().encode(), output_hex);
        }
        MLKEMAction::CheckConsistency => {
            let buf = read_from_file_or_stdin(skfile);
            let sk = match parse_mlkem768_sk(buf.as_slice()) {
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
            let pk = match parse_mlkem768_pk(pk_bytes.as_slice()) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            match MLKEM768::keypair_consistency_check(&pk, &sk) {
                Ok(_) => {
                    println!("SUCCESS: pk and sk match.");
                }
                Err(_) => {
                    eprintln!("FAILURE: pk and sk do not match.");
                    exit(-1);
                }
            }
        }
        MLKEMAction::Encaps => {
            // first, read the pk
            let pk_bytes = read_from_file_or_stdin(pkfile);
            let pk = match parse_mlkem768_pk(pk_bytes.as_slice()) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            let (ss, ct) = MLKEM768::encaps(&pk).unwrap();

            if ctfile.is_some() {
                // write ct to file and ss to stdout
                write_bytes_or_hex_to_file(&ct, ctfile.as_ref().unwrap(), output_hex);
                write_bytes_or_hex(ss.ref_to_bytes(), output_hex);
            } else {
                // write both to stdout in hex, separated by a newline.
                write_bytes_or_hex(&ct, true);
                println!();
                write_bytes_or_hex(ss.ref_to_bytes(), true);
            }
        }
        MLKEMAction::Decaps => {
            // first, read the sk
            let sk_bytes = read_from_file_or_stdin(skfile);

            let sk = match parse_mlkem768_sk(sk_bytes.as_slice()) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            let ct_vec = read_from_file_or_stdin(ctfile);
            if ct_vec.len() != MLKEM768_CT_LEN {
                eprintln!("Error: ciphertexts is not the correct length.");
                exit(-1);
            }

            let ct: [u8; MLKEM768_CT_LEN] = ct_vec.try_into().unwrap();

            let ss = match MLKEM768::decaps(&sk, &ct) {
                Ok(ss) => ss,
                Err(estr) => {
                    eprintln!("{:?}", estr);
                    exit(-1);
                }
            };

            write_bytes_or_hex(ss.ref_to_bytes(), output_hex);
        }
    }
}

pub(crate) fn mlkem1024_cmd(
    action: &MLKEMAction,
    skfile: &Option<String>,
    pkfile: &Option<String>,
    ctfile: &Option<String>,
    output_hex: bool,
) {
    match action {
        MLKEMAction::Keygen => {
            let (_pk, sk) = MLKEM512::keygen().unwrap();
            write_bytes_or_hex(&sk.encode(), output_hex);
        }
        MLKEMAction::KeygenFromSeed => {
            let buf = read_from_file_or_stdin(skfile);
            let seed = parse_seed(&buf).unwrap();

            let (_pk, sk) = MLKEM1024::keygen_from_seed(&seed).unwrap();
            write_bytes_or_hex(&sk.encode(), output_hex);
        }
        MLKEMAction::PkFromSk => {
            let buf = read_from_file_or_stdin(skfile);
            let sk = match parse_mlkem1024_sk(&buf) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            write_bytes_or_hex(&sk.pk().encode(), output_hex);
        }
        MLKEMAction::CheckConsistency => {
            let buf = read_from_file_or_stdin(skfile);
            let sk = match parse_mlkem1024_sk(buf.as_slice()) {
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
            let pk = match parse_mlkem1024_pk(pk_bytes.as_slice()) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            match MLKEM1024::keypair_consistency_check(&pk, &sk) {
                Ok(_) => {
                    println!("SUCCESS: pk and sk match.");
                }
                Err(_) => {
                    eprintln!("FAILURE: pk and sk do not match.");
                    exit(-1);
                }
            }
        }
        MLKEMAction::Encaps => {
            // first, read the pk
            let pk_bytes = read_from_file_or_stdin(pkfile);
            let pk = match parse_mlkem1024_pk(pk_bytes.as_slice()) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            let (ss, ct) = MLKEM1024::encaps(&pk).unwrap();

            if ctfile.is_some() {
                // write ct to file and ss to stdout
                write_bytes_or_hex_to_file(&ct, ctfile.as_ref().unwrap(), output_hex);
                write_bytes_or_hex(ss.ref_to_bytes(), output_hex);
            } else {
                // write both to stdout in hex, separated by a newline.
                write_bytes_or_hex(&ct, true);
                println!();
                write_bytes_or_hex(ss.ref_to_bytes(), true);
            }
        }
        MLKEMAction::Decaps => {
            // first, read the sk
            let sk_bytes = read_from_file_or_stdin(skfile);

            let sk = match parse_mlkem1024_sk(sk_bytes.as_slice()) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            let ct_vec = read_from_file_or_stdin(ctfile);
            if ct_vec.len() != MLKEM1024_CT_LEN {
                eprintln!("Error: ciphertexts is not the correct length.");
                exit(-1);
            }

            let ct: [u8; MLKEM1024_CT_LEN] = ct_vec.try_into().unwrap();

            let ss = match MLKEM1024::decaps(&sk, &ct) {
                Ok(ss) => ss,
                Err(estr) => {
                    eprintln!("{:?}", estr);
                    exit(-1);
                }
            };

            write_bytes_or_hex(ss.ref_to_bytes(), output_hex);
        }
    }
}

fn parse_mlkem512_sk(bytes: &[u8]) -> Result<MLKEM512PrivateKey, &'static str> {
    // try it in Biggest -> Smallest order

    // try it as a hex'd full key
    if bytes.len() >= 2 * MLKEM512_SK_LEN {
        let maybe_sk = hex::decode(&bytes[..2 * MLKEM512_SK_LEN]);
        if maybe_sk.is_ok() {
            // it was hex
            let sk = MLKEM512PrivateKey::from_bytes(&maybe_sk.unwrap());
            if sk.is_ok() {
                return Ok(sk.unwrap());
            } // else: keep trying things
        }
    }

    // try it as a binary full key
    if bytes.len() == MLKEM512_SK_LEN {
        let sk = MLKEM512PrivateKey::from_bytes(&bytes);
        if sk.is_ok() {
            return Ok(sk.unwrap());
        }
    } // else: keep trying things

    // try it as a seed
    let seed = parse_seed(bytes);
    if seed.is_ok() {
        let maybe_sk = MLKEM512::keygen_from_seed(&seed.unwrap());
        if maybe_sk.is_ok() {
            let (_pk, sk) = maybe_sk.unwrap();
            return Ok(sk);
        } // else: we're out of things to try
    }

    Err("Error: couldn't parse the input as a valid ML-KEM-512 private key or seed.")
}

fn parse_mlkem512_pk(bytes: &[u8]) -> Result<MLKEM512PublicKey, &'static str> {
    // try it in Biggest -> Smallest order

    // try it as a hex'd full key
    if bytes.len() >= 2 * MLKEM512_PK_LEN {
        let maybe_pk = hex::decode(&bytes[..2 * MLKEM512_PK_LEN]);
        if maybe_pk.is_ok() {
            // it was hex
            let pk = MLKEM512PublicKey::from_bytes(&maybe_pk.unwrap());
            if pk.is_ok() {
                return Ok(pk.unwrap());
            } // else: keep trying things
        }
    }

    // try it as a binary full key
    if bytes.len() == MLKEM512_PK_LEN {
        let pk = MLKEM512PublicKey::from_bytes(&bytes);
        if pk.is_ok() {
            return Ok(pk.unwrap());
        }
    } // else: we're out of things to try

    Err("Error: couldn't parse the input as a valid ML-KEM-768 public key.")
}

fn parse_mlkem768_sk(bytes: &[u8]) -> Result<MLKEM768PrivateKey, &'static str> {
    // try it in Biggest -> Smallest order

    // try it as a hex'd full key
    if bytes.len() >= 2 * MLKEM768_SK_LEN {
        let maybe_sk = hex::decode(&bytes[..2 * MLKEM768_SK_LEN]);
        if maybe_sk.is_ok() {
            // it was hex
            let sk = MLKEM768PrivateKey::from_bytes(&maybe_sk.unwrap());
            if sk.is_ok() {
                return Ok(sk.unwrap());
            } // else: keep trying things
        }
    }

    // try it as a binary full key
    if bytes.len() == MLKEM768_SK_LEN {
        let sk = MLKEM768PrivateKey::from_bytes(&bytes);
        if sk.is_ok() {
            return Ok(sk.unwrap());
        }
    } // else: keep trying things

    // try it as a seed
    let seed = parse_seed(bytes);
    if seed.is_ok() {
        let maybe_sk = MLKEM768::keygen_from_seed(&seed.unwrap());
        if maybe_sk.is_ok() {
            let (_pk, sk) = maybe_sk.unwrap();
            return Ok(sk);
        } // else: we're out of things to try
    }

    Err("Error: couldn't parse the input as a valid ML-KEM-768 private key or seed.")
}

fn parse_mlkem768_pk(bytes: &[u8]) -> Result<MLKEM768PublicKey, &'static str> {
    // try it in Biggest -> Smallest order

    // try it as a hex'd full key
    if bytes.len() >= 2 * MLKEM768_PK_LEN {
        let maybe_pk = hex::decode(&bytes[..2 * MLKEM512_PK_LEN]);
        if maybe_pk.is_ok() {
            // it was hex
            let pk = MLKEM768PublicKey::from_bytes(&maybe_pk.unwrap());
            if pk.is_ok() {
                return Ok(pk.unwrap());
            } // else: keep trying things
        }
    }

    // try it as a binary full key
    if bytes.len() == MLKEM768_PK_LEN {
        let pk = MLKEM768PublicKey::from_bytes(&bytes);
        if pk.is_ok() {
            return Ok(pk.unwrap());
        }
    } // else: we're out of things to try

    Err("Error: couldn't parse the input as a valid ML-KEM-768 public key.")
}

fn parse_mlkem1024_sk(bytes: &[u8]) -> Result<MLKEM1024PrivateKey, &'static str> {
    // try it in Biggest -> Smallest order

    // try it as a hex'd full key
    if bytes.len() >= 2 * MLKEM1024_SK_LEN {
        let maybe_sk = hex::decode(&bytes[..2 * MLKEM1024_SK_LEN]);
        if maybe_sk.is_ok() {
            // it was hex
            let sk = MLKEM1024PrivateKey::from_bytes(&maybe_sk.unwrap());
            if sk.is_ok() {
                return Ok(sk.unwrap());
            } // else: keep trying things
        }
    }

    // try it as a binary full key
    if bytes.len() == MLKEM1024_SK_LEN {
        let sk = MLKEM1024PrivateKey::from_bytes(&bytes);
        if sk.is_ok() {
            return Ok(sk.unwrap());
        }
    } // else: keep trying things

    // try it as a seed
    let seed = parse_seed(bytes);
    if seed.is_ok() {
        let maybe_sk = MLKEM1024::keygen_from_seed(&seed.unwrap());
        if maybe_sk.is_ok() {
            let (_pk, sk) = maybe_sk.unwrap();
            return Ok(sk);
        } // else: we're out of things to try
    }

    Err("Error: couldn't parse the input as a valid ML-KEM-1024 private key or seed.")
}

fn parse_mlkem1024_pk(bytes: &[u8]) -> Result<MLKEM1024PublicKey, &'static str> {
    // try it in Biggest -> Smallest order

    // try it as a hex'd full key
    if bytes.len() >= 2 * MLKEM1024_PK_LEN {
        let maybe_pk = hex::decode(&bytes[..2 * MLKEM1024_PK_LEN]);
        if maybe_pk.is_ok() {
            // it was hex
            let pk = MLKEM1024PublicKey::from_bytes(&maybe_pk.unwrap());
            if pk.is_ok() {
                return Ok(pk.unwrap());
            } // else: keep trying things
        }
    }

    // try it as a binary full key
    if bytes.len() == MLKEM1024_PK_LEN {
        let pk = MLKEM1024PublicKey::from_bytes(&bytes);
        if pk.is_ok() {
            return Ok(pk.unwrap());
        }
    } // else: we're out of things to try

    Err("Error: couldn't parse the input as a valid ML-KEM-1024 public key.")
}
