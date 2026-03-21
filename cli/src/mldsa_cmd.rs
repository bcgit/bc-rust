//! Yup, this file is as absolutely atrocious mess of duplicate code that could be much improved
//! by using generics or macros. I just, haven't ... yet.

use crate::{MLDSAAction, write_bytes_or_hex};
use bouncycastle::core_interface::key_material::{KeyMaterial256, KeyType};
use bouncycastle::core_interface::traits::{
    KeyMaterial, SecurityStrength, Signature, SignaturePrivateKey, SignaturePublicKey,
};
use bouncycastle::hex;
use bouncycastle::mldsa::{MLDSA44, MLDSA44_SK_LEN, MLDSA44PrivateKey, MLDSA87_SK_LEN, MLDSAPrivateKeyTrait, MLDSATrait, MLDSA44PublicKey, MLDSA44_PK_LEN, MLDSA65_SK_LEN, MLDSA65PrivateKey, MLDSA65, MLDSA65PublicKey, MLDSA65_PK_LEN, MLDSA87PrivateKey, MLDSA87, MLDSA87PublicKey, MLDSA87_PK_LEN, HashMLDSA44_with_SHA512, HashMLDSA65_with_SHA512, HashMLDSA87_with_SHA512};
use std::{fs, io};
use std::io::{Read};
use std::process::exit;

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
            let mut buf = [0u8; 100]; // comfortably above a hex'd seed
            let bytes_read = read_from_file_or_stdin(skfile, &mut buf);
            let seed = parse_seed(&buf[..bytes_read]).unwrap();

            let (_pk, sk) = MLDSA44::keygen_from_seed(&seed).unwrap();
            write_bytes_or_hex(&sk.encode(), output_hex);
        }
        MLDSAAction::PkFromSk => {
            let mut buf = [0u8; 2*2560+1];
            let bytes_read = read_from_file_or_stdin(skfile, &mut buf);
            let sk = match parse_mldsa44_sk(&buf[..bytes_read]) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            write_bytes_or_hex(&sk.derive_pk().encode(), output_hex);
        }
        MLDSAAction::CheckConsistency => {
            let mut buf = [0u8; 2*2560+1];
            let bytes_read = read_from_file_or_stdin(skfile, &mut buf);
            let sk = match parse_mldsa44_sk(&buf[..bytes_read]) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            // first, read the pk
            let mut pk_bytes = [0u8; 2*1312+1];
            let pk_len: usize;
            if pkfile.is_some() {
                pk_len = read_from_file(pkfile.as_ref().unwrap(), &mut pk_bytes);
            } else {
                eprintln!("Error: no pkfile provided.");
                exit(-1);
            }
            let pk = match parse_mldsa44_pk(&pk_bytes[..pk_len]) {
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
            let mut sk_bytes = [0u8; 2*2560+1];
            let sk_len: usize;
            if skfile.is_some() {
                sk_len = read_from_file(skfile.as_ref().unwrap(), &mut sk_bytes);
            } else {
                eprintln!("Error: no skfile provided.");
                exit(-1);
            }

            // then read ctx
            let ctx = if ctxfile.is_some() {
                let mut ctxbuf = [0u8; 2*255];
                let bytes_read = read_from_file(ctxfile.as_ref().unwrap(), &mut ctxbuf);
                match hex::decode(&ctxbuf[..bytes_read]) {
                    Ok(ctx) => ctx,
                    Err(_) => {
                        eprintln!("Error: couldn't parse the input as a valid context.");
                        exit(-1);
                    }
                }
            } else { vec![0u8;0] };

            // and now sign, streaming the message from stdin
            let sk = match parse_mldsa44_sk(&sk_bytes[..sk_len]) {
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
            let mut pk_bytes = [0u8; 2*1312+1];
            let pk_len: usize;
            if pkfile.is_some() {
                pk_len = read_from_file(pkfile.as_ref().unwrap(), &mut pk_bytes);
            } else {
                eprintln!("Error: no pkfile provided.");
                exit(-1);
            }
            let pk = match parse_mldsa44_pk(&pk_bytes[..pk_len]) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            // then read ctx
            let ctx = if ctxfile.is_some() {
                let mut ctxbuf = [0u8; 2*255+1];
                let bytes_read = read_from_file(ctxfile.as_ref().unwrap(), &mut ctxbuf);
                match hex::decode(&ctxbuf[..bytes_read]) {
                    Ok(ctx) => ctx,
                    Err(_) => {
                        eprintln!("Error: couldn't parse the input as a valid ctx.");
                        exit(-1);
                    }
                }
            } else { vec![0u8;0] };

            // then read the sig
            let sig = if sigfile.is_some() {
                let mut sigbuf = [0u8; 2 * 2420];
                let bytes_read = read_from_file(sigfile.as_ref().unwrap(), &mut sigbuf);

                // first try hex, by length
                match hex::decode(&sigbuf[..bytes_read]) {
                    Ok(sig) => sig,
                    Err(_) => {
                        Vec::from(&sigbuf[..bytes_read])
                    },
                }
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
            let mut buf = [0u8; 100]; // comfortably above a hex'd seed
            let bytes_read = read_from_file_or_stdin(skfile, &mut buf);
            let seed = parse_seed(&buf[..bytes_read]).unwrap();

            let (_pk, sk) = MLDSA65::keygen_from_seed(&seed).unwrap();
            write_bytes_or_hex(&sk.encode(), output_hex);
        }
        MLDSAAction::PkFromSk => {
            let mut buf = [0u8; 2*4032+1];
            let bytes_read = read_from_file_or_stdin(skfile, &mut buf);
            let sk = match parse_mldsa65_sk(&buf[..bytes_read]) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            write_bytes_or_hex(&sk.derive_pk().encode(), output_hex);
        }
        MLDSAAction::CheckConsistency => {
            let mut buf = [0u8; 2*4032+1];
            let bytes_read = read_from_file_or_stdin(skfile, &mut buf);
            let sk = match parse_mldsa65_sk(&buf[..bytes_read]) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            // first, read the pk
            let mut pk_bytes = [0u8; 2*1952+1];
            let pk_len: usize;
            if pkfile.is_some() {
                pk_len = read_from_file(pkfile.as_ref().unwrap(), &mut pk_bytes);
            } else {
                eprintln!("Error: no pkfile provided.");
                exit(-1);
            }
            let pk = match parse_mldsa65_pk(&pk_bytes[..pk_len]) {
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
            let mut sk_bytes = [0u8; 2*4032+1];
            let sk_len: usize;
            if skfile.is_some() {
                sk_len = read_from_file(skfile.as_ref().unwrap(), &mut sk_bytes);
            } else {
                eprintln!("Error: no skfile provided.");
                exit(-1);
            }

            // then read ctx
            let ctx = if ctxfile.is_some() {
                let mut ctxbuf = [0u8; 2*255];
                let bytes_read = read_from_file(ctxfile.as_ref().unwrap(), &mut ctxbuf);
                match hex::decode(&ctxbuf[..bytes_read]) {
                    Ok(ctx) => ctx,
                    Err(_) => {
                        eprintln!("Error: couldn't parse the input as a valid context.");
                        exit(-1);
                    }
                }
            } else { vec![0u8;0] };

            // and now sign, streaming the message from stdin
            let sk = match parse_mldsa65_sk(&sk_bytes[..sk_len]) {
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
            let mut pk_bytes = [0u8; 2*1952+1];
            let pk_len: usize;
            if pkfile.is_some() {
                pk_len = read_from_file(pkfile.as_ref().unwrap(), &mut pk_bytes);
            } else {
                eprintln!("Error: no pkfile provided.");
                exit(-1);
            }
            let pk = match parse_mldsa65_pk(&pk_bytes[..pk_len]) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            // then read ctx
            let ctx = if ctxfile.is_some() {
                let mut ctxbuf = [0u8; 2*255+1];
                let bytes_read = read_from_file(ctxfile.as_ref().unwrap(), &mut ctxbuf);
                match hex::decode(&ctxbuf[..bytes_read]) {
                    Ok(ctx) => ctx,
                    Err(_) => {
                        eprintln!("Error: couldn't parse the input as a valid ctx.");
                        exit(-1);
                    }
                }
            } else { vec![0u8;0] };

            // then read the sig
            let sig = if sigfile.is_some() {
                let mut sigbuf = [0u8; 2 * 3309];
                let bytes_read = read_from_file(sigfile.as_ref().unwrap(), &mut sigbuf);

                // first try hex, by length
                match hex::decode(&sigbuf[..bytes_read]) {
                    Ok(sig) => sig,
                    Err(_) => {
                        Vec::from(&sigbuf[..bytes_read])
                    },
                }
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
            let mut buf = [0u8; 100]; // comfortably above a hex'd seed
            let bytes_read = read_from_file_or_stdin(skfile, &mut buf);
            let seed = parse_seed(&buf[..bytes_read]).unwrap();

            let (_pk, sk) = MLDSA87::keygen_from_seed(&seed).unwrap();
            write_bytes_or_hex(&sk.encode(), output_hex);
        }
        MLDSAAction::PkFromSk => {
            let mut buf = [0u8; 2*4627+1];
            let bytes_read = read_from_file_or_stdin(skfile, &mut buf);
            let sk = match parse_mldsa87_sk(&buf[..bytes_read]) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            write_bytes_or_hex(&sk.derive_pk().encode(), output_hex);
        }
        MLDSAAction::CheckConsistency => {
            let mut buf = [0u8; 2*4627+1];
            let bytes_read = read_from_file_or_stdin(skfile, &mut buf);
            let sk = match parse_mldsa87_sk(&buf[..bytes_read]) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };


            // first, read the pk
            let mut pk_bytes = [0u8; 2*2592+1];
            let pk_len: usize;
            if pkfile.is_some() {
                pk_len = read_from_file(pkfile.as_ref().unwrap(), &mut pk_bytes);
            } else {
                eprintln!("Error: no pkfile provided.");
                exit(-1);
            }
            let pk = match parse_mldsa87_pk(&pk_bytes[..pk_len]) {
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
            let mut sk_bytes = [0u8; 2*4627+1];
            let sk_len: usize;
            if skfile.is_some() {
                sk_len = read_from_file(skfile.as_ref().unwrap(), &mut sk_bytes);
            } else {
                eprintln!("Error: no skfile provided.");
                exit(-1);
            }

            // then read ctx
            let ctx = if ctxfile.is_some() {
                let mut ctxbuf = [0u8; 2*255];
                let bytes_read = read_from_file(ctxfile.as_ref().unwrap(), &mut ctxbuf);
                match hex::decode(&ctxbuf[..bytes_read]) {
                    Ok(ctx) => ctx,
                    Err(_) => {
                        eprintln!("Error: couldn't parse the input as a valid context.");
                        exit(-1);
                    }
                }
            } else { vec![0u8;0] };

            // and now sign, streaming the message from stdin
            let sk = match parse_mldsa87_sk(&sk_bytes[..sk_len]) {
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
            let mut pk_bytes = [0u8; 2*2592+1];
            let pk_len: usize;
            if pkfile.is_some() {
                pk_len = read_from_file(pkfile.as_ref().unwrap(), &mut pk_bytes);
            } else {
                eprintln!("Error: no pkfile provided.");
                exit(-1);
            }
            let pk = match parse_mldsa87_pk(&pk_bytes[..pk_len]) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            // then read ctx
            let ctx = if ctxfile.is_some() {
                let mut ctxbuf = [0u8; 2*255+1];
                let bytes_read = read_from_file(ctxfile.as_ref().unwrap(), &mut ctxbuf);
                match hex::decode(&ctxbuf[..bytes_read]) {
                    Ok(ctx) => ctx,
                    Err(_) => {
                        eprintln!("Error: couldn't parse the input as a valid ctx.");
                        exit(-1);
                    }
                }
            } else { vec![0u8;0] };

            // then read the sig
            let sig = if sigfile.is_some() {
                let mut sigbuf = [0u8; 2 * 4627];
                let bytes_read = read_from_file(sigfile.as_ref().unwrap(), &mut sigbuf);

                // first try hex, by length
                match hex::decode(&sigbuf[..bytes_read]) {
                    Ok(sig) => sig,
                    Err(_) => {
                        Vec::from(&sigbuf[..bytes_read])
                    },
                }
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
            let mut buf = [0u8; 100]; // comfortably above a hex'd seed
            let bytes_read = read_from_file_or_stdin(skfile, &mut buf);
            let seed = parse_seed(&buf[..bytes_read]).unwrap();

            let (_pk, sk) = HashMLDSA44_with_SHA512::keygen_from_seed(&seed).unwrap();
            write_bytes_or_hex(&sk.encode(), output_hex);
        }
        MLDSAAction::PkFromSk => {
            let mut buf = [0u8; 2*2560+1];
            let bytes_read = read_from_file_or_stdin(skfile, &mut buf);
            let sk = match parse_mldsa44_sk(&buf[..bytes_read]) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            write_bytes_or_hex(&sk.derive_pk().encode(), output_hex);
        }
        MLDSAAction::CheckConsistency => {
            let mut buf = [0u8; 2*2560+1];
            let bytes_read = read_from_file_or_stdin(skfile, &mut buf);
            let sk = match parse_mldsa44_sk(&buf[..bytes_read]) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            // first, read the pk
            let mut pk_bytes = [0u8; 2*1312+1];
            let pk_len: usize;
            if pkfile.is_some() {
                pk_len = read_from_file(pkfile.as_ref().unwrap(), &mut pk_bytes);
            } else {
                eprintln!("Error: no pkfile provided.");
                exit(-1);
            }
            let pk = match parse_mldsa44_pk(&pk_bytes[..pk_len]) {
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
            let mut sk_bytes = [0u8; 2*2560+1];
            let sk_len: usize;
            if skfile.is_some() {
                sk_len = read_from_file(skfile.as_ref().unwrap(), &mut sk_bytes);
            } else {
                eprintln!("Error: no skfile provided.");
                exit(-1);
            }

            // then read ctx
            let ctx = if ctxfile.is_some() {
                let mut ctxbuf = [0u8; 2*255];
                let bytes_read = read_from_file(ctxfile.as_ref().unwrap(), &mut ctxbuf);
                match hex::decode(&ctxbuf[..bytes_read]) {
                    Ok(ctx) => ctx,
                    Err(_) => {
                        eprintln!("Error: couldn't parse the input as a valid context.");
                        exit(-1);
                    }
                }
            } else { vec![0u8;0] };

            // and now sign, streaming the message from stdin
            let sk = match parse_mldsa44_sk(&sk_bytes[..sk_len]) {
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
            let mut pk_bytes = [0u8; 2*1312+1];
            let pk_len: usize;
            if pkfile.is_some() {
                pk_len = read_from_file(pkfile.as_ref().unwrap(), &mut pk_bytes);
            } else {
                eprintln!("Error: no pkfile provided.");
                exit(-1);
            }
            let pk = match parse_mldsa44_pk(&pk_bytes[..pk_len]) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            // then read ctx
            let ctx = if ctxfile.is_some() {
                let mut ctxbuf = [0u8; 2*255+1];
                let bytes_read = read_from_file(ctxfile.as_ref().unwrap(), &mut ctxbuf);
                match hex::decode(&ctxbuf[..bytes_read]) {
                    Ok(ctx) => ctx,
                    Err(_) => {
                        eprintln!("Error: couldn't parse the input as a valid ctx.");
                        exit(-1);
                    }
                }
            } else { vec![0u8;0] };

            // then read the sig
            let sig = if sigfile.is_some() {
                let mut sigbuf = [0u8; 2 * 2420];
                let bytes_read = read_from_file(sigfile.as_ref().unwrap(), &mut sigbuf);

                // first try hex, by length
                match hex::decode(&sigbuf[..bytes_read]) {
                    Ok(sig) => sig,
                    Err(_) => {
                        Vec::from(&sigbuf[..bytes_read])
                    },
                }
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
            let mut buf = [0u8; 100]; // comfortably above a hex'd seed
            let bytes_read = read_from_file_or_stdin(skfile, &mut buf);
            let seed = parse_seed(&buf[..bytes_read]).unwrap();

            let (_pk, sk) = MLDSA65::keygen_from_seed(&seed).unwrap();
            write_bytes_or_hex(&sk.encode(), output_hex);
        }
        MLDSAAction::PkFromSk => {
            let mut buf = [0u8; 2*4032+1];
            let bytes_read = read_from_file_or_stdin(skfile, &mut buf);
            let sk = match parse_mldsa65_sk(&buf[..bytes_read]) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            write_bytes_or_hex(&sk.derive_pk().encode(), output_hex);
        }
        MLDSAAction::CheckConsistency => {
            let mut buf = [0u8; 2*4032+1];
            let bytes_read = read_from_file_or_stdin(skfile, &mut buf);
            let sk = match parse_mldsa65_sk(&buf[..bytes_read]) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            // first, read the pk
            let mut pk_bytes = [0u8; 2*1952+1];
            let pk_len: usize;
            if pkfile.is_some() {
                pk_len = read_from_file(pkfile.as_ref().unwrap(), &mut pk_bytes);
            } else {
                eprintln!("Error: no pkfile provided.");
                exit(-1);
            }
            let pk = match parse_mldsa65_pk(&pk_bytes[..pk_len]) {
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
            let mut sk_bytes = [0u8; 2*4032+1];
            let sk_len: usize;
            if skfile.is_some() {
                sk_len = read_from_file(skfile.as_ref().unwrap(), &mut sk_bytes);
            } else {
                eprintln!("Error: no skfile provided.");
                exit(-1);
            }

            // then read ctx
            let ctx = if ctxfile.is_some() {
                let mut ctxbuf = [0u8; 2*255];
                let bytes_read = read_from_file(ctxfile.as_ref().unwrap(), &mut ctxbuf);
                match hex::decode(&ctxbuf[..bytes_read]) {
                    Ok(ctx) => ctx,
                    Err(_) => {
                        eprintln!("Error: couldn't parse the input as a valid context.");
                        exit(-1);
                    }
                }
            } else { vec![0u8;0] };

            // and now sign, streaming the message from stdin
            let sk = match parse_mldsa65_sk(&sk_bytes[..sk_len]) {
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
            let mut pk_bytes = [0u8; 2*1952+1];
            let pk_len: usize;
            if pkfile.is_some() {
                pk_len = read_from_file(pkfile.as_ref().unwrap(), &mut pk_bytes);
            } else {
                eprintln!("Error: no pkfile provided.");
                exit(-1);
            }
            let pk = match parse_mldsa65_pk(&pk_bytes[..pk_len]) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            // then read ctx
            let ctx = if ctxfile.is_some() {
                let mut ctxbuf = [0u8; 2*255+1];
                let bytes_read = read_from_file(ctxfile.as_ref().unwrap(), &mut ctxbuf);
                match hex::decode(&ctxbuf[..bytes_read]) {
                    Ok(ctx) => ctx,
                    Err(_) => {
                        eprintln!("Error: couldn't parse the input as a valid ctx.");
                        exit(-1);
                    }
                }
            } else { vec![0u8;0] };

            // then read the sig
            let sig = if sigfile.is_some() {
                let mut sigbuf = [0u8; 2 * 3309];
                let bytes_read = read_from_file(sigfile.as_ref().unwrap(), &mut sigbuf);

                // first try hex, by length
                match hex::decode(&sigbuf[..bytes_read]) {
                    Ok(sig) => sig,
                    Err(_) => {
                        Vec::from(&sigbuf[..bytes_read])
                    },
                }
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
            let mut buf = [0u8; 100]; // comfortably above a hex'd seed
            let bytes_read = read_from_file_or_stdin(skfile, &mut buf);
            let seed = parse_seed(&buf[..bytes_read]).unwrap();

            let (_pk, sk) = MLDSA87::keygen_from_seed(&seed).unwrap();
            write_bytes_or_hex(&sk.encode(), output_hex);
        }
        MLDSAAction::PkFromSk => {
            let mut buf = [0u8; 2*4627+1];
            let bytes_read = read_from_file_or_stdin(skfile, &mut buf);
            let sk = match parse_mldsa87_sk(&buf[..bytes_read]) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            write_bytes_or_hex(&sk.derive_pk().encode(), output_hex);
        }
        MLDSAAction::CheckConsistency => {
            let mut buf = [0u8; 2*4627+1];
            let bytes_read = read_from_file_or_stdin(skfile, &mut buf);
            let sk = match parse_mldsa87_sk(&buf[..bytes_read]) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            // first, read the pk
            let mut pk_bytes = [0u8; 2*2592+1];
            let pk_len: usize;
            if pkfile.is_some() {
                pk_len = read_from_file(pkfile.as_ref().unwrap(), &mut pk_bytes);
            } else {
                eprintln!("Error: no pkfile provided.");
                exit(-1);
            }
            let pk = match parse_mldsa87_pk(&pk_bytes[..pk_len]) {
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
            let mut sk_bytes = [0u8; 2*4627+1];
            let sk_len: usize;
            if skfile.is_some() {
                sk_len = read_from_file(skfile.as_ref().unwrap(), &mut sk_bytes);
            } else {
                eprintln!("Error: no skfile provided.");
                exit(-1);
            }

            // then read ctx
            let ctx = if ctxfile.is_some() {
                let mut ctxbuf = [0u8; 2*255];
                let bytes_read = read_from_file(ctxfile.as_ref().unwrap(), &mut ctxbuf);
                match hex::decode(&ctxbuf[..bytes_read]) {
                    Ok(ctx) => ctx,
                    Err(_) => {
                        eprintln!("Error: couldn't parse the input as a valid context.");
                        exit(-1);
                    }
                }
            } else { vec![0u8;0] };

            // and now sign, streaming the message from stdin
            let sk = match parse_mldsa87_sk(&sk_bytes[..sk_len]) {
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
            let mut pk_bytes = [0u8; 2*2592+1];
            let pk_len: usize;
            if pkfile.is_some() {
                pk_len = read_from_file(pkfile.as_ref().unwrap(), &mut pk_bytes);
            } else {
                eprintln!("Error: no pkfile provided.");
                exit(-1);
            }
            let pk = match parse_mldsa87_pk(&pk_bytes[..pk_len]) {
                Ok(sk) => sk,
                Err(estr) => {
                    eprintln!("{}", estr);
                    exit(-1);
                }
            };

            // then read ctx
            let ctx = if ctxfile.is_some() {
                let mut ctxbuf = [0u8; 2*255+1];
                let bytes_read = read_from_file(ctxfile.as_ref().unwrap(), &mut ctxbuf);
                match hex::decode(&ctxbuf[..bytes_read]) {
                    Ok(ctx) => ctx,
                    Err(_) => {
                        eprintln!("Error: couldn't parse the input as a valid ctx.");
                        exit(-1);
                    }
                }
            } else { vec![0u8;0] };

            // then read the sig
            let sig = if sigfile.is_some() {
                let mut sigbuf = [0u8; 2 * 4627];
                let bytes_read = read_from_file(sigfile.as_ref().unwrap(), &mut sigbuf);

                // first try hex, by length
                match hex::decode(&sigbuf[..bytes_read]) {
                    Ok(sig) => sig,
                    Err(_) => {
                        Vec::from(&sigbuf[..bytes_read])
                    },
                }
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

fn read_from_file(filename: &str, buf: &mut [u8]) -> usize {
    let file = fs::File::open(&filename);
    if file.is_ok() {
        match file.unwrap().read(buf) {
            Ok(bytes_read) => { return bytes_read },
            Err(_) => {
                eprintln!("Error: couldn't open file '{}'", &filename);
                exit(-1);
            },
        }
    } else {
        eprintln!("Error: couldn't open file '{}'", &filename);
        exit(-1);
    }
}
fn read_from_file_or_stdin(filename: &Option<String>, buf: &mut [u8]) -> usize {
    if filename.is_some() {
        return read_from_file(filename.as_ref().unwrap(), buf);
    }

    let mut bytes_read = io::stdin().read(buf).expect("Failed to read from stdin");
    let mut pos = bytes_read;
    while bytes_read != 0 {
        bytes_read = io::stdin().read(&mut buf[pos..]).expect("Failed to read from stdin");
        pos += bytes_read;
    }

    pos
}

/// Loads it as either hex or bytes
fn parse_seed(bytes: &[u8]) -> Result<KeyMaterial256, &'static str> {
    let bytes = if bytes.len() == 65 { &bytes[..64] } else { bytes };

    // try decoding it as hex first
    let seed_bytes: [u8; 32] = match &hex::decode(&bytes) {
        Ok(bytes) => {
            if bytes.len() < 32 {
                // it was valid hex, but too short
                eprintln!("Error: seed must be at least 32 bytes of binary or hex.");
                exit(-1)
            }
            // otherwise it was valid hex; just use the first 32 bytes .. whatever they are
            if bytes.len() > 33 {
                // just cause things often have a trailing \0 or \n which is not worth complaining about
                eprintln!("Warning: seed input longer than 32 bytes; truncating");
            }
            bytes[..32].try_into().unwrap()
        }
        Err(_) => {
            // it's not hex, so just take the fist 32 bytes
            if bytes.len() < 32 {
                return Err("Error: seed must be at least 32 bytes of binary or hex.");
            }
            // otherwise just use the first 32 bytes .. whatever they are
            if bytes.len() > 33 {
                // just cause things often have a trailing \0 or \n which is not worth complaining about
                eprintln!("Warning: seed input longer than 32 bytes; truncating");
            }
            bytes[..32].try_into().unwrap()
        }
    };

    // I think I've checked for all the error conditions, so this shouldn't fail.
    let mut seed = KeyMaterial256::from_bytes_as_type(&seed_bytes, KeyType::Seed).unwrap();

    if seed.key_type() == KeyType::Zeroized || seed.security_strength() < SecurityStrength::_256bit
    {
        eprintln!(
            "Warning: low entropy seed provided. We'll still process it, but it may be insecure."
        );
        seed.allow_hazardous_operations();
        seed.set_key_type(KeyType::Seed).unwrap();
        seed.set_security_strength(SecurityStrength::_256bit).unwrap();
        seed.drop_hazardous_operations();
    }
    Ok(seed)
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

    Err("Error: couldn't parse the input as a valid MLDSA44 private key or seed.")
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
    } // else: keep trying things

    // try it as a seed
    let seed = parse_seed(bytes);
    if seed.is_ok() {
        let maybe_sk = MLDSA44::keygen_from_seed(&seed.unwrap());
        if maybe_sk.is_ok() {
            let (pk, _sk) = maybe_sk.unwrap();
            return Ok(pk);
        } // else: we're out of things to try
    }

    Err("Error: couldn't parse the input as a valid MLDSA44 public key or seed.")
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

    Err("Error: couldn't parse the input as a valid MLDSA44 private key or seed.")
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
    } // else: keep trying things

    // try it as a seed
    let seed = parse_seed(bytes);
    if seed.is_ok() {
        let maybe_sk = MLDSA65::keygen_from_seed(&seed.unwrap());
        if maybe_sk.is_ok() {
            let (pk, _sk) = maybe_sk.unwrap();
            return Ok(pk);
        } // else: we're out of things to try
    }

    Err("Error: couldn't parse the input as a valid MLDSA44 public key or seed.")
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

    Err("Error: couldn't parse the input as a valid MLDSA44 private key or seed.")
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
    } // else: keep trying things

    // try it as a seed
    let seed = parse_seed(bytes);
    if seed.is_ok() {
        let maybe_sk = MLDSA87::keygen_from_seed(&seed.unwrap());
        if maybe_sk.is_ok() {
            let (pk, _sk) = maybe_sk.unwrap();
            return Ok(pk);
        } // else: we're out of things to try
    }

    Err("Error: couldn't parse the input as a valid MLDSA44 public key or seed.")
}