use std::io;
use std::io::{Read, Write};
use std::process::exit;
use bouncycastle::core_interface::key_material::{KeyMaterial256, KeyType};
use bouncycastle::core_interface::traits::{Signature, SignaturePrivateKey};
use bouncycastle::hex;
use crate::{print_bytes_or_hex, MLDSAAction};
use bouncycastle::mldsa::{MLDSATrait, MLDSA44};

pub(crate) fn mldsa44_cmd(action: &MLDSAAction, output_hex: bool) {
    match action {
        MLDSAAction::Keygen => {
            let (_pk, sk) = MLDSA44::keygen().unwrap();
            print_bytes_or_hex(&sk.encode(), output_hex);
        },
        MLDSAAction::KeygenFromSeed => {
            let mut buf: [u8; 1024] = [0u8; 1024];
            let bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
            let seed = if bytes_read == 32 {
                KeyMaterial256::from_bytes_as_type(&buf, KeyType::Seed).unwrap()
            } else {
                let seed_bytes: [u8; 32] = match &hex::decode(&buf) { // try decoding it as hex first
                    Ok(bytes) => {
                        if bytes.len() != 32 {
                            eprintln!("Error: ML-DSA seeds must be 32 bytes");
                            exit(-1)
                        }
                        bytes[..32].try_into().unwrap()
                    },
                    Err(_) => {
                        // it's not hex, so just take the fist 32 bytes
                        if buf.len() < 32 {
                            eprintln!("Error: seed does not appear to be either 32 bytes or valid hex.");
                            exit(-1)
                        }
                        buf[..32].try_into().unwrap()
                    },
                };

                KeyMaterial256::from_bytes_as_type(&seed_bytes, KeyType::Seed).unwrap()
            };

            let (_pk, sk) = MLDSA44::keygen_from_seed(&seed).unwrap();
            print_bytes_or_hex(&sk.encode(), output_hex);
        },
        MLDSAAction::PkFromSk => { println!("Generating new public key from private key..."); },
        MLDSAAction::Sign => { println!("Signing message with private key..."); },
        MLDSAAction::Verify => { println!("Verifying message with public key and signature..."); },
    }
}