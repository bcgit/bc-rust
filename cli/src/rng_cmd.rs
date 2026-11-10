//! The `rng` subcommand: bytes from a Hash_DRBG (SP 800-90A Rev. 1), seeded from the operating
//! system, or from a file for a reproducible stream.

use bouncycastle::core::hazmat::do_hazardous_operations;
use bouncycastle::core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle::core::security_strength::SecurityStrength;
use bouncycastle::core::traits::RNG;
use bouncycastle::rng::hazmat::NewUninitialized;
use bouncycastle::rng::{HashDRBG_SHA256, HashDRBG_SHA512, Sp80090ADrbg};
use clap::ValueEnum;
use std::process::exit;

use crate::helpers::{CHUNK_LEN, read_secret_file, write_bytes_or_hex, write_stdout};

/// The hash under the DRBG: SHA-256 gives a 128-bit instance, SHA-512 a 256-bit one.
#[derive(ValueEnum, Clone, Copy, Debug)]
pub(crate) enum DrbgHash {
    Sha256,
    Sha512,
}

pub(crate) fn rng_cmd(
    len: Option<u32>,
    hash: DrbgHash,
    seed_file: &Option<String>,
    output_hex: bool,
) {
    match (hash, seed_file) {
        (DrbgHash::Sha256, None) => generate(HashDRBG_SHA256::new_from_os(), len, output_hex),
        (DrbgHash::Sha512, None) => generate(HashDRBG_SHA512::new_from_os(), len, output_hex),
        (DrbgHash::Sha256, Some(file)) => {
            generate(seeded::<HashDRBG_SHA256>(file, SecurityStrength::_128bit), len, output_hex)
        }
        (DrbgHash::Sha512, Some(file)) => {
            generate(seeded::<HashDRBG_SHA512>(file, SecurityStrength::_256bit), len, output_hex)
        }
    }
}

/// A DRBG instantiated from the bytes of `file` as its entropy input, with an empty nonce and
/// personalization string (SP 800-90A Rev. 1 Section 10.1.1.2): the same file gives the same
/// stream, which is the point, and the reason the help calls it hazardous. With no nonce, the
/// seed must carry 3/2 of the instance's strength (Section 9.1), which the library checks by its
/// length.
fn seeded<D: NewUninitialized + Sp80090ADrbg>(file: &str, strength: SecurityStrength) -> D {
    let mut seed = read_secret_file(file);
    do_hazardous_operations(&mut seed, |seed| seed.set_key_type(KeyType::Seed)).unwrap_or_else(
        |e| {
            eprintln!("Error: couldn't use the seed file: {e:?}");
            exit(-1);
        },
    );
    let mut drbg = D::new_uninitialized();
    drbg.instantiate(false, seed, &KeyMaterial::<0>::new(), &[], strength).unwrap_or_else(|e| {
        eprintln!(
            "Error: couldn't instantiate the DRBG from the seed file (with no nonce it must be at least {} bytes): {e:?}",
            strength.as_int() * 3 / 16
        );
        exit(-1);
    });
    drbg
}

fn generate(mut rng: impl RNG, len: Option<u32>, output_hex: bool) {
    let mut buf = vec![0u8; CHUNK_LEN];

    let loop_forever = len.is_none();
    let mut bytes_left_to_write = len.unwrap_or(u32::MAX) as usize;
    while loop_forever || bytes_left_to_write > 0 {
        rng.next_bytes_out(&mut buf).unwrap_or_else(|e| {
            eprintln!("Error: the DRBG refused to generate: {e:?}");
            exit(-1);
        });

        if bytes_left_to_write < buf.len() {
            buf.truncate(bytes_left_to_write);
        }
        write_bytes_or_hex(&buf, output_hex);
        bytes_left_to_write -= buf.len();
    }
    // Only a hex line gets a terminator: raw output is exactly `len` bytes, so that
    // `rng --len 16 > key.bin` is a 16-byte key and not a 17-byte one.
    if output_hex {
        write_stdout(b"\n");
    }
}
