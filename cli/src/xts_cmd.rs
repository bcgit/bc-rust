//! XTS-AES encryption and decryption of stdin to stdout, one data unit at a time: the
//! `aes128-xts` and `aes256-xts` commands, one generic function that `main` instantiates per key
//! length.
//!
//! The input is a sequence of data units of `--data-unit-len` bytes, and must be a whole number of
//! them: an XTS key protects data units of one fixed length (NIST SP 800-38E Sec 4), and the
//! library fixes that length in the key's type, so the command offers the usual sector sizes and
//! instantiates a key type for the one chosen. The first data unit is processed under `--tweak` and
//! each later one under the tweak before it plus one, read as a 128-bit little-endian integer: the
//! numbering and the encoding of IEEE 1619-2007 Sec 5.1. Nothing is prepended or appended: the
//! output is exactly as long as the input.
//!
//! # Warning
//!
//! XTS provides confidentiality only, and only for data at rest; see the subcommand help.

use crate::helpers::block_mode_helpers::{CipherDirection, load_key_object};
use crate::helpers::{
    decode_hex_arg, flush_stdout, read_stdin_chunk, write_bytes_or_hex, write_stdout,
};
use bouncycastle::cipher::modes::{XTS_TWEAK_LEN, XTSKey};
use bouncycastle::core::hazmat::BlockPermutation;
use bouncycastle::core::symmetric_key::FromKeyMaterial;
use std::process::exit;

/// XTS over the permutation `P` with a `KEY_LEN`-byte key, `Key_1 | Key_2`; `alg` names the
/// algorithm in messages. Exits with an error for a `data_unit_len` it does not offer.
pub(crate) fn xts_cmd<P, const KEY_LEN: usize>(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    tweak: &str,
    data_unit_len: usize,
    output_hex: bool,
    alg: &str,
) where
    P: BlockPermutation<16>,
    XTSKey<P, 512>: FromKeyMaterial<KEY_LEN>,
    XTSKey<P, 1024>: FromKeyMaterial<KEY_LEN>,
    XTSKey<P, 2048>: FromKeyMaterial<KEY_LEN>,
    XTSKey<P, 4096>: FromKeyMaterial<KEY_LEN>,
{
    let tweak = load_tweak(tweak);
    match data_unit_len {
        512 => run::<P, KEY_LEN, 512>(action, key, key_file, &tweak, output_hex, alg),
        1024 => run::<P, KEY_LEN, 1024>(action, key, key_file, &tweak, output_hex, alg),
        2048 => run::<P, KEY_LEN, 2048>(action, key, key_file, &tweak, output_hex, alg),
        4096 => run::<P, KEY_LEN, 4096>(action, key, key_file, &tweak, output_hex, alg),
        other => {
            eprintln!("Error: --data-unit-len must be 512, 1024, 2048 or 4096 bytes, not {other}.");
            exit(-1);
        }
    }
}

/// `--tweak`: exactly 16 bytes of hex, the 128-bit tweak of the first data unit.
fn load_tweak(tweak: &str) -> [u8; XTS_TWEAK_LEN] {
    let bytes = decode_hex_arg(tweak, "tweak");
    bytes.as_slice().try_into().unwrap_or_else(|_| {
        eprintln!("Error: the tweak is {} bytes; XTS takes exactly {XTS_TWEAK_LEN}.", bytes.len());
        exit(-1)
    })
}

/// Processes stdin a data unit at a time under consecutive tweaks from `first_tweak`.
fn run<P, const KEY_LEN: usize, const N: usize>(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    first_tweak: &[u8; XTS_TWEAK_LEN],
    output_hex: bool,
    alg: &str,
) where
    P: BlockPermutation<16>,
    XTSKey<P, N>: FromKeyMaterial<KEY_LEN>,
{
    let key = load_key_object::<XTSKey<P, N>, KEY_LEN>(key, key_file, alg);
    let mut sequence_number = u128::from_le_bytes(*first_tweak);
    let mut data_unit = [0u8; N];
    let mut units = 0u64;
    loop {
        let filled = fill(&mut data_unit);
        if filled == 0 {
            break;
        }
        if filled < N {
            // The whole data units before it are already written; flush them so that the error
            // follows the output rather than landing inside it.
            flush_stdout();
            eprintln!(
                "\nError: input to {alg} must be a whole number of {N}-byte data units \
                 (data contained {filled} trailing byte(s))."
            );
            exit(-1);
        }
        if units > 0 {
            // Fail rather than wrap round to a tweak an earlier data unit may have used.
            sequence_number = sequence_number.checked_add(1).unwrap_or_else(|| {
                flush_stdout();
                eprintln!("\nError: the tweak cannot go past 2^128 - 1.");
                exit(-1)
            });
        }
        let tweak = sequence_number.to_le_bytes();
        match action {
            CipherDirection::Encrypt => key.encrypt_inplace(&tweak, &mut data_unit),
            CipherDirection::Decrypt => key.decrypt_inplace(&tweak, &mut data_unit),
        };
        write_bytes_or_hex(&data_unit, output_hex);
        units += 1;
    }
    if output_hex {
        write_stdout(b"\n");
    }
    flush_stdout();
}

/// Reads stdin into `buf` until it is full or the input ends, and returns how much was read.
fn fill(buf: &mut [u8]) -> usize {
    let mut filled = 0;
    while filled < buf.len() {
        let n = read_stdin_chunk(&mut buf[filled..]);
        if n == 0 {
            break;
        }
        filled += n;
    }
    filled
}
