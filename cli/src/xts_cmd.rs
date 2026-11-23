//! XTS-AES encryption and decryption of stdin to stdout, one data unit at a time: the
//! `aes128-xts` and `aes256-xts` commands, one generic function that `main` instantiates per key
//! length.
//!
//! The input is a sequence of data units of `--data-unit-len` bytes, and must be a whole number of
//! them: an XTS key protects data units of one fixed length (NIST SP 800-38E Sec 4), so one length
//! serves the whole input. The first data unit is processed under `--tweak` and each later one
//! under the tweak before it plus one, read as a 128-bit little-endian integer: the numbering and
//! the encoding of IEEE 1619-2007 Sec 5.1. Nothing is prepended or appended: the output is exactly
//! as long as the input.
//!
//! # Warning
//!
//! XTS provides confidentiality only, and only for data at rest; see the subcommand help.

use crate::helpers::block_mode_helpers::{CipherDirection, load_key_object};
use crate::helpers::{
    decode_hex_arg, flush_stdout, read_stdin_chunk, write_bytes_or_hex, write_stdout,
};
use bouncycastle::cipher::modes::{
    XTS_MAX_DATA_UNIT_LEN, XTS_MIN_DATA_UNIT_LEN, XTS_TWEAK_LEN, XTSKey,
};
use bouncycastle::core::hazmat::BlockPermutation;
use bouncycastle::core::symmetric_key::FromKeyMaterial;
use std::process::exit;

/// XTS over the permutation `P` with a `KEY_LEN`-byte key, `Key_1 | Key_2`, on `data_unit_len`-byte
/// data units; `alg` names the algorithm in messages.
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
    XTSKey<P>: FromKeyMaterial<KEY_LEN>,
{
    let first_tweak = load_tweak(tweak);
    // The library refuses a data unit outside these bounds at each call; checking the length here
    // as well refuses it before the buffer of that length is allocated or any input is read.
    if !(XTS_MIN_DATA_UNIT_LEN..=XTS_MAX_DATA_UNIT_LEN).contains(&data_unit_len) {
        eprintln!(
            "Error: --data-unit-len must be from {XTS_MIN_DATA_UNIT_LEN} to \
             {XTS_MAX_DATA_UNIT_LEN} bytes (one block to 2^20 blocks), not {data_unit_len}."
        );
        exit(-1);
    }
    let key = load_key_object::<XTSKey<P>, KEY_LEN>(key, key_file, alg);

    // `None` once a data unit has taken the tweak 2^128 - 1: there is no next one, and wrapping
    // round to 0 could repeat a tweak an earlier data unit used.
    let mut next_tweak = Some(u128::from_le_bytes(first_tweak));
    let mut data_unit = vec![0u8; data_unit_len];
    loop {
        let filled = fill(&mut data_unit);
        if filled == 0 {
            break;
        }
        if filled < data_unit_len {
            // The whole data units before it are already written; flush them so that the error
            // follows the output rather than landing inside it.
            flush_stdout();
            eprintln!(
                "\nError: input to {alg} must be a whole number of {data_unit_len}-byte data \
                 units (data contained {filled} trailing byte(s))."
            );
            exit(-1);
        }
        let Some(sequence_number) = next_tweak else {
            flush_stdout();
            eprintln!("\nError: the tweak cannot go past 2^128 - 1.");
            exit(-1)
        };
        let tweak = sequence_number.to_le_bytes();
        let processed = match action {
            CipherDirection::Encrypt => key.encrypt_inplace(&tweak, &mut data_unit),
            CipherDirection::Decrypt => key.decrypt_inplace(&tweak, &mut data_unit),
        };
        if let Err(e) = processed {
            flush_stdout();
            eprintln!("\nError: {alg} refused the data unit: {e:?}");
            exit(-1);
        }
        write_bytes_or_hex(&data_unit, output_hex);
        next_tweak = sequence_number.checked_add(1);
    }
    if output_hex {
        write_stdout(b"\n");
    }
    flush_stdout();
}

/// `--tweak`: exactly 16 bytes of hex, the 128-bit tweak of the first data unit.
fn load_tweak(tweak: &str) -> [u8; XTS_TWEAK_LEN] {
    let bytes = decode_hex_arg(tweak, "tweak");
    bytes.as_slice().try_into().unwrap_or_else(|_| {
        eprintln!("Error: the tweak is {} bytes; XTS takes exactly {XTS_TWEAK_LEN}.", bytes.len());
        exit(-1)
    })
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
