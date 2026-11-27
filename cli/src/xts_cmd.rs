//! The `aes128-xts` and `aes256-xts` commands: one generic function that `main` instantiates per
//! key length. What the commands do with their input, the tweak and the key is in the subcommand
//! help in `main.rs`.

use crate::helpers::block_mode_helpers::CipherDirection;
use crate::helpers::{
    decode_hex_arg, flush_stdout, load_secret, read_stdin_chunk, strip_trailing_newline,
    write_bytes_or_hex, write_stdout,
};
use bouncycastle::core::hazmat::BlockPermutation;
use bouncycastle::core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle::core::symmetric_key::FromKeyMaterial;
use bouncycastle::symmetric::modes::{
    XTS_MAX_DATA_UNIT_LEN, XTS_MIN_DATA_UNIT_LEN, XTS_TWEAK_LEN, XTSKey,
};
use bouncycastle_utils::ct::{ct_eq_bytes, ct_eq_zero_bytes};
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
    let key = load_xts_key::<P, KEY_LEN>(key, key_file, alg);

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

/// The XTS key from `--key-file` or `--key`, exactly `KEY_LEN` bytes after one trailing newline
/// in a raw file is set aside, as the other cipher commands load theirs.
///
/// The two keys XTS refuses are named here, before the key is built: the block cipher commands'
/// loader would accept an all-zero key with a warning that it is proceeding, which XTS does not,
/// and the library's refusal of an all-zero half does not say which key it is refusing or why.
fn load_xts_key<P, const KEY_LEN: usize>(
    key: &Option<String>,
    key_file: &Option<String>,
    alg: &str,
) -> XTSKey<P>
where
    XTSKey<P>: FromKeyMaterial<KEY_LEN>,
{
    let secret = load_secret(key, key_file, "key");
    let trimmed = strip_trailing_newline(secret.ref_to_bytes());
    let key_bytes = if trimmed.len() == KEY_LEN { trimmed } else { secret.ref_to_bytes() };
    if key_bytes.len() != KEY_LEN {
        eprintln!("Error: {alg} needs a {KEY_LEN}-byte key, got {} bytes.", key_bytes.len());
        exit(-1);
    }

    // Key = Key_1 | Key_2. Compared in constant time, as the library does: only the refusal is
    // public.
    let (key1, key2) = key_bytes.split_at(KEY_LEN / 2);
    if ct_eq_bytes(key1, key2) {
        eprintln!(
            "Error: the two halves of the {alg} key, Key_1 and Key_2, are equal (an all-zero key \
             is the usual case). XTS requires Key_1 != Key_2 (FIPS 140-3 IG C.I)."
        );
        exit(-1);
    }
    if ct_eq_zero_bytes(key1) | ct_eq_zero_bytes(key2) {
        eprintln!(
            "Error: one half of the {alg} key, Key_1 or Key_2, is all zeros. Each half is an AES \
             key, and an all-zero AES key is refused."
        );
        exit(-1);
    }

    let material =
        KeyMaterial::<KEY_LEN>::from_bytes_as_type(key_bytes, KeyType::SymmetricCipherKey)
            .unwrap_or_else(|e| {
                eprintln!("Error: couldn't load the key: {e:?}");
                exit(-1);
            });
    XTSKey::<P>::from_key_material(&material).unwrap_or_else(|e| {
        eprintln!("Error: couldn't load the key: {e:?}");
        exit(-1);
    })
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
