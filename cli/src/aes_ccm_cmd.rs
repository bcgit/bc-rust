//! AES-CCM authenticated encryption and decryption (NIST SP 800-38C).
//!
//! # This command does not stream, and cannot
//!
//! Every other cipher command here streams stdin to stdout in 1 KiB chunks. This one reads stdin to
//! the end first, and that is a property of CCM rather than a shortcut. SP 800-38C Sec 3:
//!
//! > CCM is intended for use in a packet environment, i.e., when all of the data is available in
//! > storage before CCM is applied; CCM is not designed to support partial processing or stream
//! > processing.
//!
//! Appendix A.2.1 puts the payload's octet length inside `B0`, the first block the CBC-MAC absorbs,
//! so nothing can be authenticated until the whole payload length is known. Buffering the input is
//! therefore the correct behaviour, not a compromise -- and it has a real benefit on the decryption
//! side: unlike `ascon-aead128`, this command writes **no plaintext at all** until the tag has
//! verified, so a non-zero exit leaves nothing to discard.
//!
//! The practical consequence is that memory use is proportional to the input, so this is not the
//! command to point at a multi-gigabyte file. `aes256-ctr` piped through a separate MAC, or
//! `ascon-aead128`, are the streaming alternatives.
//!
//! # The nonce is supplied, not generated
//!
//! This is the one cipher command here with a `--nonce` flag. The other modes generate their IV or
//! nonce and prepend it to the output, because for them an unpredictable value is what is required.
//! CCM needs the nonce to be **unique**, not unpredictable -- Sec 5.3: "The nonce is not required
//! to be random" -- and a caller with a message counter can guarantee uniqueness better than a
//! DRBG draw can. Since a repeated nonce under one key is fatal for CCM (see the subcommand help),
//! the choice is the caller's to make explicitly.
//!
//! The nonce is not written to the output, so `encrypt` and `decrypt` both need the same
//! `--nonce`.
//!
//! # Lengths
//!
//! `--nonce` must be 7..=13 bytes and `--tag-len` one of 4, 6, 8, 10, 12, 14, 16, both from
//! Appendix A.1. The nonce length fixes the maximum payload at `2^(8 * (15 - n)) - 1` bytes, which
//! this command checks against the actual input length. Because those are const generic parameters
//! of the mode, the runtime value is dispatched to one of the seven nonce lengths and seven tag
//! lengths below.
//!
//! The output layout is Sec 6.1 step 8's own: `ciphertext || tag`.

use std::io::{self, Read};
use std::process::exit;

use bouncycastle::aes::{AES_128, AES_192, AES_256};
use bouncycastle::core::errors::SymmetricCipherError;
use bouncycastle::core::key_material::KeyMaterial;
use bouncycastle::core::traits::ElectronicCodeBook;
use bouncycastle::hex;
use bouncycastle::modes::{Ccm, Decrypting, Encrypting};

use crate::block_mode_cmd::{BLOCK_LEN, BlockModeAction, load_key};
use crate::helpers;

/// AES-128 CCM. See the module docs and the subcommand help.
pub(crate) fn aes128_ccm_cmd(
    action: &BlockModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    nonce: &Option<String>,
    nonce_file: &Option<String>,
    aad: &Option<String>,
    tag_len: usize,
    output_hex: bool,
) {
    run::<AES_128, 16>(
        action,
        &load_key::<16>(key, key_file, "AES-128"),
        nonce,
        nonce_file,
        aad,
        tag_len,
        output_hex,
    );
}

/// AES-192 CCM. See [`aes128_ccm_cmd`].
pub(crate) fn aes192_ccm_cmd(
    action: &BlockModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    nonce: &Option<String>,
    nonce_file: &Option<String>,
    aad: &Option<String>,
    tag_len: usize,
    output_hex: bool,
) {
    run::<AES_192, 24>(
        action,
        &load_key::<24>(key, key_file, "AES-192"),
        nonce,
        nonce_file,
        aad,
        tag_len,
        output_hex,
    );
}

/// AES-256 CCM. See [`aes128_ccm_cmd`].
pub(crate) fn aes256_ccm_cmd(
    action: &BlockModeAction,
    key: &Option<String>,
    key_file: &Option<String>,
    nonce: &Option<String>,
    nonce_file: &Option<String>,
    aad: &Option<String>,
    tag_len: usize,
    output_hex: bool,
) {
    run::<AES_256, 32>(
        action,
        &load_key::<32>(key, key_file, "AES-256"),
        nonce,
        nonce_file,
        aad,
        tag_len,
        output_hex,
    );
}

/// Loads the nonce from `--nonce` (hex) or `--nonce-file` (hex or binary).
///
/// Unlike the key there is no entropy question here: Sec 5.3 asks for uniqueness, not randomness,
/// so an all-zero nonce is a perfectly valid *first* nonce and only a repeat is a problem.
fn load_nonce(nonce: &Option<String>, nonce_file: &Option<String>) -> Vec<u8> {
    let bytes = if let Some(file) = nonce_file {
        helpers::read_from_file(file)
    } else if let Some(v) = nonce {
        hex::decode(v).unwrap_or_else(|_| {
            eprintln!("Error: nonce is not valid hex.");
            exit(-1)
        })
    } else {
        eprintln!("Error: --nonce or --nonce-file must be supplied. CCM has no generated nonce;");
        eprintln!("       see the subcommand help for why, and for the uniqueness requirement.");
        exit(-1)
    };

    // Appendix A.1: "n is an element of {7, 8, 9, 10, 11, 12, 13}".
    if !(7..=13).contains(&bytes.len()) {
        eprintln!(
            "Error: nonce is {} bytes; CCM requires 7 to 13 (SP 800-38C Appendix A.1).",
            bytes.len()
        );
        exit(-1)
    }
    bytes
}

fn load_aad(aad: &Option<String>) -> Vec<u8> {
    match aad {
        Some(v) => hex::decode(v).unwrap_or_else(|_| {
            eprintln!("Error: associated data is not valid hex.");
            exit(-1)
        }),
        None => Vec::new(),
    }
}

/// Reads all of stdin. See the module docs on why this is not a streaming command.
fn read_all_stdin() -> Vec<u8> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input).expect("Failed to read from stdin");
    input
}

/// Turns the runtime nonce and tag lengths into the mode's const generic parameters.
///
/// `NONCE_LEN` and `TAG_LEN` are const parameters of `Ccm` -- that is what makes A.1's length
/// conditions compile-time checks rather than runtime ones -- so a command-line value has to be
/// matched into one of the permitted instantiations. The two nested matches are the price of that,
/// and they are exhaustive over A.1's sets: 7 nonce lengths x 7 tag lengths.
fn run<P, const KEY_LEN: usize>(
    action: &BlockModeAction,
    key: &KeyMaterial<KEY_LEN>,
    nonce: &Option<String>,
    nonce_file: &Option<String>,
    aad: &Option<String>,
    tag_len: usize,
    output_hex: bool,
) where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    let nonce_bytes = load_nonce(nonce, nonce_file);
    let aad_bytes = load_aad(aad);
    let input = read_all_stdin();
    let encrypt = matches!(action, BlockModeAction::Encrypt);

    // Appendix A.1: "t is an element of {4, 6, 8, 10, 12, 14, 16}".
    macro_rules! with_tag_len {
        ($n:literal) => {
            match tag_len {
                4 => go::<P, KEY_LEN, $n, 4>(
                    key, &nonce_bytes, &aad_bytes, &input, encrypt, output_hex,
                ),
                6 => go::<P, KEY_LEN, $n, 6>(
                    key, &nonce_bytes, &aad_bytes, &input, encrypt, output_hex,
                ),
                8 => go::<P, KEY_LEN, $n, 8>(
                    key, &nonce_bytes, &aad_bytes, &input, encrypt, output_hex,
                ),
                10 => go::<P, KEY_LEN, $n, 10>(
                    key, &nonce_bytes, &aad_bytes, &input, encrypt, output_hex,
                ),
                12 => go::<P, KEY_LEN, $n, 12>(
                    key, &nonce_bytes, &aad_bytes, &input, encrypt, output_hex,
                ),
                14 => go::<P, KEY_LEN, $n, 14>(
                    key, &nonce_bytes, &aad_bytes, &input, encrypt, output_hex,
                ),
                16 => go::<P, KEY_LEN, $n, 16>(
                    key, &nonce_bytes, &aad_bytes, &input, encrypt, output_hex,
                ),
                other => {
                    eprintln!(
                        "Error: --tag-len is {other}; CCM requires one of 4, 6, 8, 10, 12, 14, 16 \
                         (SP 800-38C Appendix A.1)."
                    );
                    exit(-1)
                }
            }
        };
    }

    // `load_nonce` has already rejected anything outside 7..=13, so the fall-through is unreachable;
    // it is spelled out rather than `unreachable!()` so this cannot panic on a future edit.
    match nonce_bytes.len() {
        7 => with_tag_len!(7),
        8 => with_tag_len!(8),
        9 => with_tag_len!(9),
        10 => with_tag_len!(10),
        11 => with_tag_len!(11),
        12 => with_tag_len!(12),
        13 => with_tag_len!(13),
        other => {
            eprintln!("Error: nonce is {other} bytes; CCM requires 7 to 13.");
            exit(-1)
        }
    }
}

/// One fully-instantiated CCM run.
fn go<P, const KEY_LEN: usize, const NONCE_LEN: usize, const TAG_LEN: usize>(
    key: &KeyMaterial<KEY_LEN>,
    nonce_bytes: &[u8],
    aad: &[u8],
    input: &[u8],
    encrypt: bool,
    output_hex: bool,
) where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    type Enc<P, const K: usize, const N: usize, const T: usize> =
        Ccm<P, Encrypting, K, BLOCK_LEN, N, T>;
    type Dec<P, const K: usize, const N: usize, const T: usize> =
        Ccm<P, Decrypting, K, BLOCK_LEN, N, T>;

    // `run` dispatched on this exact length, so the conversion cannot fail.
    let Ok(nonce) = <[u8; NONCE_LEN]>::try_from(nonce_bytes) else {
        eprintln!("Error: internal nonce length mismatch.");
        exit(-1)
    };

    if encrypt {
        let mut out = vec![0u8; input.len() + TAG_LEN];
        match Enc::<P, KEY_LEN, NONCE_LEN, TAG_LEN>::encrypt(key, &nonce, aad, input, &mut out) {
            Ok(written) => {
                helpers::write_bytes_or_hex(&out[..written], output_hex);
                if output_hex {
                    println!();
                }
            }
            Err(SymmetricCipherError::GenericError(msg)) => {
                // The only `GenericError` reachable here is the payload limit: A.1's `p < 2^8q`,
                // where `q = 15 - n`. Report it with the numbers, since the fix is a shorter nonce.
                eprintln!("Error: {msg}");
                eprintln!(
                    "       Input is {} bytes; with a {NONCE_LEN}-byte nonce, q = {} and the \
                     limit is {} bytes.",
                    input.len(),
                    15 - NONCE_LEN,
                    payload_limit(15 - NONCE_LEN),
                );
                eprintln!("       Use a shorter nonce for a larger payload.");
                exit(-1)
            }
            Err(e) => {
                eprintln!("Error: AES-CCM encryption failed: {e:?}");
                exit(-1)
            }
        }
    } else {
        if input.len() < TAG_LEN {
            // Sec 6.2 step 1: "If Clen <= Tlen, then return INVALID".
            eprintln!(
                "Error: input is {} bytes, shorter than the {TAG_LEN}-byte tag it must end with.",
                input.len()
            );
            exit(-1)
        }
        let mut out = vec![0u8; input.len() - TAG_LEN];
        match Dec::<P, KEY_LEN, NONCE_LEN, TAG_LEN>::decrypt(key, &nonce, aad, input, &mut out) {
            Ok(written) => {
                helpers::write_bytes_or_hex(&out[..written], output_hex);
                if output_hex {
                    println!();
                }
            }
            Err(SymmetricCipherError::AEADTagCheckFailed) => {
                // Nothing has been written to stdout at this point, which is what buffering buys:
                // Sec 6.2's "the payload P and the MAC T shall not be revealed" holds end to end.
                eprintln!("Error: AES-CCM authentication failed; the input is not authentic.");
                exit(-1)
            }
            Err(e) => {
                eprintln!("Error: AES-CCM decryption failed: {e:?}");
                exit(-1)
            }
        }
    }
}

/// A.1's `2^8q - 1`, for the error message above. Saturates at `u64::MAX` for `q = 8`, where the
/// bound is beyond any real input anyway.
fn payload_limit(q: usize) -> u64 {
    if q >= 8 { u64::MAX } else { (1u64 << (8 * q)) - 1 }
}
