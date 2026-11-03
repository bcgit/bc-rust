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
//! The AAD is read whole too: the key's one-shot takes it as a slice. (A.2.2 needs its length
//! before its first byte, so streaming it would need the declared-length constructor the packet
//! type keeps for itself.)
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
//! of the key type, the runtime value is dispatched to one of the seven nonce lengths and seven tag
//! lengths below.
//!
//! The output layout is Sec 6.1 step 8's own: `ciphertext || tag`.

use std::io::{self, Read};
use std::process::exit;

use bouncycastle::aes::{AES128Key, AES192Key, AES256Key};
use bouncycastle::cipher::modes::CCM;
use bouncycastle::core::errors::SymmetricCipherError;
use bouncycastle::core::key_material::KeyMaterial;
use bouncycastle::core::symmetric_key::{
    AeadPacketDecryptionKey, AeadPacketEncryptionKey, FromKeyMaterial,
};
use bouncycastle::hex;

use crate::helpers;
use crate::helpers::block_mode_helpers::{CipherDirection, load_key};

/// The CCM key type for one AES key length, at every nonce and tag length `run` can dispatch to.
///
/// The one-shots this command uses are on the key's role traits, and the key type carries the
/// nonce and tag lengths as const parameters, so a generic `run` over the key length needs a way
/// to name the key type for an `(N, T)` it chooses at run time: this generic associated type.
trait CcmKeys<const KEY_LEN: usize> {
    /// The key type at nonce length `N` and tag length `T`.
    type Key<const N: usize, const T: usize>: FromKeyMaterial<KEY_LEN>
        + AeadPacketEncryptionKey<KEY_LEN, N, T, T>
        + AeadPacketDecryptionKey<KEY_LEN, N, T, T>;
}

struct Aes128;
struct Aes192;
struct Aes256;

impl CcmKeys<16> for Aes128 {
    type Key<const N: usize, const T: usize> = AES128Key<CCM<N, T>>;
}

impl CcmKeys<24> for Aes192 {
    type Key<const N: usize, const T: usize> = AES192Key<CCM<N, T>>;
}

impl CcmKeys<32> for Aes256 {
    type Key<const N: usize, const T: usize> = AES256Key<CCM<N, T>>;
}

/// AES-128 CCM. See the module docs and the subcommand help.
pub(crate) fn aes128_ccm_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    nonce: &Option<String>,
    nonce_file: &Option<String>,
    aad: &Option<String>,
    aad_file: &Option<String>,
    tag_len: usize,
    output_hex: bool,
) {
    run::<Aes128, 16>(
        action,
        &load_key::<16>(key, key_file, "AES-128"),
        nonce,
        nonce_file,
        aad,
        aad_file,
        tag_len,
        output_hex,
    );
}

/// AES-192 CCM. See [`aes128_ccm_cmd`].
pub(crate) fn aes192_ccm_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    nonce: &Option<String>,
    nonce_file: &Option<String>,
    aad: &Option<String>,
    aad_file: &Option<String>,
    tag_len: usize,
    output_hex: bool,
) {
    run::<Aes192, 24>(
        action,
        &load_key::<24>(key, key_file, "AES-192"),
        nonce,
        nonce_file,
        aad,
        aad_file,
        tag_len,
        output_hex,
    );
}

/// AES-256 CCM. See [`aes128_ccm_cmd`].
pub(crate) fn aes256_ccm_cmd(
    action: &CipherDirection,
    key: &Option<String>,
    key_file: &Option<String>,
    nonce: &Option<String>,
    nonce_file: &Option<String>,
    aad: &Option<String>,
    aad_file: &Option<String>,
    tag_len: usize,
    output_hex: bool,
) {
    run::<Aes256, 32>(
        action,
        &load_key::<32>(key, key_file, "AES-256"),
        nonce,
        nonce_file,
        aad,
        aad_file,
        tag_len,
        output_hex,
    );
}

/// Loads the nonce from `--nonce` (hex) or `--nonce-file` (raw bytes, exactly as they are).
///
/// Unlike the key there is no entropy question here: Sec 5.3 asks for uniqueness, not randomness,
/// so an all-zero nonce is a perfectly valid *first* nonce and only a repeat is a problem.
///
/// `--nonce-file` reads raw bytes ([`helpers::read_from_file_raw`]), not the hex-or-raw guess
/// [`helpers::read_from_file`] uses for keys: a repeated nonce under one key is fatal for CCM (see
/// the module docs), so two distinct binary nonce files that happen to look like hex text of the
/// same value must not silently collapse to the same nonce.
///
/// For the same reason a trailing newline is **not** stripped: a 13-byte file ending in `0x0a` and
/// the 12-byte file without it are two different nonces, and silently treating them as one would
/// be exactly the collapse above. But every length from 7 to 13 is valid, so a 12-byte nonce
/// written with `echo` rather than `echo -n` is accepted as a *different*, 13-byte nonce, and the
/// only symptom is a failed tag check on the other side. That case is warned about on stderr so it
/// is not a silent one; the bytes are still used exactly as they are.
fn load_nonce(nonce: &Option<String>, nonce_file: &Option<String>) -> Vec<u8> {
    let bytes = if let Some(file) = nonce_file {
        let bytes = helpers::read_from_file_raw(file);
        if bytes.last() == Some(&b'\n') {
            eprintln!(
                "Warning: nonce file '{file}' ends with a newline byte (0x0a), which is used as \
                 part of the nonce."
            );
            eprintln!(
                "         If that is not intended (for example the file was written by `echo`), \
                 write it with `printf` or `echo -n`."
            );
        }
        bytes
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

/// Loads the AAD from `--aad-file` (raw bytes, never hex-decoded) or `--aad` (hex); the file wins
/// if both are given, as for `aes*-gcm`. Empty if neither is given.
fn load_aad(aad: &Option<String>, aad_file: &Option<String>) -> Vec<u8> {
    if let Some(path) = aad_file {
        helpers::read_from_file_raw(path)
    } else if let Some(v) = aad {
        hex::decode(v).unwrap_or_else(|_| {
            eprintln!("Error: associated data is not valid hex. Use --aad-file for raw bytes.");
            exit(-1)
        })
    } else {
        Vec::new()
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
/// `NONCE_LEN` and `TAG_LEN` are const parameters of the key type -- that is what makes A.1's
/// length conditions compile-time checks rather than runtime ones -- so a command-line value has to
/// be matched into one of the permitted instantiations. The two nested matches are the price of
/// that, and they are exhaustive over A.1's sets: 7 nonce lengths x 7 tag lengths.
fn run<F: CcmKeys<KEY_LEN>, const KEY_LEN: usize>(
    action: &CipherDirection,
    key: &KeyMaterial<KEY_LEN>,
    nonce: &Option<String>,
    nonce_file: &Option<String>,
    aad: &Option<String>,
    aad_file: &Option<String>,
    tag_len: usize,
    output_hex: bool,
) {
    // Reject this before opening nonce/AAD files or waiting for stdin. Appendix A.1: "t is an
    // element of {4, 6, 8, 10, 12, 14, 16}".
    if !matches!(tag_len, 4 | 6 | 8 | 10 | 12 | 14 | 16) {
        eprintln!(
            "Error: --tag-len is {tag_len}; CCM requires one of 4, 6, 8, 10, 12, 14, 16 \
             (SP 800-38C Appendix A.1)."
        );
        exit(-1)
    }

    let nonce_bytes = load_nonce(nonce, nonce_file);
    let aad = load_aad(aad, aad_file);
    let input = read_all_stdin();
    let encrypt = matches!(action, CipherDirection::Encrypt);

    macro_rules! with_tag_len {
        ($n:literal) => {
            match tag_len {
                4 => go::<F, KEY_LEN, $n, 4>(key, &nonce_bytes, &aad, input, encrypt, output_hex),
                6 => go::<F, KEY_LEN, $n, 6>(key, &nonce_bytes, &aad, input, encrypt, output_hex),
                8 => go::<F, KEY_LEN, $n, 8>(key, &nonce_bytes, &aad, input, encrypt, output_hex),
                10 => go::<F, KEY_LEN, $n, 10>(key, &nonce_bytes, &aad, input, encrypt, output_hex),
                12 => go::<F, KEY_LEN, $n, 12>(key, &nonce_bytes, &aad, input, encrypt, output_hex),
                14 => go::<F, KEY_LEN, $n, 14>(key, &nonce_bytes, &aad, input, encrypt, output_hex),
                16 => go::<F, KEY_LEN, $n, 16>(key, &nonce_bytes, &aad, input, encrypt, output_hex),
                _ => unreachable!("tag length was validated before stdin was read"),
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

/// Reports the one-shots' refusal of a payload past the `q` limit and exits.
///
/// The only [`SymmetricCipherError::GenericError`] they can return is that limit: A.1's
/// `p < 2^8q`, where `q = 15 - n`. Both directions hit it -- the decrypt side on the input minus
/// its tag -- so both report it here, with the numbers, since the fix is a shorter nonce.
fn payload_past_the_q_limit<const NONCE_LEN: usize>(msg: &str, payload_len: usize) -> ! {
    let q = 15 - NONCE_LEN;
    // `2^8q - 1`; at n = 7, q = 8 and the limit is every u64.
    let limit = if q >= 8 { u64::MAX } else { (1u64 << (8 * q)) - 1 };
    eprintln!("Error: {msg}");
    eprintln!(
        "       Payload is {payload_len} bytes; with a {NONCE_LEN}-byte nonce, q = {q} and the \
         limit is {limit} bytes."
    );
    eprintln!("       Use a shorter nonce for a larger payload.");
    exit(-1)
}

/// One fully-instantiated CCM run.
///
/// `input` is processed in place through the key's in-place one-shots, so there is no second
/// buffer the size of `input` to allocate or copy into, and on the decrypt side nothing is written
/// to stdout until the tag has verified: the one-shot zeroizes the buffer on a failed check, so
/// Sec 6.2's "the payload P and the MAC T shall not be revealed" holds end to end.
fn go<F: CcmKeys<KEY_LEN>, const KEY_LEN: usize, const NONCE_LEN: usize, const TAG_LEN: usize>(
    key: &KeyMaterial<KEY_LEN>,
    nonce_bytes: &[u8],
    aad: &[u8],
    mut input: Vec<u8>,
    encrypt: bool,
    output_hex: bool,
) {
    // `run` dispatched on this exact length, so the conversion cannot fail.
    let Ok(nonce) = <[u8; NONCE_LEN]>::try_from(nonce_bytes) else {
        eprintln!("Error: internal nonce length mismatch.");
        exit(-1)
    };
    // `load_key` has already checked the length and type, so this is the schedule expansion.
    let key = F::Key::<NONCE_LEN, TAG_LEN>::from_key_material(key).unwrap_or_else(|e| {
        eprintln!("Error: AES-CCM key is not usable: {e:?}");
        exit(-1)
    });

    if encrypt {
        match key.encrypt_detached_in_place_nonce(&nonce, aad, &mut input) {
            Ok(tag) => {
                helpers::write_bytes_or_hex(&input, output_hex);
                helpers::write_bytes_or_hex(&tag, output_hex);
                if output_hex {
                    crate::helpers::write_stdout(b"\n");
                }
            }
            Err(SymmetricCipherError::GenericError(msg)) => {
                payload_past_the_q_limit::<NONCE_LEN>(msg, input.len())
            }
            Err(e) => {
                eprintln!("Error: AES-CCM encryption failed: {e:?}");
                exit(-1)
            }
        }
    } else {
        // `split_last_chunk_mut` is `None` exactly when there is no room for a `TAG_LEN`-byte tag,
        // the same octet-level test (and the same allowance for an empty payload plus its tag)
        // as Sec 6.2 step 1.
        let Some((data, tag)) = input.split_last_chunk_mut::<TAG_LEN>() else {
            eprintln!(
                "Error: input is {} bytes, shorter than the {TAG_LEN}-byte tag it must end with.",
                input.len()
            );
            exit(-1)
        };
        match key.decrypt_detached_in_place(&nonce, aad, data, tag) {
            Ok(()) => {
                helpers::write_bytes_or_hex(data, output_hex);
                if output_hex {
                    crate::helpers::write_stdout(b"\n");
                }
            }
            Err(SymmetricCipherError::AEADTagCheckFailed) => {
                eprintln!("Error: AES-CCM authentication failed; the input is not authentic.");
                exit(-1)
            }
            Err(SymmetricCipherError::GenericError(msg)) => {
                payload_past_the_q_limit::<NONCE_LEN>(msg, data.len())
            }
            Err(e) => {
                eprintln!("Error: AES-CCM decryption failed: {e:?}");
                exit(-1)
            }
        }
    }
}
