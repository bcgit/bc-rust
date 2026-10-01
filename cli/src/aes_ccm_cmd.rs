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
//! The AAD is different: `--aad-file` is streamed. CCM needs the AAD's length before its first
//! byte (A.2.2 puts the encoding of `a` in front of `A`), and a regular file's size is known
//! before it is read, so the file is declared by its size and fed to the MAC in 1 KiB chunks
//! without ever being held whole. A file with no size to declare -- a pipe, `/dev/stdin` -- is
//! read whole instead.
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

use std::fs::File;
use std::io::{self, Read};
use std::process::exit;

use bouncycastle::aes::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle::cipher::modes::{Ccm, Decrypting, Encrypting};
use bouncycastle::core::errors::SymmetricCipherError;
use bouncycastle::core::hazmat::ElectronicCodeBook;
use bouncycastle::core::key_material::KeyMaterial;
use bouncycastle::hex;

use crate::helpers;
use crate::helpers::block_mode_helpers::{BLOCK_LEN, CipherDirection, load_key};

/// Bytes of `--aad-file` read per call, matching the other commands' streaming chunk.
const CHUNK_LEN: usize = 1024;

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
    run::<AES128Internal, 16>(
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
    run::<AES192Internal, 24>(
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
    run::<AES256Internal, 32>(
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
/// `--nonce-file` reads raw bytes ([`r#mod::read_from_file_raw`]), not the hex-or-raw guess
/// [`r#mod::read_from_file`] uses for keys: a repeated nonce under one key is fatal for CCM (see
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

/// Where the AAD comes from.
enum Aad {
    /// `--aad` (hex), a `--aad-file` with no size to declare, or no AAD at all: held whole.
    Bytes(Vec<u8>),
    /// A `--aad-file` that is a regular file: declared by its size and read in [`CHUNK_LEN`]
    /// pieces by [`feed_aad`], never held whole.
    File { file: File, path: String, len: usize },
}

impl Aad {
    /// The AAD length to declare to [`Ccm::new_with_lengths`].
    fn len(&self) -> usize {
        match self {
            Aad::Bytes(bytes) => bytes.len(),
            Aad::File { len, .. } => *len,
        }
    }
}

/// Loads the AAD from `--aad-file` (raw bytes, never hex-decoded) or `--aad` (hex); the file wins
/// if both are given, as for `aes*-gcm`. Empty if neither is given.
///
/// A regular file is only opened and sized here; [`feed_aad`] reads it. Anything else -- a pipe, a
/// character device -- has no size to declare in advance, so it is read whole.
fn load_aad(aad: &Option<String>, aad_file: &Option<String>) -> Aad {
    if let Some(path) = aad_file {
        let file = File::open(path).unwrap_or_else(|e| {
            eprintln!("Error: couldn't read file '{path}': {e}");
            exit(-1)
        });
        let metadata = file.metadata().unwrap_or_else(|e| {
            eprintln!("Error: couldn't read file '{path}': {e}");
            exit(-1)
        });
        if !metadata.is_file() {
            return Aad::Bytes(helpers::read_from_file_raw(path));
        }
        let Ok(len) = usize::try_from(metadata.len()) else {
            eprintln!("Error: AAD file '{path}' is too large for this platform.");
            exit(-1)
        };
        Aad::File { file, path: path.clone(), len }
    } else if let Some(v) = aad {
        Aad::Bytes(hex::decode(v).unwrap_or_else(|_| {
            eprintln!("Error: associated data is not valid hex. Use --aad-file for raw bytes.");
            exit(-1)
        }))
    } else {
        Aad::Bytes(Vec::new())
    }
}

/// Supplies all of the AAD declared as [`Aad::len`] to `ccm`, reading an [`Aad::File`] a chunk at
/// a time.
///
/// The declared length is the file's size when it was opened. If the file changes size while it
/// is being read, the declared length is wrong, and the tag would be computed over a length
/// encoding that does not match the AAD; that is reported and the command exits rather than
/// producing it.
fn feed_aad<P, Dir, const KEY_LEN: usize, const NONCE_LEN: usize, const TAG_LEN: usize>(
    ccm: &mut Ccm<P, Dir, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN>,
    aad: &mut Aad,
) where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    match aad {
        Aad::Bytes(bytes) => {
            // Declared as exactly `bytes.len()`, and supplied in this one call.
            ccm.do_update_aad(bytes).expect("declared AAD length matches what was sent");
        }
        Aad::File { file, path, len } => {
            let mut buf = [0u8; CHUNK_LEN];
            let mut read = 0usize;
            loop {
                let n = file.read(&mut buf).unwrap_or_else(|e| {
                    eprintln!("Error: couldn't read file '{path}': {e}");
                    exit(-1)
                });
                if n == 0 {
                    break;
                }
                read += n;
                if ccm.do_update_aad(&buf[..n]).is_err() {
                    eprintln!("Error: AAD file '{path}' grew while it was being read.");
                    exit(-1)
                }
            }
            if read != *len {
                eprintln!("Error: AAD file '{path}' shrank while it was being read.");
                exit(-1)
            }
        }
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
    action: &CipherDirection,
    key: &KeyMaterial<KEY_LEN>,
    nonce: &Option<String>,
    nonce_file: &Option<String>,
    aad: &Option<String>,
    aad_file: &Option<String>,
    tag_len: usize,
    output_hex: bool,
) where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
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
    let mut aad = load_aad(aad, aad_file);
    let input = read_all_stdin();
    let encrypt = matches!(action, CipherDirection::Encrypt);

    macro_rules! with_tag_len {
        ($n:literal) => {
            match tag_len {
                4 => {
                    go::<P, KEY_LEN, $n, 4>(key, &nonce_bytes, &mut aad, input, encrypt, output_hex)
                }
                6 => {
                    go::<P, KEY_LEN, $n, 6>(key, &nonce_bytes, &mut aad, input, encrypt, output_hex)
                }
                8 => {
                    go::<P, KEY_LEN, $n, 8>(key, &nonce_bytes, &mut aad, input, encrypt, output_hex)
                }
                10 => go::<P, KEY_LEN, $n, 10>(
                    key, &nonce_bytes, &mut aad, input, encrypt, output_hex,
                ),
                12 => go::<P, KEY_LEN, $n, 12>(
                    key, &nonce_bytes, &mut aad, input, encrypt, output_hex,
                ),
                14 => go::<P, KEY_LEN, $n, 14>(
                    key, &nonce_bytes, &mut aad, input, encrypt, output_hex,
                ),
                16 => go::<P, KEY_LEN, $n, 16>(
                    key, &nonce_bytes, &mut aad, input, encrypt, output_hex,
                ),
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

/// Reports [`Ccm::new_with_lengths`]'s refusal of a payload past the `q` limit and exits.
///
/// The only [`SymmetricCipherError::GenericError`] it can return is that limit: A.1's
/// `p < 2^8q`, where `q = 15 - n`. Both directions hit it -- the decrypt side on the input minus
/// its tag -- so both report it here, with the numbers, since the fix is a shorter nonce.
fn payload_past_the_q_limit<P, const KEY_LEN: usize, const NONCE_LEN: usize, const TAG_LEN: usize>(
    msg: &str,
    payload_len: usize,
) -> !
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    eprintln!("Error: {msg}");
    eprintln!(
        "       Payload is {payload_len} bytes; with a {NONCE_LEN}-byte nonce, q = {} and the \
         limit is {} bytes.",
        15 - NONCE_LEN,
        Ccm::<P, Encrypting, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN>::MAX_PAYLOAD_LEN,
    );
    eprintln!("       Use a shorter nonce for a larger payload.");
    exit(-1)
}

/// One fully-instantiated CCM run.
///
/// `input` is processed in place through [`Ccm`]'s own streaming API rather than through the
/// one-shot [`Ccm::encrypt_out`]/[`Ccm::decrypt_out`], which each need a second, freshly allocated buffer
/// the size of `input`: the declared-length constructor already has everything a one-shot needs,
/// so there is no second buffer to allocate or copy into. The AAD goes in through
/// [`Ccm::new_with_lengths`] and [`feed_aad`], so a `--aad-file` is streamed rather than loaded.
fn go<P, const KEY_LEN: usize, const NONCE_LEN: usize, const TAG_LEN: usize>(
    key: &KeyMaterial<KEY_LEN>,
    nonce_bytes: &[u8],
    aad: &mut Aad,
    mut input: Vec<u8>,
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
        match Enc::<P, KEY_LEN, NONCE_LEN, TAG_LEN>::new_with_lengths(
            key,
            &nonce,
            aad.len(),
            input.len(),
        ) {
            Ok(mut ccm) => {
                feed_aad(&mut ccm, aad);
                // `new` already accepted this exact length as `input.len()`, and this is the one
                // and only call supplying it, so `take_owed` can never see too much and `owed`
                // can never be left nonzero: neither of these can fail on the path that reaches
                // them.
                ccm.do_encrypt(&mut input).expect("declared length matches what was sent");
                let tag = ccm.do_encrypt_final().expect("declared length was fully supplied");
                helpers::write_bytes_or_hex(&input, output_hex);
                helpers::write_bytes_or_hex(&tag, output_hex);
                if output_hex {
                    crate::helpers::write_stdout(b"\n");
                }
            }
            Err(SymmetricCipherError::GenericError(msg)) => {
                payload_past_the_q_limit::<P, KEY_LEN, NONCE_LEN, TAG_LEN>(msg, input.len())
            }
            Err(e) => {
                eprintln!("Error: AES-CCM encryption failed: {e:?}");
                exit(-1)
            }
        }
    } else {
        // `split_last_chunk_mut` is `None` exactly when there is no room for a `TAG_LEN`-byte tag,
        // which is the same octet-level test (and the same allowance for an empty payload plus its
        // tag) that `Ccm::decrypt_out`'s own doc comment explains for Sec 6.2 step 1.
        let Some((data, tag)) = input.split_last_chunk_mut::<TAG_LEN>() else {
            eprintln!(
                "Error: input is {} bytes, shorter than the {TAG_LEN}-byte tag it must end with.",
                input.len()
            );
            exit(-1)
        };
        match Dec::<P, KEY_LEN, NONCE_LEN, TAG_LEN>::new_with_lengths(
            key,
            &nonce,
            aad.len(),
            data.len(),
        ) {
            Ok(mut ccm) => {
                feed_aad(&mut ccm, aad);
                // As the encrypt arm above: `data.len()` is exactly the length just declared, and
                // it is supplied in this one call, so this cannot fail.
                ccm.do_decrypt_update(data).expect("declared length matches what was sent");
                match ccm.do_decrypt_final(tag) {
                    Ok(()) => {
                        helpers::write_bytes_or_hex(data, output_hex);
                        if output_hex {
                            crate::helpers::write_stdout(b"\n");
                        }
                    }
                    Err(SymmetricCipherError::AEADTagCheckFailed) => {
                        // Nothing has been written to stdout at this point, which is what
                        // processing in place still buys here: Sec 6.2's "the payload P and the
                        // MAC T shall not be revealed" holds end to end.
                        eprintln!(
                            "Error: AES-CCM authentication failed; the input is not authentic."
                        );
                        exit(-1)
                    }
                    Err(e) => {
                        eprintln!("Error: AES-CCM decryption failed: {e:?}");
                        exit(-1)
                    }
                }
            }
            Err(SymmetricCipherError::GenericError(msg)) => {
                payload_past_the_q_limit::<P, KEY_LEN, NONCE_LEN, TAG_LEN>(msg, data.len())
            }
            Err(e) => {
                eprintln!("Error: AES-CCM decryption failed: {e:?}");
                exit(-1)
            }
        }
    }
}
