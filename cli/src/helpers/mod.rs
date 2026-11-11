//! Shared plumbing: how files and stdin are read, how secrets are held, how output is written,
//! and the streaming loops the hash-like commands share.
//!
//! # Input conventions, the same for every subcommand
//!
//! - A value given inline (`--key`, `--iv`, `--nonce`, `--aad`, `--salt`, `--ikm`, `--verify`,
//!   `--element`, `--customization-hex`, ...) is hex.
//! - A value given as a file (`--key-file`, `--iv-file`, `--skfile`, `--sigfile`, ...), or on
//!   stdin where a command reads a key, seed, signature or ciphertext there, is the file's raw
//!   bytes. With the global `--hex-input` flag it is hex text instead, with whitespace, `\x`
//!   prefixes and a trailing newline ignored. There is no guessing: a raw file whose bytes happen
//!   to be hex digits is still raw.
//! - A trailing newline is part of a raw value except where a command says it strips one.
//! - Keys, seeds, private keys, salts and IKM are read into [`SecretBytes`], a `KeyMaterial`
//!   buffer that is zeroized when dropped, and never through a `Vec`; a secret longer than
//!   [`MAX_SECRET_LEN`] is refused.
//! - A read or write failure, a malformed value and a wrong length are reported on stderr with
//!   an `Error:` line and exit status 255; a panic is never the answer to input.

use bouncycastle::core::hazmat::do_hazardous_operations;
use bouncycastle::core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle::core::security_strength::SecurityStrength;
use bouncycastle::core::traits::{Hash, XOF, XOFSqueezer};
use bouncycastle::hex;
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::ops::RangeInclusive;
use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};

pub mod aead_cipher_helpers;
pub mod block_mode_helpers;
pub mod stream_mode_helpers;

/// Bytes read from stdin per call, and squeezed per call for an XOF.
pub(crate) const CHUNK_LEN: usize = 1024;

/// The most a secret read from a file, stdin or the command line may be: enough for an ML-DSA-87
/// private key (4896 bytes) in hex with room to spare.
pub(crate) const MAX_SECRET_LEN: usize = 16 * 1024;

/// A secret as read: a zeroized buffer holding up to [`MAX_SECRET_LEN`] bytes, tagged
/// [`KeyType::Unknown`] (or `Zeroized` when all zero); the command re-tags what it makes of it.
pub(crate) type SecretBytes = KeyMaterial<MAX_SECRET_LEN>;

/// The parsed `--hex-input` flag, process-wide: a CLI has one invocation, and `main` stores it
/// before any reader below runs, so no reader can see the default by mistake.
static HEX_INPUT: AtomicBool = AtomicBool::new(false);

/// Records the global `--hex-input` flag for the readers below.
pub(crate) fn set_hex_input(on: bool) {
    HEX_INPUT.store(on, Ordering::Relaxed);
}

/// Whether files and stdin values are hex text rather than raw bytes.
pub(crate) fn hex_input() -> bool {
    HEX_INPUT.load(Ordering::Relaxed)
}

// ---- public (non-secret) input ---------------------------------------------------------------

/// A file's bytes exactly as they are, regardless of `--hex-input`: for the data a command
/// authenticates or hashes rather than a value it decodes.
pub(crate) fn read_file(filename: &str) -> Vec<u8> {
    std::fs::read(filename).unwrap_or_else(|e| {
        eprintln!("Error: couldn't read file '{filename}': {e}");
        exit(-1);
    })
}

/// A file's value: its raw bytes, or its hex decoding under `--hex-input`.
pub(crate) fn read_input_file(filename: &str) -> Vec<u8> {
    let bytes = read_file(filename);
    if !hex_input() {
        return bytes;
    }
    hex::decode(&bytes).unwrap_or_else(|e| {
        eprintln!("Error: file '{filename}' is not valid hex (given --hex-input): {e:?}");
        exit(-1);
    })
}

/// Stdin's value, as [`read_input_file`] for a file.
pub(crate) fn read_input_stdin() -> Vec<u8> {
    let bytes = read_stdin_all();
    if !hex_input() {
        return bytes;
    }
    hex::decode(&bytes).unwrap_or_else(|e| {
        eprintln!("Error: stdin is not valid hex (given --hex-input): {e:?}");
        exit(-1);
    })
}

/// The value from the file when one is named, else from stdin.
pub(crate) fn read_input_file_or_stdin(filename: &Option<String>) -> Vec<u8> {
    match filename {
        Some(filename) => read_input_file(filename),
        None => read_input_stdin(),
    }
}

/// Decodes an inline hex argument, naming the flag in the error.
pub(crate) fn decode_hex_arg(value: &str, flag: &str) -> Vec<u8> {
    hex::decode(value).unwrap_or_else(|_| {
        eprintln!("Error: `--{flag}` must be hex.");
        exit(-1);
    })
}

// ---- secret input ----------------------------------------------------------------------------

/// Reads `source` to its end into a fresh [`SecretBytes`], refusing more than
/// [`MAX_SECRET_LEN`] bytes. `what` names the source for the messages.
fn read_secret_from(source: &mut impl Read, what: &str) -> SecretBytes {
    let mut secret = SecretBytes::new();
    let mut len = 0usize;
    let result = do_hazardous_operations(&mut secret, |secret| {
        let buf = secret.ref_to_bytes_mut()?;
        loop {
            let n = source.read(&mut buf[len..]).unwrap_or_else(|e| {
                eprintln!("Error: couldn't read {what}: {e}");
                exit(-1);
            });
            if n == 0 {
                break;
            }
            len += n;
            if len == buf.len() {
                // Full: anything more is over the limit. (A read of 0 into an empty slice is
                // indistinguishable from end of input, so probe explicitly.)
                let mut probe = [0u8; 1];
                if source.read(&mut probe).unwrap_or(0) != 0 {
                    eprintln!(
                        "Error: {what} is longer than the {MAX_SECRET_LEN} bytes a secret may be."
                    );
                    exit(-1);
                }
                break;
            }
        }
        secret.set_key_len(len)?;
        secret.set_key_type(KeyType::Unknown)
    });
    secret_tagging_error(result, what);
    secret
}

/// The hex decoding of `text`, into a fresh [`SecretBytes`]: the decoder writes straight into
/// the zeroized buffer, so the plaintext of the secret is never in a `Vec`.
fn decode_secret_hex(text: &[u8], what: &str) -> SecretBytes {
    let mut secret = SecretBytes::new();
    let result = do_hazardous_operations(&mut secret, |secret| {
        let out = secret.ref_to_bytes_mut()?;
        let len = hex::decode_out(text, out).unwrap_or_else(|e| {
            eprintln!("Error: {what} is not valid hex: {e:?}");
            exit(-1);
        });
        secret.set_key_len(len)?;
        secret.set_key_type(KeyType::Unknown)
    });
    secret_tagging_error(result, what);
    secret
}

/// `set_key_len` and `set_key_type` refuse nothing a reader can cause except an all-zero value,
/// which they tag `Zeroized` and report; that is a value, not an error, so it passes.
fn secret_tagging_error(
    result: Result<(), bouncycastle::core::errors::KeyMaterialError>,
    what: &str,
) {
    use bouncycastle::core::errors::KeyMaterialError;
    match result {
        Ok(()) | Err(KeyMaterialError::ActingOnZeroizedKey) => {}
        Err(e) => {
            eprintln!("Error: couldn't hold {what} as key material: {e:?}");
            exit(-1);
        }
    }
}

/// A secret from a file: its raw bytes, or its hex decoding under `--hex-input`.
pub(crate) fn read_secret_file(filename: &str) -> SecretBytes {
    let mut file = File::open(filename).unwrap_or_else(|e| {
        eprintln!("Error: couldn't open file '{filename}': {e}");
        exit(-1);
    });
    let what = format!("file '{filename}'");
    let raw = read_secret_from(&mut file, &what);
    if !hex_input() {
        return raw;
    }
    decode_secret_hex(raw.ref_to_bytes(), &what)
}

/// A secret from stdin, as [`read_secret_file`] for a file.
pub(crate) fn read_secret_stdin() -> SecretBytes {
    let raw = read_secret_from(&mut io::stdin(), "stdin");
    if !hex_input() {
        return raw;
    }
    decode_secret_hex(raw.ref_to_bytes(), "stdin")
}

/// The secret from the file when one is named, else from stdin.
pub(crate) fn read_secret_file_or_stdin(filename: &Option<String>) -> SecretBytes {
    match filename {
        Some(filename) => read_secret_file(filename),
        None => read_secret_stdin(),
    }
}

/// A secret given inline, in hex. The command line is visible to other users and kept in shell
/// history, which the help texts say; this only decodes what was given.
pub(crate) fn decode_hex_secret(value: &str, flag: &str) -> SecretBytes {
    decode_secret_hex(value.as_bytes(), &format!("`--{flag}`"))
}

/// A secret from `--<flag>-file` or `--<flag>` (hex); the file wins when both are given, as the
/// help texts say. Neither is an error.
pub(crate) fn load_secret(
    inline: &Option<String>,
    file: &Option<String>,
    flag: &str,
) -> SecretBytes {
    match (file, inline) {
        (Some(file), _) => read_secret_file(file),
        (None, Some(value)) => decode_hex_secret(value, flag),
        (None, None) => {
            eprintln!("Error: either `--{flag}` or `--{flag}-file` must be supplied.");
            exit(-1);
        }
    }
}

/// `bytes` without one trailing line ending (`\n` or `\r\n`), if it has one. Only the caller
/// knows, by the length it expects, whether that byte is part of the value.
pub(crate) fn strip_trailing_newline(bytes: &[u8]) -> &[u8] {
    bytes.strip_suffix(b"\r\n").or_else(|| bytes.strip_suffix(b"\n")).unwrap_or(bytes)
}

/// Warns on stderr, then lets the caller carry on, if `key` is empty or all zero bytes. A CLI is
/// used for test vectors and scripting, where such a key is a legitimate thing to want, so this
/// is a warning and not a refusal. Shared by every MAC key loader so they all say the same thing.
///
/// This looks at the bytes, not at [`KeyType::Zeroized`]: the secret readers above tag what they
/// read `Unknown` inside a hazardous-operations closure, which never produces `Zeroized`.
pub(crate) fn warn_if_zeroized_key(key: &impl KeyMaterialTrait) {
    if bouncycastle_utils::ct::ct_eq_zero_bytes(key.ref_to_bytes()) {
        eprintln!(
            "Warning: all-zero (or otherwise zeroized) key provided. Proceeding, but this is not secure."
        );
    }
}

/// The MAC key from `--key-file` or `--key` (hex), tagged as a MAC key with no stated strength
/// (a CLI is used for test vectors and scripting, so the commands build their keys allow-weak).
/// An all-zero key is accepted with a warning, see [`warn_if_zeroized_key`].
///
/// `len` is the algorithm's bound on the key length where it has one (BLAKE2b 1 to 64 bytes,
/// BLAKE2s 1 to 32, BLAKE3 exactly 32), refused here with a message naming the limit rather than
/// as the constructor's error. HMAC and KMAC pass `None`: HMAC hashes a key longer than its block
/// (RFC 2104 Section 2) and KMAC encodes the key's length (SP 800-185 Section 4.2), so any length
/// the secret buffer holds is accepted.
pub(crate) fn load_mac_key(
    key: &Option<String>,
    key_file: &Option<String>,
    len: Option<(&str, RangeInclusive<usize>)>,
) -> SecretBytes {
    let mut key = load_secret(key, key_file, "key");
    if let Some((alg_name, range)) = len {
        let got = key.key_len();
        if !range.contains(&got) {
            let (min_len, max_len) = (range.start(), range.end());
            if min_len == max_len {
                eprintln!("Error: {alg_name} requires a {min_len}-byte key; got {got} bytes.");
            } else {
                eprintln!(
                    "Error: {alg_name} requires a key of {min_len} to {max_len} bytes; got {got} bytes."
                );
            }
            exit(-1);
        }
    }
    warn_if_zeroized_key(&key);
    do_hazardous_operations(&mut key, |key| key.set_key_type(KeyType::MACKey)).unwrap_or_else(
        |e| {
            eprintln!("Error: couldn't load the key: {e:?}");
            exit(-1);
        },
    );
    key
}

// ---- stdin as data ---------------------------------------------------------------------------

/// One read from stdin into `buf`; a read error is reported, not a panic. Returns 0 at the end.
pub(crate) fn read_stdin_chunk(buf: &mut [u8]) -> usize {
    io::stdin().read(buf).unwrap_or_else(|e| {
        eprintln!("Error: failed to read from stdin: {e}");
        exit(-1);
    })
}

/// Feeds stdin to `sink` in pieces of at most [`CHUNK_LEN`] bytes, so a long input is never
/// held in memory.
pub(crate) fn stream_stdin(mut sink: impl FnMut(&[u8])) {
    let mut buf = [0u8; CHUNK_LEN];
    loop {
        let n = read_stdin_chunk(&mut buf);
        if n == 0 {
            return;
        }
        sink(&buf[..n]);
    }
}

/// All of stdin, where the whole input must be held anyway.
pub(crate) fn read_stdin_all() -> Vec<u8> {
    let mut out = Vec::new();
    stream_stdin(|chunk| out.extend_from_slice(chunk));
    out
}

// ---- output ----------------------------------------------------------------------------------

/// Writes `bytes` to stdout, exiting quietly if the reader has gone away.
///
/// A closed stdout -- `bc-rust ... | head -c 16` -- is the reader's choice, not a failure of ours,
/// and Unix tools die silently of SIGPIPE in that case. Rust ignores SIGPIPE and reports the
/// condition as an `io::Error` of kind `BrokenPipe` instead, which `print!`, `println!` and an
/// `.unwrap()` on a write all turn into a panic. So every write to stdout in this binary goes
/// through here or [`flush_stdout`], and a broken pipe is a quiet exit with status 0: the reader
/// got what it asked for. Any other write failure is reported and is an error.
pub(crate) fn write_stdout(bytes: &[u8]) {
    if let Err(e) = io::stdout().write_all(bytes) {
        exit_on_write_error(e);
    }
}

/// Flushes stdout; see [`write_stdout`] for the broken-pipe behaviour.
pub(crate) fn flush_stdout() {
    if let Err(e) = io::stdout().flush() {
        exit_on_write_error(e);
    }
}

/// `println!` without the panic: `text` and a newline, through [`write_stdout`].
pub(crate) fn println_stdout(text: &str) {
    write_stdout(text.as_bytes());
    write_stdout(b"\n");
}

fn exit_on_write_error(e: io::Error) -> ! {
    if e.kind() == io::ErrorKind::BrokenPipe {
        exit(0);
    }
    eprintln!("Error: failed to write to stdout: {e}");
    exit(-1);
}

pub(crate) fn write_bytes_or_hex(bytes: &[u8], output_hex: bool) {
    if output_hex {
        write_stdout(hex::encode(bytes).as_bytes());
    } else {
        write_stdout(bytes);
    }
}

/// Writes `bytes`, raw or as hex, to a new file `filename`; a failure names the path.
pub(crate) fn write_bytes_or_hex_to_file(bytes: &[u8], filename: &str, output_hex: bool) {
    let result = File::create(filename).and_then(|mut file| {
        if output_hex {
            file.write_all(hex::encode(bytes).as_bytes())
        } else {
            file.write_all(bytes)
        }
    });
    if let Err(e) = result {
        eprintln!("Error: couldn't write file '{filename}': {e}");
        exit(-1);
    }
}

// ---- seeds -----------------------------------------------------------------------------------

/// Why a seed was refused: its length, which is the only thing checked.
pub(crate) struct SeedError {
    pub(crate) got: usize,
}

/// A `SEED_LEN`-byte seed from its bytes, which the caller has already read (raw, or decoded
/// from hex under `--hex-input`). One trailing newline is tolerated, since a seed file written
/// with `echo` has one.
///
/// A seed is required to be unpredictable at the parameter set's strength; the CLI cannot know
/// whether it is, so an all-zero seed is accepted with a warning, which is what test vectors
/// need.
pub(crate) fn parse_seed<const SEED_LEN: usize>(
    bytes: &[u8],
) -> Result<KeyMaterial<SEED_LEN>, SeedError> {
    let bytes = if bytes.len() == SEED_LEN + 1 { strip_trailing_newline(bytes) } else { bytes };
    if bytes.len() != SEED_LEN {
        return Err(SeedError { got: bytes.len() });
    }
    let mut seed = KeyMaterial::<SEED_LEN>::from_bytes_as_type(bytes, KeyType::Seed)
        .unwrap_or_else(|e| {
            eprintln!("Error: couldn't hold the seed as key material: {e:?}");
            exit(-1);
        });
    if seed.key_type() == KeyType::Zeroized || seed.security_strength() < SecurityStrength::_256bit
    {
        eprintln!(
            "Warning: low entropy seed provided. We'll still process it, but it may be insecure."
        );
        do_hazardous_operations(&mut seed, |seed| {
            seed.set_key_type(KeyType::Seed)?;
            seed.set_security_strength(SecurityStrength::_256bit)
        })
        .unwrap_or_else(|e| {
            eprintln!("Error: couldn't tag the seed: {e:?}");
            exit(-1);
        });
    }
    Ok(seed)
}

/// Reports a refused seed and exits.
pub(crate) fn seed_error<const SEED_LEN: usize>(e: SeedError) -> ! {
    eprintln!(
        "Error: the seed must be {SEED_LEN} bytes (raw, or hex with --hex-input), got {} bytes.",
        e.got
    );
    exit(-1);
}

// ---- streaming loops -------------------------------------------------------------------------

/// Streams stdin through a [`Hash`] and writes the digest to stdout (hex or binary), followed by
/// a newline. Used by the SHA-2, SHA-3, SM3 and Ascon-Hash256 subcommands.
pub(crate) fn stream_hash(mut hasher: impl Hash, output_hex: bool) {
    stream_stdin(|chunk| hasher.do_update(chunk));
    let out = hasher.do_final();
    write_bytes_or_hex(&out, output_hex);
    write_stdout(b"\n");
}

/// Streams stdin through an [`XOF`] and squeezes `output_len` bytes to stdout (hex or binary),
/// followed by a newline. Used by the SHAKE, cSHAKE, the SP 800-185 XOFs and Ascon-XOF128/CXOF128
/// subcommands.
pub(crate) fn stream_xof(mut xof: impl XOF, output_len: usize, output_hex: bool) {
    stream_stdin(|chunk| xof.do_update(chunk));
    squeeze_to_stdout(xof.into_squeezer(), output_len, output_hex);
}

/// Writes `output_len` bytes of `squeezer` to stdout in [`CHUNK_LEN`] pieces, followed by a
/// newline, so the output is never held whole and a very long one is a long run rather than an
/// allocation.
pub(crate) fn squeeze_to_stdout(
    mut squeezer: impl XOFSqueezer,
    output_len: usize,
    output_hex: bool,
) {
    let mut buf = [0u8; CHUNK_LEN];
    let mut left = output_len;
    while left > 0 {
        let n = left.min(CHUNK_LEN);
        squeezer.do_output_out(&mut buf[..n]);
        write_bytes_or_hex(&buf[..n], output_hex);
        left -= n;
    }
    write_stdout(b"\n");
}
