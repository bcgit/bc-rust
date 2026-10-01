use bouncycastle::core::key_material::{
    KeyMaterial, KeyMaterialTrait, KeyType, do_hazardous_operations,
};
use bouncycastle::core::security_strength::SecurityStrength;
use bouncycastle::core::traits::{Hash, XOF, XOFSqueezer};
use bouncycastle::hex;
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::process::exit;

pub mod aead_cipher_helpers;
pub mod block_mode_helpers;
pub mod stream_mode_helpers;

/// Reads a file's bytes exactly as they are, with no hex-or-raw guessing.
///
/// Use this where a misread would silently change the *value* the caller asked for rather than
/// merely fail to match it -- a nonce is the reason this exists: two distinct binary nonce files
/// that happen to decode as hex to the same bytes must not collapse to one nonce (see
/// `aes_ccm_cmd::load_nonce`). [`read_from_file`]'s "try hex, fall back to raw" heuristic is fine
/// for a key, where a wrong guess only ever produces a mismatch, never a same-looking-different
/// value.
pub(crate) fn read_from_file_raw(filename: &str) -> Vec<u8> {
    std::fs::read(filename).unwrap_or_else(|e| {
        eprintln!("Error: couldn't read file '{filename}': {e}");
        exit(-1);
    })
}

/// `bytes` without one trailing line ending (`\n` or `\r\n`), if it has one.
///
/// Files written by shell tools usually end in a newline that is not part of the value. Whether
/// stripping it is right depends on what the caller expects -- a binary key whose last byte
/// happens to be `0x0a` must not lose it -- so this only removes the bytes; the caller decides,
/// by the length it knows, whether to use the result.
pub(crate) fn strip_trailing_newline(bytes: &[u8]) -> &[u8] {
    bytes.strip_suffix(b"\r\n").or_else(|| bytes.strip_suffix(b"\n")).unwrap_or(bytes)
}

/// The bytes a hex-or-raw input stands for: its hex decoding if it is hex -- with one trailing
/// line ending ignored, since files and pasted input usually end in one -- and the bytes
/// themselves, untouched, otherwise. A raw input keeps its trailing newline; only the caller
/// knows whether that byte is part of the value (see `block_mode_helpers::load_key`).
pub(crate) fn hex_or_raw(buf: Vec<u8>) -> Vec<u8> {
    match hex::decode(strip_trailing_newline(&buf)) {
        Ok(decoded) => decoded,
        Err(_) => buf,
    }
}

/// Reads either bin or hex
pub(crate) fn read_from_file(filename: &str) -> Vec<u8> {
    let file = File::open(&filename);
    if file.is_ok() {
        let mut buf = Vec::<u8>::new();
        match file.unwrap().read_to_end(&mut buf) {
            Ok(_bytes_read) => hex_or_raw(buf),
            Err(_) => {
                eprintln!("Error: couldn't open file '{}'", &filename);
                exit(-1);
            }
        }
    } else {
        eprintln!("Error: couldn't open file '{}'", &filename);
        exit(-1);
    }
}

/// Reads either bin or hex
pub(crate) fn read_from_file_or_stdin(filename: &Option<String>) -> Vec<u8> {
    if filename.is_some() {
        // This already reads either bin or hex
        return read_from_file(filename.as_ref().unwrap());
    }

    let mut buf = Vec::<u8>::new();
    io::stdin().read_to_end(&mut buf).expect("Failed to read from stdin");
    hex_or_raw(buf)
}

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

pub(crate) fn write_bytes_or_hex_to_file(bytes: &[u8], filename: &str, output_hex: bool) {
    let mut file = File::create(filename).expect("Failed to create file");

    if output_hex {
        for b in bytes.iter() {
            file.write_all(format!("{b:02x}").as_bytes()).unwrap();
        }
    } else {
        file.write_all(bytes).unwrap();
    }
}

/// Loads it as either hex or bytes
pub(crate) fn parse_seed<const SEED_LEN: usize>(bytes: &[u8]) -> Result<KeyMaterial<SEED_LEN>, ()> {
    let bytes = if bytes.len() == 65 { &bytes[..64] } else { bytes };

    // try decoding it as hex first
    let seed_bytes: [u8; SEED_LEN] = match &hex::decode(&bytes) {
        Ok(decoded_bytes) => {
            if decoded_bytes.len() < SEED_LEN || decoded_bytes.len() > SEED_LEN + 1 {
                // it was valid hex, but the wrong length
                return Err(());
            }

            decoded_bytes[..SEED_LEN].try_into().unwrap()
        }
        Err(_) => {
            // it's not hex, so take the first SEED_LEN bytes of the raw binary
            if bytes.len() < SEED_LEN || bytes.len() > SEED_LEN + 1 {
                return Err(());
            }

            bytes[..SEED_LEN].try_into().unwrap()
        }
    };

    // TODO: Verify that all error conditions have been checked
    let mut seed = KeyMaterial::<SEED_LEN>::from_bytes_as_type(&seed_bytes, KeyType::Seed).unwrap();

    if seed.key_type() == KeyType::Zeroized || seed.security_strength() < SecurityStrength::_256bit
    {
        eprintln!(
            "Warning: low entropy seed provided. We'll still process it, but it may be insecure."
        );

        do_hazardous_operations(&mut seed, |seed| {
            seed.set_key_type(KeyType::Seed)?;
            seed.set_security_strength(SecurityStrength::_256bit)
        })
        .unwrap();
    }

    Ok(seed)
}

/// Stream stdin through a [`Hash`] and write the digest to stdout (hex or binary), followed by a
/// newline. Used by both the SHA-3 and Ascon-Hash256 subcommands.
pub(crate) fn stream_hash(mut hasher: impl Hash, output_hex: bool) {
    let mut buf: [u8; 1024] = [0u8; 1024];

    let mut bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");

    while bytes_read != 0 {
        hasher.do_update(&buf[..bytes_read]);

        bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    }

    let out = hasher.do_final();
    write_bytes_or_hex(&out, output_hex);
    write_stdout(b"\n");
}

/// Stream stdin through an [`XOF`] and squeeze `output_len` bytes to stdout (hex or binary),
/// followed by a newline. Used by both the SHAKE and Ascon-XOF128/CXOF128 subcommands.
pub(crate) fn stream_xof(mut xof: impl XOF, output_len: usize, output_hex: bool) {
    let mut buf: [u8; 1024] = [0u8; 1024];

    let mut bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");

    while bytes_read != 0 {
        xof.do_update(&buf[..bytes_read]);

        bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    }

    let out = xof.into_squeezer().do_final(output_len);
    write_bytes_or_hex(&out, output_hex);
    write_stdout(b"\n");
}
