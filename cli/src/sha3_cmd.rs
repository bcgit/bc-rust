//! The SHA-3 family subcommands: `sha3-*`, `shake*`, `tuplehash*` and `parallelhash*`.

use bouncycastle::core::traits::Hash;

use bouncycastle::sha3::parallelhash::{ParallelHash128, ParallelHash256};
use bouncycastle::sha3::tuplehash::{TupleHash128, TupleHash256};
use bouncycastle::sha3::{SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256};
use core::num::NonZeroUsize;
use std::process::exit;

use crate::helpers::{decode_hex_arg, read_stdin_all, stream_hash, stream_stdin, stream_xof};

/// The most a fixed-length SP 800-185 function (KMAC, TupleHash, ParallelHash) will produce
/// here: their output length is bound into the computation before any output, so the library
/// computes it whole, and a request of gigabytes would be an allocation rather than a run. The
/// `*xof` subcommands stream any length.
pub(crate) const MAX_FIXED_OUTPUT_LEN: usize = 1 << 28;

#[allow(non_camel_case_types)]
pub(crate) enum SHA3Variant {
    SHA3_224,
    SHA3_256,
    SHA3_384,
    SHA3_512,
}

/// The security strength that selects a SHAKE-based function's instance: SHAKE128 or SHAKE256,
/// and with them the 128- and 256-bit KMAC, TupleHash and ParallelHash.
#[derive(Clone, Copy)]
pub(crate) enum Strength {
    Bits128,
    Bits256,
}

/// The customization string S of SP 800-185, from `--customization` (the characters) or
/// `--customization-hex` (bytes); empty when neither is given. Both given is an error, since
/// the one would silently win over the other.
pub(crate) fn load_customization(text: &Option<String>, hex: &Option<String>) -> Vec<u8> {
    match (text, hex) {
        (Some(_), Some(_)) => {
            eprintln!("Error: give `--customization` or `--customization-hex`, not both.");
            exit(-1);
        }
        (Some(text), None) => text.as_bytes().to_vec(),
        (None, Some(hex)) => decode_hex_arg(hex, "customization-hex"),
        (None, None) => Vec::new(),
    }
}

fn refuse_long_fixed_output(output_len: usize, xof_command: &str) {
    if output_len > MAX_FIXED_OUTPUT_LEN {
        eprintln!(
            "Error: this output is computed whole; the command takes at most {MAX_FIXED_OUTPUT_LEN} bytes. Use {xof_command} for a long, streamed output."
        );
        exit(-1);
    }
}

pub(crate) fn sha3_cmd(variant: SHA3Variant, output_hex: bool) {
    match variant {
        SHA3Variant::SHA3_224 => stream_hash(SHA3_224::new(), output_hex),
        SHA3Variant::SHA3_256 => stream_hash(SHA3_256::new(), output_hex),
        SHA3Variant::SHA3_384 => stream_hash(SHA3_384::new(), output_hex),
        SHA3Variant::SHA3_512 => stream_hash(SHA3_512::new(), output_hex),
    }
}

pub(crate) fn shake_cmd(strength: Strength, output_len: usize, output_hex: bool) {
    match strength {
        Strength::Bits128 => stream_xof(SHAKE128::new(), output_len, output_hex),
        Strength::Bits256 => stream_xof(SHAKE256::new(), output_len, output_hex),
    }
}

/// TupleHash (NIST SP 800-185 Sec 5): hashes a *tuple* of strings unambiguously.
///
/// The tuple comes from repeated `--element` flags, each a hex string. With none given, stdin is
/// hashed as a single-element tuple -- which is not the same as hashing those bytes with SHAKE,
/// because the element is length-prefixed.
pub(crate) fn tuplehash_cmd(
    strength: Strength,
    output_len: usize,
    elements: &[String],
    customization: &[u8],
    output_hex: bool,
) {
    refuse_long_fixed_output(output_len, "tuplehashxof*");
    let tuple = load_tuple(elements);
    let refs: Vec<&[u8]> = tuple.iter().map(|v| v.as_slice()).collect();

    let out = match strength {
        Strength::Bits128 => TupleHash128::new(customization, output_len)
            .unwrap_or_else(|_| output_len_error())
            .hash_tuple(&refs),
        Strength::Bits256 => TupleHash256::new(customization, output_len)
            .unwrap_or_else(|_| output_len_error())
            .hash_tuple(&refs),
    };
    write_out(&out, output_hex);
}

/// The tuple: the `--element` flags decoded, or stdin as the single element.
pub(crate) fn load_tuple(elements: &[String]) -> Vec<Vec<u8>> {
    if elements.is_empty() {
        vec![read_stdin_all()]
    } else {
        elements.iter().map(|e| decode_hex_arg(e, "element")).collect()
    }
}

fn output_len_error() -> ! {
    eprintln!("Error: the output length is larger than SP 800-185 allows here (Sec 7.2).");
    exit(-1);
}

/// ParallelHash (NIST SP 800-185 Sec 6): hashes stdin in `block_size`-byte blocks.
///
/// The block size is part of the function, not a tuning knob -- the same input under a different
/// block size gives an unrelated hash, so it must match on both sides.
pub(crate) fn parallelhash_cmd(
    strength: Strength,
    output_len: usize,
    block_size: usize,
    customization: &[u8],
    output_hex: bool,
) {
    refuse_long_fixed_output(output_len, "parallelhashxof*");
    let block_size = require_block_size(block_size);
    match strength {
        Strength::Bits128 => {
            let mut p = ParallelHash128::new(block_size, customization, output_len)
                .unwrap_or_else(|_| output_len_error());
            stream_stdin(|chunk| p.do_update(chunk));
            write_out(&p.do_final(), output_hex);
        }
        Strength::Bits256 => {
            let mut p = ParallelHash256::new(block_size, customization, output_len)
                .unwrap_or_else(|_| output_len_error());
            stream_stdin(|chunk| p.do_update(chunk));
            write_out(&p.do_final(), output_hex);
        }
    }
}

/// SP 800-185 Sec 6.2: B must be greater than zero.
pub(crate) fn require_block_size(block_size: usize) -> NonZeroUsize {
    NonZeroUsize::new(block_size).unwrap_or_else(|| {
        eprintln!("Error: --block-size must be greater than zero (SP 800-185 Sec 6.2).");
        exit(-1);
    })
}

/// Writes the digest as raw bytes or hex, with the trailing newline the other commands emit.
fn write_out(out: &[u8], output_hex: bool) {
    crate::helpers::write_bytes_or_hex(out, output_hex);
    crate::helpers::write_stdout(b"\n");
}
