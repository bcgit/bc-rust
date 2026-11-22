//! Good old fashioned hex encoder and decoder.
//!
//! This one is implemented using constant-time operations in the conversions
//! from Strings to byte values, so it is safe to use on cryptographic secret values.
//!
//! It should just work as expected:
//! encode takes any bytes-like rust type and returns a String,
//! decode takes a String (which can be in any bytes-like container) and returns a `Vec<u8>`.
//!
//! Moreover, the API of this crate is intended to mirror that of the public `hex` crate,
//! so you should generally be able to swap `use hex` for `use bouncycastle_hex` and all the function
//! calls and behaviours should work as expected.
//!
//! ```
//! # #[cfg(feature = "std")] {
//! use bouncycastle_hex as hex;
//!
//! let out = hex::encode(b"\x00\x01\x02\x03"); // "00010203"
//! let out = hex::encode(&[0x00, 0x01, 0x02, 0x03]); // "00010203"
//! let out = hex::encode(vec![0x00, 0x01, 0x02, 0x03]); // "00010203"
//!
//! let out = hex::decode("00010203").unwrap(); // [0x00, 0x01, 0x02, 0x03]
//! let out = hex::decode(b"00010203").unwrap(); // [0x00, 0x01, 0x02, 0x03]
//! # }
//! ```
//!
//! The decoder ignores whitespace, NUL and "\x".
//!
//! [`encode_out`] and [`decode_out`] write into the caller's buffer instead, sized by
//! [`encode_out_len`] and [`decode_out_len`], and need no allocator; [`encode`] and [`decode`]
//! need the `std` feature.

#![no_std]
// Docs link to the allocating one-shots, which a build without `std` does not have.
#![cfg_attr(not(feature = "std"), allow(rustdoc::broken_intra_doc_links))]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

#[cfg(feature = "std")]
extern crate std;

use bouncycastle_utils::ct::Condition;
#[cfg(feature = "std")]
use std::{string::String, vec, vec::Vec};

/// Return type for errors relating to Hex encoding and decoding.
#[derive(Debug)]
pub enum HexError {
    /// Invalid hex character encountered at the given index.
    InvalidHexCharacter(usize),
    /// Since hex encodes each byte as two characters, the input must have an even length.
    OddLengthInput,
    /// The output buffer is shorter than [`encode_out_len`] or [`decode_out_len`] asks for.
    InsufficientOutputBufferSize,
}

/// One-shot encode from bytes to a hex-encoded string using a constant-time implementation.
///
/// Only available with the `std` feature.
#[cfg(feature = "std")]
pub fn encode<T: AsRef<[u8]>>(input: T) -> String {
    let mut out = vec![0u8; encode_out_len(input.as_ref().len())];
    encode_out(input.as_ref(), &mut out).expect("the buffer is encode_out_len long");

    String::from_utf8(out).expect("hex output is ASCII")
}

/// As [`encode`], into `out`, which is zeroized first and must be at least
/// [`encode_out_len`]`(input.len())` long. Returns the number of bytes written.
pub fn encode_out<T: AsRef<[u8]>>(input: T, out: &mut [u8]) -> Result<usize, HexError> {
    out.fill(0);
    let inref = input.as_ref();
    if out.len() < encode_out_len(inref.len()) {
        return Err(HexError::InsufficientOutputBufferSize);
    }

    for i in 0..inref.len() {
        out[2 * i] = ct_word_to_hex(inref[i] >> 4);
        out[2 * i + 1] = ct_word_to_hex(inref[i] & 0x0F);
    }
    return Ok(inref.len() * 2);

    /// Expects a 4-bit word in the least significant bits.
    fn ct_word_to_hex(mut c: u8) -> u8 {
        // Make sure there's nothing in the top bits
        c &= 0x0F;

        // let in_09 = Condition::<i64>::is_within_range(c as i64, 0, 9);
        let in_af = Condition::<i64>::is_within_range(c as i64, 10, 15);

        // TODO: redo this once we have ct::u8 implemented
        // The i64 is wasteful

        let c_09: i64 = '0' as i64 + (c as i64);
        let c_az: i64 = 'a' as i64 + (c as i64 - 10);

        let mut ret: i64 = c_09 as i64;
        ret = in_af.select(c_az as i64, ret);
        ret as u8
    }
}

/// The length of the hex encoding of `input_len` bytes: what [`encode_out`] writes and needs.
pub const fn encode_out_len(input_len: usize) -> usize {
    // Saturating, so that a length too large to represent fails the buffer check.
    input_len.saturating_mul(2)
}

/// One-shot decode from a hex string to a bytes using a constant-time implementation.
/// ignores whitespace, NUL and \x
///
/// Only available with the `std` feature.
#[cfg(feature = "std")]
pub fn decode<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>, HexError> {
    let inref = input.as_ref();
    let mut out: Vec<u8> = vec![0u8; decode_out_len(inref.len())];
    let bytes_written = decode_out(inref, &mut out)?;
    out.truncate(bytes_written);
    Ok(out)
}

/// An upper bound on what [`decode_out`] writes for `input_len` characters, and so the buffer it
/// needs; exact when the input has no whitespace, NUL or `\x`.
pub const fn decode_out_len(input_len: usize) -> usize {
    input_len / 2
}

/// As [`decode`], into `out`, which is zeroized first and must be at least
/// [`decode_out_len`]`(input.len())` long. Returns the number of bytes written. On an error `out`
/// is left zeroized.
pub fn decode_out<T: AsRef<[u8]>>(input: T, out: &mut [u8]) -> Result<usize, HexError> {
    out.fill(0);
    let inref = input.as_ref();
    if out.len() < decode_out_len(inref.len()) {
        return Err(HexError::InsufficientOutputBufferSize);
    }
    let result = decode_into(inref, out);
    if result.is_err() {
        out.fill(0);
    }
    result
}

fn decode_into(inref: &[u8], out: &mut [u8]) -> Result<usize, HexError> {
    let mut b = 0u8;
    let mut b_i = 0u8;
    let mut out_i = 0_usize;
    let mut i = 0_usize;
    while i < inref.len() {
        let c = inref[i];

        // first check for whitespace and string null terminators, \x and invalid characters,
        // which unfortunately cannot be done fully constant-time.
        match c {
            b' ' | b'\t' | b'\n' | b'\r' | 0 => {
                i += 1;
                continue;
            }
            b'\\' => {
                // A backslash is only ever skippable as the `\x` prefix of an escaped byte. One
                // that ends the input, or is followed by anything else, falls through to the
                // digit lookup below and is reported as an invalid character at its own index.
                if i + 1 < inref.len() && inref[i + 1] == b'x' {
                    i += 2;
                    continue;
                }
            }
            _ => {}
        }

        // parse two hex digits to form one output byte;
        // the first one is the upper 4 bits.
        b |= match ct_hex_to_word(c) {
            0xFF => return Err(HexError::InvalidHexCharacter(i)),
            c => c,
        } << (4 * (1 - b_i));

        if b_i == 1 {
            out[out_i] = b;
            out_i += 1;
            b = 0;
            b_i = 0;
        } else {
            b_i = 1;
        }
        i += 1;
    }
    // if b_i != 0, then we have an un-processed word in the buffer.
    if b_i != 0 {
        return Err(HexError::OddLengthInput);
    }

    return Ok(out_i);

    fn ct_hex_to_word(b: u8) -> u8 {
        let in_09 = Condition::<i64>::is_within_range(b as i64, 48, 57);
        let in_af = Condition::<i64>::is_within_range(b as i64, 97, 102);
        #[allow(non_snake_case)]
        let in_AF = Condition::<i64>::is_within_range(b as i64, 65, 70);

        // TODO: redo this once we have ct::u8 implemented
        // The i64 is wasteful

        let c_09: i64 = b as i64 - ('0' as i64);
        #[allow(non_snake_case)]
        let c_AF: i64 = b as i64 - ('A' as i64) + 10;
        let c_af: i64 = b as i64 - ('a' as i64) + 10;

        let mut ret: i64 = 0xFFi64;

        ret = in_09.select(c_09, ret);
        ret = in_AF.select(c_AF, ret);
        ret = in_af.select(c_af, ret);

        ret as u8
    }
}
