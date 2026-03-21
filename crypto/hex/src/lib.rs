//! Good old fashioned hex encoder and decoder.
//!
//! This one is implemented using constant-time operations in the conversions
//! from Strings to byte values, so it is safe to use on cryptographic secret values.
//!
//! It should just work the way you expect: encode takes any bytes-like rust type
//! and returns a String, decode takes a String (which can be in any bytes-like container)
//! and returns a `Vec<u8>`.
//!
//! ```
//! use bouncycastle_hex as hex;
//!
//! let out = hex::encode(b"\x00\x01\x02\x03"); // "00010203"
//! let out = hex::encode(&[0x00, 0x01, 0x02, 0x03]); // "00010203"
//! let out = hex::encode(vec![0x00, 0x01, 0x02, 0x03]); // "00010203"
//!
//! let out = hex::decode("00010203").unwrap(); // [0x00, 0x01, 0x02, 0x03]
//! let out = hex::decode(b"00010203").unwrap(); // [0x00, 0x01, 0x02, 0x03]
//! ```
//!
//! The decoder ignores whitespace and "\x".

#![forbid(unsafe_code)]

use bouncycastle_utils::ct::Condition;

#[derive(Debug)]
pub enum HexError {
    InvalidHexCharacter(usize),
    OddLengthInput,
    InsufficientOutputBufferSize,
}

/// One-shot encode from bytes to a hex-encoded string using a constant-time implementation.
pub fn encode<T: AsRef<[u8]>>(input: T) -> String {
    let mut out = vec![0u8; input.as_ref().len() * 2];
    encode_out(input.as_ref(), &mut out).unwrap();

    String::from_utf8(out).unwrap()
}

/// expects an output array which is at least input.len() / 2 in size.
/// Returns the number of bytes written.
pub fn encode_out<T: AsRef<[u8]>>(input: T, out: &mut [u8]) -> Result<usize, HexError> {
    let inref = input.as_ref();
    if out.len() < inref.len() * 2 {
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

        // TODO: redo this once we have ct::u8 implemented ... the i64 is wasteful

        let c_09: i64 = '0' as i64 + (c as i64);
        let c_az: i64 = 'a' as i64 + (c as i64 - 10);

        let mut ret: i64 = c_09 as i64;
        ret = in_af.select(c_az as i64, ret);
        ret as u8
    }
}

/// One-shot decode from a hex string to a bytes using a constant-time implementation.
/// ignores whitespace and \x
pub fn decode<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>, HexError> {
    let inref = input.as_ref();
    let mut out: Vec<u8> = vec![0u8; inref.len() / 2];
    let bytes_written = decode_out(inref, &mut out)?;
    out.truncate(bytes_written);
    Ok(out)
}

/// expects an output array which is at least input.len() / 2 in size.
/// Returns the number of bytes written.
pub fn decode_out<T: AsRef<[u8]>>(input: T, out: &mut [u8]) -> Result<usize, HexError> {
    let inref = input.as_ref();
    if out.len() < inref.len() / 2 {
        return Err(HexError::InsufficientOutputBufferSize);
    }

    let mut b = 0u8;
    let mut b_i = 0u8;
    let mut out_i = 0_usize;
    let mut i = 0_usize;
    while i < inref.len() {
        let c = inref[i];

        // first check for whitespace and string null terminators, \x and invalid characters, which unfortunately cannot be done fully constant-time.
        match c {
            b' ' | b'\t' | b'\n' | b'\r' | 0 => {
                i += 1;
                continue;
            }
            b'\\' => {
                if inref[i + 1] == b'x' {
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

        // TODO: redo this once we have ct::u8 implemented ... the i64 is wasteful

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
