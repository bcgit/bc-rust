//! Good old fashioned base64 encoder and decoder.
//!
//! It should just work the way base64 normally works:
//! [`encode`] takes any bytes-like rust type and returns a String,
//! while [`decode`] takes a String (which can be in any bytes-like container)
//! and returns a `Vec<u8>`.
//!
//! Every function also has an `_out` form that writes into the caller's buffer and returns the
//! number of bytes written ([`encode_out`], [`decode_out`], and `do_update_out` / `do_final_out`
//! on the streaming types), with `_out_len` functions giving the buffer size needed. Those need
//! no allocator; the forms that return a `String` or a `Vec` need the `alloc` feature.
//!
//! ```
//! use bouncycastle_core::base64 as base64;
//!
//! let mut b64 = [0u8; 20];
//! let n = base64::encode_out(b"Hello, World!", &mut b64).unwrap();
//! assert_eq!(&b64[..n], b"SGVsbG8sIFdvcmxkIQ==");
//!
//! let mut bytes = [0u8; 15];
//! let n = base64::decode_out(&b64[..n], &mut bytes).unwrap();
//! assert_eq!(&bytes[..n], b"Hello, World!");
//! ```
//!
//!```
//! # #[cfg(feature = "alloc")] {
//! use bouncycastle_core::base64 as base64;
//!
//! let out = base64::encode(b"\x00"); // "AA=="
//! let out = base64::encode(b"Hello, World!"); // "SGVsbG8sIFdvcmxkIQ=="
//! let out = base64::encode(b"\x00\x01\x02\x03\x04\x05\x06"); // "AAECAwQFBg=="
//!
//! let out = base64::decode("AA==").unwrap(); // b"\x00"
//! let out = base64::decode("SGVsbG8sIFdvcmxkIQ==").unwrap(); // b"Hello, World!"
//! let out = base64::decode("AAECAwQFBg==").unwrap(); // b"\x00\x01\x02\x03\x04\x05\x06"
//!
//! // note that the decoder automatically ignores whitespace in the b64 input
//! let out1 = base64::decode("AAEC   Aw QFB\ng==").unwrap(); // b"\x00\x01\x02\x03\x04\x05\x06"
//! assert_eq!(out, out1);
//!
//! // it is also tolerant of missing padding characters
//! let out = base64::decode("AAECAwQFBg==").unwrap(); // b"\x00\x01\x02\x03\x04\x05\x06"
//! let out1 = base64::decode("AAECAwQFBg=").unwrap(); // b"\x00\x01\x02\x03\x04\x05\x06"
//! assert_eq!(out, out1);
//! let out2 = base64::decode("AAECAwQFBg").unwrap(); // b"\x00\x01\x02\x03\x04\x05\x06"
//! assert_eq!(out, out2);
//! # }
//! ```
//!
//! # Streaming
//! Unlike Hex, Base64 does not align cleanly to byte boundaries.
//! That means that the above one-shot APIs should only be used if you have the entire content to
//! process at the same time.
//! In other words, if data is arbitrarily broken into chunks and handed to the one-shot [`encode`] and [`decode`] APIs,
//! the results obtained will be incorrect.
//! Whenever it is necessary to process data in chunks, the streaming API that allows repeated calls to `do_update`
//! must be used. This produces output as it goes, and correctly holds on to the unprocessed
//! partial block until either `do_update` or `do_final` is called.
//!
//! ```
//! # #[cfg(feature = "alloc")] {
//! use bouncycastle_core::base64 as base64;
//!
//! let mut b64_str: String = String::new();
//! let mut encoder = base64::Base64Encoder::new();
//! b64_str.push_str( encoder.do_update(b"Hello,").as_str() );
//! b64_str.push_str( encoder.do_final(b" World!").as_str() );
//! assert_eq!(b64_str, "SGVsbG8sIFdvcmxkIQ==");
//!
//! let mut out_bytes = Vec::<u8>::new();
//! let mut decoder = base64::Base64Decoder::new(/*skip_whitespace*/ false);
//! out_bytes.extend( decoder.do_update("SGVs").unwrap() );
//! out_bytes.extend( decoder.do_final("bG8sIFdvcmxkIQ==").unwrap() );
//! assert_eq!(out_bytes, b"Hello, World!");
//! # }
//! ```
//!
//! # Security and constant-time
//!
//! The following paper proves that extremely clever attack algorithms exist to recover private keys
//! if the attacker is allowed to observe closely side-channels of the base64 decode process.
//!
//! > [Util::Lookup: Exploiting key decoding in cryptographic libraries (Sieck, 2021)](https://arxiv.org/pdf/2108.04600.pdf),
//!
//! As this is a cryptography library, it can be assumed that this base64 implementation will be used to encode
//! and decode private keys in PEM and JWK formats and so we are only providing a constant-time implementation
//! in order to remove the temptation to shoot yourself in the foot in the name of a small performance gain.
//!
//! During testing, a naïve lookup table-based implementation of base64::decode was 1.7x faster than
//! a constant-time implementation.
//! We are quite sure that optimized base64 implementations exist that provide still better performance.
//! It is necessary to encode gigabytes of non-sensitive data on base64, it is advised to use
//! one of the good, fast, but non-constant-time base64 implementations available from other projects.
//!
//!
//! # Alphabets:
//!
//! At the present time, this base64 implementation only supports the standard alphabet with "+" and "/", specifically:
//! ```text
//! ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=
//! ```
//! but additional alphabets such as the URLSafe alphabet will likely be added in future versions.
//     /// "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_="
//     URLSafe,

#[cfg(feature = "alloc")]
use alloc::{string::String, vec, vec::Vec};
use bouncycastle_utils::ct::Condition;
use bouncycastle_utils::secret::Secret;

/// One-shot encode from bytes to a base64-encoded string using a constant-time implementation.
///
/// Only available with the `alloc` feature.
#[cfg(feature = "alloc")]
pub fn encode<T: AsRef<[u8]>>(input: T) -> String {
    let input = input.as_ref();
    let mut out = vec![0u8; encode_out_len(input.len())];
    let n = encode_out(input, &mut out).expect("the buffer is encode_out_len long");
    out.truncate(n);
    String::from_utf8(out).expect("base64 output is ASCII")
}

/// As [`encode`], into `out`, which is zeroized first and must be at least
/// [`encode_out_len`]`(input.len())` long. Returns the number of bytes written.
pub fn encode_out<T: AsRef<[u8]>>(input: T, out: &mut [u8]) -> Result<usize, Base64Error> {
    Base64Encoder::new().do_final_out(input, out)
}

/// The length of the base64 encoding of `input_len` bytes, padding included: what [`encode_out`]
/// writes and needs.
pub const fn encode_out_len(input_len: usize) -> usize {
    // Saturating, so that a length too large to represent fails the buffer check.
    input_len.div_ceil(3).saturating_mul(4)
}

/// One-shot decode from a base64-encoded string to bytes using a constant-time implementation.
///
/// Only available with the `alloc` feature.
#[cfg(feature = "alloc")]
pub fn decode<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>, Base64Error> {
    let input = input.as_ref();
    let mut out = vec![0u8; decode_out_len(input.len())];
    let n = decode_out(input, &mut out)?;
    out.truncate(n);
    Ok(out)
}

/// As [`decode`], into `out`, which is zeroized first and must be at least
/// [`decode_out_len`]`(input.len())` long. Returns the number of bytes written. On an error `out`
/// is left zeroized.
pub fn decode_out<T: AsRef<[u8]>>(input: T, out: &mut [u8]) -> Result<usize, Base64Error> {
    Base64Decoder::new(true).do_final_out(input, out)
}

/// An upper bound on what [`decode_out`] writes for `input_len` characters of input, and so the
/// buffer it needs. Padding and skipped whitespace make the actual output shorter.
pub const fn decode_out_len(input_len: usize) -> usize {
    Base64Decoder::final_len_bound(0, input_len)
}

/// Return type for errors relating to Base64 encoding and decoding. Implements
/// [`core::error::Error`].
#[derive(Debug)]
pub enum Base64Error {
    /// The [`Base64Decoder::do_update`] method must not be called on a block that contains padding.
    /// If this error is returned, then the provided input has not been processed and the caller must instead
    /// pass the same input to [`Base64Decoder::do_final`]. Note that do_final() is tolerant of incomplete padding blocks,
    /// so even if an additional padding character is contained in the next chunk of input, do_final()
    /// will still produce the correct output -- ie any additional chunks held by the caller can be discarded.
    PaddingEncounteredDuringDoUpdate,

    /// Input contained a character that was not in the base64 alphabet. The index of the illegal character is included in the output.
    InvalidB64Character(usize),

    /// Padding where the data cannot end, or something other than the rest of the padding (and,
    /// when whitespace is skipped, whitespace) after it. The index of the offending character in
    /// the input to [`Base64Decoder::do_final`] is included.
    InvalidPadding(usize),

    /// The input ended one symbol into a block: six bits, which encode no whole byte.
    TruncatedInput,

    /// A [`Base64Decoder`] whose `do_update` or `do_update_out` failed for any reason other than
    /// padding or a short output buffer decodes nothing more: every later call returns this
    /// error. Make a new decoder.
    DecoderFailed,

    /// The output buffer of an `_out` function is shorter than its `_out_len` function asks for.
    /// No input was processed; after a `do_update_out` the encoder or decoder is as it was before
    /// the call.
    InsufficientOutputBufferSize,
}

// The input may be secret, so the messages leave out the index of the offending character.
impl core::fmt::Display for Base64Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::PaddingEncounteredDuringDoUpdate => "base64 padding passed to do_update",
            Self::InvalidB64Character(_) => "invalid base64 character",
            Self::InvalidPadding(_) => "invalid base64 padding",
            Self::TruncatedInput => "truncated base64 input",
            Self::DecoderFailed => "base64 decoder failed on an earlier call",
            Self::InsufficientOutputBufferSize => "output buffer too small",
        })
    }
}

impl core::error::Error for Base64Error {}

/// The stateful base64 encoder that supports streaming. The bytes it holds between calls, the
/// start of an incomplete block, are wiped when it is dropped.
pub struct Base64Encoder {
    buf: Secret<[u8; 3]>,
    vals_in_buf: usize,
}

impl Base64Encoder {
    /// Create a new instance.
    pub fn new() -> Self {
        Self { buf: Secret::new(), vals_in_buf: 0 }
    }

    fn ct_bin_to_b64(c: u8) -> u8 {
        let in_az = Condition::<i64>::is_within_range(c as i64, 26, 51);
        let in_09 = Condition::<i64>::is_within_range(c as i64, 52, 61);
        let eq_plus = Condition::<i64>::is_equal(c as i64, 62);
        let eq_slash = Condition::<i64>::is_equal(c as i64, 63);

        // TODO: redo this once we have ct::u8 implemented ... the i64 is wasteful

        #[allow(non_snake_case)]
        let c_AZ: i64 = 'A' as i64 + c as i64;
        let c_az: i64 = 'a' as i64 + (c as i64 - 26);
        let c_09: i64 = '0' as i64 + (c as i64 - 2 * 26);
        let c_plus: i64 = '+' as i64;
        let c_slash: i64 = '/' as i64;

        let mut ret: i64 = c_AZ as i64;
        ret = in_az.select(c_az as i64, ret);
        ret = in_09.select(c_09 as i64, ret);
        ret = eq_plus.select(c_plus, ret);
        ret = eq_slash.select(c_slash, ret);
        ret as u8
    }

    /// Streaming API that performs Base64 encoding of the provided input, but does not apply
    /// the final padding and will hold an incomplete block while waiting for more input.
    ///
    /// Only available with the `alloc` feature.
    #[cfg(feature = "alloc")]
    pub fn do_update<T: AsRef<[u8]>>(&mut self, input: T) -> String {
        let input = input.as_ref();
        let mut out = vec![0u8; self.update_out_len(input.len())];
        let n = self.do_update_out(input, &mut out).expect("the buffer is update_out_len long");
        out.truncate(n);
        String::from_utf8(out).expect("base64 output is ASCII")
    }

    /// As [`do_update`](Self::do_update), into `out`, which is zeroized first and must be at
    /// least [`update_out_len`](Self::update_out_len)`(input.len())` long. Returns the number of
    /// bytes written.
    pub fn do_update_out<T: AsRef<[u8]>>(
        &mut self,
        input: T,
        out: &mut [u8],
    ) -> Result<usize, Base64Error> {
        out.fill(0);
        let inref = input.as_ref();
        if out.len() < self.update_out_len(inref.len()) {
            return Err(Base64Error::InsufficientOutputBufferSize);
        }

        let mut written = 0;
        for &b in inref {
            self.buf[self.vals_in_buf] = b;
            self.vals_in_buf += 1;

            if self.vals_in_buf == 3 {
                Self::encode_block(&self.buf[..], &mut out[written..written + 4]);
                written += 4;
                self.vals_in_buf = 0;
            }
        }
        Ok(written)
    }

    /// What [`do_update_out`](Self::do_update_out) writes for `input_len` more bytes: four
    /// characters for every complete block, counting the bytes this encoder already holds.
    pub fn update_out_len(&self, input_len: usize) -> usize {
        (self.vals_in_buf.saturating_add(input_len) / 3).saturating_mul(4)
    }

    /// As you would expect, do_final() consumes the object along with a final block.
    /// do_final may be called with the entire content; ie without any do_update's before it.
    ///
    /// Only available with the `alloc` feature.
    #[cfg(feature = "alloc")]
    pub fn do_final<T: AsRef<[u8]>>(self, input: T) -> String {
        let input = input.as_ref();
        let mut out = vec![0u8; self.final_out_len(input.len())];
        let n = self.do_final_out(input, &mut out).expect("the buffer is final_out_len long");
        out.truncate(n);
        String::from_utf8(out).expect("base64 output is ASCII")
    }

    /// As [`do_final`](Self::do_final), into `out`, which is zeroized first and must be at least
    /// [`final_out_len`](Self::final_out_len)`(input.len())` long. Returns the number of bytes
    /// written. On [`Base64Error::InsufficientOutputBufferSize`] the encoder is consumed and
    /// nothing is written.
    pub fn do_final_out<T: AsRef<[u8]>>(
        mut self,
        input: T,
        out: &mut [u8],
    ) -> Result<usize, Base64Error> {
        out.fill(0);
        let input = input.as_ref();
        if out.len() < self.final_out_len(input.len()) {
            return Err(Base64Error::InsufficientOutputBufferSize);
        }
        let mut written = self.do_update_out(input, out)?;

        // pad the last block.
        if self.vals_in_buf != 0 {
            if self.vals_in_buf == 1 {
                self.buf[1] = 0;
            }
            if self.vals_in_buf <= 2 {
                self.buf[2] = 0;
            }
            let block = &mut out[written..written + 4];
            Self::encode_block(&self.buf[..], block);
            if self.vals_in_buf <= 2 {
                block[3] = b'=';
            }
            if self.vals_in_buf == 1 {
                block[2] = b'=';
            }
            written += 4;
        }
        Ok(written)
    }

    /// What [`do_final_out`](Self::do_final_out) writes for `input_len` more bytes: the encoding
    /// of everything this encoder holds and is given, padding included.
    pub fn final_out_len(&self, input_len: usize) -> usize {
        encode_out_len(self.vals_in_buf.saturating_add(input_len))
    }

    fn encode_block<T: AsRef<[u8]>>(input: T, out: &mut [u8]) {
        let inref = input.as_ref();
        assert!(inref.len() >= 3);
        assert!(out.len() >= 4);

        out.fill(0);

        out[0] = Self::ct_bin_to_b64(inref[0] >> 2);
        out[1] = Self::ct_bin_to_b64(((inref[0] & 0x03) << 4) | inref[1] >> 4);
        out[2] = Self::ct_bin_to_b64(((inref[1] & 0x0F) << 2) | inref[2] >> 6);
        out[3] = Self::ct_bin_to_b64(inref[2] & 0x3F);
    }
}

/// The stateful base64 decoder that supports streaming. The symbols it holds between calls, the
/// start of an incomplete block, are wiped when it is dropped. Once a call has failed on input
/// that is not base64, the decoder refuses every later call with [`Base64Error::DecoderFailed`],
/// so output cannot silently resume part-way through a message.
pub struct Base64Decoder {
    buf: Secret<[u8; 4]>,
    vals_in_buf: usize,
    skip_whitespace: bool,
    failed: bool,
}

impl Base64Decoder {
    /// Create a new instance.
    pub fn new(skip_whitespace: bool) -> Self {
        Base64Decoder { buf: Secret::new(), vals_in_buf: 0, skip_whitespace, failed: false }
    }

    fn ct_b64_to_bin(b: u8) -> u8 {
        let in_az = Condition::<i64>::is_within_range(b as i64, 97, 122);
        #[allow(non_snake_case)]
        let in_AZ = Condition::<i64>::is_within_range(b as i64, 65, 90);
        let in_09 = Condition::<i64>::is_within_range(b as i64, 48, 57);
        let is_plus = Condition::<i64>::is_equal(b as i64, 43);
        let is_slash = Condition::<i64>::is_equal(b as i64, 47);
        let is_padding = Condition::<i64>::is_equal(b as i64, 61);
        let is_whitespace = Condition::<i64>::is_in_list(
            b as i64,
            &[' ' as i64, '\t' as i64, '\n' as i64, '\r' as i64],
        );

        #[allow(non_snake_case)]
        let c_AZ: i64 = b as i64 - 'A' as i64;
        let c_az: i64 = b as i64 - 'a' as i64 + 26;
        let c_09: i64 = b as i64 - '0' as i64 + 2 * 26;

        let mut ret: i64 = 0xFFi64;

        ret = in_AZ.select(c_AZ, ret);
        ret = in_az.select(c_az, ret);
        ret = in_09.select(c_09, ret);
        ret = is_plus.select(62, ret);
        ret = is_slash.select(63, ret);
        ret = is_padding.select(0x81, ret);
        ret = is_whitespace.select(0x80, ret);

        ret as u8
    }

    /// Three bytes for every complete block of four symbols among `held` already held and
    /// `input_len` more, counting every input character as a symbol: an upper bound, since
    /// whitespace and padding are not symbols.
    const fn decoded_len_bound(held: usize, input_len: usize) -> usize {
        held.saturating_add(input_len) / 4 * 3
    }

    /// As [`decoded_len_bound`](Self::decoded_len_bound), with what a last partial block of two
    /// or three symbols decodes to (one or two bytes).
    const fn final_len_bound(held: usize, input_len: usize) -> usize {
        Self::decoded_len_bound(held, input_len)
            + (held.saturating_add(input_len) % 4).saturating_sub(1)
    }

    /// Streaming API that decodes the provided Base64 input, holding an incomplete block of
    /// symbols while waiting for more input. Padding is for [`do_final`](Self::do_final).
    ///
    /// Only available with the `alloc` feature.
    #[cfg(feature = "alloc")]
    pub fn do_update<T: AsRef<[u8]>>(&mut self, input: T) -> Result<Vec<u8>, Base64Error> {
        let input = input.as_ref();
        let mut out = vec![0u8; self.update_out_len(input.len())];
        let n = self.do_update_out(input, &mut out)?;
        out.truncate(n);
        Ok(out)
    }

    /// As [`do_update`](Self::do_update), into `out`, which is zeroized first and must be at
    /// least [`update_out_len`](Self::update_out_len)`(input.len())` long. Returns the number of
    /// bytes written. On an error `out` is left zeroized; on
    /// [`Base64Error::PaddingEncounteredDuringDoUpdate`] and
    /// [`Base64Error::InsufficientOutputBufferSize`] the decoder is as it was before the call, and
    /// on any other error it is wiped and fails: this and every later call returns
    /// [`Base64Error::DecoderFailed`].
    pub fn do_update_out<T: AsRef<[u8]>>(
        &mut self,
        input: T,
        out: &mut [u8],
    ) -> Result<usize, Base64Error> {
        out.fill(0);
        if self.failed {
            return Err(Base64Error::DecoderFailed);
        }
        let input = input.as_ref();
        if out.len() < self.update_out_len(input.len()) {
            return Err(Base64Error::InsufficientOutputBufferSize);
        }
        match self.decode_internal(input, true, out) {
            Ok((written, _)) => Ok(written),
            Err(e) => {
                out.fill(0);
                // The input is not base64, so the message cannot be decoded and the decoder
                // refuses to go on, rather than resume part-way through it; padding rolled the
                // state back for `do_final` to take over.
                if !matches!(e, Base64Error::PaddingEncounteredDuringDoUpdate) {
                    self.buf.zeroize();
                    self.vals_in_buf = 0;
                    self.failed = true;
                }
                Err(e)
            }
        }
    }

    /// An upper bound on what [`do_update_out`](Self::do_update_out) writes for `input_len` more
    /// characters, and so the buffer it needs.
    pub fn update_out_len(&self, input_len: usize) -> usize {
        Self::decoded_len_bound(self.vals_in_buf, input_len)
    }

    /// Decodes up to the first padding character into `out`, which the caller has sized by
    /// [`decoded_len_bound`](Self::decoded_len_bound), returning the number of bytes written and,
    /// if there was one, the padding character's index.
    fn decode_internal(
        &mut self,
        inref: &[u8],
        rollback_if_padding: bool,
        out: &mut [u8],
    ) -> Result<(usize, Option<usize>), Base64Error> {
        // copy the current state so that we can restore it if we encounter a padding character.
        let mut starting_state = Secret::<[u8; 4]>::new();
        starting_state.copy_from_slice(&self.buf[..]);
        let starting_vals_in_block: usize = self.vals_in_buf;

        let mut written: usize = 0;

        let mut i: usize = 0;
        while i < inref.len() {
            self.buf[self.vals_in_buf] = Self::ct_b64_to_bin(inref[i]);
            if self.buf[self.vals_in_buf] == 0xFF {
                return Err(Base64Error::InvalidB64Character(i));
            }
            if self.buf[self.vals_in_buf] == 0x80 {
                if self.skip_whitespace {
                    i += 1;
                    continue;
                } else {
                    return Err(Base64Error::InvalidB64Character(i));
                }
            }
            if self.buf[self.vals_in_buf] == 0x81 {
                // Padding. In `do_update` that is a contract violation: restore the state from
                // the start of the call and report it, discarding whatever this call had already
                // decoded, so that the caller can hand the *same* input to `do_final` and get all
                // of it back. Returning `Ok` with the partial output here would hand the caller
                // bytes the restored state is about to produce again. In `do_final` the padding
                // simply ends the data, and the partial block is finished by the caller.
                if rollback_if_padding {
                    self.buf.copy_from_slice(&starting_state[..]);
                    self.vals_in_buf = starting_vals_in_block;
                    return Err(Base64Error::PaddingEncounteredDuringDoUpdate);
                }
                return Ok((written, Some(i)));
            }

            i += 1;
            self.vals_in_buf += 1;

            // here, it can be assumed that the buffer contains no padding.
            if self.vals_in_buf == 4 {
                // decode block
                out[written] = self.buf[0] << 2 | self.buf[1] >> 4;
                out[written + 1] = self.buf[1] << 4 | self.buf[2] >> 2;
                out[written + 2] = self.buf[2] << 6 | self.buf[3];
                written += 3;
                self.vals_in_buf = 0;
                continue;
            }
        }

        Ok((written, None))
    }

    /// As can be expected, do_final() consumes the object.
    ///
    /// Missing padding is tolerated, but padding must come where the data can end, after two or
    /// three symbols of a block, and may be followed only by the rest of that padding (and
    /// whitespace, when it is skipped): anything else is [`Base64Error::InvalidPadding`]. Input
    /// ending one symbol into a block is [`Base64Error::TruncatedInput`].
    ///
    /// Only available with the `alloc` feature.
    #[cfg(feature = "alloc")]
    pub fn do_final<T: AsRef<[u8]>>(self, input: T) -> Result<Vec<u8>, Base64Error> {
        let input = input.as_ref();
        let mut out = vec![0u8; self.final_out_len(input.len())];
        let n = self.do_final_out(input, &mut out)?;
        out.truncate(n);
        Ok(out)
    }

    /// As [`do_final`](Self::do_final), into `out`, which is zeroized first and must be at least
    /// [`final_out_len`](Self::final_out_len)`(input.len())` long. Returns the number of bytes
    /// written. On an error `out` is left zeroized.
    pub fn do_final_out<T: AsRef<[u8]>>(
        self,
        input: T,
        out: &mut [u8],
    ) -> Result<usize, Base64Error> {
        out.fill(0);
        if self.failed {
            return Err(Base64Error::DecoderFailed);
        }
        let input = input.as_ref();
        if out.len() < self.final_out_len(input.len()) {
            return Err(Base64Error::InsufficientOutputBufferSize);
        }
        let result = self.finish_into(input, out);
        if result.is_err() {
            out.fill(0);
        }
        result
    }

    /// An upper bound on what [`do_final_out`](Self::do_final_out) writes for `input_len` more
    /// characters, and so the buffer it needs: the complete blocks, and one or two bytes for a
    /// last partial block of two or three symbols.
    pub fn final_out_len(&self, input_len: usize) -> usize {
        Self::final_len_bound(self.vals_in_buf, input_len)
    }

    fn finish_into(mut self, input: &[u8], out: &mut [u8]) -> Result<usize, Base64Error> {
        // process as much as we can the usual way.
        let (mut written, pad_at) = match self.decode_internal(input, false, out) {
            Ok(decoded) => decoded,
            Err(Base64Error::PaddingEncounteredDuringDoUpdate) => {
                unreachable!(
                    "rollback_if_padding = false should not produce a Base64Error::PaddingEncounteredDuringDoUpdate"
                );
            }
            Err(e) => return Err(e),
        };

        // RFC 4648 Section 4: a final quantum of 8 bits is two symbols and "==", of 16 bits three
        // symbols and "=". Section 3.3: implementations "MUST reject the encoded data if it
        // contains characters outside the base alphabet", which includes anything after the
        // padding, such as a second message.
        if let Some(pad_at) = pad_at {
            let pads_due = match self.vals_in_buf {
                2 => 2,
                3 => 1,
                _ => return Err(Base64Error::InvalidPadding(pad_at)),
            };
            let mut pads = 0;
            for (offset, &c) in input[pad_at..].iter().enumerate() {
                // Only padding and whitespace may follow, both public, so branching is fine.
                match Self::ct_b64_to_bin(c) {
                    0x81 if pads < pads_due => pads += 1,
                    0x80 if self.skip_whitespace => {}
                    _ => return Err(Base64Error::InvalidPadding(pad_at + offset)),
                }
            }
        }

        // now, a single block containing padding remains to be dealt with.
        match self.vals_in_buf {
            0 => {}
            // Six bits encode no whole byte.
            1 => return Err(Base64Error::TruncatedInput),
            2 => {
                out[written] = self.buf[0] << 2 | self.buf[1] >> 4;
                written += 1;
            }
            _ => {
                out[written] = self.buf[0] << 2 | self.buf[1] >> 4;
                out[written + 1] = self.buf[1] << 4 | self.buf[2] >> 2;
                written += 2;
            }
        }

        Ok(written)
    }
}
