//! Good old fashioned base64 encoder and decoder.
//!
//! It should just work the way you expect: [encode] takes any bytes-like rust type
//! and returns a String, while [decode] takes a String (which can be in any bytes-like container)
//! and returns a `Vec<u8>`.
//!
//!```
//! use bouncycastle_base64 as base64;
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
//! ```
//!
//! # Streaming
//! Unlike Hex, Base64 does not align cleanly to byte boundaries.
//! That means that the above one-shot APIs should only be used if you have the entire content to
//! process at the same time.
//! In other words, if you arbitrarily break your data into chunks and hand it to the one-shot [encode] and [decode] APIs,
//! you will get incorrect results.
//! If you need to process your data in chunks, you need to use the streaming API that allows
//! repeated calls to `do_update`, producing output as it goes, and correctly holds on to the unprocessed
//! partial block until either `do_update` or `do_final` is called.
//!
//! ```
//! use bouncycastle_base64 as base64;
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
//! ```
//!
//! # Security and constant-time
//!
//! The following paper proves that extremely clever attack algorithms exist to recover private keys
//! if the attacker is allowed to observe closely side-channels of the base64 decode process.
//!
//! > [Util::Lookup: Exploiting key decoding in cryptographic libraries (Sieck, 2021)](https://arxiv.org/pdf/2108.04600.pdf),
//!
//! As this is a cryptography library, we are assuming that this base64 implementation will be used to encode
//! and decode private keys in PEM and JWK formats and so we are only providing a constant-time implementation
//! in order to remove the temptation to shoot yourself in the foot in the name of a small performance gain.
//!
//! In our testing, a naïve lookup table-based implementation of base64::decode was 1.7x faster than
//! our constant-time implementation, and we are quite sure that optimized base64 implementations exist that
//! provide still better performance.
//! So if you find yourself in a position of needing to base64 encode gigabytes of non-sensitive data, then
//! we recommend you use one of the good, fast, but non-constant-time base64 implementations available from other projects.
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


use bouncycastle_utils::ct::Condition;

/// One-shot encode from bytes to a base64-encoded string using a constant-time implementation.
pub fn encode<T: AsRef<[u8]>>(input: T) -> String {
    Base64Encoder::new().do_final(input)
}

/// One-shot decode from a base64-encoded string to bytes using a constant-time implementation.
pub fn decode<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>, Base64Error> {
    Base64Decoder::new(true).do_final(input)
}

#[derive(Debug)]
pub enum Base64Error {
    /// the do_update() method must not be called on a block that contains padding.
    /// If this error is returned, then the provided input has not been processed and the caller must instead
    /// pass the same input to do_final(). Note that do_final() is tolerant of incomplete padding blocks,
    /// so even if an additional padding character is contained in the next chunk of input, do_final() will still produce
    /// the correct output -- ie any additional chunks held by the caller can be discarded.
    PaddingEnconteredDuringDoUpdate,

    /// Input contained a character that was not in the base64 alphabet. The index of the illegal character is included in the output.
    InvalidB64Character(usize),
}

/// The stateful base64 encoder that supports streaming.
pub struct Base64Encoder {
    buf: [u8; 3],
    vals_in_buf: usize,
}

impl Base64Encoder {
    /// Create a new instance.
    pub fn new() -> Self {
        Self { buf: [0; 3], vals_in_buf: 0 }
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

    pub fn do_update<T: AsRef<[u8]>>(&mut self, input: T) -> String {
        let inref = input.as_ref();
        let mut out: Vec<u8> = Vec::with_capacity(inref.len() * 4 / 3 + 4);
        let mut out_buf: [u8; 4] = [0; 4];

        for i in 0..inref.len() {
            self.buf[self.vals_in_buf] = inref[i];
            self.vals_in_buf += 1;

            if self.vals_in_buf == 3 {
                // process a block
                Self::encode_block(&self.buf, &mut out_buf);
                out.append(&mut out_buf.to_vec());
                self.vals_in_buf = 0;
            }
        }

        String::from_utf8(out).unwrap()
    }

    /// As you would expect, do_final() consumes the object along with a final block.
    /// do_final may be called with the entire content; ie without any do_update's before it.
    pub fn do_final<T: AsRef<[u8]>>(mut self, input: T) -> String {
        let mut out = self.do_update(input);

        // pad the last block.
        if self.vals_in_buf != 0 {
            let mut out_buf: [u8; 4] = [0; 4];
            if self.vals_in_buf == 1 {
                self.buf[1] = 0;
            }
            if self.vals_in_buf <= 2 {
                self.buf[2] = 0;
            }
            Self::encode_block(&self.buf, &mut out_buf);
            if self.vals_in_buf <= 2 {
                out_buf[3] = b'=';
            }
            if self.vals_in_buf == 1 {
                out_buf[2] = b'=';
            }
            out.push_str(std::str::from_utf8(&out_buf).unwrap());
        }
        out
    }

    fn encode_block<T: AsRef<[u8]>>(input: T, out: &mut [u8]) {
        let inref = input.as_ref();
        assert!(inref.len() >= 3);
        assert!(out.len() >= 4);

        out[0] = Self::ct_bin_to_b64(inref[0] >> 2);
        out[1] = Self::ct_bin_to_b64(((inref[0] & 0x03) << 4) | inref[1] >> 4);
        out[2] = Self::ct_bin_to_b64(((inref[1] & 0x0F) << 2) | inref[2] >> 6);
        out[3] = Self::ct_bin_to_b64(inref[2] & 0x3F);
    }
}

/// The stateful base64 decoder that supports streaming.
pub struct Base64Decoder {
    buf: [u8; 4],
    vals_in_buf: usize,
    skip_whitespace: bool,
}

impl Base64Decoder {
    /// Create a new instance.
    pub fn new(skip_whitespace: bool) -> Self {
        Base64Decoder { buf: [0; 4], vals_in_buf: 0, skip_whitespace }
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
        let c_09: i64 = b as i64 - '0' as i64 + 2*26;

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

    pub fn do_update<T: AsRef<[u8]>>(&mut self, input: T) -> Result<Vec<u8>, Base64Error> {
        self.decode_internal(input, true)
    }

    fn decode_internal<T: AsRef<[u8]>>(
        &mut self,
        input: T,
        rollback_if_padding: bool,
    ) -> Result<Vec<u8>, Base64Error> {
        // copy the current state so that we can restore it if we encounter a padding character.
        let starting_state: [u8; 4] = self.buf.clone();
        let starting_vals_in_block: usize = self.vals_in_buf;

        let inref = input.as_ref();
        let mut out: Vec<u8> = vec![];

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
                // Error: we found padding.
                if rollback_if_padding {
                    // Roll back and return Base64Error::NonFinalBlockContainsPadding.
                    self.buf = starting_state.clone();
                    self.vals_in_buf = starting_vals_in_block;
                }
                return Ok(out);
            }

            i += 1;
            self.vals_in_buf += 1;

            // here we get to assume that the buffer contains no padding.
            if self.vals_in_buf == 4 {
                // decode block
                out.push(self.buf[0] << 2 | self.buf[1] >> 4);
                out.push(self.buf[1] << 4 | self.buf[2] >> 2);
                out.push(self.buf[2] << 6 | self.buf[3]);
                self.vals_in_buf = 0;
                continue;
            }
        }

        Ok(out)
    }

    /// As you would expect, do_final() consumes the object.
    pub fn do_final<T: AsRef<[u8]>>(mut self, input: T) -> Result<Vec<u8>, Base64Error> {
        // process as much as we can the usual way.
        let mut out = match self.decode_internal(input, false) {
            Ok(out) => out,
            Err(Base64Error::PaddingEnconteredDuringDoUpdate) => {
                panic!("rollback_if_padding = false should not produce a Base64Error::PaddingEnconteredDuringDoUpdate");
            }
            Err(e) => return Err(e),
        };

        // now we only, maybe, have a single block containing padding to deal with.
        if self.vals_in_buf != 0 {
            // be tolerant of missing padding
            // if we're at the end and it's not a complete block, then imagine the missing padding.
            let pad_count: u8 = 3 - (self.vals_in_buf as u8 - 1);

            out.push(self.buf[0] << 2 | self.buf[1] >> 4);
            if pad_count != 2 {
                out.push(self.buf[1] << 4 | self.buf[2] >> 2);
            }
            if pad_count == 0 {
                out.push(self.buf[2] << 6 | self.buf[3]);
            }
        }

        Ok(out)
    }
}
