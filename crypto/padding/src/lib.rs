//! Block padding schemes implementing [`bouncycastle_core::traits::Padding`].
//!
//! * [`PKCS7`] — the padding scheme of RFC 5652 §6.3.
//! * [`NoPadding`] — adds nothing and refuses to: for data that must already be a whole number of
//!   blocks, where a partial final block is a caller error rather than something to pad.
//! * [`PaddedEncryptor`] / [`PaddedDecryptor`] — adapt a block-aligned
//!   [`BlockCipherEncryptor`](bouncycastle_core::traits::BlockCipherEncryptor) /
//!   [`BlockCipherDecryptor`](bouncycastle_core::traits::BlockCipherDecryptor) to arbitrary-length
//!   data, streaming or one-shot. With [`NoPadding`] they instead *enforce* block alignment: an
//!   aligned message passes through unchanged in length, and an unaligned one fails at `do_final`.
//!
//! # Usage Examples
//!
//! ```
//! use bouncycastle_core::traits::Padding;
//! use bouncycastle_padding::PKCS7;
//!
//! // 5 data bytes in a 16-byte block: pad with 11 bytes of value 0x0b.
//! let mut block = [0u8; 16];
//! block[..5].copy_from_slice(b"hello");
//! <PKCS7 as Padding<16>>::pad(&mut block, 5).unwrap();
//! assert_eq!(&block[..5], b"hello");
//! assert_eq!(&block[5..], &[0x0b; 11]);
//!
//! // Unpadding recovers the data length.
//! let data_len = <PKCS7 as Padding<16>>::unpad(&block).unwrap();
//! assert_eq!(data_len, 5);
//!
//! // A block that is not well-formed padding is rejected.
//! block[15] = 0x00;
//! assert!(<PKCS7 as Padding<16>>::unpad(&block).is_err());
//! ```
//!
//! `NoPadding` never writes a byte: asking it to is the error that tells the caller their data was
//! not block-aligned, and a "padded" block is all data.
//!
//! ```
//! use bouncycastle_core::errors::PaddingError;
//! use bouncycastle_core::traits::Padding;
//! use bouncycastle_padding::NoPadding;
//!
//! let mut block = [0x42u8; 16];
//! assert_eq!(<NoPadding as Padding<16>>::pad(&mut block, 5), Err(PaddingError::PaddingNotPermitted));
//! assert_eq!(block, [0x42u8; 16], "nothing was written");
//! assert_eq!(<NoPadding as Padding<16>>::unpad(&block), Ok(16));
//! ```
//!
//! # Memory Usage
//!
//! | Operation             | Stack (excluding the caller's buffers and the inner cipher) |
//! |-----------------------|-------------------------------------------------------------|
//! | `PKCS7::pad`          | O(1)                                                        |
//! | `PKCS7::unpad`        | O(1)                                                        |
//! | `NoPadding::pad` / `unpad` | O(1), touches no data                                  |
//! | `PaddedEncryptor`     | one `BLOCK_LEN` buffer (in a `Secret`) + a length            |
//! | `PaddedDecryptor`     | two `BLOCK_LEN` buffers + a length                          |
//!
//! # Security Considerations
//!
//! `unpad` is the classic padding-oracle site: if timing or the error depends on *which* byte was
//! malformed, an attacker who can submit ciphertexts can decrypt them byte by byte. [`PKCS7::unpad`]
//! inspects every byte with constant-time masks and returns a single undifferentiated
//! [`PaddingError::InvalidPadding`]. This does not make unauthenticated encryption safe: still
//! authenticate the ciphertext (MAC or AEAD) so the error is never reachable by an attacker.
//!
//! [`NoPadding`] has no padding to inspect and so no oracle of that kind; its `unpad` is a constant.
//! It does not make unauthenticated encryption safe either.

#![forbid(unsafe_code)]
#![forbid(missing_docs)]
#![no_std]

mod padded;
pub use padded::{PaddedDecryptor, PaddedEncryptor};

use bouncycastle_core::errors::PaddingError;
use bouncycastle_core::traits::Padding;
use bouncycastle_utils::ct::Condition;

/// RFC 5652 §6.3 padding (the CMS successor to PKCS #7): "the input shall be padded at the trailing
/// end with `k-(lth mod k)` octets all having value `k-(lth mod k)`". Defined only for block lengths
/// `0 < k < 256`, enforced at compile time.
pub struct PKCS7;

impl<const BLOCK_LEN: usize> Padding<BLOCK_LEN> for PKCS7 {
    /// RFC 5652 §6.3 always adds at least one octet, so an aligned input gets a whole extra block
    /// of padding (`pad(block, 0)`); otherwise the last block could not be unpadded unambiguously.
    const ALWAYS_PADS: bool = true;

    fn pad(block: &mut [u8; BLOCK_LEN], data_len: usize) -> Result<(), PaddingError> {
        const {
            assert!(
                BLOCK_LEN > 0 && BLOCK_LEN < 256,
                "PKCS7 padding is only defined for block lengths 1..=255 (RFC 5652 §6.3)"
            )
        }
        if data_len >= BLOCK_LEN {
            return Err(PaddingError::DataLengthTooLong(BLOCK_LEN - 1));
        }
        // RFC 5652 §6.3: pad with k - (lth mod k) octets of value k - (lth mod k). Here the caller
        // has already reduced lth mod k to data_len, so the value is simply BLOCK_LEN - data_len.
        // `data_len < BLOCK_LEN < 256` so this fits in a u8.
        let pad_byte = (BLOCK_LEN - data_len) as u8;
        // Constant-time in data_len: every byte is visited, and a mask selects data vs padding.
        for (i, b) in block.iter_mut().enumerate() {
            let is_padding = Condition::<i64>::is_gte(i as i64, data_len as i64);
            *b = is_padding.select(pad_byte as i64, *b as i64) as u8;
        }
        Ok(())
    }

    fn unpad(block: &[u8; BLOCK_LEN]) -> Result<usize, PaddingError> {
        const {
            assert!(
                BLOCK_LEN > 0 && BLOCK_LEN < 256,
                "PKCS7 padding is only defined for block lengths 1..=255 (RFC 5652 §6.3)"
            )
        }
        let k = BLOCK_LEN as i64;
        // The last byte declares the padding length p; the block is valid iff 1 <= p <= k and the
        // final p bytes all equal p. Every byte is examined regardless, so timing is independent of
        // where (or whether) the padding is malformed.
        let p = block[BLOCK_LEN - 1] as i64;
        let mut valid = Condition::<i64>::is_within_range(p, 1, k);
        for (i, b) in block.iter().enumerate() {
            // Position i is a padding position iff i >= k - p. (If p is out of range this may select
            // every position, but `valid` is already FALSE and cannot become TRUE again.)
            let in_padding = Condition::<i64>::is_gte(i as i64, k - p);
            let matches = Condition::<i64>::is_equal(*b as i64, p);
            valid &= matches | !in_padding;
        }
        // Single public decision point: the caller learns only valid/invalid.
        if valid.to_bool() {
            // p is within 1..=k here, so k - p is in 0..k and the cast is lossless.
            Ok((k - p) as usize)
        } else {
            Err(PaddingError::InvalidPadding)
        }
    }
}

/// The absence of padding, as a [`Padding`] scheme: for data that must already be a whole number of
/// blocks.
///
/// `pad` never writes anything -- it returns [`PaddingError::PaddingNotPermitted`] whenever it is
/// called, because being called means there was a partial block to pad -- and `unpad` reports the
/// whole block as data. Since [`ALWAYS_PADS`](Padding::ALWAYS_PADS) is `false`, a [`PaddedEncryptor`]
/// over it emits no final block for an aligned message and fails at `do_final` for an unaligned one,
/// and a [`PaddedDecryptor`] releases every block as data. The adapters thereby turn "the caller must
/// supply whole blocks" into a checked error instead of a silent assumption, which is what this
/// scheme is for: interoperating with formats that are defined on whole blocks (and, when used with
/// ECB, with the raw block-by-block operation they specify) while keeping the arbitrary-length API
/// shape.
///
/// It offers nothing that authentication would; see the crate's "Security Considerations".
pub struct NoPadding;

impl<const BLOCK_LEN: usize> Padding<BLOCK_LEN> for NoPadding {
    /// Adds nothing to aligned data: an aligned message is finished with no final block.
    const ALWAYS_PADS: bool = false;

    /// Always an error: this scheme adds no bytes, so being asked to means the data was not a
    /// whole number of blocks. `block` is left untouched. `data_len >= BLOCK_LEN` is reported as
    /// [`PaddingError::DataLengthTooLong`], as for every scheme.
    fn pad(_block: &mut [u8; BLOCK_LEN], data_len: usize) -> Result<(), PaddingError> {
        if data_len >= BLOCK_LEN {
            return Err(PaddingError::DataLengthTooLong(BLOCK_LEN - 1));
        }
        Err(PaddingError::PaddingNotPermitted)
    }

    /// The whole block is data. Constant, so trivially constant-time.
    fn unpad(_block: &[u8; BLOCK_LEN]) -> Result<usize, PaddingError> {
        Ok(BLOCK_LEN)
    }
}
