//! Block padding schemes implementing [`bouncycastle_core::traits::Padding`].
//!
//! * [`PKCS7`] — the padding scheme of RFC 5652 §6.3.
//! * [`PaddedEncryptor`] / [`PaddedDecryptor`] — adapt a block-aligned
//!   [`BlockCipherEncryptor`](bouncycastle_core::traits::BlockCipherEncryptor) /
//!   [`BlockCipherDecryptor`](bouncycastle_core::traits::BlockCipherDecryptor) to arbitrary-length
//!   data, streaming or one-shot.
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
//! # Memory Usage
//!
//! | Operation             | Stack (excluding the caller's buffers and the inner cipher) |
//! |-----------------------|-------------------------------------------------------------|
//! | `PKCS7::pad`          | O(1)                                                        |
//! | `PKCS7::unpad`        | O(1)                                                        |
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
