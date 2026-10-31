//! Poly1305 one-time authentication from [RFC 8439, section 2.5](https://www.rfc-editor.org/rfc/rfc8439#section-2.5).
//!
//! A [`Poly1305Key`] authenticates exactly one message: [`Poly1305Key::into_mac`] consumes it into
//! the one [`Poly1305`] worker it makes, which implements [`MAC`] with full 16-byte tags only:
//! truncation is rejected. Streaming and output-buffer methods do not allocate. Secret state is
//! zeroized on drop.
//!
//! A key is made from raw bytes by [`hazmat::key_from_bytes`], for a construction that derives a
//! fresh key for every message, as ChaCha20-Poly1305 does. For a key that authenticates any
//! number of messages, use a ChaCha20-Poly1305 key (`bouncycastle-chacha20-poly1305-aead`), which
//! derives the Poly1305 key from each nonce.
//!
//! # Usage Examples
//!
//! ```
//! use bouncycastle_core::traits::MAC;
//! use bouncycastle_poly1305::TAG_LEN;
//! use bouncycastle_poly1305::hazmat::key_from_bytes;
//! // Illustrative key only; a real one-time key is fresh, unpredictable and used once.
//! let one_time_key = [0x42; 32];
//! let mut mac = key_from_bytes(&one_time_key).into_mac();
//! mac.do_update(b"message");
//! let mut tag = [0u8; TAG_LEN];
//! mac.do_final_out(&mut tag).unwrap();
//! assert!(key_from_bytes(&one_time_key).into_mac().verify(b"message", &tag));
//! ```
//!
//! # Memory Usage
//!
//! | Type | In-memory size (bytes) |
//! |------|------------------------|
//! | [`Poly1305Key`] | 88 |
//! | [`Poly1305`] | 192 |
//!
//! "In-memory size" is `core::mem::size_of` on a 64-bit target. There are no heap allocations in
//! the streaming and `*_out` APIs, so this crate has no `mem_usage_benches` harness.
//!
//! # 🚨 Security Considerations 🚨
//!
//! - A key must be used for **exactly one message**: tags on two different messages under one
//!   key let an attacker forge others. A [`Poly1305Key`] is consumed by the one worker it makes,
//!   so it cannot authenticate a second message, but nothing stops a second key being made from
//!   the same bytes: that is the caller's to prevent, which is why the constructor is in
//!   [`hazmat`].

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

extern crate alloc;

pub mod hazmat;

use alloc::vec::Vec;
use bouncycastle_core::errors::MACError;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, MAC};
use bouncycastle_utils::ct::{self, Condition};
use bouncycastle_utils::secret::Secret;

/// One-time key length in bytes.
pub const KEY_LEN: usize = 32;
/// Authentication tag length in bytes.
pub const TAG_LEN: usize = 16;
/// Message block length in bytes.
const BLOCK_LEN: usize = 16;

const MASK: u64 = (1 << 26) - 1;

/// A full block's 2^128, as bit 24 of the top radix-2^26 limb.
const FULL_BLOCK_BIT: u64 = 1 << 24;

/// A Poly1305 key: the one-time key `r || s` of RFC 8439 Sec 2.5, clamped and split, made by
/// [`hazmat::key_from_bytes`] and consumed by the one [`Poly1305`] worker it makes. The key words
/// live in [`Secret`]s, zeroized on drop; there is no `Debug` and no way to read them back.
///
/// A key authenticates one message, so it cannot be used again once consumed, cannot be cloned,
/// and is neither a [`MacGenerationKey`](bouncycastle_core::symmetric_key::MacGenerationKey) nor a
/// [`MacVerificationKey`](bouncycastle_core::symmetric_key::MacVerificationKey), whose keys
/// authenticate any number. None of these compiles:
///
/// ```compile_fail
/// # use bouncycastle_core::traits::MAC;
/// # use bouncycastle_poly1305::hazmat::key_from_bytes;
/// let key = key_from_bytes(&[0x42; 32]);
/// let first = key.into_mac().mac(b"first message");
/// let second = key.into_mac().mac(b"second message");
/// ```
/// ```compile_fail
/// # use bouncycastle_poly1305::Poly1305Key;
/// fn cloneable<T: Clone>() {}
/// cloneable::<Poly1305Key>();
/// ```
/// ```compile_fail
/// # use bouncycastle_core::symmetric_key::MacGenerationKey;
/// # use bouncycastle_poly1305::Poly1305Key;
/// fn generation_key<K: MacGenerationKey>() {}
/// generation_key::<Poly1305Key>();
/// ```
/// ```compile_fail
/// # use bouncycastle_core::symmetric_key::MacVerificationKey;
/// # use bouncycastle_poly1305::Poly1305Key;
/// fn verification_key<K: MacVerificationKey>() {}
/// verification_key::<Poly1305Key>();
/// ```
///
/// Each compiles without its last line, as does [`Poly1305`]'s:
///
/// ```
/// # use bouncycastle_core::symmetric_key::{MacGenerationKey, MacVerificationKey};
/// # use bouncycastle_core::traits::MAC;
/// # use bouncycastle_poly1305::hazmat::key_from_bytes;
/// # use bouncycastle_poly1305::{Poly1305, Poly1305Key};
/// let key = key_from_bytes(&[0x42; 32]);
/// let first = key.into_mac().mac(b"first message");
/// fn cloneable<T: Clone>() {}
/// fn generation_key<K: MacGenerationKey>() {}
/// fn verification_key<K: MacVerificationKey>() {}
/// ```
pub struct Poly1305Key {
    /// `r`, clamped, in five radix-2^26 limbs.
    r: Secret<[u64; 5]>,
    /// `5 * r[1..5]`, the multipliers of the product terms that wrap past 2^130; see
    /// `Poly1305::process_block`. Computed once per key rather than per block.
    r5: Secret<[u64; 4]>,
    /// `s`, the half of the key added at the end, as four little-endian words.
    pad: Secret<[u32; 4]>,
}

impl Poly1305Key {
    /// RFC 8439 Sec 2.5's `clamp(r)` and its split of the key into `r` and `s`.
    fn from_key_bytes(bytes: &[u8; KEY_LEN]) -> Self {
        let mut r: Secret<[u64; 5]> = Secret::new();
        // Sec 2.5's `clamp(r): r &= 0x0ffffffc0ffffffc0ffffffc0fffffff`, little-endian: the top
        // four bits of bytes 3, 7, 11 and 15 and the low two bits of bytes 4, 8 and 12 are
        // cleared. Each limb is 26 bits of `r` read from a 32-bit window, so those bits land in
        // the limb masks: none in limb 0, bits 2-7 of limb 1, 8-13 of limb 2, 14-19 of limb 3,
        // and 20-23 of limb 4, which has only 24 bits to begin with.
        r[0] = load32(bytes, 0) & 0x3ffffff;
        r[1] = (load32(bytes, 3) >> 2) & 0x3ffff03;
        r[2] = (load32(bytes, 6) >> 4) & 0x3ffc0ff;
        r[3] = (load32(bytes, 9) >> 6) & 0x3f03fff;
        r[4] = (load32(bytes, 12) >> 8) & 0x00fffff;
        let mut pad: Secret<[u32; 4]> = Secret::new();
        let (s_words, _) = bytes[16..].as_chunks::<4>();
        for (word, chunk) in pad.iter_mut().zip(s_words) {
            *word = u32::from_le_bytes(*chunk);
        }
        let mut r5: Secret<[u64; 4]> = Secret::new();
        for (r5, r) in r5.iter_mut().zip(&r[1..]) {
            *r5 = 5 * r;
        }
        Self { r, r5, pad }
    }

    /// Consumes the key into the [`MAC`] worker for its one message, which can compute the tag
    /// or check one.
    pub fn into_mac(self) -> Poly1305 {
        Poly1305::from_key(self)
    }
}

/// The worker for a single Poly1305 message, made by [`Poly1305Key::into_mac`], using five
/// radix-2^26 limbs and 64-bit products. It cannot be cloned, since two workers under one key
/// could authenticate two messages:
///
/// ```compile_fail
/// # use bouncycastle_poly1305::Poly1305;
/// fn cloneable<T: Clone>() {}
/// cloneable::<Poly1305>();
/// ```
///
/// The implementation has no secret-dependent branches or memory indices. Multiplication
/// must have operand-independent timing on the target processor for constant-time execution.
pub struct Poly1305 {
    // The key the worker was made from, moved in: a key makes one worker, so there is nothing to
    // borrow it from.
    key: Poly1305Key,
    h: Secret<[u64; 5]>,
    /// `process_block`'s product accumulator: a function of `h` and `r`, so kept in a `Secret`
    /// that lives with the instance rather than being re-allocated and zeroized every block.
    product: Secret<[u64; 5]>,
    buffer: Secret<[u8; BLOCK_LEN]>,
    buffered: usize,
}

impl Algorithm for Poly1305 {
    const ALG_NAME: &'static str = "Poly1305";
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

impl Poly1305 {
    /// A fresh message under `key`.
    fn from_key(key: Poly1305Key) -> Self {
        Self { key, h: Secret::new(), product: Secret::new(), buffer: Secret::new(), buffered: 0 }
    }

    /// RFC 8439 Sec 2.5's `Acc = ((Acc+block)*r) % p` for one 16-byte block, with `high_bit` its
    /// "one bit beyond the number of octets": `FULL_BLOCK_BIT` for a full block, or 0 for the
    /// final partial one, which carries that bit as a `0x01` byte the caller has written in.
    fn process_block(&mut self, block: &[u8; BLOCK_LEN], high_bit: u64) {
        self.h[0] += load32(block, 0) & MASK;
        self.h[1] += (load32(block, 3) >> 2) & MASK;
        self.h[2] += (load32(block, 6) >> 4) & MASK;
        self.h[3] += (load32(block, 9) >> 6) & MASK;
        self.h[4] += (load32(block, 12) >> 8) | high_bit;

        // 2^130 = 5 (mod 2^130 - 5). Each sum is below 2^58, so u64 suffices.
        let product = &mut *self.product;
        *product = [0; 5];
        for i in 0..5 {
            for j in 0..5 {
                let index = i + j;
                if index < 5 {
                    product[index] += self.h[i] * self.key.r[j];
                } else {
                    // index >= 5 implies j >= 1. The same value as `5 * h[i] * r[j]`.
                    product[index - 5] += self.h[i] * self.key.r5[j - 1];
                }
            }
        }
        for i in 0..4 {
            self.h[i] = product[i] & MASK;
            product[i + 1] += product[i] >> 26;
        }
        self.h[4] = product[4] & MASK;
        self.h[0] += 5 * (product[4] >> 26);
        self.h[1] += self.h[0] >> 26;
        self.h[0] &= MASK;
    }

    /// Consumes this message and returns its full authentication tag: the body of the `MAC`
    /// impl's three finals.
    fn finalize(mut self) -> [u8; TAG_LEN] {
        if self.buffered != 0 {
            // The last, partial block: Sec 2.5.1's `| [0x01]` after its bytes, then zeros.
            // The bytes past `buffered` are already zero: the buffer is a fresh `Secret`
            // whenever a block completes, and `do_update` writes only the first `buffered`.
            let mut block = core::mem::replace(&mut self.buffer, Secret::new());
            block[self.buffered] = 1;
            self.process_block(&block, 0);
        }
        for i in 1..4 {
            self.h[i + 1] += self.h[i] >> 26;
            self.h[i] &= MASK;
        }
        self.h[0] += 5 * (self.h[4] >> 26);
        self.h[4] &= MASK;
        self.h[1] += self.h[0] >> 26;
        self.h[0] &= MASK;

        // Compute h - p and select it iff h >= p, without branching on the accumulator.
        let mut reduced: Secret<[u64; 5]> = Secret::new();
        reduced[0] = self.h[0] + 5;
        for i in 0..4 {
            reduced[i + 1] = self.h[i + 1] + (reduced[i] >> 26);
            reduced[i] &= MASK;
        }
        reduced[4] = reduced[4].wrapping_sub(1 << 26);
        // h >= p iff the borrow out of h - p is clear, i.e. iff reduced[4]'s top bit is 0; so h is
        // kept iff that bit is set.
        let keep_h = Condition::<u64>::from_msb(reduced[4]);
        for i in 0..5 {
            self.h[i] = keep_h.select(self.h[i], reduced[i]);
        }

        let mut words: Secret<[u64; 4]> = Secret::new();
        words[0] = (self.h[0] | (self.h[1] << 26)) & 0xffffffff;
        words[1] = ((self.h[1] >> 6) | (self.h[2] << 20)) & 0xffffffff;
        words[2] = ((self.h[2] >> 12) | (self.h[3] << 14)) & 0xffffffff;
        words[3] = ((self.h[3] >> 18) | (self.h[4] << 8)) & 0xffffffff;
        let mut tag = [0u8; TAG_LEN];
        for i in 0..4 {
            words[i] += u64::from(self.key.pad[i]);
            if i != 0 {
                words[i] += words[i - 1] >> 32;
            }
            tag[4 * i..4 * i + 4].copy_from_slice(&(words[i] as u32).to_le_bytes());
        }
        tag
    }
}

/// The little-endian 32-bit word at `at`, as the `u64` the limb arithmetic works in. Every call
/// site reads a fixed window of a fixed-length array, so the indices cannot miss.
fn load32<const N: usize>(bytes: &[u8; N], at: usize) -> u64 {
    u64::from(u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]))
}

impl MAC for Poly1305 {
    fn output_len(&self) -> usize {
        TAG_LEN
    }

    fn mac(mut self, data: &[u8]) -> Vec<u8> {
        self.do_update(data);
        self.do_final()
    }

    fn mac_out(mut self, data: &[u8], out: &mut [u8]) -> Result<usize, MACError> {
        self.do_update(data);
        self.do_final_out(out)
    }

    fn verify(mut self, data: &[u8], mac: &[u8]) -> bool {
        self.do_update(data);
        self.do_verify_final(mac)
    }

    fn do_update(&mut self, mut data: &[u8]) {
        // A partial block left by an earlier call is topped up first, and is the only data
        // that goes through the buffer apart from this call's own tail.
        if self.buffered != 0 {
            let n = (BLOCK_LEN - self.buffered).min(data.len());
            self.buffer[self.buffered..self.buffered + n].copy_from_slice(&data[..n]);
            self.buffered += n;
            data = &data[n..];
            if self.buffered < BLOCK_LEN {
                return;
            }
            let block = core::mem::replace(&mut self.buffer, Secret::new());
            self.process_block(&block, FULL_BLOCK_BIT);
            self.buffered = 0;
        }
        let (blocks, tail) = data.as_chunks::<BLOCK_LEN>();
        for block in blocks {
            self.process_block(block, FULL_BLOCK_BIT);
        }
        self.buffer[..tail.len()].copy_from_slice(tail);
        self.buffered = tail.len();
    }

    fn do_final(self) -> Vec<u8> {
        self.finalize().to_vec()
    }

    /// Writes the full 16-byte tag and clears the rest of `out`. Short buffers are cleared
    /// and rejected: Poly1305 tags must not be truncated.
    fn do_final_out(self, out: &mut [u8]) -> Result<usize, MACError> {
        out.fill(0);
        if out.len() < TAG_LEN {
            return Err(MACError::InvalidLength("Poly1305 requires a full 16-byte tag"));
        }
        out[..TAG_LEN].copy_from_slice(&self.finalize());
        Ok(TAG_LEN)
    }

    fn do_verify_final(self, mac: &[u8]) -> bool {
        ct::ct_eq_bytes(&self.finalize(), mac)
    }

    fn max_security_strength(&self) -> SecurityStrength {
        Self::MAX_SECURITY_STRENGTH
    }
}
