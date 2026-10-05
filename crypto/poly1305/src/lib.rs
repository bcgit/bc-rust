//! Poly1305 one-time authentication from [RFC 8439, section 2.5](https://www.rfc-editor.org/rfc/rfc8439#section-2.5).
//!
//! A 32-byte key must be used for **exactly one message**. Finalization consumes the instance;
//! callers remain responsible for never initializing another message with that key.
//! This implements [`MAC`] with full 16-byte tags only: truncation is rejected. Streaming and
//! output-buffer methods do not allocate. Secret state is zeroized on drop.
//!
//! ```
//! use bouncycastle_core::{key_material::{KeyMaterial, KeyType}, traits::MAC};
//! use bouncycastle_poly1305::Poly1305;
//! // Illustrative key only; use a fresh, unpredictable one-time key in an application.
//! let key = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::MACKey).unwrap();
//! let mut mac = Poly1305::new(&key).unwrap();
//! mac.do_update(b"message");
//! let tag = mac.finalize();
//! assert_eq!(tag.len(), 16);
//! ```

#![forbid(unsafe_code)]
#![forbid(missing_docs)]

use bouncycastle_core::errors::{KeyMaterialError, MACError};
use bouncycastle_core::key_material::{KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, MAC};
use bouncycastle_utils::{ct, secret::Secret};

/// One-time key length in bytes.
pub const KEY_LEN: usize = 32;
/// Authentication tag length in bytes.
pub const TAG_LEN: usize = 16;
/// Message block length in bytes.
pub const BLOCK_LEN: usize = 16;

const MASK: u64 = (1 << 26) - 1;

/// A single Poly1305 message, using five radix-2^26 limbs and 64-bit products.
///
/// The implementation has no secret-dependent branches or memory indices. Multiplication
/// must have operand-independent timing on the target processor for constant-time execution.
pub struct Poly1305 {
    r: Secret<[u64; 5]>,
    pad: Secret<[u32; 4]>,
    h: Secret<[u64; 5]>,
    buffer: Secret<[u8; BLOCK_LEN]>,
    buffered: usize,
}

impl Algorithm for Poly1305 {
    const ALG_NAME: &'static str = "Poly1305";
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

impl Poly1305 {
    fn init(key: &impl KeyMaterialTrait, allow_weak: bool) -> Result<Self, MACError> {
        if key.key_len() != KEY_LEN {
            return Err(MACError::InvalidLength("Poly1305 requires a 32-byte one-time key"));
        }
        if key.key_type() != KeyType::MACKey && !(allow_weak && key.key_type() == KeyType::Zeroized)
        {
            return Err(KeyMaterialError::InvalidKeyType("Poly1305 requires a MAC key").into());
        }
        if !allow_weak && key.security_strength() < Self::MAX_SECURITY_STRENGTH {
            return Err(KeyMaterialError::SecurityStrength(
                "Poly1305 requires at least 128-bit key strength",
            )
            .into());
        }
        let bytes = key.ref_to_bytes();
        let mut r: Secret<[u64; 5]> = Secret::new();
        // RFC 8439 clamping, expressed directly in the radix-2^26 representation.
        r[0] = load32(&bytes[0..4]) & 0x3ffffff;
        r[1] = (load32(&bytes[3..7]) >> 2) & 0x3ffff03;
        r[2] = (load32(&bytes[6..10]) >> 4) & 0x3ffc0ff;
        r[3] = (load32(&bytes[9..13]) >> 6) & 0x3f03fff;
        r[4] = (load32(&bytes[12..16]) >> 8) & 0x00fffff;
        let mut pad: Secret<[u32; 4]> = Secret::new();
        for (word, chunk) in pad.iter_mut().zip(bytes[16..].chunks_exact(4)) {
            *word = u32::from_le_bytes(chunk.try_into().unwrap());
        }
        Ok(Self { r, pad, h: Secret::new(), buffer: Secret::new(), buffered: 0 })
    }

    fn process_block(&mut self) {
        // Append one bit immediately above the message bytes, even on a partial block.
        let high_bit = if self.buffered == BLOCK_LEN {
            1 << 24
        } else {
            self.buffer[self.buffered] = 1;
            self.buffer[self.buffered + 1..].fill(0);
            0
        };
        self.h[0] += load32(&self.buffer[0..4]) & MASK;
        self.h[1] += (load32(&self.buffer[3..7]) >> 2) & MASK;
        self.h[2] += (load32(&self.buffer[6..10]) >> 4) & MASK;
        self.h[3] += (load32(&self.buffer[9..13]) >> 6) & MASK;
        self.h[4] += (load32(&self.buffer[12..16]) >> 8) | high_bit;

        // 2^130 = 5 (mod 2^130 - 5). Each sum is below 2^58, so u64 suffices.
        let mut product: Secret<[u64; 5]> = Secret::new();
        for i in 0..5 {
            for j in 0..5 {
                let index = i + j;
                if index < 5 {
                    product[index] += self.h[i] * self.r[j];
                } else {
                    product[index - 5] += 5 * self.h[i] * self.r[j];
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
        self.buffered = 0;
    }

    /// Consumes this message and returns its full authentication tag without allocation.
    pub fn finalize(mut self) -> [u8; TAG_LEN] {
        if self.buffered != 0 {
            self.process_block();
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
        let select_reduced = (reduced[4] >> 63).wrapping_sub(1);
        for i in 0..5 {
            self.h[i] = (self.h[i] & !select_reduced) | (reduced[i] & select_reduced);
        }

        let mut words: Secret<[u64; 4]> = Secret::new();
        words[0] = (self.h[0] | (self.h[1] << 26)) & 0xffffffff;
        words[1] = ((self.h[1] >> 6) | (self.h[2] << 20)) & 0xffffffff;
        words[2] = ((self.h[2] >> 12) | (self.h[3] << 14)) & 0xffffffff;
        words[3] = ((self.h[3] >> 18) | (self.h[4] << 8)) & 0xffffffff;
        let mut tag = [0u8; TAG_LEN];
        for i in 0..4 {
            words[i] += u64::from(self.pad[i]);
            if i != 0 {
                words[i] += words[i - 1] >> 32;
            }
            tag[4 * i..4 * i + 4].copy_from_slice(&(words[i] as u32).to_le_bytes());
        }
        tag
    }
}

fn load32(bytes: &[u8]) -> u64 {
    u64::from(u32::from_le_bytes(bytes.try_into().unwrap()))
}

impl MAC for Poly1305 {
    fn new(key: &impl KeyMaterialTrait) -> Result<Self, MACError> {
        Self::init(key, false)
    }

    fn new_allow_weak_key(key: &impl KeyMaterialTrait) -> Result<Self, MACError> {
        Self::init(key, true)
    }

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
        while !data.is_empty() {
            let n = (BLOCK_LEN - self.buffered).min(data.len());
            self.buffer[self.buffered..self.buffered + n].copy_from_slice(&data[..n]);
            self.buffered += n;
            data = &data[n..];
            if self.buffered == BLOCK_LEN {
                self.process_block();
            }
        }
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
