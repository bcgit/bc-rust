//! Ascon-Hash256 — a 256-bit cryptographic hash function from NIST SP 800-232.
//!
//! Ascon-Hash256 is a sponge construction over the 320-bit Ascon permutation
//! with rate `r = 64` bits and capacity `c = 256` bits. It produces a
//! fixed 256-bit (32-byte) output and is targeted at constrained / IoT
//! environments where SHA-2 / SHA-3 are too heavy.
//!
//! # Examples
//!
//! One-shot:
//!
//! ```
//! use bouncycastle_core_interface::traits::Hash;
//! use bouncycastle_ascon::AsconHash256;
//!
//! let data: &[u8] = b"Hello, world!";
//! let digest: Vec<u8> = AsconHash256::new().hash(data);
//! assert_eq!(digest.len(), 32);
//! ```
//!
//! Streaming:
//!
//! ```
//! use bouncycastle_core_interface::traits::Hash;
//! use bouncycastle_ascon::AsconHash256;
//!
//! let mut hasher = AsconHash256::new();
//! hasher.do_update(b"Hello, ");
//! hasher.do_update(b"world!");
//! let digest: Vec<u8> = hasher.do_final();
//! assert_eq!(digest.len(), 32);
//! ```

use alloc::vec;
use alloc::vec::Vec;
use bouncycastle_core_interface::errors::HashError;
use bouncycastle_core_interface::traits::{Algorithm, Hash, HashAlgParams, SecurityStrength};

use crate::state::AsconState;

/// Rate of the Ascon-Hash256 sponge, in bytes. The capacity is 256 bits.
const RATE_BYTES: usize = 8;

/// Output length of Ascon-Hash256, in bytes (256 bits).
pub const ASCON_HASH256_OUTPUT_LEN: usize = 32;

/// Algorithm name as registered with NIST.
pub const ASCON_HASH256_NAME: &str = "Ascon-Hash256";

/// Ascon-Hash256 hasher state.
///
/// Implements the [`Hash`] trait. The sponge state is zeroized when this
/// struct is dropped via the underlying [`AsconState`] `Drop` impl.
#[derive(Clone)]
pub struct AsconHash256 {
    state: AsconState,
    buf: [u8; RATE_BYTES],
    buf_pos: usize,
}

impl AsconHash256 {
    /// Create a new hasher initialized to the Ascon-Hash256 IV from
    /// NIST SP 800-232.
    pub fn new() -> Self {
        // IV values are precomputed per NIST SP 800-232 §4.2 — applying the
        // Ascon-Hash256 initialization word through `p[12]`.
        let state = AsconState::from_lanes(
            0x9B1E_5494_E934_D681,
            0x4BC3_A01E_3337_51D2,
            0xAE65_396C_6B34_B81A,
            0x3C7F_D4A4_D56A_4DB3,
            0x1A5C_4649_06C5_976D,
        );
        Self { state, buf: [0u8; RATE_BYTES], buf_pos: 0 }
    }

    /// Absorb additional input. Equivalent to [`Hash::do_update`] but kept
    /// as an inherent method for callers that prefer the spelling and to
    /// avoid requiring the trait import.
    pub fn absorb(&mut self, input: &[u8]) {
        if input.is_empty() {
            return;
        }

        let mut input = input;

        if self.buf_pos > 0 {
            let available = RATE_BYTES - self.buf_pos;
            if input.len() < available {
                self.buf[self.buf_pos..self.buf_pos + input.len()].copy_from_slice(input);
                self.buf_pos += input.len();
                return;
            }
            self.buf[self.buf_pos..].copy_from_slice(&input[..available]);
            self.state.s0 ^= u64::from_le_bytes(self.buf);
            self.state.permute_12();
            input = &input[available..];
            self.buf_pos = 0;
        }

        while input.len() >= RATE_BYTES {
            self.state.s0 ^= u64::from_le_bytes(input[..RATE_BYTES].try_into().unwrap());
            self.state.permute_12();
            input = &input[RATE_BYTES..];
        }

        self.buf[..input.len()].copy_from_slice(input);
        self.buf_pos = input.len();
    }

    /// Finalize the hash and write the digest into `output`.
    ///
    /// `output` must hold at least [`ASCON_HASH256_OUTPUT_LEN`] bytes. After
    /// this call, the hasher state is reset; the instance cannot be reused
    /// without calling [`AsconHash256::absorb`] again (which would treat it
    /// as a fresh hash).
    ///
    /// # Errors
    /// Returns [`HashError::InvalidLength`] if `output` is shorter than
    /// [`ASCON_HASH256_OUTPUT_LEN`].
    pub fn finalize(&mut self, output: &mut [u8]) -> Result<usize, HashError> {
        if output.len() < ASCON_HASH256_OUTPUT_LEN {
            return Err(HashError::InvalidLength("output buffer too short for Ascon-Hash256"));
        }
        self.pad_and_absorb();
        output[0..8].copy_from_slice(&self.state.s0.to_le_bytes());
        for i in 1..4 {
            self.state.permute_12();
            output[i * 8..(i + 1) * 8].copy_from_slice(&self.state.s0.to_le_bytes());
        }
        self.reset();
        Ok(ASCON_HASH256_OUTPUT_LEN)
    }

    /// Internal infallible finalize for the [`Hash`] trait, which uses
    /// fixed-length 32-byte buffers and cannot fail.
    fn finalize_infallible(&mut self, output: &mut [u8]) {
        debug_assert!(output.len() >= ASCON_HASH256_OUTPUT_LEN);
        self.pad_and_absorb();
        output[0..8].copy_from_slice(&self.state.s0.to_le_bytes());
        for i in 1..4 {
            self.state.permute_12();
            output[i * 8..(i + 1) * 8].copy_from_slice(&self.state.s0.to_le_bytes());
        }
        self.reset();
    }

    /// Reset the hasher to its initial Ascon-Hash256 IV.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Pad the final partial block per NIST SP 800-232 §4.2: XOR the message
    /// bytes into lane `s0`, append the single 1-bit at position `buf_pos`,
    /// then apply `p[12]`.
    fn pad_and_absorb(&mut self) {
        // Zero the unused tail of the buffer so a stale value from a prior
        // absorb cannot leak into the final block.
        for b in &mut self.buf[self.buf_pos..] {
            *b = 0;
        }
        let final_bits = self.buf_pos << 3;
        let x = u64::from_le_bytes(self.buf);
        let mask =
            if final_bits == 0 { 0u64 } else { 0x00FF_FFFF_FFFF_FFFF_u64 >> (56 - final_bits) };
        self.state.s0 ^= x & mask;
        self.state.s0 ^= 0x01u64 << final_bits;
        self.state.permute_12();
    }
}

impl Default for AsconHash256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for AsconHash256 {
    fn drop(&mut self) {
        // AsconState already zeroizes its lanes on drop. We additionally
        // zeroize the message-buffer fields here so no plaintext fragment
        // outlives the hasher on the stack.
        self.buf.fill(0);
        self.buf_pos = 0;
    }
}

impl Algorithm for AsconHash256 {
    const ALG_NAME: &'static str = ASCON_HASH256_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

impl HashAlgParams for AsconHash256 {
    const OUTPUT_LEN: usize = ASCON_HASH256_OUTPUT_LEN;
    const BLOCK_LEN: usize = RATE_BYTES;
}

impl Hash for AsconHash256 {
    fn block_bitlen(&self) -> usize {
        RATE_BYTES * 8
    }

    fn output_len(&self) -> usize {
        ASCON_HASH256_OUTPUT_LEN
    }

    fn hash(mut self, data: &[u8]) -> Vec<u8> {
        self.absorb(data);
        let mut out = vec![0u8; ASCON_HASH256_OUTPUT_LEN];
        self.finalize_infallible(&mut out);
        out
    }

    fn hash_out(mut self, data: &[u8], output: &mut [u8]) -> usize {
        self.absorb(data);
        self.finalize_infallible(output);
        ASCON_HASH256_OUTPUT_LEN
    }

    fn do_update(&mut self, data: &[u8]) {
        self.absorb(data);
    }

    fn do_final(mut self) -> Vec<u8> {
        let mut out = vec![0u8; ASCON_HASH256_OUTPUT_LEN];
        self.finalize_infallible(&mut out);
        out
    }

    fn do_final_out(mut self, output: &mut [u8]) -> usize {
        self.finalize_infallible(output);
        ASCON_HASH256_OUTPUT_LEN
    }

    fn do_final_partial_bits(
        self,
        _partial_byte: u8,
        _num_partial_bits: usize,
    ) -> Result<Vec<u8>, HashError> {
        Err(HashError::InvalidInput("Ascon-Hash256 does not support partial byte input"))
    }

    fn do_final_partial_bits_out(
        self,
        _partial_byte: u8,
        _num_partial_bits: usize,
        _output: &mut [u8],
    ) -> Result<usize, HashError> {
        Err(HashError::InvalidInput("Ascon-Hash256 does not support partial byte input"))
    }

    fn max_security_strength(&self) -> SecurityStrength {
        Self::MAX_SECURITY_STRENGTH
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const MSG_21: [u8; 21] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
    ];
    const MD_21: [u8; 32] = [
        0x41, 0xC8, 0xF7, 0x33, 0xB9, 0xD8, 0x23, 0xBE, 0x30, 0xB6, 0x4E, 0xE7, 0x17, 0xC3, 0x22,
        0xC5, 0x76, 0xD3, 0x67, 0x81, 0xFF, 0xC5, 0xF7, 0xD6, 0xC7, 0x30, 0xEC, 0xA5, 0x49, 0x78,
        0x97, 0x25,
    ];

    #[test]
    fn streaming_matches_one_shot_across_chunk_sizes() {
        let expected = AsconHash256::new().hash(&MSG_21);
        for chunk in 1..=MSG_21.len() {
            let mut h = AsconHash256::new();
            for c in MSG_21.chunks(chunk) {
                h.absorb(c);
            }
            let mut out = [0u8; 32];
            h.finalize(&mut out).unwrap();
            assert_eq!(&out[..], &expected[..], "mismatch at chunk size {chunk}");
        }
    }

    #[test]
    fn matches_nist_vector() {
        let mut out = [0u8; 32];
        let mut h = AsconHash256::new();
        h.absorb(&MSG_21);
        h.finalize(&mut out).unwrap();
        assert_eq!(out, MD_21);
    }

    #[test]
    fn finalize_rejects_short_output() {
        let mut out = [0u8; 31];
        let mut h = AsconHash256::new();
        h.absorb(&MSG_21);
        match h.finalize(&mut out) {
            Err(HashError::InvalidLength(_)) => {}
            other => panic!("expected InvalidLength, got {other:?}"),
        }
    }

    #[test]
    fn partial_bits_is_rejected() {
        let h = AsconHash256::new();
        assert!(matches!(h.do_final_partial_bits(0, 1), Err(HashError::InvalidInput(_))));

        let h = AsconHash256::new();
        let mut out = [0u8; 32];
        assert!(matches!(
            h.do_final_partial_bits_out(0, 1, &mut out),
            Err(HashError::InvalidInput(_)),
        ));
    }

    #[test]
    fn reset_returns_to_initial_state() {
        let mut a = AsconHash256::new();
        a.absorb(b"some data");
        a.reset();
        a.absorb(&MSG_21);
        let mut out_a = [0u8; 32];
        a.finalize(&mut out_a).unwrap();
        assert_eq!(out_a, MD_21);
    }

    #[test]
    fn empty_input_produces_known_digest() {
        let d1 = AsconHash256::new().hash(b"");
        let d2 = AsconHash256::new().hash(b"");
        assert_eq!(d1, d2);
        assert_eq!(d1.len(), 32);
    }

    #[test]
    fn algorithm_constants() {
        assert_eq!(AsconHash256::ALG_NAME, "Ascon-Hash256");
        assert_eq!(AsconHash256::MAX_SECURITY_STRENGTH, SecurityStrength::_128bit);
        assert_eq!(AsconHash256::OUTPUT_LEN, 32);
        assert_eq!(AsconHash256::BLOCK_LEN, 8);
        assert_eq!(AsconHash256::new().block_bitlen(), 64);
        assert_eq!(AsconHash256::new().output_len(), 32);
    }
}
