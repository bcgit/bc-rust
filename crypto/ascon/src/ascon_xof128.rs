//! Ascon-XOF128 — an extendable-output function from NIST SP 800-232.
//!
//! Ascon-XOF128 is a sponge construction over the 320-bit Ascon permutation
//! with rate `r = 64` bits and capacity `c = 256` bits. Output is produced
//! by squeezing, so any number of output bytes may be requested.
//!
//! # XOF distinguishing-attack note
//! As with all XOFs, the overlapping prefix of two outputs of different
//! lengths absorbed from the same input is identical. If two output streams
//! produced from the same absorbed input need to be distinguishable, mix a
//! domain-separating salt into the absorbed input (or use the customized
//! variant [`crate::ascon_cxof128::AsconCXof128`]).
//!
//! # Examples
//! ```
//! use bouncycastle_core_interface::traits::XOF;
//! use bouncycastle_ascon::AsconXof128;
//!
//! let data: &[u8] = b"Hello, world!";
//! let out: Vec<u8> = AsconXof128::new().hash_xof(data, 64);
//! assert_eq!(out.len(), 64);
//! ```

use alloc::vec;
use alloc::vec::Vec;
use bouncycastle_core_interface::errors::HashError;
use bouncycastle_core_interface::traits::{Algorithm, SecurityStrength, XOF};

use crate::state::AsconState;

/// Rate of the Ascon-XOF128 sponge, in bytes.
const RATE_BYTES: usize = 8;

/// Algorithm name.
pub const ASCON_XOF128_NAME: &str = "Ascon-XOF128";

/// Ascon-XOF128 sponge state.
///
/// The sponge tracks whether it is in the *absorb* phase (taking input) or
/// the *squeeze* phase (producing output). Once squeezing has begun, the
/// inherent [`AsconXof128::absorb_input`] returns
/// [`HashError::InvalidState`]; the [`XOF`] trait's `absorb` method (which
/// does not return `Result` in bc-rust) silently ignores absorbs in the
/// squeeze phase — application code should prefer the inherent method.
pub struct AsconXof128 {
    state: AsconState,
    buf: [u8; RATE_BYTES],
    buf_pos: usize,
    squeezing: bool,
}

impl AsconXof128 {
    /// Create a fresh Ascon-XOF128 instance loaded with the IV from
    /// NIST SP 800-232.
    pub fn new() -> Self {
        // Precomputed IV per NIST SP 800-232 §5.2.
        let state = AsconState::from_lanes(
            0xDA82_CE76_8D94_47EB,
            0xCC7C_E6C7_5F1E_F969,
            0xE750_8FD7_8008_5631,
            0x0EE0_EA53_416B_58CC,
            0xE054_7524_DB6F_0BDE,
        );
        Self { state, buf: [0u8; RATE_BYTES], buf_pos: 0, squeezing: false }
    }

    /// Absorb additional input.
    ///
    /// # Errors
    /// Returns [`HashError::InvalidState`] if called after the first
    /// [`AsconXof128::squeeze_into`] / [`XOF::squeeze`].
    pub fn absorb_input(&mut self, input: &[u8]) -> Result<(), HashError> {
        if self.squeezing {
            return Err(HashError::InvalidState(
                "Ascon-XOF128: cannot absorb after squeezing has begun",
            ));
        }
        self.absorb_inner(input);
        Ok(())
    }

    fn absorb_inner(&mut self, input: &[u8]) {
        let available = RATE_BYTES - self.buf_pos;
        if input.len() < available {
            self.buf[self.buf_pos..self.buf_pos + input.len()].copy_from_slice(input);
            self.buf_pos += input.len();
            return;
        }

        let mut input = input;

        if self.buf_pos > 0 {
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

    /// Squeeze output bytes from the sponge.
    ///
    /// May be called repeatedly. The first call applies the final-block
    /// padding and switches the sponge into the squeeze phase.
    pub fn squeeze_into(&mut self, output: &mut [u8]) -> usize {
        let result = output.len();
        let mut output = output;

        if !self.squeezing {
            self.pad_and_absorb();
            self.squeezing = true;
            self.buf_pos = RATE_BYTES;
        } else if self.buf_pos < RATE_BYTES {
            let available = RATE_BYTES - self.buf_pos;
            if output.len() <= available {
                let end_pos = self.buf_pos + output.len();
                output.copy_from_slice(&self.buf[self.buf_pos..end_pos]);
                self.buf_pos = end_pos;
                return result;
            }
            output[..available].copy_from_slice(&self.buf[self.buf_pos..]);
            output = &mut output[available..];
            self.buf_pos = RATE_BYTES;
        }

        while output.len() >= RATE_BYTES {
            self.state.permute_12();
            output[..RATE_BYTES].copy_from_slice(&self.state.s0.to_le_bytes());
            output = &mut output[RATE_BYTES..];
        }

        if !output.is_empty() {
            self.state.permute_12();
            self.buf = self.state.s0.to_le_bytes();
            output.copy_from_slice(&self.buf[..output.len()]);
            self.buf_pos = output.len();
        }

        result
    }

    /// Reset the XOF to its initial state, ready to absorb new input.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Pad the final partial block per NIST SP 800-232 §5.2.
    fn pad_and_absorb(&mut self) {
        for b in &mut self.buf[self.buf_pos..] {
            *b = 0;
        }
        let final_bits = (self.buf_pos as u32) << 3;
        let mask: u64 = if final_bits == 0 {
            0x00FF_FFFF_FFFF_FFFF
        } else {
            0x00FF_FFFF_FFFF_FFFF >> (56 - final_bits)
        };
        self.state.s0 ^= u64::from_le_bytes(self.buf) & mask;
        self.state.s0 ^= 0x01u64 << final_bits;
    }
}

impl Default for AsconXof128 {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for AsconXof128 {
    fn drop(&mut self) {
        self.buf.fill(0);
        self.buf_pos = 0;
        self.squeezing = false;
    }
}

impl Algorithm for AsconXof128 {
    const ALG_NAME: &'static str = ASCON_XOF128_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

impl XOF for AsconXof128 {
    fn hash_xof(mut self, data: &[u8], result_len: usize) -> Vec<u8> {
        self.absorb_inner(data);
        let mut out = vec![0u8; result_len];
        self.squeeze_into(&mut out);
        out
    }

    fn hash_xof_out(mut self, data: &[u8], output: &mut [u8]) -> usize {
        self.absorb_inner(data);
        self.squeeze_into(output)
    }

    fn absorb(&mut self, data: &[u8]) {
        // bc-rust's trait surface is infallible; we mirror that by silently
        // ignoring post-squeeze absorbs. Callers who need to detect the
        // misuse should use the inherent `absorb_input` which returns a
        // `Result`.
        let _ = self.absorb_input(data);
    }

    fn absorb_last_partial_byte(
        &mut self,
        _partial_byte: u8,
        _num_partial_bits: usize,
    ) -> Result<(), HashError> {
        Err(HashError::InvalidInput("Ascon-XOF128 does not support partial byte input"))
    }

    fn squeeze(&mut self, num_bytes: usize) -> Vec<u8> {
        let mut out = vec![0u8; num_bytes];
        self.squeeze_into(&mut out);
        out
    }

    fn squeeze_out(&mut self, output: &mut [u8]) -> usize {
        self.squeeze_into(output)
    }

    fn squeeze_partial_byte_final(self, _num_bits: usize) -> Result<u8, HashError> {
        Err(HashError::InvalidInput("Ascon-XOF128 does not support partial byte output"))
    }

    fn squeeze_partial_byte_final_out(
        self,
        _num_bits: usize,
        _output: &mut u8,
    ) -> Result<(), HashError> {
        Err(HashError::InvalidInput("Ascon-XOF128 does not support partial byte output"))
    }

    fn max_security_strength(&self) -> SecurityStrength {
        Self::MAX_SECURITY_STRENGTH
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const MSG: &[u8] = &[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
    ];
    const OUTPUT: [u8; 32] = [
        0x25, 0x9D, 0x67, 0x08, 0x87, 0xF1, 0x77, 0xCE, 0x37, 0x7D, 0x40, 0xFD, 0xE8, 0x13, 0x04,
        0xBE, 0xA7, 0x2B, 0x32, 0x46, 0xCC, 0x38, 0xDB, 0x74, 0x64, 0xBC, 0x20, 0x40, 0x8B, 0x45,
        0x0C, 0xFB,
    ];

    #[test]
    fn matches_nist_vector_32_bytes() {
        let mut out = [0u8; 32];
        let mut x = AsconXof128::new();
        x.absorb_input(MSG).unwrap();
        x.squeeze_into(&mut out);
        assert_eq!(out, OUTPUT);
    }

    #[test]
    fn streaming_matches_one_shot_across_chunk_sizes() {
        let expected = AsconXof128::new().hash_xof(MSG, 64);
        for chunk in 1..=MSG.len() {
            let mut x = AsconXof128::new();
            for c in MSG.chunks(chunk) {
                x.absorb_input(c).unwrap();
            }
            let mut got = vec![0u8; 64];
            x.squeeze_into(&mut got);
            assert_eq!(got, expected, "mismatch at chunk size {chunk}");
        }
    }

    #[test]
    fn multi_squeeze_equals_single_squeeze() {
        let big = AsconXof128::new().hash_xof(MSG, 64);
        let mut x = AsconXof128::new();
        x.absorb_input(MSG).unwrap();
        let mut a = vec![0u8; 32];
        let mut b = vec![0u8; 32];
        x.squeeze_into(&mut a);
        x.squeeze_into(&mut b);
        let mut combined = a;
        combined.extend(b);
        assert_eq!(combined, big);
    }

    #[test]
    fn absorb_after_squeeze_is_rejected() {
        let mut x = AsconXof128::new();
        x.absorb_input(b"hello").unwrap();
        let mut out = [0u8; 8];
        x.squeeze_into(&mut out);
        let err = x.absorb_input(b"more").unwrap_err();
        assert!(matches!(err, HashError::InvalidState(_)));
    }

    #[test]
    fn partial_byte_paths_are_rejected() {
        let mut x = AsconXof128::new();
        assert!(matches!(
            x.absorb_last_partial_byte(0, 1),
            Err(HashError::InvalidInput(_)),
        ));
        let x = AsconXof128::new();
        assert!(matches!(
            x.squeeze_partial_byte_final(1),
            Err(HashError::InvalidInput(_)),
        ));
    }

    #[test]
    fn algorithm_constants() {
        assert_eq!(AsconXof128::ALG_NAME, "Ascon-XOF128");
        assert_eq!(AsconXof128::MAX_SECURITY_STRENGTH, SecurityStrength::_128bit);
    }
}
