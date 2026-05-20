//! Ascon-CXOF128 — a customizable extendable-output function from
//! NIST SP 800-232.
//!
//! Ascon-CXOF128 is identical in structure to [`crate::ascon_xof128::AsconXof128`]
//! except that it can be parameterised with a *customization string* `Z` (up
//! to 256 bytes) that is absorbed into the initial state. This provides
//! domain separation: two CXOF instances with different `Z` produce
//! independent output streams from the same absorbed input. It is the
//! recommended construction when an application would otherwise be vulnerable
//! to the XOF distinguishing attack (see [`crate::ascon_xof128`]).
//!
//! # Examples
//! ```
//! use bouncycastle_core_interface::traits::XOF;
//! use bouncycastle_ascon::AsconCXof128;
//!
//! let out_a = AsconCXof128::with_customization(b"context-A").hash_xof(b"msg", 32);
//! let out_b = AsconCXof128::with_customization(b"context-B").hash_xof(b"msg", 32);
//! assert_ne!(out_a, out_b);
//! ```

use alloc::vec;
use alloc::vec::Vec;
use bouncycastle_core_interface::errors::HashError;
use bouncycastle_core_interface::traits::{Algorithm, SecurityStrength, XOF};

use crate::state::AsconState;

const RATE_BYTES: usize = 8;

/// Maximum customization-string length, in bytes, allowed by NIST SP 800-232.
pub const MAX_CUSTOMIZATION_BYTES: usize = 256;

/// Algorithm name.
pub const ASCON_CXOF128_NAME: &str = "Ascon-CXOF128";

/// Ascon-CXOF128 sponge state, parameterised by an absorbed customization
/// string `Z`. The post-customization IV is cached in lanes `z0..z4` so
/// [`AsconCXof128::reset`] returns to it without re-absorbing `Z`.
pub struct AsconCXof128 {
    state: AsconState,
    z0: u64,
    z1: u64,
    z2: u64,
    z3: u64,
    z4: u64,
    buf: [u8; RATE_BYTES],
    buf_pos: usize,
    squeezing: bool,
}

impl AsconCXof128 {
    /// Create a new Ascon-CXOF128 instance with no customization string.
    pub fn new() -> Self {
        Self::with_customization(&[])
    }

    fn from_cached_iv(z0: u64, z1: u64, z2: u64, z3: u64, z4: u64) -> Self {
        Self {
            state: AsconState::from_lanes(z0, z1, z2, z3, z4),
            z0,
            z1,
            z2,
            z3,
            z4,
            buf: [0u8; RATE_BYTES],
            buf_pos: 0,
            squeezing: false,
        }
    }

    /// Create a new Ascon-CXOF128 instance customized with the bytes of `z`.
    ///
    /// # Panics
    /// Panics if `z.len() > MAX_CUSTOMIZATION_BYTES`. The XOF trait surface
    /// has no constructor variant, so this is the only point where the
    /// length check can fire; an oversized `Z` is a programmer error and
    /// panicking is consistent with `assert!`-style invariants elsewhere in
    /// the crate.
    pub fn with_customization(z: &[u8]) -> Self {
        assert!(
            z.len() <= MAX_CUSTOMIZATION_BYTES,
            "Ascon-CXOF128: customization string exceeds {MAX_CUSTOMIZATION_BYTES} bytes",
        );

        if z.is_empty() {
            // Precomputed IV for empty Z (NIST SP 800-232 §6.2).
            return Self::from_cached_iv(
                0x500C_CCC8_94E3_C9E8,
                0x5BED_06F2_8F71_248D,
                0x3B03_A0F9_30AF_D512,
                0x112E_F093_AA5C_698B,
                0x00C8_3563_40A3_47F0,
            );
        }

        // Non-empty Z: load the customized-CXOF IV, absorb bitlen(z) into
        // lane 0, run p[12], absorb z, pad, run p[12].
        let mut st = Self::from_cached_iv(
            0x6755_27C2_A0E8_DE03,
            0x43D1_2D7D_C037_7BBC,
            0xE990_1DEC_426E_81B5,
            0x2AB1_4907_7207_80B6,
            0x8F3F_1D02_D432_BC46,
        );

        let bit_length = (z.len() as u64) << 3;
        st.state.s0 ^= bit_length;
        st.state.permute_12();
        st.absorb_inner(z);
        st.pad_and_absorb();
        st.state.permute_12();
        st.buf_pos = 0;

        st.z0 = st.state.s0;
        st.z1 = st.state.s1;
        st.z2 = st.state.s2;
        st.z3 = st.state.s3;
        st.z4 = st.state.s4;
        st
    }

    /// Absorb additional input.
    ///
    /// # Errors
    /// Returns [`HashError::InvalidState`] if called after squeezing has
    /// begun.
    pub fn absorb_input(&mut self, input: &[u8]) -> Result<(), HashError> {
        if self.squeezing {
            return Err(HashError::InvalidState(
                "Ascon-CXOF128: cannot absorb after squeezing has begun",
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

    /// Squeeze output bytes. May be called repeatedly.
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

    /// Reset to the cached post-customization initial state.
    pub fn reset(&mut self) {
        self.state = AsconState::from_lanes(self.z0, self.z1, self.z2, self.z3, self.z4);
        self.buf.fill(0);
        self.buf_pos = 0;
        self.squeezing = false;
    }

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

impl Default for AsconCXof128 {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for AsconCXof128 {
    fn drop(&mut self) {
        // Cached IV lanes may encode customization-string content; wipe.
        self.z0 = 0;
        self.z1 = 0;
        self.z2 = 0;
        self.z3 = 0;
        self.z4 = 0;
        self.buf.fill(0);
        self.buf_pos = 0;
        self.squeezing = false;
    }
}

impl Algorithm for AsconCXof128 {
    const ALG_NAME: &'static str = ASCON_CXOF128_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

impl XOF for AsconCXof128 {
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
        let _ = self.absorb_input(data);
    }

    fn absorb_last_partial_byte(
        &mut self,
        _partial_byte: u8,
        _num_partial_bits: usize,
    ) -> Result<(), HashError> {
        Err(HashError::InvalidInput("Ascon-CXOF128 does not support partial byte input"))
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
        Err(HashError::InvalidInput("Ascon-CXOF128 does not support partial byte output"))
    }

    fn squeeze_partial_byte_final_out(
        self,
        _num_bits: usize,
        _output: &mut u8,
    ) -> Result<(), HashError> {
        Err(HashError::InvalidInput("Ascon-CXOF128 does not support partial byte output"))
    }

    fn max_security_strength(&self) -> SecurityStrength {
        Self::MAX_SECURITY_STRENGTH
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn empty_customization_matches_explicit_empty_z() {
        let a = AsconCXof128::new().hash_xof(b"hello", 32);
        let b = AsconCXof128::with_customization(&[]).hash_xof(b"hello", 32);
        assert_eq!(a, b);
    }

    #[test]
    fn different_customizations_produce_different_output() {
        let a = AsconCXof128::with_customization(b"alpha").hash_xof(b"msg", 64);
        let b = AsconCXof128::with_customization(b"beta").hash_xof(b"msg", 64);
        assert_ne!(a, b);
    }

    #[test]
    fn streaming_matches_one_shot() {
        let msg: &[u8] = b"streaming-customization-test";
        let z: &[u8] = b"context";
        let expected = AsconCXof128::with_customization(z).hash_xof(msg, 96);

        for chunk in 1..=msg.len() {
            let mut x = AsconCXof128::with_customization(z);
            for c in msg.chunks(chunk) {
                x.absorb_input(c).unwrap();
            }
            let mut got = vec![0u8; 96];
            x.squeeze_into(&mut got);
            assert_eq!(got, expected, "mismatch at chunk size {chunk}");
        }
    }

    #[test]
    fn reset_restores_post_customization_state() {
        let z: &[u8] = b"reset-test-Z";
        let msg: &[u8] = b"hello";

        let mut x = AsconCXof128::with_customization(z);
        x.absorb_input(b"garbage").unwrap();
        let mut throwaway = [0u8; 8];
        x.squeeze_into(&mut throwaway);

        x.reset();
        x.absorb_input(msg).unwrap();
        let mut got = vec![0u8; 32];
        x.squeeze_into(&mut got);

        let expected = AsconCXof128::with_customization(z).hash_xof(msg, 32);
        assert_eq!(got, expected);
    }

    #[test]
    fn absorb_after_squeeze_is_rejected() {
        let mut x = AsconCXof128::with_customization(b"ctx");
        x.absorb_input(b"hello").unwrap();
        let mut out = [0u8; 4];
        x.squeeze_into(&mut out);
        let err = x.absorb_input(b"more").unwrap_err();
        assert!(matches!(err, HashError::InvalidState(_)));
    }

    #[test]
    #[should_panic(expected = "customization string exceeds")]
    fn oversized_customization_panics() {
        let big = vec![0u8; MAX_CUSTOMIZATION_BYTES + 1];
        let _ = AsconCXof128::with_customization(&big);
    }
}
