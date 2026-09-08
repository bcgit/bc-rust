//! Ascon-XOF128 extendable-output function (NIST SP 800-232 §5.2).
//!
//! Sponge mode over `Ascon-p[12]` with rate = 64 bits, capacity = 256 bits. Supports the streaming
//! absorb/squeeze API of SP 800-232 §5.4 (squeeze may be called repeatedly).

use bouncycastle_core::errors::{HashError, SuspendableError};
use bouncycastle_core::suspendable_state::{add_lib_ver, check_lib_ver};
use bouncycastle_core::traits::{Algorithm, SecurityStrength, Suspendable, XOF};
use bouncycastle_utils::secret::Secret;

use crate::sponge::{RATE, Sponge};

/// Ascon-XOF128 as specified in NIST SP 800-232.
#[derive(Clone)]
pub struct AsconXof128 {
    sponge: Sponge,
}

impl AsconXof128 {
    /// Creates a new Ascon-XOF128 instance.
    pub fn new() -> Self {
        // Precomputed state after the initialization permutation (SP 800-232 Table 12).
        Self {
            sponge: Sponge::from_state([
                0xDA82CE768D9447EB, 0xCC7CE6C75F1EF969, 0xE7508FD780085631, 0x0EE0EA53416B58CC,
                0xE0547524DB6F0BDE,
            ]),
        }
    }

    // Squeeze `output.len()` bytes of output. May be called multiple times; the first call ends the
    // absorb phase by padding and absorbing the final block. Returns the number of bytes written.
    fn squeeze_into(&mut self, output: &mut [u8]) -> usize {
        let written = output.len();
        if !self.sponge.squeezing() {
            self.sponge.pad_and_absorb();
        }
        self.sponge.squeeze(output);
        written
    }
}

impl Default for AsconXof128 {
    fn default() -> Self {
        Self::new()
    }
}

impl Algorithm for AsconXof128 {
    const ALG_NAME: &'static str = "Ascon-XOF128";
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

impl XOF for AsconXof128 {
    fn hash_xof(mut self, data: &[u8], result_len: usize) -> Vec<u8> {
        self.sponge.absorb(data);
        let mut out = vec![0u8; result_len];
        self.squeeze_into(&mut out);
        out
    }

    fn hash_xof_out(mut self, data: &[u8], output: &mut [u8]) -> usize {
        self.sponge.absorb(data);
        self.squeeze_into(output)
    }

    fn absorb(&mut self, data: &[u8]) -> Result<(), HashError> {
        if self.sponge.squeezing() {
            return Err(HashError::InvalidState(
                "Ascon-XOF128 cannot absorb after squeezing has begun",
            ));
        }
        self.sponge.absorb(data);
        Ok(())
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
        SecurityStrength::_128bit
    }
}

/// Length in bytes of the serialized state of [`AsconXof128`].
/// Layout: 3-byte library version || 1-byte state tag || 40-byte sponge state (5 × u64 LE)
/// || 8-byte rate buffer || 1-byte buffer position || 1-byte squeezing flag.
pub const SUSPENDED_ASCON_XOF128_STATE_LEN: usize = 54;

// Distinguishes an Ascon-XOF128 serialized state from the other (same-shaped) Ascon sponge states.
const XOF128_STATE_TAG: u8 = 0x02;

impl Suspendable<SUSPENDED_ASCON_XOF128_STATE_LEN> for AsconXof128 {
    fn suspend(self) -> [u8; SUSPENDED_ASCON_XOF128_STATE_LEN] {
        let mut out_to_return = [0u8; SUSPENDED_ASCON_XOF128_STATE_LEN];
        // infallible: add_lib_ver returns a slice of exactly SUSPENDED_ASCON_XOF128_STATE_LEN - 3 = 51 bytes.
        let out: &mut [u8; SUSPENDED_ASCON_XOF128_STATE_LEN - 3] =
            add_lib_ver(&mut out_to_return).try_into().unwrap();

        out[0] = XOF128_STATE_TAG;
        let state = self.sponge.state_words();
        for i in 0..5 {
            out[1 + i * 8..1 + i * 8 + 8].copy_from_slice(&state[i].to_le_bytes());
        }
        out[41..49].copy_from_slice(&self.sponge.buf_bytes());
        debug_assert!(self.sponge.buf_pos() <= RATE);
        out[49] = self.sponge.buf_pos() as u8;
        out[50] = self.sponge.squeezing() as u8;

        out_to_return
    }

    fn from_suspended(
        serialized_state: [u8; SUSPENDED_ASCON_XOF128_STATE_LEN],
    ) -> Result<Self, SuspendableError> {
        // infallible: check_lib_ver returns a slice of exactly SUSPENDED_ASCON_XOF128_STATE_LEN - 3 = 51 bytes.
        let input: &[u8; SUSPENDED_ASCON_XOF128_STATE_LEN - 3] =
            check_lib_ver(&serialized_state, None)?.try_into().unwrap();

        if input[0] != XOF128_STATE_TAG {
            return Err(SuspendableError::InvalidData);
        }
        let mut s = Secret::<[u64; 5]>::new();
        for i in 0..5 {
            // infallible: each slice is exactly 8 bytes (1+i*8..1+i*8+8) by construction.
            s[i] = u64::from_le_bytes(input[1 + i * 8..1 + i * 8 + 8].try_into().unwrap());
        }
        let mut buf = Secret::<[u8; RATE]>::new();
        buf.copy_from_slice(&input[41..49]);
        let buf_pos = input[49] as usize;
        let squeezing = match input[50] {
            0 => false,
            1 => true,
            _ => return Err(SuspendableError::InvalidData),
        };
        // While absorbing, buf_pos must be < RATE (a full buffer is drained immediately); once
        // squeezing, buf_pos may equal RATE (meaning "no leftover squeezed byte buffered").
        let valid_pos = if squeezing { buf_pos <= RATE } else { buf_pos < RATE };
        if !valid_pos {
            return Err(SuspendableError::InvalidData);
        }

        Ok(AsconXof128 { sponge: Sponge::from_parts(s, buf, buf_pos, squeezing) })
    }
}
