//! Ascon-CXOF128 customized extendable-output function (NIST SP 800-232 §5.3).
//!
//! A variant of Ascon-XOF128 that first absorbs a user-supplied customization string `Z`
//! (length-prefixed per SP 800-232 Alg. 7) to provide domain separation. Same sponge parameters as
//! Ascon-XOF128 (rate = 64 bits, capacity = 256 bits, `Ascon-p[12]`).

use bouncycastle_core::errors::{HashError, SuspendableError};
use bouncycastle_core::suspendable_state::{add_lib_ver, check_lib_ver};
use bouncycastle_core::traits::{Algorithm, SecurityStrength, Suspendable, XOF};
use bouncycastle_utils::secret::Secret;

use crate::sponge::{RATE, Sponge};

/// Maximum customization-string length in bytes (2048 bits, per SP 800-232 §5.3).
const MAX_CUSTOMIZATION_BYTES: usize = 256;

/// Ascon-CXOF128 customized extendable-output function (NIST SP 800-232 §5.3).
#[derive(Clone)]
pub struct AsconCXof128 {
    sponge: Sponge,
}

impl AsconCXof128 {
    /// Create a new Ascon-CXOF128 instance with no customization string.
    pub fn new() -> Self {
        // Precomputed state after initializing and then absorbing an empty customization string
        // (SP 800-232 Algorithm 7 with |Z| = 0): starting from the Table 12 CXOF128 initialization
        // state, XOR the length word Z_0 = int64(0) into S[0..63], Ascon-p[12], then XOR the
        // pad-only last customization block (Eq. 77: pad(empty, 64) = 0x01 || 0^63) into S[0..63]
        // and Ascon-p[12] again. Recomputed from those raw Table 12 words and pinned by
        // `permutation::tests::cxof128_empty_customization_state_matches_algorithm_7`.
        let mut sponge = Sponge::from_state([
            0x500CCCC894E3C9E8, 0x5BED06F28F71248D, 0x3B03A0F930AFD512, 0x112EF093AA5C698B,
            0x00C8356340A347F0,
        ]);
        sponge.reset_buffer();
        Self { sponge }
    }

    /// Create a new Ascon-CXOF128 instance with the given customization string `z`.
    ///
    /// Returns [`HashError::InvalidInput`] if `z` is longer than 256 bytes (2048 bits, the bound
    /// required by SP 800-232 §5.3).
    pub fn with_customization(z: &[u8]) -> Result<Self, HashError> {
        if z.len() > MAX_CUSTOMIZATION_BYTES {
            return Err(HashError::InvalidInput(
                "Ascon-CXOF128 customization string exceeds 256 bytes",
            ));
        }
        if z.is_empty() {
            return Ok(Self::new());
        }

        // Precomputed state after the initialization permutation (SP 800-232 Table 12).
        let mut sponge = Sponge::from_state([
            0x675527C2A0E8DE03, 0x43D12D7DC0377BBC, 0xE9901DEC426E81B5, 0x2AB14907720780B6,
            0x8F3F1D02D432BC46,
        ]);

        // Z0 = int64(|Z|) in bits, then absorb the parsed/padded customization blocks
        // (SP 800-232 §5.3 Eq. 75-78 / Algorithm 7, "Customization" loop).
        let bit_length = (z.len() as u64) << 3;
        sponge.xor_word0(bit_length);
        sponge.permute();
        sponge.absorb(z);
        sponge.pad_and_absorb();
        sponge.permute();

        // Customization is complete; reset the buffer to begin the message-absorb phase.
        sponge.reset_buffer();
        Ok(Self { sponge })
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

impl Default for AsconCXof128 {
    fn default() -> Self {
        Self::new()
    }
}

impl Algorithm for AsconCXof128 {
    const ALG_NAME: &'static str = "Ascon-CXOF128";
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

impl XOF for AsconCXof128 {
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
                "Ascon-CXOF128 cannot absorb after squeezing has begun",
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
        SecurityStrength::_128bit
    }
}

/// Length in bytes of the serialized state of [`AsconCXof128`].
/// Layout: 3-byte library version || 1-byte state tag || 40-byte sponge state (5 × u64 LE)
/// || 8-byte rate buffer || 1-byte buffer position || 1-byte squeezing flag.
///
/// Note: the customization string is absorbed at construction time and is not part of the
/// suspended state; resuming continues the message-absorb / squeeze phase already in progress.
pub const SUSPENDED_ASCON_CXOF128_STATE_LEN: usize = 54;

// Distinguishes an Ascon-CXOF128 serialized state from the other (same-shaped) Ascon sponge states.
const CXOF128_STATE_TAG: u8 = 0x03;

impl Suspendable<SUSPENDED_ASCON_CXOF128_STATE_LEN> for AsconCXof128 {
    fn suspend(self) -> [u8; SUSPENDED_ASCON_CXOF128_STATE_LEN] {
        let mut out_to_return = [0u8; SUSPENDED_ASCON_CXOF128_STATE_LEN];
        // infallible: add_lib_ver returns a slice of exactly SUSPENDED_ASCON_CXOF128_STATE_LEN - 3 = 51 bytes.
        let out: &mut [u8; SUSPENDED_ASCON_CXOF128_STATE_LEN - 3] =
            add_lib_ver(&mut out_to_return).try_into().unwrap();

        out[0] = CXOF128_STATE_TAG;
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
        serialized_state: [u8; SUSPENDED_ASCON_CXOF128_STATE_LEN],
    ) -> Result<Self, SuspendableError> {
        // infallible: check_lib_ver returns a slice of exactly SUSPENDED_ASCON_CXOF128_STATE_LEN - 3 = 51 bytes.
        let input: &[u8; SUSPENDED_ASCON_CXOF128_STATE_LEN - 3] =
            check_lib_ver(&serialized_state, None)?.try_into().unwrap();

        if input[0] != CXOF128_STATE_TAG {
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

        Ok(AsconCXof128 { sponge: Sponge::from_parts(s, buf, buf_pos, squeezing) })
    }
}
