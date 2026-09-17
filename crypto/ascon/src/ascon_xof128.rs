//! Ascon-XOF128 extendable-output function (NIST SP 800-232 §5.2).
//!
//! Sponge mode over `Ascon-p[12]` with rate = 64 bits, capacity = 256 bits. Supports the streaming
//! absorb/squeeze API of SP 800-232 §5.4 (squeeze may be called repeatedly).

use bouncycastle_core::errors::{HashError, SuspendableError};
use bouncycastle_core::suspendable_state::{add_lib_ver, check_lib_ver};
use bouncycastle_core::traits::{
    Algorithm, Hash, HashAlgParams, SecurityStrength, Suspendable, XOF, XOFSqueezer,
};
use bouncycastle_utils::secret::Secret;

use crate::sponge::{RATE, Sponge};

const XOF_HASH_BYTES: usize = 32;

/// Ascon-XOF128 as specified in NIST SP 800-232.
#[derive(Clone)]
pub struct AsconXof128 {
    sponge: Sponge,
}

/// Squeezing state for [`AsconXof128`].
#[derive(Clone)]
pub struct AsconXof128Squeezer {
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

    /// Compatibility helper for the old streaming API: absorb bytes while still in the input phase.
    pub fn absorb(&mut self, data: &[u8]) -> Result<(), HashError> {
        if self.sponge.squeezing() {
            return Err(HashError::InvalidState(
                "Ascon-XOF128 cannot absorb after squeezing has begun",
            ));
        }
        self.sponge.absorb(data);
        Ok(())
    }

    /// Compatibility helper for the old one-shot XOF API.
    pub fn hash_xof(self, data: &[u8], result_len: usize) -> Vec<u8> {
        <Self as XOF>::xof(self, data, result_len)
    }

    /// Compatibility helper for the old one-shot XOF API.
    pub fn hash_xof_out(self, data: &[u8], output: &mut [u8]) -> usize {
        <Self as XOF>::xof_out(self, data, output)
    }

    /// Compatibility helper for the old streaming API: produce `num_bytes` bytes.
    pub fn squeeze(&mut self, num_bytes: usize) -> Vec<u8> {
        let mut out = vec![0u8; num_bytes];
        self.squeeze_out(&mut out);
        out
    }

    /// Compatibility helper for the old streaming API: fill `output` from the XOF stream.
    pub fn squeeze_out(&mut self, output: &mut [u8]) -> usize {
        output.fill(0);
        if !self.sponge.squeezing() {
            self.sponge.pad_and_absorb();
        }
        self.sponge.squeeze(output);
        output.len()
    }

    /// Ascon-XOF128 does not support bit-level input.
    pub fn absorb_last_partial_byte(
        &mut self,
        _partial_byte: u8,
        _num_partial_bits: usize,
    ) -> Result<(), HashError> {
        Err(HashError::InvalidInput("Ascon-XOF128 does not support partial byte input"))
    }

    /// Ascon-XOF128 does not support bit-level output.
    pub fn squeeze_partial_byte_final(self, _num_bits: usize) -> Result<u8, HashError> {
        Err(HashError::InvalidInput("Ascon-XOF128 does not support partial byte output"))
    }

    /// Ascon-XOF128 does not support bit-level output.
    pub fn squeeze_partial_byte_final_out(
        self,
        _num_bits: usize,
        _output: &mut u8,
    ) -> Result<(), HashError> {
        Err(HashError::InvalidInput("Ascon-XOF128 does not support partial byte output"))
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

impl HashAlgParams for AsconXof128 {
    const OUTPUT_LEN: usize = XOF_HASH_BYTES;
    const BLOCK_LEN: usize = RATE;
}

impl Hash for AsconXof128 {
    fn block_bitlen(&self) -> usize {
        RATE * 8
    }

    fn output_len(&self) -> usize {
        XOF_HASH_BYTES
    }

    fn hash(mut self, data: &[u8]) -> Vec<u8> {
        self.sponge.absorb(data);
        self.into_squeezer().do_final(XOF_HASH_BYTES)
    }

    fn hash_out(mut self, data: &[u8], output: &mut [u8]) -> usize {
        self.sponge.absorb(data);
        output.fill(0);
        let n = core::cmp::min(output.len(), XOF_HASH_BYTES);
        self.into_squeezer().do_final_out(&mut output[..n])
    }

    fn do_update(&mut self, data: &[u8]) {
        if self.sponge.squeezing() {
            panic!("Ascon-XOF128 cannot absorb after squeezing has begun");
        }
        self.sponge.absorb(data);
    }

    fn do_final(self) -> Vec<u8> {
        self.into_squeezer().do_final(XOF_HASH_BYTES)
    }

    fn do_final_out(self, output: &mut [u8]) -> usize {
        output.fill(0);
        let n = core::cmp::min(output.len(), XOF_HASH_BYTES);
        self.into_squeezer().do_final_out(&mut output[..n])
    }

    fn do_final_partial_bits(
        self,
        _partial_byte: u8,
        _num_partial_bits: usize,
    ) -> Result<Vec<u8>, HashError> {
        Err(HashError::InvalidInput("Ascon-XOF128 does not support partial byte input"))
    }

    fn do_final_partial_bits_out(
        self,
        _partial_byte: u8,
        _num_partial_bits: usize,
        _output: &mut [u8],
    ) -> Result<usize, HashError> {
        Err(HashError::InvalidInput("Ascon-XOF128 does not support partial byte input"))
    }

    fn max_security_strength(&self) -> SecurityStrength {
        SecurityStrength::_128bit
    }
}

impl XOF for AsconXof128 {
    type Squeezer = AsconXof128Squeezer;

    fn into_squeezer(mut self) -> Self::Squeezer {
        if !self.sponge.squeezing() {
            self.sponge.pad_and_absorb();
        }
        AsconXof128Squeezer { sponge: self.sponge }
    }

    fn into_squeezer_partial_bits(
        self,
        _partial_byte: u8,
        _num_bits: usize,
    ) -> Result<Self::Squeezer, HashError> {
        Err(HashError::InvalidInput("Ascon-XOF128 does not support partial byte input"))
    }

    fn xof(mut self, data: &[u8], result_len: usize) -> Vec<u8> {
        self.sponge.absorb(data);
        self.into_squeezer().do_final(result_len)
    }

    fn xof_out(mut self, data: &[u8], output: &mut [u8]) -> usize {
        self.sponge.absorb(data);
        self.into_squeezer().do_final_out(output)
    }
}

impl XOFSqueezer for AsconXof128Squeezer {
    fn do_output(&mut self, num_bytes: usize) -> Vec<u8> {
        let mut out = vec![0u8; num_bytes];
        self.do_output_out(&mut out);
        out
    }

    fn do_output_out(&mut self, output: &mut [u8]) -> usize {
        output.fill(0);
        self.sponge.squeeze(output);
        output.len()
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
