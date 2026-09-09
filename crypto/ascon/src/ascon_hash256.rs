//! Ascon-Hash256 cryptographic hash (NIST SP 800-232 §5.1), producing a 256-bit digest.
//!
//! Sponge mode over `Ascon-p[12]` with rate = 64 bits, capacity = 256 bits.

use bouncycastle_core::errors::{HashError, SuspendableError};
use bouncycastle_core::suspendable_state::{add_lib_ver, check_lib_ver};
use bouncycastle_core::traits::{Algorithm, Hash, HashAlgParams, SecurityStrength, Suspendable};
use bouncycastle_utils::secret::Secret;

use crate::sponge::{RATE, Sponge};

const DIGEST_BYTES: usize = 32;

/// Ascon-Hash256 hash function (NIST SP 800-232 §5.1), producing a 256-bit digest.
#[derive(Clone)]
pub struct AsconHash256 {
    sponge: Sponge,
}

impl AsconHash256 {
    /// Creates a new AsconHash256 instance.
    pub fn new() -> Self {
        // Precomputed state after the initialization permutation (SP 800-232 Table 12).
        Self {
            sponge: Sponge::from_state([
                0x9B1E_5494_E934_D681, 0x4BC3_A01E_3337_51D2, 0xAE65_396C_6B34_B81A,
                0x3C7F_D4A4_D56A_4DB3, 0x1A5C_4649_06C5_976D,
            ]),
        }
    }

    /// One-shot hash of `data`, returning the 32-byte digest.
    pub fn digest(data: &[u8]) -> [u8; DIGEST_BYTES] {
        let mut hasher = Self::new();
        hasher.sponge.absorb(data);
        let mut out = [0u8; DIGEST_BYTES];
        hasher.squeeze_into(&mut out);
        out
    }

    // Pad, absorb the final block, and squeeze the four 64-bit digest blocks (SP 800-232
    // Algorithm 5). The 32-byte digest is exactly RATE * 4 bytes, so a single generic
    // `Sponge::squeeze()` call over the whole output produces all four blocks with no leftover.
    fn squeeze_into(&mut self, output: &mut [u8; DIGEST_BYTES]) {
        self.sponge.pad_and_absorb();
        self.sponge.squeeze(output);
    }
}

impl Default for AsconHash256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Algorithm for AsconHash256 {
    const ALG_NAME: &'static str = "Ascon-Hash256";
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

impl HashAlgParams for AsconHash256 {
    const OUTPUT_LEN: usize = DIGEST_BYTES;
    const BLOCK_LEN: usize = RATE;
}

impl Hash for AsconHash256 {
    fn block_bitlen(&self) -> usize {
        RATE * 8
    }

    fn output_len(&self) -> usize {
        DIGEST_BYTES
    }

    fn hash(mut self, data: &[u8]) -> Vec<u8> {
        self.sponge.absorb(data);
        let mut out = [0u8; DIGEST_BYTES];
        self.squeeze_into(&mut out);
        out.to_vec()
    }

    fn hash_out(mut self, data: &[u8], output: &mut [u8]) -> usize {
        self.sponge.absorb(data);
        output.fill(0);
        let mut out = [0u8; DIGEST_BYTES];
        self.squeeze_into(&mut out);
        let n = core::cmp::min(output.len(), DIGEST_BYTES);
        output[..n].copy_from_slice(&out[..n]);
        n
    }

    fn do_update(&mut self, data: &[u8]) {
        self.sponge.absorb(data);
    }

    fn do_final(mut self) -> Vec<u8> {
        let mut out = [0u8; DIGEST_BYTES];
        self.squeeze_into(&mut out);
        out.to_vec()
    }

    fn do_final_out(mut self, output: &mut [u8]) -> usize {
        output.fill(0);
        let mut out = [0u8; DIGEST_BYTES];
        self.squeeze_into(&mut out);
        let n = core::cmp::min(output.len(), DIGEST_BYTES);
        output[..n].copy_from_slice(&out[..n]);
        n
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
        SecurityStrength::_128bit
    }
}

/// Length in bytes of the serialized state of [`AsconHash256`].
/// Layout: 3-byte library version || 1-byte state tag || 40-byte sponge state (5 × u64 LE)
/// || 8-byte rate buffer || 1-byte buffer position.
pub const SUSPENDED_ASCON_HASH256_STATE_LEN: usize = 53;

// Distinguishes an Ascon-Hash256 serialized state from the other (same-shaped) Ascon sponge states.
const HASH256_STATE_TAG: u8 = 0x01;

impl Suspendable<SUSPENDED_ASCON_HASH256_STATE_LEN> for AsconHash256 {
    fn suspend(self) -> [u8; SUSPENDED_ASCON_HASH256_STATE_LEN] {
        let mut out_to_return = [0u8; SUSPENDED_ASCON_HASH256_STATE_LEN];
        // infallible: add_lib_ver returns a slice of exactly SUSPENDED_ASCON_HASH256_STATE_LEN - 3 = 50 bytes.
        let out: &mut [u8; SUSPENDED_ASCON_HASH256_STATE_LEN - 3] =
            add_lib_ver(&mut out_to_return).try_into().unwrap();

        out[0] = HASH256_STATE_TAG;
        let state = self.sponge.state_words();
        for i in 0..5 {
            out[1 + i * 8..1 + i * 8 + 8].copy_from_slice(&state[i].to_le_bytes());
        }
        out[41..49].copy_from_slice(&self.sponge.buf_bytes());
        // buf_pos is always < RATE (8) before squeezing has begun, so it fits in one byte.
        debug_assert!(self.sponge.buf_pos() < RATE);
        out[49] = self.sponge.buf_pos() as u8;

        out_to_return
    }

    fn from_suspended(
        serialized_state: [u8; SUSPENDED_ASCON_HASH256_STATE_LEN],
    ) -> Result<Self, SuspendableError> {
        // infallible: check_lib_ver returns a slice of exactly SUSPENDED_ASCON_HASH256_STATE_LEN - 3 = 50 bytes.
        let input: &[u8; SUSPENDED_ASCON_HASH256_STATE_LEN - 3] =
            check_lib_ver(&serialized_state, None)?.try_into().unwrap();

        if input[0] != HASH256_STATE_TAG {
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
        if buf_pos >= RATE {
            return Err(SuspendableError::InvalidData);
        }

        Ok(AsconHash256 { sponge: Sponge::from_parts(s, buf, buf_pos, false) })
    }
}
