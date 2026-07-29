//! Ascon-Hash256 cryptographic hash (NIST SP 800-232 §5.1), producing a 256-bit digest.
//!
//! Sponge mode over `Ascon-p[12]` with rate = 64 bits, capacity = 256 bits.

use bouncycastle_core::errors::{HashError, SuspendableError};
use bouncycastle_core::suspendable_state::{add_lib_ver, check_lib_ver};
use bouncycastle_core::traits::{Algorithm, Hash, SecurityStrength, Suspendable};
use bouncycastle_utils::secret::Secret;

use crate::util::load_u64_le;

const RATE: usize = 8;
const DIGEST_BYTES: usize = 32;

/// Ascon-Hash256 hash function (NIST SP 800-232 §5.1), producing a 256-bit digest.
#[derive(Clone)]
pub struct AsconHash256 {
    // 320-bit sponge state (five 64-bit words S0..S4). Wrapped in `Secret` so the working state
    // -- which absorbs the message -- is scrubbed with volatile writes when dropped.
    s: Secret<[u64; 5]>,
    // Rate buffer holding a partial (< RATE) block between calls.
    buf: Secret<[u8; RATE]>,
    buf_pos: usize,
}

impl AsconHash256 {
    /// Creates a new AsconHash256 instance.
    pub fn new() -> Self {
        // Precomputed state after the initialization permutation (SP 800-232 Table 12).
        let mut s: Secret<[u64; 5]> = Secret::new();
        *s = [
            0x9B1E_5494_E934_D681,
            0x4BC3_A01E_3337_51D2,
            0xAE65_396C_6B34_B81A,
            0x3C7F_D4A4_D56A_4DB3,
            0x1A5C_4649_06C5_976D,
        ];
        Self { s, buf: Secret::new(), buf_pos: 0 }
    }

    /// Returns the digest size in bytes (32).
    pub fn digest_size() -> usize {
        DIGEST_BYTES
    }

    /// One-shot hash of `data`, returning the 32-byte digest.
    pub fn digest(data: &[u8]) -> [u8; DIGEST_BYTES] {
        let mut hasher = Self::new();
        hasher.update_bytes(data);
        let mut out = [0u8; DIGEST_BYTES];
        hasher.squeeze_into(&mut out);
        out
    }

    /// Updates the hasher with a single byte.
    pub fn update(&mut self, input: u8) {
        self.buf[self.buf_pos] = input;
        self.buf_pos += 1;
        if self.buf_pos == RATE {
            self.s[0] ^= u64::from_le_bytes(*self.buf);
            self.p12();
            self.buf_pos = 0;
        }
    }

    /// Updates the hasher with the given input data (streaming absorb).
    pub fn update_bytes(&mut self, input: &[u8]) {
        if input.is_empty() {
            return;
        }

        let mut in_pos = 0;

        if self.buf_pos > 0 {
            let available = RATE - self.buf_pos;
            if input.len() < available {
                self.buf[self.buf_pos..self.buf_pos + input.len()].copy_from_slice(input);
                self.buf_pos += input.len();
                return;
            } else {
                self.buf[self.buf_pos..].copy_from_slice(&input[..available]);
                self.s[0] ^= u64::from_le_bytes(*self.buf);
                self.p12();
                self.buf_pos = 0;
                in_pos += available;
            }
        }

        while input.len() - in_pos >= RATE {
            self.s[0] ^= load_u64_le(input, in_pos);
            self.p12();
            in_pos += RATE;
        }

        let remaining = input.len() - in_pos;
        self.buf[..remaining].copy_from_slice(&input[in_pos..]);
        self.buf_pos = remaining;
    }

    /// Finalizes the hasher, consuming it and writing the 32-byte digest into `output`.
    pub fn do_final_into(mut self, output: &mut [u8; DIGEST_BYTES]) {
        self.squeeze_into(output);
    }

    // Pad, absorb the final block, and squeeze the four 64-bit digest blocks (SP 800-232 Alg. 5).
    fn squeeze_into(&mut self, output: &mut [u8; DIGEST_BYTES]) {
        self.pad_and_absorb();

        output[0..8].copy_from_slice(&self.s[0].to_le_bytes());
        for i in 1..4 {
            self.p12();
            output[i * 8..(i + 1) * 8].copy_from_slice(&self.s[0].to_le_bytes());
        }
    }

    fn pad_and_absorb(&mut self) {
        let final_bits = self.buf_pos << 3;
        let x = u64::from_le_bytes(*self.buf);
        let mask =
            if final_bits == 0 { 0u64 } else { 0x00FF_FFFF_FFFF_FFFF_u64 >> (56 - final_bits) };
        self.s[0] ^= x & mask;
        self.s[0] ^= 0x01u64 << final_bits;

        self.p12();
    }

    fn p12(&mut self) {
        self.round(0xF0);
        self.round(0xE1);
        self.round(0xD2);
        self.round(0xC3);
        self.round(0xB4);
        self.round(0xA5);
        self.round(0x96);
        self.round(0x87);
        self.round(0x78);
        self.round(0x69);
        self.round(0x5A);
        self.round(0x4B);
    }

    // One round p = p_L ∘ p_S ∘ p_C (SP 800-232 §3.2–3.4).
    #[inline(always)]
    fn round(&mut self, c: u64) {
        let sx = self.s[2] ^ c;
        let t0 = self.s[0] ^ self.s[1] ^ sx ^ self.s[3] ^ (self.s[1] & (self.s[0] ^ sx ^ self.s[4]));
        let t1 = self.s[0] ^ sx ^ self.s[3] ^ self.s[4] ^ ((self.s[1] ^ sx) & (self.s[1] ^ self.s[3]));
        let t2 = self.s[1] ^ sx ^ self.s[4] ^ (self.s[3] & self.s[4]);
        let t3 = self.s[0] ^ self.s[1] ^ sx ^ (!self.s[0] & (self.s[3] ^ self.s[4]));
        let t4 = self.s[1] ^ self.s[3] ^ self.s[4] ^ ((self.s[0] ^ self.s[4]) & self.s[1]);

        self.s[0] = t0 ^ t0.rotate_right(19) ^ t0.rotate_right(28);
        self.s[1] = t1 ^ t1.rotate_right(39) ^ t1.rotate_right(61);
        self.s[2] = !(t2 ^ t2.rotate_right(1) ^ t2.rotate_right(6));
        self.s[3] = t3 ^ t3.rotate_right(10) ^ t3.rotate_right(17);
        self.s[4] = t4 ^ t4.rotate_right(7) ^ t4.rotate_right(41);
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

impl Hash for AsconHash256 {
    fn block_bitlen(&self) -> usize {
        RATE * 8
    }

    fn output_len(&self) -> usize {
        DIGEST_BYTES
    }

    fn hash(mut self, data: &[u8]) -> Vec<u8> {
        self.update_bytes(data);
        let mut out = [0u8; DIGEST_BYTES];
        self.squeeze_into(&mut out);
        out.to_vec()
    }

    fn hash_out(mut self, data: &[u8], output: &mut [u8]) -> usize {
        self.update_bytes(data);
        output[..DIGEST_BYTES].fill(0);
        let mut out = [0u8; DIGEST_BYTES];
        self.squeeze_into(&mut out);
        output[..DIGEST_BYTES].copy_from_slice(&out);
        DIGEST_BYTES
    }

    fn do_update(&mut self, data: &[u8]) {
        self.update_bytes(data);
    }

    fn do_final(mut self) -> Vec<u8> {
        let mut out = [0u8; DIGEST_BYTES];
        self.squeeze_into(&mut out);
        out.to_vec()
    }

    fn do_final_out(mut self, output: &mut [u8]) -> usize {
        output[..DIGEST_BYTES].fill(0);
        let mut out = [0u8; DIGEST_BYTES];
        self.squeeze_into(&mut out);
        output[..DIGEST_BYTES].copy_from_slice(&out);
        DIGEST_BYTES
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
        // Version prefix; `add_lib_ver` returns the remaining bytes after the 3-byte tag.
        let out: &mut [u8; SUSPENDED_ASCON_HASH256_STATE_LEN - 3] =
            add_lib_ver(&mut out_to_return).try_into().unwrap();

        out[0] = HASH256_STATE_TAG;
        for i in 0..5 {
            out[1 + i * 8..1 + i * 8 + 8].copy_from_slice(&self.s[i].to_le_bytes());
        }
        out[41..49].copy_from_slice(&*self.buf);
        // buf_pos is always < RATE (8), so it fits in one byte.
        debug_assert!(self.buf_pos < RATE);
        out[49] = self.buf_pos as u8;

        out_to_return
    }

    fn from_suspended(
        serialized_state: [u8; SUSPENDED_ASCON_HASH256_STATE_LEN],
    ) -> Result<Self, SuspendableError> {
        let input: &[u8; SUSPENDED_ASCON_HASH256_STATE_LEN - 3] =
            check_lib_ver(&serialized_state, None)?.try_into().unwrap();

        if input[0] != HASH256_STATE_TAG {
            return Err(SuspendableError::InvalidData);
        }
        let mut s = Secret::<[u64; 5]>::new();
        for i in 0..5 {
            s[i] = u64::from_le_bytes(input[1 + i * 8..1 + i * 8 + 8].try_into().unwrap());
        }
        let mut buf = Secret::<[u8; RATE]>::new();
        buf.copy_from_slice(&input[41..49]);
        let buf_pos = input[49] as usize;
        if buf_pos >= RATE {
            return Err(SuspendableError::InvalidData);
        }

        Ok(AsconHash256 { s, buf, buf_pos })
    }
}
