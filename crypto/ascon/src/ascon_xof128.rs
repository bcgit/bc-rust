//! Ascon-XOF128 extendable-output function (NIST SP 800-232 §5.2).
//!
//! Sponge mode over `Ascon-p[12]` with rate = 64 bits, capacity = 256 bits. Supports the streaming
//! absorb/squeeze API of SP 800-232 §5.4 (squeeze may be called repeatedly).

use bouncycastle_core::errors::{HashError, SuspendableError};
use bouncycastle_core::suspendable_state::{add_lib_ver, check_lib_ver};
use bouncycastle_core::traits::{Algorithm, SecurityStrength, Suspendable, XOF};
use bouncycastle_utils::secret::Secret;

use crate::util::{load_u64_le, store_u64_le};

const RATE: usize = 8;

/// Ascon-XOF128 as specified in NIST SP 800-232.
#[derive(Clone)]
pub struct AsconXof128 {
    // 320-bit sponge state (five 64-bit words S0..S4). Wrapped in `Secret` so the working state
    // is scrubbed with volatile writes when dropped.
    s: Secret<[u64; 5]>,
    // Rate buffer: partial input block while absorbing, or leftover squeezed bytes afterwards.
    buf: Secret<[u8; RATE]>,
    buf_pos: usize,
    squeezing: bool,
}

impl AsconXof128 {
    /// Creates a new Ascon-XOF128 instance.
    pub fn new() -> Self {
        // Precomputed state after the initialization permutation (SP 800-232 Table 12).
        let mut s: Secret<[u64; 5]> = Secret::new();
        *s = [
            0xDA82CE768D9447EB,
            0xCC7CE6C75F1EF969,
            0xE7508FD780085631,
            0x0EE0EA53416B58CC,
            0xE0547524DB6F0BDE,
        ];
        Self { s, buf: Secret::new(), buf_pos: 0, squeezing: false }
    }

    /// Absorb input data. Cannot be called once squeezing has begun.
    pub fn update(&mut self, input: &[u8]) {
        if self.squeezing {
            panic!("attempt to absorb while squeezing");
        }

        let available = RATE - self.buf_pos;
        if input.len() < available {
            self.buf[self.buf_pos..self.buf_pos + input.len()].copy_from_slice(input);
            self.buf_pos += input.len();
            return;
        }

        let mut input = input;

        if self.buf_pos > 0 {
            self.buf[self.buf_pos..].copy_from_slice(&input[..available]);
            self.s[0] ^= u64::from_le_bytes(*self.buf);
            self.p12();
            input = &input[available..];
        }

        while input.len() >= RATE {
            self.s[0] ^= load_u64_le(input, 0);
            self.p12();
            input = &input[RATE..];
        }

        self.buf[..input.len()].copy_from_slice(input);
        self.buf_pos = input.len();
    }

    /// Absorb a single byte. Cannot be called once squeezing has begun.
    pub fn update_byte(&mut self, input: u8) {
        if self.squeezing {
            panic!("attempt to absorb while squeezing");
        }
        self.buf[self.buf_pos] = input;
        self.buf_pos += 1;
        if self.buf_pos == RATE {
            self.s[0] ^= u64::from_le_bytes(*self.buf);
            self.p12();
            self.buf_pos = 0;
        }
    }

    /// Squeeze `output.len()` bytes of output. May be called multiple times; the first call ends the
    /// absorb phase by padding and absorbing the final block. Returns the number of bytes written.
    pub fn squeeze_into(&mut self, output: &mut [u8]) -> usize {
        let result = output.len();
        let mut output = output;

        if !self.squeezing {
            self.pad_and_absorb();
            self.squeezing = true;
            self.buf_pos = RATE;
        } else if self.buf_pos < RATE {
            let available = RATE - self.buf_pos;
            if output.len() <= available {
                let end_pos = self.buf_pos + output.len();
                output.copy_from_slice(&self.buf[self.buf_pos..end_pos]);
                self.buf_pos = end_pos;
                return result;
            }

            output[..available].copy_from_slice(&self.buf[self.buf_pos..]);
            output = &mut output[available..];
            self.buf_pos = RATE;
        }

        while output.len() >= RATE {
            self.p12();
            store_u64_le(output, 0, self.s[0]);
            output = &mut output[RATE..];
        }

        if !output.is_empty() {
            self.p12();
            *self.buf = self.s[0].to_le_bytes();
            output.copy_from_slice(&self.buf[..output.len()]);
            self.buf_pos = output.len();
        }

        result
    }

    // Pad the final absorbed block (SP 800-232 §5.2 step 3 / Alg. 6).
    fn pad_and_absorb(&mut self) {
        let final_bits = (self.buf_pos << 3) as u32;
        let mask: u64 = if final_bits == 0 {
            0x00FFFFFFFFFFFFFF
        } else {
            0x00FFFFFFFFFFFFFF >> (56 - final_bits)
        };

        let mut block_val = 0u64;
        if self.buf_pos > 0 {
            let mut temp = [0u8; RATE];
            for (i, t) in temp.iter_mut().enumerate() {
                *t = if i < self.buf_pos { self.buf[i] } else { 0 };
            }
            block_val = u64::from_le_bytes(temp);
        }

        self.s[0] ^= block_val & mask;
        self.s[0] ^= 0x01u64 << final_bits;
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
        let t3 = self.s[0] ^ self.s[1] ^ sx ^ ((!self.s[0]) & (self.s[3] ^ self.s[4]));
        let t4 = self.s[1] ^ self.s[3] ^ self.s[4] ^ ((self.s[0] ^ self.s[4]) & self.s[1]);

        self.s[0] = t0 ^ t0.rotate_right(19) ^ t0.rotate_right(28);
        self.s[1] = t1 ^ t1.rotate_right(39) ^ t1.rotate_right(61);
        self.s[2] = !(t2 ^ t2.rotate_right(1) ^ t2.rotate_right(6));
        self.s[3] = t3 ^ t3.rotate_right(10) ^ t3.rotate_right(17);
        self.s[4] = t4 ^ t4.rotate_right(7) ^ t4.rotate_right(41);
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
        self.update(data);
        let mut out = vec![0u8; result_len];
        self.squeeze_into(&mut out);
        out
    }

    fn hash_xof_out(mut self, data: &[u8], output: &mut [u8]) -> usize {
        self.update(data);
        self.squeeze_into(output)
    }

    fn absorb(&mut self, data: &[u8]) -> Result<(), HashError> {
        if self.squeezing {
            return Err(HashError::InvalidState(
                "Ascon-XOF128 cannot absorb after squeezing has begun",
            ));
        }
        self.update(data);
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
        let out: &mut [u8; SUSPENDED_ASCON_XOF128_STATE_LEN - 3] =
            add_lib_ver(&mut out_to_return).try_into().unwrap();

        out[0] = XOF128_STATE_TAG;
        for i in 0..5 {
            out[1 + i * 8..1 + i * 8 + 8].copy_from_slice(&self.s[i].to_le_bytes());
        }
        out[41..49].copy_from_slice(&*self.buf);
        debug_assert!(self.buf_pos <= RATE);
        out[49] = self.buf_pos as u8;
        out[50] = self.squeezing as u8;

        out_to_return
    }

    fn from_suspended(
        serialized_state: [u8; SUSPENDED_ASCON_XOF128_STATE_LEN],
    ) -> Result<Self, SuspendableError> {
        let input: &[u8; SUSPENDED_ASCON_XOF128_STATE_LEN - 3] =
            check_lib_ver(&serialized_state, None)?.try_into().unwrap();

        if input[0] != XOF128_STATE_TAG {
            return Err(SuspendableError::InvalidData);
        }
        let mut s = Secret::<[u64; 5]>::new();
        for i in 0..5 {
            s[i] = u64::from_le_bytes(input[1 + i * 8..1 + i * 8 + 8].try_into().unwrap());
        }
        let mut buf = Secret::<[u8; RATE]>::new();
        buf.copy_from_slice(&input[41..49]);
        // While absorbing, buf_pos < RATE; once squeezing, it may equal RATE (buffer drained).
        let buf_pos = input[49] as usize;
        if buf_pos > RATE {
            return Err(SuspendableError::InvalidData);
        }
        let squeezing = match input[50] {
            0 => false,
            1 => true,
            _ => return Err(SuspendableError::InvalidData),
        };

        Ok(AsconXof128 { s, buf, buf_pos, squeezing })
    }
}
