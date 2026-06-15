//! Ascon-CXOF128 customized extendable-output function (NIST SP 800-232 §5.3).
//!
//! A variant of Ascon-XOF128 that first absorbs a user-supplied customization string `Z`
//! (length-prefixed per SP 800-232 Alg. 7) to provide domain separation. Same sponge parameters as
//! Ascon-XOF128 (rate = 64 bits, capacity = 256 bits, `Ascon-p[12]`).

use bouncycastle_core::errors::HashError;
use bouncycastle_core::traits::{Algorithm, SecurityStrength, XOF};

use crate::util::{load_u64_le, store_u64_le};

const RATE: usize = 8;

/// Maximum customization-string length in bytes (2048 bits, per SP 800-232 §5.3).
const MAX_CUSTOMIZATION_BYTES: usize = 256;

/// Ascon-CXOF128 customized extendable-output function (NIST SP 800-232 §5.3).
pub struct AsconCXof128 {
    s0: u64,
    s1: u64,
    s2: u64,
    s3: u64,
    s4: u64,

    buf: [u8; RATE],
    buf_pos: usize,
    squeezing: bool,
}

impl AsconCXof128 {
    /// Create a new Ascon-CXOF128 instance with no customization string.
    pub fn new() -> Self {
        Self::with_customization(&[])
    }

    /// Create a new Ascon-CXOF128 instance with the given customization string `z`.
    /// `z` must be at most 256 bytes (2048 bits).
    pub fn with_customization(z: &[u8]) -> Self {
        if z.len() > MAX_CUSTOMIZATION_BYTES {
            panic!("Ascon-CXOF128 customization string exceeds 256 bytes");
        }

        let mut st = if z.is_empty() {
            // Precomputed state after initialization + absorbing an empty (length-0) customization
            // string and its padding block.
            AsconCXof128 {
                s0: 0x500CCCC894E3C9E8,
                s1: 0x5BED06F28F71248D,
                s2: 0x3B03A0F930AFD512,
                s3: 0x112EF093AA5C698B,
                s4: 0x00C8356340A347F0,
                buf: [0u8; RATE],
                buf_pos: 0,
                squeezing: false,
            }
        } else {
            // Precomputed state after the initialization permutation (SP 800-232 Table 12).
            let mut st = AsconCXof128 {
                s0: 0x675527C2A0E8DE03,
                s1: 0x43D12D7DC0377BBC,
                s2: 0xE9901DEC426E81B5,
                s3: 0x2AB14907720780B6,
                s4: 0x8F3F1D02D432BC46,
                buf: [0u8; RATE],
                buf_pos: 0,
                squeezing: false,
            };

            // Z0 = int64(|Z|) in bits, then absorb the parsed/padded customization blocks
            // (SP 800-232 Alg. 7, "Customization" loop).
            let bit_length = (z.len() as u64) << 3;
            st.s0 ^= bit_length;
            st.p12();
            st.update(z);
            st.pad_and_absorb();
            st.p12();
            st
        };

        // Customization is complete; reset the buffer to begin the message-absorb phase.
        st.buf.fill(0);
        st.buf_pos = 0;
        st
    }

    /// Absorb message input. Cannot be called once squeezing has begun.
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
            self.s0 ^= u64::from_le_bytes(self.buf);
            self.p12();
            input = &input[available..];
        }

        while input.len() >= RATE {
            self.s0 ^= load_u64_le(input, 0);
            self.p12();
            input = &input[RATE..];
        }

        self.buf[..input.len()].copy_from_slice(input);
        self.buf_pos = input.len();
    }

    /// Absorb a single message byte. Cannot be called once squeezing has begun.
    pub fn update_byte(&mut self, input: u8) {
        if self.squeezing {
            panic!("attempt to absorb while squeezing");
        }
        self.buf[self.buf_pos] = input;
        self.buf_pos += 1;
        if self.buf_pos == RATE {
            self.s0 ^= u64::from_le_bytes(self.buf);
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
            store_u64_le(output, 0, self.s0);
            output = &mut output[RATE..];
        }

        if !output.is_empty() {
            self.p12();
            self.buf = self.s0.to_le_bytes();
            output.copy_from_slice(&self.buf[..output.len()]);
            self.buf_pos = output.len();
        }

        result
    }

    // Pad the final absorbed block (SP 800-232 §5.2 step 3 / Alg. 7).
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

        self.s0 ^= block_val & mask;
        self.s0 ^= 0x01u64 << final_bits;
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
        let sx = self.s2 ^ c;

        let t0 = self.s0 ^ self.s1 ^ sx ^ self.s3 ^ (self.s1 & (self.s0 ^ sx ^ self.s4));
        let t1 = self.s0 ^ sx ^ self.s3 ^ self.s4 ^ ((self.s1 ^ sx) & (self.s1 ^ self.s3));
        let t2 = self.s1 ^ sx ^ self.s4 ^ (self.s3 & self.s4);
        let t3 = self.s0 ^ self.s1 ^ sx ^ ((!self.s0) & (self.s3 ^ self.s4));
        let t4 = self.s1 ^ self.s3 ^ self.s4 ^ ((self.s0 ^ self.s4) & self.s1);

        self.s0 = t0 ^ t0.rotate_right(19) ^ t0.rotate_right(28);
        self.s1 = t1 ^ t1.rotate_right(39) ^ t1.rotate_right(61);
        self.s2 = !(t2 ^ t2.rotate_right(1) ^ t2.rotate_right(6));
        self.s3 = t3 ^ t3.rotate_right(10) ^ t3.rotate_right(17);
        self.s4 = t4 ^ t4.rotate_right(7) ^ t4.rotate_right(41);
    }
}

impl Default for AsconCXof128 {
    fn default() -> Self {
        Self::new()
    }
}

// Zeroize the working state and buffer before returning the memory to the OS.
impl Drop for AsconCXof128 {
    fn drop(&mut self) {
        self.buf.fill(0);
        self.s0 = 0;
        self.s1 = 0;
        self.s2 = 0;
        self.s3 = 0;
        self.s4 = 0;
    }
}

impl Algorithm for AsconCXof128 {
    const ALG_NAME: &'static str = "Ascon-CXOF128";
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

impl XOF for AsconCXof128 {
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

    fn absorb(&mut self, data: &[u8]) {
        self.update(data);
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
