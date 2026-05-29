use arrayref::{array_mut_ref, array_ref};
use core_interface::errors::HashError;
use core_interface::traits::{Algorithm, SecurityStrength, XOF};

// Ensuring constant-time by avoiding secret-dependent branches or indexing should not be an issue
// for this construction, as we are dealing with hashing/XOF mode without secret keys. We just need
// to ensure standard best practices and avoid secret-dependent data flow. The code below follows
// the logic from the provided C# reference as closely as possible, using Rust idioms.
//
// The permutation and transformations are from the Ascon specification. All operations that might
// cause overflow are performed using wrapping arithmetic if needed, and no secret values are used
// in conditions or loops. Input length and buffer positions are public information, so using loops
// on them is acceptable.
//
// Endianness has been updated to little endian as required by the specification update.

pub struct AsconCXof128 {
    s0: u64,
    s1: u64,
    s2: u64,
    s3: u64,
    s4: u64,

    // Cached initial state
    z0: u64,
    z1: u64,
    z2: u64,
    z3: u64,
    z4: u64,

    buf: [u8; 8],
    buf_pos: usize,
    squeezing: bool,
}

impl AsconCXof128 {
    /// Create a new Ascon-CXOF128 instance with no customization string.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self::with_customization(&[])
    }

    /// Create a new Ascon-CXOF128 instance with a given customization string `z`.
    /// `z` must be at most 256 bytes.
    pub fn with_customization(z: &[u8]) -> Self {
        if z.len() > 256 {
            panic!("customization string too long");
        }

        let mut st = AsconCXof128 {
            s0: 0,
            s1: 0,
            s2: 0,
            s3: 0,
            s4: 0,
            z0: 0,
            z1: 0,
            z2: 0,
            z3: 0,
            z4: 0,
            buf: [0u8; 8],
            buf_pos: 0,
            squeezing: false,
        };

        // st.s0 = 0x0000080000CC0004;
        // st.s1 = 0;
        // st.s2 = 0;
        // st.s3 = 0;
        // st.s4 = 0;
        // st.p12();

        if z.is_empty() {
            // st.p12();
            // st.pad_and_absorb();
            // st.p12();

            st.s0 = 0x500CCCC894E3C9E8;
            st.s1 = 0x5BED06F28F71248D;
            st.s2 = 0x3B03A0F930AFD512;
            st.s3 = 0x112EF093AA5C698B;
            st.s4 = 0x00C8356340A347F0;
        } else {
            st.s0 = 0x675527C2A0E8DE03;
            st.s1 = 0x43D12D7DC0377BBC;
            st.s2 = 0xE9901DEC426E81B5;
            st.s3 = 0x2AB14907720780B6;
            st.s4 = 0x8F3F1D02D432BC46;

            let bit_length = (z.len() as u64) << 3;
            st.s0 ^= bit_length;
            st.p12();
            st.update(z);
            st.pad_and_absorb();
            st.p12();
        }

        st.buf_pos = 0;

        // Cache the initialized state for reset
        st.z0 = st.s0;
        st.z1 = st.s1;
        st.z2 = st.s2;
        st.z3 = st.s3;
        st.z4 = st.s4;

        st
    }

    pub fn reset(&mut self) {
        self.s0 = self.z0;
        self.s1 = self.z1;
        self.s2 = self.z2;
        self.s3 = self.z3;
        self.s4 = self.z4;

        self.buf.fill(0);
        self.buf_pos = 0;
        self.squeezing = false;
    }

    pub fn update(&mut self, input: &[u8]) {
        if self.squeezing {
            panic!("attempt to absorb while squeezing");
        }

        let available = 8 - self.buf_pos;
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
            // self.buf_pos = 0;
        }

        while input.len() >= 8 {
            self.s0 ^= u64::from_le_bytes(*array_ref![input, 0, 8]);
            self.p12();
            input = &input[8..];
        }

        self.buf[..input.len()].copy_from_slice(input);
        self.buf_pos = input.len();
    }

    pub fn update_byte(&mut self, input: u8) {
        if self.squeezing {
            panic!("attempt to absorb while squeezing");
        }
        self.buf[self.buf_pos] = input;
        self.buf_pos += 1;
        if self.buf_pos == 8 {
            self.s0 ^= u64::from_le_bytes(self.buf);
            self.p12();
            self.buf_pos = 0;
        }
    }

    pub fn output(&mut self, output: &mut [u8]) -> usize {
        let result = output.len();
        let mut output = output;

        if !self.squeezing {
            self.pad_and_absorb();
            self.squeezing = true;
            self.buf_pos = 8;
        } else if self.buf_pos < 8 {
            let available = 8 - self.buf_pos;
            if output.len() <= available {
                let end_pos = self.buf_pos + output.len();
                output.copy_from_slice(&self.buf[self.buf_pos..end_pos]);
                self.buf_pos = end_pos;
                return result;
            }

            output[..available].copy_from_slice(&self.buf[self.buf_pos..]);
            output = &mut output[available..];
            self.buf_pos = 8;
        }

        while output.len() >= 8 {
            self.p12();
            *array_mut_ref![output, 0, 8] = self.s0.to_le_bytes();
            output = &mut output[8..];
        }

        if !output.is_empty() {
            self.p12();
            self.buf = self.s0.to_le_bytes();
            output.copy_from_slice(&self.buf[..output.len()]);
            self.buf_pos = output.len();
        }

        result
    }

    pub fn output_final(&mut self, output: &mut [u8]) -> usize {
        let n = self.output(output);
        self.reset();
        n
    }

    // TODO Simplify
    fn pad_and_absorb(&mut self) {
        let final_bits = (self.buf_pos << 3) as u32;
        let mask: u64 = if final_bits == 0 {
            0x00FFFFFFFFFFFFFF
        } else {
            0x00FFFFFFFFFFFFFF >> (56 - final_bits)
        };

        let mut block_val = 0u64;
        if self.buf_pos > 0 {
            let mut temp = [0u8; 8];
            for (i, t) in temp.iter_mut().enumerate() {
                *t = if i < self.buf_pos { self.buf[i] } else { 0 };
            }
            block_val = u64::from_le_bytes(temp);
        }

        self.s0 ^= block_val & mask;
        self.s0 ^= 0x01u64 << final_bits; // padding bit
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

impl Algorithm for AsconCXof128 {
    const ALG_NAME: &'static str = "Ascon-CXOF128";
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

impl XOF for AsconCXof128 {
    fn hash_xof(mut self, data: &[u8], result_len: usize) -> Vec<u8> {
        self.update(data);
        let mut out = vec![0u8; result_len];
        self.output(&mut out);
        out
    }

    fn hash_xof_out(mut self, data: &[u8], output: &mut [u8]) -> usize {
        self.update(data);
        self.output(output)
    }

    fn absorb(&mut self, data: &[u8]) -> Result<(), HashError> {
        self.update(data);
        Ok(())
    }

    fn absorb_last_partial_byte(
        &mut self,
        _partial_byte: u8,
        _num_partial_bits: usize,
    ) -> Result<(), HashError> {
        Err(HashError::InvalidInput("Ascon-CXOF128 does not support partial byte input"))
    }

    fn squeeze(&mut self, num_bytes: usize) -> Result<Vec<u8>, HashError> {
        let mut out = vec![0u8; num_bytes];
        self.output(&mut out);
        Ok(out)
    }

    fn squeeze_out(&mut self, output: &mut [u8]) -> Result<usize, HashError> {
        Ok(self.output(output))
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
