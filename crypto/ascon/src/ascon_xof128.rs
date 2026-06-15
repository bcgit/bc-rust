use arrayref::{array_mut_ref, array_ref};
use bouncycastle_core::errors::HashError;
use bouncycastle_core::traits::{Algorithm, SecurityStrength, XOF};

/// Ascon-XOF128 as specified in NIST SP 800-232.
pub struct AsconXof128 {
    s0: u64,
    s1: u64,
    s2: u64,
    s3: u64,
    s4: u64,
    buf: [u8; 8],
    buf_pos: usize,
    squeezing: bool,
}

impl AsconXof128 {
    pub fn new() -> Self {
        let mut instance =
            Self { s0: 0, s1: 0, s2: 0, s3: 0, s4: 0, buf: [0u8; 8], buf_pos: 0, squeezing: false };
        instance.reset();
        instance
    }

    pub fn reset(&mut self) {
        self.s0 = 0xDA82CE768D9447EB;
        self.s1 = 0xCC7CE6C75F1EF969;
        self.s2 = 0xE7508FD780085631;
        self.s3 = 0x0EE0EA53416B58CC;
        self.s4 = 0xE0547524DB6F0BDE;

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
        self.output(&mut out);
        out
    }

    fn hash_xof_out(mut self, data: &[u8], output: &mut [u8]) -> usize {
        self.update(data);
        self.output(output)
    }

    fn absorb(&mut self, data: &[u8]) {
        self.update(data);
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
        self.output(&mut out);
        out
    }

    fn squeeze_out(&mut self, output: &mut [u8]) -> usize {
        self.output(output)
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
