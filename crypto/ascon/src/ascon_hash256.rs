// crates/ascon/src/ascon_hash256.rs

//! Ascon-Hash256 implementation.

use core_interface::errors::HashError;
use core_interface::traits::{Algorithm, Hash, SecurityStrength};
use utils::pack;

#[derive(Clone)]
pub struct AsconHash256 {
    buf: [u8; 8],
    buf_pos: usize,
    s0: u64,
    s1: u64,
    s2: u64,
    s3: u64,
    s4: u64,
}

impl AsconHash256 {
    /// Creates a new AsconHash256 instance.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let mut hasher = Self { buf: [0u8; 8], buf_pos: 0, s0: 0, s1: 0, s2: 0, s3: 0, s4: 0 };
        hasher.reset();
        hasher
    }

    /// Returns the digest size in bytes.
    pub fn digest_size() -> usize {
        32
    }

    /// Updates the hasher with a single byte.
    pub fn update(&mut self, input: u8) {
        self.buf[self.buf_pos] = input;
        self.buf_pos += 1;
        if self.buf_pos == 8 {
            let x = pack::little_endian_to_u64(&self.buf);
            self.s0 ^= x;
            self.p12();
            self.buf_pos = 0;
        }
    }

    /// Updates the hasher with the given input data.
    pub fn update_bytes(&mut self, input: &[u8]) {
        if input.is_empty() {
            return;
        }

        let mut in_pos = 0;
        const RATE: usize = 8;

        if self.buf_pos > 0 {
            let available = RATE - self.buf_pos;
            if input.len() < available {
                self.buf[self.buf_pos..self.buf_pos + input.len()].copy_from_slice(input);
                self.buf_pos += input.len();
                return;
            } else {
                self.buf[self.buf_pos..].copy_from_slice(&input[..available]);
                let x = pack::little_endian_to_u64(&self.buf);
                self.s0 ^= x;
                self.p12();
                self.buf_pos = 0;
                in_pos += available;
            }
        }

        while input.len() - in_pos >= RATE {
            let x = pack::little_endian_to_u64(&input[in_pos..in_pos + RATE]);
            self.s0 ^= x;
            self.p12();
            in_pos += RATE;
        }

        let remaining = input.len() - in_pos;
        self.buf[..remaining].copy_from_slice(&input[in_pos..]);
        self.buf_pos = remaining;
    }

    /// Finalizes the hasher and writes the output digest.
    pub fn finalize(&mut self, output: &mut [u8]) {
        assert!(output.len() >= Self::digest_size(), "output buffer too short");

        self.pad_and_absorb();

        pack::u64_to_little_endian(self.s0, &mut output[0..8]);

        for i in 1..4 {
            self.p12();
            pack::u64_to_little_endian(self.s0, &mut output[i * 8..(i + 1) * 8]);
        }

        self.reset();
    }

    /// Resets the hasher to its initial state.
    pub fn reset(&mut self) {
        self.s0 = 0x9B1E_5494_E934_D681;
        self.s1 = 0x4BC3_A01E_3337_51D2;
        self.s2 = 0xAE65_396C_6B34_B81A;
        self.s3 = 0x3C7F_D4A4_D56A_4DB3;
        self.s4 = 0x1A5C_4649_06C5_976D;

        self.buf = [0u8; 8];
        self.buf_pos = 0;
    }

    fn pad_and_absorb(&mut self) {
        let final_bits = self.buf_pos << 3;
        let x = pack::little_endian_to_u64(&self.buf);
        let mask =
            if final_bits == 0 { 0u64 } else { 0x00FF_FFFF_FFFF_FFFF_u64 >> (56 - final_bits) };
        self.s0 ^= x & mask;
        self.s0 ^= 0x01u64 << final_bits;

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

    fn round(&mut self, c: u64) {
        let sx = self.s2 ^ c;
        let t0 = self.s0 ^ self.s1 ^ sx ^ self.s3 ^ (self.s1 & (self.s0 ^ sx ^ self.s4));
        let t1 = self.s0 ^ sx ^ self.s3 ^ self.s4 ^ ((self.s1 ^ sx) & (self.s1 ^ self.s3));
        let t2 = self.s1 ^ sx ^ self.s4 ^ (self.s3 & self.s4);
        let t3 = self.s0 ^ self.s1 ^ sx ^ (!self.s0 & (self.s3 ^ self.s4));
        let t4 = self.s1 ^ self.s3 ^ self.s4 ^ ((self.s0 ^ self.s4) & self.s1);

        self.s0 = t0 ^ t0.rotate_right(19) ^ t0.rotate_right(28);
        self.s1 = t1 ^ t1.rotate_right(39) ^ t1.rotate_right(61);
        self.s2 = !(t2 ^ t2.rotate_right(1) ^ t2.rotate_right(6));
        self.s3 = t3 ^ t3.rotate_right(10) ^ t3.rotate_right(17);
        self.s4 = t4 ^ t4.rotate_right(7) ^ t4.rotate_right(41);
    }
}

impl Algorithm for AsconHash256 {
    const ALG_NAME: &'static str = "Ascon-Hash256";
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

impl Hash for AsconHash256 {
    fn block_bitlen(&self) -> usize {
        64
    }

    fn output_len(&self) -> usize {
        32
    }

    fn hash(mut self, data: &[u8]) -> Vec<u8> {
        self.update_bytes(data);
        let mut out = vec![0u8; 32];
        self.finalize(&mut out);
        out
    }

    fn hash_out(mut self, data: &[u8], output: &mut [u8]) -> Result<usize, HashError> {
        self.update_bytes(data);
        self.finalize(output);
        Ok(32)
    }

    fn do_update(&mut self, data: &[u8]) -> Result<(), HashError> {
        self.update_bytes(data);
        Ok(())
    }

    fn do_final(mut self) -> Result<Vec<u8>, HashError> {
        let mut out = vec![0u8; 32];
        self.finalize(&mut out);
        Ok(out)
    }

    fn do_final_out(mut self, output: &mut [u8]) -> Result<usize, HashError> {
        self.finalize(output);
        Ok(32)
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
