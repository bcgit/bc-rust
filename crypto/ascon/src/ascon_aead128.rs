//! Ascon-AEAD128 authenticated encryption, as specified in NIST SP 800-232 §4.
//!
//! Rate = 128 bits, capacity = 192 bits, 128-bit key/nonce/tag. Initialization and finalization use
//! `Ascon-p[12]`; associated-data and plaintext/ciphertext blocks use `Ascon-p[8]`.

use core::fmt::{self, Debug, Display, Formatter};

use bouncycastle_core::errors::AeadError;
use bouncycastle_core::traits::{AeadCipher, Algorithm, Secret, SecurityStrength};

use crate::util::{load_u64_le, store_u64_le};

const CRYPTO_KEYBYTES: usize = 16;
const CRYPTO_ABYTES: usize = 16;
const RATE: usize = 16;
const BUF_SIZE_DECRYPT: usize = RATE + CRYPTO_ABYTES; // 16 + 16 = 32

/// Ascon-AEAD128 initial value (SP 800-232 Table 14).
const ASCON_IV: u64 = 0x00001000808C0001;

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    EncInit,
    EncAad,
    EncData,
    EncFinal,
    DecInit,
    DecAad,
    DecData,
    DecFinal,
}

/// An implementation of the Ascon-AEAD128 algorithm (NIST SP 800-232).
///
/// A single instance performs one operation (encryption or decryption) under one (key, nonce) pair.
/// See [`AsconAead128::new`] for the streaming workflow and [`AsconAead128::encrypt`] /
/// [`AsconAead128::decrypt`] for the one-shot APIs.
pub struct AsconAead128 {
    // Secret key and nonce (both 128 bits).
    k0: u64,
    k1: u64,
    n0: u64,
    n1: u64,
    // 320-bit internal state (five 64-bit words).
    s0: u64,
    s1: u64,
    s2: u64,
    s3: u64,
    s4: u64,
    // Buffer used for processing AAD or (de)ciphertext.
    // For decryption the buffer size is RATE + CRYPTO_ABYTES = 32 bytes.
    buf: [u8; BUF_SIZE_DECRYPT],
    buf_pos: usize,
    // The computed authentication tag (after encryption finalization).
    mac: Option<[u8; CRYPTO_ABYTES]>,
    // State machine for enforcing the call order.
    state: State,
    // true for encryption mode; false for decryption.
    for_encryption: bool,
    finished: bool,
}

impl AsconAead128 {
    /// Create a new instance.
    /// * `key` is the 128-bit secret key.
    /// * `nonce` is the 128-bit nonce. It **must** be unique per encryption under a given key.
    /// * `ad` is optional associated data (authenticated, not encrypted); processed immediately.
    /// * `for_encryption` is true for encryption, false for decryption.
    pub fn new(
        key: &[u8; CRYPTO_KEYBYTES],
        nonce: &[u8; CRYPTO_KEYBYTES],
        ad: Option<&[u8]>,
        for_encryption: bool,
    ) -> Self {
        let k0 = load_u64_le(key, 0);
        let k1 = load_u64_le(key, 8);
        let n0 = load_u64_le(nonce, 0);
        let n1 = load_u64_le(nonce, 8);
        let state = if for_encryption { State::EncInit } else { State::DecInit };
        let mut aead = AsconAead128 {
            k0,
            k1,
            n0,
            n1,
            s0: 0,
            s1: 0,
            s2: 0,
            s3: 0,
            s4: 0,
            buf: [0u8; BUF_SIZE_DECRYPT],
            buf_pos: 0,
            mac: None,
            state,
            for_encryption,
            finished: false,
        };
        aead.init_state();
        if let Some(ad_bytes) = ad
            && !ad_bytes.is_empty()
        {
            aead.process_aad_bytes(ad_bytes);
        }
        aead
    }

    /// One-shot authenticated encryption (SP 800-232 Algorithm 3).
    /// Writes ciphertext followed by the 128-bit tag into `out`, which must be at least
    /// `plaintext.len() + 16` bytes. Returns the number of bytes written.
    pub fn encrypt(
        key: &[u8; CRYPTO_KEYBYTES],
        nonce: &[u8; CRYPTO_KEYBYTES],
        ad: Option<&[u8]>,
        plaintext: &[u8],
        out: &mut [u8],
    ) -> usize {
        let mut cipher = Self::new(key, nonce, ad, true);
        let n = cipher.encrypt_update(plaintext, out);
        n + cipher.encrypt_finalize(&mut out[n..])
    }

    /// One-shot authenticated decryption (SP 800-232 Algorithm 4).
    /// `ciphertext` is the ciphertext followed by the 128-bit tag. Writes the recovered plaintext
    /// into `out`, which must be at least `ciphertext.len() - 16` bytes. Returns the number of bytes
    /// written, or [`AeadError::AuthenticationFailed`] if the tag does not verify.
    pub fn decrypt(
        key: &[u8; CRYPTO_KEYBYTES],
        nonce: &[u8; CRYPTO_KEYBYTES],
        ad: Option<&[u8]>,
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, AeadError> {
        let mut cipher = Self::new(key, nonce, ad, false);
        let n = cipher.decrypt_update(ciphertext, out);
        Ok(n + cipher.decrypt_finalize(&mut out[n..])?)
    }

    // Initialization (SP 800-232 §4.1.1 step 1): S = IV || K || N, then Ascon-p[12], then XOR K into
    // the last 128 bits. No caching, since the key and/or nonce change for every operation.
    fn init_state(&mut self) {
        self.s0 = ASCON_IV;
        self.s1 = self.k0;
        self.s2 = self.k1;
        self.s3 = self.n0;
        self.s4 = self.n1;
        self.p12();
        self.s3 ^= self.k0;
        self.s4 ^= self.k1;
    }

    fn p12(&mut self) {
        // Round constants c_i for Ascon-p[12] (SP 800-232 Table 5, indices 4..=15).
        let round_consts: [u64; 12] =
            [0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B];
        for &c in round_consts.iter() {
            self.round(c);
        }
    }

    fn p8(&mut self) {
        // Round constants c_i for Ascon-p[8] (SP 800-232 Table 5, indices 8..=15).
        let round_consts: [u64; 8] = [0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B];
        for &c in round_consts.iter() {
            self.round(c);
        }
    }

    // One round p = p_L ∘ p_S ∘ p_C (SP 800-232 §3.2–3.4). The S-box (§3.3 Eq. 7) and the per-word
    // linear diffusion Σ0..Σ4 (§3.4 Eq. 8–12) are fused here in their bitsliced form.
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

    /// Returns a 64-bit value with a single "1" at bit position (i*8): the integer form of the
    /// padding rule for a partial block (SP 800-232 Appendix A.2).
    fn pad(i: usize) -> u64 {
        debug_assert!(i < 8);
        0x01u64 << (i * 8)
    }

    fn check_aad(&mut self) {
        match self.state {
            State::DecInit => self.state = State::DecAad,
            State::EncInit => self.state = State::EncAad,
            State::DecAad | State::EncAad => {}
            State::EncFinal => panic!("Ascon-AEAD128 cannot be reused for encryption"),
            _ => panic!("Ascon-AEAD128 needs to be initialized"),
        }
    }

    fn finish_aad(&mut self, next_state: State) {
        if matches!(self.state, State::DecAad | State::EncAad) {
            debug_assert!(self.buf_pos < RATE);

            self.buf[self.buf_pos] = 0x01;

            let block0 = load_u64_le(&self.buf, 0);
            if self.buf_pos >= 8 {
                self.s0 ^= block0;

                let block1 = load_u64_le(&self.buf, 8);
                self.s1 ^= block1 & (u64::MAX >> (56 - ((self.buf_pos - 8) * 8)));
            } else {
                self.s0 ^= block0 & (u64::MAX >> (56 - (self.buf_pos * 8)));
            }
            self.p8();
        }
        // Domain separation (SP 800-232 §4.1.1 step 2: S ← S ⊕ (0^319 || 1)).
        self.s4 ^= 0x8000000000000000;
        self.buf_pos = 0;
        self.state = next_state;
    }

    fn finish_data(&mut self, next_state: State) {
        // Finalization (SP 800-232 §4.1.1 step 4 / §4.1.2 step 4).
        self.s2 ^= self.k0;
        self.s3 ^= self.k1;
        self.p12();
        self.s3 ^= self.k0;
        self.s4 ^= self.k1;

        self.state = next_state;
    }

    fn check_data(&mut self) -> bool {
        match self.state {
            State::DecInit | State::DecAad => {
                self.finish_aad(State::DecData);
                false
            }
            State::EncInit | State::EncAad => {
                self.finish_aad(State::EncData);
                true
            }
            State::DecData => false,
            State::EncData => true,
            State::EncFinal => panic!("Ascon-AEAD128 cannot be reused for encryption"),
            _ => panic!("Ascon-AEAD128 needs to be initialized"),
        }
    }

    /// Process associated data (AAD) bytes. May be called multiple times, but only before any
    /// plaintext/ciphertext is processed.
    pub fn process_aad_bytes(&mut self, input: &[u8]) {
        if input.is_empty() {
            return;
        }

        self.check_aad();

        let mut input = input;

        if self.buf_pos > 0 {
            let available = RATE - self.buf_pos;
            if input.len() < available {
                self.buf[self.buf_pos..self.buf_pos + input.len()].copy_from_slice(input);
                self.buf_pos += input.len();
                return;
            }

            self.buf[self.buf_pos..RATE].copy_from_slice(&input[..available]);
            input = &input[available..];

            let mut tmp = [0u8; RATE];
            tmp.copy_from_slice(&self.buf[..RATE]);
            self.process_buffer_aad(&tmp);
        }

        while input.len() >= RATE {
            self.process_buffer_aad(&input[..RATE]);
            input = &input[RATE..];
        }

        self.buf[..input.len()].copy_from_slice(input);
        self.buf_pos = input.len();
    }

    fn process_buffer_aad(&mut self, block: &[u8]) {
        debug_assert!(block.len() >= RATE);

        self.s0 ^= load_u64_le(block, 0);
        self.s1 ^= load_u64_le(block, 8);

        self.p8();
    }

    fn process_buffer_encrypt(&mut self, block: &[u8], output: &mut [u8]) {
        debug_assert!(block.len() >= RATE);
        debug_assert!(output.len() >= RATE);

        self.s0 ^= load_u64_le(block, 0);
        store_u64_le(output, 0, self.s0);

        self.s1 ^= load_u64_le(block, 8);
        store_u64_le(output, 8, self.s1);

        self.p8();
    }

    fn process_buffer_decrypt(&mut self, block: &[u8], output: &mut [u8]) {
        debug_assert!(block.len() >= RATE);
        debug_assert!(output.len() >= RATE);

        let t0 = load_u64_le(block, 0);
        store_u64_le(output, 0, self.s0 ^ t0);
        self.s0 = t0;

        let t1 = load_u64_le(block, 8);
        store_u64_le(output, 8, self.s1 ^ t1);
        self.s1 = t1;

        self.p8();
    }

    fn process_final_encrypt_64(input: &[u8], output: &mut [u8], s: &mut u64) {
        debug_assert!((1..8).contains(&input.len()));
        debug_assert!(output.len() >= input.len());
        let mut t = 0u64;
        for (i, &b) in input.iter().enumerate() {
            t |= (b as u64) << (i * 8);
        }
        *s ^= t;
        let s_bytes = s.to_le_bytes();
        output[..input.len()].copy_from_slice(&s_bytes[..input.len()]);
    }

    fn process_final_encrypt(&mut self, input: &[u8], output: &mut [u8]) {
        debug_assert!(input.len() < RATE);

        if input.len() >= 8 {
            self.s0 ^= load_u64_le(input, 0);
            store_u64_le(output, 0, self.s0);

            let input = &input[8..];
            if !input.is_empty() {
                Self::process_final_encrypt_64(input, &mut output[8..], &mut self.s1);
            }

            self.s1 ^= Self::pad(input.len());
        } else {
            if !input.is_empty() {
                Self::process_final_encrypt_64(input, output, &mut self.s0);
            }

            self.s0 ^= Self::pad(input.len());
        }
        self.finish_data(State::EncFinal);
    }

    fn process_final_decrypt_64(input: &[u8], output: &mut [u8], s: &mut u64) {
        debug_assert!((1..8).contains(&input.len()));
        debug_assert!(output.len() >= input.len());
        let mut t = 0u64;
        for (i, &b) in input.iter().enumerate() {
            t |= (b as u64) << (i * 8);
        }
        let res = *s ^ t;
        let res_bytes = res.to_le_bytes();
        output[..input.len()].copy_from_slice(&res_bytes[..input.len()]);
        *s = (*s & (u64::MAX << (input.len() * 8))) ^ t;
    }

    fn process_final_decrypt(&mut self, input: &[u8], output: &mut [u8]) {
        debug_assert!(input.len() < RATE);

        if input.len() >= 8 {
            let t0 = load_u64_le(input, 0);
            store_u64_le(output, 0, self.s0 ^ t0);
            self.s0 = t0;

            let input = &input[8..];
            if !input.is_empty() {
                Self::process_final_decrypt_64(input, &mut output[8..], &mut self.s1);
            }

            self.s1 ^= Self::pad(input.len());
        } else {
            if !input.is_empty() {
                Self::process_final_decrypt_64(input, output, &mut self.s0);
            }

            self.s0 ^= Self::pad(input.len());
        }
        self.finish_data(State::DecFinal);
    }

    /// Process plaintext bytes (encryption update).
    /// Returns the number of output (ciphertext) bytes produced.
    pub fn encrypt_update(&mut self, plaintext: &[u8], output: &mut [u8]) -> usize {
        if self.finished {
            panic!("Ascon-AEAD128 cannot be reused after finish");
        }
        if !self.for_encryption {
            panic!("Not initialized for encryption");
        }
        if !matches!(self.state, State::EncData) {
            self.check_data();
        }

        let mut in_off = 0;
        let mut len = plaintext.len();
        let mut out_off = 0;
        if self.buf_pos > 0 {
            let available = RATE - self.buf_pos;
            if len < available {
                self.buf[self.buf_pos..self.buf_pos + len].copy_from_slice(plaintext);
                self.buf_pos += len;
                return 0;
            }
            self.buf[self.buf_pos..RATE].copy_from_slice(&plaintext[..available]);
            in_off += available;
            len -= available;
            let mut tmp = [0u8; RATE];
            tmp.copy_from_slice(&self.buf[..RATE]);
            self.process_buffer_encrypt(&tmp, &mut output[out_off..out_off + RATE]);
            out_off += RATE;
            self.buf_pos = 0;
        }
        while len >= RATE {
            self.process_buffer_encrypt(
                &plaintext[in_off..in_off + RATE],
                &mut output[out_off..out_off + RATE],
            );
            in_off += RATE;
            len -= RATE;
            out_off += RATE;
        }
        if len > 0 {
            self.buf[0..len].copy_from_slice(&plaintext[in_off..in_off + len]);
            self.buf_pos = len;
        }
        out_off
    }

    /// Finalize encryption and output the last (possibly partial) ciphertext block followed by the
    /// 128-bit tag. Returns the number of bytes written.
    pub fn encrypt_finalize(&mut self, output: &mut [u8]) -> usize {
        if self.finished {
            panic!("Ascon-AEAD128 cannot be reused after finish");
        }
        if !self.for_encryption {
            panic!("Not initialized for encryption");
        }
        if !matches!(self.state, State::EncData) {
            self.check_data();
        }
        let in_len = self.buf_pos;
        let mut tmp = [0u8; RATE];
        tmp.copy_from_slice(&self.buf[..RATE]);
        self.process_final_encrypt(&tmp[..in_len], output);

        let mut tag = [0u8; CRYPTO_ABYTES];
        store_u64_le(&mut tag, 0, self.s3);
        store_u64_le(&mut tag, 8, self.s4);

        output[in_len..in_len + CRYPTO_ABYTES].copy_from_slice(&tag);
        self.mac = Some(tag);
        self.finished = true;
        in_len + CRYPTO_ABYTES
    }

    /// Process ciphertext bytes (decryption update). Returns the number of plaintext bytes produced.
    #[allow(clippy::assertions_on_constants)]
    pub fn decrypt_update(&mut self, ciphertext: &[u8], output: &mut [u8]) -> usize {
        if self.finished {
            panic!("Ascon-AEAD128 cannot be reused after finish");
        }
        if self.for_encryption {
            panic!("Not initialized for decryption");
        }
        if !matches!(self.state, State::DecData) {
            self.check_data();
        }

        let mut len = ciphertext.len();
        let mut out_off = 0;
        let available = BUF_SIZE_DECRYPT - self.buf_pos;
        if len < available {
            self.buf[self.buf_pos..self.buf_pos + len].copy_from_slice(ciphertext);
            self.buf_pos += len;
            return 0;
        }

        debug_assert!(RATE >= CRYPTO_ABYTES);
        if self.buf_pos >= RATE {
            let mut tmp = [0u8; RATE];
            tmp.copy_from_slice(&self.buf[..RATE]);
            self.process_buffer_decrypt(&tmp, &mut output[..RATE]);
            out_off += RATE;

            self.buf_pos -= RATE;
            let (head, tail) = self.buf.split_at_mut(RATE);
            head[..self.buf_pos].copy_from_slice(&tail[..self.buf_pos]);

            let available = BUF_SIZE_DECRYPT - self.buf_pos;
            if len < available {
                self.buf[self.buf_pos..self.buf_pos + len].copy_from_slice(ciphertext);
                self.buf_pos += len;
                return out_off;
            }
        }

        let fill = RATE - self.buf_pos;
        self.buf[self.buf_pos..RATE].copy_from_slice(&ciphertext[..fill]);
        let mut in_off = fill;
        len -= fill;
        let mut tmp = [0u8; RATE];
        tmp.copy_from_slice(&self.buf[..RATE]);
        self.process_buffer_decrypt(&tmp, &mut output[out_off..out_off + RATE]);
        out_off += RATE;

        while len >= BUF_SIZE_DECRYPT {
            self.process_buffer_decrypt(
                &ciphertext[in_off..in_off + RATE],
                &mut output[out_off..out_off + RATE],
            );
            in_off += RATE;
            len -= RATE;
            out_off += RATE;
        }

        self.buf[..len].copy_from_slice(&ciphertext[in_off..in_off + len]);
        self.buf_pos = len;
        out_off
    }

    /// Finalize decryption, verifying the tag.
    /// Returns the number of plaintext bytes produced, or [`AeadError::AuthenticationFailed`] if the
    /// tag does not verify.
    pub fn decrypt_finalize(&mut self, output: &mut [u8]) -> Result<usize, AeadError> {
        if self.finished {
            return Err(AeadError::InvalidState("Ascon-AEAD128 already finalized"));
        }
        if self.for_encryption {
            return Err(AeadError::InvalidState("Not initialized for decryption"));
        }
        if self.buf_pos < CRYPTO_ABYTES {
            return Err(AeadError::InvalidLength("Ascon-AEAD128 ciphertext shorter than tag"));
        }

        let data_len = self.buf_pos - CRYPTO_ABYTES;
        let mut tmp = [0u8; RATE];
        tmp.copy_from_slice(&self.buf[..RATE]);
        self.process_final_decrypt(&tmp[..data_len], output);

        // Recompute the tag in the state and compare against the supplied tag. XORing the supplied
        // tag into the final state words yields zero iff they match; folding both words and testing
        // against zero is branch-free (constant time w.r.t. the tag value).
        self.s3 ^= load_u64_le(&self.buf, data_len);
        self.s4 ^= load_u64_le(&self.buf, data_len + 8);
        if (self.s3 | self.s4) != 0 {
            return Err(AeadError::AuthenticationFailed);
        }
        self.finished = true;
        Ok(data_len)
    }
}

impl Algorithm for AsconAead128 {
    const ALG_NAME: &'static str = "Ascon-AEAD128";
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

impl AeadCipher for AsconAead128 {
    fn process_aad_byte(&mut self, input: u8) {
        self.process_aad_bytes(&[input]);
    }

    fn process_aad_bytes(&mut self, in_bytes: &[u8]) {
        self.process_aad_bytes(in_bytes);
    }

    fn process_byte(&mut self, input: u8, out_bytes: &mut [u8]) -> usize {
        if self.for_encryption {
            self.encrypt_update(&[input], out_bytes)
        } else {
            self.decrypt_update(&[input], out_bytes)
        }
    }

    fn process_bytes(&mut self, in_bytes: &[u8], out_bytes: &mut [u8]) -> usize {
        if self.for_encryption {
            self.encrypt_update(in_bytes, out_bytes)
        } else {
            self.decrypt_update(in_bytes, out_bytes)
        }
    }

    fn do_final(mut self, out_bytes: &mut [u8]) -> Result<usize, AeadError> {
        if self.for_encryption {
            Ok(self.encrypt_finalize(out_bytes))
        } else {
            self.decrypt_finalize(out_bytes)
        }
    }

    fn get_mac(&self) -> [u8; CRYPTO_ABYTES] {
        self.mac.unwrap_or([0u8; CRYPTO_ABYTES])
    }

    fn get_update_output_size(&self, len: usize) -> usize {
        match self.state {
            State::EncFinal | State::DecFinal => 0,
            State::EncInit | State::EncAad | State::EncData => ((self.buf_pos + len) / RATE) * RATE,
            State::DecInit | State::DecAad | State::DecData => {
                let total = self.buf_pos + len;
                if total >= BUF_SIZE_DECRYPT { ((total - CRYPTO_ABYTES) / RATE) * RATE } else { 0 }
            }
        }
    }

    fn get_output_size(&self, len: usize) -> usize {
        match self.state {
            State::EncFinal | State::DecFinal => 0,
            State::EncInit | State::EncAad | State::EncData => self.buf_pos + len + CRYPTO_ABYTES,
            State::DecInit | State::DecAad | State::DecData => {
                (self.buf_pos + len).saturating_sub(CRYPTO_ABYTES)
            }
        }
    }
}

impl Debug for AsconAead128 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "AsconAead128 (key/state masked)")
    }
}

impl Display for AsconAead128 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "AsconAead128 (key/state masked)")
    }
}

// Zeroize the key, nonce, working state, and buffer before returning the memory to the OS.
impl Drop for AsconAead128 {
    fn drop(&mut self) {
        self.k0 = 0;
        self.k1 = 0;
        self.n0 = 0;
        self.n1 = 0;
        self.s0 = 0;
        self.s1 = 0;
        self.s2 = 0;
        self.s3 = 0;
        self.s4 = 0;
        self.buf.fill(0);
        self.mac = None;
    }
}

impl Secret for AsconAead128 {}
