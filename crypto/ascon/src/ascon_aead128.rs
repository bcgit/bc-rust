//! Ascon-AEAD128 authenticated encryption, as specified in NIST SP 800-232 §4.
//!
//! Rate = 128 bits, capacity = 192 bits, 128-bit key/nonce/tag. Initialization and finalization use
//! `Ascon-p[12]`; associated-data and plaintext/ciphertext blocks use `Ascon-p[8]`.

use core::fmt::{self, Debug, Display, Formatter};

use bouncycastle_core::errors::{KeyMaterialError, SuspendableError, SymmetricCipherError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::suspendable_state::{add_lib_ver, check_lib_ver};
use bouncycastle_core::traits::{
    AEADCipher, Algorithm, SecurityStrength, SuspendableKeyed, SymmetricCipher, RNG,
};
use bouncycastle_rng::HashDRBG_SHA512;
use bouncycastle_utils::secret::Secret;

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

impl State {
    // Stable u8 encoding used when suspending/resuming the AEAD state machine.
    fn to_u8(self) -> u8 {
        match self {
            State::EncInit => 0,
            State::EncAad => 1,
            State::EncData => 2,
            State::EncFinal => 3,
            State::DecInit => 4,
            State::DecAad => 5,
            State::DecData => 6,
            State::DecFinal => 7,
        }
    }

    fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => State::EncInit,
            1 => State::EncAad,
            2 => State::EncData,
            3 => State::EncFinal,
            4 => State::DecInit,
            5 => State::DecAad,
            6 => State::DecData,
            7 => State::DecFinal,
            _ => return None,
        })
    }
}

/// An implementation of the Ascon-AEAD128 algorithm (NIST SP 800-232).
///
/// A single instance performs one operation (encryption or decryption) under one (key, nonce) pair.
/// See [`AsconAead128::new`] for the streaming workflow and [`AsconAead128::encrypt`] /
/// [`AsconAead128::decrypt`] for the one-shot APIs.
#[derive(Clone)]
pub struct AsconAead128 {
    // 128-bit secret key (two 64-bit words). It is re-added to the state at finalization, so it must
    // be retained; wrapped in `Secret` for volatile-write zeroization on drop.
    key: Secret<[u64; 2]>,
    // 128-bit nonce (two 64-bit words). Public per the AEAD contract and used only during init.
    nonce: [u64; 2],
    // 320-bit internal state (five 64-bit words). Carries keystream/plaintext-derived material, so
    // it is likewise wrapped in `Secret`.
    s: Secret<[u64; 5]>,
    // Buffer used for processing AAD or (de)ciphertext. Transiently holds plaintext/ciphertext, so
    // it is wrapped in `Secret`. For decryption the buffer size is RATE + CRYPTO_ABYTES = 32 bytes.
    buf: Secret<[u8; BUF_SIZE_DECRYPT]>,
    buf_pos: usize,
    // The computed authentication tag (public output) after encryption finalization.
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
        let mut key_words: Secret<[u64; 2]> = Secret::new();
        key_words[0] = load_u64_le(key, 0);
        key_words[1] = load_u64_le(key, 8);
        let nonce = [load_u64_le(nonce, 0), load_u64_le(nonce, 8)];
        let state = if for_encryption { State::EncInit } else { State::DecInit };
        let mut aead = AsconAead128 {
            key: key_words,
            nonce,
            s: Secret::new(),
            buf: Secret::new(),
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
    /// written, or [`SymmetricCipherError::AEADTagCheckFailed`] if the tag does not verify.
    pub fn decrypt(
        key: &[u8; CRYPTO_KEYBYTES],
        nonce: &[u8; CRYPTO_KEYBYTES],
        ad: Option<&[u8]>,
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        let mut cipher = Self::new(key, nonce, ad, false);
        let n = cipher.decrypt_update(ciphertext, out);
        Ok(n + cipher.decrypt_finalize(&mut out[n..])?)
    }

    // Initialization (SP 800-232 §4.1.1 step 1): S = IV || K || N, then Ascon-p[12], then XOR K into
    // the last 128 bits. No caching, since the key and/or nonce change for every operation.
    fn init_state(&mut self) {
        self.s[0] = ASCON_IV;
        self.s[1] = self.key[0];
        self.s[2] = self.key[1];
        self.s[3] = self.nonce[0];
        self.s[4] = self.nonce[1];
        self.p12();
        self.s[3] ^= self.key[0];
        self.s[4] ^= self.key[1];
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

            let block0 = load_u64_le(&self.buf[..], 0);
            if self.buf_pos >= 8 {
                self.s[0] ^= block0;

                let block1 = load_u64_le(&self.buf[..], 8);
                self.s[1] ^= block1 & (u64::MAX >> (56 - ((self.buf_pos - 8) * 8)));
            } else {
                self.s[0] ^= block0 & (u64::MAX >> (56 - (self.buf_pos * 8)));
            }
            self.p8();
        }
        // Domain separation (SP 800-232 §4.1.1 step 2: S ← S ⊕ (0^319 || 1)).
        self.s[4] ^= 0x8000000000000000;
        self.buf_pos = 0;
        self.state = next_state;
    }

    fn finish_data(&mut self, next_state: State) {
        // Finalization (SP 800-232 §4.1.1 step 4 / §4.1.2 step 4).
        self.s[2] ^= self.key[0];
        self.s[3] ^= self.key[1];
        self.p12();
        self.s[3] ^= self.key[0];
        self.s[4] ^= self.key[1];

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

        self.s[0] ^= load_u64_le(block, 0);
        self.s[1] ^= load_u64_le(block, 8);

        self.p8();
    }

    fn process_buffer_encrypt(&mut self, block: &[u8], output: &mut [u8]) {
        debug_assert!(block.len() >= RATE);
        debug_assert!(output.len() >= RATE);

        self.s[0] ^= load_u64_le(block, 0);
        store_u64_le(output, 0, self.s[0]);

        self.s[1] ^= load_u64_le(block, 8);
        store_u64_le(output, 8, self.s[1]);

        self.p8();
    }

    fn process_buffer_decrypt(&mut self, block: &[u8], output: &mut [u8]) {
        debug_assert!(block.len() >= RATE);
        debug_assert!(output.len() >= RATE);

        let t0 = load_u64_le(block, 0);
        store_u64_le(output, 0, self.s[0] ^ t0);
        self.s[0] = t0;

        let t1 = load_u64_le(block, 8);
        store_u64_le(output, 8, self.s[1] ^ t1);
        self.s[1] = t1;

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
            self.s[0] ^= load_u64_le(input, 0);
            store_u64_le(output, 0, self.s[0]);

            let input = &input[8..];
            if !input.is_empty() {
                Self::process_final_encrypt_64(input, &mut output[8..], &mut self.s[1]);
            }

            self.s[1] ^= Self::pad(input.len());
        } else {
            if !input.is_empty() {
                Self::process_final_encrypt_64(input, output, &mut self.s[0]);
            }

            self.s[0] ^= Self::pad(input.len());
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
            store_u64_le(output, 0, self.s[0] ^ t0);
            self.s[0] = t0;

            let input = &input[8..];
            if !input.is_empty() {
                Self::process_final_decrypt_64(input, &mut output[8..], &mut self.s[1]);
            }

            self.s[1] ^= Self::pad(input.len());
        } else {
            if !input.is_empty() {
                Self::process_final_decrypt_64(input, output, &mut self.s[0]);
            }

            self.s[0] ^= Self::pad(input.len());
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
        store_u64_le(&mut tag, 0, self.s[3]);
        store_u64_le(&mut tag, 8, self.s[4]);

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
            let (head, tail) = self.buf[..].split_at_mut(RATE);
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
    /// Returns the number of plaintext bytes produced, or
    /// [`SymmetricCipherError::AEADTagCheckFailed`] if the tag does not verify.
    pub fn decrypt_finalize(&mut self, output: &mut [u8]) -> Result<usize, SymmetricCipherError> {
        if self.finished {
            return Err(SymmetricCipherError::StateError("Ascon-AEAD128 already finalized"));
        }
        if self.for_encryption {
            return Err(SymmetricCipherError::StateError("Not initialized for decryption"));
        }
        if self.buf_pos < CRYPTO_ABYTES {
            return Err(SymmetricCipherError::GenericError(
                "Ascon-AEAD128 ciphertext shorter than tag",
            ));
        }

        let data_len = self.buf_pos - CRYPTO_ABYTES;
        let mut tmp = [0u8; RATE];
        tmp.copy_from_slice(&self.buf[..RATE]);
        self.process_final_decrypt(&tmp[..data_len], output);

        // Recompute the tag in the state and compare against the supplied tag. XORing the supplied
        // tag into the final state words yields zero iff they match; folding both words and testing
        // against zero is branch-free (constant time w.r.t. the tag value).
        self.s[3] ^= load_u64_le(&self.buf[..], data_len);
        self.s[4] ^= load_u64_le(&self.buf[..], data_len + 8);
        if (self.s[3] | self.s[4]) != 0 {
            return Err(SymmetricCipherError::AEADTagCheckFailed);
        }
        self.finished = true;
        Ok(data_len)
    }
}

impl Algorithm for AsconAead128 {
    const ALG_NAME: &'static str = "Ascon-AEAD128";
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

// Private helpers shared by the `SymmetricCipher` / `AEADCipher` trait impls.
impl AsconAead128 {
    /// Validate a [`KeyMaterial`] for use with Ascon-AEAD128 and copy out its 16 key bytes.
    /// The key must be tagged as a [`KeyType::SymmetricCipherKey`] and carry at least the
    /// algorithm's 128-bit security strength (SP 800-232 R1/R2).
    fn checked_key(
        key: &KeyMaterial<CRYPTO_KEYBYTES>,
    ) -> Result<[u8; CRYPTO_KEYBYTES], SymmetricCipherError> {
        if key.key_type() != KeyType::SymmetricCipherKey {
            return Err(KeyMaterialError::InvalidKeyType(
                "Ascon-AEAD128 requires a SymmetricCipherKey",
            )
            .into());
        }
        if key.security_strength() < SecurityStrength::_128bit {
            return Err(KeyMaterialError::SecurityStrength(
                "Ascon-AEAD128 requires a key with at least 128-bit security strength",
            )
            .into());
        }
        let bytes = key.ref_to_bytes();
        if bytes.len() != CRYPTO_KEYBYTES {
            return Err(KeyMaterialError::InvalidLength.into());
        }
        let mut k = [0u8; CRYPTO_KEYBYTES];
        k.copy_from_slice(bytes);
        Ok(k)
    }

    /// Draw a fresh, unique 128-bit nonce from the library's default OS-seeded DRBG.
    ///
    /// The one-shot APIs of main's cipher framework generate the init data / nonce internally, so
    /// Ascon's per-encryption nonce-uniqueness requirement (SP 800-232 R3) is satisfied by sourcing
    /// each nonce from a CSPRNG. Callers who need deterministic, caller-supplied nonces should use
    /// the inherent streaming API ([`AsconAead128::new`]).
    fn fresh_nonce() -> Result<[u8; CRYPTO_KEYBYTES], SymmetricCipherError> {
        let mut rng = HashDRBG_SHA512::new_from_os();
        let mut nonce = [0u8; CRYPTO_KEYBYTES];
        rng.next_bytes_out(&mut nonce)?;
        Ok(nonce)
    }
}

// Ascon-AEAD128 as a `SymmetricCipher`: the "basic" (non-AEAD) view. The init data is the 128-bit
// nonce, and the ciphertext produced by these APIs is `Ascon ciphertext || 16-byte tag` (empty AAD).
impl SymmetricCipher<CRYPTO_KEYBYTES, CRYPTO_KEYBYTES> for AsconAead128 {
    #[cfg(feature = "std")]
    fn encrypt(
        key: &KeyMaterial<CRYPTO_KEYBYTES>,
        plaintext: &[u8],
    ) -> Result<([u8; CRYPTO_KEYBYTES], Vec<u8>), SymmetricCipherError> {
        let mut ciphertext = vec![0u8; plaintext.len() + CRYPTO_ABYTES];
        let (nonce, written) = Self::encrypt_out(key, plaintext, &mut ciphertext)?;
        ciphertext.truncate(written);
        Ok((nonce, ciphertext))
    }

    fn encrypt_out(
        key: &KeyMaterial<CRYPTO_KEYBYTES>,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<([u8; CRYPTO_KEYBYTES], usize), SymmetricCipherError> {
        let k = Self::checked_key(key)?;
        let needed = plaintext.len() + CRYPTO_ABYTES;
        if ciphertext.len() < needed {
            return Err(SymmetricCipherError::IncorrectOutputBufferLength(
                "Ascon-AEAD128 ciphertext buffer too small (need plaintext length + 16)",
                needed,
            ));
        }
        let nonce = Self::fresh_nonce()?;
        // No associated data for the plain SymmetricCipher view; the tag is appended to `ciphertext`.
        let mut cipher = Self::new(&k, &nonce, None, true);
        let n = cipher.encrypt_update(plaintext, ciphertext);
        let written = cipher.encrypt_finalize(&mut ciphertext[n..]);
        Ok((nonce, n + written))
    }

    #[cfg(feature = "std")]
    fn decrypt(
        key: &KeyMaterial<CRYPTO_KEYBYTES>,
        init_data: [u8; CRYPTO_KEYBYTES],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SymmetricCipherError> {
        if ciphertext.len() < CRYPTO_ABYTES {
            return Err(SymmetricCipherError::GenericError(
                "Ascon-AEAD128 ciphertext shorter than tag",
            ));
        }
        let mut plaintext = vec![0u8; ciphertext.len() - CRYPTO_ABYTES];
        let written = Self::decrypt_out(key, init_data, ciphertext, &mut plaintext)?;
        plaintext.truncate(written);
        Ok(plaintext)
    }

    fn decrypt_out(
        key: &KeyMaterial<CRYPTO_KEYBYTES>,
        init_data: [u8; CRYPTO_KEYBYTES],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        let k = Self::checked_key(key)?;
        if ciphertext.len() < CRYPTO_ABYTES {
            return Err(SymmetricCipherError::GenericError(
                "Ascon-AEAD128 ciphertext shorter than tag",
            ));
        }
        if plaintext.len() < ciphertext.len() - CRYPTO_ABYTES {
            return Err(SymmetricCipherError::IncorrectOutputBufferLength(
                "Ascon-AEAD128 plaintext buffer too small",
                ciphertext.len() - CRYPTO_ABYTES,
            ));
        }
        // `ciphertext` is `Ascon ciphertext || 16-byte tag`; the streaming API splits it internally.
        let mut cipher = Self::new(&k, &init_data, None, false);
        let n = cipher.decrypt_update(ciphertext, plaintext);
        let m = cipher.decrypt_finalize(&mut plaintext[n..])?;
        Ok(n + m)
    }
}

// Ascon-AEAD128 as an `AEADCipher`: the full AEAD view with associated data and a separate tag.
impl AEADCipher<CRYPTO_KEYBYTES, CRYPTO_KEYBYTES, CRYPTO_ABYTES> for AsconAead128 {
    #[cfg(feature = "std")]
    fn aead_encrypt(
        key: &KeyMaterial<CRYPTO_KEYBYTES>,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<([u8; CRYPTO_KEYBYTES], Vec<u8>, [u8; CRYPTO_ABYTES]), SymmetricCipherError> {
        let mut ciphertext = vec![0u8; plaintext.len()];
        let (nonce, written, tag) = Self::aead_encrypt_out(key, aad, plaintext, &mut ciphertext)?;
        ciphertext.truncate(written);
        Ok((nonce, ciphertext, tag))
    }

    fn aead_encrypt_out(
        key: &KeyMaterial<CRYPTO_KEYBYTES>,
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<([u8; CRYPTO_KEYBYTES], usize, [u8; CRYPTO_ABYTES]), SymmetricCipherError> {
        let k = Self::checked_key(key)?;
        if ciphertext.len() < plaintext.len() {
            return Err(SymmetricCipherError::IncorrectOutputBufferLength(
                "Ascon-AEAD128 ciphertext buffer too small",
                plaintext.len(),
            ));
        }
        let nonce = Self::fresh_nonce()?;
        let aad_opt = if aad.is_empty() { None } else { Some(aad) };
        let mut cipher = Self::new(&k, &nonce, aad_opt, true);
        // Encrypt the full rate-blocks into `ciphertext`; finalize emits the last partial block
        // (< 16 bytes) followed by the 16-byte tag, which we then split apart.
        let n = cipher.encrypt_update(plaintext, ciphertext);
        let mut tail = [0u8; BUF_SIZE_DECRYPT]; // up to 15 partial ciphertext bytes + 16 tag bytes
        let written = cipher.encrypt_finalize(&mut tail);
        let partial = written - CRYPTO_ABYTES;
        ciphertext[n..n + partial].copy_from_slice(&tail[..partial]);
        let mut tag = [0u8; CRYPTO_ABYTES];
        tag.copy_from_slice(&tail[partial..partial + CRYPTO_ABYTES]);
        Ok((nonce, n + partial, tag))
    }

    fn do_aead_encrypt_final(mut self) -> Result<[u8; CRYPTO_ABYTES], SymmetricCipherError> {
        let mut tail = [0u8; BUF_SIZE_DECRYPT];
        let written = self.encrypt_finalize(&mut tail);
        let partial = written - CRYPTO_ABYTES;
        let mut tag = [0u8; CRYPTO_ABYTES];
        tag.copy_from_slice(&tail[partial..partial + CRYPTO_ABYTES]);
        Ok(tag)
    }

    #[cfg(feature = "std")]
    fn aead_decrypt(
        key: &KeyMaterial<CRYPTO_KEYBYTES>,
        nonce: &[u8; CRYPTO_KEYBYTES],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; CRYPTO_ABYTES],
    ) -> Result<Vec<u8>, SymmetricCipherError> {
        let mut plaintext = vec![0u8; ciphertext.len()];
        let written = Self::aead_decrypt_out(key, nonce, aad, ciphertext, tag, &mut plaintext)?;
        plaintext.truncate(written);
        Ok(plaintext)
    }

    fn aead_decrypt_out(
        key: &KeyMaterial<CRYPTO_KEYBYTES>,
        nonce: &[u8; CRYPTO_KEYBYTES],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; CRYPTO_ABYTES],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        let k = Self::checked_key(key)?;
        if plaintext.len() < ciphertext.len() {
            return Err(SymmetricCipherError::IncorrectOutputBufferLength(
                "Ascon-AEAD128 plaintext buffer too small",
                ciphertext.len(),
            ));
        }
        let aad_opt = if aad.is_empty() { None } else { Some(aad) };
        let mut cipher = Self::new(&k, nonce, aad_opt, false);
        // The streaming decryptor treats the trailing 16 bytes of its input as the tag, so feed the
        // ciphertext followed by the separate `tag`: chunk boundaries do not affect the result.
        let n = cipher.decrypt_update(ciphertext, plaintext);
        let n2 = cipher.decrypt_update(tag, &mut plaintext[n..]);
        let m = cipher.decrypt_finalize(&mut plaintext[n + n2..])?;
        Ok(n + n2 + m)
    }

    fn do_aead_decrypt_final(mut self, tag: &[u8; CRYPTO_ABYTES]) -> Result<(), SymmetricCipherError> {
        let mut scratch = [0u8; BUF_SIZE_DECRYPT];
        let _ = self.decrypt_update(tag, &mut scratch);
        self.decrypt_finalize(&mut scratch)?;
        Ok(())
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

/// Length in bytes of the serialized state of [`AsconAead128`].
/// Layout: 3-byte library version || 1-byte state tag || 40-byte permutation state (5 × u64 LE)
/// || 16-byte nonce (2 × u64 LE) || 32-byte working buffer || 1-byte buffer position
/// || 1-byte tag-present flag || 16-byte tag || 1-byte call-state || 1-byte direction
/// || 1-byte finished flag. The secret key is **not** serialized; it is re-supplied to
/// [`SuspendableKeyed::from_suspended`].
pub const SUSPENDED_ASCON_AEAD128_STATE_LEN: usize = 113;

const AEAD128_STATE_TAG: u8 = 0x04;

impl SuspendableKeyed<SUSPENDED_ASCON_AEAD128_STATE_LEN> for AsconAead128 {
    // The 128-bit key must be re-supplied when resuming; it is never part of the serialized state.
    type Key = [u8; CRYPTO_KEYBYTES];

    fn suspend(self) -> [u8; SUSPENDED_ASCON_AEAD128_STATE_LEN] {
        let mut out_to_return = [0u8; SUSPENDED_ASCON_AEAD128_STATE_LEN];
        let out: &mut [u8; SUSPENDED_ASCON_AEAD128_STATE_LEN - 3] =
            add_lib_ver(&mut out_to_return).try_into().unwrap();

        out[0] = AEAD128_STATE_TAG;
        for i in 0..5 {
            out[1 + i * 8..1 + i * 8 + 8].copy_from_slice(&self.s[i].to_le_bytes());
        }
        out[41..49].copy_from_slice(&self.nonce[0].to_le_bytes());
        out[49..57].copy_from_slice(&self.nonce[1].to_le_bytes());
        out[57..89].copy_from_slice(&*self.buf);
        debug_assert!(self.buf_pos <= BUF_SIZE_DECRYPT);
        out[89] = self.buf_pos as u8;
        match self.mac {
            Some(tag) => {
                out[90] = 1;
                out[91..107].copy_from_slice(&tag);
            }
            None => out[90] = 0,
        }
        out[107] = self.state.to_u8();
        out[108] = self.for_encryption as u8;
        out[109] = self.finished as u8;

        out_to_return
    }

    fn from_suspended(
        serialized_state: [u8; SUSPENDED_ASCON_AEAD128_STATE_LEN],
        key: &Self::Key,
    ) -> Result<Self, SuspendableError> {
        let input: &[u8; SUSPENDED_ASCON_AEAD128_STATE_LEN - 3] =
            check_lib_ver(&serialized_state, None)?.try_into().unwrap();

        if input[0] != AEAD128_STATE_TAG {
            return Err(SuspendableError::InvalidData);
        }
        let mut s = Secret::<[u64; 5]>::new();
        for i in 0..5 {
            s[i] = u64::from_le_bytes(input[1 + i * 8..1 + i * 8 + 8].try_into().unwrap());
        }
        let nonce = [
            u64::from_le_bytes(input[41..49].try_into().unwrap()),
            u64::from_le_bytes(input[49..57].try_into().unwrap()),
        ];
        let mut buf = Secret::<[u8; BUF_SIZE_DECRYPT]>::new();
        buf.copy_from_slice(&input[57..89]);
        let buf_pos = input[89] as usize;
        if buf_pos > BUF_SIZE_DECRYPT {
            return Err(SuspendableError::InvalidData);
        }
        let mac = match input[90] {
            0 => None,
            1 => {
                let mut tag = [0u8; CRYPTO_ABYTES];
                tag.copy_from_slice(&input[91..107]);
                Some(tag)
            }
            _ => return Err(SuspendableError::InvalidData),
        };
        let state = State::from_u8(input[107]).ok_or(SuspendableError::InvalidData)?;
        let for_encryption = match input[108] {
            0 => false,
            1 => true,
            _ => return Err(SuspendableError::InvalidData),
        };
        let finished = match input[109] {
            0 => false,
            1 => true,
            _ => return Err(SuspendableError::InvalidData),
        };

        // The key is never serialized; rebuild the key words from the re-supplied key.
        let mut key_words = Secret::<[u64; 2]>::new();
        key_words[0] = load_u64_le(key, 0);
        key_words[1] = load_u64_le(key, 8);

        Ok(AsconAead128 {
            key: key_words,
            nonce,
            s,
            buf,
            buf_pos,
            mac,
            state,
            for_encryption,
            finished,
        })
    }
}

