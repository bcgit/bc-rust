//! Ascon-AEAD128 — authenticated encryption with associated data, from
//! NIST SP 800-232.
//!
//! Ascon-AEAD128 takes a 128-bit key, a 128-bit nonce, optional associated
//! data, and produces a ciphertext concatenated with a 128-bit authentication
//! tag. Decryption recovers the plaintext only if the tag verifies.
//!
//! # Single-use rule
//! As required by NIST SP 800-232 §7, an Ascon-AEAD128 encryption context
//! MUST NOT be reused with the same (key, nonce) pair to encrypt more than
//! one message. The [`AsconAead128`] type enforces this at the state-machine
//! level: after [`AsconAead128::encrypt_finalize`] the context parks in
//! `EncFinal` and a subsequent encryption update / finalize will return
//! [`AsconAeadError::InvalidState`].
//!
//! # Errors
//! All length / state / authentication failures are surfaced as
//! [`AsconAeadError`] from the inherent API. The cross-crate
//! [`bouncycastle_core_interface::traits::AeadCipher`] trait does not carry
//! a `Result` on `do_final`, so a failed tag verification under the trait
//! API panics — applications doing decryption SHOULD prefer the inherent
//! [`AsconAead128::decrypt_finalize`] over the trait method.
//!
//! # Examples
//!
//! Encrypt and decrypt with the inherent API:
//!
//! ```
//! use bouncycastle_ascon::AsconAead128;
//!
//! let key   = [0u8; 16];
//! let nonce = [1u8; 16];
//! let pt    = b"hello, ascon";
//!
//! let mut enc = AsconAead128::new(&key, &nonce, None, true);
//! let mut ct = vec![0u8; pt.len() + 16];
//! let n = enc.encrypt_update(pt, &mut ct);
//! let m = enc.encrypt_finalize(&mut ct[n..]).unwrap();
//! ct.truncate(n + m);
//!
//! let mut dec = AsconAead128::new(&key, &nonce, None, false);
//! let mut plain = vec![0u8; pt.len()];
//! let n = dec.decrypt_update(&ct, &mut plain);
//! let m = dec.decrypt_finalize(&mut plain[n..]).unwrap();
//! plain.truncate(n + m);
//! assert_eq!(plain.as_slice(), pt);
//! ```

use alloc::vec::Vec;
use bouncycastle_core_interface::traits::{AeadCipher, Algorithm, SecurityStrength};

use crate::state::AsconState;

/// Key length in bytes (128 bits).
pub const KEY_LEN: usize = 16;
/// Nonce length in bytes (128 bits).
pub const NONCE_LEN: usize = 16;
/// Authentication tag length in bytes (128 bits).
pub const TAG_LEN: usize = 16;
/// Algorithm name.
pub const ASCON_AEAD128_NAME: &str = "Ascon-AEAD128";
/// Rate of the AEAD sponge, in bytes (128 bits).
const RATE: usize = 16;
/// Decryption buffer must hold one rate-sized block plus the trailing
/// tag-or-ciphertext bytes that cannot be classified until finalization.
const DECRYPT_BUF_LEN: usize = RATE + TAG_LEN;

/// The Ascon-AEAD128 initialization vector word, per NIST SP 800-232 §7.2.
const ASCON_AEAD_IV: u64 = 0x0000_1000_808C_0001;

// Static invariant: the decrypt buffer arithmetic in `decrypt_update` assumes
// the rate is at least as large as the tag.
const _: () = assert!(RATE >= TAG_LEN, "Ascon-AEAD128 requires RATE >= TAG_LEN");

/// Errors raised by the Ascon-AEAD128 inherent API.
#[derive(Debug, PartialEq, Eq)]
pub enum AsconAeadError {
    /// Output buffer too small for the requested operation.
    InvalidLength(&'static str),
    /// Operation not valid in the current state (e.g. reusing an encryption
    /// context after finalize, or finalising before the trailing tag bytes
    /// have been provided to a decryption context).
    InvalidState(&'static str),
    /// Authentication tag verification failed during decryption. The
    /// recovered plaintext (if any) MUST NOT be released to the caller.
    VerificationFailed,
}

/// State-machine positions for the AEAD context.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum AeadState {
    Uninitialized,
    EncInit,
    EncAad,
    EncData,
    EncFinal,
    DecInit,
    DecAad,
    DecData,
    DecFinal,
}

/// Snapshot of the AEAD context taken at the end of [`AsconAead128::init`]:
/// state lanes after key/nonce setup and AAD absorption, plus the buffer
/// state (which may hold a partial AAD block) and the phase we were in.
///
/// Used by [`AsconAead128::reset`] to return to the post-init state
/// without re-running the (potentially expensive) AAD absorption. This is
/// the same trick [`crate::ascon_cxof128::AsconCXof128`] uses for
/// post-customization state caching.
///
/// Replaces a `Vec<u8>` of AAD bytes — the snapshot is fixed-size
/// (~80 bytes regardless of AAD length) so the AEAD context holds no
/// heap allocations, making it usable in a `no_std + no_alloc` context.
#[derive(Clone)]
struct InitSnapshot {
    state: AsconState,
    buf: [u8; DECRYPT_BUF_LEN],
    buf_pos: usize,
    phase: AeadState,
}

impl Drop for InitSnapshot {
    fn drop(&mut self) {
        // AsconState already zeroizes itself; we wipe the buffer in case
        // it held a partial-block of AAD (which may be sensitive in some
        // protocols, e.g. context strings binding session metadata).
        self.buf.fill(0);
        self.buf_pos = 0;
    }
}

/// An Ascon-AEAD128 authenticated-encryption context.
///
/// Keys, nonces and the sponge state lanes are sensitive: the inner
/// [`AsconState`] zeroizes on drop and this struct's own `Drop` impl
/// zeroizes the cached key / nonce words, the working buffer, and the
/// init snapshot.
pub struct AsconAead128 {
    k0: u64,
    k1: u64,
    n0: u64,
    n1: u64,
    state: AsconState,
    buf: [u8; DECRYPT_BUF_LEN],
    buf_pos: usize,
    /// Snapshot of the state taken at the end of [`AsconAead128::init`].
    /// `None` while the context is still in [`AeadState::Uninitialized`].
    init_snapshot: Option<InitSnapshot>,
    mac: Option<[u8; TAG_LEN]>,
    phase: AeadState,
    for_encryption: bool,
    finished: bool,
}

impl AsconAead128 {
    /// Create an uninitialized AEAD context, intended to be configured via
    /// a subsequent call to [`AsconAead128::init`].
    pub fn new_uninit() -> Self {
        Self {
            k0: 0,
            k1: 0,
            n0: 0,
            n1: 0,
            state: AsconState::zero(),
            buf: [0u8; DECRYPT_BUF_LEN],
            buf_pos: 0,
            init_snapshot: None,
            mac: None,
            phase: AeadState::Uninitialized,
            for_encryption: false,
            finished: false,
        }
    }

    /// Create a new AEAD context initialised with the given key, nonce, and
    /// optional associated data.
    ///
    /// Key and nonce sizes are enforced at the type level via fixed-size
    /// array references — supplying a wrong-sized buffer is a compile
    /// error.
    pub fn new(
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        ad: Option<&[u8]>,
        for_encryption: bool,
    ) -> Self {
        let mut aead = Self::new_uninit();
        aead.init(key, nonce, ad, for_encryption);
        aead
    }

    /// (Re-)initialise this AEAD context. Equivalent to dropping and
    /// reconstructing via [`AsconAead128::new`], but reuses the existing
    /// allocation.
    ///
    /// This is an inherent method, not on the [`AeadCipher`] trait: AEAD
    /// constructions vary in how they want to receive a key (e.g.
    /// fixed-length array reference for compile-time length checking) and a
    /// generic trait surface would either lose type safety or invite misuse.
    pub fn init(
        &mut self,
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        ad: Option<&[u8]>,
        for_encryption: bool,
    ) {
        self.k0 = u64::from_le_bytes(key[0..8].try_into().unwrap());
        self.k1 = u64::from_le_bytes(key[8..16].try_into().unwrap());
        self.n0 = u64::from_le_bytes(nonce[0..8].try_into().unwrap());
        self.n1 = u64::from_le_bytes(nonce[8..16].try_into().unwrap());
        self.for_encryption = for_encryption;
        self.phase = if for_encryption { AeadState::EncInit } else { AeadState::DecInit };
        self.buf = [0u8; DECRYPT_BUF_LEN];
        self.buf_pos = 0;
        self.mac = None;
        self.finished = false;
        // Clear any previous snapshot before we build a fresh one.
        self.init_snapshot = None;

        self.init_state();
        if let Some(ad_bytes) = ad {
            self.process_aad(ad_bytes).expect("freshly initialised AEAD context");
        }

        // Snapshot the post-init state so reset() can restore it without
        // re-running init_state + AAD absorption.
        self.init_snapshot = Some(InitSnapshot {
            state: self.state.clone(),
            buf: self.buf,
            buf_pos: self.buf_pos,
            phase: self.phase,
        });
    }

    /// Absorb additional associated-data bytes. Must be called before any
    /// plaintext / ciphertext is processed.
    ///
    /// # Errors
    /// Returns [`AsconAeadError::InvalidState`] if called after plaintext /
    /// ciphertext processing has begun, or on an uninitialised context.
    pub fn process_aad(&mut self, input: &[u8]) -> Result<(), AsconAeadError> {
        if input.is_empty() {
            return Ok(());
        }
        self.check_aad_state()?;
        self.process_aad_bytes_inner(input);
        Ok(())
    }

    /// Encrypt-update: process plaintext, writing ciphertext into `output`.
    /// Returns the number of ciphertext bytes written.
    pub fn encrypt_update(&mut self, plaintext: &[u8], output: &mut [u8]) -> usize {
        self.try_encrypt_update(plaintext, output).expect("encrypt_update")
    }

    /// Fallible variant of [`AsconAead128::encrypt_update`].
    pub fn try_encrypt_update(
        &mut self,
        plaintext: &[u8],
        output: &mut [u8],
    ) -> Result<usize, AsconAeadError> {
        if self.finished {
            return Err(AsconAeadError::InvalidState(
                "Ascon-AEAD128 context already finalised",
            ));
        }
        if !self.for_encryption {
            return Err(AsconAeadError::InvalidState(
                "Ascon-AEAD128 context is not initialised for encryption",
            ));
        }
        if !matches!(self.phase, AeadState::EncData) {
            self.advance_to_data_phase()?;
        }

        let expected_out = ((self.buf_pos + plaintext.len()) / RATE) * RATE;
        if output.len() < expected_out {
            return Err(AsconAeadError::InvalidLength(
                "Ascon-AEAD128: encrypt_update output buffer too small",
            ));
        }

        let mut in_off = 0;
        let mut len = plaintext.len();
        let mut out_off = 0;

        if self.buf_pos > 0 {
            let available = RATE - self.buf_pos;
            if len < available {
                self.buf[self.buf_pos..self.buf_pos + len].copy_from_slice(plaintext);
                self.buf_pos += len;
                return Ok(0);
            }
            self.buf[self.buf_pos..RATE].copy_from_slice(&plaintext[..available]);
            in_off += available;
            len -= available;
            let mut block = [0u8; RATE];
            block.copy_from_slice(&self.buf[..RATE]);
            self.process_buffer_encrypt(&block, &mut output[out_off..out_off + RATE]);
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
            self.buf[..len].copy_from_slice(&plaintext[in_off..in_off + len]);
            self.buf_pos = len;
        }
        Ok(out_off)
    }

    /// Finalize encryption: emit the final (possibly partial) ciphertext
    /// block followed by the 16-byte authentication tag. Returns the total
    /// number of bytes written.
    pub fn encrypt_finalize(&mut self, output: &mut [u8]) -> Result<usize, AsconAeadError> {
        if self.finished {
            return Err(AsconAeadError::InvalidState(
                "Ascon-AEAD128 context already finalised",
            ));
        }
        if !self.for_encryption {
            return Err(AsconAeadError::InvalidState(
                "Ascon-AEAD128 context is not initialised for encryption",
            ));
        }
        if !matches!(self.phase, AeadState::EncData) {
            self.advance_to_data_phase()?;
        }
        let in_len = self.buf_pos;
        let required = in_len + TAG_LEN;
        if output.len() < required {
            return Err(AsconAeadError::InvalidLength(
                "Ascon-AEAD128: encrypt_finalize output buffer too small for tail+tag",
            ));
        }

        let mut block = [0u8; RATE];
        block.copy_from_slice(&self.buf[..RATE]);
        self.process_final_encrypt(&block[..in_len], output);

        let mut tag = [0u8; TAG_LEN];
        tag[0..8].copy_from_slice(&self.state.s3.to_le_bytes());
        tag[8..16].copy_from_slice(&self.state.s4.to_le_bytes());
        output[in_len..in_len + TAG_LEN].copy_from_slice(&tag);
        self.mac = Some(tag);
        self.finished = true;
        Ok(required)
    }

    /// Decrypt-update: process ciphertext, writing plaintext into `output`.
    /// Returns the number of plaintext bytes written.
    pub fn decrypt_update(&mut self, ciphertext: &[u8], output: &mut [u8]) -> usize {
        self.try_decrypt_update(ciphertext, output).expect("decrypt_update")
    }

    /// Fallible variant of [`AsconAead128::decrypt_update`].
    pub fn try_decrypt_update(
        &mut self,
        ciphertext: &[u8],
        output: &mut [u8],
    ) -> Result<usize, AsconAeadError> {
        if self.finished {
            return Err(AsconAeadError::InvalidState(
                "Ascon-AEAD128 context already finalised",
            ));
        }
        if self.for_encryption {
            return Err(AsconAeadError::InvalidState(
                "Ascon-AEAD128 context is not initialised for decryption",
            ));
        }
        if !matches!(self.phase, AeadState::DecData) {
            self.advance_to_data_phase()?;
        }

        let mut len = ciphertext.len();
        let mut out_off = 0;
        let available = DECRYPT_BUF_LEN - self.buf_pos;
        if len < available {
            self.buf[self.buf_pos..self.buf_pos + len].copy_from_slice(ciphertext);
            self.buf_pos += len;
            return Ok(0);
        }

        if self.buf_pos >= RATE {
            if output.len() < RATE {
                return Err(AsconAeadError::InvalidLength(
                    "Ascon-AEAD128: decrypt_update output buffer too small",
                ));
            }
            let mut block = [0u8; RATE];
            block.copy_from_slice(&self.buf[..RATE]);
            self.process_buffer_decrypt(&block, &mut output[..RATE]);
            out_off += RATE;

            self.buf_pos -= RATE;
            let (head, tail) = self.buf.split_at_mut(RATE);
            head[..self.buf_pos].copy_from_slice(&tail[..self.buf_pos]);

            let available = DECRYPT_BUF_LEN - self.buf_pos;
            if len < available {
                self.buf[self.buf_pos..self.buf_pos + len].copy_from_slice(ciphertext);
                self.buf_pos += len;
                return Ok(out_off);
            }
        }

        let fill = RATE - self.buf_pos;
        self.buf[self.buf_pos..RATE].copy_from_slice(&ciphertext[..fill]);
        let mut in_off = fill;
        len -= fill;
        if output.len() < out_off + RATE {
            return Err(AsconAeadError::InvalidLength(
                "Ascon-AEAD128: decrypt_update output buffer too small",
            ));
        }
        let mut block = [0u8; RATE];
        block.copy_from_slice(&self.buf[..RATE]);
        self.process_buffer_decrypt(&block, &mut output[out_off..out_off + RATE]);
        out_off += RATE;

        while len >= DECRYPT_BUF_LEN {
            if output.len() < out_off + RATE {
                return Err(AsconAeadError::InvalidLength(
                    "Ascon-AEAD128: decrypt_update output buffer too small",
                ));
            }
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
        Ok(out_off)
    }

    /// Finalize decryption: emit the final (possibly partial) plaintext
    /// block and verify the authentication tag.
    ///
    /// # Errors
    /// Returns [`AsconAeadError::VerificationFailed`] if the tag does not
    /// match; in that case the bytes that would have been written to the
    /// finalize segment of `output` are zeroized before returning. Plaintext
    /// already emitted by earlier `decrypt_update` calls is *not* zeroized
    /// (it lives in caller memory) and MUST be discarded by the caller on
    /// auth failure.
    pub fn decrypt_finalize(&mut self, output: &mut [u8]) -> Result<usize, AsconAeadError> {
        if self.finished {
            return Err(AsconAeadError::InvalidState(
                "Ascon-AEAD128 context already finalised",
            ));
        }
        if self.for_encryption {
            return Err(AsconAeadError::InvalidState(
                "Ascon-AEAD128 context is not initialised for decryption",
            ));
        }
        if self.buf_pos < TAG_LEN {
            return Err(AsconAeadError::InvalidState(
                "Ascon-AEAD128: ciphertext truncated below tag length",
            ));
        }
        let data_len = self.buf_pos - TAG_LEN;
        if output.len() < data_len {
            return Err(AsconAeadError::InvalidLength(
                "Ascon-AEAD128: decrypt_finalize output buffer too small",
            ));
        }

        let mut block = [0u8; RATE];
        block.copy_from_slice(&self.buf[..RATE]);
        self.process_final_decrypt(&block[..data_len], output);

        let received_lo = u64::from_le_bytes(self.buf[data_len..data_len + 8].try_into().unwrap());
        let received_hi =
            u64::from_le_bytes(self.buf[data_len + 8..data_len + 16].try_into().unwrap());
        // OR of the two-lane XOR is the standard Ascon tag-comparison trick.
        let diff = (self.state.s3 ^ received_lo) | (self.state.s4 ^ received_hi);
        self.finished = true;
        if diff != 0 {
            for b in output[..data_len].iter_mut() {
                *b = 0;
            }
            return Err(AsconAeadError::VerificationFailed);
        }
        Ok(data_len)
    }

    /// Return the authentication tag produced by [`AsconAead128::encrypt_finalize`].
    pub fn get_tag(&self) -> Option<[u8; TAG_LEN]> {
        self.mac
    }

    /// Reset the context.
    ///
    /// For decryption contexts, this returns to the post-AD initial state.
    /// For encryption contexts, reset is a no-op other than parking the
    /// state in `EncFinal` — encryption reuse under the same (key, nonce)
    /// is forbidden by NIST SP 800-232.
    pub fn reset(&mut self) {
        if self.for_encryption {
            self.phase = AeadState::EncFinal;
            return;
        }
        // Restore from the post-init snapshot rather than re-running
        // init_state + AAD absorption. The snapshot must exist after a
        // successful init(); panic loudly if reset() is called on a
        // never-initialised context, since restoring nothing would leave
        // the state inconsistent.
        let snap = self
            .init_snapshot
            .as_ref()
            .expect("AsconAead128::reset called before init");
        self.state = snap.state.clone();
        self.buf = snap.buf;
        self.buf_pos = snap.buf_pos;
        self.phase = snap.phase;
        self.mac = None;
        self.finished = false;
    }

    /* ----------------------------- private helpers ----------------------------- */

    fn init_state(&mut self) {
        self.state.s0 = ASCON_AEAD_IV;
        self.state.s1 = self.k0;
        self.state.s2 = self.k1;
        self.state.s3 = self.n0;
        self.state.s4 = self.n1;
        self.state.permute_12();
        self.state.s3 ^= self.k0;
        self.state.s4 ^= self.k1;
    }

    /// Returns a 64-bit value with a single `1` byte at byte-position `i`.
    fn pad_byte_at(i: usize) -> u64 {
        debug_assert!(i < 8);
        0x01u64 << (i * 8)
    }

    fn check_aad_state(&mut self) -> Result<(), AsconAeadError> {
        match self.phase {
            AeadState::DecInit => self.phase = AeadState::DecAad,
            AeadState::EncInit => self.phase = AeadState::EncAad,
            AeadState::DecAad | AeadState::EncAad => {}
            AeadState::EncFinal => {
                return Err(AsconAeadError::InvalidState(
                    "Ascon-AEAD128 encryption context cannot be reused",
                ));
            }
            _ => {
                return Err(AsconAeadError::InvalidState(
                    "Ascon-AEAD128 context not initialised",
                ));
            }
        }
        Ok(())
    }

    fn process_aad_bytes_inner(&mut self, input: &[u8]) {
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
            let mut block = [0u8; RATE];
            block.copy_from_slice(&self.buf[..RATE]);
            self.process_buffer_aad(&block);
        }
        while input.len() >= RATE {
            self.process_buffer_aad(&input[..RATE]);
            input = &input[RATE..];
        }
        self.buf[..input.len()].copy_from_slice(input);
        self.buf_pos = input.len();
    }

    fn finish_aad(&mut self, next_state: AeadState) {
        if matches!(self.phase, AeadState::DecAad | AeadState::EncAad) {
            debug_assert!(self.buf_pos < RATE);
            self.buf[self.buf_pos] = 0x01;
            let block0 = u64::from_le_bytes(self.buf[0..8].try_into().unwrap());
            if self.buf_pos >= 8 {
                self.state.s0 ^= block0;
                let block1 = u64::from_le_bytes(self.buf[8..16].try_into().unwrap());
                self.state.s1 ^= block1 & (u64::MAX >> (56 - ((self.buf_pos - 8) * 8)));
            } else {
                self.state.s0 ^= block0 & (u64::MAX >> (56 - (self.buf_pos * 8)));
            }
            self.state.permute_8();
        }
        // Domain-separation bit between AD and message.
        self.state.s4 ^= 0x8000_0000_0000_0000;
        self.buf_pos = 0;
        self.phase = next_state;
    }

    fn finish_data(&mut self, next_state: AeadState) {
        self.state.s2 ^= self.k0;
        self.state.s3 ^= self.k1;
        self.state.permute_12();
        self.state.s3 ^= self.k0;
        self.state.s4 ^= self.k1;
        self.phase = next_state;
    }

    fn advance_to_data_phase(&mut self) -> Result<(), AsconAeadError> {
        match self.phase {
            AeadState::DecInit | AeadState::DecAad => {
                self.finish_aad(AeadState::DecData);
                Ok(())
            }
            AeadState::EncInit | AeadState::EncAad => {
                self.finish_aad(AeadState::EncData);
                Ok(())
            }
            AeadState::DecData | AeadState::EncData => Ok(()),
            AeadState::EncFinal => Err(AsconAeadError::InvalidState(
                "Ascon-AEAD128 encryption context cannot be reused",
            )),
            _ => Err(AsconAeadError::InvalidState(
                "Ascon-AEAD128 context not initialised",
            )),
        }
    }

    fn process_buffer_aad(&mut self, block: &[u8]) {
        debug_assert!(block.len() >= RATE);
        self.state.s0 ^= u64::from_le_bytes(block[0..8].try_into().unwrap());
        self.state.s1 ^= u64::from_le_bytes(block[8..16].try_into().unwrap());
        self.state.permute_8();
    }

    fn process_buffer_encrypt(&mut self, block: &[u8], output: &mut [u8]) {
        debug_assert!(block.len() >= RATE);
        debug_assert!(output.len() >= RATE);
        self.state.s0 ^= u64::from_le_bytes(block[0..8].try_into().unwrap());
        output[0..8].copy_from_slice(&self.state.s0.to_le_bytes());
        self.state.s1 ^= u64::from_le_bytes(block[8..16].try_into().unwrap());
        output[8..16].copy_from_slice(&self.state.s1.to_le_bytes());
        self.state.permute_8();
    }

    fn process_buffer_decrypt(&mut self, block: &[u8], output: &mut [u8]) {
        debug_assert!(block.len() >= RATE);
        debug_assert!(output.len() >= RATE);
        let t0 = u64::from_le_bytes(block[0..8].try_into().unwrap());
        output[0..8].copy_from_slice(&(self.state.s0 ^ t0).to_le_bytes());
        self.state.s0 = t0;
        let t1 = u64::from_le_bytes(block[8..16].try_into().unwrap());
        output[8..16].copy_from_slice(&(self.state.s1 ^ t1).to_le_bytes());
        self.state.s1 = t1;
        self.state.permute_8();
    }

    fn process_final_encrypt_partial(input: &[u8], output: &mut [u8], s: &mut u64) {
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
            self.state.s0 ^= u64::from_le_bytes(input[0..8].try_into().unwrap());
            output[0..8].copy_from_slice(&self.state.s0.to_le_bytes());
            let input = &input[8..];
            if !input.is_empty() {
                Self::process_final_encrypt_partial(input, &mut output[8..], &mut self.state.s1);
            }
            self.state.s1 ^= Self::pad_byte_at(input.len());
        } else {
            if !input.is_empty() {
                Self::process_final_encrypt_partial(input, output, &mut self.state.s0);
            }
            self.state.s0 ^= Self::pad_byte_at(input.len());
        }
        self.finish_data(AeadState::EncFinal);
    }

    fn process_final_decrypt_partial(input: &[u8], output: &mut [u8], s: &mut u64) {
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
            let t0 = u64::from_le_bytes(input[0..8].try_into().unwrap());
            output[0..8].copy_from_slice(&(self.state.s0 ^ t0).to_le_bytes());
            self.state.s0 = t0;
            let input = &input[8..];
            if !input.is_empty() {
                Self::process_final_decrypt_partial(input, &mut output[8..], &mut self.state.s1);
            }
            self.state.s1 ^= Self::pad_byte_at(input.len());
        } else {
            if !input.is_empty() {
                Self::process_final_decrypt_partial(input, output, &mut self.state.s0);
            }
            self.state.s0 ^= Self::pad_byte_at(input.len());
        }
        self.finish_data(AeadState::DecFinal);
    }
}

impl Drop for AsconAead128 {
    fn drop(&mut self) {
        self.k0 = 0;
        self.k1 = 0;
        self.n0 = 0;
        self.n1 = 0;
        self.buf.fill(0);
        self.buf_pos = 0;
        if let Some(ref mut tag) = self.mac {
            tag.fill(0);
        }
        self.mac = None;
        // InitSnapshot has its own Drop that zeroes the cached buffer
        // and the inner AsconState zeroizes its lanes.
        self.init_snapshot = None;
    }
}

impl Algorithm for AsconAead128 {
    const ALG_NAME: &'static str = ASCON_AEAD128_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

impl AeadCipher for AsconAead128 {
    fn process_aad_byte(&mut self, input: u8) {
        let _ = self.process_aad(&[input]);
    }

    fn process_aad_bytes(&mut self, in_bytes: &[u8]) {
        let _ = self.process_aad(in_bytes);
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

    fn do_final(&mut self, out_bytes: &mut [u8]) {
        if self.for_encryption {
            self.encrypt_finalize(out_bytes).expect("Ascon-AEAD128 encrypt_finalize");
        } else {
            self.decrypt_finalize(out_bytes)
                .expect("Ascon-AEAD128: authentication tag verification failed");
        }
    }

    fn get_mac(&self) -> Vec<u8> {
        match &self.mac {
            Some(tag) => tag.to_vec(),
            None => Vec::new(),
        }
    }

    fn get_mac_out(&self, out: &mut [u8]) -> usize {
        match &self.mac {
            Some(tag) => {
                let n = tag.len().min(out.len());
                out[..n].copy_from_slice(&tag[..n]);
                n
            }
            None => 0,
        }
    }

    fn get_update_output_size(&self, len: usize) -> usize {
        // `buf_pos` has different meaning across phases: in *Aad it's the
        // number of buffered AAD bytes (which produce no ciphertext
        // output), in *Data it's the number of buffered PT/CT bytes
        // (which DO produce ciphertext output once the rate is reached).
        // The `_Aad` branches therefore must NOT add `buf_pos` to the
        // prediction — pushing PT in that state will first finalize the
        // AD via `advance_to_data_phase`, which resets `buf_pos` to 0
        // before the PT bytes start filling the buffer.
        match self.phase {
            AeadState::Uninitialized | AeadState::EncFinal | AeadState::DecFinal => 0,
            AeadState::EncInit | AeadState::EncAad => (len / RATE) * RATE,
            AeadState::EncData => ((self.buf_pos + len) / RATE) * RATE,
            AeadState::DecInit | AeadState::DecAad => {
                if len >= DECRYPT_BUF_LEN {
                    ((len - TAG_LEN) / RATE) * RATE
                } else {
                    0
                }
            }
            AeadState::DecData => {
                let total = self.buf_pos + len;
                if total >= DECRYPT_BUF_LEN {
                    ((total - TAG_LEN) / RATE) * RATE
                } else {
                    0
                }
            }
        }
    }

    fn get_output_size(&self, len: usize) -> usize {
        // See note in `get_update_output_size`: buffered AAD bytes do not
        // contribute to ciphertext output, so the `_Aad` branches must
        // not add `buf_pos`.
        match self.phase {
            AeadState::Uninitialized | AeadState::EncFinal | AeadState::DecFinal => 0,
            AeadState::EncInit | AeadState::EncAad => len + TAG_LEN,
            AeadState::EncData => self.buf_pos + len + TAG_LEN,
            AeadState::DecInit | AeadState::DecAad => len.saturating_sub(TAG_LEN),
            AeadState::DecData => (self.buf_pos + len).saturating_sub(TAG_LEN),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn aead_encrypt(key: &[u8; 16], nonce: &[u8; 16], ad: Option<&[u8]>, pt: &[u8]) -> Vec<u8> {
        let mut enc = AsconAead128::new(key, nonce, ad, true);
        let mut out = vec![0u8; pt.len() + TAG_LEN];
        let n = enc.encrypt_update(pt, &mut out);
        let m = enc.encrypt_finalize(&mut out[n..]).unwrap();
        out.truncate(n + m);
        out
    }

    fn aead_decrypt(
        key: &[u8; 16],
        nonce: &[u8; 16],
        ad: Option<&[u8]>,
        ct: &[u8],
    ) -> Result<Vec<u8>, AsconAeadError> {
        let mut dec = AsconAead128::new(key, nonce, ad, false);
        let pt_len = ct.len() - TAG_LEN;
        let mut out = vec![0u8; pt_len];
        let n = dec.try_decrypt_update(ct, &mut out)?;
        let m = dec.decrypt_finalize(&mut out[n..])?;
        out.truncate(n + m);
        Ok(out)
    }

    const KEY: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F,
    ];
    const NONCE: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F,
    ];

    #[test]
    fn roundtrip_with_aad() {
        let pt: &[u8] = b"the quick brown fox jumps over the lazy dog";
        let ad: &[u8] = b"associated";
        let ct = aead_encrypt(&KEY, &NONCE, Some(ad), pt);
        let recovered = aead_decrypt(&KEY, &NONCE, Some(ad), &ct).unwrap();
        assert_eq!(recovered.as_slice(), pt);
    }

    #[test]
    fn roundtrip_empty_plaintext() {
        let ct = aead_encrypt(&KEY, &NONCE, None, b"");
        assert_eq!(ct.len(), TAG_LEN);
        let recovered = aead_decrypt(&KEY, &NONCE, None, &ct).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn tampered_ciphertext_fails_with_verification_error() {
        let pt = b"trusted plaintext";
        let mut ct = aead_encrypt(&KEY, &NONCE, None, pt);
        ct[0] ^= 0x01;
        let err = aead_decrypt(&KEY, &NONCE, None, &ct).unwrap_err();
        assert_eq!(err, AsconAeadError::VerificationFailed);
    }

    #[test]
    fn tampered_tag_fails_with_verification_error() {
        let pt = b"data";
        let mut ct = aead_encrypt(&KEY, &NONCE, None, pt);
        let last = ct.len() - 1;
        ct[last] ^= 0x80;
        let err = aead_decrypt(&KEY, &NONCE, None, &ct).unwrap_err();
        assert_eq!(err, AsconAeadError::VerificationFailed);
    }

    #[test]
    fn wrong_key_fails_with_verification_error() {
        let pt = b"trusted";
        let ct = aead_encrypt(&KEY, &NONCE, None, pt);
        let mut wrong_key = KEY;
        wrong_key[0] ^= 0xFF;
        let err = aead_decrypt(&wrong_key, &NONCE, None, &ct).unwrap_err();
        assert_eq!(err, AsconAeadError::VerificationFailed);
    }

    #[test]
    fn wrong_aad_fails_with_verification_error() {
        let pt = b"trusted";
        let ct = aead_encrypt(&KEY, &NONCE, Some(b"context-A"), pt);
        let err = aead_decrypt(&KEY, &NONCE, Some(b"context-B"), &ct).unwrap_err();
        assert_eq!(err, AsconAeadError::VerificationFailed);
    }

    #[test]
    fn auth_failure_zeroes_partial_plaintext() {
        let pt = b"sensitive plaintext content";
        let mut ct = aead_encrypt(&KEY, &NONCE, None, pt);
        ct[3] ^= 0x01;

        let mut dec = AsconAead128::new(&KEY, &NONCE, None, false);
        let pt_len = ct.len() - TAG_LEN;
        let mut out = vec![0xAAu8; pt_len];
        let n = dec.try_decrypt_update(&ct, &mut out).unwrap();
        let err = dec.decrypt_finalize(&mut out[n..]).unwrap_err();
        assert_eq!(err, AsconAeadError::VerificationFailed);

        let tail = &out[n..];
        assert!(tail.iter().all(|&b| b == 0), "tail of output should be scrubbed: {tail:?}");
    }

    #[test]
    fn encrypt_after_finalize_is_rejected() {
        let mut enc = AsconAead128::new(&KEY, &NONCE, None, true);
        let mut out = [0u8; 16];
        enc.encrypt_finalize(&mut out).unwrap();
        let err = enc.try_encrypt_update(b"more", &mut out).unwrap_err();
        assert!(matches!(err, AsconAeadError::InvalidState(_)));
    }

    #[test]
    fn decrypt_too_short_for_tag_is_rejected() {
        let mut dec = AsconAead128::new(&KEY, &NONCE, None, false);
        let mut throwaway = [0u8; 0];
        dec.try_decrypt_update(&[0u8; 5], &mut throwaway).unwrap();
        let err = dec.decrypt_finalize(&mut throwaway).unwrap_err();
        assert!(matches!(err, AsconAeadError::InvalidState(_)));
    }

    #[test]
    fn streaming_matches_one_shot_across_chunk_sizes() {
        let pt: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEF";
        let ad: &[u8] = b"aad";
        let one_shot = aead_encrypt(&KEY, &NONCE, Some(ad), pt);

        for chunk in 1..=pt.len() {
            let mut enc = AsconAead128::new(&KEY, &NONCE, Some(ad), true);
            let mut out = vec![0u8; pt.len() + TAG_LEN];
            let mut o = 0;
            for c in pt.chunks(chunk) {
                o += enc.encrypt_update(c, &mut out[o..]);
            }
            o += enc.encrypt_finalize(&mut out[o..]).unwrap();
            out.truncate(o);
            assert_eq!(out, one_shot, "mismatch at chunk size {chunk}");
        }
    }

    #[test]
    fn nist_kat_smoke() {
        let pt = [0x00u8];
        let ad = [0x00u8];
        let expected_ct = [
            0x25, 0xEB, 0x4B, 0x70, 0x0E, 0xD4, 0xAC, 0x85, 0x17, 0xDC, 0xBA, 0x20, 0xF6, 0x73,
            0x29, 0x22, 0x30,
        ];
        let ct = aead_encrypt(&KEY, &NONCE, Some(&ad), &pt);
        assert_eq!(&ct[..], &expected_ct[..]);
        let recovered = aead_decrypt(&KEY, &NONCE, Some(&ad), &ct).unwrap();
        assert_eq!(recovered, pt.to_vec());
    }

    #[test]
    fn init_can_reinitialise_existing_context() {
        let mut a = AsconAead128::new(&KEY, &NONCE, None, true);
        let mut ct1 = vec![0u8; 16];
        a.encrypt_finalize(&mut ct1).unwrap();

        // Reuse the same allocation under a different (key, nonce, dir).
        let other_key = [0x42u8; 16];
        let other_nonce = [0x99u8; 16];
        a.init(&other_key, &other_nonce, Some(b"label"), true);
        let mut ct2 = vec![0u8; 16];
        a.encrypt_finalize(&mut ct2).unwrap();

        // Different (key, nonce) → different tag.
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn algorithm_constants() {
        assert_eq!(AsconAead128::ALG_NAME, "Ascon-AEAD128");
        assert_eq!(AsconAead128::MAX_SECURITY_STRENGTH, SecurityStrength::_128bit);
    }

    #[test]
    fn get_mac_out_matches_get_mac() {
        // Encrypt something, then verify the trait's two tag-retrieval
        // paths return identical bytes.
        let pt = b"plaintext for tag retrieval";
        let mut enc = AsconAead128::new(&KEY, &NONCE, None, true);
        let mut ct = vec![0u8; pt.len() + TAG_LEN];
        let n = enc.encrypt_update(pt, &mut ct);
        enc.encrypt_finalize(&mut ct[n..]).unwrap();

        let via_vec: Vec<u8> = AeadCipher::get_mac(&enc);
        assert_eq!(via_vec.len(), TAG_LEN);

        // Right-sized buffer
        let mut tag_buf = [0u8; TAG_LEN];
        let written = AeadCipher::get_mac_out(&enc, &mut tag_buf);
        assert_eq!(written, TAG_LEN);
        assert_eq!(&tag_buf[..], via_vec.as_slice());

        // Oversized buffer: first TAG_LEN bytes filled, rest untouched.
        let mut over = [0xAAu8; TAG_LEN + 4];
        let written = AeadCipher::get_mac_out(&enc, &mut over);
        assert_eq!(written, TAG_LEN);
        assert_eq!(&over[..TAG_LEN], via_vec.as_slice());
        assert_eq!(&over[TAG_LEN..], &[0xAA, 0xAA, 0xAA, 0xAA]);

        // Undersized buffer: only the first out.len() bytes of the tag.
        let mut under = [0u8; 8];
        let written = AeadCipher::get_mac_out(&enc, &mut under);
        assert_eq!(written, 8);
        assert_eq!(&under[..], &via_vec[..8]);
    }

    #[test]
    fn get_mac_out_before_finalize_returns_zero() {
        let enc = AsconAead128::new(&KEY, &NONCE, None, true);
        let mut buf = [0xFFu8; TAG_LEN];
        let n = AeadCipher::get_mac_out(&enc, &mut buf);
        assert_eq!(n, 0);
        // Buffer must not be touched when no tag is available.
        assert_eq!(buf, [0xFFu8; TAG_LEN]);
    }

    #[test]
    fn reset_restores_post_init_state_with_aad() {
        // Decrypt the same (key, nonce, ad) ciphertext twice using
        // reset() between rounds. The snapshot path must reproduce
        // exactly what a fresh init() would.
        let ad: &[u8] = b"snapshot test AD";
        let pt: &[u8] = b"snapshot round trip";

        // Build a canonical ciphertext.
        let mut enc = AsconAead128::new(&KEY, &NONCE, Some(ad), true);
        let mut ct = vec![0u8; pt.len() + TAG_LEN];
        let n = enc.encrypt_update(pt, &mut ct);
        let m = enc.encrypt_finalize(&mut ct[n..]).unwrap();
        ct.truncate(n + m);

        // First decryption via fresh init.
        let mut dec = AsconAead128::new(&KEY, &NONCE, Some(ad), false);
        let mut out1 = vec![0u8; pt.len()];
        let a = dec.try_decrypt_update(&ct, &mut out1).unwrap();
        let b = dec.decrypt_finalize(&mut out1[a..]).unwrap();
        out1.truncate(a + b);
        assert_eq!(out1.as_slice(), pt);

        // Reuse the same context via reset() — must produce the same plaintext.
        dec.reset();
        let mut out2 = vec![0u8; pt.len()];
        let a = dec.try_decrypt_update(&ct, &mut out2).unwrap();
        let b = dec.decrypt_finalize(&mut out2[a..]).unwrap();
        out2.truncate(a + b);
        assert_eq!(out2.as_slice(), pt);
    }
}
