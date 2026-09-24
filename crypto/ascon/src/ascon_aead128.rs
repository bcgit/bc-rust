//! Ascon-AEAD128 authenticated encryption, as specified in NIST SP 800-232 §4.
//!
//! Rate = 128 bits, capacity = 192 bits, 128-bit key/nonce/tag. Initialization and finalization use
//! `Ascon-p[12]`; associated-data and plaintext/ciphertext blocks use `Ascon-p[8]`.
//!
//! Every byte of plaintext/ciphertext is transformed and emitted as soon as it is seen (no
//! held-back buffering across `do_encrypt_update`/`do_decrypt_update` calls); this is what lets the
//! finalizers be plain `self -> tag` / `self -> Result<(), _>` calls with nothing left to flush.
//! Ascon-AEAD128 permits this because within a 128-bit rate block each plaintext/ciphertext byte
//! is transformed independently of the others in that block; the permutation only runs once a
//! full 16-byte block has been absorbed, or at finalization.
//!
//! [`AsconAead128Encryptor`] / [`AsconAead128Decryptor`] adapt this type's direction-agnostic
//! streaming API (a single [`AsconAead128`] value serves either direction, fixed at construction
//! by [`AsconAead128::new_encrypting`] / [`AsconAead128::new_decrypting`]) to
//! [`AEADCipherEncryptor`] / [`AEADCipherDecryptor`], whose
//! direction is fixed by the type: each newtype wraps an [`AsconAead128`] already constructed for
//! its own direction and only ever calls that direction's inherent methods, so the wrong-direction
//! panics inside [`AsconAead128::do_encrypt_update`] and friends are unreachable through them. See
//! their docs for why a thin newtype pair rather than encoding the direction into `AsconAead128`
//! itself: the inherent API is deliberately one type serving both directions, which is what the
//! in-place streaming and the explicit-nonce one-shots are built on.

use core::fmt::{self, Debug, Display, Formatter};

use bouncycastle_core::errors::{KeyMaterialError, SuspendableError, SymmetricCipherError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::suspendable_state::{add_lib_ver, check_lib_ver};
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, Algorithm, RNG, SecurityStrength, SuspendableKeyed,
    SymmetricCipherDecryptor, SymmetricCipherEncryptor,
};
use bouncycastle_modes::{Decrypting, Encrypting};
use bouncycastle_rng::HashDRBG_SHA512;
use bouncycastle_utils::ct::ct_eq_bytes;
use bouncycastle_utils::secret::Secret;

use crate::permutation::{AsconState, load_u64_le, p8, p12, store_u64_le};

/// Length in bytes of the Ascon-AEAD128 key.
pub const KEY_LEN: usize = 16;
/// Length in bytes of the Ascon-AEAD128 nonce.
pub const NONCE_LEN: usize = 16;
/// Length in bytes of the Ascon-AEAD128 authentication tag.
pub const TAG_LEN: usize = 16;
const RATE: usize = 16;

/// Ascon-AEAD128 initial value (SP 800-232 Table 14).
const ASCON_IV: u64 = 0x00001000808C0001;

/// State machine for enforcing the call order and remembering the direction (encrypt/decrypt).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum StateMachine {
    EncInit,
    EncAad,
    EncData,
    DecInit,
    DecAad,
    DecData,
}

impl StateMachine {
    // Stable u8 encoding used when suspending/resuming the AEAD state machine.
    fn to_u8(self) -> u8 {
        match self {
            StateMachine::EncInit => 0,
            StateMachine::EncAad => 1,
            StateMachine::EncData => 2,
            StateMachine::DecInit => 4,
            StateMachine::DecAad => 5,
            StateMachine::DecData => 6,
        }
    }

    fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => StateMachine::EncInit,
            1 => StateMachine::EncAad,
            2 => StateMachine::EncData,
            4 => StateMachine::DecInit,
            5 => StateMachine::DecAad,
            6 => StateMachine::DecData,
            _ => return None,
        })
    }

    fn is_encrypt(self) -> bool {
        matches!(self, StateMachine::EncInit | StateMachine::EncAad | StateMachine::EncData)
    }

    fn is_init(self) -> bool {
        matches!(self, StateMachine::EncInit | StateMachine::DecInit)
    }
}

/// An implementation of the Ascon-AEAD128 algorithm (NIST SP 800-232).
///
/// A single instance performs one operation (encryption or decryption) under one (key, nonce) pair.
/// See [`AsconAead128::new_encrypting`] for the streaming workflow and
/// [`AsconAead128::encrypt`] /
/// [`AsconAead128::decrypt`] for the one-shot APIs.
#[derive(Clone)]
pub struct AsconAead128 {
    // 128-bit secret key (two 64-bit words). It is re-added to the state at finalization, so it must
    // be retained; wrapped in `Secret` for volatile-write zeroization on drop.
    key: Secret<[u64; 2]>,
    // 320-bit internal state (five 64-bit words). Carries keystream/plaintext-derived material, so
    // it is likewise wrapped in `Secret`.
    state: Secret<AsconState>,
    // Byte position (0..RATE) within the current rate block.
    pos: usize,
    // State machine for enforcing the call order and remembering the direction.
    state_machine: StateMachine,
}

impl AsconAead128 {
    /// Validate a [`KeyMaterial`] for use with Ascon-AEAD128 and return its key words.
    /// The key must be tagged as a [`KeyType::SymmetricCipherKey`] and carry at least the
    /// algorithm's 128-bit security strength (SP 800-232 R1/R2).
    fn checked_key(key: &KeyMaterial<KEY_LEN>) -> Result<[u64; 2], SymmetricCipherError> {
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
        if bytes.len() != KEY_LEN {
            return Err(KeyMaterialError::InvalidLength.into());
        }
        Ok([load_u64_le(bytes, 0), load_u64_le(bytes, 8)])
    }

    /// Draw a fresh, unique 128-bit nonce from the library's default OS-seeded DRBG.
    ///
    /// The one-shot APIs of main's cipher framework generate the init data / nonce internally, so
    /// Ascon's per-encryption nonce-uniqueness requirement (SP 800-232 R3) is satisfied by sourcing
    /// each nonce from a CSPRNG. Callers who need deterministic, caller-supplied nonces should use
    /// the inherent streaming API ([`AsconAead128::new_encrypting`]).
    fn fresh_nonce() -> Result<[u8; NONCE_LEN], SymmetricCipherError> {
        let mut rng = HashDRBG_SHA512::new_from_os();
        let mut nonce = [0u8; NONCE_LEN];
        rng.next_bytes_out(&mut nonce)?;
        Ok(nonce)
    }

    /// Creates a streaming instance for **encryption** under a caller-supplied nonce.
    /// * `key` is validated as a [`KeyType::SymmetricCipherKey`] with at least 128-bit strength.
    /// * `nonce` is the 128-bit nonce. It **must** be unique per encryption under a given key;
    ///   [`AsconAead128Encryptor`] generates one instead, which is the safer default.
    /// * `ad` is optional associated data (authenticated, not encrypted); processed immediately.
    ///
    /// Only the `do_encrypt_*` methods may be called on the result; the decrypting ones panic.
    pub fn new_encrypting(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
        ad: Option<&[u8]>,
    ) -> Result<Self, SymmetricCipherError> {
        Self::new(key, nonce, ad, true)
    }

    /// Creates a streaming instance for **decryption** under the nonce the ciphertext was produced
    /// with; see [`new_encrypting`](Self::new_encrypting) for the arguments.
    ///
    /// Only the `do_decrypt_*` methods may be called on the result; the encrypting ones panic.
    pub fn new_decrypting(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
        ad: Option<&[u8]>,
    ) -> Result<Self, SymmetricCipherError> {
        Self::new(key, nonce, ad, false)
    }

    /// The body of [`new_encrypting`](Self::new_encrypting) / [`new_decrypting`](Self::new_decrypting).
    /// Private because a `bool` for the direction is not something the public API should ask a
    /// caller to get right: every public entry point fixes it, either by name here or by type on
    /// [`AsconAead128Encryptor`] / [`AsconAead128Decryptor`].
    fn new(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
        ad: Option<&[u8]>,
        for_encryption: bool,
    ) -> Result<Self, SymmetricCipherError> {
        let key_words = Self::checked_key(key)?;
        let mut key_secret: Secret<[u64; 2]> = Secret::new();
        *key_secret = key_words;

        let mut state: Secret<AsconState> = Secret::new();
        // Initialization (SP 800-232 §4.1.1 step 1 / Eq. 15-17): S = IV||K||N, then Ascon-p[12],
        // then XOR K into the last 128 bits.
        state[0] = ASCON_IV;
        state[1] = key_words[0];
        state[2] = key_words[1];
        state[3] = load_u64_le(nonce, 0);
        state[4] = load_u64_le(nonce, 8);
        p12(&mut state);
        state[3] ^= key_words[0];
        state[4] ^= key_words[1];

        let mut aead = AsconAead128 {
            key: key_secret,
            state,
            pos: 0,
            state_machine: if for_encryption {
                StateMachine::EncInit
            } else {
                StateMachine::DecInit
            },
        };
        if let Some(ad_bytes) = ad {
            // infallible: a freshly constructed instance has processed no data yet, so
            // `check_aad` cannot return `StateError`.
            aead.do_update_aad(ad_bytes).unwrap();
        }
        Ok(aead)
    }

    /// One-shot authenticated encryption with a caller-supplied nonce (SP 800-232 Algorithm 3).
    /// Writes ciphertext followed by the 128-bit tag into `out`, which must be at least
    /// `plaintext.len() + 16` bytes. Returns the number of bytes written.
    pub fn encrypt(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
        ad: Option<&[u8]>,
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        let needed = plaintext.len() + TAG_LEN;
        if out.len() < needed {
            return Err(SymmetricCipherError::OutputBufferTooSmall(needed));
        }
        let mut cipher = Self::new(key, nonce, ad, true)?;
        out[..plaintext.len()].copy_from_slice(plaintext);
        cipher.do_encrypt_update(&mut out[..plaintext.len()]);
        let tag = cipher.do_encrypt_final();
        out[plaintext.len()..needed].copy_from_slice(&tag);
        Ok(needed)
    }

    /// One-shot authenticated decryption with a caller-supplied nonce (SP 800-232 Algorithm 4).
    /// `ciphertext` is the ciphertext followed by the 128-bit tag. Writes the recovered plaintext
    /// into `out`, which must be at least `ciphertext.len() - 16` bytes. Returns the number of
    /// bytes written, or [`SymmetricCipherError::AEADTagCheckFailed`] if the tag does not verify --
    /// in which case `out` is zeroized before returning.
    pub fn decrypt(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
        ad: Option<&[u8]>,
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        if ciphertext.len() < TAG_LEN {
            return Err(SymmetricCipherError::GenericError(
                "Ascon-AEAD128 ciphertext shorter than tag",
            ));
        }
        let pt_len = ciphertext.len() - TAG_LEN;
        if out.len() < pt_len {
            return Err(SymmetricCipherError::OutputBufferTooSmall(pt_len));
        }
        let mut cipher = Self::new(key, nonce, ad, false)?;
        out[..pt_len].copy_from_slice(&ciphertext[..pt_len]);
        cipher.do_decrypt_update(&mut out[..pt_len]);
        // infallible: ciphertext.len() - pt_len == TAG_LEN by construction above.
        let tag: &[u8; TAG_LEN] = ciphertext[pt_len..].try_into().unwrap();
        match cipher.do_decrypt_final(tag) {
            Ok(()) => Ok(pt_len),
            Err(e) => {
                out[..pt_len].fill(0);
                Err(e)
            }
        }
    }

    /// Read the value of state byte `pos` (0 = LSB of word 0, ..., 15 = MSB of word 1).
    fn state_byte(&self, pos: usize) -> u8 {
        let word = if pos < 8 { self.state[0] } else { self.state[1] };
        (word >> ((pos % 8) * 8)) as u8
    }

    /// XOR `b` into state byte `pos`.
    fn xor_state_byte(&mut self, pos: usize, b: u8) {
        let shifted = (b as u64) << ((pos % 8) * 8);
        if pos < 8 { self.state[0] ^= shifted } else { self.state[1] ^= shifted }
    }

    /// Overwrite state byte `pos` with `b`.
    fn set_state_byte(&mut self, pos: usize, b: u8) {
        let shift = (pos % 8) * 8;
        let mask = !(0xFFu64 << shift);
        let shifted = (b as u64) << shift;
        if pos < 8 {
            self.state[0] = (self.state[0] & mask) | shifted;
        } else {
            self.state[1] = (self.state[1] & mask) | shifted;
        }
    }

    /// Advance to the next byte position, running `Ascon-p[8]` and wrapping back to 0 once a full
    /// rate block (16 bytes) has been absorbed.
    fn advance(&mut self) {
        self.pos += 1;
        if self.pos == RATE {
            p8(&mut self.state);
            self.pos = 0;
        }
    }

    fn absorb_aad_byte(&mut self, b: u8) {
        self.xor_state_byte(self.pos, b);
        self.advance();
    }

    fn encrypt_byte(&mut self, p: u8) -> u8 {
        self.xor_state_byte(self.pos, p);
        let c = self.state_byte(self.pos);
        self.advance();
        c
    }

    fn decrypt_byte(&mut self, c: u8) -> u8 {
        let prev = self.state_byte(self.pos);
        self.set_state_byte(self.pos, c);
        self.advance();
        prev ^ c
    }

    fn check_aad(&mut self) -> Result<(), SymmetricCipherError> {
        match self.state_machine {
            StateMachine::EncInit => self.state_machine = StateMachine::EncAad,
            StateMachine::DecInit => self.state_machine = StateMachine::DecAad,
            StateMachine::EncAad | StateMachine::DecAad => {}
            StateMachine::EncData | StateMachine::DecData => {
                return Err(SymmetricCipherError::StateError(
                    "Ascon-AEAD128: associated data must be processed before plaintext/ciphertext",
                ));
            }
        }
        Ok(())
    }

    // Ends the associated-data phase (SP 800-232 §4.1.1/§4.1.2 step 2): pads and absorbs the
    // final (possibly empty) AAD block only if any AAD was actually supplied, then applies the
    // domain-separation bit unconditionally.
    fn finish_aad(&mut self) {
        if matches!(self.state_machine, StateMachine::EncAad | StateMachine::DecAad) {
            self.xor_state_byte(self.pos, 0x01);
            p8(&mut self.state);
            self.pos = 0;
        }
        // Domain separation (Eq. 22/40: S ^= (0^319 || 1)).
        self.state[4] ^= 0x8000000000000000;
        self.state_machine = match self.state_machine {
            StateMachine::EncInit | StateMachine::EncAad => StateMachine::EncData,
            StateMachine::DecInit | StateMachine::DecAad => StateMachine::DecData,
            StateMachine::EncData | StateMachine::DecData => unreachable!(),
        };
    }

    fn check_data(&mut self) {
        if !matches!(self.state_machine, StateMachine::EncData | StateMachine::DecData) {
            self.finish_aad();
        }
    }

    // Finalization (SP 800-232 §4.1.1 step 4 / §4.1.2 step 4, Eq. 30-32 / 49-51): re-add the key,
    // permute with Ascon-p[12], and add the key again; the tag is the resulting last 128 bits.
    fn finish_data(&mut self) -> [u8; TAG_LEN] {
        self.state[2] ^= self.key[0];
        self.state[3] ^= self.key[1];
        p12(&mut self.state);
        self.state[3] ^= self.key[0];
        self.state[4] ^= self.key[1];

        let mut tag = [0u8; TAG_LEN];
        store_u64_le(&mut tag, 0, self.state[3]);
        store_u64_le(&mut tag, 8, self.state[4]);
        tag
    }

    /// Process associated data (AAD) bytes. May be called multiple times, but only before any
    /// plaintext/ciphertext is processed; an empty `input` is always a no-op, even after data.
    ///
    /// # Errors
    /// [`SymmetricCipherError::StateError`] if `input` is non-empty and plaintext/ciphertext has
    /// already been processed.
    pub fn do_update_aad(&mut self, input: &[u8]) -> Result<(), SymmetricCipherError> {
        if input.is_empty() {
            return Ok(());
        }
        self.check_aad()?;

        let mut input = input;
        while !input.is_empty() {
            if self.pos == 0 && input.len() >= RATE {
                self.state[0] ^= load_u64_le(input, 0);
                self.state[1] ^= load_u64_le(input, 8);
                p8(&mut self.state);
                input = &input[RATE..];
            } else {
                self.absorb_aad_byte(input[0]);
                input = &input[1..];
            }
        }
        Ok(())
    }

    /// Encrypt `data` in place (SP 800-232 §4.1.1 step 3). Every byte is transformed and emitted
    /// immediately; nothing is buffered across calls.
    pub fn do_encrypt_update(&mut self, data: &mut [u8]) {
        if !self.state_machine.is_encrypt() {
            panic!("Ascon-AEAD128: do_encrypt_update called on a decryptor");
        }
        self.check_data();

        let mut data = data;
        while !data.is_empty() {
            if self.pos == 0 && data.len() >= RATE {
                let c0 = self.state[0] ^ load_u64_le(data, 0);
                let c1 = self.state[1] ^ load_u64_le(data, 8);
                store_u64_le(data, 0, c0);
                store_u64_le(data, 8, c1);
                self.state[0] = c0;
                self.state[1] = c1;
                p8(&mut self.state);
                data = &mut data[RATE..];
            } else {
                data[0] = self.encrypt_byte(data[0]);
                data = &mut data[1..];
            }
        }
    }

    /// Finish encryption; returns the 128-bit tag (SP 800-232 §4.1.1 steps 3-4). Pads the final
    /// (possibly empty) plaintext block; no further bytes are emitted here since every
    /// plaintext/ciphertext byte was already written by `do_encrypt_update`.
    pub fn do_encrypt_final(mut self) -> [u8; TAG_LEN] {
        if !self.state_machine.is_encrypt() {
            panic!("Ascon-AEAD128: do_encrypt_final called on a decryptor");
        }
        self.check_data();
        // Padding of the final (possibly empty) plaintext block (Eq. 27).
        self.xor_state_byte(self.pos, 0x01);
        self.finish_data()
    }

    /// Decrypt `data` in place (SP 800-232 §4.1.2 step 3). Every byte is transformed and emitted
    /// immediately; the plaintext is **not** authenticated until [`AsconAead128::do_decrypt_final`]
    /// returns `Ok`.
    pub fn do_decrypt_update(&mut self, data: &mut [u8]) {
        if self.state_machine.is_encrypt() {
            panic!("Ascon-AEAD128: do_decrypt_update called on an encryptor");
        }
        self.check_data();

        let mut data = data;
        while !data.is_empty() {
            if self.pos == 0 && data.len() >= RATE {
                let t0 = load_u64_le(data, 0);
                let t1 = load_u64_le(data, 8);
                store_u64_le(data, 0, self.state[0] ^ t0);
                store_u64_le(data, 8, self.state[1] ^ t1);
                self.state[0] = t0;
                self.state[1] = t1;
                p8(&mut self.state);
                data = &mut data[RATE..];
            } else {
                data[0] = self.decrypt_byte(data[0]);
                data = &mut data[1..];
            }
        }
    }

    /// Finish decryption, checking `tag` in constant time (SP 800-232 §4.1.2 steps 3-4).
    pub fn do_decrypt_final(mut self, tag: &[u8; TAG_LEN]) -> Result<(), SymmetricCipherError> {
        if self.state_machine.is_encrypt() {
            panic!("Ascon-AEAD128: do_decrypt_final called on an encryptor");
        }
        self.check_data();
        // Padding of the final (possibly empty) ciphertext block (Eq. 47).
        self.xor_state_byte(self.pos, 0x01);
        let computed = self.finish_data();

        if !ct_eq_bytes(&computed, tag) {
            return Err(SymmetricCipherError::AEADTagCheckFailed);
        }
        Ok(())
    }
}

impl Algorithm for AsconAead128 {
    const ALG_NAME: &'static str = "Ascon-AEAD128";
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

/// Adapts [`AsconAead128`]'s encrypting direction to [`AEADCipherEncryptor`] and, through it,
/// [`SymmetricCipherEncryptor`]; see the module docs for why this is a thin wrapper rather than a
/// change to `AsconAead128` itself.
///
/// `FINAL_LEN` is `TAG_LEN`: Ascon-AEAD128 holds nothing back, so the inline
/// [`SymmetricCipherEncryptor::do_final`] writes only the tag, and the detached
/// [`AEADCipherEncryptor::do_final_out_detached`] writes nothing.
pub struct AsconAead128Encryptor(AsconAead128);

impl Algorithm for AsconAead128Encryptor {
    const ALG_NAME: &'static str = AsconAead128::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = AsconAead128::MAX_SECURITY_STRENGTH;
}

impl SymmetricCipherEncryptor<KEY_LEN, NONCE_LEN, TAG_LEN> for AsconAead128Encryptor {
    fn do_encrypt_init(
        key: &KeyMaterial<KEY_LEN>,
    ) -> Result<(Self, [u8; NONCE_LEN]), SymmetricCipherError> {
        let nonce = AsconAead128::fresh_nonce()?;
        Ok((Self(AsconAead128::new(key, &nonce, None, true)?), nonce))
    }

    fn do_encrypt_init_rng(
        key: &KeyMaterial<KEY_LEN>,
        rng: &mut dyn RNG,
    ) -> Result<(Self, [u8; NONCE_LEN]), SymmetricCipherError> {
        let mut nonce = [0u8; NONCE_LEN];
        rng.next_bytes_out(&mut nonce)?;
        Ok((Self(AsconAead128::new(key, &nonce, None, true)?), nonce))
    }

    /// Ascon-AEAD128 never buffers: every byte given is a byte returned.
    fn update_out_len(&self, input_len: usize) -> usize {
        input_len
    }

    fn do_update_out(
        &mut self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        if ciphertext.len() < plaintext.len() {
            return Err(SymmetricCipherError::OutputBufferTooSmall(plaintext.len()));
        }
        let out = &mut ciphertext[..plaintext.len()];
        out.copy_from_slice(plaintext);
        self.0.do_encrypt_update(out);
        Ok(plaintext.len())
    }

    /// The inline layout: nothing is held back, so the final buffer is exactly the tag.
    fn do_final(self) -> Result<([u8; TAG_LEN], usize), SymmetricCipherError> {
        Ok((self.0.do_encrypt_final(), TAG_LEN))
    }

    /// The ciphertext, which is as long as the plaintext, followed by the tag.
    fn encrypt_out_len(plaintext_len: usize) -> usize {
        plaintext_len + TAG_LEN
    }
}

impl AEADCipherEncryptor<KEY_LEN, NONCE_LEN, TAG_LEN, TAG_LEN> for AsconAead128Encryptor {
    fn do_update_aad(&mut self, aad: &[u8]) -> Result<(), SymmetricCipherError> {
        self.0.do_update_aad(aad)
    }

    /// Nothing is ever held back to flush, so `ciphertext` is left untouched.
    fn do_final_out_detached(
        self,
        _ciphertext: &mut [u8; TAG_LEN],
    ) -> Result<(usize, [u8; TAG_LEN]), SymmetricCipherError> {
        Ok((0, self.0.do_encrypt_final()))
    }
}

/// Adapts [`AsconAead128`]'s decrypting direction to [`AEADCipherDecryptor`] and, through it,
/// [`SymmetricCipherDecryptor`]; see the module docs for why this is a thin wrapper rather than a
/// change to `AsconAead128` itself.
///
/// Unlike the inherent API this does hold data back: the last `TAG_LEN` bytes of ciphertext it has
/// seen, since until the stream ends it cannot know whether they are the inline tag
/// ([`SymmetricCipherDecryptor::do_final`]) or ciphertext with the tag carried separately
/// ([`AEADCipherDecryptor::do_final_out_detached`]). They are ciphertext, not plaintext, so they need
/// no [`Secret`] wrapper.
pub struct AsconAead128Decryptor {
    cipher: AsconAead128,
    // The most recent `held_len` bytes of ciphertext, not yet given to `cipher`.
    held: [u8; TAG_LEN],
    // Always `min(TAG_LEN, total ciphertext seen)`.
    held_len: usize,
}

impl Algorithm for AsconAead128Decryptor {
    const ALG_NAME: &'static str = AsconAead128::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = AsconAead128::MAX_SECURITY_STRENGTH;
}

impl SymmetricCipherDecryptor<KEY_LEN, NONCE_LEN, TAG_LEN> for AsconAead128Decryptor {
    fn do_decrypt_init(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Self, SymmetricCipherError> {
        Ok(Self {
            cipher: AsconAead128::new(key, nonce, None, false)?,
            held: [0u8; TAG_LEN],
            held_len: 0,
        })
    }

    /// Everything but the last `TAG_LEN` bytes seen so far is released.
    fn update_out_len(&self, input_len: usize) -> usize {
        (self.held_len + input_len).saturating_sub(TAG_LEN)
    }

    fn do_update_out(
        &mut self,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        let release = self.update_out_len(ciphertext.len());
        if plaintext.len() < release {
            return Err(SymmetricCipherError::OutputBufferTooSmall(release));
        }
        // The oldest bytes go first: the held-back ones, then the front of `ciphertext`.
        let from_held = release.min(self.held_len);
        let from_input = release - from_held;
        let out = &mut plaintext[..release];
        out[..from_held].copy_from_slice(&self.held[..from_held]);
        out[from_held..].copy_from_slice(&ciphertext[..from_input]);
        // Called even when `release` is 0: that is what ends the AAD phase in `cipher`, so a
        // later non-empty `do_update_aad` is refused however little ciphertext has been seen.
        self.cipher.do_decrypt_update(out);
        // Keep the newest `TAG_LEN` (or fewer) bytes: what is left of `held`, then the tail of
        // `ciphertext`.
        let kept = self.held_len - from_held;
        self.held.copy_within(from_held..self.held_len, 0);
        let new_len = kept + ciphertext.len() - from_input;
        self.held[kept..new_len].copy_from_slice(&ciphertext[from_input..]);
        self.held_len = new_len;
        Ok(release)
    }

    /// The inline layout: the held-back bytes are the tag, so there is no plaintext left to
    /// release.
    ///
    /// # Errors
    /// [`SymmetricCipherError::DecryptionFailed`] if fewer than `TAG_LEN` bytes were seen in all;
    /// [`SymmetricCipherError::AEADTagCheckFailed`] if the tag does not verify.
    fn do_final(self) -> Result<([u8; TAG_LEN], usize), SymmetricCipherError> {
        if self.held_len < TAG_LEN {
            return Err(SymmetricCipherError::DecryptionFailed);
        }
        self.cipher.do_decrypt_final(&self.held)?;
        Ok(([0u8; TAG_LEN], 0))
    }

    /// Everything but the trailing tag.
    fn decrypt_out_max_len(ciphertext_len: usize) -> usize {
        ciphertext_len.saturating_sub(TAG_LEN)
    }
}

impl AEADCipherDecryptor<KEY_LEN, NONCE_LEN, TAG_LEN, TAG_LEN> for AsconAead128Decryptor {
    /// # Errors
    /// [`SymmetricCipherError::StateError`] if `aad` is non-empty and
    /// [`SymmetricCipherDecryptor::do_update_out`] has already been called.
    fn do_update_aad(&mut self, aad: &[u8]) -> Result<(), SymmetricCipherError> {
        self.cipher.do_update_aad(aad)
    }

    /// The held-back bytes are ciphertext: decrypts them into `plaintext`, then checks `tag`. On a
    /// failed check `plaintext` is zeroized, so the error leaves nothing unauthenticated behind in
    /// it (what earlier `do_update_out` calls released is the caller's to scrub).
    fn do_final_out_detached(
        mut self,
        tag: &[u8; TAG_LEN],
        plaintext: &mut [u8; TAG_LEN],
    ) -> Result<usize, SymmetricCipherError> {
        let n = self.held_len;
        plaintext[..n].copy_from_slice(&self.held[..n]);
        self.cipher.do_decrypt_update(&mut plaintext[..n]);
        if let Err(e) = self.cipher.do_decrypt_final(tag) {
            plaintext.fill(0);
            return Err(e);
        }
        Ok(n)
    }
}

/// Projects a direction marker onto the Ascon-AEAD128 type for that direction, which is what lets
/// [`Ascon_AEAD128`] take its direction as a parameter: a plain type alias cannot choose between two
/// distinct types, so it is written as a projection through this trait instead.
///
/// Implemented for [`Encrypting`] and [`Decrypting`] and for nothing else, so those are the only
/// usable values of `Dir`.
pub trait AsconAead128Mode {
    /// [`AsconAead128Encryptor`] or [`AsconAead128Decryptor`].
    type Mode;
}

impl AsconAead128Mode for Encrypting {
    type Mode = AsconAead128Encryptor;
}

impl AsconAead128Mode for Decrypting {
    type Mode = AsconAead128Decryptor;
}

/// Ascon-AEAD128 (NIST SP 800-232), spelled as the specification spells it, in one direction:
/// `Ascon_AEAD128<Encrypting>` is [`AsconAead128Encryptor`] and `Ascon_AEAD128<Decrypting>` is
/// [`AsconAead128Decryptor`]. The wrong direction is a compile error, not a runtime check, and the
/// nonce is generated by encryption and returned, never supplied.
///
/// Both directions implement [`AEADCipherEncryptor`] / [`AEADCipherDecryptor`] and, through them,
/// [`SymmetricCipherEncryptor`] / [`SymmetricCipherDecryptor`] -- which is the AEAD with no
/// associated data and the tag inline:
///
/// ```
/// use bouncycastle_ascon::Ascon_AEAD128;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::traits::{SymmetricCipherDecryptor, SymmetricCipherEncryptor};
/// use bouncycastle_modes::{Decrypting, Encrypting};
///
/// type Enc = Ascon_AEAD128<Encrypting>;
/// type Dec = Ascon_AEAD128<Decrypting>;
///
/// let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
///     .expect("a 16-byte symmetric cipher key");
///
/// let message = b"hello";
/// let mut ciphertext = [0u8; 5 + 16]; // Enc::encrypt_out_len(5): ciphertext || tag
/// let (nonce, written) = Enc::encrypt_out(&key, message, &mut ciphertext).expect("encryption");
/// assert_eq!(written, 21);
///
/// let mut plaintext = [0u8; 5]; // Dec::decrypt_out_max_len(21)
/// let n = Dec::decrypt_out(&key, &nonce, &ciphertext, &mut plaintext).expect("decryption");
/// assert_eq!(&plaintext[..n], message);
/// ```
#[allow(non_camel_case_types)]
pub type Ascon_AEAD128<Dir> = <Dir as AsconAead128Mode>::Mode;

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
/// || 1-byte byte position within the current rate block || 1-byte call-state/direction.
/// The secret key is **not** serialized; it is re-supplied to [`SuspendableKeyed::from_suspended`].
pub const SUSPENDED_ASCON_AEAD128_STATE_LEN: usize = 46;

const AEAD128_STATE_TAG: u8 = 0x04;

impl SuspendableKeyed<SUSPENDED_ASCON_AEAD128_STATE_LEN> for AsconAead128 {
    // The 128-bit key must be re-supplied when resuming; it is never part of the serialized state,
    // and is re-validated exactly as `new()` validates it.
    type Key = KeyMaterial<KEY_LEN>;

    fn suspend(self) -> [u8; SUSPENDED_ASCON_AEAD128_STATE_LEN] {
        let mut out_to_return = [0u8; SUSPENDED_ASCON_AEAD128_STATE_LEN];
        // infallible: add_lib_ver returns a slice of exactly SUSPENDED_ASCON_AEAD128_STATE_LEN - 3 = 43 bytes.
        let out: &mut [u8; SUSPENDED_ASCON_AEAD128_STATE_LEN - 3] =
            add_lib_ver(&mut out_to_return).try_into().unwrap();

        out[0] = AEAD128_STATE_TAG;
        for i in 0..5 {
            out[1 + i * 8..1 + i * 8 + 8].copy_from_slice(&self.state[i].to_le_bytes());
        }
        debug_assert!(self.pos < RATE);
        out[41] = self.pos as u8;
        out[42] = self.state_machine.to_u8();

        out_to_return
    }

    fn from_suspended(
        serialized_state: [u8; SUSPENDED_ASCON_AEAD128_STATE_LEN],
        key: &Self::Key,
    ) -> Result<Self, SuspendableError> {
        // infallible: check_lib_ver returns a slice of exactly SUSPENDED_ASCON_AEAD128_STATE_LEN - 3 = 43 bytes.
        let input: &[u8; SUSPENDED_ASCON_AEAD128_STATE_LEN - 3] =
            check_lib_ver(&serialized_state, None)?.try_into().unwrap();

        if input[0] != AEAD128_STATE_TAG {
            return Err(SuspendableError::InvalidData);
        }
        let mut s = Secret::<AsconState>::new();
        for i in 0..5 {
            // infallible: each slice is exactly 8 bytes (1+i*8..1+i*8+8) by construction.
            s[i] = u64::from_le_bytes(input[1 + i * 8..1 + i * 8 + 8].try_into().unwrap());
        }
        let pos = input[41] as usize;
        if pos >= RATE {
            return Err(SuspendableError::InvalidData);
        }
        let state_machine =
            StateMachine::from_u8(input[42]).ok_or(SuspendableError::InvalidData)?;
        // A nonzero byte position implies at least one AAD/data byte has already been absorbed
        // into the current rate block, which is only possible once the *Aad or *Data phase has
        // begun -- never while still in *Init.
        if pos != 0 && state_machine.is_init() {
            return Err(SuspendableError::InvalidData);
        }

        let key_words = Self::checked_key(key).map_err(|_| SuspendableError::InvalidData)?;
        let mut key_secret = Secret::<[u64; 2]>::new();
        *key_secret = key_words;

        Ok(AsconAead128 { key: key_secret, state: s, pos, state_machine })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // StateMachine is private, so its to_u8/from_u8 round trip -- exercised end-to-end via
    // suspend/resume in tests/aead128_tests.rs for the states reachable there -- is pinned
    // directly here for every discriminant, including ones a successful resume never needs to
    // decode into (EncInit/EncAad/DecInit/DecAad never survive to be the *end* state of a
    // still-running cipher in the integration tests, since further processing always advances
    // them to *Data).
    #[test]
    fn state_machine_u8_round_trip() {
        let all = [
            StateMachine::EncInit,
            StateMachine::EncAad,
            StateMachine::EncData,
            StateMachine::DecInit,
            StateMachine::DecAad,
            StateMachine::DecData,
        ];
        for s in all {
            assert_eq!(StateMachine::from_u8(s.to_u8()), Some(s), "round trip failed for {s:?}");
        }
        // Unassigned discriminants (3 and 7 are deliberately skipped by to_u8's encoding) must
        // be rejected, not silently mapped to a variant.
        for v in [3u8, 7, 200] {
            assert_eq!(StateMachine::from_u8(v), None, "discriminant {v} must be rejected");
        }
    }
}
