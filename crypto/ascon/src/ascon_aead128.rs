//! Ascon-AEAD128 authenticated encryption, as specified in NIST SP 800-232 §4.
//!
//! Rate = 128 bits, capacity = 192 bits, 128-bit key/nonce/tag. Initialization and finalization use
//! `Ascon-p[12]`; associated-data and plaintext/ciphertext blocks use `Ascon-p[8]`.
//!
//! Every byte of plaintext/ciphertext is transformed and emitted as soon as it is seen (no
//! held-back buffering across update calls); this is what lets the cipher's finalizers be plain
//! `self -> tag` / `self -> Result<(), _>` calls with nothing left to flush.
//! Ascon-AEAD128 permits this because within a 128-bit rate block each plaintext/ciphertext byte
//! is transformed independently of the others in that block; the permutation only runs once a
//! full 16-byte block has been absorbed, or at finalization.
//!
//! [`Ascon_AEAD128<Encrypting>`](Ascon_AEAD128) / [`Ascon_AEAD128<Decrypting>`](Ascon_AEAD128) is
//! the cipher with the direction in its type, implementing [`AEADCipherEncryptor`] /
//! [`AEADCipherDecryptor`] and the symmetric-cipher traits they extend, plus an in-place pair.
//! The decrypting side holds back the trailing tag until the final; the cipher core underneath
//! emits every byte as it is seen.

use core::fmt::{self, Debug, Display, Formatter};

use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::errors::{KeyMaterialError, SuspendableError, SymmetricCipherError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{AeadDecryptionKey, AeadEncryptionKey, FromKeyMaterial};
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, Algorithm, RNG, SuspendableKeyed,
    SymmetricCipherDecryptor, SymmetricCipherEncryptor,
};
use bouncycastle_utils::ct::ct_eq_bytes;
use bouncycastle_utils::secret::Secret;
use bouncycastle_utils::suspendable_state::{add_lib_ver, check_lib_ver};
use core::marker::PhantomData;

use crate::ASCON_AEAD128_NAME;
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

/// Where the call sequence is: nothing absorbed yet, absorbing associated data, or absorbing
/// plaintext/ciphertext. The direction is not here; it is the type parameter of [`Ascon_AEAD128`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    Init,
    Aad,
    Data,
}

impl Phase {
    // Stable encoding of the low bits of the suspended call-state byte; the direction supplies
    // the rest (see `ENC_DIR_BITS` / `DEC_DIR_BITS`).
    fn to_u8(self) -> u8 {
        match self {
            Phase::Init => 0,
            Phase::Aad => 1,
            Phase::Data => 2,
        }
    }

    fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Phase::Init,
            1 => Phase::Aad,
            2 => Phase::Data,
            _ => return None,
        })
    }
}

/// Ascon-AEAD128 (NIST SP 800-232), spelled as the specification spells it, in one direction:
/// `Dir` is [`Encrypting`] or [`Decrypting`], and only that direction's methods exist on the type,
/// so the wrong direction is a compile error. One instance performs one operation under one
/// (key, nonce) pair.
///
/// Both directions are made by [`AsconAEAD128Key`], and implement [`AEADCipherEncryptor`] /
/// [`AEADCipherDecryptor`] and, through them, [`SymmetricCipherEncryptor`] /
/// [`SymmetricCipherDecryptor`] -- which is the AEAD with no associated data and the tag inline:
///
/// ```
/// use bouncycastle_ascon::{Ascon_AEAD128, AsconAEAD128Key};
/// use bouncycastle_cipher::{Decrypting, Encrypting};
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::symmetric_key::{AeadDecryptionKey, AeadEncryptionKey, FromKeyMaterial};
/// use bouncycastle_core::traits::{SymmetricCipherDecryptor, SymmetricCipherEncryptor};
/// use bouncycastle_rng::HashDRBG_SHA512;
///
/// type Enc = Ascon_AEAD128<Encrypting>;
/// type Dec = Ascon_AEAD128<Decrypting>;
///
/// let material = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
///     .expect("a 16-byte symmetric cipher key");
/// let key = AsconAEAD128Key::from_key_material(&material).expect("a valid key");
///
/// let message = b"hello";
/// let (mut enc, nonce) = key.create_encryptor(&mut HashDRBG_SHA512::new_from_os()).unwrap();
/// let mut ciphertext = [0u8; 5 + 16]; // Enc::encrypt_out_len(5): ciphertext || tag
/// let written = enc.do_encrypt_out(message, &mut ciphertext).expect("encryption");
/// let (tag, tag_len) = enc.do_encrypt_final().expect("the tag");
/// ciphertext[written..].copy_from_slice(&tag[..tag_len]);
///
/// let mut dec = key.create_decryptor(&nonce);
/// let mut plaintext = [0u8; 5]; // Dec::decrypt_out_len(21)
/// let n = dec.do_decrypt_out(&ciphertext, &mut plaintext).expect("decryption");
/// dec.do_decrypt_final().expect("the tag verifies");
/// assert_eq!(&plaintext[..n], message);
/// ```
///
/// The encrypting side implements [`AEADCipherEncryptor`] and [`SymmetricCipherEncryptor`]; the
/// nonce is drawn by the key's `create_encryptor` and returned, or supplied to
/// `create_encryptor_nonce` by a caller who takes on its uniqueness. `FINAL_LEN` is `TAG_LEN`:
/// nothing is held back, so the
/// inline [`SymmetricCipherEncryptor::do_encrypt_final`] writes only the tag, and the detached
/// [`AEADCipherEncryptor::do_encrypt_final_detached_out`] only zeroes its buffer.
///
/// The decrypting side implements [`AEADCipherDecryptor`] and [`SymmetricCipherDecryptor`]. The
/// cipher emits every byte as it is seen, but this side holds back the last `TAG_LEN` bytes of
/// ciphertext, since until the stream ends it cannot know whether they are the inline tag
/// ([`SymmetricCipherDecryptor::do_decrypt_final`]) or ciphertext with the tag carried separately
/// ([`AEADCipherDecryptor::do_decrypt_final_detached_out`]). They are ciphertext, not plaintext,
/// so they need no [`Secret`] wrapper; the encrypting side carries the same fields unused.
///
/// ```compile_fail
/// # use bouncycastle_ascon::AsconAEAD128Key;
/// # use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// # use bouncycastle_core::symmetric_key::{AeadDecryptionKey, FromKeyMaterial};
/// # use bouncycastle_core::traits::{SymmetricCipherDecryptor, SymmetricCipherEncryptor};
/// # let material = KeyMaterial::<16>::from_bytes_as_type(&[7; 16], KeyType::SymmetricCipherKey).unwrap();
/// # let key = AsconAEAD128Key::from_key_material(&material).unwrap();
/// let mut dec = key.create_decryptor(&[0u8; 16]);
/// dec.do_encrypt_out(&[0u8; 4], &mut [0u8; 4]);   // no such method on the decrypting type
/// ```
#[allow(non_camel_case_types)]
pub struct Ascon_AEAD128<Dir> {
    // 128-bit secret key (two 64-bit words). It is re-added to the state at finalization, so it must
    // be retained; wrapped in `Secret` for volatile-write zeroization on drop.
    key: Secret<[u64; 2]>,
    // 320-bit internal state (five 64-bit words). Carries keystream/plaintext-derived material, so
    // it is likewise wrapped in `Secret`.
    state: Secret<AsconState>,
    // Byte position (0..RATE) within the current rate block.
    pos: usize,
    // Where the call sequence is, for enforcing the call order.
    phase: Phase,
    /// Decrypting only: the most recent `held_len` bytes of ciphertext, not yet given to the
    /// cipher. Always `min(TAG_LEN, total ciphertext seen)`.
    held: [u8; TAG_LEN],
    held_len: usize,
    _dir: PhantomData<Dir>,
}

// Written out rather than derived so that `Dir`, a marker type, need not be `Clone`.
impl<Dir> Clone for Ascon_AEAD128<Dir> {
    fn clone(&self) -> Self {
        Self {
            key: self.key.clone(),
            state: self.state.clone(),
            pos: self.pos,
            phase: self.phase,
            held: self.held,
            held_len: self.held_len,
            _dir: PhantomData,
        }
    }
}

impl<Dir> Ascon_AEAD128<Dir> {
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

    /// Step 1 from already-validated key words: what [`AsconAEAD128Key`] calls per message.
    fn from_key_words(key_words: &[u64; 2], nonce: &[u8; NONCE_LEN]) -> Self {
        let mut key_secret: Secret<[u64; 2]> = Secret::new();
        *key_secret = *key_words;

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

        Ascon_AEAD128 {
            key: key_secret,
            state,
            pos: 0,
            phase: Phase::Init,
            held: [0u8; TAG_LEN],
            held_len: 0,
            _dir: PhantomData,
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
        match self.phase {
            Phase::Init => self.phase = Phase::Aad,
            Phase::Aad => {}
            Phase::Data => {
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
        if self.phase == Phase::Aad {
            self.xor_state_byte(self.pos, 0x01);
            p8(&mut self.state);
            self.pos = 0;
        }
        // Domain separation (Eq. 22/40: S ^= (0^319 || 1)).
        self.state[4] ^= 0x8000000000000000;
        self.phase = Phase::Data;
    }

    fn check_data(&mut self) {
        if self.phase != Phase::Data {
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
    fn absorb_aad(&mut self, input: &[u8]) -> Result<(), SymmetricCipherError> {
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
}

impl Ascon_AEAD128<Encrypting> {
    /// Encrypt `data` in place (SP 800-232 §4.1.1 step 3). Every byte is transformed and emitted
    /// immediately; nothing is buffered across calls.
    fn encrypt_bytes(&mut self, data: &mut [u8]) {
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
    /// plaintext/ciphertext byte was already written by `encrypt_bytes`.
    fn finish_tag(mut self) -> [u8; TAG_LEN] {
        self.check_data();
        // Padding of the final (possibly empty) plaintext block (Eq. 27).
        self.xor_state_byte(self.pos, 0x01);
        self.finish_data()
    }
}

impl Ascon_AEAD128<Decrypting> {
    /// Decrypt `data` in place (SP 800-232 §4.1.2 step 3). Every byte is transformed and emitted
    /// immediately; the plaintext is **not** authenticated until `verify_tag` returns `Ok`.
    fn decrypt_bytes(&mut self, data: &mut [u8]) {
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
    fn verify_tag(mut self, tag: &[u8; TAG_LEN]) -> Result<(), SymmetricCipherError> {
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

impl<Dir> Algorithm for Ascon_AEAD128<Dir> {
    const ALG_NAME: &'static str = ASCON_AEAD128_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

impl SymmetricCipherEncryptor<NONCE_LEN, TAG_LEN> for Ascon_AEAD128<Encrypting> {
    /// Ascon-AEAD128 never buffers: every byte given is a byte returned.
    fn do_encrypt_out_len(&self, input_len: usize) -> usize {
        input_len
    }

    fn do_encrypt_out(
        &mut self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        ciphertext.fill(0);
        if ciphertext.len() < plaintext.len() {
            return Err(SymmetricCipherError::OutputBufferTooSmall(plaintext.len()));
        }
        let out = &mut ciphertext[..plaintext.len()];
        out.copy_from_slice(plaintext);
        self.encrypt_bytes(out);
        Ok(plaintext.len())
    }

    /// The inline layout: nothing is held back, so the final buffer is exactly the tag.
    fn do_encrypt_final(self) -> Result<([u8; TAG_LEN], usize), SymmetricCipherError> {
        Ok((self.finish_tag(), TAG_LEN))
    }

    /// The ciphertext, which is as long as the plaintext, followed by the tag.
    fn encrypt_out_len(plaintext_len: usize) -> usize {
        plaintext_len + TAG_LEN
    }
}

impl AEADCipherEncryptor<NONCE_LEN, TAG_LEN, TAG_LEN> for Ascon_AEAD128<Encrypting> {
    fn do_update_aad(&mut self, aad: &[u8]) -> Result<(), SymmetricCipherError> {
        self.absorb_aad(aad)
    }

    /// Nothing is ever held back to flush, so `ciphertext` is left zeroed.
    fn do_encrypt_final_detached_out(
        self,
        ciphertext: &mut [u8; TAG_LEN],
    ) -> Result<(usize, [u8; TAG_LEN]), SymmetricCipherError> {
        ciphertext.fill(0);
        Ok((0, self.finish_tag()))
    }
}

impl SymmetricCipherDecryptor<NONCE_LEN, TAG_LEN> for Ascon_AEAD128<Decrypting> {
    /// Everything but the last `TAG_LEN` bytes seen so far is released.
    fn do_decrypt_out_len(&self, input_len: usize) -> usize {
        (self.held_len + input_len).saturating_sub(TAG_LEN)
    }

    fn do_decrypt_out(
        &mut self,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        plaintext.fill(0);
        let release = self.do_decrypt_out_len(ciphertext.len());
        if plaintext.len() < release {
            return Err(SymmetricCipherError::OutputBufferTooSmall(release));
        }
        // The oldest bytes go first: the held-back ones, then the front of `ciphertext`.
        let from_held = release.min(self.held_len);
        let from_input = release - from_held;
        let out = &mut plaintext[..release];
        out[..from_held].copy_from_slice(&self.held[..from_held]);
        out[from_held..].copy_from_slice(&ciphertext[..from_input]);
        // Called even when `release` is 0: that is what ends the AAD phase, so a later non-empty
        // `do_update_aad` is refused however little ciphertext has been seen.
        self.decrypt_bytes(out);
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
    fn do_decrypt_final(self) -> Result<([u8; TAG_LEN], usize), SymmetricCipherError> {
        if self.held_len < TAG_LEN {
            return Err(SymmetricCipherError::DecryptionFailed);
        }
        let tag = self.held;
        self.verify_tag(&tag)?;
        Ok(([0u8; TAG_LEN], 0))
    }

    /// Everything but the trailing tag.
    fn decrypt_out_len(ciphertext_len: usize) -> usize {
        ciphertext_len.saturating_sub(TAG_LEN)
    }
}

impl AEADCipherDecryptor<NONCE_LEN, TAG_LEN, TAG_LEN> for Ascon_AEAD128<Decrypting> {
    /// # Errors
    /// [`SymmetricCipherError::StateError`] if `aad` is non-empty and
    /// [`SymmetricCipherDecryptor::do_decrypt_out`] has already been called.
    fn do_update_aad(&mut self, aad: &[u8]) -> Result<(), SymmetricCipherError> {
        self.absorb_aad(aad)
    }

    /// The held-back bytes are ciphertext: decrypts them into `plaintext`, then checks `tag`. On a
    /// failed check `plaintext` is zeroized, so the error leaves nothing unauthenticated behind in
    /// it (what earlier `do_update_out` calls released is the caller's to scrub).
    fn do_decrypt_final_detached_out(
        mut self,
        tag: &[u8; TAG_LEN],
        plaintext: &mut [u8; TAG_LEN],
    ) -> Result<usize, SymmetricCipherError> {
        plaintext.fill(0);
        let n = self.held_len;
        plaintext[..n].copy_from_slice(&self.held[..n]);
        self.decrypt_bytes(&mut plaintext[..n]);
        if let Err(e) = self.verify_tag(tag) {
            plaintext.fill(0);
            return Err(e);
        }
        Ok(n)
    }
}

impl Ascon_AEAD128<Encrypting> {
    /// Encrypts `data` in place: every byte is replaced by its ciphertext as it is seen and
    /// nothing is held back, so a message can stream through one buffer. The tag comes from the
    /// final as usual; this is the in-place twin of
    /// [`SymmetricCipherEncryptor::do_encrypt_out`].
    pub fn do_encrypt_inplace(&mut self, data: &mut [u8]) {
        self.encrypt_bytes(data);
    }
}

impl Ascon_AEAD128<Decrypting> {
    /// Decrypts in place, in one buffer: the in-place twin of
    /// [`SymmetricCipherDecryptor::do_decrypt_out`], with the same hold-back. The plaintext
    /// released by this call, the oldest `(held + data.len()) - TAG_LEN` bytes of ciphertext seen
    /// so far, is written to the front of `data` and its length returned; the newest `TAG_LEN`
    /// bytes are held back for the final, so either final can follow. Whatever is in `data` past
    /// the returned count is not plaintext.
    pub fn do_decrypt_inplace(&mut self, data: &mut [u8]) -> usize {
        let release = self.do_decrypt_out_len(data.len());
        let from_held = release.min(self.held_len);
        let from_input = release - from_held;

        // The bytes to hold back after this call: what is left of `held`, then the tail of
        // `data`, saved before the shift below overwrites the tail.
        let kept = self.held_len - from_held;
        let input_kept = data.len() - from_input;
        let mut new_held = [0u8; TAG_LEN];
        new_held[..kept].copy_from_slice(&self.held[from_held..self.held_len]);
        new_held[kept..kept + input_kept].copy_from_slice(&data[from_input..]);

        // The released ciphertext, oldest first, assembled at the front of `data`: the front of
        // the input moves right to make room for the held-back bytes ahead of it.
        data.copy_within(..from_input, from_held);
        data[..from_held].copy_from_slice(&self.held[..from_held]);
        // Called even when `release` is 0, which is what ends the AAD phase.
        self.decrypt_bytes(&mut data[..release]);

        self.held = new_held;
        self.held_len = kept + input_kept;
        release
    }
}

/// An Ascon-AEAD128 key: the 128-bit key validated once, from which the encryptors and
/// decryptors for each message are made. The key words live in a [`Secret`], zeroized on drop;
/// there is no `Debug` and no way to read them back.
///
/// ```
/// use bouncycastle_ascon::AsconAEAD128Key;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::symmetric_key::{AeadDecryptionKey, AeadEncryptionKey, FromKeyMaterial};
/// use bouncycastle_rng::HashDRBG_SHA512;
///
/// let mut rng = HashDRBG_SHA512::new_from_os();
/// let material = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
///     .expect("a 16-byte symmetric cipher key");
/// let key = AsconAEAD128Key::from_key_material(&material).expect("a valid Ascon-AEAD128 key");
///
/// // The nonce is drawn from `rng` and returned with the ciphertext; the tag is detached.
/// let (nonce, ciphertext, tag) = key.encrypt_detached(&mut rng, b"header", b"attack at dawn").unwrap();
/// let plaintext = key.decrypt_detached(&nonce, b"header", &ciphertext, &tag).unwrap();
/// assert_eq!(plaintext, b"attack at dawn");
/// ```
#[allow(non_camel_case_types)]
pub struct AsconAEAD128Key {
    key: Secret<[u64; 2]>,
}

impl Clone for AsconAEAD128Key {
    fn clone(&self) -> Self {
        Self { key: self.key.clone() }
    }
}

// `Secret`'s equality: every byte is inspected, so the time taken does not say where two keys
// differ.
impl PartialEq for AsconAEAD128Key {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl Eq for AsconAEAD128Key {}

impl FromKeyMaterial<KEY_LEN> for AsconAEAD128Key {
    const KEY_TYPE: KeyType = KeyType::SymmetricCipherKey;

    /// # Errors
    /// * [`KeyMaterialError::InvalidKeyType`] if the key is not a `SymmetricCipherKey`, or is
    ///   bound to another algorithm (`KeyMaterialTrait::set_algorithm`).
    /// * [`KeyMaterialError::InvalidLength`] if the key is not 16 bytes long.
    /// * [`KeyMaterialError::SecurityStrength`] if the key carries a strength below 128 bits.
    fn from_key_material(key: &KeyMaterial<KEY_LEN>) -> Result<Self, SymmetricCipherError> {
        let mut key_secret: Secret<[u64; 2]> = Secret::new();
        *key_secret = Ascon_AEAD128::<Encrypting>::checked_key(key)?;
        Ok(Self { key: key_secret })
    }
}

impl AeadEncryptionKey<KEY_LEN, NONCE_LEN, TAG_LEN, TAG_LEN> for AsconAEAD128Key {
    type Encryptor<'k>
        = Ascon_AEAD128<Encrypting>
    where
        Self: 'k;

    /// # Errors
    /// [`SymmetricCipherError::RNGError`] if the nonce draw fails; nothing else can.
    fn create_encryptor<'k>(
        &'k self,
        rng: &mut dyn RNG,
    ) -> Result<(Self::Encryptor<'k>, [u8; NONCE_LEN]), SymmetricCipherError> {
        let mut nonce = [0u8; NONCE_LEN];
        rng.next_bytes_out(&mut nonce)?;
        Ok((Ascon_AEAD128::from_key_words(&self.key, &nonce), nonce))
    }

    /// Under a nonce the caller supplies, who takes on the obligation that it never repeat
    /// under this key (SP 800-232 R3).
    fn create_encryptor_nonce<'k>(&'k self, nonce: &[u8; NONCE_LEN]) -> Self::Encryptor<'k> {
        Ascon_AEAD128::from_key_words(&self.key, nonce)
    }
}

impl AeadDecryptionKey<KEY_LEN, NONCE_LEN, TAG_LEN, TAG_LEN> for AsconAEAD128Key {
    type Decryptor<'k>
        = Ascon_AEAD128<Decrypting>
    where
        Self: 'k;

    fn create_decryptor<'k>(&'k self, nonce: &[u8; NONCE_LEN]) -> Self::Decryptor<'k> {
        Ascon_AEAD128::from_key_words(&self.key, nonce)
    }
}

impl<Dir> Debug for Ascon_AEAD128<Dir> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Ascon-AEAD128 (key/state masked)")
    }
}

impl<Dir> Display for Ascon_AEAD128<Dir> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Ascon-AEAD128 (key/state masked)")
    }
}

/// Length in bytes of the serialized state of `Ascon_AEAD128<Encrypting>`:
/// 3-byte library version || 1-byte state tag || 40-byte permutation state (5 × u64 LE)
/// || 1-byte byte position within the current rate block || 1-byte call-state/direction.
/// The secret key is **not** serialized; it is re-supplied to [`SuspendableKeyed::from_suspended`].
pub const SUSPENDED_ASCON_AEAD128_ENCRYPTOR_STATE_LEN: usize = CIPHER_STATE_LEN;

/// Length in bytes of the serialized state of `Ascon_AEAD128<Decrypting>`: the encrypting
/// side's layout, then the up to `TAG_LEN` bytes it holds back and their count.
pub const SUSPENDED_ASCON_AEAD128_DECRYPTOR_STATE_LEN: usize = CIPHER_STATE_LEN + TAG_LEN + 1;

/// The cipher core's serialized state: the whole of the encrypting side's and the head of the
/// decrypting side's.
const CIPHER_STATE_LEN: usize = 46;

/// The byte after the library version that marks a suspended state as Ascon-AEAD128's;
/// `from_suspended` rejects any other value as [`SuspendableError::InvalidData`]. This is a
/// bc-rust serialization tag, not an SP 800-232 value (its Table 13 identifies Ascon-AEAD128 as
/// `v = 1`). The crate's tags are unique: Ascon-Hash256 0x01, Ascon-XOF128 0x02,
/// Ascon-CXOF128 0x03, Ascon-AEAD128 0x04. Never renumber one, or older states are misread.
const AEAD128_STATE_TAG: u8 = 0x04;

/// The direction's part of the suspended call-state byte, with the [`Phase`] in the low two
/// bits: `0..=2` encrypting, `4..=6` decrypting. The encoding predates the direction being in
/// the type; never renumber it, or older states are misread.
const ENC_DIR_BITS: u8 = 0;
const DEC_DIR_BITS: u8 = 4;

impl<'k> SuspendableKeyed<'k, SUSPENDED_ASCON_AEAD128_ENCRYPTOR_STATE_LEN>
    for Ascon_AEAD128<Encrypting>
{
    // The key is never part of the serialized state; the key object the worker was made from is
    // re-supplied, already validated.
    type Key = AsconAEAD128Key;

    fn suspend(self) -> [u8; SUSPENDED_ASCON_AEAD128_ENCRYPTOR_STATE_LEN] {
        self.suspend_as(ENC_DIR_BITS)
    }

    /// A state suspended by the decrypting side is [`SuspendableError::InvalidData`] here.
    fn from_suspended(
        serialized_state: [u8; SUSPENDED_ASCON_AEAD128_ENCRYPTOR_STATE_LEN],
        key: &'k Self::Key,
    ) -> Result<Self, SuspendableError> {
        Self::resume_as(serialized_state, key, ENC_DIR_BITS)
    }
}

/// The core's state, then the held-back bytes and their count; see
/// [`SUSPENDED_ASCON_AEAD128_DECRYPTOR_STATE_LEN`].
impl<'k> SuspendableKeyed<'k, SUSPENDED_ASCON_AEAD128_DECRYPTOR_STATE_LEN>
    for Ascon_AEAD128<Decrypting>
{
    type Key = AsconAEAD128Key;

    fn suspend(self) -> [u8; SUSPENDED_ASCON_AEAD128_DECRYPTOR_STATE_LEN] {
        let mut out = [0u8; SUSPENDED_ASCON_AEAD128_DECRYPTOR_STATE_LEN];
        out[CIPHER_STATE_LEN..CIPHER_STATE_LEN + TAG_LEN].copy_from_slice(&self.held);
        debug_assert!(self.held_len <= TAG_LEN);
        out[CIPHER_STATE_LEN + TAG_LEN] = self.held_len as u8;
        out[..CIPHER_STATE_LEN].copy_from_slice(&self.suspend_as(DEC_DIR_BITS));
        out
    }

    /// A state suspended by the encrypting side, or a held-back count above `TAG_LEN`, is
    /// [`SuspendableError::InvalidData`].
    fn from_suspended(
        serialized_state: [u8; SUSPENDED_ASCON_AEAD128_DECRYPTOR_STATE_LEN],
        key: &'k Self::Key,
    ) -> Result<Self, SuspendableError> {
        // infallible: the slice is exactly CIPHER_STATE_LEN bytes by construction.
        let cipher_state: [u8; CIPHER_STATE_LEN] =
            serialized_state[..CIPHER_STATE_LEN].try_into().unwrap();
        let mut dec = Self::resume_as(cipher_state, key, DEC_DIR_BITS)?;
        dec.held.copy_from_slice(&serialized_state[CIPHER_STATE_LEN..CIPHER_STATE_LEN + TAG_LEN]);
        dec.held_len = serialized_state[CIPHER_STATE_LEN + TAG_LEN] as usize;
        if dec.held_len > TAG_LEN {
            return Err(SuspendableError::InvalidData);
        }
        Ok(dec)
    }
}

impl<Dir> Ascon_AEAD128<Dir> {
    /// The body of both directions' [`SuspendableKeyed::suspend`]; `dir_bits` marks the direction.
    fn suspend_as(self, dir_bits: u8) -> [u8; CIPHER_STATE_LEN] {
        let mut out_to_return = [0u8; CIPHER_STATE_LEN];
        // infallible: add_lib_ver returns a slice of exactly CIPHER_STATE_LEN - 3 = 43 bytes.
        let out: &mut [u8; CIPHER_STATE_LEN - 3] =
            add_lib_ver(&mut out_to_return).try_into().unwrap();

        out[0] = AEAD128_STATE_TAG;
        for i in 0..5 {
            out[1 + i * 8..1 + i * 8 + 8].copy_from_slice(&self.state[i].to_le_bytes());
        }
        debug_assert!(self.pos < RATE);
        out[41] = self.pos as u8;
        out[42] = dir_bits | self.phase.to_u8();

        out_to_return
    }

    /// The body of both directions' [`SuspendableKeyed::from_suspended`]: a call-state byte whose
    /// direction is not `dir_bits` is refused, so a state never resumes in the other direction.
    fn resume_as(
        serialized_state: [u8; CIPHER_STATE_LEN],
        key: &AsconAEAD128Key,
        dir_bits: u8,
    ) -> Result<Self, SuspendableError> {
        // infallible: check_lib_ver returns a slice of exactly CIPHER_STATE_LEN - 3 = 43 bytes.
        let input: &[u8; CIPHER_STATE_LEN - 3] =
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
        // The phase is the low two bits; everything above them must be exactly this direction.
        if input[42] & !0x03 != dir_bits {
            return Err(SuspendableError::InvalidData);
        }
        let phase = Phase::from_u8(input[42] & 0x03).ok_or(SuspendableError::InvalidData)?;
        // A nonzero byte position implies at least one AAD/data byte has already been absorbed
        // into the current rate block, which is only possible once the Aad or Data phase has
        // begun -- never while still in Init.
        if pos != 0 && phase == Phase::Init {
            return Err(SuspendableError::InvalidData);
        }

        let mut key_secret = Secret::<[u64; 2]>::new();
        *key_secret = *key.key;

        Ok(Ascon_AEAD128 {
            key: key_secret,
            state: s,
            pos,
            phase,
            held: [0u8; TAG_LEN],
            held_len: 0,
            _dir: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Phase is private, so its to_u8/from_u8 round trip -- exercised end-to-end via
    // suspend/resume in tests/aead128_tests.rs for the phases reachable there -- is pinned
    // directly here for every discriminant, including ones a successful resume never needs to
    // decode into (Init and Aad never survive to be the *end* phase of a still-running cipher in
    // the integration tests, since further processing always advances them to Data).
    #[test]
    fn phase_u8_round_trip() {
        for s in [Phase::Init, Phase::Aad, Phase::Data] {
            assert_eq!(Phase::from_u8(s.to_u8()), Some(s), "round trip failed for {s:?}");
        }
        // The unassigned low-bits value (3, which the old six-state encoding also skipped) must
        // be rejected, not silently mapped to a variant.
        assert_eq!(Phase::from_u8(3), None);
    }
}
