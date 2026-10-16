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
//! The public API is [`AsconAead128Encryptor`] / [`AsconAead128Decryptor`] (or the pair through
//! [`Ascon_AEAD128`]), which implement [`AEADCipherEncryptor`] / [`AEADCipherDecryptor`] and the
//! symmetric-cipher traits they extend. Both wrap the crate-private `AsconAead128<Dir>`, the
//! cipher itself with the direction in its type; the decryptor also holds back the trailing tag
//! the cipher takes separately at its final.

use core::fmt::{self, Debug, Display, Formatter};

use bouncycastle_cipher::{Decrypting, Direction, Encrypting};
use bouncycastle_core::errors::{KeyMaterialError, SuspendableError, SymmetricCipherError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, Algorithm, RNG, SuspendableKeyed,
    SymmetricCipherDecryptor, SymmetricCipherEncryptor,
};
use bouncycastle_rng::HashDRBG_SHA512;
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
/// plaintext/ciphertext. The direction is not here; it is the type parameter of [`AsconAead128`].
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

/// The Ascon-AEAD128 cipher (NIST SP 800-232) in one direction: `Dir` is [`Encrypting`] or
/// [`Decrypting`], and only that direction's methods exist on the type. One instance performs one
/// operation under one (key, nonce) pair, in place, with the tag separate from the data. The
/// public wrappers [`AsconAead128Encryptor`] / [`AsconAead128Decryptor`] give it the trait API.
pub(crate) struct AsconAead128<Dir> {
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
    _dir: PhantomData<Dir>,
}

// Written out rather than derived so that `Dir`, a marker type, need not be `Clone`.
impl<Dir> Clone for AsconAead128<Dir> {
    fn clone(&self) -> Self {
        Self {
            key: self.key.clone(),
            state: self.state.clone(),
            pos: self.pos,
            phase: self.phase,
            _dir: PhantomData,
        }
    }
}

/// Draw a fresh, unique 128-bit nonce from the library's default OS-seeded DRBG.
///
/// The one-shot APIs of main's cipher framework generate the init data / nonce internally, so
/// Ascon's per-encryption nonce-uniqueness requirement (SP 800-232 R3) is satisfied by sourcing
/// each nonce from a CSPRNG. A caller who manages its own nonces uses
/// [`AEADCipherEncryptor::do_encrypt_init_nonce`] instead.
fn fresh_nonce() -> Result<[u8; NONCE_LEN], SymmetricCipherError> {
    let mut rng = HashDRBG_SHA512::new_from_os();
    let mut nonce = [0u8; NONCE_LEN];
    rng.next_bytes_out(&mut nonce)?;
    Ok(nonce)
}

impl<Dir> AsconAead128<Dir> {
    /// Validate a [`KeyMaterial`] for use with Ascon-AEAD128 and return its key words.
    /// The key must be tagged as a [`KeyType::SymmetricCipherKey`], not be bound to another
    /// algorithm, and carry at least the algorithm's 128-bit security strength (SP 800-232 R1/R2).
    fn checked_key(key: &KeyMaterial<KEY_LEN>) -> Result<[u64; 2], SymmetricCipherError> {
        if key.key_type() != KeyType::SymmetricCipherKey {
            return Err(KeyMaterialError::InvalidKeyType(
                "Ascon-AEAD128 requires a SymmetricCipherKey",
            )
            .into());
        }
        key.check_algorithm(ASCON_AEAD128_NAME)?;
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

    /// SP 800-232 Sec 4.1.1 / 4.1.2 step 1, the same in both directions: validates `key` as a
    /// [`KeyType::SymmetricCipherKey`] of at least 128-bit strength and initialises the state
    /// under `nonce`. The direction is whatever type this is called on.
    fn new(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
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

        Ok(AsconAead128 { key: key_secret, state, pos: 0, phase: Phase::Init, _dir: PhantomData })
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
    fn do_update_aad(&mut self, input: &[u8]) -> Result<(), SymmetricCipherError> {
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

impl AsconAead128<Encrypting> {
    /// Encrypt `data` in place (SP 800-232 §4.1.1 step 3). Every byte is transformed and emitted
    /// immediately; nothing is buffered across calls.
    fn do_encrypt_inplace(&mut self, data: &mut [u8]) {
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
    /// plaintext/ciphertext byte was already written by `do_encrypt_inplace`.
    fn do_encrypt_final(mut self) -> [u8; TAG_LEN] {
        self.check_data();
        // Padding of the final (possibly empty) plaintext block (Eq. 27).
        self.xor_state_byte(self.pos, 0x01);
        self.finish_data()
    }
}

impl AsconAead128<Decrypting> {
    /// Decrypt `data` in place (SP 800-232 §4.1.2 step 3). Every byte is transformed and emitted
    /// immediately; the plaintext is **not** authenticated until `do_decrypt_final` returns `Ok`.
    fn do_decrypt_inplace(&mut self, data: &mut [u8]) {
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
    fn do_decrypt_final(mut self, tag: &[u8; TAG_LEN]) -> Result<(), SymmetricCipherError> {
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

impl<Dir> Algorithm for AsconAead128<Dir> {
    const ALG_NAME: &'static str = ASCON_AEAD128_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

/// Ascon-AEAD128 encryption through [`AEADCipherEncryptor`] and, through it,
/// [`SymmetricCipherEncryptor`]. The nonce is drawn by `do_encrypt_init` and returned, or supplied
/// to `do_encrypt_init_nonce` by a caller who takes on its uniqueness.
///
/// `FINAL_LEN` is `TAG_LEN`: Ascon-AEAD128 holds nothing back, so the inline
/// [`SymmetricCipherEncryptor::do_encrypt_final`] writes only the tag, and the detached
/// [`AEADCipherEncryptor::do_encrypt_final_detached_out`] only zeroes its buffer.
#[derive(Clone)]
pub struct AsconAead128Encryptor(AsconAead128<Encrypting>);

impl Debug for AsconAead128Encryptor {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "AsconAead128Encryptor (key/state masked)")
    }
}

impl Display for AsconAead128Encryptor {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "AsconAead128Encryptor (key/state masked)")
    }
}

impl Algorithm for AsconAead128Encryptor {
    const ALG_NAME: &'static str = AsconAead128::<Encrypting>::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength =
        AsconAead128::<Encrypting>::MAX_SECURITY_STRENGTH;
}

impl SymmetricCipherEncryptor<KEY_LEN, NONCE_LEN, TAG_LEN> for AsconAead128Encryptor {
    fn do_encrypt_init(
        key: &KeyMaterial<KEY_LEN>,
    ) -> Result<(Self, [u8; NONCE_LEN]), SymmetricCipherError> {
        let nonce = fresh_nonce()?;
        Ok((Self(AsconAead128::new(key, &nonce)?), nonce))
    }

    fn do_encrypt_init_rng(
        key: &KeyMaterial<KEY_LEN>,
        rng: &mut dyn RNG,
    ) -> Result<(Self, [u8; NONCE_LEN]), SymmetricCipherError> {
        let mut nonce = [0u8; NONCE_LEN];
        rng.next_bytes_out(&mut nonce)?;
        Ok((Self(AsconAead128::new(key, &nonce)?), nonce))
    }

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
        self.0.do_encrypt_inplace(out);
        Ok(plaintext.len())
    }

    /// The inline layout: nothing is held back, so the final buffer is exactly the tag.
    fn do_encrypt_final(self) -> Result<([u8; TAG_LEN], usize), SymmetricCipherError> {
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

    fn do_encrypt_init_nonce(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Self, SymmetricCipherError> {
        Ok(Self(AsconAead128::new(key, nonce)?))
    }

    /// Nothing is ever held back to flush, so `ciphertext` is left zeroed.
    fn do_encrypt_final_detached_out(
        self,
        ciphertext: &mut [u8; TAG_LEN],
    ) -> Result<(usize, [u8; TAG_LEN]), SymmetricCipherError> {
        ciphertext.fill(0);
        Ok((0, self.0.do_encrypt_final()))
    }
}

/// Ascon-AEAD128 decryption through [`AEADCipherDecryptor`] and, through it,
/// [`SymmetricCipherDecryptor`].
///
/// The cipher itself emits every byte as it is seen, but this type holds back the last `TAG_LEN`
/// bytes of ciphertext, since until the stream ends it cannot know whether they are the inline
/// tag ([`SymmetricCipherDecryptor::do_decrypt_final`]) or ciphertext with the tag carried
/// separately ([`AEADCipherDecryptor::do_decrypt_final_detached_out`]). They are ciphertext, not
/// plaintext, so they need no [`Secret`] wrapper.
///
/// The direction is in the type, so the wrong direction is a compile error:
///
/// ```compile_fail
/// # use bouncycastle_ascon::AsconAead128Decryptor;
/// # use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// # use bouncycastle_core::traits::{SymmetricCipherDecryptor, SymmetricCipherEncryptor};
/// # let key = KeyMaterial::<16>::from_bytes_as_type(&[7; 16], KeyType::SymmetricCipherKey).unwrap();
/// let mut dec = AsconAead128Decryptor::do_decrypt_init(&key, &[0u8; 16]).unwrap();
/// dec.do_encrypt_out(&[0u8; 4], &mut [0u8; 4]);   // no such method on the decryptor
/// ```
#[derive(Clone)]
pub struct AsconAead128Decryptor {
    cipher: AsconAead128<Decrypting>,
    /// The most recent `held_len` bytes of ciphertext, not yet given to `cipher`.
    held: [u8; TAG_LEN],
    /// Always `min(TAG_LEN, total ciphertext seen)`.
    held_len: usize,
}

impl Algorithm for AsconAead128Decryptor {
    const ALG_NAME: &'static str = AsconAead128::<Decrypting>::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength =
        AsconAead128::<Decrypting>::MAX_SECURITY_STRENGTH;
}

impl SymmetricCipherDecryptor<KEY_LEN, NONCE_LEN, TAG_LEN> for AsconAead128Decryptor {
    fn do_decrypt_init(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Self, SymmetricCipherError> {
        Ok(Self { cipher: AsconAead128::new(key, nonce)?, held: [0u8; TAG_LEN], held_len: 0 })
    }

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
        // Called even when `release` is 0: that is what ends the AAD phase in `cipher`, so a
        // later non-empty `do_update_aad` is refused however little ciphertext has been seen.
        self.cipher.do_decrypt_inplace(out);
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
        self.cipher.do_decrypt_final(&self.held)?;
        Ok(([0u8; TAG_LEN], 0))
    }

    /// Everything but the trailing tag.
    fn decrypt_out_len(ciphertext_len: usize) -> usize {
        ciphertext_len.saturating_sub(TAG_LEN)
    }
}

impl AEADCipherDecryptor<KEY_LEN, NONCE_LEN, TAG_LEN, TAG_LEN> for AsconAead128Decryptor {
    /// # Errors
    /// [`SymmetricCipherError::StateError`] if `aad` is non-empty and
    /// [`SymmetricCipherDecryptor::do_decrypt_out`] has already been called.
    fn do_update_aad(&mut self, aad: &[u8]) -> Result<(), SymmetricCipherError> {
        self.cipher.do_update_aad(aad)
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
        self.cipher.do_decrypt_inplace(&mut plaintext[..n]);
        if let Err(e) = self.cipher.do_decrypt_final(tag) {
            plaintext.fill(0);
            return Err(e);
        }
        Ok(n)
    }
}

impl AsconAead128Encryptor {
    /// Encrypts `data` in place: every byte is replaced by its ciphertext as it is seen and
    /// nothing is held back, so a message can stream through one buffer. The tag comes from the
    /// final as usual; this is the in-place twin of
    /// [`SymmetricCipherEncryptor::do_encrypt_out`].
    pub fn do_encrypt_inplace(&mut self, data: &mut [u8]) {
        self.0.do_encrypt_inplace(data);
    }
}

impl AsconAead128Decryptor {
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
        // Called even when `release` is 0, which is what ends the AAD phase in `cipher`.
        self.cipher.do_decrypt_inplace(&mut data[..release]);

        self.held = new_held;
        self.held_len = kept + input_kept;
        release
    }
}

/// Ascon-AEAD128 (NIST SP 800-232), spelled as the specification spells it, in one direction:
/// `Ascon_AEAD128<Encrypting>` is [`AsconAead128Encryptor`] and `Ascon_AEAD128<Decrypting>` is
/// [`AsconAead128Decryptor`]. The wrong direction is a compile error, not a runtime check, and the
/// nonce is generated by encryption and returned, never supplied.
///
/// A plain alias cannot choose between two types, so this is a projection through the sealed
/// [`Direction`] trait, which only [`Encrypting`] and [`Decrypting`] implement.
///
/// Both directions implement [`AEADCipherEncryptor`] / [`AEADCipherDecryptor`] and, through them,
/// [`SymmetricCipherEncryptor`] / [`SymmetricCipherDecryptor`] -- which is the AEAD with no
/// associated data and the tag inline:
///
/// ```
/// use bouncycastle_ascon::Ascon_AEAD128;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_cipher::{Decrypting, Encrypting};
/// use bouncycastle_core::traits::{SymmetricCipherDecryptor, SymmetricCipherEncryptor};
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
/// let mut plaintext = [0u8; 5]; // Dec::decrypt_out_len(21)
/// let n = Dec::decrypt_out(&key, &nonce, &ciphertext, &mut plaintext).expect("decryption");
/// assert_eq!(&plaintext[..n], message);
/// ```
#[allow(non_camel_case_types)]
pub type Ascon_AEAD128<Dir> =
    <Dir as Direction>::Select<AsconAead128Encryptor, AsconAead128Decryptor>;

impl Debug for AsconAead128Decryptor {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "AsconAead128Decryptor (key/state masked)")
    }
}

impl Display for AsconAead128Decryptor {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "AsconAead128Decryptor (key/state masked)")
    }
}

/// Length in bytes of the serialized state of [`AsconAead128Encryptor`], which is the cipher's:
/// 3-byte library version || 1-byte state tag || 40-byte permutation state (5 × u64 LE)
/// || 1-byte byte position within the current rate block || 1-byte call-state/direction.
/// The secret key is **not** serialized; it is re-supplied to [`SuspendableKeyed::from_suspended`].
pub const SUSPENDED_ASCON_AEAD128_ENCRYPTOR_STATE_LEN: usize = CIPHER_STATE_LEN;

/// Length in bytes of the serialized state of [`AsconAead128Decryptor`]: the cipher's state as
/// for the encryptor, then the up to `TAG_LEN` bytes it holds back and their count.
pub const SUSPENDED_ASCON_AEAD128_DECRYPTOR_STATE_LEN: usize = CIPHER_STATE_LEN + TAG_LEN + 1;

/// The cipher's own serialized state, the whole of the encryptor's and the head of the decryptor's.
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

impl SuspendableKeyed<SUSPENDED_ASCON_AEAD128_ENCRYPTOR_STATE_LEN> for AsconAead128Encryptor {
    // The 128-bit key must be re-supplied when resuming; it is never part of the serialized state,
    // and is re-validated exactly as construction validates it.
    type Key = KeyMaterial<KEY_LEN>;

    fn suspend(self) -> [u8; SUSPENDED_ASCON_AEAD128_ENCRYPTOR_STATE_LEN] {
        self.0.suspend_as(ENC_DIR_BITS)
    }

    /// A state suspended by [`AsconAead128Decryptor`] is [`SuspendableError::InvalidData`] here.
    fn from_suspended(
        serialized_state: [u8; SUSPENDED_ASCON_AEAD128_ENCRYPTOR_STATE_LEN],
        key: &Self::Key,
    ) -> Result<Self, SuspendableError> {
        Ok(Self(AsconAead128::resume_as(serialized_state, key, ENC_DIR_BITS)?))
    }
}

/// The cipher's state, then the held-back bytes and their count; see
/// [`SUSPENDED_ASCON_AEAD128_DECRYPTOR_STATE_LEN`].
impl SuspendableKeyed<SUSPENDED_ASCON_AEAD128_DECRYPTOR_STATE_LEN> for AsconAead128Decryptor {
    type Key = KeyMaterial<KEY_LEN>;

    fn suspend(self) -> [u8; SUSPENDED_ASCON_AEAD128_DECRYPTOR_STATE_LEN] {
        let mut out = [0u8; SUSPENDED_ASCON_AEAD128_DECRYPTOR_STATE_LEN];
        out[..CIPHER_STATE_LEN].copy_from_slice(&self.cipher.suspend_as(DEC_DIR_BITS));
        out[CIPHER_STATE_LEN..CIPHER_STATE_LEN + TAG_LEN].copy_from_slice(&self.held);
        debug_assert!(self.held_len <= TAG_LEN);
        out[CIPHER_STATE_LEN + TAG_LEN] = self.held_len as u8;
        out
    }

    /// A state suspended by [`AsconAead128Encryptor`], or a held-back count above `TAG_LEN`, is
    /// [`SuspendableError::InvalidData`].
    fn from_suspended(
        serialized_state: [u8; SUSPENDED_ASCON_AEAD128_DECRYPTOR_STATE_LEN],
        key: &Self::Key,
    ) -> Result<Self, SuspendableError> {
        // infallible: the slice is exactly CIPHER_STATE_LEN bytes by construction.
        let cipher_state: [u8; CIPHER_STATE_LEN] =
            serialized_state[..CIPHER_STATE_LEN].try_into().unwrap();
        let cipher = AsconAead128::resume_as(cipher_state, key, DEC_DIR_BITS)?;
        let mut held = [0u8; TAG_LEN];
        held.copy_from_slice(&serialized_state[CIPHER_STATE_LEN..CIPHER_STATE_LEN + TAG_LEN]);
        let held_len = serialized_state[CIPHER_STATE_LEN + TAG_LEN] as usize;
        if held_len > TAG_LEN {
            return Err(SuspendableError::InvalidData);
        }
        Ok(Self { cipher, held, held_len })
    }
}

impl<Dir> AsconAead128<Dir> {
    /// The body of both wrappers' [`SuspendableKeyed::suspend`]; `dir_bits` marks the direction.
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

    /// The body of both wrappers' [`SuspendableKeyed::from_suspended`]: a call-state byte whose
    /// direction is not `dir_bits` is refused, so a state never resumes in the other direction.
    fn resume_as(
        serialized_state: [u8; CIPHER_STATE_LEN],
        key: &KeyMaterial<KEY_LEN>,
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

        let key_words = Self::checked_key(key).map_err(|_| SuspendableError::InvalidData)?;
        let mut key_secret = Secret::<[u64; 2]>::new();
        *key_secret = key_words;

        Ok(AsconAead128 { key: key_secret, state: s, pos, phase, _dir: PhantomData })
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
