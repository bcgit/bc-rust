//! Galois/Counter Mode (NIST SP 800-38D), the authenticated encryption mode built from CTR
//! and the GHASH universal hash.
//!
//! # Nonce and Tag
//!
//! [`Gcm`] fixes the nonce at 96 bits (12 bytes, [`GCM_NONCE_LEN`]): SP 800-38D Sec 5.2.1.1
//! recommends that implementations "restrict support to the length of 96 bits", and the other IV
//! lengths are not implemented. The nonce is never taken from the caller: instead
//! [`SymmetricCipherEncryptor::do_encrypt_init`] and [`SymmetricCipherEncryptor::do_encrypt_init_rng`]
//! draw it from the default OS RNG or the provided RNG, respectively.
//!
//! The tag length is a const generic `TAG_LEN`, checked at compile time to lie in `12..=16` bytes
//! (96, 104, 112, 120 or 128 bits -- Sec 5.2.1.2's five recommended values). The 32- and 64-bit tags
//! Sec 5.2.1.2 permits "for certain applications" (Appendix C) are not supported.
//!
//! # Usage Examples
//!
//! [`Gcm`] is used through [`AEADCipherEncryptor`] / [`AEADCipherDecryptor`], with
//! `FINAL_LEN = TAG_LEN`, and through the [`SymmetricCipherEncryptor`] /
//! [`SymmetricCipherDecryptor`] traits they extend:
//!
//! Used through the SymmetricCipher traits, there is no option to include additional associated data (aad),
//! and the tag is inlined into the ciphertext as `ciphertext || tag`.
//!
//! ```
//! use bouncycastle_core_test_framework::ToyBlockCipher;
//! use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
//! use bouncycastle_core::traits::{SymmetricCipherDecryptor, SymmetricCipherEncryptor};
//! use bouncycastle_core::errors::SymmetricCipherError;
//! use bouncycastle_cipher::modes::Gcm;
//! use bouncycastle_cipher::{Decrypting, Encrypting};
//!
//! type ToyGcm<Dir> = Gcm<ToyBlockCipher, Dir, 16, 16>;
//!
//! let key = KeyMaterial128::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//! let aad = b"header, sent in the clear";
//! let plaintext: [u8; 16] = *b"attack at dawn!!";
//!
//! let (nonce, ciphertext) = ToyGcm::<Encrypting>::encrypt(&key, &plaintext).expect("encrypt");
//!
//! let mut recovered = ToyGcm::<Decrypting>::decrypt(&key, &nonce, &ciphertext).expect("decrypt");
//! assert_eq!(recovered, plaintext);
//!
//! // A tampered ciphertext will be caught by the tag
//! let mut tampered_ct = ciphertext.clone();
//! tampered_ct[1] ^= 0xFF;
//! match ToyGcm::<Decrypting>::decrypt(&key, &nonce, &tampered_ct).unwrap_err() {
//!     SymmetricCipherError::AEADTagCheckFailed => { /* good */ }
//!     _ => { panic!() }
//! }
//! ```
//!
//! The AEADCipher traits provide the AEAD-specific functionality, including accepting the aad, and
//! the `_detached()` methods handle the tag separately, instead of inlined into the ciphertext.
//!
//! ```
//! use bouncycastle_core_test_framework::ToyBlockCipher;
//! use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
//! use bouncycastle_core::traits::{AEADCipherDecryptor, AEADCipherEncryptor};
//! use bouncycastle_cipher::modes::Gcm;
//! use bouncycastle_cipher::{Decrypting, Encrypting};
//!
//! type ToyGcm<Dir> = Gcm<ToyBlockCipher, Dir, 16, 16>;
//!
//! let key = KeyMaterial128::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//! let aad = b"header, sent in the clear";
//! let plaintext = *b"attack at dawn!!";
//!
//! let mut ciphertext = [0u8; 16];
//! let (nonce, _bytes_written, tag) =
//!     ToyGcm::<Encrypting>::encrypt_out_detached(&key, aad, &plaintext, &mut ciphertext).unwrap();
//!
//! let mut recovered = [0u8; 16];
//! ToyGcm::<Decrypting>::decrypt_out_detached(&key, &nonce, aad, &ciphertext, &tag, &mut recovered)
//!     .unwrap();
//! assert_eq!(recovered, plaintext);
//! ```
//!
//! There is also a streaming mode.
//! Note that the aad must be supplied before any plaintext or ciphertext; attempting to call
//! `do_update_aad()` after a `do_encrypt()` will result in a [`SymmetricCipherError::StateError`].
//!
//! ```
//! use bouncycastle_core_test_framework::ToyBlockCipher;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::{
//!     AEADCipherDecryptor, AEADCipherEncryptor, SymmetricCipherDecryptor, SymmetricCipherEncryptor,
//! };
//! use bouncycastle_cipher::modes::Gcm;
//! use bouncycastle_cipher::{Decrypting, Encrypting};
//!
//! type ToyGcm<Dir> = Gcm<ToyBlockCipher, Dir, 16, 16>;
//!
//! let key = KeyMaterial::<16>::from_bytes_as_type(&[0x07; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//! let aad = b"some associated data";
//! let message = b"a message that streams in over more than one call";
//!
//! let (mut enc, nonce) = ToyGcm::<Encrypting>::do_encrypt_init(&key).unwrap();
//! enc.do_update_aad(aad).unwrap();
//! let mut ct = vec![0u8; message.len()];
//! enc.do_encrypt_out(message, &mut ct).unwrap();
//! let (tag_block, tag_len) = enc.do_final().unwrap();
//! ct.extend_from_slice(&tag_block[..tag_len]);
//!
//! let mut dec = ToyGcm::<Decrypting>::do_decrypt_init(&key, &nonce).unwrap();
//! dec.do_update_aad(aad).unwrap();
//! let mut pt = vec![0u8; ct.len()];
//! let written = dec.do_decrypt_out(&ct, &mut pt).unwrap();
//! let (_last, last_len) = dec.do_final().unwrap();
//! pt.truncate(written + last_len);
//! assert_eq!(pt, message);
//! ```
//!
//! # Suspending and resuming execution
//!
//! [`Gcm`] implements [`SuspendableKeyed`], so a message in progress can be suspended to a byte
//! array and resumed later with the re-supplied key. The state is the CTR half, the running GHASH,
//! the byte counts and whatever a decryptor is holding back as a possible tag; `H` and the tag mask
//! are re-derived from the key. The array length is `Gcm::SUSPENDED_STATE_LEN`; see [the crate
//! docs](crate#suspending-and-resuming-execution) for an example.
//!
//! # 🚨 Security Considerations 🚨
//!
//! ## Nonce uniqueness
//!
//! As with all symmetric cipher modes, repeated key and nonce for multiple messages is catastrophic
//! for security, which is why the nonce is always drawn from the library's default RNG or a provided
//! RNG and never accepted from the caller.
//!
//! ## Invocation limit
//!
//! NIST SP 800-38D Sec 8.3:
//!
//! > "the total number of invocations of the authenticated encryption function shall not exceed 2^32
//! > ... with the given key."
//!
//! This is a caller obligation this type cannot enforce across calls; rotate the key well
//!   before 2^32 messages.
//!
//! ## Forgery probability and failed-verification limits
//!
//! Appendix B: a targeted forgery over
//!   `n` blocks of AAD and ciphertext succeeds with probability about `n / 2^t`, and each success
//!   leaks information about `H`; "the system or protocol that implements GCM should monitor and, if
//!   necessary, limit the number of unsuccessful verification attempts for each key."
//!
//! ## Streaming decryption releases plaintext before the tag is checked
//!
//! [`SymmetricCipherDecryptor::do_decrypt_out`] hands back plaintext as it goes, which is
//! unauthenticated until the tag has been checked after the final block.
//! It is the application's responsibility not to take any action on the decrypted plaintext until
//! the end of the ciphertext has been reached, and the `do_final` / `do_final_detached` succeeds.
//!
//! The one-shots (`decrypt_out`, `decrypt_out_detached`, `decrypt_out_with_aad`) verify the
//! tag first and release nothing on failure, making them more robust.
//!
//! * **GMAC is GCM with no plaintext** (Sec 5.2): feed only AAD and call `do_final_detached`: there
//!   is no separate `Gmac` type.

use crate::modes::Ctr;
use crate::modes::ghash::{GHASH_STATE_LEN, Ghash};
use crate::modes::hazmat::CtrKeyStream;
use crate::{Decrypting, Encrypting};
use bouncycastle_core::errors::{SuspendableError, SymmetricCipherError};
use bouncycastle_core::hazmat::ElectronicCodeBook;
use bouncycastle_core::key_material::KeyMaterial;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, Algorithm, RNG, StreamCipherDecryptor,
    StreamCipherEncryptor, SuspendableKeyed, SymmetricCipherDecryptor, SymmetricCipherEncryptor,
};
use bouncycastle_rng::HashDRBG_SHA512;
use bouncycastle_utils::ct::ct_eq_bytes;
use bouncycastle_utils::secret::Secret;
use bouncycastle_utils::suspendable_state::{
    Cursor, CursorMut, LIB_VERSION_LEN, SuspendableComponent, bounded_usize, resume_component,
    suspend_component,
};
use core::marker::PhantomData;

/// The nonce (IV) length this type uses: 96 bits, SP 800-38D Sec 5.2.1.1's recommended length.
pub const GCM_NONCE_LEN: usize = 12;

/// Which category of bytes `Gcm` is currently absorbing into GHASH: additional authenticated data,
/// or plaintext/ciphertext. AAD is only accepted in the first phase (SP 800-38D Algorithm 4 absorbs
/// `A` before `C`); the transition also pads the AAD to a block boundary (the `0^v` of step 5).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Aad = 0,
    Data = 1,
}

impl Phase {
    /// The inverse of `as u8`, for a suspended state; anything but the two values is refused.
    fn from_u8(v: u8) -> Result<Self, SuspendableError> {
        match v {
            0 => Ok(Phase::Aad),
            1 => Ok(Phase::Data),
            _ => Err(SuspendableError::InvalidData),
        }
    }
}

/// Galois/Counter Mode over any [`ElectronicCodeBook`] permutation, direction typed as
/// [`Encrypting`] / [`Decrypting`]. See the module docs for the two APIs this type exposes and
/// [`GCM_NONCE_LEN`] / `TAG_LEN` for what is fixed and what is chosen.
#[derive(Clone)]
pub struct Gcm<P, Dir, const KEY_LEN: usize, const TAG_LEN: usize>
where
    P: ElectronicCodeBook<KEY_LEN, 16>,
{
    /// `GCTR_K(inc32(J0), .)`: Algorithm 4 step 3 / Algorithm 5 step 4, started at counter 2 (see
    /// [`Gcm::setup`]).
    ctr: Ctr<P, Dir, KEY_LEN, 16, GCM_NONCE_LEN>,
    /// `GHASH_H` over `A || 0^v || C || 0^u`, Algorithm 4/5 step 5/6.
    ghash: Ghash,
    /// `CIPH_K(J0)`, the one-time mask for the tag (step 6's `GCTR_K(J0, S) = S (+) CIPH_K(J0)`,
    /// valid because `S` is exactly one block).
    ek_j0: Secret<[u8; 16]>,
    /// `len(A)` in bytes so far; converted to bits at [`Gcm::tag_block`].
    aad_len: u64,
    /// `len(C)` in bytes so far; converted to bits at [`Gcm::tag_block`].
    data_len: u64,
    phase: Phase,
    /// The last up to `TAG_LEN` bytes of ciphertext seen by [`SymmetricCipherDecryptor::do_decrypt_out`]
    /// but not yet released, because they might be the tag. Meaningful only on the `Decrypting`
    /// side; kept on both directions rather than splitting the struct by `Dir` -- seeded random
    /// bytes are indistinguishable from a design that carries them deliberately, so this trades
    /// `TAG_LEN` bytes of unused state on the encryptor for one struct definition instead of two.
    tail: Secret<[u8; TAG_LEN]>,
    /// How many bytes of `tail` are meaningful, `0..=TAG_LEN`.
    tail_len: usize,
    _dir: PhantomData<Dir>,
}

impl<P, Dir, const KEY_LEN: usize, const TAG_LEN: usize> Gcm<P, Dir, KEY_LEN, TAG_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, 16>,
{
    /// The `N` of this type's [`SuspendableKeyed<N>`] impl: the version header, the CTR state,
    /// the GHASH state, the two byte counts, the phase, the held-back tail and its length. See
    /// [`bouncycastle_utils::suspendable_state`].
    pub const SUSPENDED_STATE_LEN: usize =
        LIB_VERSION_LEN + <Self as SuspendableComponent>::STATE_LEN;

    /// The CTR half's share of the suspended state.
    const CTR_STATE_LEN: usize =
        <Ctr<P, Dir, KEY_LEN, 16, GCM_NONCE_LEN> as SuspendableComponent>::STATE_LEN;

    /// The compile-time shape check: `TAG_LEN` must be one of Sec 5.2.1.2's five recommended tag
    /// lengths in bytes (96, 104, 112, 120, 128 bits -- Appendix C's 32- and 64-bit tags are a
    /// documented non-goal; see the module docs). Called from every constructor.
    #[inline]
    fn check_shape() {
        const {
            assert!(
                TAG_LEN >= 12 && TAG_LEN <= 16,
                "GCM tag length must be 12..=16 bytes (96, 104, 112, 120 or 128 bits), \
                 SP 800-38D Sec 5.2.1.2"
            );
        };
    }

    /// Algorithm 4 steps 1-2 and the precomputation for step 6's tag mask.
    fn setup(perm: P, nonce: [u8; GCM_NONCE_LEN]) -> Self {
        Self::check_shape();

        // Step 1: H = CIPH_K(0^128). Encrypted in place inside a `Secret` so that `H` is never
        // held in an unzeroized stack array (Sec 5.3; Appendix A on what `H` gives an attacker).
        let mut h: Secret<[u8; 16]> = Secret::new();
        perm.encrypt_block(&mut h);

        // Step 2 (len(IV) = 96 branch, the only one this type implements): J0 = IV || 0^31 || 1,
        // built directly in the `Secret` that will hold CIPH_K(J0).
        //
        // Precompute CIPH_K(J0) now, while J0 is fully known: step 6's GCTR_K(J0, S) reduces to
        // S (+) CIPH_K(J0) because S is exactly one block (Algorithm 3 with a single, complete
        // input block), so this one-time mask is all GCTR at J0 will ever be asked to produce.
        let mut ek_j0: Secret<[u8; 16]> = Secret::new();
        ek_j0[..GCM_NONCE_LEN].copy_from_slice(&nonce);
        ek_j0[15] = 1;
        perm.encrypt_block(&mut ek_j0);

        // Step 3's inc32(J0): J0's rightmost 32 bits are 1, so inc32(J0) has counter field 2.
        let ctr = Ctr::from_keystream(CtrKeyStream::start_at(perm, nonce, 2));

        Self {
            ctr,
            ghash: Ghash::new(&h),
            ek_j0,
            aad_len: 0,
            data_len: 0,
            phase: Phase::Aad,
            tail: Secret::new(),
            tail_len: 0,
            _dir: PhantomData,
        }
    }

    /// Absorbs additional authenticated data: the body of both directions'
    /// `AEADCipher*::do_update_aad`. Any number of calls before the first `do_update_out`; a
    /// non-empty call after data has started is [`SymmetricCipherError::StateError`] (Algorithm 4
    /// absorbs `A` before `C` in one GHASH pass, D4). Empty AAD is always a no-op.
    fn absorb_aad(&mut self, aad: &[u8]) -> Result<(), SymmetricCipherError> {
        if self.phase == Phase::Data {
            if aad.is_empty() {
                return Ok(());
            }
            return Err(SymmetricCipherError::StateError(
                "GCM: additional authenticated data must be supplied before any plaintext or \
                 ciphertext (SP 800-38D Algorithm 4 absorbs A before C in one GHASH pass)",
            ));
        }
        self.ghash.update(aad);
        self.aad_len =
            self.aad_len.checked_add(aad.len() as u64).ok_or(SymmetricCipherError::StateError(
                "GCM: additional authenticated data length exceeds the supported range",
            ))?;
        Ok(())
    }

    /// The AAD-to-data transition: pads the AAD to a block boundary (the `0^v` of step 5) the
    /// first time data arrives. A no-op on every later call.
    fn begin_data_if_needed(&mut self) {
        if self.phase == Phase::Aad {
            self.ghash.pad_to_block();
            self.phase = Phase::Data;
        }
    }

    /// Absorbs `data` -- always ciphertext, whichever direction is calling -- into GHASH and
    /// tracks its length. Shared by the encryptor (which calls this *after* GCTR has turned
    /// plaintext into ciphertext in place) and the decryptor (which calls this *before* GCTR turns
    /// the ciphertext back into plaintext): either way GHASH must see ciphertext, never plaintext.
    fn absorb_data(&mut self, data: &[u8]) -> Result<(), SymmetricCipherError> {
        self.begin_data_if_needed();
        self.ghash.update(data);
        self.data_len = self.data_len.checked_add(data.len() as u64).ok_or(
            SymmetricCipherError::StateError("GCM: data length exceeds the supported range"),
        )?;
        Ok(())
    }

    /// Algorithm 4 steps 4-6 / Algorithm 5 steps 5-7: pads GHASH to the block boundary (the `0^u`
    /// of step 5), appends `[len(A)]_64 || [len(C)]_64`, and masks the result with `CIPH_K(J0)`.
    /// Writes the full 16-byte block to `out`; callers truncate to `TAG_LEN`. `out` is a `Secret`
    /// because on the decrypting side it is the expected tag `T'`, which forges the rejected
    /// ciphertext if it survives a failed comparison.
    ///
    /// The byte-to-bit multiplication (`* 8`) is not checked for overflow: `aad_len` and `data_len`
    /// are accumulated with `checked_add` at every absorption (`absorb_aad`, `absorb_data`), so
    /// reaching a count whose `* 8` could overflow `u64` would already require far more calls than
    /// are physically possible to make.
    fn tag_block(&mut self, out: &mut Secret<[u8; 16]>) {
        self.ghash.pad_to_block();
        let aad_bits = self.aad_len * 8;
        let data_bits = self.data_len * 8;
        self.ghash.finish(aad_bits, data_bits, out);
        for (o, m) in out.iter_mut().zip(self.ek_j0.iter()) {
            *o ^= m;
        }
    }
}

impl<P, Dir, const KEY_LEN: usize, const TAG_LEN: usize> Algorithm for Gcm<P, Dir, KEY_LEN, TAG_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, 16>,
{
    const ALG_NAME: &'static str = P::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = P::MAX_SECURITY_STRENGTH;
}

impl<P, const KEY_LEN: usize, const TAG_LEN: usize> Gcm<P, Encrypting, KEY_LEN, TAG_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, 16>,
{
    /// Encrypts `data` in place (GCTR, Algorithm 4 step 3) and absorbs the resulting ciphertext
    /// into GHASH (step 5). Nothing is held back.
    ///
    /// # Errors
    /// [`SymmetricCipherError::DataLimitExceeded`] if the underlying `Ctr` counter would be
    /// exhausted -- the SP 800-38D Sec 5.2.1.1 bound `len(P) <= 2^39 - 256` bits -- or
    /// [`SymmetricCipherError::StateError`] if the AAD/data length bookkeeping would overflow.
    /// Nothing is consumed in either case.
    fn encrypt_in_place(&mut self, data: &mut [u8]) -> Result<(), SymmetricCipherError> {
        self.ctr.do_encrypt(data)?;
        self.absorb_data(data)
    }

    /// Algorithm 4 steps 4-6: finishes the message and returns the detached authentication tag,
    /// truncated to `TAG_LEN` bytes (`MSB_t`, step 6). Consumes the encryptor.
    fn finish(mut self) -> [u8; TAG_LEN] {
        // Covers an AAD-only or entirely empty message, where no data was ever encrypted.
        self.begin_data_if_needed();
        let mut full: Secret<[u8; 16]> = Secret::new();
        self.tag_block(&mut full);
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&full[..TAG_LEN]);
        tag
    }
}

impl<P, const KEY_LEN: usize, const TAG_LEN: usize>
    SymmetricCipherEncryptor<KEY_LEN, GCM_NONCE_LEN, TAG_LEN>
    for Gcm<P, Encrypting, KEY_LEN, TAG_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, 16>,
{
    fn do_encrypt_init(
        key: &KeyMaterial<KEY_LEN>,
    ) -> Result<(Self, [u8; GCM_NONCE_LEN]), SymmetricCipherError> {
        let mut rng = HashDRBG_SHA512::new_from_os();
        Self::do_encrypt_init_rng(key, &mut rng)
    }

    fn do_encrypt_init_rng(
        key: &KeyMaterial<KEY_LEN>,
        rng: &mut dyn RNG,
    ) -> Result<(Self, [u8; GCM_NONCE_LEN]), SymmetricCipherError> {
        Self::check_shape();
        let perm = P::new(key)?;
        let nonce = crate::modes::iv::random_iv::<GCM_NONCE_LEN>(rng)?;
        Ok((Self::setup(perm, nonce), nonce))
    }

    /// The identity: GCM's encryptor holds nothing back.
    fn do_encrypt_out_len(&self, input_len: usize) -> usize {
        input_len
    }

    fn do_encrypt_out(
        &mut self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        if ciphertext.len() < plaintext.len() {
            return Err(SymmetricCipherError::OutputBufferTooSmall(plaintext.len()));
        }
        ciphertext[..plaintext.len()].copy_from_slice(plaintext);
        self.encrypt_in_place(&mut ciphertext[..plaintext.len()])?;
        Ok(plaintext.len())
    }

    fn do_final(self) -> Result<([u8; TAG_LEN], usize), SymmetricCipherError> {
        let tag = self.finish();
        Ok((tag, TAG_LEN))
    }

    fn encrypt_out_len(plaintext_len: usize) -> usize {
        plaintext_len + TAG_LEN
    }
}

/// The AEAD view: [`AEADCipherEncryptor`] over the [`SymmetricCipherEncryptor`] impl above, with
/// `FINAL_LEN = TAG_LEN`. The encryptor holds nothing back, so the detached final flushes nothing
/// and returns only the tag.
impl<P, const KEY_LEN: usize, const TAG_LEN: usize>
    AEADCipherEncryptor<KEY_LEN, GCM_NONCE_LEN, TAG_LEN, TAG_LEN>
    for Gcm<P, Encrypting, KEY_LEN, TAG_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, 16>,
{
    fn do_update_aad(&mut self, aad: &[u8]) -> Result<(), SymmetricCipherError> {
        self.absorb_aad(aad)
    }

    /// Algorithm 4 steps 4-6; `ciphertext` is left untouched, since nothing is held back.
    fn do_final_out_detached(
        self,
        _ciphertext: &mut [u8; TAG_LEN],
    ) -> Result<(usize, [u8; TAG_LEN]), SymmetricCipherError> {
        Ok((0, self.finish()))
    }
}

impl<P, const KEY_LEN: usize, const TAG_LEN: usize> Gcm<P, Decrypting, KEY_LEN, TAG_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, 16>,
{
    /// Absorbs `data` (ciphertext) into GHASH, then decrypts it in place. Order matters and is the
    /// reverse of the encryptor's: GHASH must see ciphertext on both sides, so it is absorbed
    /// *before* GCTR turns it into plaintext here.
    ///
    /// The plaintext this releases is **not yet authenticated**; see the module docs' Security
    /// Considerations section.
    ///
    /// # Errors
    /// As `encrypt_in_place`.
    fn decrypt_in_place(&mut self, data: &mut [u8]) -> Result<(), SymmetricCipherError> {
        self.absorb_data(data)?;
        self.ctr.do_decrypt(data)?;
        Ok(())
    }

    /// Algorithm 5 steps 5-8: recomputes `T'` and compares it against `tag` in constant time.
    /// Consumes the decryptor; `Ok(())` is the only thing that makes the plaintext released so far
    /// trustworthy.
    ///
    /// # Errors
    /// [`SymmetricCipherError::AEADTagCheckFailed`] if the tag does not match.
    fn finish(mut self, tag: &[u8; TAG_LEN]) -> Result<(), SymmetricCipherError> {
        self.begin_data_if_needed();
        let mut full: Secret<[u8; 16]> = Secret::new();
        self.tag_block(&mut full);
        if ct_eq_bytes(&full[..TAG_LEN], tag) {
            Ok(())
        } else {
            Err(SymmetricCipherError::AEADTagCheckFailed)
        }
    }

    /// Shared by the trait one-shots (`decrypt_out`, `decrypt_out_detached`,
    /// `decrypt_out_with_aad`): absorbs `aad` and
    /// `data` (still ciphertext) into GHASH and checks the tag *before* touching `data`, so no
    /// unauthenticated plaintext is ever written to the caller's buffer. The preamble of Sec 7
    /// explicitly permits this: "in Algorithm 5, the verification of the tag may precede the
    /// computation of the plaintext". Only on success is `data` decrypted.
    fn verify_then_decrypt(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; GCM_NONCE_LEN],
        aad: &[u8],
        data: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), SymmetricCipherError> {
        Self::check_shape();
        let perm = P::new(key)?;
        let mut gcm = Self::setup(perm, *nonce);
        gcm.absorb_aad(aad)?;
        gcm.absorb_data(data)?;
        let mut computed: Secret<[u8; 16]> = Secret::new();
        gcm.tag_block(&mut computed);
        if !ct_eq_bytes(&computed[..TAG_LEN], tag) {
            return Err(SymmetricCipherError::AEADTagCheckFailed);
        }
        gcm.ctr.do_decrypt(data)?;
        Ok(())
    }
}

impl<P, const KEY_LEN: usize, const TAG_LEN: usize>
    SymmetricCipherDecryptor<KEY_LEN, GCM_NONCE_LEN, TAG_LEN>
    for Gcm<P, Decrypting, KEY_LEN, TAG_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, 16>,
{
    fn do_decrypt_init(
        key: &KeyMaterial<KEY_LEN>,
        init_data: &[u8; GCM_NONCE_LEN],
    ) -> Result<Self, SymmetricCipherError> {
        Self::check_shape();
        let perm = P::new(key)?;
        Ok(Self::setup(perm, *init_data))
    }

    /// `tail_len + input_len`, minus up to `TAG_LEN` bytes held back because they might be the tag.
    fn do_decrypt_out_len(&self, input_len: usize) -> usize {
        (self.tail_len + input_len).saturating_sub(TAG_LEN)
    }

    /// Releases every byte of `tail ++ ciphertext` except the last (up to) `TAG_LEN`, which become
    /// the new tail. Decrypts (via `decrypt_in_place`) exactly the bytes released this call, so
    /// GHASH absorbs each ciphertext byte exactly once across the whole stream.
    fn do_decrypt_out(
        &mut self,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        let release = self.do_decrypt_out_len(ciphertext.len());
        if plaintext.len() < release {
            return Err(SymmetricCipherError::OutputBufferTooSmall(release));
        }
        // Data has started even if every byte is still held back as a possible tag, so the AAD
        // phase ends here rather than at the first byte released: otherwise a `do_update_aad`
        // after a first call shorter than `TAG_LEN` would be accepted, and absorbed as if it came
        // before the ciphertext (Algorithm 5 absorbs `A` before `C`).
        self.begin_data_if_needed();

        // Bytes of the old tail that are now known to be ciphertext, then bytes of the new input
        // that are also released this call.
        let tail_release = release.min(self.tail_len);
        let input_release = release - tail_release;
        if tail_release > 0 {
            plaintext[..tail_release].copy_from_slice(&self.tail[..tail_release]);
        }
        if input_release > 0 {
            plaintext[tail_release..release].copy_from_slice(&ciphertext[..input_release]);
        }
        if release > 0 {
            self.decrypt_in_place(&mut plaintext[..release])?;
        }

        // The new tail is whatever of (old tail ++ ciphertext) survives past `release` bytes --
        // at most TAG_LEN bytes, by construction of `release` above.
        let mut new_tail = [0u8; TAG_LEN];
        let old_tail_kept = self.tail_len - tail_release;
        new_tail[..old_tail_kept].copy_from_slice(&self.tail[tail_release..self.tail_len]);
        let input_kept = ciphertext.len() - input_release;
        new_tail[old_tail_kept..old_tail_kept + input_kept]
            .copy_from_slice(&ciphertext[input_release..]);
        *self.tail = new_tail;
        self.tail_len = old_tail_kept + input_kept;

        Ok(release)
    }

    /// If fewer than `TAG_LEN` bytes were ever seen, the ciphertext was too short to carry a tag at
    /// all (Algorithm 5 step 1's "lengths not supported"). Otherwise checks the tag held in `tail`
    /// against the GHASH state built up by every prior `do_update_out` call. Releases nothing: an
    /// authenticated cipher's final output may be empty once the tag has been checked.
    fn do_final(self) -> Result<([u8; TAG_LEN], usize), SymmetricCipherError> {
        if self.tail_len < TAG_LEN {
            return Err(SymmetricCipherError::DecryptionFailed);
        }
        let tag = *self.tail;
        self.finish(&tag)?;
        Ok(([0u8; TAG_LEN], 0))
    }

    fn decrypt_out_max_len(ciphertext_len: usize) -> usize {
        ciphertext_len.saturating_sub(TAG_LEN)
    }

    /// Overrides the trait's default (which would stream plaintext out before the tag is checked):
    /// verifies the tag first and only then decrypts, so this one-shot never exposes
    /// unauthenticated plaintext. The streaming path above, by its nature, still does.
    fn decrypt_out(
        key: &KeyMaterial<KEY_LEN>,
        init_data: &[u8; GCM_NONCE_LEN],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        <Self as AEADCipherDecryptor<KEY_LEN, GCM_NONCE_LEN, TAG_LEN, TAG_LEN>>::decrypt_out_with_aad(
            key,
            init_data,
            &[],
            ciphertext,
            plaintext,
        )
    }
}

/// The AEAD view: [`AEADCipherDecryptor`] over the [`SymmetricCipherDecryptor`] impl above, with
/// `FINAL_LEN = TAG_LEN`. The one-shots are overridden, as `decrypt_out` is, to check the tag
/// before any plaintext is written.
impl<P, const KEY_LEN: usize, const TAG_LEN: usize>
    AEADCipherDecryptor<KEY_LEN, GCM_NONCE_LEN, TAG_LEN, TAG_LEN>
    for Gcm<P, Decrypting, KEY_LEN, TAG_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, 16>,
{
    fn do_update_aad(&mut self, aad: &[u8]) -> Result<(), SymmetricCipherError> {
        self.absorb_aad(aad)
    }

    /// The detached layout: the up to `TAG_LEN` bytes held back as a possible tag are ciphertext
    /// after all, so they are decrypted into `plaintext` before the tag is checked against `tag`
    /// (Algorithm 5 steps 5-8). On failure `plaintext` is zeroized before the error is returned.
    fn do_final_out_detached(
        mut self,
        tag: &[u8; TAG_LEN],
        plaintext: &mut [u8; TAG_LEN],
    ) -> Result<usize, SymmetricCipherError> {
        let n = self.tail_len;
        plaintext[..n].copy_from_slice(&self.tail[..n]);
        self.decrypt_in_place(&mut plaintext[..n])?;
        if let Err(e) = self.finish(tag) {
            plaintext.fill(0);
            return Err(e);
        }
        Ok(n)
    }

    /// Verifies `tag` before decrypting, so no unauthenticated plaintext reaches `plaintext`; on
    /// failure what was written there is zeroized.
    fn decrypt_out_detached(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; GCM_NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; TAG_LEN],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        let len = ciphertext.len();
        if plaintext.len() < len {
            return Err(SymmetricCipherError::OutputBufferTooSmall(len));
        }
        plaintext[..len].copy_from_slice(ciphertext);
        Self::verify_then_decrypt(key, nonce, aad, &mut plaintext[..len], tag).inspect_err(
            |_| {
                // The buffer holds ciphertext rather than unauthenticated plaintext here, since the
                // tag is checked before decryption, but the trait's contract is a zeroized buffer on
                // failure, and a caller who ignores the `Result` should find nothing in it at all.
                plaintext[..len].fill(0);
            },
        )?;
        Ok(len)
    }

    /// The inline layout with AAD: splits the trailing `TAG_LEN` bytes off as the tag and verifies
    /// it before decrypting, as the detached one-shot does, zeroizing `plaintext` on failure.
    fn decrypt_out_with_aad(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; GCM_NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        let needed = Self::decrypt_out_max_len(ciphertext.len());
        if plaintext.len() < needed {
            return Err(SymmetricCipherError::OutputBufferTooSmall(needed));
        }
        let Some((data, tag)) = ciphertext.split_last_chunk::<TAG_LEN>() else {
            return Err(SymmetricCipherError::DecryptionFailed);
        };
        let len = data.len();
        plaintext[..len].copy_from_slice(data);
        Self::verify_then_decrypt(key, nonce, aad, &mut plaintext[..len], tag)
            .inspect_err(|_| plaintext[..len].fill(0))?;
        Ok(len)
    }
}

/// The suspended state is the CTR half, the running GHASH, the two byte counts, the phase, and
/// the up-to-`TAG_LEN` bytes a decryptor holds back. `H` and `CIPH_K(J0)` are not in it: both
/// derive from the key and the nonce, and `setup` re-derives them on resume. See
/// [`bouncycastle_utils::suspendable_state`].
impl<P, Dir, const KEY_LEN: usize, const TAG_LEN: usize> SuspendableComponent
    for Gcm<P, Dir, KEY_LEN, TAG_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, 16>,
{
    const STATE_LEN: usize = Self::CTR_STATE_LEN + GHASH_STATE_LEN + 8 + 8 + 1 + TAG_LEN + 8;
    type Key = KeyMaterial<KEY_LEN>;

    fn write_state(&self, out: &mut [u8]) {
        let (ctr, rest) = out.split_at_mut(Self::CTR_STATE_LEN);
        self.ctr.write_state(ctr);
        let (ghash, rest) = rest.split_at_mut(GHASH_STATE_LEN);
        self.ghash.write_state(ghash);
        let mut w = CursorMut::new(rest);
        w.u64(self.aad_len);
        w.u64(self.data_len);
        w.u8(self.phase as u8);
        w.bytes(&*self.tail);
        w.u64(self.tail_len as u64);
        debug_assert!(w.is_done());
    }

    fn read_state(state: &[u8], key: &Self::Key) -> Result<Self, SuspendableError> {
        Self::check_shape();
        let (ctr, rest) = state.split_at(Self::CTR_STATE_LEN);
        let (ghash, rest) = rest.split_at(GHASH_STATE_LEN);

        // `setup` re-derives `H` and `CIPH_K(J0)` from the key and the nonce, which is the
        // leading part of the CTR state. Its fresh CTR and GHASH are then replaced by the
        // suspended ones; the CTR read expands the key a second time, a one-off cost at resume.
        let nonce = CtrKeyStream::<P, KEY_LEN, 16, GCM_NONCE_LEN>::nonce_from_state(ctr);
        let perm = P::new(key).map_err(|_| SuspendableError::InvalidData)?;
        let mut gcm = Self::setup(perm, nonce);
        gcm.ctr = <Ctr<P, Dir, KEY_LEN, 16, GCM_NONCE_LEN> as SuspendableComponent>::read_state(
            ctr, key,
        )?;
        gcm.ghash.restore_state(ghash)?;

        let mut r = Cursor::new(rest);
        gcm.aad_len = r.u64();
        gcm.data_len = r.u64();
        gcm.phase = Phase::from_u8(r.u8())?;
        (*gcm.tail).copy_from_slice(r.bytes(TAG_LEN));
        gcm.tail_len = bounded_usize(r.u64(), TAG_LEN)?;
        debug_assert!(r.is_done());
        Ok(gcm)
    }
}

/// `N` must be [`Gcm::SUSPENDED_STATE_LEN`]; anything else is a compile error.
impl<P, Dir, const KEY_LEN: usize, const TAG_LEN: usize, const N: usize> SuspendableKeyed<N>
    for Gcm<P, Dir, KEY_LEN, TAG_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, 16>,
{
    type Key = KeyMaterial<KEY_LEN>;

    fn suspend(self) -> [u8; N] {
        suspend_component(&self)
    }

    fn from_suspended(state: [u8; N], key: &Self::Key) -> Result<Self, SuspendableError> {
        resume_component(&state, key)
    }
}
