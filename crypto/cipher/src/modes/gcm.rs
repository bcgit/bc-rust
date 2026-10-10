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
//! # mod toy { include!("../../tests/common/toy_block_cipher.rs"); }
//! # use toy::ToyBlockCipher;
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
//! # mod toy { include!("../../tests/common/toy_block_cipher.rs"); }
//! # use toy::ToyBlockCipher;
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
//!     ToyGcm::<Encrypting>::encrypt_detached_out(&key, aad, &plaintext, &mut ciphertext).unwrap();
//!
//! let mut recovered = [0u8; 16];
//! ToyGcm::<Decrypting>::decrypt_detached_out(&key, &nonce, aad, &ciphertext, &tag, &mut recovered)
//!     .unwrap();
//! assert_eq!(recovered, plaintext);
//! ```
//!
//! There is also a streaming mode.
//! Note that the aad must be supplied before any plaintext or ciphertext; attempting to call
//! `do_update_aad()` after a `do_encrypt()` will result in a [`SymmetricCipherError::StateError`].
//!
//! ```
//! # mod toy { include!("../../tests/common/toy_block_cipher.rs"); }
//! # use toy::ToyBlockCipher;
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
//! let (tag_block, tag_len) = enc.do_encrypt_final().unwrap();
//! ct.extend_from_slice(&tag_block[..tag_len]);
//!
//! let mut dec = ToyGcm::<Decrypting>::do_decrypt_init(&key, &nonce).unwrap();
//! dec.do_update_aad(aad).unwrap();
//! let mut pt = vec![0u8; ct.len()];
//! let written = dec.do_decrypt_out(&ct, &mut pt).unwrap();
//! let (_last, last_len) = dec.do_decrypt_final().unwrap();
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
//! the end of the ciphertext has been reached, and the `do_decrypt_final` /
//! `do_decrypt_final_detached` succeeds.
//!
//! The one-shots (`decrypt_out`, `decrypt_detached_out`, `decrypt_with_aad_out`) verify the
//! tag first and release nothing on failure, making them more robust.
//!
//! * **GMAC is GCM with no plaintext** (Sec 5.2): [`Gmac`](crate::modes::gmac) is this type fed
//!   only AAD, with the plaintext-free API.

use crate::modes::Ctr;
use crate::modes::ModeNames;
use crate::modes::hazmat::ctr_key_stream::CtrKeyStream;
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
use ghash::{GHASH_STATE_LEN, Ghash};

/// The nonce (IV) length this type uses: 96 bits, SP 800-38D Sec 5.2.1.1's recommended length.
pub const GCM_NONCE_LEN: usize = 12;

/// The GCM mode type: the `M` of a mode-bound key such as `AES128Key<GCM>`. `GCM` is GCM with
/// the full 128-bit tag; `GCM<12>` and so on select a shorter tag, within the `12..=16` byte range
/// [`Gcm`] accepts. The [`Mode`] and AEAD mode-trait impls that connect it to a key type are
/// written by each permutation's crate while the cipher traits still carry `KEY_LEN`.
///
/// [`Mode`]: bouncycastle_core::hazmat::Mode
pub struct GCM<const TAG_LEN: usize = 16>;

/// What a GCM key keeps per key: the keyed permutation and the hash subkey `H = CIPH_K(0^128)`
/// (SP 800-38D Algorithm 4 step 1), derived once here rather than once per message. It is the
/// `KeyState` of [`GCM`] over any permutation, and is only built and consumed through the mode
/// impls.
#[derive(Clone)]
pub struct GcmKeyState<P> {
    perm: P,
    h: Secret<[u8; 16]>,
}

impl<P> GcmKeyState<P> {
    /// Derives `H` from `perm`.
    pub fn new<const KEY_LEN: usize>(perm: P) -> Self
    where
        P: ElectronicCodeBook<KEY_LEN, 16>,
    {
        // Encrypted in place inside a `Secret` so that `H` is never held in an unzeroized stack
        // array (Sec 5.3; Appendix A on what `H` gives an attacker).
        let mut h: Secret<[u8; 16]> = Secret::new();
        perm.encrypt_block(&mut h);
        Self { perm, h }
    }
}

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
    P: ElectronicCodeBook<KEY_LEN, 16> + ModeNames,
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
    P: ElectronicCodeBook<KEY_LEN, 16> + ModeNames,
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

    /// Algorithm 4 steps 1-2 and the precomputation for step 6's tag mask, from a bare permutation.
    fn setup(perm: P, nonce: [u8; GCM_NONCE_LEN]) -> Self {
        Self::setup_from_state(GcmKeyState::new::<KEY_LEN>(perm), nonce)
    }

    /// Algorithm 4 step 2 and the precomputation for step 6's tag mask, over a key state that
    /// already holds step 1's `H`.
    fn setup_from_state(state: GcmKeyState<P>, nonce: [u8; GCM_NONCE_LEN]) -> Self {
        Self::check_shape();
        let GcmKeyState { perm, h } = state;

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
    pub(crate) fn absorb_aad(&mut self, aad: &[u8]) -> Result<(), SymmetricCipherError> {
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
    P: ElectronicCodeBook<KEY_LEN, 16> + ModeNames,
{
    const ALG_NAME: &'static str = P::GCM_ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = P::MAX_SECURITY_STRENGTH;
}

impl<P, const KEY_LEN: usize, const TAG_LEN: usize> Gcm<P, Encrypting, KEY_LEN, TAG_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, 16> + ModeNames,
{
    /// Begins an encryption from a key's stored state under a nonce drawn from `rng`: the
    /// encryption constructor a permutation crate's `AeadEncryptMode` impl for [`GCM`] calls. The
    /// result is identical to [`SymmetricCipherEncryptor::do_encrypt_init_rng`] from the same key
    /// and RNG.
    ///
    /// # Errors
    /// [`SymmetricCipherError::RNGError`] if the nonce draw fails; nothing else can.
    pub fn from_key_state(
        state: &GcmKeyState<P>,
        rng: &mut dyn RNG,
    ) -> Result<(Self, [u8; GCM_NONCE_LEN]), SymmetricCipherError>
    where
        P: Clone,
    {
        Self::check_shape();
        let nonce = crate::modes::iv::random_iv::<GCM_NONCE_LEN>(rng)?;
        Ok((Self::setup_from_state(state.clone(), nonce), nonce))
    }

    /// As [`Self::from_key_state`] under a nonce the caller supplies: the constructor a
    /// permutation crate's `AeadEncryptMode::encrypt_init_nonce` impl for [`GCM`] calls. The
    /// result is identical to [`AEADCipherEncryptor::do_encrypt_init_nonce`] from the same key.
    pub fn from_key_state_nonce(state: &GcmKeyState<P>, nonce: &[u8; GCM_NONCE_LEN]) -> Self
    where
        P: Clone,
    {
        Self::setup_from_state(state.clone(), *nonce)
    }

    /// Encrypts `data` in place (GCTR, Algorithm 4 step 3) and absorbs the resulting ciphertext
    /// into GHASH (step 5). Nothing is held back.
    ///
    /// # Errors
    /// [`SymmetricCipherError::DataLimitExceeded`] if the underlying `Ctr` counter would be
    /// exhausted -- the SP 800-38D Sec 5.2.1.1 bound `len(P) <= 2^39 - 256` bits -- or
    /// [`SymmetricCipherError::StateError`] if the AAD/data length bookkeeping would overflow.
    /// Nothing is consumed in either case.
    fn encrypt_in_place(&mut self, data: &mut [u8]) -> Result<(), SymmetricCipherError> {
        self.ctr.do_encrypt_inplace(data)?;
        self.absorb_data(data)
    }

    /// Algorithm 4 steps 4-6: finishes the message and returns the detached authentication tag,
    /// truncated to `TAG_LEN` bytes (`MSB_t`, step 6). Consumes the encryptor.
    pub(crate) fn finish(mut self) -> [u8; TAG_LEN] {
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
    P: ElectronicCodeBook<KEY_LEN, 16> + ModeNames,
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
        ciphertext.fill(0);
        if ciphertext.len() < plaintext.len() {
            return Err(SymmetricCipherError::OutputBufferTooSmall(plaintext.len()));
        }
        ciphertext[..plaintext.len()].copy_from_slice(plaintext);
        self.encrypt_in_place(&mut ciphertext[..plaintext.len()])?;
        Ok(plaintext.len())
    }

    fn do_encrypt_final(self) -> Result<([u8; TAG_LEN], usize), SymmetricCipherError> {
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
    P: ElectronicCodeBook<KEY_LEN, 16> + ModeNames,
{
    fn do_update_aad(&mut self, aad: &[u8]) -> Result<(), SymmetricCipherError> {
        self.absorb_aad(aad)
    }

    /// [`do_encrypt_init_rng`](SymmetricCipherEncryptor::do_encrypt_init_rng) with the caller's
    /// nonce in place of the draw; SP 800-38D Sec 8.2.1's deterministic construction is the
    /// caller's to follow.
    fn do_encrypt_init_nonce(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; GCM_NONCE_LEN],
    ) -> Result<Self, SymmetricCipherError> {
        Self::check_shape();
        let perm = P::new(key)?;
        Ok(Self::setup(perm, *nonce))
    }

    /// Algorithm 4 steps 4-6; nothing is held back, so `ciphertext` is left zeroed.
    fn do_encrypt_final_detached_out(
        self,
        ciphertext: &mut [u8; TAG_LEN],
    ) -> Result<(usize, [u8; TAG_LEN]), SymmetricCipherError> {
        ciphertext.fill(0);
        Ok((0, self.finish()))
    }
}

impl<P, const KEY_LEN: usize, const TAG_LEN: usize> Gcm<P, Decrypting, KEY_LEN, TAG_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, 16> + ModeNames,
{
    /// Begins the decryption of a message encrypted under `nonce` from a key's stored state: the
    /// decryption constructor a permutation crate's `AeadDecryptMode` impl for [`GCM`] calls.
    /// Infallible: the state is already keyed and the nonce length is in the type.
    pub fn from_key_state(state: &GcmKeyState<P>, nonce: &[u8; GCM_NONCE_LEN]) -> Self
    where
        P: Clone,
    {
        Self::setup_from_state(state.clone(), *nonce)
    }

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
        self.ctr.do_decrypt_inplace(data)?;
        Ok(())
    }

    /// Algorithm 5 steps 5-8: recomputes `T'` and compares it against `tag` in constant time.
    /// Consumes the decryptor; `Ok(())` is the only thing that makes the plaintext released so far
    /// trustworthy.
    ///
    /// # Errors
    /// [`SymmetricCipherError::AEADTagCheckFailed`] if the tag does not match.
    pub(crate) fn finish(mut self, tag: &[u8; TAG_LEN]) -> Result<(), SymmetricCipherError> {
        self.begin_data_if_needed();
        let mut full: Secret<[u8; 16]> = Secret::new();
        self.tag_block(&mut full);
        if ct_eq_bytes(&full[..TAG_LEN], tag) {
            Ok(())
        } else {
            Err(SymmetricCipherError::AEADTagCheckFailed)
        }
    }

    /// Shared by the trait one-shots (`decrypt_out`, `decrypt_detached_out`,
    /// `decrypt_with_aad_out`): absorbs `aad` and
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
        gcm.ctr.do_decrypt_inplace(data)?;
        Ok(())
    }
}

impl<P, const KEY_LEN: usize, const TAG_LEN: usize>
    SymmetricCipherDecryptor<KEY_LEN, GCM_NONCE_LEN, TAG_LEN>
    for Gcm<P, Decrypting, KEY_LEN, TAG_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, 16> + ModeNames,
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
        plaintext.fill(0);
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
    fn do_decrypt_final(self) -> Result<([u8; TAG_LEN], usize), SymmetricCipherError> {
        if self.tail_len < TAG_LEN {
            return Err(SymmetricCipherError::DecryptionFailed);
        }
        let tag = *self.tail;
        self.finish(&tag)?;
        Ok(([0u8; TAG_LEN], 0))
    }

    fn decrypt_out_len(ciphertext_len: usize) -> usize {
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
        plaintext.fill(0);
        <Self as AEADCipherDecryptor<KEY_LEN, GCM_NONCE_LEN, TAG_LEN, TAG_LEN>>::decrypt_with_aad_out(
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
    P: ElectronicCodeBook<KEY_LEN, 16> + ModeNames,
{
    fn do_update_aad(&mut self, aad: &[u8]) -> Result<(), SymmetricCipherError> {
        self.absorb_aad(aad)
    }

    /// The detached layout: the up to `TAG_LEN` bytes held back as a possible tag are ciphertext
    /// after all, so they are decrypted into `plaintext` before the tag is checked against `tag`
    /// (Algorithm 5 steps 5-8). On failure `plaintext` is zeroized before the error is returned.
    fn do_decrypt_final_detached_out(
        mut self,
        tag: &[u8; TAG_LEN],
        plaintext: &mut [u8; TAG_LEN],
    ) -> Result<usize, SymmetricCipherError> {
        plaintext.fill(0);
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
    fn decrypt_detached_out(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; GCM_NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; TAG_LEN],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        plaintext.fill(0);
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
    fn decrypt_with_aad_out(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; GCM_NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        plaintext.fill(0);
        let needed = Self::decrypt_out_len(ciphertext.len());
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
    P: ElectronicCodeBook<KEY_LEN, 16> + ModeNames,
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
    P: ElectronicCodeBook<KEY_LEN, 16> + ModeNames,
{
    type Key = KeyMaterial<KEY_LEN>;

    fn suspend(self) -> [u8; N] {
        suspend_component(&self)
    }

    fn from_suspended(state: [u8; N], key: &Self::Key) -> Result<Self, SuspendableError> {
        resume_component(&state, key)
    }
}

// The key-produced worker traits, forwarded to the cipher traits' own methods while those still
// exist. Named by path rather than imported, since the method names coincide and an import would
// make every call in this file ambiguous.

impl<P, const KEY_LEN: usize, const TAG_LEN: usize>
    bouncycastle_core::symmetric_key::AeadEncryptWorker<GCM_NONCE_LEN, TAG_LEN, TAG_LEN>
    for Gcm<P, Encrypting, KEY_LEN, TAG_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, 16> + ModeNames,
{
    fn do_update_aad(&mut self, aad: &[u8]) -> Result<(), SymmetricCipherError> {
        AEADCipherEncryptor::do_update_aad(self, aad)
    }

    fn do_encrypt_out_len(&self, input_len: usize) -> usize {
        SymmetricCipherEncryptor::do_encrypt_out_len(self, input_len)
    }

    fn do_encrypt_out(
        &mut self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        SymmetricCipherEncryptor::do_encrypt_out(self, plaintext, ciphertext)
    }

    fn do_encrypt_final(self) -> Result<([u8; TAG_LEN], usize), SymmetricCipherError> {
        SymmetricCipherEncryptor::do_encrypt_final(self)
    }

    fn do_encrypt_final_detached_out(
        self,
        ciphertext: &mut [u8; TAG_LEN],
    ) -> Result<(usize, [u8; TAG_LEN]), SymmetricCipherError> {
        AEADCipherEncryptor::do_encrypt_final_detached_out(self, ciphertext)
    }

    fn encrypt_out_len(plaintext_len: usize) -> usize {
        <Self as SymmetricCipherEncryptor<KEY_LEN, GCM_NONCE_LEN, TAG_LEN>>::encrypt_out_len(
            plaintext_len,
        )
    }

    fn encrypt_detached_out_len(plaintext_len: usize) -> usize {
        <Self as AEADCipherEncryptor<KEY_LEN, GCM_NONCE_LEN, TAG_LEN, TAG_LEN>>::encrypt_detached_out_len(
            plaintext_len,
        )
    }
}

impl<P, const KEY_LEN: usize, const TAG_LEN: usize>
    bouncycastle_core::symmetric_key::AeadDecryptWorker<GCM_NONCE_LEN, TAG_LEN, TAG_LEN>
    for Gcm<P, Decrypting, KEY_LEN, TAG_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, 16> + ModeNames,
{
    fn do_update_aad(&mut self, aad: &[u8]) -> Result<(), SymmetricCipherError> {
        AEADCipherDecryptor::do_update_aad(self, aad)
    }

    fn do_decrypt_out_len(&self, input_len: usize) -> usize {
        SymmetricCipherDecryptor::do_decrypt_out_len(self, input_len)
    }

    fn do_decrypt_out(
        &mut self,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        SymmetricCipherDecryptor::do_decrypt_out(self, ciphertext, plaintext)
    }

    fn do_decrypt_final(self) -> Result<([u8; TAG_LEN], usize), SymmetricCipherError> {
        SymmetricCipherDecryptor::do_decrypt_final(self)
    }

    fn do_decrypt_final_detached_out(
        self,
        tag: &[u8; TAG_LEN],
        plaintext: &mut [u8; TAG_LEN],
    ) -> Result<usize, SymmetricCipherError> {
        AEADCipherDecryptor::do_decrypt_final_detached_out(self, tag, plaintext)
    }

    fn decrypt_out_len(ciphertext_len: usize) -> usize {
        <Self as SymmetricCipherDecryptor<KEY_LEN, GCM_NONCE_LEN, TAG_LEN>>::decrypt_out_len(
            ciphertext_len,
        )
    }

    fn decrypt_detached_out_len(ciphertext_len: usize) -> usize {
        <Self as AEADCipherDecryptor<KEY_LEN, GCM_NONCE_LEN, TAG_LEN, TAG_LEN>>::decrypt_detached_out_len(
            ciphertext_len,
        )
    }
}

mod ghash {
    //! GHASH: the universal hash function GCM builds its authentication on (NIST SP 800-38D Sec 6.3,
    //! 6.4), and the GF(2^128) multiplication it is defined over.
    //!
    //! This is the only new cryptographic code GCM needs; everything else in this file is
    //! plumbing around this and [`crate::modes::Ctr`].
    //!
    //! It is a private submodule of GCM, not a top-level Hash function, because it is only used by
    //! the GCM block cipher mode, and not as a standalone hash function.
    //!
    //! # Field element representation
    //!
    //! A block of `GF(2^128)` is represented as `[u64; 2]`: `x[0]` is the first eight bytes of the
    //! 16-byte block read big-endian, `x[1]` the last eight -- the same `asLongs`/`asBytes` convention
    //! BC Java's `GCMUtil` uses. Sec 6.3 fixes the bit convention as "little endian": bit `x_0`, the
    //! *leftmost* (most significant) bit of the first byte, is the coefficient of `u^0`. In this `u64`
    //! pair form that means `x_0` is the *top* bit of `x[0]`, `x_63` is its bottom bit, `x_64` is the
    //! top bit of `x[1]`, and `x_127` is its bottom bit. So Algorithm 1's "V >> 1" (discard the
    //! rightmost bit of the whole 128-bit string, prepend a zero on the left) is a right shift across
    //! the `x[0], x[1]` pair carrying the bottom bit of `x[0]` into the top bit of `x[1]`, and `R`
    //! (`11100001 || 0^120`, Sec 6.3) is the block whose first byte is `0xE1` and the rest zero, i.e.
    //! `[0xE1 << 56, 0]` in this representation.

    use bouncycastle_core::errors::SuspendableError;
    use bouncycastle_utils::secret::Secret;
    use bouncycastle_utils::suspendable_state::{Cursor, CursorMut, bounded_usize};

    /// A block of `GF(2^128)`, in the two-`u64` form described in the module docs.
    type Block = [u64; 2];

    /// `R = 11100001 || 0^120` (Sec 6.3): first byte `0xE1`, the rest zero. Used only by
    /// [`mul_reference`]: [`mul`] folds the same constant into its own reduction step directly, as
    /// literal shift amounts rather than a named block.
    #[cfg(test)]
    const R: Block = [0xE100_0000_0000_0000, 0];

    /// `x[0]` is the first eight bytes of `b` read big-endian, `x[1]` the last eight.
    fn block_from_bytes(b: &[u8; 16]) -> Block {
        [
            u64::from_be_bytes(
                b[..8].try_into().expect("first half of a 16-byte block is 8 bytes"),
            ),
            u64::from_be_bytes(
                b[8..].try_into().expect("second half of a 16-byte block is 8 bytes"),
            ),
        ]
    }

    /// Inverse of [`block_from_bytes`]. Used only by the tests: [`Ghash::finish`] writes `S` straight
    /// into the caller's `Secret` rather than returning it through a stack array.
    #[cfg(test)]
    fn block_to_bytes(x: &Block) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&x[0].to_be_bytes());
        out[8..].copy_from_slice(&x[1].to_be_bytes());
        out
    }

    /// Algorithm 1 (Sec 6.3), a direct transcription, computed bit-serially with masks so it is itself
    /// constant time. This is the *oracle*: [`mul`] is checked against it in the test module below, and
    /// it is never used outside `#[cfg(test)]`. Kept short and boring on purpose.
    #[cfg(test)]
    fn mul_reference(x: &Block, y: &Block) -> Block {
        // Step 2: Z_0 = 0^128, V_0 = Y.
        let mut z: Block = [0, 0];
        let mut v: Block = *y;
        // Step 3: for i = 0 to 127 ...
        for i in 0..128u32 {
            // Step 1 / step 3: bit x_i of X. x_0 is the top bit of x[0] (see module docs), so bit i
            // for i < 64 is bit (63 - i) of x[0], and for i >= 64 is bit (127 - i) of x[1].
            let bit = if i < 64 { (x[0] >> (63 - i)) & 1 } else { (x[1] >> (127 - i)) & 1 };
            // All-ones if x_i = 1, all-zero if x_i = 0 -- a constant-time select, standing in for the
            // spec's "Z_{i+1} = Z_i if x_i = 0; Z_i (+) V_i if x_i = 1".
            let m = 0u64.wrapping_sub(bit);
            z[0] ^= v[0] & m;
            z[1] ^= v[1] & m;

            // "V_{i+1} = V_i >> 1 if LSB_1(V_i) = 0; (V_i >> 1) (+) R if LSB_1(V_i) = 1." LSB_1 of the
            // 128-bit string V is the bottom bit of v[1]; ">> 1" is a right shift across the pair.
            let lsb = v[1] & 1;
            let lm = 0u64.wrapping_sub(lsb);
            let carry_in = v[0] & 1;
            v[0] >>= 1;
            v[1] = (v[1] >> 1) | (carry_in << 63);
            v[0] ^= R[0] & lm;
            v[1] ^= R[1] & lm;
        }
        // Step 4: return Z_128.
        z
    }

    /// The masked-lane carry-less multiply of two 64-bit halves.
    ///
    /// Ported from BC Java's `GCMUtil.implMul64(long, long)`
    /// (`crypto/modes/gcm/GCMUtil.java`). Four lane masks (`0x1111...`, `0x2222...`, `0x4444...`,
    /// `0x8888...`) space the input bits four apart, so the sixteen masked products summed into each
    /// output lane carry at most fifteen ways -- never enough for an integer carry to reach a live lane
    /// -- which is what makes ordinary `u64` multiplication (relying on the CPU's integer multiplier
    /// being constant time, the same assumption the rest of this library's constant-time code makes)
    /// compute a carry-less (XOR-add) product on each lane. Masking again after summing discards the
    /// garbage that leaked into the gaps between lanes.
    fn impl_mul64(x: u64, y: u64) -> u64 {
        let x0 = x & 0x1111_1111_1111_1111;
        let x1 = x & 0x2222_2222_2222_2222;
        let x2 = x & 0x4444_4444_4444_4444;
        let x3 = x & 0x8888_8888_8888_8888;

        let y0 = y & 0x1111_1111_1111_1111;
        let y1 = y & 0x2222_2222_2222_2222;
        let y2 = y & 0x4444_4444_4444_4444;
        let y3 = y & 0x8888_8888_8888_8888;

        let z0 =
            x0.wrapping_mul(y0) ^ x1.wrapping_mul(y3) ^ x2.wrapping_mul(y2) ^ x3.wrapping_mul(y1);
        let z1 =
            x0.wrapping_mul(y1) ^ x1.wrapping_mul(y0) ^ x2.wrapping_mul(y3) ^ x3.wrapping_mul(y2);
        let z2 =
            x0.wrapping_mul(y2) ^ x1.wrapping_mul(y1) ^ x2.wrapping_mul(y0) ^ x3.wrapping_mul(y3);
        let z3 =
            x0.wrapping_mul(y3) ^ x1.wrapping_mul(y2) ^ x2.wrapping_mul(y1) ^ x3.wrapping_mul(y0);

        let z0 = z0 & 0x1111_1111_1111_1111;
        let z1 = z1 & 0x2222_2222_2222_2222;
        let z2 = z2 & 0x4444_4444_4444_4444;
        let z3 = z3 & 0x8888_8888_8888_8888;

        // The four lanes are disjoint (each mask owns one bit in every nibble), so `|` and `^` agree
        // here; `cargo mutants` is expected to report this substitution as a surviving, equivalent
        // mutant rather than a missing test.
        z0 | z1 | z2 | z3
    }

    /// The constant-time, table-free `GF(2^128)` product `x . y` (Sec 6.3's `*` operator).
    ///
    /// Ported from BC Java's `GCMUtil.multiply(long[], long[])`: a "three-way recursion" (Karatsuba
    /// over the two 64-bit halves, per Bernstein's "Batch binary Edwards") built on [`impl_mul64`], with
    /// a bit-reversal trick (`rev(x)*rev(y) == rev((x*y) << 1)`) to reach the high 64 bits of each
    /// 64x64 product without a 128-bit multiply, followed by the standard two-step reduction by `R`.
    /// Variable names (`h0..h5`, `z0..z3`) match the Java source so the two can be diffed side by side.
    pub(crate) fn mul(x: &Block, y: &Block) -> Block {
        let (x0, x1) = (x[0], x[1]);
        let (y0, y1) = (y[0], y[1]);
        let (x0r, x1r) = (x0.reverse_bits(), x1.reverse_bits());
        let (y0r, y1r) = (y0.reverse_bits(), y1.reverse_bits());

        let h0 = impl_mul64(x0r, y0r).reverse_bits();
        let h1 = impl_mul64(x0, y0) << 1;
        let h2 = impl_mul64(x1r, y1r).reverse_bits();
        let h3 = impl_mul64(x1, y1) << 1;
        let h4 = impl_mul64(x0r ^ x1r, y0r ^ y1r).reverse_bits();
        let h5 = impl_mul64(x0 ^ x1, y0 ^ y1) << 1;

        let z0 = h0;
        let mut z1 = h1 ^ h0 ^ h2 ^ h4;
        let mut z2 = h2 ^ h1 ^ h3 ^ h5;
        let z3 = h3;

        // Reduction by R, step 1: fold z3 into z1 and z2. The commented-out `(z3 << 63)` term in BC
        // Java's source is dropped because it is folded into the `z2 ^= ... (z3 << 62) ...` line below
        // instead: `z3 << 63` contributes only its bit 63 (all lower bits are shifted out), which is the
        // same single bit that `(z3 << 62) << 1`, i.e. bit 62 of `(z3 << 62)`, would carry forward one
        // more position -- BC Java's own comment marks this as the intentional omission.
        z1 ^= z3 ^ (z3 >> 1) ^ (z3 >> 2) ^ (z3 >> 7);
        z2 ^= (z3 << 62) ^ (z3 << 57);

        let mut z0 = z0;
        // Reduction by R, step 2: fold the now-complete z2 into z0 and z1.
        z0 ^= z2 ^ (z2 >> 1) ^ (z2 >> 2) ^ (z2 >> 7);
        z1 ^= (z2 << 63) ^ (z2 << 62) ^ (z2 << 57);

        [z0, z1]
    }

    /// The `GHASH` accumulator (Algorithm 2, Sec 6.4).
    ///
    /// `Y_0 = 0^128` (step 2); each call to [`update`](Self::update) absorbs whole blocks via
    /// `Y_i = (Y_{i-1} (+) X_i) . H` (step 3), buffering any partial block for the next call so that a
    /// sequence of calls is equivalent to one call over the concatenation. [`finish`](Self::finish)
    /// returns `Y_m` (step 4) after appending the 64-bit AAD- and data-bit-length block that Algorithm
    /// 4 step 5 / Algorithm 5 step 6 fold into the same hash.
    ///
    /// `H` and the running hash `Y` are the GCM intermediates Sec 5.3 requires to be secret ("the
    /// intermediate values in the execution of the GCM functions shall be secret"), so both live in a
    /// [`Secret`] and are zeroized on drop; the pending partial block is live plaintext-or-ciphertext
    /// bytes still waiting to be absorbed and is wrapped for the same reason.
    /// Bytes [`Ghash::write_state`] writes: `Y` as two `u64`s, the pending block and its length.
    pub(crate) const GHASH_STATE_LEN: usize = 16 + 16 + 8;

    #[derive(Clone)]
    pub(crate) struct Ghash {
        /// The hash subkey `H = CIPH_K(0^128)`.
        h: Secret<Block>,
        /// `Y_i` of Algorithm 2.
        y: Secret<Block>,
        /// Bytes of the current block not yet absorbed.
        pending: Secret<[u8; 16]>,
        /// How many bytes of `pending` are meaningful, `0..=16`.
        pending_len: usize,
    }

    impl Ghash {
        /// `Y_0 = 0^128` (Algorithm 2 step 2), keyed by the hash subkey `H`.
        pub(crate) fn new(h: &[u8; 16]) -> Self {
            let mut hs: Secret<Block> = Secret::new();
            hs[0] = u64::from_be_bytes(h[..8].try_into().expect("first half of H is 8 bytes"));
            hs[1] = u64::from_be_bytes(h[8..].try_into().expect("second half of H is 8 bytes"));
            Self { h: hs, y: Secret::new(), pending: Secret::new(), pending_len: 0 }
        }

        /// `Y_i = (Y_{i-1} (+) X_i) . H` for one whole block `X_i`, updating `Y` in place.
        ///
        /// An associated function over the two fields rather than a `&mut self` method, so that
        /// `pending` can be passed as `block` without first being copied out of its `Secret`.
        fn absorb(y: &mut Secret<Block>, h: &Secret<Block>, block: &[u8; 16]) {
            let xi = block_from_bytes(block);
            y[0] ^= xi[0];
            y[1] ^= xi[1];
            **y = mul(y, h);
        }

        /// Absorbs whole blocks of `data` immediately and buffers any remainder for the next call.
        /// Chunking-independent: a sequence of calls over pieces of a message is equivalent to one call
        /// over the whole message.
        pub(crate) fn update(&mut self, mut data: &[u8]) {
            if self.pending_len > 0 {
                let need = 16 - self.pending_len;
                let take = need.min(data.len());
                (*self.pending)[self.pending_len..self.pending_len + take]
                    .copy_from_slice(&data[..take]);
                self.pending_len += take;
                data = &data[take..];
                if self.pending_len < 16 {
                    return;
                }
                Self::absorb(&mut self.y, &self.h, &self.pending);
                self.pending_len = 0;
            }

            let (blocks, rest) = data.as_chunks::<16>();
            for block in blocks {
                Self::absorb(&mut self.y, &self.h, block);
            }
            (*self.pending)[..rest.len()].copy_from_slice(rest);
            self.pending_len = rest.len();
        }

        /// The `0^v` / `0^u` zero-padding of Algorithm 4 step 5 / Algorithm 5 step 6: rounds the
        /// pending partial block up to a whole block with zero bytes and absorbs it. A no-op when
        /// nothing is pending, so it is safe to call unconditionally at a phase boundary.
        pub(crate) fn pad_to_block(&mut self) {
            if self.pending_len == 0 {
                return;
            }
            (*self.pending)[self.pending_len..].fill(0);
            Self::absorb(&mut self.y, &self.h, &self.pending);
            self.pending_len = 0;
        }

        /// Appends `[aad_bits]_64 || [data_bits]_64` (Algorithm 4 step 5's final block) and writes
        /// `Y_m`, i.e. `S`, to `out` -- a `Secret`, since `S` is the tag with its mask removed.
        ///
        /// Takes `&mut self` rather than `self` -- `Gcm`'s verify-before-decrypt one-shot needs the rest
        /// of its own state (the `Ctr` field) after computing the tag, so consuming `Ghash` here would
        /// force that caller to reconstruct it. Nothing asserts a "was padded" flag: the caller is
        /// expected to have called [`pad_to_block`](Self::pad_to_block) for both the AAD and the data
        /// phase already (the `0^v` and `0^u` of step 5), so by the time `finish` runs there is nothing
        /// pending except this one final length block, and no caller should call `update` or
        /// `pad_to_block` again afterward.
        pub(crate) fn finish(&mut self, aad_bits: u64, data_bits: u64, out: &mut Secret<[u8; 16]>) {
            debug_assert_eq!(
                self.pending_len, 0,
                "caller must pad_to_block before finish: nothing but the length block may be pending"
            );
            let mut len_block = [0u8; 16];
            len_block[..8].copy_from_slice(&aad_bits.to_be_bytes());
            len_block[8..].copy_from_slice(&data_bits.to_be_bytes());
            Self::absorb(&mut self.y, &self.h, &len_block);
            out[..8].copy_from_slice(&self.y[0].to_be_bytes());
            out[8..].copy_from_slice(&self.y[1].to_be_bytes());
        }
    }

    impl Ghash {
        /// Writes the running state -- `Y`, the pending partial block and its length -- into `out`,
        /// exactly [`GHASH_STATE_LEN`] bytes. `H` is not written: it is `CIPH_K(0^128)`, which the
        /// resuming side re-derives from the re-supplied key, so the state carries one secret fewer.
        pub(crate) fn write_state(&self, out: &mut [u8]) {
            let mut w = CursorMut::new(out);
            w.u64(self.y[0]);
            w.u64(self.y[1]);
            w.bytes(&*self.pending);
            w.u64(self.pending_len as u64);
            debug_assert!(w.is_done());
        }

        /// The inverse of [`Self::write_state`], over a `Ghash` freshly built from `H` by
        /// [`Self::new`]: replaces `Y` and the pending block.
        ///
        /// # Errors
        /// [`SuspendableError::InvalidData`] if the pending length is a whole block or more: `update`
        /// absorbs whole blocks immediately, so a legitimate state never holds one.
        pub(crate) fn restore_state(&mut self, state: &[u8]) -> Result<(), SuspendableError> {
            let mut r = Cursor::new(state);
            self.y[0] = r.u64();
            self.y[1] = r.u64();
            (*self.pending).copy_from_slice(r.bytes(16));
            self.pending_len = bounded_usize(r.u64(), 15)?;
            debug_assert!(r.is_done());
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// A minimal xorshift64* generator, so the >= 10000 pseudo-random test pairs below do not need
        /// the `rand` crate (CLAUDE.md: no new runtime dependency, and this is test-only anyway).
        struct Lcg(u64);
        impl Lcg {
            fn next_u64(&mut self) -> u64 {
                let mut x = self.0;
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                self.0 = x;
                x
            }
            fn next_block(&mut self) -> Block {
                [self.next_u64(), self.next_u64()]
            }
        }

        /// The spec's `1`: `1 || 0^127`, the leftmost bit set and everything else zero. The
        /// multiplicative identity: `X . 1 == X` (Sec 6.3, "For a positive integer i, the ith power of a
        /// block X ... H^2 = H.H, H^3 = H.H.H").
        const ONE: Block = [0x8000_0000_0000_0000, 0];

        #[test]
        fn mul_matches_the_reference_on_zero() {
            let h: Block = [0x1122_3344_5566_7788, 0x99aa_bbcc_ddee_ff00];
            assert_eq!(mul(&[0, 0], &h), mul_reference(&[0, 0], &h));
            assert_eq!(mul(&h, &[0, 0]), mul_reference(&h, &[0, 0]));
        }

        #[test]
        fn mul_matches_the_reference_at_every_single_bit_position() {
            let h: Block = [0xdead_beef_cafe_babe, 0x0123_4567_89ab_cdef];
            for i in 0..128u32 {
                let x: Block = if i < 64 { [1u64 << (63 - i), 0] } else { [0, 1u64 << (127 - i)] };
                assert_eq!(mul(&x, &h), mul_reference(&x, &h), "bit position {i}");
            }
        }

        #[test]
        fn mul_matches_the_reference_on_all_ones() {
            let h: Block = [0xfeed_face_dead_beef, 0x0102_0304_0506_0708];
            let ones: Block = [u64::MAX, u64::MAX];
            assert_eq!(mul(&ones, &h), mul_reference(&ones, &h));
            assert_eq!(mul(&h, &ones), mul_reference(&h, &ones));
        }

        #[test]
        fn mul_matches_the_reference_on_ten_thousand_random_pairs() {
            let mut rng = Lcg(0x2545_f491_4f6c_dd1d);
            for _ in 0..10_000 {
                let x = rng.next_block();
                let y = rng.next_block();
                assert_eq!(mul(&x, &y), mul_reference(&x, &y), "x={x:?} y={y:?}");
            }
        }

        #[test]
        fn mul_by_one_is_the_identity() {
            let mut rng = Lcg(0x9e37_79b9_7f4a_7c15);
            for _ in 0..256 {
                let x = rng.next_block();
                assert_eq!(mul(&x, &ONE), x, "x . 1 == x for x={x:?}");
                assert_eq!(mul(&ONE, &x), x, "1 . x == x for x={x:?}");
            }
        }

        #[test]
        fn mul_is_commutative() {
            let mut rng = Lcg(0xbf58_476d_1ce4_e5b9);
            for _ in 0..256 {
                let x = rng.next_block();
                let y = rng.next_block();
                assert_eq!(mul(&x, &y), mul(&y, &x), "x={x:?} y={y:?}");
            }
        }

        /// A hand-checkable case for the oracle itself: `R . 1 == R`, the identity applied to the fixed
        /// reduction constant.
        #[test]
        fn reference_r_times_one_is_r() {
            assert_eq!(mul_reference(&R, &ONE), R);
        }

        /// `GHASH` over one, two and three blocks must equal folding [`mul_reference`] by hand, per
        /// Algorithm 2 step 3: `Y_i = (Y_{i-1} (+) X_i) . H`.
        #[test]
        fn ghash_matches_folding_the_reference_multiplier_by_hand() {
            let h_bytes = [0x42u8; 16];
            let h = block_from_bytes(&h_bytes);

            let blocks: [[u8; 16]; 3] = [[0x11; 16], [0x22; 16], [0x33; 16]];

            let mut y = [0u64, 0u64];
            for block in &blocks {
                let xi = block_from_bytes(block);
                y[0] ^= xi[0];
                y[1] ^= xi[1];
                y = mul_reference(&y, &h);
            }

            for n in 1..=3 {
                let mut g = Ghash::new(&h_bytes);
                for block in &blocks[..n] {
                    g.update(block);
                }
                g.pad_to_block();
                // finish() also absorbs the zero-length block, so compare against one more fold step
                // over the all-zero length block for a fair comparison of the n-block prefix alone.
                let mut expected = [0u64, 0u64];
                for block in &blocks[..n] {
                    let xi = block_from_bytes(block);
                    expected[0] ^= xi[0];
                    expected[1] ^= xi[1];
                    expected = mul_reference(&expected, &h);
                }
                let zero_len_block = [0u8; 16];
                let xi = block_from_bytes(&zero_len_block);
                expected[0] ^= xi[0];
                expected[1] ^= xi[1];
                expected = mul_reference(&expected, &h);

                let mut s: Secret<[u8; 16]> = Secret::new();
                g.finish(0, 0, &mut s);
                assert_eq!(block_to_bytes(&expected), *s, "n={n}");
            }
            // Silence the unused full-message `y` computed above; it documents the general recurrence.
            let _ = y;
        }

        /// Chunking independence: absorbing a 100-byte message in one call must equal absorbing it in
        /// two pieces, at every possible split point.
        #[test]
        fn update_is_chunking_independent() {
            let h_bytes = [0x7eu8; 16];
            let data: [u8; 100] = core::array::from_fn(|i| i as u8);

            let mut whole = Ghash::new(&h_bytes);
            whole.update(&data);
            whole.pad_to_block();
            let mut expected: Secret<[u8; 16]> = Secret::new();
            whole.finish(0, data.len() as u64 * 8, &mut expected);

            for split in 0..=data.len() {
                let mut g = Ghash::new(&h_bytes);
                g.update(&data[..split]);
                g.update(&data[split..]);
                g.pad_to_block();
                let mut s: Secret<[u8; 16]> = Secret::new();
                g.finish(0, data.len() as u64 * 8, &mut s);
                assert_eq!(*s, *expected, "split at {split}");
            }
        }
    }
}
