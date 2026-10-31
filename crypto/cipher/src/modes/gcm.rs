//! Galois/Counter Mode (NIST SP 800-38D), the authenticated encryption mode built from CTR
//! and the GHASH universal hash.
//!
//! # Nonce and Tag
//!
//! [`Gcm`] fixes the nonce at 96 bits (12 bytes, [`GCM_NONCE_LEN`]): SP 800-38D Sec 5.2.1.1
//! recommends that implementations "restrict support to the length of 96 bits", and the other IV
//! lengths are not implemented. The nonce is drawn from the RNG the key is given, or supplied
//! through the `_nonce` forms, which put its uniqueness on the caller.
//!
//! The tag length is a const generic `TAG_LEN`, checked at compile time to lie in `12..=16` bytes
//! (96, 104, 112, 120 or 128 bits -- Sec 5.2.1.2's five recommended values). The 32- and 64-bit tags
//! Sec 5.2.1.2 permits "for certain applications" (Appendix C) are not supported.
//!
//! # Usage Examples
//!
//! [`Gcm`] is the worker a mode-bound key hands out -- [`GCM`] on a key type such as
//! `bouncycastle_aes::AES128Key<GCM>`, whose AEAD role traits carry the one-shots -- and it
//! implements [`AEADCipherEncryptor`] / [`AEADCipherDecryptor`] with `FINAL_LEN = TAG_LEN`, and the
//! [`SymmetricCipherEncryptor`] / [`SymmetricCipherDecryptor`] traits they extend. The key holds a
//! [`GcmKeyState`] and starts each message from it, which is the route over the toy permutation.
//!
//! Through the SymmetricCipher methods there is no additional associated data (aad), and the tag
//! is inlined into the ciphertext as `ciphertext || tag`:
//!
//! ```
//! # mod toy { include!("../../tests/common/toy_block_cipher.rs"); }
//! # use toy::ToyBlockCipher;
//! use bouncycastle_core::errors::SymmetricCipherError;
//! use bouncycastle_core::hazmat::ElectronicCodeBook;
//! use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
//! use bouncycastle_core::traits::{SymmetricCipherDecryptor, SymmetricCipherEncryptor};
//! use bouncycastle_cipher::modes::{Gcm, GcmKeyState};
//! use bouncycastle_cipher::{Decrypting, Encrypting};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! type ToyGcm<'k, Dir> = Gcm<'k, ToyBlockCipher, Dir, 16>;
//!
//! let key = KeyMaterial128::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//! let state = GcmKeyState::new(ToyBlockCipher::new(&key).unwrap());
//! let plaintext: [u8; 16] = *b"attack at dawn!!";
//!
//! let (mut enc, nonce) = ToyGcm::<Encrypting>::from_key_state(&state, &mut HashDRBG_SHA512::new_from_os())
//!     .expect("nonce draw");
//! let mut ciphertext = vec![0u8; 16 + 16];
//! let n = enc.do_encrypt_out(&plaintext, &mut ciphertext).expect("encrypt");
//! let (tag, tag_len) = enc.do_encrypt_final().expect("the tag");
//! ciphertext[n..].copy_from_slice(&tag[..tag_len]);
//!
//! let open = |ct: &[u8]| -> Result<Vec<u8>, SymmetricCipherError> {
//!     let mut dec = ToyGcm::<Decrypting>::from_key_state(&state, &nonce);
//!     let mut pt = vec![0u8; ct.len()];
//!     let n = dec.do_decrypt_out(ct, &mut pt)?;
//!     let (last, last_len) = dec.do_decrypt_final()?;
//!     pt.truncate(n);
//!     pt.extend_from_slice(&last[..last_len]);
//!     Ok(pt)
//! };
//! assert_eq!(open(&ciphertext).expect("decrypt"), plaintext);
//!
//! // A tampered ciphertext will be caught by the tag
//! let mut tampered_ct = ciphertext.clone();
//! tampered_ct[1] ^= 0xFF;
//! assert_eq!(open(&tampered_ct).unwrap_err(), SymmetricCipherError::AEADTagCheckFailed);
//! ```
//!
//! The AEADCipher methods provide the AEAD-specific functionality, including accepting the aad,
//! and the `_detached` finals handle the tag separately, instead of inlined into the ciphertext.
//! The aad must be supplied before any plaintext or ciphertext; attempting to call
//! `do_update_aad()` after a `do_encrypt()` will result in a [`SymmetricCipherError::StateError`].
//!
//! ```
//! # mod toy { include!("../../tests/common/toy_block_cipher.rs"); }
//! # use toy::ToyBlockCipher;
//! use bouncycastle_core::hazmat::ElectronicCodeBook;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::{
//!     AEADCipherDecryptor, AEADCipherEncryptor, SymmetricCipherDecryptor, SymmetricCipherEncryptor,
//! };
//! use bouncycastle_cipher::modes::{Gcm, GcmKeyState};
//! use bouncycastle_cipher::{Decrypting, Encrypting};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! type ToyGcm<'k, Dir> = Gcm<'k, ToyBlockCipher, Dir, 16>;
//!
//! let key = KeyMaterial::<16>::from_bytes_as_type(&[0x07; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//! let state = GcmKeyState::new(ToyBlockCipher::new(&key).unwrap());
//! let aad = b"some associated data";
//! let message = b"a message that streams in over more than one call";
//!
//! let (mut enc, nonce) =
//!     ToyGcm::<Encrypting>::from_key_state(&state, &mut HashDRBG_SHA512::new_from_os()).unwrap();
//! enc.do_update_aad(aad).unwrap();
//! let mut ct = vec![0u8; message.len()];
//! enc.do_encrypt_out(message, &mut ct).unwrap();
//! let (_, tag) = enc.do_encrypt_final_detached_out(&mut [0u8; 16]).unwrap();
//!
//! let mut dec = ToyGcm::<Decrypting>::from_key_state(&state, &nonce);
//! dec.do_update_aad(aad).unwrap();
//! let mut pt = vec![0u8; ct.len()];
//! let written = dec.do_decrypt_out(&ct, &mut pt).unwrap();
//! let mut last = [0u8; 16];
//! let last_len = dec.do_decrypt_final_detached_out(&tag, &mut last).unwrap();
//! pt.truncate(written);
//! pt.extend_from_slice(&last[..last_len]);
//! assert_eq!(pt, message);
//! ```
//!
//! The same with an inline tag:
//!
//! ```
//! # mod toy { include!("../../tests/common/toy_block_cipher.rs"); }
//! # use toy::ToyBlockCipher;
//! use bouncycastle_core::hazmat::ElectronicCodeBook;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::{
//!     AEADCipherDecryptor, AEADCipherEncryptor, SymmetricCipherDecryptor, SymmetricCipherEncryptor,
//! };
//! use bouncycastle_cipher::modes::{Gcm, GcmKeyState};
//! use bouncycastle_cipher::{Decrypting, Encrypting};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! type ToyGcm<'k, Dir> = Gcm<'k, ToyBlockCipher, Dir, 16>;
//!
//! let key = KeyMaterial::<16>::from_bytes_as_type(&[0x07; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//! let state = GcmKeyState::new(ToyBlockCipher::new(&key).unwrap());
//! let aad = b"some associated data";
//! let message = b"a message that streams in over more than one call";
//!
//! let (mut enc, nonce) =
//!     ToyGcm::<Encrypting>::from_key_state(&state, &mut HashDRBG_SHA512::new_from_os()).unwrap();
//! enc.do_update_aad(aad).unwrap();
//! let mut ct = vec![0u8; message.len()];
//! enc.do_encrypt_out(message, &mut ct).unwrap();
//! let (tag_block, tag_len) = enc.do_encrypt_final().unwrap();
//! ct.extend_from_slice(&tag_block[..tag_len]);
//!
//! let mut dec = ToyGcm::<Decrypting>::from_key_state(&state, &nonce);
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
//! array and resumed later over the re-supplied key state. The state is the CTR half, the running
//! GHASH, the byte counts, the phase with the direction it was suspended in, and whatever a
//! decryptor is holding back as a possible tag; `H` is the key state's and the tag mask is
//! re-derived from it. A state resumes only in its own direction: the other type refuses it. The array length is `Gcm::SUSPENDED_STATE_LEN`; see [the crate
//! docs](crate#suspending-and-resuming-execution) for an example.
//!
//! # 🚨 Security Considerations 🚨
//!
//! ## Nonce uniqueness
//!
//! As with all symmetric cipher modes, repeated key and nonce for multiple messages is catastrophic
//! for security, which is why the key's `create_encryptor` draws the nonce from the caller's RNG.
//! The forms that take a supplied nonce, `create_encryptor_nonce` and the `_nonce` one-shots on
//! the key and [`Gcm::from_key_state_nonce`] here, leave uniqueness to the caller.
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
//! The one-shots (`decrypt_out`, `decrypt_detached_out`, `decrypt_with_aad_out`) zeroize their
//! output buffer when the tag check fails, so nothing is released on failure.
//!
//! * **GMAC is GCM with no plaintext** (Sec 5.2): [`Gmac`](crate::modes::gmac) is this type fed
//!   only AAD, with the plaintext-free API.

use crate::modes::Ctr;
use crate::modes::ModeNames;
use crate::modes::hazmat::ctr_key_stream::CtrKeyStream;
use crate::{Decrypting, Direction, Encrypting};
use bouncycastle_core::errors::{SuspendableError, SymmetricCipherError};
use bouncycastle_core::hazmat::{
    AeadDecryptMode, AeadEncryptMode, BlockPermutation, ElectronicCodeBook, Mode,
};
use bouncycastle_core::key_material::KeyType;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, Algorithm, RNG, StreamCipherDecryptor,
    StreamCipherEncryptor, SuspendableKeyed, SymmetricCipherDecryptor, SymmetricCipherEncryptor,
};
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

/// Sec 5.2.1.1's `len(A) <= 2^64 - 1` bits, in bytes.
const MAX_AAD_LEN: u64 = (1 << 61) - 1;

/// Sec 5.2.1.1's `len(P) <= 2^39 - 256` bits, in bytes: the `2^32 - 2` counter blocks left once
/// `J0` and `inc32(J0)` are taken, which is also where the keystream runs out.
const MAX_DATA_LEN: u64 = (1 << 36) - 32;

/// The GCM mode type: the `M` of a mode-bound key such as `AES128Key<GCM>`. `GCM` is GCM with
/// the full 128-bit tag; `GCM<12>` and so on select a shorter tag, within the `12..=16` byte range
/// [`Gcm`] accepts. The [`Mode`] and AEAD mode-trait impls below are generic over any
/// [`BlockPermutation`] with a 128-bit block, so a permutation crate's key type needs nothing of
/// its own.
pub struct GCM<const TAG_LEN: usize = 16>;

impl<P, const TAG_LEN: usize> Mode<P> for GCM<TAG_LEN>
where
    P: BlockPermutation<16> + ModeNames + Clone,
{
    type KeyState = GcmKeyState<P>;
    const KEY_TYPE: KeyType = KeyType::SymmetricCipherKey;

    fn key_state(perm: P) -> Self::KeyState {
        GcmKeyState::new(perm)
    }
}

impl<P, const KEY_LEN: usize, const TAG_LEN: usize>
    AeadEncryptMode<P, KEY_LEN, GCM_NONCE_LEN, TAG_LEN, TAG_LEN> for GCM<TAG_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, 16> + ModeNames + Clone,
{
    type Encryptor<'k>
        = Gcm<'k, P, Encrypting, TAG_LEN>
    where
        P: 'k;

    fn encrypt_init<'k>(
        state: &'k Self::KeyState,
        rng: &mut dyn RNG,
    ) -> Result<(Self::Encryptor<'k>, [u8; GCM_NONCE_LEN]), SymmetricCipherError> {
        Gcm::<P, Encrypting, TAG_LEN>::from_key_state(state, rng)
    }

    fn encrypt_init_nonce<'k>(
        state: &'k Self::KeyState,
        nonce: &[u8; GCM_NONCE_LEN],
    ) -> Self::Encryptor<'k> {
        Gcm::<P, Encrypting, TAG_LEN>::from_key_state_nonce(state, nonce)
    }
}

impl<P, const KEY_LEN: usize, const TAG_LEN: usize>
    AeadDecryptMode<P, KEY_LEN, GCM_NONCE_LEN, TAG_LEN, TAG_LEN> for GCM<TAG_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, 16> + ModeNames + Clone,
{
    type Decryptor<'k>
        = Gcm<'k, P, Decrypting, TAG_LEN>
    where
        P: 'k;

    fn decrypt_init<'k>(
        state: &'k Self::KeyState,
        nonce: &[u8; GCM_NONCE_LEN],
    ) -> Self::Decryptor<'k> {
        Gcm::<P, Decrypting, TAG_LEN>::from_key_state(state, nonce)
    }
}

/// What a GCM key keeps per key: the keyed permutation and the hash subkey `H = CIPH_K(0^128)`
/// (SP 800-38D Algorithm 4 step 1), derived once here rather than once per message. It is the
/// `KeyState` of [`GCM`] over any permutation: built by [`new`](Self::new) or through the mode
/// impls, and consumed through them.
#[derive(Clone)]
pub struct GcmKeyState<P> {
    perm: P,
    h: Secret<[u8; 16]>,
}

// Both fields are compared, joined with `&` rather than `&&` so that the time taken does not say
// which of them differed. `P`'s equality is expected to be constant-time, as a keyed permutation's
// must be; `H`'s is `Secret`'s.
impl<P: PartialEq> PartialEq for GcmKeyState<P> {
    fn eq(&self, other: &Self) -> bool {
        (self.perm == other.perm) & (self.h == other.h)
    }
}

impl<P: Eq> Eq for GcmKeyState<P> {}

impl<P> GcmKeyState<P> {
    /// Derives `H` from `perm`.
    pub fn new(perm: P) -> Self
    where
        P: BlockPermutation<16>,
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
/// [`GCM_NONCE_LEN`] / `TAG_LEN` for what is fixed and what is chosen. A worker borrows the key
/// state it was made from for `'k`: the schedule and `H` stay in the key.
#[derive(Clone)]
pub struct Gcm<'k, P, Dir, const TAG_LEN: usize>
where
    P: BlockPermutation<16> + ModeNames,
{
    /// `GCTR_K(inc32(J0), .)`: Algorithm 4 step 3 / Algorithm 5 step 4, started at counter 2 (see
    /// [`Gcm::setup`]).
    ctr: Ctr<'k, P, Dir, 16, GCM_NONCE_LEN>,
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

impl<'k, P, Dir, const TAG_LEN: usize> Gcm<'k, P, Dir, TAG_LEN>
where
    P: BlockPermutation<16> + ModeNames,
{
    /// The `N` of this type's [`SuspendableKeyed<'k, N>`] impl: the version header, the CTR state,
    /// the GHASH state, the two byte counts, the phase, the held-back tail and its length. See
    /// [`bouncycastle_utils::suspendable_state`].
    pub const SUSPENDED_STATE_LEN: usize = LIB_VERSION_LEN + Self::COMPONENT_STATE_LEN;

    /// The component's share, spelled out here rather than read through the trait so that it is
    /// nameable for any `Dir`; the trait impl's `STATE_LEN` is this constant.
    const COMPONENT_STATE_LEN: usize =
        Self::CTR_STATE_LEN + GHASH_STATE_LEN + 8 + 8 + 1 + TAG_LEN + 8;

    /// The CTR half's share of the suspended state.
    const CTR_STATE_LEN: usize =
        <Ctr<'k, P, Dir, 16, GCM_NONCE_LEN> as SuspendableComponent<'k>>::STATE_LEN;

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

    /// Algorithm 4 step 2 and the precomputation for step 6's tag mask, over a key state that
    /// already holds step 1's `H`, which the worker borrows for `'k`.
    fn setup_from_state(state: &'k GcmKeyState<P>, nonce: [u8; GCM_NONCE_LEN]) -> Self {
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
            ghash: Ghash::new(h),
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
        self.aad_len = match self.aad_len.checked_add(aad.len() as u64) {
            Some(total) if total <= MAX_AAD_LEN => total,
            _ => {
                return Err(SymmetricCipherError::StateError(
                    "GCM: additional authenticated data longer than SP 800-38D Sec 5.2.1.1's \
                     2^64 - 1 bits",
                ));
            }
        };
        self.ghash.update(aad);
        Ok(())
    }

    /// `data_len` after `len` more bytes, if that is still within Sec 5.2.1.1's plaintext limit.
    fn data_len_after(&self, len: usize) -> Result<u64, SymmetricCipherError> {
        match self.data_len.checked_add(len as u64) {
            Some(total) if total <= MAX_DATA_LEN => Ok(total),
            _ => Err(SymmetricCipherError::DataLimitExceeded),
        }
    }

    /// Whether `len` more data bytes can be taken: within Sec 5.2.1.1's plaintext limit and the
    /// keystream left under this nonce. Both directions ask before they copy anything into an
    /// output buffer, so a refused call leaves the buffer zeroed rather than holding the
    /// caller's plaintext, and before they absorb anything, so it leaves the state untouched.
    fn accepts_data(&self, len: usize) -> Result<(), SymmetricCipherError> {
        self.data_len_after(len)?;
        self.ctr.accepts(len)
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
        self.data_len = self.data_len_after(data.len())?;
        self.begin_data_if_needed();
        self.ghash.update(data);
        Ok(())
    }

    /// Algorithm 4 steps 4-6 / Algorithm 5 steps 5-7: pads GHASH to the block boundary (the `0^u`
    /// of step 5), appends `[len(A)]_64 || [len(C)]_64`, and masks the result with `CIPH_K(J0)`.
    /// Writes the full 16-byte block to `out`; callers truncate to `TAG_LEN`. `out` is a `Secret`
    /// because on the decrypting side it is the expected tag `T'`, which forges the rejected
    /// ciphertext if it survives a failed comparison.
    ///
    /// The byte-to-bit multiplication (`* 8`) cannot overflow: `aad_len` and `data_len` are held
    /// under [`MAX_AAD_LEN`] and [`MAX_DATA_LEN`] at every absorption and on resume.
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

impl<'k, P, Dir, const TAG_LEN: usize> Algorithm for Gcm<'k, P, Dir, TAG_LEN>
where
    P: BlockPermutation<16> + ModeNames,
{
    const ALG_NAME: &'static str = P::GCM_ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = P::MAX_SECURITY_STRENGTH;
}

impl<'k, P, const TAG_LEN: usize> Gcm<'k, P, Encrypting, TAG_LEN>
where
    P: BlockPermutation<16> + ModeNames,
{
    /// Begins an encryption over a key's stored state under a nonce drawn from `rng`: the
    /// encryption constructor a permutation crate's `AeadEncryptMode` impl for [`GCM`] calls.
    /// Nothing is copied out of `state`; the worker reads the schedule and `H` through the
    /// borrow and cannot outlive it.
    ///
    /// # Errors
    /// [`SymmetricCipherError::RNGError`] if the nonce draw fails; nothing else can.
    pub fn from_key_state(
        state: &'k GcmKeyState<P>,
        rng: &mut dyn RNG,
    ) -> Result<(Self, [u8; GCM_NONCE_LEN]), SymmetricCipherError> {
        Self::check_shape();
        let nonce = crate::modes::iv::random_iv::<GCM_NONCE_LEN>(rng)?;
        Ok((Self::setup_from_state(state, nonce), nonce))
    }

    /// As [`Self::from_key_state`] under a nonce the caller supplies: the constructor a
    /// permutation crate's `AeadEncryptMode::encrypt_init_nonce` impl for [`GCM`] calls.
    pub fn from_key_state_nonce(state: &'k GcmKeyState<P>, nonce: &[u8; GCM_NONCE_LEN]) -> Self {
        Self::setup_from_state(state, *nonce)
    }

    /// Encrypts `data` in place (GCTR, Algorithm 4 step 3) and absorbs the resulting ciphertext
    /// into GHASH (step 5). Nothing is held back.
    ///
    /// # Errors
    /// [`SymmetricCipherError::DataLimitExceeded`] if `data` would take the message past the
    /// SP 800-38D Sec 5.2.1.1 bound `len(P) <= 2^39 - 256` bits, which is where the `Ctr`
    /// counter would be exhausted. Nothing is consumed in that case.
    fn encrypt_in_place(&mut self, data: &mut [u8]) -> Result<(), SymmetricCipherError> {
        self.accepts_data(data.len())?;
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

impl<'k, P, const TAG_LEN: usize> SymmetricCipherEncryptor<GCM_NONCE_LEN, TAG_LEN>
    for Gcm<'k, P, Encrypting, TAG_LEN>
where
    P: BlockPermutation<16> + ModeNames,
{
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
        self.accepts_data(plaintext.len())?;
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
impl<'k, P, const TAG_LEN: usize> AEADCipherEncryptor<GCM_NONCE_LEN, TAG_LEN, TAG_LEN>
    for Gcm<'k, P, Encrypting, TAG_LEN>
where
    P: BlockPermutation<16> + ModeNames,
{
    fn do_update_aad(&mut self, aad: &[u8]) -> Result<(), SymmetricCipherError> {
        self.absorb_aad(aad)
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

impl<'k, P, const TAG_LEN: usize> Gcm<'k, P, Decrypting, TAG_LEN>
where
    P: BlockPermutation<16> + ModeNames,
{
    /// Begins the decryption of a message encrypted under `nonce` from a key's stored state: the
    /// decryption constructor a permutation crate's `AeadDecryptMode` impl for [`GCM`] calls.
    /// Infallible: the state is already keyed and the nonce length is in the type.
    pub fn from_key_state(state: &'k GcmKeyState<P>, nonce: &[u8; GCM_NONCE_LEN]) -> Self {
        Self::setup_from_state(state, *nonce)
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
        self.accepts_data(data.len())?;
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
}

impl<'k, P, const TAG_LEN: usize> SymmetricCipherDecryptor<GCM_NONCE_LEN, TAG_LEN>
    for Gcm<'k, P, Decrypting, TAG_LEN>
where
    P: BlockPermutation<16> + ModeNames,
{
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
        self.accepts_data(release)?;
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
}

/// The AEAD view: [`AEADCipherDecryptor`] over the [`SymmetricCipherDecryptor`] impl above, with
/// `FINAL_LEN = TAG_LEN`. The one-shots are the key's provided ones, which zeroize the output on
/// a failed tag check.
impl<'k, P, const TAG_LEN: usize> AEADCipherDecryptor<GCM_NONCE_LEN, TAG_LEN, TAG_LEN>
    for Gcm<'k, P, Decrypting, TAG_LEN>
where
    P: BlockPermutation<16> + ModeNames,
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
        self.accepts_data(n)?;
        plaintext[..n].copy_from_slice(&self.tail[..n]);
        self.decrypt_in_place(&mut plaintext[..n])?;
        if let Err(e) = self.finish(tag) {
            plaintext.fill(0);
            return Err(e);
        }
        Ok(n)
    }
}

/// The suspended state is the CTR half, the running GHASH, the two byte counts, the phase, and
/// the up-to-`TAG_LEN` bytes a decryptor holds back. `H` and `CIPH_K(J0)` are not in it: `H` is
/// the key state's, and `CIPH_K(J0)` is re-derived from it and the nonce on resume. See
/// [`bouncycastle_utils::suspendable_state`].
impl<'k, P, Dir, const TAG_LEN: usize> SuspendableComponent<'k> for Gcm<'k, P, Dir, TAG_LEN>
where
    P: BlockPermutation<16> + ModeNames,
    Dir: Direction,
{
    const STATE_LEN: usize = Self::COMPONENT_STATE_LEN;
    type Key = GcmKeyState<P>;

    fn write_state(&self, out: &mut [u8]) {
        let (ctr, rest) = out.split_at_mut(Self::CTR_STATE_LEN);
        self.ctr.write_state(ctr);
        let (ghash, rest) = rest.split_at_mut(GHASH_STATE_LEN);
        self.ghash.write_state(ghash);
        let mut w = CursorMut::new(rest);
        w.u64(self.aad_len);
        w.u64(self.data_len);
        // The phase in the low nibble, the direction above it, so that a state suspended while
        // encrypting cannot be resumed as a decryptor or the reverse.
        w.u8(Dir::STATE_BITS | self.phase as u8);
        w.bytes(&*self.tail);
        w.u64(self.tail_len as u64);
        debug_assert!(w.is_done());
    }

    fn read_state(state: &[u8], key: &'k Self::Key) -> Result<Self, SuspendableError> {
        Self::check_shape();
        let (ctr, rest) = state.split_at(Self::CTR_STATE_LEN);
        let (ghash, rest) = rest.split_at(GHASH_STATE_LEN);

        // `setup_from_state` takes `H` from the key state and re-derives `CIPH_K(J0)` from the
        // nonce, which is the leading part of the CTR state. Its fresh CTR and GHASH are then
        // replaced by the suspended ones.
        let nonce = CtrKeyStream::<'k, P, 16, GCM_NONCE_LEN>::nonce_from_state(ctr);
        let mut gcm = Self::setup_from_state(key, nonce);
        gcm.ctr = <Ctr<'k, P, Dir, 16, GCM_NONCE_LEN> as SuspendableComponent<'k>>::read_state(
            ctr, &key.perm,
        )?;
        gcm.ghash.restore_state(ghash)?;

        let mut r = Cursor::new(rest);
        gcm.aad_len = r.u64();
        gcm.data_len = r.u64();
        if gcm.aad_len > MAX_AAD_LEN || gcm.data_len > MAX_DATA_LEN {
            return Err(SuspendableError::InvalidData);
        }
        let call_state = r.u8();
        if call_state & 0xF0 != Dir::STATE_BITS {
            return Err(SuspendableError::InvalidData);
        }
        gcm.phase = Phase::from_u8(call_state & 0x0F)?;
        (*gcm.tail).copy_from_slice(r.bytes(TAG_LEN));
        gcm.tail_len = bounded_usize(r.u64(), TAG_LEN)?;
        debug_assert!(r.is_done());
        Ok(gcm)
    }
}

/// `N` must be [`Gcm::SUSPENDED_STATE_LEN`]; anything else is a compile error.
impl<'k, P, Dir, const TAG_LEN: usize, const N: usize> SuspendableKeyed<'k, N>
    for Gcm<'k, P, Dir, TAG_LEN>
where
    P: BlockPermutation<16> + ModeNames,
    Dir: Direction,
{
    type Key = GcmKeyState<P>;

    fn suspend(self) -> [u8; N] {
        suspend_component(&self)
    }

    fn from_suspended(state: [u8; N], key: &'k Self::Key) -> Result<Self, SuspendableError> {
        resume_component(&state, key)
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
        /// Takes `&mut self` rather than `self`, so that `Gcm` keeps the rest of its state around
        /// the call. Nothing asserts a "was padded" flag: the caller is
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
