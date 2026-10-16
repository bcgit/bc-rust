//! Type aliases for AES in GMAC (NIST SP 800-38D Sec 5.2), and the `GMAC` mode impls and the
//! generator/verifier pair that make [`AES128Key<GMAC>`] and friends GMAC keys.
//!
//! See [`bouncycastle_cipher::modes::gmac`] for the construction, the nonce and the security
//! considerations. [`AES_GMAC_128`] and friends pin the permutation and its key length and fix
//! the tag at 128 bits, as the `AES_GCM_*` aliases do; for a shorter tag name
//! [`Gmac`] directly, or the key's mode as `GMAC<12>`.
//!
//! A GMAC tag is bound to a nonce, so the pair is the MAC role pair's names with the nonce added,
//! which is the AEAD role pair's shape with no ciphertext. It is inherent on the key rather than a
//! role trait in `core` because GMAC is the only nonce-based MAC in the tree.
//!
//! # Usage Examples
//!
//! ```
//! use bouncycastle_aes::AES256Key;
//! use bouncycastle_cipher::modes::GMAC;
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::symmetric_key::FromKeyMaterial;
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();   // one RNG, held across messages
//! let material = KeyMaterial256::from_bytes_as_type(&[0x42; 32], KeyType::MACKey).unwrap();
//! let key = AES256Key::<GMAC>::from_key_material(&material).expect("a valid AES-256 MAC key");
//!
//! // The nonce is drawn from `rng` and returned; the Result is for that draw only.
//! let (mut generator, nonce) = key.create_generator(&mut rng).expect("nonce draw");
//! generator.do_update(b"a message that arrives ");
//! generator.do_update(b"in pieces");
//! let tag = generator.do_final();
//!
//! // Verification needs the nonce the tag was made under, and is infallible to set up.
//! assert!(key.create_verifier(&nonce).verify(b"a message that arrives in pieces", &tag));
//! assert!(!key.create_verifier(&nonce).verify(b"another message", &tag));
//! ```
//!
//! # Memory Usage
//!
//! A key is the expanded schedule plus the 16-byte hash subkey, the same as a GCM key: 192, 224
//! and 256 bytes for AES-128, -192 and -256. A worker is a `Gcm` of the same shape.
//!
//! [`AES128Key<GMAC>`]: crate::AES128Key

use crate::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use crate::{AES128Key, AES192Key, AES256Key};
use bouncycastle_cipher::modes::{GCM_NONCE_LEN, GMAC, GcmKeyState, Gmac, ModeNames};
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::hazmat::Mode;
use bouncycastle_core::key_material::KeyType;
use bouncycastle_core::traits::RNG;

/// AES-128 in GMAC with a 128-bit tag. `Dir` is [`Encrypting`] to generate a tag or
/// [`Decrypting`] to verify one.
#[allow(non_camel_case_types)]
pub type AES_GMAC_128<Dir> = Gmac<AES128Internal, Dir, 16, 16>;

/// AES-192 in GMAC with a 128-bit tag. See [`AES_GMAC_128`].
#[allow(non_camel_case_types)]
pub type AES_GMAC_192<Dir> = Gmac<AES192Internal, Dir, 24, 16>;

/// AES-256 in GMAC with a 128-bit tag. See [`AES_GMAC_128`].
#[allow(non_camel_case_types)]
pub type AES_GMAC_256<Dir> = Gmac<AES256Internal, Dir, 32, 16>;

// Per key length for the reason the GCM impls are (see `gcm.rs`): the worker carries `KEY_LEN`,
// which cannot be tied to `Mode<P>` from a generic impl. The pair is per key length for the same
// reason, since its return types name the worker.

impl<const TAG_LEN: usize> Mode<AES128Internal> for GMAC<TAG_LEN> {
    type KeyState = GcmKeyState<AES128Internal>;
    const KEY_TYPE: KeyType = KeyType::MACKey;
    const ALG_NAME: &'static str = AES128Internal::GMAC_ALG_NAME;

    fn key_state(perm: AES128Internal) -> Self::KeyState {
        GcmKeyState::new::<16>(perm)
    }
}

impl<const TAG_LEN: usize> AES128Key<GMAC<TAG_LEN>> {
    /// Begins a tag under a nonce drawn from `rng`, which is returned with the generator.
    ///
    /// # Errors
    /// [`SymmetricCipherError::RNGError`] if the nonce draw fails; nothing else can.
    pub fn create_generator(
        &self,
        rng: &mut dyn RNG,
    ) -> Result<
        (Gmac<AES128Internal, Encrypting, 16, TAG_LEN>, [u8; GCM_NONCE_LEN]),
        SymmetricCipherError,
    > {
        Gmac::<AES128Internal, Encrypting, 16, TAG_LEN>::from_key_state(&self.state, rng)
    }

    /// Begins a tag under a nonce the caller supplies, who takes on the obligation that it never
    /// repeat under this key.
    pub fn create_generator_nonce(
        &self,
        nonce: &[u8; GCM_NONCE_LEN],
    ) -> Gmac<AES128Internal, Encrypting, 16, TAG_LEN> {
        Gmac::<AES128Internal, Encrypting, 16, TAG_LEN>::from_key_state_nonce(&self.state, nonce)
    }

    /// Begins the verification of a tag made under `nonce`. Infallible.
    pub fn create_verifier(
        &self,
        nonce: &[u8; GCM_NONCE_LEN],
    ) -> Gmac<AES128Internal, Decrypting, 16, TAG_LEN> {
        Gmac::<AES128Internal, Decrypting, 16, TAG_LEN>::from_key_state(&self.state, nonce)
    }
}

impl<const TAG_LEN: usize> Mode<AES192Internal> for GMAC<TAG_LEN> {
    type KeyState = GcmKeyState<AES192Internal>;
    const KEY_TYPE: KeyType = KeyType::MACKey;
    const ALG_NAME: &'static str = AES192Internal::GMAC_ALG_NAME;

    fn key_state(perm: AES192Internal) -> Self::KeyState {
        GcmKeyState::new::<24>(perm)
    }
}

impl<const TAG_LEN: usize> AES192Key<GMAC<TAG_LEN>> {
    /// As [`AES128Key::create_generator`].
    ///
    /// # Errors
    /// As [`AES128Key::create_generator`].
    pub fn create_generator(
        &self,
        rng: &mut dyn RNG,
    ) -> Result<
        (Gmac<AES192Internal, Encrypting, 24, TAG_LEN>, [u8; GCM_NONCE_LEN]),
        SymmetricCipherError,
    > {
        Gmac::<AES192Internal, Encrypting, 24, TAG_LEN>::from_key_state(&self.state, rng)
    }

    /// As [`AES128Key::create_generator_nonce`].
    pub fn create_generator_nonce(
        &self,
        nonce: &[u8; GCM_NONCE_LEN],
    ) -> Gmac<AES192Internal, Encrypting, 24, TAG_LEN> {
        Gmac::<AES192Internal, Encrypting, 24, TAG_LEN>::from_key_state_nonce(&self.state, nonce)
    }

    /// As [`AES128Key::create_verifier`].
    pub fn create_verifier(
        &self,
        nonce: &[u8; GCM_NONCE_LEN],
    ) -> Gmac<AES192Internal, Decrypting, 24, TAG_LEN> {
        Gmac::<AES192Internal, Decrypting, 24, TAG_LEN>::from_key_state(&self.state, nonce)
    }
}

impl<const TAG_LEN: usize> Mode<AES256Internal> for GMAC<TAG_LEN> {
    type KeyState = GcmKeyState<AES256Internal>;
    const KEY_TYPE: KeyType = KeyType::MACKey;
    const ALG_NAME: &'static str = AES256Internal::GMAC_ALG_NAME;

    fn key_state(perm: AES256Internal) -> Self::KeyState {
        GcmKeyState::new::<32>(perm)
    }
}

impl<const TAG_LEN: usize> AES256Key<GMAC<TAG_LEN>> {
    /// As [`AES128Key::create_generator`].
    ///
    /// # Errors
    /// As [`AES128Key::create_generator`].
    pub fn create_generator(
        &self,
        rng: &mut dyn RNG,
    ) -> Result<
        (Gmac<AES256Internal, Encrypting, 32, TAG_LEN>, [u8; GCM_NONCE_LEN]),
        SymmetricCipherError,
    > {
        Gmac::<AES256Internal, Encrypting, 32, TAG_LEN>::from_key_state(&self.state, rng)
    }

    /// As [`AES128Key::create_generator_nonce`].
    pub fn create_generator_nonce(
        &self,
        nonce: &[u8; GCM_NONCE_LEN],
    ) -> Gmac<AES256Internal, Encrypting, 32, TAG_LEN> {
        Gmac::<AES256Internal, Encrypting, 32, TAG_LEN>::from_key_state_nonce(&self.state, nonce)
    }

    /// As [`AES128Key::create_verifier`].
    pub fn create_verifier(
        &self,
        nonce: &[u8; GCM_NONCE_LEN],
    ) -> Gmac<AES256Internal, Decrypting, 32, TAG_LEN> {
        Gmac::<AES256Internal, Decrypting, 32, TAG_LEN>::from_key_state(&self.state, nonce)
    }
}
