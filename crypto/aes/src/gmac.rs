//! Type aliases for AES in GMAC (NIST SP 800-38D Sec 5.2), and the generator/verifier pair that
//! makes [`AES128Key<GMAC>`] and friends GMAC keys.
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

use crate::hazmat::{AES128Internal, AES192Internal, AES256Internal, AESInternal};
use crate::{AESKey, AESParams};
use bouncycastle_cipher::modes::{GCM_NONCE_LEN, GMAC, Gmac, ModeNames};
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::hazmat::BlockPermutation;
use bouncycastle_core::traits::RNG;

// Imports needed for docs
#[allow(unused_imports)]
use crate::AES128Key;
// end of imports needed for docs

/// AES-128 in GMAC with a 128-bit tag. `Dir` is [`Encrypting`] to generate a tag or
/// [`Decrypting`] to verify one.
#[allow(non_camel_case_types)]
pub type AES_GMAC_128<'k, Dir> = Gmac<'k, AES128Internal, Dir, 16>;

/// AES-192 in GMAC with a 128-bit tag. See [`AES_GMAC_128`].
#[allow(non_camel_case_types)]
pub type AES_GMAC_192<'k, Dir> = Gmac<'k, AES192Internal, Dir, 16>;

/// AES-256 in GMAC with a 128-bit tag. See [`AES_GMAC_128`].
#[allow(non_camel_case_types)]
pub type AES_GMAC_256<'k, Dir> = Gmac<'k, AES256Internal, Dir, 16>;

// The pair is inherent on the key rather than a role trait, since a GMAC tag is bound to a nonce;
// one impl over every AES key length.
impl<P, const TAG_LEN: usize> AESKey<P, GMAC<TAG_LEN>>
where
    P: AESParams,
    AESInternal<P>: BlockPermutation<16> + ModeNames + Clone,
{
    /// Begins a tag under a nonce drawn from `rng`, which is returned with the generator.
    ///
    /// # Errors
    /// [`SymmetricCipherError::RNGError`] if the nonce draw fails; nothing else can.
    pub fn create_generator<'k>(
        &'k self,
        rng: &mut dyn RNG,
    ) -> Result<
        (Gmac<'k, AESInternal<P>, Encrypting, TAG_LEN>, [u8; GCM_NONCE_LEN]),
        SymmetricCipherError,
    > {
        Gmac::<AESInternal<P>, Encrypting, TAG_LEN>::from_key_state(&self.state, rng)
    }

    /// Begins a tag under a nonce the caller supplies, who takes on the obligation that it never
    /// repeat under this key.
    pub fn create_generator_nonce<'k>(
        &'k self,
        nonce: &[u8; GCM_NONCE_LEN],
    ) -> Gmac<'k, AESInternal<P>, Encrypting, TAG_LEN> {
        Gmac::<AESInternal<P>, Encrypting, TAG_LEN>::from_key_state_nonce(&self.state, nonce)
    }

    /// Begins the verification of a tag made under `nonce`. Infallible.
    pub fn create_verifier<'k>(
        &'k self,
        nonce: &[u8; GCM_NONCE_LEN],
    ) -> Gmac<'k, AESInternal<P>, Decrypting, TAG_LEN> {
        Gmac::<AESInternal<P>, Decrypting, TAG_LEN>::from_key_state(&self.state, nonce)
    }
}
