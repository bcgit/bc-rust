//! GMAC, the authentication-only specialization of GCM (NIST SP 800-38D Sec 5.2): "An
//! implementation may restrict the input to the non-confidential data, i.e., without any
//! confidential data. The resulting variant of GCM is called GMAC. For GMAC, the authenticated
//! encryption and decryption functions become the functions for generating and verifying an
//! authentication tag on the non-confidential data."
//!
//! [`Gmac`] is a [`Gcm`] that is only ever given AAD, so it inherits `Gcm`'s 96-bit nonce and its
//! `TAG_LEN` range of 12 to 16 bytes. Following that sentence of Sec 5.2, the direction markers
//! carry over too: `Gmac<.., Encrypting, ..>` generates a tag and `Gmac<.., Decrypting, ..>`
//! verifies one.
//!
//! Every tag is bound to a nonce, which is why GMAC implements neither [`MAC`] (whose `new` has
//! nowhere to put one) nor the MAC mode trait. The generating side draws the nonce from the RNG
//! it is given and returns it, or takes one from a caller who manages its own; the verifying side
//! takes the nonce the tag was made under. A mode-bound key, `AES128Key<GMAC>`, hands out both
//! sides from one stored `H`.
//!
//! The key is [`KeyType::MACKey`] material, as CMAC's is, and so cannot also be a GCM key: a
//! nonce shared between a GMAC tag and a GCM message under one key is a repeated nonce.
//!
//! # Usage Examples
//!
//! From a key state, which is what a mode-bound key holds:
//!
//! ```
//! # mod toy { include!("../../tests/common/toy_block_cipher.rs"); }
//! # use toy::ToyBlockCipher;
//! use bouncycastle_cipher::modes::{GcmKeyState, Gmac};
//! use bouncycastle_cipher::{Decrypting, Encrypting};
//! use bouncycastle_core::hazmat::ElectronicCodeBook;
//! use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! type ToyGmac<Dir> = Gmac<ToyBlockCipher, Dir, 16, 16>;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let key = KeyMaterial128::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap();
//! let state = GcmKeyState::new::<16>(ToyBlockCipher::new(&key).unwrap());
//!
//! let (mut generator, nonce) = ToyGmac::<Encrypting>::from_key_state(&state, &mut rng).unwrap();
//! generator.do_update(b"a message ");
//! generator.do_update(b"in two parts");
//! let tag = generator.do_final();
//!
//! let mut verifier = ToyGmac::<Decrypting>::from_key_state(&state, &nonce);
//! verifier.do_update(b"a message in two parts");
//! assert!(verifier.do_verify_final(&tag));
//! ```
//!
//! From the material, for one message:
//!
//! ```
//! # mod toy { include!("../../tests/common/toy_block_cipher.rs"); }
//! # use toy::ToyBlockCipher;
//! use bouncycastle_cipher::modes::Gmac;
//! use bouncycastle_cipher::{Decrypting, Encrypting};
//! use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! type ToyGmac<Dir> = Gmac<ToyBlockCipher, Dir, 16, 16>;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let key = KeyMaterial128::from_bytes_as_type(&[0x42; 16], KeyType::MACKey).unwrap();
//! let (generator, nonce) = ToyGmac::<Encrypting>::new(&key, &mut rng).unwrap();
//! let tag = generator.mac(b"a message");
//! assert!(ToyGmac::<Decrypting>::new(&key, &nonce).unwrap().verify(b"a message", &tag));
//! ```
//!
//! # 🚨 Security Considerations 🚨
//!
//! Everything in the [`gcm`](crate::modes::gcm) module's security considerations applies: above
//! all, a nonce repeated under one key lets an attacker recover the hash subkey `H` and forge tags
//! (SP 800-38D Sec 8 and Appendix A), and the key is limited to 2^32 invocations (Sec 8.3). The
//! `_nonce` constructors put the uniqueness obligation on the caller.
//!
//! [`MAC`]: bouncycastle_core::traits::MAC
//! [`KeyType::MACKey`]: bouncycastle_core::key_material::KeyType::MACKey

use crate::modes::ModeNames;
use crate::modes::gcm::{GCM_NONCE_LEN, Gcm, GcmKeyState};
use crate::{Decrypting, Encrypting};
use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::hazmat::{ElectronicCodeBook, do_hazardous_operations};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{
    AEADCipherEncryptor, Algorithm, RNG, SymmetricCipherDecryptor, SymmetricCipherEncryptor,
};

/// The GMAC mode type: the `M` of a mode-bound key such as `AES128Key<GMAC>`. `GMAC` is GMAC with
/// the full 128-bit tag; `GMAC<12>` and so on select a shorter tag, within the `12..=16` byte
/// range [`Gcm`] accepts. Its key state is [`GcmKeyState`], so a GMAC key caches `H` as a GCM key
/// does. The [`Mode`] impl and the generator/verifier pair that connect it to a key type are
/// written by each permutation's crate while the cipher traits still carry `KEY_LEN`.
///
/// [`Mode`]: bouncycastle_core::hazmat::Mode
pub struct GMAC<const TAG_LEN: usize = 16>;

/// GMAC over the permutation `P`, generating (`Dir = Encrypting`) or verifying (`Dir =
/// Decrypting`) a `TAG_LEN`-byte tag. See the module docs.
pub struct Gmac<P, Dir, const KEY_LEN: usize, const TAG_LEN: usize>
where
    P: ElectronicCodeBook<KEY_LEN, 16> + ModeNames,
{
    gcm: Gcm<P, Dir, KEY_LEN, TAG_LEN>,
}

/// `Gcm`'s AAD absorption fails only if AAD follows data, which GMAC never supplies, or if the
/// running AAD length overflows a `u64`, which needs 2^64 bytes of input.
const AAD_INFALLIBLE: &str = "GMAC: GCM rejects AAD only after data or past 2^64 bytes";

/// The material route's key check: GMAC takes a `MACKey` of exactly `KEY_LEN` bytes, and the
/// permutation accepts only a `SymmetricCipherKey`, so the key is handed on as a retagged copy at
/// the same strength -- the permutation's strength check still applies -- used for nothing else.
fn mac_key_as_cipher_key<const KEY_LEN: usize>(
    key: &KeyMaterial<KEY_LEN>,
) -> Result<KeyMaterial<KEY_LEN>, SymmetricCipherError> {
    if key.key_type() != KeyType::MACKey {
        return Err(KeyMaterialError::InvalidKeyType("GMAC: key type must be a MAC key").into());
    }
    let mut cipher_key = KeyMaterial::<KEY_LEN>::from_bytes_as_type(
        key.ref_to_bytes(),
        KeyType::SymmetricCipherKey,
    )?;
    do_hazardous_operations(&mut cipher_key, |k| {
        k.set_key_type(KeyType::SymmetricCipherKey)?;
        k.set_security_strength(key.security_strength())
    })?;
    Ok(cipher_key)
}

impl<P, Dir, const KEY_LEN: usize, const TAG_LEN: usize> Algorithm
    for Gmac<P, Dir, KEY_LEN, TAG_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, 16> + ModeNames,
{
    const ALG_NAME: &'static str = P::GMAC_ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = P::MAX_SECURITY_STRENGTH;
}

impl<P, const KEY_LEN: usize, const TAG_LEN: usize> Gmac<P, Encrypting, KEY_LEN, TAG_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, 16> + ModeNames,
{
    /// Begins a tag from a key's stored state under a nonce drawn from `rng`: what a mode-bound
    /// key's `create_generator` calls.
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
        let (gcm, nonce) = Gcm::<P, Encrypting, KEY_LEN, TAG_LEN>::from_key_state(state, rng)?;
        Ok((Self { gcm }, nonce))
    }

    /// As [`from_key_state`](Self::from_key_state) under a nonce the caller supplies, who takes
    /// on the obligation that it never repeat under this key.
    pub fn from_key_state_nonce(state: &GcmKeyState<P>, nonce: &[u8; GCM_NONCE_LEN]) -> Self
    where
        P: Clone,
    {
        Self { gcm: Gcm::from_key_state_nonce(state, nonce) }
    }

    /// Begins a tag from the material, under a nonce drawn from `rng`.
    ///
    /// # Errors
    /// [`KeyMaterialError::InvalidKeyType`] if the key is not a
    /// [`KeyType::MACKey`], the permutation's own refusals (a strength below the key length,
    /// an all-zero key), or [`SymmetricCipherError::RNGError`] if the nonce draw fails.
    pub fn new(
        key: &KeyMaterial<KEY_LEN>,
        rng: &mut dyn RNG,
    ) -> Result<(Self, [u8; GCM_NONCE_LEN]), SymmetricCipherError> {
        let cipher_key = mac_key_as_cipher_key(key)?;
        let (gcm, nonce) = Gcm::do_encrypt_init_rng(&cipher_key, rng)?;
        Ok((Self { gcm }, nonce))
    }

    /// As [`new`](Self::new) under a nonce the caller supplies.
    ///
    /// # Errors
    /// As [`new`](Self::new), less the RNG.
    pub fn new_nonce(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; GCM_NONCE_LEN],
    ) -> Result<Self, SymmetricCipherError> {
        let cipher_key = mac_key_as_cipher_key(key)?;
        Ok(Self { gcm: Gcm::do_encrypt_init_nonce(&cipher_key, nonce)? })
    }

    /// Absorbs more of the message.
    pub fn do_update(&mut self, data: &[u8]) {
        self.gcm.absorb_aad(data).expect(AAD_INFALLIBLE);
    }

    /// The tag over everything passed to [`do_update`](Self::do_update).
    pub fn do_final(self) -> [u8; TAG_LEN] {
        self.gcm.finish()
    }

    /// One-shot: the tag over `data`, consuming the generator.
    pub fn mac(mut self, data: &[u8]) -> [u8; TAG_LEN] {
        self.do_update(data);
        self.do_final()
    }
}

impl<P, const KEY_LEN: usize, const TAG_LEN: usize> Gmac<P, Decrypting, KEY_LEN, TAG_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, 16> + ModeNames,
{
    /// Begins verifying a tag made under `nonce` from a key's stored state: what a mode-bound
    /// key's `create_verifier` calls. Infallible: the state is keyed and the nonce length is in
    /// the type.
    pub fn from_key_state(state: &GcmKeyState<P>, nonce: &[u8; GCM_NONCE_LEN]) -> Self
    where
        P: Clone,
    {
        Self { gcm: Gcm::<P, Decrypting, KEY_LEN, TAG_LEN>::from_key_state(state, nonce) }
    }

    /// Begins verifying a tag made under `nonce`, from the material.
    ///
    /// # Errors
    /// As the generating side's `new`, less the RNG.
    pub fn new(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; GCM_NONCE_LEN],
    ) -> Result<Self, SymmetricCipherError> {
        let cipher_key = mac_key_as_cipher_key(key)?;
        Ok(Self { gcm: Gcm::do_decrypt_init(&cipher_key, nonce)? })
    }

    /// Absorbs more of the message.
    pub fn do_update(&mut self, data: &[u8]) {
        self.gcm.absorb_aad(data).expect(AAD_INFALLIBLE);
    }

    /// Whether `tag` is the tag over everything passed to [`do_update`](Self::do_update),
    /// compared in constant time.
    pub fn do_verify_final(self, tag: &[u8; TAG_LEN]) -> bool {
        self.gcm.finish(tag).is_ok()
    }

    /// One-shot: whether `tag` is the tag over `data`, consuming the verifier.
    pub fn verify(mut self, data: &[u8], tag: &[u8; TAG_LEN]) -> bool {
        self.do_update(data);
        self.do_verify_final(tag)
    }
}
