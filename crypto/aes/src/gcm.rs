//! Type aliases for AES in GCM (NIST SP 800-38D).
//!
//! See [`bouncycastle_cipher::modes::gcm`] for details on the abstract Galois/Counter Mode construction.
//!
//! The aliases here are authenticated ciphers: encryption produces a tag as well as a ciphertext,
//! and decryption either returns the plaintext or fails the tag check. Both directions implement
//! [`AEADCipherEncryptor`] / [`AEADCipherDecryptor`], which keep the tag detached, and
//! [`SymmetricCipherEncryptor`] / [`SymmetricCipherDecryptor`], which carry it inline as
//! `ciphertext || tag`. They come from a key, [`AES128Key<GCM>`](crate::AES128Key) and friends,
//! through the [`AeadEncryptionKey`] / [`AeadDecryptionKey`] pair, which draws the nonce from
//! the caller's RNG and returns it, or takes the caller's through its `_nonce` forms. `Dir` is
//! [`Encrypting`] or [`Decrypting`]; the wrong direction is a compile error, not a runtime check.
//!
//! The tag is fixed at 128 bits, the maximum SP 800-38D Sec 5.2.1.2 allows. For a shorter tag
//! (96, 104, 112 or 120 bits), name the key's mode as `GCM<12>` and so on, or [`Gcm`] directly
//! with the desired `TAG_LEN`. The nonce is always [`GCM_NONCE_LEN`] (12 bytes / 96 bits): `Gcm`
//! has no nonce-length parameter at all, unlike `Ctr`'s aliases, because SP 800-38D's
//! `len(IV) != 96` branch (deriving `J0` from a GHASH of the IV) is not implemented.
//!
//! # Usage Examples
//!
//! ## One-shot API
//!
//! The detached one-shots return the tag separately from the ciphertext:
//!
//! ```
//! use bouncycastle_aes::AES256Key;
//! use bouncycastle_cipher::modes::GCM;
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::symmetric_key::{AeadDecryptionKey, AeadEncryptionKey, FromKeyMaterial};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();   // one RNG, held across messages
//! let material = KeyMaterial256::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey)
//!     .expect("a 32-byte symmetric cipher key");
//! let key = AES256Key::<GCM>::from_key_material(&material).expect("a valid AES-256 key");
//!
//! // The associated data is authenticated but not encrypted; the message is both.
//! let aad = b"header, sent in the clear";
//! let message = b"a message of no particular length";
//!
//! // The nonce is drawn from `rng` and returned.
//! let (nonce, ciphertext, tag) = key.encrypt_detached(&mut rng, aad, message).expect("encryption");
//! assert_eq!(ciphertext.len(), message.len(), "GCM never expands the payload");
//!
//! let recovered = key.decrypt_detached(&nonce, aad, &ciphertext, &tag).expect("decryption");
//! assert_eq!(recovered, message);
//!
//! // Tampering with the ciphertext, the tag or the associated data fails the tag check.
//! let mut tampered = ciphertext.clone();
//! tampered[0] ^= 1;
//! assert!(key.decrypt_detached(&nonce, aad, &tampered, &tag).is_err());
//! assert!(key.decrypt_detached(&nonce, b"other header", &ciphertext, &tag).is_err());
//! ```
//!
//! ## Inline `ciphertext || tag`
//!
//! Through the `_with_aad` one-shots the tag is appended to the ciphertext, so the output is 16
//! bytes longer than the input; an empty AAD is the no-AAD case:
//!
//! ```
//! use bouncycastle_aes::AES128Key;
//! use bouncycastle_cipher::modes::GCM;
//! use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
//! use bouncycastle_core::symmetric_key::{AeadDecryptionKey, AeadEncryptionKey, FromKeyMaterial};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let material = KeyMaterial128::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//! let key = AES128Key::<GCM>::from_key_material(&material).expect("a valid AES-128 key");
//! let message = b"a message of no particular length at all";
//!
//! let (nonce, ciphertext) = key.encrypt_with_aad(&mut rng, &[], message).expect("encryption");
//! assert_eq!(ciphertext.len(), message.len() + 16, "the ciphertext plus the tag");
//!
//! let plaintext = key.decrypt_with_aad(&nonce, &[], &ciphertext).expect("decryption");
//! assert_eq!(plaintext, message);
//! ```
//!
//! ## Streaming API
//!
//! For data that arrives in pieces, the workers' streaming methods can be used. All associated
//! data must be given via `do_update_aad` before the first piece of data, and the tag comes from
//! `do_encrypt_final`:
//!
//! ```
//! use bouncycastle_aes::AES128Key;
//! use bouncycastle_cipher::modes::GCM;
//! use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
//! use bouncycastle_core::symmetric_key::{AeadDecryptionKey, AeadEncryptionKey, FromKeyMaterial};
//! use bouncycastle_core::traits::{
//!     AEADCipherDecryptor, AEADCipherEncryptor, SymmetricCipherDecryptor, SymmetricCipherEncryptor,
//! };
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let material = KeyMaterial128::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//! let key = AES128Key::<GCM>::from_key_material(&material).expect("a valid AES-128 key");
//! let aad = b"header";
//! let plaintext = [0x5Au8; 50];
//!
//! // Encrypt in 7-byte pieces. A piece is encrypted as soon as it is given, so each call writes
//! // exactly as many bytes as it was handed.
//! let (mut encryptor, nonce) = key.create_encryptor(&mut rng).expect("nonce draw");
//! encryptor.do_update_aad(aad).expect("aad");
//! let mut ciphertext = Vec::new();
//! for piece in plaintext.chunks(7) {
//!     let mut out = [0u8; 7];
//!     let bytes_written = encryptor.do_encrypt_out(piece, &mut out).expect("encryption");
//!     ciphertext.extend_from_slice(&out[..bytes_written]);
//! }
//! // The tag is computed over everything, so it is the last thing out.
//! let (tag, tag_len) = encryptor.do_encrypt_final().expect("the tag");
//! ciphertext.extend_from_slice(&tag[..tag_len]);
//! assert_eq!(ciphertext.len(), plaintext.len() + 16);
//!
//! // Decrypt in 19-byte pieces. The decryptor holds back the last 16 bytes it has seen, since
//! // those may be the tag, so a call can write fewer bytes than it was handed; `do_decrypt_final`
//! // checks the tag and releases whatever is still held back.
//! let mut decryptor = key.create_decryptor(&nonce);
//! decryptor.do_update_aad(aad).expect("aad");
//! let mut recovered = Vec::new();
//! for piece in ciphertext.chunks(19) {
//!     let mut out = [0u8; 19];
//!     let bytes_written = decryptor.do_decrypt_out(piece, &mut out).expect("decryption");
//!     recovered.extend_from_slice(&out[..bytes_written]);
//! }
//! let (last, last_len) = decryptor.do_decrypt_final().expect("a valid tag");
//! recovered.extend_from_slice(&last[..last_len]);
//! assert_eq!(recovered, plaintext);
//! ```
//!
//! # 🚨 Security Considerations 🚨
//!
//! All security considerations from [`bouncycastle_cipher::modes::gcm`] apply.

use crate::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle_cipher::modes::{GCM, GCM_NONCE_LEN, Gcm, GcmKeyState, ModeNames};
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::hazmat::{AeadDecryptMode, AeadEncryptMode, Mode};
use bouncycastle_core::key_material::KeyType;
use bouncycastle_core::traits::RNG;

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_core::symmetric_key::{AeadDecryptionKey, AeadEncryptionKey};
#[allow(unused_imports)]
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, SymmetricCipherDecryptor, SymmetricCipherEncryptor,
};
// end of imports needed for docs

/// AES-128 in GCM with a 128-bit tag.
#[allow(non_camel_case_types)]
pub type AES_GCM_128<'k, Dir> = Gcm<'k, AES128Internal, Dir, 16, 16>;

/// AES-192 in GCM with a 128-bit tag.
#[allow(non_camel_case_types)]
pub type AES_GCM_192<'k, Dir> = Gcm<'k, AES192Internal, Dir, 24, 16>;

/// AES-256 in GCM with a 128-bit tag. See [`AES_GCM_128`].
#[allow(non_camel_case_types)]
pub type AES_GCM_256<'k, Dir> = Gcm<'k, AES256Internal, Dir, 32, 16>;

// The `GCM` mode impls for the three AES permutations, which is what makes `AES128Key<GCM>` and
// friends AEAD keys. Written per key length rather than once over `AESInternal<P>`: the generic
// form needs `Gcm<'k, AESInternal<P>, Dir, { P::KEY_LEN }, TAG_LEN>`, a const expression stable Rust
// rejects, and a generic impl in `cipher` over `P: ElectronicCodeBook<KEY_LEN, 16>` leaves
// `KEY_LEN` unconstrained on `Mode<P>`. Both go once `KEY_LEN` leaves the cipher traits.

impl<const TAG_LEN: usize> Mode<AES128Internal> for GCM<TAG_LEN> {
    type KeyState = GcmKeyState<AES128Internal>;
    const KEY_TYPE: KeyType = KeyType::SymmetricCipherKey;
    const ALG_NAME: &'static str = AES128Internal::GCM_ALG_NAME;

    fn key_state(perm: AES128Internal) -> Self::KeyState {
        GcmKeyState::new::<16>(perm)
    }
}

impl<const TAG_LEN: usize> AeadEncryptMode<AES128Internal, 16, GCM_NONCE_LEN, TAG_LEN, TAG_LEN>
    for GCM<TAG_LEN>
{
    type Encryptor<'k> = Gcm<'k, AES128Internal, Encrypting, 16, TAG_LEN>;

    fn encrypt_init<'k>(
        state: &'k Self::KeyState,
        rng: &mut dyn RNG,
    ) -> Result<(Self::Encryptor<'k>, [u8; GCM_NONCE_LEN]), SymmetricCipherError> {
        <Self::Encryptor<'k>>::from_key_state(state, rng)
    }

    fn encrypt_init_nonce<'k>(
        state: &'k Self::KeyState,
        nonce: &[u8; GCM_NONCE_LEN],
    ) -> Self::Encryptor<'k> {
        <Self::Encryptor<'k>>::from_key_state_nonce(state, nonce)
    }
}

impl<const TAG_LEN: usize> AeadDecryptMode<AES128Internal, 16, GCM_NONCE_LEN, TAG_LEN, TAG_LEN>
    for GCM<TAG_LEN>
{
    type Decryptor<'k> = Gcm<'k, AES128Internal, Decrypting, 16, TAG_LEN>;

    fn decrypt_init<'k>(
        state: &'k Self::KeyState,
        nonce: &[u8; GCM_NONCE_LEN],
    ) -> Self::Decryptor<'k> {
        <Self::Decryptor<'k>>::from_key_state(state, nonce)
    }
}

impl<const TAG_LEN: usize> Mode<AES192Internal> for GCM<TAG_LEN> {
    type KeyState = GcmKeyState<AES192Internal>;
    const KEY_TYPE: KeyType = KeyType::SymmetricCipherKey;
    const ALG_NAME: &'static str = AES192Internal::GCM_ALG_NAME;

    fn key_state(perm: AES192Internal) -> Self::KeyState {
        GcmKeyState::new::<24>(perm)
    }
}

impl<const TAG_LEN: usize> AeadEncryptMode<AES192Internal, 24, GCM_NONCE_LEN, TAG_LEN, TAG_LEN>
    for GCM<TAG_LEN>
{
    type Encryptor<'k> = Gcm<'k, AES192Internal, Encrypting, 24, TAG_LEN>;

    fn encrypt_init<'k>(
        state: &'k Self::KeyState,
        rng: &mut dyn RNG,
    ) -> Result<(Self::Encryptor<'k>, [u8; GCM_NONCE_LEN]), SymmetricCipherError> {
        <Self::Encryptor<'k>>::from_key_state(state, rng)
    }

    fn encrypt_init_nonce<'k>(
        state: &'k Self::KeyState,
        nonce: &[u8; GCM_NONCE_LEN],
    ) -> Self::Encryptor<'k> {
        <Self::Encryptor<'k>>::from_key_state_nonce(state, nonce)
    }
}

impl<const TAG_LEN: usize> AeadDecryptMode<AES192Internal, 24, GCM_NONCE_LEN, TAG_LEN, TAG_LEN>
    for GCM<TAG_LEN>
{
    type Decryptor<'k> = Gcm<'k, AES192Internal, Decrypting, 24, TAG_LEN>;

    fn decrypt_init<'k>(
        state: &'k Self::KeyState,
        nonce: &[u8; GCM_NONCE_LEN],
    ) -> Self::Decryptor<'k> {
        <Self::Decryptor<'k>>::from_key_state(state, nonce)
    }
}

impl<const TAG_LEN: usize> Mode<AES256Internal> for GCM<TAG_LEN> {
    type KeyState = GcmKeyState<AES256Internal>;
    const KEY_TYPE: KeyType = KeyType::SymmetricCipherKey;
    const ALG_NAME: &'static str = AES256Internal::GCM_ALG_NAME;

    fn key_state(perm: AES256Internal) -> Self::KeyState {
        GcmKeyState::new::<32>(perm)
    }
}

impl<const TAG_LEN: usize> AeadEncryptMode<AES256Internal, 32, GCM_NONCE_LEN, TAG_LEN, TAG_LEN>
    for GCM<TAG_LEN>
{
    type Encryptor<'k> = Gcm<'k, AES256Internal, Encrypting, 32, TAG_LEN>;

    fn encrypt_init<'k>(
        state: &'k Self::KeyState,
        rng: &mut dyn RNG,
    ) -> Result<(Self::Encryptor<'k>, [u8; GCM_NONCE_LEN]), SymmetricCipherError> {
        <Self::Encryptor<'k>>::from_key_state(state, rng)
    }

    fn encrypt_init_nonce<'k>(
        state: &'k Self::KeyState,
        nonce: &[u8; GCM_NONCE_LEN],
    ) -> Self::Encryptor<'k> {
        <Self::Encryptor<'k>>::from_key_state_nonce(state, nonce)
    }
}

impl<const TAG_LEN: usize> AeadDecryptMode<AES256Internal, 32, GCM_NONCE_LEN, TAG_LEN, TAG_LEN>
    for GCM<TAG_LEN>
{
    type Decryptor<'k> = Gcm<'k, AES256Internal, Decrypting, 32, TAG_LEN>;

    fn decrypt_init<'k>(
        state: &'k Self::KeyState,
        nonce: &[u8; GCM_NONCE_LEN],
    ) -> Self::Decryptor<'k> {
        <Self::Decryptor<'k>>::from_key_state(state, nonce)
    }
}
