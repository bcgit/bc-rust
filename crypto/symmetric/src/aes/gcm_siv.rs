//! Key aliases for AES-GCM-SIV (RFC 8452). The docs are on [`AES_GCM_SIV_128`], which the module
//! root re-exports.

use crate::aes::{AES128Key, AES256Key};
use crate::modes::GCM_SIV;

pub use crate::modes::{GCM_SIV_NONCE_LEN, GCM_SIV_TAG_LEN};

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_core::symmetric_key::{AeadInPlaceDecryptionKey, AeadInPlaceEncryptionKey};
// end of imports needed for docs

/// An AES-128 key for AES-GCM-SIV, the nonce misuse-resistant AEAD of RFC 8452
/// (`AEAD_AES_128_GCM_SIV`): [`AES128Key`]`<GCM_SIV>`.
///
/// See [`crate::modes::gcm_siv`] for details on the mode.
///
/// The mode cannot take a message in pieces, so where this module's other mode aliases name a
/// worker, this one names the key: there is no worker. The key carries
/// [`AeadInPlaceEncryptionKey`] / [`AeadInPlaceDecryptionKey`] and no other role. A whole message
/// is encrypted or decrypted in its own buffer, the ciphertext the same length as the plaintext,
/// with the tag of [`GCM_SIV_TAG_LEN`] (16) bytes detached. The nonce is [`GCM_SIV_NONCE_LEN`]
/// (12) bytes, drawn from the caller's RNG and returned, or taken from the caller by the `_nonce`
/// form.
///
/// RFC 8452 Section 6 defines the mode for 16- and 32-byte keys only, so there is this alias and
/// [`AES_GCM_SIV_256`], and an AES-192 key cannot be bound to the mode:
///
/// ```compile_fail,E0277
/// use bouncycastle_symmetric::aes::AES192Key;
/// use bouncycastle_symmetric::modes::GCM_SIV;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::symmetric_key::FromKeyMaterial;
///
/// let material = KeyMaterial::<24>::from_bytes_as_type(&[0x42; 24], KeyType::SymmetricCipherKey)
///     .expect("a 24-byte symmetric cipher key");
/// // The same line with `GCM` in place of `GCM_SIV` compiles.
/// let key = AES192Key::<GCM_SIV>::from_key_material(&material);
/// ```
///
/// # Usage Examples
///
/// ```
/// use bouncycastle_symmetric::aes::AES256Key;
/// use bouncycastle_symmetric::modes::GCM_SIV;
/// use bouncycastle_core::errors::SymmetricCipherError;
/// use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
/// use bouncycastle_core::symmetric_key::{
///     AeadInPlaceDecryptionKey, AeadInPlaceEncryptionKey, FromKeyMaterial,
/// };
/// use bouncycastle_rng::HashDRBG_SHA512;
///
/// let mut rng = HashDRBG_SHA512::new_from_os();   // one RNG, held across messages
/// let material = KeyMaterial256::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey)
///     .expect("a 32-byte symmetric cipher key");
/// // Validated and expanded once, for any number of messages.
/// let key = AES256Key::<GCM_SIV>::from_key_material(&material).expect("a valid AES-256 key");
///
/// // The associated data is authenticated but not encrypted; the message is both.
/// let aad = b"header, sent in the clear";
/// let mut buf = *b"a message of no particular length";
///
/// // The nonce is drawn from `rng` and returned with the tag; `buf` now holds the ciphertext.
/// let (nonce, tag) = key.encrypt_detached_inplace(&mut rng, aad, &mut buf).expect("encryption");
/// assert_ne!(&buf, b"a message of no particular length");
///
/// // A changed ciphertext, tag, nonce or associated data fails the tag check, and the buffer is
/// // zeroized rather than left holding plaintext that was never authenticated.
/// let mut tampered = buf;
/// tampered[0] ^= 1;
/// assert_eq!(
///     key.decrypt_detached_inplace(&nonce, aad, &mut tampered, &tag),
///     Err(SymmetricCipherError::AEADTagCheckFailed)
/// );
/// assert_eq!(tampered, [0u8; 33]);
///
/// key.decrypt_detached_inplace(&nonce, aad, &mut buf, &tag).expect("decryption");
/// assert_eq!(&buf, b"a message of no particular length");
/// ```
///
/// There is no streaming form to reach for: the key has no `create_encryptor`.
///
/// ```compile_fail,E0599
/// use bouncycastle_symmetric::aes::AES256Key;
/// use bouncycastle_symmetric::modes::GCM_SIV;
/// use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
/// use bouncycastle_core::symmetric_key::{AeadEncryptionKey, FromKeyMaterial};
/// use bouncycastle_rng::HashDRBG_SHA512;
///
/// let mut rng = HashDRBG_SHA512::new_from_os();
/// let material = KeyMaterial256::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey)
///     .expect("a 32-byte symmetric cipher key");
/// let key = AES256Key::<GCM_SIV>::from_key_material(&material).expect("a valid AES-256 key");
/// // The same line on an `AES256Key<GCM>` compiles.
/// let (nonce, encryptor) = key.create_encryptor(&mut rng).expect("nonce draw");
/// ```
///
/// # Memory Usage
///
/// A key is the expanded schedule and nothing else: 176 bytes for AES-128 and 240 for AES-256.
/// Each call derives that message's keys from the nonce and expands a second schedule on its own
/// stack, which is wiped when the call returns. Measured as the deepest frame chain below each
/// call in the release build on x86-64 (return addresses included, the caller's buffer not), over
/// `mem_usage_benches/src/bench_gcm_siv_mem_usage.rs`, on rustc 1.97 nightly:
///
/// | Call | AES-128 | AES-256 |
/// |---|---|---|
/// | `from_key_material` | 528 B | 672 B |
/// | `encrypt_detached_inplace_nonce` | 1 912 B | 1 912 B |
/// | `decrypt_detached_inplace` | 1 928 B | 1 928 B |
///
/// The peak of a call is the wipe's own frame, 1 816 B, the same for both key lengths, which
/// reaches below everything the encryption or decryption wrote.
///
/// # 🚨 Security Considerations 🚨
///
/// All security considerations from [`crate::modes::gcm_siv`] apply. Above all,
/// surviving a repeated nonce is a safety net and not a licence to repeat one.
#[allow(non_camel_case_types)]
pub type AES_GCM_SIV_128 = AES128Key<GCM_SIV>;

/// An AES-256 key for AES-GCM-SIV (`AEAD_AES_256_GCM_SIV`): [`AES256Key`]`<GCM_SIV>`. See
/// [`AES_GCM_SIV_128`].
#[allow(non_camel_case_types)]
pub type AES_GCM_SIV_256 = AES256Key<GCM_SIV>;
