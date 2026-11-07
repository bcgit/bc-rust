//! Type aliases for ARIA in GCM (NIST SP 800-38D). The docs are on [`ARIA_GCM_128`], which the
//! crate root re-exports.

use crate::hazmat::{ARIA128Internal, ARIA192Internal, ARIA256Internal};
use bouncycastle_cipher::modes::Gcm;

/// ARIA-128 in GCM with a 128-bit tag: the `Gcm` worker of `bouncycastle-cipher` over the ARIA
/// permutation, from an `ARIA128Key<GCM>` through the `AeadEncryptionKey` / `AeadDecryptionKey`
/// pair. The construction, the API and its security considerations are those of
/// [`bouncycastle_cipher::modes::gcm`] and, alias for alias, of `AES_GCM_128` in
/// `bouncycastle-aes`; only the permutation differs. RFC 5794 Appendix B names it
/// `id-aria128-gcm`.
///
/// # Usage Examples
///
/// ```
/// use bouncycastle_aria::ARIA256Key;
/// use bouncycastle_cipher::modes::GCM;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::symmetric_key::{AeadDecryptionKey, AeadEncryptionKey, FromKeyMaterial};
/// use bouncycastle_rng::HashDRBG_SHA512;
///
/// let mut rng = HashDRBG_SHA512::new_from_os();
/// let material = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey)
///     .expect("a 32-byte symmetric cipher key");
/// let key = ARIA256Key::<GCM>::from_key_material(&material).expect("a valid ARIA-256 key");
///
/// let aad = b"header, sent in the clear";
/// let (nonce, ciphertext, tag) = key.encrypt_detached(&mut rng, aad, b"message").expect("encryption");
/// assert_eq!(key.decrypt_detached(&nonce, aad, &ciphertext, &tag).expect("decryption"), b"message");
/// assert!(key.decrypt_detached(&nonce, b"other header", &ciphertext, &tag).is_err());
/// ```
#[allow(non_camel_case_types)]
pub type ARIA_GCM_128<'k, Dir> = Gcm<'k, ARIA128Internal, Dir, 16>;

/// ARIA-192 in GCM with a 128-bit tag. See [`ARIA_GCM_128`].
#[allow(non_camel_case_types)]
pub type ARIA_GCM_192<'k, Dir> = Gcm<'k, ARIA192Internal, Dir, 16>;

/// ARIA-256 in GCM with a 128-bit tag. See [`ARIA_GCM_128`].
#[allow(non_camel_case_types)]
pub type ARIA_GCM_256<'k, Dir> = Gcm<'k, ARIA256Internal, Dir, 16>;
