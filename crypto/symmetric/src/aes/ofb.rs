//! Type aliases for AES in OFB mode (NIST SP 800-38A Sec 6.4). The docs are on [`AES_OFB_128`],
//! which the module root re-exports.

use crate::aes::AES_BLOCK_LEN;
use crate::aes::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use crate::modes::Ofb;

// Imports needed for docs
#[allow(unused_imports)]
use crate::{Decrypting, Encrypting};
#[allow(unused_imports)]
use bouncycastle_core::symmetric_key::{SymmetricDecryptionKey, SymmetricEncryptionKey};
// end of imports needed for docs

/// AES-128 in OFB mode.
///
/// See [`crate::modes::ofb`] for details on the Output Feedback construction.
///
/// The aliases here are stream ciphers: the data is a `&mut [u8]` of any length, encrypted or
/// decrypted in place, and the ciphertext is exactly as long as the plaintext. They come from a
/// key, [`AES128Key<OFB>`](crate::aes::AES128Key) and friends, through the [`SymmetricEncryptionKey`]
/// / [`SymmetricDecryptionKey`] pair. `create_encryptor` draws the IV from the caller's RNG and
/// returns it; `create_encryptor_nonce` takes it from the caller, who must then never repeat it
/// under the key. `Dir` is [`Encrypting`] or [`Decrypting`].
///
/// # Usage Examples
///
/// ```
/// use bouncycastle_symmetric::aes::AES128Key;
/// use bouncycastle_symmetric::modes::OFB;
/// use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
/// use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey};
/// use bouncycastle_core::traits::{StreamCipherDecryptor, StreamCipherEncryptor};
/// use bouncycastle_rng::HashDRBG_SHA512;
///
/// let mut rng = HashDRBG_SHA512::new_from_os();
/// let material = KeyMaterial128::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
///     .expect("a 16-byte symmetric cipher key");
/// let key = AES128Key::<OFB>::from_key_material(&material).expect("a valid AES-128 key");
///
/// // One-shot, in place, at any length. The IV is drawn from `rng` and returned.
/// let plaintext = [0x5Au8; 47];
/// let mut data = plaintext;
/// let (_, iv) = key.encrypt_inplace(&mut rng, &mut data).expect("encryption");
/// key.decrypt_inplace(&iv, &mut data).expect("decryption");
/// assert_eq!(data, plaintext);
///
/// // Streaming, in pieces of any length.
/// let (mut encryptor, iv) = key.create_encryptor(&mut rng).expect("IV draw");
/// let mut ciphertext = plaintext;
/// for piece in ciphertext.chunks_mut(7) {
///     encryptor.do_encrypt_inplace(piece).expect("encryption");
/// }
/// let mut decryptor = key.create_decryptor(&iv);
/// for piece in ciphertext.chunks_mut(19) {
///     decryptor.do_decrypt_inplace(piece).expect("decryption");
/// }
/// assert_eq!(ciphertext, plaintext);
/// ```
///
/// # 🚨 Security Considerations 🚨
///
/// All security considerations from [`crate::modes::ofb`] apply.
#[allow(non_camel_case_types)]
pub type AES_OFB_128<'k, Dir> = Ofb<'k, AES128Internal, Dir, AES_BLOCK_LEN>;

/// AES-192 in OFB mode. See [`AES_OFB_128`].
#[allow(non_camel_case_types)]
pub type AES_OFB_192<'k, Dir> = Ofb<'k, AES192Internal, Dir, AES_BLOCK_LEN>;

/// AES-256 in OFB mode. See [`AES_OFB_128`].
#[allow(non_camel_case_types)]
pub type AES_OFB_256<'k, Dir> = Ofb<'k, AES256Internal, Dir, AES_BLOCK_LEN>;
