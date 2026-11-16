//! Type alias for SM4 in OFB mode (draft-ribose-cfrg-sm4-10 Sec 8.6; NIST SP 800-38A Sec 6.4).
//! The docs are on [`SM4_OFB`], which the crate root re-exports.

use crate::BLOCK_LEN;
use crate::hazmat::SM4Internal;
use bouncycastle_cipher::modes::Ofb;

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_core::symmetric_key::{SymmetricDecryptionKey, SymmetricEncryptionKey};
// end of imports needed for docs

/// SM4 in OFB mode, the draft's **SM4-OFB**. `Dir` is [`bouncycastle_cipher::Encrypting`] or
/// [`bouncycastle_cipher::Decrypting`].
///
/// See `bouncycastle_cipher::modes::ofb` for the construction and its security considerations.
/// The alias is a stream cipher: the data is a `&mut [u8]` of any length, encrypted or decrypted
/// in place. It comes from a key, [`SM4Key<OFB>`](crate::SM4Key), through the
/// [`SymmetricEncryptionKey`] / [`SymmetricDecryptionKey`] pair; the IV is one block, drawn from
/// the caller's RNG by `create_encryptor` and returned, or supplied to `create_encryptor_nonce`
/// by a caller who then must never repeat it under the key (Sec 8.6: "the IV *MUST* be unique for
/// each execution for an input key").
///
/// ```
/// use bouncycastle_sm4::SM4Key;
/// use bouncycastle_cipher::modes::OFB;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey};
/// use bouncycastle_core::symmetric_key::SymmetricEncryptionKey;
/// use bouncycastle_rng::HashDRBG_SHA512;
///
/// let mut rng = HashDRBG_SHA512::new_from_os();
/// let material = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
///     .expect("a 16-byte symmetric cipher key");
/// let key = SM4Key::<OFB>::from_key_material(&material).expect("a valid SM4 key");
///
/// // 47 bytes: a stream cipher does not need a whole number of blocks.
/// let message = [0u8; 47];
/// let mut data = message;
/// let (_, iv) = key.encrypt_inplace(&mut rng, &mut data).unwrap();
/// assert_ne!(data, message);
/// key.decrypt_inplace(&iv, &mut data).unwrap();
/// assert_eq!(data, message);
/// ```
#[allow(non_camel_case_types)]
pub type SM4_OFB<'k, Dir> = Ofb<'k, SM4Internal, Dir, BLOCK_LEN>;
