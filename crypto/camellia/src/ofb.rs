//! Type aliases for Camellia (RFC 3713) in OFB mode (NIST SP 800-38A Sec 6.4). The docs are on
//! [`Camellia_OFB_128`], which the crate root re-exports.

use crate::BLOCK_LEN;
use crate::hazmat::{Camellia128Internal, Camellia192Internal, Camellia256Internal};
use bouncycastle_cipher::modes::Ofb;

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_core::symmetric_key::{SymmetricDecryptionKey, SymmetricEncryptionKey};
// end of imports needed for docs

/// Camellia-128 in OFB mode. `Dir` is [`bouncycastle_cipher::Encrypting`] or
/// [`bouncycastle_cipher::Decrypting`].
///
/// See `bouncycastle_cipher::modes::ofb` for the construction and its security considerations.
/// The alias is a stream cipher: the data is a `&mut [u8]` of any length, encrypted or decrypted
/// in place. It comes from a key, [`Camellia128Key<OFB>`](crate::Camellia128Key), through the
/// [`SymmetricEncryptionKey`] / [`SymmetricDecryptionKey`] pair; the IV is one block, drawn from
/// the caller's RNG by `create_encryptor` and returned, or supplied to `create_encryptor_nonce`
/// by a caller who then must never repeat it under the key.
///
/// ```
/// use bouncycastle_camellia::Camellia128Key;
/// use bouncycastle_cipher::modes::OFB;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey};
/// use bouncycastle_core::symmetric_key::SymmetricEncryptionKey;
/// use bouncycastle_rng::HashDRBG_SHA512;
///
/// let mut rng = HashDRBG_SHA512::new_from_os();
/// let material = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
///     .expect("a 16-byte symmetric cipher key");
/// let key = Camellia128Key::<OFB>::from_key_material(&material).expect("a valid Camellia-128 key");
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
pub type Camellia_OFB_128<'k, Dir> = Ofb<'k, Camellia128Internal, Dir, BLOCK_LEN>;

/// Camellia-192 in OFB mode. See [`Camellia_OFB_128`].
#[allow(non_camel_case_types)]
pub type Camellia_OFB_192<'k, Dir> = Ofb<'k, Camellia192Internal, Dir, BLOCK_LEN>;

/// Camellia-256 in OFB mode. See [`Camellia_OFB_128`].
#[allow(non_camel_case_types)]
pub type Camellia_OFB_256<'k, Dir> = Ofb<'k, Camellia256Internal, Dir, BLOCK_LEN>;
