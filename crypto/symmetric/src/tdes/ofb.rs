//! Type aliases for TDES in OFB mode (NIST SP 800-38A Sec 6.4). The docs are on [`TDES_OFB`],
//! which the module root re-exports.

use crate::tdes::BLOCK_LEN;
use crate::tdes::hazmat::{TDES2Internal, TDESInternal};
use bouncycastle_cipher::Decrypting;
use bouncycastle_cipher::modes::Ofb;

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_core::symmetric_key::{SymmetricDecryptionKey, SymmetricEncryptionKey};
// end of imports needed for docs

/// TDES in OFB mode. `Dir` is [`bouncycastle_cipher::Encrypting`] or
/// [`bouncycastle_cipher::Decrypting`].
///
/// This is the TOFB mode that SP 800-38A Appendix E says is equivalent to OFB "with the TDEA as
/// the underlying block cipher". See `bouncycastle_cipher::modes::ofb` for the construction and
/// its security considerations. The alias is a stream cipher: the data is a `&mut [u8]` of any
/// length, encrypted or decrypted in place. It comes from a key,
/// [`TDES3Key<OFB>`](crate::tdes::TDES3Key), through the [`SymmetricEncryptionKey`] /
/// [`SymmetricDecryptionKey`] pair; the IV is one block (8 bytes), drawn from the caller's RNG by
/// `create_encryptor` and returned, or supplied to `create_encryptor_nonce` by a caller who then
/// must never repeat it under the key.
///
/// ```
/// use bouncycastle_symmetric::tdes::TDES3Key;
/// use bouncycastle_cipher::modes::OFB;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey};
/// use bouncycastle_core::symmetric_key::SymmetricEncryptionKey;
/// use bouncycastle_rng::HashDRBG_SHA512;
///
/// let mut rng = HashDRBG_SHA512::new_from_os();
/// // Three distinct component keys; see `TDESInternal` for what a key bundle must satisfy.
/// let bytes: [u8; 24] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
/// let material = KeyMaterial::<24>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey)
///     .expect("a 24-byte symmetric cipher key");
/// let key = TDES3Key::<OFB>::from_key_material(&material).expect("a valid key bundle");
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
pub type TDES_OFB<'k, Dir> = Ofb<'k, TDESInternal, Dir, BLOCK_LEN>;

/// Two-key TDES in OFB mode, **decryption only** (SP 800-131A Rev 2 Table 1). No direction
/// parameter: this is the `Decrypting` direction, and the key's `create_encryptor` does not
/// compile; see [`TDES2Internal`]. The IV is one 8-byte block, supplied by the caller as received.
///
/// ```
/// use bouncycastle_symmetric::tdes::TDES2Key;
/// use bouncycastle_cipher::modes::OFB;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey};
///
/// // NIST CAVP TOFBMMT2.rsp, [DECRYPT] COUNT = 0: KEY1 || KEY2 (KEY3 = KEY1).
/// let material = KeyMaterial::<16>::from_bytes_as_type(
///     &[0x15, 0xda, 0x6d, 0x40, 0x97, 0xc1, 0xb5, 0xbc,
///       0x02, 0x6e, 0x3e, 0x3e, 0xe5, 0x32, 0xf4, 0x52],
///     KeyType::SymmetricCipherKey,
/// ).expect("a 16-byte symmetric cipher key");
/// let key = TDES2Key::<OFB>::from_key_material(&material).expect("a valid two-key bundle");
/// let iv = [0xdd, 0x0f, 0x8d, 0x89, 0x21, 0xe4, 0x6c, 0x11];
/// let mut data = [0x21, 0xc3, 0xf8, 0x7a, 0x3f, 0x01, 0xbd, 0xf0];
///
/// key.decrypt_inplace(&iv, &mut data).expect("decryption");
/// assert_eq!(data, [0xa8, 0x6d, 0xf6, 0x79, 0x1e, 0x48, 0x2b, 0x72]);
/// ```
#[allow(non_camel_case_types)]
pub type TDES2_OFB<'k> = Ofb<'k, TDES2Internal, Decrypting, BLOCK_LEN>;
