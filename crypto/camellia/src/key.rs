//! Camellia key objects: [`BlockCipherKey`] over the Camellia permutations, one alias per key length.
//! The docs are on [`Camellia128Key`], which the crate root re-exports.

use crate::hazmat::{Camellia128Internal, Camellia192Internal, Camellia256Internal};
use bouncycastle_cipher::BlockCipherKey;

/// A Camellia-128 key for the mode `M`: 16 bytes of material, expanded to the 18-round subkeys.
///
/// [`Camellia128Key<M>`], [`Camellia192Key<M>`] and [`Camellia256Key<M>`] are one type each per mode `M`:
/// [`BlockCipherKey`] over the Camellia permutations, as `AES128Key<M>` and friends are over AES's.
/// Which workers a key hands out is decided by its mode, as that type's docs say; the crate names
/// the workers of CBC, CFB, CFB8, CTR, GCM, CCM, CMAC, GMAC and KW as the `Camellia_*`
/// aliases, and the rest are reached by naming the mode.
///
/// # Usage Examples
///
/// ```
/// use bouncycastle_camellia::Camellia256Key;
/// use bouncycastle_cipher::modes::CBC;
/// use bouncycastle_cipher::padding::PKCS7;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey};
/// use bouncycastle_core::symmetric_key::SymmetricEncryptionKey;
/// use bouncycastle_rng::HashDRBG_SHA512;
///
/// let mut rng = HashDRBG_SHA512::new_from_os();   // one RNG, held across messages
/// let material = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey)
///     .expect("a 32-byte symmetric cipher key");
/// let key = Camellia256Key::<CBC<PKCS7>>::from_key_material(&material)
///     .expect("a valid Camellia-256 key");
///
/// let (iv, ciphertext) = key.encrypt(&mut rng, b"a message of no particular length").unwrap();
/// assert_eq!(key.decrypt(&iv, &ciphertext).unwrap(), b"a message of no particular length");
/// ```
///
/// # Memory Usage
///
/// A key is its mode's per-key state: the expanded schedule, 208, 272 or 272 bytes for
/// Camellia-128, -192 and -256, plus whatever the mode keeps per key (16 bytes of hash subkey
/// under `GCM` and `GMAC`, 32 bytes of subkeys under `CMAC`). The cost is paid per key, not per
/// message.
#[allow(non_camel_case_types)]
pub type Camellia128Key<M> = BlockCipherKey<Camellia128Internal, M>;

/// A Camellia-192 key for the mode `M`: 24 bytes of material, expanded to the 24-round subkeys. See [`Camellia128Key`].
#[allow(non_camel_case_types)]
pub type Camellia192Key<M> = BlockCipherKey<Camellia192Internal, M>;

/// A Camellia-256 key for the mode `M`: 32 bytes of material, expanded to the 24-round subkeys. See [`Camellia128Key`].
#[allow(non_camel_case_types)]
pub type Camellia256Key<M> = BlockCipherKey<Camellia256Internal, M>;
