//! ARIA key objects: [`BlockCipherKey`] over the ARIA permutations, one alias per key length.
//! The docs are on [`ARIA128Key`], which the crate root re-exports.

use crate::hazmat::{ARIA128Internal, ARIA192Internal, ARIA256Internal};
use bouncycastle_cipher::BlockCipherKey;

/// An ARIA-128 key for the mode `M`: 16 bytes of material, expanded to a 12-round schedule.
///
/// [`ARIA128Key<M>`], [`ARIA192Key<M>`] and [`ARIA256Key<M>`] are one type each per mode `M`:
/// [`BlockCipherKey`] over the ARIA permutations, as `AES128Key<M>` and friends are over AES's.
/// Which workers a key hands out is decided by its mode, as that type's docs say; the crate names
/// the workers of CBC, CFB, CFB8, CTR, GCM, CCM, CMAC, GMAC, KW and KWP as the `ARIA_*`
/// aliases, and the rest are reached by naming the mode.
///
/// # Usage Examples
///
/// ```
/// use bouncycastle_aria::ARIA256Key;
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
/// let key = ARIA256Key::<CBC<PKCS7>>::from_key_material(&material).expect("a valid ARIA-256 key");
///
/// let (iv, ciphertext) = key.encrypt(&mut rng, b"a message of no particular length").unwrap();
/// assert_eq!(key.decrypt(&iv, &ciphertext).unwrap(), b"a message of no particular length");
/// ```
///
/// # Memory Usage
///
/// A key is its mode's per-key state: the expanded schedule, 208, 240 or 272 bytes for ARIA-128,
/// -192 and -256, plus whatever the mode keeps per key (16 bytes of hash subkey under `GCM` and
/// `GMAC`, 32 bytes of subkeys under `CMAC`). The cost is paid per key, not per message.
#[allow(non_camel_case_types)]
pub type ARIA128Key<M> = BlockCipherKey<ARIA128Internal, M>;

/// An ARIA-192 key for the mode `M`: 24 bytes of material, expanded to a 14-round schedule. See [`ARIA128Key`].
#[allow(non_camel_case_types)]
pub type ARIA192Key<M> = BlockCipherKey<ARIA192Internal, M>;

/// An ARIA-256 key for the mode `M`: 32 bytes of material, expanded to a 16-round schedule. See [`ARIA128Key`].
#[allow(non_camel_case_types)]
pub type ARIA256Key<M> = BlockCipherKey<ARIA256Internal, M>;
