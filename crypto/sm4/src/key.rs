//! SM4 key objects: [`BlockCipherKey`] over the SM4 permutation. The docs are on [`SM4Key`], which
//! the crate root re-exports.

use crate::hazmat::SM4Internal;
use bouncycastle_cipher::BlockCipherKey;

/// An SM4 key for the mode `M`: 16 bytes of material, expanded to the 32 round keys.
///
/// [`SM4Key<M>`] is one type per mode `M`: [`BlockCipherKey`] over the SM4 permutation, as
/// `AES128Key<M>` is over AES-128's. Which workers a key hands out is decided by its mode, as
/// that type's docs say. The eight modes this crate aliases as `SM4_*` are CBC, CFB, CFB8, CTR,
/// GCM, CCM, KW and KWP; a key under `ECB<Blocks>`, `CMAC` or `GMAC` carries the roles those
/// modes give every permutation, but no alias and no known answers here, since no SM4 standard
/// names them.
///
/// # Usage Examples
///
/// ```
/// use bouncycastle_sm4::SM4Key;
/// use bouncycastle_cipher::modes::CBC;
/// use bouncycastle_cipher::padding::PKCS7;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey};
/// use bouncycastle_core::symmetric_key::SymmetricEncryptionKey;
/// use bouncycastle_rng::HashDRBG_SHA512;
///
/// let mut rng = HashDRBG_SHA512::new_from_os();   // one RNG, held across messages
/// let material = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
///     .expect("a 16-byte symmetric cipher key");
/// let key = SM4Key::<CBC<PKCS7>>::from_key_material(&material).expect("a valid SM4 key");
///
/// let (iv, ciphertext) = key.encrypt(&mut rng, b"a message of no particular length").unwrap();
/// assert_eq!(key.decrypt(&iv, &ciphertext).unwrap(), b"a message of no particular length");
/// ```
///
/// # Memory Usage
///
/// A key is its mode's per-key state: the 128-byte round-key schedule, which the four
/// unauthenticated aliased modes keep alone, plus the 16-byte hash subkey under `GCM`, 144 bytes.
/// The cost is paid per key, not per message.
pub type SM4Key<M> = BlockCipherKey<SM4Internal, M>;
