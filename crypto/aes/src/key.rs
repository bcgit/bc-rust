//! AES key objects: [`BlockCipherKey`] over the AES permutations, one alias per key length. The
//! docs are on [`AES128Key`], which the crate root re-exports.

use crate::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle_cipher::BlockCipherKey;

/// An AES-128 key for the mode `M`: 16 bytes of material, expanded once to a 10-round schedule.
///
/// The only state is the mode's per-key state, which holds the expanded schedule in a `Secret`
/// and so is zeroized on drop; the key has no `Debug` and no way to read the material back. A
/// caller who needs the bytes again keeps the `KeyMaterial`.
///
/// [`AES128Key<M>`], [`AES192Key<M>`] and [`AES256Key<M>`] are one type each per mode `M`:
/// [`BlockCipherKey`] over the AES permutations, so a key is bound to its AES variant and its mode
/// by the Rust type. Which workers a key hands out is decided by its mode, as that type's docs
/// say; the aliases `AES_CBC_128` and friends name them, and [`AES_GMAC_128`](crate::AES_GMAC_128)
/// the nonce-bound GMAC pair.
///
/// # Usage Examples
///
/// ```
/// use bouncycastle_aes::AES256Key;
/// use bouncycastle_cipher::modes::GCM;
/// use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
/// use bouncycastle_core::symmetric_key::{AeadDecryptionKey, AeadEncryptionKey, FromKeyMaterial};
/// use bouncycastle_core::traits::{AEADCipherDecryptor, AEADCipherEncryptor, SymmetricCipherEncryptor};
/// use bouncycastle_rng::HashDRBG_SHA512;
///
/// let mut rng = HashDRBG_SHA512::new_from_os();   // one RNG, held across messages
/// let material = KeyMaterial256::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey)
///     .expect("a 32-byte symmetric cipher key");
/// let key = AES256Key::<GCM>::from_key_material(&material).expect("a valid AES-256 key");
///
/// // Streaming: the nonce is drawn from `rng` and returned; the Result is for that draw only.
/// let (mut enc, nonce) = key.create_encryptor(&mut rng).expect("nonce draw");
/// enc.do_update_aad(b"header").expect("aad");
/// let mut ciphertext = [0u8; 14];
/// enc.do_encrypt_out(b"attack at dawn", &mut ciphertext).expect("encryption");
/// let (_, tag) = enc.do_encrypt_final_detached_out(&mut [0u8; 16]).expect("the tag");
///
/// // Decryption from the same key is infallible to set up; the nonce type follows from the key.
/// let mut dec = key.create_decryptor(&nonce);
/// dec.do_update_aad(b"header").expect("aad");
/// // ... feed `ciphertext`, then check `tag` with `do_decrypt_final_detached_out`.
///
/// // One-shots take the same path.
/// let (n, nonce) = key
///     .encrypt_with_aad_out(&mut rng, b"header", b"attack at dawn", &mut [0u8; 30])
///     .expect("one-shot");
/// assert_eq!(n, 14 + 16);
/// ```
///
/// The nonce a decryptor takes is the array the key's mode fixes, so a nonce of another length is
/// a compile error rather than a runtime one:
///
/// ```compile_fail
/// # use bouncycastle_aes::AES128Key;
/// # use bouncycastle_cipher::modes::GCM;
/// # use bouncycastle_core::symmetric_key::{AeadDecryptionKey, FromKeyMaterial};
/// # use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
/// # let km = KeyMaterial128::from_bytes_as_type(&[1; 16], KeyType::SymmetricCipherKey).unwrap();
/// let key = AES128Key::<GCM>::from_key_material(&km).unwrap();
/// let dec = key.create_decryptor(&[0u8; 16]);   // GCM's nonce is 12 bytes
/// ```
///
/// # Memory Usage
///
/// A key is its mode's per-key state: the expanded schedule, 176, 208 or 240 bytes for AES-128,
/// -192 and -256, plus 16 bytes of hash subkey under `GCM` or `GMAC`, or 32 bytes of subkeys
/// under `CMAC`.
/// The cost is paid per key, not per message, and replaces the per-message validation and
/// expansion of the `KeyMaterial` path.
#[allow(non_camel_case_types)]
pub type AES128Key<M> = BlockCipherKey<AES128Internal, M>;

/// An AES-192 key for the mode `M`: 24 bytes of material, expanded to a 12-round schedule. See
/// [`AES128Key`].
#[allow(non_camel_case_types)]
pub type AES192Key<M> = BlockCipherKey<AES192Internal, M>;

/// An AES-256 key for the mode `M`: 32 bytes of material, expanded to a 14-round schedule. See
/// [`AES128Key`].
#[allow(non_camel_case_types)]
pub type AES256Key<M> = BlockCipherKey<AES256Internal, M>;
