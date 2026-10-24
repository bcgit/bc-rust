//! Type aliases for TDES in CTR mode (NIST SP 800-38A Sec 6.5).
//!
//! See `bouncycastle_cipher::modes::ctr` for the construction. The aliases are stream ciphers:
//! the data is a `&mut [u8]` of any length, encrypted or decrypted in place since the ciphertext
//! is exactly as long as the plaintext. They come from a key,
//! [`TDES3Key<CTR<CTR_NONCE_LEN, BLOCK_LEN>>`](crate::TDES3Key), through the
//! [`SymmetricEncryptionKey`] / [`SymmetricDecryptionKey`] pair; the nonce is drawn from the
//! caller's RNG by encryption and returned, and there is no API for supplying one. `CTR`'s
//! defaults are AES's 12-byte nonce on a 16-byte block, so both parameters must be spelled out
//! for TDEA.
//!
//! SP 800-38A Appendix E: "the Triple DES algorithm, i.e., TDEA, as described above, may be used
//! as the underlying block cipher algorithm for the six modes in this recommendation. One of the
//! resulting modes of Triple DES is new, i.e., not specified in ANSI X9.52: the CTR mode of the
//! TDEA."
//!
//! # The nonce is 6 bytes, so the counter is 2
//!
//! `Ctr` splits the 8-byte counter block into a nonce and a counter by the length of its init
//! data. A 64-bit block leaves very little room, and the split is a trade between two limits:
//!
//! * The counter bounds one message. Two bytes is 65 536 blocks, 512 KiB, after which the mode
//!   errors rather than repeat a counter block.
//! * The nonce is random (Appendix B.2), so two messages under one key bundle collide with
//!   probability about `n^2 / 2^(8 * nonce_len + 1)` after `n` messages. A collision repeats the
//!   keystream, which is fatal for CTR.
//!
//! SP 800-67r2 Sec 3.4 caps a key bundle at `2^20` blocks in total, so at most `2^20` messages can
//! ever be encrypted under one bundle, and 512 KiB per message is one sixteenth of the bundle's
//! whole budget. Against that, the collision probability over a bundle's lifetime is at most about
//! `2^-9` with a 6-byte nonce, `2^-1` with 5 bytes, and a certainty with 4. Six is the widest nonce
//! whose counter can still reach a useful message size, and it is what [`CTR_NONCE_LEN`] chooses.
//! Name `CTR<N, 8>` with another `N` as the key's mode for a different split.

use crate::BLOCK_LEN;
use crate::hazmat::{TDES2Internal, TDESInternal};
use bouncycastle_cipher::Decrypting;
use bouncycastle_cipher::modes::Ctr;

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_core::symmetric_key::{SymmetricDecryptionKey, SymmetricEncryptionKey};
// end of imports needed for docs

/// The nonce length the [`TDES_CTR`] alias uses, leaving a 2-byte counter. See the module docs.
pub const CTR_NONCE_LEN: usize = 6;

/// TDES in CTR mode with a 6-byte nonce. `Dir` is [`bouncycastle_cipher::Encrypting`] or
/// [`bouncycastle_cipher::Decrypting`]; the wrong direction is a compile error, not a runtime check.
///
/// A message longer than 65 536 blocks (512 KiB) is an error, not a repeated counter; see the
/// module docs.
///
/// ```
/// use bouncycastle_tdes::{BLOCK_LEN, CTR_NONCE_LEN, TDES3Key};
/// use bouncycastle_cipher::modes::CTR;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey};
/// use bouncycastle_core::traits::{StreamCipherDecryptor, StreamCipherEncryptor};
/// use bouncycastle_rng::HashDRBG_SHA512;
///
/// let mut rng = HashDRBG_SHA512::new_from_os();
/// // Three distinct component keys; see `TDESInternal` for what a key bundle must satisfy.
/// let bytes: [u8; 24] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
/// let material = KeyMaterial::<24>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey)
///     .expect("a 24-byte symmetric cipher key");
/// let key = TDES3Key::<CTR<CTR_NONCE_LEN, BLOCK_LEN>>::from_key_material(&material)
///     .expect("a valid key bundle");
///
/// // 47 bytes: a stream cipher does not need a whole number of blocks.
/// let message = [0u8; 47];
/// let mut data = message;
/// let (_, nonce) = key.encrypt_inplace(&mut rng, &mut data).unwrap();
/// assert_eq!(nonce.len(), 6);
/// assert_ne!(data, message);
/// key.decrypt_inplace(&nonce, &mut data).unwrap();
/// assert_eq!(data, message);
///
/// // Streaming, at any byte boundary:
/// let (mut enc, nonce) = key.create_encryptor(&mut rng).unwrap();
/// let mut first = [0u8; 5];
/// let mut rest = [1u8; 30];
/// enc.do_encrypt_inplace(&mut first).unwrap();
/// enc.do_encrypt_inplace(&mut rest).unwrap();
/// let mut dec = key.create_decryptor(&nonce);
/// dec.do_decrypt_inplace(&mut first).unwrap();
/// dec.do_decrypt_inplace(&mut rest).unwrap();
/// assert_eq!(first, [0u8; 5]);
/// assert_eq!(rest, [1u8; 30]);
/// ```
#[allow(non_camel_case_types)]
pub type TDES_CTR<'k, Dir> = Ctr<'k, TDESInternal, Dir, BLOCK_LEN, CTR_NONCE_LEN>;

/// Two-key TDES in CTR mode with a 6-byte nonce, **decryption only** (SP 800-131A Rev 2 Table 1).
/// No direction parameter: this is the `Decrypting` direction, and the key's `create_encryptor`
/// does not compile; see [`TDES2Internal`]. The nonce is supplied by the caller as received, and
/// the counter block is `nonce || counter` with the counter starting at zero, as for [`TDES_CTR`].
///
/// There is no NIST vector for TDEA in CTR mode, so this example checks the mode's definition
/// instead: the first keystream block is the forward cipher function of `nonce || 0x0000`.
///
/// ```
/// use bouncycastle_tdes::hazmat::TDES2Internal;
/// use bouncycastle_tdes::{BLOCK_LEN, CTR_NONCE_LEN, TDES2Key};
/// use bouncycastle_cipher::modes::CTR;
/// use bouncycastle_core::hazmat::{BlockPermutation, ElectronicCodeBook};
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey};
///
/// let bytes: [u8; 16] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
/// let material = KeyMaterial::<16>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).unwrap();
/// let nonce = [1, 2, 3, 4, 5, 6];
///
/// // What a legacy sender would have produced: the first counter block, through the permutation.
/// let mut keystream = [1, 2, 3, 4, 5, 6, 0, 0];
/// TDES2Internal::new(&material).unwrap().encrypt_block(&mut keystream);
/// let plaintext = *b"8 bytes!";
/// let mut data: [u8; 8] = core::array::from_fn(|i| plaintext[i] ^ keystream[i]);
///
/// let key = TDES2Key::<CTR<CTR_NONCE_LEN, BLOCK_LEN>>::from_key_material(&material).unwrap();
/// key.decrypt_inplace(&nonce, &mut data).expect("decryption");
/// assert_eq!(data, plaintext);
/// ```
#[allow(non_camel_case_types)]
pub type TDES2_CTR<'k> = Ctr<'k, TDES2Internal, Decrypting, BLOCK_LEN, CTR_NONCE_LEN>;
