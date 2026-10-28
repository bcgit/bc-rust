//! Type alias for SM4 in CFB mode (draft-ribose-cfrg-sm4-10 Sec 8.5; NIST SP 800-38A Sec 6.3),
//! full-block segment.
//!
//! See `bouncycastle_cipher::modes::cfb` for the construction. The alias is a stream cipher: the
//! data is a `&mut [u8]` of any length, encrypted or decrypted in place. It comes from a key,
//! [`SM4Key<CFB>`](crate::SM4Key), through the [`SymmetricEncryptionKey`] /
//! [`SymmetricDecryptionKey`] pair; the IV is one block, drawn from the caller's RNG by encryption
//! and returned, and there is no API for supplying one.
//!
//! The segment size is the full block, so this is the draft's **SM4-CFB-128**, one of the four
//! variants Sec 8.5.1 names: "SM4-CFB-1 ... SM4-CFB-8 ... SM4-CFB-64 ... SM4-CFB-128, the 128-bit
//! SM4-CFB mode, where s is set to 128." The `s = 8` variant is a different, non-interoperable mode
//! with its own alias, [`SM4_CFB8`](crate::SM4_CFB8); `s = 1` and `s = 64` are not implemented.
//!
//! Sec 8.5 says the plaintext "must be a multiple of the block size". `Cfb` accepts any length and
//! treats a short tail as a final segment of `s = 8r`, which is what every streaming CFB128
//! implementation does; see "The final partial segment" in the `bouncycastle_cipher::modes::Cfb`
//! docs for why that is well defined. On whole blocks -- the only lengths the draft's Appendix
//! A.2.4 vectors cover -- the two readings coincide.
//!
//! ```
//! use bouncycastle_sm4::SM4Key;
//! use bouncycastle_cipher::modes::CFB;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey};
//! use bouncycastle_core::symmetric_key::SymmetricEncryptionKey;
//! use bouncycastle_core::traits::{StreamCipherDecryptor, StreamCipherEncryptor};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let material = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//! let key = SM4Key::<CFB>::from_key_material(&material).expect("a valid SM4 key");
//!
//! // 47 bytes: a stream cipher does not need a whole number of blocks.
//! let message = [0u8; 47];
//! let mut data = message;
//! let (_, iv) = key.encrypt_inplace(&mut rng, &mut data).unwrap();
//! assert_ne!(data, message);
//! key.decrypt_inplace(&iv, &mut data).unwrap();
//! assert_eq!(data, message);
//!
//! // Streaming, at any byte boundary:
//! let (mut enc, iv) = key.create_encryptor(&mut rng).unwrap();
//! let mut first = [0u8; 5];
//! let mut rest = [1u8; 30];
//! enc.do_encrypt_inplace(&mut first).unwrap();
//! enc.do_encrypt_inplace(&mut rest).unwrap();
//! let mut dec = key.create_decryptor(&iv);
//! dec.do_decrypt_inplace(&mut first).unwrap();
//! dec.do_decrypt_inplace(&mut rest).unwrap();
//! assert_eq!(first, [0u8; 5]);
//! assert_eq!(rest, [1u8; 30]);
//! ```

use crate::BLOCK_LEN;
use crate::hazmat::SM4Internal;
use bouncycastle_cipher::modes::Cfb;

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_core::symmetric_key::{SymmetricDecryptionKey, SymmetricEncryptionKey};
// end of imports needed for docs

/// SM4 in CFB128 mode. `Dir` is [`bouncycastle_cipher::Encrypting`] or
/// [`bouncycastle_cipher::Decrypting`]; the wrong direction is a compile error, not a runtime
/// check.
#[allow(non_camel_case_types)]
pub type SM4_CFB<'k, Dir> = Cfb<'k, SM4Internal, Dir, BLOCK_LEN>;
