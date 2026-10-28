//! Type alias for SM4 in CFB8 mode (draft-ribose-cfrg-sm4-10 Sec 8.5 with `s = 8`; NIST
//! SP 800-38A Sec 6.3, `s = 8`).
//!
//! See `bouncycastle_cipher::modes::cfb8` for the construction. The alias is a stream cipher with
//! a one-byte segment, and comes from a key, [`SM4Key<CFB8>`](crate::SM4Key), through the
//! [`SymmetricEncryptionKey`] / [`SymmetricDecryptionKey`] pair; the IV is one block, drawn from
//! the caller's RNG by encryption and returned.
//!
//! This is the draft's **SM4-CFB-8**, named in Sec 8.5.1 as "the 8-bit SM4-CFB mode, where s is set
//! to 8". It is a **different, non-interoperable mode** from SM4-CFB-128, not a variant of it:
//! their ciphertexts differ from the second byte, and it costs a full SM4 call per byte, sixteen
//! times the work of [`SM4_CFB`](crate::SM4_CFB). See the `bouncycastle_cipher::modes::Cfb8` docs
//! for when that is the right trade.
//!
//! The draft defines the mode but publishes no example for it -- Appendix A.2.4's vectors are all
//! `s = 128` -- so `tests/stream_mode_tests.rs` pins this alias against the Sec 8.5.2 equations
//! evaluated directly over the permutation instead.
//!
//! ```
//! use bouncycastle_sm4::SM4Key;
//! use bouncycastle_cipher::modes::{CFB, CFB8};
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey};
//! use bouncycastle_core::symmetric_key::SymmetricEncryptionKey;
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let material = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//! let cfb8_key = SM4Key::<CFB8>::from_key_material(&material).expect("a valid SM4 key");
//!
//! // 5 bytes: CFB8's segment is one byte, so any length at all is fine.
//! let message = *b"hello";
//! let mut data = message;
//! let (_, iv) = cfb8_key.encrypt_inplace(&mut rng, &mut data).unwrap();
//! assert_ne!(data, message);
//! cfb8_key.decrypt_inplace(&iv, &mut data).unwrap();
//! assert_eq!(data, message);
//!
//! // SM4-CFB-8 and SM4-CFB-128 are not interchangeable: same key material, same IV, different
//! // ciphertext.
//! let cfb_key = SM4Key::<CFB>::from_key_material(&material).unwrap();
//! let mut as_cfb8 = message;
//! let (_, iv) = cfb8_key.encrypt_inplace(&mut rng, &mut as_cfb8).unwrap();
//! let mut as_cfb128 = as_cfb8;
//! cfb_key.decrypt_inplace(&iv, &mut as_cfb128).unwrap();
//! assert_ne!(as_cfb128, message);
//! ```

use crate::BLOCK_LEN;
use crate::hazmat::SM4Internal;
use bouncycastle_cipher::modes::Cfb8;

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_core::symmetric_key::{SymmetricDecryptionKey, SymmetricEncryptionKey};
// end of imports needed for docs

/// SM4 in CFB8 mode. `Dir` is [`bouncycastle_cipher::Encrypting`] or
/// [`bouncycastle_cipher::Decrypting`]; the wrong direction is a compile error, not a runtime
/// check.
#[allow(non_camel_case_types)]
pub type SM4_CFB8<'k, Dir> = Cfb8<'k, SM4Internal, Dir, BLOCK_LEN>;
