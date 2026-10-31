//! Type alias for SM4 in CTR mode (draft-ribose-cfrg-sm4-10 Sec 8.7; NIST SP 800-38A Sec 6.5).
//!
//! See `bouncycastle_cipher::modes::ctr` for the construction. The alias is a stream cipher: the
//! data is a `&mut [u8]` of any length, encrypted or decrypted in place. It comes from a key,
//! [`SM4Key<CTR>`](crate::SM4Key), through the [`SymmetricEncryptionKey`] /
//! [`SymmetricDecryptionKey`] pair; the nonce is drawn from the caller's RNG by encryption and
//! returned, and there is no API for supplying one.
//!
//! # The nonce length is 12, so the counter is 4
//!
//! `Ctr` splits the counter block into a nonce and a counter by the length of its init data, and
//! this alias, like `CTR`'s default, chooses a **12-byte nonce**, leaving the 4-byte counter that
//! is the mode's maximum. That allows 2^32 blocks -- 64 GiB -- in one message, and past it the
//! mode errors rather than repeating keystream. A shorter message limit in exchange for more nonce
//! bits is available by naming `CTR<13>`, `CTR<14>` or `CTR<15>` as the key's mode.
//!
//! Sec 8.7 takes the counter sequence `T` as an input beside the nonce and requires only that "the
//! counter could be any sequence that does not repeat within the block size", so `nonce || counter`
//! is one admissible choice rather than a deviation; SP 800-38A Appendix B.2, which `Ctr`
//! implements, is the same construction spelled out. The draft's own Appendix A.2.5 examples take a
//! different one -- the whole 16-byte IV is `T_1` and the block is incremented as a unit -- which
//! this split cannot express, so those vectors drive a reference CTR over the permutation in
//! `tests/stream_mode_tests.rs` and the `CTR` key is checked against that reference.
//!
//! ```
//! use bouncycastle_sm4::SM4Key;
//! use bouncycastle_cipher::modes::CTR;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey};
//! use bouncycastle_core::symmetric_key::SymmetricEncryptionKey;
//! use bouncycastle_core::traits::{StreamCipherDecryptor, StreamCipherEncryptor};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let material = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//! let key = SM4Key::<CTR>::from_key_material(&material).expect("a valid SM4 key");
//!
//! // 47 bytes: a stream cipher does not need a whole number of blocks.
//! let message = [0u8; 47];
//! let mut data = message;
//! let (_, nonce) = key.encrypt_inplace(&mut rng, &mut data).unwrap();
//! assert_eq!(nonce.len(), 12);
//! assert_ne!(data, message);
//! key.decrypt_inplace(&nonce, &mut data).unwrap();
//! assert_eq!(data, message);
//!
//! // Streaming, at any byte boundary:
//! let (mut enc, nonce) = key.create_encryptor(&mut rng).unwrap();
//! let mut first = [0u8; 5];
//! let mut rest = [1u8; 30];
//! enc.do_encrypt_inplace(&mut first).unwrap();
//! enc.do_encrypt_inplace(&mut rest).unwrap();
//! let mut dec = key.create_decryptor(&nonce);
//! dec.do_decrypt_inplace(&mut first).unwrap();
//! dec.do_decrypt_inplace(&mut rest).unwrap();
//! assert_eq!(first, [0u8; 5]);
//! assert_eq!(rest, [1u8; 30]);
//! ```

use crate::BLOCK_LEN;
use crate::hazmat::SM4Internal;
use bouncycastle_cipher::modes::Ctr;

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_core::symmetric_key::{SymmetricDecryptionKey, SymmetricEncryptionKey};
// end of imports needed for docs

/// The nonce length this alias uses, leaving a 4-byte counter.
pub const CTR_NONCE_LEN: usize = 12;

/// SM4 in CTR mode with a 12-byte nonce. `Dir` is [`bouncycastle_cipher::Encrypting`] or
/// [`bouncycastle_cipher::Decrypting`]; the wrong direction is a compile error, not a runtime
/// check.
#[allow(non_camel_case_types)]
pub type SM4_CTR<'k, Dir> = Ctr<'k, SM4Internal, Dir, BLOCK_LEN, CTR_NONCE_LEN>;
