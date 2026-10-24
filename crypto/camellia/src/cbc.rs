//! Type aliases for Camellia (RFC 3713) in CBC mode (NIST SP 800-38A Sec 6.2), with padding.
//!
//! See `bouncycastle_cipher::modes::cbc` for the construction. The aliases name the padded
//! workers, which accept input of any size; `NoPadding` accepts only whole blocks but goes through
//! the same adapter. The workers come from a key: [`Camellia128Key<CBC<PKCS7>>`](crate::Camellia128Key)
//! (or `CBC<NoPadding>`) hands them out through the [`SymmetricEncryptionKey`] /
//! [`SymmetricDecryptionKey`] pair, and `Camellia128Key<CBC<Blocks>>` hands out the unpadded `Cbc`
//! itself through the block pair.
//!
//! CBC is defined only on whole blocks (SP 800-38A Sec 5.2), so CBC on data of any other length is
//! always CBC *plus a padding scheme*, and the scheme changes the ciphertext and must be agreed by
//! both ends. Naming it in the key's mode makes that choice explicit and makes a mismatched pair a
//! compile error.
//!
//! ```
//! use bouncycastle_camellia::Camellia128Key;
//! use bouncycastle_cipher::modes::CBC;
//! use bouncycastle_cipher::padding::PKCS7;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let material = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//! let key = Camellia128Key::<CBC<PKCS7>>::from_key_material(&material).expect("a valid Camellia-128 key");
//! let message = b"a message of no particular length";
//!
//! // The IV is drawn from `rng` and returned; there is no API for supplying one.
//! let (iv, ciphertext) = key.encrypt(&mut rng, message).expect("encryption");
//! let recovered = key.decrypt(&iv, &ciphertext).expect("decryption");
//! assert_eq!(recovered, message);
//! ```
//!
//! With [`NoPadding`] nothing is added, and a message that is not a whole number of blocks is an
//! error rather than something silently padded:
//!
//! ```
//! use bouncycastle_camellia::Camellia128Key;
//! use bouncycastle_cipher::modes::CBC;
//! use bouncycastle_cipher::padding::NoPadding;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricEncryptionKey};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let material = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap();
//! let key = Camellia128Key::<CBC<NoPadding>>::from_key_material(&material).unwrap();
//!
//! let mut out = [0u8; 16];
//! let (written, _iv) = key.encrypt_out(&mut rng, &[0u8; 16], &mut out).expect("aligned");
//! assert_eq!(written, 16);
//! assert!(key.encrypt_out(&mut rng, b"hello", &mut out).is_err());
//! ```

use crate::BLOCK_LEN;
use crate::hazmat::{Camellia128Internal, Camellia192Internal, Camellia256Internal};
use bouncycastle_cipher::Direction;
use bouncycastle_cipher::modes::Cbc;
use bouncycastle_cipher::padding::{PaddedBlockCipherDecryptor, PaddedBlockCipherEncryptor};
use bouncycastle_cipher::{Decrypting, Encrypting};

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_cipher::padding::{NoPadding, PKCS7};
#[allow(unused_imports)]
use bouncycastle_core::symmetric_key::{SymmetricDecryptionKey, SymmetricEncryptionKey};
// end of imports needed for docs

/// Camellia-128 in CBC mode with a padding scheme: what an [`Camellia128Key`](crate::Camellia128Key) under
/// `CBC<Pad>` hands out. `Dir` is [`Encrypting`] or [`Decrypting`] and `Pad` is [`PKCS7`] or
/// [`NoPadding`]; the wrong direction is a compile error, not a runtime check.
#[allow(non_camel_case_types)]
pub type Camellia_CBC_128<'k, Dir, Pad> = <Dir as Direction>::Select<
    PaddedBlockCipherEncryptor<
        Cbc<'k, Camellia128Internal, Encrypting, BLOCK_LEN>,
        Pad,
        BLOCK_LEN,
        BLOCK_LEN,
    >,
    PaddedBlockCipherDecryptor<
        Cbc<'k, Camellia128Internal, Decrypting, BLOCK_LEN>,
        Pad,
        BLOCK_LEN,
        BLOCK_LEN,
    >,
>;

/// Camellia-192 in CBC mode with a padding scheme. See [`Camellia_CBC_128`].
#[allow(non_camel_case_types)]
pub type Camellia_CBC_192<'k, Dir, Pad> = <Dir as Direction>::Select<
    PaddedBlockCipherEncryptor<
        Cbc<'k, Camellia192Internal, Encrypting, BLOCK_LEN>,
        Pad,
        BLOCK_LEN,
        BLOCK_LEN,
    >,
    PaddedBlockCipherDecryptor<
        Cbc<'k, Camellia192Internal, Decrypting, BLOCK_LEN>,
        Pad,
        BLOCK_LEN,
        BLOCK_LEN,
    >,
>;

/// Camellia-256 in CBC mode with a padding scheme. See [`Camellia_CBC_128`].
#[allow(non_camel_case_types)]
pub type Camellia_CBC_256<'k, Dir, Pad> = <Dir as Direction>::Select<
    PaddedBlockCipherEncryptor<
        Cbc<'k, Camellia256Internal, Encrypting, BLOCK_LEN>,
        Pad,
        BLOCK_LEN,
        BLOCK_LEN,
    >,
    PaddedBlockCipherDecryptor<
        Cbc<'k, Camellia256Internal, Decrypting, BLOCK_LEN>,
        Pad,
        BLOCK_LEN,
        BLOCK_LEN,
    >,
>;
