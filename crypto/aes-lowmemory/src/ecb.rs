//! Type aliases for AES in ECB mode (NIST SP 800-38A Sec 6.1).
//!
//! `bouncycastle-modes` is deliberately cipher-agnostic, so `Ecb` takes the permutation, the
//! direction, and the `KEY_LEN` / `BLOCK_LEN` const parameters. These aliases pin the AES values so
//! callers never spell them out.
//!
//! **ECB is not a confidentiality mode for data.** Under a given key every plaintext block maps to
//! the same ciphertext block (Sec 6.1), so the structure of the plaintext shows through, and blocks
//! can be reordered, repeated or removed undetectably. These aliases exist for interoperability with
//! systems that use ECB and for driving test vectors; for data, use CBC or CFB under authentication,
//! or better an AEAD. See the crate docs, "A block permutation is not a cipher".

use crate::{Aes128, Aes192, Aes256, BLOCK_LEN};
use bouncycastle_modes::Ecb;

/// AES-128 in ECB mode. `Dir` is [`bouncycastle_modes::Encrypting`] or
/// [`bouncycastle_modes::Decrypting`]; the wrong direction is a compile error, not a runtime check.
///
/// There is no IV: `encrypt` returns an empty array and `decrypt` takes one. Encryption and
/// decryption work in place. **Not confidential for data** -- see the module docs.
///
/// ```
/// use bouncycastle_aes_lowmemory::AES_ECB_128;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::traits::{BlockCipherDecryptor, BlockCipherEncryptor};
/// use bouncycastle_modes::{Decrypting, Encrypting};
///
/// let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
///     .expect("a 16-byte symmetric cipher key");
/// // 48 bytes: three whole blocks. The length is checked at compile time.
/// let message = [0u8; 48];
/// let mut data = message;
/// let no_iv: [u8; 0] = AES_ECB_128::<Encrypting>::encrypt(&key, &mut data).unwrap();
/// assert_ne!(data, message);
/// // The codebook property: three equal plaintext blocks give three equal ciphertext blocks.
/// assert_eq!(data[..16], data[16..32]);
/// assert_eq!(data[..16], data[32..]);
/// AES_ECB_128::<Decrypting>::decrypt(&key, &no_iv, &mut data).unwrap();
/// assert_eq!(data, message);
///
/// // Streaming, a few blocks at a time:
/// let (mut enc, _) = AES_ECB_128::<Encrypting>::do_encrypt_init(&key).unwrap();
/// let mut first = [0u8; 16];
/// let mut rest = [1u8; 32];
/// enc.do_encrypt(&mut first).unwrap();
/// enc.do_encrypt(&mut rest).unwrap();
/// let mut dec = AES_ECB_128::<Decrypting>::do_decrypt_init(&key, &[]).unwrap();
/// dec.do_decrypt(&mut first).unwrap();
/// dec.do_decrypt(&mut rest).unwrap();
/// assert_eq!(first, [0u8; 16]);
/// assert_eq!(rest, [1u8; 32]);
/// ```
///
/// A length that is not a whole number of blocks is a **compile** error, not a runtime one:
///
/// ```compile_fail
/// use bouncycastle_aes_lowmemory::AES_ECB_128;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::traits::BlockCipherEncryptor;
/// use bouncycastle_modes::Encrypting;
///
/// let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap();
/// // 47 bytes is not a multiple of 16: the inline const assertion in `encrypt` fails to compile.
/// let _ = AES_ECB_128::<Encrypting>::encrypt(&key, &mut [0u8; 47]);
/// ```
#[allow(non_camel_case_types)]
pub type AES_ECB_128<Dir> = Ecb<Aes128, Dir, 16, BLOCK_LEN>;

/// AES-192 in ECB mode. See [`AES_ECB_128`].
///
/// ```
/// use bouncycastle_aes_lowmemory::AES_ECB_192;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::traits::{BlockCipherDecryptor, BlockCipherEncryptor};
/// use bouncycastle_modes::{Decrypting, Encrypting};
///
/// let key = KeyMaterial::<24>::from_bytes_as_type(&[0x42; 24], KeyType::SymmetricCipherKey).unwrap();
/// let mut data = [0u8; 32];
/// let no_iv = AES_ECB_192::<Encrypting>::encrypt(&key, &mut data).unwrap();
/// AES_ECB_192::<Decrypting>::decrypt(&key, &no_iv, &mut data).unwrap();
/// assert_eq!(data, [0u8; 32]);
/// ```
#[allow(non_camel_case_types)]
pub type AES_ECB_192<Dir> = Ecb<Aes192, Dir, 24, BLOCK_LEN>;

/// AES-256 in ECB mode. See [`AES_ECB_128`].
///
/// ```
/// use bouncycastle_aes_lowmemory::AES_ECB_256;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::traits::{BlockCipherDecryptor, BlockCipherEncryptor};
/// use bouncycastle_modes::{Decrypting, Encrypting};
///
/// let key = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey).unwrap();
/// let mut data = [0u8; 32];
/// let no_iv = AES_ECB_256::<Encrypting>::encrypt(&key, &mut data).unwrap();
/// AES_ECB_256::<Decrypting>::decrypt(&key, &no_iv, &mut data).unwrap();
/// assert_eq!(data, [0u8; 32]);
/// ```
#[allow(non_camel_case_types)]
pub type AES_ECB_256<Dir> = Ecb<Aes256, Dir, 32, BLOCK_LEN>;
