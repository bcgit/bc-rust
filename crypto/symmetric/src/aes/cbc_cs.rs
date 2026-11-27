//! Type aliases for AES under CBC with ciphertext stealing (Addendum to NIST SP 800-38A): CBC-CS1,
//! CBC-CS2 and CBC-CS3, and CTS, another name for CBC-CS3. The docs are on [`AES_CBC_CS1_128`],
//! which the module root re-exports.

use crate::aes::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use crate::modes::{CS1, CS2, CS3, CbcCs};

// Imports needed for docs
#[allow(unused_imports)]
use crate::modes::{CBC_CS1, CBC_CS2, CBC_CS3, CTS};
#[allow(unused_imports)]
use bouncycastle_core::symmetric_key::{SymmetricDecryptionKey, SymmetricEncryptionKey};
// end of imports needed for docs

/// AES-128 under CBC-CS1 (Addendum to NIST SP 800-38A Sec 2): CBC on a message of any length of
/// at least one block, with no padding, so the ciphertext is exactly as long as the plaintext.
///
/// See [`crate::modes::cbc_cs`] for the three variants, how they differ and the lengths they
/// take. The aliases here name the workers: [`AES128Key<CBC_CS1>`](crate::aes::AES128Key) hands
/// them out through the [`SymmetricEncryptionKey`] / [`SymmetricDecryptionKey`] pair, as the
/// `CBC_CS2`, `CBC_CS3` and `CTS` keys hand out [`AES_CBC_CS2_128`], [`AES_CBC_CS3_128`] and
/// [`AES_CTS_128`], the last two one type.
///
/// # Usage Examples
///
/// ## One-shot API
///
/// ```
/// use bouncycastle_symmetric::aes::AES256Key;
/// use bouncycastle_symmetric::modes::CBC_CS3;
/// use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
/// use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey};
/// use bouncycastle_rng::HashDRBG_SHA512;
///
/// let mut rng = HashDRBG_SHA512::new_from_os();   // one RNG, held across messages
/// let material = KeyMaterial256::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey)
///     .expect("a 32-byte symmetric cipher key");
/// let key = AES256Key::<CBC_CS3>::from_key_material(&material).expect("a valid AES-256 key");
///
/// // Any length from one block up, with no padding: 50 bytes encrypt to 50 bytes.
/// let plaintext = [0x5Au8; 50];
/// let (iv, ciphertext) = key.encrypt(&mut rng, &plaintext).expect("encryption");
/// assert_eq!(ciphertext.len(), 50);
///
/// let recovered = key.decrypt(&iv, &ciphertext).expect("decryption");
/// assert_eq!(recovered, plaintext);
///
/// // Less than one block is refused, in both directions.
/// assert!(key.encrypt(&mut rng, &[0x5Au8; 15]).is_err());
/// assert!(key.decrypt(&iv, &ciphertext[..15]).is_err());
/// ```
///
/// ## Streaming API
///
/// ```
/// use bouncycastle_symmetric::aes::AES128Key;
/// use bouncycastle_symmetric::modes::{CBC_CS1, CBC_CS_FINAL_LEN};
/// use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
/// use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey};
/// use bouncycastle_core::traits::{SymmetricCipherDecryptor, SymmetricCipherEncryptor};
/// use bouncycastle_rng::HashDRBG_SHA512;
///
/// let mut rng = HashDRBG_SHA512::new_from_os();
/// let material = KeyMaterial128::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
///     .expect("a 16-byte symmetric cipher key");
/// let key = AES128Key::<CBC_CS1>::from_key_material(&material).expect("a valid AES-128 key");
///
/// let plaintext = [0x5Au8; 50];
///
/// // A block is written once more than one further block of the message follows it: the last
/// // two portions depend on where the message ends, and the final writes them.
/// let (mut encryptor, iv) = key.create_encryptor(&mut rng).expect("IV draw");
/// let mut ciphertext = Vec::new();
/// for piece in plaintext.chunks(7) {
///     let mut out = vec![0u8; encryptor.do_encrypt_out_len(piece.len())];
///     let written = encryptor.do_encrypt_out(piece, &mut out).expect("encryption");
///     ciphertext.extend_from_slice(&out[..written]);
/// }
/// let (last, last_len) = encryptor.do_encrypt_final().expect("a message of at least a block");
/// ciphertext.extend_from_slice(&last[..last_len]);
/// assert_eq!(ciphertext.len(), 50);
///
/// let mut decryptor = key.create_decryptor(&iv);
/// let mut recovered = Vec::new();
/// for piece in ciphertext.chunks(19) {
///     let mut out = vec![0u8; decryptor.do_decrypt_out_len(piece.len())];
///     let written = decryptor.do_decrypt_out(piece, &mut out).expect("decryption");
///     recovered.extend_from_slice(&out[..written]);
/// }
/// let mut last = [0u8; CBC_CS_FINAL_LEN];
/// let last_len = decryptor.do_decrypt_final_out(&mut last).expect("a ciphertext of at least a block");
/// recovered.extend_from_slice(&last[..last_len]);
/// assert_eq!(recovered, plaintext);
/// ```
///
/// ## CTS is CBC-CS3
///
/// `CTS` is another name for `CBC_CS3`, so the two keys are one type. This reproduces the first
/// AES-128 vector of RFC 3962 Appendix B, a 17-byte message under an all-zero IV; the IV is
/// supplied because the vector fixes it:
///
/// ```
/// use bouncycastle_symmetric::aes::AES128Key;
/// use bouncycastle_symmetric::modes::{CBC_CS3, CTS};
/// use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
/// use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricEncryptionKey};
///
/// let material = KeyMaterial128::from_bytes_as_type(b"chicken teriyaki", KeyType::SymmetricCipherKey)
///     .expect("the vector's 16-byte key");
/// let key: AES128Key<CBC_CS3> = AES128Key::<CTS>::from_key_material(&material).expect("a key");
///
/// let ciphertext = key.encrypt_nonce(&[0u8; 16], b"I would like the ").expect("encryption");
/// assert_eq!(
///     ciphertext,
///     [
///         0xc6, 0x35, 0x35, 0x68, 0xf2, 0xbf, 0x8c, 0xb4, 0xd8, 0xa5, 0x80, 0x36, 0x2d, 0xa7,
///         0xff, 0x7f, 0x97
///     ]
/// );
/// ```
///
/// # Memory Usage
///
/// A key is its AES schedule, as for every AES mode, and a worker is 72 bytes: the end of the
/// message it holds back, at most 32 bytes, CBC's chaining block and a borrow of the key. A one-shot
/// works in the caller's buffers, so its stack does not grow with the message. Measured as the
/// deepest frame chain below each call in the release build on x86-64 (return addresses included,
/// the caller's buffers not), over `mem_usage_benches/src/bench_aes_mem_usage.rs`, the same for all
/// three variants and all three key lengths:
///
/// | Call | Stack |
/// |---|---|
/// | `encrypt_nonce_out` | 224 B |
/// | `decrypt_out` | 568 B |
///
/// Decryption is the deeper because the blocks it releases go through the permutation's four-block
/// path, as CBC's do. The drawing `encrypt_out` adds the RNG's draw.
///
/// # 🚨 Security Considerations 🚨
///
/// All security considerations from [`crate::modes::cbc_cs`] apply.
#[allow(non_camel_case_types)]
pub type AES_CBC_CS1_128<'k, Dir> = CbcCs<'k, AES128Internal, Dir, CS1>;

/// AES-192 under CBC-CS1. See [`AES_CBC_CS1_128`].
#[allow(non_camel_case_types)]
pub type AES_CBC_CS1_192<'k, Dir> = CbcCs<'k, AES192Internal, Dir, CS1>;

/// AES-256 under CBC-CS1. See [`AES_CBC_CS1_128`].
#[allow(non_camel_case_types)]
pub type AES_CBC_CS1_256<'k, Dir> = CbcCs<'k, AES256Internal, Dir, CS1>;

/// AES-128 under CBC-CS2 (Addendum to NIST SP 800-38A Sec 3), which swaps the last two portions
/// when the last block is partial. See [`AES_CBC_CS1_128`].
#[allow(non_camel_case_types)]
pub type AES_CBC_CS2_128<'k, Dir> = CbcCs<'k, AES128Internal, Dir, CS2>;

/// AES-192 under CBC-CS2. See [`AES_CBC_CS2_128`].
#[allow(non_camel_case_types)]
pub type AES_CBC_CS2_192<'k, Dir> = CbcCs<'k, AES192Internal, Dir, CS2>;

/// AES-256 under CBC-CS2. See [`AES_CBC_CS2_128`].
#[allow(non_camel_case_types)]
pub type AES_CBC_CS2_256<'k, Dir> = CbcCs<'k, AES256Internal, Dir, CS2>;

/// AES-128 under CBC-CS3 (Addendum to NIST SP 800-38A Sec 4), which always swaps the last two
/// portions; also named [`AES_CTS_128`]. See [`AES_CBC_CS1_128`].
#[allow(non_camel_case_types)]
pub type AES_CBC_CS3_128<'k, Dir> = CbcCs<'k, AES128Internal, Dir, CS3>;

/// AES-192 under CBC-CS3; also named [`AES_CTS_192`]. See [`AES_CBC_CS3_128`].
#[allow(non_camel_case_types)]
pub type AES_CBC_CS3_192<'k, Dir> = CbcCs<'k, AES192Internal, Dir, CS3>;

/// AES-256 under CBC-CS3; also named [`AES_CTS_256`]. See [`AES_CBC_CS3_128`].
#[allow(non_camel_case_types)]
pub type AES_CBC_CS3_256<'k, Dir> = CbcCs<'k, AES256Internal, Dir, CS3>;

/// AES-128 under CTS, ciphertext stealing as RFC 2040 Sec 8 defines it, which is CBC-CS3: the same
/// type as [`AES_CBC_CS3_128`].
#[allow(non_camel_case_types)]
pub type AES_CTS_128<'k, Dir> = AES_CBC_CS3_128<'k, Dir>;

/// AES-192 under CTS: the same type as [`AES_CBC_CS3_192`].
#[allow(non_camel_case_types)]
pub type AES_CTS_192<'k, Dir> = AES_CBC_CS3_192<'k, Dir>;

/// AES-256 under CTS: the same type as [`AES_CBC_CS3_256`].
#[allow(non_camel_case_types)]
pub type AES_CTS_256<'k, Dir> = AES_CBC_CS3_256<'k, Dir>;
