//! Type aliases for ARIA in CMAC (NIST SP 800-38B). The docs are on [`ARIA_CMAC_128`], which the
//! crate root re-exports.

use crate::hazmat::{ARIA128Internal, ARIA192Internal, ARIA256Internal};
use bouncycastle_cipher::modes::Cmac;

/// ARIA-128 in CMAC: the `Cmac` worker of `bouncycastle-cipher` over the ARIA permutation, a
/// `MACGenerator` (`Dir = Encrypting`) or `MACVerifier` (`Dir = Decrypting`) with a 16-byte tag,
/// from an `ARIA128Key<CMAC>` of `KeyType::MACKey` material through `MacGenerationKey` and
/// `MacVerificationKey`. The construction, the key requirements and the security considerations
/// are those of [`bouncycastle_cipher::modes::cmac`] and, alias for alias, of `AES_CMAC_128` in
/// `bouncycastle-aes`; only the permutation differs.
/// RFC 5794 Appendix B names it `id-aria128-cmac`.
///
/// # Usage Examples
///
/// ```
/// use bouncycastle_aria::ARIA256Key;
/// use bouncycastle_cipher::modes::CMAC;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::symmetric_key::{FromKeyMaterial, MacGenerationKey, MacVerificationKey};
/// use bouncycastle_core::traits::MACGenerator;
///
/// let material = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::MACKey).unwrap();
/// let key = ARIA256Key::<CMAC>::from_key_material(&material).expect("a valid ARIA-256 MAC key");
///
/// let mut generator = key.create_generator();
/// generator.do_update(b"a message that arrives ");
/// generator.do_update(b"in pieces");
/// let tag: [u8; 16] = generator.do_final();
/// assert!(key.verify(b"a message that arrives in pieces", &tag).is_ok());
/// assert!(key.verify(b"another message", &tag).is_err());
/// ```
///
/// # Memory Usage
///
/// A key is the expanded schedule plus the two 16-byte subkeys: 240, 272 and 304 bytes for
/// ARIA-128, -192 and -256. A worker borrows that and adds 48 bytes, as under AES.
#[allow(non_camel_case_types)]
pub type ARIA_CMAC_128<'k, Dir> = Cmac<'k, ARIA128Internal, Dir, 16>;

/// ARIA-192 in CMAC. See [`ARIA_CMAC_128`].
#[allow(non_camel_case_types)]
pub type ARIA_CMAC_192<'k, Dir> = Cmac<'k, ARIA192Internal, Dir, 16>;

/// ARIA-256 in CMAC. See [`ARIA_CMAC_128`].
#[allow(non_camel_case_types)]
pub type ARIA_CMAC_256<'k, Dir> = Cmac<'k, ARIA256Internal, Dir, 16>;
