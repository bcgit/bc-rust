//! Type aliases for ARIA Key Wrap, KW, and Key Wrap with Padding, KWP (NIST SP 800-38F Sec 6.2
//! and 6.3 over the ARIA permutation; RFC 5794 Appendix B). The docs are on [`ARIA_KW_128`],
//! which the crate root re-exports.

use crate::hazmat::{ARIA128Internal, ARIA192Internal, ARIA256Internal};
use bouncycastle_cipher::modes::{Kw, Kwp};

/// ARIA-128 Key Wrap: the `Kw` worker of `bouncycastle-cipher` over the ARIA permutation, which
/// implements `KeyWrapper` and `KeyUnwrapper`, from an `ARIA128Key<KW>` of
/// `KeyType::SymmetricCipherKey` material through `KeyWrappingKey` and `KeyUnwrappingKey`. The
/// construction, the length rules, the one-shots and the security considerations are those of
/// [`bouncycastle_cipher::modes::kw`] and, alias for alias, of `AES_KW_128` in `bouncycastle-aes`;
/// only the permutation differs. [`ARIA_KWP_128`] is the padded form, as `AES_KWP_128` is.
///
/// RFC 5794 Appendix B names them: `id-aria128-kw`, `id-aria192-kw` and `id-aria256-kw` are
/// 1.2.410.200046.1.1.40 to .42, and `id-aria128-kwp`, `id-aria192-kwp` and `id-aria256-kwp`
/// are 1.2.410.200046.1.1.43 to .45.
///
/// # Usage Examples
///
/// ```
/// use bouncycastle_aria::{ARIA128Key, ARIA256Key};
/// use bouncycastle_cipher::modes::{KW, KWP};
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::symmetric_key::{FromKeyMaterial, KeyUnwrappingKey, KeyWrappingKey};
///
/// let material = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey)
///     .expect("a 32-byte symmetric cipher key");
/// let kek = ARIA256Key::<KW>::from_key_material(&material).expect("a valid ARIA-256 KEK");
///
/// // A 16-byte key wraps to 24 bytes; any other pair of lengths is a compile error.
/// let key_to_wrap = [0x5Au8; 16];
/// let wrapped: [u8; 24] = kek.wrap_key(&key_to_wrap).expect("wrapping");
/// assert_eq!(*kek.unwrap_key::<16, 24>(&wrapped).expect("unwrapping"), key_to_wrap);
///
/// // KWP takes any length, here through the allocating one-shots.
/// let material = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
///     .expect("a 16-byte symmetric cipher key");
/// let kek = ARIA128Key::<KWP>::from_key_material(&material).expect("a valid ARIA-128 KEK");
/// let payload = b"an encoded private key, of whatever length it happens to be";
/// let wrapped = kek.wrap(payload).expect("wrapping");
/// assert_eq!(kek.unwrap(&wrapped).expect("unwrapping"), payload);
/// ```
///
/// # Memory Usage
///
/// A key is the expanded schedule: 208, 240 and 272 bytes for ARIA-128, -192 and -256. A worker
/// is the borrow of it, one pointer, and the wrapping function's scratch is one block on the
/// stack; the data is wrapped and unwrapped in the caller's buffers.
#[allow(non_camel_case_types)]
pub type ARIA_KW_128<'k> = Kw<'k, ARIA128Internal>;

/// ARIA-192 Key Wrap. See [`ARIA_KW_128`].
#[allow(non_camel_case_types)]
pub type ARIA_KW_192<'k> = Kw<'k, ARIA192Internal>;

/// ARIA-256 Key Wrap. See [`ARIA_KW_128`].
#[allow(non_camel_case_types)]
pub type ARIA_KW_256<'k> = Kw<'k, ARIA256Internal>;

/// ARIA-128 Key Wrap with Padding: the `Kwp` worker over the ARIA permutation, from an
/// `ARIA128Key<KWP>`. See [`ARIA_KW_128`].
#[allow(non_camel_case_types)]
pub type ARIA_KWP_128<'k> = Kwp<'k, ARIA128Internal>;

/// ARIA-192 Key Wrap with Padding. See [`ARIA_KW_128`].
#[allow(non_camel_case_types)]
pub type ARIA_KWP_192<'k> = Kwp<'k, ARIA192Internal>;

/// ARIA-256 Key Wrap with Padding. See [`ARIA_KW_128`].
#[allow(non_camel_case_types)]
pub type ARIA_KWP_256<'k> = Kwp<'k, ARIA256Internal>;
