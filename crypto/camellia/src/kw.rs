//! Type aliases for Camellia Key Wrap, KW (NIST SP 800-38F Sec 6.2 over the Camellia
//! permutation; RFC 3657 Sec 3). The docs are on [`Camellia_KW_128`], which the crate root
//! re-exports.

use crate::hazmat::{Camellia128Internal, Camellia192Internal, Camellia256Internal};
use bouncycastle_cipher::modes::Kw;

/// Camellia-128 Key Wrap: the `Kw` worker of `bouncycastle-cipher` over the Camellia
/// permutation, which implements `KeyWrapper` and `KeyUnwrapper`, from a `Camellia128Key<KW>`
/// of `KeyType::SymmetricCipherKey` material through `KeyWrappingKey` and `KeyUnwrappingKey`.
/// The construction, the length rules, the one-shots and the security considerations are those
/// of [`bouncycastle_cipher::modes::kw`] and, alias for alias, of `AES_KW_128` in
/// `bouncycastle-aes`; only the permutation differs.
///
/// RFC 3657 Sec 3 defines Camellia key wrapping as the RFC 3394 algorithm over Camellia, and
/// Sec 2 names it: `id-camellia128-wrap`, `id-camellia192-wrap` and `id-camellia256-wrap` are
/// 1.2.392.200011.61.1.1.3.2 to .4. No padded form is specified for Camellia; a
/// `Camellia128Key<KWP>` works all the same, but carries no identifier.
///
/// # Usage Examples
///
/// ```
/// use bouncycastle_camellia::Camellia256Key;
/// use bouncycastle_cipher::modes::KW;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::symmetric_key::{FromKeyMaterial, KeyUnwrappingKey, KeyWrappingKey};
///
/// let material = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey)
///     .expect("a 32-byte symmetric cipher key");
/// let kek = Camellia256Key::<KW>::from_key_material(&material).expect("a valid Camellia-256 KEK");
///
/// // A 16-byte key wraps to 24 bytes; any other pair of lengths is a compile error.
/// let key_to_wrap = [0x5Au8; 16];
/// let wrapped: [u8; 24] = kek.wrap_key(&key_to_wrap).expect("wrapping");
/// assert_eq!(*kek.unwrap_key::<16, 24>(&wrapped).expect("unwrapping"), key_to_wrap);
///
/// // Lengths known only at run time, through the allocating one-shots.
/// let wrapped = kek.wrap(&[0x5Au8; 40]).expect("wrapping");
/// assert_eq!(kek.unwrap(&wrapped).expect("unwrapping"), [0x5Au8; 40]);
/// ```
///
/// # Memory Usage
///
/// A key is the expanded schedule: 208, 272 and 272 bytes for Camellia-128, -192 and -256. A
/// worker is the borrow of it, one pointer, and the wrapping function's scratch is one block on
/// the stack; the data is wrapped and unwrapped in the caller's buffers.
#[allow(non_camel_case_types)]
pub type Camellia_KW_128<'k, Dir> = Kw<'k, Camellia128Internal, Dir>;

/// Camellia-192 Key Wrap. See [`Camellia_KW_128`].
#[allow(non_camel_case_types)]
pub type Camellia_KW_192<'k, Dir> = Kw<'k, Camellia192Internal, Dir>;

/// Camellia-256 Key Wrap. See [`Camellia_KW_128`].
#[allow(non_camel_case_types)]
pub type Camellia_KW_256<'k, Dir> = Kw<'k, Camellia256Internal, Dir>;
