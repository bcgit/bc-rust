//! Type aliases for SM4 Key Wrap, KW, and Key Wrap with Padding, KWP (NIST SP 800-38F Sec 6.2 and
//! 6.3 over the SM4 permutation). The docs are on [`SM4_KW`], which the crate root re-exports.

use crate::hazmat::SM4Internal;
use bouncycastle_cipher::modes::{Kw, Kwp};

/// SM4 Key Wrap: the `Kw` worker of `bouncycastle-cipher` over the SM4 permutation, which
/// implements `KeyWrapper` and `KeyUnwrapper`, from an `SM4Key<KW>` of
/// `KeyType::SymmetricCipherKey` material through `KeyWrappingKey` and `KeyUnwrappingKey`. The
/// construction, the length rules, the one-shots and the security considerations are those of
/// [`bouncycastle_cipher::modes::kw`] and, alias for alias, of `AES_KW_128` in `bouncycastle-aes`;
/// only the permutation differs. [`SM4_KWP`] is the padded form, as `AES_KWP_128` is.
///
/// GM/T 0006 identifies the two as `sms4_wrap`, 1.2.156.10197.1.104.11, and `sms4_wrap_pad`,
/// 1.2.156.10197.1.104.12, as BC Java's `GMObjectIdentifiers` records them. No test vectors are
/// published for either; `tests/kw_reference_tests.rs` pins the composition against RFC 3394 and
/// RFC 5649 written out over the raw permutation.
///
/// # Usage Examples
///
/// ```
/// use bouncycastle_cipher::modes::{KW, KWP};
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::symmetric_key::{FromKeyMaterial, KeyUnwrappingKey, KeyWrappingKey};
/// use bouncycastle_sm4::SM4Key;
///
/// let material = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
///     .expect("a 16-byte symmetric cipher key");
/// let kek = SM4Key::<KW>::from_key_material(&material).expect("a valid SM4 KEK");
///
/// // A 16-byte key wraps to 24 bytes; any other pair of lengths is a compile error.
/// let key_to_wrap = [0x5Au8; 16];
/// let wrapped: [u8; 24] = kek.wrap_key(&key_to_wrap).expect("wrapping");
/// assert_eq!(*kek.unwrap_key::<16, 24>(&wrapped).expect("unwrapping"), key_to_wrap);
///
/// // KWP takes any length, here through the allocating one-shots.
/// let kek = SM4Key::<KWP>::from_key_material(&material).expect("a valid SM4 KEK");
/// let payload = b"an encoded private key, of whatever length it happens to be";
/// let wrapped = kek.wrap(payload).expect("wrapping");
/// assert_eq!(kek.unwrap(&wrapped).expect("unwrapping"), payload);
/// ```
///
/// # Memory Usage
///
/// A key is the 32 round keys, 128 bytes. A worker is the borrow of it, one pointer, and the
/// wrapping function's scratch is one block on the stack; the data is wrapped and unwrapped in
/// the caller's buffers.
#[allow(non_camel_case_types)]
pub type SM4_KW<'k> = Kw<'k, SM4Internal>;

/// SM4 Key Wrap with Padding: the `Kwp` worker over the SM4 permutation, from an `SM4Key<KWP>`.
/// See [`SM4_KW`].
#[allow(non_camel_case_types)]
pub type SM4_KWP<'k> = Kwp<'k, SM4Internal>;
