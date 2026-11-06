//! Type aliases for TDEA Key Wrap, TKW (NIST SP 800-38F Sec 7). The docs are on [`TDES_TKW`],
//! which the crate root re-exports.

use crate::hazmat::{TDES2Internal, TDESInternal};
use bouncycastle_cipher::Decrypting;
use bouncycastle_cipher::modes::Tkw;

/// TDEA Key Wrap: the `Tkw` worker of `bouncycastle-cipher` over the three-key TDEA
/// permutation, which implements `KeyWrapper` and `KeyUnwrapper`, from a `TDES3Key<TKW>` of
/// `KeyType::SymmetricCipherKey` material through `KeyWrappingKey` and `KeyUnwrappingKey`. It
/// wraps data that is a whole number of 4-byte semiblocks, at least 8 bytes, to one semiblock
/// more; the construction, the one-shots and the security notes are those of
/// [`bouncycastle_cipher::modes::tkw`], and the API is that of `AES_KW_128` in `bouncycastle-aes`
/// at half the width.
///
/// SP 800-38F Sec 8: TKW is "approved to support legacy systems but should not be used for new
/// applications". A forgery passes its check with probability 2^-32 per attempt (Appendix A.3),
/// against 2^-64 for KW, and TDEA is itself a legacy algorithm; see the crate's security
/// considerations. SP 800-38F publishes no vectors for it; the NIST CAVP `TKW_AE` and `TKW_AD`
/// sample files are run from `bc-test-data`.
///
/// # Usage Examples
///
/// ```
/// use bouncycastle_tdes::TDES3Key;
/// use bouncycastle_cipher::modes::TKW;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::symmetric_key::{FromKeyMaterial, KeyUnwrappingKey, KeyWrappingKey};
///
/// // Three distinct component keys; see `TDESInternal` for what a key bundle must satisfy.
/// let bytes: [u8; 24] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
/// let material = KeyMaterial::<24>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey)
///     .expect("a 24-byte symmetric cipher key");
/// let kek = TDES3Key::<TKW>::from_key_material(&material).expect("a valid key bundle");
///
/// // A 16-byte key wraps to 20 bytes; any other pair of lengths is a compile error.
/// let key_to_wrap = [0x5Au8; 16];
/// let wrapped: [u8; 20] = kek.wrap_key(&key_to_wrap).expect("wrapping");
/// assert_eq!(*kek.unwrap_key::<16, 20>(&wrapped).expect("unwrapping"), key_to_wrap);
///
/// // Lengths known only at run time, through the allocating one-shots.
/// let wrapped = kek.wrap(&[0x5Au8; 24]).expect("wrapping");
/// assert_eq!(kek.unwrap(&wrapped).expect("unwrapping"), [0x5Au8; 24]);
/// ```
///
/// `Dir` is [`Encrypting`](bouncycastle_cipher::Encrypting) for the wrapper and [`Decrypting`]
/// for the unwrapper, as for the cipher modes.
///
/// # Memory Usage
///
/// A key is the engine's expanded schedule, as for the other modes (see the crate's table). A
/// worker is the borrow of it, one pointer, and the wrapping function's scratch is one 8-byte
/// block on the stack; the data is wrapped and unwrapped in the caller's buffers.
#[allow(non_camel_case_types)]
pub type TDES_TKW<'k, Dir> = Tkw<'k, TDESInternal, Dir>;

/// Two-key TDEA Key Wrap, unwrapping only: what a [`TDES2Key<TKW>`](crate::TDES2Key) hands out
/// through `KeyUnwrappingKey`. Two-key TDEA may not apply protection (SP 800-131A Rev 2 Table 1),
/// and its engine decrypts only, so the key's `create_wrapper` and every wrapping one-shot refuse
/// to compile, exactly as its `create_encryptor` does under the cipher modes:
///
/// ```compile_fail
/// use bouncycastle_tdes::TDES2Key;
/// use bouncycastle_cipher::modes::TKW;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::symmetric_key::{FromKeyMaterial, KeyWrappingKey};
///
/// let bytes: [u8; 16] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
/// let material = KeyMaterial::<16>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey)
///     .unwrap();
/// let kek = TDES2Key::<TKW>::from_key_material(&material).unwrap();
///
/// // Two-key TDEA may not wrap: this does not compile.
/// let _ = kek.wrap(&[0u8; 16]);
/// ```
///
/// The unwrapper the key hands out is `Tkw<'k, TDES2Internal, Decrypting>`, a type with no
/// wrapping method, so neither of these compiles either:
///
/// ```compile_fail
/// use bouncycastle_tdes::TDES2Key;
/// use bouncycastle_cipher::modes::TKW;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::symmetric_key::{FromKeyMaterial, KeyUnwrappingKey};
/// use bouncycastle_core::traits::KeyWrapper;
///
/// let bytes: [u8; 16] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
/// let material = KeyMaterial::<16>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey)
///     .unwrap();
/// let kek = TDES2Key::<TKW>::from_key_material(&material).unwrap();
///
/// // error[E0599]: no method named `wrap_out` found for the unwrapper
/// let mut out = [0u8; 20];
/// let _ = kek.create_unwrapper().wrap_out(&[0u8; 16], &mut out);
/// ```
///
/// ```compile_fail
/// use bouncycastle_tdes::TDES2Key;
/// use bouncycastle_cipher::modes::TKW;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::symmetric_key::{FromKeyMaterial, KeyUnwrappingKey};
/// use bouncycastle_core::traits::KeyWrapper;
///
/// let bytes: [u8; 16] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
/// let material = KeyMaterial::<16>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey)
///     .unwrap();
/// let kek = TDES2Key::<TKW>::from_key_material(&material).unwrap();
///
/// // error[E0277]: `KeyWrapper` is not implemented for the unwrapper
/// let unwrapper = kek.create_unwrapper();
/// let _: &dyn KeyWrapper = &unwrapper;
/// ```
///
/// Unwrapping works, with the ciphertext as it was received:
///
/// ```
/// use bouncycastle_tdes::TDES2Key;
/// use bouncycastle_cipher::modes::TKW;
/// use bouncycastle_core::errors::SymmetricCipherError;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::symmetric_key::{FromKeyMaterial, KeyUnwrappingKey};
///
/// let bytes: [u8; 16] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
/// let material = KeyMaterial::<16>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey)
///     .unwrap();
/// let kek = TDES2Key::<TKW>::from_key_material(&material).unwrap();
///
/// // Not a ciphertext this key made, so it is rejected rather than unwrapped to garbage.
/// assert!(matches!(kek.unwrap(&[0u8; 20]), Err(SymmetricCipherError::DecryptionFailed)));
/// ```
#[allow(non_camel_case_types)]
pub type TDES2_TKW<'k> = Tkw<'k, TDES2Internal, Decrypting>;
