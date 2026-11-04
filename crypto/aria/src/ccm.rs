//! Type aliases for ARIA in CCM mode (NIST SP 800-38C). The docs are on [`ARIA_CCM_128`], which
//! the crate root re-exports.

use crate::BLOCK_LEN;
use crate::hazmat::{ARIA128Internal, ARIA192Internal, ARIA256Internal};
use bouncycastle_cipher::Direction;
use bouncycastle_cipher::modes::{CcmPacketDecryptor, CcmPacketEncryptor};

/// The nonce length to use unless there is a reason not to: 12 bytes, which leaves `q = 3` and
/// so a payload of up to 16 MiB - 1 bytes. The same choice as `bouncycastle-aes`'s.
pub const CCM_NONCE_LEN: usize = 12;

/// The tag length to use unless there is a reason not to: the full 16 bytes, the largest
/// Appendix A.1 permits.
pub const CCM_TAG_LEN: usize = 16;

/// ARIA-128 in CCM mode for frames of exactly `DATA_LEN` payload bytes, as an
/// `AEADCipherEncryptor` or `AEADCipherDecryptor` by `Dir`: the fixed-frame pair of
/// `bouncycastle-cipher`'s CCM over the ARIA permutation, from an
/// `ARIA128Key<CCM_Packet<NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN>>`. A message of any length goes
/// through `ARIA128Key<CCM<NONCE_LEN, TAG_LEN>>` and its declared-length pair instead. The
/// construction, the parameter rules (`NONCE_LEN` in `7..=13`, `TAG_LEN` one of 4, 6, .., 16),
/// the API and its security considerations are those of [`bouncycastle_cipher::modes::ccm`] and,
/// alias for alias, of `AES_CCM_128` in `bouncycastle-aes`; only the permutation differs. RFC 5794
/// Appendix B names it `id-aria128-ccm`.
///
/// # Usage Examples
///
/// ```
/// use bouncycastle_aria::{ARIA128Key, CCM_NONCE_LEN, CCM_TAG_LEN};
/// use bouncycastle_cipher::modes::CCM;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::symmetric_key::{
///     AeadDeclaredDecryptionKey, AeadDeclaredEncryptionKey, FromKeyMaterial,
/// };
/// use bouncycastle_rng::HashDRBG_SHA512;
///
/// let mut rng = HashDRBG_SHA512::new_from_os();
/// let material = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
///     .expect("a 16-byte symmetric cipher key");
/// let key = ARIA128Key::<CCM<CCM_NONCE_LEN, CCM_TAG_LEN>>::from_key_material(&material)
///     .expect("a valid ARIA-128 key");
///
/// let aad = b"header";
/// let mut buf = *b"a message of no particular length";
/// let (nonce, tag) = key.encrypt_detached_in_place(&mut rng, aad, &mut buf).expect("encryption");
/// key.decrypt_detached_in_place(&nonce, aad, &mut buf, &tag).expect("decryption");
/// assert_eq!(&buf, b"a message of no particular length");
/// ```
#[allow(non_camel_case_types)]
pub type ARIA_CCM_128<
    'k,
    Dir,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const AAD_LEN: usize,
    const DATA_LEN: usize,
> = <Dir as Direction>::Select<
    CcmPacketEncryptor<'k, ARIA128Internal, BLOCK_LEN, NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN>,
    CcmPacketDecryptor<'k, ARIA128Internal, BLOCK_LEN, NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN>,
>;

/// ARIA-192 in CCM mode. See [`ARIA_CCM_128`].
#[allow(non_camel_case_types)]
pub type ARIA_CCM_192<
    'k,
    Dir,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const AAD_LEN: usize,
    const DATA_LEN: usize,
> = <Dir as Direction>::Select<
    CcmPacketEncryptor<'k, ARIA192Internal, BLOCK_LEN, NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN>,
    CcmPacketDecryptor<'k, ARIA192Internal, BLOCK_LEN, NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN>,
>;

/// ARIA-256 in CCM mode. See [`ARIA_CCM_128`].
#[allow(non_camel_case_types)]
pub type ARIA_CCM_256<
    'k,
    Dir,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const AAD_LEN: usize,
    const DATA_LEN: usize,
> = <Dir as Direction>::Select<
    CcmPacketEncryptor<'k, ARIA256Internal, BLOCK_LEN, NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN>,
    CcmPacketDecryptor<'k, ARIA256Internal, BLOCK_LEN, NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN>,
>;
