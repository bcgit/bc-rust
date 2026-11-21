//! Type aliases for XTS-AES (NIST SP 800-38E; IEEE Std 1619-2007). The docs are on
//! [`XTS_AES_128`], which the crate root re-exports.

use crate::hazmat::{AES128Internal, AES256Internal};
use bouncycastle_cipher::modes::XTSKey;

/// XTS-AES-128 (NIST SP 800-38E; IEEE Std 1619-2007) for data units of exactly `DATA_UNIT_LEN`
/// bytes: a 256-bit key `Key_1 | Key_2`, each half an AES-128 key, `Key_1` for the data and
/// `Key_2` for the tweak.
///
/// It is the key object of [`bouncycastle_cipher::modes::xts`], which describes the tweak and the
/// security considerations; read those before using XTS, which is unauthenticated and meant for
/// storage. The key is built once with [`FromKeyMaterial`] and encrypts and decrypts one data
/// unit at a time, in place: [`encrypt_inplace`](XTSKey::encrypt_inplace) and
/// [`decrypt_inplace`](XTSKey::decrypt_inplace). A data unit is from 16 bytes to 2^20 blocks,
/// and a length outside that range does not compile. IEEE 1619-2007 Sec 6 defines XTS-AES-128
/// and XTS-AES-256 only, so there is no XTS-AES-192.
///
/// # Usage Examples
///
/// NIST's ACVP sample vector ACVP-AES-XTS-2.0 tcId 125, a 23-byte data unit -- one block and
/// seven bytes, so the last two blocks are ciphertext-stolen -- under sequence number 202:
///
/// ```
/// use bouncycastle_aes::XTS_AES_128;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::symmetric_key::FromKeyMaterial;
///
/// let key_bytes = [
///     0xc3, 0xd3, 0xdc, 0x0b, 0x7a, 0x34, 0x5c, 0xcf, 0xe4, 0x8b, 0x23, 0x20, 0x75, 0xe4,
///     0x72, 0x99, 0xeb, 0xf1, 0x1e, 0x5c, 0x40, 0xe1, 0xbf, 0xe4, 0x2a, 0xcf, 0x96, 0xe1,
///     0x84, 0x0b, 0x73, 0x53,
/// ];
/// let material = KeyMaterial::<32>::from_bytes_as_type(&key_bytes, KeyType::SymmetricCipherKey)
///     .expect("a 32-byte symmetric cipher key");
/// let key = XTS_AES_128::<23>::from_key_material(&material).expect("a valid XTS-AES-128 key");
///
/// let plaintext = [
///     0xea, 0xfd, 0xbd, 0x33, 0x05, 0x11, 0xba, 0xa1, 0xc9, 0x12, 0xea, 0x24, 0xb7, 0xb1,
///     0x30, 0x35, 0x07, 0xab, 0x3a, 0xab, 0xe6, 0x62, 0x1c,
/// ];
/// // The tweak value, here the sequence number, in little-endian bytes (IEEE 1619-2007 Sec 5.1).
/// let tweak = 202u128.to_le_bytes();
///
/// let mut data_unit = plaintext;
/// assert_eq!(key.encrypt_inplace(&tweak, &mut data_unit), 23);
/// assert_eq!(
///     data_unit,
///     [
///         0xb0, 0xc6, 0x8b, 0x8a, 0x8c, 0x23, 0x0a, 0x35, 0x67, 0x63, 0x38, 0x54, 0x6d, 0x36,
///         0x1e, 0x15, 0x17, 0x8b, 0x8c, 0xc3, 0x42, 0x6e, 0x31,
///     ]
/// );
/// key.decrypt_inplace(&tweak, &mut data_unit);
/// assert_eq!(data_unit, plaintext);
/// ```
///
/// A run of 4096-byte sectors under a fresh XTS-AES-256 key, each under its own sequence number:
///
/// ```
/// use bouncycastle_aes::XTS_AES_256;
/// use bouncycastle_core::symmetric_key::FromKeyMaterial;
/// use bouncycastle_rng::HashDRBG_SHA512;
///
/// let mut rng = HashDRBG_SHA512::new_from_os();
/// let key = XTS_AES_256::<4096>::generate(&mut rng).expect("a 256-bit RNG");
///
/// let mut disk = vec![0u8; 8 * 4096];
/// let (sectors, rest) = disk.as_chunks_mut::<4096>();
/// assert!(rest.is_empty());
/// for (n, sector) in (100u128..).zip(sectors.iter_mut()) {
///     key.encrypt_inplace(&n.to_le_bytes(), sector);
/// }
/// // Equal plaintext sectors, under different sequence numbers, encrypt differently.
/// assert_ne!(sectors[0], sectors[1]);
/// ```
///
/// # Memory Usage
///
/// A key is two AES schedules: 352 bytes for XTS-AES-128 and 480 for XTS-AES-256. A call works in
/// the caller's buffer; beside the permutation's own frame it keeps the tweak's mask and the
/// masks of the four blocks in flight on the stack.
///
/// [`FromKeyMaterial`]: bouncycastle_core::symmetric_key::FromKeyMaterial
#[allow(non_camel_case_types)]
pub type XTS_AES_128<const DATA_UNIT_LEN: usize> = XTSKey<AES128Internal, DATA_UNIT_LEN>;

/// XTS-AES-256 (NIST SP 800-38E; IEEE Std 1619-2007) for data units of exactly `DATA_UNIT_LEN`
/// bytes: a 512-bit key `Key_1 | Key_2`, each half an AES-256 key. See [`XTS_AES_128`].
#[allow(non_camel_case_types)]
pub type XTS_AES_256<const DATA_UNIT_LEN: usize> = XTSKey<AES256Internal, DATA_UNIT_LEN>;
