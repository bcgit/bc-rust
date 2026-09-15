//! Type aliases for AES in CCM mode (NIST SP 800-38C).
//!
//! `bouncycastle-modes` is deliberately cipher-agnostic, so `Ccm` takes the permutation and the
//! `KEY_LEN` / `BLOCK_LEN` / `NONCE_LEN` / `TAG_LEN` const parameters. These aliases pin the AES
//! values so callers never spell them out. They add nothing to the engine: the permutation still
//! implements none of the data-encryption traits itself (see the crate docs), the mode does.
//!
//! AES is the *only* cipher CCM can use. SP 800-38C Sec 3: "CCM is based on an approved symmetric
//! key block cipher algorithm whose block size is 128 bits ... thus, CCM cannot be used with the
//! Triple Data Encryption Algorithm, whose block size is 64 bits", and Sec 5.1 adds that
//! "currently, the AES algorithm is the only approved block cipher algorithm with this block size".
//!
//! # The nonce length and the tag length stay parameters
//!
//! `Dir` is [`Encrypting`](bouncycastle_modes::Encrypting) or
//! [`Decrypting`](bouncycastle_modes::Decrypting), as for the other modes. Beyond that, and unlike
//! the other aliases in this crate, these do not pin everything: `NONCE_LEN` and `TAG_LEN`
//! are real cryptographic choices, and CCM ties them to the payload limit and to the strength of
//! the authentication respectively, so hiding them behind a default would hide the decision:
//!
//! * **`NONCE_LEN` (the spec's `n`) fixes the maximum payload.** A.1 requires `n + q = 15`, and
//!   `q` bounds the payload at `2^8q - 1` bytes. So a 13-byte nonce caps a message at 64 KiB - 1,
//!   and a 7-byte nonce lifts the cap entirely at the cost of nonce space. See
//!   [`Ccm`](bouncycastle_modes::Ccm) for the table.
//! * **`TAG_LEN` (the spec's `t`) is the forgery bound.** Sec B.2: "a value of Tlen that is less
//!   than 64 shall not be used without a careful analysis of the risks of accepting inauthentic
//!   data as authentic".
//!
//! Both are still checked at compile time against A.1's permitted sets, so a wrong value is a
//! compile error rather than a runtime `Err`.
//!
//! [`CCM_NONCE_LEN`] and [`CCM_TAG_LEN`] name the sensible default pair -- a 12-byte nonce and a
//! 16-byte tag, which is what the NIST ACVP vectors and most protocols use -- for callers who have
//! no reason to choose otherwise:
//!
//! ```text
//! AES_CCM_128<Encrypting, CCM_NONCE_LEN, CCM_TAG_LEN>  // 12-byte nonce, 16-byte tag, < 16 MiB
//! AES_CCM_128<Decrypting, 13, 8>                       // IEEE 802.11 CCMP's pair
//! ```
//!
//! # Streaming needs the buffering pair
//!
//! These aliases are for [`Ccm`](bouncycastle_modes::Ccm) itself: its one-shots and its
//! length-declared streaming API, neither of which buffers. Code written against
//! [`AEADCipherEncryptor`] / [`AEADCipherDecryptor`] wants
//! [`AES_CCM_128_Encryptor`] / [`AES_CCM_128_Decryptor`] instead, which carry the extra
//! `BUFFER_LEN` those traits force; see [`CcmEncryptor`](bouncycastle_modes::CcmEncryptor) for why.

use crate::{AES_128, AES_192, AES_256, BLOCK_LEN};
use bouncycastle_modes::{Ccm, CcmDecryptor, CcmEncryptor};

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_core::traits::{AEADCipherDecryptor, AEADCipherEncryptor};
// end of imports needed for docs

/// The nonce length to use unless there is a reason not to: 12 bytes, which is what the NIST ACVP
/// `ACVP-AES-CCM` vectors use in every group. It leaves `q = 3`, so a payload of up to
/// 16 MiB - 1 bytes.
pub const CCM_NONCE_LEN: usize = 12;

/// The tag length to use unless there is a reason not to: the full 16 bytes, the largest A.1
/// permits. See the module docs on Sec B.2.
pub const CCM_TAG_LEN: usize = 16;

/// AES-128 in CCM mode (SP 800-38C).
///
/// `NONCE_LEN` must be 7..=13 and `TAG_LEN` one of 4, 6, 8, 10, 12, 14, 16 (A.1); anything else is
/// a compile error. Use [`CCM_NONCE_LEN`] and [`CCM_TAG_LEN`] if you have no reason to choose.
///
/// The nonce is **supplied**, not generated, because CCM requires it to be unique but not random
/// (Sec 5.3), so a caller with a counter can do better than a draw from a DRBG. It must never
/// repeat under one key; see [`Ccm`]'s security considerations.
///
/// ```
/// use bouncycastle_aes::{AES_CCM_128, CCM_NONCE_LEN, CCM_TAG_LEN};
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_modes::{Decrypting, Encrypting};
///
/// type Ccm128<Dir> = AES_CCM_128<Dir, CCM_NONCE_LEN, CCM_TAG_LEN>;
///
/// let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
///     .expect("a 16-byte symmetric cipher key");
/// let nonce = [0x01u8; CCM_NONCE_LEN];
/// let header = b"authenticated but not encrypted";
/// let message = b"authenticated and encrypted";
///
/// // The spec's own layout: ciphertext with the tag appended (Sec 6.1 step 8).
/// let mut sealed = vec![0u8; message.len() + CCM_TAG_LEN];
/// let n = Ccm128::<Encrypting>::encrypt(&key, &nonce, header, message, &mut sealed).expect("encryption");
/// assert_eq!(n, sealed.len());
///
/// let mut opened = vec![0u8; message.len()];
/// let n = Ccm128::<Decrypting>::decrypt(&key, &nonce, header, &sealed, &mut opened).expect("decryption");
/// assert_eq!(&opened[..n], message);
///
/// // Tampering with either the ciphertext or the header is caught.
/// let mut tampered = sealed.clone();
/// tampered[0] ^= 1;
/// assert!(Ccm128::<Decrypting>::decrypt(&key, &nonce, header, &tampered, &mut opened).is_err());
/// assert!(Ccm128::<Decrypting>::decrypt(&key, &nonce, b"other header", &sealed, &mut opened).is_err());
/// ```
///
/// A detached tag, for a wire format that carries it separately:
///
/// ```
/// use bouncycastle_aes::{AES_CCM_128, CCM_NONCE_LEN, CCM_TAG_LEN};
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_modes::{Decrypting, Encrypting};
///
/// type Ccm128<Dir> = AES_CCM_128<Dir, CCM_NONCE_LEN, CCM_TAG_LEN>;
/// let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
///     .unwrap();
/// let nonce = [0x02u8; CCM_NONCE_LEN];
/// let message = b"a short packet";
///
/// let mut ct = vec![0u8; message.len()];
/// let (n, tag) = Ccm128::<Encrypting>::encrypt_detached(&key, &nonce, &[], message, &mut ct).unwrap();
/// assert_eq!(n, message.len(), "CCM never expands the payload");
///
/// let mut pt = vec![0u8; message.len()];
/// Ccm128::<Decrypting>::decrypt_detached(&key, &nonce, &[], &ct, &tag, &mut pt).unwrap();
/// assert_eq!(&pt[..], message);
/// ```
#[allow(non_camel_case_types)]
pub type AES_CCM_128<Dir, const NONCE_LEN: usize, const TAG_LEN: usize> =
    Ccm<AES_128, Dir, 16, BLOCK_LEN, NONCE_LEN, TAG_LEN>;

/// AES-192 in CCM mode. See [`AES_CCM_128`].
///
/// ```
/// use bouncycastle_aes::{AES_CCM_192, CCM_NONCE_LEN, CCM_TAG_LEN};
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_modes::{Decrypting, Encrypting};
///
/// type Ccm192<Dir> = AES_CCM_192<Dir, CCM_NONCE_LEN, CCM_TAG_LEN>;
/// let key = KeyMaterial::<24>::from_bytes_as_type(&[0x42; 24], KeyType::SymmetricCipherKey)
///     .unwrap();
/// let nonce = [0x03u8; CCM_NONCE_LEN];
/// let message = [0u8; 30];
///
/// let mut sealed = vec![0u8; message.len() + CCM_TAG_LEN];
/// Ccm192::<Encrypting>::encrypt(&key, &nonce, &[], &message, &mut sealed).unwrap();
/// let mut opened = vec![0u8; message.len()];
/// Ccm192::<Decrypting>::decrypt(&key, &nonce, &[], &sealed, &mut opened).unwrap();
/// assert_eq!(opened, message);
/// ```
#[allow(non_camel_case_types)]
pub type AES_CCM_192<Dir, const NONCE_LEN: usize, const TAG_LEN: usize> =
    Ccm<AES_192, Dir, 24, BLOCK_LEN, NONCE_LEN, TAG_LEN>;

/// AES-256 in CCM mode. See [`AES_CCM_128`].
///
/// ```
/// use bouncycastle_aes::{AES_CCM_256, CCM_NONCE_LEN, CCM_TAG_LEN};
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_modes::{Decrypting, Encrypting};
///
/// type Ccm256<Dir> = AES_CCM_256<Dir, CCM_NONCE_LEN, CCM_TAG_LEN>;
/// let key = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey)
///     .unwrap();
/// let nonce = [0x04u8; CCM_NONCE_LEN];
/// let message = [0u8; 30];
///
/// let mut sealed = vec![0u8; message.len() + CCM_TAG_LEN];
/// Ccm256::<Encrypting>::encrypt(&key, &nonce, &[], &message, &mut sealed).unwrap();
/// let mut opened = vec![0u8; message.len()];
/// Ccm256::<Decrypting>::decrypt(&key, &nonce, &[], &sealed, &mut opened).unwrap();
/// assert_eq!(opened, message);
/// ```
#[allow(non_camel_case_types)]
pub type AES_CCM_256<Dir, const NONCE_LEN: usize, const TAG_LEN: usize> =
    Ccm<AES_256, Dir, 32, BLOCK_LEN, NONCE_LEN, TAG_LEN>;

/// AES-128 CCM as an [`AEADCipherEncryptor`], for code written against the generic AEAD trait.
///
/// `BUFFER_LEN` is the largest message and the largest AAD this will accept, and is also the
/// trait's `FINAL_LEN`. It exists because the trait's `do_encrypt_init` is handed no length and CCM
/// needs one; see [`CcmEncryptor`]. The nonce is generated here, unlike [`AES_CCM_128`]'s, because
/// the trait generates it.
///
/// ```
/// use bouncycastle_aes::{AES_CCM_128_Decryptor, AES_CCM_128_Encryptor};
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::traits::{AEADCipherDecryptor, AEADCipherEncryptor};
///
/// // 2 KiB is comfortably above an 802.11 frame, the packet size CCM was designed for.
/// type Enc = AES_CCM_128_Encryptor<12, 16, 2048>;
/// type Dec = AES_CCM_128_Decryptor<12, 16, 2048>;
///
/// let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
///     .unwrap();
/// let (nonce, ciphertext, tag) = Enc::encrypt(&key, b"header", b"message").unwrap();
/// let plaintext = Dec::decrypt(&key, &nonce, b"header", &ciphertext, &tag).unwrap();
/// assert_eq!(plaintext, b"message");
/// ```
#[allow(non_camel_case_types)]
pub type AES_CCM_128_Encryptor<
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const BUFFER_LEN: usize,
> = CcmEncryptor<AES_128, 16, BLOCK_LEN, NONCE_LEN, TAG_LEN, BUFFER_LEN>;

/// AES-128 CCM as an [`AEADCipherDecryptor`]. See [`AES_CCM_128_Encryptor`].
#[allow(non_camel_case_types)]
pub type AES_CCM_128_Decryptor<
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const BUFFER_LEN: usize,
> = CcmDecryptor<AES_128, 16, BLOCK_LEN, NONCE_LEN, TAG_LEN, BUFFER_LEN>;

/// AES-192 CCM as an [`AEADCipherEncryptor`]. See [`AES_CCM_128_Encryptor`].
#[allow(non_camel_case_types)]
pub type AES_CCM_192_Encryptor<
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const BUFFER_LEN: usize,
> = CcmEncryptor<AES_192, 24, BLOCK_LEN, NONCE_LEN, TAG_LEN, BUFFER_LEN>;

/// AES-192 CCM as an [`AEADCipherDecryptor`]. See [`AES_CCM_128_Encryptor`].
#[allow(non_camel_case_types)]
pub type AES_CCM_192_Decryptor<
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const BUFFER_LEN: usize,
> = CcmDecryptor<AES_192, 24, BLOCK_LEN, NONCE_LEN, TAG_LEN, BUFFER_LEN>;

/// AES-256 CCM as an [`AEADCipherEncryptor`]. See [`AES_CCM_128_Encryptor`].
#[allow(non_camel_case_types)]
pub type AES_CCM_256_Encryptor<
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const BUFFER_LEN: usize,
> = CcmEncryptor<AES_256, 32, BLOCK_LEN, NONCE_LEN, TAG_LEN, BUFFER_LEN>;

/// AES-256 CCM as an [`AEADCipherDecryptor`]. See [`AES_CCM_128_Encryptor`].
#[allow(non_camel_case_types)]
pub type AES_CCM_256_Decryptor<
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const BUFFER_LEN: usize,
> = CcmDecryptor<AES_256, 32, BLOCK_LEN, NONCE_LEN, TAG_LEN, BUFFER_LEN>;
