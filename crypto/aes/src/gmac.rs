//! Type aliases for AES in GMAC (NIST SP 800-38D Sec 5.2), and the nonce-bound MAC roles that
//! make [`AES128Key<GMAC>`] and friends GMAC keys. The docs are on [`AES_GMAC_128`], which the
//! crate root re-exports.

use crate::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle_cipher::modes::Gmac;

// Imports needed for docs
#[allow(unused_imports)]
use crate::AES128Key;
// end of imports needed for docs

/// AES-128 in GMAC with a 128-bit tag. `Dir` is [`Encrypting`](bouncycastle_cipher::Encrypting) to generate a tag or
/// [`Decrypting`](bouncycastle_cipher::Decrypting) to verify one.
///
/// See [`bouncycastle_cipher::modes::gmac`] for the construction, the nonce and the security
/// considerations. [`AES_GMAC_128`] and friends pin the permutation and its key length and fix
/// the tag at 128 bits, as the `AES_GCM_*` aliases do; for a shorter tag name
/// [`Gmac`] directly, or the key's mode as `GMAC<12>`.
///
/// A GMAC tag is bound to a nonce, so the key, [`AES128Key<GMAC>`], carries the nonce-bound role
/// pair [`NonceMacGenerationKey`] / [`NonceMacVerificationKey`]: the MAC roles' shape with the
/// nonce added, which is the AEAD roles' shape with no ciphertext.
///
/// # Usage Examples
///
/// ```
/// use bouncycastle_aes::AES256Key;
/// use bouncycastle_cipher::modes::GMAC;
/// use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
/// use bouncycastle_core::symmetric_key::{FromKeyMaterial, NonceMacGenerationKey, NonceMacVerificationKey};
/// use bouncycastle_core::traits::MACGenerator;
/// use bouncycastle_rng::HashDRBG_SHA512;
///
/// let mut rng = HashDRBG_SHA512::new_from_os();   // one RNG, held across messages
/// let material = KeyMaterial256::from_bytes_as_type(&[0x42; 32], KeyType::MACKey).unwrap();
/// let key = AES256Key::<GMAC>::from_key_material(&material).expect("a valid AES-256 MAC key");
///
/// // The nonce is drawn from `rng` and returned; the Result is for that draw only.
/// let (mut generator, nonce) = key.create_generator(&mut rng).expect("nonce draw");
/// generator.do_update(b"a message that arrives ");
/// generator.do_update(b"in pieces");
/// let tag = generator.do_final();
///
/// // Verification needs the nonce the tag was made under.
/// assert!(key.verify(&nonce, b"a message that arrives in pieces", &tag).is_ok());
/// assert!(key.verify(&nonce, b"another message", &tag).is_err());
/// ```
///
/// # Memory Usage
///
/// A key is the expanded schedule plus the 16-byte hash subkey, the same as a GCM key: 192, 224
/// and 256 bytes for AES-128, -192 and -256. A worker is a `Gcm` of the same shape.
///
/// [`AES128Key<GMAC>`]: crate::AES128Key
/// [`NonceMacGenerationKey`]: bouncycastle_core::symmetric_key::NonceMacGenerationKey
/// [`NonceMacVerificationKey`]: bouncycastle_core::symmetric_key::NonceMacVerificationKey
#[allow(non_camel_case_types)]
pub type AES_GMAC_128<'k, Dir> = Gmac<'k, AES128Internal, Dir, 16>;

/// AES-192 in GMAC with a 128-bit tag. See [`AES_GMAC_128`].
#[allow(non_camel_case_types)]
pub type AES_GMAC_192<'k, Dir> = Gmac<'k, AES192Internal, Dir, 16>;

/// AES-256 in GMAC with a 128-bit tag. See [`AES_GMAC_128`].
#[allow(non_camel_case_types)]
pub type AES_GMAC_256<'k, Dir> = Gmac<'k, AES256Internal, Dir, 16>;
