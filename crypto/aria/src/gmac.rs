//! Type aliases for ARIA in GMAC (NIST SP 800-38D Sec 5.2), and the generator/verifier pair that
//! makes `ARIA128Key<GMAC>` and friends GMAC keys. The docs are on [`ARIA_GMAC_128`], which the
//! crate root re-exports.

use crate::hazmat::{ARIA128Internal, ARIA192Internal, ARIA256Internal};
use bouncycastle_cipher::modes::Gmac;

/// ARIA-128 in GMAC with a 128-bit tag: the `Gmac` worker of `bouncycastle-cipher` over the ARIA
/// permutation, `Dir` [`Encrypting`](bouncycastle_cipher::Encrypting) to generate a tag or [`Decrypting`](bouncycastle_cipher::Decrypting) to verify one. A GMAC
/// tag is bound to a nonce, so the pair is inherent on the key, `ARIA128Key<GMAC>` of
/// `KeyType::MACKey` material: [`create_generator`](bouncycastle_cipher::BlockCipherKey::create_generator) draws the nonce,
/// [`create_generator_nonce`](bouncycastle_cipher::BlockCipherKey::create_generator_nonce) takes the caller's, and
/// [`create_verifier`](bouncycastle_cipher::BlockCipherKey::create_verifier) checks under it. The construction, the nonce
/// rule and the security considerations are those of [`bouncycastle_cipher::modes::gmac`] and,
/// alias for alias, of `AES_GMAC_128` in `bouncycastle-aes`; only the permutation differs. RFC
/// 5794 Appendix B assigns GMAC no identifier.
///
/// # Usage Examples
///
/// ```
/// use bouncycastle_aria::ARIA256Key;
/// use bouncycastle_cipher::modes::GMAC;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::symmetric_key::FromKeyMaterial;
/// use bouncycastle_rng::HashDRBG_SHA512;
///
/// let mut rng = HashDRBG_SHA512::new_from_os();
/// let material = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::MACKey).unwrap();
/// let key = ARIA256Key::<GMAC>::from_key_material(&material).expect("a valid ARIA-256 MAC key");
///
/// let (mut generator, nonce) = key.create_generator(&mut rng).expect("nonce draw");
/// generator.do_update(b"a message that arrives ");
/// generator.do_update(b"in pieces");
/// let tag = generator.do_final();
///
/// assert!(key.create_verifier(&nonce).verify(b"a message that arrives in pieces", &tag));
/// assert!(!key.create_verifier(&nonce).verify(b"another message", &tag));
/// ```
#[allow(non_camel_case_types)]
pub type ARIA_GMAC_128<'k, Dir> = Gmac<'k, ARIA128Internal, Dir, 16>;

/// ARIA-192 in GMAC with a 128-bit tag. See [`ARIA_GMAC_128`].
#[allow(non_camel_case_types)]
pub type ARIA_GMAC_192<'k, Dir> = Gmac<'k, ARIA192Internal, Dir, 16>;

/// ARIA-256 in GMAC with a 128-bit tag. See [`ARIA_GMAC_128`].
#[allow(non_camel_case_types)]
pub type ARIA_GMAC_256<'k, Dir> = Gmac<'k, ARIA256Internal, Dir, 16>;
