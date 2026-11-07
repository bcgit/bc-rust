//! Type aliases for Camellia in GMAC (NIST SP 800-38D Sec 5.2), and the generator/verifier pair that
//! makes `Camellia128Key<GMAC>` and friends GMAC keys. The docs are on [`Camellia_GMAC_128`], which the
//! crate root re-exports.

use crate::hazmat::{
    Camellia128Internal, Camellia192Internal, Camellia256Internal, CamelliaInternal,
};
use crate::{CamelliaKey, CamelliaParams};
use bouncycastle_cipher::modes::{GCM_NONCE_LEN, GMAC, Gmac, ModeNames};
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::hazmat::{BlockPermutation, NonceMacMode};
use bouncycastle_core::traits::RNG;

/// Camellia-128 in GMAC with a 128-bit tag: the `Gmac` worker of `bouncycastle-cipher` over the Camellia
/// permutation, `Dir` [`Encrypting`] to generate a tag or [`Decrypting`] to verify one. A GMAC
/// tag is bound to a nonce, so the pair is inherent on the key, `Camellia128Key<GMAC>` of
/// `KeyType::MACKey` material: [`create_generator`](CamelliaKey::create_generator) draws the nonce,
/// [`create_generator_nonce`](CamelliaKey::create_generator_nonce) takes the caller's, and
/// [`create_verifier`](CamelliaKey::create_verifier) checks under it. The construction, the nonce
/// rule and the security considerations are those of [`bouncycastle_cipher::modes::gmac`] and,
/// alias for alias, of `AES_GMAC_128` in `bouncycastle-aes`; only the permutation differs.
///
/// # Usage Examples
///
/// ```
/// use bouncycastle_camellia::Camellia256Key;
/// use bouncycastle_cipher::modes::GMAC;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::symmetric_key::FromKeyMaterial;
/// use bouncycastle_rng::HashDRBG_SHA512;
///
/// let mut rng = HashDRBG_SHA512::new_from_os();
/// let material = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::MACKey).unwrap();
/// let key = Camellia256Key::<GMAC>::from_key_material(&material).expect("a valid Camellia-256 MAC key");
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
pub type Camellia_GMAC_128<'k, Dir> = Gmac<'k, Camellia128Internal, Dir, 16>;

/// Camellia-192 in GMAC with a 128-bit tag. See [`Camellia_GMAC_128`].
#[allow(non_camel_case_types)]
pub type Camellia_GMAC_192<'k, Dir> = Gmac<'k, Camellia192Internal, Dir, 16>;

/// Camellia-256 in GMAC with a 128-bit tag. See [`Camellia_GMAC_128`].
#[allow(non_camel_case_types)]
pub type Camellia_GMAC_256<'k, Dir> = Gmac<'k, Camellia256Internal, Dir, 16>;

// The pair is inherent on the key rather than a role trait, since a GMAC tag is bound to a nonce;
// one impl over every Camellia key length, forwarding to the mode's `NonceMacMode` impl as the role
// impls forward to theirs.
impl<P, const TAG_LEN: usize> CamelliaKey<P, GMAC<TAG_LEN>>
where
    P: CamelliaParams,
    CamelliaInternal<P>: BlockPermutation<16> + ModeNames + Clone,
{
    /// A generator under a nonce drawn from `rng`, which is returned with it.
    ///
    /// # Errors
    /// [`SymmetricCipherError::RNGError`] if the draw fails.
    #[allow(clippy::type_complexity)] // the worker and its nonce, as the AES key returns them
    pub fn create_generator<'k>(
        &'k self,
        rng: &mut dyn RNG,
    ) -> Result<
        (Gmac<'k, CamelliaInternal<P>, Encrypting, TAG_LEN>, [u8; GCM_NONCE_LEN]),
        SymmetricCipherError,
    > {
        GMAC::<TAG_LEN>::generate_init(&self.state, rng)
    }

    /// A generator under the caller's nonce, which must not repeat under this key.
    pub fn create_generator_nonce<'k>(
        &'k self,
        nonce: &[u8; GCM_NONCE_LEN],
    ) -> Gmac<'k, CamelliaInternal<P>, Encrypting, TAG_LEN> {
        GMAC::<TAG_LEN>::generate_init_nonce(&self.state, nonce)
    }

    /// A verifier under the nonce the tag was made under.
    pub fn create_verifier<'k>(
        &'k self,
        nonce: &[u8; GCM_NONCE_LEN],
    ) -> Gmac<'k, CamelliaInternal<P>, Decrypting, TAG_LEN> {
        GMAC::<TAG_LEN>::verify_init(&self.state, nonce)
    }
}
