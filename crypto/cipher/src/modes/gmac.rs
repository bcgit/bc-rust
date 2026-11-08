//! GMAC, the authentication-only specialization of GCM (NIST SP 800-38D Sec 5.2): "An
//! implementation may restrict the input to the non-confidential data, i.e., without any
//! confidential data. The resulting variant of GCM is called GMAC. For GMAC, the authenticated
//! encryption and decryption functions become the functions for generating and verifying an
//! authentication tag on the non-confidential data."
//!
//! [`Gmac`] is a [`Gcm`] that is only ever given AAD, so it inherits `Gcm`'s 96-bit nonce and its
//! `TAG_LEN` range of 12 to 16 bytes. Following that sentence of Sec 5.2, the direction markers
//! carry over too: `Gmac<'k, .., Encrypting, ..>` generates a tag and `Gmac<'k, .., Decrypting, ..>`
//! verifies one.
//!
//! Every tag is bound to a nonce, which is why GMAC is a [`NonceMacMode`] rather than a `MacMode`,
//! and a mode-bound key, `AES128Key<GMAC>`, hands out both sides through the nonce-bound role
//! pair [`NonceMacGenerationKey`] / [`NonceMacVerificationKey`] from one stored `H`, which the
//! workers borrow: the generating side draws the nonce from the RNG it is given and returns it,
//! or takes one from a caller who manages its own; the verifying side takes the nonce the tag was
//! made under. The workers are the ordinary [`MACGenerator`] / [`MACVerifier`].
//!
//! The key is [`KeyType::MACKey`] material, as CMAC's is, and so cannot also be a GCM key: a
//! nonce shared between a GMAC tag and a GCM message under one key is a repeated nonce.
//!
//! # Usage Examples
//!
//! From a mode-bound key, which holds the key state the workers borrow; over the toy permutation
//! the key is [`BlockCipherKey`](crate::BlockCipherKey), as it is for AES:
//!
//! ```
//! # mod toy { include!("../../tests/common/toy_block_cipher.rs"); }
//! # use toy::ToyBlockCipher;
//! use bouncycastle_cipher::BlockCipherKey;
//! use bouncycastle_cipher::modes::GMAC;
//! use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
//! use bouncycastle_core::symmetric_key::{FromKeyMaterial, NonceMacGenerationKey, NonceMacVerificationKey};
//! use bouncycastle_core::traits::{MACGenerator, MACVerifier};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let material = KeyMaterial128::from_bytes_as_type(&[0x42; 16], KeyType::MACKey).unwrap();
//! let key = BlockCipherKey::<ToyBlockCipher, GMAC>::from_key_material(&material).unwrap();
//!
//! let (mut generator, nonce) = key.create_generator(&mut rng).unwrap();
//! generator.do_update(b"a message ");
//! generator.do_update(b"in two parts");
//! let tag: [u8; 16] = generator.do_final();
//!
//! let mut verifier = key.create_verifier(&nonce);
//! verifier.do_update(b"a message in two parts");
//! assert!(verifier.do_verify_final(&tag).is_ok());
//! assert!(key.verify(&nonce, b"a message in two parts", &tag).is_ok());   // the one-shot
//! ```
//!
//! # 🚨 Security Considerations 🚨
//!
//! Everything in the [`gcm`](crate::modes::gcm) module's security considerations applies: above
//! all, a nonce repeated under one key lets an attacker recover the hash subkey `H` and forge tags
//! (SP 800-38D Sec 8 and Appendix A), and the key is limited to 2^32 invocations (Sec 8.3). The
//! `_nonce` constructors put the uniqueness obligation on the caller.
//!
//! [`NonceMacGenerationKey`]: bouncycastle_core::symmetric_key::NonceMacGenerationKey
//! [`NonceMacVerificationKey`]: bouncycastle_core::symmetric_key::NonceMacVerificationKey
//! [`KeyType::MACKey`]: bouncycastle_core::key_material::KeyType::MACKey

use crate::modes::ModeNames;
use crate::modes::gcm::{GCM_NONCE_LEN, Gcm, GcmKeyState};
use crate::{Decrypting, Encrypting};
use bouncycastle_core::errors::MACError;
use bouncycastle_core::hazmat::{BlockPermutation, Mode, NonceMacMode};
use bouncycastle_core::key_material::KeyType;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, MACGenerator, MACVerifier, RNG};

/// The GMAC mode type: the `M` of a mode-bound key such as `AES128Key<GMAC>`. `GMAC` is GMAC with
/// the full 128-bit tag; `GMAC<12>` and so on select a shorter tag, within the `12..=16` byte
/// range [`Gcm`] accepts. Its key state is [`GcmKeyState`], so a GMAC key caches `H` as a GCM key
/// does. The [`Mode`] and [`NonceMacMode`] impls below are generic over any [`BlockPermutation`]
/// with a 128-bit block, and a key's nonce-bound role pair forwards to the latter.
pub struct GMAC<const TAG_LEN: usize = 16>;

impl<P, const TAG_LEN: usize> Mode<P> for GMAC<TAG_LEN>
where
    P: BlockPermutation<16> + ModeNames + Clone,
{
    type KeyState = GcmKeyState<P>;
    const KEY_TYPE: KeyType = KeyType::MACKey;

    fn key_state(perm: P) -> Self::KeyState {
        GcmKeyState::new(perm)
    }
}

impl<P, const TAG_LEN: usize> NonceMacMode<P, GCM_NONCE_LEN, TAG_LEN> for GMAC<TAG_LEN>
where
    P: BlockPermutation<16> + ModeNames + Clone,
{
    type Generator<'k>
        = Gmac<'k, P, Encrypting, TAG_LEN>
    where
        P: 'k;
    type Verifier<'k>
        = Gmac<'k, P, Decrypting, TAG_LEN>
    where
        P: 'k;

    fn generate_init<'k>(
        state: &'k Self::KeyState,
        rng: &mut dyn RNG,
    ) -> Result<(Self::Generator<'k>, [u8; GCM_NONCE_LEN]), MACError> {
        Gmac::<P, Encrypting, TAG_LEN>::from_key_state(state, rng)
    }

    fn generate_init_nonce<'k>(
        state: &'k Self::KeyState,
        nonce: &[u8; GCM_NONCE_LEN],
    ) -> Self::Generator<'k> {
        Gmac::<P, Encrypting, TAG_LEN>::from_key_state_nonce(state, nonce)
    }

    fn verify_init<'k>(
        state: &'k Self::KeyState,
        nonce: &[u8; GCM_NONCE_LEN],
    ) -> Self::Verifier<'k> {
        Gmac::<P, Decrypting, TAG_LEN>::from_key_state(state, nonce)
    }
}

/// GMAC over the permutation `P`, generating (`Dir = Encrypting`) or verifying (`Dir =
/// Decrypting`) a `TAG_LEN`-byte tag. See the module docs.
pub struct Gmac<'k, P, Dir, const TAG_LEN: usize>
where
    P: BlockPermutation<16> + ModeNames,
{
    gcm: Gcm<'k, P, Dir, TAG_LEN>,
}

/// `Gcm`'s AAD absorption fails only if AAD follows data, which GMAC never supplies, or if the
/// running AAD length overflows a `u64`, which needs 2^64 bytes of input.
const AAD_INFALLIBLE: &str = "GMAC: GCM rejects AAD only after data or past 2^64 bytes";

impl<'k, P, Dir, const TAG_LEN: usize> Algorithm for Gmac<'k, P, Dir, TAG_LEN>
where
    P: BlockPermutation<16> + ModeNames,
{
    const ALG_NAME: &'static str = P::GMAC_ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = P::MAX_SECURITY_STRENGTH;
}

impl<'k, P, const TAG_LEN: usize> Gmac<'k, P, Encrypting, TAG_LEN>
where
    P: BlockPermutation<16> + ModeNames,
{
    /// Begins a tag from a key's stored state under a nonce drawn from `rng`: what a mode-bound
    /// key's `create_generator` calls.
    ///
    /// # Errors
    /// [`MACError::RNGError`] if the nonce draw fails; nothing else can.
    pub(crate) fn from_key_state(
        state: &'k GcmKeyState<P>,
        rng: &mut dyn RNG,
    ) -> Result<(Self, [u8; GCM_NONCE_LEN]), MACError> {
        // The draw is `Gcm`'s (SP 800-38A Appendix C's "random data block"), under this mode's
        // error type.
        let mut nonce = [0u8; GCM_NONCE_LEN];
        rng.next_bytes_out(&mut nonce)?;
        Ok((Self::from_key_state_nonce(state, &nonce), nonce))
    }

    /// As [`from_key_state`](Self::from_key_state) under a nonce the caller supplies, who takes
    /// on the obligation that it never repeat under this key.
    pub(crate) fn from_key_state_nonce(
        state: &'k GcmKeyState<P>,
        nonce: &[u8; GCM_NONCE_LEN],
    ) -> Self {
        Self { gcm: Gcm::from_key_state_nonce(state, nonce) }
    }
}

impl<'k, P, const TAG_LEN: usize> MACGenerator<TAG_LEN> for Gmac<'k, P, Encrypting, TAG_LEN>
where
    P: BlockPermutation<16> + ModeNames,
{
    fn do_update(&mut self, data: &[u8]) {
        self.gcm.absorb_aad(data).expect(AAD_INFALLIBLE);
    }

    fn do_final_out(self, out: &mut [u8; TAG_LEN]) -> usize {
        *out = self.gcm.finish();
        TAG_LEN
    }
}

impl<'k, P, const TAG_LEN: usize> Gmac<'k, P, Decrypting, TAG_LEN>
where
    P: BlockPermutation<16> + ModeNames,
{
    /// Begins verifying a tag made under `nonce` from a key's stored state: what a mode-bound
    /// key's `create_verifier` calls. Infallible: the state is keyed and the nonce length is in
    /// the type.
    pub(crate) fn from_key_state(state: &'k GcmKeyState<P>, nonce: &[u8; GCM_NONCE_LEN]) -> Self {
        Self { gcm: Gcm::<P, Decrypting, TAG_LEN>::from_key_state(state, nonce) }
    }
}

impl<'k, P, const TAG_LEN: usize> MACVerifier<TAG_LEN> for Gmac<'k, P, Decrypting, TAG_LEN>
where
    P: BlockPermutation<16> + ModeNames,
{
    fn do_update(&mut self, data: &[u8]) {
        self.gcm.absorb_aad(data).expect(AAD_INFALLIBLE);
    }

    /// `Gcm`'s tag check, in constant time.
    fn do_verify_final(self, tag: &[u8; TAG_LEN]) -> Result<(), MACError> {
        self.gcm.finish(tag).map_err(|_| MACError::VerificationFailed)
    }
}
