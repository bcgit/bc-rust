//! [`SignatureKeyPair`]: the ECDSA key pair of a curve, reached from its [`bouncycastle_ec`] marker.
//!
//! [`DerivePublicKey`]: a small trait every curve's private key type in this crate implements, so
//! `d`'s matching public key `Q = [d]G` can be recomputed on demand rather than only ever obtained
//! from `keys::keygen` (or its per-curve equivalents) at generation time. Exists for the CLI's
//! `PkFromSk`/`CheckConsistency` actions, mirroring the shape (if not the name) of
//! `bouncycastle_mldsa::MLDSAPrivateKeyTrait::derive_pk`/`bouncycastle_mlkem::MLKEMPrivateKeyTrait::pk`,
//! which those crates' own CLI commands already use for the same purpose -- kept local to this
//! crate rather than added to `bouncycastle_core::traits`, since no other primitive in this
//! workspace shares this exact shape (a public key that is *always* a fixed, cheap function of the
//! private key alone, with no additional state).

use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{RNG, SignaturePublicKey};

/// Implemented by a curve's private key type: recomputes the matching public key `Q = [d]G`
/// directly from the wrapped private scalar `d`, using the same fixed-base multiplier
/// `keys_p256::keygen` (or its per-curve equivalent) uses internally.
pub trait DerivePublicKey<PK: SignaturePublicKey<PK_LEN>, const PK_LEN: usize> {
    /// Recomputes `Q = [d]G`.
    fn derive_pk(&self) -> PK;
}

/// Implemented on a [`bouncycastle_ec`] curve marker: the ECDSA key pair of that curve, so a caller
/// starts from the curve and the trait in scope says what the pair is for
/// (`bouncycastle_eccdh::keys_common::AgreementKeyPair` gives the same marker its key agreement
/// pair, a different type). Each impl is that curve's `keygen`. The RNG is an argument, not a
/// default: a key is only as good as the source it was drawn from, which is the caller's to name.
pub trait SignatureKeyPair {
    /// The curve's ECDSA public key.
    type PublicKey;
    /// The curve's ECDSA private key.
    type PrivateKey;

    /// FIPS 186-5 Appendix A.2.1 key pair generation from `rng`, which must offer the curve's
    /// strength.
    ///
    /// # Errors
    /// [`SignatureError::RNGError`] if the RNG is weaker than the curve or fails to deliver.
    fn generate_signature_key_pair(
        rng: &mut dyn RNG,
    ) -> Result<(Self::PublicKey, Self::PrivateKey), SignatureError>;
}
