//! [`AgreementKeyPair`]: the ECC CDH key pair of a curve, reached from its [`bouncycastle_ec`] marker.
//!
//! [`DerivePublicKey`]: the private key recomputes its public key `Q = [d]G`, SP 800-56A Rev. 3
//! Section 5.6.2.1.4's pair-wise consistency check ("compute dG ... compare the result to the
//! public key"), for the CLI's `pk-from-sk` and `check-consistency`.
//! Local to this crate, as `bouncycastle_ecdsa::keys_common::DerivePublicKey` is to that one: the
//! two are bound to different public-key traits.

use bouncycastle_core::errors::KeyAgreementError;
use bouncycastle_core::traits::{KeyAgreementPublicKey, RNG};

/// Implemented by the private key: recomputes the matching public key `Q = [d]G` from the
/// wrapped private scalar `d`, with the fixed-base multiplier `keygen` uses.
pub trait DerivePublicKey<PK: KeyAgreementPublicKey<PK_LEN>, const PK_LEN: usize> {
    /// Recomputes `Q = [d]G`.
    fn derive_pk(&self) -> PK;
}

/// Implemented on a [`bouncycastle_ec`] curve marker: the ECC CDH key pair of that curve, so a
/// caller starts from the curve and the trait in scope says what the pair is for
/// (`bouncycastle_ecdsa::keys_common::SignatureKeyPair` gives the same marker its signature pair,
/// a different type: SP 800-56A Rev. 3 Section 5.6.3.2 item 5 keeps the two apart). One impl
/// over every [`Curve`](bouncycastle_ec::curve::Curve), which is [`keys::keygen`](crate::keys::keygen).
/// The RNG is an argument, not a default: a key is only as good as the source it was drawn from,
/// which is the caller's to name.
pub trait AgreementKeyPair {
    /// The curve's ECC CDH public key.
    type PublicKey;
    /// The curve's ECC CDH private key.
    type PrivateKey;

    /// SP 800-56A Rev. 3 Section 5.6.1.2.1 key pair generation from `rng`, which must offer the
    /// curve's strength.
    ///
    /// # Errors
    /// [`KeyAgreementError::RNGError`] if the RNG is weaker than the curve or fails to deliver.
    fn generate_agreement_key_pair(
        rng: &mut dyn RNG,
    ) -> Result<(Self::PublicKey, Self::PrivateKey), KeyAgreementError>;
}
