//! [`AgreementKeyPair`]: the ECC CDH key pair of a curve, reached from its [`bouncycastle_ec`](crate) marker.

use bouncycastle_core::errors::KeyAgreementError;
use bouncycastle_core::traits::RNG;

/// Implemented on a [`bouncycastle_ec`](crate) curve marker: the ECC CDH key pair of that curve, so a
/// caller starts from the curve and the trait in scope says what the pair is for
/// (`crate::ecdsa::keys_common::SignatureKeyPair` gives the same marker its signature pair,
/// a different type: SP 800-56A Rev. 3 Section 5.6.3.2 item 5 keeps the two apart). One impl
/// over every [`Curve`](crate::curve::Curve), which is [`keys::keygen`](crate::eccdh::keys::keygen).
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

    /// The private key of [`generate_agreement_key_pair`](Self::generate_agreement_key_pair)
    /// into `sk`, a key you hold, as [`keys::keygen_out`](crate::eccdh::keys::keygen_out)
    /// generates it; the public key is `sk.pub_key()`.
    ///
    /// # Errors
    /// As [`generate_agreement_key_pair`](Self::generate_agreement_key_pair), with `sk` left
    /// zeroized.
    fn generate_agreement_key_out(
        rng: &mut dyn RNG,
        sk: &mut Self::PrivateKey,
    ) -> Result<(), KeyAgreementError>;
}
