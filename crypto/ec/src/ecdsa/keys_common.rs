//! [`SignatureKeyPair`]: the ECDSA key pair of a curve, reached from its [`bouncycastle_ec`](crate) marker.

use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{CollisionResistantHash, RNG};

use crate::curve::Curve;
use crate::ecdsa::ecdsa::EcdsaHash;
use crate::ecdsa::keys::{ECDSAPrivateKey, ECDSAPublicKey};

/// Implemented on a [`bouncycastle_ec`](crate) curve marker: the ECDSA key pair of that curve, so a caller
/// starts from the curve and the trait in scope says what the pair is for
/// (`crate::eccdh::keys_common::AgreementKeyPair` gives the same marker its key agreement
/// pair, a different type). One impl over every [`Curve`], which
/// is [`keys::keygen`](crate::ecdsa::keys::keygen). Neither the RNG nor the hash is defaulted: a key
/// is only as good as the source it was drawn from, and the hash it will sign with is a choice
/// the caller spells (`P256::generate_signature_key_pair::<SHA256>(&mut rng)`), since the
/// customary pairing is a convention that moves.
pub trait SignatureKeyPair: Curve {
    /// FIPS 186-5 Appendix A.2.1 key pair generation from `rng`, which must offer the curve's
    /// strength, for ECDSA over this curve and the hash `H`, which is one the pair can sign with:
    ///
    /// ```compile_fail,E0277
    /// use bouncycastle_ec::P256;
    /// use bouncycastle_ec::ecdsa::keys_common::SignatureKeyPair;
    /// use bouncycastle_digest::ripemd::RIPEMD160;
    /// use bouncycastle_rng::HashDRBG_SHA512;
    ///
    /// let _ = P256::generate_signature_key_pair::<RIPEMD160>(&mut HashDRBG_SHA512::new_from_os());
    /// ```
    ///
    /// # Errors
    /// [`SignatureError::RNGError`] if the RNG is weaker than the curve or fails to deliver.
    fn generate_signature_key_pair<H: EcdsaHash + CollisionResistantHash>(
        rng: &mut dyn RNG,
    ) -> Result<(ECDSAPublicKey<Self, H>, ECDSAPrivateKey<Self, H>), SignatureError>;

    /// The private key of [`generate_signature_key_pair`](Self::generate_signature_key_pair)
    /// into `sk`, a key you hold, as [`keys::keygen_out`](crate::ecdsa::keys::keygen_out)
    /// generates it; the public key is `sk.pub_key()`.
    ///
    /// # Errors
    /// As [`generate_signature_key_pair`](Self::generate_signature_key_pair), with `sk` left
    /// zeroized.
    fn generate_signature_key_out<H: EcdsaHash + CollisionResistantHash>(
        rng: &mut dyn RNG,
        sk: &mut ECDSAPrivateKey<Self, H>,
    ) -> Result<(), SignatureError>;
}
