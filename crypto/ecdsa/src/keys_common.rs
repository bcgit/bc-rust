//! [`SignatureKeyPair`]: the ECDSA key pair of a curve, reached from its [`bouncycastle_ec`] marker.
//!
//! [`DerivePublicKey`]: a small trait the private key implements, so `d`'s matching public key
//! `Q = [d]G` can be recomputed on demand rather than only ever obtained from `keys::keygen` at
//! generation time. Exists for the CLI's
//! `PkFromSk`/`CheckConsistency` actions, mirroring the shape (if not the name) of
//! `bouncycastle_mldsa::MLDSAPrivateKeyTrait::derive_pk`/`bouncycastle_mlkem::MLKEMPrivateKeyTrait::pk`,
//! which those crates' own CLI commands already use for the same purpose -- kept local to this
//! crate rather than added to `bouncycastle_core::traits`, since no other primitive in this
//! workspace shares this exact shape (a public key that is *always* a fixed, cheap function of the
//! private key alone, with no additional state).

use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{RNG, SignaturePublicKey};

use crate::ecdsa::EcdsaHash;
use crate::keys::{ECDSAPrivateKey, ECDSAPublicKey};
use bouncycastle_ec::curve::Curve;

/// Implemented by the private key: recomputes the matching public key `Q = [d]G` directly from
/// the wrapped private scalar `d`, using the same fixed-base multiplier `keys::keygen` uses.
pub trait DerivePublicKey<PK: SignaturePublicKey<PK_LEN>, const PK_LEN: usize> {
    /// Recomputes `Q = [d]G`.
    fn derive_pk(&self) -> PK;
}

/// Implemented on a [`bouncycastle_ec`] curve marker: the ECDSA key pair of that curve, so a caller
/// starts from the curve and the trait in scope says what the pair is for
/// (`bouncycastle_eccdh::keys_common::AgreementKeyPair` gives the same marker its key agreement
/// pair, a different type). One impl over every [`Curve`], which
/// is [`keys::keygen`](crate::keys::keygen). Neither the RNG nor the hash is defaulted: a key
/// is only as good as the source it was drawn from, and the hash it will sign with is a choice
/// the caller spells (`P256::generate_signature_key_pair::<SHA256>(&mut rng)`), since the
/// customary pairing is a convention that moves.
pub trait SignatureKeyPair: Curve {
    /// FIPS 186-5 Appendix A.2.1 key pair generation from `rng`, which must offer the curve's
    /// strength, for ECDSA over this curve and the hash `H`.
    ///
    /// # Errors
    /// [`SignatureError::RNGError`] if the RNG is weaker than the curve or fails to deliver.
    fn generate_signature_key_pair<H: EcdsaHash>(
        rng: &mut dyn RNG,
    ) -> Result<(ECDSAPublicKey<Self, H>, ECDSAPrivateKey<Self, H>), SignatureError>;
}
