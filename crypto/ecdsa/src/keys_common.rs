//! [`DerivePublicKey`]: a small trait every curve's private key type in this crate implements, so
//! `d`'s matching public key `Q = [d]G` can be recomputed on demand rather than only ever obtained
//! from `keys::keygen` (or its per-curve equivalents) at generation time. Exists for the CLI's
//! `PkFromSk`/`CheckConsistency` actions, mirroring the shape (if not the name) of
//! `bouncycastle_mldsa::MLDSAPrivateKeyTrait::derive_pk`/`bouncycastle_mlkem::MLKEMPrivateKeyTrait::pk`,
//! which those crates' own CLI commands already use for the same purpose -- kept local to this
//! crate rather than added to `bouncycastle_core::traits`, since no other primitive in this
//! workspace shares this exact shape (a public key that is *always* a fixed, cheap function of the
//! private key alone, with no additional state).

use bouncycastle_core::traits::SignaturePublicKey;

/// Implemented by a curve's private key type: recomputes the matching public key `Q = [d]G`
/// directly from the wrapped private scalar `d`, using the same fixed-base multiplier
/// `keys::keygen_from_rng` (or its per-curve equivalent) uses internally.
pub trait DerivePublicKey<PK: SignaturePublicKey<PK_LEN>, const PK_LEN: usize> {
    /// Recomputes `Q = [d]G`.
    fn derive_pk(&self) -> PK;
}
