//! [`DerivePublicKey`]: every curve's private key type in this crate recomputes its public key
//! `Q = [d]G`, SP 800-56A Rev. 3 Section 5.6.2.1.4's pair-wise consistency check ("compute dG
//! ... compare the result to the public key"), for the CLI's `pk-from-sk` and `check-consistency`.
//! Local to this crate, as `bouncycastle_ecdsa::keys_common::DerivePublicKey` is to that one: the
//! two are bound to different public-key traits.

use bouncycastle_core::traits::KeyAgreementPublicKey;

/// Implemented by a curve's private key type: recomputes the matching public key `Q = [d]G`
/// from the wrapped private scalar `d`, with the fixed-base multiplier `keygen` uses.
pub trait DerivePublicKey<PK: KeyAgreementPublicKey<PK_LEN>, const PK_LEN: usize> {
    /// Recomputes `Q = [d]G`.
    fn derive_pk(&self) -> PK;
}
