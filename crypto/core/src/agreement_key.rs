//! Key objects for two-party key agreement: how an agreement worker is made, and the one-shot
//! over it.
//!
//! The shape is [`crate::kem_key`]'s. A private key is bound to one key encoding and may serve
//! several agreement algorithms with it (ECC CDH now, and a one-step KDF form over the same
//! curve keys later). What tells them apart at the call is what a worker is made from beyond
//! the key, `Params` in [`AgreementKey<Params, SS_LEN>`]: `()` for the raw primitive (ECC CDH,
//! SP 800-56Ar3 Section 5.7.1.2), the caller-configured KDF, with whatever salt or fixed info it
//! needs, for an algorithm that derives its output. The parameter type selects the impl, and
//! both parties are made to name the same parameter type. The algorithm itself is the impl's
//! [`Algorithm`](AgreementKey::Algorithm), a [`KeyAgreementAlgorithm`] marker that carries the
//! metadata and holds no state. The worker trait in [`crate::traits`], [`KeyAgreement`],
//! describes only an object that already exists.
//!
//! ```text
//! let agreement = sk_a.create_agreement(())?;      // AgreementKey<(), _>, ECC CDH
//! let z = agreement.agree(&pk_b)?;                 // the same Z as sk_b.agree(&pk_a, ())?
//! agreement.agree_out(&pk_b, &mut z_buf)?;        // or into a buffer the caller owns
//! ```
//!
//! `Z` comes back as [`KeyMaterial`] typed [`KeyType::SharedSecret`](crate::key_material::KeyType::SharedSecret)
//! at the algorithm's strength: keying material for a KDF (Section 5.8), not a key.

use crate::errors::KeyAgreementError;
use crate::key_material::{KeyMaterial, KeyMaterialTrait};
use crate::traits::{Algorithm, KeyAgreement};

/// Marker for one key-agreement algorithm: ECC CDH over P-256, say. It carries the metadata
/// through [`Algorithm`] and holds no state; a key names it as the
/// [`Algorithm`](AgreementKey::Algorithm) of each role impl, so that one key can serve every
/// algorithm its encoding fits.
pub trait KeyAgreementAlgorithm: Algorithm {}

/// A private key that agrees a shared secret with a peer's public key under the algorithm its
/// impl names, made from `Params`.
///
/// The worker is the algorithm's ordinary [`KeyAgreement`]; this trait adds where it comes from.
/// The one-shot is provided over [`create_agreement`](Self::create_agreement) and returns what
/// the worker would. A key implements the trait once per algorithm, each with its own `Params`
/// type.
pub trait AgreementKey<Params, const SS_LEN: usize> {
    /// The algorithm this impl agrees with.
    type Algorithm: KeyAgreementAlgorithm;

    /// The peer key type this key agrees with.
    type PublicKey;

    /// The worker this key produces, borrowing the key for `'k`.
    type Agreement<'k>: KeyAgreement<Self::PublicKey, SS_LEN>
    where
        Self: 'k;

    /// Makes an agreement worker from this key and `params`.
    ///
    /// # Errors
    /// Whatever the algorithm rejects in `params`; an algorithm that takes `()` never fails.
    fn create_agreement<'k>(
        &'k self,
        params: Params,
    ) -> Result<Self::Agreement<'k>, KeyAgreementError>;

    /// One-shot: the shared secret with `peer_pk` into `ss`, zeroized first, and the number of
    /// bytes written, always `SS_LEN`.
    ///
    /// # Errors
    /// Those of [`create_agreement`](Self::create_agreement) and of
    /// [`KeyAgreement::agree_out`]; `ss` is left zeroized.
    fn agree_out(
        &self,
        peer_pk: &Self::PublicKey,
        params: Params,
        ss: &mut KeyMaterial<SS_LEN>,
    ) -> Result<usize, KeyAgreementError> {
        ss.zeroize();
        self.create_agreement(params)?.agree_out(peer_pk, ss)
    }

    /// One-shot: the shared secret with `peer_pk`.
    ///
    /// # Errors
    /// As [`agree_out`](Self::agree_out).
    fn agree(
        &self,
        peer_pk: &Self::PublicKey,
        params: Params,
    ) -> Result<KeyMaterial<SS_LEN>, KeyAgreementError> {
        self.create_agreement(params)?.agree(peer_pk)
    }
}
