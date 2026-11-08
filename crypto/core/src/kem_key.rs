//! Key objects for key encapsulation: how an encapsulator or decapsulator is made, and the
//! one-shots over them.
//!
//! A KEM key is bound to one key encoding and may serve several algorithms with it, as a
//! signature key does. What tells the algorithms apart at the call is what a worker is made
//! from beyond the key, `Params` in [`EncapsulatingKey<Params, CT_LEN, SS_LEN>`]: `()` for an
//! algorithm whose output is the primitive's own shared secret (ML-KEM), the caller-configured
//! KDF, with whatever salt or fixed info it needs, for one that derives its output. The
//! parameter type selects the impl, so `pk.encaps(&mut rng, ())` and
//! `pk.encaps(&mut rng, hkdf_params)` on one key are two algorithms with no annotation, and
//! both sides of an exchange are made to name the same parameter type. The algorithm itself is
//! the impl's [`Algorithm`](EncapsulatingKey::Algorithm), a [`KEMAlgorithm`] marker that carries
//! the metadata and holds no state. The worker traits in [`crate::traits`],
//! [`KEMEncapsulator`] and [`KEMDecapsulator`], describe only an object that already exists.
//!
//! ```text
//! let enc = pk.create_encapsulator(())?;         // EncapsulatingKey<(), _, _>, ML-KEM-768
//! let (ss, ct) = enc.encaps(&mut rng)?;
//! let ss1 = sk.decaps(&ct, ())?;                 // DecapsulatingKey<(), _, _>
//! ```
//!
//! Nothing here instantiates a DRBG for the caller: a method that draws randomness takes
//! `&mut dyn RNG`.

use crate::errors::KEMError;
use crate::key_material::{KeyMaterial, KeyMaterialTrait};
use crate::traits::{Algorithm, KEMDecapsulator, KEMEncapsulator, RNG};

/// Marker for one KEM algorithm: ML-KEM-768, or RSA-KEM under a named KDF. It carries the
/// metadata through [`Algorithm`] and holds no state; a key names it as the
/// [`Algorithm`](EncapsulatingKey::Algorithm) of each role impl, so that one key can serve
/// every algorithm its encoding fits.
pub trait KEMAlgorithm: Algorithm {}

/// A key that encapsulates with the algorithm its impl names, made from `Params`.
///
/// The encapsulator is the algorithm's ordinary worker; this trait adds where it comes from. The
/// one-shots are provided over [`create_encapsulator`](Self::create_encapsulator) and return
/// what the worker would. A key implements the trait once per algorithm, each with its own
/// `Params` type; two algorithms that would take the same parameters on one key need a wrapper
/// key type to tell them apart.
pub trait EncapsulatingKey<Params, const CT_LEN: usize, const SS_LEN: usize> {
    /// The algorithm this impl encapsulates with.
    type Algorithm: KEMAlgorithm;

    /// The encapsulator this key produces, borrowing the key for `'k`.
    type Encapsulator<'k>: KEMEncapsulator<CT_LEN, SS_LEN>
    where
        Self: 'k;

    /// Makes an encapsulator from this key and `params`.
    ///
    /// # Errors
    /// Whatever the algorithm rejects in `params`; an algorithm that takes `()` never fails.
    fn create_encapsulator<'k>(
        &'k self,
        params: Params,
    ) -> Result<Self::Encapsulator<'k>, KEMError>;

    /// One-shot: encapsulates into `ct` and `ss`, both zeroized first, and returns the number of
    /// ciphertext bytes written, always `CT_LEN`.
    ///
    /// # Errors
    /// Those of [`create_encapsulator`](Self::create_encapsulator) and of
    /// [`KEMEncapsulator::encaps_out`]; both buffers are left zeroized.
    fn encaps_out(
        &self,
        rng: &mut dyn RNG,
        params: Params,
        ct: &mut [u8; CT_LEN],
        ss: &mut KeyMaterial<SS_LEN>,
    ) -> Result<usize, KEMError> {
        ct.fill(0);
        ss.zeroize();
        self.create_encapsulator(params)?.encaps_out(rng, ct, ss)
    }

    /// One-shot: the shared secret and the ciphertext.
    ///
    /// # Errors
    /// As [`encaps_out`](Self::encaps_out).
    fn encaps(
        &self,
        rng: &mut dyn RNG,
        params: Params,
    ) -> Result<(KeyMaterial<SS_LEN>, [u8; CT_LEN]), KEMError> {
        self.create_encapsulator(params)?.encaps(rng)
    }
}

/// A key that decapsulates ciphertexts of the algorithm its impl names, made from `Params`. A
/// key may implement this and no encapsulating trait, which is what a private key is.
pub trait DecapsulatingKey<Params, const CT_LEN: usize, const SS_LEN: usize> {
    /// The algorithm this impl decapsulates for.
    type Algorithm: KEMAlgorithm;

    /// The decapsulator this key produces, borrowing the key for `'k`.
    type Decapsulator<'k>: KEMDecapsulator<CT_LEN, SS_LEN>
    where
        Self: 'k;

    /// Makes a decapsulator from this key and `params`.
    ///
    /// # Errors
    /// Whatever the algorithm rejects in `params`; an algorithm that takes `()` never fails.
    fn create_decapsulator<'k>(
        &'k self,
        params: Params,
    ) -> Result<Self::Decapsulator<'k>, KEMError>;

    /// One-shot: decapsulates `ct` into `ss`, zeroized first, and returns the number of bytes
    /// written, always `SS_LEN`.
    ///
    /// # Errors
    /// Those of [`create_decapsulator`](Self::create_decapsulator) and of
    /// [`KEMDecapsulator::decaps_out`]; `ss` is left zeroized.
    fn decaps_out(
        &self,
        ct: &[u8; CT_LEN],
        params: Params,
        ss: &mut KeyMaterial<SS_LEN>,
    ) -> Result<usize, KEMError> {
        ss.zeroize();
        self.create_decapsulator(params)?.decaps_out(ct, ss)
    }

    /// One-shot: the shared secret of `ct`.
    ///
    /// # Errors
    /// As [`decaps_out`](Self::decaps_out).
    fn decaps(&self, ct: &[u8; CT_LEN], params: Params) -> Result<KeyMaterial<SS_LEN>, KEMError> {
        self.create_decapsulator(params)?.decaps(ct)
    }
}
