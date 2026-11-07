//! The parameters an algorithm that derives its output through a KDF is made from: a borrowed
//! KDF instance and the fixed info of the derivation.

use crate::traits::KDF;

/// A KDF instance and the fixed info an algorithm that derives its output through it is made
/// from, borrowed from the caller for `'p`: a KEM such as ML-KEM-512-HKDF-SHA256, or a key
/// agreement such as ECC-CDH-P256-X963KDF-SHA256.
///
/// The KDF is the type's parameter, so as the `Params` of a key's role impl the value selects
/// the algorithm at the call, `pk.encaps(&mut rng, params)`, with no annotation, and a KDF the
/// key is not paired with is a compile error. The instance holds whatever the KDF is made from
/// (an HKDF's salt, through `new_with_salt`), validated when it was made; one that has also
/// absorbed input through a streaming API is refused at the derivation, as [`KDF`]'s docs say,
/// so give an algorithm a fresh instance. The info is the fixed info of [`KDF::derive_key_out`]
/// (RFC 5869's info, SEC 1's `SharedInfo`). It is `Copy`, so one value serves every
/// construction on both sides of an exchange. `K` may be unsized, so a role implemented over
/// `KdfParams<'p, dyn KDF>` would take a derivation chosen at run time; the library's pairings
/// are over concrete KDF types.
pub struct KdfParams<'p, K: KDF + ?Sized> {
    kdf: &'p K,
    info: &'p [u8],
}

impl<'p, K: KDF + ?Sized> KdfParams<'p, K> {
    /// The KDF instance and the fixed info.
    pub fn new(kdf: &'p K, info: &'p [u8]) -> Self {
        Self { kdf, info }
    }

    /// The KDF.
    pub fn kdf(&self) -> &'p K {
        self.kdf
    }

    /// The fixed info.
    pub fn info(&self) -> &'p [u8] {
        self.info
    }
}

// Written out rather than derived: a derive would demand `K: Copy` of the KDF.
impl<K: KDF + ?Sized> Clone for KdfParams<'_, K> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<K: KDF + ?Sized> Copy for KdfParams<'_, K> {}
