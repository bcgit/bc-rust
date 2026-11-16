//! The parameters an algorithm that derives its output through a KDF is made from: a borrowed
//! description of the KDF, the fixed info of the derivation, and the length of what it derives.

use crate::errors::KDFError;
use crate::traits::{AlgorithmInfo, KDF};

/// The length of the key a derivation produces, in bytes, as a value: the third argument of
/// [`KdfParams::new`], `KeyLen::<32>`, or a bare `KeyLen` when the key the caller binds names
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyLen<const N: usize>;

/// What a KDF is made from, readable, and the KDF it builds: a description of the derivation
/// rather than a running instance, so that a key held where the shared secret must not leave
/// (a token, an HSM) can read the KDF's identity and parameters and hand the device the same
/// derivation, while a software key builds the [`Engine`](Self::Engine) and runs it. HKDF's
/// description is its hash and its salt; a KDF with no constructor parameters, the X9.63 or
/// concatenation KDF, describes itself. Implemented by the KDF crates for the library's KDFs,
/// and by a caller for a KDF of its own, as the `Params` the role traits are implemented over
/// through [`KdfParams`].
pub trait KdfDescription: AlgorithmInfo {
    /// The software KDF the description builds.
    type Engine: KDF;

    /// A fresh engine holding what the description says, validated as the KDF's own
    /// constructor validates it (an HKDF keyed with the salt). Built once per derivation by a
    /// software pairing; the cost is the KDF's construction, two hash blocks for HKDF.
    ///
    /// # Errors
    /// What the KDF's constructor refuses: for HKDF a salt typed `Unknown`, as
    /// [`KDFError::MACError`].
    fn engine(&self) -> Result<Self::Engine, KDFError>;
}

/// A KDF's description, the fixed info and the output length an algorithm that derives its
/// output through a KDF is made from, the first two borrowed from the caller for `'p`: a KEM
/// such as ML-KEM-512-HKDF-SHA256, or a key agreement such as ECC-CDH-P256-X963KDF-SHA256.
///
/// The description is the type's parameter and the length its const, so as the `Params` of a
/// key's role impl the value selects the algorithm and the derived key's length at the call,
/// `pk.encaps(&mut rng, params)`: a KDF the key is not paired with is a compile error, and the
/// length is the one the caller named, `KdfParams::new(&hkdf, info, KeyLen::<32>)`, or with a
/// bare `KeyLen` the one the key it binds has, `let key: KeyMaterial<32> = ..`. What lengths a
/// pairing allows is the pairing's to say and check. The length is the protocol's to fix, as the
/// info is: a KDF's outputs at two lengths under one info are not independent keys (HKDF's
/// shorter one is a prefix of the longer, RFC 5869 Section 2.3), so two keys from one exchange
/// take two infos, never two lengths. The description holds whatever the KDF is made from (an
/// HKDF's salt), readable through its own accessors, which is what lets a key that cannot run
/// the derivation itself hand it on; a software pairing builds the engine from it for each
/// derivation ([`KdfDescription::engine`]). The info is the fixed info of
/// [`KDF::derive_key_out`] (RFC 5869's info, SEC 1's `SharedInfo`). It is `Copy`, so one value
/// serves every construction on both sides of an exchange. `D` may be unsized, so a role
/// implemented over `KdfParams<'p, dyn KdfDescription<Engine = E>, LEN>` would take a
/// derivation chosen at run time; the library's pairings are over concrete descriptions.
pub struct KdfParams<'p, D: KdfDescription + ?Sized, const LEN: usize> {
    kdf: &'p D,
    info: &'p [u8],
}

impl<'p, D: KdfDescription + ?Sized, const LEN: usize> KdfParams<'p, D, LEN> {
    /// The length of the key derived through these parameters, in bytes.
    pub const LEN: usize = LEN;

    /// The KDF's description, the fixed info and the length of the key to derive. The length
    /// is agreed by the protocol as the info is, and it does not separate keys: outputs at two
    /// lengths under one info are prefixes of each other, so two keys want two infos.
    pub fn new(kdf: &'p D, info: &'p [u8], _len: KeyLen<LEN>) -> Self {
        Self { kdf, info }
    }

    /// The KDF's description.
    pub fn kdf(&self) -> &'p D {
        self.kdf
    }

    /// The fixed info.
    pub fn info(&self) -> &'p [u8] {
        self.info
    }
}

// Written out rather than derived: a derive would demand `D: Copy` of the description.
impl<D: KdfDescription + ?Sized, const LEN: usize> Clone for KdfParams<'_, D, LEN> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<D: KdfDescription + ?Sized, const LEN: usize> Copy for KdfParams<'_, D, LEN> {}
