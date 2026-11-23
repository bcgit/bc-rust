//! [`GcmSivPermutation`], the marker that says which permutations AES-GCM-SIV is defined over.

/// Asserts that the implementing permutation is AES with a 128- or 256-bit key, as RFC 8452
/// requires: its Section 4 uses AES-128 for a 16-byte key and AES-256 for a 32-byte one, and
/// Section 6 defines no other AEAD. [`GCM_SIV`](crate::modes::GCM_SIV) implements its mode traits
/// only over a permutation that carries this marker, so a key for any other cipher, or for
/// AES-192, has no GCM-SIV role and does not compile.
///
/// # 🚨 Security Considerations 🚨
///
/// The marker is a claim the compiler cannot check, which is why it is under
/// [`hazmat`](crate::modes::hazmat). Implementing it for a permutation that is not AES-128 or
/// AES-256 builds a cipher no specification defines and no analysis covers; only an AES
/// implementation should implement it, for those two key lengths.
pub trait GcmSivPermutation {
    /// The name of AES-GCM-SIV over this permutation, which a key bound to
    /// [`GCM_SIV`](crate::modes::GCM_SIV) reports as its
    /// [`ALG_NAME`](bouncycastle_core::traits::Algorithm::ALG_NAME). It is here and not in
    /// [`ModeNames`](crate::modes::ModeNames) because only the permutations the mode is defined
    /// over have one.
    const GCM_SIV_ALG_NAME: &'static str;
}
