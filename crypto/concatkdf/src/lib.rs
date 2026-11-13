//! The NIST concatenation KDF: the one-step key-derivation function of SP 800-56C Rev. 2
//! Section 4.1 with Option 1's auxiliary function, `H(x) = hash(x)`. The derived keying material
//! is the leftmost `L` bits of `K(1) || K(2) || ...`, with `K(i) = H(counter || Z || FixedInfo)`
//! and `counter` a 4-byte big-endian count from 1. It is the KDF of the SP 800-56A key-agreement
//! schemes, turning the shared secret `Z` into keying material, with `FixedInfo` the context both
//! parties agree on.
//!
//! [`ConcatKDF<H>`] is the function over any hash that implements [`ConcatKDFParams`]; the aliases
//! [`ConcatKDF_SHA224`] to [`ConcatKDF_SHA3_512`] are the instantiations over the SHA-2 and SHA-3
//! hashes of the Section 4.2 Table 1 that the library has (all but SHA-1). An instance and the
//! `FixedInfo` are the `bouncycastle_core::kdf_params::KdfParams` a key-agreement role impl is made
//! from.
//!
//! # Usage Examples
//!
//! Keying material of any length from a shared secret, [`ConcatKDF::derive_out`]:
//!
//! ```
//! use bouncycastle_core::hazmat::do_hazardous_operations;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
//! use bouncycastle_core::security_strength::SecurityStrength;
//! use bouncycastle_concatkdf::ConcatKDF_SHA256;
//!
//! // The Z of a key agreement, typed for a KDF at the scheme's strength, which its producer
//! // states (a `SharedSecret`'s length says nothing about its entropy); here stand-in bytes.
//! let mut z = KeyMaterial::<32>::from_bytes_as_type(&[0x5A; 32], KeyType::SharedSecret).unwrap();
//! do_hazardous_operations(&mut z, |z| z.set_security_strength(SecurityStrength::_128bit)).unwrap();
//!
//! let mut dkm = KeyMaterial::<48>::new();
//! let written = ConcatKDF_SHA256::derive_out(&z, b"example protocol v1", 48, &mut dkm).unwrap();
//! assert_eq!(written, 48);
//! assert_eq!(dkm.key_type(), KeyType::CryptographicRandom);
//! ```
//!
//! Through the [`KDF`] trait, with `FixedInfo` as the fixed info and the length asked for:
//!
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
//! use bouncycastle_core::traits::KDF;
//! use bouncycastle_concatkdf::ConcatKDF_SHA256;
//!
//! let z = KeyMaterial::<32>::from_bytes_as_type(&[0x5A; 32], KeyType::SharedSecret).unwrap();
//! let key = ConcatKDF_SHA256::new().derive_key(&z, b"example protocol v1", 32).unwrap();
//! assert_eq!(key.key_len(), 32);
//! ```
//!
//! # Memory Usage
//!
//! The function is stateless: beyond the hash's own state it holds one output block of
//! [`MAX_HASH_OUTPUT_LEN`] bytes in a [`Secret`] on the stack, and writes straight into the
//! caller's buffer.
//!
//! # 🚨 Security Considerations 🚨
//!
//! - `Z` is credited as keying material only when it is typed full-entropy material (a key
//!   agreement's `SharedSecret`, say); the output is `CryptographicRandom` once at least half a
//!   hash output of such material has gone in, the policy HKDF applies, and otherwise `Unknown`.
//!   Its strength is the least of `Z`'s, the hash's and the output length's: the KDF stretches
//!   keying material and creates none.
//! - `FixedInfo` is context, not keying material: it is not credited, and both parties must
//!   supply the same octets. Option 1 has no salt; a fresh `Z` per agreement is what makes the
//!   output fresh. Outputs at two lengths under one `FixedInfo` are prefixes of each other, which
//!   is why SP 800-56C suggests `L` be part of `FixedInfo`.
//! - `L` is a whole number of bytes here, at most `H_outputBits / 8 * (2^32 - 1)` (Section 4.1
//!   step 2) and no more than the output buffer holds. Step 4's bound on `counter || Z ||
//!   FixedInfo`, the hash's maximum message length, is not checked: it is `2^61 - 1` bytes for
//!   SHA-224 and SHA-256 and `2^125 - 1` for the other SHA-2 hashes, which no buffer this
//!   library is given in practice comes near, though a 64-bit slice could in principle reach
//!   the former; SHA-3 has no such limit.

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

use bouncycastle_core::errors::KDFError;
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::kdf_params::KdfDescription;
use bouncycastle_core::key_material::{KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, HashAlgParams, HashOneShot, KDF};
use bouncycastle_sha2::{SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256};
use bouncycastle_sha3::{SHA3_224, SHA3_256, SHA3_384, SHA3_512};
use bouncycastle_utils::secret::Secret;
use bouncycastle_utils::{max, min};
use core::marker::PhantomData;

/// The largest hash output this crate's block buffer holds: 64 bytes, SHA-512's and SHA3-512's.
/// A hash with a longer output is refused at compile time.
pub const MAX_HASH_OUTPUT_LEN: usize = 64;

/// A hash the KDF is instantiated over: [`HashOneShot`] and [`HashAlgParams`], plus the name the
/// instantiation reports. Implemented for the SHA-2 and SHA-3 hashes of SP 800-56C Rev. 2
/// Table 1.
pub trait ConcatKDFParams: HashOneShot + HashAlgParams {
    /// The instantiation's name, as reported by `Algorithm::ALG_NAME`.
    const CONCAT_KDF_ALG_NAME: &'static str;
}

/// The name of the KDF over SHA-224.
pub const CONCAT_KDF_SHA224_NAME: &str = "ConcatKDF-SHA224";
/// The name of the KDF over SHA-256.
pub const CONCAT_KDF_SHA256_NAME: &str = "ConcatKDF-SHA256";
/// The name of the KDF over SHA-384.
pub const CONCAT_KDF_SHA384_NAME: &str = "ConcatKDF-SHA384";
/// The name of the KDF over SHA-512.
pub const CONCAT_KDF_SHA512_NAME: &str = "ConcatKDF-SHA512";
/// The name of the KDF over SHA-512/224.
pub const CONCAT_KDF_SHA512_224_NAME: &str = "ConcatKDF-SHA512/224";
/// The name of the KDF over SHA-512/256.
pub const CONCAT_KDF_SHA512_256_NAME: &str = "ConcatKDF-SHA512/256";
/// The name of the KDF over SHA3-224.
pub const CONCAT_KDF_SHA3_224_NAME: &str = "ConcatKDF-SHA3-224";
/// The name of the KDF over SHA3-256.
pub const CONCAT_KDF_SHA3_256_NAME: &str = "ConcatKDF-SHA3-256";
/// The name of the KDF over SHA3-384.
pub const CONCAT_KDF_SHA3_384_NAME: &str = "ConcatKDF-SHA3-384";
/// The name of the KDF over SHA3-512.
pub const CONCAT_KDF_SHA3_512_NAME: &str = "ConcatKDF-SHA3-512";

impl ConcatKDFParams for SHA224 {
    const CONCAT_KDF_ALG_NAME: &'static str = CONCAT_KDF_SHA224_NAME;
}
impl ConcatKDFParams for SHA256 {
    const CONCAT_KDF_ALG_NAME: &'static str = CONCAT_KDF_SHA256_NAME;
}
impl ConcatKDFParams for SHA384 {
    const CONCAT_KDF_ALG_NAME: &'static str = CONCAT_KDF_SHA384_NAME;
}
impl ConcatKDFParams for SHA512 {
    const CONCAT_KDF_ALG_NAME: &'static str = CONCAT_KDF_SHA512_NAME;
}
impl ConcatKDFParams for SHA512_224 {
    const CONCAT_KDF_ALG_NAME: &'static str = CONCAT_KDF_SHA512_224_NAME;
}
impl ConcatKDFParams for SHA512_256 {
    const CONCAT_KDF_ALG_NAME: &'static str = CONCAT_KDF_SHA512_256_NAME;
}
impl ConcatKDFParams for SHA3_224 {
    const CONCAT_KDF_ALG_NAME: &'static str = CONCAT_KDF_SHA3_224_NAME;
}
impl ConcatKDFParams for SHA3_256 {
    const CONCAT_KDF_ALG_NAME: &'static str = CONCAT_KDF_SHA3_256_NAME;
}
impl ConcatKDFParams for SHA3_384 {
    const CONCAT_KDF_ALG_NAME: &'static str = CONCAT_KDF_SHA3_384_NAME;
}
impl ConcatKDFParams for SHA3_512 {
    const CONCAT_KDF_ALG_NAME: &'static str = CONCAT_KDF_SHA3_512_NAME;
}

/// The concatenation KDF over SHA-224.
#[allow(non_camel_case_types)]
pub type ConcatKDF_SHA224 = ConcatKDF<SHA224>;
/// The concatenation KDF over SHA-256.
#[allow(non_camel_case_types)]
pub type ConcatKDF_SHA256 = ConcatKDF<SHA256>;
/// The concatenation KDF over SHA-384.
#[allow(non_camel_case_types)]
pub type ConcatKDF_SHA384 = ConcatKDF<SHA384>;
/// The concatenation KDF over SHA-512.
#[allow(non_camel_case_types)]
pub type ConcatKDF_SHA512 = ConcatKDF<SHA512>;
/// The concatenation KDF over SHA-512/224.
#[allow(non_camel_case_types)]
pub type ConcatKDF_SHA512_224 = ConcatKDF<SHA512_224>;
/// The concatenation KDF over SHA-512/256.
#[allow(non_camel_case_types)]
pub type ConcatKDF_SHA512_256 = ConcatKDF<SHA512_256>;
/// The concatenation KDF over SHA3-224.
#[allow(non_camel_case_types)]
pub type ConcatKDF_SHA3_224 = ConcatKDF<SHA3_224>;
/// The concatenation KDF over SHA3-256.
#[allow(non_camel_case_types)]
pub type ConcatKDF_SHA3_256 = ConcatKDF<SHA3_256>;
/// The concatenation KDF over SHA3-384.
#[allow(non_camel_case_types)]
pub type ConcatKDF_SHA3_384 = ConcatKDF<SHA3_384>;
/// The concatenation KDF over SHA3-512.
#[allow(non_camel_case_types)]
pub type ConcatKDF_SHA3_512 = ConcatKDF<SHA3_512>;

/// The concatenation KDF (SP 800-56C Rev. 2 Section 4.1, Option 1) over the hash `H`. It holds
/// no state: the derivation is [`ConcatKDF::derive_out`], which the [`KDF`] trait's methods run.
pub struct ConcatKDF<H: ConcatKDFParams> {
    _hash: PhantomData<H>,
}

// Written out rather than derived: a derive would demand `H: Clone` of the hash marker.
impl<H: ConcatKDFParams> Clone for ConcatKDF<H> {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl<H: ConcatKDFParams> Default for ConcatKDF<H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<H: ConcatKDFParams> Algorithm for ConcatKDF<H> {
    const ALG_NAME: &'static str = H::CONCAT_KDF_ALG_NAME;
    /// The hash's: the KDF cannot exceed what its hash provides.
    const MAX_SECURITY_STRENGTH: SecurityStrength = H::MAX_SECURITY_STRENGTH;
}

/// The KDF is made from nothing but its hash, which the type names, so it describes itself:
/// the engine is a fresh instance.
impl<H: ConcatKDFParams> KdfDescription for ConcatKDF<H> {
    type Engine = Self;

    fn engine(&self) -> Result<Self, KDFError> {
        Ok(Self::new())
    }
}

impl<H: ConcatKDFParams> ConcatKDF<H> {
    /// The most bytes one derivation produces: `reps` hash outputs with `reps` at most
    /// `2^32 - 1` (SP 800-56C Rev. 2 Section 4.1 step 2), or `usize::MAX` where that does not fit.
    pub const MAX_LEN: usize = {
        let max = H::OUTPUT_LEN as u128 * 0xFFFF_FFFF;
        if max > usize::MAX as u128 { usize::MAX } else { max as usize }
    };

    /// A KDF instance, for the [`KDF`] trait; [`ConcatKDF::derive_out`] needs none.
    pub fn new() -> Self {
        Self { _hash: PhantomData }
    }

    /// SP 800-56C Rev. 2 Section 4.1, Option 1: `L = 8 * len` bits of keying material from the
    /// shared secret `Z` and `FixedInfo`, written to the front of `dkm`, which is zeroized first.
    /// Returns the number of bytes written, `len`.
    ///
    /// The output is typed as the crate docs' Security Considerations say: `CryptographicRandom`
    /// at the least of `z`'s, the hash's and the length's strengths when `z` is full-entropy
    /// material of at least half a hash output, else `Unknown`.
    ///
    /// # Errors
    /// [`KDFError::InvalidLength`] if `len` is zero (step 1), exceeds [`ConcatKDF::MAX_LEN`]
    /// (step 2), or exceeds `dkm`'s capacity; `dkm` is left zeroized.
    pub fn derive_out(
        z: &(impl KeyMaterialTrait + ?Sized),
        fixed_info: &[u8],
        len: usize,
        dkm: &mut (impl KeyMaterialTrait + ?Sized),
    ) -> Result<usize, KDFError> {
        Self::derive_keys_out(&[z], fixed_info, len, dkm)
    }

    /// [`ConcatKDF::derive_out`] with `Z` the concatenation of `keys`, as the [`KDF`] trait's
    /// multi-key methods define their input: a bare concatenation with no length framing, which
    /// is SP 800-56C Rev. 2 Section 2's hybrid `Z' = Z || T` only when the parties have agreed
    /// the format and length of `T`, as that section requires and the caller is left to meet.
    /// The entropy credited is the sum of the full-entropy keys', at the strongest's strength.
    fn derive_keys_out<K: KeyMaterialTrait + ?Sized>(
        keys: &[&K],
        fixed_info: &[u8],
        len: usize,
        dkm: &mut (impl KeyMaterialTrait + ?Sized),
    ) -> Result<usize, KDFError> {
        const { assert!(H::OUTPUT_LEN <= MAX_HASH_OUTPUT_LEN) };
        const { assert!(H::OUTPUT_LEN > 0) };

        // The `_out` rule: nothing stale survives, whichever way this returns.
        dkm.zeroize();

        // Step 1: L > 0, else an error. A derivation from no keys is refused too: its output
        // would be a function of FixedInfo alone. A key of length zero is not refused: the
        // trait derives from `Zeroized` and empty material and types the output `Unknown`.
        if len == 0 {
            return Err(KDFError::InvalidLength("a zero-length derivation is refused"));
        }
        if keys.is_empty() {
            return Err(KDFError::InvalidLength("a derivation from no keys is refused"));
        }
        // Step 2: reps = ceil(L / H_outputBits) must not exceed 2^32 - 1, which keeps the counter
        // in four bytes; and the caller's buffer must hold L.
        if len > Self::MAX_LEN {
            return Err(KDFError::InvalidLength("reps must not exceed 2^32 - 1"));
        }
        if len > dkm.capacity() {
            return Err(KDFError::InvalidLength("the output buffer cannot hold L bits"));
        }

        // What the output can claim: the full-entropy keys' bytes count towards seeding, their
        // strongest strength towards the output's.
        let mut credited = 0usize;
        let mut strength = SecurityStrength::None;
        for key in keys {
            // [`KDF`]'s rule: a full-entropy key with a strength credits its bytes; one with
            // none (a `SharedSecret` whose producer stated nothing) credits nothing.
            if key.is_full_entropy() && key.security_strength() != SecurityStrength::None {
                credited = credited.saturating_add(key.key_len());
                strength = *max(&strength, &key.security_strength());
            }
        }

        // Steps 3 to 8. K(i) is keying material, so its block zeroizes on drop. Each block is
        // written to `dkm` as it is made; nothing after the checks above can fail, so the whole
        // of DerivedKeyingMaterial exists before the caller can read any of it (Section 4.1's
        // note), and step 5's Result is `dkm` itself.
        let mut block = Secret::<[u8; MAX_HASH_OUTPUT_LEN]>::new();
        let reps = len.div_ceil(H::OUTPUT_LEN);
        let labelled = do_hazardous_operations(dkm, |dkm| {
            let out = dkm.ref_to_bytes_mut()?;
            let mut written = 0usize;
            // Step 3: counter = 0x00000000; step 6: for i = 1 to reps, step 6.1 incrementing it
            // first, so K(1) is computed under counter 0x00000001.
            for counter in 1..=reps as u32 {
                // Step 6.2: K(i) = H(counter || Z || FixedInfo); Z is the keys in order.
                let mut hash = H::default();
                hash.do_update(&counter.to_be_bytes());
                for key in keys {
                    hash.do_update(key.ref_to_bytes());
                }
                hash.do_update(fixed_info);
                let block_len = hash.do_final_out(&mut block[..H::OUTPUT_LEN]);
                // Steps 6.3 and 7: Result(i) = Result(i - 1) || K(i), and DerivedKeyingMaterial
                // its leftmost L bits.
                let take = *min(&block_len, &(len - written));
                out[written..written + take].copy_from_slice(&block[..take]);
                written += take;
            }
            dkm.set_key_len(len)?;
            if credited >= H::OUTPUT_LEN / 2 {
                dkm.set_key_type(KeyType::CryptographicRandom)?;
                let by_len = SecurityStrength::from_bytes(len);
                dkm.set_security_strength(*min(min(&strength, &H::MAX_SECURITY_STRENGTH), &by_len))
            } else {
                dkm.set_key_type(KeyType::Unknown)?;
                dkm.set_security_strength(SecurityStrength::None)
            }
        });
        // The blocks are in `dkm` by now, so the `_out` rule's promise for the error path is kept
        // here, although no setter after the loop fails on a buffer that passed the checks above.
        if labelled.is_err() {
            dkm.zeroize();
        }
        labelled?;
        Ok(len)
    }
}

impl<H: ConcatKDFParams> KDF for ConcatKDF<H> {
    /// [`ConcatKDF::derive_out`], `FixedInfo` being `fixed_info`.
    fn derive_key_out(
        &self,
        ikm: &dyn KeyMaterialTrait,
        fixed_info: &[u8],
        len: usize,
        output_key: &mut dyn KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        Self::derive_out(ikm, fixed_info, len, output_key)
    }

    /// [`ConcatKDF::derive_out`] with `Z` the bare concatenation of `ikms`, with no length framing
    /// (this library's convention for the multi-key forms); an empty `ikms` is
    /// [`KDFError::InvalidLength`].
    fn derive_key_from_multiple_out(
        &self,
        ikms: &[&dyn KeyMaterialTrait],
        fixed_info: &[u8],
        len: usize,
        output_key: &mut dyn KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        Self::derive_keys_out(ikms, fixed_info, len, output_key)
    }
}
