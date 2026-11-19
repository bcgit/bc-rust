//! The ANSI X9.63 key derivation function, as SEC 1 v2 Section 3.6.1 specifies it: keying data
//! `K = K_1 || K_2 || ...` truncated to `keydatalen` octets, with `K_i = Hash(Z || Counter ||
//! [SharedInfo])` and `Counter` a 4-octet big-endian count from 1. It is the KDF of SEC 1's
//! elliptic curve Diffie-Hellman scheme (Section 6.1), turning the shared secret `Z` of a key
//! agreement into keying data, with `SharedInfo` the context both parties agree on.
//!
//! [`X963KDF<H>`] is the function over any hash that implements [`X963KDFParams`];
//! [`X963KDF_SHA224`], [`X963KDF_SHA256`], [`X963KDF_SHA384`] and [`X963KDF_SHA512`] are the
//! instantiations over the SHA-2 hashes SEC 1 Section 3.5 lists. An instance and the `SharedInfo`
//! are the `bouncycastle_core::kdf_params::KdfParams` a key-agreement role impl is made from, so
//! that `sk.agree(&peer_pk, KdfParams::new(&X963KDF_SHA256::new(), shared_info))` is the agreement
//! with the KDF applied.
//!
//! # Usage Examples
//!
//! Keying data of any length from a shared secret, [`X963KDF::derive_out`]:
//!
//! ```
//! use bouncycastle_core::hazmat::do_hazardous_operations;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
//! use bouncycastle_core::security_strength::SecurityStrength;
//! use bouncycastle_x963kdf::X963KDF_SHA256;
//!
//! // The Z of a key agreement, typed for a KDF at the scheme's strength, which its producer
//! // states (a `SharedSecret`'s length says nothing about its entropy); here stand-in bytes.
//! let mut z = KeyMaterial::<32>::from_bytes_as_type(&[0x5A; 32], KeyType::SharedSecret).unwrap();
//! do_hazardous_operations(&mut z, |z| z.set_security_strength(SecurityStrength::_128bit)).unwrap();
//!
//! let mut keying_data = KeyMaterial::<48>::new();
//! let written = X963KDF_SHA256::derive_out(&z, b"example protocol v1", 48, &mut keying_data).unwrap();
//! assert_eq!(written, 48);
//! assert_eq!(keying_data.key_type(), KeyType::CryptographicRandom);
//! ```
//!
//! Through the [`KDF`] trait, with `SharedInfo` as the fixed info and the length asked for:
//!
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
//! use bouncycastle_core::traits::KDF;
//! use bouncycastle_x963kdf::X963KDF_SHA256;
//!
//! let z = KeyMaterial::<32>::from_bytes_as_type(&[0x5A; 32], KeyType::SharedSecret).unwrap();
//! let key = X963KDF_SHA256::new().derive_key(&z, b"example protocol v1", 32).unwrap();
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
//! - `SharedInfo` is context, not keying material: it is not credited, and both parties must
//!   supply the same octets. There is no salt; a fresh `Z` per agreement is what makes the output
//!   fresh.
//! - `keydatalen` must be below `hashlen * (2^32 - 1)` (Section 3.6.1 step 2) and fit the output
//!   buffer. Step 1's bound, `|Z| + |SharedInfo| + 4 < hashmaxlen`, is not checked: hashmaxlen
//!   is `2^61 - 1` octets for SHA-224 and SHA-256 and `2^125 - 1` for SHA-384 and SHA-512
//!   (Section 3.5), and no buffer this library is given in practice comes near the former,
//!   though a 64-bit slice could in principle.
//! - A derivation from no keys is refused, as the [`KDF`] trait says; a key of length zero, like a
//!   `Zeroized` one, is derived from (the output is then `Hash(Counter || SharedInfo)`) and
//!   yields `Unknown` output with no strength, the trait's rule for material it cannot credit.

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

use bouncycastle_core::errors::KDFError;
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::kdf_params::KdfDescription;
use bouncycastle_core::key_material::{KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, HashAlgParams, HashOneShot, KDF};
use bouncycastle_sha2::{SHA224, SHA256, SHA384, SHA512};
use bouncycastle_utils::secret::Secret;
use bouncycastle_utils::{max, min};
use core::marker::PhantomData;

/// The largest hash output this crate's block buffer holds: 64 bytes, SHA-512's. A hash with a
/// longer output is refused at compile time.
pub const MAX_HASH_OUTPUT_LEN: usize = 64;

/// A hash the KDF is instantiated over: [`HashOneShot`] and [`HashAlgParams`], plus the name the
/// instantiation reports. Implemented for the SHA-2 hashes of SEC 1 Section 3.5.
pub trait X963KDFParams: HashOneShot + HashAlgParams {
    /// The instantiation's name, as reported by `Algorithm::ALG_NAME`.
    const X963KDF_ALG_NAME: &'static str;
}

/// The name of the KDF over SHA-224.
pub const X963KDF_SHA224_NAME: &str = "X963KDF-SHA224";
/// The name of the KDF over SHA-256.
pub const X963KDF_SHA256_NAME: &str = "X963KDF-SHA256";
/// The name of the KDF over SHA-384.
pub const X963KDF_SHA384_NAME: &str = "X963KDF-SHA384";
/// The name of the KDF over SHA-512.
pub const X963KDF_SHA512_NAME: &str = "X963KDF-SHA512";

impl X963KDFParams for SHA224 {
    const X963KDF_ALG_NAME: &'static str = X963KDF_SHA224_NAME;
}
impl X963KDFParams for SHA256 {
    const X963KDF_ALG_NAME: &'static str = X963KDF_SHA256_NAME;
}
impl X963KDFParams for SHA384 {
    const X963KDF_ALG_NAME: &'static str = X963KDF_SHA384_NAME;
}
impl X963KDFParams for SHA512 {
    const X963KDF_ALG_NAME: &'static str = X963KDF_SHA512_NAME;
}

/// The ANSI X9.63 KDF over SHA-224.
#[allow(non_camel_case_types)]
pub type X963KDF_SHA224 = X963KDF<SHA224>;
/// The ANSI X9.63 KDF over SHA-256.
#[allow(non_camel_case_types)]
pub type X963KDF_SHA256 = X963KDF<SHA256>;
/// The ANSI X9.63 KDF over SHA-384.
#[allow(non_camel_case_types)]
pub type X963KDF_SHA384 = X963KDF<SHA384>;
/// The ANSI X9.63 KDF over SHA-512.
#[allow(non_camel_case_types)]
pub type X963KDF_SHA512 = X963KDF<SHA512>;

/// The ANSI X9.63 KDF (SEC 1 v2 Section 3.6.1) over the hash `H`. It holds no state: the
/// derivation is [`X963KDF::derive_out`], which the [`KDF`] trait's methods run.
pub struct X963KDF<H: X963KDFParams> {
    _hash: PhantomData<H>,
}

// Written out rather than derived: a derive would demand `H: Clone` of the hash marker.
impl<H: X963KDFParams> Clone for X963KDF<H> {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl<H: X963KDFParams> Default for X963KDF<H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<H: X963KDFParams> Algorithm for X963KDF<H> {
    const ALG_NAME: &'static str = H::X963KDF_ALG_NAME;
    /// The hash's: the KDF cannot exceed what its hash provides.
    const MAX_SECURITY_STRENGTH: SecurityStrength = H::MAX_SECURITY_STRENGTH;
}

/// The KDF is made from nothing but its hash, which the type names, so it describes itself:
/// the engine is a fresh instance.
impl<H: X963KDFParams> KdfDescription for X963KDF<H> {
    type Engine = Self;

    fn engine(&self) -> Result<Self, KDFError> {
        Ok(Self::new())
    }
}

impl<H: X963KDFParams> X963KDF<H> {
    /// A KDF instance, for the [`KDF`] trait; [`X963KDF::derive_out`] needs none.
    pub fn new() -> Self {
        Self { _hash: PhantomData }
    }

    /// SEC 1 v2 Section 3.6.1: `keydatalen` octets of keying data from the shared secret `Z` and
    /// `SharedInfo`, written to the front of `okm`, which is zeroized first. Returns the number
    /// of bytes written, `key_data_len`.
    ///
    /// The output is typed as the crate docs' Security Considerations say: `CryptographicRandom`
    /// at the least of `z`'s, the hash's and the length's strengths when `z` is full-entropy
    /// material of at least half a hash output, else `Unknown`.
    ///
    /// # Errors
    /// [`KDFError::InvalidLength`] if `key_data_len` is not below `hashlen * (2^32 - 1)`
    /// (Section 3.6.1 step 2), is zero, or exceeds `okm`'s capacity; `okm` is left zeroized.
    pub fn derive_out(
        z: &(impl KeyMaterialTrait + ?Sized),
        shared_info: &[u8],
        key_data_len: usize,
        okm: &mut (impl KeyMaterialTrait + ?Sized),
    ) -> Result<usize, KDFError> {
        Self::derive_keys_out(&[z], shared_info, key_data_len, okm)
    }

    /// [`X963KDF::derive_out`] with `Z` the concatenation of `keys`, as the [`KDF`] trait's
    /// multi-key methods define their input: this library's convention, a bare concatenation
    /// with no length framing, since SEC 1 specifies the KDF over one `Z`. The entropy credited
    /// is the sum of the full-entropy keys', at the strongest's strength.
    fn derive_keys_out<K: KeyMaterialTrait + ?Sized>(
        keys: &[&K],
        shared_info: &[u8],
        key_data_len: usize,
        okm: &mut (impl KeyMaterialTrait + ?Sized),
    ) -> Result<usize, KDFError> {
        const { assert!(H::OUTPUT_LEN <= MAX_HASH_OUTPUT_LEN) };
        const { assert!(H::OUTPUT_LEN > 0) };

        // The `_out` rule: nothing stale survives, whichever way this returns.
        okm.zeroize();

        // A zero-length derivation is refused, as every KDF's is ([`KDF`]'s docs), and so is one
        // from no keys, whose output would be a function of the SharedInfo alone. A key of
        // length zero is not refused: the trait derives from `Zeroized` and empty material and
        // types the output `Unknown`, which the accounting below does.
        if key_data_len == 0 {
            return Err(KDFError::InvalidLength("a zero-length derivation is refused"));
        }
        if keys.is_empty() {
            return Err(KDFError::InvalidLength("a derivation from no keys is refused"));
        }
        // Step 2: keydatalen < hashlen * (2^32 - 1), which is what keeps the counter in four
        // octets; and the caller's buffer must hold it.
        if key_data_len as u128 >= H::OUTPUT_LEN as u128 * 0xFFFF_FFFF {
            return Err(KDFError::InvalidLength("keydatalen must be below hashlen * (2^32 - 1)"));
        }
        if key_data_len > okm.capacity() {
            return Err(KDFError::InvalidLength("the output buffer cannot hold keydatalen bytes"));
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

        // Steps 3 to 5. K_i is keying material, so its block zeroizes on drop.
        let mut block = Secret::<[u8; MAX_HASH_OUTPUT_LEN]>::new();
        let blocks = key_data_len.div_ceil(H::OUTPUT_LEN);
        let labelled = do_hazardous_operations(okm, |okm| {
            let out = okm.ref_to_bytes_mut()?;
            let mut written = 0usize;
            // Step 3: Counter starts at 00000001; step 4: for i = 1 to ceil(keydatalen / hashlen).
            for counter in 1..=blocks as u32 {
                // Step 4.1: K_i = Hash(Z || Counter || [SharedInfo]); Z is the keys in order.
                let mut hash = H::default();
                for key in keys {
                    hash.do_update(key.ref_to_bytes());
                }
                hash.do_update(&counter.to_be_bytes());
                hash.do_update(shared_info);
                let len = hash.do_final_out(&mut block[..H::OUTPUT_LEN]);
                // Step 5: K is the leftmost keydatalen octets of K_1 || K_2 || ...
                let take = *min(&len, &(key_data_len - written));
                out[written..written + take].copy_from_slice(&block[..take]);
                written += take;
                // Step 4.2: increment Counter (the loop's).
            }
            okm.set_key_len(key_data_len)?;
            if credited >= H::OUTPUT_LEN / 2 {
                okm.set_key_type(KeyType::CryptographicRandom)?;
                let by_len = SecurityStrength::from_bytes(key_data_len);
                okm.set_security_strength(*min(min(&strength, &H::MAX_SECURITY_STRENGTH), &by_len))
            } else {
                okm.set_key_type(KeyType::Unknown)?;
                okm.set_security_strength(SecurityStrength::None)
            }
        });
        // The blocks are in `okm` by now, so the `_out` rule's promise for the error path is kept
        // here, although no setter after the loop fails on a buffer that passed the checks above.
        if labelled.is_err() {
            okm.zeroize();
        }
        labelled?;
        Ok(key_data_len)
    }
}

impl<H: X963KDFParams> KDF for X963KDF<H> {
    /// [`X963KDF::derive_out`], `SharedInfo` being `fixed_info`.
    fn derive_key_out(
        &self,
        ikm: &dyn KeyMaterialTrait,
        fixed_info: &[u8],
        len: usize,
        output_key: &mut dyn KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        Self::derive_out(ikm, fixed_info, len, output_key)
    }

    /// [`X963KDF::derive_out`] with `Z` the bare concatenation of `ikms`, with no length framing
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
