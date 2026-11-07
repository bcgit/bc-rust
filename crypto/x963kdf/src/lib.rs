//! The ANSI X9.63 key derivation function, as SEC 1 v2 Section 3.6.1 specifies it: keying data
//! `K = K_1 || K_2 || ...` truncated to `keydatalen` octets, with `K_i = Hash(Z || Counter ||
//! [SharedInfo])` and `Counter` a 4-octet big-endian count from 1. It is the KDF of SEC 1's
//! elliptic curve Diffie-Hellman scheme (Section 6.1), turning the shared secret `Z` of a key
//! agreement into keying data, with `SharedInfo` the context both parties agree on.
//!
//! [`X963KDF<H>`] is the function over any hash that implements [`X963KDFParams`];
//! [`X963KDF_SHA224`], [`X963KDF_SHA256`], [`X963KDF_SHA384`] and [`X963KDF_SHA512`] are the
//! instantiations over the SHA-2 hashes SEC 1 Section 3.5 lists. [`X963KdfParams`] carries the
//! `SharedInfo` as the parameters a key-agreement role impl is made from, as `HkdfParams` does for
//! HKDF, so that `sk.agree(&peer_pk, X963KdfParams::<SHA256>::new(shared_info))` is the agreement
//! with the KDF applied.
//!
//! # Usage Examples
//!
//! Keying data of any length from a shared secret, [`X963KDF::derive_out`]:
//!
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
//! use bouncycastle_x963kdf::X963KDF_SHA256;
//!
//! // The Z of a key agreement, typed for a KDF; here stand-in bytes.
//! let z = KeyMaterial::<32>::from_bytes_as_type(&[0x5A; 32], KeyType::SharedSecret).unwrap();
//!
//! let mut keying_data = KeyMaterial::<48>::new();
//! let written = X963KDF_SHA256::derive_out(&z, b"example protocol v1", 48, &mut keying_data).unwrap();
//! assert_eq!(written, 48);
//! assert_eq!(keying_data.key_type(), KeyType::CryptographicRandom);
//! ```
//!
//! Through the [`KDF`] trait, which fixes the output at one hash output (`derive_key`) or fills
//! the buffer it is given (`derive_key_out`), with `SharedInfo` as the additional input:
//!
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
//! use bouncycastle_core::traits::KDF;
//! use bouncycastle_x963kdf::X963KDF_SHA256;
//!
//! let z = KeyMaterial::<32>::from_bytes_as_type(&[0x5A; 32], KeyType::SharedSecret).unwrap();
//! let key = X963KDF_SHA256::new().derive_key(&z, b"example protocol v1").unwrap();
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
//!   buffer; step 1's bound on `|Z| + |SharedInfo| + 4` is the hash's maximum message length,
//!   which the SHA-2 hashes put far beyond any slice this function can be handed, so it is not
//!   checked.

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

use bouncycastle_core::errors::KDFError;
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::key_material::{KeyMaterial512, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, HashAlgParams, HashOneShot, KDF};
use bouncycastle_sha2::{SHA224, SHA256, SHA384, SHA512};
use bouncycastle_utils::secret::Secret;
use bouncycastle_utils::{max, min};
use core::marker::PhantomData;

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_core::key_material::KeyMaterial;
// End imports needed for docs

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
/// derivation is [`X963KDF::derive_out`], and the [`KDF`] trait's methods run it at the trait's
/// lengths.
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
        okm: &mut impl KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        Self::derive_keys_out(&[z], shared_info, key_data_len, okm)
    }

    /// [`X963KDF::derive_out`] with `Z` the concatenation of `keys`, for a hybrid shared secret
    /// (`Z || T`, as SP 800-56C Rev. 2 Section 2 allows) and the [`KDF`] trait's multi-key
    /// methods; the entropy credited is the sum of the full-entropy keys', at the strongest's
    /// strength.
    fn derive_keys_out<K: KeyMaterialTrait + ?Sized>(
        keys: &[&K],
        shared_info: &[u8],
        key_data_len: usize,
        okm: &mut impl KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        const { assert!(H::OUTPUT_LEN <= MAX_HASH_OUTPUT_LEN) };
        const { assert!(H::OUTPUT_LEN > 0) };

        // The `_out` rule: nothing stale survives, whichever way this returns.
        okm.zeroize();

        // A zero-length derivation is refused, as every KDF's is ([`KDF`]'s docs).
        if key_data_len == 0 {
            return Err(KDFError::InvalidLength("a zero-length derivation is refused"));
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
        do_hazardous_operations(okm, |okm| {
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
        })?;
        Ok(key_data_len)
    }
}

impl<H: X963KDFParams> KDF for X963KDF<H> {
    /// One hash output of keying data, `SharedInfo` being `additional_input`.
    fn derive_key(
        self,
        key: &impl KeyMaterialTrait,
        additional_input: &[u8],
    ) -> Result<alloc::boxed::Box<dyn KeyMaterialTrait>, KDFError> {
        let mut output_key = KeyMaterial512::new();
        Self::derive_out(key, additional_input, H::OUTPUT_LEN, &mut output_key)?;
        Ok(alloc::boxed::Box::new(output_key))
    }

    /// Fills `output_key` to its capacity, `SharedInfo` being `additional_input`.
    fn derive_key_out(
        self,
        key: &impl KeyMaterialTrait,
        additional_input: &[u8],
        output_key: &mut impl KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        Self::derive_out(key, additional_input, output_key.capacity(), output_key)
    }

    /// As [`KDF::derive_key`] with `Z` the concatenation of `keys`.
    fn derive_key_from_multiple(
        self,
        keys: &[&impl KeyMaterialTrait],
        additional_input: &[u8],
    ) -> Result<alloc::boxed::Box<dyn KeyMaterialTrait>, KDFError> {
        let mut output_key = KeyMaterial512::new();
        Self::derive_keys_out(keys, additional_input, H::OUTPUT_LEN, &mut output_key)?;
        Ok(alloc::boxed::Box::new(output_key))
    }

    /// As [`KDF::derive_key_out`] with `Z` the concatenation of `keys`.
    fn derive_key_from_multiple_out(
        self,
        keys: &[&impl KeyMaterialTrait],
        additional_input: &[u8],
        output_key: &mut impl KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        Self::derive_keys_out(keys, additional_input, output_key.capacity(), output_key)
    }
}

extern crate alloc;

/// The `SharedInfo` an algorithm that derives its output through the X9.63 KDF over `H` is made
/// from, borrowed from the caller for `'p`, with the hash as the type's parameter: as the
/// `Params` of a key-agreement role impl, `X963KdfParams::<SHA256>::new(shared_info)` selects
/// the algorithm at the call. `Copy`, so one value serves every construction on both sides.
pub struct X963KdfParams<'p, H: X963KDFParams> {
    shared_info: &'p [u8],
    _hash: PhantomData<H>,
}

impl<'p, H: X963KDFParams> X963KdfParams<'p, H> {
    /// The `SharedInfo` of SEC 1 Section 3.6.1, which may be empty.
    pub fn new(shared_info: &'p [u8]) -> Self {
        Self { shared_info, _hash: PhantomData }
    }

    /// The `SharedInfo`.
    pub fn shared_info(&self) -> &'p [u8] {
        self.shared_info
    }
}

// Written out rather than derived: a derive would demand `H: Copy` of the hash marker.
impl<H: X963KDFParams> Clone for X963KdfParams<'_, H> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<H: X963KDFParams> Copy for X963KdfParams<'_, H> {}
