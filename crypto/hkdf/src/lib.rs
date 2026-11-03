//! The generic HMAC-based Extract-and-Expand Key Derivation Function (HKDF) construction, as per
//! RFC 5869, which NIST SP 800-56Cr2 Section 5.1 describes as "a version of the above
//! extraction-then-expansion key-derivation procedure using HMAC for both the extraction and
//! expansion steps".
//!
//! This is a utility crate and is not intended to be used directly. It provides [`HKDF`] -- the
//! construction, generic over any hash that implements [`HMACParams`], the extension point through
//! which a hash declares the metadata from which the HMAC and HKDF instances are built.
//! The library provides the following concrete instantiations of HKDF:
//!
//! | Hash family | Instantiations                                                           |
//! |-------------|--------------------------------------------------------------------------|
//! | SHA-2       | `bouncycastle_sha2::hkdf` -- `HKDF_SHA256`, `HKDF_SHA384`, `HKDF_SHA512` |
//!
//! # Instantiating HKDF over a hash
//!
//! HKDF uses HMAC as its underlying primitive, so it works with exactly the hashes HMAC works with:
//! [`HKDF`] needs [`HMACParams`], which also carries the HKDF name ([`HMACParams::HKDF_ALG_NAME`]).
//! There is no separate HKDF params trait -- HKDF has no per-hash OIDs -- so an instantiation is just
//! a type alias plus, by convention, a suspended-state length.
//!
//! What the alias has to supply is [`HKDF`]'s two const parameters:
//!
//! * `HASH_STATE_LEN` -- the hash's own suspended-state length, i.e. the `N` in
//!   `H: Suspendable<N>`.
//! * `HKDF_STATE_LEN` -- this HKDF's suspended-state length, which is always `HASH_STATE_LEN + 14`.
//!
//! Both are const parameters of the struct rather than being derived from the hash because
//! [`SuspendableKeyed`] takes its length as a const generic, and naming `HASH_STATE_LEN + 14` in that
//! position requires the unstable `generic_const_exprs` feature. Carrying both on the struct is what
//! lets a single blanket [`SuspendableKeyed`] impl serve every hash while still pinning the two
//! lengths together per concrete type. They are given no defaults on purpose: there is no value that
//! is correct for more than one hash, so each instantiation states them. Getting the pair wrong is a
//! compile error at the point of use, not a silent mis-sizing -- the blanket impl only applies when
//! `HASH_STATE_LEN` really is the hash's `Suspendable` length.
//!
//! One limitation to be aware of when instantiating over a hash of your own: the extract phase
//! writes its pseudorandom key into a [`MAX_HMAC_OUTPUT_LEN`]-byte buffer, so the hash's output
//! length must not exceed that (64 bytes). See the note on that constant.
//!
//! ## Worked example
//!
//! As an example, the `bouncycastle-sha2` crate instantiates HKDF-SHA256, HKDF-SHA384 and
//! HKDF-SHA512 this way. The library does not ship HKDF-SHA224, so that makes a good illustration of
//! adding one -- for a hash in this library or for a hash of your own, the shape is identical:
//!
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::traits::{KDF, SuspendableKeyed};
//! use bouncycastle_hkdf::HKDF;
//! use bouncycastle_sha2::{SHA224, SUSPENDED_SHA256_STATE_LEN};
//!
//! // SHA-224 is a member of the SHA-256 family, so its suspended state is the SHA-256 one.
//! const SUSPENDED_HKDF_SHA224_STATE_LEN: usize = SUSPENDED_SHA256_STATE_LEN + 14;
//!
//! #[allow(non_camel_case_types)]
//! pub type HKDF_SHA224 =
//!     HKDF<SHA224, SUSPENDED_SHA256_STATE_LEN, SUSPENDED_HKDF_SHA224_STATE_LEN>;
//!
//! pub const HKDF_SHA224_NAME: &str = "HKDF-SHA224";
//!
//! // That is all it takes: the KDF trait and the extract/expand API are now available.
//! let ikm = KeyMaterial256::from_bytes_as_type(
//!             b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
//!             KeyType::Seed).unwrap();
//! let okm = HKDF_SHA224::new().derive_key(&ikm, b"extra input").unwrap();
//!
//! // ...and so is suspend/resume, because SHA-224 implements Suspendable and the two const
//! // parameters above agree.
//! let salt = KeyMaterial256::from_bytes_as_type(
//!             b"\x0f\x0e\x0d\x0c\x0b\x0a\x09\x08\x07\x06\x05\x04\x03\x02\x01\x00",
//!             KeyType::MACKey).unwrap();
//! let mut hkdf = HKDF_SHA224::new();
//! hkdf.do_extract_init(&salt).unwrap();
//! hkdf.do_extract_update_bytes(b"part 1").unwrap();
//! let suspended = hkdf.suspend();
//! assert_eq!(suspended.len(), SUSPENDED_HKDF_SHA224_STATE_LEN);
//!
//! let mut resumed = HKDF_SHA224::from_suspended(suspended, &salt).unwrap();
//! resumed.do_extract_update_bytes(b"part 2").unwrap();
//! let _prk = resumed.do_extract_final().unwrap();
//! ```
//!
//! # 🚨 Security Considerations 🚨
//!
//! These apply to every instantiation; `bouncycastle_sha2::hkdf` repeats the ones that matter most in
//! day-to-day use.
//!
//! * HKDF is keyed by its `salt`, which keys the extract-phase HMAC. The salt is deliberately
//!   excluded from the suspended state and must be re-supplied on resume; resuming with a different
//!   salt cannot be detected and silently produces a different PRK.
//! * Entropy is credited only for input supplied via [`HKDF::do_extract_update_key`], and for a
//!   salt typed [`KeyType::MACKey`], which is how a caller marks it as the secret salt of SP
//!   800-56Cr2 Section 5.1. A salt of any other type is RFC 5869 Section 2.2's "non-secret random
//!   value" and credits nothing: anyone who knows it can compute the PRK from the IKM. Bytes supplied
//!   via [`HKDF::do_extract_update_bytes`] are treated as uncredited context, so a PRK derived only
//!   from raw bytes will not be tagged as full-entropy key material even if those bytes were random.
//!   [`HKDF::do_extract_update_key`] is rejected after the first call to
//!   [`HKDF::do_extract_update_bytes`], so that the input matches the ordering of the key-extraction
//!   method in NIST SP 800-133r2 Section 6.3, `K = T(HMAC-hash(salt, K1 || ... || Kn || D1 || ...
//!   || Dm), kLen)`, in which the component keys precede the other data. Note (h) of that method
//!   permits other orderings, so this is a deliberate restriction of this API rather than a
//!   requirement of the specification.
//! * HKDF stretches key material but does not create entropy. The output key inherits the
//!   [`SecurityStrength`] of its inputs: 200 bytes expanded from a 128-bit seed is 200 bytes at a
//!   128-bit security level, not a 1600-bit key.
//! * RFC 5869 Section 3.1 recommends a random salt where one is available. SP 800-56Cr2 permits an
//!   all-zero salt, and the extract phase accepts one, but a salt that the caller believes to be
//!   random and is not provides none of the benefit the recommendation is aimed at.
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

use bouncycastle_core::errors::{KDFError, KeyMaterialError, MACError, SuspendableError};
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::key_material::{
    KeyMaterial, KeyMaterial0, KeyMaterial512, KeyMaterialTrait, KeyType,
};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{FromAnyKeyMaterial, MacGenerationKey};
use bouncycastle_core::traits::{Algorithm, KDF, MAC, Suspendable, SuspendableKeyed};
use bouncycastle_hmac::hazmat as hmac_hazmat;
use bouncycastle_hmac::{HMACParams, HmacKey, LARGEST_HASHER_BLOCK_LEN};
use bouncycastle_utils::secret::Secret;
use bouncycastle_utils::suspendable_state::{add_lib_ver, bounded_usize, check_lib_ver};
use bouncycastle_utils::{max, min};
use std::marker::PhantomData;
// Imports needed only for docs
#[allow(unused_imports)]
use bouncycastle_core::traits::XOF;
// end doc-only imports

/*** Constants ***/
/// The size of the output key material from the HKDF-Extract phase `prk`, in bytes.
/// This has been sized so that the output KeyMaterial has enough capacity to accommodate the
/// underlying hash primitive with the largest output size.
/// If the given hash function has a smaller output size, then the output KeyMaterial will be
/// under-full (ie have a key_len that does not use its full capacity).
/// TODO: This is a dirty dirty hack because correctly sizing the output key
///       really requires the generic_const_exprs feature, which is currently only available on
///       nightly Rust, and not on stable. Once they merge that feature, we will be able to get rid of this
///       and declare `prk: &mut KeyMaterial<H::OUTPUT_LEN>` instead of this hack.
pub const MAX_HMAC_OUTPUT_LEN: usize = 64;

/*** Types ***/
/// The generic HKDF construction (RFC 5869).
///
/// Can be instantiated with hash functions other than the ones provided by this library (even custom
/// ones). The concrete instantiations over the library's own hashes, along with their name constants,
/// live in the hash crates -- see `bouncycastle_sha2::hkdf::HKDF_SHA256` and
/// `bouncycastle_sha2::hkdf::HKDF_SHA512`.
///
/// # Const parameters
///
/// `HASH_STATE_LEN` is the suspended-state length of `H` (as in `H: Suspendable<HASH_STATE_LEN>`) and
/// `HKDF_STATE_LEN` is this HKDF's own suspended-state length, which is always `HASH_STATE_LEN + 14`
/// (see the [`SuspendableKeyed`] impl below for the layout that accounts for those 14 bytes).
///
/// Both are const parameters of the struct rather than being derived from `H` because `SuspendableKeyed`
/// takes its length as a const generic, and naming `HASH_STATE_LEN + 14` in that position requires
/// the `generic_const_exprs` feature. Carrying both on the struct is what lets a single blanket
/// `SuspendableKeyed` impl serve every hash while still pinning the two lengths together per concrete
/// type. They are deliberately given no defaults: there is no value that is correct for more than one
/// hash, so each instantiation must state them.
/// todo: once rust stabilizes generic_const_exprs, delete both const parameters and write the impl as
///     `SuspendableKeyed<{HASH_STATE_LEN + 14}>` over `H: Suspendable<HASH_STATE_LEN>`.
#[derive(Clone)]
pub struct HKDF<H: HMACParams, const HASH_STATE_LEN: usize, const HKDF_STATE_LEN: usize> {
    // Optional because the extract-phase HMAC cannot be keyed until the salt is provided.
    // None must correspond to a state of Uninitialized.
    hmac: Option<HkdfExtract<H>>,
    entropy: HkdfEntropyTracker<H>,
    state: HkdfStates,
}

/// The extract phase's HMAC, held as its two halves: the salt key and the inner hash absorbing
/// the IKM. An `HMAC` worker borrows its key, and a struct cannot borrow from itself, so the
/// phase is run through `bouncycastle_hmac::hazmat`'s `inner_state` and `finish_out` instead.
#[derive(Clone)]
struct HkdfExtract<H: HMACParams> {
    key: HmacKey<H>,
    inner: H,
}

// No Drop impl of its own: the sensitive state is the salt-keyed pad states inside `hmac` (RFC
// 2104 Section 4 says they "need to be treated and protected the same as secret keys"), and the
// hash types zeroize those in their own Drop.

#[derive(Clone, Debug, PartialOrd, PartialEq)]
#[repr(u8)]
enum HkdfStates {
    /// waiting for salt
    Uninitialized = 0,

    /// Salt set, waiting for IKMs or do_final
    Initialized = 1,

    /// [`HKDF::do_extract_update_key`] has been called, after which no more credited IKMs can be given.
    /// This keeps the input in the order used by the key-extraction method of NIST SP 800-133r2
    /// Section 6.3, `K = T(HMAC-hash(salt, K1 || ... || Kn || D1 || ... || Dm), kLen)`, in which the
    /// component keys precede the other data. Note (h) of that method explicitly permits alternative
    /// orderings ("including interleaving the keys and data"), so this ordering is conformant but is
    /// a restriction this API chooses, not one the specification imposes.
    TakingAdditionalInfo = 2,
}

impl TryFrom<u8> for HkdfStates {
    type Error = SuspendableError;

    /// Inverse of `self as u8`; rejects unrecognized discriminants with [`SuspendableError::InvalidData`].
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0 => Self::Uninitialized,
            1 => Self::Initialized,
            2 => Self::TakingAdditionalInfo,
            _ => return Err(SuspendableError::InvalidData),
        })
    }
}

#[derive(Clone)]
struct HkdfEntropyTracker<H: HMACParams> {
    _phantomhash: PhantomData<H>,
    entropy: usize,
    security_strength: SecurityStrength,
}

impl<H: HMACParams> HkdfEntropyTracker<H> {
    /// The most the label can say: HMAC's strength is bounded by half the hash output (the
    /// `min(K, 2C)` rule), so no input, and no resumed state, raises it past this.
    const MAX_STRENGTH: SecurityStrength = SecurityStrength::from_bytes(H::OUTPUT_LEN / 2);

    fn new() -> Self {
        Self { _phantomhash: PhantomData, entropy: 0, security_strength: SecurityStrength::None }
    }

    /// Takes in a KeyMaterial that is being mixed and figures out how much entropy to credit.
    /// Returns the amount of entropy credited.
    fn credit_entropy(&mut self, key: &impl KeyMaterialTrait) -> usize {
        let additional_entropy = if key.is_full_entropy() { key.key_len() } else { 0 };
        // Saturating: the counter is bookkeeping, and a resumed state may carry any value.
        self.entropy = self.entropy.saturating_add(additional_entropy);
        self.security_strength = max(&self.security_strength, &key.security_strength()).clone();
        self.security_strength = min(&self.security_strength, &Self::MAX_STRENGTH).clone();
        additional_entropy
    }

    pub fn get_entropy(&self) -> usize {
        self.entropy
    }

    // Library policy, not a rule from a standard: the output is credited as CryptographicRandom
    // once at least OUTPUT_LEN bytes of typed key material have gone in. SP 800-133r2 Section 6.3
    // (method 3, note (g)) asks that the component keys' min-entropies sum to at least the
    // min-entropy the output needs, and "should be at least twice that amount"; this counts bytes
    // of material typed as key rather than min-entropy, so the threshold is the full output length.
    pub fn is_fully_seeded(&self) -> bool {
        self.entropy >= H::OUTPUT_LEN
    }

    /// [`KeyType::CryptographicRandom`] once at least `OUTPUT_LEN` bytes of typed key material have
    /// been credited (see [`Self::is_fully_seeded`]), else [`KeyType::Unknown`].
    fn get_output_key_type(&self) -> KeyType {
        if self.is_fully_seeded() { KeyType::CryptographicRandom } else { KeyType::Unknown }
    }
}

/// The name is [`HMACParams::HKDF_ALG_NAME`]; the strength is the hash's, which the extract
/// and expand HMACs cannot exceed.
impl<H: HMACParams, const HASH_STATE_LEN: usize, const HKDF_STATE_LEN: usize> Algorithm
    for HKDF<H, HASH_STATE_LEN, HKDF_STATE_LEN>
{
    const ALG_NAME: &'static str = H::HKDF_ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = H::MAX_SECURITY_STRENGTH;
}

impl<H: HMACParams, const HASH_STATE_LEN: usize, const HKDF_STATE_LEN: usize> Default
    for HKDF<H, HASH_STATE_LEN, HKDF_STATE_LEN>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<H: HMACParams, const HASH_STATE_LEN: usize, const HKDF_STATE_LEN: usize>
    HKDF<H, HASH_STATE_LEN, HKDF_STATE_LEN>
{
    /// Get a new, uninstantiated HKDF object.
    pub fn new() -> Self {
        Self { hmac: None, entropy: HkdfEntropyTracker::new(), state: HkdfStates::Uninitialized }
    }

    /// Returns the amount of entropy currently credited from the keys inputted so far.
    pub fn get_entropy(&self) -> usize {
        self.entropy.get_entropy()
    }

    /// Check whether the entropy input so far met the threshold for this object to be considered fully seeded
    pub fn is_fully_seeded(&self) -> bool {
        self.entropy.is_fully_seeded()
    }

    /// RFC 5869 Section 2.2:
    ///
    /// HKDF-Extract(salt, IKM) -> PRK
    ///    Options:
    ///       Hash     a hash function; HashLen denotes the length of the
    ///                hash function output in octets
    ///
    ///    Inputs:
    ///       salt     optional salt value (a non-secret random value);
    ///                if not provided, it is set to a string of HashLen zeros.
    ///       IKM      input keying material
    ///
    ///    Output:
    ///       PRK      a pseudorandom key (of HashLen octets)
    ///
    /// The salt can be of any [`KeyType`] but [`KeyType::Unknown`], which is refused as
    /// [`KeyMaterialError::InvalidKeyType`]; the IKM can be of any type, and credits entropy only
    /// when it is a full-entropy one. The salt credits entropy only when it is typed
    /// [`KeyType::MACKey`], a secret salt; see the crate's Security Considerations. The type of the
    /// output is set from what was credited.
    /// The output KeyMaterial will be of fixed size, with a capacity large enough to cover any
    /// underlying hash function, but the actual key length will be appropriate to the underlying hash function.
    ///
    /// Salt is optional, which is indicated by providing an uninitialized KeyMaterial object of length zero,
    /// the capacity is irrelevant, so KeyMaterial256::new() or KeyMaterial0::new() would both count as an absent salt.
    pub fn extract(
        salt: &impl KeyMaterialTrait,
        ikm: &impl KeyMaterialTrait,
    ) -> Result<impl KeyMaterialTrait, MACError> {
        let mut prk = KeyMaterial::<MAX_HMAC_OUTPUT_LEN>::new();
        Self::extract_out(salt, ikm, &mut prk)?;
        Ok(prk)
    }

    /// Same as [`HKDF::extract`], but writes the output to a provided KeyMaterial buffer.
    /// Note that the provided KeyMaterial must be correctly sized to the hash function output length.
    pub fn extract_out(
        salt: &impl KeyMaterialTrait,
        ikm: &impl KeyMaterialTrait,
        prk: &mut KeyMaterial<MAX_HMAC_OUTPUT_LEN>,
    ) -> Result<usize, MACError> {
        // PRK = HMAC-Hash(salt, IKM)

        let mut hkdf = Self::new();
        hkdf.do_extract_init(salt)?;
        hkdf.do_extract_update_key(ikm)?;
        let bytes_written = hkdf.do_extract_final_out(prk)?;

        Ok(bytes_written)
    }

    /// The definition of HKDF-Expand from RFC5869 is as follows:
    /// HKDF-Expand(PRK, info, L) -> OKM
    ///    Options:
    ///       Hash     a hash function; HashLen denotes the length of the
    ///                hash function output in octets
    ///    Inputs:
    ///       PRK      a pseudorandom key of at least HashLen octets
    ///                (usually, the output from the extract step)
    ///       info     optional context and application specific information
    ///                (can be a zero-length string)
    ///       L        length of output keying material in octets
    ///                (<= 255*HashLen)
    ///
    ///   Output:
    ///       OKM      output keying material (of L octets)
    ///
    /// Due to the details of the KeyMaterial object needing to compile to a known size, there is (currently)
    /// no way (within a no_std context) to dynamically allocate a KeyMaterial object according to the given 'L',
    /// therefore this function is provided only as expand_out(), filling the provided KeyMaterial object,
    /// and no analogous expand() is provided.
    ///
    /// The salt can be of any [`KeyType`] but [`KeyType::Unknown`], which is refused as
    /// [`KeyMaterialError::InvalidKeyType`]; the IKM can be of any type. The type of the output is
    /// set from what was credited, as [`Self::extract_out`] says.
    ///
    /// L is the output length. [`KDFError::InvalidLength`] is returned if L exceeds 255 * HashLen,
    /// if `okm` cannot hold L bytes, or if `prk` is shorter than HashLen (RFC 5869 Section 2.3).
    /// There is no upper bound on the PRK: one longer than the hash block is hashed first, as HMAC
    /// does with a long key (RFC 2104 Section 3), so the output is what HMAC keyed with it gives.
    ///
    /// Returns the number of bytes written.
    #[allow(non_snake_case)] // for L
    pub fn expand_out(
        prk: &impl KeyMaterialTrait,
        info: &[u8],
        L: usize,
        okm: &mut impl KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        // RFC 5869 Section 2.3:
        //    N = ceil(L/HashLen)
        //    T = T(1) | T(2) | T(3) | ... | T(N)
        //    OKM = first L octets of T
        //
        //    where:
        //    T(0) = empty string (zero length)
        //    T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
        //    T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
        //    T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
        //    ...
        //
        //    (where the constant concatenated to the end of each T(n) is a
        //    single octet.)

        let hash_len = H::OUTPUT_LEN;
        if L > 255 * hash_len {
            return Err(KDFError::InvalidLength(
                "HKDF-Expand cannot produce more than 255*HashLen bytes of output",
            ));
        }

        if L > okm.capacity() {
            return Err(KDFError::InvalidLength(
                "Provided KeyMaterial is too small to hold the requested output length.",
            ));
        }

        // RFC 5869 Section 2.3: "PRK  a pseudorandom key of at least HashLen octets".
        if prk.key_len() < hash_len {
            return Err(KDFError::InvalidLength(
                "HKDF-Expand: PRK must be at least HashLen bytes (RFC 5869 Sec 2.3)",
            ));
        }

        let mut entropy = HkdfEntropyTracker::<H>::new();
        entropy.credit_entropy(prk);

        #[allow(non_snake_case)]
        let N = L.div_ceil(hash_len) as u8;
        let mut bytes_written: usize = 0;

        // Could potentially speed this up by unrolling T(0) and T(1)

        // The PRK, re-typed as the MAC key it is (see mac_key_copy). One key object for the whole
        // expansion: the pads are computed once here, before any byte of `okm` is written, and each
        // block's HMAC starts from a clone of them.
        let prk_key = HmacKey::<H>::from_key_material(&Self::mac_key_copy(prk.ref_to_bytes())?)?;

        // T(i) is output key material, so it zeroizes on drop.
        #[allow(non_snake_case)]
        let mut T: Secret<[u8; MAX_HMAC_OUTPUT_LEN]> = Secret::new();
        let mut t_len: usize = 0;
        let mut i = 1u8;

        let filled: Result<(), KDFError> = (|| {
            do_hazardous_operations(okm, |okm| {
                let out = okm.ref_to_bytes_mut()?;
                while i < N {
                    let mut hmac = prk_key.create_generator();
                    hmac.do_update(&T[..t_len]);
                    hmac.do_update(info);
                    hmac.do_update(&[i]);

                    t_len = hmac
                        .do_final_out(&mut T[..])
                        .map_err(|_| KeyMaterialError::GenericError("HMAC finalization failed"))?;
                    debug_assert_eq!(t_len, hash_len); // this will be true for every iteration after T(0) / T(1)
                    out[bytes_written..bytes_written + t_len].copy_from_slice(&T[..t_len]);
                    bytes_written += t_len;
                    i += 1;
                }
                Ok(())
            })?;

            // Part of the output is not taken on the last iteration. "OKM = first L octets of T", so the
            // last block T(N) is computed in full and only its first `remaining` octets are kept. Asking
            // HMAC for a `remaining`-octet output instead would be a truncated MAC, which HMAC refuses
            // below MIN_FIPS_DIGEST_LEN: that rejected every L with L mod HashLen in 1..=3.
            let remaining = L - bytes_written;
            let mut hmac = prk_key.create_generator();
            hmac.do_update(&T[..t_len]);
            hmac.do_update(info);
            hmac.do_update(&[i]);

            t_len = hmac.do_final_out(&mut T[..hash_len])?;
            debug_assert_eq!(t_len, hash_len);

            do_hazardous_operations(okm, |okm| {
                let out = okm.ref_to_bytes_mut()?;
                out[bytes_written..bytes_written + remaining].copy_from_slice(&T[..remaining]);
                Ok(())
            })?;
            bytes_written += remaining;
            Ok(())
        })();
        // A partly written OKM is key material: on any failure above, none of it is left behind.
        if filled.is_err() {
            okm.zeroize();
        }
        filled?;

        // Set the KeyType of the output
        // Since some computation has been performed, the result will not actually be zeroized, even if all input key material was zeroized.
        do_hazardous_operations(okm, |okm| {
            if prk.key_type() == KeyType::Zeroized {
                okm.set_key_type(KeyType::Unknown)?;
            } else {
                okm.set_key_type(prk.key_type().clone())?;
            }
            okm.set_key_len(bytes_written)?;
            if okm.key_type() <= KeyType::Unknown {
                okm.set_security_strength(SecurityStrength::None)
            } else {
                okm.set_security_strength(
                    min(&SecurityStrength::from_bytes(okm.key_len()), &entropy.security_strength)
                        .clone(),
                )
            }
        })?;

        Ok(bytes_written)
    }

    /// Salt is optional, which is indicated by providing an uninitialized KeyMaterial object of length zero,
    /// the capacity is irrelevant, so KeyMaterial256::new() or KeyMaterial0::new() would both count as an absent salt.
    #[allow(non_snake_case)]
    pub fn extract_and_expand_out(
        salt: &impl KeyMaterialTrait,
        ikm: &impl KeyMaterialTrait,
        info: &[u8],
        L: usize,
        okm: &mut impl KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        let prk = Self::extract(salt, ikm)?;
        Self::expand_out(&prk, info, L, okm)
    }

    /// The salt as the MAC key it is: RFC 5869 Section 2.2, `PRK = HMAC-Hash(salt, IKM)`.
    ///
    /// [`HmacKey`] accepts only [`KeyType::MACKey`] or [`KeyType::Zeroized`] material, while a salt
    /// may carry any `KeyType` (a nonce drawn from an RNG is `CryptographicRandom`), so it is
    /// copied and re-typed here through [`Self::mac_key_copy`], as [`Self::expand_out`] does for
    /// the PRK. The exception is [`KeyType::Unknown`]: bytes of unknown provenance are promoted to
    /// a key only inside [`do_hazardous_operations`], never here, so they are refused. The empty
    /// salt stays an empty `Zeroized` key, which HMAC zero-pads
    /// to a block (RFC 2104 Section 2 step (1)): that is both RFC 5869 Section 2.2's "string of
    /// HashLen zeros" and SP 800-56Cr2 Section 5.1's "all-zero byte string whose length is equal to
    /// that of a single input block", so all three default salts key HMAC the same way.
    fn salt_as_mac_key(
        salt: &impl KeyMaterialTrait,
    ) -> Result<KeyMaterial<LARGEST_HASHER_BLOCK_LEN>, MACError> {
        if salt.key_type() == KeyType::Unknown {
            return Err(MACError::KeyMaterialError(KeyMaterialError::InvalidKeyType(
                "HKDF salt must not be KeyType::Unknown",
            )));
        }
        Ok(Self::mac_key_copy(salt.ref_to_bytes())?)
    }

    /// `bytes` as a [`KeyType::MACKey`] of [`LARGEST_HASHER_BLOCK_LEN`] capacity, HMAC's own bound.
    ///
    /// HMAC replaces a key "longer than B bytes" by its hash (RFC 2104 Section 3), so bytes longer
    /// than the hash block are hashed here first: the copy then keys HMAC identically to `bytes`
    /// and never overflows. The salt and the PRK both go through this.
    fn mac_key_copy(
        bytes: &[u8],
    ) -> Result<KeyMaterial<LARGEST_HASHER_BLOCK_LEN>, KeyMaterialError> {
        const { assert!(H::BLOCK_LEN <= LARGEST_HASHER_BLOCK_LEN) };
        const { assert!(H::OUTPUT_LEN <= MAX_HMAC_OUTPUT_LEN) };
        if bytes.len() <= H::BLOCK_LEN {
            return KeyMaterial::from_bytes_as_type(bytes, KeyType::MACKey);
        }
        let mut digest: Secret<[u8; MAX_HMAC_OUTPUT_LEN]> = Secret::new();
        let written = H::hash_out(bytes, &mut digest[..H::OUTPUT_LEN]);
        KeyMaterial::from_bytes_as_type(&digest[..written], KeyType::MACKey)
    }

    /// This, together with [`HKDF::do_extract_update_key`], [`HKDF::do_extract_update_bytes`] and [`HKDF::do_extract_final`]
    /// provide a streaming interface for very long values of `ikm`.
    /// In this mode, entropy is credited for the keys given to [`HKDF::do_extract_update_key`] and
    /// for a salt typed [`KeyType::MACKey`] (a secret salt); a salt of any other type credits
    /// nothing, since RFC 5869 Section 2.2's salt is "a non-secret random value".
    /// The salt can be of any [`KeyType`] but [`KeyType::Unknown`], which is refused as
    /// [`KeyMaterialError::InvalidKeyType`]; the type of the output is set from what was credited.
    /// The output KeyMaterial will be of fixed size, with a capacity large enough to cover any
    /// underlying hash function, but the actual key length will be appropriate to the underlying hash function.
    ///
    /// Salt is optional; to omit it, provide a KeyMaterial0, which will cause HKDF to use the default all-zero salt.
    ///
    /// Returns the number of bytes of entropy credited to this input key material.
    pub fn do_extract_init(&mut self, salt: &impl KeyMaterialTrait) -> Result<usize, MACError> {
        if self.state >= HkdfStates::Initialized {
            return Err(MACError::InvalidState("Initialized twice"));
        };

        // The salt is often empty or short, so HMAC's key-strength check is skipped; the entropy
        // tracker below accounts for it.
        let salt_key = Self::salt_as_mac_key(salt)?;
        let key = HmacKey::<H>::from_key_material_allow_weak(&salt_key)?;
        let inner = hmac_hazmat::inner_state(&key);
        self.hmac = Some(HkdfExtract { key, inner });

        // RFC 5869 Section 2.2 defines the salt as "a non-secret random value", and SP 800-133r2
        // Section 6.3 note (g) counts the component keys' entropy, not the salt's: a salt the
        // caller has not marked as a key credits nothing, or a public salt alone would label the
        // PRK full-entropy key material. A MACKey salt is SP 800-56Cr2 Section 5.1's secret salt.
        let additional_entropy =
            if salt.key_type() == KeyType::MACKey { self.entropy.credit_entropy(salt) } else { 0 };
        self.state = HkdfStates::Initialized;

        Ok(additional_entropy)
    }

    /// An update function that allows adding an IKM as a [`KeyMaterialTrait`].
    /// Credits the entropy contained in the IKM.
    /// This function may be called zero or more times in a workflow.
    /// In particular, this function may be called multiple times to add more than one IKM.
    ///
    /// Returns the number of bytes of entropy credited to this input key material.
    pub fn do_extract_update_key(
        &mut self,
        ikm: &impl KeyMaterialTrait,
    ) -> Result<usize, MACError> {
        if self.state == HkdfStates::Uninitialized {
            return Err(MACError::InvalidState(
                "Must call do_extract_init() before calling do_extract_update_key()",
            ));
        };

        if self.state == HkdfStates::TakingAdditionalInfo {
            return Err(MACError::InvalidState(
                "Cannot accept more credited IKMs via do_extract_update_key(&KeyMaterial) after an uncredited key has been provided via do_extract_update(&[u8])",
            ));
        }
        debug_assert_eq!(self.state, HkdfStates::Initialized);
        debug_assert!(self.hmac.is_some());

        let additional_entropy = self.entropy.credit_entropy(ikm);
        self.hmac.as_mut().unwrap().inner.do_update(ikm.ref_to_bytes());

        Ok(additional_entropy)
    }

    /// An update function that allows streaming of the IKM as bytes.
    /// Note that since this interface takes the IKM as raw bytes, it cannot track its entropy
    /// and therefore any IKM material provided through this interface will not count towards
    /// the entropy of the output key.
    ///
    /// State machine: this function must be called after [`HKDF::do_extract_init`], followed by
    /// zero or more calls of [`HKDF::do_extract_update_key`], and before [`HKDF::do_extract_final`].
    ///
    /// Returns the number of bytes of entropy credited to this input key material, which is always 0 for this function.
    pub fn do_extract_update_bytes(&mut self, ikm_chunk: &[u8]) -> Result<usize, MACError> {
        if self.state == HkdfStates::Uninitialized {
            return Err(MACError::InvalidState(
                "Must call do_extract_init() before calling do_extract_update()",
            ));
        };
        self.state = HkdfStates::TakingAdditionalInfo;

        self.hmac.as_mut().unwrap().inner.do_update(ikm_chunk);
        Ok(0)
    }

    /// Finish the HKDF-Extract phase and produce the output `prk`.
    #[allow(non_snake_case)]
    pub fn do_extract_final(self) -> Result<KeyMaterial<MAX_HMAC_OUTPUT_LEN>, MACError> {
        let mut prk = KeyMaterial::<MAX_HMAC_OUTPUT_LEN>::new();
        self.do_extract_final_out(&mut prk)?;
        Ok(prk)
    }

    /// Finish the HKDF-Extract phase and fill the provided `prk`.
    /// The PRK is `HashLen` bytes (RFC 5869 Section 2.2), which the provided KeyMaterial always holds.
    #[allow(non_snake_case)]
    pub fn do_extract_final_out(
        self,
        prk: &mut KeyMaterial<MAX_HMAC_OUTPUT_LEN>,
    ) -> Result<usize, MACError> {
        if self.state == HkdfStates::Uninitialized {
            return Err(MACError::InvalidState(
                "Must call do_extract_init() before calling do_extract_final().",
            ));
        };
        debug_assert!(self.hmac.is_some());

        let output_key_type = self.entropy.get_output_key_type(); // need to do this above self.hmac.do_final_out, which will consume self.

        let mut bytes_written = 0;
        let HkdfExtract { key, inner } = self.hmac.unwrap();
        do_hazardous_operations(prk, |okm| {
            bytes_written = hmac_hazmat::finish_out(&key, inner, okm.ref_to_bytes_mut()?)
                .map_err(|_| KeyMaterialError::GenericError("HMAC do_final_out failed"))?;
            okm.set_key_len(bytes_written)?;
            okm.set_key_type(output_key_type)?;
            if output_key_type <= KeyType::Unknown {
                okm.set_security_strength(SecurityStrength::None)
            } else {
                okm.set_security_strength(
                    min(
                        &SecurityStrength::from_bytes(okm.key_len()),
                        &self.entropy.security_strength,
                    )
                    .clone(),
                )
            }
        })?;
        // By RFC5869, the output size of prk is HashLen denotes the length of the
        //                hash function output in octets
        debug_assert_eq!(prk.key_len(), H::OUTPUT_LEN);
        Ok(bytes_written)
    }
}

/// HKDF's extract-then-expand is RFC 5869's, which NIST SP 800-56Cr2 Section 5.1 names as "a
/// version of" its two-step key derivation "using HMAC for both the extraction and expansion
/// steps"; the expansion step's input layout (`T(i-1) || info || i`) is RFC 5869's own rather than
/// SP 800-108r1 Section 4.2's feedback mode. The default salt is empty: RFC 5869 Section 2.2 sets an absent salt
/// to "a string of HashLen zeros", SP 800-56Cr2 Section 5.1 to an all-zero string of one hash input
/// block, and HMAC zero-pads its key to a block, so the three key HMAC identically (see
/// `salt_as_mac_key`). All key material and additional_input is mapped to HKDF's ikm input.
/// While this is not the only mode in which HKDF can be used as a KDF, this is considered the default mode
/// that is exposed through [`KDF::derive_key`] and [`KDF::derive_key_out`].
/// More advanced control of the inputs to HKDF can be achieved by using [`KDF::derive_key_from_multiple`] and
/// [`KDF::derive_key_from_multiple_out`], or by using the [`HKDF`] impl directly.
///
/// Entropy tracking: this implementation will map entropy from the input keys to the output key.
impl<H: HMACParams, const HASH_STATE_LEN: usize, const HKDF_STATE_LEN: usize> KDF
    for HKDF<H, HASH_STATE_LEN, HKDF_STATE_LEN>
{
    /// This invokes [`HKDF::extract_and_expand_out`] with a zero salt and using the provided key as ikm.
    /// This provides a fixed-length output, which may be truncated as needed.
    fn derive_key(
        self,
        key: &impl KeyMaterialTrait,
        additional_input: &[u8],
    ) -> Result<Box<dyn KeyMaterialTrait>, KDFError> {
        let mut output_key = KeyMaterial512::new();
        _ = self.derive_key_out(key, additional_input, &mut output_key)?;
        output_key.set_key_len(H::OUTPUT_LEN)?;
        Ok(Box::new(output_key))
    }

    /// This invokes [`HKDF::extract_and_expand_out`] with a zero salt and using the provided key as ikm.
    /// This fills the provided [`KeyMaterialTrait`] object in place of exposing a Length parameter.
    fn derive_key_out(
        self,
        key: &impl KeyMaterialTrait,
        additional_input: &[u8],
        output_key: &mut impl KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        let bytes_written = Self::extract_and_expand_out(
            &KeyMaterial::<0>::new(),
            key,
            additional_input,
            output_key.capacity(),
            output_key,
        )?;
        Ok(bytes_written)
    }

    /// As with [`KDF::derive_key`] and [`KDF::derive_key_out`],
    /// This invokes HKDF in the extract_and_expand mode and maps the provided keys in the following way:
    /// - The first (0'th) key is used as the salt for HKDF.extract.
    /// - The remaining keys are concatenated to form HKDF's ikm parameter.
    /// - Entropy of all provided keys are tracked to determine the output key's entropy.
    ///
    /// Therefore, derive_key_from_multiple(&[KeyMaterial0::new(), &key], &info) is equivalent to derive_key(&key, &info).
    ///
    /// This provides a fixed-length output, which may be truncated as needed.
    fn derive_key_from_multiple(
        self,
        keys: &[&impl KeyMaterialTrait],
        additional_input: &[u8],
    ) -> Result<Box<dyn KeyMaterialTrait>, KDFError> {
        let mut output_key = KeyMaterial512::new();
        _ = self.derive_key_from_multiple_out(keys, additional_input, &mut output_key)?;
        output_key.set_key_len(*min(&output_key.key_len(), &H::OUTPUT_LEN))?;
        Ok(Box::new(output_key))
    }

    /// This behaves the same as [`KDF::derive_key_from_multiple`], except that it fills the provided
    /// [`KeyMaterialTrait`] object in place of exposing a Length parameter.
    fn derive_key_from_multiple_out(
        self,
        keys: &[&impl KeyMaterialTrait],
        additional_input: &[u8],
        output_key: &mut impl KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        // The object's own tracker credits every key: the salt in do_extract_init and each ikm in
        // do_extract_update_key. do_extract_final_out types the PRK from it and expand_out types
        // the output from the PRK, so no second tracker and no override are needed here.
        let mut hkdf = Self::new();
        match keys.split_first() {
            Some((salt, ikms)) => {
                hkdf.do_extract_init(*salt)?;
                for ikm in ikms {
                    hkdf.do_extract_update_key(*ikm)?;
                }
            }
            None => {
                hkdf.do_extract_init(&KeyMaterial0::new())?;
            }
        }
        let mut prk = KeyMaterial::<MAX_HMAC_OUTPUT_LEN>::new();
        _ = hkdf.do_extract_final_out(&mut prk)?;
        Self::expand_out(&prk, additional_input, output_key.capacity(), output_key)
    }
}

/// HKDF is *keyed by its salt* -- the salt keys the extract-phase HMAC -- so it implements
/// [`SuspendableKeyed`] (not [`Suspendable`]). An in-progress
/// extract operation can be suspended and resumed, but the salt is NOT written into the serialized
/// state and must be re-supplied to [`SuspendableKeyed::from_suspended`].
///
/// Only the extract phase carries resumable state (expand is a one-shot static operation). As with
/// HMAC, resuming with the wrong salt cannot be detected and will silently produce a wrong PRK.
///
/// Serialized layout: HKDF writes its own 3-byte library version header first and checks it before
/// parsing anything else. This matters because the inner HMAC blob (which carries its own header) is
/// absent before extract is initialized -- without HKDF's own header, a pre-init state would have no
/// version tag at all. Using `B` = the inner HMAC blob length:
///
/// ```text
///   [0 .. 3)             HKDF library version header (checked on resume)
///   [3]                  inner-HMAC present flag (0 = extract not yet initialized)
///   [4 .. 4 + B)         the inner HMAC's SuspendableKeyed blob (salt excluded); zeroed when absent
///   [4 + B]              state-machine tag (see `HkdfStates`)
///   [5 + B .. 13 + B)    entropy counter (usize serialized as u64, little-endian)
///   [13 + B]             accumulated security strength (1-byte tag)
/// ```
///
/// So the total per HKDF variant is the 3-byte version header + 11 bytes of HKDF bookkeeping
/// (present flag, state tag, entropy counter, security strength) + the inner HMAC's blob = `B + 14`,
/// which is the relationship `HKDF_STATE_LEN == HASH_STATE_LEN + 14` asserted below.
impl<'k, H, const HASH_STATE_LEN: usize, const HKDF_STATE_LEN: usize>
    SuspendableKeyed<'k, HKDF_STATE_LEN> for HKDF<H, HASH_STATE_LEN, HKDF_STATE_LEN>
where
    H: HMACParams + Suspendable<HASH_STATE_LEN>,
{
    // HMAC accepts any key material, so the key type is the trait object `dyn KeyMaterialTrait`
    // rather than a single concrete key type. The key is only used (by reference) to reload the key
    // bytes at from_serialized_state, so dynamic dispatch here is negligible.
    type Key = dyn KeyMaterialTrait;

    fn suspend(self) -> [u8; HKDF_STATE_LEN] {
        debug_assert_eq!(HKDF_STATE_LEN, HASH_STATE_LEN + 14);
        let mut state = [0u8; HKDF_STATE_LEN];

        // HKDF's own library version header comes first: the inner HMAC blob is absent before
        // extract is initialized, so we can't rely on its header being present.
        add_lib_ver(&mut state);

        // The present flag, then (when present) the inner salt-keyed HMAC blob right after it.
        if let Some(hmac) = self.hmac {
            state[3] = 1; // present flag
            state[4..4 + HASH_STATE_LEN].copy_from_slice(&hmac.inner.suspend());
        }
        // else None:
        //  the presence flag = 0
        //  the content = [u8; 0]
        // which is how it already is, so nothing to do.

        state[4 + HASH_STATE_LEN] = self.state as u8;
        state[5 + HASH_STATE_LEN..13 + HASH_STATE_LEN]
            .copy_from_slice(&(self.entropy.entropy as u64).to_le_bytes());
        state[13 + HASH_STATE_LEN] = self.entropy.security_strength as u8;

        state
    }

    fn from_suspended(
        state: [u8; HKDF_STATE_LEN],
        salt: &'k Self::Key,
    ) -> Result<Self, SuspendableError> {
        debug_assert_eq!(HKDF_STATE_LEN, HASH_STATE_LEN + 14);

        // Check HKDF's own version header before parsing anything else.
        check_lib_ver(&state, None)?;

        // Rebuild the salt-keyed HMAC (when present) by re-supplying the salt.
        let hmac = match state[3] {
            0 => None,
            // infallible: the sub-slice is exactly HASH_STATE_LEN bytes by const construction.
            1 => Some(HkdfExtract {
                key: HmacKey::<H>::from_key_material_allow_weak(salt)
                    .map_err(|_| SuspendableError::InvalidData)?,
                inner: H::from_suspended(state[4..4 + HASH_STATE_LEN].try_into().unwrap())?,
            }),
            _ => return Err(SuspendableError::InvalidData),
        };

        let hkdf_state = HkdfStates::try_from(state[4 + HASH_STATE_LEN])?;

        // Check that the hkdf_state aligns with the presence of an hmac: an hmac object should not
        // be present in the init state, and any other state must have one.
        if (hmac.is_some() && hkdf_state == HkdfStates::Uninitialized)
            || (hmac.is_none() && hkdf_state != HkdfStates::Uninitialized)
        {
            return Err(SuspendableError::InvalidData);
        }

        // infallible: the sub-slice is exactly 8 bytes by const construction. The counter is
        // refused rather than truncated where `usize` is narrower than the encoding.
        let entropy = bounded_usize(
            u64::from_le_bytes(state[5 + HASH_STATE_LEN..13 + HASH_STATE_LEN].try_into().unwrap()),
            usize::MAX,
        )?;
        let security_strength = SecurityStrength::try_from(state[13 + HASH_STATE_LEN])?;
        // The bookkeeping is checked against what this type writes: the label never exceeds the
        // hash's cap (credit_entropy applies it), and a state that has not been initialized
        // carries no entropy and no strength (new() has none). Otherwise a state whose two
        // bookkeeping bytes were edited would label a PRK derived from nothing as full-entropy
        // material at a strength the hash cannot give.
        if security_strength > HkdfEntropyTracker::<H>::MAX_STRENGTH
            || (hkdf_state == HkdfStates::Uninitialized
                && (entropy != 0 || security_strength != SecurityStrength::None))
        {
            return Err(SuspendableError::InvalidData);
        }

        Ok(HKDF {
            hmac,
            entropy: HkdfEntropyTracker { _phantomhash: PhantomData, entropy, security_strength },
            state: hkdf_state,
        })
    }
}

// Because this struct is not public, the tests have to go here.
#[cfg(test)]
mod tests {
    use super::*;
    use bouncycastle_sha2::SHA256;

    #[test]
    fn test_entropy_tracker() {
        let mut entropy = HkdfEntropyTracker::<SHA256>::new();

        assert_eq!(entropy.get_entropy(), 0);
        assert_eq!(entropy.get_output_key_type(), KeyType::Unknown);

        let key = KeyMaterial512::from_bytes_as_type(
            b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
            KeyType::CryptographicRandom,
        )
        .unwrap();
        entropy.credit_entropy(&key);
        assert_eq!(entropy.get_entropy(), 16);
        assert_eq!(entropy.is_fully_seeded(), false);
        assert_eq!(entropy.get_output_key_type(), KeyType::Unknown);

        entropy.credit_entropy(&key);
        assert_eq!(entropy.get_entropy(), 32);
        assert_eq!(entropy.is_fully_seeded(), true);
        assert_eq!(entropy.get_output_key_type(), KeyType::CryptographicRandom);
    }
}
