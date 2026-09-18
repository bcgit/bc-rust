//! The generic HMAC-based Extract-and-Expand Key Derivation Function (HKDF) construction, as per
//! RFC 5869, as allowed by NIST SP 800-56Cr2.
//!
//! This is a utility crate and is not intended to be used directly. It provides [`HKDF`] -- the
//! construction, generic over any struct that implements [`Hash`] and [`HashAlgParams`], the extension
//! point through which a hash declares the metadata from which the HKDF instance is built.
//! The library provides the following concrete instantiations of HKDF:
//!
//! | Hash family | Instantiations                                                |
//! |-------------|---------------------------------------------------------------|
//! | SHA-2       | `bouncycastle_sha2::hkdf` -- `HKDF_SHA256`, `HKDF_SHA512`     |
//!
//! # Instantiating HKDF over a hash
//!
//! HKDF uses HMAC as its underlying primitive, so it works with any hash that HMAC works with:
//! [`HKDF`] needs only [`Hash`] + [`HashAlgParams`] + [`Default`]. Unlike HMAC there is no additional
//! HKDF params trait to implement -- HKDF has no per-hash OIDs and derives its name from nothing --
//! so an instantiation is just a type alias plus, by convention, a name constant and a suspended-state
//! length.
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
//! As an example, the `bouncycastle-sha2` crate instantiates HKDF-SHA256 and HKDF-SHA512 this way. The library does not ship
//! HKDF-SHA384, so that makes a good illustration of adding one -- for a hash in this library or for
//! a hash of your own, the shape is identical:
//!
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::traits::{KDF, SuspendableKeyed};
//! use bouncycastle_hkdf::HKDF;
//! use bouncycastle_sha2::hmac::HMAC_SHA384Params;
//! use bouncycastle_sha2::{SHA384, SUSPENDED_SHA512_STATE_LEN};
//!
//! // SHA-384 is a member of the SHA-512 family, so its suspended state is the SHA-512 one.
//! const SUSPENDED_HKDF_SHA384_STATE_LEN: usize = SUSPENDED_SHA512_STATE_LEN + 14;
//!
//! #[allow(non_camel_case_types)]
//! pub type HKDF_SHA384 =
//!     HKDF<SHA384, HMAC_SHA384Params, SUSPENDED_SHA512_STATE_LEN, SUSPENDED_HKDF_SHA384_STATE_LEN>;
//!
//! pub const HKDF_SHA384_NAME: &str = "HKDF-SHA384";
//!
//! // That is all it takes: the KDF trait and the extract/expand API are now available.
//! let ikm = KeyMaterial256::from_bytes_as_type(
//!             b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
//!             KeyType::Seed).unwrap();
//! let okm = HKDF_SHA384::new().derive_key(&ikm, b"extra input").unwrap();
//!
//! // ...and so is suspend/resume, because SHA-384 implements Suspendable and the two const
//! // parameters above agree.
//! let salt = KeyMaterial256::from_bytes_as_type(
//!             b"\x0f\x0e\x0d\x0c\x0b\x0a\x09\x08\x07\x06\x05\x04\x03\x02\x01\x00",
//!             KeyType::MACKey).unwrap();
//! let mut hkdf = HKDF_SHA384::new();
//! hkdf.do_extract_init(&salt).unwrap();
//! hkdf.do_extract_update_bytes(b"part 1").unwrap();
//! let suspended = hkdf.suspend();
//! assert_eq!(suspended.len(), SUSPENDED_HKDF_SHA384_STATE_LEN);
//!
//! let mut resumed = HKDF_SHA384::from_suspended(suspended, &salt).unwrap();
//! resumed.do_extract_update_bytes(b"part 2").unwrap();
//! let _prk = resumed.do_extract_final().unwrap();
//! ```
//!
//! # Security Considerations
//!
//! These apply to every instantiation; `bouncycastle_sha2::hkdf` repeats the ones that matter most in
//! day-to-day use.
//!
//! * HKDF is keyed by its `salt`, which keys the extract-phase HMAC. The salt is deliberately
//!   excluded from the suspended state and must be re-supplied on resume; resuming with a different
//!   salt cannot be detected and silently produces a different PRK.
//! * Entropy is credited only for input supplied via [`HKDF::do_extract_update_key`]. Bytes supplied
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
use bouncycastle_core::key_material;
use bouncycastle_core::key_material::{
    KeyMaterial, KeyMaterial0, KeyMaterial512, KeyMaterialTrait, KeyType,
};
use bouncycastle_core::suspendable_state::{add_lib_ver, check_lib_ver};
use bouncycastle_core::traits::{
    Hash, HashAlgParams, KDF, MAC, SecurityStrength, Suspendable, SuspendableKeyed,
};
use bouncycastle_hmac::{HMAC, HMACParams};
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
pub struct HKDF<
    H: Hash + HashAlgParams + Default,
    PARAMS: HMACParams,
    const HASH_STATE_LEN: usize,
    const HKDF_STATE_LEN: usize,
> {
    // Optional because an HMAC cannot be constructed until a key is provided
    // to initialize it with.
    // None must correspond to a state of Uninitialized.
    hmac: Option<HMAC<H, PARAMS>>,
    entropy: HkdfEntropyTracker<H>,
    state: HkdfStates,
}

// Note: does not need to impl Drop because HKDF itself does not hold any sensitive state data.

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
struct HkdfEntropyTracker<H: Hash + HashAlgParams + Default> {
    _phantomhash: PhantomData<H>,
    entropy: usize,
    security_strength: SecurityStrength,
}

impl<H: Hash + HashAlgParams + Default> HkdfEntropyTracker<H> {
    fn new() -> Self {
        Self { _phantomhash: PhantomData, entropy: 0, security_strength: SecurityStrength::None }
    }

    /// Takes in a KeyMaterial that is being mixed and figures out how much entropy to credit.
    /// Returns the amount of entropy credited.
    fn credit_entropy(&mut self, key: &impl KeyMaterialTrait) -> usize {
        let additional_entropy = if key.is_full_entropy() { key.key_len() } else { 0 };
        self.entropy += additional_entropy;
        self.security_strength = max(&self.security_strength, &key.security_strength()).clone();
        self.security_strength =
            min(&self.security_strength, &SecurityStrength::from_bytes(H::OUTPUT_LEN / 2)).clone();
        additional_entropy
    }

    pub fn get_entropy(&self) -> usize {
        self.entropy
    }

    // According to NIST SP 800-56Cr2, a KDF is fully seeded when its underlying hash primitive has a full block.
    pub fn is_fully_seeded(&self) -> bool {
        self.entropy >= H::OUTPUT_LEN
    }

    /// Either [`KeyMaterialTrait::BytesLowEntropy`] or [`KeyMaterialTrait::BytesFullEntropy`] depending on
    /// whether enough input key material was provided for the internal hash function to have a full block.
    fn get_output_key_type(&self) -> KeyType {
        if self.is_fully_seeded() { KeyType::CryptographicRandom } else { KeyType::Unknown }
    }
}

impl<
    H: Hash + HashAlgParams + Default,
    PARAMS: HMACParams,
    const HASH_STATE_LEN: usize,
    const HKDF_STATE_LEN: usize,
> Default for HKDF<H, PARAMS, HASH_STATE_LEN, HKDF_STATE_LEN>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<
    H: Hash + HashAlgParams + Default,
    PARAMS: HMACParams,
    const HASH_STATE_LEN: usize,
    const HKDF_STATE_LEN: usize,
> HKDF<H, PARAMS, HASH_STATE_LEN, HKDF_STATE_LEN>
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
    /// The KeyMaterial input parameters can be of any [`KeyType`]; but the type of the output will be set accordingly.
    /// The output KeyMaterial will be of fixed size, with a capacity large enough to cover any
    /// underlying hash function, but the actual key length will be appropriate to the underlying hash function.
    ///
    /// Salt is optional, which is indicated by providing an uninitialized KeyMaterial object of length zero,
    /// the capacity is irrelevant, so KeyMateriol256::new() or KeyMaterial_internal::<0>::new() would both count as an absent salt.
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
    /// The KeyMaterial input parameters can be of any KeyType; but the type of the output will be set accordingly.
    ///
    /// L is the output length. This will throw a [`MACError::InvalidLength`] if the provided KeyMaterial is too small to hold the requested output.
    ///
    /// Returns the number of bytes written.
    #[allow(non_snake_case)] // for L
    pub fn expand_out(
        prk: &impl KeyMaterialTrait,
        info: &[u8],
        L: usize,
        okm: &mut impl KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        // From RFC5896
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
                "HMAC can not produce more than 255*HashLen bytes out output",
            ));
        }

        if L > okm.capacity() {
            return Err(KDFError::InvalidLength(
                "Provided KeyMaterial is too small to hold the requested output length.",
            ));
        }

        let mut entropy = HkdfEntropyTracker::<H>::new();
        entropy.credit_entropy(prk);

        #[allow(non_snake_case)]
        let N = L.div_ceil(hash_len) as u8;
        let mut bytes_written: usize = 0;

        // Could potentially speed this up by unrolling T(0) and T(1)

        // The prk key type must be temporarily changed to MACKey to satisfy HMAC, then restored afterwards.
        let prk_as_mac_key = KeyMaterial::<MAX_HMAC_OUTPUT_LEN>::from_bytes_as_type(
            prk.ref_to_bytes(),
            KeyType::MACKey,
        )?;

        #[allow(non_snake_case)]
        let mut T = [0u8; MAX_HMAC_OUTPUT_LEN];
        let mut t_len: usize = 0;
        let mut i = 1u8;

        key_material::do_hazardous_operations(okm, |okm| {
            let out = okm.ref_to_bytes_mut()?;
            while i < N {
                let mut hmac = HMAC::<H, PARAMS>::new(&prk_as_mac_key)
                    .map_err(|_| KeyMaterialError::GenericError("HMAC initialization failed"))?;
                hmac.do_update(&T[..t_len]);
                hmac.do_update(info);
                hmac.do_update(&[i]);

                t_len = hmac
                    .do_final_out(&mut T)
                    .map_err(|_| KeyMaterialError::GenericError("HMAC finalization failed"))?;
                debug_assert_eq!(t_len, hash_len); // this will be true for every iteration after T(0) / T(1)
                out[bytes_written..bytes_written + t_len].copy_from_slice(&T[..t_len]);
                bytes_written += t_len;
                i += 1;
            }
            Ok(())
        })?;

        // Part of the output is not taken on the last iteration
        let remaining = L - bytes_written;
        let mut hmac = HMAC::<H, PARAMS>::new(&prk_as_mac_key)?;
        hmac.do_update(&T[..t_len]);
        hmac.do_update(info);
        hmac.do_update(&[i]);

        t_len = hmac.do_final_out(&mut T[..remaining])?;
        debug_assert_eq!(t_len, remaining); // this will be true for every iteration after T(0) / T(1)

        key_material::do_hazardous_operations(okm, |okm| {
            let out = okm.ref_to_bytes_mut()?;
            out[bytes_written..bytes_written + t_len].copy_from_slice(&T[..t_len]);
            Ok(())
        })?;
        bytes_written += t_len;

        // Set the KeyType of the output
        // Since some computation has been performed, the result will not actually be zeroized, even if all input key material was zeroized.
        key_material::do_hazardous_operations(okm, |okm| {
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
    /// the capacity is irrelevant, so KeyMateriol256::new() or KeyMaterial_internal::<0>::new() would both count as an absent salt.
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

    /// This, together with [`HKDF::do_extract_update_key`], [`HKDF::do_extract_update_bytes`] and [`HKDF::do_extract_final`]
    /// provide a streaming interface for very long values of `ikm`.
    /// In this mode, the entropy of `ikm` is untracked, and so only the entropy ef `salt` is taken into account
    /// when computing the entropy of the output `prk`.
    /// The KeyMaterial input parameters can be of any [`KeyType`]; but the type of the output will be set accordingly.
    /// The output KeyMaterial will be of fixed size, with a capacity large enough to cover any
    /// underlying hash function, but the actual key length will be appropriate to the underlying hash function.
    ///
    /// Salt is optional; to omit it, provide a KeyMaterial0, which will cause HKDF to use the default all-zero salt.
    ///
    /// Returns the number of bits of entropy credited to this input key material.
    pub fn do_extract_init(&mut self, salt: &impl KeyMaterialTrait) -> Result<usize, MACError> {
        if self.state >= HkdfStates::Initialized {
            return Err(MACError::InvalidState("Initialized twice"));
        };

        // Often HMAC is initialized with a zero salt,
        // Key strength errors are ignored here.
        // This will all be tabulated correctly via entropy.credit_entropy()
        self.hmac = Some(HMAC::<H, PARAMS>::new_allow_weak_key(salt)?);

        let additional_entropy = self.entropy.credit_entropy(salt);
        self.state = HkdfStates::Initialized;

        Ok(additional_entropy)
    }

    /// An update function that allows adding an IKM as a [`KeyMaterialTrait`].
    /// Credits the entropy contained in the IKM.
    /// This function may be called zero or more times in a workflow.
    /// In particular, this function may be called multiple times to add more than one IKM.
    ///
    /// Returns the number of bits of entropy credited to this input key material.
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
        let hmac_ref: &mut HMAC<H, PARAMS> = self.hmac.as_mut().unwrap();
        hmac_ref.do_update(ikm.ref_to_bytes());
        // self.hmac.as_mut().unwrap().do_update(ikm.ref_to_bytes());

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
    /// Returns the number of bits of entropy credited to this input key material, which is always 0 for this function.
    pub fn do_extract_update_bytes(&mut self, ikm_chunk: &[u8]) -> Result<usize, MACError> {
        if self.state == HkdfStates::Uninitialized {
            return Err(MACError::InvalidState(
                "Must call do_extract_init() before calling do_extract_update()",
            ));
        };
        self.state = HkdfStates::TakingAdditionalInfo;

        self.hmac.as_mut().unwrap().do_update(ikm_chunk);
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
    /// Note that the provided KeyMaterial must be correctly sized to the HMAC block length.
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
        key_material::do_hazardous_operations(prk, |okm| {
            bytes_written = self
                .hmac
                .unwrap()
                .do_final_out(&mut okm.ref_to_bytes_mut()?)
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

/// As per NIST SP 800-56Cr2 section 5.1, HKDF extract_and_expand can be used as a KDF.
/// Additionally, section 4.1 says that when using HMAC as a KDF, the salt may be set to
/// a string of HashLen zeros. All key material and additional_input is mapped to HKDF's ikm input.
/// While this is not the only mode in which HKDF can be used as a KDF, this is considered the default mode
/// that is exposed through [`KDF::derive_key`] and [`KDF::derive_key_out`].
/// More advanced control of the inputs to HKDF can be achieved by using [`KDF::derive_key_from_multiple`] and
/// [`KDF::derive_key_from_multiple_out`], or by using the [`HKDF`] impl directly.
///
/// Entropy tracking: this implementation will map entropy from the input keys to the output key.
impl<
    H: Hash + HashAlgParams + Default,
    PARAMS: HMACParams,
    const HASH_STATE_LEN: usize,
    const HKDF_STATE_LEN: usize,
> KDF for HKDF<H, PARAMS, HASH_STATE_LEN, HKDF_STATE_LEN>
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
        let mut hkdf = Self::new();
        let mut entropy = HkdfEntropyTracker::<H>::new();

        if keys.len() >= 1 {
            hkdf.do_extract_init(keys[0])?;
            entropy.credit_entropy(keys[0]);
        } else {
            hkdf.do_extract_init(&KeyMaterial0::new())?;
        };

        if keys.len() != 0 {
            for key in &keys[1..] {
                hkdf.do_extract_update_bytes(key.ref_to_bytes())?;
                entropy.credit_entropy(*key);
            }
        }
        let mut prk = KeyMaterial::<MAX_HMAC_OUTPUT_LEN>::new();
        _ = hkdf.do_extract_final_out(&mut prk)?;
        let bytes_written =
            Self::expand_out(&prk, additional_input, output_key.capacity(), output_key)?;

        key_material::do_hazardous_operations(output_key, |output_key| {
            output_key.set_key_type(entropy.get_output_key_type())?;
            output_key.set_security_strength(
                min(
                    &SecurityStrength::from_bytes(output_key.key_len()),
                    &entropy.security_strength,
                )
                .clone(),
            )
        })?;

        Ok(bytes_written)
    }

    fn max_security_strength(&self) -> SecurityStrength {
        H::default().max_security_strength()
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
impl<H, PARAMS: HMACParams, const HASH_STATE_LEN: usize, const HKDF_STATE_LEN: usize>
    SuspendableKeyed<HKDF_STATE_LEN> for HKDF<H, PARAMS, HASH_STATE_LEN, HKDF_STATE_LEN>
where
    H: Hash + HashAlgParams + Default + Suspendable<HASH_STATE_LEN>,
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
            state[4..4 + HASH_STATE_LEN].copy_from_slice(&hmac.suspend());
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
        salt: &Self::Key,
    ) -> Result<Self, SuspendableError> {
        debug_assert_eq!(HKDF_STATE_LEN, HASH_STATE_LEN + 14);

        // Check HKDF's own version header before parsing anything else.
        check_lib_ver(&state, None)?;

        // Rebuild the salt-keyed HMAC (when present) by re-supplying the salt.
        let hmac = match state[3] {
            0 => None,
            // infallible: the sub-slice is exactly HASH_STATE_LEN bytes by const construction.
            1 => Some(HMAC::<H, PARAMS>::from_suspended(
                state[4..4 + HASH_STATE_LEN].try_into().unwrap(),
                salt,
            )?),
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

        // infallible: the sub-slice is exactly 8 bytes by const construction.
        let entropy =
            u64::from_le_bytes(state[5 + HASH_STATE_LEN..13 + HASH_STATE_LEN].try_into().unwrap())
                as usize;
        let security_strength = SecurityStrength::try_from(state[13 + HASH_STATE_LEN])?;

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
