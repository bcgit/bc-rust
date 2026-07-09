//! HMAC-based Extract-and-Expand Key Derivation Function (HKDF) as per RFC5859, as allowed by
//! NIST SP 800-56Cr2.
//!
//! # Usage
//!
//! Since HKDF uses `HMAC<HASH>` as its underlying primitive, most of what is said in the [HMAC] crate docs
//! about instantiating HMAC objects applies here as well. Unlike HMAC, an HKDF object is created without
//! an initial key, and will self-initialize the internal HMAC object as part of the [HKDF::extract] phase.
//!
//!
//! # Examples
//! ## Constructing an object
//!
//! HMAC objects can be constructed with any underlying hash function that implements [Hash].
//! Type aliases are provided for the common HKDF-HASH algorithms.
//!
//! The following object instantiations are equivalent:
//!
//! ```
//! use bouncycastle_hkdf::HKDF_SHA256;
//!
//! let hkdf = HKDF_SHA256::new();
//! ```
//! and
//! ```
//! use bouncycastle_hkdf::HKDF;
//! use bouncycastle_sha2::SHA256;
//!
//! let hkdf = HKDF::<SHA256>::new();
//! ```
//!
//! ## Deriving a key via the [KDF] trait
//! Being a Key Derivation Function (KDF), the objective of HKDF is to take input key material which is not
//! directly usable for its intended purpose and transform into a suitable output key.
//! Typically, this takes one or both of the following forms:
//!
//! * Starting with a seed and mixing in additional input to diversify the output key (ie make it unique). An example of this would be starting with a secret seed and mixing in a public ID or URL to generate keys which are unique per URL.
//! * Starting with a full-entropy seed which is at the correct security level for the application, but which is not long enough. An example could be starting with a 128-bit seed and mixing it with the strings "read" and "write" to produce one AES-128 key for each of the two directions of a communication channel.
//!
//! The simplest usage is via the one-shot functions provided by the [KDF] trait.
//!
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::traits::{KDF };
//! use bouncycastle_hkdf::HKDF_SHA256;
//!
//! let key = KeyMaterial256::from_bytes_as_type(
//!             b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
//!             KeyType::Seed).unwrap();
//!
//! let hkdf = HKDF_SHA256::new();
//! let key = hkdf.derive_key(&key, b"extra input").unwrap();
//! ```
//!
//! [KDF::derive_key] will produce a key the same length as the underlying hash function.
//! Longer output can be requested by instead using [KDF::derive_key_out] and providing a larger output buffer,
//! which will be filled.
//!
//! As with other uses of [KeyMaterialTrait], the [KDF::derive_key] function will track the entropy of the input
//! key material, and will set the entropy of the output key material accordingly.
//!
//! The [KDF] trait also provides the [KDF::derive_key_from_multiple] and [KDF::derive_key_from_multiple_out]
//! functions, which allows for multiple inputs to be mixed into a single output key, and which allows
//! for some advanced control of the underlying HKDF primitive.
//!
//!
//! ## HKDF Extract-and-Expand
//!
//! The HKDF algorithm defined in RFC5896 and SP 800-56Cr2 is a two-step KDF, broken into an Extract step
//! which essentially absorbs entropy from the input key material,
//! and an Expand step which produces the output key material of any requested size.
//! This interface is essentially a pre-cursor to the [XOF] API which was introduced with SHA3; the main
//! difference being that HKDF-Expand needs to be told up-front how much output to produce, whereas XOFs
//! can stream output as needed.
//!
//! Naturally, the full two-step HKDF-Extract and HKDF-Expand interface is provided by the [HKDF] struct,
//! and exposes additional HKDF-specific parameters beyond what is exposed by the functions of the [KDF] trait.
//!
//! The usage pattern here is flexible, but generally follows the pattern of first calling [HKDF::extract]
//! with a `salt` and an input key material `ikm`, which produces a pseudorandom key `prk`.
//! The `prk` will have a [KeyType] and [SecurityStrength] that results from combining the two provided input keys,
//! The `prk` may be! used directly as a full-entropy cryptographic key.
//!
//! Since the extract step may be called with any number of input keys, a streaming interface is provided
//! whereby streaming mode in initialized with a call to [HKDF::do_extract_init], and then
//! repeated calls to [HKDF::do_extract_update_key] and [HKDF::do_extract_update_bytes] may be made.
//! Entropy from the inputs keys provided via [HKDF::do_extract_update_key] are credited towards the output key,
//! while bytes provided via [HKDF::do_extract_update_bytes] are not.
//! One restriction here is that once you start provided un-credited bytes via [HKDF::do_extract_update_bytes],
//! no more calls to [HKDF::do_extract_update_key] may be made.
//! The streaming API is completed with a call to either [HKDF::do_extract_final] or [HKDF::do_extract_final_out].
//!
//! The second stage, [HKDF::expand_out] stretches the `prk` into a longer output key, still of the same [KeyType]
//! and [SecurityStrength].
//!
//! A typical flow looks like this:
//!
//! ```
//! use bouncycastle_core::key_material::{KeyMaterialTrait, KeyMaterial256, KeyMaterial, KeyType};
//! use bouncycastle_core::traits::KDF;
//! use bouncycastle_hkdf::{HKDF, HKDF_SHA256};
//! use bouncycastle_sha2::{SHA256};
//!
//! // setup variables
//! let salt = KeyMaterial256::from_bytes_as_type(
//!             b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
//!             KeyType::MACKey).unwrap();
//!
//!  let ikm = KeyMaterial256::from_bytes_as_type(
//!             b"\x0f\x0e\x0d\x0c\x0b\x0a\x09\x08\x07\x06\x05\x04\x03\x02\x01\x00",
//!             KeyType::MACKey).unwrap();
//!
//! let info = b"some extra context info";
//!
//!  // Use the streaming API to derive an output key of length 200 bytes.
//!  let mut okm = KeyMaterial::<200>::new();
//!  let mut hkdf = HKDF::<SHA256>::default();
//!  hkdf.do_extract_init(&salt).unwrap();
//!  hkdf.do_extract_update_bytes(ikm.ref_to_bytes()).unwrap();
//!  let prk = hkdf.do_extract_final().unwrap();
//!  HKDF_SHA256::expand_out(&prk, info, 200, &mut okm).unwrap();
//! ```
//!
//! Various convenience wrapper functions are provided which can reduce the amount of boilerplate code
//! for common cases.
//! For example, the above code can be condensed to:
//!
//! ```
//! use bouncycastle_core::key_material::{KeyMaterialTrait, KeyMaterial256, KeyMaterial, KeyType};
//! use bouncycastle_hkdf::{HKDF_SHA256};
//!
//! // setup variables
//! let salt = KeyMaterial256::from_bytes_as_type(
//!             b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
//!             KeyType::MACKey).unwrap();
//!
//!  let ikm = KeyMaterial256::from_bytes_as_type(
//!             b"\x0f\x0e\x0d\x0c\x0b\x0a\x09\x08\x07\x06\x05\x04\x03\x02\x01\x00",
//!             KeyType::MACKey).unwrap();
//!
//! let info = b"some extra context info";
//!
//! // Use the one-shot API to derive an output key of length 200 bytes.
//! let mut okm = KeyMaterial::<200>::new();
//! let _bytes_written = HKDF_SHA256::extract_and_expand_out(&salt, &ikm, info, 200, &mut okm).unwrap();
//! ```
//!
//! # Suspending and resuming execution
//!
//! The *HKDF-Extract* phase supports a streaming API whereby any amount of additional input keying
//! material can be provided either via [HKDF::do_extract_update_key] -- which will
//! credit the entropy of the provided [KeyMaterial] -- or as raw uncredited bytes via
//! [HKDF::do_extract_update_bytes].
//!
//! As such, The *HKDF-Extract* phase can be suspended to a cache and resumed later via the
//! [SuspendableKeyed] trait.
//!
//! The HKDF algorithm is keyed by a `salt`, which is required twice: once at initialization and again
//! during finalization. Suspension and resumption are supported via the [SuspendableKeyed] trait
//! which requires the caller to store the salt securely and provide it again during resumption.
//! Note that providing a different salt during resumption cannot be detected by the library and
//! would silently produce a different PRK.
//!
//! ```rust
//! use bouncycastle_hkdf::HKDF_SHA256;
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::traits::SuspendableKeyed;
//!
//! let salt = KeyMaterial256::from_bytes_as_type(
//!             b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
//!             KeyType::MACKey).unwrap();
//! let ikm_part1 = b"input keying material part 1";
//! let ikm_part2 = b" ...and part 2";
//!
//! let mut hkdf = HKDF_SHA256::new();
//! hkdf.do_extract_init(&salt).unwrap();
//! hkdf.do_extract_update_bytes(ikm_part1).unwrap();
//!
//! // suspend the in-progress extract (the salt is NOT included in the serialized state)
//! let serialized_state = hkdf.suspend();
//!
//! // ...
//! // do other things in the meantime
//! // ...
//!
//! // ... later, possibly on another host: resume from the serialized state by re-supplying
//! // the same salt (make sure you store it securely!).
//! let mut hkdf = HKDF_SHA256::from_suspended(serialized_state, &salt).unwrap();
//! hkdf.do_extract_update_bytes(ikm_part2).unwrap();
//! let _prk = hkdf.do_extract_final().unwrap();
//! ```

#![forbid(unsafe_code)]

use bouncycastle_core::errors::{KDFError, KeyMaterialError, MACError, SuspendableError};
use bouncycastle_core::key_material;
use bouncycastle_core::key_material::{
    KeyMaterial, KeyMaterial0, KeyMaterial512, KeyMaterialTrait, KeyType,
};
use bouncycastle_core::suspendable_state::{add_lib_ver, check_lib_ver};
use bouncycastle_core::traits::{
    Hash, HashAlgParams, KDF, MAC, SecurityStrength, SuspendableKeyed,
};
use bouncycastle_hmac::{HMAC, SUSPENDED_HMAC_SHA256_STATE_LEN, SUSPENDED_HMAC_SHA512_STATE_LEN};
use bouncycastle_sha2::{SHA256, SHA512};
use bouncycastle_utils::{max, min};
use std::marker::PhantomData;
// Imports needed only for docs
#[allow(unused_imports)]
use bouncycastle_core::traits::XOF;
// end doc-only imports

/*** Constants ***/
// Slightly hacky, but set this to accommodate the underlying hash primitive with the largest output size.
// Would be better to somehow pull that at compile time from H, but I'm not sure how to do that.
const HMAC_BLOCK_LEN: usize = 64;

/*** String constants ***/

pub const HKDF_SHA256_NAME: &str = "HKDF-SHA256";
pub const HKDF_SHA512_NAME: &str = "HKDF-SHA512";

/*** Types ***/
#[allow(non_camel_case_types)]
pub type HKDF_SHA256 = HKDF<SHA256>;
#[allow(non_camel_case_types)]
pub type HKDF_SHA512 = HKDF<SHA512>;

#[derive(Clone)]
pub struct HKDF<H: Hash + HashAlgParams + Default> {
    // Optional because we can't construct an HMAC until they give us a key
    // to initialize it with.
    // None should correspond to a state of Uninitialized.
    hmac: Option<HMAC<H>>,
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

    /// [HKDF::do_extract_update_key] has been called, after which no more credited IKMs can be given.
    /// This is in conformance with NIST SP 800-133 which requires all keys to come before other inputs.
    TakingAdditionalInfo = 2,
}

impl TryFrom<u8> for HkdfStates {
    type Error = SuspendableError;

    /// Inverse of `self as u8`; rejects unrecognized discriminants with [SuspendableError::InvalidData].
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

    /// Either [KeyMaterialTrait::BytesLowEntropy] or [KeyMaterialTrait::BytesFullEntropy] depending on
    /// whether enough input key material was provided for the internal hash function to have a full block.
    fn get_output_key_type(&self) -> KeyType {
        if self.is_fully_seeded() { KeyType::CryptographicRandom } else { KeyType::Unknown }
    }
}

// Since I don't want this struct to be public, the tests have to go here.
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

impl<H: Hash + HashAlgParams + Default> Default for HKDF<H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<H: Hash + HashAlgParams + Default> HKDF<H> {
    pub fn new() -> Self {
        Self { hmac: None, entropy: HkdfEntropyTracker::new(), state: HkdfStates::Uninitialized }
    }

    /// Returns the amount of entropy currently credited from the keys inputted so far.
    pub fn get_entropy(&self) -> usize {
        self.entropy.get_entropy()
    }

    /// Has the entropy input so far met the threshold for this object to be considered fully seeded?
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
    /// The KeyMaterial input parameters can be of any [KeyType]; but the type of the output will be set accordingly.
    /// The output KeyMaterial will be of fixed size, with a capacity large enough to cover any
    /// underlying hash function, but the actual key length will be appropriate to the underlying hash function.
    ///
    /// Salt is optional, which is indicated by providing an uninitialized KeyMaterial object of length zero,
    /// the capacity is irrelevant, so KeyMateriol256::new() or KeyMaterial_internal::<0>::new() would both count as an absent salt.
    pub fn extract(
        salt: &impl KeyMaterialTrait,
        ikm: &impl KeyMaterialTrait,
    ) -> Result<impl KeyMaterialTrait, MACError> {
        let mut prk = KeyMaterial::<HMAC_BLOCK_LEN>::new();
        Self::extract_out(salt, ikm, &mut prk)?;
        Ok(prk)
    }

    /// Same as [HKDF::extract], but writes the output to a provided KeyMaterial buffer.
    pub fn extract_out(
        salt: &impl KeyMaterialTrait,
        ikm: &impl KeyMaterialTrait,
        prk: &mut impl KeyMaterialTrait,
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
    /// L is the output length. This will throw a [MACError::InvalidLength] if the provided KeyMaterial is too small to hold the requested output.
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

        // We're gonna have to kludge the prk key type to MACKey to make HMAC happy, but we'll set it back to the original value afterwards.
        let prk_as_mac_key =
            KeyMaterial::<HMAC_BLOCK_LEN>::from_bytes_as_type(prk.ref_to_bytes(), KeyType::MACKey)?;

        #[allow(non_snake_case)]
        let mut T = [0u8; HMAC_BLOCK_LEN];
        let mut t_len: usize = 0;
        let mut i = 1u8;

        key_material::do_hazardous_operations(okm, |okm| {
            let out = okm.ref_to_bytes_mut()?;
            while i < N {
                let mut hmac = HMAC::<H>::new(&prk_as_mac_key)
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

        // On the last iteration, we don't take all of the output.
        let remaining = L - bytes_written;
        let mut hmac = HMAC::<H>::new(&prk_as_mac_key)?;
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

        // set the KeyType of the output
        // since we've done some computation, the result will not actually be zeroized, even if all input key material was zeroized.
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

    /// This, together with [HKDF::do_extract_update_key], [HKDF::do_extract_update_bytes] and [HKDF::do_extract_final]
    /// provide a streaming interface for very long values of `ikm`.
    /// In this mode, the entropy of `ikm` is untracked, and so only the entropy ef `salt` is taken into account
    /// when computing the entropy of the output `prk`.
    /// The KeyMaterial input parameters can be of any [KeyType]; but the type of the output will be set accordingly.
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
        // So we're gonna ignore key strength errors here
        // This will all be tabulated correctly via entropy.credit_entropy()
        self.hmac = Some(HMAC::<H>::new_allow_weak_key(salt)?);

        let additional_entropy = self.entropy.credit_entropy(salt);
        self.state = HkdfStates::Initialized;

        Ok(additional_entropy)
    }

    /// An update function that allows adding an IKM as a [KeyMaterialTrait].
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
        let hmac_ref: &mut HMAC<H> = self.hmac.as_mut().unwrap();
        hmac_ref.do_update(ikm.ref_to_bytes());
        // self.hmac.as_mut().unwrap().do_update(ikm.ref_to_bytes());

        Ok(additional_entropy)
    }

    /// An update function that allows streaming of the IKM as bytes.
    /// Note that since this interface takes the IKM as raw bytes, it cannot track its entropy
    /// and therefore any IKM material provided through this interface will not count towards
    /// the entropy of the output key.
    ///
    /// State machine: this function must be called after [HKDF::do_extract_init], followed by
    /// zero or more calls of [HKDF::do_extract_update_key], and before [HKDF::do_extract_final].
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

    #[allow(non_snake_case)]
    pub fn do_extract_final(self) -> Result<impl KeyMaterialTrait, MACError> {
        let mut okm = KeyMaterial::<HMAC_BLOCK_LEN>::new();
        self.do_extract_final_out(&mut okm)?;
        Ok(okm)
    }

    #[allow(non_snake_case)]
    pub fn do_extract_final_out(self, okm: &mut impl KeyMaterialTrait) -> Result<usize, MACError> {
        if self.state == HkdfStates::Uninitialized {
            return Err(MACError::InvalidState(
                "Must call do_extract_init() before calling do_extract_complete().",
            ));
        };
        debug_assert!(self.hmac.is_some());

        let output_key_type = self.entropy.get_output_key_type(); // need to do this above self.hmac.do_final_out, which will consume self.

        let mut bytes_written = 0;
        key_material::do_hazardous_operations(okm, |okm| {
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
        Ok(bytes_written)
    }
}

/// As per NIST SP 800-56Cr2 section 5.1, HKDF extract_and_expand can be used as a KDF.
/// Additionally, section 4.1 says that when using HMAC as a KDF, the salt may be set to
/// a string of HashLen zeros. All key material and additional_input is mapped to HKDF's ikm input.
/// While this is not the only mode in which HKDF can be used as a KDF, this is considered the default mode
/// that is exposed through [KDF::derive_key] and [KDF::derive_key_out].
/// More advanced control of the inputs to HKDF can be achieved by using [KDF::derive_key_from_multiple] and
/// [KDF::derive_key_from_multiple_out], or by using the [HKDF] impl directly.
///
/// Entropy tracking: this implementation will map entropy from the input keys to the output key.
impl<H: Hash + HashAlgParams + Default> KDF for HKDF<H> {
    /// This invokes [HKDF::extract_and_expand_out] with a zero salt and using the provided key as ikm.
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

    /// This invokes [HKDF::extract_and_expand_out] with a zero salt and using the provided key as ikm.
    /// This fills the provided [KeyMaterialTrait] object in place of exposing a Length parameter.
    fn derive_key_out(
        self,
        key: &impl KeyMaterialTrait,
        additional_input: &[u8],
        output_key: &mut impl KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        let bytes_written = HKDF::<H>::extract_and_expand_out(
            &KeyMaterial::<0>::new(),
            key,
            additional_input,
            output_key.capacity(),
            output_key,
        )?;
        Ok(bytes_written)
    }

    /// As with [KDF::derive_key] and [KDF::derive_key_out],
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

    /// This behaves the same as [KDF::derive_key_from_multiple], except that it fills the provided
    /// [KeyMaterialTrait] object in place of exposing a Length parameter.
    fn derive_key_from_multiple_out(
        self,
        keys: &[&impl KeyMaterialTrait],
        additional_input: &[u8],
        output_key: &mut impl KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        let mut hkdf = HKDF::<H>::new();
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
        let mut prk = KeyMaterial::<HMAC_BLOCK_LEN>::new();
        _ = hkdf.do_extract_final_out(&mut prk)?;
        let bytes_written =
            HKDF::<H>::expand_out(&prk, additional_input, output_key.capacity(), output_key)?;

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

/// Length in bytes of the serialized state of [HKDF_SHA256].
pub const SUSPENDED_HKDF_SHA256_STATE_LEN: usize = SUSPENDED_HMAC_SHA256_STATE_LEN + 14;
/// Length in bytes of the serialized state of [HKDF_SHA512].
pub const SUSPENDED_HKDF_SHA512_STATE_LEN: usize = SUSPENDED_HMAC_SHA512_STATE_LEN + 14;

/// HKDF is *keyed by its salt* -- the salt keys the extract-phase HMAC -- so it implements
/// [SuspendableKeyed] (not [SerializableState]). An in-progress
/// extract operation can be suspended and resumed, but the salt is NOT written into the serialized
/// state and must be re-supplied to [SuspendableKeyed::from_serialized_state].
///
/// Only the extract phase carries resumable state (expand is a one-shot static operation). As with
/// HMAC, resuming with the wrong salt cannot be detected and will silently produce a wrong PRK.
///
/// Serialized layout: HKDF writes its own 3-byte library version header first and checks it before
/// parsing anything else. This matters because the inner HMAC blob (which carries its own header) is
/// absent before extract is initialized -- without HKDF's own header, a pre-init state would have no
/// version tag at all. Using `B` = the inner HMAC blob length:
///   [0 .. 3)             HKDF library version header (checked on resume)
///   [3]                  inner-HMAC present flag (0 = extract not yet initialized)
///   [4 .. 4 + B)         the inner HMAC's SuspendableKeyed blob (salt excluded); zeroed when absent
///   [4 + B]              state-machine tag (see `HkdfStates`)
///   [5 + B .. 13 + B)    entropy counter (usize serialized as u64, little-endian)
///   [13 + B]             accumulated security strength (1-byte tag)
/// So the total per HKDF variant is the 3-byte version header + 11 bytes of HKDF bookkeeping
/// (present flag, state tag, entropy counter, security strength) + the inner HMAC's blob = `B + 14`.
macro_rules! impl_suspendable_keyed_state_for_hkdf {
    // $hash: the concrete hash; $serialized_hmac_len: the inner HMAC's serialized-state length for that
    // hash; $serialized_hkdf_len: the full HKDF serialized-state length (= 3 + 11 + $serialized_hmac_len).
    ($hash:ty, $serialized_hmac_len:expr, $serialized_hkdf_len:expr) => {
        impl SuspendableKeyed<{ $serialized_hkdf_len }> for HKDF<$hash> {
            // HMAC accepts any key material, so the key type is the trait object `dyn KeyMaterialTrait`
            // rather than a single concrete key type. The key is only used (by reference) to reload the key
            // bytes at from_serialized_state, so dynamic dispatch here is negligible.
            type Key = dyn KeyMaterialTrait;

            fn suspend(self) -> [u8; $serialized_hkdf_len] {
                debug_assert_eq!($serialized_hkdf_len, $serialized_hmac_len + 14);
                let mut state = [0u8; $serialized_hkdf_len];

                // HKDF's own library version header comes first: the inner HMAC blob is absent before
                // extract is initialized, so we can't rely on its header being present.
                add_lib_ver(&mut state);

                // The present flag, then (when present) the inner salt-keyed HMAC blob right after it.
                if let Some(hmac) = self.hmac {
                    state[3] = 1; // present flag
                    state[4..4 + $serialized_hmac_len].copy_from_slice(&hmac.suspend());
                }
                // else None:
                //  the presence flag = 0
                //  the content = [u8; 0]
                // which is how it already is, so nothing to do.

                state[4 + $serialized_hmac_len] = self.state as u8;
                state[5 + $serialized_hmac_len..13 + $serialized_hmac_len]
                    .copy_from_slice(&(self.entropy.entropy as u64).to_le_bytes());
                state[13 + $serialized_hmac_len] = self.entropy.security_strength as u8;

                state
            }

            fn from_suspended(
                state: [u8; $serialized_hkdf_len],
                salt: &Self::Key,
            ) -> Result<Self, SuspendableError> {
                // Check HKDF's own version header before parsing anything else.
                check_lib_ver(&state, None)?;

                // Rebuild the salt-keyed HMAC (when present) by re-supplying the salt.
                let hmac = match state[3] {
                    0 => None,
                    // infallible: the sub-slice is exactly $serialized_hmac_len bytes by const construction.
                    1 => Some(HMAC::<$hash>::from_suspended(
                        state[4..4 + $serialized_hmac_len].try_into().unwrap(),
                        salt,
                    )?),
                    _ => return Err(SuspendableError::InvalidData),
                };

                let hkdf_state = HkdfStates::try_from(state[4 + $serialized_hmac_len])?;

                // check that the hkdf_state aligns with the presence of an hmac
                if
                    // an hmac object should not be present in the init state.
                    (hmac.is_some() && hkdf_state == HkdfStates::Uninitialized) ||
                    // any other state must have an hmac object.
                    (hmac.is_none() && hkdf_state != HkdfStates::Uninitialized)
                {
                    return Err(SuspendableError::InvalidData);
                }

                // infallible: the sub-slice is exactly 8 bytes by const construction.
                let entropy = u64::from_le_bytes(
                    state[5 + $serialized_hmac_len..13 + $serialized_hmac_len].try_into().unwrap(),
                ) as usize;
                let security_strength =
                    SecurityStrength::try_from(state[13 + $serialized_hmac_len])?;

                Ok(HKDF {
                    hmac,
                    entropy: HkdfEntropyTracker {
                        _phantomhash: PhantomData,
                        entropy,
                        security_strength,
                    },
                    state: hkdf_state,
                })
            }
        }
    };
}

impl_suspendable_keyed_state_for_hkdf!(
    SHA256,
    SUSPENDED_HMAC_SHA256_STATE_LEN,
    SUSPENDED_HKDF_SHA256_STATE_LEN
);
impl_suspendable_keyed_state_for_hkdf!(
    SHA512,
    SUSPENDED_HMAC_SHA512_STATE_LEN,
    SUSPENDED_HKDF_SHA512_STATE_LEN
);
