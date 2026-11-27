//! The generic HMAC-based Extract-and-Expand Key Derivation Function (HKDF) construction, as per
//! RFC 5869, which NIST SP 800-56Cr2 Section 5.1 describes as "a version of the above
//! extraction-then-expansion key-derivation procedure using HMAC for both the extraction and
//! expansion steps".
//!
//! It provides [`HKDF`] -- the construction, generic over any hash that implements
//! [`HKDFParams`], which names the HKDF over a hash that already has an HMAC ([`HMACParams`]) --
//! and its instantiations over the library's hashes:
//!
//! | Hash family | Instantiations                                      |
//! |-------------|-----------------------------------------------------|
//! | SHA-2       | [`HKDF_SHA256`], [`HKDF_SHA384`], [`HKDF_SHA512`]   |
//! | SM3         | [`HKDF_SM3`]                                        |
//! | RIPEMD      | [`HKDF_RIPEMD160`]                                  |
//!
//! The CLI exposes HKDF-SHA256 and HKDF-SHA512.
//!
//! An algorithm that derives its output through HKDF (a KEM such as ML-KEM-512-HKDF-SHA256) is
//! made from an [`HkdfDescription`], the hash and the salt as readable fields, as the KDF of a
//! `bouncycastle_core::kdf_params::KdfParams`; the pairing builds an instance keyed with the
//! salt from it for each derivation, and a key held in a token reads the fields instead.
//!
//! # Usage
//!
//! Since HKDF uses HMAC as its underlying primitive, most of what is said in the [`crate::hmac`]
//! module docs about key material applies here as well. Unlike HMAC, an HKDF object is created
//! without an initial key, and will self-initialize the internal HMAC object as part of the
//! [`HKDF::extract`] phase.
//!
//! # Usage Examples
//!
//! ## Deriving a key via the [`KDF`] trait
//!
//! Being a Key Derivation Function (KDF), the objective of HKDF is to take input key material which is not
//! directly usable for its intended purpose and transform into a suitable output key.
//! Typically, this takes one or both of the following forms:
//!
//! * Starting with a seed and mixing in additional input to diversify the output key (ie make it unique). An example of this would be starting with a secret seed and mixing in a public ID or URL to generate keys which are unique per URL.
//! * Starting with a full-entropy seed which is at the correct security level for the application, but which is not long enough. An example could be starting with a 128-bit seed and mixing it with the strings "read" and "write" to produce one AES-128 key for each of the two directions of a communication channel.
//!
//! The simplest usage is via the one-shot functions provided by the [`KDF`] trait.
//!
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::traits::KDF;
//! use bouncycastle_digest::hkdf::HKDF_SHA256;
//!
//! let key = KeyMaterial256::from_bytes_as_type(
//!             b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
//!             KeyType::Seed).unwrap();
//!
//! let hkdf = HKDF_SHA256::new();
//! let key = hkdf.derive_key(&key, b"extra input", 32).unwrap();
//! ```
//!
//! [`KDF::derive_key`] takes the length to produce, up to `255 * HashLen` (RFC 5869 Section 2.3);
//! [`KDF::derive_key_out`] writes it into a buffer of the caller's. An instance from
//! [`HKDF::new_with_salt`] runs the extract phase with that salt, one from [`HKDF::new`] with the
//! absent salt.
//!
//! As with other uses of [`KeyMaterialTrait`], the [`KDF::derive_key`] function will track the entropy of the input
//! key material, and will set the entropy of the output key material accordingly.
//!
//! The [`KDF`] trait also provides the [`KDF::derive_key_from_multiple`] and [`KDF::derive_key_from_multiple_out`]
//! functions, which allows for multiple inputs to be mixed into a single output key, and which allows
//! for some advanced control of the underlying HKDF primitive.
//!
//! ## HKDF Extract-and-Expand
//!
//! The HKDF algorithm defined in RFC 5869 and SP 800-56Cr2 is a two-step KDF, broken into an Extract step
//! which essentially absorbs entropy from the input key material,
//! and an Expand step which produces the output key material of any requested size.
//! This interface is essentially a pre-cursor to the [`XOF`] API which was introduced with SHA3; the main
//! difference being that HKDF-Expand needs to be told up-front how much output to produce, whereas XOFs
//! can stream output as needed.
//!
//! Naturally, the full two-step HKDF-Extract and HKDF-Expand interface is provided by the [`HKDF`] struct,
//! and exposes additional HKDF-specific parameters beyond what is exposed by the functions of the [`KDF`] trait.
//!
//! The usage pattern here is flexible, but generally follows the pattern of first calling [`HKDF::extract`]
//! with a `salt` and an input key material `ikm`, which produces a pseudorandom key `prk`.
//! The `prk` will have a [`KeyType`] and [`SecurityStrength`] that results from combining the two provided input keys,
//! The `prk` may be used directly as a full-entropy cryptographic key.
//!
//! Since the extract step may be called with any number of input keys, a streaming interface is provided
//! whereby streaming mode in initialized with a call to [`HKDF::do_extract_init`], and then
//! repeated calls to [`HKDF::do_extract_update_key`] and [`HKDF::do_extract_update_bytes`] may be made.
//! Entropy from the inputs keys provided via [`HKDF::do_extract_update_key`] are credited towards the output key,
//! while bytes provided via [`HKDF::do_extract_update_bytes`] are not.
//! One restriction here is that once you start provided un-credited bytes via [`HKDF::do_extract_update_bytes`],
//! no more calls to [`HKDF::do_extract_update_key`] may be made.
//! The streaming API is completed with a call to either [`HKDF::do_extract_final`] or [`HKDF::do_extract_final_out`].
//!
//! The second stage, [`HKDF::expand_out`] stretches the `prk` into a longer output key, typed
//! [`KeyType::CryptographicRandom`] when the PRK was credited and at the PRK's [`SecurityStrength`].
//!
//! A typical flow looks like this:
//!
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial, KeyMaterial256, KeyMaterialTrait, KeyType};
//! use bouncycastle_digest::hkdf::HKDF_SHA256;
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
//!  let mut hkdf = HKDF_SHA256::default();
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
//! use bouncycastle_core::key_material::{KeyMaterial, KeyMaterial256, KeyType};
//! use bouncycastle_digest::hkdf::HKDF_SHA256;
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
//! # Instantiating HKDF over a hash
//!
//! HKDF uses HMAC as its underlying primitive, so it works with the hashes HMAC works with:
//! [`HKDFParams`] has [`HMACParams`] as its supertrait and adds only the HKDF's name, HKDF
//! having no per-hash OID. This module implements it for the library's SHA-2, SHA-3, SM3 and
//! RIPEMD-160 hashes; for one of those an instantiation is just a type alias, and for a hash of
//! your own it is the one-line impl first.
//!
//! One limitation to be aware of when instantiating over a hash of your own: the extract phase
//! writes its pseudorandom key into a [`MAX_HMAC_OUTPUT_LEN`]-byte buffer, so the hash's output
//! length must not exceed that (64 bytes). See the note on that constant.
//!
//! ## Worked example
//!
//! This module instantiates HKDF-SHA256, HKDF-SHA384 and HKDF-SHA512 this way. The library does
//! not ship an HKDF-SHA224 alias, so that makes a good illustration of adding one:
//!
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::traits::KDF;
//! use bouncycastle_digest::hkdf::HKDF;
//! use bouncycastle_digest::sha2::SHA224;
//!
//! #[allow(non_camel_case_types)]
//! pub type HKDF_SHA224 = HKDF<SHA224>;
//!
//! // That is all it takes: the KDF trait and the extract/expand API are now available.
//! let ikm = KeyMaterial256::from_bytes_as_type(
//!             b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
//!             KeyType::Seed).unwrap();
//! let okm = HKDF_SHA224::new().derive_key(&ikm, b"extra input", 28).unwrap();
//! ```
//!
//! # Memory Usage
//!
//! The [`HKDF`] object uses no heap memory, and the `*_out` methods allocate nothing; the
//! `Box<dyn KeyMaterialTrait>`-returning one-shots of the `KDF` trait allocate their output.
//!
//! | Object           | Size (bytes) |
//! |------------------|--------------|
//! | `HKDF_SHA256`    | 368          |
//! | `HKDF_SHA384`    | 656          |
//! | `HKDF_SHA512`    | 656          |
//! | `HKDF_SM3`       | 368          |
//! | `HKDF_RIPEMD160` | 344          |
//!
//! The object is an `Option` of the extract phase's two halves, the salt key (two hash states,
//! the pads) and the inner hash absorbing the IKM -- three hash states, 336 bytes for SHA-256,
//! 624 for SHA-384 and SHA-512 -- plus the bookkeeping (the entropy counter, the accumulated
//! security strength, the state-machine tag and the absorbed flag, with padding); the `Option`
//! is niche-filled for SHA-256 and not for the larger pair, hence the uneven step.
//!
//! # 🚨 Security Considerations 🚨
//!
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
//! * The output is labelled full-entropy only once the credited input carries half a hash output
//!   of bytes, so the hash sets the bar: a 16-byte `CryptographicRandom` key seeds HKDF-SHA256
//!   and derives a `CryptographicRandom` key at 128 bits, but through HKDF-SHA512 the same key
//!   derives `Unknown` output. Choosing the stronger hash does not strengthen the label.
//! * Over a hash that claims no strength (RIPEMD-160) a seeded output is `CryptographicRandom`
//!   with [`SecurityStrength::None`]. A PRK so labelled has no strength for
//!   [`HKDF::expand_out`] to credit, so the two steps by hand give `Unknown` output where
//!   [`HKDF::extract_and_expand_out`] and the [`KDF`] derivations, which type the output from
//!   the keys that went in, give `CryptographicRandom`.
//! * RFC 5869 Section 3.1 recommends a random salt where one is available. SP 800-56Cr2 permits an
//!   all-zero salt, and the extract phase accepts one, but a salt that the caller believes to be
//!   random and is not provides none of the benefit the recommendation is aimed at.

use crate::hmac::hazmat as hmac_hazmat;
use crate::hmac::{HMACParams, HmacKey, LARGEST_HASHER_BLOCK_LEN};
use crate::ripemd::RIPEMD160;
use crate::sha2::{SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256};
use crate::sha3::{SHA3_224, SHA3_256, SHA3_384, SHA3_512};
use crate::sm3::SM3;
use bouncycastle_core::errors::{KDFError, KeyMaterialError, MACError};
use bouncycastle_core::hazmat::{
    KdfCredit, WithoutCollisionResistance, do_hazardous_operations, label_kdf_output,
};
use bouncycastle_core::kdf_params::KdfDescription;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterial0, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, KDF};
use bouncycastle_utils::secret::Secret;
use bouncycastle_utils::stack_wipe::wipe_stack_below;
use core::marker::PhantomData;
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

/// How much stack [`wipe_stack_below`] overwrites after each HKDF operation, which runs in a frame
/// of its own (the `*_in_own_frame` functions, `expand_fill`), in 64-bit words, for a hash whose
/// state is at most [`SMALL_HASH_STATE_LEN`] bytes (SHA-2, SM3, RIPEMD-160): more than an
/// operation leaves written below the frame that wipes, with room for a compiler that lays the
/// frames out less tightly. In the x86-64 release build 384 words clear every such hash with
/// rustc 1.88 and nightly (320 leave 48 bytes of a `KDF` derivation over SHA-384 or SHA-512;
/// HMAC's finishing wipes its own frames), and rustc 1.100 needs 452 for a `KDF` derivation over
/// SHA-512. 504 rather than 512: under massif, `bench_mlkem_mem_usage`'s HKDF rows read 2.5 to
/// 4 kB deeper with a 4096-byte wipe than with 4032. An unoptimised build's frames are not covered.
const HKDF_WIPED_STACK_WORDS: usize = 504;

/// As [`HKDF_WIPED_STACK_WORDS`], for a hash with a larger state (SHA-3): 768 words clear
/// SHA3-224 and SHA3-256, and a `KDF` derivation over SHA3-384 or SHA3-512 needs 960 (896 leave
/// 8 bytes) in the x86-64 release build.
const HKDF_LARGE_STATE_WIPED_STACK_WORDS: usize = 1152;

/// The hash state size, in bytes, up to which [`HKDF_WIPED_STACK_WORDS`] is enough. The depth an
/// operation writes to follows the size of the hash: its frames hold copies of hash states and of
/// [`HmacKey`]s, two states each, so SHA-3's 400-odd bytes of sponge reach further than SHA-512's
/// 200-odd. The block length does not order them the same way (SHA3-512's is shorter than
/// SHA-512's).
const SMALL_HASH_STATE_LEN: usize = 256;

/*** Parameters ***/

/// A hash HKDF is instantiated over: one with an HMAC ([`HMACParams`]), plus the name the
/// instantiation reports. Implemented here for the library's SHA-2, SHA-3, SM3 and RIPEMD-160
/// hashes; not sealed, so a hash defined elsewhere implements it the same way.
pub trait HKDFParams: HMACParams {
    /// The name of HKDF (RFC 5869) over this hash, as reported by [`Algorithm::ALG_NAME`].
    const HKDF_ALG_NAME: &'static str;
}

/*** Instantiations ***/

/// The name of HKDF over SHA-224, for `HKDFParams::HKDF_ALG_NAME`.
pub const HKDF_SHA224_NAME: &str = "HKDF-SHA224";
/// The name of HKDF over SHA-256, for `HKDFParams::HKDF_ALG_NAME`.
pub const HKDF_SHA256_NAME: &str = "HKDF-SHA256";
/// The name of HKDF over SHA-384, for `HKDFParams::HKDF_ALG_NAME`.
pub const HKDF_SHA384_NAME: &str = "HKDF-SHA384";
/// The name of HKDF over SHA-512, for `HKDFParams::HKDF_ALG_NAME`.
pub const HKDF_SHA512_NAME: &str = "HKDF-SHA512";
/// The name of HKDF over SHA-512/224, for `HKDFParams::HKDF_ALG_NAME`.
pub const HKDF_SHA512_224_NAME: &str = "HKDF-SHA512/224";
/// The name of HKDF over SHA-512/256, for `HKDFParams::HKDF_ALG_NAME`.
pub const HKDF_SHA512_256_NAME: &str = "HKDF-SHA512/256";

/// The name of HKDF over SHA3-224, for `HKDFParams::HKDF_ALG_NAME`.
pub const HKDF_SHA3_224_NAME: &str = "HKDF-SHA3-224";
/// The name of HKDF over SHA3-256, for `HKDFParams::HKDF_ALG_NAME`.
pub const HKDF_SHA3_256_NAME: &str = "HKDF-SHA3-256";
/// The name of HKDF over SHA3-384, for `HKDFParams::HKDF_ALG_NAME`.
pub const HKDF_SHA3_384_NAME: &str = "HKDF-SHA3-384";
/// The name of HKDF over SHA3-512, for `HKDFParams::HKDF_ALG_NAME`.
pub const HKDF_SHA3_512_NAME: &str = "HKDF-SHA3-512";
/// The name of HKDF over SM3, for `HKDFParams::HKDF_ALG_NAME`.
pub const HKDF_SM3_NAME: &str = "HKDF-SM3";
/// The name of HKDF over RIPEMD-160, for `HKDFParams::HKDF_ALG_NAME`.
pub const HKDF_RIPEMD160_NAME: &str = "HKDF-RIPEMD160";

impl HKDFParams for SHA224 {
    const HKDF_ALG_NAME: &'static str = HKDF_SHA224_NAME;
}
impl HKDFParams for SHA256 {
    const HKDF_ALG_NAME: &'static str = HKDF_SHA256_NAME;
}
impl HKDFParams for SHA384 {
    const HKDF_ALG_NAME: &'static str = HKDF_SHA384_NAME;
}
impl HKDFParams for SHA512 {
    const HKDF_ALG_NAME: &'static str = HKDF_SHA512_NAME;
}
impl HKDFParams for SHA512_224 {
    const HKDF_ALG_NAME: &'static str = HKDF_SHA512_224_NAME;
}
impl HKDFParams for SHA512_256 {
    const HKDF_ALG_NAME: &'static str = HKDF_SHA512_256_NAME;
}
impl HKDFParams for SHA3_224 {
    const HKDF_ALG_NAME: &'static str = HKDF_SHA3_224_NAME;
}
impl HKDFParams for SHA3_256 {
    const HKDF_ALG_NAME: &'static str = HKDF_SHA3_256_NAME;
}
impl HKDFParams for SHA3_384 {
    const HKDF_ALG_NAME: &'static str = HKDF_SHA3_384_NAME;
}
impl HKDFParams for SHA3_512 {
    const HKDF_ALG_NAME: &'static str = HKDF_SHA3_512_NAME;
}
impl HKDFParams for SM3 {
    const HKDF_ALG_NAME: &'static str = HKDF_SM3_NAME;
}
impl HKDFParams for RIPEMD160 {
    const HKDF_ALG_NAME: &'static str = HKDF_RIPEMD160_NAME;
}

/// HKDF over [`WithoutCollisionResistance<H>`] is HKDF over `H`, as its HMAC is.
impl<H: HKDFParams> HKDFParams for WithoutCollisionResistance<H> {
    const HKDF_ALG_NAME: &'static str = H::HKDF_ALG_NAME;
}

/// Public type for HKDF using SHA256.
#[allow(non_camel_case_types)]
pub type HKDF_SHA256 = HKDF<SHA256>;
/// Public type for HKDF using SHA384.
#[allow(non_camel_case_types)]
pub type HKDF_SHA384 = HKDF<SHA384>;
/// Public type for HKDF using SHA512.
#[allow(non_camel_case_types)]
pub type HKDF_SHA512 = HKDF<SHA512>;
/// Public type for HKDF using SM3.
#[allow(non_camel_case_types)]
pub type HKDF_SM3 = HKDF<SM3>;
/// Public type for HKDF using RIPEMD-160.
#[allow(non_camel_case_types)]
pub type HKDF_RIPEMD160 = HKDF<RIPEMD160>;

/*** Types ***/
/// The generic HKDF construction (RFC 5869).
///
/// Can be instantiated with hash functions other than the ones provided by this library (even custom
/// ones). The instantiations over the library's own hashes are the aliases in this module, such as
/// [`HKDF_SHA256`].
///
/// Not `Clone`: mid-extract it holds the salt key's pad states and an inner hash that has
/// absorbed the IKM, and keyed workers do not clone. A second derivation comes from the salt.
///
/// ```compile_fail
/// # use bouncycastle_digest::hkdf::HKDF;
/// # use bouncycastle_digest::sha2::SHA256;
/// fn cloneable<T: Clone>() {}
/// cloneable::<HKDF<SHA256>>();
/// ```
pub struct HKDF<H: HKDFParams> {
    // Optional because the extract-phase HMAC cannot be keyed until the salt is provided.
    // None must correspond to a state of Uninitialized.
    hmac: Option<HkdfExtract<H>>,
    /// What the salt, if typed [`KeyType::MACKey`], and the IKMs given as keys have credited.
    credit: KdfCredit,
    state: HkdfStates,
    /// Whether the extract phase has absorbed input keying material through the streaming API,
    /// which `Initialized` alone does not say: the [`KDF`] derivations refuse such an instance.
    ikm_absorbed: bool,
}

/// The extract phase's HMAC, held as its two halves: the salt key and the inner hash absorbing
/// the IKM. An `HMAC` worker borrows its key, and a struct cannot borrow from itself, so the
/// phase is run through `bouncycastle_digest::hmac::hazmat`'s `inner_state` and `finish_out` instead.
struct HkdfExtract<H: HKDFParams> {
    key: HmacKey<H>,
    inner: H,
}

// No Drop impl of its own: the sensitive state is the salt-keyed pad states inside `hmac` (RFC
// 2104 Section 4 says they "need to be treated and protected the same as secret keys"), and the
// hash types zeroize those in their own Drop.

#[derive(Clone, Debug, PartialOrd, PartialEq)]
enum HkdfStates {
    /// waiting for salt
    Uninitialized,

    /// Salt set, waiting for IKMs or do_final
    Initialized,

    /// [`HKDF::do_extract_update_key`] has been called, after which no more credited IKMs can be given.
    /// This keeps the input in the order used by the key-extraction method of NIST SP 800-133r2
    /// Section 6.3, `K = T(HMAC-hash(salt, K1 || ... || Kn || D1 || ... || Dm), kLen)`, in which the
    /// component keys precede the other data. Note (h) of that method explicitly permits alternative
    /// orderings ("including interleaving the keys and data"), so this ordering is conformant but is
    /// a restriction this API chooses, not one the specification imposes.
    TakingAdditionalInfo,
}

/// The name is [`HKDFParams::HKDF_ALG_NAME`]; the strength is the hash's, which the extract
/// and expand HMACs cannot exceed.
impl<H: HKDFParams> Algorithm for HKDF<H> {
    const ALG_NAME: &'static str = H::HKDF_ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = H::MAX_SECURITY_STRENGTH;
}

impl<H: HKDFParams> Default for HKDF<H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<H: HKDFParams> HKDF<H> {
    /// The credited bytes that seed a derivation, as `seed_len` of the [`KDF`] trait's rule.
    /// Library policy, not a rule from a standard: the output is credited as
    /// CryptographicRandom once at least OUTPUT_LEN / 2 bytes of typed key material with a
    /// strength have gone in, the bytes that carry the most the label can say
    /// (`MAX_STRENGTH`). SP 800-133r2 Section 6.3 (method 3, note (g)) asks that the component
    /// keys' min-entropies sum to at least the min-entropy the output needs; this counts bytes
    /// of material typed as key rather than min-entropy, and the same key given twice counts
    /// twice. The threshold is the strength bound rather than the full output length so that
    /// one 32-byte key, a KEM shared secret say, seeds HKDF-SHA512 as it does HKDF-SHA256.
    const SEED_LEN: usize = H::OUTPUT_LEN / 2;

    /// The most the label can say, as `max_strength` of the [`KDF`] trait's rule: the strength
    /// half a hash output of bytes holds, which for each of the library's hashes is also
    /// [`Algorithm::MAX_SECURITY_STRENGTH`] of the hash, the HMAC and this HKDF. Library
    /// policy: SP 800-56Cr2 Table 4 allows HMAC-hash extraction up to the full output length
    /// (112 <= s <= 256 for SHA-256), so this is the conservative choice, and it is why a
    /// 192- or 256-bit secret is paired with HKDF-SHA512. No input raises the label past it,
    /// and for a hash whose half output is under 112 bits (RIPEMD-160) it is
    /// [`SecurityStrength::None`], so a seeded output of that hash carries no strength.
    const MAX_STRENGTH: SecurityStrength = SecurityStrength::from_bytes(H::OUTPUT_LEN / 2);

    /// Overwrites the stack an operation's own-frame function used, by the hash's class (see
    /// [`SMALL_HASH_STATE_LEN`]). The branch is on a constant, so only one wipe is compiled in.
    /// Inlined, so that the wipe's frames start at the caller's stack pointer, where the
    /// operation's frame did, and not below a frame of this.
    #[inline(always)]
    fn wipe_below() {
        if size_of::<H>() <= SMALL_HASH_STATE_LEN {
            wipe_stack_below::<HKDF_WIPED_STACK_WORDS>();
        } else {
            wipe_stack_below::<HKDF_LARGE_STATE_WIPED_STACK_WORDS>();
        }
    }

    /// Get a new, uninstantiated HKDF object.
    pub fn new() -> Self {
        Self {
            hmac: None,
            credit: KdfCredit::new(),
            state: HkdfStates::Uninitialized,
            ikm_absorbed: false,
        }
    }

    /// An instance keyed with `salt` for the [`KDF`] trait's derivations, which then run
    /// extract-then-expand with it: RFC 5869 Section 2.2's salt, of any [`KeyType`] but
    /// [`KeyType::Unknown`], credited as keying material only when typed [`KeyType::MACKey`]
    /// (see [`HKDF::do_extract_init`]).
    ///
    /// # Errors
    /// [`KeyMaterialError::InvalidKeyType`], as a [`MACError`], for a salt typed `Unknown`.
    pub fn new_with_salt(salt: &(impl KeyMaterialTrait + ?Sized)) -> Result<Self, MACError> {
        let mut hkdf = Self::new();
        hkdf.do_extract_init(salt)?;
        Ok(hkdf)
    }

    /// Returns the amount of entropy currently credited from the keys inputted so far.
    pub fn get_entropy(&self) -> usize {
        self.credit.credited()
    }

    /// Check whether the entropy input so far met the threshold for this object to be considered fully seeded
    pub fn is_fully_seeded(&self) -> bool {
        self.credit.credited() >= Self::SEED_LEN
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
    /// [`KeyType::MACKey`], a secret salt; see the module's Security Considerations. The type of
    /// the output is set from what was credited.
    /// The output KeyMaterial will be of fixed size, with a capacity large enough to cover any
    /// underlying hash function, but the actual key length will be appropriate to the underlying hash function.
    ///
    /// Salt is optional, which is indicated by providing an uninitialized KeyMaterial object of length zero,
    /// the capacity is irrelevant, so KeyMaterial256::new() or KeyMaterial0::new() would both count as an absent salt.
    /// An algorithm that derives through HKDF holds the salt in an instance instead, from
    /// [`HKDF::new_with_salt`] or, for the absent salt, [`HKDF::new`], and derives through [`KDF`].
    pub fn extract(
        salt: &(impl KeyMaterialTrait + ?Sized),
        ikm: &(impl KeyMaterialTrait + ?Sized),
    ) -> Result<impl KeyMaterialTrait, MACError> {
        let mut prk = KeyMaterial::<MAX_HMAC_OUTPUT_LEN>::new();
        Self::extract_out(salt, ikm, &mut prk)?;
        Ok(prk)
    }

    /// Same as [`HKDF::extract`], but writes the output to a provided KeyMaterial buffer.
    /// Note that the provided KeyMaterial must be correctly sized to the hash function output length.
    pub fn extract_out(
        salt: &(impl KeyMaterialTrait + ?Sized),
        ikm: &(impl KeyMaterialTrait + ?Sized),
        prk: &mut KeyMaterial<MAX_HMAC_OUTPUT_LEN>,
    ) -> Result<usize, MACError> {
        // The `_out` rule: nothing stale survives, whichever way this returns.
        prk.zeroize();
        let result = Self::extract_in_own_frame(salt, ikm, prk);
        Self::wipe_below();
        result
    }

    /// [`Self::extract_out`]'s work. Never inlined, so that what it leaves of the salt key, the
    /// IKM and the PRK lies below its caller's frame, where the caller's wipe reaches it.
    #[inline(never)]
    fn extract_in_own_frame(
        salt: &(impl KeyMaterialTrait + ?Sized),
        ikm: &(impl KeyMaterialTrait + ?Sized),
        prk: &mut KeyMaterial<MAX_HMAC_OUTPUT_LEN>,
    ) -> Result<usize, MACError> {
        // PRK = HMAC-Hash(salt, IKM)
        let mut hkdf = Self::new();
        hkdf.do_extract_init_inner(salt)?;
        hkdf.do_extract_update_key(ikm)?;
        let bytes_written = hkdf.do_extract_final_in_own_frame(prk)?;

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
    /// The output is typed [`KeyType::CryptographicRandom`] when the PRK is full-entropy material
    /// with a strength, whatever its own type, and [`KeyType::Unknown`] otherwise, at the least of
    /// the PRK's strength, this HKDF's and the length's.
    ///
    /// L is the output length. [`KDFError::InvalidLength`] is returned if L is zero, exceeds
    /// 255 * HashLen, if `okm` cannot hold L bytes, or if `prk` is shorter than HashLen (RFC 5869
    /// Section 2.3).
    /// There is no upper bound on the PRK: one longer than the hash block is hashed first, as HMAC
    /// does with a long key (RFC 2104 Section 3), so the output is what HMAC keyed with it gives.
    ///
    /// Returns the number of bytes written.
    #[allow(non_snake_case)] // for L
    pub fn expand_out(
        prk: &(impl KeyMaterialTrait + ?Sized),
        info: &[u8],
        L: usize,
        okm: &mut (impl KeyMaterialTrait + ?Sized),
    ) -> Result<usize, KDFError> {
        // The `_out` rule: nothing stale survives, whichever way this returns.
        okm.zeroize();
        let written = Self::expand_fill(prk.ref_to_bytes(), info, L, okm);
        Self::wipe_below();
        let written = written?;
        // The output is the KDF's, not the PRK's: the [`KDF`] trait's rule with the PRK as the
        // one key. It is at least HashLen bytes, so a PRK that credits at all seeds the output.
        let labelled = label_kdf_output(&[prk], written, Self::SEED_LEN, Self::MAX_STRENGTH, okm);
        if labelled.is_err() {
            okm.zeroize();
        }
        labelled?;
        Ok(written)
    }

    /// RFC 5869 Section 2.3 with `prk` as the PRK: checks the lengths and writes the first `L`
    /// octets of T to the front of `okm`'s buffer, which the caller has zeroized and which is
    /// left for the caller to type, its length included. Returns `L`.
    ///
    /// # Errors
    /// [`KDFError::InvalidLength`] as [`Self::expand_out`] documents; `okm` is left zeroized.
    ///
    /// Never inlined, so that what it leaves of the PRK, its pad states and T lies below its
    /// caller's frame, where the caller's wipe reaches it.
    #[allow(non_snake_case)] // for L
    #[inline(never)]
    fn expand_fill(
        prk: &[u8],
        info: &[u8],
        L: usize,
        okm: &mut (impl KeyMaterialTrait + ?Sized),
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
        if L == 0 {
            return Err(KDFError::InvalidLength("HKDF-Expand: a zero-length output is refused"));
        }
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
        if prk.len() < hash_len {
            return Err(KDFError::InvalidLength(
                "HKDF-Expand: PRK must be at least HashLen bytes (RFC 5869 Sec 2.3)",
            ));
        }

        #[allow(non_snake_case)]
        let N = L.div_ceil(hash_len) as u8;
        let mut bytes_written: usize = 0;

        // Could potentially speed this up by unrolling T(0) and T(1)

        // The PRK, re-typed as the MAC key it is (see mac_key_copy). One key object for the whole
        // expansion: the pads are computed once here, before any byte of `okm` is written, and each
        // block's HMAC starts from a clone of them.
        let prk_key = HmacKey::<H>::from_key_material_unwiped(&Self::mac_key_copy(prk)?, false)?;

        // T(i) is output key material, so it zeroizes on drop.
        #[allow(non_snake_case)]
        let mut T: Secret<[u8; MAX_HMAC_OUTPUT_LEN]> = Secret::new();
        let mut t_len: usize = 0;
        let mut i = 1u8;

        let filled: Result<(), KDFError> = (|| {
            do_hazardous_operations(okm, |okm| {
                let out = okm.ref_to_bytes_mut()?;
                while i < N {
                    // The HMAC as its two hazmat halves, generic over the hash: the role impls
                    // name the tag length as a const, which `H: HMACParams` alone does not give.
                    let mut hmac = hmac_hazmat::inner_state(&prk_key);
                    hmac.do_update(&T[..t_len]);
                    hmac.do_update(info);
                    hmac.do_update(&[i]);

                    t_len = hmac_hazmat::finish_out(&prk_key, &mut hmac, &mut T[..hash_len]);
                    debug_assert_eq!(t_len, hash_len); // this will be true for every iteration after T(0) / T(1)
                    out[bytes_written..bytes_written + t_len].copy_from_slice(&T[..t_len]);
                    bytes_written += t_len;
                    i += 1;
                }
                Ok(())
            })?;

            // Part of the output is not taken on the last iteration. "OKM = first L octets of T", so the
            // last block T(N) is computed in full and only its first `remaining` octets are kept.
            let remaining = L - bytes_written;
            let mut hmac = hmac_hazmat::inner_state(&prk_key);
            hmac.do_update(&T[..t_len]);
            hmac.do_update(info);
            hmac.do_update(&[i]);

            t_len = hmac_hazmat::finish_out(&prk_key, &mut hmac, &mut T[..hash_len]);
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

        Ok(bytes_written)
    }

    /// Salt is optional, which is indicated by providing an uninitialized KeyMaterial object of length zero,
    /// the capacity is irrelevant, so KeyMaterial256::new() or KeyMaterial0::new() would both count as an absent salt.
    #[allow(non_snake_case)]
    pub fn extract_and_expand_out(
        salt: &(impl KeyMaterialTrait + ?Sized),
        ikm: &(impl KeyMaterialTrait + ?Sized),
        info: &[u8],
        L: usize,
        okm: &mut (impl KeyMaterialTrait + ?Sized),
    ) -> Result<usize, KDFError> {
        // The `_out` rule: nothing stale survives, whichever way this returns.
        okm.zeroize();
        let result = Self::extract_and_expand_in_own_frame(salt, ikm, info, L, okm);
        Self::wipe_below();
        result
    }

    /// [`Self::extract_and_expand_out`]'s work, on an `okm` the caller has zeroized. Never
    /// inlined, so that what it leaves of the salt key, the IKM, the PRK and T lies below its
    /// caller's frame, where the caller's wipe reaches it.
    #[allow(non_snake_case)]
    #[inline(never)]
    fn extract_and_expand_in_own_frame(
        salt: &(impl KeyMaterialTrait + ?Sized),
        ikm: &(impl KeyMaterialTrait + ?Sized),
        info: &[u8],
        L: usize,
        okm: &mut (impl KeyMaterialTrait + ?Sized),
    ) -> Result<usize, KDFError> {
        let mut hkdf = Self::new();
        hkdf.do_extract_init_inner(salt)?;
        hkdf.do_extract_update_key(ikm)?;
        // `do_extract_init` has set it.
        let HkdfExtract { key, inner } = hkdf.hmac.as_mut().unwrap();
        Self::extract_then_expand_out(key, inner, &hkdf.credit, info, L, okm)
    }

    /// Extract-then-expand as one derivation: RFC 5869 Section 2.2's `PRK = HMAC-Hash(salt,
    /// IKM)` finished from `inner`, which has absorbed the IKM under the salt `key`, then
    /// Section 2.3's expansion of it into `okm`, which the caller has zeroized. Returns `L`.
    ///
    /// The output is typed once, by the [`KDF`] trait's rule from `credit`, the account of the
    /// salt and the IKMs, and not through a typed PRK: a PRK carries what was credited only as
    /// its type and strength, and under a hash whose `MAX_STRENGTH` is none (RIPEMD-160) a
    /// seeded PRK has no strength for [`Self::expand_out`] to credit.
    #[allow(non_snake_case)] // for L
    fn extract_then_expand_out(
        key: &HmacKey<H>,
        inner: &mut H,
        credit: &KdfCredit,
        info: &[u8],
        L: usize,
        okm: &mut (impl KeyMaterialTrait + ?Sized),
    ) -> Result<usize, KDFError> {
        // The PRK is keying material in flight; a stack scratch, zeroized on drop.
        let mut prk: Secret<[u8; MAX_HMAC_OUTPUT_LEN]> = Secret::new();
        let prk_len = hmac_hazmat::finish_out(key, inner, &mut prk[..H::OUTPUT_LEN]);
        let written = Self::expand_fill(&prk[..prk_len], info, L, okm)?;
        let labelled = credit.label_output(written, Self::SEED_LEN, Self::MAX_STRENGTH, okm);
        if labelled.is_err() {
            okm.zeroize();
        }
        labelled?;
        Ok(written)
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
        salt: &(impl KeyMaterialTrait + ?Sized),
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
    pub fn do_extract_init(
        &mut self,
        salt: &(impl KeyMaterialTrait + ?Sized),
    ) -> Result<usize, MACError> {
        let result = self.do_extract_init_inner(salt);
        Self::wipe_below();
        result
    }

    /// [`Self::do_extract_init`]'s work. Never inlined, so that the copies of the salt key's pad
    /// states that moving it into `self` leaves lie below its caller's frame, where the caller's
    /// wipe reaches them.
    #[inline(never)]
    fn do_extract_init_inner(
        &mut self,
        salt: &(impl KeyMaterialTrait + ?Sized),
    ) -> Result<usize, MACError> {
        if self.state >= HkdfStates::Initialized {
            return Err(MACError::InvalidState("Initialized twice"));
        };

        // The salt is often empty or short, so HMAC's key-strength check is skipped; the entropy
        // credit below accounts for it.
        let salt_key = Self::salt_as_mac_key(salt)?;
        let key = HmacKey::<H>::from_key_material_unwiped(&salt_key, true)?;
        let inner = hmac_hazmat::inner_state(&key);
        self.hmac = Some(HkdfExtract { key, inner });

        // RFC 5869 Section 2.2 defines the salt as "a non-secret random value", and SP 800-133r2
        // Section 6.3 note (g) counts the component keys' entropy, not the salt's: a salt the
        // caller has not marked as a key credits nothing, or a public salt alone would label the
        // PRK full-entropy key material. A MACKey salt is SP 800-56Cr2 Section 5.1's secret salt.
        let additional_entropy =
            if salt.key_type() == KeyType::MACKey { self.credit.credit(salt) } else { 0 };
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
        ikm: &(impl KeyMaterialTrait + ?Sized),
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

        let additional_entropy = self.credit.credit(ikm);
        self.hmac.as_mut().unwrap().inner.do_update(ikm.ref_to_bytes());
        self.ikm_absorbed = true;

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
        self.ikm_absorbed = true;
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
        mut self,
        prk: &mut KeyMaterial<MAX_HMAC_OUTPUT_LEN>,
    ) -> Result<usize, MACError> {
        let result = self.do_extract_final_in_own_frame(prk);
        Self::wipe_below();
        result
    }

    /// [`Self::do_extract_final_out`]'s work, on the instance where it sits. Never inlined, so
    /// that what it leaves of the PRK lies below its caller's frame, where the caller's wipe
    /// reaches it.
    #[inline(never)]
    fn do_extract_final_in_own_frame(
        &mut self,
        prk: &mut KeyMaterial<MAX_HMAC_OUTPUT_LEN>,
    ) -> Result<usize, MACError> {
        // The `_out` rule: nothing stale survives, whichever way this returns.
        prk.zeroize();
        if self.state == HkdfStates::Uninitialized {
            return Err(MACError::InvalidState(
                "Must call do_extract_init() before calling do_extract_final().",
            ));
        };
        debug_assert!(self.hmac.is_some());

        let mut bytes_written = 0;
        let HkdfExtract { key, inner } = self.hmac.as_mut().unwrap();
        let filled = do_hazardous_operations(prk, |prk| {
            bytes_written = hmac_hazmat::finish_out(key, inner, prk.ref_to_bytes_mut()?);
            Ok(())
        });
        // What the PRK can claim is the [`KDF`] trait's rule over what was credited.
        let labelled = filled.and_then(|()| {
            self.credit.label_output(bytes_written, Self::SEED_LEN, Self::MAX_STRENGTH, prk)
        });
        if labelled.is_err() {
            prk.zeroize();
        }
        labelled?;
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
impl<H: HKDFParams> KDF for HKDF<H> {
    /// Extract-then-expand with the salt this instance was made with ([`HKDF::new_with_salt`]),
    /// or RFC 5869 Section 2.2's absent salt for one from [`HKDF::new`]: `ikm` is the IKM,
    /// `fixed_info` the expand phase's `info`.
    fn derive_key_out(
        &self,
        ikm: &dyn KeyMaterialTrait,
        fixed_info: &[u8],
        len: usize,
        output_key: &mut dyn KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        self.derive_key_from_multiple_out(&[ikm], fixed_info, len, output_key)
    }

    /// As [`KDF::derive_key_out`] with the IKM the concatenation of `ikms`, each credited (the
    /// same key twice is credited twice).
    ///
    /// # Errors
    /// As [`KDF::derive_key_out`]; [`KDFError::InvalidLength`] if `ikms` is empty; and
    /// [`KDFError::MACError`] with [`MACError::InvalidState`] if this instance has absorbed
    /// input keying material through the streaming API, since the derivation would then be over
    /// that material too.
    fn derive_key_from_multiple_out(
        &self,
        ikms: &[&dyn KeyMaterialTrait],
        fixed_info: &[u8],
        len: usize,
        output_key: &mut dyn KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        output_key.zeroize();
        let result = self.derive_in_own_frame(ikms, fixed_info, len, output_key);
        Self::wipe_below();
        result
    }
}

impl<H: HKDFParams> HKDF<H> {
    /// [`KDF::derive_key_from_multiple_out`]'s work, on an `output_key` the caller has zeroized.
    /// Never inlined, so that what it leaves of the IKMs, the PRK and T lies below its caller's
    /// frame, where the caller's wipe reaches it.
    #[inline(never)]
    fn derive_in_own_frame(
        &self,
        ikms: &[&dyn KeyMaterialTrait],
        fixed_info: &[u8],
        len: usize,
        output_key: &mut dyn KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        if ikms.is_empty() {
            return Err(KDFError::InvalidLength("a derivation from no keys is refused"));
        }
        if self.ikm_absorbed {
            return Err(KDFError::MACError(MACError::InvalidState(
                "a KDF instance holds its salt and nothing else; this HKDF has absorbed input keying material",
            )));
        }
        // The extract runs over the salt key where it sits, so the instance serves every
        // derivation and no second copy of the key's pad states is made: what a derivation makes
        // is the inner hash and the count of what was credited, which start from the instance's
        // (the refusal above means its own inner hash has absorbed nothing). An instance never
        // keyed takes RFC 5869 Section 2.2's absent salt, as `do_extract_init` builds it.
        let absent_salt;
        let key = match &self.hmac {
            Some(extract) => &extract.key,
            None => {
                let no_salt = Self::salt_as_mac_key(&KeyMaterial0::new())?;
                absent_salt = HmacKey::<H>::from_key_material_unwiped(&no_salt, true)?;
                &absent_salt
            }
        };
        let mut inner = hmac_hazmat::inner_state(key);
        let mut credit = self.credit;
        for ikm in ikms {
            credit.credit(*ikm);
            inner.do_update(ikm.ref_to_bytes());
        }
        Self::extract_then_expand_out(key, &mut inner, &credit, fixed_info, len, output_key)
    }
}

/// What an HKDF derivation is made from, as a KDF's description
/// ([`KdfDescription`]): the hash `H` and the salt, RFC 5869 Section 2.2's optional
/// `salt`, borrowed for `'s` and readable through [`salt`](Self::salt), absent for the
/// "string of HashLen zeros". An algorithm that derives through HKDF is made from one of these
/// as the KDF of `bouncycastle_core::kdf_params::KdfParams`; a software pairing keys an
/// [`HKDF`] with the salt through [`engine`](KdfDescription::engine) for each derivation, as
/// [`HKDF::new_with_salt`] does, and a key held where the secret must not leave reads the salt
/// and hands the device the same derivation. The salt is typed as the caller's material is: a
/// [`KeyType::MACKey`] salt is the secret salt the module's Security Considerations describe,
/// credited by the engine; any other type but [`KeyType::Unknown`], which is refused, is RFC
/// 5869's non-secret random value.
pub struct HkdfDescription<'s, H: HKDFParams> {
    salt: Option<&'s dyn KeyMaterialTrait>,
    _hash: PhantomData<H>,
}

impl<'s, H: HKDFParams> HkdfDescription<'s, H> {
    /// HKDF over `H` with the salt absent: RFC 5869 Section 2.2's "string of HashLen zeros".
    pub const fn new() -> Self {
        Self { salt: None, _hash: PhantomData }
    }

    /// HKDF over `H` keyed with `salt`, of any [`KeyType`] but [`KeyType::Unknown`]; a
    /// zero-length salt is the absent one.
    ///
    /// # Errors
    /// [`KeyMaterialError::InvalidKeyType`] for a salt typed `Unknown`, the refusal
    /// [`HKDF::new_with_salt`] makes, so that a description an engine cannot be built from does
    /// not exist.
    pub fn with_salt(salt: &'s dyn KeyMaterialTrait) -> Result<Self, KeyMaterialError> {
        if salt.key_type() == KeyType::Unknown {
            return Err(KeyMaterialError::InvalidKeyType("HKDF salt must not be KeyType::Unknown"));
        }
        Ok(Self { salt: Some(salt), _hash: PhantomData })
    }

    /// The salt, or `None` for the absent one.
    pub fn salt(&self) -> Option<&'s dyn KeyMaterialTrait> {
        self.salt
    }
}

impl<H: HKDFParams> Default for HkdfDescription<'_, H> {
    fn default() -> Self {
        Self::new()
    }
}

// Written out rather than derived: a derive would demand `H: Clone` of the hash.
impl<H: HKDFParams> Clone for HkdfDescription<'_, H> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<H: HKDFParams> Copy for HkdfDescription<'_, H> {}

/// The engine's name and strength, [`HKDF`]'s.
impl<H: HKDFParams> Algorithm for HkdfDescription<'_, H> {
    const ALG_NAME: &'static str = H::HKDF_ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = H::MAX_SECURITY_STRENGTH;
}

impl<H: HKDFParams> KdfDescription for HkdfDescription<'_, H> {
    type Engine = HKDF<H>;

    /// [`HKDF::new_with_salt`] with the salt, or [`HKDF::new`] without one.
    fn engine(&self) -> Result<HKDF<H>, KDFError> {
        match self.salt {
            Some(salt) => HKDF::new_with_salt(salt).map_err(KDFError::MACError),
            None => Ok(HKDF::new()),
        }
    }
}
