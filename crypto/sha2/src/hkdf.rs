//! HMAC-based Extract-and-Expand Key Derivation Function (HKDF) over the SHA-2 hashes, as per
//! RFC 5869, as allowed by NIST SP 800-56Cr2.
//!
//! Uses [`bouncycastle_hkdf`] to provide the HKDF-SHA2 instantiations: [`HKDF_SHA256`] and
//! [`HKDF_SHA512`]. Only those two are instantiated, matching what the KDF factory and the CLI
//! expose.
//!
//! HKDF is implemented generically in [`bouncycastle_hkdf`]; this module pins its const parameters
//! to the SHA-2 hashes and publishes the resulting type aliases, so that HKDF over a SHA-2 hash is
//! found in this crate, and [`bouncycastle_hkdf`] serves as a utility crate rather than as part of
//! the library's public API.
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
//! use bouncycastle_sha2::hkdf::HKDF_SHA256;
//!
//! let key = KeyMaterial256::from_bytes_as_type(
//!             b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
//!             KeyType::Seed).unwrap();
//!
//! let hkdf = HKDF_SHA256::new();
//! let key = hkdf.derive_key(&key, b"extra input").unwrap();
//! ```
//!
//! [`KDF::derive_key`] will produce a key the same length as the underlying hash function.
//! Longer output can be requested by instead using [`KDF::derive_key_out`] and providing a larger output buffer,
//! which will be filled.
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
//! The second stage, [`HKDF::expand_out`] stretches the `prk` into a longer output key, still of the same [`KeyType`]
//! and [`SecurityStrength`].
//!
//! A typical flow looks like this:
//!
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial, KeyMaterial256, KeyMaterialTrait, KeyType};
//! use bouncycastle_sha2::hkdf::HKDF_SHA256;
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
//! use bouncycastle_sha2::hkdf::HKDF_SHA256;
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
//! ## Suspending and resuming execution
//!
//! The *HKDF-Extract* phase supports a streaming API whereby any amount of additional input keying
//! material can be provided either via [`HKDF::do_extract_update_key`] -- which will
//! credit the entropy of the provided [`KeyMaterial`] -- or as raw uncredited bytes via
//! [`HKDF::do_extract_update_bytes`].
//!
//! As such, the *HKDF-Extract* phase can be suspended to a cache and resumed later via the
//! [`SuspendableKeyed`] trait.
//!
//! The HKDF algorithm is keyed by a `salt`, which is required twice: once at initialization and again
//! during finalization. Suspension and resumption are supported via the [`SuspendableKeyed`] trait
//! which requires the caller to store the salt securely and provide it again during resumption.
//! Note that providing a different salt during resumption cannot be detected by the library and
//! would silently produce a different PRK.
//!
//! ```rust
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::traits::SuspendableKeyed;
//! use bouncycastle_sha2::hkdf::HKDF_SHA256;
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
//!
//! # Memory Usage
//!
//! The HKDF object itself uses no heap memory; the `Vec`-returning and `Box<dyn KeyMaterialTrait>`
//! -returning convenience methods of the [`KDF`] trait allocate their output, and the `*_out`
//! variants allocate nothing.
//!
//! | Object                                            | Size (bytes) |
//! |---------------------------------------------------|--------------|
//! | `HKDF_SHA256`                                     | 216          |
//! | `HKDF_SHA512`                                     | 376          |
//! | Suspended `HKDF_SHA256` state                     | 122          |
//! | Suspended `HKDF_SHA512` state                     | 218          |
//!
//! The object is an `Option` of the inner extract-phase HMAC -- 192 bytes for SHA-256, 352 for
//! SHA-512 -- plus 24 bytes of bookkeeping (the entropy counter, the accumulated security strength
//! and the state-machine tag, with padding). The inner HMAC is the published
//! [`crate::hmac::HMAC_SHA256`] rather than an anonymous one, so its key buffer is sized to the
//! hash's block length like any other: an `HKDF_SHA256` is 32 bytes larger than the HMAC it is
//! built on, not 112.
//!
//! The suspended state is the inner HMAC's suspended state (which is the hash's) plus 14 bytes; the
//! salt is deliberately excluded and must be re-supplied on resume.
//!
//! # Security Considerations
//!
//! * Resuming a suspended HKDF with a different salt cannot be detected and silently produces a
//!   different PRK; see the suspend/resume section above.
//! * Entropy is only credited for input supplied via [`HKDF::do_extract_update_key`]. Bytes supplied
//!   via [`HKDF::do_extract_update_bytes`] are treated as uncredited context, so a PRK derived only
//!   from raw bytes will not be tagged as full-entropy key material even if those bytes were in fact
//!   random.
//! * The output key inherits the [`SecurityStrength`] of the inputs. HKDF stretches key material but
//!   does not create entropy: asking for 200 bytes of output from a 128-bit seed yields 200 bytes at
//!   a 128-bit security level, not a 1600-bit key.
//! * RFC 5869 Section 3.1 recommends a random salt where one is available; SP 800-56Cr2 permits an
//!   all-zero salt. An all-zero salt is not a [`KeyType::MACKey`], so it needs
//!   `MAC::new_allow_weak_key` semantics -- which is exactly what the extract phase does internally.
use crate::hmac::{SUSPENDED_HMAC_SHA256_STATE_LEN, SUSPENDED_HMAC_SHA512_STATE_LEN};
use crate::{SHA256, SHA512};
use crate::{SUSPENDED_SHA256_STATE_LEN, SUSPENDED_SHA512_STATE_LEN};
use bouncycastle_hkdf::HKDF;

/*** Imports needed for docs ***/
#[allow(unused_imports)]
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
#[allow(unused_imports)]
use bouncycastle_core::traits::{KDF, SecurityStrength, SuspendableKeyed, XOF};

/*** String constants ***/
///
pub const HKDF_SHA256_NAME: &str = "HKDF-SHA256";
///
pub const HKDF_SHA512_NAME: &str = "HKDF-SHA512";

/*** Serialized-state length constants ***/
// HKDF wraps the inner extract-phase HMAC's blob in 14 bytes of its own bookkeeping (a 3-byte library
// version header plus 11 bytes of present flag, state tag, entropy counter and security strength);
// see the `SuspendableKeyed` impl in `bouncycastle-hkdf` for the layout.
/// Length in bytes of the serialized state of [`HKDF_SHA256`].
pub const SUSPENDED_HKDF_SHA256_STATE_LEN: usize = SUSPENDED_HMAC_SHA256_STATE_LEN + 14;
/// Length in bytes of the serialized state of [`HKDF_SHA512`].
pub const SUSPENDED_HKDF_SHA512_STATE_LEN: usize = SUSPENDED_HMAC_SHA512_STATE_LEN + 14;

/*** Type aliases ***/
/// Public type for HKDF using SHA256.
#[allow(non_camel_case_types)]
pub type HKDF_SHA256 = HKDF<
    SHA256,
    crate::hmac::HMAC_SHA256Params,
    SUSPENDED_SHA256_STATE_LEN,
    SUSPENDED_HKDF_SHA256_STATE_LEN,
>;
/// Public type for HKDF using SHA512.
#[allow(non_camel_case_types)]
pub type HKDF_SHA512 = HKDF<
    SHA512,
    crate::hmac::HMAC_SHA512Params,
    SUSPENDED_SHA512_STATE_LEN,
    SUSPENDED_HKDF_SHA512_STATE_LEN,
>;
