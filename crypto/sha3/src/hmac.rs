//! HMAC over the SHA-3 hashes, as specified in RFC 2104, taking into account NIST Implementation
//! Guidance in FIPS 140-2 IG A.8 and NIST SP 800-107-r1.
//!
//! Uses [`bouncycastle_hmac`] to provide the HMAC-SHA3 instantiations: [`HMAC_SHA3_224`],
//! [`HMAC_SHA3_256`], [`HMAC_SHA3_384`] and [`HMAC_SHA3_512`].
//!
//! HMAC itself is implemented generically in [`bouncycastle_hmac`]; this module declares one
//! [`HMACParams`] marker type per instantiation (such as [`HMAC_SHA3_256Params`]), carrying that
//! HMAC's name, claimed strength, OID and key type, and publishes the type alias pairing each
//! marker with its hash. This mirrors how the hashes themselves are built, where `SHA256` is
//! `SHA256Internal<SHA256Params>`. The upshot is that
//! HMAC over a SHA3 hash is found in this crate, and [`bouncycastle_hmac`] serves as a utility crate
//! rather than as part of library's public API.
//!
//! Each params type sizes the internal key buffer to its hash's block length: per RFC 2104, a key no
//! longer than the block is used verbatim, and only longer keys are pre-hashed down to the output
//! length, so the buffer must be able to hold a full block. It is taken from
//! [`HashAlgParams::BLOCK_LEN`] -- the values FIPS 202 Table 3 ("Input block sizes for HMAC") gives
//! for the SHA-3 hash functions -- rather than restated as a literal so the two cannot drift apart.
//! Note that for SHA-3 the block length is the sponge *rate*, which *shrinks* as the output size
//! grows, so HMAC-SHA3-224 has the largest key buffer (144 bytes) and HMAC-SHA3-512 the smallest
//! (72 bytes) -- the opposite of the SHA-2 family.
//!
//! # Usage
//!
//! An HMAC object (and the [`MAC`] trait in general) is used in three phases:
//!
//! * The initialization phase where you specify the underlying hash function and the key material.
//! * The update phase where you feed in the content being MAC'd, either in one-shot or in chunks.
//! * The finalization phase where you either obtain the MAC value or verify an existing MAC value.
//!
//! The initialization phase is primarily performed via the [`MAC::new`] function which performs
//! checks on the provided key to ensure that it is of the correct type [`KeyType::MACKey`] and tagged
//! at the correct security level for the chosen hash function. In cases where you need to use HMAC
//! with an intentially week key (such as an all-zero salt), the alternative constructor
//! [`MAC::new_allow_weak_key`] can be used.
//!
//! The update phase supports streaming of the content via the repeated calls to the [`MAC::do_update`] function.
//! One-shot APIs are provided that combine the update and finalization phases into a single function call.
//!
//! # Usage Examples
//!
//! ## Constructing an HMAC object
//!
//! Instantiation of an HMAC object is straightforward. A key of the right length for the chosen hash
//! can be generated with [`HMAC::keygen_from_rng`]:
//!
//! ```
//! use bouncycastle_core::key_material::KeyMaterial256;
//! use bouncycastle_core::traits::MAC;
//! use bouncycastle_rng::DefaultRNG;
//! use bouncycastle_sha3::hmac::HMAC_SHA3_256;
//!
//! let mut rng = DefaultRNG::new_from_os();
//! let key: KeyMaterial256 = HMAC_SHA3_256::keygen_from_rng(&mut rng)
//!         .expect("Will only fail if the system RNG can't start up.");
//!
//! let hmac = HMAC_SHA3_256::new(&key).expect(
//!         "Should succeed because key is long enough and tagged KeyType::MACKey");
//! ```
//!
//! Alternatively, if you have key material from somewhere else, you can create the key manually,
//! like so:
//!
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::traits::MAC;
//! use bouncycastle_sha3::hmac::HMAC_SHA3_256;
//!
//! let key = KeyMaterial256::from_bytes_as_type(
//!             b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
//!             KeyType::MACKey).unwrap();
//!
//! let hmac = HMAC_SHA3_256::new(&key).expect(
//!         "Should succeed because key is long enough and tagged KeyType::MACKey");
//! ```
//!
//! ## Computing a MAC
//!
//! MAC functionality is accessed via the [`MAC`] trait.
//!
//! The simplest usage is via the one-shot functions.
//!
//! ```
//! use bouncycastle_core::key_material::KeyMaterial256;
//! use bouncycastle_core::traits::MAC;
//! use bouncycastle_rng::DefaultRNG;
//! use bouncycastle_sha3::hmac::HMAC_SHA3_256;
//!
//! let mut rng = DefaultRNG::new_from_os();
//! let key: KeyMaterial256 = HMAC_SHA3_256::keygen_from_rng(&mut rng)
//!         .expect("Will only fail if the system RNG can't start up.");
//!
//! let data: &[u8] = b"Hello, world!";
//! let hmac = HMAC_SHA3_256::new(&key).expect("Should succeed because key is long enough and tagged KeyType::MACKey");
//! let output: Vec<u8> = hmac.mac(data);
//! ```
//!
//! More advanced usage will require creating an HMAC object to hold state between successive calls,
//! for example if input is received in chunks and not all available at the same time:
//!
//! ```
//! use bouncycastle_core::key_material::KeyMaterial256;
//! use bouncycastle_core::traits::MAC;
//! use bouncycastle_rng::DefaultRNG;
//! use bouncycastle_sha3::hmac::HMAC_SHA3_256;
//!
//! let mut rng = DefaultRNG::new_from_os();
//! let key: KeyMaterial256 = HMAC_SHA3_256::keygen_from_rng(&mut rng)
//!         .expect("Will only fail if the system RNG can't start up.");
//!
//! let mut hmac = HMAC_SHA3_256::new(&key).expect("Should succeed because key is long enough and tagged KeyType::MACKey");
//! hmac.do_update(b"Hello,");
//! hmac.do_update(b" world!");
//! let output: Vec<u8> = hmac.do_final();
//! ```
//!
//! ## Verifying a MAC
//!
//! The [`MAC`] trait also provides functions for MAC verification. The built-in verification
//! functions use constant-time comparisons and so are *strongly recommended* rather than
//! re-computing the MAC value and comparing it yourself.
//!
//! The simplest usage is via the one-shot functions.
//!
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::traits::MAC;
//! use bouncycastle_sha3::hmac::HMAC_SHA3_256;
//!
//! // For this example to work, we are hard-coding both the key and the MAC value that it generates
//! // for this data.
//! let key = KeyMaterial256::from_bytes_as_type(
//!             b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
//!             KeyType::MACKey).unwrap();
//!
//! let data: &[u8] = b"Hello, world!";
//!
//! // .verify() returns a bool: true if the MAC is valid, false otherwise.
//! if HMAC_SHA3_256::new(&key).unwrap()
//!                 .verify(data,
//!                         b"\x9c\x49\x05\x83\xff\xf3\x59\x6a\x59\x01\x4a\x0d\x95\xb4\x64\x00
//!                            \x7d\x5b\xb7\x40\xb3\x84\x20\x7a\x3c\x76\x76\xd8\xc9\x93\xda\xd7"
//!                         )
//! {
//!     println!("MAC is valid!");
//! } else {
//!     println!("MAC is invalid!");
//! }
//! ```
//!
//! Similarly, a streaming version is available, which is identical to the streaming interface for
//! computing a mac value, but calls [`MAC::do_verify_final`] instead of [`MAC::do_final`].
//!
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::traits::MAC;
//! use bouncycastle_sha3::hmac::HMAC_SHA3_256;
//!
//! // For this example to work, we are hard-coding both the key and the MAC value that it generates
//! // for this data.
//! let key = KeyMaterial256::from_bytes_as_type(
//!             b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
//!             KeyType::MACKey).unwrap();
//! let mut hmac = HMAC_SHA3_256::new(&key).unwrap();
//! hmac.do_update(b"Hello,");
//! hmac.do_update(b" world!");
//! if hmac.do_verify_final(b"\x9c\x49\x05\x83\xff\xf3\x59\x6a\x59\x01\x4a\x0d\x95\xb4\x64\x00\x7d\x5b\xb7\x40\xb3\x84\x20\x7a\x3c\x76\x76\xd8\xc9\x93\xda\xd7"
//!                     )
//! {
//!     println!("MAC is valid!");
//! } else {
//!     println!("MAC is invalid!");
//! }
//! ```
//!
//! ## Suspending and resuming execution
//!
//! When MAC'ing a large message, it can be advantageous to be able to suspend the operation
//! to a cache and resume it later; for example if waiting for the message to stream over a slow
//! network connection. For this reason, all HMAC algorithms impl [`SuspendableKeyed`].
//!
//! Note that since HMAC is a keyed algorithm and we do not want to serialize the private key into
//! the state, the trait structure forces you to re-provide the same key when you resume the
//! operation. Securely storing this key in the interim is the responsibility of the caller. Note
//! also that if you resume the HMAC with the wrong key, [`SuspendableKeyed::from_suspended`] has no
//! way to detect this, so the end result will be a broken MAC value computed with different keys in
//! the inner and outer pad. So make sure you resume with the same key!
//!
//! ```rust
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::traits::{MAC, SuspendableKeyed};
//! use bouncycastle_sha3::hmac::HMAC_SHA3_256;
//!
//! let msg_part1 = b"The quick brown fox";
//! let msg_part2 = b" jumped over the lazy dog";
//!
//! let key = KeyMaterial256::from_bytes_as_type(
//!             b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
//!             KeyType::MACKey).unwrap();
//!
//! let mut hmac = HMAC_SHA3_256::new(&key).unwrap();
//! hmac.do_update(msg_part1);
//!
//! // suspend the in-progress mac (the key is NOT included in the serialized state)
//! let serialized_state = hmac.suspend();
//!
//! // ...
//! // do other things in the meantime
//! // ...
//!
//! // ... later, possibly on another host: resume from the serialized state by re-supplying
//! // the same key (make sure you store it securely!).
//! let mut hmac_resumed = HMAC_SHA3_256::from_suspended(serialized_state, &key).unwrap();
//! hmac_resumed.do_update(msg_part2);
//! let h: Vec<u8> = hmac_resumed.do_final();
//! ```
//!
//! # Memory Usage
//!
//! No heap memory is used by the algorithm itself; the `Vec<u8>`-returning convenience methods
//! allocate only the output buffer, and the `*_out` variants allocate nothing.
//!
//! | Object                                    | Size (bytes) |
//! |-------------------------------------------|--------------|
//! | `HMAC_SHA3_224`                           | 592          |
//! | `HMAC_SHA3_256`                           | 584          |
//! | `HMAC_SHA3_384`                           | 552          |
//! | `HMAC_SHA3_512`                           | 520          |
//! | Suspended state, all four ([`SuspendableKeyed`]) | 415   |
//!
//! The object is the Keccak-f\[1600\] sponge (440 bytes, see the crate-level Memory Usage section),
//! plus one block of key buffer, plus a `usize` recording the key length -- so 440 + 144 + 8 = 592
//! for HMAC-SHA3-224 down to 440 + 72 + 8 = 520 for HMAC-SHA3-512. That is why the sizes *decrease*
//! as the output size grows. The suspended state is exactly the inner hash's suspended state -- the
//! key is deliberately excluded -- so all four share the sponge's single value.
//!
//! # Security Considerations
//!
//! * The key must carry at least the security strength claimed by the HMAC, and [`MAC::new`]
//!   enforces that. [`MAC::new_allow_weak_key`] deliberately skips the check; use it only where a
//!   weak or all-zero key is called for by the protocol, not to silence an error.
//! * Verify with [`MAC::verify`] or [`MAC::do_verify_final`] rather than computing the MAC yourself
//!   and comparing: those use a constant-time comparison, while `==` on the byte slices leaks how
//!   many leading bytes matched.
//! * Truncating the MAC output below [`MIN_FIPS_DIGEST_LEN`] (4 bytes) is rejected, per FIPS 140-2
//!   IG A.8 / NIST SP 800-107-r1 Section 5.3.3. That is a floor, not a recommendation -- RFC 2104
//!   Section 5 recommends that the output length "be not less than half the length of the hash
//!   output ... and not less than 80 bits".
//! * Resuming a suspended HMAC with the wrong key cannot be detected and silently produces a wrong
//!   MAC; see the suspend/resume section above.
//! * SHA-3 is a sponge and is not vulnerable to the length-extension attack that motivates HMAC for
//!   Merkle-Damgard hashes, so a plain `SHA3(k || m)` is not broken the way `SHA256(k || m)` is.
//!   HMAC-SHA3 remains the right choice for interoperability and for FIPS 198-1 conformance, and
//!   KMAC (NIST SP 800-185) is the SHA-3-native alternative.

use crate::SUSPENDED_SHA3_STATE_LEN;
use crate::{SHA3_224, SHA3_256, SHA3_384, SHA3_512};
use bouncycastle_core::key_material::KeyMaterial;
use bouncycastle_core::traits::{Algorithm, AlgorithmOID, HashAlgParams, SecurityStrength};
use bouncycastle_hmac::{HMAC, HMACParams};

/*** Imports needed for docs ***/
#[allow(unused_imports)]
use bouncycastle_core::key_material::KeyType;
#[allow(unused_imports)]
use bouncycastle_core::traits::{MAC, SuspendableKeyed};
#[allow(unused_imports)]
use bouncycastle_hmac::MIN_FIPS_DIGEST_LEN;

/*** String constants ***/
///
pub const HMAC_SHA3_224_NAME: &str = "HMAC-SHA3-224";
///
pub const HMAC_SHA3_256_NAME: &str = "HMAC-SHA3-256";
///
pub const HMAC_SHA3_384_NAME: &str = "HMAC-SHA3-384";
///
pub const HMAC_SHA3_512_NAME: &str = "HMAC-SHA3-512";

/*** Params types and type aliases ***/
// TODO: the MAX_SECURITY_STRENGTH values below are each hash's collision strength, which NIST
// SP 800-107r1 Section 5.3.4 says is not the right basis for an HMAC. See the TODO above the
// equivalent params types in bouncycastle-sha2 for the analysis. Note that its recommendation
// covers SHA-2 only: SP 800-107r1 predates SHA-3 and reasons about a Merkle-Damgard chaining
// value, which a sponge does not have, so these need FIPS 202 / SP 800-185 read first.

/// The parameters for HMAC-SHA3_224 -- see [`HMAC_SHA3_224`].
#[derive(Clone)]
#[allow(non_camel_case_types)]
pub struct HMAC_SHA3_224Params;

impl Algorithm for HMAC_SHA3_224Params {
    const ALG_NAME: &'static str = HMAC_SHA3_224_NAME;
    // The strength this HMAC claims. Deliberately stated here rather than read off
    // SHA3_224: HMAC does not rest on the hash's collision resistance, so in principle the
    // two can differ (NIST SP 800-107-r1 Section 5.3.4 bounds HMAC's strength by
    // `min(strength of K, 2C)` for a `C`-bit chaining value). This is the value
    // `MAC::new` enforces against the key and `keygen_from_rng` against the RNG.
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_112bit;
}

/// Assigned by NIST in the Computer Security Objects Register: id-hmacWithSHA3-224 { hashAlgs 13 }
impl AlgorithmOID for HMAC_SHA3_224Params {
    const OID: &'static [u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 13];
    const OID_DER: &'static [u8] =
        &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0d];
}

impl HMACParams for HMAC_SHA3_224Params {
    type MACKey = KeyMaterial<{ <SHA3_224 as HashAlgParams>::OUTPUT_LEN }>;
    type KeyBuf = [u8; <SHA3_224 as HashAlgParams>::BLOCK_LEN];
}

/// Public type for HMAC using SHA3_224.
#[allow(non_camel_case_types)]
pub type HMAC_SHA3_224 = HMAC<SHA3_224, HMAC_SHA3_224Params>;

/// The parameters for HMAC-SHA3_256 -- see [`HMAC_SHA3_256`].
#[derive(Clone)]
#[allow(non_camel_case_types)]
pub struct HMAC_SHA3_256Params;

impl Algorithm for HMAC_SHA3_256Params {
    const ALG_NAME: &'static str = HMAC_SHA3_256_NAME;
    // The strength this HMAC claims. Deliberately stated here rather than read off
    // SHA3_256: HMAC does not rest on the hash's collision resistance, so in principle the
    // two can differ (NIST SP 800-107-r1 Section 5.3.4 bounds HMAC's strength by
    // `min(strength of K, 2C)` for a `C`-bit chaining value). This is the value
    // `MAC::new` enforces against the key and `keygen_from_rng` against the RNG.
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

/// Assigned by NIST in the Computer Security Objects Register: id-hmacWithSHA3-256 { hashAlgs 14 }
impl AlgorithmOID for HMAC_SHA3_256Params {
    const OID: &'static [u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 14];
    const OID_DER: &'static [u8] =
        &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0e];
}

impl HMACParams for HMAC_SHA3_256Params {
    type MACKey = KeyMaterial<{ <SHA3_256 as HashAlgParams>::OUTPUT_LEN }>;
    type KeyBuf = [u8; <SHA3_256 as HashAlgParams>::BLOCK_LEN];
}

/// Public type for HMAC using SHA3_256.
#[allow(non_camel_case_types)]
pub type HMAC_SHA3_256 = HMAC<SHA3_256, HMAC_SHA3_256Params>;

/// The parameters for HMAC-SHA3_384 -- see [`HMAC_SHA3_384`].
#[derive(Clone)]
#[allow(non_camel_case_types)]
pub struct HMAC_SHA3_384Params;

impl Algorithm for HMAC_SHA3_384Params {
    const ALG_NAME: &'static str = HMAC_SHA3_384_NAME;
    // The strength this HMAC claims. Deliberately stated here rather than read off
    // SHA3_384: HMAC does not rest on the hash's collision resistance, so in principle the
    // two can differ (NIST SP 800-107-r1 Section 5.3.4 bounds HMAC's strength by
    // `min(strength of K, 2C)` for a `C`-bit chaining value). This is the value
    // `MAC::new` enforces against the key and `keygen_from_rng` against the RNG.
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_192bit;
}

/// Assigned by NIST in the Computer Security Objects Register: id-hmacWithSHA3-384 { hashAlgs 15 }
impl AlgorithmOID for HMAC_SHA3_384Params {
    const OID: &'static [u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 15];
    const OID_DER: &'static [u8] =
        &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0f];
}

impl HMACParams for HMAC_SHA3_384Params {
    type MACKey = KeyMaterial<{ <SHA3_384 as HashAlgParams>::OUTPUT_LEN }>;
    type KeyBuf = [u8; <SHA3_384 as HashAlgParams>::BLOCK_LEN];
}

/// Public type for HMAC using SHA3_384.
#[allow(non_camel_case_types)]
pub type HMAC_SHA3_384 = HMAC<SHA3_384, HMAC_SHA3_384Params>;

/// The parameters for HMAC-SHA3_512 -- see [`HMAC_SHA3_512`].
#[derive(Clone)]
#[allow(non_camel_case_types)]
pub struct HMAC_SHA3_512Params;

impl Algorithm for HMAC_SHA3_512Params {
    const ALG_NAME: &'static str = HMAC_SHA3_512_NAME;
    // The strength this HMAC claims. Deliberately stated here rather than read off
    // SHA3_512: HMAC does not rest on the hash's collision resistance, so in principle the
    // two can differ (NIST SP 800-107-r1 Section 5.3.4 bounds HMAC's strength by
    // `min(strength of K, 2C)` for a `C`-bit chaining value). This is the value
    // `MAC::new` enforces against the key and `keygen_from_rng` against the RNG.
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
}

/// Assigned by NIST in the Computer Security Objects Register: id-hmacWithSHA3-512 { hashAlgs 16 }
impl AlgorithmOID for HMAC_SHA3_512Params {
    const OID: &'static [u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 16];
    const OID_DER: &'static [u8] =
        &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x10];
}

impl HMACParams for HMAC_SHA3_512Params {
    type MACKey = KeyMaterial<{ <SHA3_512 as HashAlgParams>::OUTPUT_LEN }>;
    type KeyBuf = [u8; <SHA3_512 as HashAlgParams>::BLOCK_LEN];
}

/// Public type for HMAC using SHA3_512.
#[allow(non_camel_case_types)]
pub type HMAC_SHA3_512 = HMAC<SHA3_512, HMAC_SHA3_512Params>;

/*** Serialized-state length constants ***/
// HMAC's suspended state is exactly the inner hasher's state -- the key is deliberately excluded and
// must be re-supplied on resume -- so each of these is the underlying hash's own state length. All
// four SHA-3 hashes share one Keccak state size, hence one constant.
/// Length in bytes of the serialized state of [`HMAC_SHA3_224`].
pub const SUSPENDED_HMAC_SHA3_224_STATE_LEN: usize = SUSPENDED_SHA3_STATE_LEN;
/// Length in bytes of the serialized state of [`HMAC_SHA3_256`].
pub const SUSPENDED_HMAC_SHA3_256_STATE_LEN: usize = SUSPENDED_SHA3_STATE_LEN;
/// Length in bytes of the serialized state of [`HMAC_SHA3_384`].
pub const SUSPENDED_HMAC_SHA3_384_STATE_LEN: usize = SUSPENDED_SHA3_STATE_LEN;
/// Length in bytes of the serialized state of [`HMAC_SHA3_512`].
pub const SUSPENDED_HMAC_SHA3_512_STATE_LEN: usize = SUSPENDED_SHA3_STATE_LEN;
