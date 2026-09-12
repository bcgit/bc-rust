//! HMAC over the SHA-2 hashes, as specified in RFC 2104, taking into account NIST Implementation
//! Guidance in FIPS 140-2 IG A.8 and NIST SP 800-107-r1.
//!
//! Uses [`bouncycastle_hmac`] to provide the HMAC-SHA2 instantiations: [`HMAC_SHA224`],
//! [`HMAC_SHA256`], [`HMAC_SHA384`] and [`HMAC_SHA512`].
//!
//! HMAC itself is implemented generically in [`bouncycastle_hmac`]; this module declares one
//! [`HMACParams`] marker type per instantiation (such as [`HMAC_SHA256Params`]), carrying that
//! HMAC's name, claimed strength, OID and key type, and publishes the type alias pairing each
//! marker with its hash. This mirrors how the hashes themselves are built, where `SHA256` is
//! `SHA256Internal<SHA256Params>`. The upshot is that
//! HMAC over a SHA2 hash is found in this crate, and [`bouncycastle_hmac`] serves as a utility crate
//! rather than as part of library's public API.
//!
//! Each params type sizes the internal key buffer to its hash's block length: per RFC 2104, a key
//! no longer than the block is used verbatim, and only longer keys are pre-hashed down to the
//! output length, so the buffer must be able to hold a full block. It is taken from
//! [`HashAlgParams::BLOCK_LEN`] rather than restated as a literal so the two cannot drift apart.
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
//! use bouncycastle_sha2::hmac::HMAC_SHA256;
//!
//! let mut rng = DefaultRNG::new_from_os();
//! let key: KeyMaterial256 = HMAC_SHA256::keygen_from_rng(&mut rng)
//!         .expect("Will only fail if the system RNG can't start up.");
//!
//! let hmac = HMAC_SHA256::new(&key).expect(
//!         "Should succeed because key is long enough and tagged KeyType::MACKey");
//! ```
//!
//! Alternatively, if you have key material from somewhere else, you can create the key manually,
//! like so:
//!
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::traits::MAC;
//! use bouncycastle_sha2::hmac::HMAC_SHA256;
//!
//! let key = KeyMaterial256::from_bytes_as_type(
//!             b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\
//!               \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
//!             KeyType::MACKey).unwrap();
//!
//! let hmac = HMAC_SHA256::new(&key).expect(
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
//! use bouncycastle_sha2::hmac::HMAC_SHA256;
//!
//! let mut rng = DefaultRNG::new_from_os();
//! let key: KeyMaterial256 = HMAC_SHA256::keygen_from_rng(&mut rng)
//!         .expect("Will only fail if the system RNG can't start up.");
//!
//! let data: &[u8] = b"Hello, world!";
//! let hmac = HMAC_SHA256::new(&key).expect("Should succeed because key is long enough and tagged KeyType::MACKey");
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
//! use bouncycastle_sha2::hmac::HMAC_SHA256;
//!
//! let mut rng = DefaultRNG::new_from_os();
//! let key: KeyMaterial256 = HMAC_SHA256::keygen_from_rng(&mut rng)
//!         .expect("Will only fail if the system RNG can't start up.");
//!
//! let mut hmac = HMAC_SHA256::new(&key).expect("Should succeed because key is long enough and tagged KeyType::MACKey");
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
//! use bouncycastle_sha2::hmac::HMAC_SHA256;
//!
//! // For this example to work, we are hard-coding both the key and the MAC value that it generates
//! // for this data.
//! let key = KeyMaterial256::from_bytes_as_type(
//!             b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\
//!               \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
//!             KeyType::MACKey).unwrap();
//!
//! let data: &[u8] = b"Hello, world!";
//!
//! // .verify() returns a bool: true if the MAC is valid, false otherwise.
//! if HMAC_SHA256::new(&key).unwrap()
//!                 .verify(data,
//!                         b"\x76\xd0\x69\x2c\x75\x6f\x89\x94\x96\xf3\x51\x63\x6a\x69\x69\xe5
//!                            \x4e\xbf\xb2\x3a\xbb\x09\xfd\x61\x40\x86\x13\x6a\xc9\xab\x26\x77"
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
//! use bouncycastle_sha2::hmac::HMAC_SHA256;
//!
//! // For this example to work, we are hard-coding both the key and the MAC value that it generates
//! // for this data.
//! let key = KeyMaterial256::from_bytes_as_type(
//!             b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\
//!               \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
//!             KeyType::MACKey).unwrap();
//! let mut hmac = HMAC_SHA256::new(&key).unwrap();
//! hmac.do_update(b"Hello,");
//! hmac.do_update(b" world!");
//! if hmac.do_verify_final(b"\x76\xd0\x69\x2c\x75\x6f\x89\x94\x96\xf3\x51\x63\x6a\x69\x69\xe5\x4e\xbf\xb2\x3a\xbb\x09\xfd\x61\x40\x86\x13\x6a\xc9\xab\x26\x77"
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
//! use bouncycastle_sha2::hmac::HMAC_SHA256;
//!
//! let msg_part1 = b"The quick brown fox";
//! let msg_part2 = b" jumped over the lazy dog";
//!
//! let key = KeyMaterial256::from_bytes_as_type(
//!             b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\
//!               \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
//!             KeyType::MACKey).unwrap();
//!
//! let mut hmac = HMAC_SHA256::new(&key).unwrap();
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
//! let mut hmac_resumed = HMAC_SHA256::from_suspended(serialized_state, &key).unwrap();
//! hmac_resumed.do_update(msg_part2);
//! let h: Vec<u8> = hmac_resumed.do_final();
//! ```
//!
//! # Memory Usage
//!
//! No heap memory is used by the algorithm itself; the `Vec<u8>`-returning convenience methods
//! allocate only the output buffer, and the `*_out` variants allocate nothing.
//!
//! | Object                                                    | Size (bytes) |
//! |-----------------------------------------------------------|--------------|
//! | `HMAC_SHA224`, `HMAC_SHA256`                              | 184          |
//! | `HMAC_SHA384`, `HMAC_SHA512`                              | 344          |
//! | Suspended `HMAC_SHA224`/`HMAC_SHA256` state               | 108          |
//! | Suspended `HMAC_SHA384`/`HMAC_SHA512` state               | 204          |
//!
//! The object is the underlying hash object (see the crate-level Memory Usage section), plus one
//! block of key buffer, plus a `usize` recording the key length: 112 + 64 + 8 = 184 for the SHA-256
//! family, 208 + 128 + 8 = 344 for the SHA-512 family. The suspended state is exactly the inner
//! hash's suspended state -- the key is deliberately excluded -- so it matches the corresponding row
//! for the bare hash.
//!
//! # Security Considerations
//!
//! * Each of these HMACs claims the strength NIST SP 800-107r1 Section 5.3.4 gives it, which is
//!   `min(strength of K, 2C)` and works out to the key length for the whole SHA-2 family: 224 bits
//!   for HMAC-SHA224 and 256 or more for the rest. `SecurityStrength` has no 224-bit category and
//!   tops out at 256, so the declared values are `_192bit` for HMAC-SHA224 and `_256bit` for
//!   HMAC-SHA256, HMAC-SHA384 and HMAC-SHA512. Note these are *not* the underlying hashes'
//!   collision strengths, which are half as large; footnote 4 of that section puts collision
//!   attacks out of scope for HMAC.
//! * The key must carry at least the strength claimed by the HMAC, and [`MAC::new`] enforces that.
//!   A 20-byte key is therefore no longer enough for HMAC-SHA256; a full 32-byte key is.
//!   [`MAC::new_allow_weak_key`] deliberately skips the check; use it only where a weak or all-zero
//!   key is called for by the protocol (an all-zero HKDF salt, or a fixed test vector such as
//!   RFC 4231's 20-byte keys), not to silence an error.
//! * The same rule applies to the generator. [`HMAC::keygen_from_rng`] tags the key it returns at
//!   the HMAC's claimed strength, so it refuses any RNG that cannot back that tag: a 256-bit
//!   generator is required for HMAC-SHA256 and above, and `bouncycastle_rng::DefaultRNG` is
//!   `HashDRBG_SHA512` and qualifies for all of them. `HashDRBG_SHA256` offers 128 bits and is now
//!   refused by every HMAC in this module. There is no weak-RNG opt-out, because a generator cannot
//!   be asked for entropy it does not have; build the key yourself and use
//!   [`MAC::new_allow_weak_key`] if that is genuinely what you want.
//! * Verify with [`MAC::verify`] or [`MAC::do_verify_final`] rather than computing the MAC yourself
//!   and comparing: those use a constant-time comparison, while `==` on the byte slices leaks how
//!   many leading bytes matched.
//! * Truncating the MAC output below [`MIN_FIPS_DIGEST_LEN`] (4 bytes) is rejected, per FIPS 140-2
//!   IG A.8 / NIST SP 800-107-r1 Section 5.3.3. That is a floor, not a recommendation -- RFC 2104
//!   Section 5 recommends that the output length "be not less than half the length of the hash
//!   output ... and not less than 80 bits".
//! * Resuming a suspended HMAC with the wrong key cannot be detected and silently produces a wrong
//!   MAC; see the suspend/resume section above.
//! * A key longer than the hash's block length is pre-hashed down to the output length (RFC 2104
//!   Section 2), so very long keys add no strength beyond that point.
use crate::{SHA224, SHA256, SHA384, SHA512};
use crate::{SUSPENDED_SHA256_STATE_LEN, SUSPENDED_SHA512_STATE_LEN};
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
pub const HMAC_SHA224_NAME: &str = "HMAC-SHA224";
///
pub const HMAC_SHA256_NAME: &str = "HMAC-SHA256";
///
pub const HMAC_SHA384_NAME: &str = "HMAC-SHA384";
///
pub const HMAC_SHA512_NAME: &str = "HMAC-SHA512";

/*** Params types and type aliases ***/

/// The parameters for HMAC-SHA224 -- see [`HMAC_SHA224`].
#[derive(Clone)]
#[allow(non_camel_case_types)]
pub struct HMAC_SHA224Params;

impl Algorithm for HMAC_SHA224Params {
    const ALG_NAME: &'static str = HMAC_SHA224_NAME;
    // SP 800-107r1 s.5.3.4: min(strength of K, 2C). SHA-224 has C = 256, so 2C = 512,
    // and the key is OUTPUT_LEN = 224 bits, so the key binds: 224 bits, rounded down to the nearest category.
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_192bit;
}

/// Defined in RFC 4231: id-hmacWithSHA224 { digestAlgorithm 8 }
impl AlgorithmOID for HMAC_SHA224Params {
    const OID: &'static [u32] = &[1, 2, 840, 113549, 2, 8];
    const OID_DER: &'static [u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x08];
}

impl HMACParams for HMAC_SHA224Params {
    type MACKey = KeyMaterial<{ <SHA224 as HashAlgParams>::OUTPUT_LEN }>;
    type KeyBuf = [u8; <SHA224 as HashAlgParams>::BLOCK_LEN];
}

/// Public type for HMAC using SHA224.
#[allow(non_camel_case_types)]
pub type HMAC_SHA224 = HMAC<SHA224, HMAC_SHA224Params>;

/// The parameters for HMAC-SHA256 -- see [`HMAC_SHA256`].
#[derive(Clone)]
#[allow(non_camel_case_types)]
pub struct HMAC_SHA256Params;

impl Algorithm for HMAC_SHA256Params {
    const ALG_NAME: &'static str = HMAC_SHA256_NAME;
    // SP 800-107r1 s.5.3.4: min(strength of K, 2C). SHA-256 has C = 256, so 2C = 512,
    // and the key is OUTPUT_LEN = 256 bits, so the key binds: 256 bits.
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
}

/// Defined in RFC 4231: id-hmacWithSHA256 { digestAlgorithm 9 }
impl AlgorithmOID for HMAC_SHA256Params {
    const OID: &'static [u32] = &[1, 2, 840, 113549, 2, 9];
    const OID_DER: &'static [u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09];
}

impl HMACParams for HMAC_SHA256Params {
    type MACKey = KeyMaterial<{ <SHA256 as HashAlgParams>::OUTPUT_LEN }>;
    type KeyBuf = [u8; <SHA256 as HashAlgParams>::BLOCK_LEN];
}

/// Public type for HMAC using SHA256.
#[allow(non_camel_case_types)]
pub type HMAC_SHA256 = HMAC<SHA256, HMAC_SHA256Params>;

/// The parameters for HMAC-SHA384 -- see [`HMAC_SHA384`].
#[derive(Clone)]
#[allow(non_camel_case_types)]
pub struct HMAC_SHA384Params;

impl Algorithm for HMAC_SHA384Params {
    const ALG_NAME: &'static str = HMAC_SHA384_NAME;
    // SP 800-107r1 s.5.3.4: min(strength of K, 2C). SHA-384 has C = 512, so 2C = 1024,
    // and the key is OUTPUT_LEN = 384 bits, so the key binds: 384 bits, capped at the top of `SecurityStrength`.
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
}

/// Defined in RFC 4231: id-hmacWithSHA384 { digestAlgorithm 10 }
impl AlgorithmOID for HMAC_SHA384Params {
    const OID: &'static [u32] = &[1, 2, 840, 113549, 2, 10];
    const OID_DER: &'static [u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0a];
}

impl HMACParams for HMAC_SHA384Params {
    type MACKey = KeyMaterial<{ <SHA384 as HashAlgParams>::OUTPUT_LEN }>;
    type KeyBuf = [u8; <SHA384 as HashAlgParams>::BLOCK_LEN];
}

/// Public type for HMAC using SHA384.
#[allow(non_camel_case_types)]
pub type HMAC_SHA384 = HMAC<SHA384, HMAC_SHA384Params>;

/// The parameters for HMAC-SHA512 -- see [`HMAC_SHA512`].
#[derive(Clone)]
#[allow(non_camel_case_types)]
pub struct HMAC_SHA512Params;

impl Algorithm for HMAC_SHA512Params {
    const ALG_NAME: &'static str = HMAC_SHA512_NAME;
    // SP 800-107r1 s.5.3.4: min(strength of K, 2C). SHA-512 has C = 512, so 2C = 1024,
    // and the key is OUTPUT_LEN = 512 bits, so the key binds: 512 bits, capped at the top of `SecurityStrength`.
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
}

/// Defined in RFC 4231: id-hmacWithSHA512 { digestAlgorithm 11 }
impl AlgorithmOID for HMAC_SHA512Params {
    const OID: &'static [u32] = &[1, 2, 840, 113549, 2, 11];
    const OID_DER: &'static [u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0b];
}

impl HMACParams for HMAC_SHA512Params {
    type MACKey = KeyMaterial<{ <SHA512 as HashAlgParams>::OUTPUT_LEN }>;
    type KeyBuf = [u8; <SHA512 as HashAlgParams>::BLOCK_LEN];
}

/// Public type for HMAC using SHA512.
#[allow(non_camel_case_types)]
pub type HMAC_SHA512 = HMAC<SHA512, HMAC_SHA512Params>;

/*** Serialized-state length constants ***/
// HMAC's suspended state is exactly the inner hasher's state -- the key is deliberately excluded and
// must be re-supplied on resume -- so each of these is the underlying hash's own state length.
/// Length in bytes of the serialized state of [`HMAC_SHA224`].
pub const SUSPENDED_HMAC_SHA224_STATE_LEN: usize = SUSPENDED_SHA256_STATE_LEN;
/// Length in bytes of the serialized state of [`HMAC_SHA256`].
pub const SUSPENDED_HMAC_SHA256_STATE_LEN: usize = SUSPENDED_SHA256_STATE_LEN;
/// Length in bytes of the serialized state of [`HMAC_SHA384`].
pub const SUSPENDED_HMAC_SHA384_STATE_LEN: usize = SUSPENDED_SHA512_STATE_LEN;
/// Length in bytes of the serialized state of [`HMAC_SHA512`].
pub const SUSPENDED_HMAC_SHA512_STATE_LEN: usize = SUSPENDED_SHA512_STATE_LEN;
