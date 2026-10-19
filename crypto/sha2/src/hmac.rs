//! HMAC over the SHA-2 hashes, as specified in RFC 2104, taking into account NIST Implementation
//! Guidance in FIPS 140-2 IG A.8 and NIST SP 800-107-r1.
//!
//! Uses [`bouncycastle_hmac`] to provide the HMAC-SHA2 instantiations: [`HMAC_SHA224`],
//! [`HMAC_SHA256`], [`HMAC_SHA384`] and [`HMAC_SHA512`].
//!
//! HMAC itself is implemented generically in [`bouncycastle_hmac`]; this module supplies the
//! SHA-2-specific parameters via [`HMACParams`] and publishes the resulting type aliases, so that
//! HMAC over a SHA2 hash is found in this crate, and [`bouncycastle_hmac`] serves as a utility crate
//! rather than as part of library's public API.
//!
//! A key of any length is accepted: per RFC 2104, a key longer than the hash's block is pre-hashed
//! to the output length. The key's two pad states are computed once, when the [`HmacKey`] is built.
//!
//! # Usage
//!
//! An [`HmacKey`] is built once from key material and hands out [`MAC`] workers, one per message:
//!
//! * [`FromAnyKeyMaterial::from_key_material`] checks that the material is a [`KeyType::MACKey`]
//!   tagged at the security strength of the chosen hash. Where a protocol calls for a weak key
//!   (an all-zero salt, say), [`FromAnyKeyMaterial::from_key_material_allow_weak`] skips the
//!   strength check.
//! * [`MacGenerationKey::create_generator`] / [`MacVerificationKey::create_verifier`] start a
//!   worker, whose [`MAC::do_update`] takes the content in chunks and whose [`MAC::do_final`] /
//!   [`MAC::do_verify_final`] finish it. The key's own [`MacGenerationKey::mac`] and
//!   [`MacVerificationKey::verify`] are the one-shots.
//!
//! # Usage Examples
//!
//! ## Building the key
//!
//! A key of the right length for the chosen hash is drawn with [`FromAnyKeyMaterial::generate`]:
//!
//! ```
//! use bouncycastle_core::symmetric_key::FromAnyKeyMaterial;
//! use bouncycastle_hmac::HmacKey;
//! use bouncycastle_rng::HashDRBG_SHA256;
//! use bouncycastle_sha2::SHA256;
//!
//! let mut rng = HashDRBG_SHA256::new_from_os();
//! let key = HmacKey::<SHA256>::generate(&mut rng)
//!         .expect("Will only fail if the system RNG can't start up.");
//! ```
//!
//! Alternatively, if you have key material from somewhere else, you can build the key from it:
//!
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::symmetric_key::FromAnyKeyMaterial;
//! use bouncycastle_hmac::HmacKey;
//! use bouncycastle_sha2::SHA256;
//!
//! let key_material = KeyMaterial256::from_bytes_as_type(
//!             b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
//!             KeyType::MACKey).unwrap();
//!
//! let key = HmacKey::<SHA256>::from_key_material(&key_material).expect(
//!         "Should succeed because key is long enough and tagged KeyType::MACKey");
//! ```
//!
//! ## Computing a MAC
//!
//! The simplest usage is the key's one-shot:
//!
//! ```
//! use bouncycastle_core::symmetric_key::{FromAnyKeyMaterial, MacGenerationKey};
//! use bouncycastle_hmac::HmacKey;
//! use bouncycastle_rng::HashDRBG_SHA256;
//! use bouncycastle_sha2::SHA256;
//!
//! let mut rng = HashDRBG_SHA256::new_from_os();
//! let key = HmacKey::<SHA256>::generate(&mut rng)
//!         .expect("Will only fail if the system RNG can't start up.");
//!
//! let data: &[u8] = b"Hello, world!";
//! let output: Vec<u8> = key.mac(data);
//! ```
//!
//! A worker holds state between successive calls, for example if input is received in chunks and
//! not all available at the same time:
//!
//! ```
//! use bouncycastle_core::symmetric_key::{FromAnyKeyMaterial, MacGenerationKey};
//! use bouncycastle_core::traits::MAC;
//! use bouncycastle_hmac::HmacKey;
//! use bouncycastle_rng::HashDRBG_SHA256;
//! use bouncycastle_sha2::SHA256;
//! use bouncycastle_sha2::hmac::HMAC_SHA256;
//!
//! let mut rng = HashDRBG_SHA256::new_from_os();
//! let key = HmacKey::<SHA256>::generate(&mut rng)
//!         .expect("Will only fail if the system RNG can't start up.");
//!
//! let mut hmac: HMAC_SHA256 = key.create_generator();
//! hmac.do_update(b"Hello,");
//! hmac.do_update(b" world!");
//! let output: Vec<u8> = hmac.do_final();
//! ```
//!
//! ## Verifying a MAC
//!
//! The built-in verification functions use constant-time comparisons and so are *strongly
//! recommended* rather than re-computing the MAC value and comparing it yourself.
//!
//! The simplest usage is the key's one-shot:
//!
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::symmetric_key::{FromAnyKeyMaterial, MacVerificationKey};
//! use bouncycastle_hmac::HmacKey;
//! use bouncycastle_sha2::SHA256;
//!
//! // For this example to work, we are hard-coding both the key and the MAC value that it generates
//! // for this data.
//! let key_material = KeyMaterial256::from_bytes_as_type(
//!             b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
//!             KeyType::MACKey).unwrap();
//! let key = HmacKey::<SHA256>::from_key_material(&key_material).unwrap();
//!
//! let data: &[u8] = b"Hello, world!";
//!
//! // .verify() returns a bool: true if the MAC is valid, false otherwise.
//! if key.verify(data,
//!               b"\xa2\xd1\x2e\xcf\xfc\x41\xba\xf1\x23\xd6\x3e\x44\xfc\x27\x88\x90
//!                  \x47\xcd\x08\xe7\x05\xd7\x0f\xa3\xb8\xaa\x8a\x5c\x18\x7c\x6c\xa9")
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
//! use bouncycastle_core::symmetric_key::{FromAnyKeyMaterial, MacVerificationKey};
//! use bouncycastle_core::traits::MAC;
//! use bouncycastle_hmac::HmacKey;
//! use bouncycastle_sha2::SHA256;
//!
//! // For this example to work, we are hard-coding both the key and the MAC value that it generates
//! // for this data.
//! let key_material = KeyMaterial256::from_bytes_as_type(
//!             b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
//!             KeyType::MACKey).unwrap();
//! let key = HmacKey::<SHA256>::from_key_material(&key_material).unwrap();
//! let mut hmac = key.create_verifier();
//! hmac.do_update(b"Hello,");
//! hmac.do_update(b" world!");
//! if hmac.do_verify_final(b"\xa2\xd1\x2e\xcf\xfc\x41\xba\xf1\x23\xd6\x3e\x44\xfc\x27\x88\x90\x47\xcd\x08\xe7\x05\xd7\x0f\xa3\xb8\xaa\x8a\x5c\x18\x7c\x6c\xa9"
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
//! use bouncycastle_core::symmetric_key::{FromAnyKeyMaterial, MacGenerationKey};
//! use bouncycastle_core::traits::{MAC, SuspendableKeyed};
//! use bouncycastle_hmac::HmacKey;
//! use bouncycastle_sha2::SHA256;
//! use bouncycastle_sha2::hmac::HMAC_SHA256;
//!
//! let msg_part1 = b"The quick brown fox";
//! let msg_part2 = b" jumped over the lazy dog";
//!
//! let key = KeyMaterial256::from_bytes_as_type(
//!             b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
//!             KeyType::MACKey).unwrap();
//!
//! let mut hmac = HmacKey::<SHA256>::from_key_material(&key).unwrap().create_generator();
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
//! | `HMAC_SHA224`, `HMAC_SHA256`, and their `HmacKey`          | 224          |
//! | `HMAC_SHA384`, `HMAC_SHA512`, and their `HmacKey`          | 416          |
//! | Suspended `HMAC_SHA224`/`HMAC_SHA256` state               | 108          |
//! | Suspended `HMAC_SHA384`/`HMAC_SHA512` state               | 204          |
//!
//! The worker and the key are each two of the underlying hash object (see the crate-level Memory
//! Usage section): the inner hash and the outer pad state, 2 x 112 = 224 for the SHA-256 family,
//! 2 x 208 = 416 for the SHA-512 family. The suspended state is exactly the inner hash's suspended
//! state -- the key is deliberately excluded -- so it matches the corresponding row for the bare
//! hash.
//!
//! # 🚨 Security Considerations 🚨
//!
//! * The key must carry at least the security strength claimed by the HMAC, and
//!   [`FromAnyKeyMaterial::from_key_material`] enforces that.
//!   [`FromAnyKeyMaterial::from_key_material_allow_weak`] deliberately skips the check; use it only
//!   where a weak or all-zero key is called for by the protocol (an all-zero HKDF salt, for
//!   example), not to silence an error.
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
use crate::{SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256};
use crate::{SUSPENDED_SHA256_STATE_LEN, SUSPENDED_SHA512_STATE_LEN};
use bouncycastle_core::key_material::KeyMaterial;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::HashAlgParams;
use bouncycastle_hmac::{HMAC, HMACParams};

/*** Imports needed for docs ***/
#[allow(unused_imports)]
use bouncycastle_core::key_material::KeyType;
#[allow(unused_imports)]
use bouncycastle_core::symmetric_key::{FromAnyKeyMaterial, MacGenerationKey, MacVerificationKey};
#[allow(unused_imports)]
use bouncycastle_core::traits::{MAC, SuspendableKeyed};
#[allow(unused_imports)]
use bouncycastle_hmac::{HmacKey, MIN_FIPS_DIGEST_LEN};

/*** String constants ***/
///
pub const HMAC_SHA224_NAME: &str = "HMAC-SHA224";
///
pub const HMAC_SHA256_NAME: &str = "HMAC-SHA256";
///
pub const HMAC_SHA384_NAME: &str = "HMAC-SHA384";
///
pub const HMAC_SHA512_NAME: &str = "HMAC-SHA512";
///
pub const HMAC_SHA512_224_NAME: &str = "HMAC-SHA512/224";
///
pub const HMAC_SHA512_256_NAME: &str = "HMAC-SHA512/256";

/*** Type aliases ***/
/// Public type for HMAC using SHA224.
#[allow(non_camel_case_types)]
pub type HMAC_SHA224 = HMAC<SHA224>;
impl HMACParams for SHA224 {
    type MACKey = KeyMaterial<{ <SHA224 as HashAlgParams>::OUTPUT_LEN }>;
    const HMAC_ALG_NAME: &'static str = HMAC_SHA224_NAME;
    const HMAC_MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_112bit;
    /// Defined in RFC 4231: id-hmacWithSHA224 { digestAlgorithm 8 }
    const HMAC_OID: &'static [u32] = &[1, 2, 840, 113549, 2, 8];
    const HMAC_OID_DER: &'static [u8] =
        &[0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x08];
}

/// Public type for HMAC using SHA256.
#[allow(non_camel_case_types)]
pub type HMAC_SHA256 = HMAC<SHA256>;
impl HMACParams for SHA256 {
    type MACKey = KeyMaterial<{ <SHA256 as HashAlgParams>::OUTPUT_LEN }>;
    const HMAC_ALG_NAME: &'static str = HMAC_SHA256_NAME;
    const HMAC_MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
    /// Defined in RFC 4231: id-hmacWithSHA256 { digestAlgorithm 9 }
    const HMAC_OID: &'static [u32] = &[1, 2, 840, 113549, 2, 9];
    const HMAC_OID_DER: &'static [u8] =
        &[0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09];
}

/// Public type for HMAC using SHA384.
#[allow(non_camel_case_types)]
pub type HMAC_SHA384 = HMAC<SHA384>;
impl HMACParams for SHA384 {
    type MACKey = KeyMaterial<{ <SHA384 as HashAlgParams>::OUTPUT_LEN }>;
    const HMAC_ALG_NAME: &'static str = HMAC_SHA384_NAME;
    const HMAC_MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_192bit;
    /// Defined in RFC 4231: id-hmacWithSHA384 { digestAlgorithm 10 }
    const HMAC_OID: &'static [u32] = &[1, 2, 840, 113549, 2, 10];
    const HMAC_OID_DER: &'static [u8] =
        &[0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0a];
}

/// Public type for HMAC using SHA512.
#[allow(non_camel_case_types)]
pub type HMAC_SHA512 = HMAC<SHA512>;
impl HMACParams for SHA512 {
    type MACKey = KeyMaterial<{ <SHA512 as HashAlgParams>::OUTPUT_LEN }>;
    const HMAC_ALG_NAME: &'static str = HMAC_SHA512_NAME;
    const HMAC_MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
    /// Defined in RFC 4231: id-hmacWithSHA512 { digestAlgorithm 11 }
    const HMAC_OID: &'static [u32] = &[1, 2, 840, 113549, 2, 11];
    const HMAC_OID_DER: &'static [u8] =
        &[0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0b];
}

/// Public type for HMAC using SHA512/224.
#[allow(non_camel_case_types)]
pub type HMAC_SHA512_224 = HMAC<SHA512_224>;
impl HMACParams for SHA512_224 {
    type MACKey = KeyMaterial<{ <SHA512_224 as HashAlgParams>::OUTPUT_LEN }>;
    const HMAC_ALG_NAME: &'static str = HMAC_SHA512_224_NAME;
    const HMAC_MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_112bit;
    /// Defined in RFC 8018 Appendix B.1.2: id-hmacWithSHA512-224 { digestAlgorithm 12 }
    const HMAC_OID: &'static [u32] = &[1, 2, 840, 113549, 2, 12];
    const HMAC_OID_DER: &'static [u8] =
        &[0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0c];
}

/// Public type for HMAC using SHA512/256.
#[allow(non_camel_case_types)]
pub type HMAC_SHA512_256 = HMAC<SHA512_256>;
impl HMACParams for SHA512_256 {
    type MACKey = KeyMaterial<{ <SHA512_256 as HashAlgParams>::OUTPUT_LEN }>;
    const HMAC_ALG_NAME: &'static str = HMAC_SHA512_256_NAME;
    const HMAC_MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
    /// Defined in RFC 8018 Appendix B.1.2: id-hmacWithSHA512-256 { digestAlgorithm 13 }
    const HMAC_OID: &'static [u32] = &[1, 2, 840, 113549, 2, 13];
    const HMAC_OID_DER: &'static [u8] =
        &[0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0d];
}

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
/// Length in bytes of the serialized state of [`HMAC_SHA512_224`].
pub const SUSPENDED_HMAC_SHA512_224_STATE_LEN: usize = SUSPENDED_SHA512_STATE_LEN;
/// Length in bytes of the serialized state of [`HMAC_SHA512_256`].
pub const SUSPENDED_HMAC_SHA512_256_STATE_LEN: usize = SUSPENDED_SHA512_STATE_LEN;
