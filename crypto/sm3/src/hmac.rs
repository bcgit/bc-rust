//! HMAC over SM3, as specified in RFC 2104, taking into account NIST Implementation Guidance in
//! FIPS 140-2 IG A.8 and NIST SP 800-107-r1.
//!
//! Uses [`bouncycastle_hmac`] to provide the HMAC-SM3 instantiation: [`HMAC_SM3`].
//!
//! HMAC itself is implemented generically in [`bouncycastle_hmac`]; this module supplies the
//! SM3-specific parameters via [`HMACParams`] and publishes the resulting type alias, so that HMAC
//! over SM3 is found in this crate, and [`bouncycastle_hmac`] serves as a utility crate rather than
//! as part of the library's public API. See [`bouncycastle_hmac`] for the full description of the
//! three-phase [`MAC`] lifecycle, key typing and suspend/resume.
//!
//! The key buffer length is the underlying hash's block length: per RFC 2104, a key no longer than
//! the block is used verbatim, and only longer keys are pre-hashed down to the output length, so the
//! buffer must be able to hold a full block. It is taken from [`HashAlgParams::BLOCK_LEN`] -- the
//! 512-bit block GB/T 32905-2016 s. 5.2 pads to -- rather than restated as a literal so the two
//! cannot drift apart.
//!
//! # Usage Examples
//!
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::traits::MAC;
//! use bouncycastle_sm3::hmac::HMAC_SM3;
//!
//! let key = KeyMaterial256::from_bytes_as_type(&[0x0b; 32], KeyType::MACKey).unwrap();
//! let tag = HMAC_SM3::new(&key).unwrap().mac(b"Hi There");
//! assert_eq!(tag.len(), 32);
//! ```
//!
//! # Security Considerations
//!
//! * Verify with [`MAC::verify`] or [`MAC::do_verify_final`] rather than computing the MAC yourself
//!   and comparing: those use a constant-time comparison, while `==` on the byte slices leaks how
//!   many leading bytes matched.
//! * Truncating the MAC output below [`MIN_FIPS_DIGEST_LEN`] (4 bytes) is rejected, per FIPS 140-2
//!   IG A.8 / NIST SP 800-107-r1 Section 5.3.3. That is a floor, not a recommendation -- RFC 2104
//!   Section 5 recommends that the output length "be not less than half the length of the hash
//!   output ... and not less than 80 bits".
//! * Resuming a suspended HMAC with the wrong key cannot be detected and silently produces a wrong
//!   MAC.
//! * SM3 is a Merkle-Damgard construction and so is subject to length extension; `SM3(k || m)` is
//!   not a secure MAC and HMAC-SM3 is the right construction for keyed hashing over SM3.

use crate::{SM3, SUSPENDED_SM3_STATE_LEN};
use bouncycastle_core::key_material::KeyMaterial;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, AlgorithmOID, HashAlgParams};
use bouncycastle_hmac::{HMAC, HMACParams};

/*** Imports needed for docs ***/
#[allow(unused_imports)]
use bouncycastle_core::key_material::KeyType;
#[allow(unused_imports)]
use bouncycastle_core::traits::MAC;
#[allow(unused_imports)]
use bouncycastle_hmac::MIN_FIPS_DIGEST_LEN;
/*** end of doc-only imports ***/

/*** String constants ***/
/// Algorithm name string for HMAC-SM3, as used by the factories and CLI.
pub const HMAC_SM3_NAME: &str = "HMAC-SM3";

/*** Params types and type aliases ***/
/// The parameters for HMAC-SM3 -- see [`HMAC_SM3`].
#[derive(Clone)]
#[allow(non_camel_case_types)]
pub struct HMAC_SM3Params;

impl Algorithm for HMAC_SM3Params {
    const ALG_NAME: &'static str = HMAC_SM3_NAME;
    // The strength this HMAC claims. Deliberately stated here rather than read off
    // SM3: HMAC does not rest on the hash's collision resistance, so in principle the
    // two can differ (NIST SP 800-107-r1 Section 5.3.4 bounds HMAC's strength by
    // `min(strength of K, 2C)` for a `C`-bit chaining value). This is the value
    // `MAC::new` enforces against the key and `keygen_from_rng` against the RNG.
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

/// Assigned by the Chinese OSCCA (GM/T 0006): hmac-sm3 { sm3 2 } = 1.2.156.10197.1.401.2
impl AlgorithmOID for HMAC_SM3Params {
    const OID: &'static [u32] = &[1, 2, 156, 10197, 1, 401, 2];
    const OID_DER: &'static [u8] =
        &[0x06, 0x09, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x83, 0x11, 0x02];
}

impl HMACParams for HMAC_SM3Params {
    type MACKey = KeyMaterial<{ <SM3 as HashAlgParams>::OUTPUT_LEN }>;
    type KeyBuf = [u8; <SM3 as HashAlgParams>::BLOCK_LEN];
}

/// Public type for HMAC using SM3.
#[allow(non_camel_case_types)]
pub type HMAC_SM3 = HMAC<SM3, HMAC_SM3Params>;

/*** Serialized-state length constants ***/
// HMAC's suspended state is exactly the inner hasher's state -- the key is deliberately excluded and
// must be re-supplied on resume -- so this is SM3's own state length.
/// Length in bytes of the serialized state of [`HMAC_SM3`].
pub const SUSPENDED_HMAC_SM3_STATE_LEN: usize = SUSPENDED_SM3_STATE_LEN;
