//! HMAC over SM3, as specified in RFC 2104, taking into account NIST Implementation Guidance in
//! FIPS 140-3 IG C.L.
//!
//! Uses [`bouncycastle_hmac`] to provide the HMAC-SM3 instantiation: [`HMAC_SM3`].
//!
//! HMAC itself is implemented generically in [`bouncycastle_hmac`]; this module supplies the
//! SM3-specific parameters via [`HMACParams`] and publishes the resulting type alias, so that HMAC
//! over SM3 is found in this crate, and [`bouncycastle_hmac`] serves as a utility crate rather than
//! as part of the library's public API. See [`bouncycastle_hmac`] for the full description of the
//! key and the [`MACGenerator`] / [`MACVerifier`] workers it hands out.
//!
//! A key of any length is accepted: per RFC 2104, a key longer than the hash's block -- the 512-bit
//! block GB/T 32905-2016 s. 5.2 pads to -- is pre-hashed to the output length. The key's two pad
//! states are computed once, when the [`HmacKey`] is built.
//!
//! # Usage Examples
//!
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::symmetric_key::{FromAnyKeyMaterial, MacGenerationKey};
//! use bouncycastle_hmac::HmacKey;
//! use bouncycastle_sm3::SM3;
//!
//! let key_material = KeyMaterial256::from_bytes_as_type(&[0x0b; 32], KeyType::MACKey).unwrap();
//! let key = HmacKey::<SM3>::from_key_material(&key_material).unwrap();
//! let tag = key.mac(b"Hi There");
//! assert_eq!(tag.len(), 32);
//! ```
//!
//! # 🚨 Security Considerations 🚨
//!
//! * Verify with [`MacVerificationKey::verify`] or [`MACVerifier::do_verify_final`] rather than
//!   computing the MAC yourself and comparing: those use a constant-time comparison, while `==` on
//!   the byte slices leaks how many leading bytes matched.
//! * The tag is the hash's full output; a protocol that truncates it does so on the array it gets
//!   back, and the verifier takes only the full length. RFC 2104 Section 5 recommends that a
//!   truncated length "be not less than half the length of the hash output ... and not less than
//!   80 bits"; FIPS 140-3 IG C.L Resolution C.4 sets the floor at 32 bits.
//! * SM3 is a Merkle-Damgard construction and so is subject to length extension; `SM3(k || m)` is
//!   not a secure MAC and HMAC-SM3 is the right construction for keyed hashing over SM3.

use crate::SM3;
use crate::hkdf::HKDF_SM3_NAME;
use bouncycastle_core::key_material::KeyMaterial;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::HashAlgParams;
use bouncycastle_hmac::{HMAC, HMACParams};

/*** Imports needed for docs ***/
#[allow(unused_imports)]
use bouncycastle_core::key_material::KeyType;
#[allow(unused_imports)]
use bouncycastle_core::symmetric_key::MacVerificationKey;
#[allow(unused_imports)]
use bouncycastle_core::traits::{MACGenerator, MACVerifier};
#[allow(unused_imports)]
use bouncycastle_hmac::HmacKey;
/*** end of doc-only imports ***/

/*** String constants ***/
/// Algorithm name string for HMAC-SM3, as used by the factories and CLI.
pub const HMAC_SM3_NAME: &str = "HMAC-SM3";

/*** Type aliases ***/
/// Public type for HMAC using SM3.
#[allow(non_camel_case_types)]
pub type HMAC_SM3<'k, Dir> = HMAC<'k, SM3, Dir>;
impl HMACParams for SM3 {
    type MACKey = KeyMaterial<{ <SM3 as HashAlgParams>::OUTPUT_LEN }>;
    const HMAC_ALG_NAME: &'static str = HMAC_SM3_NAME;
    const HKDF_ALG_NAME: &'static str = HKDF_SM3_NAME;
    const HMAC_MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
    /// Assigned by the Chinese OSCCA (GM/T 0006): hmac-sm3 { sm3 2 } = 1.2.156.10197.1.401.2
    const HMAC_OID: &'static [u32] = &[1, 2, 156, 10197, 1, 401, 2];
    const HMAC_OID_DER: &'static [u8] =
        &[0x06, 0x09, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x83, 0x11, 0x02];
}
