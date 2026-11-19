//! HMAC over RIPEMD-160, as specified in RFC 2104; RFC 2286 gives the test cases.
//!
//! Uses [`bouncycastle_hmac`] to provide the instantiation [`HMAC_RIPEMD160`]. HMAC itself is
//! implemented generically in [`bouncycastle_hmac`]; this module supplies the parameters via
//! [`HMACParams`] and publishes the type alias. See [`bouncycastle_hmac`] for the full
//! description of the key and the [`MACGenerator`] / [`MACVerifier`] workers it hands out.
//!
//! # Usage Examples
//!
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::symmetric_key::{FromAnyKeyMaterial, MacGenerationKey};
//! use bouncycastle_hmac::HmacKey;
//! use bouncycastle_ripemd::RIPEMD160;
//!
//! let key_material = KeyMaterial256::from_bytes_as_type(&[0x0b; 20], KeyType::MACKey).unwrap();
//! let key = HmacKey::<RIPEMD160>::from_key_material(&key_material).unwrap();
//! let tag = key.mac(b"Hi There");
//! assert_eq!(tag.len(), 20);
//! ```
//!
//! # 🚨 Security Considerations 🚨
//!
//! * This is a legacy construction: it reports [`SecurityStrength::None`], as the hash does
//!   (see the [crate docs](crate)). [`FromAnyKeyMaterial::from_key_material`] still refuses a
//!   key that carries no security strength, such as RFC 2286's 4-byte key; a protocol that
//!   needs one uses [`FromAnyKeyMaterial::from_key_material_allow_weak`].
//! * Verify with [`MacVerificationKey::verify`] or [`MACVerifier::do_verify_final`] rather than
//!   computing the MAC yourself and comparing: those use a constant-time comparison.
//! * The tag is the hash's full output; a protocol that truncates it (RFC 2857's
//!   HMAC-RIPEMD-160-96) does so on the array it gets back, and the verifier takes only the full
//!   length.

use crate::RIPEMD160;
use bouncycastle_core::key_material::KeyMaterial;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::HashAlgParams;
use bouncycastle_hmac::{HMAC, HMACParams};

/*** Imports needed for docs ***/
#[allow(unused_imports)]
use bouncycastle_core::symmetric_key::{FromAnyKeyMaterial, MacVerificationKey};
#[allow(unused_imports)]
use bouncycastle_core::traits::{MACGenerator, MACVerifier};
/*** end of doc-only imports ***/

/*** String constants ***/
/// Algorithm name string for HMAC-RIPEMD160, as used by the factories and CLI.
pub const HMAC_RIPEMD160_NAME: &str = "HMAC-RIPEMD160";

/*** Type aliases ***/
/// Public type for HMAC using RIPEMD-160.
#[allow(non_camel_case_types)]
pub type HMAC_RIPEMD160<'k, Dir> = HMAC<'k, RIPEMD160, Dir>;
impl HMACParams for RIPEMD160 {
    type MACKey = KeyMaterial<{ <RIPEMD160 as HashAlgParams>::OUTPUT_LEN }>;
    const HMAC_ALG_NAME: &'static str = HMAC_RIPEMD160_NAME;
    const HKDF_ALG_NAME: &'static str = "HKDF-RIPEMD160";
    // Half the hash's output length in bits (160 / 2 = 80), which below 112 bits is `None`.
    const HMAC_MAX_SECURITY_STRENGTH: SecurityStrength =
        SecurityStrength::from_bits(<RIPEMD160 as HashAlgParams>::OUTPUT_LEN * 8 / 2);
    /// Assigned by IANA in the registry "SMI Security for Mechanism isakmpOakley Codes":
    /// HMAC-RIPEMD160 { 1 3 6 1 5 5 8 1 4 }
    const HMAC_OID: &'static [u32] = &[1, 3, 6, 1, 5, 5, 8, 1, 4];
    const HMAC_OID_DER: &'static [u8] =
        &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x08, 0x01, 0x04];
}
