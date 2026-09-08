//! Uses [bouncycastle-hmac] to provide HMAC-SHA2 instantiations.
//!
//! HMAC itself is implemented generically in `bouncycastle-hmac`; this module supplies the
//! SHA-2-specific parameters via [`HMACParams`] and publishes the resulting type aliases, so that
//! HMAC over a SHA2 hash is found in this crate, and [bouncycastle-hmac] serves as a utility crate
//! rather than as part of library's public API.

use crate::{SHA224, SHA256, SHA384, SHA512};
use crate::{SUSPENDED_SHA256_STATE_LEN, SUSPENDED_SHA512_STATE_LEN};
use bouncycastle_core::key_material::KeyMaterial;
use bouncycastle_core::traits::{HashAlgParams, SecurityStrength};
use bouncycastle_hmac::{HMAC, HMACParams};

/*** String constants ***/
///
pub const HMAC_SHA224_NAME: &str = "HMAC-SHA224";
///
pub const HMAC_SHA256_NAME: &str = "HMAC-SHA256";
///
pub const HMAC_SHA384_NAME: &str = "HMAC-SHA384";
///
pub const HMAC_SHA512_NAME: &str = "HMAC-SHA512";

/*** Type aliases ***/
/// Public type for HMAC using SHA224.
#[allow(non_camel_case_types)]
pub type HMAC_SHA224 = HMAC<SHA224, { <SHA224 as HashAlgParams>::BLOCK_LEN }>;
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
pub type HMAC_SHA256 = HMAC<SHA256, { <SHA256 as HashAlgParams>::BLOCK_LEN }>;
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
pub type HMAC_SHA384 = HMAC<SHA384, { <SHA384 as HashAlgParams>::BLOCK_LEN }>;
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
pub type HMAC_SHA512 = HMAC<SHA512, { <SHA512 as HashAlgParams>::BLOCK_LEN }>;
impl HMACParams for SHA512 {
    type MACKey = KeyMaterial<{ <SHA512 as HashAlgParams>::OUTPUT_LEN }>;
    const HMAC_ALG_NAME: &'static str = HMAC_SHA512_NAME;
    const HMAC_MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
    /// Defined in RFC 4231: id-hmacWithSHA512 { digestAlgorithm 11 }
    const HMAC_OID: &'static [u32] = &[1, 2, 840, 113549, 2, 11];
    const HMAC_OID_DER: &'static [u8] =
        &[0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0b];
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
