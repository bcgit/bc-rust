//! Uses [bouncycastle-hmac] to provide HMAC-SHA3 instantiations.
//!
//! HMAC itself is implemented generically in `bouncycastle-hmac`; this module supplies the
//! SHA-3-specific parameters via [`HMACParams`] and publishes the resulting type aliases, so that
//! HMAC over a SHA-3 hash is found alongside the hash it is built on.
//!
//! The key buffer length of each alias is the underlying hash's block length: per RFC 2104, a key no
//! longer than the block is used verbatim, and only longer keys are pre-hashed down to the output
//! length, so the buffer must be able to hold a full block. It is taken from
//! [`HashAlgParams::BLOCK_LEN`] -- the values FIPS 202 Table 3 ("Input block sizes for HMAC") gives
//! for the SHA-3 hash functions -- rather than restated as a literal so the two cannot drift apart.

use crate::SUSPENDED_SHA3_STATE_LEN;
use crate::{SHA3_224, SHA3_256, SHA3_384, SHA3_512};
use bouncycastle_core::key_material::KeyMaterial;
use bouncycastle_core::traits::{HashAlgParams, SecurityStrength};
use bouncycastle_hmac::{HMAC, HMACParams};

/*** String constants ***/
///
pub const HMAC_SHA3_224_NAME: &str = "HMAC-SHA3-224";
///
pub const HMAC_SHA3_256_NAME: &str = "HMAC-SHA3-256";
///
pub const HMAC_SHA3_384_NAME: &str = "HMAC-SHA3-384";
///
pub const HMAC_SHA3_512_NAME: &str = "HMAC-SHA3-512";

/*** Type aliases ***/
/// Public type for HMAC using SHA3_224.
#[allow(non_camel_case_types)]
pub type HMAC_SHA3_224 = HMAC<SHA3_224, { <SHA3_224 as HashAlgParams>::BLOCK_LEN }>;
impl HMACParams for SHA3_224 {
    type MACKey = KeyMaterial<{ <SHA3_224 as HashAlgParams>::OUTPUT_LEN }>;
    const HMAC_ALG_NAME: &'static str = HMAC_SHA3_224_NAME;
    const HMAC_MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_112bit;
    /// Assigned by NIST in the Computer Security Objects Register: id-hmacWithSHA3-224 { hashAlgs 13 }
    const HMAC_OID: &'static [u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 13];
    const HMAC_OID_DER: &'static [u8] =
        &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0d];
}

/// Public type for HMAC using SHA3_256.
#[allow(non_camel_case_types)]
pub type HMAC_SHA3_256 = HMAC<SHA3_256, { <SHA3_256 as HashAlgParams>::BLOCK_LEN }>;
impl HMACParams for SHA3_256 {
    type MACKey = KeyMaterial<{ <SHA3_256 as HashAlgParams>::OUTPUT_LEN }>;
    const HMAC_ALG_NAME: &'static str = HMAC_SHA3_256_NAME;
    const HMAC_MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
    /// Assigned by NIST in the Computer Security Objects Register: id-hmacWithSHA3-256 { hashAlgs 14 }
    const HMAC_OID: &'static [u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 14];
    const HMAC_OID_DER: &'static [u8] =
        &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0e];
}

/// Public type for HMAC using SHA3_384.
#[allow(non_camel_case_types)]
pub type HMAC_SHA3_384 = HMAC<SHA3_384, { <SHA3_384 as HashAlgParams>::BLOCK_LEN }>;
impl HMACParams for SHA3_384 {
    type MACKey = KeyMaterial<{ <SHA3_384 as HashAlgParams>::OUTPUT_LEN }>;
    const HMAC_ALG_NAME: &'static str = HMAC_SHA3_384_NAME;
    const HMAC_MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_192bit;
    /// Assigned by NIST in the Computer Security Objects Register: id-hmacWithSHA3-384 { hashAlgs 15 }
    const HMAC_OID: &'static [u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 15];
    const HMAC_OID_DER: &'static [u8] =
        &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0f];
}

/// Public type for HMAC using SHA3_512.
#[allow(non_camel_case_types)]
pub type HMAC_SHA3_512 = HMAC<SHA3_512, { <SHA3_512 as HashAlgParams>::BLOCK_LEN }>;
impl HMACParams for SHA3_512 {
    type MACKey = KeyMaterial<{ <SHA3_512 as HashAlgParams>::OUTPUT_LEN }>;
    const HMAC_ALG_NAME: &'static str = HMAC_SHA3_512_NAME;
    const HMAC_MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
    /// Assigned by NIST in the Computer Security Objects Register: id-hmacWithSHA3-512 { hashAlgs 16 }
    const HMAC_OID: &'static [u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 16];
    const HMAC_OID_DER: &'static [u8] =
        &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x10];
}

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
