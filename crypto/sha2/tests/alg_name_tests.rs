//! The HMAC and HKDF names over SHA-2, spelled out: the constants are what callers and
//! registries match on, and a test against the constant itself would not see one respelled.

use bouncycastle_sha2::hkdf::{HKDF_SHA256_NAME, HKDF_SHA384_NAME, HKDF_SHA512_NAME};
use bouncycastle_sha2::hmac::{
    HMAC_SHA224_NAME, HMAC_SHA256_NAME, HMAC_SHA384_NAME, HMAC_SHA512_NAME,
};

#[test]
fn the_hmac_and_hkdf_names_are_spelled_as_published() {
    assert_eq!(HMAC_SHA224_NAME, "HMAC-SHA224");
    assert_eq!(HMAC_SHA256_NAME, "HMAC-SHA256");
    assert_eq!(HMAC_SHA384_NAME, "HMAC-SHA384");
    assert_eq!(HMAC_SHA512_NAME, "HMAC-SHA512");
    assert_eq!(HKDF_SHA256_NAME, "HKDF-SHA256");
    assert_eq!(HKDF_SHA384_NAME, "HKDF-SHA384");
    assert_eq!(HKDF_SHA512_NAME, "HKDF-SHA512");
}
