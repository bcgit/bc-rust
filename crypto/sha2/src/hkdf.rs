//! Uses [bouncycastle-hkdf] to provide HKDF-SHA2 instantiations.
//!
//! HKDF (RFC 5869) is implemented generically in [bouncycastle-hkdf]; this module pins its const
//! parameters to the SHA-2 hashes and publishes the resulting type aliases, so that HKDF over a SHA-2
//! hash is found alongside the hash it is built on.
//!
//! Only SHA-256 and SHA-512 are instantiated, matching what the KDF factory and the CLI expose.

use crate::hmac::{SUSPENDED_HMAC_SHA256_STATE_LEN, SUSPENDED_HMAC_SHA512_STATE_LEN};
use crate::{SHA256, SHA512};
use crate::{SUSPENDED_SHA256_STATE_LEN, SUSPENDED_SHA512_STATE_LEN};
use bouncycastle_hkdf::HKDF;

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
pub type HKDF_SHA256 = HKDF<SHA256, SUSPENDED_SHA256_STATE_LEN, SUSPENDED_HKDF_SHA256_STATE_LEN>;
/// Public type for HKDF using SHA512.
#[allow(non_camel_case_types)]
pub type HKDF_SHA512 = HKDF<SHA512, SUSPENDED_SHA512_STATE_LEN, SUSPENDED_HKDF_SHA512_STATE_LEN>;
