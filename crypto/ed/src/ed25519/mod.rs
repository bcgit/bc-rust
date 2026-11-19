//! Ed25519 and Ed25519ph (RFC 8032 Section 5.1; FIPS 186-5 Section 7): the arithmetic and the
//! scheme, crate-private until the key types are built on them.

// Nothing outside its tests calls the scalar arithmetic until the scheme lands.
#[allow(dead_code)]
mod scalar;
