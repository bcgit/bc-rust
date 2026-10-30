//! The Edwards curve family includes curve25519 and curve448 which are used to construct
//! the EdDSA signature schemes Ed25519 and Ed448, and the XDH key exchange schemes X25519 and X448.
//!
//! # Standards
//!
//! Standardization of the Edwards Curve algorithms is spread across a number of documents:
//! * RFC7748 specifies the core elliptic curves "curve25519" and "curve448", as well as the XDH key exchange algorithms X25519 and X448 built on top of them.
//! * RFC8032 specifies the EdDSA digital signature algorithms, also built on top of curve25519 and curve448.
//! * FIPS 186-5 section 7 specifies the EdDSA digital signature algorithms, essentially re-published from RFC 8032.
//! * NIST SP 800-186 gives an excellent treatment of the mathematics of all the families of elliptic curves used in cryptography, including Edwards curves.
//!
//! XDH (X25519 and X448) is specified only in RFC 7748. NIST SP 800-186 §3.2.2 specifies the
//! curves Curve25519 and Curve448, but its Table 2 does not list them for key establishment, and
//! NIST SP 800-56A Rev. 3 does not include XDH, so X25519 and X448 are not NIST-approved key
//! agreement schemes.
//!
//! # Usage Examples
//!
//! See the [`x25519`] module for X25519 key generation and an Alice-and-Bob key agreement that
//! derives a symmetric key from the shared secret.

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

mod curve25519;
pub mod x25519;
