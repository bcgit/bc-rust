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
//! TODO -- is XDH specified in a NIST doc?
//!

#![no_std]
#![forbid(unsafe_code)]

// TODO -- #![forbid(missing_docs)]
//          Add back at the end

mod curve25519;
pub mod x25519;
