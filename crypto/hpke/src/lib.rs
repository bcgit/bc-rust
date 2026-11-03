//! Building blocks of Hybrid Public Key Encryption (HPKE), as specified in RFC 9180.
//!
//! This is a utility crate and is not intended to be used directly. It provides
//! [`dhkem::DHKEM`] -- the DH-Based KEM of RFC 9180 Section 4.1, generic over any Diffie-Hellman
//! group that implements [`dhkem::DHKEMParams`], the extension point through which a group
//! declares its keys, its DH operation and the KDF that the DHKEM pairs it with. Each group's crate
//! implements that trait and exposes the result through the
//! [`KEMEncapsulator`](bouncycastle_core::traits::KEMEncapsulator) and
//! [`KEMDecapsulator`](bouncycastle_core::traits::KEMDecapsulator) traits on its own algorithm
//! struct
//!
//! For example:
//!
//! | KEM                          | kem_id | Exposed as                     |
//! |------------------------------|--------|--------------------------------|
//! | DHKEM(X25519, HKDF-SHA256)   | 0x0020 | `bouncycastle_ed::x25519::X25519` |
//!
//! The KDF is HKDF over the hash named by [`dhkem::DHKEMParams::KDFHash`], computed on
//! [`HMAC`](bouncycastle_hmac::HMAC) as RFC 5869 defines it, so any hash that
//! [`HMAC`](bouncycastle_hmac::HMAC) supports can be used.
//!
//! The rest of HPKE (the key schedule, AEAD encryption and secret export of RFC 9180 Section 5) is
//! not yet implemented.
//!
//! # 🚨 Security Considerations 🚨
//!
//! * [`dhkem::DHKEMParams::dh`] must perform the group's validation of the DH output (RFC 9180
//!   Section 7.1.4), such as rejecting the all-zero X25519 output. [`dhkem::DHKEM`] relies on it to
//!   reject unusable public keys.
//! * [`dhkem::DHKEM::derive_key_pair`] is deterministic: the key pair is only as secret as the
//!   input keying material.

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

pub mod dhkem;
