//! RSA digital signatures: RSASSA-PKCS1-v1_5 and RSASSA-PSS (RFC 8017 §8), built on
//! [`bouncycastle_ec`]'s constant-time limb arithmetic ([`bouncycastle_ec::nat`],
//! [`bouncycastle_ec::montgomery`]) rather than a dedicated bignum type, for the same
//! constant-time reasoning that motivates that crate's own custom-curve arithmetic: a modular
//! exponentiation over a secret exponent has to run in the same time regardless of the exponent's
//! value, which needs limbs of a fixed width known at compile time.
//!
//! # Scope
//!
//! Signature schemes only -- no RSAES-OAEP or RSAES-PKCS1-v1_5 encryption. Modulus sizes 2048
//! through 8192 bits support both signing and verification; 1024-bit moduli support verification
//! only, enforced by the absence of a private-key/signer type for that size rather than a runtime
//! check.
//!
//! # Status
//!
//! [`modexp`] (constant-time modular exponentiation over a runtime-supplied modulus) is
//! implemented. The RSA-specific layers on top of it -- keys, CRT, PKCS#1 v1.5 and PSS -- are
//! not yet.

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

pub mod modexp;
