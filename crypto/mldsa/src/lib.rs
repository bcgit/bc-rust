//! This crate implements the Module Lattice Digital Signature Algorithm (ML-DSA) as per FIPS 204.
//!
//! # Usage
//!
//! This crate has been designed to serve a wide range of use cases, from people dabbling in
//! cryptography for the first time, to cryptographic protocol designers who need access to the internal and advanced
//! functionality of the ML-DSA algorithm, to embedded systems developers who want access to memory
//! and performance optimized functions.
//!
//! This page gives examples of simple usage for generating keys and signatures, and verifying signatures.
//!
//! More examples on advanced usage can be found on the [`mldsa`] and [`hash_mldsa`] pages.
//!
//! ## Generating Keys
//!
//! ```rust
//! use bouncycastle_mldsa::{MLDSA65, MLDSATrait};
//!
//! let (pk, sk) = MLDSA65::keygen().unwrap();
//! ```
//! That's it. That will use the library's default OS-backend RNG.
//!
//! Commonly with the ML-DSA algorithm, a 32-byte seed is used as the private key, and expanded into
//! a full private key as needed. This is offered through the library's [`KeyMaterialTrait`] object:
//!
//! ```rust
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType, KeyMaterialTrait};
//! use bouncycastle_mldsa::{MLDSA65, MLDSATrait};
//! use bouncycastle_hex as hex;
//!
//! let seed = KeyMaterial256::from_bytes_as_type(
//!     &hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap(),
//!     KeyType::Seed,
//! ).unwrap();
//!
//! let (pk, sk) = MLDSA65::keygen_from_seed(&seed).unwrap();
//! ```
//!
//! See [`MLDSATrait`] and [`MLDSATrait::sign_mu_deterministic_from_seed`] for an API flow that uses a merged
//! keygen-and-sign function to provide improved speed and memory performance compared with making
//! separate calls to [`MLDSATrait::keygen_from_seed`] followed by [`Signer::sign`].
//!
//! ## Generating and Verifying Signatures
//!
//! ```rust
//! use bouncycastle_mldsa::{MLDSA65, MLDSATrait};
//! use bouncycastle_core::traits::{Signer, SignatureVerifier};
//! use bouncycastle_core::errors::SignatureError;
//!
//! let msg = b"The quick brown fox";
//!
//! let (pk, sk) = MLDSA65::keygen().unwrap();
//!
//! let sig = MLDSA65::sign(&sk, msg, None).unwrap();
//! // This is the signature value that you can save to a file or whatever you need.
//!
//! match MLDSA65::verify(&pk, msg, None, &sig) {
//!     Ok(()) => println!("Signature is valid!"),
//!     Err(SignatureError::SignatureVerificationFailed) => println!("Signature is invalid!"),
//!     Err(e) => panic!("Something else went wrong: {:?}", e),
//! }
//! ```
//!
//! And that's the basic usage! There are lots more bells-and-whistles in the form of exposed algorithm
//! parameters, streaming APIs and other goodies that you can find by poking around this documentation.
//!
//! # Memory Footprint
//!
//! The following table lists the size of the on-disk bytes encoding and the in-memory struct size of the
//! standard key objects:
//!
//! | Key Object | PK size on disk | PK size in memory | SK Size on disk | SK size in memory |
//! |------------|-----------------|-------------------|-----------------|-------------------|
//! | ML-DSA-44  | 1312            | 1312 (4128)       | 2560            | 12464             |
//! | ML-DSA-65  | 1952            | 1952 (6176)       | 4032            | 17584             |
//! | ML-DSA-87  | 2592            | 2592 (8224)       | 4896            | 23728             |
//!
//! The following table lists the size of the on-disk bytes encoding and the in-memory struct size of the
//! expanded key objects that pre-expand the public matrix A for faster repeated verify() operations:
//!
//! | Key Object          | PK size on disk | PK size in memory | SK Size on disk | SK size in memory |
//! |---------------------|-----------------|-------------------|-----------------|-------------------|
//! | ML-DSA-44_expanded  | 1312            | 20512             | 2560            | 28848             |
//! | ML-DSA-65_expanded  | 1952            | 36896             | 4032            | 48304             |
//! | ML-DSA-87_expanded  | 2592            | 65568             | 4896            | 81072             |
//!
//! All values are in bytes. The "in memory" sizes are measured by rust's `std::mem::size_of`.
//! Values in parentheses are the usual sizes in our un-optimized implementation in the \[bouncycastle_mldsa] crate.
//!
//!
//! # 🚨 Security 🚨
//!
//! This crate intends to expose only APIs that are secure to use.
//! There are, however, a few exceptions that are worth mentioning.
//!
//! If using a [`MLDSA::keygen_from_seed`], then it is your responsibility to ensure that the seed is
//! cryptographically random and unpredictable at a security strength that matches the MLDSA parameter set.
//!
//! ML-DSA and HashML-DSA take several parameters: `seed`, `mu`, `ph`, `ctx`, and `rnd`.
//! They fall into two groups with very different failure modes.
//!
//!
//! `seed` and `rnd`, however, are secret/entropy inputs and must be handled with care:
//!
//! - `seed` *is* the private key, i.e. the entire key is derived from it. It must be generated
//!   with a strong cryptographically secure PRNG, it must be kept secret, and it must never reused.
//!   A low-entropy, predictable, or disclosed seed yields a full key compromise,
//!   not merely an unverifiable signature.
//!
//! - `rnd` is the signing randomizer. ML-DSA is designed to be nonce-misuse-resistant, i.e. the
//!   signing mask is derived from a secret key value together with `rnd` and `mu`, so
//!   reusing `rnd`, or using the all-zero "deterministic" mode, does NOT
//!   leak the private key (unlike ECDSA). Deterministic signing is FIPS-approved and safe. The randomized
//!   mode exists to add resistance to fault and side-channel attacks, so `rnd`
//!   should come from a good RNG when that threat model applies.
//!
//! `mu`, `ph`, and `ctx` are binding values that the verifier must reproduce. This means that getting
//! them wrong does not compromise security, it just yields a signature the intended
//! verifier won't accept (a correctness/interoperability failure).
//! One caveat: `ctx` can still be security-relevant at the protocol level (domain separation, replay and
//! cross-protocol binding), so choosing it incorrectly can weaken those properties.

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]
// These are because the code is matching variable names exactly against FIPS 204, for example both 'K' and 'k',
// or 'A' and 'a' are used and have specific meanings.
// But need to tell the rust linter to not care.
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
// so that private traits can be used to hide internal stuff that needs to be generic within the
// MLDSA implementation, but should not get accessed from outside, such as FIPS-internal functions.
#![allow(private_bounds)]
#![allow(private_interfaces)]
// Used in HashMLDSA for oid: &'static [u8] params.
// #![allow(incomplete_features)] // needed because currently unsized_const_params is experimental
// #![feature(adt_const_params)]
// #![feature(unsized_const_params)]

// imports needed just for docs
#[allow(unused_imports)]
use bouncycastle_core::key_material::KeyMaterialTrait;
#[allow(unused_imports)]
use bouncycastle_core::traits::{SignatureVerifier, Signer};

mod aux_functions;
pub mod hash_mldsa;
mod matrix;
pub mod mldsa;
mod mldsa_keys;
mod polynomial;

/*** Exported types ***/
pub use hash_mldsa::{HashMLDSA44_with_SHA256, HashMLDSA65_with_SHA256, HashMLDSA87_with_SHA256};
pub use hash_mldsa::{HashMLDSA44_with_SHA512, HashMLDSA65_with_SHA512, HashMLDSA87_with_SHA512};
pub use mldsa::MuBuilder;
pub use mldsa::{MLDSA, MLDSA44, MLDSA65, MLDSA87, MLDSATrait};
pub use mldsa_keys::{MLDSA44PrivateKey, MLDSA65PrivateKey, MLDSA87PrivateKey, MLDSAPrivateKey};
pub use mldsa_keys::{
    MLDSA44PrivateKeyExpanded, MLDSA65PrivateKeyExpanded, MLDSA87PrivateKeyExpanded,
    MLDSAPrivateKeyExpanded,
};
pub use mldsa_keys::{MLDSA44PublicKey, MLDSA65PublicKey, MLDSA87PublicKey, MLDSAPublicKey};
pub use mldsa_keys::{
    MLDSA44PublicKeyExpanded, MLDSA65PublicKeyExpanded, MLDSA87PublicKeyExpanded,
    MLDSAPublicKeyExpanded,
};
pub use mldsa_keys::{MLDSAPrivateKeyTrait, MLDSAPublicKeyTrait};

/*** Exported constants ***/
pub use mldsa::ML_DSA_44_NAME;
pub use mldsa::ML_DSA_65_NAME;
pub use mldsa::ML_DSA_87_NAME;

pub use hash_mldsa::HASH_ML_DSA_44_with_SHA256_NAME;
pub use hash_mldsa::HASH_ML_DSA_65_WITH_SHA256_NAME;
pub use hash_mldsa::HASH_ML_DSA_87_with_SHA256_NAME;

pub use hash_mldsa::HASH_ML_DSA_44_with_SHA512_NAME;
pub use hash_mldsa::HASH_ML_DSA_65_WITH_SHA512_NAME;
pub use hash_mldsa::HASH_ML_DSA_87_WITH_SHA512_NAME;

pub use mldsa::{MLDSA_MU_LEN, MLDSA_RND_LEN, MLDSA_SEED_LEN, MLDSA_TR_LEN};
pub use mldsa::{MLDSA44_PK_LEN, MLDSA44_SIG_LEN, MLDSA44_SK_LEN};
pub use mldsa::{MLDSA65_PK_LEN, MLDSA65_SIG_LEN, MLDSA65_SK_LEN};
pub use mldsa::{MLDSA87_PK_LEN, MLDSA87_SIG_LEN, MLDSA87_SK_LEN};

pub use mldsa::SUSPENDED_MU_BUILDER_STATE_LEN;

pub use matrix::Matrix;
