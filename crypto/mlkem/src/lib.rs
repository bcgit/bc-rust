//! This crate implements the Module Lattice Key-Encapsulation Mechanism (ML-KEM) as per FIPS 203.
//!
//! # Usage
//!
//! This crate has been designed to serve a wide range of use cases, from people dabbling in
//! cryptography for the first time, to cryptographic protocol designers who need access to the internal
//! functionality of the ML-KEM algorithm, to embedded systems developers who want access to memory
//! and performance optimized functions.
//!
//! This page gives examples of simple usage for generating keys and performing encapsulation and decapsulation operations.
//!
//! More examples on advanced usage can be found on the [mlkem] page.
//!
//! # Primer on KEM algorithms
//!
//! Since Key-Encapsulation Mechanisms behave differently from the Diffie-Hellman key exchanges that many people are familiar with,
//! we start with a brief primer on KEMs.
//!
//! The core operation of a KEM is "encapsulation" which performs a mathematical operation against a KEM public key and yields
//! a shared secret key, and a ciphertext. Internally, the encapsulation routine will use a cryptographic random number generator
//! to ensure that the shared secret key and ciphertext are strongly unique to this encapsulation operation.
//! The receiving party can then perform a "decapsulation" using the corresponding private key to obtain
//! the same shared secret key from the ciphertext.
//!
//! Some sources, including FIPS 203 refer to the public key as the "encapsulation key `ek`" and the private key
//! as the "decapsulation key `dk`". These are used interchangeable with the public key `pk` and private key (or secret key) `sk`.
//!
//! The three operations of a KEM algorithm are:
//!
//! * `keygen() -> (pk, sk)`
//! * `encaps(pk) -> (ss, ct)`
//! * `decaps(sk, ct) -> (ss)`
//!
//! Since both `keygen` and `encaps` require a source of randomness, it is also common for a cryptographic
//! library to expose deterministic versions, which are often labelled as "internal" since they should
//! be used carefully as their misuse can catastrophically reduce the algorithm's security.
//! For ML-KEM in particular, these are:
//!
//! * `ML-KEM.keygen_internal(seed)` requires a seed either written as `seed: [u8;64]` sometimes decomposed into `(d: [u8;32], z: [u8;32])`.
//! * `ML-KEM.encaps_internal(pk, m)` requires a random message `m: [u8;32]`.
//!
//! Using these functions without sufficiently random values for `seed` and `m` is ill-advised.
//!
//!
//! ## Generating Keys
//!
//! ```rust
//! use bouncycastle_mlkem::MLKEM768;
//! use bouncycastle_core::traits::KEM;
//!
//! let (pk, sk) = MLKEM768::keygen().unwrap();
//! ```
//! That's it. That will use the library's default OS-backend RNG.
//!
//! Commonly with the ML-KEM algorithm, a 64-byte seed is used as the private key, and expanded into
//! a full private key as needed. This is offered through the library's [KeyMaterialTrait] object:
//!
//! ```rust
//! use bouncycastle_core::key_material::{KeyMaterial512, KeyType, KeyMaterialTrait};
//! use bouncycastle_mlkem::{MLKEM768, MLKEMTrait};
//! use bouncycastle_hex as hex;
//!
//! let seed = KeyMaterial512::from_bytes_as_type(
//!     &hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
//!                   202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f").unwrap(),
//!     KeyType::Seed,
//! ).unwrap();
//!
//! let (pk, sk) = MLKEM768::keygen_from_seed(&seed).unwrap();
//! ```
//!
//! See [MLKEM] and [MLKEM::decaps_from_seed] for an API that uses a merged
//! keygen-and-decaps function to that allows you to store the private key only as a 64-byte seed.
//!
//! ## Encapsulating and Decapsulating
//!
//! ```rust
//! use bouncycastle_mlkem::{MLKEM768, MLKEMTrait};
//! use bouncycastle_core::traits::KEM;
//! use bouncycastle_core::errors::KEMError;
//!
//! let (pk, sk) = MLKEM768::keygen().unwrap();
//!
//! // Create the shared secret and ciphertext using the public key
//! let (ss, ct) = MLKEM768::encaps(&pk).unwrap();
//!
//! // Recover the shared secret using the private key
//! let ss1 = match MLKEM768::decaps(&sk, &ct) {
//!     Err(KEMError) => panic!("Error decapsulating"),
//!     Ok(ss) => ss,
//! };
//!
//! assert_eq!(ss, ss1);
//! ```
//! And that's the basic usage!
//!
//! # Memory Footprint
//!
//! The following table lists the size of the on-disk bytes encoding and the in-memory struct size of the
//! standard key objects:
//!
//! | Key Object | PK size on disk | PK size in memory | SK Size on disk | SK size in memory |
//! |------------|-----------------|-------------------|-----------------|-------------------|
//! | ML-KEM-512  | 800            | 1056              | 1632            | 2178 |
//! | ML-KEM-768  | 1184           | 1568              | 2400            | 3202 |
//! | ML-KEM-1024 | 1568           | 2080              | 3168            | 4226 |
//!
//! The following table lists the size of the on-disk bytes encoding and the in-memory struct size of the
//! expanded key objects that pre-expand the public matrix A for faster repeated encaps() and decaps() operations:
//!
//! | Key Object           | PK size on disk | PK size in memory | SK Size on disk | SK size in memory |
//! |----------------------|-----------------|-------------------|-----------------|-------------------|
//! | ML-KEM-512_expanded  | 800            | 3104              | 1632            | 4226 |
//! | ML-KEM-768_expanded  | 1184           | 6176              | 2400            | 7810 |
//! | ML-KEM-1024_expanded | 1568           | 10272              | 3168            | 12418 |
//!
//! All values are in bytes. The "in memory" sizes are measured by rust's `std::mem::size_of`.
//! Values in parentheses are the usual sizes in our un-optimized implementation in the \[bouncycastle_mldsa] crate.
//!
//! # Security
//! All functionality exposed by this crate is considered secure to use.
//! In other words, this crate does not contain any "hazmat" except for the obvious points about
//! handling your private keys properly: if you post your private key to github, or you generate
//! production keys from a weak seed, I can't help you, that's on you.
//! It is worth mentioning, however, that if using a [MLKEM::keygen_from_seed], then it is your
//! responsibility to ensure that the seed is cryptographically random and unpredictable.
//! And also that [MLKEM::encaps_internal] requires you to provide the randomness, so the ciphertext
//! will only be as strong as the randomness that you provide.
//!
//! A note about cryptographic side-channel attacks: considerable effort has been expended to attempt
//! to make this implementation constant-time, which generally means that the core mathematical algorithm
//! code that handles secret data uses bitshift-and-xor type constructions instead of if-and-loop
//! constructions. That should give this implementation reasonably good resistance to timing and
//! power analysis key extraction attacks, however: A) this is a "best-effort" and not formally verified,
//! and B) the Rust compiler does not guarantee constant-time behaviour no matter how clever your code,
//! so like all Safe Rust code (ie Rust code that does not include inline assembly), we are at the mercy
//! of the Rust compiler's optimizer for whether our bitshift-and-xor code actually remains
//! constant-time after compilation.

#![no_std]
#![forbid(missing_docs)]
#![forbid(unsafe_code)]
#![allow(incomplete_features)] // needed because currently generic_const_exprs is experimental
#![feature(generic_const_exprs)]
#![feature(adt_const_params)]
// These are because I'm matching variable names exactly against FIPS 204, for example both 'K' and 'k',
// or 'A' and 'a' are used and have specific meanings.
// But need to tell the rust linter to not care.
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
// so I can use private traits to hide internal stuff that needs to be generic within the
// MLKEM implementation, but I don't want accessed from outside, such as FIPS-internal functions.
#![allow(private_bounds)]

// imports needed just for docs
#[allow(unused_imports)]
use bouncycastle_core::key_material::KeyMaterialTrait;

// Exposed only for testing purposes
pub mod aux_functions;
mod matrix;
pub mod mlkem;
mod mlkem_keys;
// Exposed only for testing purposes
pub mod polynomial;

/*** Exported types ***/
pub use mlkem::{MLKEM, MLKEM512, MLKEM768, MLKEM1024, MLKEMTrait};
pub use mlkem_keys::{
    MLKEM512PrivateKey, MLKEM768PrivateKey, MLKEM1024PrivateKey, MLKEMPrivateKey,
};
pub use mlkem_keys::{
    MLKEM512PrivateKeyExpanded, MLKEM768PrivateKeyExpanded, MLKEM1024PrivateKeyExpanded,
    MLKEMPrivateKeyExpanded,
};
pub use mlkem_keys::{MLKEM512PublicKey, MLKEM768PublicKey, MLKEM1024PublicKey, MLKEMPublicKey};
pub use mlkem_keys::{
    MLKEM512PublicKeyExpanded, MLKEM768PublicKeyExpanded, MLKEM1024PublicKeyExpanded,
    MLKEMPublicKeyExpanded,
};
pub use mlkem_keys::{MLKEMPrivateKeyTrait, MLKEMPublicKeyTrait};

/*** Exported constants ***/
pub use mlkem::ML_KEM_512_NAME;
pub use mlkem::ML_KEM_768_NAME;
pub use mlkem::ML_KEM_1024_NAME;

pub use mlkem::{MLKEM_RND_LEN, MLKEM_SEED_LEN, MLKEM_SS_LEN};

pub use mlkem::{MLKEM512_CT_LEN, MLKEM512_PK_LEN, MLKEM512_SK_LEN};
pub use mlkem::{MLKEM768_CT_LEN, MLKEM768_PK_LEN, MLKEM768_SK_LEN};
pub use mlkem::{MLKEM1024_CT_LEN, MLKEM1024_PK_LEN, MLKEM1024_SK_LEN};

pub use matrix::Matrix;
