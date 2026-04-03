//!
//! This crate implements the Module Lattice Digital Signature Algorithm (ML-DSA) as per FIPS 204.
//!
//! # Usage
//!
//! This crate has been designed to serve a wide range of use cases, from people dabbling in
//! cryptography for the first time, to cryptographic protocol designers who need access to the advanced
//! functionality of the ML-DSA algorithm, to embedded systems developers who want access to memory
//! and performance optimized functions.
//!
//! This page gives examples of simple usage for generating keys and signatures, and verifying signatures.//!
//!
//! More examples on advanced usage can be found on the [mldsa] and [hash_mldsa] pages.
//!
//! ## Generating Keys
//!
//! ```rust
//! use bouncycastle_mldsa::MLDSA65;
//! use bouncycastle_core_interface::traits::Signature;
//!
//! let (pk, sk) = MLDSA65::keygen().unwrap();
//! ```
//! That's it. That will use the library's default OS-backend RNG.
//!
//! Commonly with the ML-DSA algorithm, a 32-byte seed is used as the private key, and expanded into
//! a full private key as needed. This is offered through the library's [KeyMaterial] object:
//!
//! ```rust
//! use bouncycastle_core_interface::traits::KeyMaterial;
//! use bouncycastle_core_interface::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_mldsa::{MLDSA65, MLDSATrait};
//!
//! let seed = KeyMaterial256::from_bytes_as_type(
//!     &hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap(),
//!     KeyType::Seed,
//! ).unwrap();
//!
//! let (pk, sk) = MLDSA65::keygen_from_seed(&seed).unwrap();
//! ```
//!
//! See [MLDSATrait] and [MLDSATrait::sign_mu_deterministic_from_seed] for an API flow that uses a merged
//! keygen-and-sign function to provide improved speed and memory performance compared with making
//! separate calls to [MLDSATrait::keygen_from_seed] followed by [Signature::sign].
//!
//! ## Generating and Verifying Signatures
//!
//! ```rust
//! use bouncycastle_core_interface::errors::SignatureError;
//! use bouncycastle_mldsa::{MLDSA65, MLDSATrait};
//! use bouncycastle_core_interface::traits::Signature;
//!
//! let msg = b"The quick brown fox";
//!
//! let (pk, sk) = MLDSA65::keygen().unwrap();
//!
//! let sig: Vec<u8> = MLDSA65::sign(&sk, msg, None).unwrap();
//! // This is the signature value that you can save to a file or whatever you need.
//!
//! match MLDSA65::verify(&pk, msg, None, &sig) {
//!     Ok(()) => println!("Signature is valid!"),
//!     Err(SignatureError::SignatureVerificationFailed) => println!("Signature is invalid!"),
//!     Err(e) => panic!("Something else went wrong: {:?}", e),
//! }
//!
//! ```
//! And that's the basic usage! There are lots more bells-and-whistles in the form of exposed algorithm
//! parameters, streaming APIs and other goodies that you can find by poking around this documentation.
//!
//! # Security
//! All functionality exposed by this crate is considered secure to use.
//! In other words, this crate does not contain any "hazmat" except for the obvous points about
//! handling your private keys properly: if you post your private key to github, or you generate
//! production keys from a weak seed, I can't help you, that's on you.
//!
//! While the full formulation of the ML-DSA and HashML-DSA algorithms look complex with parameters
//! like `seed`, `mu`, `ph`, `ctx`, and `rnd`, rest assured that use (or misuse) of these parameters
//! do not really affect security of the algorithm; they just mean that you might produce a signature
//! that nobody else can verify.
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
// MLDSA implementation, but I don't want accessed from outside, such as FIPS-internal functions.
#![allow(private_bounds)]

// Used in HashMLDSA
#![feature(unsized_const_params)]

// imports needed just for docs
#[allow(unused_imports)]
use bouncycastle_core_interface::traits::{KeyMaterial, Signature, PHSignature};

pub mod mldsa; // todo -- pub just to get the docs. Is that right? Or should I suck the docs up here?
pub mod hash_mldsa; // todo -- pub just to get the docs. Is that right? Or should I suck the docs up here?
mod mldsa_keys;
mod polynomial;
mod aux_functions;
mod matrix;


/*** Exported types ***/
pub use mldsa::{MLDSATrait, MLDSA, MLDSA44, MLDSA65, MLDSA87};
pub use hash_mldsa::{HashMLDSA44_with_SHA256, HashMLDSA65_with_SHA256, HashMLDSA87_with_SHA256};
pub use hash_mldsa::{HashMLDSA44_with_SHA512, HashMLDSA65_with_SHA512, HashMLDSA87_with_SHA512};
pub use mldsa_keys::{MLDSAPrivateKeyTrait, MLDSAPublicKeyTrait};
pub use mldsa_keys::{MLDSAPublicKey, MLDSA44PublicKey, MLDSA65PublicKey, MLDSA87PublicKey};
pub use mldsa_keys::{MLDSAPrivateKey, MLDSA44PrivateKey, MLDSA65PrivateKey, MLDSA87PrivateKey};
pub use mldsa::{MuBuilder};

/*** Exported constants ***/
pub use mldsa::ML_DSA_44_NAME;
pub use mldsa::ML_DSA_65_NAME;
pub use mldsa::ML_DSA_87_NAME;

pub use hash_mldsa::Hash_ML_DSA_44_with_SHA256_NAME;
pub use hash_mldsa::Hash_ML_DSA_65_with_SHA256_NAME;
pub use hash_mldsa::Hash_ML_DSA_87_with_SHA256_NAME;

pub use hash_mldsa::Hash_ML_DSA_44_with_SHA512_NAME;
pub use hash_mldsa::Hash_ML_DSA_65_with_SHA512_NAME;
pub use hash_mldsa::Hash_ML_DSA_87_with_SHA512_NAME;

pub use mldsa::{TR_LEN, RND_LEN, MU_LEN};
pub use mldsa::{MLDSA44_PK_LEN, MLDSA44_SK_LEN, MLDSA44_SIG_LEN};
pub use mldsa::{MLDSA65_PK_LEN, MLDSA65_SK_LEN, MLDSA65_SIG_LEN};
pub use mldsa::{MLDSA87_PK_LEN, MLDSA87_SK_LEN, MLDSA87_SIG_LEN};
