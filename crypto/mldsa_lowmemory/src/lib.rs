//! This crate implements the Module Lattice Digital Signature Algorithm (ML-DSA) as per FIPS 204 optimized
//! to have the lowest-reasonable runtime memory footprint (aka peak memory usage).
//!
//! We achieve an approximate **1/10 the memory footprint** at a cost of approximately **3x
//! the runtime for signing and no appreciable difference for keygen and verification**,
//! compared with our un-optimized implementation in the \[bouncycastle_mldsa] crate.
//! We are extremely happy with!
//!
//! # Philosophy of a low-memory implementation
//! First, a little primer on the objects that make up an ML-DSA key pair.
//! The "elements" of the lattice are polynomials of degree 256, represented in memory as
//! arrays of 256 i32's. That's 1 kb per polynomial.
//! Then we build vectors and matrices composed of these polynomials.
//! ML-DSA is parametrized as ML-DSA-k,l where k and l are the sizes of the vectors, and the matrices
//! have size k x l.
//! So ML-DSA-44 carries vectors of 4 polynomials and matrices of 4 x 4 = 16 polynomials.
//! ML-DSA-65 is 6, 5 and 6 x 5 = 30 polynomials, and ML-DSA-87 is 8, 7, and 8 x 7 = 56 polynomials.
//!
//! A straightforward implementation of ML-DSA will start by un-compressing all the key material into
//! memory into the format that you need to perform the computation.
//! A ready-to-use private key consists of a `Vector<l>` and two `Vector<k>`s,
//! while the public key is a `Vector<k>` and a `Matrix<k,l>`.
//! For ML-DSA-65, you expect to use 53 kb of RAM just for holding expanded key material, and then
//! you expect the `.sign()` operation to require several multiples of that as variables for holding
//! intermediate values as the computation proceeds.
//! A well-written but not memory-optimized ML-DSA-65 can be expected to consume 200 - 250 kb of RAM
//! at the widest point of the `.sign()` operation.
//!
//! This crate strives to do better!
//!
//! The core observation that makes this implementation possible is that by a careful examination of
//! how the matrix multiplication works, you don't ever need the vectors and matrices to be fully
//! expanded at the same time.
//! In fact, you can work one polynomial at a time.
//! This is because the ML-DSA keygen algorithm starts with a single 32-byte seed and expands that
//! into intermediate seeds `rho` (32 byte), `rho_prime`(64 byte), and `K` (32 byte), from which all
//! of the vectors and matrices are derived via hash functions.
//! The public matrix A can be derived in a random-access fashion from `rho` and the matrix index `k,l`.
//! The various vectors cannot, but the polynomial compression algorithm given in FIPS 204 as part of
//! the key encoding procedure can be used to hold the vectors in memory compressed and only un-compress
//! a single polynomial entry at a time.
//! The downside of this approach is that it costs performance: throughout this implementation we are re-deriving
//! bits and pieces of matrices that we had in memory previously, but released.
//!
//! We also get a surprising amount of memory-savings by good coding hygiene:
//! Using un-named scopes to tell the compiler when an intermediate variable is no longer needed and
//! con be popped off the stack. This sometimes requires re-ordering the steps of the algorithms given in
//! FIPS 204 so that variables can be created, used, and released in a self-contained block.
//! Sometimes this is not possible and we have to make a choice between keeping the variable around
//! or releasing it and re-deriving it later.
//! We also attempt to be clean about noting the last time a long-lived variable is used and
//! re-using / re-naming / moving it to a new purpose rather than allocating an additional variable.
//! These hygiene points can always be further improved with increasingly aggressive design choices.
//! We feel that we have hit the point of diminishing returns that maintains an acceptable balance
//! of memory footprint, performance, and code readability, but we welcome pull requests if, for example,
//! we've missed a polynomial that doesn't need to be created.
//!
//! All this combined, we achieve an approximate *1/10 the memory footprint* at a cost of approximately *3x
//! the runtime for signing and no appreciable difference for keygen and verification*,
//! compared with our un-optimized implementation in the \[bouncycastle_mldsa] crate.
//! We are extremely happy with!
//!
//! # Performance and size numbers
//! Below, find performance charts relative to the standard ML-DSA implementation in the \[bouncycastle_mldsa] crate.
//!
//! ## Keys sizes in memory and on disk
//! This implementation greatly reduces the size of keys both on disk and in memory
//! by only handling the matrices and vectors either as seeds or in their compressed representation
//! expanding on-demand as part of a sign or verify operation rather than storing them in memory as part of a keygen or key load.
//!
//! | Key Object | PK size on disk | PK size in memory | SK Size on disk | SK size in memory |
//! |------------|-----------------|-------------------|-----------------|-------------------|
//! | ML-DSA-44  | 1312 (1312)     | 1312 (4128)       | 32 (2560) | 192 (12416) |
//! | ML-DSA-65  | 1952 (1952)     | 1952 (6176)       | 32 (4032) | 192 (17536) |
//! | ML-DSA-87  | 2592 (2592)     | 2592 (8224)       | 32 (4896) | 192 (23680) |
//!
//! All values are in bytes.
//! Values in parentheses are the usual sizes in our un-optimized implementation in the \[bouncycastle_mldsa] crate.
//! These are the sizes of the data objects, not necessarily the physical size of stack memory usage.
//!
//!
//! ## Algorithm performance and peak memory usage
//! The table below shows the performance and peak memory usage of the ML-DSA algorithms.
//! Values in parentheses are the comparison values from the un-optimized implementation in the \[bouncycastle_mldsa] crate.
//! Size numbers were collected with valgrind using a simple main program that calls only the measured function.
//! Performance throughput numbers were collected on my laptop using the library's provided benchmarks, so
//! performance throughput numbers should be taken with an extreme grain of salt.
//!
//! Actual values may vary based on build configuration.
//!
//! | Algorithm | Peak memory usage (kB) | Throughput (ops/s) |
//! |-----------|-----------------------|-------------------|
//! | MLDSA44_lowmemory/KeyGen  | 12.9 (77.9)    | 8100 (8700) |
//! | MLDSA65_lowmemory/KeyGen  | 14.8 (156.9)   | 4900 (5400) |
//! | MLDSA87_lowmemory/KeyGen  | 16.1 (270.7)   | 2900 (3400) |
//! | MLDSA44_lowmemory/Sign    | 25.5 (135.3)   | 630 (1400) |
//! | MLDSA65_lowmemory/Sign    | 29.8 (227.6)   | 370 (960) |
//! | MLDSA87_lowmemory/Sign    | 32.8 (362.0)   | 250 (730) |
//! | MLDSA44_lowmemory/Verify  | 15.8 (68.9)    | 7500 (9000) |
//! | MLDSA65_lowmemory/Verify  | 19.0 (115.7)   | 4500 (5700) |
//! | MLDSA87_lowmemory/Verify  | 20.6 (237.2)   | 2700 (3600) |
//!
//! Values in parentheses are the usual sizes in our un-optimized implementation in the \[bouncycastle_mldsa] crate.
//!
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

// todo -- need to tag the all the vec's with the alloc feature
// #![no_std]

#![forbid(missing_docs)]

#![forbid(unsafe_code)]
#![allow(incomplete_features)] // needed because currently generic_const_exprs is experimental
#![feature(generic_const_exprs)]
#![feature(int_roundings)]
#![feature(inherent_associated_types)]
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

pub mod mldsa;
pub mod hash_mldsa;
mod mldsa_keys;
mod polynomial;
mod aux_functions;
mod low_memory_helpers;
/*** Exported types ***/
pub use mldsa::{MLDSATrait, MLDSA, MLDSA44, MLDSA65, MLDSA87};
pub use hash_mldsa::{HashMLDSA44_with_SHA256, HashMLDSA65_with_SHA256, HashMLDSA87_with_SHA256};
pub use hash_mldsa::{HashMLDSA44_with_SHA512, HashMLDSA65_with_SHA512, HashMLDSA87_with_SHA512};
pub use mldsa_keys::{MLDSAPrivateKeyTrait, MLDSAPublicKeyTrait};
pub use mldsa_keys::{MLDSAPublicKey, MLDSA44PublicKey, MLDSA65PublicKey, MLDSA87PublicKey};
pub use mldsa_keys::{MLDSASeedPrivateKey, MLDSA44PrivateKey, MLDSA65PrivateKey, MLDSA87PrivateKey};
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
