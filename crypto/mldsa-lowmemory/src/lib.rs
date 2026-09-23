//! This crate implements the Module Lattice Digital Signature Algorithm (ML-DSA) as per FIPS 204 optimized
//! to have the lowest-reasonable runtime memory footprint (aka peak memory usage).
//!
//! We achieve an approximate **1/10 the memory footprint** at a cost of approximately **3x
//! the runtime for signing and no appreciable difference for keygen and verification**,
//! compared with our un-optimized implementation in the \[bouncycastle_mldsa] crate.
//! We are extremely happy with the result!
//!
//! # Philosophy of a low-memory implementation
//!
//! First, a little primer on the objects that make up an ML-DSA key pair.
//! The "elements" of the lattice are polynomials of degree 256, represented in memory as
//! arrays of 256 i32's. That's 1 kb per polynomial.
//! Then the vectors and matrices composed of these polynomials are built.
//! ML-DSA is parametrized as ML-DSA-k,l where k and l are the sizes of the vectors, and the matrices
//! have size k x l.
//! So ML-DSA-44 carries vectors of 4 polynomials and matrices of 4 x 4 = 16 polynomials.
//! ML-DSA-65 is 6, 5 and 6 x 5 = 30 polynomials, and ML-DSA-87 is 8, 7, and 8 x 7 = 56 polynomials.
//!
//! A straightforward implementation of ML-DSA will start by un-compressing all the key material into
//! memory, into the format that is needed to perform the computation.
//! A ready-to-use private key consists of a `Vector<l>` and two `Vector<k>`s,
//! while the public key is a `Vector<k>` and a `Matrix<k,l>`.
//! For ML-DSA-65, it is expected to use 53 kb of RAM just for holding expanded key material, and then
//! it is expected `.sign()` operation to require several multiples of that as variables for holding
//! intermediate values as the computation proceeds.
//! A well-written but not memory-optimized ML-DSA-65 can be expected to consume approximately 150 kb of RAM
//! at the widest point of the `.sign()` operation.
//!
//! This crate strives to do better!
//!
//! The core observation that makes this implementation possible is that, by a careful examination of
//! how the matrix multiplication works, the vectors and matrices never need to be fully
//! expanded at the same time.
//! In fact, it is possible to work one polynomial at a time.
//! This is because the ML-DSA keygen algorithm starts with a single 32-byte seed and expands that
//! into intermediate seeds `rho` (32 byte), `rho_prime`(64 byte), and `K` (32 byte), from which all
//! of the vectors and matrices are derived via hash functions.
//! The public matrix A can be derived in a random-access fashion from `rho` and the matrix index `i,j`.
//! The various vectors cannot, but the polynomial compression algorithm given in FIPS 204 as part of
//! the key encoding procedure can be used to hold the vectors in memory compressed and only un-compress
//! a single polynomial entry at a time.
//! The downside of this approach is that it costs performance:
//! throughout this implementation, bits and pieces of matrices, that previously would be in memory, are
//! instead being re-derived, used, and released.
//!
//! Furthermore, a surprising amount of memory-savings are achieved by simply following good coding hygiene:
//! Using un-named scopes to tell the compiler when an intermediate variable is no longer needed and
//! can be popped off the stack. This sometimes requires re-ordering the steps of the algorithms given in
//! FIPS 204 so that variables can be created, used, and released in a self-contained block.
//! Sometimes this is not possible, it is necessary to make a choice between keeping the variable around
//! or releasing it and re-deriving it later.
//! We also attempt to be clean about noting the last time a long-lived variable is used and
//! re-using / re-naming / moving it to a new purpose rather than allocating an additional variable.
//! These hygiene points can always be further improved with increasingly aggressive design choices.
//! The authors feel that the trade-offs have hit the point of diminishing returns, maintaining an acceptable balance
//! of memory footprint, performance, and code readability. That being said, we welcome pull requests if, for example,
//! we've missed a polynomial that doesn't need to be created has been missed and could be eliminated.
//!
//! All this combined, the implementations achieves an approximate *1/10 the memory footprint* at a cost of approximately *3x
//! the runtime for signing and no appreciable difference for keygen and verification*,
//! compared with our un-optimized implementation in the \[bouncycastle_mldsa] crate, which we are extremely happy with!
//!
//! # Memory Footprint
//!
//! Below, find performance charts relative to the standard ML-DSA implementation in the \[bouncycastle_mldsa] crate.
//!
//! ## Keys sizes in memory and on disk
//!
//! This implementation greatly reduces the size of keys both on disk and in memory
//! by only handling the matrices and vectors either as seeds or in their compressed representation
//! expanding on-demand as part of a sign or verify operation rather than storing them in memory as part of a keygen or key load.
//!
//! | Key Object | PK size on disk | PK size in memory | SK Size on disk | SK size in memory |
//! |------------|-----------------|-------------------|-----------------|-------------------|
//! | ML-DSA-44  | 1312 (1312)     | 1312 (4128)       | 32 (2560)       | 176 (12464)       |
//! | ML-DSA-65  | 1952 (1952)     | 1952 (6176)       | 32 (4032)       | 176 (17584)       |
//! | ML-DSA-87  | 2592 (2592)     | 2592 (8224)       | 32 (4896)       | 176 (23728)       |
//!
//! All values are in bytes. The "in memory" sizes are measured by rust's `std::mem::size_of`.
//! Values in parentheses are the usual sizes in our un-optimized implementation in the \[bouncycastle_mldsa] crate.
//!
//!
//! ## Algorithm Peak Memory Usage
//!
//! The table below shows peak memory usage of the ML-DSA algorithms and the rough performanc (throughput) impact.
//!
//! | Algorithm                 | Peak stack memory usage (kB) | Throughput (ops/s)  |
//! |---------------------------|-----------------------------|---------------------|
//! | MLDSA44_lowmemory/KeyGen  | 12.3 (62.3)                 | 11,700     (11,400) |
//! | MLDSA65_lowmemory/KeyGen  | 14.8 (93.9)                 | 6,800      (7,000)  |
//! | MLDSA87_lowmemory/KeyGen  | 16.8 (141.4)                | 3,900      (4,200)  |
//! | MLDSA44_lowmemory/Sign    | 22.3 (86.5)                 | 990        (3,400)  |
//! | MLDSA65_lowmemory/Sign    | 27.9 (128.0)                | 490        (2,400)  |
//! | MLDSA87_lowmemory/Sign    | 31.6 (187.3)                | 330        (1,700)  |
//! | MLDSA44_lowmemory/Verify  | 15.2 (56.4)                 | 11,200     (13,200) |
//! | MLDSA65_lowmemory/Verify  | 19.1 (86.2)                 | 6,400      (8,000)  |
//! | MLDSA87_lowmemory/Verify  | 22.3 (130.0)                | 3,700      (4,800)  |
//!
//! Values in parentheses are the comparison values from the un-optimized implementation in the \[bouncycastle_mldsa] crate.
//!
//! **Caveates**
//!
//! Throughput numbers are meant to show relative difference between the two implementations and not be
//! absolute performance measurements.
//!
//! Size numbers were collected with valgrind using a simple main program that calls only the measured function.
//! Measurements include the public key and signature buffer, which is a realistic setting, but
//! numbers would be lower if those were on the heap and excluded from the measurement.
//! Actual values may vary based on build configuration and target architecture.
//! The peak also depends on how the compiler lays out the measured function's stack frame relative
//! to its caller and whether it elides copies at the call boundary, which is outside
//! the library's control.
//! This effect is small for the low-memory crates (well under 1 kB) and larger for the full implementations
//! in parentheses (a few kB), so treat the latter as approximate.
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
//! More examples on advanced usage can be found on the [`mldsa`] and [`hash_mldsa`] pages.
//!
//! ## Generating Keys
//!
//! ```rust
//! use bouncycastle_mldsa_lowmemory::{MLDSA65, MLDSATrait};
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
//! use bouncycastle_hex as hex;
//! use bouncycastle_mldsa_lowmemory::{MLDSA65, MLDSATrait};
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
//! use bouncycastle_core::errors::SignatureError;
//! use bouncycastle_core::traits::{Signer, SignatureVerifier};
//! use bouncycastle_mldsa_lowmemory::{MLDSA65, MLDSATrait};
//!
//! let msg = b"The quick brown fox";
//!
//! let (pk, sk) = MLDSA65::keygen().unwrap();
//!
//! let sig = MLDSA65::sign(&sk, msg, None).unwrap();
//! // This is the signature value that can be saved to a file or whatever it is need.
//!
//! match MLDSA65::verify(&pk, msg, None, &sig) {
//!     Ok(()) => println!("Signature is valid!"),
//!     Err(SignatureError::SignatureVerificationFailed) => println!("Signature is invalid!"),
//!     Err(e) => panic!("Something else went wrong: {:?}", e),
//! }
//!
//! ```
//! And that's the basic usage! There are lots more bells-and-whistles in the form of exposed algorithm
//! parameters, streaming APIs and other goodies that can be found by poking around this documentation.
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
// These are because the code matching variable names exactly against FIPS 204, for example both 'K' and 'k',
// or 'A' and 'a' are used and have specific meanings.
// But need to tell the rust linter to not care.
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
// so that private traits can be used to hide internal stuff that needs to be generic within the
// MLDSA implementation, but should not get accessed from outside, such as FIPS-internal functions.
#![allow(private_bounds)]

// imports needed just for docs
#[allow(unused_imports)]
use bouncycastle_core::key_material::KeyMaterialTrait;
#[allow(unused_imports)]
use bouncycastle_core::traits::{SignatureVerifier, Signer};

mod aux_functions;
pub mod hash_mldsa;
mod low_memory_helpers;
pub mod mldsa;
mod mldsa_keys;
mod params;
mod polynomial;

/*** Exported types ***/
pub use hash_mldsa::{HashMLDSA44_with_SHA256, HashMLDSA65_with_SHA256, HashMLDSA87_with_SHA256};
pub use hash_mldsa::{HashMLDSA44_with_SHA512, HashMLDSA65_with_SHA512, HashMLDSA87_with_SHA512};
pub use mldsa::MuBuilder;
pub use mldsa::{MLDSA, MLDSA44, MLDSA65, MLDSA87, MLDSATrait};
pub use mldsa_keys::{
    MLDSA44PrivateKey, MLDSA65PrivateKey, MLDSA87PrivateKey, MLDSASeedPrivateKey,
};
pub use mldsa_keys::{MLDSA44PublicKey, MLDSA65PublicKey, MLDSA87PublicKey, MLDSAPublicKey};
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

pub use mldsa::{MLDSA_MU_LEN, MLDSA_RND_LEN, MLDSA_TR_LEN};
pub use mldsa::{MLDSA44_PK_LEN, MLDSA44_SIG_LEN, MLDSA44_SK_LEN};
pub use mldsa::{MLDSA65_PK_LEN, MLDSA65_SIG_LEN, MLDSA65_SK_LEN};
pub use mldsa::{MLDSA87_PK_LEN, MLDSA87_SIG_LEN, MLDSA87_SK_LEN};

pub use mldsa::SUSPENDED_MU_BUILDER_STATE_LEN;
