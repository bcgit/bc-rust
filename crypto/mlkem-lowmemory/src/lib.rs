//! This crate implements the Module Lattice Key-Encapsulation Mechanism (ML-KEM) as per FIPS 203.
//!
//! # Philosophy of a low-memory implementation
//!
//! First, a little primer on the objects that make up an ML-KEM key pair.
//! The "elements" of the lattice are polynomials of degree 256, represented in memory as
//! arrays of 256 i16's. That's 512 bytes per polynomial.
//! Then we build vectors and matrices composed of these polynomials.
//! ML-KEM is parametrized as ML-KEM-k where k in {2, 3, 4} is the size of the vectors, and the matrices
//! have size k x k.
//! So ML-KEM-512 carries vectors of 2 polynomials and matrices of 2 x 2 = 4 polynomials.
//! ML-KEM-768 is 3 and 3 x 3 = 9 polynomials, and ML-KEM-1024 is 4, and 4 x 4 = 16 polynomials.
//!
//! A straightforward implementation of ML-KEM will start by un-compressing all the key material into
//! memory into the format that you need to perform the computation.
//! A ready-to-use private key consists of a `Vector<k>`
//! while the public key is a `Vector<k>` and a `Matrix<k,k>`.
//! For ML-KEM-768, you expect to use 6 kb of RAM just for holding expanded key material, and then
//! you expect the `.encaps()` and `.decaps()` operations to require several multiples of that as variables for holding
//! intermediate values as the computation proceeds.
//! A well-written but not memory-optimized ML-KEM-768 can be expected to consume approximately 40 kb of RAM
//! at the widest point of the `.decaps()` operation.
//!
//! This crate strives to do better!
//!
//! The core observation that makes this implementation possible is that by a careful examination of
//! how the matrix multiplication works, you don't ever need the vectors and matrices to be fully
//! expanded at the same time.
//! In fact, you can work one polynomial at a time.
//! This is because the ML-KEM keygen algorithm starts with a single 64-byte seed and expands that
//! into intermediate seeds `rho` (32 byte), and `sigma` (32 byte), from which all
//! of the vectors and matrices are derived via hash functions.
//! The public matrix A can be derived in a random-access fashion from `rho` and the matrix index `i,j`.
//! The various vectors cannot, but the polynomial compression algorithm given in FIPS 203 as part of
//! the key encoding procedure can be used to hold the vectors in memory compressed and only un-compress
//! a single polynomial entry at a time.
//! The downside of this approach is that it costs performance: throughout this implementation we are re-deriving
//! bits and pieces of matrices that we had in memory previously, but released.
//!
//! We also get a surprising amount of memory-savings by good coding hygiene:
//! Using un-named scopes to tell the compiler when an intermediate variable is no longer needed and
//! con be popped off the stack. This sometimes requires re-ordering the steps of the algorithms given in
//! FIPS 203 so that variables can be created, used, and released in a self-contained block.
//! Sometimes this is not possible and we have to make a choice between keeping the variable around
//! or releasing it and re-deriving it later.
//! We also attempt to be clean about noting the last time a long-lived variable is used and
//! re-using / re-naming / moving it to a new purpose rather than allocating an additional variable.
//! These hygiene points can always be further improved with increasingly aggressive design choices.
//! We feel that we have hit the point of diminishing returns that maintains an acceptable balance
//! of memory footprint, performance, and code readability, but we welcome pull requests if, for example,
//! we've missed a polynomial that doesn't need to be created.
//!
//! All this combined, we achieve an approximate *1/3 the memory footprint* at a cost of approximately *3x
//! the runtime for decapsulating and no appreciable difference for encapsulation*,
//! compared with our un-optimized implementation in the \[bouncycastle_mlkem] crate, which we are extremely happy with!
//!
//! # Memory Footprint
//!
//! Below, find performance charts relative to the standard ML-KEM implementation in the \[bouncycastle_mlkem] crate.
//!
//! ## Keys sizes in memory and on disk
//!
//! This implementation greatly reduces the size of keys both on disk and in memory
//! by only handling the matrices and vectors either as seeds or in their compressed representation
//! expanding on-demand as part of a sign or verify operation rather than storing them in memory as part of a keygen or key load.
//!
//! | Key Object | PK size on disk | PK size in memory | SK Size on disk | SK size in memory |
//! |------------|-----------------|-------------------|-----------------|-------------------|
//! | ML-KEM-512  | 800 (800)      | 800 (1056)        | 32 (1632)       | 161 (2178) |
//! | ML-KEM-768  | 1184 (1184)    | 1184 (1568)       | 32 (2400)       | 161 (3202) |
//! | ML-KEM-1024 | 1568 (1568)    | 1568 (2080)       | 32 (3168)       | 161 (4226) |
//!
//! All values are in bytes. The "in memory" sizes are measured by rust's `std::mem::size_of`.
//! Values in parentheses are the usual sizes in our un-optimized implementation in the \[bouncycastle_mldsa] crate.
//!
//!
//! ## Algorithm Peak Memory Usage
//!
//! The table below shows peak memory usage of the ML-KEM algorithms and the rough performanc (throughput) impact.
//!
//! Measuring peak application memory usage can be a bit tricky, and the numbers you get depend heavily on how you designed your
//! measurement harness. Here, we aim to provide a conservative measurement, meaning that we are aiming for an
//! over-estimate so that any deployment within an existing application will use incrementally less additional memory
//! than the amount stated here.
//!
//! Our measurement methodology is to compile a simple standalone HelloWorld application that only calls the function under test
//! with as minimal as possible hard-coded data (such as keys or ciphertexts) and measure the peak memory usage of running
//! the compiled binary using `valgrind --tool=massif --heap=no --stack=yes`. The flags for heap and stack
//! reflect the fact that this is a `no_std` rust application and therefore the cryptographic functions use no heap memory.
//! The measurements may over-estimate by as much as 3 kb since that that's the measured peak memory usage of a do-nothing
//! HelloWorld rust application.
//!
//! | Algorithm                  | Peak stack memory usage (kB) | Throughput (Kops/s) |
//! |----------------------------|------------------------|-------------------|
//! | MLKEM512_lowmemory/KeyGen  | 5.8 (21.7)             | 50.1 (48.7) |
//! | MLKEM512_lowmemory/KeyGen  | 7.3 (28.9)             | 28.3 (28.8) |
//! | MLKEM1024_lowmemory/KeyGen | 9.3 (41.4)             | 16.9 (18.1) |
//! | MLKEM512_lowmemory/Encaps  | 8.9 (18.8)             | 37.8 (43.7) |
//! | MLKEM768_lowmemory/Encaps  | 9.9 (27.9)             | 22.3 (26.0) |
//! | MLKEM1024_lowmemory/Encaps | 11.2 (44.2)            | 14.2 (15.6) |
//! | MLKEM512_lowmemory/Decaps  | 13.6 (25.7)            | 13.4 (31.6) |
//! | MLKEM768_lowmemory/Decaps  | 16.6 (40.6)            | 7.8 (21.0) |
//! | MLKEM1024_lowmemory/Decaps | 20.5 (58.4)            | 4.9 (13.6) |
//!
//! Values in parentheses are the comparison values from the un-optimized implementation in the \[bouncycastle_mldsa] crate.
//! Size numbers were collected with valgrind using a simple main program that calls only the measured function.
//! Performance throughput numbers were collected on my laptop using the library's provided benchmarks, so
//! performance they should be taken with an extreme grain of salt.
//!
//! Actual values may vary based on build configuration and target architecture.
//!
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
//! * `ML-KEM.keygen_internal(seed: \[u8; 64])`, sometimes written as `ML-KEM.keygen_internal(d: \[u8; 32], z: \[u8; 32])`
//! * `ML-KEM.encaps_internal(pk, m: \[u8; 32])`
//!
//!
//!
//! ## Generating Keys
//!
//! ```rust
//! use bouncycastle_mlkem_lowmemory::MLKEM768;
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
//! use bouncycastle_mlkem_lowmemory::{MLKEM768, MLKEMTrait};
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
//! use bouncycastle_mlkem_lowmemory::{MLKEM768, MLKEMTrait};
//! use bouncycastle_core::traits::{KEMEncapsulator, KEMDecapsulator};
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

mod aux_functions;
mod low_memory_helpers;
pub mod mlkem;
mod mlkem_keys;
mod polynomial;

/*** Exported types ***/
pub use mlkem::{MLKEM, MLKEM512, MLKEM768, MLKEM1024, MLKEMTrait};
pub use mlkem_keys::{
    MLKEM512PrivateKey, MLKEM768PrivateKey, MLKEM1024PrivateKey, MLKEMSeedPrivateKey,
};
pub use mlkem_keys::{MLKEM512PublicKey, MLKEM768PublicKey, MLKEM1024PublicKey, MLKEMPublicKey};
pub use mlkem_keys::{MLKEMPrivateKeyTrait, MLKEMPublicKeyTrait};

/*** Exported constants ***/
pub use mlkem::ML_KEM_512_NAME;
pub use mlkem::ML_KEM_768_NAME;
pub use mlkem::ML_KEM_1024_NAME;

pub use mlkem::{MLKEM_RND_LEN, MLKEM_SEED_LEN, MLKEM_SS_LEN};

pub use mlkem::{MLKEM512_CT_LEN, MLKEM512_PK_LEN, MLKEM512_SK_LEN};
pub use mlkem::{MLKEM768_CT_LEN, MLKEM768_PK_LEN, MLKEM768_SK_LEN};
pub use mlkem::{MLKEM1024_CT_LEN, MLKEM1024_PK_LEN, MLKEM1024_SK_LEN};

// re-export just so it's visible to unit tests
pub use polynomial::Polynomial;
