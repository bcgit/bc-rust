//! This module implements the Module Lattice Key-Encapsulation Mechanism (ML-KEM) as per FIPS 203.
//!
//! # Philosophy of a low-memory implementation
//!
//! First, a little primer on the objects that make up an ML-KEM key pair.
//! The "elements" of the lattice are polynomials of degree 256, represented in memory as
//! arrays of 256 i16's. That's 512 bytes per polynomial.
//! Vectors and matrices are built from these polynomials.
//! ML-KEM is parametrized as ML-KEM-k where k in {2, 3, 4} is the size of the vectors, and the matrices
//! have size k x k.
//! So ML-KEM-512 carries vectors of 2 polynomials and matrices of 2 x 2 = 4 polynomials.
//! ML-KEM-768 is 3 and 3 x 3 = 9 polynomials, and ML-KEM-1024 is 4, and 4 x 4 = 16 polynomials.
//!
//! A straightforward implementation of ML-KEM will start by un-compressing all the key material into
//! memory into the format needed to perform the computation.
//! A ready-to-use private key consists of a `Vector<k>`
//! while the public key is a `Vector<k>` and a `Matrix<k,k>`.
//! For ML-KEM-768, it is expected to use 6 kb of RAM just for holding expanded key material, and then
//! the `.encaps()` and `.decaps()` operations are expected to require several multiples of that as variables for holding
//! intermediate values as the computation proceeds.
//! A well-written but not memory-optimized ML-KEM-768 consumes over 20 kb of stack at the widest point of the
//! `.decaps()` operation; the [`pqc::mlkem`](crate::mlkem) module's figure is in the table below.
//!
//! This module does better.
//!
//! The core observation that makes this implementation possible is that by a careful examination of
//! how the matrix multiplication works, the vectors and matrices don't ever need to be fully
//! expanded at the same time.
//! In fact, it is possible to work one polynomial at a time.
//! This is because the ML-KEM keygen algorithm starts with a single 64-byte seed and expands that
//! into intermediate seeds `rho` (32 byte), and `sigma` (32 byte), from which all
//! of the vectors and matrices are derived via hash functions.
//! The public matrix A can be derived in a random-access fashion from `rho` and the matrix index `i,j`.
//! The various vectors cannot, but the polynomial compression algorithm given in FIPS 203 as part of
//! the key encoding procedure can be used to hold the vectors in memory compressed and only un-compress
//! a single polynomial entry at a time.
//! The downside of this approach is that it costs performance: throughout this implementation, pieces of
//! matrices that were in memory earlier and released are re-derived.
//!
//! A surprising amount of the saving comes from coding hygiene:
//! un-named scopes tell the compiler when an intermediate variable is no longer needed and
//! can be popped off the stack. This sometimes requires re-ordering the steps of the algorithms given in
//! FIPS 203 so that variables can be created, used, and released in a self-contained block.
//! Where that is not possible, the choice is between keeping the variable and releasing it to
//! re-derive it later. The last use of a long-lived variable is noted and the variable is
//! re-used, renamed or moved to a new purpose rather than a new one being allocated.
//! These points can always be pushed further; this module stops at what keeps an acceptable balance
//! of memory footprint, performance and readability. Pull requests are welcome if, for example,
//! a polynomial that does not need to exist has been missed.
//!
//! All this combined gives roughly a half to five sixths of the peak stack of the un-optimized implementation
//! in the [`pqc::mlkem`](crate::mlkem) module for encapsulation and decapsulation, at a cost in throughput that is largest
//! for decapsulation; the table below has both.
//!
//! # Memory Usage
//!
//! Below are the figures relative to the standard ML-KEM implementation in the [`pqc::mlkem`](crate::mlkem) module.
//!
//! ## Keys sizes in memory and on disk
//!
//! This implementation greatly reduces the size of keys both on disk and in memory
//! by only handling the matrices and vectors either as seeds or in their compressed representation
//! expanding on demand as part of an encapsulation or decapsulation rather than storing them in memory as part of a keygen or key load.
//!
//! | Key Object | PK size on disk | PK size in memory | SK Size on disk | SK size in memory |
//! |------------|-----------------|-------------------|-----------------|-------------------|
//! | ML-KEM-512  | 800 (800)      | 800 (1056)        | 64 (1632)       | 160 (2178) |
//! | ML-KEM-768  | 1184 (1184)    | 1184 (1568)       | 64 (2400)       | 160 (3202) |
//! | ML-KEM-1024 | 1568 (1568)    | 1568 (2080)       | 64 (3168)       | 160 (4226) |
//!
//! All values are in bytes. The "in memory" sizes are measured by rust's `std::mem::size_of`.
//! Values in parentheses are the sizes in the un-optimized implementation in the [`pqc::mlkem`](crate::mlkem) module.
//! The private key is the 64-byte seed on disk and, in memory, the seed with 𝜌, 𝜎 and H(ek) alongside.
//! [`MLKEMSeedPrivateKeyExpanded`] adds the packed 𝐭̂ (384𝑘 bytes: 928 / 1312 / 1696 in
//! memory) and in exchange decapsulates without the key generation a seed key runs each time; its
//! encoding on disk is the same 64-byte seed.
//!
//! ## Algorithm Peak Memory Usage
//!
//! The table below shows peak memory usage of the ML-KEM algorithms and the rough performance (throughput) impact.
//!
//! Measuring peak application memory usage can be a bit tricky, and the numbers that are obtained depend heavily on how the
//! measurement harness is designed. The figures here are conservative, meaning an over-estimate, so that
//! a deployment within an existing application uses incrementally less additional memory than stated.
//!
//! The measurement compiles a simple standalone HelloWorld application that only calls the function under test
//! with as minimal as possible hard-coded data (such as keys or ciphertexts) and measure the peak memory usage of running
//! the compiled binary using `valgrind --tool=massif --heap=no --stacks=yes`. The flags for heap and stack
//! reflect the fact that this is a `no_std` rust application and therefore the cryptographic functions use no heap memory.
//! The measurement has a floor of 7.7 kB: a do-nothing HelloWorld rust application in the same harness
//! (`bench_do_nothing`) peaks at 7,680 bytes, reached in process start-up before `main` runs, so no row can read
//! lower, and the two KeyGen rows that read 7.7 are at that floor. The Encaps and Decaps rows are the operation
//! alone, on a key the caller already holds.
//!
//! | Algorithm                  | Peak stack memory (kB) | Throughput (Kops/s) |
//! |----------------------------|------------------------|-------------------|
//! | MLKEM512_lowmemory/KeyGen  | 9.6 (21.6)             | 39.8 (40.3)       |
//! | MLKEM768_lowmemory/KeyGen  | 11.5 (29.5)            | 24.5 (31.2)       |
//! | MLKEM1024_lowmemory/KeyGen | 13.4 (39.0)            | 13.9 (15.7)       |
//! | MLKEM512_lowmemory/KeyGen, `keygen_out`  | 7.7 (11.5) |                   |
//! | MLKEM768_lowmemory/KeyGen, `keygen_out`  | 7.7 (16.0) |                   |
//! | MLKEM1024_lowmemory/KeyGen, `keygen_out` | 8.4 (21.5) |                   |
//! | MLKEM512_lowmemory/Encaps  | 8.9 (13.6)             | 35.8 (48.8)       |
//! | MLKEM768_lowmemory/Encaps  | 9.9 (19.7)             | 21.1 (28.8)       |
//! | MLKEM1024_lowmemory/Encaps | 11.3 (26.8)            | 14.4 (19.7)       |
//! | MLKEM512_lowmemory/Decaps  | 11.1 (12.8)            | 19.2 (37.4)       |
//! | MLKEM768_lowmemory/Decaps  | 12.5 (18.3)            | 10.8 (28.6)       |
//! | MLKEM1024_lowmemory/Decaps | 14.3 (25.0)            | 7.1 (20.4)        |
//! | MLKEM512_lowmemory/KdfEncaps  | 10.8 (14.9)         |                   |
//! | MLKEM768_lowmemory/KdfEncaps  | 12.7 (21.7)         |                   |
//! | MLKEM1024_lowmemory/KdfEncaps | 15.0 (28.7)         |                   |
//! | MLKEM512_lowmemory/KdfDecaps  | 11.2 (13.3)         |                   |
//! | MLKEM768_lowmemory/KdfDecaps  | 13.7 (18.6)         |                   |
//! | MLKEM1024_lowmemory/KdfDecaps | 15.0 (25.2)         |                   |
//!
//! The Kdf rows derive a 32-byte key through [`MLKEM512_HKDF_SHA256`] and a 64-byte one through
//! [`MLKEM768_HKDF_SHA512`] and [`MLKEM1024_HKDF_SHA512`]; they have no throughput figure.
//!
//! Values in parentheses are the comparison values from the un-optimized implementation in the [`pqc::mlkem`](crate::mlkem) module.
//! Memory figures were measured with `mem_usage_benches/bench_mlkem_mem_usage` under massif on 2026-11-24;
//! throughput figures come from the modules' criterion benches on 2026-11-24, on a developer desktop
//! shared with other work, where a figure moves by up to 15% between runs.
//! The `keygen_out` rows generate into a key the caller holds, which leaves no copy of it behind.
//! Both KeyGen forms run in a frame of their own and leave the keys in storage the caller holds,
//! the by-value form's result being moved there, so the two compare like with like.
//! Actual values vary with build configuration and target architecture.
//!
//! # Usage Examples
//!
//! This module has been designed to serve a wide range of use cases, from people dabbling in
//! cryptography for the first time, to cryptographic protocol designers who need access to the internal
//! functionality of the ML-KEM algorithm, to embedded systems developers who want access to memory
//! and performance optimized functions.
//!
//! This page gives examples of simple usage for generating keys and performing encapsulation and decapsulation operations.
//!
//! What this module adds beyond the core traits, including the expanded private key for repeated
//! decapsulations, is on the [`mlkem`] page.
//!
//! # Primer on KEM algorithms
//!
//! Since Key-Encapsulation Mechanisms behave differently from the Diffie-Hellman key exchanges that many people are familiar with,
//! here is a brief primer on KEMs.
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
//! * `keygen(rng) -> (pk, sk)`
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
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_pqc::mlkem_lowmemory::{MLKEM768, MLKEMTrait};
//!
//! let (pk, sk) = MLKEM768::keygen(&mut HashDRBG_SHA512::new_from_os()).unwrap();
//! ```
//! That's it. That will use the library's default OS-backend RNG.
//!
//! Commonly with the ML-KEM algorithm, a 64-byte seed is used as the private key, and expanded into
//! a full private key as needed. This is offered through the library's [`KeyMaterialTrait`] object:
//!
//! ```rust
//! use bouncycastle_core::key_material::{KeyMaterial512, KeyType, KeyMaterialTrait};
//! use bouncycastle_pqc::mlkem_lowmemory::{MLKEM768, MLKEMTrait};
//! use bouncycastle_core::hex as hex;
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
//! See [`MLKEM`] and [`MLKEM::decaps_from_seed`] for an API that uses a merged
//! keygen-and-decaps function to that allows to store the private key only as a 64-byte seed.
//!
//! ## Encapsulating and Decapsulating
//!
//! Encapsulation and decapsulation are methods of the keys, through the
//! [`EncapsulatingKey`](bouncycastle_core::kem_key::EncapsulatingKey) and
//! [`DecapsulatingKey`](bouncycastle_core::kem_key::DecapsulatingKey) roles. Each takes the
//! caller's RNG and the parameters the algorithm is made from, which for ML-KEM are none: `()`.
//!
//! ```rust
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_pqc::mlkem_lowmemory::{MLKEM768, MLKEMTrait};
//! use bouncycastle_core::kem_key::{EncapsulatingKey, DecapsulatingKey};
//! use bouncycastle_core::errors::KEMError;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let (pk, sk) = MLKEM768::keygen(&mut rng).unwrap();
//!
//! // Create the shared secret and ciphertext using the public key
//! let (ss, ct) = pk.encaps(&mut rng, ()).unwrap();
//!
//! // Recover the shared secret using the private key
//! let ss1 = match sk.decaps(&ct, ()) {
//!     Err(KEMError) => panic!("Error decapsulating"),
//!     Ok(ss) => ss,
//! };
//!
//! assert_eq!(ss, ss1);
//! ```
//! And that's the basic usage! A key that will be used many times hands out a worker once
//! instead, `pk.create_encapsulator(())?` or `sk.create_decapsulator(())?`, which the
//! [`KEMEncapsulator`](bouncycastle_core::traits::KEMEncapsulator) and
//! [`KEMDecapsulator`](bouncycastle_core::traits::KEMDecapsulator) traits describe.
//!
//! ## Deriving the shared secret through HKDF
//!
//! The same keys run ML-KEM-512-HKDF-SHA256, ML-KEM-768-HKDF-SHA512 and ML-KEM-1024-HKDF-SHA512
//! ([`MLKEM512_HKDF_SHA256`], [`MLKEM768_HKDF_SHA512`], [`MLKEM1024_HKDF_SHA512`]), whose shared
//! secret is HKDF-Hash(salt, 𝐾, info) over the ML-KEM secret 𝐾, of the length the parameters name. The
//! parameters are a [`KdfParams`]: a borrowed description of the HKDF, its hash and RFC 5869's
//! salt (`bouncycastle_digest::hkdf::HkdfDescription`; key material of any length but
//! [`KeyType::Unknown`](bouncycastle_core::key_material::KeyType::Unknown), a zero-length one
//! being the absent salt), and the info. The description is readable, so a key that cannot run
//! the derivation itself, one held in a token, can hand it on; a software key builds the HKDF
//! from it. The KDF type on the parameters selects the algorithm, and each parameter set is
//! paired with one HKDF, so the wrong one is a compile error.
//!
//! ```rust
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_pqc::mlkem_lowmemory::{KdfParams, KeyLen, MLKEM512, MLKEMTrait};
//! use bouncycastle_core::kem_key::{EncapsulatingKey, DecapsulatingKey};
//! use bouncycastle_core::key_material::KeyMaterial;
//! use bouncycastle_digest::hkdf::HkdfDescription;
//! use bouncycastle_digest::sha2::SHA256;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let (pk, sk) = MLKEM512::keygen(&mut rng).unwrap();
//!
//! // The KDF and info both parties agree on: HKDF-SHA256 with the salt, as a description.
//! let salt = KeyMaterial::<32>::from_rng(&mut rng).unwrap();
//! let hkdf = HkdfDescription::<SHA256>::with_salt(&salt).unwrap();
//! // The parameters name the key's length too: here one SHA-256 output.
//! let params = KdfParams::new(&hkdf, b"example protocol v1", KeyLen::<32>);
//!
//! let (key, ct) = pk.encaps(&mut rng, params).unwrap();
//! let key1 = sk.decaps(&ct, params).unwrap();
//! assert_eq!(key, key1);
//! ```
//!
//! # 🚨 Security Considerations 🚨
//!
//! This module intends to expose only APIs that are secure to use.
//! There are, however, a few exceptions worth mentioning.
//!
//! If using [`MLKEMTrait::keygen_from_seed`], it is the caller's responsibility to ensure that the seed is
//! cryptographically random and unpredictable at a security strength that matches the ML-KEM parameter set.
//!
//! A private key here *is* its 64-byte seed. `PrivateKey::from_bytes` therefore takes any 64 bytes
//! as a seed at the parameter set's strength, with no check possible on where they came from, so an
//! all-zero or otherwise weak file loads as a key; [`MLKEMTrait::keygen_from_seed`] on typed
//! [`KeyMaterial`](bouncycastle_core::key_material::KeyMaterial) is the path that enforces key type
//! and strength.
//!
//! Also, [`hazmat::EncapsWithRandomness`] requires the encapsulation randomness to be provided, so the ciphertext
//! will only be as strong as the randomness that you provide.
//!
//! A note about cryptographic side-channel attacks: considerable effort has been expended to attempt
//! to make this implementation constant-time, which generally means that the core mathematical algorithm
//! code that handles secret data uses bitshift-and-xor type constructions instead of if-and-loop
//! constructions. That should give this implementation reasonably good resistance to timing and
//! power analysis key extraction attacks, however:
//!     A) this is a "best-effort" and not formally verified, and
//!     B) the Rust compiler does not guarantee constant-time behaviour no matter how good the design is,
//! so like all Safe Rust code (ie Rust code that does not include inline assembly),
//! it is up to the Rust compiler's optimizer whether the bitshift-and-xor code actually remains
//! constant-time after compilation.

// These are because variable names need to be matched exactly against FIPS 203,
// for example both 'K' and 'k', or 'A' and 'a' are used and have specific meanings.
// linter needs to be instructed to ignore these cases
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
// This is so that private traits can be used to hide internal components that needs to be generic within the
// MLKEM implementation without providing access from outside, such as FIPS-internal functions.
#![allow(private_bounds)]

// imports needed just for docs
#[allow(unused_imports)]
use bouncycastle_core::key_material::KeyMaterialTrait;

pub mod hazmat;
mod low_memory_helpers;
pub mod mlkem;
mod mlkem_kdf;
mod mlkem_keys;
mod params;

/*** Exported types ***/
#[doc(inline)]
pub use crate::mlkem_common::kdf::MLKEMKdfDecapsulator;
#[doc(inline)]
pub use crate::mlkem_common::kdf::{
    ML_KEM_512_HKDF_SHA256_NAME, ML_KEM_768_HKDF_SHA512_NAME, ML_KEM_1024_HKDF_SHA512_NAME,
};
#[doc(inline)]
pub use crate::mlkem_common::kdf::{
    MLKEM512_HKDF_SHA256, MLKEM768_HKDF_SHA512, MLKEM1024_HKDF_SHA512, MLKEMKdfPairing,
};
#[doc(inline)]
pub use crate::mlkem_common::kdf::{
    MLKEM512_HKDF_SHA256_SS_LEN, MLKEM768_HKDF_SHA512_SS_LEN, MLKEM1024_HKDF_SHA512_SS_LEN,
};
pub use bouncycastle_core::kdf_params::{KdfParams, KeyLen};
pub use mlkem::{MLKEM, MLKEM512, MLKEM768, MLKEM1024, MLKEMTrait};
pub use mlkem::{MLKEMDecapsulator, MLKEMEncapsulator};
pub use mlkem_kdf::MLKEMKdfEncapsulator;
pub use mlkem_keys::{
    MLKEM512PrivateKey, MLKEM768PrivateKey, MLKEM1024PrivateKey, MLKEMSeedPrivateKey,
};
pub use mlkem_keys::{
    MLKEM512PrivateKeyExpanded, MLKEM768PrivateKeyExpanded, MLKEM1024PrivateKeyExpanded,
    MLKEMSeedPrivateKeyExpanded,
};
pub use mlkem_keys::{MLKEM512PublicKey, MLKEM768PublicKey, MLKEM1024PublicKey, MLKEMPublicKey};
pub use mlkem_keys::{MLKEMPrivateKeyTrait, MLKEMPublicKeyTrait};
pub use params::{CiphertextLen, PrivateKeyLen, PublicKeyLen};

/*** Exported constants ***/
pub use mlkem::ML_KEM_512_NAME;
pub use mlkem::ML_KEM_768_NAME;
pub use mlkem::ML_KEM_1024_NAME;

pub use mlkem::{MLKEM_RND_LEN, MLKEM_SEED_LEN, MLKEM_SS_LEN};

pub use mlkem::{MLKEM512_CT_LEN, MLKEM512_PK_LEN, MLKEM512_SK_LEN};
pub use mlkem::{MLKEM768_CT_LEN, MLKEM768_PK_LEN, MLKEM768_SK_LEN};
pub use mlkem::{MLKEM1024_CT_LEN, MLKEM1024_PK_LEN, MLKEM1024_SK_LEN};

/*** Parameter sets ***/
