//! This crate implements the Module Lattice Key-Encapsulation Mechanism (ML-KEM) as per FIPS 203.
//!
//! # Usage Examples
//!
//! This crate has been designed to serve a wide range of use cases, from people dabbling in
//! cryptography for the first time, to cryptographic protocol designers who need access to the internal
//! functionality of the ML-KEM algorithm, to embedded systems developers who want access to memory
//! and performance optimized functions.
//!
//! This page gives examples of simple usage for generating keys and performing encapsulation and decapsulation operations.
//!
//! More examples on advanced usage can be found on the [`mlkem`] page.
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
//! * `ML-KEM.keygen_internal(seed)` requires a seed either written as `seed: [u8;64]` sometimes decomposed into `(d: [u8;32], z: [u8;32])`.
//! * `ML-KEM.encaps_internal(pk, m)` requires a random message `m: [u8;32]`.
//!
//! Using these functions without sufficiently random values for `seed` and `m` is ill-advised.
//!
//!
//! ## Generating Keys
//!
//! ```rust
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_mlkem::{MLKEM768, MLKEMTrait};
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
//! See [`MLKEM`] and [`MLKEM::decaps_from_seed`] for an API that uses a merged
//! keygen-and-decaps function that allows the private key to be stored only as a 64-byte seed.
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
//! use bouncycastle_mlkem::{MLKEM768, MLKEMTrait};
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
//! salt (`bouncycastle_hkdf::HkdfDescription`; key material of any length but
//! [`KeyType::Unknown`](bouncycastle_core::key_material::KeyType::Unknown), a zero-length one
//! being the absent salt), and the info. The description is readable, so a key that cannot run
//! the derivation itself, one held in a token, can hand it on; a software key builds the HKDF
//! from it. The KDF type on the parameters selects the algorithm, and each parameter set is
//! paired with one HKDF, so the wrong one is a compile error.
//!
//! ```rust
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_mlkem::{KdfParams, KeyLen, MLKEM512, MLKEMTrait};
//! use bouncycastle_core::kem_key::{EncapsulatingKey, DecapsulatingKey};
//! use bouncycastle_core::key_material::KeyMaterial;
//! use bouncycastle_hkdf::HkdfDescription;
//! use bouncycastle_sha2::SHA256;
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
//! # Memory Usage
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
//!
//! Peak stack usage of each operation, measured with `mem_usage_benches/bench_mlkem_mem_usage` under
//! `valgrind --tool=massif --stacks=yes` (release build, one call on a fixed key, unexpanded keys):
//!
//! | Operation | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 |
//! |-----------|------------|------------|-------------|
//! | KeyGen    | 13,960 | 20,520 | 30,152 |
//! | Encaps    | 16,424 | 27,256 | 38,840 |
//! | Decaps    | 20,920 | 33,560 | 47,240 |
//!
//! Values are in bytes and include the harness's own frames (about 3 KB).
//!
//! # 🚨 Security Considerations 🚨
//!
//! Everything at the crate root is considered secure to use. The one
//! [hazmat](bouncycastle_core::hazmat) item is [`hazmat::EncapsWithRandomness`], which takes the
//! encapsulation randomness from the caller, so the ciphertext is only as strong as the randomness
//! provided. Beyond that, the obvious points about handling your private keys properly apply: if
//! you post your private key to github, or you generate production keys from a weak seed, that use
//! is unsupported. If using [`MLKEM::keygen_from_seed`], it is your responsibility to ensure that
//! the seed is cryptographically random and unpredictable.
//!
//! A note about cryptographic side-channel attacks: considerable effort has been expended to attempt
//! to make this implementation constant-time, which generally means that the core mathematical algorithm
//! code that handles secret data uses bitshift-and-xor type constructions instead of if-and-loop
//! constructions. That should give this implementation reasonably good resistance to timing and
//! power analysis key extraction attacks, however: A) this is a "best-effort" and not formally verified,
//! and B) the Rust compiler does not guarantee constant-time behaviour no matter how clever your code,
//! so like all Safe Rust code (ie Rust code that does not include inline assembly), the Rust compiler's optimizer
//! determines whether the bitshift-and-xor code actually remains
//! constant-time after compilation.

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]
// These are because variable names are matched exactly against FIPS 203, for example both 'K' and 'k',
// or 'A' and 'a' are used and have specific meanings.
// But need to tell the rust linter to not care.
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
// so private traits can hide internal items that need to be generic within the
// MLKEM implementation, but should not be accessed from outside, such as FIPS-internal functions.
#![allow(private_bounds)]

// imports needed just for docs
#[allow(unused_imports)]
use bouncycastle_core::key_material::KeyMaterialTrait;

mod aux_functions;
pub mod hazmat;
mod matrix;
pub mod mlkem;
mod mlkem_kdf;
mod mlkem_keys;
mod params;

/*** Exported types ***/
pub use bouncycastle_core::kdf_params::{KdfParams, KeyLen};
#[doc(inline)]
pub use bouncycastle_mlkem_common::kdf::{
    ML_KEM_512_HKDF_SHA256_NAME, ML_KEM_768_HKDF_SHA512_NAME, ML_KEM_1024_HKDF_SHA512_NAME,
};
#[doc(inline)]
pub use bouncycastle_mlkem_common::kdf::{
    MLKEM512_HKDF_SHA256, MLKEM768_HKDF_SHA512, MLKEM1024_HKDF_SHA512, MLKEMKdfPairing,
};
#[doc(inline)]
pub use bouncycastle_mlkem_common::kdf::{
    MLKEM512_HKDF_SHA256_SS_LEN, MLKEM768_HKDF_SHA512_SS_LEN, MLKEM1024_HKDF_SHA512_SS_LEN,
};
pub use mlkem::{MLKEM, MLKEM512, MLKEM768, MLKEM1024, MLKEMTrait};
pub use mlkem::{MLKEMDecapsulator, MLKEMEncapsulator};
pub use mlkem_kdf::{MLKEMKdfDecapsulator, MLKEMKdfEncapsulator};
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
pub use params::{CiphertextLen, PrivateKeyLen, PublicKeyLen};

/*** Exported constants ***/
pub use mlkem::ML_KEM_512_NAME;
pub use mlkem::ML_KEM_768_NAME;
pub use mlkem::ML_KEM_1024_NAME;

pub use mlkem::{MLKEM_RND_LEN, MLKEM_SEED_LEN, MLKEM_SS_LEN};
pub use mlkem::{MLKEM512_CT_LEN, MLKEM512_PK_LEN, MLKEM512_SK_LEN};
pub use mlkem::{MLKEM768_CT_LEN, MLKEM768_PK_LEN, MLKEM768_SK_LEN};
pub use mlkem::{MLKEM1024_CT_LEN, MLKEM1024_PK_LEN, MLKEM1024_SK_LEN};
