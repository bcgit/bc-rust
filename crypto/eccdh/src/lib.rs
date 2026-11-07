//! ECC CDH, the Elliptic Curve Cryptography Cofactor Diffie-Hellman primitive of SP 800-56A
//! Rev. 3 Section 5.7.1.2, over seven curves, built on [`bouncycastle_ec`]'s arithmetic, SEC 1
//! encodings and constant-time multipliers. Each curve has one algorithm marker (`ECCDHP256`,
//! `ECCDHP384`, ...) and a key pair of its own; the private key agrees through the `core` role
//! trait [`AgreementKey`](bouncycastle_core::agreement_key::AgreementKey), which hands out a
//! reusable [`KeyAgreement`](bouncycastle_core::traits::KeyAgreement) worker, and the shared
//! secret `Z` comes back as [`KeyMaterial`](bouncycastle_core::key_material::KeyMaterial) typed
//! [`KeyType::SharedSecret`](bouncycastle_core::key_material::KeyType::SharedSecret): keying
//! material for a KDF (Section 5.8), which nothing else accepts as a key. The raw primitive is
//! the role impl over `()`; on P-256 the same keys also run `ECCDHP256_HKDF_SHA256` over
//! [`HkdfParams<'p, SHA256>`](bouncycastle_hkdf::HkdfParams), `Z` derived through HKDF-SHA256.
//!
//! # Usage Examples
//!
//! Each party generates a pair, sends its public key, and agrees with the other's. The one-shot
//! `agree` and a worker from `create_agreement` compute the same `Z`; a static key keeps its
//! worker and uses it against every peer:
//!
//! ```
//! use bouncycastle_core::agreement_key::AgreementKey;
//! use bouncycastle_core::key_material::{KeyMaterialTrait, KeyType};
//! use bouncycastle_core::traits::KeyAgreement;
//! use bouncycastle_eccdh::keys_p256::keygen;
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let (pk_a, sk_a) = keygen(&mut rng)?;
//! let (pk_b, sk_b) = keygen(&mut rng)?;
//!
//! let z_a = sk_a.agree(&pk_b, ())?;
//! let z_b = sk_b.create_agreement(())?.agree(&pk_a)?;
//! assert!(z_a.equals(&z_b));
//! assert_eq!(z_a.key_type(), KeyType::SharedSecret);
//! # Ok::<(), bouncycastle_core::errors::KeyAgreementError>(())
//! ```
//!
//! `Z` is not a key. Pass it through a KDF: the P-256 keys do that for you over
//! `HkdfParams<SHA256>`, and any curve's `Z` goes into HKDF by hand:
//!
//! ```
//! use bouncycastle_core::agreement_key::AgreementKey;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
//! use bouncycastle_eccdh::keys_p256::keygen;
//! use bouncycastle_hkdf::HkdfParams;
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_sha2::SHA256;
//! use bouncycastle_sha2::hkdf::HKDF_SHA256;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let (pk_a, sk_a) = keygen(&mut rng)?;
//! let (pk_b, sk_b) = keygen(&mut rng)?;
//!
//! // ECC-CDH-P256-HKDF-SHA256: the hash on the parameter type selects it.
//! let salt = KeyMaterial::<32>::from_rng(&mut rng)?;
//! let params = HkdfParams::<SHA256>::new(&salt, b"example protocol v1");
//! let key_a = sk_a.agree(&pk_b, params)?;
//! let key_b = sk_b.agree(&pk_a, params)?;
//! assert!(key_a.equals(&key_b));
//! assert_eq!(key_a.key_type(), KeyType::CryptographicRandom);
//!
//! // The same derivation by hand from the raw Z.
//! let z = sk_a.agree(&pk_b, ())?;
//! let mut okm = KeyMaterial::<32>::new();
//! HKDF_SHA256::extract_and_expand_out(&salt, &z, b"example protocol v1", 32, &mut okm).unwrap();
//! assert!(okm.equals(&key_a));
//! # Ok::<(), bouncycastle_core::errors::KeyAgreementError>(())
//! ```
//!
//! A peer key is validated when it is decoded (SP 800-56A Rev. 3 Section 5.6.2.3.3), so a point
//! off the curve never reaches an agreement:
//!
//! ```
//! use bouncycastle_core::errors::KeyAgreementError;
//! use bouncycastle_core::traits::KeyAgreementPublicKey;
//! use bouncycastle_eccdh::keys_p256::{ECCDHP256PublicKey, keygen};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let (pk, _sk) = keygen(&mut HashDRBG_SHA512::new_from_os())?;
//! let mut off_curve = pk.encode();
//! off_curve[64] ^= 1;
//! assert!(matches!(
//!     ECCDHP256PublicKey::from_bytes(&off_curve),
//!     Err(KeyAgreementError::DecodingError(_))
//! ));
//! # Ok::<(), bouncycastle_core::errors::KeyAgreementError>(())
//! ```
//!
//! The other curves have the same shape under their own modules: `eccdh_p384`/`keys_p384`,
//! `eccdh_p521`/`keys_p521`, `eccdh_p256k1`/`keys_p256k1`, `eccdh_bp256r1`/`keys_bp256r1`,
//! `eccdh_bp384r1`/`keys_bp384r1`, `eccdh_bp512r1`/`keys_bp512r1`.
//!
//! # Status
//!
//! Seven curves: P-256, P-384, P-521, secp256k1, brainpoolP256r1, brainpoolP384r1 and
//! brainpoolP512r1, each with cofactor 1. The KDF step is on the P-256 keys as
//! ECC-CDH-P256-HKDF-SHA256; the other curves return `Z` for the caller's KDF. Not here: the
//! key-agreement schemes of SP 800-56A Rev. 3 Section 6 and key confirmation, ECC MQV
//! (Section 5.7.2.3), X25519/X448 (another curve form), and SM2 key exchange.
//!
//! # Memory Usage
//!
//! The on-disk encoding and in-memory struct size of each curve's key objects, the latter by
//! `core::mem::size_of` (the key types wrap the same `bouncycastle_ec` scalar and field elements
//! as the ECDSA ones):
//!
//! | Key Object               | PK size on disk | PK size in memory | SK size on disk | SK size in memory |
//! |--------------------------|-----------------|-------------------|-----------------|-------------------|
//! | ECC CDH P-256            | 65              | 64                | 32              | 32                |
//! | ECC CDH P-384            | 97              | 96                | 48              | 48                |
//! | ECC CDH P-521            | 133             | 144               | 66              | 72                |
//! | ECC CDH secp256k1        | 65              | 64                | 32              | 32                |
//! | ECC CDH brainpoolP256r1  | 65              | 64                | 32              | 32                |
//! | ECC CDH brainpoolP384r1  | 97              | 96                | 48              | 48                |
//! | ECC CDH brainpoolP512r1  | 129             | 128               | 64              | 64                |
//!
//! Peak stack usage of key generation and agreement per curve is measured by `mem_usage_benches`'
//! `bench_eccdh_mem_usage` harness under `valgrind --tool=massif --stacks=yes`; see its docs.
//!
//! # 🚨 Security Considerations 🚨
//!
//! - **`Z` goes to a KDF and nowhere else** (SP 800-56A Rev. 3 Section 5.8): it is typed
//!   `SharedSecret`, which the library's KDFs credit and its ciphers and MACs refuse. It is the
//!   x-coordinate of a point, not uniformly distributed, and must not be used as a key.
//! - **A key pair is for key agreement only.** Section 5.6.3.2 item 5: one static key pair is not
//!   used for different purposes, so these types are distinct from the ECDSA ones even though the
//!   encodings coincide. Do not load a signing key's bytes as an agreement key.
//! - **An ephemeral private key is used in exactly one transaction** and dropped (Section
//!   5.6.3.3 item 1); the types do not enforce that. A static key's worker may be reused: it
//!   holds nothing but the key.
//! - **The peer key is fully validated at decode** (Section 5.6.2.3.3 steps 1 to 3); step 4 is
//!   not computed because every curve here has cofactor 1, so a point on the curve other than the
//!   identity has order n. Full validation is what static keys require (Section 5.6.2.2.1), and
//!   it is applied to every key, ephemeral or not.
//! - **Everything done with `d` is branch-free and does not index memory by its value**: the
//!   variable-base multiplication `[d]Q`, the affine conversion of `x_P` and the encoding, with
//!   the intermediates zeroized as Section 5.7.1.2 step 4 asks. The one branch is Section
//!   5.7.1.2 step 2's test for the identity, which no validated peer key and in-range `d` can
//!   reach. Key generation draws `len(n) + 64` bits and reduces them in constant time (Section
//!   5.6.1.2.1).

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

pub mod eccdh_bp256r1;
pub mod eccdh_bp384r1;
pub mod eccdh_bp512r1;
pub mod eccdh_p256;
pub mod eccdh_p256k1;
pub mod eccdh_p384;
pub mod eccdh_p521;
pub mod keys_bp256r1;
pub mod keys_bp384r1;
pub mod keys_bp512r1;
pub mod keys_common;
pub mod keys_p256;
pub mod keys_p256k1;
pub mod keys_p384;
pub mod keys_p521;
