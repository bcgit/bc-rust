//! ECC CDH, the Elliptic Curve Cryptography Cofactor Diffie-Hellman primitive of SP 800-56A
//! Rev. 3 Section 5.7.1.2, over seven curves, built on [`bouncycastle_ec`]'s arithmetic, SEC 1
//! encodings and constant-time multipliers, written once over [`bouncycastle_ec::curve::Curve`].
//! The algorithm is [`ECCDH<C>`](eccdh::ECCDH) for a curve marker `C` from [`bouncycastle_ec`],
//! with a key pair of its own, generated from the marker through
//! [`AgreementKeyPair`](keys_common::AgreementKeyPair) (`P256::generate_agreement_key_pair(&mut
//! rng)`) or [`keys::keygen`]; the private key agrees through the `core` role
//! trait [`AgreementKey`](bouncycastle_core::agreement_key::AgreementKey), which hands out a
//! reusable [`KeyAgreement`](bouncycastle_core::traits::KeyAgreement) worker, and the shared
//! secret `Z` comes back as [`KeyMaterial`](bouncycastle_core::key_material::KeyMaterial) typed
//! [`KeyType::SharedSecret`](bouncycastle_core::key_material::KeyType::SharedSecret): keying
//! material for a KDF (Section 5.8), which nothing else accepts as a key. The raw primitive is
//! the role impl over `()`. The same keys also run a KDF over `Z`, through
//! [`KdfParams`](bouncycastle_core::kdf_params::KdfParams) naming a borrowed description of the
//! KDF (readable, for a key that hands the derivation to a device) and the fixed info: SEC 1 Section 6.1's ECDH scheme, the ANSI X9.63 KDF over the hash matched to
//! the curve ([`ECCDH_X963KDF`](eccdh::ECCDH_X963KDF), `ECC-CDH-P256-X963KDF-SHA256` and so
//! on), SP 800-56A Rev. 3 Section 5.8's one-step derivation, the NIST concatenation KDF over the
//! same hash ([`ECCDH_ConcatKDF`](eccdh::ECCDH_ConcatKDF)), and on P-256 HKDF-SHA256
//! ([`ECCDH_HKDF_SHA256`](eccdh::ECCDH_HKDF_SHA256)); the pairing trait is in [`kdf`].
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
//! use bouncycastle_ec::P256;
//! use bouncycastle_eccdh::keys_common::AgreementKeyPair;
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let (pk_a, sk_a) = P256::generate_agreement_key_pair(&mut rng)?;
//! let (pk_b, sk_b) = P256::generate_agreement_key_pair(&mut rng)?;
//!
//! let z_a = sk_a.agree(&pk_b, ())?;
//! let z_b = sk_b.create_agreement(())?.agree(&pk_a)?;
//! assert!(z_a.equals(&z_b));
//! assert_eq!(z_a.key_type(), KeyType::SharedSecret);
//! # Ok::<(), bouncycastle_core::errors::KeyAgreementError>(())
//! ```
//!
//! `Z` is not a key. Pass it through a KDF: the P-256 keys do that for you over
//! `KdfParams<HkdfDescription<SHA256>, LEN>`, and any curve's `Z` goes into HKDF by hand:
//!
//! ```
//! use bouncycastle_core::agreement_key::AgreementKey;
//! use bouncycastle_core::kdf_params::{KdfParams, KeyLen};
//! use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
//! use bouncycastle_ec::P256;
//! use bouncycastle_eccdh::keys_common::AgreementKeyPair;
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_hkdf::HkdfDescription;
//! use bouncycastle_sha2::SHA256;
//! use bouncycastle_sha2::hkdf::HKDF_SHA256;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let (pk_a, sk_a) = P256::generate_agreement_key_pair(&mut rng)?;
//! let (pk_b, sk_b) = P256::generate_agreement_key_pair(&mut rng)?;
//!
//! // ECC-CDH-P256-HKDF-SHA256: the KDF type on the parameters selects it, the KeyLen the length.
//! let salt = KeyMaterial::<32>::from_rng(&mut rng)?;
//! let hkdf = HkdfDescription::<SHA256>::with_salt(&salt).unwrap();
//! let params = KdfParams::new(&hkdf, b"example protocol v1", KeyLen::<32>);
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
//! use bouncycastle_ec::P256;
//! use bouncycastle_eccdh::keys::{ECCDHPublicKey, keygen};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let (pk, _sk) = keygen::<P256>(&mut HashDRBG_SHA512::new_from_os())?;
//! let mut off_curve = pk.encode();
//! off_curve[64] ^= 1;
//! assert!(matches!(
//!     ECCDHPublicKey::<P256>::from_bytes(&off_curve),
//!     Err(KeyAgreementError::DecodingError(_))
//! ));
//! # Ok::<(), bouncycastle_core::errors::KeyAgreementError>(())
//! ```
//!
//! Every type is generic over the curve, a marker from [`bouncycastle_ec`] (`P256`, `P384`,
//! `P521`, `Secp256K1`, `Bp256r1`, `Bp384r1`, `Bp512r1`): the algorithm is
//! [`ECCDH<C>`](eccdh::ECCDH), the keys [`ECCDHPublicKey<C>`](keys::ECCDHPublicKey) and
//! [`ECCDHPrivateKey<C>`](keys::ECCDHPrivateKey), and code written once over `C: Curve` serves
//! all seven.
//!
//! # Status
//!
//! Seven curves: P-256, P-384, P-521, secp256k1, brainpoolP256r1, brainpoolP384r1 and
//! brainpoolP512r1, each with cofactor 1. SP 800-56A Rev. 3 approves the NIST curves for key
//! agreement (Appendix D); secp256k1 and the brainpool curves are not in that list, so its
//! procedures are applied to them by analogy, as SP 800-186 Appendix H allows the brainpool
//! curves "for interoperability reasons" and secp256k1 "for blockchain-related applications".
//! Every curve carries the X9.63 KDF and the
//! concatenation KDF variants over the hash matched to its strength (SHA-256, SHA-384 or
//! SHA-512), and P-256 the HKDF-SHA256 one; the raw
//! `Z` is there for any other KDF. Not here: the
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
//! Peak stack usage of each operation, in bytes, as the deepest frame chain below the
//! `mem_usage_benches` harness's `measure` wrapper (the sum of the frames on the deepest path
//! through the crate's own symbols, plus a return address per hop, from the compiler's
//! frame-layout remarks and the release binary's call graph; rustc 1.97.0-nightly, x86-64).
//! `agree` is dominated by the variable-base multiplier's per-call table of sixteen Jacobian
//! points; `keygen`'s figure excludes the caller's RNG, which it reaches through `dyn RNG`:
//!
//! | Curve           | keygen | agree |
//! |-----------------|--------|-------|
//! | P-256           | 2,600  | 4,216 |
//! | P-384           | 2,232  | 5,736 |
//! | P-521           | 5,352  | 8,520 |
//! | secp256k1       | 2,424  | 4,056 |
//! | brainpoolP256r1 | 2,712  | 4,312 |
//! | brainpoolP384r1 | 2,528  | 5,712 |
//! | brainpoolP512r1 | 4,672  | 7,600 |
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
//! - **Everything done with `d` and `Z` is branch-free and does not index memory by its value,
//!   in optimised builds**: the variable-base multiplication `[d]Q`, the affine conversion of
//!   `x_P`, the encoding and the private key's range check (debug builds also run
//!   [`bouncycastle_ec`]'s debug assertions, which can short-circuit on a carry). Four decisions
//!   depend on secret data, each on a condition that is public or that no valid input reaches:
//!   Section 5.7.1.2 step 2's identity test, made after the intermediates are scrubbed and false
//!   for every validated peer key and in-range `d`; the typing of an all-zero `Z` (`x_P = 0`, on
//!   the curve for P-256, P-384 and P-521 only, and not arrangeable without `d`; the buffer
//!   decides it, and skips the test while the caller's hazardous window is open); the one masked
//!   decision of the private key's range check, which reveals whether the key loaded; and
//!   `to_affine`'s identity branch at key generation and in `derive_pk`, false for every valid
//!   `d`. Of Section 5.7.1.2 step 4's destruction of intermediates, this crate does its own
//!   part: `P`, `z`, the inverse of `P`'s `Z` coordinate and its square, and the byte string are
//!   zeroized on every path, and `Z` is written into the caller's buffer. What is not reached:
//!   a value a one-shot returns (`agree`'s `Z` or derived key, `keygen`'s private key, the key
//!   `from_bytes` decodes) is moved out of the frame that built it, and a move does not wipe its
//!   source, so use the `_out` forms into a buffer you own where that matters -- agreement and
//!   the paired derivations have one, a private key has none, so key generation and decoding
//!   leave `d` where the move staged it; the KDF's hash finalises by value
//!   ([`Hash::do_final_out`](bouncycastle_core::traits::Hash::do_final_out) takes `self`), so
//!   the hasher's block buffer, which held `Z`, is moved and its source is not wiped, on the
//!   `_out` path too; and the arithmetic's intermediates in [`bouncycastle_ec`] (the
//!   multiplier's superseded accumulators, table and a limb of the scalar in its frames, the
//!   inversion's table of powers) are that crate's and are not reached, as its docs say. Key
//!   generation draws at least `len(n) + 64` bits, rounded up to a byte, and reduces them in
//!   constant time (Section 5.6.1.2.1), writing each step into a `Secret`.

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

pub mod eccdh;
pub mod kdf;
pub mod keys;
pub mod keys_common;
