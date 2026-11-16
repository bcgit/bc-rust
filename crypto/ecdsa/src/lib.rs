//! ECDSA over seven curves and any hash: key generation (FIPS 186-5 Appendix A.2.1), signature
//! generation (Section 6.4.1) and verification (Section 6.4.2), written once over
//! [`bouncycastle_ec::curve::Curve`] and [`EcdsaHash`](ecdsa::EcdsaHash), which every SHA-2 and
//! SHA-3 hash implements. The algorithm is
//! [`ECDSA<C, H>`](ecdsa::ECDSA) for a curve marker `C` from [`bouncycastle_ec`] and a hash `H`,
//! named `ECDSA-P256-SHA256` and so on, at the lesser of the curve's and the hash's strength;
//! the keys [`ECDSAPublicKey<C, H>`](keys::ECDSAPublicKey) and
//! [`ECDSAPrivateKey<C, H>`](keys::ECDSAPrivateKey) name their pairing in full, with no default
//! hash, since the customary pairing (SHA-256 for the 256-bit curves, SHA-384 for the 384-bit
//! ones, SHA-512 for P-521 and brainpoolP512r1) is a convention that moves; the aliases
//! [`ECDSAP256`](ecdsa::ECDSAP256) and siblings spell today's. A pair is
//! generated from the curve's marker through [`SignatureKeyPair`](keys_common::SignatureKeyPair)
//! (`P256::generate_signature_key_pair::<SHA256>(&mut rng)`) or [`keys::keygen`]; both take the
//! hash spelled out. The private key signs
//! through the `core` key role traits, [`SigningKey`](bouncycastle_core::signature_key::SigningKey)
//! with a random per-message `k` (Section 6.3.1, Appendix A.3.1) and
//! [`DeterministicSigningKey`](bouncycastle_core::signature_key::DeterministicSigningKey) with
//! `k` derived from the private key and the message hash (Section 6.3.2, Appendix A.3.3, RFC
//! 6979), and the public key verifies through
//! [`VerifyingKey`](bouncycastle_core::signature_key::VerifyingKey). Since the choice of `k`
//! "does not impact the signature verification process" (FIPS 186-5 Section 6), one verifier
//! serves both, and the RFC 6979 signer reports its own name (`ECDetDSA-P256-SHA256`) from
//! `alg_name()`. Raw `r || s` is the signature encoding; [`der`] offers DER `SEQUENCE { r, s }`
//! (RFC 3279 Section 2.2.3) as an alternative for interop that needs it.
//!
//! # Usage Examples
//!
//! The key pair comes from the curve and the hash: `P256` with `SHA256` gives ECDSA-P256-SHA256
//! keys. `sign` draws a fresh `k` from the RNG it is given, so two signatures of one message
//! differ; `sign_deterministic` takes no RNG and reproduces the same signature every time:
//!
//! ```
//! use bouncycastle_core::signature_key::{DeterministicSigningKey, SigningKey, VerifyingKey};
//! use bouncycastle_ec::P256;
//! use bouncycastle_ecdsa::keys_common::SignatureKeyPair;
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_sha2::SHA256;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let (pk, sk) = P256::generate_signature_key_pair::<SHA256>(&mut rng)?;
//! let message = b"the message to sign";
//!
//! // ECDSA has no context string; the traits' `ctx` parameter is accepted and ignored.
//! let random = sk.sign(&mut rng, message, None)?;
//! assert_ne!(random, sk.sign(&mut rng, message, None)?, "a fresh k each time");
//!
//! let deterministic = sk.sign_deterministic(message, None)?;
//! assert_eq!(deterministic, sk.sign_deterministic(message, None)?, "RFC 6979");
//!
//! // One verifier for both.
//! pk.verify(message, None, &random)?;
//! pk.verify(message, None, &deterministic)?;
//! assert!(pk.verify(b"a different message", None, &random).is_err());
//! # Ok::<(), bouncycastle_core::errors::SignatureError>(())
//! ```
//!
//! Streaming, for a message you do not want to hold in memory at once. The random `k` is drawn
//! when the signer is created, so the worker itself only hashes:
//!
//! ```
//! use bouncycastle_core::signature_key::{DeterministicSigningKey, SigningKey, VerifyingKey};
//! use bouncycastle_core::traits::{AlgorithmInfo, SignatureSigner, SignatureVerifier};
//! use bouncycastle_ec::P256;
//! use bouncycastle_ecdsa::keys_common::SignatureKeyPair;
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_sha2::SHA256;
//!
//! let (pk, sk) = P256::generate_signature_key_pair::<SHA256>(&mut HashDRBG_SHA512::new_from_os())?;
//!
//! let mut signer = sk.create_signer(&mut HashDRBG_SHA512::new_from_os(), None)?;
//! assert_eq!(signer.alg_name(), "ECDSA-P256-SHA256");
//! signer.do_update(b"the first chunk, ");
//! signer.do_update(b"then the second");
//! let signature = signer.do_final()?;
//!
//! let mut verifier = pk.create_verifier(None)?;
//! verifier.do_update(b"the first chunk, then the second");
//! verifier.do_verify_final(&signature)?;
//!
//! let mut signer = sk.create_signer_deterministic(None)?;
//! assert_eq!(signer.alg_name(), "ECDetDSA-P256-SHA256");
//! signer.do_update(b"the first chunk, then the second");
//! pk.verify(b"the first chunk, then the second", None, &signer.do_final()?)?;
//! # Ok::<(), bouncycastle_core::errors::SignatureError>(())
//! ```
//!
//! Another hash is another pairing of the same key bytes: the key types carry it, so a key is
//! re-paired with [`with_hash`](keys::ECDSAPrivateKey::with_hash) or decoded under the pairing
//! wanted, and `sign` and `verify` resolve without naming the algorithm. The strength reported
//! is the lesser of the curve's and the hash's; FIPS 186-5 Section 6.4.1 asks the hash's to be
//! at least the key pair's when signing:
//!
//! ```
//! use bouncycastle_core::signature_key::{SigningKey, VerifyingKey};
//! use bouncycastle_core::traits::{Algorithm, SignaturePublicKey};
//! use bouncycastle_ec::P256;
//! use bouncycastle_ecdsa::ecdsa::ECDSA;
//! use bouncycastle_ecdsa::keys::ECDSAPublicKey;
//! use bouncycastle_ecdsa::keys_common::SignatureKeyPair;
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_sha2::{SHA256, SHA384};
//! use bouncycastle_sha3::SHA3_256;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let (pk, sk) = P256::generate_signature_key_pair::<SHA256>(&mut rng)?;
//!
//! let sk_sha384 = sk.with_hash::<SHA384>();
//! let sig = sk_sha384.sign(&mut rng, b"message", None)?;
//! let pk_sha384 = ECDSAPublicKey::<P256, SHA384>::from_bytes(&pk.encode())?;
//! pk_sha384.verify(b"message", None, &sig)?;
//! assert_eq!(ECDSA::<P256, SHA384>::ALG_NAME, "ECDSA-P256-SHA384");
//! assert_eq!(ECDSA::<P256, SHA3_256>::ALG_NAME, "ECDSA-P256-SHA3-256");
//! # Ok::<(), bouncycastle_core::errors::SignatureError>(())
//! ```
//!
//! Keys encode as SEC 1 octets -- `04 || X || Y` for a public key (the 33-byte compressed form is
//! also accepted on decode), a fixed-width big-endian integer for a private key. Both reject
//! malformed input rather than reinterpreting it:
//!
//! ```
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_sha2::SHA256;
//! use bouncycastle_core::traits::{SignaturePrivateKey, SignaturePublicKey};
//! use bouncycastle_ec::P256;
//! use bouncycastle_ecdsa::keys::{ECDSAPrivateKey, ECDSAPublicKey};
//! use bouncycastle_ecdsa::keys_common::SignatureKeyPair;
//!
//! let (pk, sk) = P256::generate_signature_key_pair::<SHA256>(&mut HashDRBG_SHA512::new_from_os())?;
//!
//! let pk_bytes = pk.encode();
//! assert_eq!(pk_bytes[0], 0x04);
//! assert_eq!(ECDSAPublicKey::<P256, SHA256>::from_bytes(&pk_bytes)?, pk);
//!
//! let sk_bytes = sk.encode();
//! assert_eq!(ECDSAPrivateKey::<P256, SHA256>::from_bytes(&sk_bytes)?, sk);
//!
//! // `d` must be in [1, n-1]: zero, `n`, and anything above it are rejected rather than reduced.
//! assert!(ECDSAPrivateKey::<P256, SHA256>::from_bytes(&[0u8; 32]).is_err());
//! assert!(ECDSAPrivateKey::<P256, SHA256>::from_bytes(&[0xff; 32]).is_err());
//! # Ok::<(), bouncycastle_core::errors::SignatureError>(())
//! ```
//!
//! For interop that needs DER `SEQUENCE { r, s }` rather than raw `r || s`, [`der`] encodes and
//! decodes it around the role traits:
//!
//! ```
//! use bouncycastle_core::signature_key::{SigningKey, VerifyingKey};
//! use bouncycastle_ec::P256;
//! use bouncycastle_ecdsa::der;
//! use bouncycastle_ecdsa::keys_common::SignatureKeyPair;
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_sha2::SHA256;
//!
//! let (pk, sk) = P256::generate_signature_key_pair::<SHA256>(&mut HashDRBG_SHA512::new_from_os())?;
//! let raw = sk.sign(&mut HashDRBG_SHA512::new_from_os(), b"message", None)?;
//! let mut encoded = [0u8; der::max_len(32)];
//! let len = der::encode(&raw[..32], &raw[32..], &mut encoded);
//!
//! let mut decoded = [0u8; 64];
//! let (r, s) = decoded.split_at_mut(32);
//! der::decode(&encoded[..len], r, s).expect("a well-formed SEQUENCE { r, s }");
//! pk.verify(b"message", None, &decoded)?;
//! # Ok::<(), bouncycastle_core::errors::SignatureError>(())
//! ```
//!
//! # Status
//!
//! Seven curves, P-256, P-384, P-521, secp256k1, brainpoolP256r1, brainpoolP384r1 and
//! brainpoolP512r1, under any hash that implements [`EcdsaHash`](ecdsa::EcdsaHash):
//! the SHA-2 family, SHA-3 and SM3; the SHAKE pairings of FIPS 186-5 (an XOF in place of the
//! hash) are not implemented. The conventional pairing of each curve has an alias and is what the
//! CLI offers. Tested against the CAVP SigGen and SigVer sets for P-256, P-384 and P-521 under
//! SHA-224, SHA-256, SHA-384 and SHA-512, RFC 6979's Appendix A.2.5 to A.2.7 under the same
//! hashes, and the Wycheproof files for every curve and hash here, SHA-3 included. SM2 is a
//! different signature algorithm rather than another ECDSA curve, and lives in
//! [`bouncycastle_sm2`](../bouncycastle_sm2/index.html).
//!
//! # Memory Footprint
//!
//! The following table lists the size of the on-disk bytes encoding and the in-memory struct size
//! of each curve's key objects:
//!
//! | Key Object            | PK size on disk | PK size in memory | SK size on disk | SK size in memory |
//! |------------------------|-----------------|--------------------|------------------|--------------------|
//! | ECDSA P-256            | 65              | 64                 | 32               | 32                 |
//! | ECDSA P-384            | 97              | 96                 | 48               | 48                 |
//! | ECDSA P-521            | 133             | 144                | 66               | 72                 |
//! | ECDSA secp256k1        | 65              | 64                 | 32               | 32                 |
//! | ECDSA brainpoolP256r1  | 65              | 64                 | 32               | 32                 |
//! | ECDSA brainpoolP384r1  | 97              | 96                 | 48               | 48                 |
//! | ECDSA brainpoolP512r1  | 129             | 128                | 64               | 64                 |
//!
//! All values are in bytes. The "in memory" sizes are measured by rust's `std::mem::size_of`; the
//! "on disk" sizes are the curve's `PK_UNCOMPRESSED_LEN`/`SCALAR_LEN`. P-521's odd numbers come from its 521-bit
//! (not byte-aligned) field: a coordinate needs 66 bytes on disk (`ceil(521/8)`) but a `P521FieldElement`
//! is stored in 9 `u64` limbs (72 bytes) rather than a tighter packing. These numbers are produced
//! by `mem_usage_benches`' `bench_ecdsa_mem_usage` binary's `print_struct_sizes()`; that binary is
//! also the stack-usage measurement harness (see its own doc comment for the `valgrind`/`massif`
//! invocation).
//!
//! # 🚨 Security Considerations 🚨
//!
//! - **Everything done with the private key `d` and the accepted per-message secret `k` is
//! branch-free and does not index memory by their value**: inversion, multiplication, the
//! fixed-base scalar multiplication `[k]G`. `d` lives in
//! [`bouncycastle_ec::hazmat::p256_scalar::P256Scalar`] (a [`bouncycastle_utils::secret::Secret`]);
//! see [`bouncycastle_ec`]'s own module docs for the constant-time discipline this crate builds on
//! and the exceptions it documents. This crate adds two exceptions of its own:
//!   - The RFC 6979 candidate loop of the deterministic signers runs a data-dependent number of
//!     iterations (the random-`k` signers draw `k` per FIPS 186-5 Appendix A.3.1, which has no
//!     rejection loop). On the NIST curves
//!     and secp256k1 a candidate is rejected with negligible probability; on the brainpool curves
//!     33 % to 45 % of signatures reject at least one. Under the PRF assumption the count is
//!     independent of the accepted `k` and reveals nothing about `d`, but it is deterministic per
//!     `(d, message)`, so a remote observer gets a per-message timing fingerprint. See
//!     `rfc6979_p256::generate_k`'s docs for the argument, the brainpool modules' for the rates, and
//!     `rfc6979_bp256r1::generate_k`'s for what the fingerprint is worth.
//!   - On `r = 0` or `s = 0`, FIPS 186-5 §6.4.1 step 11 has the random-`k` signer draw another
//!     `k` and the deterministic one output failure (RFC 6979 §3.4 would continue its loop
//!     instead). Both signers here report failure: the random `k` is drawn when the signer is
//!     created and there is no RNG at `do_final` to draw another from, so the caller makes a fresh
//!     signer. Either branch is on a public outcome, taken with probability about `2^-(len(n)-1)`.
//! - **`k` must never repeat across two signatures under the same key with different messages.**
//!   A repeated `k` leaks `d` directly from two signatures' `(r, s)` pairs (elementary algebra on
//!   the ECDSA equation). The random-`k` signer therefore depends on the RNG handed to
//!   `create_signer` / `sign` being correctly seeded for every signature. The deterministic signer
//!   removes that dependency: `k` is a function of `d` and the message hash, so the same
//!   `(d, message)` pair always regenerates the same `k` and distinct messages give distinct `k`
//!   (FIPS 186-5 §6.3.2: "This protects against attacks arising from generating signatures with
//!   insufficient randomness in the per-message secret number").
//! - **Deterministic signatures are a fault-attack target** (FIPS 186-5 §6, first paragraph): an
//!   attacker who can induce a computational fault and observe the faulty signature may be able to
//!   recover `d`, because a deterministic scheme will reproduce the exact same `k` on a retry. This
//!   is a property of determinism itself, not a defect in this implementation; see FIPS 186-5's
//!   references \[17\]-\[22\] for mitigations at the deployment level (e.g. verifying a signature
//!   in-device before releasing it). Where that attacker is in the threat model and the RNG is
//!   trusted, the random-`k` signer (`SigningKey`) is the one to use.
//! - **The hash is the caller's choice, and FIPS 186-5 constrains it.** Section 6.4.1's input 3
//!   asks the hash's security strength to be at least the key pair's when signing; `ECDSA<C, H>`
//!   accepts any pairing and reports the lesser of the two strengths, so that a signature made
//!   with a weaker hash can be verified and so that the choice is visible, not refused. Signing
//!   below the curve's strength (P-384 with SHA-256, say) is outside FIPS 186-5.
//! - **`ctx` is accepted but ignored.** ECDSA (FIPS 186-5, SEC 1) has no context-string input;
//!   the key traits' `ctx` parameter is accepted for trait conformance and silently discarded. A
//!   caller relying on `ctx` to bind a signature to an application context gets no such binding
//!   from ECDSA.

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

pub mod der;
pub mod ecdsa;
pub mod keys;
pub mod keys_common;
pub(crate) mod rfc6979;
