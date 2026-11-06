//! ECDSA over seven curves: key generation (FIPS 186-5 Appendix A.2.1), signature generation
//! (§6.4.1) and verification (§6.4.2), built on [`bouncycastle_ec`]'s field/scalar/point
//! arithmetic, SEC 1 encodings, and comb/wNAF multipliers. Each curve has one algorithm marker
//! (`ECDSAP256`, `ECDSAP384`, ...) and a key pair; the private key signs through the `core` key
//! role traits, [`SigningKey`](bouncycastle_core::signature_key::SigningKey) with a random
//! per-message `k` (§6.3.1, Appendix A.3.1) and
//! [`DeterministicSigningKey`](bouncycastle_core::signature_key::DeterministicSigningKey) with
//! `k` derived from the private key and the message hash (§6.3.2, Appendix A.3.3, RFC 6979), and
//! the public key verifies through
//! [`VerifyingKey`](bouncycastle_core::signature_key::VerifyingKey). Since the choice of `k`
//! "does not impact the signature verification process" (FIPS 186-5 §6), one verifier serves
//! both, and the RFC 6979 signer reports its own name (`ECDetDSA-P256`) from `alg_name()`. Raw
//! `r || s` is the default signature encoding; [`der`] offers DER `SEQUENCE { r, s }` (RFC 3279
//! §2.2.3) as an alternative for interop that needs it.
//!
//! # Usage Examples
//!
//! `sign` draws a fresh `k` from the RNG it is given, so two signatures of one message differ;
//! `sign_deterministic` takes no RNG and reproduces the same signature every time:
//!
//! ```
//! use bouncycastle_core::signature_key::{DeterministicSigningKey, SigningKey, VerifyingKey};
//! use bouncycastle_ecdsa::keys_p256::keygen;
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let (pk, sk) = keygen(&mut HashDRBG_SHA512::new_from_os())?;
//! let mut rng = HashDRBG_SHA512::new_from_os();
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
//! use bouncycastle_ecdsa::keys_p256::keygen;
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let (pk, sk) = keygen(&mut HashDRBG_SHA512::new_from_os())?;
//!
//! let mut signer = sk.create_signer(&mut HashDRBG_SHA512::new_from_os(), None)?;
//! assert_eq!(signer.alg_name(), "ECDSA-P256");
//! signer.do_update(b"the first chunk, ");
//! signer.do_update(b"then the second");
//! let signature = signer.do_final()?;
//!
//! let mut verifier = pk.create_verifier(None)?;
//! verifier.do_update(b"the first chunk, then the second");
//! verifier.do_verify_final(&signature)?;
//!
//! let mut signer = sk.create_signer_deterministic(None)?;
//! assert_eq!(signer.alg_name(), "ECDetDSA-P256");
//! signer.do_update(b"the first chunk, then the second");
//! pk.verify(b"the first chunk, then the second", None, &signer.do_final()?)?;
//! # Ok::<(), bouncycastle_core::errors::SignatureError>(())
//! ```
//!
//! Keys encode as SEC 1 octets -- `04 || X || Y` for a public key (the 33-byte compressed form is
//! also accepted on decode), a fixed-width big-endian integer for a private key. Both reject
//! malformed input rather than reinterpreting it:
//!
//! ```
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_core::traits::{SignaturePrivateKey, SignaturePublicKey};
//! use bouncycastle_ecdsa::keys_p256::{ECDSAP256PrivateKey, ECDSAP256PublicKey, keygen};
//!
//! let (pk, sk) = keygen(&mut HashDRBG_SHA512::new_from_os())?;
//!
//! let pk_bytes = pk.encode();
//! assert_eq!(pk_bytes[0], 0x04);
//! assert_eq!(ECDSAP256PublicKey::from_bytes(&pk_bytes)?, pk);
//!
//! let sk_bytes = sk.encode();
//! assert_eq!(ECDSAP256PrivateKey::from_bytes(&sk_bytes)?, sk);
//!
//! // `d` must be in [1, n-1]: zero, `n`, and anything above it are rejected rather than reduced.
//! assert!(ECDSAP256PrivateKey::from_bytes(&[0u8; 32]).is_err());
//! assert!(ECDSAP256PrivateKey::from_bytes(&[0xff; 32]).is_err());
//! # Ok::<(), bouncycastle_core::errors::SignatureError>(())
//! ```
//!
//! For interop that needs DER `SEQUENCE { r, s }` rather than raw `r || s`, the keys have
//! `sign_der` / `sign_der_deterministic` and `verify_der`:
//!
//! ```
//! use bouncycastle_ecdsa::keys_p256::keygen;
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let (pk, sk) = keygen(&mut HashDRBG_SHA512::new_from_os())?;
//! let (der, der_len) = sk.sign_der(&mut HashDRBG_SHA512::new_from_os(), b"message", None)?;
//! pk.verify_der(b"message", None, &der[..der_len])?;
//! let (der, der_len) = sk.sign_der_deterministic(b"message", None)?;
//! pk.verify_der(b"message", None, &der[..der_len])?;
//! # Ok::<(), bouncycastle_core::errors::SignatureError>(())
//! ```
//!
//! Every curve follows the same shape, in its own module pair: `ecdsa_p256`/`keys_p256`,
//! `ecdsa_p384`/`keys_p384`, `ecdsa_p521`/`keys_p521`, `ecdsa_p256k1`/`keys_p256k1`,
//! `ecdsa_bp256r1`/`keys_bp256r1`, `ecdsa_bp384r1`/`keys_bp384r1`,
//! `ecdsa_bp512r1`/`keys_bp512r1`.
//!
//! # Status
//!
//! Seven curves, each paired with the hash whose output matches its order: P-256 (SHA-256), P-384
//! (SHA-384), P-521 (SHA-512), secp256k1 (SHA-256), brainpoolP256r1 (SHA-256), brainpoolP384r1
//! (SHA-384), and brainpoolP512r1 (SHA-512). SM2 is a different signature algorithm rather than
//! another ECDSA curve, and lives in [`bouncycastle_sm2`](../bouncycastle_sm2/index.html).
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
//! "on disk" sizes are each curve's `PK_LEN`/`SK_LEN`. P-521's odd numbers come from its 521-bit
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
//!     [`rfc6979_p256::generate_k`]'s docs for the argument, the brainpool modules' for the rates, and
//!     [`rfc6979_bp256r1::generate_k`]'s for what the fingerprint is worth.
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
//! - **`ctx` is accepted but ignored.** ECDSA (FIPS 186-5, SEC 1) has no context-string input;
//!   the key traits' `ctx` parameter is accepted for trait conformance and silently discarded. A
//!   caller relying on `ctx` to bind a signature to an application context gets no such binding
//!   from ECDSA.

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

pub mod der;
pub mod ecdsa_bp256r1;
pub mod ecdsa_bp384r1;
pub mod ecdsa_bp512r1;
pub mod ecdsa_p256;
pub mod ecdsa_p256k1;
pub mod ecdsa_p384;
pub mod ecdsa_p521;
pub mod keys_bp256r1;
pub mod keys_bp384r1;
pub mod keys_bp512r1;
pub mod keys_common;
pub mod keys_p256;
pub mod keys_p256k1;
pub mod keys_p384;
pub mod keys_p521;
pub mod rfc6979_bp256r1;
pub mod rfc6979_bp384r1;
pub mod rfc6979_bp512r1;
pub mod rfc6979_p256;
pub mod rfc6979_p256k1;
pub mod rfc6979_p384;
pub mod rfc6979_p521;
