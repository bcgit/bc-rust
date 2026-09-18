//! ECDSA over seven curves: key generation (FIPS 186-5 Appendix A.2.1), signature generation
//! (§6.4.1, deterministic per §6.3.2/Appendix A.3.3/RFC 6979 by default, randomised per
//! §6.3.1/Appendix A.3.1 as an additional API), and verification (§6.4.2), built on
//! [`bouncycastle_ec`]'s field/scalar/point arithmetic, SEC 1 encodings, and comb/wNAF
//! multipliers. Raw `r || s` is the default signature encoding; [`der`] offers DER `SEQUENCE { r,
//! s }` (RFC 3279 §2.2.3) as an alternative for interop that needs it.
//!
//! # Usage Examples
//!
//! Signing is deterministic (RFC 6979), so the same key and message always produce the same
//! signature:
//!
//! ```
//! use bouncycastle_core::traits::{SignatureVerifier, Signer};
//! use bouncycastle_ecdsa::ecdsa_p256::ECDSAP256;
//! use bouncycastle_ecdsa::keys::keygen;
//!
//! let (pk, sk) = keygen()?;
//! let message = b"the message to sign";
//!
//! // ECDSA has no context string; the trait's `ctx` parameter is accepted and ignored.
//! let signature = ECDSAP256::sign(&sk, message, None)?;
//! assert_eq!(signature, ECDSAP256::sign(&sk, message, None)?, "RFC 6979 is deterministic");
//!
//! ECDSAP256::verify(&pk, message, None, &signature)?;
//! assert!(ECDSAP256::verify(&pk, b"a different message", None, &signature).is_err());
//! # Ok::<(), bouncycastle_core::errors::SignatureError>(())
//! ```
//!
//! Streaming, for a message you do not want to hold in memory at once:
//!
//! ```
//! use bouncycastle_core::traits::{SignatureVerifier, Signer};
//! use bouncycastle_ecdsa::ecdsa_p256::ECDSAP256;
//! use bouncycastle_ecdsa::keys::keygen;
//!
//! let (pk, sk) = keygen()?;
//!
//! let mut signer = ECDSAP256::sign_init(&sk, None)?;
//! signer.sign_update(b"the first chunk, ");
//! signer.sign_update(b"then the second");
//! let signature = signer.sign_final()?;
//!
//! let mut verifier = ECDSAP256::verify_init(&pk, None)?;
//! verifier.verify_update(b"the first chunk, then the second");
//! verifier.verify_final(&signature)?;
//! # Ok::<(), bouncycastle_core::errors::SignatureError>(())
//! ```
//!
//! Keys encode as SEC 1 octets -- `04 || X || Y` for a public key (the 33-byte compressed form is
//! also accepted on decode), a fixed-width big-endian integer for a private key. Both reject
//! malformed input rather than reinterpreting it:
//!
//! ```
//! use bouncycastle_core::traits::{SignaturePrivateKey, SignaturePublicKey};
//! use bouncycastle_ecdsa::keys::{ECDSAP256PrivateKey, ECDSAP256PublicKey, keygen};
//!
//! let (pk, sk) = keygen()?;
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
//! For interop that needs DER `SEQUENCE { r, s }` rather than raw `r || s`:
//!
//! ```
//! use bouncycastle_ecdsa::ecdsa_p256::ECDSAP256;
//! use bouncycastle_ecdsa::keys::keygen;
//!
//! let (pk, sk) = keygen()?;
//! let (der, der_len) = ECDSAP256::sign_der(&sk, b"message", None)?;
//! ECDSAP256::verify_der(&pk, b"message", None, &der[..der_len])?;
//! # Ok::<(), bouncycastle_core::errors::SignatureError>(())
//! ```
//!
//! Every curve follows the same shape, in its own module pair: `ecdsa_p256`/`keys`,
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
//! # Security Considerations
//!
//! - **The private key `d` and the per-message secret `k` are never handled in variable time.**
//!   `d` lives in [`bouncycastle_ec::p256_scalar::P256Scalar`] (a [`bouncycastle_utils::secret::Secret`]);
//!   every operation performed on it or on `k` -- inversion, multiplication, the fixed-base
//!   scalar multiplication `[k]G` -- is branch-free and does not index memory by their value. See
//!   [`bouncycastle_ec`]'s own module docs for the constant-time discipline this crate builds on.
//! - **`k` must never repeat across two signatures under the same key with different messages.**
//!   A repeated `k` leaks `d` directly from two signatures' `(r, s)` pairs (elementary algebra on
//!   the ECDSA equation). This is why deterministic generation (RFC 6979) is the default here: `k`
//!   is a function of `d` and the message hash, so the same `(d, message)` pair always regenerates
//!   the same `k` rather than depending on a caller's RNG being correctly seeded every time.
//! - **Deterministic signatures are a fault-attack target** (FIPS 186-5 §6, first paragraph): an
//!   attacker who can induce a computational fault and observe the faulty signature may be able to
//!   recover `d`, because a deterministic scheme will reproduce the exact same `k` on a retry. This
//!   is a property of determinism itself, not a defect in this implementation; see FIPS 186-5's
//!   references \[17\]-\[22\] for mitigations at the deployment level (e.g. verifying a signature
//!   in-device before releasing it).
//! - **`ctx` is accepted but ignored.** ECDSA (FIPS 186-5, SEC 1) has no context-string input;
//!   `Signer`/`SignatureVerifier`'s `ctx` parameter is accepted for trait conformance and silently
//!   discarded, per the sanctioned behaviour `core::traits::Signer`'s own docs list ("ignore the
//!   provided ctx value"). A caller relying on `ctx` to bind a signature to an application context
//!   gets no such binding from ECDSA.

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
pub mod extra_bits;
pub mod extra_bits_bp256r1;
pub mod extra_bits_bp384r1;
pub mod extra_bits_bp512r1;
pub mod extra_bits_p256k1;
pub mod extra_bits_p384;
pub mod keys;
pub mod keys_bp256r1;
pub mod keys_bp384r1;
pub mod keys_bp512r1;
pub mod keys_common;
pub mod keys_p256k1;
pub mod keys_p384;
pub mod keys_p521;
pub mod rfc6979;
pub mod rfc6979_bp256r1;
pub mod rfc6979_bp384r1;
pub mod rfc6979_bp512r1;
pub mod rfc6979_p256k1;
pub mod rfc6979_p384;
pub mod rfc6979_p521;
