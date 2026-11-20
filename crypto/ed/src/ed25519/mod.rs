//! Ed25519 and Ed25519ph (RFC 8032 Section 5.1; EdDSA and HashEdDSA over edwards25519 in FIPS
//! 186-5 Section 7), on the signature roles: [`Ed25519PrivateKey`] and [`Ed25519PublicKey`]
//! serve both algorithms, named by the markers [`Ed25519`] and [`Ed25519ph`]. Ed25519ctx is not
//! provided.
//!
//! # Usage Examples
//!
//! ## Generating keys
//!
//! [`keygen`] draws the 32-octet private key from the caller's RNG, which must offer 128 bits;
//! [`keygen_out`] does so into a key the caller holds. An existing key is imported with
//! `from_bytes`, from its 32 octets, or with [`Ed25519PrivateKey::from_bytes_out`] into a key
//! the caller holds.
//!
//! ```rust
//! use bouncycastle_core::traits::{PrivateKey, PublicKey};
//! use bouncycastle_ed::ed25519::{Ed25519PrivateKey, Ed25519PublicKey, keygen};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let (pk, sk) = keygen(&mut HashDRBG_SHA512::new_from_os())?;
//! assert_eq!(sk.pk()?, pk);
//!
//! // Decoding a public key validates it in full, which costs about as much as a verification.
//! let pk2 = Ed25519PublicKey::from_bytes(&pk.encode())?;
//! assert_eq!(pk2, pk);
//! assert!(Ed25519PrivateKey::from_bytes(&sk.encode())? == sk);
//! # Ok::<(), bouncycastle_core::errors::SignatureError>(())
//! ```
//!
//! ## Ed25519
//!
//! Ed25519 takes the whole message, through the one-shot roles. The keys implement those roles
//! for both algorithms, so the call names the one it means:
//!
//! ```rust
//! use bouncycastle_core::signature_key::{DeterministicOneShotSigningKey, OneShotVerifyingKey};
//! use bouncycastle_ed::ed25519::{Ed25519, keygen};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let (pk, sk) = keygen(&mut HashDRBG_SHA512::new_from_os())?;
//!
//! let sig = DeterministicOneShotSigningKey::<Ed25519, _>::sign_deterministic(&sk, b"msg", None)?;
//! OneShotVerifyingKey::<Ed25519, _>::verify(&pk, b"msg", None, &sig)?;
//! # Ok::<(), bouncycastle_core::errors::SignatureError>(())
//! ```
//!
//! ## Ed25519ph
//!
//! Ed25519ph signs the SHA-512 digest of the message under an optional context, so the message
//! can be streamed. Only Ed25519ph has the streaming roles, so these calls need no marker; its
//! one-shots do, as above.
//!
//! ```rust
//! use bouncycastle_core::signature_key::{
//!     DeterministicOneShotSigningKey, DeterministicSigningKey, OneShotVerifyingKey, VerifyingKey,
//! };
//! use bouncycastle_core::traits::{SignatureSigner, SignatureVerifier};
//! use bouncycastle_ed::ed25519::{Ed25519ph, keygen};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let (pk, sk) = keygen(&mut HashDRBG_SHA512::new_from_os())?;
//!
//! let mut signer = sk.create_signer_deterministic(Some(b"my protocol"))?;
//! signer.do_update(b"a message ");
//! signer.do_update(b"in two parts");
//! let sig = signer.do_final()?;
//!
//! let mut verifier = pk.create_verifier(Some(b"my protocol"))?;
//! verifier.do_update(b"a message in two parts");
//! verifier.do_verify_final(&sig)?;
//!
//! // The one-shots give and take the same signature.
//! let msg = b"a message in two parts";
//! let ctx = Some(&b"my protocol"[..]);
//! let one_shot =
//!     DeterministicOneShotSigningKey::<Ed25519ph, _>::sign_deterministic(&sk, msg, ctx)?;
//! assert_eq!(one_shot, sig);
//! OneShotVerifyingKey::<Ed25519ph, _>::verify(&pk, msg, ctx, &sig)?;
//! # Ok::<(), bouncycastle_core::errors::SignatureError>(())
//! ```
//!
//! # Memory Usage
//!
//! The base-point tables are constants, and nothing is allocated.
//!
//! | Key Object | PK size on disk | PK size in memory | SK size on disk | SK size in memory |
//! |------------|-----------------|-------------------|-----------------|-------------------|
//! | Ed25519    | 32              | 80                | 32              | 128               |
//!
//! All values are in bytes. The "in memory" sizes are measured by rust's `std::mem::size_of`.
//! [`Ed25519PublicKey`] holds the decoded point; [`Ed25519PrivateKey`] holds the private key,
//! the scalar and prefix derived from it, and the encoded public key.
//!
//! Per-call stack usage, measured as the deepest frame chain from the `measure` wrapper of
//! `mem_usage_benches`' ed25519 harness down, the wrapper's own frame included, in the release
//! build (x86-64 Linux, rustc 1.97.0-nightly, return addresses included):
//!
//! | Entry point                          | Stack  |
//! |--------------------------------------|--------|
//! | `keygen`                             | 2952 B |
//! | `keygen_out`                         | 2600 B |
//! | `Ed25519PrivateKey::from_bytes`      | 2536 B |
//! | `Ed25519PrivateKey::from_bytes_out`  | 2200 B |
//! | `Ed25519PublicKey::from_bytes`       | 3704 B |
//! | `Ed25519PrivateKey::pk`              | 2072 B |
//! | Ed25519 sign                         | 2952 B |
//! | Ed25519 verify                       | 5224 B |
//! | Ed25519ph sign                       | 4040 B |
//! | Ed25519ph verify                     | 6408 B |
//!
//! The key generation figures leave out the RNG. The Ed25519ph figures are for the streaming
//! signer and verifier, and include the worker: a SHA-512 state and the context.
//!
//! # 🚨 Security Considerations 🚨
//!
//! **Signatures are deterministic** (RFC 8032 Section 8.2): signing draws no randomness, and
//! the same key, message and context always give the same signature. The roles are the
//! deterministic ones for that reason, and only [`keygen`] takes an RNG.
//!
//! **Verification is cofactored**: it checks the first equation of RFC 8032 Section 5.1.7,
//! `[8][S]B = [8]R + [8][k]A'`, which the RFC and FIPS 186-5 Section 7.7 state first. A
//! verifier that checks the equation without the factor of 8 refuses some signatures this one
//! accepts, those whose `R` is off by a point of small order; RFC 8032 Section 8.8 notes that
//! "in some applications it is undesirable for implementations to disagree about the exact set
//! of valid signatures". An honest signer never produces such a signature. `S` is required to
//! be below the group order, the check Section 8.4 rests non-malleability on.
//!
//! **Public keys are validated in full when decoded.** [`Ed25519PublicKey`]'s `from_bytes`
//! refuses a non-canonical encoding, a point off the curve, and any point outside the
//! prime-order subgroup: the eight points of small order and every point of mixed order.
//! Verifiers that accept such keys exist, so a key and signature another library accepts can be
//! refused here at the key. The validation costs about one scalar multiplication per decoding;
//! see [`Ed25519PublicKey`].
//!
//! **Ed25519 has no context**, and a non-empty one is refused, not ignored. Ed25519ph binds
//! its context, of up to 255 octets; RFC 8032 Section 8.3 has advice on choosing one.
//!
//! **Ed25519ph trades strength for streaming.** RFC 8032 Section 8.5: "The prehashing also
//! makes the functions greatly more vulnerable to weaknesses in hash functions used. These
//! variants SHOULD NOT be used." Prefer Ed25519 unless the message cannot be held. A streaming
//! verifier has also read the whole message before it can say whether the signature is good;
//! Section 8.7 warns against acting on data before then. One key pair may serve both algorithms
//! (Section 8.6). The digest is computed here, from the message: a caller that holds only a
//! SHA-512 digest cannot sign or verify it as Ed25519ph.
//!
//! **Constant time.** Key expansion and signing are constant time in the private key and
//! everything derived from it, on a target that multiplies two 64-bit words into 128 bits in
//! time independent of their values; on a 32-bit target that product is a call into the
//! compiler's runtime, and constant time rests on that routine. Decoding a public key and
//! verification are variable time: their inputs are public.
//!
//! **What is wiped, and what is not.** The private key, the scalar and prefix derived from it,
//! and the secret intermediates of signing live in `Secret`s or self-wiping types and are
//! cleared at the end of their lifetime. A value returned by value is moved, and a move does
//! not wipe its source: that holds for the key pair of [`keygen`], for the trait's `from_bytes`,
//! for `clone` and for the array `encode` returns. Use [`keygen_out`],
//! [`Ed25519PrivateKey::from_bytes_out`], `clone_from` and `encode_out` into a key or buffer you
//! own where that matters. Signing also overwrites the stack its last step used, where the
//! compiler otherwise leaves limbs of the scalar it held in registers; a scan of the dead stack
//! after each signing call finds none of the key in release builds for x86-64 and arm64, the
//! two scanned. SHA-512 is outside that: its load of the block that holds the private key can
//! leave words of it on the stack, seen as one word after `from_bytes_out` in the arm64 build.
//!
//! Each fixed-base multiplication checks that its result is a point of the curve before
//! anything is released, and a failure is reported as an error; no input causes one.

mod keys;
mod point;
mod precomp;
mod scalar;
mod scheme;

pub use keys::{
    ED25519_NAME, ED25519PH_NAME, Ed25519, Ed25519PrivateKey, Ed25519PublicKey, Ed25519ph,
    Ed25519phSigner, Ed25519phVerifier, keygen, keygen_out, keypair_consistency_check,
};
pub use scheme::{CONTEXT_MAX_LEN, PRIVATE_KEY_LEN, PUBLIC_KEY_LEN, SIGNATURE_LEN};
