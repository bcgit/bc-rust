//! Ed448 and Ed448ph (RFC 8032 Section 5.2; EdDSA and HashEdDSA over edwards448 in FIPS 186-5
//! Section 7), on the signature roles. [`Ed448PrivateKey`] and [`Ed448PublicKey`] are keys of
//! [`Ed448`], and [`Ed448ph`] is reached through a key's `as_prehash()`, which gives a view that
//! borrows the key: [`Ed448phPrivateKey`], [`Ed448phPublicKey`]. The module has the shape of
//! [`ed25519`](crate::ed::ed25519); what differs is that both algorithms take a context, and the
//! lengths.
//!
//! # Usage Examples
//!
//! ## Generating keys
//!
//! [`keygen`] draws the 57-octet private key from the caller's RNG, which must offer 192 bits;
//! [`keygen_out`] does so into a key the caller holds. An existing key is imported with
//! `from_bytes`, from its 57 octets, or with [`Ed448PrivateKey::from_bytes_out`] into a key
//! the caller holds.
//!
//! ```rust
//! use bouncycastle_core::traits::{PrivateKey, PublicKey};
//! use bouncycastle_ec::ed::ed448::{Ed448PrivateKey, Ed448PublicKey, keygen};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let (pk, sk) = keygen(&mut HashDRBG_SHA512::new_from_os())?;
//! assert_eq!(sk.pk()?, pk);
//!
//! // Decoding a public key validates it in full, which costs about as much as a verification.
//! let pk2 = Ed448PublicKey::from_bytes(&pk.encode())?;
//! assert_eq!(pk2, pk);
//! assert!(Ed448PrivateKey::from_bytes(&sk.encode())? == sk);
//! # Ok::<(), bouncycastle_core::errors::SignatureError>(())
//! ```
//!
//! ## Ed448
//!
//! Ed448 takes the whole message, through the one-shot roles, under an optional context:
//!
//! ```rust
//! use bouncycastle_core::signature_key::{DeterministicOneShotSigningKey, OneShotVerifyingKey};
//! use bouncycastle_ec::ed::ed448::keygen;
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let (pk, sk) = keygen(&mut HashDRBG_SHA512::new_from_os())?;
//!
//! let sig = sk.sign_deterministic(b"msg", None)?;
//! pk.verify(b"msg", None, &sig)?;
//!
//! let ctx = Some(&b"my protocol"[..]);
//! let sig = sk.sign_deterministic(b"msg", ctx)?;
//! pk.verify(b"msg", ctx, &sig)?;
//! assert!(pk.verify(b"msg", None, &sig).is_err());
//! # Ok::<(), bouncycastle_core::errors::SignatureError>(())
//! ```
//!
//! ## Ed448ph
//!
//! Ed448ph signs the first 64 octets of SHAKE256 of the message, so the message can be
//! streamed. It is asked for by name, with `as_prehash()` on either key; the workers borrow the
//! key, so the view need not be kept.
//!
//! ```rust
//! use bouncycastle_core::signature_key::{
//!     DeterministicOneShotSigningKey, DeterministicSigningKey, OneShotVerifyingKey, VerifyingKey,
//! };
//! use bouncycastle_core::traits::{SignatureSigner, SignatureVerifier};
//! use bouncycastle_ec::ed::ed448::keygen;
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let (pk, sk) = keygen(&mut HashDRBG_SHA512::new_from_os())?;
//!
//! let mut signer = sk.as_prehash().create_signer_deterministic(Some(b"my protocol"))?;
//! signer.do_update(b"a message ");
//! signer.do_update(b"in two parts");
//! let sig = signer.do_final()?;
//!
//! let mut verifier = pk.as_prehash().create_verifier(Some(b"my protocol"))?;
//! verifier.do_update(b"a message in two parts");
//! verifier.do_verify_final(&sig)?;
//!
//! // The one-shots give and take the same signature.
//! let msg = b"a message in two parts";
//! let ctx = Some(&b"my protocol"[..]);
//! assert_eq!(sk.as_prehash().sign_deterministic(msg, ctx)?, sig);
//! pk.as_prehash().verify(msg, ctx, &sig)?;
//!
//! // It is not an Ed448 signature, under the same context or none.
//! assert!(pk.verify(msg, ctx, &sig).is_err());
//! # Ok::<(), bouncycastle_core::errors::SignatureError>(())
//! ```
//!
//! # Memory Usage
//!
//! The base-point tables are constants, about 18 kB of them, and nothing is allocated.
//!
//! | Key Object | PK size on disk | PK size in memory | SK size on disk | SK size in memory |
//! |------------|-----------------|-------------------|-----------------|-------------------|
//! | Ed448      | 57              | 128               | 57              | 228               |
//!
//! All values are in bytes. The "in memory" sizes are measured by rust's `std::mem::size_of`.
//! [`Ed448PublicKey`] holds the decoded point; [`Ed448PrivateKey`] holds the private key, the
//! scalar and prefix derived from it, and the encoded public key.
//!
//! Per-call stack usage, measured as the deepest frame chain from the `measure` wrapper of
//! `mem_usage_benches`' ed448 harness down, the wrapper's own frame included, in the release
//! build (x86-64 Linux, rustc 1.97.0-nightly, return addresses included):
//!
//! | Entry point                        | Stack   |
//! |------------------------------------|---------|
//! | `keygen`                           | 4192 B  |
//! | `keygen_out`                       | 3728 B  |
//! | `Ed448PrivateKey::from_bytes`      | 4064 B  |
//! | `Ed448PrivateKey::from_bytes_out`  | 3392 B  |
//! | `Ed448PublicKey::from_bytes`       | 7232 B  |
//! | `Ed448PrivateKey::pk`              | 3136 B  |
//! | Ed448 sign                         | 4144 B  |
//! | Ed448 verify                       | 10320 B |
//! | Ed448ph sign                       | 5888 B  |
//! | Ed448ph verify                     | 12352 B |
//!
//! The key generation figures leave out the RNG. The Ed448ph figures are for the streaming
//! signer and verifier, and include the worker: a SHAKE256 state and the context.
//!
//! # 🚨 Security Considerations 🚨
//!
//! **Signatures are deterministic** (RFC 8032 Section 8.2): signing draws no randomness, the
//! roles are the deterministic ones, and only [`keygen`] takes an RNG.
//!
//! **Both algorithms take a context**, of up to 255 octets and empty by default, which "has to
//! match octet by octet for verification to be successful" (RFC 8032 Section 5.2); Section 8.3
//! has advice on choosing one. This is where Ed448 differs from Ed25519, which refuses one.
//! RFC 8410 defines no use of contexts in X.509, so a signature made for a certificate or a
//! CMS structure under `id-Ed448` has the empty context.
//!
//! **Verification is cofactored**: it checks the first equation of RFC 8032 Section 5.2.7,
//! `[4][S]B = [4]R + [4][k]A'`, which the RFC and FIPS 186-5 Section 7.7 state first. A
//! verifier that checks the equation without the factor of 4 refuses some signatures this one
//! accepts, those whose `R` is off by a point of order 2 or 4 (Section 8.8); an honest signer
//! never produces one. `S` is required to be below the group order, the check Section 8.4
//! rests non-malleability on.
//!
//! **Public keys are validated in full when decoded.** [`Ed448PublicKey`]'s `from_bytes`
//! refuses a non-canonical encoding, a point off the curve, and any point outside the
//! prime-order subgroup: the four points of small order and every point of mixed order.
//! Verifiers that accept such keys exist, so a key and signature another library accepts can be
//! refused here at the key. The validation costs about one scalar multiplication per decoding;
//! see [`Ed448PublicKey`].
//!
//! **One private key is refused that RFC 8032 would take**: the one whose derived scalar is
//! four times the group order, and whose public key is therefore the neutral element. Decoding
//! it is an error and [`keygen`] fails on it without retrying. Finding such a key is finding a
//! SHAKE256 preimage, and none is known; see [`Ed448PrivateKey`].
//!
//! **Ed448ph trades strength for streaming.** RFC 8032 Section 8.5 says of the prehashed
//! variants that they "SHOULD NOT be used"; prefer Ed448 unless the message cannot be held. A
//! streaming verifier has read the whole message before it can say whether the signature is
//! good (Section 8.7). One key pair may serve both algorithms (Section 8.6), and the two never
//! verify each other's signatures; a key is Ed448's unless `as_prehash()` is called on it, so
//! no call selects Ed448ph unasked. RFC 8410 gives Ed448ph no identifier, so both sides have
//! to know it is meant. The digest is computed here, from the message: a caller that holds only
//! a digest cannot sign or verify it as Ed448ph.
//!
//! **Strength.** RFC 8032 Section 8.5 gives Ed448 and Ed448ph "the strength of 224". The
//! library has no 224-bit level, so they are classed at 192 bits, which is what [`keygen`]
//! asks of its RNG.
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
//! [`Ed448PrivateKey::from_bytes_out`], `clone_from` and `encode_out` into a key or buffer you
//! own where that matters.
//!
//! Three computations would leave secrets on the stack that no `Secret` reaches. One is the last
//! step of signing, where the compiler spills limbs of the scalar it held in registers, and
//! another each fixed-base multiplication (key expansion's `[s]B`, signing's `[r]B`), which
//! spills limbs of the point's coordinates and of the inversion that normalizes them: each runs
//! in a frame of its own whose stack is overwritten afterwards. The third is every
//! SHAKE256 over the private key or the prefix: a sponge that is moved to be squeezed leaves
//! the private key and whole Keccak states of the prefix's hash behind, so each is finished
//! where it sits, and `bouncycastle_digest::sha3` overwrites the frame of each Keccak permutation,
//! which spills lanes of the state. With both in place, a scan of the dead stack
//! after each operation finds none of the private key, the scalar, the prefix, the digests,
//! the nonce `r`, `r + k s` or those Keccak states after `keygen_out`, `from_bytes_out`,
//! `clone_from`, `encode_out`, `pk`, `==`, `keypair_consistency_check` and every form of
//! signing, in the release build for x86-64 Linux (rustc 1.97.0-nightly), the one build
//! scanned. The by-value forms leave what a move leaves, as above.
//!
//! Each fixed-base multiplication checks that its result is a point of the curve before
//! anything is released, and a failure is reported as an error; no input causes one.

mod keys;
mod point;
mod precomp;
mod scalar;
mod scheme;

pub use keys::{
    ED448_NAME, ED448PH_NAME, Ed448, Ed448PrivateKey, Ed448PublicKey, Ed448ph, Ed448phPrivateKey,
    Ed448phPublicKey, Ed448phSigner, Ed448phVerifier, keygen, keygen_out,
    keypair_consistency_check,
};
pub use scheme::{CONTEXT_MAX_LEN, PRIVATE_KEY_LEN, PUBLIC_KEY_LEN, SIGNATURE_LEN};
