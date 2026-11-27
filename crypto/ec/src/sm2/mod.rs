//! SM2: the Chinese national-standard elliptic-curve public key algorithms. This module has the
//! Digital Signature Algorithm (GB/T 32918.2-2016, mirrored by the IETF informational draft
//! `draft-shen-sm2-ecdsa-02`, whose §5 is the same algorithm) -- key generation ([`keys`]) and
//! signing/verification ([`sm2::SM2`]) -- and the Public Key Encryption Algorithm (GB/T
//! 32918.4-2016; the draft's §7) with its own key pair ([`encryption`]). Both are built on
//! [`crate::hazmat::sm2`]'s field/scalar/point arithmetic, SEC 1 encoding, and multipliers, and
//! on [`bouncycastle_digest::sm3`] for the hash (see [`sm2`]'s docs on why only SM3).
//!
//! # Scope
//!
//! The SM2 Key Exchange Protocol (GB/T 32918.3-2016; the draft's §6) is not implemented, and
//! neither is the ASN.1 form of a ciphertext. SM2's Digital Signature Algorithm is *not*
//! ECDSA -- it has its own signing equation and its own identity-binding `ZA` digest (see
//! `za`'s docs) -- despite both being built on the same family of elliptic-curve arithmetic that
//! `crate::ecdsa`'s curves use.
//!
//! # `ctx` carries the signer's identity
//!
//! Every SM2 signing/verification operation needs the signer's identity octet string `IDA`, which
//! `ZA` binds into the hash (GB/T 32918.2-2016 §5.5; the draft's §5.1.4.4). This module carries it
//! in the key traits' `ctx` parameter -- see [`sm2`]'s module docs for the full reasoning and the
//! resulting requirement that `ctx` must be `Some`.
//!
//! # Usage Examples
//!
//! Every SM2 operation needs the signer's identity `IDA`, which `ZA` binds into the message hash;
//! this module carries it in `ctx`, and rejects `None`. Signing draws a fresh `k` from the RNG it
//! is given, so signatures are not reproducible:
//!
//! ```
//! use bouncycastle_core::signature_key::{OneShotSigningKey, OneShotVerifyingKey};
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_ec::sm2::keys::keygen;
//!
//! let (pk, sk) = keygen(&mut HashDRBG_SHA512::new_from_os())?;
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let id = b"alice@example.com";
//! let message = b"the message to sign";
//!
//! let signature = sk.sign(&mut rng, message, Some(id))?;
//! pk.verify(message, Some(id), &signature)?;
//!
//! // The identity is part of what is signed: verifying under a different one fails.
//! assert!(pk.verify(message, Some(b"bob@example.com"), &signature).is_err());
//! // And `ctx` is not optional here, unlike every other primitive in this workspace.
//! assert!(sk.sign(&mut rng, message, None).is_err());
//! # Ok::<(), bouncycastle_core::errors::SignatureError>(())
//! ```
//!
//! Streaming, for a message too large to hold at once. `ZA` is absorbed, and `k` drawn, when the
//! signer is created, so only the message itself passes through `do_update`:
//!
//! ```
//! use bouncycastle_core::signature_key::{SigningKey, VerifyingKey};
//! use bouncycastle_core::traits::{SignatureSigner, SignatureVerifier};
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_ec::sm2::keys::keygen;
//!
//! let (pk, sk) = keygen(&mut HashDRBG_SHA512::new_from_os())?;
//! let id = b"alice@example.com";
//!
//! let mut signer = sk.create_signer(&mut HashDRBG_SHA512::new_from_os(), Some(id))?;
//! signer.do_update(b"the first chunk, ");
//! signer.do_update(b"then the second");
//! let signature = signer.do_final()?;
//!
//! let mut verifier = pk.create_verifier(Some(id))?;
//! verifier.do_update(b"the first chunk, then the second");
//! verifier.do_verify_final(&signature)?;
//! # Ok::<(), bouncycastle_core::errors::SignatureError>(())
//! ```
//!
//! Keys use the same SEC 1 encodings as `crate::ecdsa` -- `04 || X || Y` for a public key
//! (the 33-byte compressed form is also accepted on decode), a 32-byte big-endian integer for a
//! private key, with `dA` required to be in `[1, n-2]`:
//!
//! ```
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_core::traits::{PrivateKey, PublicKey};
//! use bouncycastle_ec::sm2::keys::{SM2PrivateKey, SM2PublicKey, keygen};
//!
//! let (pk, sk) = keygen(&mut HashDRBG_SHA512::new_from_os())?;
//!
//! assert_eq!(SM2PublicKey::from_bytes(&pk.encode())?, pk);
//! assert_eq!(SM2PrivateKey::from_bytes(&sk.encode())?, sk);
//! // A private key carries its own public key, so this costs nothing to ask for.
//! assert_eq!(sk.derive_pk(), pk);
//!
//! assert!(SM2PrivateKey::from_bytes(&[0u8; 32]).is_err());
//! # Ok::<(), bouncycastle_core::errors::SignatureError>(())
//! ```
//!
//! Encryption has a key pair of its own, with the same encodings. The detached pair works on
//! the message where it lies and hands back `C1` (the sender's ephemeral point) and `C3` (a
//! hash over the message and the shared point); the buffer then holds `C2`. `C1` is 65 bytes:
//! encryption writes it uncompressed, and decryption takes the uncompressed or the hybrid form
//! and refuses the 33-byte compressed one (see [`encryption`]):
//!
//! ```
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_ec::sm2::encryption::keygen;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let (pk, sk) = keygen(&mut rng)?;
//!
//! let mut buf = *b"a message, encrypted where it lies";
//! let (c1, c3) = pk.encrypt_detached_inplace(&mut rng, &mut buf)?;
//! assert_ne!(&buf, b"a message, encrypted where it lies");
//!
//! sk.decrypt_detached_inplace(&c1, &c3, &mut buf)?;
//! assert_eq!(&buf, b"a message, encrypted where it lies");
//! # Ok::<(), bouncycastle_core::errors::PublicKeyEncryptionError>(())
//! ```
//!
//! The `_out` forms lay the three parts out in one buffer. `encrypt_out` and `decrypt_out` use
//! the standard's order, `C1 || C3 || C2`; the `c1c2c3` forms use `C1 || C2 || C3`, which is
//! what `draft-shen-sm2-ecdsa-02` and Bouncy Castle Java's `SM2Engine` by default produce. A
//! ciphertext does not say which order it is in, and the wrong one fails to decrypt:
//!
//! ```
//! use bouncycastle_core::errors::PublicKeyEncryptionError;
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_ec::sm2::encryption::{OVERHEAD_LEN, keygen};
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let (pk, sk) = keygen(&mut rng)?;
//! let message = b"the message";
//!
//! let mut ciphertext = [0u8; 11 + OVERHEAD_LEN];
//! assert_eq!(pk.encrypt_out_len(message.len()), ciphertext.len());
//! pk.encrypt_out(&mut rng, message, &mut ciphertext)?;
//! let mut plaintext = [0u8; 11];
//! let len = sk.decrypt_out(&ciphertext, &mut plaintext)?;
//! assert_eq!(&plaintext[..len], message);
//!
//! pk.encrypt_c1c2c3_out(&mut rng, message, &mut ciphertext)?;
//! let len = sk.decrypt_c1c2c3_out(&ciphertext, &mut plaintext)?;
//! assert_eq!(&plaintext[..len], message);
//!
//! // One error for every ciphertext of a valid length that does not decrypt, and no
//! // plaintext left behind.
//! assert_eq!(
//!     sk.decrypt_out(&ciphertext, &mut plaintext),
//!     Err(PublicKeyEncryptionError::DecryptionFailed)
//! );
//! assert_eq!(plaintext, [0u8; 11]);
//! # Ok::<(), PublicKeyEncryptionError>(())
//! ```
//!
//! # Memory Usage
//!
//! The following table lists the size of the on-disk bytes encoding and the in-memory struct size
//! of the key objects:
//!
//! | Key Object | PK size on disk | PK size in memory | SK size on disk | SK size in memory |
//! |------------|-----------------|--------------------|------------------|--------------------|
//! | SM2        | 65              | 64                 | 32               | 128                |
//! | SM2 encryption | 65          | 64                 | 32               | 32                 |
//!
//! All values are in bytes. The "in memory" sizes are measured by rust's `std::mem::size_of`; the
//! "on disk" sizes are [`keys::PK_LEN`]/[`keys::SK_LEN`]. These numbers are produced by
//! `mem_usage_benches`' `bench_sm2_mem_usage` binary's `print_struct_sizes()`; that binary is also
//! the stack-usage measurement harness (see its own doc comment for the `valgrind`/`massif`
//! invocation).
//!
//! An `SM2PrivateKey` is 128 bytes in memory against a 32-byte encoding because it carries two
//! values derived from `dA` alongside it: the matching public key `PA` (two 32-byte field
//! elements) and `(1 + dA)^-1 mod n` (32 bytes, held in `Secret` like `dA` itself). Neither is
//! redundancy: `ZA` mixes `PA` into every signature, so without it each `sign` would have to
//! recompute `[dA]G` and cost two fixed-base scalar multiplications instead of one; and step A6
//! divides by `1 + dA` on every signature, so without the cached inverse each `sign` paid a
//! constant-time inversion for a value that never changes. See [`keys::SM2PrivateKey`]'s own
//! docs. An encryption private key is `dB` alone.
//!
//! Stack written below the call, in bytes, as `dev_scripts/sm2_stack_harness` reports it (it
//! paints the stack, runs the operation and looks for the lowest byte written; release build,
//! x86-64, rustc 1.97 nightly and rustc 1.88), and the same with the body of the stack wipe
//! taken out, which is what the computation itself uses (see the Security Considerations):
//!
//! | Operation                   | Stack, 1.97 | Stack, 1.88 | Unwiped, 1.97 | Unwiped, 1.88 |
//! |-----------------------------|-------------|-------------|---------------|---------------|
//! | `encryption::keygen`        | 4,296       | 4,248       | 2,552         | 2,272         |
//! | `derive_pk`                 | 4,200       | 4,200       | 2,440         | 2,208         |
//! | `encrypt_detached_inplace`  | 8,728       | 8,728       | 4,776         | 4,672         |
//! | `encrypt_out`               | 8,952       | 8,952       | 5,016         | 4,896         |
//! | `decrypt_detached_inplace`  | 8,536       | 8,616       | 4,392         | 4,352         |
//! | `decrypt_out`               | 8,632       | 8,712       | 4,488         | 4,448         |
//! | `keys::keygen`              | 5,320       | 5,272       | 2,968         | 2,688         |
//! | `SM2PrivateKey::from_bytes` | 5,304       | 5,256       | 2,664         | 2,384         |
//! | `create_signer`             | 4,680       | 4,584       | 1,528         | 1,384         |
//! | `sign_out`                  | 5,080       | 5,032       | 3,208         | 3,008         |
//! | signer's final (boxed)      | 4,408       | 4,440       | 2,840         | 2,640         |
//!
//! # 🚨 Security Considerations 🚨
//!
//! - **Everything done with the private key `dA` and the used per-message secret `k` is
//! branch-free and does not index memory by their value**: the inversion of `1 + dA`,
//! multiplication, the fixed-base scalar multiplication `[k]G`. `dA` lives in
//! [`crate::hazmat::sm2_scalar::Sm2Scalar`] (a [`bouncycastle_utils::secret::Secret`]).
//! The exceptions are GB/T 32918.2-2016 §6.1's two retry checks, step A5's `r = 0` or `r + k = n`
//! and step A6's `s = 0`: each is a branch, taken with probability about `2^-256`, and a taken
//! branch discards that `k` (the signer reports failure and the caller makes a fresh one), so
//! neither reveals anything about a `k` that is used.
//! - **`k` must never repeat across two signatures under the same key with different messages.** As
//!   with ECDSA, a repeated `k` leaks `dA` directly from two signatures' `(r, s)` pairs. Unlike
//!   `crate::ecdsa`'s curves, there is no deterministic (RFC 6979-style) default here: the
//!   standard only specifies randomised `k` generation (GB/T 32918.2-2016 §6.1 step A3), so
//!   [`SigningKey::create_signer`](bouncycastle_core::signature_key::SigningKey::create_signer)
//!   draws `k` from the RNG it is handed, once per signer -- see [`sm2`]'s module docs.
//! - **The stack used to load or generate a signing key, to draw `k` and to sign is overwritten
//!   afterwards**, as for encryption below: after `from_bytes`, `keygen`, `create_signer`,
//!   `sign_out` and the signer's final, by 5,120 bytes after the first two and 4,096 after the
//!   others, sized from measurements of optimised x86-64 builds with rustc 1.88 and 1.97 and
//!   checked by `dev_scripts/check_sm2_stack.sh`, with the same limits as encryption's check. A signer holds `k` in
//!   a `Secret` until it is dropped; where a caller moves the signer, as `do_final` takes it by
//!   value, the place it was moved from is the caller's to look after.
//!
//! For encryption ([`encryption`]):
//!
//! - **A ciphertext says nothing about who made it.** Anyone holding the public key can
//!   encrypt, so a ciphertext that decrypts is not evidence of its sender. Authenticate the
//!   sender by other means, such as a signature under a different key pair.
//! - **Nothing but the message is bound.** GB/T 32918.4-2016 uses no identity, no `ZA` and no
//!   label or associated data, so a ciphertext decrypts the same in any context. What it is
//!   for belongs inside the message, or to the protocol around it.
//! - **The ciphertext is 97 bytes longer than the message**, so it gives the message's length
//!   exactly. Pad before encrypting if that matters.
//! - **A ciphertext that does not decrypt is one error**,
//!   [`DecryptionFailed`](bouncycastle_core::errors::PublicKeyEncryptionError::DecryptionFailed),
//!   whether `C1` is not a valid encoding of a point on the curve, the key stream is all
//!   zero, or `C3` does not match. The all-zero and `C3` tests are combined, and decryption
//!   branches once, on the combined result. Decryption computes the message before it can
//!   check it, in the caller's buffer; on any failure that buffer is zeroized before the call
//!   returns. The time taken does tell a `C1` that is not a valid point encoding from the
//!   other two. A length no ciphertext or buffer can have is reported apart, as
//!   `InvalidInputLength` or `OutputBufferTooSmall`, which depend only on the public lengths.
//! - **Keep signing and encryption to separate key pairs.** The two key types have the same
//!   encodings, and nothing stops the same bytes being loaded as both; the types are separate
//!   so that it is not done by accident. This is this library's advice; GB/T 32918.4-2016
//!   says nothing on the point.
//! - **No claim is made here about security against chosen ciphertexts.** `C3` is a hash over
//!   the message and the shared point, and this module's tests show a changed bit anywhere in
//!   a ciphertext being refused. That is a test, not an analysis: none was consulted for this
//!   implementation, and these docs state no security notion.
//! - **`k` is as secret as the message, and must not repeat.** Encryption draws it from the
//!   caller's RNG, which must offer 128 bits of security strength. Whoever learns `k` can
//!   compute the key stream from the public key, and two messages to one recipient under the
//!   same `k` are encrypted under the same key stream.
//! - **The private key `dB`, `k` and the shared point are handled branch-free**, by the
//!   constant-time multipliers of [`crate::hazmat::sm2_comb`] and [`crate::hazmat::sm2_mul`],
//!   and `C3` is compared in constant time. There are two exceptions in encryption, each a
//!   branch on a value derived from a `k` that is discarded when it is taken: the retry when
//!   the key stream is all zero (step A5), taken about once in 256 calls for a one-byte
//!   message, and a defensive test for the point at infinity among `[k]G` and `[k]PB`, which a
//!   `k` in `[1, n-1]` and a valid public key never take.
//! - **The stack the computation used is overwritten afterwards**, as well as the named
//!   secrets being zeroized, since the arithmetic and SM3 leave copies in spilled registers
//!   and temporaries: after encryption, decryption, key generation and `derive_pk`. The sizes
//!   of those wipes, 8,192 bytes after encryption and decryption and 4,096 after the other
//!   two, were chosen from measurements of optimised x86-64 builds with rustc 1.88 and 1.97,
//!   and `dev_scripts/check_sm2_stack.sh` checks that they reach what the computation wrote;
//!   CI runs it for x86-64 and arm64 Linux. On another target, compiler or an unoptimised
//!   build they may not reach everything. Loading a private key (`from_bytes`) zeroizes the
//!   copies it makes and has no such wipe, and neither have `encode`, `encode_out` and
//!   `clone`; in the x86-64 and arm64 builds the check finds nothing of the key on the stack
//!   after any of the four. The key a call returns, and the bytes `encode` returns, are the caller's to
//!   look after.

pub mod encryption;
pub(in crate::sm2) mod encryption_core;
pub mod extra_bits;
pub mod keys;
pub mod sm2;
pub(in crate::sm2) mod za;
