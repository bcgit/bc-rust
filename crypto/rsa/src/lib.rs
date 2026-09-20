//! RSA digital signatures: RSASSA-PKCS1-v1_5 and RSASSA-PSS (RFC 8017 §8), built on
//! [`bouncycastle_ec`]'s constant-time limb arithmetic ([`bouncycastle_ec::nat`],
//! [`bouncycastle_ec::montgomery`]) rather than a dedicated bignum type, for the same
//! constant-time reasoning that motivates that crate's own custom-curve arithmetic: a modular
//! exponentiation over a secret exponent has to run in the same time regardless of the exponent's
//! value, which needs limbs of a fixed width known at compile time.
//!
//! # Scope
//!
//! Signature schemes only -- no RSAES-OAEP or RSAES-PKCS1-v1_5 encryption. Modulus sizes 2048
//! through 8192 bits ([`rsa_2048`], [`rsa_3072`], [`rsa_4096`], [`rsa_8192`]) support both signing
//! and verification; 1024- and 1536-bit moduli ([`rsa_1024`], [`rsa_1536`]) support verification
//! only, enforced by the absence of a private-key type (and so of any `Signer` impl) for those
//! sizes rather than a runtime check.
//!
//! Every (scheme, hash, modulus size) pairing is available two ways over one implementation:
//! as a pair of free functions taking a whole message (`pkcs1_v1_5_sign_sha256`/`..._verify_...`
//! in each size module), and as a type implementing [`bouncycastle_core`]'s
//! [`Signer`](bouncycastle_core::traits::Signer)/[`SignatureVerifier`](bouncycastle_core::traits::SignatureVerifier)
//! traits (`RSASSA_PKCS1_v1_5_SHA256` and siblings in each size module), which adds the
//! streaming `_init`/`_update`/`_final` form. The key types implement
//! [`SignaturePrivateKey`](bouncycastle_core::traits::SignaturePrivateKey)/[`SignaturePublicKey`](bouncycastle_core::traits::SignaturePublicKey)
//! per size.
//!
//! # Usage Examples
//!
//! RSA-2048 with SHA-256 through the `bouncycastle_core` signature traits ([`rsa_2048`]), the
//! way code written against those traits (and this workspace's CLI) uses every signature scheme:
//!
//! ```
//! use bouncycastle_core::traits::{SignaturePrivateKey, SignaturePublicKey, SignatureVerifier, Signer};
//! use bouncycastle_rsa::rsa_2048::{RSASSA_PKCS1_v1_5_SHA256, RSASSA_PSS_SHA256, Rsa2048PrivateKey, Rsa2048PublicKey};
//! # // The same genuine RSA-2048 keypair as the next example; see there for its provenance.
//! # const P: [u64; 16] = [0x0ea36cfb3a5b18f1, 0x48a6e65332119129, 0x110ad9e7b48a1c93, 0x569156b90113e2e9, 0xe79813a575cfad9c, 0x69d659d143ec6f17, 0xe81e6bab5ddaa783, 0xbff1c5b80a69f788, 0x978f6c35814f50ee, 0xe6a289ad4cfbf78f, 0x34d5681e5809d415, 0xbb028bda42eeb5d2, 0x41c56e4de086b0d5, 0x58b8d1e24f3b55d0, 0xfb5248247d98cb7d, 0xdc431050f782e894];
//! # const Q: [u64; 16] = [0x669f140cfbc20f25, 0xb97bb03677207d95, 0xfd4e06f3ed7299d4, 0x160f90536abc9492, 0xf5b131f39098f7bc, 0xae8d72c57088d7ab, 0x89b94fbde542aba9, 0x3d3f9880ec47d5e0, 0x1378a6868af3b7a0, 0x5544070beb057c94, 0x16611debc472fac4, 0xe500ffb79f5b8868, 0x308a5e32196603b2, 0xea5fb19eb4eabc38, 0x122273ae3222b598, 0xbd1a81e7977f9898];
//! # const D_P: [u64; 16] = [0x209f33f09515d7c1, 0xb4a9b37656917205, 0x276933bb07e4efb9, 0x8c14019808e00414, 0x289f96da220711e5, 0xfbbd2923d31532fe, 0xc06b414e61c0e1e7, 0x4c23c4588488961d, 0x4dc48ae34514759c, 0x9c786961ae3e2c35, 0x497e8d9c650688e0, 0x18bf08472612dbe5, 0x8885fb161870ee12, 0xf21d7c1479d99d47, 0x9121d91952ffd1c7, 0xa94b528b28f29159];
//! # const D_Q: [u64; 16] = [0xf7597ffb68011d8d, 0x7b3cc538c4bab8c9, 0xa8fa480a81a925af, 0x6d6ede7251a383bf, 0x8a63f788ce3a0f85, 0x0b920502eb478bc9, 0x7e37e755edfe70d9, 0x9cf9948422a16555, 0x0d6d9ea1f2ef71fd, 0xf7efa32ea0cb6e00, 0x0629b114ca7f780f, 0xcf51176359654348, 0x540cdcbd4ad35435, 0x31c02ff1a2bc437c, 0xff2503df78bafed5, 0x3af0e72a933aef09];
//! # const Q_INV: [u64; 16] = [0x552fe4bfce945f7b, 0x67e50c999c67247b, 0xfb54ef17be3b2853, 0x241f5921b5ad3983, 0x02de5eccd143cf31, 0x74e45f6fcc60f216, 0xafa5428a74f12708, 0x88d42294b6a2759b, 0xe923e1097c0c562f, 0xc968b48a91c38b5b, 0x933e85179c0320b0, 0x7993d0445f758d51, 0x9bfc042ee0924b1b, 0x41f956d90fa8a793, 0xee7a87b6483a66ee, 0x2640fbfbcfefb163];
//! let sk = Rsa2048PrivateKey::from_crt_components(&P, &Q, &D_P, &D_Q, &Q_INV)?;
//! let pk = Rsa2048PublicKey::new(sk.n(), 0x10001)?;
//!
//! // One-shot. RSA has no context string, so `ctx` is `None` (a `Some` is accepted and ignored).
//! let signature = RSASSA_PKCS1_v1_5_SHA256::sign(&sk, b"the message to sign", None)?;
//! RSASSA_PKCS1_v1_5_SHA256::verify(&pk, b"the message to sign", None, &signature)?;
//!
//! // Streaming: the message arrives in chunks and is hashed as it goes.
//! let mut signer = RSASSA_PKCS1_v1_5_SHA256::sign_init(&sk, None)?;
//! signer.sign_update(b"the message ");
//! signer.sign_update(b"to sign");
//! let streamed = signer.sign_final()?;
//! assert_eq!(streamed, signature); // PKCS#1 v1.5 is deterministic
//!
//! let mut verifier = RSASSA_PKCS1_v1_5_SHA256::verify_init(&pk, None)?;
//! verifier.verify_update(b"the message to sign");
//! verifier.verify_final(&streamed)?;
//!
//! // `verify` takes a `&[u8]`: a signature of the wrong length is rejected as invalid
//! // (RFC 8017 §8.2.2 step 1), as is one over a different message.
//! assert!(RSASSA_PKCS1_v1_5_SHA256::verify(&pk, b"the message to sign", None, &signature[1..]).is_err());
//! assert!(RSASSA_PKCS1_v1_5_SHA256::verify(&pk, b"a different message", None, &signature).is_err());
//!
//! // RSASSA-PSS through the same traits draws its salt from the library's default RNG.
//! let sig_a = RSASSA_PSS_SHA256::sign(&sk, b"the message to sign", None)?;
//! let sig_b = RSASSA_PSS_SHA256::sign(&sk, b"the message to sign", None)?;
//! assert_ne!(sig_a, sig_b);
//! RSASSA_PSS_SHA256::verify(&pk, b"the message to sign", None, &sig_a)?;
//! RSASSA_PSS_SHA256::verify(&pk, b"the message to sign", None, &sig_b)?;
//!
//! // Keys round-trip through the traits' raw fixed-width encoding (see `keys`'s docs).
//! let pk_again = Rsa2048PublicKey::from_bytes(&pk.encode())?;
//! assert_eq!(pk_again, pk);
//! let sk_again = Rsa2048PrivateKey::from_bytes(&sk.encode())?;
//! assert_eq!(sk_again, sk);
//! # Ok::<(), bouncycastle_core::errors::SignatureError>(())
//! ```
//!
//! The same RSA-2048/SHA-256 pairing through the free functions, which take a whole message and
//! (for PSS) an explicit RNG or salt:
//!
//! ```
//! use bouncycastle_rsa::rsa_2048::{Rsa2048PrivateKey, Rsa2048PublicKey, pkcs1_v1_5_sign_sha256, pkcs1_v1_5_verify_sha256};
//! # // A genuine RSA-2048 keypair (Wycheproof rsa_pkcs1_2048_sig_gen_test.json's first SHA-256
//! # // group; `tests/rsa_2048_pkcs1_v1_5_tests.rs` has the full, sourced provenance).
//! # const P: [u64; 16] = [0x0ea36cfb3a5b18f1, 0x48a6e65332119129, 0x110ad9e7b48a1c93, 0x569156b90113e2e9, 0xe79813a575cfad9c, 0x69d659d143ec6f17, 0xe81e6bab5ddaa783, 0xbff1c5b80a69f788, 0x978f6c35814f50ee, 0xe6a289ad4cfbf78f, 0x34d5681e5809d415, 0xbb028bda42eeb5d2, 0x41c56e4de086b0d5, 0x58b8d1e24f3b55d0, 0xfb5248247d98cb7d, 0xdc431050f782e894];
//! # const Q: [u64; 16] = [0x669f140cfbc20f25, 0xb97bb03677207d95, 0xfd4e06f3ed7299d4, 0x160f90536abc9492, 0xf5b131f39098f7bc, 0xae8d72c57088d7ab, 0x89b94fbde542aba9, 0x3d3f9880ec47d5e0, 0x1378a6868af3b7a0, 0x5544070beb057c94, 0x16611debc472fac4, 0xe500ffb79f5b8868, 0x308a5e32196603b2, 0xea5fb19eb4eabc38, 0x122273ae3222b598, 0xbd1a81e7977f9898];
//! # const D_P: [u64; 16] = [0x209f33f09515d7c1, 0xb4a9b37656917205, 0x276933bb07e4efb9, 0x8c14019808e00414, 0x289f96da220711e5, 0xfbbd2923d31532fe, 0xc06b414e61c0e1e7, 0x4c23c4588488961d, 0x4dc48ae34514759c, 0x9c786961ae3e2c35, 0x497e8d9c650688e0, 0x18bf08472612dbe5, 0x8885fb161870ee12, 0xf21d7c1479d99d47, 0x9121d91952ffd1c7, 0xa94b528b28f29159];
//! # const D_Q: [u64; 16] = [0xf7597ffb68011d8d, 0x7b3cc538c4bab8c9, 0xa8fa480a81a925af, 0x6d6ede7251a383bf, 0x8a63f788ce3a0f85, 0x0b920502eb478bc9, 0x7e37e755edfe70d9, 0x9cf9948422a16555, 0x0d6d9ea1f2ef71fd, 0xf7efa32ea0cb6e00, 0x0629b114ca7f780f, 0xcf51176359654348, 0x540cdcbd4ad35435, 0x31c02ff1a2bc437c, 0xff2503df78bafed5, 0x3af0e72a933aef09];
//! # const Q_INV: [u64; 16] = [0x552fe4bfce945f7b, 0x67e50c999c67247b, 0xfb54ef17be3b2853, 0x241f5921b5ad3983, 0x02de5eccd143cf31, 0x74e45f6fcc60f216, 0xafa5428a74f12708, 0x88d42294b6a2759b, 0xe923e1097c0c562f, 0xc968b48a91c38b5b, 0x933e85179c0320b0, 0x7993d0445f758d51, 0x9bfc042ee0924b1b, 0x41f956d90fa8a793, 0xee7a87b6483a66ee, 0x2640fbfbcfefb163];
//! let sk = Rsa2048PrivateKey::from_crt_components(&P, &Q, &D_P, &D_Q, &Q_INV)?;
//! let pk = Rsa2048PublicKey::new(sk.n(), 0x10001)?;
//!
//! let signature = pkcs1_v1_5_sign_sha256(&sk, b"the message to sign")?;
//! pkcs1_v1_5_verify_sha256(&pk, b"the message to sign", &signature)?;
//!
//! // A signature does not verify against a different message.
//! assert!(pkcs1_v1_5_verify_sha256(&pk, b"a different message", &signature).is_err());
//!
//! // RSASSA-PSS is randomized (a fresh salt each time), so two signatures of the same message
//! // differ, but both verify.
//! use bouncycastle_rsa::rsa_2048::{pss_sign_sha256, pss_verify_sha256};
//! use bouncycastle_rng::DefaultRNG;
//!
//! let mut rng = DefaultRNG::default();
//! let sig_a = pss_sign_sha256(&sk, b"the message to sign", &mut rng)?;
//! let sig_b = pss_sign_sha256(&sk, b"the message to sign", &mut rng)?;
//! assert_ne!(sig_a, sig_b);
//! pss_verify_sha256(&pk, b"the message to sign", &sig_a)?;
//! pss_verify_sha256(&pk, b"the message to sign", &sig_b)?;
//! # Ok::<(), bouncycastle_core::errors::SignatureError>(())
//! ```
//!
//! RSA-1024 verification, the other major usage pattern: no private key or signer exists for this
//! size at all (see `# Scope` above), only verification against a signature produced elsewhere --
//! here, one of Wycheproof's own genuine `rsa_pkcs1_1024_sig_gen_test.json` signatures
//! (`tests/rsa_1024_tests.rs` has the full, sourced provenance):
//!
//! ```
//! use bouncycastle_rsa::rsa_1024::{Rsa1024PublicKey, pkcs1_v1_5_verify_sha256};
//! # const N: [u64; 16] = [0xd00343468eaacfbf, 0xb7c7044cc202dcca, 0x9686f30f478db649, 0x5179b54951fff6aa, 0xbabb14f550d5d0dd, 0x5405db7c5c8f4cf6, 0x9816e2eda41fd7b9, 0xb31b6abd805bace9, 0xb909dd0f4c6014f2, 0x9c8a5810b6d05990, 0x40760d1f23fe9250, 0x90adb011a919575a, 0x45e48572113cab28, 0xcb9ca9ec12000fc8, 0x91b4fcaf62a14595, 0xac9048a7a4f560af];
//! let sig: [u8; 128] = bouncycastle_hex::decode("41339884a9b3940e8488d666bb158063c6a2a2717cae7f564834a876fcbf7098ecf3acbfabf37d38a8e6127b1e313744f1f896e165efdaea0b2e7673867842b9e94db0868ed9a92bcdcb370a4e20ff275c82595e4400a8b9e9f12482f014846b48216f321266ae6ae6338dbcdc41b711e483e6e3e728772e7f9f5ef95c30196b").unwrap().try_into().unwrap();
//! let msg = [0u8; 20]; // Wycheproof's own genuine message for this signature.
//! let pk = Rsa1024PublicKey::new(&N, 0x10001)?;
//! pkcs1_v1_5_verify_sha256(&pk, &msg, &sig)?;
//! # Ok::<(), bouncycastle_core::errors::SignatureError>(())
//! ```
//!
//! RSASSA-PSS-SHAKE128/256 (RFC 8702 §3.2.1, [`rsa_2048::pss_shake128_sign`]/`_verify` and
//! siblings at RSA-3072/4096) follow the exact same `sign`/`sign_with_salt`/`verify` shape as
//! `pss_sign_sha256`/`pss_verify_sha256` above, just with a different function name per §5's
//! recommended pairing (SHAKE128 at 2048/3072, SHAKE256 at 4096) -- see [`rsa_2048`]'s own docs
//! rather than a second, near-identical example here.
//!
//! # Status
//!
//! [`modexp`] (constant-time modular exponentiation over a runtime-supplied modulus), [`keys`]
//! (the CRT key types), the CRT-based RSASP1/RSAVP1 primitives (crate-private, in `rsa_core`),
//! RSASSA-PKCS1-v1_5 ([`rsassa_pkcs1_v1_5`]), and RSASSA-PSS ([`rsassa_pss`]) are implemented,
//! with SHA-256, SHA-384, and SHA-512 wired up for every modulus size this crate offers -- 1024
//! and 1536 (verification only, per `# Scope` above) and 2048/3072/4096/8192 (both directions) --
//! and validated against genuine vectors: Wycheproof for every size except 8192, which it has no
//! key material for at all (cross-checked against BC Java instead); see each `rsa_*.rs` module's
//! own tests for the specifics at each size. Every pairing also implements `bouncycastle_core`'s
//! `Signer`/`SignatureVerifier` traits (see `# Scope`), exercised through
//! `bouncycastle_core_test_framework`'s shared signature conformance suite at each size.
//!
//! RSASSA-PSS-SHAKE128 and RSASSA-PSS-SHAKE256 (RFC 8702 §3.2.1 -- SHAKE128/SHAKE256 used
//! natively as both the message hash and the mask generation function, in place of a hash+MGF1
//! split) are also implemented ([`rsassa_pss_shake`], built on `emsa_pss_shake` rather than
//! `mgf1`), wired up for the pairings RFC 8702 §5 recommends: SHAKE128 with RSA-2048/3072
//! ([`rsa_2048`], [`rsa_3072`]) and SHAKE256 with RSA-4096 ([`rsa_4096`]), each validated against
//! its own genuine Wycheproof `rsa_pss_*_shake*_test.json` vectors.
//!
//! # Memory Usage
//!
//! | Key Object       | PK size on disk | PK size in memory | SK size on disk | SK size in memory |
//! |-------------------|------------------|--------------------|------------------|--------------------|
//! | RSA-1024 (verify-only) | 132        | 136                | --               | --                 |
//! | RSA-1536 (verify-only) | 196        | 200                | --               | --                 |
//! | RSA-2048          | 260              | 264                | 640              | 896                |
//! | RSA-3072          | 388              | 392                | 960              | 1344               |
//! | RSA-4096          | 516              | 520                | 1280             | 1792               |
//! | RSA-8192          | 1028             | 1032               | 2560             | 3584               |
//!
//! All values are in bytes. "On disk" is the `SignaturePublicKey`/`SignaturePrivateKey` raw
//! layout ([`keys::RsaPublicKey`]'s and [`keys::RsaPrivateKey`]'s `# Encoding`: `n || e`, and
//! `p || q || dP || dQ || qInv` respectively); "in memory" is `core::mem::size_of`. A signature
//! is the same size as the modulus itself (`K_LEN = 8 * L` bytes: 128/192/256/384/512/1024 for
//! 1024/1536/2048/3072/4096/8192). These numbers are produced by `mem_usage_benches`'
//! `bench_rsa_mem_usage` binary's `print_key_sizes()`; that binary is also the stack-usage
//! measurement harness (see its own doc comment for the `valgrind`/`massif` invocation) -- only
//! one representative (scheme, hash) pairing is profiled there per modulus size, since stack
//! usage is dominated by the modulus's own limb count `L`, not by which hash or scheme fed into
//! RSASP1/RSAVP1's modular exponentiation. A `Signer`/`SignatureVerifier` streaming state
//! (`RSASSA_*` in each size module) additionally holds a clone of its key for its lifetime --
//! the "SK size in memory" column, for a signer -- plus the hash state.
//!
//! # Security Considerations
//!
//! - **RSASP1 (private-key signing) is not blinded against its input.** [`modexp`]'s `mod_pow` is
//!   constant-time in the *exponent* (the CRT exponents `dP`/`dQ`), which defeats a pure timing
//!   attack, but neither it nor `rsa_core::rsasp1` multiplies the message by a random blinding
//!   factor before exponentiating and removes it afterward. An attacker able to mount a
//!   chosen-message physical side-channel attack (power or cache analysis, not just wall-clock
//!   timing) against many signatures under the same key may still be able to recover information
//!   about `p`/`q`/`dP`/`dQ`, per Kocher (1996) and Boneh & Brumley (2003) -- see [`modexp`]'s own
//!   docs for the exact boundary of what is and is not covered.
//! - **This crate does not generate or validate primality of `p`/`q`.** [`keys::RsaPrivateKey::from_crt_components`]
//!   checks that `p`/`q` are odd and distinct and that `dP`/`dQ`/`qInv` are in range, but it has no
//!   way to check that `p` and `q` are actually prime (that would need a primality test this crate
//!   does not implement) or that `e` is coprime to `λ(n)`. Supplying non-prime or otherwise
//!   malformed CRT components produces a key that computes *something*, silently, rather than
//!   being rejected -- validating the inputs' number-theoretic properties before construction is
//!   entirely the caller's responsibility.
//! - **RSASSA-PSS's salt is only as good as its source.** `Signer::sign` draws it from the
//!   library's default OS-backed RNG; `sign_randomized` takes the caller's RNG and
//!   `set_signer_salt` takes the salt itself. Unlike ECDSA's per-message secret `k`, a repeated
//!   or predictable PSS salt does not hand an attacker the private key by itself (there is no
//!   algebraic relation analogous to ECDSA's nonce-reuse equation), but PSS's random-oracle
//!   security argument (RFC 8017 §8.1, Appendix A.2.3's references) assumes the salt is drawn
//!   fresh and unpredictably each time. Signing with a low-quality or unseeded RNG, or reusing a
//!   fixed salt outside a test, weakens that argument even though it will not directly leak `d`.
//! - **`ctx` is accepted but ignored.** RSASSA-PKCS1-v1_5 and RSASSA-PSS (RFC 8017 §8) have no
//!   context-string input; `Signer`/`SignatureVerifier`'s `ctx` parameter is accepted for trait
//!   conformance and silently ignored, as `bouncycastle-ecdsa` does for ECDSA. A caller relying
//!   on `ctx` to bind a signature to an application context gets no such binding here and must
//!   fold the context into the message itself.
//! - **RSA-1024 and RSA-1536 are legacy sizes, exposed for verification only.** Both fall below
//!   the 112-bit security level NIST SP 800-131A requires for new use (RSA-1024 offers roughly
//!   80 bits, RSA-1536 roughly 96); this crate offers no way to sign with either (see `# Scope`)
//!   precisely so they can only be used to check signatures against legacy/third-party data, not
//!   to produce new ones.
//! - **RSASSA-PSS's salt length is fixed to the hash's own output length** (RFC 8017 §9.1 note
//!   4's "typical" choice) rather than being caller-configurable. A verifier that expects a
//!   different salt length (including the zero-length salt some other implementations default
//!   to) will not interoperate with signatures this crate produces, and this crate's own verifier
//!   will reject signatures made with a different salt length.

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

mod codec;
mod emsa_pkcs1_v1_5;
mod emsa_pss;
mod emsa_pss_shake;
pub mod keys;
mod mgf1;
pub mod modexp;
pub mod rsa_1024;
pub mod rsa_1536;
pub mod rsa_2048;
pub mod rsa_3072;
pub mod rsa_4096;
pub mod rsa_8192;
mod rsa_core;
pub mod rsassa_pkcs1_v1_5;
pub mod rsassa_pss;
pub mod rsassa_pss_shake;
