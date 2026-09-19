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
//! only, enforced by the absence of a private-key/signer type for those sizes rather than a
//! runtime check.
//!
//! # Usage Examples
//!
//! RSA-2048 with SHA-256, the one concrete pairing wired up so far ([`rsa_2048`]):
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
//! # Status
//!
//! [`modexp`] (constant-time modular exponentiation over a runtime-supplied modulus), [`keys`]
//! (the CRT key types), the CRT-based RSASP1/RSAVP1 primitives (crate-private, in `rsa_core`),
//! RSASSA-PKCS1-v1_5 ([`rsassa_pkcs1_v1_5`]), and RSASSA-PSS ([`rsassa_pss`]) are implemented,
//! with SHA-256, SHA-384, and SHA-512 wired up for every modulus size this crate offers -- 1024
//! and 1536 (verification only, per `# Scope` above) and 2048/3072/4096/8192 (both directions) --
//! and validated against genuine vectors: Wycheproof for every size except 8192, which it has no
//! key material for at all (cross-checked against BC Java instead); see each `rsa_*.rs` module's
//! own tests for the specifics at each size.
//!
//! RSASSA-PSS-SHAKE128 and RSASSA-PSS-SHAKE256 (RFC 8702 §3.2.1 -- SHAKE128/SHAKE256 used
//! natively as both the message hash and the mask generation function, in place of a hash+MGF1
//! split) are also implemented ([`rsassa_pss_shake`], built on `emsa_pss_shake` rather than
//! `mgf1`), wired up for the pairings RFC 8702 §5 recommends: SHAKE128 with RSA-2048/3072
//! ([`rsa_2048`], [`rsa_3072`]) and SHAKE256 with RSA-4096 ([`rsa_4096`]), each validated against
//! its own genuine Wycheproof `rsa_pss_*_shake*_test.json` vectors.

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
