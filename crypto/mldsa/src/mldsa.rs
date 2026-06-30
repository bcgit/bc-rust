//! This page documents advanced features of the Module Lattice Digital Signature Algorithm (ML-DSA)
//! available in this crate.
//!
//!
//! # Streaming APIs
//!
//! Sometimes the message you need to sign or verify is too big to fit in device memory all at once.
//! No worries, we got you covered!
//!
//! ```rust
//! use bouncycastle_core::errors::SignatureError;
//! use bouncycastle_core::traits::{Signer, SignatureVerifier};
//! use bouncycastle_mldsa::{MLDSA65, MLDSATrait, MLDSAPublicKeyTrait, MuBuilder};
//!
//! let (pk, sk) = MLDSA65::keygen().unwrap();
//!
//! // Let's pretend this message was so long that you couldn't possibly
//! // stream the whole thing over a network, and you need it pre-hashed.
//! let msg_chunk1 = b"The quick brown fox ";
//! let msg_chunk2 = b"jumped over the lazy dog";
//!
//! let mut signer = MLDSA65::sign_init(&sk, None).unwrap();
//! signer.sign_update(msg_chunk1);
//! signer.sign_update(msg_chunk2);
//! let sig = signer.sign_final().unwrap();
//! // This is the signature value that you can save to a file or whatever you need.
//!
//! // This is compatible with a verifies that takes the whole message as one chunk:
//! let msg = b"The quick brown fox jumped over the lazy dog";
//! match MLDSA65::verify(&pk, msg, None, &sig) {
//!     Ok(()) => println!("Signature is valid!"),
//!     Err(SignatureError::SignatureVerificationFailed) => println!("Signature is invalid!"),
//!     Err(e) => panic!("Something else went wrong: {:?}", e),
//! }
//!
//! // But of course there's also a streaming API for the verifier!
//! let mut verifier = MLDSA65::verify_init(&pk, None).unwrap();
//! verifier.verify_update(msg_chunk1);
//! verifier.verify_update(msg_chunk2);
//!
//! match verifier.verify_final(&sig.as_slice()) {
//!     Ok(()) => println!("Signature is valid!"),
//!     Err(SignatureError::SignatureVerificationFailed) => println!("Signature is invalid!"),
//!     Err(e) => panic!("Something else went wrong: {:?}", e),
//! }
//! ```
//!
//!
//! Note that the streaming API also supports setting the signing context `ctx` and signing nonce `rnd`,
//! which are explained in more detail below.
//!
//! ```rust
//! use bouncycastle_core::errors::SignatureError;
//! use bouncycastle_core::traits::{Signer, SignatureVerifier};
//! use bouncycastle_mldsa::{MLDSA65, MLDSATrait, MLDSAPublicKeyTrait, MuBuilder};
//!
//! let (pk, sk) = MLDSA65::keygen().unwrap();
//!
//! // Let's pretend this message was so long that you couldn't possibly
//! // stream the whole thing over a network, and you need it pre-hashed.
//! let msg_chunk1 = b"The quick brown fox ";
//! let msg_chunk2 = b"jumped over the lazy dog";
//!
//! let mut signer = MLDSA65::sign_init(&sk, Some(b"signing ctx value")).unwrap();
//! signer.set_signer_rnd([0u8; 32]); // an all-zero rnd is the "deterministic" mode of ML-DSA
//! signer.sign_update(msg_chunk1);
//! signer.sign_update(msg_chunk2);
//! let sig = signer.sign_final().unwrap();
//! ```
//!
//! # External Mu mode
//!
//! Here, `mu` refers to the message digest which is computed internally to the ML-DSA algorithm:
//!
//! > 𝜇 ← H(BytesToBits(𝑡𝑟)||𝑀′, 64)
//! >   ▷ message representative that may optionally be computed in a different cryptographic module
//!
//! The External Mu mode of ML-DSA fulfills a similar function to [hash_mldsa] in that it allows large
//! messages to be pre-digested outside of the cryptographic module that holds the private key,
//! but it does it in a way that is compatible with the ML-DSA verification function.
//! In other works, whereas [hash_mldsa] represents a different signature algorithm, the external mu
//! mode of ML-DSA is simply internal implementation detail of how the signature was computed and
//! produces signatures that are indistinguishable from "direct" ML-DSA mode.
//!
//! The one potential complication with external mu mode -- that [hash_mldsa] does not have --
//! is that it requires you to know the public key that you are about to sign the message with.
//! Or, more specifically, the hash of the public key `tr`.
//! `tr` is a public value (derivable from the public key), so there is no harm in, for example,
//! sending it down to a client device so that it can pre-hash a large message and only send the
//! 64-byte `mu` value up to the server to be signed.
//! But in some contexts, the message has to be pre-hashed for performance reasons but
//! the public key that will be used for signing cannot be known in advance.
//! For those use cases, your only choice is to use [hash_mldsa].
//!
//! This library exposes [MuBuilder] which can be used to pre-hash a large to-be-signed message
//! along with the public key hash `tr`:
//!
//! ```rust
//! use bouncycastle_core::errors::SignatureError;
//! use bouncycastle_mldsa::{MLDSA65, MLDSATrait, MLDSAPublicKeyTrait, MuBuilder};
//! use bouncycastle_core::traits::{Signer, SignatureVerifier};
//!
//! let (pk, _) = MLDSA65::keygen().unwrap();
//!
//! // Let's pretend this message was so long that you couldn't possibly
//! // stream the whole thing over a network, and you need it pre-hashed.
//! let msg = b"The quick brown fox jumped over the lazy dog";
//!
//! let mu: [u8; 64] = MuBuilder::compute_mu(&pk.compute_tr(), msg, None).unwrap();
//! ```
//!
//! Note: if you are going to bind a `ctx` value (explained below), then you need to do in in [MuBuilder::compute_mu].
//!
//! If the message really is so huge that you can't hold it all in memory at once, then you might prefer a streaming API for
//! computing mu:
//!
//! ```rust
//! use bouncycastle_core::errors::SignatureError;
//! use bouncycastle_core::traits::{Signer, SignatureVerifier};
//! use bouncycastle_mldsa::{MLDSA65, MLDSATrait, MLDSAPublicKeyTrait, MuBuilder};
//!
//! let (pk, _) = MLDSA65::keygen().unwrap();
//!
//! // Let's pretend this message was so long that you couldn't possibly
//! // stream the whole thing over a network, and you need it pre-hashed.
//! let msg_chunk1 = b"The quick brown fox ";
//! let msg_chunk2 = b"jumped over the lazy dog";
//!
//! let mut mb = MuBuilder::do_init(&pk.compute_tr(), None).unwrap();
//! mb.do_update(msg_chunk1);
//! mb.do_update(msg_chunk2);
//! let mu = mb.do_final();
//! ```
//!
//! Given a mu value, you can compute a signature that verifies as normal (no mu's required!):
//!
//! ```rust
//! use bouncycastle_core::errors::SignatureError;
//! use bouncycastle_core::traits::{Signer, SignatureVerifier};
//! use bouncycastle_mldsa::{MLDSA65, MLDSATrait, MLDSAPublicKeyTrait, MuBuilder};
//!
//! let msg = b"The quick brown fox jumped over the lazy dog";
//!
//! let (pk, sk) = MLDSA65::keygen().unwrap();
//!
//! // Assume this was computed somewhere else and sent to you.
//! // They would have had to know pk!
//! let mu: [u8; 64] = MuBuilder::compute_mu(&pk.compute_tr(), msg, None).unwrap();
//!
//! let sig = MLDSA65::sign_mu(&sk, None, &mu).unwrap();
//! // This is the signature value that you can save to a file or whatever you need.
//!
//! match MLDSA65::verify(&pk, msg, None, &sig) {
//!     Ok(()) => println!("Signature is valid!"),
//!     Err(SignatureError::SignatureVerificationFailed) => println!("Signature is invalid!"),
//!     Err(e) => panic!("Something else went wrong: {:?}", e),
//! }
//!
//! ```
//!
//! # Ctx and Rnd params
//! Various functions in this crate let you set the signing context value (`ctx`) and the signing nonce (`rnd`).
//! Let's talk about them both:
//!
//! ## ctx
//! The `ctx` value allows the signer to bind the signature value to an extra piece of information
//! (up to 255 bytes long) that must also be known to the verifier in order to successfully verify the signature.
//! This optional parameter allows cryptographic protocol designers to get additional binding properties
//! from the ML-DSA signature.
//! The `ctx` value should be something that is known to both the signer and verifier,
//! does not necessarily need to be a secret, but should not go over the wire as part of the not-yet-verified message.
//! Examples of uses of the `ctx` could include binding the application data type (ex: `FooEmailData`) in order
//! to disambiguate other data types that share an encoding (ex: `FooTextDocumentData`) and might otherwise be possible for an
//! attacker to trick a verifier into accepting one in place of the other.
//! In a network protocol, `ctx` could be used to bind a transaction ID or protocol nonce in order to strongly
//! protect against replay attacks.
//! Generally, `ctx` is one of those things that if you don't know what it does, then you're probably
//! fine to ignore it.
//!
//! Example of signing and verifying with a `ctx` value:
//!
//! ```rust
//! use bouncycastle_core::errors::SignatureError;
//! use bouncycastle_mldsa::{MLDSA65, MLDSATrait};
//! use bouncycastle_core::traits::{Signer, SignatureVerifier};
//!
//! let msg = b"The quick brown fox";
//! let ctx = b"FooTextDocumentFormat";
//!
//! let (pk, sk) = MLDSA65::keygen().unwrap();
//!
//! let sig = MLDSA65::sign(&sk, msg, Some(ctx)).unwrap();
//! // This is the signature value that you can save to a file or whatever you need.
//!
//! match MLDSA65::verify(&pk, msg, Some(ctx), &sig) {
//!     Ok(()) => println!("Signature is valid!"),
//!     Err(SignatureError::SignatureVerificationFailed) => println!("Signature is invalid!"),
//!     Err(e) => panic!("Something else went wrong: {:?}", e),
//! }
//! ```
//!
//! ## rnd
//!
//! This is the signature nonce, whose purpose is to ensure that you get different signature values
//! if you sign the same message with the same public key multiple times.
//!
//! In general, the "deterministic" mode of ML-DSA (which usually uses an all-zero `rnd`) is considered
//! secure and safe to use but you may lose certain privacy properties, because, for example,
//! it becomes obvious that multiple identical signatures means that the same message was signed multiple times
//! by the same private key.
//!
//! The default mode of ML-DSA uses a `rnd` generated by the library's OS-backed RNG, but you can set the `rnd`
//! if you need to; for example if you are running on an embedded device that does not have access to an RNG.
//!
//! Note that in order to avoid combinatorial explosion of API functions, setting the `rnd` value is only
//! available in conjunction with external mu or streaming modes. The example of setting `rnd` on the streaming
//! API was shown above.
//!
//! Here is an example of using the [MLDSA::sign_mu_deterministic] function:
//!
//! ```rust
//! use bouncycastle_core::errors::SignatureError;
//! use bouncycastle_core::traits::{Signer, SignatureVerifier};
//! use bouncycastle_mldsa::{MLDSA65, MLDSATrait, MLDSAPublicKeyTrait, MuBuilder};
//!
//! let msg = b"The quick brown fox jumped over the lazy dog";
//!
//! let (pk, sk) = MLDSA65::keygen().unwrap();
//!
//! // Assume this was computed somewhere else and sent to you.
//! // They would have had to know pk!
//! let mu: [u8; 64] = MuBuilder::compute_mu(&pk.compute_tr(), msg, None).unwrap();
//!
//! // Typically, "deterministic" mode of ML-DSA will use an all-zero rnd,
//! // but we've exposed it so you can set any value you need to.
//! let sig = MLDSA65::sign_mu_deterministic(&sk, None, &mu, [0u8; 32]).unwrap();
//! // This is the signature value that you can save to a file or whatever you need.
//!
//! match MLDSA65::verify(&pk, msg, None, &sig) {
//!     Ok(()) => println!("Signature is valid!"),
//!     Err(SignatureError::SignatureVerificationFailed) => println!("Signature is invalid!"),
//!     Err(e) => panic!("Something else went wrong: {:?}", e),
//! }
//! ```
//!
//! # Pre-expanding the public key for repeated use
//!
//! Within the usual ML-DSA public key representation, the public matrix A is stored as a seed rho, which
//! means that both the ML-DSA.sign() and ML-DSA.verify() operations need to expand it into a full matrix
//! before performing the matrix multiplication.
//! We offer a version of the public and private key structs that pre-expand the public matrix for repeated use.
//!
//! The runtime of ML-DSA.sign() is dominated by the rejection sampling look, making the A-expansion
//! a negligible part of the function -- accounting for only about 2% of the computation.
//! However, for ML-DSA.verify(), pre-expansion of the public matrix A gives speedups of 38% / 45% / 63%
//! speedup for ML-DSA 44 / 65 / 87, especially if verifying multiple signatures against the same public key.
//!
//! ```rust
//! use bouncycastle_mldsa::{MLDSA65, MLDSATrait};
//! use bouncycastle_mldsa::{MLDSA65PublicKeyExpanded, MLDSA65PrivateKeyExpanded};
//! use bouncycastle_core::traits::{Signer, SignatureVerifier};
//! use bouncycastle_core::errors::SignatureError;
//!
//! let msg = b"The quick brown fox";
//!
//! let (pk, sk) = MLDSA65::keygen().unwrap();
//!
//! // The pre-expanded private key uses more memory, but has performance
//! // improvements if doing multiple decapsulations with the same key
//! // although the performance improvements on signing are slight -- only around 2%.
//! let sk_expanded = MLDSA65PrivateKeyExpanded::from(&sk);
//! let sig = MLDSA65::sign_with_expanded_key(&sk_expanded, msg, None).unwrap();
//!
//! // The pre-expand the public key uses more memory, but has performance
//! // improvements if doing multiple encapsulations for the same key.
//! let pk_expanded = MLDSA65PublicKeyExpanded::from(&pk);
//! match MLDSA65::verify_with_expanded_key(&pk_expanded, msg, None, &sig) {
//!     Ok(()) => println!("Signature is valid!"),
//!     Err(SignatureError::SignatureVerificationFailed) => println!("Signature is invalid!"),
//!     Err(e) => panic!("Something else went wrong: {:?}", e),
//! }
//! ```
//!
//! # sign_from_seed
//!
//! This mode is intended for users with extreme performance or resource-limitation requirements.
//!
//! A very careful analysis of the ML-DSA signing algorithm will show that you don't actually need
//! the entire ML-DSA private key to be in memory at the same time. In fact, it is possible to merge
//! the keygen() and sign() functions
//!
//! We provide [MLDSA::sign_mu_deterministic_from_seed] which implements such an algorithm.
//! It has a significantly lower peak-memory-footprint than the regular signing API (although there's
//! always room for more optimization), and according to our benchmarks it is only around 25% slower
//! than signing with a fully-expanded private key -- which is still faster than performing a full
//! keygen followed by a regular sign since there are intermediate values common to keygen and sign
//! that the merged function is able to only compute once.
//!
//! Since this is intended for hard-core embedded systems people, we have not wrapped this in all
//! the beginner-friendly APIs. If you need this, then we assume you know what you're doing!
//!
//! Example usage:
//!
//! ```rust
//! use bouncycastle_core::errors::SignatureError;
//! use bouncycastle_core::traits::{Signer, SignatureVerifier};
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType, KeyMaterialTrait};
//! use bouncycastle_hex as hex;
//! use bouncycastle_mldsa::{MLDSA44, MLDSA44_SIG_LEN, MLDSATrait, MLDSAPublicKeyTrait, MuBuilder};
//!
//! let msg = b"The quick brown fox jumped over the lazy dog";
//!
//! let seed = KeyMaterial256::from_bytes_as_type(
//!     &hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap(),
//!     KeyType::Seed,
//! ).unwrap();
//!
//! // At some point, you'll need to compute the public key, both to get `tr`, and so other
//! // people can verify your signature.
//! // There's no possible short-cut to efficiently computing the public key or `tr` from the seed;
//! // you have to run the full keygen to get the full private key, at least momentarily, then
//! // you can discard it in only keep `tr` and `seed`.
//! let (pk, _) = MLDSA44::keygen_from_seed(&seed).unwrap();
//! let tr: [u8; 64] = pk.compute_tr();
//!
//! // Assume this was computed somewhere else and sent to you.
//! // They would have had to know pk!
//! let mu: [u8; 64] = MuBuilder::compute_mu(&tr, msg, None).unwrap();
//! let rnd: [u8; 32] = [0u8; 32]; // with this API, you're responsible for your own nonce
//!                                // because in the cases where this level of memory optimization
//!                                // is needed, our RNG probably won't work anyway.
//!
//! let mut sig = [0u8; MLDSA44_SIG_LEN];
//! let bytes_written = MLDSA44::sign_mu_deterministic_from_seed_out(&seed, &mu, rnd, &mut sig)
//!                                                                                 .unwrap();
//!
//! // it can be verified normally
//! match MLDSA44::verify(&pk, msg, None, &sig) {
//!     Ok(()) => println!("Signature is valid!"),
//!     Err(SignatureError::SignatureVerificationFailed) => println!("Signature is invalid!"),
//!     Err(e) => panic!("Something else went wrong: {:?}", e),
//! }
//! ```
//!
//! While this is currently only supported when operating from a seed-based private key, something analogous
//! could be done that merges the sk_decode() and sign() routines when working with the standardized
//! private key encoding (which is often called the "semi-expanded format" since the in-memory representation
//! is still larger).
//! Contact us if you need such a thing implemented.
//!
//!
//! # Pre-expanding the public key for repeated use
//!
//! One of the computationally expensive parts of both ML-DSA.sign() and ML-DSA.verify() is expansion
//! of the public matrix A from the public seed that is stored in with the compressed representation.
//! When done as part of the keygen, expansion of the public matrix accounts for 20% - 30% of the keygen
//! and verification time (depending on parameter set), and around 5% of the signing time since the
//! rejection sampling loop dominates the runtime of the sign operation.
//!
//! If the key is loaded and used once for a single signature or a single verification,
//! then there is no performance difference to whether the
//! public matrix A is expanded as part of keygen or as part of sign / verify, but it does make both
//! the public and private key take up more space in memory, so the default ML-DSA public and private key
//! objects defer expansion until it is needed.
//!
//! However, in uses where many sign or verify operations are performed against the same
//! key pair in quick succession, there can be substantial performance improvements to pre-computing
//! this and holding on to a larger key object.
//! This is accomplished via constructing a [MLDSAPublicKeyExpanded] or [MLDSAPrivateKeyExpanded] object
//! of the appropriate parameter set from the original key, and then using this with [MLDSA::sign_with_expanded_key]
//! or [MLDSA::verify_with_expanded_key].
//! Both [MLDSAPublicKeyExpanded] and [MLDSAPrivateKeyExpanded] implement the same traits
//! and therefore behave the same as their non-expanded counterparts in most regards.
//!
//! ```rust
//! use bouncycastle_mldsa::{MLDSA65, MLDSATrait};
//! use bouncycastle_mldsa::{MLDSA65PublicKeyExpanded, MLDSA65PrivateKeyExpanded};
//! use bouncycastle_core::traits::{Signer, SignatureVerifier};
//! use bouncycastle_core::errors::SignatureError;
//!
//! let msg = b"The quick brown fox jumped over the lazy dog";
//!
//! let (pk, sk) = MLDSA65::keygen().unwrap();
//!
//! // pre-expand the private key, which uses more memory, but has performance
//! // improvements if doing multiple decapsulations with the same key
//! let sk_expanded = MLDSA65PrivateKeyExpanded::from(&sk);
//!
//! let sig = MLDSA65::sign_with_expanded_key(&sk_expanded, msg, None).unwrap();
//!
//! // pre-expand the public key, which uses more memory, but has performance
//! // improvements if doing multiple verifications with the same key
//! let pk_expanded = MLDSA65PublicKeyExpanded::from(&pk);
//!
//! match MLDSA65::verify_with_expanded_key(&pk_expanded, msg, None, &sig) {
//!     Ok(()) => println!("Signature is valid!"),
//!     Err(SignatureError::SignatureVerificationFailed) => println!("Signature is invalid!"),
//!     Err(e) => panic!("Something else went wrong: {:?}", e),
//! }
//! ```

use crate::aux_functions::{
    expand_mask, expandA, expandS, make_hint_vecs, power_2_round_vec, sample_in_ball, sig_decode,
    sig_encode, use_hint_vecs,
};
use crate::matrix::{Matrix, Vector};
use crate::mldsa_keys::{MLDSAPrivateKeyInternalTrait, MLDSAPrivateKeyTrait};
use crate::mldsa_keys::{MLDSAPublicKeyInternalTrait, MLDSAPublicKeyTrait};
use crate::{
    MLDSA44PrivateKey, MLDSA44PublicKey, MLDSA65PrivateKey, MLDSA65PublicKey, MLDSA87PrivateKey,
    MLDSA87PublicKey, MLDSAPrivateKeyExpanded, MLDSAPublicKeyExpanded,
};
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterial256, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{Algorithm, RNG, SecurityStrength, SignatureVerifier, Signer, XOF};
use bouncycastle_rng::HashDRBG_SHA512;
use bouncycastle_sha3::{SHAKE128, SHAKE256};
use core::marker::PhantomData;

// imports needed just for docs
#[allow(unused_imports)]
use crate::hash_mldsa;
#[allow(unused_imports)]
use bouncycastle_core::traits::{PHSignatureVerifier, PHSigner};

/*** Constants ***/

///
pub const ML_DSA_44_NAME: &str = "ML-DSA-44";
///
pub const ML_DSA_65_NAME: &str = "ML-DSA-65";
///
pub const ML_DSA_87_NAME: &str = "ML-DSA-87";

// From FIPS 204 Table 1 and Table 2

// Constants that are the same for all parameter sets
pub(crate) const N: usize = 256;
pub(crate) const q: i32 = 8380417;
pub(crate) const q_inv: i32 = 58728449; // q ^ (-1) mod 2 ^32
pub(crate) const d: i32 = 13;
/// Length of the \[u8] holding an ML-DSA seed value.
pub const MLDSA_SEED_LEN: usize = 32;
/// Length of the \[u8] holding an ML-DSA signing random value.
pub const MLDSA_RND_LEN: usize = 32;
/// Length of the \[u8] holding an ML-DSA tr value (which is the SHAKE256 hash of the public key).
pub const MLDSA_TR_LEN: usize = 64;
/// Length of the \[u8] holding an ML-DSA mu value.
pub const MLDSA_MU_LEN: usize = 64;
pub(crate) const POLY_T0PACKED_LEN: usize = 416;
pub(crate) const POLY_T1PACKED_LEN: usize = 320;

/* ML-DSA-44 params */

/// Length of the \[u8] holding a ML-DSA-44 public key.
pub const MLDSA44_PK_LEN: usize = 1312;
/// Length of the \[u8] holding a ML-DSA-44 private key.
pub const MLDSA44_SK_LEN: usize = 2560;
/// Length of the \[u8] holding a ML-DSA-44 signature value.
pub const MLDSA44_SIG_LEN: usize = 2420;
pub(crate) const MLDSA44_TAU: i32 = 39;
pub(crate) const MLDSA44_LAMBDA: i32 = 128;
pub(crate) const MLDSA44_GAMMA1: i32 = 1 << 17;
pub(crate) const MLDSA44_GAMMA2: i32 = (q - 1) / 88; // mutants note: because of the bitshifting, the "- 1" ends up not mattering
pub(crate) const MLDSA44_k: usize = 4;
pub(crate) const MLDSA44_l: usize = 4;
pub(crate) const MLDSA44_ETA: usize = 2;
pub(crate) const MLDSA44_BETA: i32 = 78;
pub(crate) const MLDSA44_OMEGA: i32 = 80;

// Useful derived values
pub(crate) const MLDSA44_C_TILDE: usize = 32;
pub(crate) const MLDSA44_POLY_Z_PACKED_LEN: usize = 576;
pub(crate) const MLDSA44_POLY_W1_PACKED_LEN: usize = 192;
pub(crate) const MLDSA44_LAMBDA_over_4: usize = 128 / 4;
pub(crate) const MLDSA44_GAMMA1_MINUS_BETA: i32 = MLDSA44_GAMMA1 - MLDSA44_BETA;
pub(crate) const MLDSA44_GAMMA2_MINUS_BETA: i32 = MLDSA44_GAMMA2 - MLDSA44_BETA;

// Alg 32
// 1: 𝑐 ← 1 + bitlen (𝛾1 − 1)
pub(crate) const MLDSA44_GAMMA1_MASK_LEN: usize = 576; // 32*(1 + bitlen (𝛾1 − 1) )

/* ML-DSA-65 params */

/// Length of the \[u8] holding a ML-DSA-65 public key.
pub const MLDSA65_PK_LEN: usize = 1952;
/// Length of the \[u8] holding a ML-DSA-65 private key.
pub const MLDSA65_SK_LEN: usize = 4032;
/// Length of the \[u8] holding a ML-DSA-65 signature value.
pub const MLDSA65_SIG_LEN: usize = 3309;
pub(crate) const MLDSA65_TAU: i32 = 49;
pub(crate) const MLDSA65_LAMBDA: i32 = 192;
pub(crate) const MLDSA65_GAMMA1: i32 = 1 << 19;
pub(crate) const MLDSA65_GAMMA2: i32 = (q - 1) / 32; // mutants note: because of the bitshifting, the "- 1" ends up not mattering
pub(crate) const MLDSA65_k: usize = 6;
pub(crate) const MLDSA65_l: usize = 5;
pub(crate) const MLDSA65_ETA: usize = 4;
pub(crate) const MLDSA65_BETA: i32 = 196;
pub(crate) const MLDSA65_OMEGA: i32 = 55;

// Useful derived values
pub(crate) const MLDSA65_C_TILDE: usize = 48;
pub(crate) const MLDSA65_POLY_Z_PACKED_LEN: usize = 640;
pub(crate) const MLDSA65_POLY_W1_PACKED_LEN: usize = 128;
pub(crate) const MLDSA65_LAMBDA_over_4: usize = 192 / 4;
pub(crate) const MLDSA65_GAMMA1_MINUS_BETA: i32 = MLDSA65_GAMMA1 - MLDSA65_BETA;
pub(crate) const MLDSA65_GAMMA2_MINUS_BETA: i32 = MLDSA65_GAMMA2 - MLDSA65_BETA;

// Alg 32
// 1: 𝑐 ← 1 + bitlen (𝛾1 − 1)
pub(crate) const MLDSA65_GAMMA1_MASK_LEN: usize = 640;

/* ML-DSA-87 params */

/// Length of the \[u8] holding a ML-DSA-87 public key.
pub const MLDSA87_PK_LEN: usize = 2592;
/// Length of the \[u8] holding a ML-DSA-87 private key.
pub const MLDSA87_SK_LEN: usize = 4896;
/// Length of the \[u8] holding a ML-DSA-87 signature value.
pub const MLDSA87_SIG_LEN: usize = 4627;
pub(crate) const MLDSA87_TAU: i32 = 60;
pub(crate) const MLDSA87_LAMBDA: i32 = 256;
pub(crate) const MLDSA87_GAMMA1: i32 = 1 << 19;
pub(crate) const MLDSA87_GAMMA2: i32 = (q - 1) / 32; // mutants note: because of the bitshifting, the "- 1" ends up not mattering
pub(crate) const MLDSA87_k: usize = 8;
pub(crate) const MLDSA87_l: usize = 7;
pub(crate) const MLDSA87_ETA: usize = 2;
pub(crate) const MLDSA87_BETA: i32 = 120;
pub(crate) const MLDSA87_OMEGA: i32 = 75;

// Useful derived values
pub(crate) const MLDSA87_C_TILDE: usize = 64;
pub(crate) const MLDSA87_POLY_Z_PACKED_LEN: usize = 640;
pub(crate) const MLDSA87_POLY_W1_PACKED_LEN: usize = 128;
pub(crate) const MLDSA87_LAMBDA_over_4: usize = 256 / 4;
pub(crate) const MLDSA87_GAMMA1_MINUS_BETA: i32 = MLDSA87_GAMMA1 - MLDSA87_BETA;
pub(crate) const MLDSA87_GAMMA2_MINUS_BETA: i32 = MLDSA87_GAMMA2 - MLDSA87_BETA;

// Alg 32
// 1: 𝑐 ← 1 + bitlen (𝛾1 − 1)
pub(crate) const MLDSA87_GAMMA1_MASK_LEN: usize = 640;

// Typedefs just to make the algorithms look more like the FIPS 204 sample code.
pub(crate) type H = SHAKE256;
pub(crate) type G = SHAKE128;

/*** Pub Types ***/

/// The ML-DSA-44 algorithm.
pub type MLDSA44 = MLDSA<
    MLDSA44_PK_LEN,
    MLDSA44_SK_LEN,
    MLDSA44_SIG_LEN,
    MLDSA44PublicKey,
    MLDSA44PrivateKey,
    MLDSA44_TAU,
    MLDSA44_LAMBDA,
    MLDSA44_GAMMA1,
    MLDSA44_GAMMA2,
    MLDSA44_k,
    MLDSA44_l,
    MLDSA44_ETA,
    MLDSA44_BETA,
    MLDSA44_OMEGA,
    MLDSA44_C_TILDE,
    MLDSA44_POLY_Z_PACKED_LEN,
    MLDSA44_POLY_W1_PACKED_LEN,
    MLDSA44_LAMBDA_over_4,
    MLDSA44_GAMMA1_MINUS_BETA,
    MLDSA44_GAMMA2_MINUS_BETA,
    MLDSA44_GAMMA1_MASK_LEN,
>;

impl Algorithm for MLDSA44 {
    const ALG_NAME: &'static str = ML_DSA_44_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

/// The ML-DSA-65 algorithm.
pub type MLDSA65 = MLDSA<
    MLDSA65_PK_LEN,
    MLDSA65_SK_LEN,
    MLDSA65_SIG_LEN,
    MLDSA65PublicKey,
    MLDSA65PrivateKey,
    MLDSA65_TAU,
    MLDSA65_LAMBDA,
    MLDSA65_GAMMA1,
    MLDSA65_GAMMA2,
    MLDSA65_k,
    MLDSA65_l,
    MLDSA65_ETA,
    MLDSA65_BETA,
    MLDSA65_OMEGA,
    MLDSA65_C_TILDE,
    MLDSA65_POLY_Z_PACKED_LEN,
    MLDSA65_POLY_W1_PACKED_LEN,
    MLDSA65_LAMBDA_over_4,
    MLDSA65_GAMMA1_MINUS_BETA,
    MLDSA65_GAMMA2_MINUS_BETA,
    MLDSA65_GAMMA1_MASK_LEN,
>;

impl Algorithm for MLDSA65 {
    const ALG_NAME: &'static str = ML_DSA_65_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_192bit;
}

/// The ML-DSA-87 algorithm.
pub type MLDSA87 = MLDSA<
    MLDSA87_PK_LEN,
    MLDSA87_SK_LEN,
    MLDSA87_SIG_LEN,
    MLDSA87PublicKey,
    MLDSA87PrivateKey,
    MLDSA87_TAU,
    MLDSA87_LAMBDA,
    MLDSA87_GAMMA1,
    MLDSA87_GAMMA2,
    MLDSA87_k,
    MLDSA87_l,
    MLDSA87_ETA,
    MLDSA87_BETA,
    MLDSA87_OMEGA,
    MLDSA87_C_TILDE,
    MLDSA87_POLY_Z_PACKED_LEN,
    MLDSA87_POLY_W1_PACKED_LEN,
    MLDSA87_LAMBDA_over_4,
    MLDSA87_GAMMA1_MINUS_BETA,
    MLDSA87_GAMMA2_MINUS_BETA,
    MLDSA87_GAMMA1_MASK_LEN,
>;

impl Algorithm for MLDSA87 {
    const ALG_NAME: &'static str = ML_DSA_87_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
}

/// The core internal implementation of the ML-DSA algorithm.
/// This needs to be public for the compiler to be able to find it, but you shouldn't ever
/// need to use this directly. Please use the named public types.
pub struct MLDSA<
    const PK_LEN: usize,
    const SK_LEN: usize,
    const SIG_LEN: usize,
    PK: MLDSAPublicKeyTrait<k, l, PK_LEN> + MLDSAPublicKeyInternalTrait<k, PK_LEN>,
    SK: MLDSAPrivateKeyTrait<k, l, ETA, SK_LEN, PK_LEN>
        + MLDSAPrivateKeyInternalTrait<k, l, ETA, SK_LEN, PK_LEN>,
    const TAU: i32,
    const LAMBDA: i32,
    const GAMMA1: i32,
    const GAMMA2: i32,
    const k: usize,
    const l: usize,
    const ETA: usize,
    const BETA: i32,
    const OMEGA: i32,
    const C_TILDE: usize,
    const POLY_VEC_H_PACKED_LEN: usize,
    const POLY_W1_PACKED_LEN: usize,
    const LAMBDA_over_4: usize,
    const GAMMA1_MINUS_BETA: i32,
    const GAMMA2_MINUS_BETA: i32,
    const GAMMA1_MASK_LEN: usize,
> {
    _phantom: PhantomData<(PK, SK)>,

    /// used for streaming the message for both signing and verifying
    mu_builder: MuBuilder,

    signer_rnd: Option<[u8; MLDSA_RND_LEN]>,

    /// only used in streaming sign operations
    sk: Option<SK>,

    /// only used in streaming sign operations instead of sk
    seed: Option<KeyMaterial<32>>,

    /// only used in streaming verify operations
    pk: Option<PK>,
}

impl<
    const PK_LEN: usize,
    const SK_LEN: usize,
    const SIG_LEN: usize,
    PK: MLDSAPublicKeyTrait<k, l, PK_LEN> + MLDSAPublicKeyInternalTrait<k, PK_LEN>,
    SK: MLDSAPrivateKeyTrait<k, l, ETA, SK_LEN, PK_LEN>
        + MLDSAPrivateKeyInternalTrait<k, l, ETA, SK_LEN, PK_LEN>,
    const TAU: i32,
    const LAMBDA: i32,
    const GAMMA1: i32,
    const GAMMA2: i32,
    const k: usize,
    const l: usize,
    const ETA: usize,
    const BETA: i32,
    const OMEGA: i32,
    const C_TILDE: usize,
    const POLY_Z_PACKED_LEN: usize,
    const POLY_W1_PACKED_LEN: usize,
    const LAMBDA_over_4: usize,
    const GAMMA1_MINUS_BETA: i32,
    const GAMMA2_MINUS_BETA: i32,
    const GAMMA1_MASK_LEN: usize,
>
    MLDSA<
        PK_LEN,
        SK_LEN,
        SIG_LEN,
        PK,
        SK,
        TAU,
        LAMBDA,
        GAMMA1,
        GAMMA2,
        k,
        l,
        ETA,
        BETA,
        OMEGA,
        C_TILDE,
        POLY_Z_PACKED_LEN,
        POLY_W1_PACKED_LEN,
        LAMBDA_over_4,
        GAMMA1_MINUS_BETA,
        GAMMA2_MINUS_BETA,
        GAMMA1_MASK_LEN,
    >
{
    /// Generate a keypair, sourcing randomness from bouncycastle's default os-backed RNG.
    ///
    /// Key generation is intentionally not part of the [Signer] / [SignatureVerifier] traits;
    /// it is provided as an inherent associated function directly on the algorithm struct.
    /// Error condition: basically only on RNG failures.
    pub fn keygen() -> Result<(PK, SK), SignatureError> {
        Self::keygen_from_os_rng()
    }

    /// Should still be ok in FIPS mode
    pub fn keygen_from_os_rng() -> Result<(PK, SK), SignatureError> {
        let mut seed = KeyMaterial256::new();
        HashDRBG_SHA512::new_from_os().fill_keymaterial_out(&mut seed)?;
        Self::keygen_internal(&seed)
    }
    /// Implements Algorithm 6 of FIPS 204
    /// Note: NIST has made a special exception in the FIPS 204 FAQ that this _internal function
    /// may in fact be exposed outside the crypto module.
    ///
    /// Unlike other interfaces across the library that take an &impl KeyMaterial, this one
    /// specifically takes a 32-byte [KeyMaterial256] and checks that it has [KeyType::Seed] and
    /// [SecurityStrength::_256bit].
    /// If you happen to have your seed in a larger KeyMaterial, you'll have to copy it using
    /// [KeyMaterialTrait::from_key]
    pub(crate) fn keygen_internal(seed: &KeyMaterial256) -> Result<(PK, SK), SignatureError> {
        if !(seed.key_type() == KeyType::Seed || seed.key_type() == KeyType::CryptographicRandom)
            || seed.key_len() != 32
        {
            return Err(SignatureError::KeyGenError(
                "Seed must be 32 bytes and KeyType::Seed or KeyType::BytesFullEntropy.",
            ));
        }

        if seed.security_strength() < SecurityStrength::from_bits(LAMBDA as usize) {
            return Err(SignatureError::KeyGenError(
                "Seed SecurityStrength must match algorithm security strength",
            ));
        }

        // Alg 6 line 1: (rho, rho_prime, K) <- H(𝜉||IntegerToBytes(𝑘, 1)||IntegerToBytes(ℓ, 1), 128)
        //   ▷ expand seed
        let mut rho: [u8; 32] = [0u8; 32];
        let mut K: [u8; 32] = [0u8; 32];

        let (s1_hat, mut s2) = {
            // scope for h
            let mut h = H::default();
            h.absorb(seed.ref_to_bytes());
            h.absorb(&(k as u8).to_le_bytes());
            h.absorb(&(l as u8).to_le_bytes());
            let bytes_written = h.squeeze_out(&mut rho);
            debug_assert_eq!(bytes_written, 32);
            let mut rho_prime: [u8; 64] = [0u8; 64];
            let bytes_written = h.squeeze_out(&mut rho_prime);
            debug_assert_eq!(bytes_written, 64);
            let bytes_written = h.squeeze_out(&mut K);
            debug_assert_eq!(bytes_written, 32);

            // 4: (𝐬1, 𝐬2) ← ExpandS(𝜌′)
            let (mut s1, s2) = expandS::<k, l, ETA>(&rho_prime);

            s1.ntt();
            (s1, s2)
        };

        let t_hat = {
            // scope for s1_hat
            // 3: 𝐀_hat ← ExpandA(𝜌) ▷ 𝐀 is generated and stored in NTT representation as 𝐀
            let A_hat = expandA::<k, l>(&rho);

            // 5: 𝐭 ← NTT−1(𝐀 ∘ NTT(𝐬1)) + 𝐬2
            //   ▷ compute 𝐭 = 𝐀𝐬1 + 𝐬2
            A_hat.matrix_vector_ntt(&s1_hat)
        };

        let (t1, mut t0) = {
            // scope for t
            let mut t = t_hat;
            t.inv_ntt();
            t.add_vector_ntt(&s2);
            t.conditional_add_q();

            // 6: (𝐭1, 𝐭0) ← Power2Round(𝐭)
            //   ▷ compress 𝐭
            //   ▷ PowerTwoRound is applied componentwise (see explanatory text in Section 7.4)
            power_2_round_vec::<k>(&t)
        };

        // 8: 𝑝𝑘 ← pkEncode(𝜌, 𝐭1)
        let pk = PK::new(rho, t1);

        // 9: 𝑡𝑟 ← H(𝑝𝑘, 64)
        let tr = pk.compute_tr();

        // 10: 𝑠𝑘 ← skEncode(𝜌, 𝐾, 𝑡𝑟, 𝐬1, 𝐬2, 𝐭0)
        //   ▷ 𝐾 and 𝑡𝑟 are for use in signing
        // Deviation from the FIPS:
        //   Hold on to s1, s2, t0 in ntt form
        //   Note: the result here is not necessarily in reduced form, but since .reduce() is expensive,
        //   we'll save that for the encode() operation since that's the only place that it matters
        //   to have them in normalized form.
        s2.ntt();
        t0.ntt();
        // let sk = SK::new(&rho, &K, &tr, &s1_hat, &s2, &t0, Some(seed.clone()));
        let sk = SK::new(rho, K, tr, s1_hat, s2, t0, Some(seed.clone()));

        // Clear the secret data before returning memory to the OS
        //   (SK::new() copies all values)
        rho.fill(0u8);
        K.fill(0u8);
        // tr is public data, does not need to be zeroized
        // s1, s2, t0 are all Vectors of Polynomials, so implement a zeroizing Drop

        // 11: return (𝑝𝑘, 𝑠𝑘)
        Ok((pk, sk))
    }

    /// Algorithm 7 ML-DSA.Sign_internal(𝑠𝑘, 𝑀′, 𝑟𝑛𝑑)
    /// modified to take an externally-computed mu instead of M', and to take the public matrix A_hat
    fn sign_internal(
        sk: &SK,
        A_hat: &Matrix<k, l>,
        mu: &[u8; 64],
        rnd: [u8; 32],
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError> {
        output.fill(0);

        // 1: (𝜌, 𝐾, 𝑡𝑟, 𝐬1, 𝐬2, 𝐭0) ← skDecode(𝑠𝑘)
        // 2: 𝐬1̂_hat ← NTT(𝐬1)
        // 3: 𝐬2̂_hat ← NTT(𝐬2)
        // 4: 𝐭0̂_hat ← NTT(𝐭0)̂
        // Already done -- the sk struct is already decoded and in NTT form

        // 5: 𝐀_hat ← ExpandA(𝜌)
        // We're doing an optimization where the user can pre-expand A_hat within the
        // public key object for faster repeated encapsulations against this public key.

        // 6: 𝜇 ← H(BytesToBits(𝑡𝑟)||𝑀 ′, 64)
        // skip: mu has already been provided

        let mut rho_p_p: [u8; 64] = {
            // scope for h
            // 7: 𝜌″ ← H(𝐾||𝑟𝑛𝑑||𝜇, 64)
            let mut h = H::new();
            h.absorb(sk.K());
            h.absorb(&rnd);
            h.absorb(mu);
            let mut rho_p_p = [0u8; 64];
            h.squeeze_out(&mut rho_p_p);

            rho_p_p
        };

        // 8: 𝜅 ← 0
        //  ▷ initialize counter 𝜅
        let mut kappa: u16 = 0;

        // 9: (𝐳, 𝐡) ← ⊥
        // handled in the loop

        // 10: while (𝐳, 𝐡) = ⊥ do
        //  ▷ rejection sampling loop

        // these need to be outside the loop because they form the encoded signature value
        let mut sig_val_c_tilde = [0u8; LAMBDA_over_4];
        let mut sig_val_z: Vector<l>;
        let mut sig_val_h: Vector<k>;
        loop {
            // FIPS 204 s. 6.2 allows:
            //   "Implementations may limit the number of iterations in this loop to not exceed a finite maximum value."
            // mutants note: there is no test for this because we don't know of a KAT that will exceed this limit.
            if kappa > 1000 * k as u16 {
                return Err(SignatureError::GenericError(
                    "Rejection sampling loop exceeded max iterations, try again with a different signing nonce.",
                ));
            }

            // 11: 𝐲 ∈ 𝑅^ℓ ← ExpandMask(𝜌″, 𝜅)
            let mut y = expand_mask::<l, GAMMA1, GAMMA1_MASK_LEN>(&rho_p_p, kappa);

            let w = {
                // scope for y_hat
                // 12: 𝐰 ← NTT−1(𝐀_hat * NTT(𝐲))
                let mut y_hat = y.clone();
                y_hat.ntt();
                let mut w = A_hat.matrix_vector_ntt(&y_hat);
                w.inv_ntt();
                w.conditional_add_q();
                w
            };

            // 13: 𝐰1 ← HighBits(𝐰)
            //  ▷ signer’s commitment
            let w1 = w.high_bits::<GAMMA2>();

            {
                // scope for h
                // 15: 𝑐_tilde ← H(𝜇||w1Encode(𝐰1), 𝜆/4)
                //  ▷ commitment hash
                let mut hash = H::new();
                hash.absorb(mu);
                w1.w1_encode_and_hash::<POLY_W1_PACKED_LEN>(&mut hash);
                hash.squeeze_out(&mut sig_val_c_tilde);
            }

            // 16: 𝑐 ∈ 𝑅𝑞 ← SampleInBall(c_tilde)
            //  ▷ verifier’s challenge
            let c_hat = {
                // scope for c
                let mut c = sample_in_ball::<LAMBDA_over_4, TAU>(&sig_val_c_tilde);

                // 17: 𝑐_hat ← NTT(𝑐)
                c.ntt();
                c
            };

            // 18: ⟨⟨𝑐𝐬1⟩⟩ ← NTT−1(𝑐_hat * 𝐬1_hat)
            //  Note: <<.>> in FIPS 204 means that this value will be used again later, so you should hang on to it.
            let mut cs1 = sk.s1_hat().scalar_vector_ntt(&c_hat);
            cs1.inv_ntt();

            // 20: 𝐳 ← 𝐲 + ⟨⟨𝑐𝐬1⟩⟩
            y.add_vector_ntt(&cs1);
            sig_val_z = y;

            // 23 (first half): if ||𝐳||∞ ≥ 𝛾1 − 𝛽 or ||𝐫0||∞ ≥ 𝛾2 − 𝛽 then (z, h) ← ⊥
            //  ▷ validity checks
            // out-of-order on purpose for performance reasons:
            //   might as well do the rejection sampling check before any extra heavy computation
            if sig_val_z.check_norm::<GAMMA1_MINUS_BETA>() {
                kappa += l as u16;
                continue;
            };

            // 19: ⟨⟨𝑐𝐬2⟩⟩ ← NTT−1(𝑐_hat * 𝐬2̂_hat)
            let mut cs2 = sk.s2_hat().scalar_vector_ntt(&c_hat);
            cs2.inv_ntt();

            // 21: 𝐫0 ← LowBits(𝐰 − ⟨⟨𝑐𝐬2⟩⟩)
            let mut r0 = w.sub_vector(&cs2).low_bits::<GAMMA2>();

            // 23 (second half): if ||𝐳||∞ ≥ 𝛾1 − 𝛽 or ||𝐫0||∞ ≥ 𝛾2 − 𝛽 then (z, h) ← ⊥
            //  ▷ validity checks
            //  Note: this could be further optimized by using the optimization described in
            //  https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf section 5.1:
            //    "instead of computing (r1, r0) = Decomposeq (w − cs2, α)
            //      and checking whether ‖r0‖∞ < γ2 − β and r1 = w1, it is equivalent to just check that
            //      ‖w0 − cs2‖∞ < γ2 − β, where w0 is the low part of w. If this check passes, w0 − cs2
            //      is the low part of w − cs2."
            if r0.check_norm::<GAMMA2_MINUS_BETA>() {
                kappa += l as u16;
                continue;
            };

            // 25: ⟨⟨𝑐𝐭0⟩⟩ ← NTT−1(𝑐_hat * 𝐭0̂_hat)
            let mut ct0 = sk.t0_hat().scalar_vector_ntt(&c_hat);
            ct0.inv_ntt();

            // 28 (first half): if ||⟨⟨𝑐𝐭0⟩⟩||∞ ≥ 𝛾2 or the number of 1’s in 𝐡 is greater than 𝜔, then (z, h) ← ⊥
            // out-of-order on purpose for performance reasons:
            //   might as well do the rejection sampling check before any extra heavy computation
            // mutants note: there is currently no unit test that triggers this branch
            if ct0.check_norm::<GAMMA2>() {
                kappa += l as u16;
                continue;
            };

            // 26: 𝐡 ← MakeHint(−⟨⟨𝑐𝐭0⟩⟩, 𝐰 − ⟨⟨𝑐𝐬2⟩⟩ + ⟨⟨𝑐𝐭0⟩⟩)
            //  ▷ Signer’s hint
            r0.add_vector_ntt(&ct0);
            r0.conditional_add_q();
            let hint_hamming_weight: i32;
            sig_val_h = {
                // scope for hint
                let (hint, inner_hint_hamming_weight) = make_hint_vecs::<k, GAMMA2>(&r0, &w1);
                hint_hamming_weight = inner_hint_hamming_weight;
                hint
            };

            // 28 (second half): if ||⟨⟨𝑐𝐭0⟩⟩||∞ ≥ 𝛾2 or the number of 1’s in 𝐡 is greater than 𝜔, then (z, h) ← ⊥
            // mutants note: there is no test KAT that triggers this branch
            if hint_hamming_weight > OMEGA {
                kappa += l as u16;
                continue;
            };

            break;
        }

        // zeroize rho_p_p before returning it to the OS
        rho_p_p.fill(0u8);

        // sig_encode does not necessarily write to all bytes of the output, so just to be safe:
        output.fill(0u8);

        // 33: 𝜎 ← sigEncode(𝑐, 𝐳̃ mod±𝑞, 𝐡)
        let bytes_written =
            sig_encode::<GAMMA1, k, l, LAMBDA_over_4, OMEGA, POLY_Z_PACKED_LEN, SIG_LEN>(
                &sig_val_c_tilde, &sig_val_z, &sig_val_h, output,
            );

        Ok(bytes_written)
    }
}

impl<
    const PK_LEN: usize,
    const SK_LEN: usize,
    const SIG_LEN: usize,
    PK: MLDSAPublicKeyTrait<k, l, PK_LEN> + MLDSAPublicKeyInternalTrait<k, PK_LEN>,
    SK: MLDSAPrivateKeyTrait<k, l, ETA, SK_LEN, PK_LEN>
        + MLDSAPrivateKeyInternalTrait<k, l, ETA, SK_LEN, PK_LEN>,
    const TAU: i32,
    const LAMBDA: i32,
    const GAMMA1: i32,
    const GAMMA2: i32,
    const k: usize,
    const l: usize,
    const ETA: usize,
    const BETA: i32,
    const OMEGA: i32,
    const C_TILDE: usize,
    const POLY_Z_PACKED_LEN: usize,
    const POLY_W1_PACKED_LEN: usize,
    const LAMBDA_over_4: usize,
    const GAMMA1_MINUS_BETA: i32,
    const GAMMA2_MINUS_BETA: i32,
    const GAMMA1_MASK_LEN: usize,
> MLDSATrait<PK_LEN, SK_LEN, SIG_LEN, PK, SK, k, l, ETA>
    for MLDSA<
        PK_LEN,
        SK_LEN,
        SIG_LEN,
        PK,
        SK,
        TAU,
        LAMBDA,
        GAMMA1,
        GAMMA2,
        k,
        l,
        ETA,
        BETA,
        OMEGA,
        C_TILDE,
        POLY_Z_PACKED_LEN,
        POLY_W1_PACKED_LEN,
        LAMBDA_over_4,
        GAMMA1_MINUS_BETA,
        GAMMA2_MINUS_BETA,
        GAMMA1_MASK_LEN,
    >
{
    fn keygen_from_seed(seed: &KeyMaterial<32>) -> Result<(PK, SK), SignatureError> {
        Self::keygen_internal(seed)
    }
    fn keygen_from_seed_and_encoded(
        seed: &KeyMaterial<32>,
        encoded_sk: &[u8; SK_LEN],
    ) -> Result<(PK, SK), SignatureError> {
        let (pk, sk) = Self::keygen_internal(seed)?;

        let sk_from_bytes = SK::sk_decode(encoded_sk)?;

        // MLDSAPrivateKey impls PartialEq with a constant-time equality check.
        if sk != sk_from_bytes {
            return Err(SignatureError::KeyGenError("Encoded key does not match generated key"));
        }

        Ok((pk, sk))
    }
    fn keypair_consistency_check(pk: &PK, sk: &SK) -> Result<(), SignatureError> {
        // This is maybe a computationally heavy way to compare them, but it works
        let derived_pk = sk.derive_pk();
        if derived_pk.compute_tr() == pk.compute_tr() {
            Ok(())
        } else {
            Err(SignatureError::ConsistencyCheckFailed())
        }
    }
    fn compute_mu_from_tr(
        tr: &[u8; 64],
        msg: &[u8],
        ctx: Option<&[u8]>,
    ) -> Result<[u8; 64], SignatureError> {
        MuBuilder::compute_mu(tr, msg, ctx)
    }
    fn compute_mu_from_pk(
        pk: &impl MLDSAPublicKeyTrait<k, l, PK_LEN>,
        msg: &[u8],
        ctx: Option<&[u8]>,
    ) -> Result<[u8; 64], SignatureError> {
        MuBuilder::compute_mu(&pk.compute_tr(), msg, ctx)
    }
    fn compute_mu_from_sk(
        sk: &impl MLDSAPrivateKeyTrait<k, l, ETA, SK_LEN, PK_LEN>,
        msg: &[u8],
        ctx: Option<&[u8]>,
    ) -> Result<[u8; 64], SignatureError> {
        MuBuilder::compute_mu(&sk.tr(), msg, ctx)
    }
    fn sign_with_expanded_key(
        sk: &MLDSAPrivateKeyExpanded<k, l, ETA, PK, SK, SK_LEN, PK_LEN>,
        msg: &[u8],
        ctx: Option<&[u8]>,
    ) -> Result<[u8; SIG_LEN], SignatureError> {
        let mu = MuBuilder::compute_mu(&sk.tr(), msg, ctx)?;
        Self::sign_mu(&sk.sk, Some(&sk.A_hat), &mu)
    }

    fn sign_with_expanded_key_out(
        sk: &MLDSAPrivateKeyExpanded<k, l, ETA, PK, SK, SK_LEN, PK_LEN>,
        msg: &[u8],
        ctx: Option<&[u8]>,
        out: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError> {
        out.fill(0);

        let mu = MuBuilder::compute_mu(&sk.tr(), msg, ctx)?;
        Self::sign_mu_out(&sk.sk, Some(&sk.A_hat), &mu, out)
    }

    fn sign_mu(
        sk: &SK,
        A_hat: Option<&Matrix<k, l>>,
        mu: &[u8; 64],
    ) -> Result<[u8; SIG_LEN], SignatureError> {
        let mut out: [u8; SIG_LEN] = [0u8; SIG_LEN];
        Self::sign_mu_out(sk, A_hat, mu, &mut out)?;

        Ok(out)
    }
    fn sign_mu_out(
        sk: &SK,
        A_hat: Option<&Matrix<k, l>>,
        mu: &[u8; 64],
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError> {
        output.fill(0);

        let mut rnd: [u8; MLDSA_RND_LEN] = [0u8; MLDSA_RND_LEN];
        HashDRBG_SHA512::new_from_os().next_bytes_out(&mut rnd)?;

        Self::sign_mu_deterministic_out(sk, A_hat, mu, rnd, output)
    }
    fn sign_mu_with_expanded_key(
        sk: &MLDSAPrivateKeyExpanded<k, l, ETA, PK, SK, SK_LEN, PK_LEN>,
        A_hat: Option<&Matrix<k, l>>,
        mu: &[u8; 64],
    ) -> Result<[u8; SIG_LEN], SignatureError> {
        let mut out: [u8; SIG_LEN] = [0u8; SIG_LEN];
        Self::sign_mu_with_expanded_key_out(sk, A_hat, mu, &mut out)?;

        Ok(out)
    }
    fn sign_mu_with_expanded_key_out(
        sk: &MLDSAPrivateKeyExpanded<k, l, ETA, PK, SK, SK_LEN, PK_LEN>,
        A_hat: Option<&Matrix<k, l>>,
        mu: &[u8; 64],
        out: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError> {
        out.fill(0);

        Self::sign_mu_out(&sk.sk, A_hat, mu, out)
    }

    fn sign_mu_deterministic(
        sk: &SK,
        A_hat: Option<&Matrix<k, l>>,
        mu: &[u8; 64],
        rnd: [u8; 32],
    ) -> Result<[u8; SIG_LEN], SignatureError> {
        let mut out: [u8; SIG_LEN] = [0u8; SIG_LEN];
        Self::sign_mu_deterministic_out(sk, A_hat, mu, rnd, &mut out)?;

        Ok(out)
    }
    fn sign_mu_deterministic_out(
        sk: &SK,
        A_hat: Option<&Matrix<k, l>>,
        mu: &[u8; 64],
        rnd: [u8; 32],
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError> {
        output.fill(0);

        match A_hat {
            Some(A_hat) => Self::sign_internal(sk, A_hat, mu, rnd, output),
            None => Self::sign_internal(sk, &sk.A_hat(), mu, rnd, output),
        }
    }
    fn sign_mu_deterministic_from_seed(
        seed: &KeyMaterial<32>,
        mu: &[u8; 64],
        rnd: [u8; 32],
    ) -> Result<[u8; SIG_LEN], SignatureError> {
        let mut out: [u8; SIG_LEN] = [0u8; SIG_LEN];
        Self::sign_mu_deterministic_from_seed_out(seed, mu, rnd, &mut out)?;
        Ok(out)
    }
    /// This function is a mash-up of keyGen (Algorithm 6) and sign (Algorithm 7)
    /// Although, while this algorithm is a precursor to the lowmemory implementation, I'm not
    /// sure that it actually gains you anything over a keygen_from_seed() followed by a sign(),
    /// and maybe I should change its implementation to that.
    fn sign_mu_deterministic_from_seed_out(
        seed: &KeyMaterial<32>,
        mu: &[u8; 64],
        rnd: [u8; 32],
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError> {
        output.fill(0);

        // This has been kept as clean as possible for correspondence with the FIPS,
        // but things have been moved around so that unnamed scopes can be used to limit how many
        // stack variables are alive at the same time.

        // 1: (𝜌, 𝐾, 𝑡𝑟, 𝐬1, 𝐬2, 𝐭0) ← skDecode(𝑠𝑘)
        // to avoid having all of it in memory at the same time,
        // we're gonna derive what we need as we need it.

        if !(seed.key_type() == KeyType::Seed || seed.key_type() == KeyType::CryptographicRandom)
            || seed.key_len() != 32
        {
            return Err(SignatureError::KeyGenError(
                "Seed must be 32 bytes and KeyType::Seed or KeyType::BytesFullEntropy.",
            ));
        }

        if seed.security_strength() < SecurityStrength::from_bits(LAMBDA as usize) {
            return Err(SignatureError::KeyGenError(
                "Seed SecurityStrength must match algorithm security strength: 128-bit (ML-DSA-44), 192-bit (ML-DSA-65), or 256-bit (ML-DSA-87).",
            ));
        }

        // Alg 7; 6: 𝜇 ← H(BytesToBits(𝑡𝑟)||𝑀 ′, 64)
        // skip: mu has already been provided

        let (rho, mut rho_p_p, s1, s2) = {
            // scope for h
            // derive sk.K
            // Alg 6; 1: (rho, rho_prime, K) <- H(𝜉||IntegerToBytes(𝑘, 1)||IntegerToBytes(ℓ, 1), 128)
            //   ▷ expand seed
            let (rho, rho_prime, K) = {
                let mut h = H::default();
                h.absorb(seed.ref_to_bytes());
                h.absorb(&(k as u8).to_le_bytes());
                h.absorb(&(l as u8).to_le_bytes());
                let mut rho = [0u8; 32];
                let bytes_written = h.squeeze_out(&mut rho);
                debug_assert_eq!(bytes_written, 32);
                let mut rho_prime = [0u8; 64];
                let bytes_written = h.squeeze_out(&mut rho_prime);
                debug_assert_eq!(bytes_written, 64);
                let mut K: [u8; 32] = [0u8; 32];
                let bytes_written = h.squeeze_out(&mut K);
                debug_assert_eq!(bytes_written, 32);

                (rho, rho_prime, K)
            };

            // Alg 7; 7: 𝜌″ ← H(𝐾||𝑟𝑛𝑑||𝜇, 64)
            let rho_p_p = {
                let mut h = H::new();
                h.absorb(&K);
                h.absorb(&rnd);
                h.absorb(mu);
                let mut rho_p_p = [0u8; 64];
                h.squeeze_out(&mut rho_p_p);

                rho_p_p
            };

            // 4: (𝐬1, 𝐬2) ← ExpandS(𝜌′)
            let (s1, s2) = expandS::<k, l, ETA>(&rho_prime);

            (rho, rho_p_p, s1, s2)
        };

        // Alg 7; 5: 𝐀_hat ← ExpandA(𝜌)
        // Note on memory optimization:
        // A_hat consumes a large bit of memory and technically could move inside the loop --
        // -- or even more aggressively, could be derived and multiplied by y_hat row-by-row --
        // But in my unit tests, I see the loop typically execute 1 - 3 times, sometimes as many
        // as 20 or even 80 times. So moving expandA() inside the loop would be a pretty drastic speed-for-memory tradeoff
        // that I'm not willing to make in general, so I leave that as an optimization that people
        // can make on a private fork if you really really need the memory squeeze.
        let A_hat = expandA::<k, l>(&rho);

        // Alg 7; 8: 𝜅 ← 0
        //  ▷ initialize counter 𝜅
        let mut kappa: u16 = 0;

        // Alg 7; 9: (𝐳, 𝐡) ← ⊥
        // handled in the loop

        // Alg 7; 10: while (𝐳, 𝐡) = ⊥ do
        //  ▷ rejection sampling loop

        // these need to be outside the loop because they form the encoded signature value
        let mut sig_val_c_tilde = [0u8; LAMBDA_over_4];
        let mut sig_val_z: Vector<l>;
        let mut sig_val_h: Vector<k>;
        loop {
            // FIPS 204 s. 6.2 allows:
            //   "Implementations may limit the number of iterations in this loop to not exceed a finite maximum value."
            // mutants note: there is no test for this because we don't know of a KAT that will exceed this limit.
            if kappa > 1000 * k as u16 {
                return Err(SignatureError::GenericError(
                    "Rejection sampling loop exceeded max iterations, try again with a different signing nonce.",
                ));
            }

            // Alg 7; 11: 𝐲 ∈ 𝑅^ℓ ← ExpandMask(𝜌″, 𝜅)
            let mut y = expand_mask::<l, GAMMA1, GAMMA1_MASK_LEN>(&rho_p_p, kappa);

            let w = {
                // scope for y_hat
                // Alg 7; 12: 𝐰 ← NTT−1(𝐀_hat * NTT(𝐲))
                let mut y_hat = y.clone();
                y_hat.ntt();
                let mut w = A_hat.matrix_vector_ntt(&y_hat);
                w.inv_ntt();
                w.conditional_add_q();
                w
            };

            // Alg 7; 13: 𝐰1 ← HighBits(𝐰)
            //  ▷ signer’s commitment
            let w1 = w.high_bits::<GAMMA2>();

            {
                // scope for h
                // 15: 𝑐_tilde ← H(𝜇||w1Encode(𝐰1), 𝜆/4)
                //  ▷ commitment hash
                let mut hash = H::new();
                hash.absorb(mu);
                w1.w1_encode_and_hash::<POLY_W1_PACKED_LEN>(&mut hash);
                hash.squeeze_out(&mut sig_val_c_tilde);
            }

            // Alg 7; 16: 𝑐 ∈ 𝑅𝑞 ← SampleInBall(c_tilde)
            //  ▷ verifier’s challenge
            let c_hat = {
                // scope for c
                let mut c = sample_in_ball::<LAMBDA_over_4, TAU>(&sig_val_c_tilde);

                // 17: 𝑐_hat ← NTT(𝑐)
                c.ntt();
                c
            };

            let t_hat: Vector<k>;
            sig_val_z = {
                // scope for s1_hat, cs1
                // Alg 7; 2: 𝐬1̂_hat ← NTT(𝐬1)
                let mut s1_hat = s1.clone();
                s1_hat.ntt();

                y = {
                    // scope for cs1
                    // Alg 7; 18: ⟨⟨𝑐𝐬1⟩⟩ ← NTT−1(𝑐_hat * 𝐬1_hat)
                    //  Note: <<.>> in FIPS 204 means that this value will be used again later, so you should hang on to it.
                    let mut cs1 = s1_hat.scalar_vector_ntt(&c_hat);
                    cs1.inv_ntt();

                    // Alg 7; 20: 𝐳 ← 𝐲 + ⟨⟨𝑐𝐬1⟩⟩
                    y.add_vector_ntt(&cs1);
                    y
                };

                // also, while we have s1_hat in memory, compute t_hat
                // Alg 6; 5: 𝐭 ← NTT−1(𝐀 ∘ NTT(𝐬1)) + 𝐬2
                //   ▷ compute 𝐭 = 𝐀𝐬1 + 𝐬2
                t_hat = A_hat.matrix_vector_ntt(&s1_hat);

                y
            };

            // Alg 7; 23 (first half): if ||𝐳||∞ ≥ 𝛾1 − 𝛽 or ||𝐫0||∞ ≥ 𝛾2 − 𝛽 then (z, h) ← ⊥
            //  ▷ validity checks
            // out-of-order on purpose for performance reasons:
            //   might as well do the rejection sampling check before any extra heavy computation
            if sig_val_z.check_norm::<GAMMA1_MINUS_BETA>() {
                kappa += l as u16;
                continue;
            };

            let t0: Vector<k>;
            let mut r0: Vector<k> = {
                // scope for s2_hat and cs2
                // 3: 𝐬2̂_hat ← NTT(𝐬2)
                let mut s2_hat = s2.clone();
                s2_hat.ntt();

                // 19: ⟨⟨𝑐𝐬2⟩⟩ ← NTT−1(𝑐_hat * 𝐬2̂_hat)
                let mut cs2 = s2_hat.scalar_vector_ntt(&c_hat);
                cs2.inv_ntt();

                // 21: 𝐫0 ← LowBits(𝐰 − ⟨⟨𝑐𝐬2⟩⟩)
                let r0 = w.sub_vector(&cs2).low_bits::<GAMMA2>();

                // while we have s2_hat in scope, derive t0
                let mut t = t_hat;
                t.inv_ntt();
                t.add_vector_ntt(&s2);
                t.conditional_add_q();

                // 6: (𝐭1, 𝐭0) ← Power2Round(𝐭)
                //   ▷ compress 𝐭
                //   ▷ PowerTwoRound is applied componentwise (see explanatory text in Section 7.4)
                let (_t1tmp, t0tmp) = power_2_round_vec::<k>(&t);
                t0 = t0tmp;

                r0
            };

            // Alg 7; 23 (second half): if ||𝐳||∞ ≥ 𝛾1 − 𝛽 or ||𝐫0||∞ ≥ 𝛾2 − 𝛽 then (z, h) ← ⊥
            //  ▷ validity checks
            if r0.check_norm::<GAMMA2_MINUS_BETA>() {
                // mutants note: mutants thinks you can replace this with -=, but in practice that makes
                //               the rejection sampling loop go forever, so is a false positive.
                kappa += l as u16;
                continue;
            };

            let ct0: Vector<k> = {
                // scope for t0_hat
                // 4: 𝐭0̂_hat ← NTT(𝐭0)̂
                let mut t0_hat = t0.clone();
                t0_hat.ntt();

                // 25: ⟨⟨𝑐𝐭0⟩⟩ ← NTT−1(𝑐_hat * 𝐭0̂_hat )
                let mut ct0 = t0_hat.scalar_vector_ntt(&c_hat);
                ct0.inv_ntt();
                ct0
            };

            // Alg 7; 28 (first half): if ||⟨⟨𝑐𝐭0⟩⟩||∞ ≥ 𝛾2 or the number of 1’s in 𝐡 is greater than 𝜔, then (z, h) ← ⊥
            // out-of-order on purpose for performance reasons:
            //   might as well do the rejection sampling check before any extra heavy computation
            // mutants note: there is currently no unit test that triggers this branch
            if ct0.check_norm::<GAMMA2>() {
                kappa += l as u16;
                continue;
            };

            // Alg 7; 26: 𝐡 ← MakeHint(−⟨⟨𝑐𝐭0⟩⟩, 𝐰 − ⟨⟨𝑐𝐬2⟩⟩ + ⟨⟨𝑐𝐭0⟩⟩)
            //  ▷ Signer’s hint
            r0.add_vector_ntt(&ct0);
            r0.conditional_add_q();
            let hint_hamming_weight: i32;
            sig_val_h = {
                // scope for hint
                let (hint, inner_hint_hamming_weight) = make_hint_vecs::<k, GAMMA2>(&r0, &w1);
                hint_hamming_weight = inner_hint_hamming_weight;
                hint
            };

            // Alg 7; 28 (second half): if ||⟨⟨𝑐𝐭0⟩⟩||∞ ≥ 𝛾2 or the number of 1’s in 𝐡 is greater than 𝜔, then (z, h) ← ⊥
            // mutants note: there is currently no unit test that triggers this branch
            if hint_hamming_weight > OMEGA {
                kappa += l as u16;
                continue;
            };

            break;
        }

        // zeroize rho_p_p before returning it to the OS
        rho_p_p.fill(0u8);

        // sig_encode does not necessarily write to all bytes of the output, so just to be safe:
        output.fill(0u8);

        // Alg 7; 33: 𝜎 ← sigEncode(𝑐, 𝐳̃ mod±𝑞, 𝐡)
        let bytes_written =
            sig_encode::<GAMMA1, k, l, LAMBDA_over_4, OMEGA, POLY_Z_PACKED_LEN, SIG_LEN>(
                &sig_val_c_tilde, &sig_val_z, &sig_val_h, output,
            );

        Ok(bytes_written)
    }
    fn set_signer_rnd(&mut self, rnd: [u8; 32]) {
        self.signer_rnd = Some(rnd);
    }
    fn sign_init_from_seed(
        seed: &KeyMaterial<32>,
        ctx: Option<&[u8]>,
    ) -> Result<Self, SignatureError> {
        let (_pk, sk) = Self::keygen_from_seed(seed)?;
        Ok(Self {
            _phantom: PhantomData,
            mu_builder: MuBuilder::do_init(&sk.tr(), ctx)?,
            signer_rnd: None,
            sk: None,
            seed: Some(seed.clone()),
            pk: None,
        })
    }

    fn verify_with_expanded_key(
        pk: &MLDSAPublicKeyExpanded<k, l, PK, PK_LEN>,
        msg: &[u8],
        ctx: Option<&[u8]>,
        sig: &[u8],
    ) -> Result<(), SignatureError> {
        let mu = MuBuilder::compute_mu(&pk.compute_tr(), msg, ctx)?;
        let sig: &[u8; SIG_LEN] = sig.try_into().map_err(|_| {
            SignatureError::LengthError("Signature value is not the correct length.")
        })?;
        Self::verify_mu_internal(&pk.pk, &pk.A_hat(), &mu, sig)
            .then_some(())
            .ok_or(SignatureError::SignatureVerificationFailed)
    }

    /// Algorithm 8 ML-DSA.Verify_internal(𝑝𝑘, 𝑀′, 𝜎)
    /// Internal function to verify a signature 𝜎 for a formatted message 𝑀′ .
    /// Input: Public key 𝑝𝑘 ∈ 𝔹32+32𝑘(bitlen (𝑞−1)−𝑑) and message 𝑀′ ∈ {0, 1}∗ .
    /// Input: Signature 𝜎 ∈ 𝔹𝜆/4+ℓ⋅32⋅(1+bitlen (𝛾1−1))+𝜔+𝑘.
    fn verify_mu_internal(
        pk: &PK,
        A_hat: &Matrix<k, l>,
        mu: &[u8; 64],
        sig: &[u8; SIG_LEN],
    ) -> bool {
        // 1: (𝜌, 𝐭1) ← pkDecode(𝑝𝑘)
        // Already done -- the pk struct is already decoded

        // 2: (𝑐_tilde, 𝐳, 𝐡) ← sigDecode(𝜎)
        //  ▷ signer’s commitment hash c_tilde, response 𝐳, and hint 𝐡
        // 3: if 𝐡 = ⊥ then return false
        let (c_tilde, z, h) = match sig_decode::<
            GAMMA1,
            k,
            l,
            LAMBDA_over_4,
            OMEGA,
            POLY_Z_PACKED_LEN,
            SIG_LEN,
        >(&sig)
        {
            Ok((c_tilde, z, h)) => (c_tilde, z, h),
            Err(_) => return false,
        };

        // 13 (first half) return [[ ||𝐳||∞ < 𝛾1 − 𝛽]]
        if z.check_norm::<GAMMA1_MINUS_BETA>() {
            return false;
        }

        // 5: 𝐀 ← ExpandA(𝜌)
        //   ▷ 𝐀 is generated and stored in NTT representation as 𝐀
        // We're doing an optimization where the user can pre-expand A_hat within the
        // public key object for faster repeated encapsulations against this public key.

        // 6: 𝑡𝑟 ← H(𝑝𝑘, 64)
        // 7: 𝜇 ← (H(BytesToBits(𝑡𝑟)||𝑀 ′, 64))
        //   ▷ message representative that may optionally be
        //     computed in a different cryptographic module
        // skip because this function is being handed mu

        // 8: 𝑐 ∈ 𝑅𝑞 ← SampleInBall(c_tilde)
        let c_hat = {
            let mut c = sample_in_ball::<LAMBDA_over_4, TAU>(&c_tilde);
            c.ntt();

            c
        };

        // 9: 𝐰′_approx ← NTT−1(𝐀_hat ∘ NTT(𝐳) − NTT(𝑐) ∘ NTT(𝐭1 ⋅ 2^𝑑))
        //   broken out for clarity:
        //   NTT−1(
        //      𝐀_hat ∘ NTT(𝐳) −
        //                  NTT(𝑐) ∘ NTT(𝐭1 ⋅ 2^𝑑)
        //   )
        // ▷ 𝐰'_approx = 𝐀𝐳 − 𝑐𝐭1 ⋅ 2^𝑑
        // weird nested scoping is to reduce peak stack memory usage
        let w1p = {
            let Az = {
                let mut z_hat = z.clone();
                z_hat.ntt();
                A_hat.matrix_vector_ntt(&z_hat)
            };
            let ct1 = {
                // potential optimization -- pre-compute this on key load?
                let mut t1_shift_hat = pk.t1().shift_left::<d>();
                t1_shift_hat.ntt();
                t1_shift_hat.scalar_vector_ntt(&c_hat)
            };
            let mut wp_approx = Az.sub_vector(&ct1);
            wp_approx.inv_ntt();
            wp_approx.conditional_add_q();

            // 10: 𝐰1′ ← UseHint(𝐡, 𝐰'_approx)
            // ▷ reconstruction of signer’s commitment
            use_hint_vecs::<k, GAMMA2>(&h, &wp_approx)
        };
        // 12: 𝑐_tilde_p ← H(𝜇||w1Encode(𝐰1'), 𝜆/4)
        // ▷ hash it; this should match 𝑐_tilde
        let c_tilde_p = {
            let mut c_tilde_p = [0u8; LAMBDA_over_4];
            let mut hash = H::new();
            hash.absorb(mu);
            w1p.w1_encode_and_hash::<POLY_W1_PACKED_LEN>(&mut hash);
            hash.squeeze_out(&mut c_tilde_p);

            c_tilde_p
        };

        // verification probably doesn't technically need to be constant-time, but why not?
        // 13 (second half): return [[ ||𝐳||∞ < 𝛾1 − 𝛽]] and [[𝑐 ̃ = 𝑐′ ]]
        bouncycastle_utils::ct::ct_eq_bytes(&c_tilde, &c_tilde_p)
    }
}

/// Trait for all three of the ML-DSA algorithm variants.
pub trait MLDSATrait<
    const PK_LEN: usize,
    const SK_LEN: usize,
    const SIG_LEN: usize,
    PK: MLDSAPublicKeyTrait<k, l, PK_LEN> + MLDSAPublicKeyInternalTrait<k, PK_LEN>,
    SK: MLDSAPrivateKeyTrait<k, l, ETA, SK_LEN, PK_LEN>
        + MLDSAPrivateKeyInternalTrait<k, l, ETA, SK_LEN, PK_LEN>,
    const k: usize,
    const l: usize,
    const ETA: usize,
>: Sized
{
    /// Imports a secret key from a seed.
    fn keygen_from_seed(seed: &KeyMaterial<32>) -> Result<(PK, SK), SignatureError>;
    /// Imports a secret key from both a seed and an encoded_sk.
    ///
    /// This is a convenience function to expand the key from seed and compare it against
    /// the provided `encoded_sk` using a constant-time equality check.
    /// If everything checks out, the secret key is returned fully populated with pk and seed.
    /// If the provided key and derived key don't match, an error is returned.
    fn keygen_from_seed_and_encoded(
        seed: &KeyMaterial<32>,
        encoded_sk: &[u8; SK_LEN],
    ) -> Result<(PK, SK), SignatureError>;
    /// Given a public key and a secret key, check that the public key matches the secret key.
    /// This is a sanity check that the public key was generated correctly from the secret key.
    ///
    /// At the current time, this is only possible if `sk` either contains a public key (in which case
    /// the two pk's are encoded and compared for byte equality), or if `sk` contains a seed
    /// (in which case a keygen_from_seed is run and then the pk's compared).
    ///
    /// Returns either `()` or [SignatureError::ConsistencyCheckFailed].
    fn keypair_consistency_check(pk: &PK, sk: &SK) -> Result<(), SignatureError>;
    /// This provides the first half of the "External Mu" interface to ML-DSA which is described
    /// in, and allowed under, NIST's FAQ that accompanies FIPS 204.
    ///
    /// This function, together with [MLDSATrait::sign_mu] perform a complete ML-DSA signature which is indistinguishable
    /// from one produced by the one-shot sign APIs.
    ///
    /// The utility of this function is exactly as described
    /// on Line 6 of Algorithm 7 of FIPS 204:
    ///
    ///    message representative that may optionally be computed in a different cryptographic module
    ///
    /// The utility is when an extremely large message needs to be signed, where the message exists on one
    /// computing system and the private key to sign it is held on another and either the transfer time or bandwidth
    /// causes operational concerns (this is common for example with network HSMs or sending large messages
    /// to be signed by a smartcard communicating over near-field radio). Another use case is if the
    /// contents of the message are sensitive and the signer does not want to transmit the message itself
    /// for fear of leaking it via proxy logging and instead would prefer to only transmit a hash of it.
    ///
    /// Since "External Mu" mode is well-defined by FIPS 204 and allowed by NIST, the mu value produced here
    /// can be used with many hardware crypto modules.
    ///
    /// This "External Mu" mode of ML-DSA provides an alternative to the HashML-DSA algorithm in that it
    /// allows the message to be externally pre-hashed, however, unlike HashML-DSA, this is merely an optimization
    /// between the application holding the to-be-signed message and the cryptographic module holding the private key
    /// -- in particular, while HashML-DSA requires the verifier to know whether ML-DSA or HashML-DSA was used to sign
    /// the message, both "direct" ML-DSA and "External Mu" signatures can be verified with a standard
    /// ML-DSA verifier.
    ///
    /// This function requires the public key hash `tr`, which can be computed from the public key
    /// using [MLDSAPublicKeyTrait::compute_tr].
    ///
    /// For a streaming version of this, see [MuBuilder].
    fn compute_mu_from_tr(
        tr: &[u8; 64],
        msg: &[u8],
        ctx: Option<&[u8]>,
    ) -> Result<[u8; 64], SignatureError>;
    /// Same as [MLDSATrait::compute_mu_from_tr], but extracts tr from the public key.
    fn compute_mu_from_pk(
        pk: &impl MLDSAPublicKeyTrait<k, l, PK_LEN>,
        msg: &[u8],
        ctx: Option<&[u8]>,
    ) -> Result<[u8; 64], SignatureError>;
    /// Same as [MLDSATrait::compute_mu_from_tr], but extracts tr from the private key.
    // dev note: defined sk this way so that it accepts either MLDSAPrivateKey or MLDSAPRivateKeyExpanded
    fn compute_mu_from_sk(
        sk: &impl MLDSAPrivateKeyTrait<k, l, ETA, SK_LEN, PK_LEN>,
        msg: &[u8],
        ctx: Option<&[u8]>,
    ) -> Result<[u8; 64], SignatureError>;
    /// Same as [Signer::sign], but signs from an [MLDSAPrivateKeyExpanded].
    fn sign_with_expanded_key(
        sk: &MLDSAPrivateKeyExpanded<k, l, ETA, PK, SK, SK_LEN, PK_LEN>,
        msg: &[u8],
        ctx: Option<&[u8]>,
    ) -> Result<[u8; SIG_LEN], SignatureError>;
    /// Same as [MLDSATrait::sign_with_expanded_key], but takes an output array.
    fn sign_with_expanded_key_out(
        sk: &MLDSAPrivateKeyExpanded<k, l, ETA, PK, SK, SK_LEN, PK_LEN>,
        msg: &[u8],
        ctx: Option<&[u8]>,
        out: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError>;
    /// Performs an ML-DSA signature using the provided external message representative `mu`.
    /// This implements FIPS 204 Algorithm 7 with line 6 removed; a modification that is allowed by both
    /// FIPS 204 itself, as well as subsequent FAQ documents.
    /// This mode uses randomized signing (called "hedged mode" in FIPS 204) using an internal RNG.
    fn sign_mu(
        sk: &SK,
        A_hat: Option<&Matrix<k, l>>,
        mu: &[u8; 64],
    ) -> Result<[u8; SIG_LEN], SignatureError>;
    /// Performs an ML-DSA signature using the provided external message representative `mu`.
    /// This implements FIPS 204 Algorithm 7 with line 6 removed; a modification that is allowed by both
    /// FIPS 204 itself, as well as subsequent FAQ documents.
    /// This mode uses randomized signing (called "hedged mode" in FIPS 204) using an internal RNG.
    ///
    /// Optionally takes the public matrix A_hat which can be extracted from either the public key or private
    /// key object -- although the more ergonomic way to use this functionality is via the
    /// [MLDSAPublicKeyExpanded] object.
    ///
    /// Returns the number of bytes written to the output buffer. Can be called with an oversized buffer.
    fn sign_mu_out(
        sk: &SK,
        A_hat: Option<&Matrix<k, l>>,
        mu: &[u8; 64],
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError>;
    /// Same as [MLDSATrait::sign_mu], but signs from an [MLDSAPrivateKeyExpanded].
    fn sign_mu_with_expanded_key(
        sk: &MLDSAPrivateKeyExpanded<k, l, ETA, PK, SK, SK_LEN, PK_LEN>,
        A_hat: Option<&Matrix<k, l>>,
        mu: &[u8; 64],
    ) -> Result<[u8; SIG_LEN], SignatureError>;
    /// Same as [MLDSATrait::sign_mu_out], but signs from an [MLDSAPrivateKeyExpanded].
    fn sign_mu_with_expanded_key_out(
        sk: &MLDSAPrivateKeyExpanded<k, l, ETA, PK, SK, SK_LEN, PK_LEN>,
        A_hat: Option<&Matrix<k, l>>,
        mu: &[u8; 64],
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError>;
    /// Algorithm 7 ML-DSA.Sign_internal(𝑠𝑘, 𝑀′, 𝑟𝑛𝑑)
    /// (modified to take an externally-computed mu instead of M')
    ///
    /// Performs an ML-DSA signature using the provided external message representative `mu`.
    /// This implements FIPS 204 Algorithm 7 with line 6 removed; a modification that is allowed by both
    /// FIPS 204 itself, as well as subsequent FAQ documents.
    ///
    /// Optionally takes the public matrix A_hat which can be extracted from either the public key or private
    /// key object -- although the more ergonomic way to use this functionality is via the
    /// [MLDSAPublicKeyExpanded] object.
    ///
    /// Security note about deterministic mode:
    /// This mode exposes deterministic signing (called "hedged mode" and allowed by FIPS 204).
    /// The ML-DSA algorithm is considered safe to use in deterministic mode, but be aware that
    /// the responsibility is on you to ensure that your nonce `rnd` is unique per signature.
    /// If not, you may lose some privacy properties; for example it becomes easy to tell if a signer
    /// has signed the same message twice or two different messagase, or to tell if the same message
    /// has been signed by the same signer twice or two different signers.
    ///
    /// Since `rnd` should be either a per-signature nonce, or a fixed value, therefore, to help
    /// prevent accidental nonce reuse, this function moves `rnd`.
    fn sign_mu_deterministic(
        sk: &SK,
        A_hat: Option<&Matrix<k, l>>,
        mu: &[u8; 64],
        rnd: [u8; 32],
    ) -> Result<[u8; SIG_LEN], SignatureError>;
    /// Algorithm 7 ML-DSA.Sign_internal(𝑠𝑘, 𝑀′, 𝑟𝑛𝑑)
    /// (modified to take an externally-computed mu instead of M')
    ///
    /// Performs an ML-DSA signature using the provided external message representative `mu`.
    /// This implements FIPS 204 Algorithm 7 with line 6 removed; a modification that is allowed by both
    /// FIPS 204 itself, as well as subsequent FAQ documents.
    /// This mode exposes deterministic signing (called "hedged mode" in FIPS 204) using an internal RNG.
    ///
    /// This mode exposes the signing nonce `rnd` either for users who wish to source the signing
    /// nonce from a source other than the library's default internal RNG, or who wish to use the
    /// "deterministic mode" defined in FIPS 204 by providing `rnd = [0u8; 32]`.
    /// In order to help prevent against accidental nonce reuse, this function moves `rnd` instead
    /// of taking it by reference.
    ///
    /// Security note about deterministic mode:
    /// This mode exposes deterministic signing (called "hedged mode" and allowed by FIPS 204).
    /// The ML-DSA algorithm is considered safe to use in deterministic mode, but be aware that
    /// the responsibility is on you to ensure that your nonce `rnd` is unique per signature.
    /// If not, you may lose some privacy properties; for example, it becomes easy to tell if a signer
    /// has signed the same message twice or two different messages, or to tell if the same message
    /// has been signed by the same signer twice or two different signers.
    ///
    /// Returns the number of bytes written to the output buffer. Can be called with an oversized buffer.
    fn sign_mu_deterministic_out(
        sk: &SK,
        A_hat: Option<&Matrix<k, l>>,
        mu: &[u8; 64],
        rnd: [u8; 32],
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError>;
    /// This contains a heavily-optimized combined keygen() and sign() which greatly reduces peak
    /// memory usage by never having the full secret key in memory at the same time,
    /// and by deriving intermediate values piece-wise as needed.
    fn sign_mu_deterministic_from_seed(
        seed: &KeyMaterial<32>,
        mu: &[u8; 64],
        rnd: [u8; 32],
    ) -> Result<[u8; SIG_LEN], SignatureError>;
    /// This contains a heavily-optimized combined keygen() and sign() which greatly reduces peak
    /// memory usage by never having the full secret key in memory at the same time,
    /// and by deriving intermediate values piece-wise as needed.
    fn sign_mu_deterministic_from_seed_out(
        seed: &KeyMaterial<32>,
        mu: &[u8; 64],
        rnd: [u8; 32],
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError>;
    /// To be used for deterministic signing in conjunction with the [MLDSA44::sign_init], [MLDSA44::sign_update], and [MLDSA44::sign_final] flow.
    /// Can be set anywhere after [MLDSA44::sign_init] and before [MLDSA44::sign_final].
    fn set_signer_rnd(&mut self, rnd: [u8; 32]);
    /// Alternative initialization of the streaming signer where you have your private key
    /// as a seed and you want to delay its expansion as late as possible for memory-usage reasons.
    fn sign_init_from_seed(
        seed: &KeyMaterial<32>,
        ctx: Option<&[u8]>,
    ) -> Result<Self, SignatureError>;
    /// Same as [SignatureVerifier::verify], but signs from an expanded key object.
    fn verify_with_expanded_key(
        pk: &MLDSAPublicKeyExpanded<k, l, PK, PK_LEN>,
        msg: &[u8],
        ctx: Option<&[u8]>,
        sig: &[u8],
    ) -> Result<(), SignatureError>;
    /// Algorithm 8 ML-DSA.Verify_internal(𝑝𝑘, 𝑀′, 𝜎)
    /// Internal function to verify a signature 𝜎 for a formatted message 𝑀′ .
    /// Input: Public key 𝑝𝑘 ∈ 𝔹32+32𝑘(bitlen (𝑞−1)−𝑑) and message 𝑀′ ∈ {0, 1}∗ .
    /// Input: Signature 𝜎 ∈ 𝔹𝜆/4+ℓ⋅32⋅(1+bitlen (𝛾1−1))+𝜔+𝑘.
    fn verify_mu_internal(
        pk: &PK,
        A_hat: &Matrix<k, l>,
        mu: &[u8; 64],
        sig: &[u8; SIG_LEN],
    ) -> bool;
}

impl<
    const PK_LEN: usize,
    const SK_LEN: usize,
    const SIG_LEN: usize,
    PK: MLDSAPublicKeyTrait<k, l, PK_LEN> + MLDSAPublicKeyInternalTrait<k, PK_LEN>,
    SK: MLDSAPrivateKeyTrait<k, l, ETA, SK_LEN, PK_LEN>
        + MLDSAPrivateKeyInternalTrait<k, l, ETA, SK_LEN, PK_LEN>,
    const TAU: i32,
    const LAMBDA: i32,
    const GAMMA1: i32,
    const GAMMA2: i32,
    const k: usize,
    const l: usize,
    const ETA: usize,
    const BETA: i32,
    const OMEGA: i32,
    const C_TILDE: usize,
    const POLY_Z_PACKED_LEN: usize,
    const POLY_W1_PACKED_LEN: usize,
    const LAMBDA_over_4: usize,
    const GAMMA1_MINUS_BETA: i32,
    const GAMMA2_MINUS_BETA: i32,
    const GAMMA1_MASK_LEN: usize,
> Signer<SK, SK_LEN, SIG_LEN>
    for MLDSA<
        PK_LEN,
        SK_LEN,
        SIG_LEN,
        PK,
        SK,
        TAU,
        LAMBDA,
        GAMMA1,
        GAMMA2,
        k,
        l,
        ETA,
        BETA,
        OMEGA,
        C_TILDE,
        POLY_Z_PACKED_LEN,
        POLY_W1_PACKED_LEN,
        LAMBDA_over_4,
        GAMMA1_MINUS_BETA,
        GAMMA2_MINUS_BETA,
        GAMMA1_MASK_LEN,
    >
{
    fn sign(sk: &SK, msg: &[u8], ctx: Option<&[u8]>) -> Result<[u8; SIG_LEN], SignatureError> {
        let mut out = [0u8; SIG_LEN];
        Self::sign_out(sk, msg, ctx, &mut out)?;

        Ok(out)
    }

    fn sign_out(
        sk: &SK,
        msg: &[u8],
        ctx: Option<&[u8]>,
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError> {
        output.fill(0);

        let mu = MuBuilder::compute_mu(&sk.tr(), msg, ctx)?;
        let bytes_written = Self::sign_mu_out(sk, None, &mu, output)?;

        Ok(bytes_written)
    }

    fn sign_init(sk: &SK, ctx: Option<&[u8]>) -> Result<Self, SignatureError> {
        Ok(Self {
            _phantom: PhantomData,
            mu_builder: MuBuilder::do_init(&sk.tr(), ctx)?,
            signer_rnd: None,
            sk: Some(sk.clone()),
            seed: None,
            pk: None,
        })
    }

    fn sign_update(&mut self, msg_chunk: &[u8]) {
        self.mu_builder.do_update(msg_chunk);
    }

    fn sign_final(self) -> Result<[u8; SIG_LEN], SignatureError> {
        let mut out = [0u8; SIG_LEN];
        self.sign_final_out(&mut out)?;
        Ok(out)
    }

    fn sign_final_out(self, output: &mut [u8; SIG_LEN]) -> Result<usize, SignatureError> {
        let mu = self.mu_builder.do_final();

        if self.sk.is_none() && self.seed.is_none() {
            return Err(SignatureError::GenericError(
                "Somehow you managed to construct a streaming signer without a private key, impressive!",
            ));
        }

        output.fill(0);

        if self.sk.is_some() {
            if self.signer_rnd.is_none() {
                Self::sign_mu_out(&self.sk.unwrap(), None, &mu, output)
            } else {
                Self::sign_mu_deterministic_out(
                    &self.sk.unwrap(),
                    None,
                    &mu,
                    self.signer_rnd.unwrap(),
                    output,
                )
            }
        } else if self.seed.is_some() {
            let rnd = if self.signer_rnd.is_some() {
                self.signer_rnd.unwrap()
            } else {
                let mut rnd: [u8; MLDSA_RND_LEN] = [0u8; MLDSA_RND_LEN];
                HashDRBG_SHA512::new_from_os().next_bytes_out(&mut rnd)?;
                rnd
            };
            Self::sign_mu_deterministic_from_seed_out(&self.seed.unwrap(), &mu, rnd, output)
        } else {
            unreachable!()
        }
    }
}

impl<
    const PK_LEN: usize,
    const SK_LEN: usize,
    const SIG_LEN: usize,
    PK: MLDSAPublicKeyTrait<k, l, PK_LEN> + MLDSAPublicKeyInternalTrait<k, PK_LEN>,
    SK: MLDSAPrivateKeyTrait<k, l, ETA, SK_LEN, PK_LEN>
        + MLDSAPrivateKeyInternalTrait<k, l, ETA, SK_LEN, PK_LEN>,
    const TAU: i32,
    const LAMBDA: i32,
    const GAMMA1: i32,
    const GAMMA2: i32,
    const k: usize,
    const l: usize,
    const ETA: usize,
    const BETA: i32,
    const OMEGA: i32,
    const C_TILDE: usize,
    const POLY_Z_PACKED_LEN: usize,
    const POLY_W1_PACKED_LEN: usize,
    const LAMBDA_over_4: usize,
    const GAMMA1_MINUS_BETA: i32,
    const GAMMA2_MINUS_BETA: i32,
    const GAMMA1_MASK_LEN: usize,
> SignatureVerifier<PK, PK_LEN, SIG_LEN>
    for MLDSA<
        PK_LEN,
        SK_LEN,
        SIG_LEN,
        PK,
        SK,
        TAU,
        LAMBDA,
        GAMMA1,
        GAMMA2,
        k,
        l,
        ETA,
        BETA,
        OMEGA,
        C_TILDE,
        POLY_Z_PACKED_LEN,
        POLY_W1_PACKED_LEN,
        LAMBDA_over_4,
        GAMMA1_MINUS_BETA,
        GAMMA2_MINUS_BETA,
        GAMMA1_MASK_LEN,
    >
{
    fn verify(pk: &PK, msg: &[u8], ctx: Option<&[u8]>, sig: &[u8]) -> Result<(), SignatureError> {
        let mu = MuBuilder::compute_mu(&pk.compute_tr(), msg, ctx)?;
        let sig: &[u8; SIG_LEN] = sig.try_into().map_err(|_| {
            SignatureError::LengthError("Signature value is not the correct length.")
        })?;
        Self::verify_mu_internal(pk, &pk.A_hat(), &mu, sig)
            .then_some(())
            .ok_or(SignatureError::SignatureVerificationFailed)
    }

    fn verify_init(pk: &PK, ctx: Option<&[u8]>) -> Result<Self, SignatureError> {
        Ok(Self {
            _phantom: Default::default(),
            mu_builder: MuBuilder::do_init(&pk.compute_tr(), ctx)?,
            signer_rnd: None,
            sk: None,
            seed: None,
            pk: Some(pk.clone()),
        })
    }

    fn verify_update(&mut self, msg_chunk: &[u8]) {
        self.mu_builder.do_update(msg_chunk);
    }

    fn verify_final(self, sig: &[u8]) -> Result<(), SignatureError> {
        let mu = self.mu_builder.do_final();

        let pk: &PK = self
            .pk
            .as_ref()
            .ok_or(SignatureError::GenericError("No public key set on streaming verifier."))?;
        let sig: &[u8; SIG_LEN] = sig.try_into().map_err(|_| {
            SignatureError::LengthError("Signature value is not the correct length.")
        })?;
        Self::verify_mu_internal(pk, &pk.A_hat(), &mu, sig)
            .then_some(())
            .ok_or(SignatureError::SignatureVerificationFailed)
    }
}

/// Implements parts of Algorithm 2 and Line 6 of Algorithm 7 of FIPS 204.
/// Provides a stateful version of [MLDSATrait::compute_mu_from_pk] and [MLDSATrait::compute_mu_from_tr]
/// that supports streaming
/// large to-be-signed messages.
///
/// Note: this struct is only exposed for "pure" ML-DSA and not for HashML-DSA because HashML-DSA
/// does not benefit from allowing external construction of the message representative mu.
/// You can get the same behaviour by computing the pre-hash `ph` with the appropriate hash function
/// and providing that to HashMLDSA via [PHSigner::sign_ph].
pub struct MuBuilder {
    h: H,
}

impl MuBuilder {
    /// Algorithm 7
    /// 6: 𝜇 ← H(BytesToBits(𝑡𝑟)||𝑀′, 64)
    pub fn compute_mu(
        tr: &[u8; 64],
        msg: &[u8],
        ctx: Option<&[u8]>,
    ) -> Result<[u8; 64], SignatureError> {
        let mut mu_builder = MuBuilder::do_init(&tr, ctx)?;
        mu_builder.do_update(msg);
        let mu = mu_builder.do_final();

        Ok(mu)
    }

    /// This function requires the public key hash `tr`, which can be computed from the public key
    /// using [MLDSAPublicKeyTrait::compute_tr].
    pub fn do_init(tr: &[u8; 64], ctx: Option<&[u8]>) -> Result<Self, SignatureError> {
        let ctx = match ctx {
            Some(ctx) => ctx,
            None => &[],
        };

        // Algorithm 2
        // 1: if |𝑐𝑡𝑥| > 255 then
        if ctx.len() > 255 {
            return Err(SignatureError::LengthError("ctx value is longer than 255 bytes"));
        }

        // Algorithm 7
        // 6: 𝜇 ← H(BytesToBits(𝑡𝑟)||𝑀', 64)
        let mut mb = Self { h: H::new() };
        mb.h.absorb(tr);

        // Algorithm 2
        // 10: 𝑀′ ← BytesToBits(IntegerToBytes(0, 1) ∥ IntegerToBytes(|𝑐𝑡𝑥|, 1) ∥ 𝑐𝑡𝑥) ∥ 𝑀
        // all done together
        mb.h.absorb(&[0u8]);
        mb.h.absorb(&[ctx.len() as u8]);
        mb.h.absorb(ctx);

        // now ready to absorb M
        Ok(mb)
    }

    /// Stream a chunk of the message.
    pub fn do_update(&mut self, msg_chunk: &[u8]) {
        self.h.absorb(msg_chunk);
    }

    /// Finalize and return the mu value.
    pub fn do_final(mut self) -> [u8; 64] {
        // Completion of
        // Algorithm 7
        // 6: 𝜇 ← H(BytesToBits(𝑡𝑟)||𝑀 ′, 64)
        let mut mu = [0u8; 64];
        self.h.squeeze_out(&mut mu);

        mu
    }
}
