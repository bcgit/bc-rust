//! This page documents advanced features of the Module Lattice Digital Signature Algorithm (ML-DSA)
//! available in this crate.
//!
//!
//! # Streaming APIs
//!
//! Sometimes the message that needs to be signed or verified is too big to fit in device memory all at once.
//! No worries, we got you covered!
//!
//! ```rust
//! use bouncycastle_core::errors::SignatureError;
//! use bouncycastle_core::signature_key::{SigningKey, VerifyingKey};
//! use bouncycastle_core::traits::{SignatureSigner, SignatureVerifier};
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_mldsa::{MLDSA65, MLDSATrait, MLDSAPublicKeyTrait, MuBuilder};
//!
//! let (pk, sk) = MLDSA65::keygen(&mut HashDRBG_SHA512::new_from_os()).unwrap();
//!
//! // For this example, assume that this message was so long that it is impractical to
//! // stream the whole text over a network, and therefore it needs to be pre-hashed.
//! let msg_chunk1 = b"The quick brown fox ";
//! let msg_chunk2 = b"jumped over the lazy dog";
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let mut signer = sk.create_signer(&mut rng, None).unwrap();
//! signer.do_update(msg_chunk1);
//! signer.do_update(msg_chunk2);
//! let sig = signer.do_final().unwrap();
//! // This is the signature value that can be saved to a file or whatever is needed.
//!
//! // This is compatible with a verifier that takes the whole message as one chunk:
//! let msg = b"The quick brown fox jumped over the lazy dog";
//! match pk.verify(msg, None, &sig) {
//!     Ok(()) => println!("Signature is valid!"),
//!     Err(SignatureError::SignatureVerificationFailed) => println!("Signature is invalid!"),
//!     Err(e) => panic!("Something else went wrong: {:?}", e),
//! }
//!
//! // There is also a streaming API for the verifier.
//!
//! let mut verifier = pk.create_verifier(None).unwrap();
//! verifier.do_update(msg_chunk1);
//! verifier.do_update(msg_chunk2);
//!
//! match verifier.do_verify_final(&sig.as_slice()) {
//!     Ok(()) => println!("Signature is valid!"),
//!     Err(SignatureError::SignatureVerificationFailed) => println!("Signature is invalid!"),
//!     Err(e) => panic!("Something else went wrong: {:?}", e),
//! }
//! ```
//!
//!
//! The streaming signer also takes the signing context `ctx`, explained below.
//!
//! ```rust
//! use bouncycastle_core::errors::SignatureError;
//! use bouncycastle_core::signature_key::{SigningKey, VerifyingKey};
//! use bouncycastle_core::traits::{SignatureSigner, SignatureVerifier};
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_mldsa::{MLDSA65, MLDSATrait, MLDSAPublicKeyTrait, MuBuilder};
//!
//! let (pk, sk) = MLDSA65::keygen(&mut HashDRBG_SHA512::new_from_os()).unwrap();
//!
//! // For this example, assume that this message was so long that it is impractical to
//! // stream the whole text over a network, and therefore it needs to be pre-hashed.
//! let msg_chunk1 = b"The quick brown fox ";
//! let msg_chunk2 = b"jumped over the lazy dog";
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let mut signer = sk.create_signer(&mut rng, Some(b"signing ctx value")).unwrap();
//! signer.do_update(msg_chunk1);
//! signer.do_update(msg_chunk2);
//! let sig = signer.do_final().unwrap();
//! ```
//!
//! # External Mu mode
//!
//! Here, `mu` refers to the message digest which is computed internally to the ML-DSA algorithm:
//!
//! > 𝜇 ← H(BytesToBits(𝑡𝑟)||𝑀′, 64)
//! >   ▷ message representative that may optionally be computed in a different cryptographic module
//!
//! The External Mu mode of ML-DSA fulfills a similar function to [`hash_mldsa`] in that it allows large
//! messages to be pre-digested outside of the cryptographic module that holds the private key,
//! but it does it in a way that is compatible with the ML-DSA verification function.
//! In other works, whereas [`hash_mldsa`] represents a different signature algorithm, the external mu
//! mode of ML-DSA is simply internal implementation detail of how the signature was computed and
//! produces signatures that are indistinguishable from "direct" ML-DSA mode.
//!
//! The one potential complication with external mu mode -- that [`hash_mldsa`] does not have --
//! is that it requires the user to know the public key that they are about to sign the message with.
//! Or, more specifically, the hash of the public key `tr`.
//! `tr` is a public value (derivable from the public key), so there is no harm in, for example,
//! sending it down to a client device so that it can pre-hash a large message and only send the
//! 64-byte `mu` value up to the server to be signed.
//! But in some contexts, the message has to be pre-hashed for performance reasons but
//! the public key that will be used for signing cannot be known in advance.
//! For those use cases, the only choice is to use [`hash_mldsa`].
//!
//! This library exposes [`MuBuilder`] which can be used to pre-hash a large to-be-signed message
//! along with the public key hash `tr`:
//!
//! ```rust
//! use bouncycastle_core::errors::SignatureError;
//! use bouncycastle_mldsa::{MLDSA65, MLDSATrait, MLDSAPublicKeyTrait, MuBuilder};
//! use bouncycastle_core::signature_key::{SigningKey, VerifyingKey};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let (pk, _) = MLDSA65::keygen(&mut HashDRBG_SHA512::new_from_os()).unwrap();
//!
//! // For this example, assume that this message was so long that it is impractical to
//! // stream the whole text over a network, and therefore it needs to be pre-hashed.
//! let msg = b"The quick brown fox jumped over the lazy dog";
//!
//! let mu: [u8; 64] = pk.compute_mu(msg, None).unwrap();
//! // or, with only the public key hash in hand:
//! let mut mb = MuBuilder::from_tr(&pk.compute_tr(), None).unwrap();
//! mb.do_update(msg);
//! let mu: [u8; 64] = mb.do_final();
//! ```
//!
//! Note: a `ctx` value (explained below) is bound into `mu` here, as the second argument.
//!
//! If the message really is so huge that it can't be hold it all in memory at once,
//! then it might be preferable to use a streaming API for computing mu:
//!
//! ```rust
//! use bouncycastle_core::errors::SignatureError;
//! use bouncycastle_core::signature_key::{SigningKey, VerifyingKey};
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_mldsa::{MLDSA65, MLDSATrait, MLDSAPublicKeyTrait, MuBuilder};
//!
//! let (pk, _) = MLDSA65::keygen(&mut HashDRBG_SHA512::new_from_os()).unwrap();
//!
//! // For this example, assume that this message was so long that it is impractical to
//! // stream the whole text over a network, and therefore it needs to be pre-hashed.
//! let msg_chunk1 = b"The quick brown fox ";
//! let msg_chunk2 = b"jumped over the lazy dog";
//!
//! let mut mb = pk.create_mu_builder(None).unwrap();
//! mb.do_update(msg_chunk1);
//! mb.do_update(msg_chunk2);
//! let mu = mb.do_final();
//! ```
//!
//! Given a mu value, the user can compute a signature that verifies as normal (no mu's required!):
//!
//! ```rust
//! use bouncycastle_core::errors::SignatureError;
//! use bouncycastle_core::signature_key::{SigningKey, VerifyingKey};
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_mldsa::{MLDSA65, MLDSATrait, MLDSAPrivateKeyTrait, MLDSAPublicKeyTrait, MuBuilder};
//!
//! let msg = b"The quick brown fox jumped over the lazy dog";
//!
//! let (pk, sk) = MLDSA65::keygen(&mut HashDRBG_SHA512::new_from_os()).unwrap();
//!
//! // Assume this was computed somewhere else, then
//! // the party that computed it would have had to know pk
//! let mu: [u8; 64] = pk.compute_mu(msg, None).unwrap();
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let sig = sk.sign_mu(&mu, &mut rng).unwrap();
//! // This is the signature value that can be saved to a file or whatever it is needed.
//!
//! match pk.verify(msg, None, &sig) {
//!     Ok(()) => println!("Signature is valid!"),
//!     Err(SignatureError::SignatureVerificationFailed) => println!("Signature is invalid!"),
//!     Err(e) => panic!("Something else went wrong: {:?}", e),
//! }
//!
//! ```
//!
//! # Ctx and Rnd params
//! Various functions in this crate let the user set the signing context value (`ctx`) and the signing nonce (`rnd`).
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
//! Generally, it is safe to ignore any property about a `ctx` object that is not well understood.
//!
//! Example of signing and verifying with a `ctx` value:
//!
//! ```rust
//! use bouncycastle_core::errors::SignatureError;
//! use bouncycastle_mldsa::{MLDSA65, MLDSATrait};
//! use bouncycastle_core::signature_key::{SigningKey, VerifyingKey};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let msg = b"The quick brown fox";
//! let ctx = b"FooTextDocumentFormat";
//!
//! let (pk, sk) = MLDSA65::keygen(&mut HashDRBG_SHA512::new_from_os()).unwrap();
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let sig = sk.sign(&mut rng, msg, Some(ctx)).unwrap();
//! // This is the signature value that can be saved to a file or whatever it is needed.
//!
//! match pk.verify(msg, Some(ctx), &sig) {
//!     Ok(()) => println!("Signature is valid!"),
//!     Err(SignatureError::SignatureVerificationFailed) => println!("Signature is invalid!"),
//!     Err(e) => panic!("Something else went wrong: {:?}", e),
//! }
//! ```
//!
//! ## rnd
//!
//! The 32-byte signing randomizer of FIPS 204 Algorithm 2, step 5. This implementation signs the
//! hedged variant: `rnd` is drawn from the RNG the caller passes to `create_signer`, `sign`,
//! `sign_mu` and the pre-hash forms, so signing one message twice gives two different signatures.
//! FIPS 204 also permits the deterministic variant, `rnd` all zeros; it is as secure against
//! forgery, but it loses some privacy: identical signatures reveal that the same message was
//! signed twice by the same key. The deterministic variant is [`DeterministicSigningKey`] on the
//! key (`create_signer_deterministic`, `sign_deterministic`), [`MLDSAPrivateKeyTrait::sign_mu_deterministic`]
//! at the mu level and [`DeterministicPreHashSigningKey`] over a pre-hash. No method takes `rnd`
//! itself; a known-answer test with some other `rnd` passes an RNG that returns it
//! (`bouncycastle_rng::FixedSeedRNG`).
//!
//! [`DeterministicPreHashSigningKey`]: bouncycastle_core::signature_key::DeterministicPreHashSigningKey
//!
//! # Pre-expanding the public key for repeated use
//!
//! Within the usual ML-DSA public key representation, the public matrix A is stored as a seed rho, which
//! means that both the ML-DSA.sign() and ML-DSA.verify() operations need to expand it into a full matrix
//! before performing the matrix multiplication.
//! The code contains a version of the public and private key structs that pre-expand the public matrix for repeated use.
//!
//! The runtime of ML-DSA.sign() is dominated by the rejection sampling look, making the A-expansion
//! a negligible part of the function -- accounting for only about 2% of the computation.
//! However, for ML-DSA.verify(), pre-expansion of the public matrix A gives speedups of 38% / 45% / 63%
//! speedup for ML-DSA 44 / 65 / 87, especially if verifying multiple signatures against the same public key.
//!
//! ```rust
//! use bouncycastle_mldsa::{MLDSA65, MLDSATrait};
//! use bouncycastle_mldsa::{MLDSA65PublicKeyExpanded, MLDSA65PrivateKeyExpanded};
//! use bouncycastle_core::signature_key::{SigningKey, VerifyingKey};
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_core::errors::SignatureError;
//!
//! let msg = b"The quick brown fox";
//!
//! let (pk, sk) = MLDSA65::keygen(&mut HashDRBG_SHA512::new_from_os()).unwrap();
//!
//! // The pre-expanded private key uses more memory, but has performance
//! // improvements if doing multiple decapsulations with the same key
//! // although the performance improvements on signing are slight -- only around 2%.
//! let sk_expanded = MLDSA65PrivateKeyExpanded::from(&sk);
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let sig = sk_expanded.sign(&mut rng, msg, None).unwrap();
//!
//! // The pre-expand the public key uses more memory, but has performance
//! // improvements if doing multiple verifications for the same key.
//! let pk_expanded = MLDSA65PublicKeyExpanded::from(&pk);
//! match pk_expanded.verify(msg, None, &sig) {
//!     Ok(()) => println!("Signature is valid!"),
//!     Err(SignatureError::SignatureVerificationFailed) => println!("Signature is invalid!"),
//!     Err(e) => panic!("Something else went wrong: {:?}", e),
//! }
//! ```
//!
//! # Signing from a seed
//!
//! A key stored as its 32-byte seed is expanded with [`MLDSATrait::keygen_from_seed`] and then
//! signs as any other; nothing is cached between calls, so a caller that signs more than once
//! should expand the key once and keep it. Signing from the seed costs a key generation on top
//! of the signature, about 40% more than signing with an expanded key on the benches.
//!
//! Example usage:
//!
//! ```rust
//! use bouncycastle_core::errors::SignatureError;
//! use bouncycastle_core::signature_key::{SigningKey, VerifyingKey};
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType, KeyMaterialTrait};
//! use bouncycastle_hex as hex;
//! use bouncycastle_mldsa::{MLDSA44, MLDSA44_SIG_LEN, MLDSATrait, MLDSAPrivateKeyTrait, MLDSAPublicKeyTrait, MuBuilder};
//!
//! let msg = b"The quick brown fox jumped over the lazy dog";
//!
//! let seed = KeyMaterial256::from_bytes_as_type(
//!     &hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap(),
//!     KeyType::Seed,
//! ).unwrap();
//!
//! // The public key is computed so that the signature can be verified by anyone.
//! // It also computes the hash `tr` of the public key to later be used to bind the public key at the time of signing.
//! // There is no short-cut to efficiently computing the public key or `tr` from the seed;
//! // The full keygen need to be run in order to get the full private key, at least momentarily, then
//! // it can be discarded and only keep `tr` and `seed`.
//! let (pk, _) = MLDSA44::keygen_from_seed(&seed).unwrap();
//! let tr: [u8; 64] = pk.compute_tr();
//!
//! // Assume this was computed somewhere else, then
//! // the party that computed it would have had to know pk
//! let mut mb = MuBuilder::from_tr(&tr, None).unwrap();
//! mb.do_update(msg);
//! let mu: [u8; 64] = mb.do_final();
//!
//! let mut sig = [0u8; MLDSA44_SIG_LEN];
//! let (_, sk) = MLDSA44::keygen_from_seed(&seed).unwrap();
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let bytes_written = sk.sign_mu_out(&mu, &mut rng, &mut sig).unwrap();
//!
//! // it can be verified normally
//! match pk.verify(msg, None, &sig) {
//!     Ok(()) => println!("Signature is valid!"),
//!     Err(SignatureError::SignatureVerificationFailed) => println!("Signature is invalid!"),
//!     Err(e) => panic!("Something else went wrong: {:?}", e),
//! }
//! ```
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
//! This is accomplished via constructing a [`MLDSAPublicKeyExpanded`] or [`MLDSAPrivateKeyExpanded`] object
//! of the appropriate parameter set from the original key. Both implement the same key role traits
//! ([`SigningKey`], [`VerifyingKey`] and the pre-hash forms) as their non-expanded counterparts,
//! so they are used the same way and simply sign and verify faster.
//!
//! ```rust
//! use bouncycastle_mldsa::{MLDSA65, MLDSATrait};
//! use bouncycastle_mldsa::{MLDSA65PublicKeyExpanded, MLDSA65PrivateKeyExpanded};
//! use bouncycastle_core::signature_key::{SigningKey, VerifyingKey};
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_core::errors::SignatureError;
//!
//! let msg = b"The quick brown fox jumped over the lazy dog";
//!
//! let (pk, sk) = MLDSA65::keygen(&mut HashDRBG_SHA512::new_from_os()).unwrap();
//!
//! // pre-expand the private key, which uses more memory, but has performance
//! // improvements if doing multiple decapsulations with the same key
//! let sk_expanded = MLDSA65PrivateKeyExpanded::from(&sk);
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let sig = sk_expanded.sign(&mut rng, msg, None).unwrap();
//!
//! // pre-expand the public key, which uses more memory, but has performance
//! // improvements if doing multiple verifications with the same key
//! let pk_expanded = MLDSA65PublicKeyExpanded::from(&pk);
//!
//! match pk_expanded.verify(msg, None, &sig) {
//!     Ok(()) => println!("Signature is valid!"),
//!     Err(SignatureError::SignatureVerificationFailed) => println!("Signature is invalid!"),
//!     Err(e) => panic!("Something else went wrong: {:?}", e),
//! }
//! ```
//!
//! # Suspending and resuming execution via SerializableState
//!
//! When signing or verifying a large message, it can be advantageous to be able to suspend the operation
//! to a cache and resume it later; for example if waiting for the message to stream over a slow network
//! connection.
//!
//! This can bo accomplished for both the ML-DSA signer and verifier through the [`MuBuilder`] object.
//!
//! Suspending an in-progress sign operation:
//!
//! ```rust
//! use bouncycastle_mldsa::{MLDSA65, MuBuilder, MLDSATrait, MLDSAPrivateKeyTrait, MLDSAPublicKeyTrait};
//! use bouncycastle_core::traits::Suspendable;
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let msg_part1 = b"The quick brown fox";
//! let msg_part2 = b" jumped over the lazy dog";
//!
//! let (pk, sk) = MLDSA65::keygen(&mut HashDRBG_SHA512::new_from_os()).unwrap();
//!
//! let mut mb = pk.create_mu_builder(None).unwrap();
//! mb.do_update(msg_part1);
//!
//! // here, we'll suspend while "waiting" for the second part of the message
//! let serialized_state = mb.suspend();
//!
//! // ...
//! // do other things in the meantime
//! // ...
//!
//! let mut mb_resumed = MuBuilder::from_suspended(serialized_state).unwrap();
//! mb_resumed.do_update(msg_part2);
//! let mu: [u8; 64] = mb_resumed.do_final();
//!
//! // Now we'll do the actual sign_mu operation
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let sig = sk.sign_mu(&mu, &mut rng).unwrap();
//! ```
//!
//! Suspending an in-progress verify operation behaves exactly the same way:
//!
//! ```rust
//! use bouncycastle_mldsa::{MLDSA65, MuBuilder, MLDSATrait, MLDSAPublicKeyTrait};
//! use bouncycastle_core::traits::Suspendable;
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_core::errors::SignatureError;
//!
//! let (pk, sk) = MLDSA65::keygen(&mut HashDRBG_SHA512::new_from_os()).unwrap();
//!
//! use bouncycastle_core::signature_key::SigningKey;
//! // first, let's generate a signature to verify
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let sig = sk.sign(&mut rng, b"The quick brown fox jumped over the lazy dog", None).unwrap();
//!
//! // Now we'll verify it with a suspension in the middle
//! let msg_part1 = b"The quick brown fox";
//! let msg_part2 = b" jumped over the lazy dog";
//!
//! let mut mb = pk.create_mu_builder(None).unwrap();
//! mb.do_update(msg_part1);
//!
//! // here, we'll suspend while "waiting" for the second part of the message
//! let serialized_state = mb.suspend();
//!
//! // ...
//! // do other things in the meantime
//! // ...
//!
//! let mut mb_resumed = MuBuilder::from_suspended(serialized_state).unwrap();
//! mb_resumed.do_update(msg_part2);
//! let mu: [u8; 64] = mb_resumed.do_final();
//!
//! // Now we'll do the actual verify_mu operation
//! match pk.verify_mu(&mu, &sig) {
//!     Ok(()) => println!("Signature is valid!"),
//!     Err(SignatureError::SignatureVerificationFailed) => println!("Signature is invalid!"),
//!     Err(e) => panic!("Something else went wrong: {:?}", e),
//! }
//! ```

use crate::aux_functions::{
    expand_mask, expandA, expandS, make_hint_vecs, power_2_round_vec, sig_decode, sig_encode,
    use_hint_vecs,
};
use crate::matrix::{MatrixTrait, VectorTrait};
use crate::mldsa_keys::{MLDSAPrivateKeyInternalTrait, MLDSAPrivateKeyTrait};
use crate::mldsa_keys::{MLDSAPublicKeyInternalTrait, MLDSAPublicKeyTrait};
use crate::params::{
    MLDSA44Params, MLDSA65Params, MLDSA87Params, MLDSAParams, MLDSAParamsBase, PrivateKeyLen,
    SignatureLen,
};
use crate::{MLDSAPrivateKey, MLDSAPrivateKeyExpanded, MLDSAPublicKey, MLDSAPublicKeyExpanded};
use bouncycastle_core::errors::{RNGError, SignatureError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterial256, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::signature_key::{
    DeterministicSigningKey, SignatureAlgorithm, SigningKey, VerifyingKey,
};
use bouncycastle_core::traits::{
    Algorithm, AlgorithmOID, Hash, RNG, SignatureSigner, SignatureVerifier, XOF, XOFSqueezer,
};
use bouncycastle_mldsa_common::aux_functions::sample_in_ball;
use bouncycastle_utils::secret::{Secret, ZeroizablePrimitive};
use core::marker::PhantomData;

// imports needed just for docs
#[allow(unused_imports)]
use crate::hash_mldsa;

/*** Constants ***/

// The constants, names and XOF aliases FIPS 204 fixes for every parameter set are shared with
// `bouncycastle-mldsa-lowmemory` and live in `bouncycastle-mldsa-common`.
pub(crate) use bouncycastle_mldsa_common::{H, N, POLY_T0PACKED_LEN, POLY_T1PACKED_LEN};
#[doc(inline)]
pub use bouncycastle_mldsa_common::{ML_DSA_44_NAME, ML_DSA_65_NAME, ML_DSA_87_NAME};
#[doc(inline)]
pub use bouncycastle_mldsa_common::{MLDSA_MU_LEN, MLDSA_RND_LEN, MLDSA_SEED_LEN, MLDSA_TR_LEN};

/*** Re-exporting length constants that a caller will need instead of the entire Params objects which contains a bunch of internal algorithm detail ***/

/// Length of the \[u8] holding an ML-DSA-44 public key.
pub const MLDSA44_PK_LEN: usize = MLDSA44Params::PK_LEN;
/// Length of the \[u8] holding an ML-DSA-44 private key.
pub const MLDSA44_SK_LEN: usize = MLDSA44Params::SK_LEN;
/// Length of the \[u8] holding an ML-DSA-44 signature value.
pub const MLDSA44_SIG_LEN: usize = MLDSA44Params::SIG_LEN;

/// Length of the \[u8] holding an ML-DSA-65 public key.
pub const MLDSA65_PK_LEN: usize = MLDSA65Params::PK_LEN;
/// Length of the \[u8] holding an ML-DSA-65 private key.
pub const MLDSA65_SK_LEN: usize = MLDSA65Params::SK_LEN;
/// Length of the \[u8] holding an ML-DSA-65 signature value.
pub const MLDSA65_SIG_LEN: usize = MLDSA65Params::SIG_LEN;

/// Length of the \[u8] holding an ML-DSA-87 public key.
pub const MLDSA87_PK_LEN: usize = MLDSA87Params::PK_LEN;
/// Length of the \[u8] holding an ML-DSA-87 private key.
pub const MLDSA87_SK_LEN: usize = MLDSA87Params::SK_LEN;
/// Length of the \[u8] holding an ML-DSA-87 signature value.
pub const MLDSA87_SIG_LEN: usize = MLDSA87Params::SIG_LEN;

/*** Pub Types ***/

/// The ML-DSA-44 algorithm.
pub type MLDSA44 = MLDSA<MLDSA44Params>;

/// The ML-DSA-65 algorithm.
pub type MLDSA65 = MLDSA<MLDSA65Params>;

/// The ML-DSA-87 algorithm.
pub type MLDSA87 = MLDSA<MLDSA87Params>;

/// The name and claimed strength of an ML-DSA algorithm are properties of its parameter set, so
/// one impl covers all three; `MLDSAParams` is sealed, so those are the only three that exist.
impl<P: MLDSAParams> Algorithm for MLDSA<P> {
    const ALG_NAME: &'static str = P::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = P::MAX_SECURITY_STRENGTH;
}

/// The OIDs NIST assigned in the Computer Security Objects Register: id-ml-dsa-44 { sigAlgs 17 },
/// id-ml-dsa-65 { sigAlgs 18 } and id-ml-dsa-87 { sigAlgs 19 }. As with [`Algorithm`], the values
/// belong to the parameter set, so one impl covers all three.
impl<P: MLDSAParams> AlgorithmOID for MLDSA<P> {
    const OID: &'static [u32] = P::OID;
    const OID_DER: &'static [u8] = P::OID_DER;
}

/// The ML-DSA algorithm marker for one parameter set: [`MLDSA44`], [`MLDSA65`], [`MLDSA87`].
/// It carries the metadata ([`Algorithm`], [`AlgorithmOID`]) and, through [`MLDSATrait`], key
/// generation; signing and verifying, over the message or over an external mu, are methods of
/// the keys ([`SigningKey`], [`VerifyingKey`], [`MLDSAPrivateKeyTrait`], [`MLDSAPublicKeyTrait`]),
/// with the marker as the algorithm they name.
pub struct MLDSA<P: MLDSAParams> {
    _phantom: PhantomData<P>,
}

impl<P: MLDSAParams> MLDSA<P> {
    /// Implements Algorithm 6 of FIPS 204
    /// Note: NIST has made a special exception in the FIPS 204 FAQ that this _internal function
    /// may in fact be exposed outside the crypto module.
    ///
    /// Unlike other interfaces across the library that take an &impl KeyMaterial, this one
    /// specifically takes a 32-byte [`KeyMaterial256`] and checks that it has [`KeyType::Seed`] and
    /// [`SecurityStrength::_256bit`].
    /// If you happen to have your seed in a larger KeyMaterial, you'll have to copy it into a
    /// correctly-sized [`KeyMaterial256`] using [`KeyMaterialTrait::truncate`].
    pub(crate) fn keygen_internal(
        seed: &KeyMaterial256,
    ) -> Result<(MLDSAPublicKey<P>, MLDSAPrivateKey<P>), SignatureError> {
        if !(seed.key_type() == KeyType::Seed || seed.key_type() == KeyType::CryptographicRandom)
            || seed.key_len() != 32
        {
            return Err(SignatureError::KeyGenError(
                "Seed must be 32 bytes and KeyType::Seed or KeyType::CryptographicRandom.",
            ));
        }

        if seed.security_strength() < P::MAX_SECURITY_STRENGTH {
            return Err(SignatureError::KeyGenError(
                "Seed SecurityStrength must match algorithm security strength",
            ));
        }

        // Alg 6 line 1: (rho, rho_prime, K) <- H(𝜉||IntegerToBytes(𝑘, 1)||IntegerToBytes(ℓ, 1), 128)
        //   ▷ expand seed
        let mut rho: [u8; 32] = [0u8; 32];
        let mut K = Secret::<[u8; 32]>::new();

        let (s1_hat, mut s2) = {
            // scope for h
            let mut h = H::default();
            h.do_update(seed.ref_to_bytes());
            h.do_update(&(P::k as u8).to_le_bytes());
            h.do_update(&(P::l as u8).to_le_bytes());
            let mut h = h.into_squeezer();
            let bytes_written = h.do_output_out(&mut rho);
            debug_assert_eq!(bytes_written, 32);
            let mut rho_prime: Secret<[u8; 64]> = Secret::new();
            let bytes_written = h.do_output_out(&mut *rho_prime);
            debug_assert_eq!(bytes_written, 64);
            let bytes_written = h.do_output_out(&mut *K);
            debug_assert_eq!(bytes_written, 32);

            // 4: (𝐬1, 𝐬2) ← ExpandS(𝜌′)
            let (mut s1, s2) = expandS::<P>(&rho_prime);

            s1.ntt();
            (s1, s2)
        };

        let t_hat = {
            // scope for s1_hat
            // 3: 𝐀_hat ← ExpandA(𝜌) ▷ 𝐀 is generated and stored in NTT representation as 𝐀
            let A_hat = expandA::<P>(&rho);

            // 5: 𝐭 ← NTT−1(𝐀 ∘ NTT(𝐬1)) + 𝐬2
            //   ▷ compute 𝐭 = 𝐀𝐬1 + 𝐬2
            A_hat.matrix_vector_ntt(&s1_hat)
        };

        let (t1, mut t0) = {
            // scope for t
            let mut t = t_hat;
            // Bound-keeping step before NTT⁻¹, not in FIPS 204: see [`Polynomial::reduce32`].
            t.reduce32();
            t.inv_ntt();
            t.add_vector_ntt(&s2);
            t.conditional_add_q();

            // 6: (𝐭1, 𝐭0) ← Power2Round(𝐭)
            //   ▷ compress 𝐭
            //   ▷ PowerTwoRound is applied componentwise (see explanatory text in Section 7.4)
            power_2_round_vec(&t)
        };

        // 8: 𝑝𝑘 ← pkEncode(𝜌, 𝐭1)
        let pk = MLDSAPublicKey::<P>::new(rho, t1);

        // 9: 𝑡𝑟 ← H(𝑝𝑘, 64)
        let tr = pk.compute_tr();

        // 10: 𝑠𝑘 ← skEncode(𝜌, 𝐾, 𝑡𝑟, 𝐬1, 𝐬2, 𝐭0)
        //   ▷ 𝐾 and 𝑡𝑟 are for use in signing
        // Deviation from the FIPS:
        //   Hold on to s1, s2, t0 in ntt form
        //   Note: the result here is not necessarily in reduced form, but since .reduce() is expensive,
        //   it is saved for the encode() operation since that is the only place where it matters
        //   to have them in normalized form.
        s2.ntt();
        t0.ntt();
        // let sk = SK::new(&rho, &K, &tr, &s1_hat, &s2, &t0, Some(seed.clone()));
        let sk = MLDSAPrivateKey::<P>::new(rho, K, tr, s1_hat, s2, t0, Some(seed.clone()));

        // tr is public data, does not need to be zeroized
        // s1, s2, t0 are all Vectors of Polynomials, so implement a zeroizing Drop

        // 11: return (𝑝𝑘, 𝑠𝑘)
        Ok((pk, sk))
    }
}

/// Algorithm 7 ML-DSA.Sign_internal(𝑠𝑘, 𝑀′, 𝑟𝑛𝑑), taking an externally computed mu in place of
/// M' and the public matrix A_hat already expanded. The key traits' `sign_mu_*` methods call it.
pub(crate) fn sign_internal<
    P: SignatureLen<SIG_LEN>,
    SK: MLDSAPrivateKeyInternalTrait<P>,
    const SIG_LEN: usize,
>(
    sk: &SK,
    A_hat: &P::MatrixA,
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
    // It does an optimization where the user can pre-expand A_hat within the
    // public key object for faster repeated verifications against this public key.

    // 6: 𝜇 ← H(BytesToBits(𝑡𝑟)||𝑀 ′, 64)
    // skip: mu has already been provided

    let rho_p_p: Secret<[u8; 64]> = {
        // scope for h
        // 7: 𝜌″ ← H(𝐾||𝑟𝑛𝑑||𝜇, 64)
        let mut h = H::new();
        h.do_update(&**sk.K());
        h.do_update(&rnd);
        h.do_update(mu);
        let mut rho_p_p: Secret<[u8; 64]> = Secret::new();
        let mut h = h.into_squeezer();
        h.do_output_out(&mut *rho_p_p);

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
    let mut sig_val_c_tilde = <P::SigCTilde as ZeroizablePrimitive>::ZEROED;
    let mut sig_val_z: P::VecL;
    let mut sig_val_h: P::VecK;
    loop {
        // FIPS 204 s. 6.2 allows:
        //   "Implementations may limit the number of iterations in this loop to not exceed a finite maximum value."
        // mutants note: there is no test for this because, at this point,
        // we don't know of a KAT that will exceed this limit.
        if kappa > 1000 * P::k as u16 {
            return Err(SignatureError::RejectionLimitExceeded);
        }

        // 11: 𝐲 ∈ 𝑅^ℓ ← ExpandMask(𝜌″, 𝜅)
        let mut y = expand_mask::<P>(&rho_p_p, kappa);

        let w = {
            // scope for y_hat
            // 12: 𝐰 ← NTT−1(𝐀_hat * NTT(𝐲))
            let mut y_hat = y;
            y_hat.ntt();
            let mut w = A_hat.matrix_vector_ntt(&y_hat);
            // Bound-keeping step before NTT⁻¹, not in FIPS 204: see [`Polynomial::reduce32`].
            w.reduce32();
            w.inv_ntt();
            w.conditional_add_q();
            w
        };

        // 13: 𝐰1 ← HighBits(𝐰)
        //  ▷ signer’s commitment
        let w1 = w.high_bits::<P>();

        {
            // scope for h
            // 15: 𝑐_tilde ← H(𝜇||w1Encode(𝐰1), 𝜆/4)
            //  ▷ commitment hash
            let mut hash = H::new();
            hash.do_update(mu);
            w1.w1_encode_and_hash::<P>(&mut hash);
            let mut hash = hash.into_squeezer();
            hash.do_output_out(sig_val_c_tilde.as_mut());
        }

        // 16: 𝑐 ∈ 𝑅𝑞 ← SampleInBall(c_tilde)
        //  ▷ verifier’s challenge
        let c_hat = {
            // scope for c
            let mut c = sample_in_ball::<P>(&sig_val_c_tilde);

            // 17: 𝑐_hat ← NTT(𝑐)
            c.ntt();
            c
        };

        // 18: ⟨⟨𝑐𝐬1⟩⟩ ← NTT−1(𝑐_hat * 𝐬1_hat)
        //  Note: <<.>> in FIPS 204 means that this value will be used again later, so this should be kept.
        let mut cs1 = sk.s1_hat().scalar_vector_ntt(&c_hat);
        cs1.inv_ntt();

        // 20: 𝐳 ← 𝐲 + ⟨⟨𝑐𝐬1⟩⟩
        y.add_vector_ntt(&cs1);
        sig_val_z = y;

        // 23 (first half): if ||𝐳||∞ ≥ 𝛾1 − 𝛽 or ||𝐫0||∞ ≥ 𝛾2 − 𝛽 then (z, h) ← ⊥
        //  ▷ validity checks
        // This is done out-of-order on purpose for performance reasons:
        // rejection sampling check is done before any extra heavy computation
        if sig_val_z.check_norm(P::gamma1_minus_beta) {
            kappa += P::l as u16;
            continue;
        };

        // 19: ⟨⟨𝑐𝐬2⟩⟩ ← NTT−1(𝑐_hat * 𝐬2̂_hat)
        let mut cs2 = sk.s2_hat().scalar_vector_ntt(&c_hat);
        cs2.inv_ntt();

        // 21: 𝐫0 ← LowBits(𝐰 − ⟨⟨𝑐𝐬2⟩⟩)
        let mut r0 = w.sub_vector(&cs2).low_bits::<P>();

        // 23 (second half): if ||𝐳||∞ ≥ 𝛾1 − 𝛽 or ||𝐫0||∞ ≥ 𝛾2 − 𝛽 then (z, h) ← ⊥
        //  ▷ validity checks
        //  Note: this could be further optimized by using the optimization described in
        //  https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf section 5.1:
        //    "instead of computing (r1, r0) = Decomposeq (w − cs2, α)
        //      and checking whether ‖r0‖∞ < γ2 − β and r1 = w1, it is equivalent to just check that
        //      ‖w0 − cs2‖∞ < γ2 − β, where w0 is the low part of w. If this check passes, w0 − cs2
        //      is the low part of w − cs2."
        if r0.check_norm(P::gamma2_minus_beta) {
            kappa += P::l as u16;
            continue;
        };

        // 25: ⟨⟨𝑐𝐭0⟩⟩ ← NTT−1(𝑐_hat * 𝐭0̂_hat)
        let mut ct0 = sk.t0_hat().scalar_vector_ntt(&c_hat);
        ct0.inv_ntt();

        // 28 (first half): if ||⟨⟨𝑐𝐭0⟩⟩||∞ ≥ 𝛾2 or the number of 1’s in 𝐡 is greater than 𝜔, then (z, h) ← ⊥
        // This is done out-of-order on purpose for performance reasons:
        // rejection sampling check is done before any extra heavy computation
        // mutants note: there is currently no unit test that triggers this branch
        if ct0.check_norm(P::gamma2) {
            kappa += P::l as u16;
            continue;
        };

        // 26: 𝐡 ← MakeHint(−⟨⟨𝑐𝐭0⟩⟩, 𝐰 − ⟨⟨𝑐𝐬2⟩⟩ + ⟨⟨𝑐𝐭0⟩⟩)
        //  ▷ Signer’s hint
        r0.add_vector_ntt(&ct0);
        r0.conditional_add_q();
        let hint_hamming_weight: i32;
        sig_val_h = {
            // scope for hint
            let (hint, inner_hint_hamming_weight) = make_hint_vecs::<P>(&r0, &w1);
            hint_hamming_weight = inner_hint_hamming_weight;
            hint
        };

        // 28 (second half): if ||⟨⟨𝑐𝐭0⟩⟩||∞ ≥ 𝛾2 or the number of 1’s in 𝐡 is greater than 𝜔, then (z, h) ← ⊥
        // mutants note: there is no test KAT that triggers this branch
        if hint_hamming_weight > P::omega {
            kappa += P::l as u16;
            continue;
        };

        break;
    }

    // sig_encode does not necessarily write to all bytes of the output, so just to be safe:
    output.fill(0u8);

    // 33: 𝜎 ← sigEncode(𝑐, 𝐳̃ mod±𝑞, 𝐡)
    let bytes_written = sig_encode::<P, SIG_LEN>(&sig_val_c_tilde, &sig_val_z, &sig_val_h, output);

    Ok(bytes_written)
}

/// Algorithm 8 ML-DSA.Verify_internal(𝑝𝑘, 𝑀′, 𝜎), taking an externally computed mu in place of
/// M' and the public matrix A_hat already expanded. The key traits' `verify_mu` calls it.
/// Input: Public key 𝑝𝑘 ∈ 𝔹32+32𝑘(bitlen (𝑞−1)−𝑑) and message 𝑀′ ∈ {0, 1}∗ .
/// Input: Signature 𝜎 ∈ 𝔹𝜆/4+ℓ⋅32⋅(1+bitlen (𝛾1−1))+𝜔+𝑘.
pub(crate) fn verify_internal<
    P: SignatureLen<SIG_LEN>,
    PK: MLDSAPublicKeyInternalTrait<P>,
    const SIG_LEN: usize,
>(
    pk: &PK,
    A_hat: &P::MatrixA,
    mu: &[u8; 64],
    sig: &[u8; SIG_LEN],
) -> Result<(), SignatureError> {
    // 1: (𝜌, 𝐭1) ← pkDecode(𝑝𝑘)
    // Already done -- the pk struct is already decoded

    // 2: (𝑐_tilde, 𝐳, 𝐡) ← sigDecode(𝜎)
    //  ▷ signer’s commitment hash c_tilde, response 𝐳, and hint 𝐡
    // 3: if 𝐡 = ⊥ then return false
    let (c_tilde, z, h) =
        sig_decode::<P, SIG_LEN>(sig).ok_or(SignatureError::SignatureVerificationFailed)?;

    // 13 (first half) return [[ ||𝐳||∞ < 𝛾1 − 𝛽]]
    if z.check_norm(P::gamma1_minus_beta) {
        return Err(SignatureError::SignatureVerificationFailed);
    }

    // 5: 𝐀 ← ExpandA(𝜌)
    //   ▷ 𝐀 is generated and stored in NTT representation as 𝐀
    // The code offers an optimization where the user can pre-expand A_hat within the
    // public key object for faster repeated verifications against this public key.

    // 6: 𝑡𝑟 ← H(𝑝𝑘, 64)
    // 7: 𝜇 ← (H(BytesToBits(𝑡𝑟)||𝑀 ′, 64))
    //   ▷ message representative that may optionally be
    //     computed in a different cryptographic module
    // skip because this function is being handed mu

    // 8: 𝑐 ∈ 𝑅𝑞 ← SampleInBall(c_tilde)
    let c_hat = {
        let mut c = sample_in_ball::<P>(&c_tilde);
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
            let mut z_hat = z;
            z_hat.ntt();
            A_hat.matrix_vector_ntt(&z_hat)
        };
        let ct1 = {
            // potential optimization -- pre-compute this on key load?
            let mut t1_shift_hat = pk.t1().shift_left_d();
            t1_shift_hat.ntt();
            t1_shift_hat.scalar_vector_ntt(&c_hat)
        };
        let mut wp_approx = Az.sub_vector(&ct1);
        // Bound-keeping step before NTT⁻¹, not in FIPS 204: see `Polynomial::reduce32`. Here it
        // is security-critical: 𝐳 and 𝐭1 are attacker-controlled, and without it a crafted
        // signature overflows the butterflies (<https://eprint.iacr.org/2026/1032>, Wycheproof mldsa_87_verify tcId 240/241).
        wp_approx.reduce32();
        wp_approx.inv_ntt();
        wp_approx.conditional_add_q();

        // 10: 𝐰1′ ← UseHint(𝐡, 𝐰'_approx)
        // ▷ reconstruction of signer’s commitment
        use_hint_vecs::<P>(&h, &wp_approx)
    };
    // 12: 𝑐_tilde_p ← H(𝜇||w1Encode(𝐰1'), 𝜆/4)
    // ▷ hash it; this should match 𝑐_tilde
    let c_tilde_p = {
        let mut c_tilde_p = <P::SigCTilde as ZeroizablePrimitive>::ZEROED;
        let mut hash = H::new();
        hash.do_update(mu);
        w1p.w1_encode_and_hash::<P>(&mut hash);
        let mut hash = hash.into_squeezer();
        hash.do_output_out(c_tilde_p.as_mut());

        c_tilde_p
    };

    // verification probably doesn't technically need to be constant-time, but why not?
    // 13 (second half): return [[ ||𝐳||∞ < 𝛾1 − 𝛽]] and [[𝑐 ̃ = 𝑐′ ]]
    if bouncycastle_utils::ct::ct_eq_bytes(c_tilde.as_ref(), c_tilde_p.as_ref()) {
        Ok(())
    } else {
        Err(SignatureError::SignatureVerificationFailed)
    }
}

impl<P: MLDSAParams> MLDSATrait<P> for MLDSA<P> {
    fn keygen_from_seed(
        seed: &KeyMaterial<32>,
    ) -> Result<(MLDSAPublicKey<P>, MLDSAPrivateKey<P>), SignatureError> {
        Self::keygen_internal(seed)
    }
    fn keygen_from_seed_and_encoded<const SK_LEN: usize>(
        seed: &KeyMaterial<32>,
        encoded_sk: &[u8; SK_LEN],
    ) -> Result<(MLDSAPublicKey<P>, MLDSAPrivateKey<P>), SignatureError>
    where
        P: PrivateKeyLen<SK_LEN>,
    {
        let (pk, sk) = Self::keygen_internal(seed)?;

        let sk_from_bytes = MLDSAPrivateKey::<P>::sk_decode(encoded_sk)?;

        // MLDSAPrivateKey impls PartialEq with a constant-time equality check.
        if sk != sk_from_bytes {
            return Err(SignatureError::KeyGenError("Encoded key does not match generated key"));
        }

        Ok((pk, sk))
    }
    fn keypair_consistency_check(
        pk: &MLDSAPublicKey<P>,
        sk: &MLDSAPrivateKey<P>,
    ) -> Result<(), SignatureError> {
        // This is maybe a computationally heavy way to compare them, but it works
        let derived_pk = sk.derive_pk();
        if bouncycastle_utils::ct::ct_eq_bytes(&derived_pk.compute_tr(), &pk.compute_tr()) {
            Ok(())
        } else {
            Err(SignatureError::ConsistencyCheckFailed)
        }
    }
}

/// Trait for all three of the ML-DSA algorithm variants.
pub trait MLDSATrait<P: MLDSAParams>: Sized {
    /// Key generation from the caller's RNG, which must offer at least the parameter set's
    /// security strength.
    // Should still be ok in FIPS mode, provided that you're using the FIPS-approved RNG.
    fn keygen(
        rng: &mut dyn RNG,
    ) -> Result<(MLDSAPublicKey<P>, MLDSAPrivateKey<P>), SignatureError> {
        // Source the seed from the provided RNG
        if rng.security_strength() < P::MAX_SECURITY_STRENGTH {
            return Err(RNGError::SecurityStrengthInsufficientForAlgorithm.into());
        }
        let mut seed = KeyMaterial256::new();
        rng.fill_keymaterial_out(&mut seed)?;
        Self::keygen_from_seed(&seed)
    }
    /// Imports a secret key from a seed.
    fn keygen_from_seed(
        seed: &KeyMaterial<32>,
    ) -> Result<(MLDSAPublicKey<P>, MLDSAPrivateKey<P>), SignatureError>;
    /// Imports a secret key from both a seed and an encoded_sk.
    ///
    /// This is a convenience function to expand the key from seed and compare it against
    /// the provided `encoded_sk` using a constant-time equality check.
    /// If everything checks out, the secret key is returned fully populated with pk and seed.
    /// If the provided key and derived key don't match, an error is returned.
    fn keygen_from_seed_and_encoded<const SK_LEN: usize>(
        seed: &KeyMaterial<32>,
        encoded_sk: &[u8; SK_LEN],
    ) -> Result<(MLDSAPublicKey<P>, MLDSAPrivateKey<P>), SignatureError>
    where
        P: PrivateKeyLen<SK_LEN>;
    /// Given a public key and a secret key, check that the public key matches the secret key.
    /// This is a sanity check that the public key was generated correctly from the secret key.
    ///
    /// At the current time, this is only possible if `sk` either contains a public key (in which case
    /// the two pk's are encoded and compared for byte equality), or if `sk` contains a seed
    /// (in which case a keygen_from_seed is run and then the pk's compared).
    ///
    /// Returns either `()` or [`SignatureError::ConsistencyCheckFailed`].
    fn keypair_consistency_check(
        pk: &MLDSAPublicKey<P>,
        sk: &MLDSAPrivateKey<P>,
    ) -> Result<(), SignatureError>;
}

impl<P: MLDSAParams> SignatureAlgorithm for MLDSA<P> {}

/// Draws `rnd` (FIPS 204 Section 3.4: "the 32-byte random value rnd shall be generated by the
/// cryptographic module that generates the signature").
pub(crate) fn draw_rnd(rng: &mut dyn RNG) -> Result<[u8; MLDSA_RND_LEN], SignatureError> {
    let mut rnd = [0u8; MLDSA_RND_LEN];
    rng.next_bytes_out(&mut rnd)?;
    Ok(rnd)
}

/// An ML-DSA signature in progress: FIPS 204 Algorithm 7, with the message representative
/// (line 6) built as the message streams in. Made by [`SigningKey::create_signer`] on an ML-DSA
/// private key, which it borrows; the signing randomizer is fixed when the signer is made.
pub struct MLDSASigner<'k, P: MLDSAParams, SK: MLDSAPrivateKeyTrait<P>> {
    _phantom: PhantomData<P>,
    sk: &'k SK,
    mu_builder: MuBuilder,
    rnd: [u8; MLDSA_RND_LEN],
}

fn new_signer<'k, P: MLDSAParams, SK: MLDSAPrivateKeyTrait<P>>(
    sk: &'k SK,
    rnd: [u8; MLDSA_RND_LEN],
    ctx: Option<&[u8]>,
) -> Result<MLDSASigner<'k, P, SK>, SignatureError> {
    Ok(MLDSASigner { _phantom: PhantomData, sk, mu_builder: sk.create_mu_builder(ctx)?, rnd })
}

impl<P: MLDSAParams, SK: MLDSAPrivateKeyTrait<P>> Algorithm for MLDSASigner<'_, P, SK> {
    const ALG_NAME: &'static str = P::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = P::MAX_SECURITY_STRENGTH;
}

impl<P: SignatureLen<SIG_LEN>, SK: MLDSAPrivateKeyTrait<P>, const SIG_LEN: usize>
    SignatureSigner<SIG_LEN> for MLDSASigner<'_, P, SK>
{
    fn do_update(&mut self, msg_chunk: &[u8]) {
        self.mu_builder.do_update(msg_chunk);
    }

    fn do_final(self) -> Result<[u8; SIG_LEN], SignatureError> {
        let mut out = [0u8; SIG_LEN];
        self.do_final_out(&mut out)?;
        Ok(out)
    }

    fn do_final_out(self, output: &mut [u8; SIG_LEN]) -> Result<usize, SignatureError> {
        let mu = self.mu_builder.do_final();
        self.sk.sign_mu_with_rnd_out(&mu, self.rnd, output)
    }
}

/// An ML-DSA verification in progress: FIPS 204 Algorithm 8, with the message representative
/// (line 7) built as the message streams in. Made by [`VerifyingKey::create_verifier`] on an
/// ML-DSA public key, which it borrows.
pub struct MLDSAVerifier<'k, P: MLDSAParams, PK: MLDSAPublicKeyTrait<P>, const SIG_LEN: usize> {
    _phantom: PhantomData<P>,
    pk: &'k PK,
    mu_builder: MuBuilder,
}

fn new_verifier<'k, P: MLDSAParams, PK: MLDSAPublicKeyTrait<P>, const SIG_LEN: usize>(
    pk: &'k PK,
    ctx: Option<&[u8]>,
) -> Result<MLDSAVerifier<'k, P, PK, SIG_LEN>, SignatureError> {
    Ok(MLDSAVerifier { _phantom: PhantomData, pk, mu_builder: pk.create_mu_builder(ctx)? })
}

impl<P: SignatureLen<SIG_LEN>, PK: MLDSAPublicKeyTrait<P>, const SIG_LEN: usize> Algorithm
    for MLDSAVerifier<'_, P, PK, SIG_LEN>
{
    const ALG_NAME: &'static str = P::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = P::MAX_SECURITY_STRENGTH;
}

impl<P: SignatureLen<SIG_LEN>, PK: MLDSAPublicKeyTrait<P>, const SIG_LEN: usize> SignatureVerifier
    for MLDSAVerifier<'_, P, PK, SIG_LEN>
{
    fn do_update(&mut self, msg_chunk: &[u8]) {
        self.mu_builder.do_update(msg_chunk);
    }

    fn do_verify_final(self, sig: &[u8]) -> Result<(), SignatureError> {
        let mu = self.mu_builder.do_final();
        let sig: &[u8; SIG_LEN] = sig.try_into().map_err(|_| {
            SignatureError::LengthError("Signature value is not the correct length.")
        })?;
        self.pk.verify_mu(&mu, sig)
    }
}

/*** The role impls: the plain keys and the expanded keys, for the parameter set they belong to ***/

impl<P: SignatureLen<SIG_LEN>, const SIG_LEN: usize> SigningKey<MLDSA<P>, SIG_LEN>
    for MLDSAPrivateKey<P>
{
    type Signer<'k>
        = MLDSASigner<'k, P, Self>
    where
        Self: 'k;

    fn create_signer<'k>(
        &'k self,
        rng: &mut dyn RNG,
        ctx: Option<&[u8]>,
    ) -> Result<Self::Signer<'k>, SignatureError> {
        new_signer(self, draw_rnd(rng)?, ctx)
    }
}

/// FIPS 204 Section 3.4, the deterministic variant: `rnd` is 32 zero bytes, so the signature is a
/// function of the key and the message alone. See the module docs on `rnd` for what that gives up.
impl<P: SignatureLen<SIG_LEN>, const SIG_LEN: usize> DeterministicSigningKey<MLDSA<P>, SIG_LEN>
    for MLDSAPrivateKey<P>
{
    type Signer<'k>
        = MLDSASigner<'k, P, Self>
    where
        Self: 'k;

    fn create_signer_deterministic<'k>(
        &'k self,
        ctx: Option<&[u8]>,
    ) -> Result<Self::Signer<'k>, SignatureError> {
        new_signer(self, [0u8; MLDSA_RND_LEN], ctx)
    }
}

impl<P: SignatureLen<SIG_LEN>, const SIG_LEN: usize> SigningKey<MLDSA<P>, SIG_LEN>
    for MLDSAPrivateKeyExpanded<'_, P>
{
    type Signer<'k>
        = MLDSASigner<'k, P, Self>
    where
        Self: 'k;

    fn create_signer<'k>(
        &'k self,
        rng: &mut dyn RNG,
        ctx: Option<&[u8]>,
    ) -> Result<Self::Signer<'k>, SignatureError> {
        new_signer(self, draw_rnd(rng)?, ctx)
    }
}

/// FIPS 204 Section 3.4, the deterministic variant: `rnd` is 32 zero bytes, so the signature is a
/// function of the key and the message alone. See the module docs on `rnd` for what that gives up.
impl<P: SignatureLen<SIG_LEN>, const SIG_LEN: usize> DeterministicSigningKey<MLDSA<P>, SIG_LEN>
    for MLDSAPrivateKeyExpanded<'_, P>
{
    type Signer<'k>
        = MLDSASigner<'k, P, Self>
    where
        Self: 'k;

    fn create_signer_deterministic<'k>(
        &'k self,
        ctx: Option<&[u8]>,
    ) -> Result<Self::Signer<'k>, SignatureError> {
        new_signer(self, [0u8; MLDSA_RND_LEN], ctx)
    }
}

impl<P: SignatureLen<SIG_LEN>, const SIG_LEN: usize> VerifyingKey<MLDSA<P>, SIG_LEN>
    for MLDSAPublicKey<P>
{
    type Verifier<'k>
        = MLDSAVerifier<'k, P, Self, SIG_LEN>
    where
        Self: 'k;

    fn create_verifier<'k>(
        &'k self,
        ctx: Option<&[u8]>,
    ) -> Result<Self::Verifier<'k>, SignatureError> {
        new_verifier(self, ctx)
    }
}

impl<P: SignatureLen<SIG_LEN>, const SIG_LEN: usize> VerifyingKey<MLDSA<P>, SIG_LEN>
    for MLDSAPublicKeyExpanded<'_, P>
{
    type Verifier<'k>
        = MLDSAVerifier<'k, P, Self, SIG_LEN>
    where
        Self: 'k;

    fn create_verifier<'k>(
        &'k self,
        ctx: Option<&[u8]>,
    ) -> Result<Self::Verifier<'k>, SignatureError> {
        new_verifier(self, ctx)
    }
}

// The message representative builder is shared with the other ML-DSA crate and lives in
// `bouncycastle-mldsa-common`.
#[doc(inline)]
pub use bouncycastle_mldsa_common::mu_builder::{MuBuilder, SUSPENDED_MU_BUILDER_STATE_LEN};
