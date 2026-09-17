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
//! use bouncycastle_mldsa_lowmemory::{MLDSA65, MLDSATrait, MLDSAPublicKeyTrait, MuBuilder};
//!
//! let (pk, sk) = MLDSA65::keygen(&mut HashDRBG_SHA512::new_from_os()).unwrap();
//!
//! // For illustration purposes, assume that this message was so long that it couldn't possibly
//! // be streamed in its entirety over a network, and therefore it needs to be pre-hashed.
//! let msg_chunk1 = b"The quick brown fox ";
//! let msg_chunk2 = b"jumped over the lazy dog";
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let mut signer = sk.create_signer(&mut rng, None).unwrap();
//! signer.do_update(msg_chunk1);
//! signer.do_update(msg_chunk2);
//! let sig = signer.do_final().unwrap();
//! // This is the signature value that can be saved to a file or whatever it is needed.
//!
//! // This is compatible with a verifies that takes the whole message as one chunk:
//! let msg = b"The quick brown fox jumped over the lazy dog";
//! match pk.verify(msg, None, &sig) {
//!     Ok(()) => println!("Signature is valid!"),
//!     Err(SignatureError::SignatureVerificationFailed) => println!("Signature is invalid!"),
//!     Err(e) => panic!("Something else went wrong: {:?}", e),
//! }
//!
//! // But of course there's also a streaming API for the verifier!
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
//! use bouncycastle_mldsa_lowmemory::{MLDSA65, MLDSATrait, MLDSAPublicKeyTrait, MuBuilder};
//!
//! let (pk, sk) = MLDSA65::keygen(&mut HashDRBG_SHA512::new_from_os()).unwrap();
//!
//! // For illustration purposes, assume that this message was so long that it couldn't possibly
//! // be streamed in its entirety over a network, and therefore it needs to be pre-hashed.
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
//! use bouncycastle_core::signature_key::{SigningKey, VerifyingKey};
//! use bouncycastle_core::traits::{SignatureSigner, SignatureVerifier};
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_mldsa_lowmemory::{MLDSA65, MLDSATrait, MLDSAPublicKeyTrait, MuBuilder};
//!
//! let (pk, _) = MLDSA65::keygen(&mut HashDRBG_SHA512::new_from_os()).unwrap();
//!
//! // Let's pretend this message was so long that it couldn't possibly
//! // streamed in its entirety over a network, and it needs to be pre-hashed.
//! let msg = b"The quick brown fox jumped over the lazy dog";
//!
//! let mu: [u8; 64] = pk.compute_mu(msg, None).unwrap();
//! ```
//!
//! Note: a `ctx` value (explained below) is bound into `mu` here, as the argument of `compute_mu`.
//!
//! If the message really is so huge that it can't all be held in memory at once, then it might
//! be preferable to use a streaming API for computing mu:
//!
//! ```rust
//! use bouncycastle_core::errors::SignatureError;
//! use bouncycastle_core::signature_key::{SigningKey, VerifyingKey};
//! use bouncycastle_core::traits::{SignatureSigner, SignatureVerifier};
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_mldsa_lowmemory::{MLDSA65, MLDSATrait, MLDSAPublicKeyTrait, MuBuilder};
//!
//! let (pk, _) = MLDSA65::keygen(&mut HashDRBG_SHA512::new_from_os()).unwrap();
//!
//! // Let's pretend this message was so long that it couldn't possibly
//! // streamed in its entirety over a network, and it needs to be pre-hashed.
//! let msg_chunk1 = b"The quick brown fox ";
//! let msg_chunk2 = b"jumped over the lazy dog";
//!
//! let mut mb = pk.create_mu_builder(None).unwrap();
//! mb.do_update(msg_chunk1);
//! mb.do_update(msg_chunk2);
//! let mu = mb.do_final();
//! ```
//!
//! Given a mu value, it is possible to compute a signature that verifies as normal (no mu's required!):
//!
//! ```rust
//! use bouncycastle_core::errors::SignatureError;
//! use bouncycastle_core::signature_key::{SigningKey, VerifyingKey};
//! use bouncycastle_core::traits::{SignatureSigner, SignatureVerifier};
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_mldsa_lowmemory::{MLDSA65, MLDSATrait, MLDSAPrivateKeyTrait, MLDSAPublicKeyTrait, MuBuilder};
//!
//! let msg = b"The quick brown fox jumped over the lazy dog";
//!
//! let (pk, sk) = MLDSA65::keygen(&mut HashDRBG_SHA512::new_from_os()).unwrap();
//!
//! // Assume this was computed somewhere else and received by the user.
//! // Then the sender would have had to know pk!
//! let mu: [u8; 64] = pk.compute_mu(msg, None).unwrap();
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let sig = sk.sign_mu(&mu, &mut rng).unwrap();
//! // This is the signature value that can be saved to a file or whatever it is need.
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
//! Various functions in this crate allows setting the signing context value (`ctx`) and the signing nonce (`rnd`).
//! Here is an overview of both:
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
//! use bouncycastle_core::signature_key::{SigningKey, VerifyingKey};
//! use bouncycastle_core::traits::{SignatureSigner, SignatureVerifier};
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_mldsa_lowmemory::{MLDSA65, MLDSATrait};
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
//! # Signing from a seed
//!
//! The private key of this crate is the seed: a very careful analysis of the ML-DSA signing
//! algorithm shows that the entire expanded private key never needs to be in memory at the same
//! time, so keygen() and sign() are merged and every signing method of the key
//! ([`SigningKey::create_signer`], [`MLDSAPrivateKeyTrait::sign_mu`] and the rest) derives
//! each row of the key as it is needed. That has a significantly lower peak memory footprint
//! than signing with a fully expanded key and, on our benchmarks, is only around 25% slower
//! than it, which is still faster than a full keygen followed by a regular sign since the
//! intermediate values common to keygen and sign are computed once.
//!
//! Since this is intended for hard-core embedded systems people, this has not been wrapped in all
//! the beginner-friendly APIs. It is implied that a user that needs this functionality also knows how
//! to use it and what they are doing
//!
//! Example usage:
//!
//! ```rust
//! use bouncycastle_core::errors::SignatureError;
//! use bouncycastle_core::signature_key::{SigningKey, VerifyingKey};
//! use bouncycastle_core::traits::{SignatureSigner, SignatureVerifier};
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType, KeyMaterialTrait};
//! use bouncycastle_hex as hex;
//! use bouncycastle_mldsa_lowmemory::{MLDSA44, MLDSA44_SIG_LEN, MLDSATrait, MLDSAPrivateKeyTrait, MLDSAPublicKeyTrait, MuBuilder};
//!
//! let msg = b"The quick brown fox jumped over the lazy dog";
//!
//! let seed = KeyMaterial256::from_bytes_as_type(
//!     &hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap(),
//!     KeyType::Seed,
//! ).unwrap();
//!
//! // The public key is computed so that the signature can be verified by anyone; the private
//! // key is the seed plus the public key hash `tr`, which binds the public key at signing time.
//! let (pk, sk) = MLDSA44::keygen_from_seed(&seed).unwrap();
//! let tr: [u8; 64] = pk.compute_tr();
//!
//! // Assume this was computed somewhere else, then
//! // the party that computed it would have had to know pk
//! let mut mb = MuBuilder::from_tr(&tr, None).unwrap();
//! mb.do_update(msg);
//! let mu: [u8; 64] = mb.do_final();
//!
//! let mut sig = [0u8; MLDSA44_SIG_LEN];
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
//! This crate's private key is the seed, so a key that exists only in FIPS 204's skEncode form (the
//! "semi-expanded" encoding `bouncycastle-mldsa` stores, from which the seed cannot be recovered)
//! cannot be imported here. A signer that derives each row from that encoding as it goes would be
//! possible in the same way; contact us if you need one.
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
//! use bouncycastle_mldsa_lowmemory::{MLDSA65, MuBuilder, MLDSATrait, MLDSAPrivateKeyTrait, MLDSAPublicKeyTrait};
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
//! use bouncycastle_mldsa_lowmemory::{MLDSA65, MuBuilder, MLDSATrait, MLDSAPublicKeyTrait};
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

use crate::aux_functions::{unpack_c_tilde, unpack_h_row};
use crate::low_memory_helpers::{
    compute_ct0_component, compute_w_row, compute_w0cs2_component, compute_wp_approx_row,
    compute_z_component, s_unpack,
};
use crate::mldsa_keys::{MLDSAPrivateKeyInternalTrait, MLDSAPrivateKeyTrait};
use crate::mldsa_keys::{MLDSAPublicKeyInternalTrait, MLDSAPublicKeyTrait};
use crate::params::{
    FullPrivateKeyLen, MLDSA44Params, MLDSA65Params, MLDSA87Params, MLDSAParams, MLDSAParamsBase,
    SignatureLen,
};
use crate::{MLDSAPublicKey, MLDSASeedPrivateKey};
use bouncycastle_core::errors::{RNGError, SignatureError};
use bouncycastle_core::key_material::KeyMaterial;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::signature_key::{
    DeterministicSigningKey, SignatureAlgorithm, SigningKey, VerifyingKey,
};
use bouncycastle_core::traits::{
    Algorithm, AlgorithmOID, Hash, RNG, SignatureSigner, SignatureVerifier, XOF, XOFSqueezer,
};
use bouncycastle_mldsa_common::aux_functions::{bitpack_gamma1_out, sample_in_ball};
use core::marker::PhantomData;

// imports needed just for docs
#[allow(unused_imports)]
use crate::hash_mldsa;
#[allow(unused_imports)]
use bouncycastle_core::key_material::{KeyMaterial256, KeyMaterialTrait};
use bouncycastle_utils::secret::{Secret, ZeroizablePrimitive};

/*** Constants ***/

// The constants, names and XOF aliases FIPS 204 fixes for every parameter set are shared with
// `bouncycastle-mldsa` and live in `bouncycastle-mldsa-common`.
pub(crate) use bouncycastle_mldsa_common::{H, N, POLY_T0PACKED_LEN, POLY_T1PACKED_LEN};
#[doc(inline)]
pub use bouncycastle_mldsa_common::{ML_DSA_44_NAME, ML_DSA_65_NAME, ML_DSA_87_NAME};
#[doc(inline)]
pub use bouncycastle_mldsa_common::{MLDSA_MU_LEN, MLDSA_RND_LEN, MLDSA_SEED_LEN, MLDSA_TR_LEN};

/*** Re-exporting length constants that a caller will need instead of the entire Params objects which contains a bunch of internal algorithm detail ***/

/// Length of the \[u8] holding an ML-DSA-44 public key.
pub const MLDSA44_PK_LEN: usize = MLDSA44Params::PK_LEN;
/// Length of the \[u8] holding an ML-DSA-44 private key, which in this implementation is just a 32-byte seed.
pub const MLDSA44_SK_LEN: usize = MLDSA44Params::SK_LEN;
/// The length of the FIPS representation of the private key, which can be produced by [`MLDSAPrivateKeyTrait::encode_full_sk`]
pub const MLDSA44_FULL_SK_LEN: usize = MLDSA44Params::FULL_SK_LEN;
/// Length of the \[u8] holding an ML-DSA-44 signature value.
pub const MLDSA44_SIG_LEN: usize = MLDSA44Params::SIG_LEN;

/// Length of the \[u8] holding an ML-DSA-65 public key.
pub const MLDSA65_PK_LEN: usize = MLDSA65Params::PK_LEN;
/// Length of the \[u8] holding an ML-DSA-65 private key, which in this implementation is just a 32-byte seed.
pub const MLDSA65_SK_LEN: usize = MLDSA65Params::SK_LEN;
/// The length of the FIPS representation of the private key, which can be produced by [`MLDSAPrivateKeyTrait::encode_full_sk`]
pub const MLDSA65_FULL_SK_LEN: usize = MLDSA65Params::FULL_SK_LEN;
/// Length of the \[u8] holding an ML-DSA-65 signature value.
pub const MLDSA65_SIG_LEN: usize = MLDSA65Params::SIG_LEN;

/// Length of the \[u8] holding an ML-DSA-87 public key.
pub const MLDSA87_PK_LEN: usize = MLDSA87Params::PK_LEN;
/// Length of the \[u8] holding an ML-DSA-87 private key, which in this implementation is just a 32-byte seed.
pub const MLDSA87_SK_LEN: usize = MLDSA87Params::SK_LEN;
/// The length of the FIPS representation of the private key, which can be produced by [`MLDSAPrivateKeyTrait::encode_full_sk`]
pub const MLDSA87_FULL_SK_LEN: usize = MLDSA87Params::FULL_SK_LEN;
/// Length of the \[u8] holding an ML-DSA-87 signature value.
pub const MLDSA87_SIG_LEN: usize = MLDSA87Params::SIG_LEN;

/*** Pub Types ***/

/// The ML-DSA-44 algorithm.
pub type MLDSA44 = MLDSA<MLDSA44Params>;

/// The ML-DSA-65 algorithm.
pub type MLDSA65 = MLDSA<MLDSA65Params>;

/// The ML-DSA-87 algorithm.
pub type MLDSA87 = MLDSA<MLDSA87Params>;

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
    /// Performs the first step of key generation to transform the single provided seed into a set of internal intermediate seeds.
    ///
    /// Unlike other interfaces across the library that take an &impl KeyMaterial, this one
    /// specifically takes a 32-byte [`KeyMaterial256`] and checks that it has [`KeyType::Seed`] and
    /// the appropriate [`SecurityStrength`] for the requested ML-DSA parameter set.
    ///
    /// If you happen to have your seed in a larger KeyMaterial, you'll have to copy it into a
    /// correctly-sized [`KeyMaterial256`] using [`KeyMaterialTrait::truncate`].
    pub(crate) fn keygen_internal(
        seed: &KeyMaterial256,
    ) -> Result<(MLDSAPublicKey<P>, MLDSASeedPrivateKey<P>), SignatureError> {
        let (sk, pk) = MLDSASeedPrivateKey::<P>::from_keymaterial_with_pk(seed)?;
        Ok((pk, sk))
    }
}

impl<P: MLDSAParams> MLDSATrait<P> for MLDSA<P> {
    /*** Key Generation and PK / SK consistency checks ***/

    /// Imports a secret key from a seed.
    fn keygen_from_seed(
        seed: &KeyMaterial<32>,
    ) -> Result<(MLDSAPublicKey<P>, MLDSASeedPrivateKey<P>), SignatureError> {
        Self::keygen_internal(seed)
    }
    /// Imports a secret key from both a seed and an encoded_sk.
    ///
    /// This is a convenience function to expand the key from seed and compare it against
    /// the provided `encoded_sk` using a constant-time equality check.
    /// If everything checks out, the secret key is returned fully populated with pk and seed.
    /// If the provided key and derived key don't match, an error is returned.
    fn keygen_from_seed_and_encoded<const FULL_SK_LEN: usize>(
        seed: &KeyMaterial<32>,
        encoded_sk: &[u8; FULL_SK_LEN],
    ) -> Result<(MLDSAPublicKey<P>, MLDSASeedPrivateKey<P>), SignatureError>
    where
        P: FullPrivateKeyLen<FULL_SK_LEN>,
    {
        let (pk, sk) = Self::keygen_internal(seed)?;

        // The stored form of a key here is the seed itself, so the only encoding worth checking
        // against is the FIPS 204 Algorithm 24 one a conventionally exported key arrives in.
        if !bouncycastle_utils::ct::ct_eq_bytes(&sk.encode_full_sk(), encoded_sk) {
            return Err(SignatureError::KeyGenError("Encoded key does not match generated key"));
        }

        Ok((pk, sk))
    }
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
        sk: &MLDSASeedPrivateKey<P>,
    ) -> Result<(), SignatureError> {
        // tr = H(pk) was computed when the key was built, so no derivation is needed here.
        if bouncycastle_utils::ct::ct_eq_bytes(sk.tr(), &pk.compute_tr()) {
            Ok(())
        } else {
            Err(SignatureError::ConsistencyCheckFailed)
        }
    }
}

/// Algorithm 7 ML-DSA.Sign_internal(𝑠𝑘, 𝑀′, 𝑟𝑛𝑑), taking an externally computed mu in place of
/// M'. The key traits' `sign_mu_*` methods call it.
///
/// This function is a mash-up of keyGen (Algorithm 6) and sign (Algorithm 7),
/// with a special emphasis on deriving values only as they are needed, which in particular
/// means that matrices and vectors are processed row or component-wise.
pub(crate) fn sign_internal<
    P: SignatureLen<SIG_LEN>,
    SK: MLDSAPrivateKeyInternalTrait<P>,
    const SIG_LEN: usize,
>(
    sk: &SK,
    mu: &[u8; 64],
    rnd: [u8; 32],
    output: &mut [u8; SIG_LEN],
) -> Result<usize, SignatureError> {
    output.fill(0);

    // This function is a mash-up of keyGen (Algorithm 6) and sign (Algorithm 7),
    // with a special emphasis on deriving values only as they are needed, which in particular
    // means that matrices and vectors are processed row or component-wise.

    // This has been kept as clean as possible for correspondence with the FIPS,
    // but things have been moved around so that unnamed scopes can be used to limit how many
    // stack variables are alive at the same time.

    // 1: (𝜌, 𝐾, 𝑡𝑟, 𝐬1, 𝐬2, 𝐭0) ← skDecode(𝑠𝑘)
    // to avoid having all of it in memory at the same time,
    // components are derived as they are needed.

    // [Optimization Note]:
    // s1 and s2 are normally part of the stored private key.
    // They are used many times through this function,
    // so they are being computed here and kept in the compressed encoding specified in
    // FIPS 204 Alg 17.
    // They are uncompresso as-needed, and only one polynomial at a time.
    // Storing these in memory can be avoided, but then all the sites where they are used
    // will require calls to sk.compute_s1_row() and sk.compute_s2_row(), which are fairly expensive.
    let s1_packed: Secret<P::S1Packed> = sk.compute_s1_packed();
    let s2_packed: Secret<P::S2Packed> = sk.compute_s2_packed();

    // 6: 𝜇 ← H(BytesToBits(𝑡𝑟)||𝑀 ′, 64)
    // skip: mu has already been provided

    // Alg 7; 7: 𝜌″ ← H(𝐾||𝑟𝑛𝑑||𝜇, 64)
    let rho_p_p: Secret<[u8; 64]> = {
        let mut h = H::new();
        h.do_update(sk.K());
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

    let z_offset = P::C_TILDE_LEN;
    let hint_offset = P::C_TILDE_LEN + P::l * P::POLY_Z_PACKED_LEN;

    loop {
        // FIPS 204 s. 6.2 allows:
        //   "Implementations may limit the number of iterations in this loop to not exceed a finite maximum value."
        // mutants note: there is no test for this because we don't have access to a KAT that will exceed this limit.
        if kappa > 1000 * P::k as u16 {
            // "the signing algorithm shall return a constant that represents an error and no
            // other output, destroying the results of the unsuccessful signing attempts"
            // (FIPS 204 s. 6.2): the rejected candidate's c~ and z are in `output`.
            output.fill(0);
            return Err(SignatureError::RejectionLimitExceeded);
        }

        // 11-15: derive c_tilde without materializing y_hat or w as full vectors.
        let sig_val_c_tilde = {
            // scope for hash
            let mut hash = H::new();
            hash.do_update(mu);
            for row in 0..P::k {
                let mut w = compute_w_row::<P>(sk.rho(), &rho_p_p, kappa, row);
                w.high_bits_inplace::<P>();
                hash.do_update(w.w1_encode::<P>().as_ref());
            }
            let mut sig_val_c_tilde = <P::SigCTilde as ZeroizablePrimitive>::ZEROED;
            let mut hash = hash.into_squeezer();
            hash.do_output_out(sig_val_c_tilde.as_mut());
            sig_val_c_tilde
        };
        // 16: 𝑐 ∈ 𝑅𝑞 ← SampleInBall(c_tilde)
        // 17: 𝑐_hat ← NTT(𝑐)
        // optimization note: c_hat is used basically until the end, it can't really be scoped
        let mut c_hat = sample_in_ball::<P>(&sig_val_c_tilde);
        c_hat.ntt();

        output.fill(0);
        output[..P::C_TILDE_LEN].copy_from_slice(sig_val_c_tilde.as_ref());

        // The 𝐳 coordinates occupy `P::l` consecutive `P::POLY_Z_PACKED_LEN`-byte windows
        // starting at `z_offset`.
        debug_assert!(z_offset + P::l * P::POLY_Z_PACKED_LEN <= SIG_LEN);

        // 18-23 (z path): compute and encode each z polynomial directly into the caller buffer.
        let mut rejected = false;
        for col in 0..P::l {
            let z = match compute_z_component::<P>(
                // [Optimization Note]:
                // This is one of the places that a row of s1 can be re-computed instead of unpacked from the compressed form.
                // weirdly, in perf testing, this actually caused memory usage to go by a small amount;
                // maybe because re-computing the intermediates adds more to the widest point of the alg?
                // sk.compute_s1_row(col),
                s_unpack::<P, _>(&s1_packed, col),
                &rho_p_p,
                &c_hat,
                kappa,
                col,
            ) {
                Some(z) => z,
                None => {
                    rejected = true;
                    break;
                }
            };

            let start = z_offset + col * P::POLY_Z_PACKED_LEN;
            bitpack_gamma1_out::<P>(&z, &mut output[start..start + P::POLY_Z_PACKED_LEN]);
        }

        if rejected {
            // mutants note: we don't have access to a test vector that exercises this
            kappa += P::l as u16;
            continue;
        }

        // 19-28 (hint path): recompute rows as needed and write the packed hint directly.
        let mut hint_count = 0usize;
        for row in 0..P::k {
            let mut w = compute_w_row::<P>(sk.rho(), &rho_p_p, kappa, row);
            let mut tmp = match compute_w0cs2_component::<P>(
                // [Optimization Note]:
                // This is one of the places that a row of s1 can be re-computed instead of unpacked from the compressed form.
                // sk.compute_s2_row(row),
                s_unpack::<P, _>(&s2_packed, row),
                &w,
                &c_hat,
            ) {
                Some(tmp) => tmp,
                None => {
                    rejected = true;
                    break;
                }
            };

            let ct0 = match compute_ct0_component::<P>(
                // [Optimization Note]:
                // This is one of the places that a row of s1 can be re-computed instead of unpacked from the compressed form.
                // sk.compute_t0_row(row), &c_hat) {
                sk.compute_t0_row(row, &s1_packed, &s2_packed),
                &c_hat,
            ) {
                Some(ct0) => ct0,
                None => {
                    rejected = true;
                    break;
                }
            };

            tmp.add_ntt(&ct0);
            tmp.conditional_add_q();

            w.high_bits_inplace::<P>();
            let (hint_row, weight) = tmp.make_hint::<P>(&w);
            let next_hint_count = hint_count + weight as usize;

            // mutants note: don't have a test vector that exercises this condition,
            //  not even in bc-test-data
            if next_hint_count > P::omega as usize {
                rejected = true;
                break;
            }

            for idx in 0..N {
                if hint_row[idx] != 0 {
                    output[hint_offset + hint_count] = idx as u8;
                    hint_count += 1;
                }
            }
            debug_assert_eq!(hint_count, next_hint_count);
            output[hint_offset + P::omega as usize + row] = hint_count as u8;
        }

        if rejected {
            kappa += P::l as u16;
            continue;
        }

        break;
    }

    Ok(SIG_LEN)
}

/// Algorithm 8 ML-DSA.Verify_internal(𝑝𝑘, 𝑀′, 𝜎), taking an externally computed mu in place of
/// M'. The key traits' `verify_mu` calls it.
/// Input: Public key 𝑝𝑘 ∈ 𝔹32+32𝑘(bitlen (𝑞−1)−𝑑) and message 𝑀′ ∈ {0, 1}∗ .
/// Input: Signature 𝜎 ∈ 𝔹𝜆/4+ℓ⋅32⋅(1+bitlen (𝛾1−1))+𝜔+𝑘.
pub(crate) fn verify_internal<
    P: SignatureLen<SIG_LEN>,
    PK: MLDSAPublicKeyInternalTrait<P>,
    const SIG_LEN: usize,
>(
    pk: &PK,
    mu: &[u8; 64],
    sig: &[u8; SIG_LEN],
) -> Result<(), SignatureError> {
    // 1: (𝜌, 𝐭1) ← pkDecode(𝑝𝑘)
    // Already done -- the pk struct is already decoded

    // 5: 𝐀 ← ExpandA(𝜌)
    //   ▷ 𝐀 is generated and stored in NTT representation as 𝐀
    // This is  done one row / polynomial at a time to reduce peak memory usage so that
    // the entirety of A_hat is never in memory at the same time.

    // 6: 𝑡𝑟 ← H(𝑝𝑘, 64)
    // 7: 𝜇 ← (H(BytesToBits(𝑡𝑟)||𝑀 ′, 64))
    //   ▷ message representative that may optionally be
    //     computed in a different cryptographic module
    // skip because this function is being handed mu

    // 8: 𝑐 ∈ 𝑅𝑞 ← SampleInBall(c_tilde)
    // NTT(𝑐) from line 9 is taken once here rather than once per row below.
    let mut c_hat = sample_in_ball::<P>(&unpack_c_tilde::<P>(sig));
    c_hat.ntt();

    // 12: 𝑐_tilde_p ← H(𝜇||w1Encode(𝐰1'), 𝜆/4)
    // ▷ hash it; this should match 𝑐_tilde
    let mut hash = H::new();
    hash.do_update(mu);

    for row in 0..P::k {
        // 9: 𝐰′_approx ← NTT−1(𝐀_hat ∘ NTT(𝐳) − NTT(𝑐) ∘ NTT(𝐭1 ⋅ 2^𝑑))
        let mut wp_approx = match compute_wp_approx_row::<P, SIG_LEN>(
            pk.rho(),
            sig,
            pk.unpack_t1_row(row),
            &c_hat,
            row,
        ) {
            Some(wp_approx) => wp_approx,
            // means the norm check on z failed
            None => return Err(SignatureError::SignatureVerificationFailed),
        };

        let h_i = match unpack_h_row::<P, SIG_LEN>(row, sig) {
            Some(h_i) => h_i,
            // means there were more than OMEGA bits set in the hint
            None => return Err(SignatureError::SignatureVerificationFailed),
        };

        // 10: 𝐰1′ ← UseHint(𝐡, 𝐰'_approx)
        // ▷ reconstruction of signer’s commitment
        wp_approx.use_hint::<P>(&h_i);
        hash.do_update(wp_approx.w1_encode::<P>().as_ref());
    }

    let mut c_tilde_p = <P::SigCTilde as ZeroizablePrimitive>::ZEROED;
    let mut hash = hash.into_squeezer();
    hash.do_output_out(c_tilde_p.as_mut());

    // Verification is also done in constant time
    // 13 (second half): return [[ ||𝐳||∞ < 𝛾1 − 𝛽]] and [[𝑐 ̃ = 𝑐′ ]]
    //   note: the first half of this check (the norm check) is buried in unpack_z_row(),
    //         which is called from compute_wp_approx_row()
    if bouncycastle_utils::ct::ct_eq_bytes(unpack_c_tilde::<P>(sig).as_ref(), c_tilde_p.as_ref()) {
        Ok(())
    } else {
        Err(SignatureError::SignatureVerificationFailed)
    }
}

/// Trait for all three of the ML-DSA algorithm variants.
pub trait MLDSATrait<P: MLDSAParams>: Sized {
    /// Key generation from the caller's RNG, which must offer at least the parameter set's
    /// security strength.
    // Should still be ok in FIPS mode, provided that you're using the FIPS-approved RNG.
    fn keygen(
        rng: &mut dyn RNG,
    ) -> Result<(MLDSAPublicKey<P>, MLDSASeedPrivateKey<P>), SignatureError> {
        // Source the seed from the provided RNG
        if rng.security_strength() < P::MAX_SECURITY_STRENGTH {
            return Err(RNGError::SecurityStrengthInsufficientForAlgorithm.into());
        }
        let mut seed = KeyMaterial::<32>::new();
        rng.fill_keymaterial_out(&mut seed)?;
        Self::keygen_from_seed(&seed)
    }
    /// Imports a secret key from a seed.
    fn keygen_from_seed(
        seed: &KeyMaterial<32>,
    ) -> Result<(MLDSAPublicKey<P>, MLDSASeedPrivateKey<P>), SignatureError>;
    /// Imports a secret key from a seed and checks it against the same key in the FIPS 204
    /// Algorithm 24 skEncode() form, `FULL_SK_LEN` bytes, with a constant-time comparison.
    ///
    /// A key here is stored as its seed, so this is the check for a caller who holds both the
    /// seed and a conventionally exported private key and wants to know they agree. On a
    /// mismatch [`SignatureError::KeyGenError`] is returned.
    fn keygen_from_seed_and_encoded<const FULL_SK_LEN: usize>(
        seed: &KeyMaterial<32>,
        encoded_sk: &[u8; FULL_SK_LEN],
    ) -> Result<(MLDSAPublicKey<P>, MLDSASeedPrivateKey<P>), SignatureError>
    where
        P: FullPrivateKeyLen<FULL_SK_LEN>;
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
        sk: &MLDSASeedPrivateKey<P>,
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
/// private key, which it borrows; the signing randomizer is fixed when the signer is made, and
/// the key is expanded from its seed only when the signature is finished.
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

/*** The role impls, for the parameter set the key belongs to ***/

impl<P: SignatureLen<SIG_LEN>, const SIG_LEN: usize> SigningKey<MLDSA<P>, SIG_LEN>
    for MLDSASeedPrivateKey<P>
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
    for MLDSASeedPrivateKey<P>
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

// The message representative builder is shared with the other ML-DSA crate and lives in
// `bouncycastle-mldsa-common`.
#[doc(inline)]
pub use bouncycastle_mldsa_common::mu_builder::{MuBuilder, SUSPENDED_MU_BUILDER_STATE_LEN};
