//! X448 (RFC 7748 Section 5), the Diffie-Hellman function over Curve448, on the key agreement
//! roles: [`X448PrivateKey`] implements [`AgreementKey`] over `()` for the raw shared secret `K`
//! of RFC 7748 Section 6.2 and over [`KdfParams`] of HKDF-SHA512 for a key derived from it, and
//! the [`DecapsulatingKey`] role for DHKEM(X448, HKDF-SHA512) of RFC 9180 Section 4.1, whose
//! [`EncapsulatingKey`] is [`X448PublicKey`]. The module has the shape of [`crate::ed::x25519`].
//!
//! # Usage Examples
//!
//! ## Generating keys
//!
//! [`keygen`] draws the 56-byte private key from the caller's RNG, which must offer 192 bits;
//! [`keygen_from_seed`] takes those bytes as a 56-byte [`KeyMaterial`] of [`KeyType::Seed`] or
//! [`KeyType::CryptographicRandom`] at [`SecurityStrength::_192bit`] or more, and refuses an
//! all-zero one, which `KeyMaterial` types `Zeroized`. [`X448PrivateKey::from_bytes`] imports
//! an existing private key from any 56 bytes, all-zero included (a valid key, `2^447` once
//! clamped), and stores them clamped.
//!
//! ```rust
//! use bouncycastle_ec::ed::x448::keygen;
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let (pk, sk) = keygen(&mut HashDRBG_SHA512::new_from_os())?;
//! assert_eq!(sk.pk()?, pk);
//! # Ok::<(), bouncycastle_core::errors::KeyAgreementError>(())
//! ```
//!
//! ## X448 key agreement
//!
//! Each party combines their own private key with the other's public key through the
//! [`AgreementKey`] role, and both arrive at the same `K`. Over `()` that is the raw shared
//! secret, typed [`KeyType::SharedSecret`]: for a KDF and nothing else (see
//! [Security Considerations](#-security-considerations-)). Over [`KdfParams`] of HKDF-SHA512
//! the key comes back derived, with the fixed info the caller supplies, which should carry both
//! public keys in an order both parties agree on.
//!
//! ```rust
//! use bouncycastle_core::agreement_key::AgreementKey;
//! use bouncycastle_core::kdf_params::{KdfParams, KeyLen};
//! use bouncycastle_core::key_material::{KeyMaterialTrait, KeyType};
//! use bouncycastle_core::security_strength::SecurityStrength;
//! use bouncycastle_core::traits::PublicKey;
//! use bouncycastle_ec::ed::x448::keygen;
//! use bouncycastle_digest::hkdf::HkdfDescription;
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_digest::sha2::SHA512;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let (alice_pk, alice_sk) = keygen(&mut rng)?;
//! let (bob_pk, bob_sk) = keygen(&mut rng)?;
//!
//! // The raw shared secret. An error means the other party's public key is unusable (a point
//! // of small order): abort the exchange.
//! let k_a = alice_sk.agree(&bob_pk, ())?;
//! let k_b = bob_sk.agree(&alice_pk, ())?;
//! assert!(k_a.equals(&k_b));
//! assert_eq!(k_a.key_type(), KeyType::SharedSecret);
//!
//! // The same agreement with the KDF applied: a 32-byte key, CryptographicRandom at X448's
//! // 192 bits, from one call on each side.
//! let mut info = [0u8; 112];
//! info[..56].copy_from_slice(&alice_pk.encode());
//! info[56..].copy_from_slice(&bob_pk.encode());
//! let hkdf = HkdfDescription::<SHA512>::new();
//! let key_a = alice_sk.agree(&bob_pk, KdfParams::new(&hkdf, &info, KeyLen::<32>))?;
//! let key_b = bob_sk.agree(&alice_pk, KdfParams::new(&hkdf, &info, KeyLen::<32>))?;
//! assert!(key_a.equals(&key_b));
//! assert_eq!(key_a.key_type(), KeyType::CryptographicRandom);
//! assert_eq!(key_a.security_strength(), SecurityStrength::_192bit);
//! # Ok::<(), bouncycastle_core::errors::KeyAgreementError>(())
//! ```
//!
//! ## X448 as a KEM
//!
//! [`X448PublicKey`] and [`X448PrivateKey`] also implement [`EncapsulatingKey`] and
//! [`DecapsulatingKey`], with `()` as the parameters, as DHKEM(X448, HKDF-SHA512) of RFC 9180
//! Section 4.1. The ciphertext is a 56-byte ephemeral public key, and the 64-byte shared secret
//! is already the output of a KDF, ready to use as a key.
//!
//! ```rust
//! use bouncycastle_core::kem_key::{DecapsulatingKey, EncapsulatingKey};
//! use bouncycastle_ec::ed::x448::keygen;
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let (pk, sk) = keygen(&mut rng).unwrap();
//!
//! let (ss, ct) = pk.encaps(&mut rng, ())?;
//! let ss1 = sk.decaps(&ct, ())?;
//! assert_eq!(ss, ss1);
//! # Ok::<(), bouncycastle_core::errors::KEMError>(())
//! ```
//!
//! A public key is its 56 bytes, compared as bytes: the two encodings of one point (`u` and
//! `u + p`, for `u` up to `2^224`) are two keys to [`PartialEq`]. A protocol that compares
//! keys should compare canonical encodings.
//!
//! Like any unauthenticated Diffie-Hellman, X448 on its own resists only passive eavesdroppers,
//! so a protocol must authenticate the public keys, for example by signing them.
//!
//! # Memory Usage
//!
//! There are no lookup tables and no heap allocation, and no state is held between calls other
//! than the keys:
//!
//! | Key Object | PK size on disk | PK size in memory | SK size on disk | SK size in memory |
//! |------------|-----------------|-------------------|-----------------|-------------------|
//! | X448       | 56              | 56                | 56              | 113               |
//!
//! All values are in bytes. The "in memory" sizes are measured by rust's `std::mem::size_of`.
//! [`X448PrivateKey`] holds its public key alongside the 56-byte scalar.
//!
//! Per-call stack usage, measured as [`crate::ed::x25519`]'s is: the deepest frame chain from the
//! `measure` wrapper of `mem_usage_benches`' x448 harness down, the wrapper's own frame
//! included, in the release build of the harness with every bench called from one `main`
//! (x86-64 Linux, rustc 1.97.0-nightly, return addresses included):
//!
//! | Entry point                       | Stack  |
//! |-----------------------------------|--------|
//! | `keygen_from_seed`                | 3352 B |
//! | `keygen_out`                      | 2728 B |
//! | `X448PrivateKey::from_bytes`      | 3064 B |
//! | `X448PrivateKey::from_bytes_out`  | 2728 B |
//! | `agree` on the private key        | 2856 B |
//! | `encaps` on the public key        | 5720 B |
//! | `decaps` on the private key       | 5224 B |
//!
//! The first five each run one Montgomery ladder plus the field inversion, which use 1800 B
//! below the entry point's own frame; the peak is the 2584 B frame that then overwrites that
//! stack (see "What is wiped" below). The `keygen_out` figure leaves out the RNG. The KEM
//! figures peak in the 2 KiB stack wipe that follows the construction of HKDF-SHA512's HMAC
//! key, and the `encaps` figure includes the DRBG that draws the ephemeral key.
//!
//! # 🚨 Security Considerations 🚨
//!
//! **A raw shared secret is not a key**. The agreement over `()` returns `K` as a
//! [`KeyMaterial`] typed [`KeyType::SharedSecret`]: the 56-byte encoding of the u-coordinate of
//! a point on curve448, which is not uniformly random. That type is accepted by the KDFs and by
//! nothing that takes a key; the HKDF-SHA512 pairing and the DHKEM are the two derivations this
//! module offers over it. Put both public keys into the KDF's info: several public keys give the same shared
//! secret as any one of them (RFC 7748 Section 7, quoted in [`crate::ed::x25519`]).
//!
//! An all-zero `K`, the output for a peer key of small order, is refused as
//! [`KeyAgreementError::AgreementFailed`]: RFC 7748 Section 6.2 makes the check optional ("both
//! sides MAY check, without leaking extra information about the value of K, whether the
//! resulting shared K is the all-zero value and abort if so") and this module always performs
//! it, in constant time, so the only thing it reveals about `K` is whether it is zero.
//!
//! **The private key `4 * order`.** Four times the order of the base point is a clamped
//! scalar, so it is an X448 private key, and the agreement role computes with it as RFC 7748
//! Section 5 says. Its public key is all zero and it contributes nothing against a point of
//! the curve, so the DHKEM refuses it as a private key ([`KEMError::DecodingError`], and
//! `DeriveKeyPair` fails on it), making the check RFC 9180 Section 7.1.2 recommends and says
//! X448 does not need. A random key is that one with probability `2^-446`.
//!
//! **`DeriveKeyPair` input.** RFC 9180 Section 7.1.3: the input keying material "SHOULD have
//! length at least Nsk, and SHOULD have at least Nsk bytes of entropy", 56 for X448. What is
//! enforced here is the strength its type carries, 192 bits, not the length: 32 full-entropy
//! octets are accepted.
//!
//! **Strength.** RFC 7748 Section 7 puts curve448 at the "~224-bit security level".
//! [`SecurityStrength`] has no such level, so X448 is classed at the next one down, 192 bits:
//! that is what its RNG and seeds must offer and what its secrets are credited with. The
//! pairing's derived key carries the least of that, the KDF's and the length's strength.
//!
//! **What is wiped, and what is not.** `K`, the decoded scalar and the ladder's and the
//! inversion's field elements each live in a `Secret` or a self-wiping field element and are
//! cleared at the end of their lifetime; `agree_out` writes into the caller's buffer, and
//! [`keygen_out`] and [`keygen_from_seed_out`] draw the scalar straight into a key the caller
//! holds. A value returned by value is moved, and a move does not wipe its source: that holds
//! for the key pairs of [`keygen`], [`keygen_from_seed`], the trait's `from_bytes` and
//! `DeriveKeyPair`, for `clone`, for the clamped scalar `encode` returns, and for the results
//! of `core`'s by-value `agree`, `encaps` and `decaps`. Use the `_out` forms,
//! [`X448PrivateKey::from_bytes_out`] and `clone_from`, into a buffer or key you own where that
//! matters. [`keygen`], [`keygen_from_seed`], `from_bytes` and `clone` build the key in a frame
//! of their own whose stack is overwritten afterwards, so the copies left are those of the
//! caller's moves, not of theirs.
//!
//! These wipes are made in the source, and a copy the compiler makes on its own is beyond them.
//! A stack probe of this module (one release build, x86-64) found register spills left below
//! the frame after every scalar multiplication: two of the eight limbs of the result, which is
//! `K` in an agreement, and two and four limbs of two intermediates of the field inversion. So
//! each scalar multiplication runs in a frame of its own and the 2560 bytes of stack below its
//! caller are overwritten afterwards, after which the same probe finds nothing secret on the
//! stack once [`keygen_out`], [`keygen_from_seed_out`] or the raw `agree_out` has returned.
//! That is a measurement of one build, not a guarantee: a compiler or target whose frames run
//! deeper is not covered. The HKDF-SHA512 pairing leaves a copy of `K` in HKDF's own frames,
//! which are that crate's. After `encaps_out` and `decaps_out` the probe finds no key and no
//! X448 output, and three of the eight 64-bit words of the KEM's shared secret in SHA-512's
//! frames; what the KDF's frames keep is in `crate::dhkem`'s Security Considerations.
//!
//! A DHKEM private key is not forward secret (RFC 9180 Section 9.7.4, quoted in
//! [`crate::ed::x25519`]).
//!
//! On a 32-bit target every `i128` product of the field arithmetic is a call into the compiler's
//! runtime (`__multi3`), so constant time there rests on that routine, not on this module.

use crate::dhkem::{
    AuthDecapsulatingKey, AuthEncapsulatingKey, DHKEM, DHKEMParams, DeriveKeyPairForm, HpkeKem,
};
use bouncycastle_core::agreement_key::{AgreementKey, KeyAgreementAlgorithm};
use bouncycastle_core::errors::{
    KEMError, KeyAgreementError, KeyDecodingError, KeyMaterialError, RNGError,
};
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::kdf_params::KdfParams;
use bouncycastle_core::kem_key::{DecapsulatingKey, EncapsulatingKey, KEMAlgorithm};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{
    Algorithm, AlgorithmOID, KEMDecapsulator, KEMEncapsulator, KeyAgreement, PrivateKey, PublicKey,
    RNG,
};
use bouncycastle_digest::hkdf::HkdfDescription;
use bouncycastle_digest::sha2::SHA512;
use bouncycastle_utils::ct::{Condition, ct_eq_bytes, ct_eq_zero_bytes};
use bouncycastle_utils::secret::{Secret, zeroize_in_place};
use bouncycastle_utils::stack_wipe::{in_wiped_frame_scaled, wipe_stack_below};
use core::fmt::{self, Display, Formatter};

use crate::ed::curve448::FieldElement448;

/*** Constants ***/

/// Size in bytes of the encoded u-coordinate of a point on curve448, which is a public key.
pub const POINT_LEN: usize = 56;
/// Size in bytes of an encoded X448 scalar, which is a private key.
pub const SCALAR_LEN: usize = 56;

/// String name of the X448 algorithm.
pub const X448_NAME: &str = "X448";

/// The base point of curve448, `U(P) = 5` (RFC 7748 Section 4.2).
const BASE_POINT: X448PublicKey = {
    let mut u = [0_u8; POINT_LEN];
    u[0] = 5;
    X448PublicKey(u)
};

/// The coefficient A of curve448, `v^2 = u^3 + A*u^2 + u` (RFC 7748 Section 4.2).
const C_A: u32 = 156326;

/// `(A + 2) / 4 = 39082`, the ladder's doubling constant.
///
/// Deviation from the RFC: RFC 7748 Section 5 uses `a24 = (156326 - 2) / 4 = 39081` in
/// `z_2 = E * (AA + a24 * E)`. Since `E = AA - BB`, `AA + a24 * E = BB + (a24 + 1) * E`, so
/// pairing the constant with BB instead needs `a24 + 1 = (A + 2) / 4`. [`ladder`] and
/// [`ladder_double`] both use that form.
const C_A24: u32 = (C_A + 2) / 4;

/// The X448 key agreement algorithm of RFC 7748 Section 5.
pub struct X448;

impl Algorithm for X448 {
    const ALG_NAME: &'static str = X448_NAME;
    // RFC 7748 Section 7: "The ~224-bit security level of curve448". SecurityStrength has no
    // 224-bit level, so the algorithm is classed at the highest level that does not exceed it.
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_192bit;
}

impl KeyAgreementAlgorithm for X448 {}

/// `id-X448` (RFC 8410 Section 3), which identifies the public key and the private key alike.
/// The HKDF-SHA512 pairing and the DHKEM have none there.
impl AlgorithmOID for X448 {
    const OID: &'static [u32] = &[1, 3, 101, 111];
    const OID_DER: &'static [u8] = &[0x06, 0x03, 0x2B, 0x65, 0x6F];
}

/// What the stack wipe overwrites, in 64-bit words, after [`keygen`], [`keygen_from_seed`], the
/// trait's `from_bytes` and `clone` build a key in a frame of their own, which the move out of
/// it would otherwise leave holding a copy: 1024 bytes. `dev_scripts/ecdsa_stack_harness` passes
/// with 320 bytes wiped and fails with 256 (x86-64 release builds, rustc 1.97 and 1.88).
const BY_VALUE_STACK_WORDS: usize = 128;

/// Generates a key pair from `rng`, which must offer X448's 192 bits: the 56 bytes it draws are
/// the private key (RFC 7748 Section 6.2: "Alice and Bob generate 56 random bytes").
///
/// [`keygen_out`] into a key you hold, moved out of this frame; a move wipes nothing (the
/// module's Security Considerations).
///
/// # Errors
/// [`KeyAgreementError::RNGError`] if the RNG is weaker than the algorithm or fails to deliver.
pub fn keygen(rng: &mut dyn RNG) -> Result<(X448PublicKey, X448PrivateKey), KeyAgreementError> {
    in_wiped_frame_scaled::<u64, 0, BY_VALUE_STACK_WORDS, _>(|| {
        let mut sk = X448PrivateKey::zeroized();
        keygen_out(rng, &mut sk)?;
        let pk = sk.pk;
        Ok((pk, sk))
    })
}

/// Generates a private key into `sk`, a key you hold: the RNG, which must offer X448's 192 bits,
/// writes the 56 bytes of the scalar straight into the key's own `Secret` (RFC 7748 Section
/// 6.2), so no copy of it is staged on the way. The public key is read from the key afterwards
/// with [`sk.pk()`](X448PrivateKey::pk), which cannot fail once this has returned `Ok`. `sk` is
/// zeroized first and left so on every error.
///
/// # Errors
/// [`KeyAgreementError::RNGError`] if the RNG is weaker than the algorithm or fails to deliver.
pub fn keygen_out(rng: &mut dyn RNG, sk: &mut X448PrivateKey) -> Result<(), KeyAgreementError> {
    sk.clear();
    if rng.security_strength() < X448::MAX_SECURITY_STRENGTH {
        return Err(RNGError::SecurityStrengthInsufficientForAlgorithm.into());
    }
    if let Err(e) = crate::rng_draw::fill_bytes(rng, &mut *sk.k) {
        sk.clear();
        return Err(e.into());
    }
    sk.fill_pk();
    Ok(())
}

/// The key pair whose private key is `seed`'s 56 bytes: a [`KeyMaterial`] typed
/// [`KeyType::Seed`] or [`KeyType::CryptographicRandom`], at [`SecurityStrength::_192bit`] or
/// more. The bytes are kept as given; the clamping of RFC 7748 Section 5 is applied when they
/// are used, and the encoding is the clamped form.
///
/// [`keygen_from_seed_out`] into a key you hold, moved out of this frame; a move wipes nothing
/// (the module's Security Considerations).
///
/// # Errors
/// [`KeyAgreementError::KeyMaterialError`] for a seed of another type or length, or of too
/// little strength.
pub fn keygen_from_seed(
    seed: &KeyMaterial<SCALAR_LEN>,
) -> Result<(X448PublicKey, X448PrivateKey), KeyAgreementError> {
    in_wiped_frame_scaled::<u64, 0, BY_VALUE_STACK_WORDS, _>(|| {
        let mut sk = X448PrivateKey::zeroized();
        keygen_from_seed_out(seed, &mut sk)?;
        let pk = sk.pk;
        Ok((pk, sk))
    })
}

/// The private key whose scalar is `seed`'s 56 bytes, into `sk`, a key you hold: the seed's
/// requirements are [`keygen_from_seed`]'s, and the bytes are copied once, into the key's own
/// `Secret`. The public key is read as after [`keygen_out`]. `sk` is zeroized first and left so
/// on every error.
///
/// # Errors
/// [`KeyAgreementError::KeyMaterialError`] for a seed of another type or length, or of too
/// little strength.
pub fn keygen_from_seed_out(
    seed: &KeyMaterial<SCALAR_LEN>,
    sk: &mut X448PrivateKey,
) -> Result<(), KeyAgreementError> {
    sk.clear();
    if seed.key_type() == KeyType::Zeroized {
        return Err(KeyMaterialError::ActingOnZeroizedKey.into());
    }
    if !(seed.key_type() == KeyType::Seed || seed.key_type() == KeyType::CryptographicRandom)
        || seed.key_len() != SCALAR_LEN
    {
        return Err(KeyMaterialError::InvalidKeyType(
            "an X448 seed is 56 bytes of KeyType::Seed or KeyType::CryptographicRandom",
        )
        .into());
    }
    if seed.security_strength() < X448::MAX_SECURITY_STRENGTH {
        return Err(KeyMaterialError::SecurityStrength(
            "an X448 seed must carry at least 192 bits of strength",
        )
        .into());
    }

    sk.k.copy_from_slice(seed.ref_to_bytes());
    sk.fill_pk();
    Ok(())
}

/// Checks that `pk` is the public key of `sk`. The keys are compared as their 56 bytes, so
/// another encoding of the same point is not the key of `sk`.
///
/// # Errors
/// [`KeyAgreementError::ConsistencyCheckFailed`] if it is not;
/// [`KeyMaterialError::ActingOnZeroizedKey`] for a private key that was never filled
/// ([`X448PrivateKey::zeroized`]).
pub fn keypair_consistency_check(
    pk: &X448PublicKey,
    sk: &X448PrivateKey,
) -> Result<(), KeyAgreementError> {
    // Both sides are public keys, so the comparison need not be constant time.
    if sk.pk()? == *pk { Ok(()) } else { Err(KeyAgreementError::ConsistencyCheckFailed) }
}

/// `K = X448(k, u)` of RFC 7748 Section 6.2 into `out`, the u-coordinate of the peer's public
/// key multiplied by our scalar as its 56-byte little-endian encoding, refused when all zero
/// (and `out` left zeroized then).
///
/// Any 56 bytes are accepted as `pk`: per Section 5, values `>= p` are processed as if reduced
/// mod p. An all-zero output means `pk` has small order; the check is constant time, so the
/// only information it reveals about `K` is whether it is zero.
fn raw_shared_secret(
    sk: &X448PrivateKey,
    pk: &X448PublicKey,
    out: &mut Secret<[u8; POINT_LEN]>,
) -> Result<(), KeyAgreementError> {
    scalar_mult_into(&sk.k, pk, out);
    if ct_eq_zero_bytes(&**out) {
        zeroize_in_place(&mut **out);
        return Err(KeyAgreementError::AgreementFailed);
    }
    Ok(())
}

/// The worker an [`X448PrivateKey`] hands out through [`AgreementKey`] over `()`: the raw `K`,
/// typed [`KeyType::SharedSecret`] at 192 bits. It holds only the key and is reusable.
pub struct X448Agreement<'k> {
    sk: &'k X448PrivateKey,
}

impl Algorithm for X448Agreement<'_> {
    const ALG_NAME: &'static str = X448::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = X448::MAX_SECURITY_STRENGTH;
}

impl KeyAgreement<X448PublicKey, POINT_LEN> for X448Agreement<'_> {
    /// `K` into the caller's buffer, zeroized first and left so on the error path.
    fn agree_out(
        &self,
        peer_pk: &X448PublicKey,
        ss: &mut KeyMaterial<POINT_LEN>,
    ) -> Result<usize, KeyAgreementError> {
        ss.zeroize();
        // `K` is computed into this frame's one Secret, which is wiped when it drops; the field
        // elements of the ladder and the inversion below it wipe themselves the same way.
        let mut k = Secret::<[u8; POINT_LEN]>::new();
        raw_shared_secret(self.sk, peer_pk, &mut k)?;
        // `K` is never all zero here, so the buffer's own zero test cannot type it `Zeroized`.
        // A SharedSecret's strength is its producer's to state: X448's 192 bits.
        if let Err(e) = ss.set_bytes_as_type(&*k, KeyType::SharedSecret).and_then(|()| {
            do_hazardous_operations(ss, |ss| ss.set_security_strength(X448::MAX_SECURITY_STRENGTH))
        }) {
            ss.zeroize();
            return Err(e.into());
        }
        Ok(POINT_LEN)
    }
}

impl AgreementKey<(), POINT_LEN> for X448PrivateKey {
    type Algorithm = X448;
    type PublicKey = X448PublicKey;
    type Agreement<'k> = X448Agreement<'k>;

    fn create_agreement<'k>(
        &'k self,
        _params: (),
    ) -> Result<Self::Agreement<'k>, KeyAgreementError> {
        if !self.filled {
            return Err(KeyMaterialError::ActingOnZeroizedKey.into());
        }
        Ok(X448Agreement { sk: self })
    }
}

/*** The same keys under HKDF-SHA512: the pairing, and the role impl over it ***/

/// X448 with its shared secret put through HKDF-SHA512, a KDF over `K` and both public keys
/// being what RFC 7748 Section 6.1 has the parties use and Section 6.2 carries over to X448:
/// the caller's [`KdfParams`] name the HKDF description (its salt, if any) and the fixed info,
/// which should carry both public keys. The derived key is typed by the KDF's accounting,
/// `CryptographicRandom` at the least of X448's 192 bits, the KDF's and the length's.
#[allow(non_camel_case_types)]
pub struct X448_HKDF_SHA512;

impl Algorithm for X448_HKDF_SHA512 {
    const ALG_NAME: &'static str = "X448-HKDF-SHA512";
    const MAX_SECURITY_STRENGTH: SecurityStrength = X448::MAX_SECURITY_STRENGTH;
}

impl KeyAgreementAlgorithm for X448_HKDF_SHA512 {}

/// The most HKDF-SHA512 can derive in one call (RFC 5869 Section 2.3: L <= 255 * HashLen),
/// which bounds the role's `LEN`.
pub const HKDF_SHA512_MAX_LEN: usize = 255 * 64;

/// The worker an [`X448PrivateKey`] hands out through [`AgreementKey`] over [`KdfParams`] of
/// HKDF-SHA512: `K` from the primitive, then the KDF, built from the description for this
/// derivation, into the caller's buffer.
pub struct X448KdfAgreement<'k, 'p, 's, const LEN: usize> {
    sk: &'k X448PrivateKey,
    params: KdfParams<'p, HkdfDescription<'s, SHA512>, LEN>,
}

impl<const LEN: usize> Algorithm for X448KdfAgreement<'_, '_, '_, LEN> {
    const ALG_NAME: &'static str = X448_HKDF_SHA512::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = X448_HKDF_SHA512::MAX_SECURITY_STRENGTH;
}

impl<const LEN: usize> KeyAgreement<X448PublicKey, LEN> for X448KdfAgreement<'_, '_, '_, LEN> {
    fn agree_out(
        &self,
        peer_pk: &X448PublicKey,
        ss: &mut KeyMaterial<LEN>,
    ) -> Result<usize, KeyAgreementError> {
        const {
            assert!(
                LEN > 0 && LEN <= HKDF_SHA512_MAX_LEN,
                "the derived key is from one byte to 255 * 64 bytes long"
            )
        };
        ss.zeroize();
        // `K` lives in this one local, wiped when it drops; what HKDF's own frames keep of it
        // is that crate's.
        let mut k = KeyMaterial::<POINT_LEN>::new();
        X448Agreement { sk: self.sk }.agree_out(peer_pk, &mut k)?;
        // The engine is an HKDF keyed with the description's salt, if any, built for this
        // derivation; `ss` is zeroized first and left so on every error.
        self.params.derive_out(&k, ss)?;
        Ok(LEN)
    }
}

impl<'p, 's, const LEN: usize> AgreementKey<KdfParams<'p, HkdfDescription<'s, SHA512>, LEN>, LEN>
    for X448PrivateKey
{
    type Algorithm = X448_HKDF_SHA512;
    type PublicKey = X448PublicKey;
    type Agreement<'k> = X448KdfAgreement<'k, 'p, 's, LEN>;

    fn create_agreement<'k>(
        &'k self,
        params: KdfParams<'p, HkdfDescription<'s, SHA512>, LEN>,
    ) -> Result<Self::Agreement<'k>, KeyAgreementError> {
        if !self.filled {
            return Err(KeyMaterialError::ActingOnZeroizedKey.into());
        }
        Ok(X448KdfAgreement { sk: self, params })
    }
}

/// An X448 private key: a 56-byte scalar, as defined in Section 5 of RFC 7748.
///
/// Any 56 bytes are a valid scalar. The fixed bits `decodeScalar448` sets and clears
/// ("clamping") are applied each time the scalar is used, so keys that differ only in those bits
/// are the same key, and compare equal. Held in a [`Secret`], so it is zeroized on drop, and
/// the type has no `Debug`.
///
/// The public key is computed once, when the private key is created or decoded, and stored with
/// it.
pub struct X448PrivateKey {
    k: Secret<[u8; SCALAR_LEN]>,
    pk: X448PublicKey,
    /// Whether the key has been generated or decoded. The public key cannot say so, as
    /// X25519's does: the clamped scalar `4 * order` is a valid X448 private key whose public
    /// key is all zero.
    filled: bool,
}

impl X448PrivateKey {
    /// The all-zero key: the key [`keygen_out`] and [`keygen_from_seed_out`] write into, so
    /// that the scalar is drawn where it will live and never moved. It is not a generated key:
    /// until one of them fills it, it has no public key and makes no agreement
    /// ([`KeyMaterialError::ActingOnZeroizedKey`]), and it is equal to no key that was generated
    /// or decoded.
    ///
    /// # 🚨 Security Considerations 🚨
    ///
    /// The encoding of this key is not refused, the encoding methods having no error to give:
    /// it is the clamped all-zero scalar, which anyone can compute. Do not store or send the
    /// encoding of a key whose generation failed.
    pub fn zeroized() -> Self {
        Self { k: Secret::new(), pk: X448PublicKey([0; POINT_LEN]), filled: false }
    }

    /// Back to the all-zero key, the scalar wiped.
    fn clear(&mut self) {
        self.k.zeroize();
        self.pk = X448PublicKey([0; POINT_LEN]);
        self.filled = false;
    }

    /// Decodes the 56 bytes of a private key into `sk`, a key you hold: they are copied
    /// straight into the key and clamped there, so no copy is staged on the way, where the
    /// trait's [`from_bytes`](PrivateKey::from_bytes) moves the key it returns. `sk` is zeroized
    /// first and left so on an error.
    ///
    /// # Errors
    ///
    /// [`KeyDecodingError`] if `bytes` is not 56 bytes.
    pub fn from_bytes_out(bytes: &[u8], sk: &mut Self) -> Result<(), KeyDecodingError> {
        sk.clear();
        if bytes.len() != SCALAR_LEN {
            return Err(KeyDecodingError("An X448 private key must be 56 bytes"));
        }
        sk.k.copy_from_slice(bytes);
        clamp(&mut sk.k);
        sk.fill_pk();
        Ok(())
    }

    /// Computes the public key of the scalar now in the key, which makes it a filled key.
    fn fill_pk(&mut self) {
        self.pk = scalar_mult_base(&self.k);
        self.filled = true;
    }

    /// Whether the scalar is a multiple of the group order, which is so exactly when the public
    /// key of a filled key is all zero (the one such clamped scalar is `4 * order`). X448
    /// itself computes with that key; the DHKEM refuses it ([`NOT_A_DHKEM_KEY`]). The public
    /// key is public, so nothing secret is branched on unless the key is that one.
    fn is_zero_mod_order(&self) -> bool {
        self.filled && self.pk.0 == [0u8; POINT_LEN]
    }

    /// Whether the DHKEM takes this key as a private key: it is filled, and not `4 * order`.
    fn check_dhkem_key(&self) -> Result<(), KEMError> {
        if !self.filled {
            return Err(KeyMaterialError::ActingOnZeroizedKey.into());
        }
        if self.is_zero_mod_order() {
            return Err(KEMError::DecodingError(NOT_A_DHKEM_KEY));
        }
        Ok(())
    }

    /// The public key, `X448(k, 5)` (RFC 7748 Section 6.2), which was computed when this key
    /// was made.
    ///
    /// # Errors
    /// [`KeyMaterialError::ActingOnZeroizedKey`] for a key that was never filled
    /// ([`zeroized`](Self::zeroized)).
    pub fn pk(&self) -> Result<X448PublicKey, KeyAgreementError> {
        if !self.filled {
            return Err(KeyMaterialError::ActingOnZeroizedKey.into());
        }
        Ok(self.pk)
    }

    /// The key bytes, [`clamp`]ed, into `out`.
    fn clamped_into(&self, out: &mut [u8; SCALAR_LEN]) {
        *out = *self.k;
        clamp(out);
    }
}

/// Applies `decodeScalar448`'s fixed bits to the key bytes `k` (RFC 7748 Section 5):
///
/// ```text
/// k_list[0] &= 252
/// k_list[55] |= 128
/// ```
fn clamp(k: &mut [u8; SCALAR_LEN]) {
    k[0] &= 252;
    k[55] |= 128;
}

/// The encoding is the 56 key bytes, clamped (the bit operations of `decodeScalar448`, RFC 7748
/// Section 5), so keys that compare equal have the same encoding.
impl PrivateKey<SCALAR_LEN> for X448PrivateKey {
    /// The clamped scalar as a plain array, the trait's contract; prefer `encode_out` into a
    /// buffer you own, since the array is moved out unwiped.
    fn encode(&self) -> [u8; SCALAR_LEN] {
        let mut out = [0u8; SCALAR_LEN];
        self.clamped_into(&mut out);
        out
    }

    fn encode_out(&self, out: &mut [u8; SCALAR_LEN]) -> usize {
        self.clamped_into(out);
        SCALAR_LEN
    }

    /// Any 56 bytes are a valid private key; they are clamped on the way in.
    ///
    /// # Errors
    ///
    /// [`KeyDecodingError`] if `bytes` is not 56 bytes.
    fn from_bytes(bytes: &[u8]) -> Result<Self, KeyDecodingError> {
        in_wiped_frame_scaled::<u64, 0, BY_VALUE_STACK_WORDS, _>(|| {
            let mut sk = Self::zeroized();
            Self::from_bytes_out(bytes, &mut sk)?;
            Ok(sk)
        })
    }
}

/// `clone` returns the copy by value, and a move wipes nothing (the module's Security
/// Considerations); `clone_from` copies field by field into a key you hold.
impl Clone for X448PrivateKey {
    fn clone(&self) -> Self {
        in_wiped_frame_scaled::<u64, 0, BY_VALUE_STACK_WORDS, _>(|| {
            let mut sk = Self::zeroized();
            sk.clone_from(self);
            sk
        })
    }

    fn clone_from(&mut self, source: &Self) {
        self.k.copy_from_slice(&*source.k);
        self.pk = source.pk;
        self.filled = source.filled;
    }
}

/// Constant-time comparison of the clamped scalars. A key that was never filled equals only
/// another such key.
impl PartialEq for X448PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        let (mut a, mut b) = (Secret::<[u8; SCALAR_LEN]>::new(), Secret::<[u8; SCALAR_LEN]>::new());
        self.clamped_into(&mut a);
        other.clamped_into(&mut b);
        // The filled state is part of the comparison (an unfilled key and the key decoded from
        // 56 zero bytes hold the same scalar); it is not secret.
        ct_eq_bytes(&*a, &*b) & (self.filled == other.filled)
    }
}

impl Eq for X448PrivateKey {}

/// An X448 public value: the u-coordinate of a point on curve448, as 56 little-endian bytes
/// (Section 5 of RFC 7748).
///
/// Any 56 bytes are accepted: Section 5 requires values `>= p` to be processed as if reduced
/// mod p. Public data, so it is `Copy` and its `Debug` shows the bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X448PublicKey([u8; POINT_LEN]);

impl X448PublicKey {
    /// The 56 encoded bytes.
    pub const fn as_bytes(&self) -> &[u8; POINT_LEN] {
        &self.0
    }
}

/// The encoding is the 56 bytes of the u-coordinate, as is (RFC 7748 Section 5).
impl PublicKey<POINT_LEN> for X448PublicKey {
    fn encode(&self) -> [u8; POINT_LEN] {
        self.0
    }

    fn encode_out(&self, out: &mut [u8; POINT_LEN]) -> usize {
        *out = self.0;
        POINT_LEN
    }

    /// Any 56 bytes are accepted: RFC 7748 Section 5 requires values `>= p` to be processed as
    /// if reduced mod p.
    ///
    /// # Errors
    ///
    /// [`KeyDecodingError`] if `bytes` is not 56 bytes.
    fn from_bytes(bytes: &[u8]) -> Result<Self, KeyDecodingError> {
        let bytes: &[u8; POINT_LEN] = bytes
            .try_into()
            .map_err(|_| KeyDecodingError("An X448 public key must be 56 bytes"))?;
        Ok(Self(*bytes))
    }
}

impl AsRef<[u8]> for X448PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// The 56 bytes in hex.
impl Display for X448PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "X448PublicKey {{ ")?;
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        write!(f, " }}")
    }
}

/// `decodeScalar448(k)` as defined in Section 5 of RFC 7748:
///
/// ```text
/// def decodeScalar448(k):
///     k_list = [ord(b) for b in k]
///     k_list[0] &= 252
///     k_list[55] |= 128
///     return decodeLittleEndian(k_list, 448)
/// ```
///
/// Section 5 on the result: "the resulting integer is of the form 2^447 plus four times a value
/// between 0 and 2^445 - 1 (inclusive)". That is why [`ladder`] can start at bit 446 against a
/// pre-swapped initial state, and why its last two iterations collapse into two
/// [`ladder_double`] calls with no trailing conditional swap.
///
/// Deviation from the RFC: the RFC masks bytes and then decodes, whereas this decodes into
/// four-byte words first and masks the equivalent word positions. `k_list[0] &= 252` becomes
/// `n[0] &= 0xFFFFFFFC`, the same low two bits, and `k_list[55] |= 128` becomes
/// `n[13] |= 0x80000000`, the same top bit.
///
/// Input: A 56-byte little-endian scalar.
/// Output: The decoded scalar, written to `n` as fourteen little-endian 32-bit words.
fn decode_scalar_448(k: &[u8; SCALAR_LEN], n: &mut [u32; 14]) {
    let (words, _) = k.as_chunks::<4>(); // 56 bytes: exactly 14 chunks, no remainder
    for (n_i, w) in n.iter_mut().zip(words) {
        *n_i = u32::from_le_bytes(*w);
    }

    n[0] &= 0xFFFFFFFC_u32;
    n[13] |= 0x80000000_u32;
}

/// `decodeUCoordinate(u, 448)` as defined in Section 5 of RFC 7748. With `bits` = 448,
/// `bits % 8` is 0 and no bit is masked: "implementations of X25519 (but not X448) MUST mask
/// the most significant bit in the final byte". What is left is the little-endian decode,
/// which is [`FieldElement448::decode_448`].
///
/// The result is not normalized, as Section 5 also requires: "Implementations MUST accept
/// non-canonical values and process them as if they had been reduced modulo the field prime.
/// The non-canonical values are ... 2^448 - 2^224 - 1 through 2^448 - 1 for X448".
fn decode_u_coordinate(u: &X448PublicKey) -> FieldElement448 {
    FieldElement448::decode_448(&u.0)
}

/// `encodeUCoordinate(u, 448)` as defined in Section 5 of RFC 7748. The RFC's `u = u % p` step
/// is [`FieldElement448::normalize`]: an X448 output is the canonical encoding of its residue
/// class.
fn encode_u_coordinate(u: &FieldElement448, r: &mut [u8; POINT_LEN]) {
    u.normalize().encode_448(r);
}

/// Doubles one point, held projectively as the pair `(x : z)` representing `u = x / z`,
/// in place: the doubling half of the ladder step in Section 5 of RFC 7748, which [`ladder`]
/// uses for its last two iterations. With `AA = (x + z)^2`, `BB = (x - z)^2` and `E = AA - BB`,
/// it writes `x = AA * BB` and `z = E * (BB + C_A24 * E)`; see [`C_A24`] for the pairing with
/// `BB`.
fn ladder_double(x: &mut FieldElement448, z: &mut FieldElement448) {
    let (mut a, mut b) = x.sum_and_difference(z);
    a = a.sqr();
    b = b.sqr();
    *x = a.mul(&b);

    a = a.sub(&b);
    let t = a.mul_u32(C_A24).add(&b);
    *z = t.mul(&a);
}

/// `X448(k, u)` as defined in Section 5 of RFC 7748: the Montgomery ladder, computing scalar
/// multiplication on curve448 from a u-coordinate alone, then the RFC's
/// `Return x_2 * (z_2^(p - 2))` and the encoding.
///
/// Constant time with respect to `k`: the ladder's iteration count is fixed, its only
/// scalar-dependent step is [`FieldElement448::cswap`], and the inversion is a fixed chain.
///
/// # Inputs
/// * `k`, a 56-byte scalar
/// * `u`, a 56-byte little-endian u-coordinate
///
/// Output: The canonical little-endian encoding of the u-coordinate of `k * u`.
///
/// The field elements wipe themselves, but the compiler also spills limbs of them to stack
/// slots that no wipe in the source reaches (a stack scan found limbs of the result and of two
/// powers of the inversion left behind), so the computation runs in a frame of its own and the
/// stack it used is overwritten afterwards.
fn scalar_mult_into(k: &[u8; SCALAR_LEN], u: &X448PublicKey, out: &mut [u8; POINT_LEN]) {
    scalar_mult_in_own_frame(k, u, out);
    wipe_stack_below::<WIPED_STACK_WORDS>();
}

/// How much stack [`wipe_stack_below`] overwrites, in 64-bit words: more than
/// [`scalar_mult_in_own_frame`] and everything it calls use (1800 bytes in the x86-64 release
/// build that was measured), with room for a compiler that lays the frames out less tightly.
const WIPED_STACK_WORDS: usize = 320;

/// The computation of [`scalar_mult_into`]. Never inlined, so that what it spills lies below
/// its caller's frame, where [`wipe_stack_below`] reaches it.
#[inline(never)]
fn scalar_mult_in_own_frame(k: &[u8; SCALAR_LEN], u: &X448PublicKey, out: &mut [u8; POINT_LEN]) {
    // The decoded scalar is as secret as `k` itself.
    let mut n: Secret<[u32; 14]> = Secret::new();
    decode_scalar_448(k, &mut n);

    // The ladder is only correct for scalars of the form 2^447 + 4m, which decode_scalar_448
    // makes of any input.
    debug_assert_eq!(1, n[13] >> 31);
    debug_assert_eq!(0, n[0] & 3);

    let x1 = decode_u_coordinate(u);
    let mut x2 = FieldElement448::zero();
    let mut z2 = FieldElement448::zero();
    ladder(&n, &x1, &mut x2, &mut z2);

    // Every field element here wipes itself when it drops: the result, the ladder's registers
    // and the inversion chain's. The encoding goes straight into the caller's buffer.
    let r = x2.mul(&z2.inv());
    encode_u_coordinate(&r, out);
}

/// The Montgomery ladder of [`scalar_mult_into`]: writes the projective u-coordinate of `n * x1`
/// to `(x2, z2)`, for a scalar `n` decoded by [`decode_scalar_448`].
///
/// Modified from the RFC to fold its first iteration into the initial state, to replace its
/// last two iterations with [`ladder_double`] calls, and to cycle its named intermediates
/// through a fixed set of registers.
// #[inline(never)]: so that the ladder's variables live in a frame of their own, popped before
// scalar_mult_into's `z2.inv()` runs (the other stack-expensive operation).
#[inline(never)]
fn ladder(n: &[u32; 14], x1: &FieldElement448, x2: &mut FieldElement448, z2: &mut FieldElement448) {
    *x2 = x1.clone();
    *z2 = FieldElement448::one();
    let mut x3 = FieldElement448::one();
    let mut z3 = FieldElement448::zero();

    let mut t1;
    let mut t2;

    let mut swap = Condition::<i64>::from_bool_const::<true>();

    // Deviation from the RFC:
    // RFC 7748 Section 5 runs `For t = bits-1 down to 0`, i.e. t = 447 down to 0, with the
    // conditional swap at the top of the body and the arithmetic after it. This loop deviates
    // in three ways, all of them consequences of the scalar's form, 2^447 + 4m:
    //
    //  1. Rotated body. The arithmetic comes first here and the swap last, so the pass for
    //     `bit` does the arithmetic of the RFC's iteration t = bit + 1 and the swap of t = bit.
    //  2. t = 447 has no swap in the loop, because bit 447 is always set and that swap is known
    //     in advance: the RFC starts from x_2 = 1, z_2 = 0, x_3 = u, z_3 = 1 and its first swap
    //     exchanges the pairs, so the registers above are seeded with the swapped values,
    //     x_2 = u, z_2 = 1, x_3 = 1, z_3 = 0, and `swap` starts at k_447. So the loop starts at
    //     446.
    //  3. The loop ends at bit 1, whose pass does the arithmetic of t = 2 and the swap of
    //     t = 1. Bits 1 and 0 are always clear, so that swap undoes the one before it, the
    //     arithmetic of t = 1 and t = 0 is a doubling of the (x_2, z_2) branch, and their
    //     swaps and the RFC's post-loop cswap are no-ops. Those are the two ladder_double
    //     calls after the loop; the debug_assert below checks the swap state they rely on.
    for bit in (1..=446_usize).rev() {
        // The RFC's lines, on registers reused to save memory.
        // Comment style:
        // <exact line from RFC 7748 Section 5>, -> <register stored to>

        // C = x_3 + z_3,               -> t1
        // D = x_3 - z_3,               -> x3
        (t1, x3) = x3.sum_and_difference(&z3);
        // A = x_2 + z_2,               -> z3
        // B = x_2 - z_2,               -> x2
        // Must follow the line above, not precede it: that one still reads the incoming z_3,
        // which this one overwrites.
        (z3, *x2) = x2.sum_and_difference(z2);
        // CB = C * B,                  -> t1
        t1 = t1.mul(x2);
        // DA = D * A,                  -> x3
        x3 = x3.mul(&z3);
        // AA = A^2,                    -> z3
        z3 = z3.sqr();
        // BB = B^2,                    -> x2
        *x2 = x2.sqr();

        // E = AA - BB,                 -> t2
        t2 = z3.sub(x2);
        // z_2 = E * (AA + a24 * E),    -> z2
        // Deviation from the RFC: written as E * (BB + C_A24 * E), an equivalent pairing of the
        // constant with the other operand. See C_A24's declaration.
        // The incoming z_2 died on the `sum_and_difference` above, which is what frees this slot.
        *z2 = t2.mul_u32(C_A24).add(x2).mul(&t2);
        // x_2 = AA * BB,               -> x2
        *x2 = x2.mul(&z3);

        // x_3 = (DA + CB)^2,           -> x3
        // z_3 = x_1 * (DA - CB)^2,     -> z3
        // Deviation from the RFC: the difference is CB - DA, negated. Harmless, as it is
        // squared.
        (x3, z3) = t1.sum_and_difference(&x3);
        // (completes x_3)
        x3 = x3.sqr();
        // (completes z_3)
        z3 = z3.sqr().mul(x1);

        // The swap, in the constant-time form the RFC recommends at the end of Section 5, with
        // an all-ones or all-zeros mask.

        // k_t = (k >> t) & 1
        let k_bit = Condition::<i64>::is_bit_set(n[bit >> 5] as i64, (bit & 0x1F) as u32);
        // swap ^= k_t
        swap ^= k_bit;
        // (x_2, x_3) = cswap(swap, x_2, x_3)
        FieldElement448::cswap(swap, x2, &mut x3);
        // (z_2, z_3) = cswap(swap, z_2, z_3)
        FieldElement448::cswap(swap, z2, &mut z3);
        // swap = k_t
        swap = k_bit;
    }

    debug_assert!(!swap.to_bool());

    for _ in 0..2 {
        ladder_double(x2, z2);
    }
}

fn scalar_mult_base(k: &[u8; SCALAR_LEN]) -> X448PublicKey {
    // The result is public, so it may live in the plain array of the key type. A fixed-base
    // table would make this faster; the variable-base ladder serves for now.
    let mut out = [0u8; POINT_LEN];
    scalar_mult_into(k, &BASE_POINT, &mut out);
    X448PublicKey(out)
}

/*** DHKEM ***/

// X448 as a KEM, through RFC 9180's DHKEM construction.

/// The length of the shared secret from [`X448`]'s KEM: Nsecret for DHKEM(X448, HKDF-SHA512)
/// (RFC 9180 Section 7.1, Table 2).
pub const DHKEM_SS_LEN: usize = 64;

/// The refusal of the private key `4 * order` by the DHKEM.
///
/// RFC 9180 Section 7.1.2: "implementors of DHKEMs SHOULD check that deserialized private keys
/// are not equivalent to 0 (mod order), where order is the order of the DH group. Note that
/// this property is trivially true for X25519 and X448 groups, since clamped values can never
/// be 0 (mod order)." The note does not hold for X448: `4 * order` is below `2^448`, has bit
/// 447 set and its two low bits clear, so it is a clamped value. The check is therefore made.
const NOT_A_DHKEM_KEY: &str =
    "An X448 private key equivalent to 0 mod the group order is not a DHKEM key";

/// DHKEM(X448, HKDF-SHA512) of RFC 9180 Section 4.1. Nenc = Npk = Nsk = 56 (Section 7.1,
/// Table 2) and Ndh = 56 (Section 4.1).
type X448DHKEM = DHKEM<X448, POINT_LEN, SCALAR_LEN, POINT_LEN, DHKEM_SS_LEN>;

/// DHKEM(X448, HKDF-SHA512): kem_id 0x0021, with Nenc = Npk = Nsk = 56 (RFC 9180 Section 7.1,
/// Table 2).
impl DHKEMParams<POINT_LEN, SCALAR_LEN, POINT_LEN> for X448 {
    type PublicKey = X448PublicKey;
    type PrivateKey = X448PrivateKey;
    type KDFHash = SHA512;
    const KEM_ID: u16 = 0x0021;

    fn with_generated_key_pair<R>(
        rng: &mut dyn RNG,
        f: impl FnOnce(&X448PublicKey, &X448PrivateKey) -> R,
    ) -> Result<R, KEMError> {
        // For X448, 56 random bytes are a private key (RFC 7748 Section 6.2). The key is
        // generated in this frame and dropped here, so its scalar is wiped where it was drawn.
        let mut sk = X448PrivateKey::zeroized();
        // keygen_out fails only through the RNG.
        keygen_out(rng, &mut sk).map_err(|e| match e {
            KeyAgreementError::RNGError(e) => KEMError::RNGError(e),
            _ => KEMError::GenericError("X448 key generation failed"),
        })?;
        let pk = sk.pk;
        Ok(f(&pk, &sk))
    }

    // RFC 9180 Section 7.1.3: "For X25519 and X448, the DeriveKeyPair() function applies a KDF
    // to the input".
    const DERIVE_KEY_PAIR: DeriveKeyPairForm = DeriveKeyPairForm::Expand;

    // Every 56 bytes are an X448 private key (RFC 7748 Section 5); the one the DHKEM does not
    // take is `None` (see NOT_A_DHKEM_KEY), which makes `DeriveKeyPair` fail on it.
    fn private_key_from_bytes(sk: &[u8; SCALAR_LEN]) -> Option<X448PrivateKey> {
        let mut key = X448PrivateKey::zeroized();
        *key.k = *sk;
        key.fill_pk();
        if key.is_zero_mod_order() { None } else { Some(key) }
    }

    /// The stored public key. For a key that was never filled that is the all-zero key, not a
    /// public key of `sk`; `dh_into` is what refuses such a key.
    fn pk(sk: &X448PrivateKey) -> X448PublicKey {
        sk.pk
    }

    fn dh_into(
        sk: &X448PrivateKey,
        pk: &X448PublicKey,
        out: &mut Secret<[u8; POINT_LEN]>,
    ) -> Result<(), KeyAgreementError> {
        // The group functions are reachable without a key's role (`DHKEM::decap_out`), so the
        // keys the roles refuse are refused here too.
        if !sk.filled {
            zeroize_in_place(&mut **out);
            return Err(KeyMaterialError::ActingOnZeroizedKey.into());
        }
        if sk.is_zero_mod_order() {
            zeroize_in_place(&mut **out);
            return Err(KeyAgreementError::DecodingError(NOT_A_DHKEM_KEY));
        }
        // RFC 9180 Section 7.1.4: "recipients MUST check whether the Diffie-Hellman shared
        // secret is the all-zero value and abort if so", which raw_shared_secret does in
        // constant time, for the sender as well.
        raw_shared_secret(sk, pk, out)
    }

    // RFC 9180 Section 7.1.1: for X448 "the SerializePublicKey() and DeserializePublicKey()
    // functions are the identity function".
    fn serialize_public_key(pk: &X448PublicKey) -> [u8; POINT_LEN] {
        pk.0
    }

    fn deserialize_public_key(pkm: &[u8; POINT_LEN]) -> Result<X448PublicKey, KEMError> {
        Ok(X448PublicKey(*pkm))
    }
}

/// DHKEM(X448, HKDF-SHA512) of RFC 9180 Section 4.1 (`kem_id` 0x0021, Section 7.1): the KEM the
/// X448 keys carry through [`EncapsulatingKey`] and [`DecapsulatingKey`], as distinct from the
/// X448 function itself, [`X448`].
#[allow(non_camel_case_types)]
pub struct DHKEM_X448_HKDF_SHA512;

impl Algorithm for DHKEM_X448_HKDF_SHA512 {
    const ALG_NAME: &'static str = "DHKEM(X448, HKDF-SHA512)";
    const MAX_SECURITY_STRENGTH: SecurityStrength = X448::MAX_SECURITY_STRENGTH;
}

impl KEMAlgorithm for DHKEM_X448_HKDF_SHA512 {}

impl HpkeKem for DHKEM_X448_HKDF_SHA512 {
    const KEM_ID: u16 = <X448 as DHKEMParams<POINT_LEN, SCALAR_LEN, POINT_LEN>>::KEM_ID;
}

/// The encapsulator an [`X448PublicKey`] hands out through [`EncapsulatingKey`]:
/// DHKEM(X448, HKDF-SHA512) of RFC 9180 Section 4.1, where the ciphertext is an ephemeral
/// public key (`enc`) and the shared secret is derived with HKDF-SHA512 from the X448 output
/// and both public keys. It borrows the recipient's key.
pub struct X448Encapsulator<'k> {
    pk: &'k X448PublicKey,
}

impl Algorithm for X448Encapsulator<'_> {
    const ALG_NAME: &'static str = DHKEM_X448_HKDF_SHA512::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = DHKEM_X448_HKDF_SHA512::MAX_SECURITY_STRENGTH;
}

impl KEMEncapsulator<POINT_LEN, DHKEM_SS_LEN> for X448Encapsulator<'_> {
    /// `Encap(pkR)` (RFC 9180 Section 4.1), drawing the ephemeral key pair from `rng`.
    ///
    /// # Errors
    ///
    /// * [`KEMError::RNGError`] if `rng`'s security strength is below 192 bits.
    /// * [`KEMError::InvalidPublicKey`] if the key gives an all-zero X448 output, the case the
    ///   agreement role refuses as [`KeyAgreementError::AgreementFailed`].
    fn encaps_out(
        &self,
        rng: &mut dyn RNG,
        ct: &mut [u8; POINT_LEN],
        ss: &mut KeyMaterial<DHKEM_SS_LEN>,
    ) -> Result<usize, KEMError> {
        ct.fill(0);
        ss.zeroize();
        X448DHKEM::encap_rng_out(self.pk, rng, ct, ss)
    }
}

/// X448 public keys encapsulate as DHKEM(X448, HKDF-SHA512), with `()` as the parameters.
impl EncapsulatingKey<(), POINT_LEN, DHKEM_SS_LEN> for X448PublicKey {
    type Algorithm = DHKEM_X448_HKDF_SHA512;
    type Encapsulator<'k> = X448Encapsulator<'k>;

    fn create_encapsulator<'k>(&'k self, _params: ()) -> Result<X448Encapsulator<'k>, KEMError> {
        Ok(X448Encapsulator { pk: self })
    }
}

/// `AuthEncap(pkR, skS)` of DHKEM(X448, HKDF-SHA512) (RFC 9180 Section 4.1), on the recipient's
/// public key: what HPKE's Auth and AuthPSK modes run over.
impl AuthEncapsulatingKey<POINT_LEN, DHKEM_SS_LEN> for X448PublicKey {
    type SenderPrivateKey = X448PrivateKey;

    /// # Errors
    ///
    /// * [`KEMError::RNGError`] if `rng`'s security strength is below 192 bits.
    /// * [`KEMError::InvalidPublicKey`] if the key gives an all-zero X448 output.
    /// * [`KEMError::KeyMaterialError`] if `sk_s` has not been filled, and
    ///   [`KEMError::DecodingError`] if it is the key `4 * order`.
    fn auth_encaps_out(
        &self,
        rng: &mut dyn RNG,
        sk_s: &X448PrivateKey,
        enc: &mut [u8; POINT_LEN],
        ss: &mut KeyMaterial<DHKEM_SS_LEN>,
    ) -> Result<usize, KEMError> {
        enc.fill(0);
        ss.zeroize();
        sk_s.check_dhkem_key()?;
        X448DHKEM::auth_encap_rng_out(self, sk_s, rng, enc, ss)
    }
}

/// `AuthDecap(enc, skR, pkS)` of DHKEM(X448, HKDF-SHA512) (RFC 9180 Section 4.1), on the
/// recipient's private key.
impl AuthDecapsulatingKey<POINT_LEN, DHKEM_SS_LEN> for X448PrivateKey {
    type SenderPublicKey = X448PublicKey;

    /// # Errors
    ///
    /// * [`KEMError::DecapsulationFailed`] if `enc` gives an all-zero X448 output.
    /// * [`KEMError::InvalidPublicKey`] if `pk_s` does.
    /// * [`KEMError::KeyMaterialError`] if this key has not been filled, and
    ///   [`KEMError::DecodingError`] if it is the key `4 * order`.
    fn auth_decaps_out(
        &self,
        enc: &[u8; POINT_LEN],
        pk_s: &X448PublicKey,
        ss: &mut KeyMaterial<DHKEM_SS_LEN>,
    ) -> Result<usize, KEMError> {
        ss.zeroize();
        self.check_dhkem_key()?;
        X448DHKEM::auth_decap_out(enc, self, pk_s, ss)
    }
}

/// The decapsulator an [`X448PrivateKey`] hands out through [`DecapsulatingKey`]:
/// DHKEM(X448, HKDF-SHA512) `Decap` of RFC 9180 Section 4.1. It borrows the recipient's key.
pub struct X448Decapsulator<'k> {
    sk: &'k X448PrivateKey,
}

impl Algorithm for X448Decapsulator<'_> {
    const ALG_NAME: &'static str = DHKEM_X448_HKDF_SHA512::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = DHKEM_X448_HKDF_SHA512::MAX_SECURITY_STRENGTH;
}

impl KEMDecapsulator<POINT_LEN, DHKEM_SS_LEN> for X448Decapsulator<'_> {
    /// `Decap(enc, skR)` (RFC 9180 Section 4.1), with the ciphertext `ct` as `enc`.
    ///
    /// # Errors
    ///
    /// [`KEMError::DecapsulationFailed`] if `ct` gives an all-zero X448 output.
    fn decaps_out(
        &self,
        ct: &[u8; POINT_LEN],
        ss: &mut KeyMaterial<DHKEM_SS_LEN>,
    ) -> Result<usize, KEMError> {
        ss.zeroize();
        X448DHKEM::decap_out(ct, self.sk, ss)
    }
}

/// X448 private keys decapsulate as DHKEM(X448, HKDF-SHA512), with `()` as the parameters.
impl DecapsulatingKey<(), POINT_LEN, DHKEM_SS_LEN> for X448PrivateKey {
    type Algorithm = DHKEM_X448_HKDF_SHA512;
    type Decapsulator<'k> = X448Decapsulator<'k>;

    /// # Errors
    ///
    /// [`KEMError::KeyMaterialError`] if the key has not been filled, and
    /// [`KEMError::DecodingError`] if it is the key `4 * order`, which the DHKEM does not take
    /// (the module's Security Considerations).
    fn create_decapsulator<'k>(&'k self, _params: ()) -> Result<X448Decapsulator<'k>, KEMError> {
        self.check_dhkem_key()?;
        Ok(X448Decapsulator { sk: self })
    }
}
