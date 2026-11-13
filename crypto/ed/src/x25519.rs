//! X25519 (RFC 7748 Section 5), the Diffie-Hellman function over Curve25519, on the key
//! agreement roles: [`X25519PrivateKey`] implements [`AgreementKey`] over `()` for the raw shared
//! secret `K` of RFC 7748 Section 6.1 and over [`KdfParams`] of HKDF-SHA256 for a key derived
//! from it, and the [`DecapsulatingKey`] role for DHKEM(X25519, HKDF-SHA256) of RFC 9180
//! Section 4.1, whose [`EncapsulatingKey`] is [`X25519PublicKey`].
//!
//! # Usage Examples
//!
//! ## Generating keys
//!
//! [`keygen`] draws the 32-byte private key from the caller's RNG, which must offer 128 bits;
//! [`keygen_from_seed`] takes those bytes as a [`KeyMaterial256`] of [`KeyType::Seed`] or
//! [`KeyType::CryptographicRandom`] at [`SecurityStrength::_128bit`] or more, and refuses an
//! all-zero one, which `KeyMaterial` types `Zeroized`. [`X25519PrivateKey::from_bytes`] imports
//! an existing private key from any 32 bytes, all-zero included (a valid key, `2^254` once
//! clamped), and stores them clamped.
//!
//! ```rust
//! use bouncycastle_ed::x25519::keygen;
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let (pk, sk) = keygen(&mut HashDRBG_SHA512::new_from_os())?;
//! assert_eq!(sk.pk(), pk);
//! # Ok::<(), bouncycastle_core::errors::KeyAgreementError>(())
//! ```
//!
//! ## X25519 key agreement
//!
//! Alice and Bob each generate a key pair and exchange public keys. Each combines their own
//! private key with the other's public key through the [`AgreementKey`] role, and both arrive
//! at the same `K`. Over `()` that is the raw shared secret, typed [`KeyType::SharedSecret`]:
//! for a KDF and nothing else (see [Security Considerations](#-security-considerations-)).
//! Over [`KdfParams`] of HKDF-SHA256 the key comes back derived, with the fixed info the
//! caller supplies; RFC 7748 Section 6.1 asks for a KDF over `K` and both public keys, so the
//! info here is the two public keys in an order both parties agree on.
//!
//! ```rust
//! use bouncycastle_core::agreement_key::AgreementKey;
//! use bouncycastle_core::kdf_params::{KdfParams, KeyLen};
//! use bouncycastle_core::key_material::{KeyMaterialTrait, KeyType};
//! use bouncycastle_core::security_strength::SecurityStrength;
//! use bouncycastle_core::traits::KeyAgreementPublicKey;
//! use bouncycastle_ed::x25519::keygen;
//! use bouncycastle_hkdf::HkdfDescription;
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_sha2::SHA256;
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
//! // The same agreement with the KDF applied: a 32-byte key, CryptographicRandom at X25519's
//! // 128 bits, from one call on each side.
//! let mut info = [0u8; 64];
//! info[..32].copy_from_slice(&alice_pk.encode());
//! info[32..].copy_from_slice(&bob_pk.encode());
//! let hkdf = HkdfDescription::<SHA256>::new();
//! let key_a = alice_sk.agree(&bob_pk, KdfParams::new(&hkdf, &info, KeyLen::<32>))?;
//! let key_b = bob_sk.agree(&alice_pk, KdfParams::new(&hkdf, &info, KeyLen::<32>))?;
//! assert!(key_a.equals(&key_b));
//! assert_eq!(key_a.key_type(), KeyType::CryptographicRandom);
//! assert_eq!(key_a.security_strength(), SecurityStrength::_128bit);
//! # Ok::<(), bouncycastle_core::errors::KeyAgreementError>(())
//! ```
//!
//! ## X25519 as a KEM
//!
//! [`X25519PublicKey`] and [`X25519PrivateKey`] also implement [`EncapsulatingKey`] and
//! [`DecapsulatingKey`], with `()` as the parameters, as DHKEM(X25519, HKDF-SHA256) of RFC 9180
//! Section 4.1, the KEM used by HPKE. The sender encapsulates against the recipient's public
//! key and gets a shared secret and a 32-byte ciphertext (an ephemeral public key) to send. The
//! shared secret is already the output of a KDF over the X25519 output and both public keys,
//! ready to use as a key.
//!
//! ```rust
//! use bouncycastle_core::kem_key::{DecapsulatingKey, EncapsulatingKey};
//! use bouncycastle_ed::x25519::keygen;
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let (pk, sk) = keygen(&mut rng).unwrap();
//!
//! // The sender encapsulates against the recipient's public key...
//! let (ss, ct) = pk.encaps(&mut rng, ())?;
//!
//! // ...and the recipient recovers the same shared secret from the ciphertext.
//! let ss1 = sk.decaps(&ct, ())?;
//! assert_eq!(ss, ss1);
//! # Ok::<(), bouncycastle_core::errors::KEMError>(())
//! ```
//!
//! A public key is its 32 bytes, compared as bytes: two encodings of one point (bit 255 set, or
//! `u + p`) are two keys to [`PartialEq`] and to `check-consistency`, and encapsulating to a
//! non-canonical encoding of the recipient's key gives a secret the recipient cannot derive from
//! the canonical one. Both follow RFC 7748 Section 5 and RFC 9180 Section 7.1.1 to the letter;
//! a protocol that compares keys should compare canonical encodings.
//!
//! Like any unauthenticated Diffie-Hellman, X25519 on its own resists only passive
//! eavesdroppers. An active attacker who can substitute public keys in transit can sit in the
//! middle, so a protocol must authenticate them, for example by signing them.
//!
//! # Memory Usage
//!
//! There are no lookup tables and no heap allocation, and no state is held between calls other
//! than the keys:
//!
//! | Key Object | PK size on disk | PK size in memory | SK size on disk | SK size in memory |
//! |------------|-----------------|-------------------|-----------------|-------------------|
//! | X25519     | 32              | 32                | 32              | 64                |
//!
//! All values are in bytes. The "in memory" sizes are measured by rust's `std::mem::size_of`.
//! [`X25519PrivateKey`] holds its public key alongside the 32-byte scalar.
//!
//! Per-call stack usage, measured as the deepest frame chain below each entry point of
//! `mem_usage_benches`' x25519 harness in the release build (x86-64 Linux, rustc 1.97.0-nightly,
//! return addresses included), on the key agreement roles with the field element's wipe:
//!
//! | Entry point                     | Stack  |
//! |---------------------------------|--------|
//! | `keygen_from_seed`              | 1784 B |
//! | `X25519PrivateKey::from_bytes`  | 1704 B |
//! | `agree` on the private key      | 1816 B |
//! | `encaps` on the public key      | 2792 B |
//! | `decaps` on the private key     | 2264 B |
//!
//! Key generation, decoding a private key, and key agreement each run one Montgomery ladder plus
//! the field inversion: the chain is the in-place scalar multiplication, the ladder and a field
//! multiplication.
//! The KEM figures additionally run HPKE.DHKEM, and their chain runs through HKDF-SHA256's HMAC
//! and SHA-256 compression. The `encaps` figure includes the DRBG that draws the ephemeral key.
//!
//! # 🚨 Security Considerations 🚨
//!
//! **A raw shared secret is not a key**. The agreement over `()` returns `K` as a
//! [`KeyMaterial`] typed [`KeyType::SharedSecret`]: the 32-byte encoding of the u-coordinate
//! of a point on curve25519, which is not uniformly random. That type is accepted by the KDFs
//! and by nothing that takes a key, so it cannot be used as one by mistake; the HKDF-SHA256
//! pairing and the DHKEM are the two derivations this crate offers over it.
//!
//! RFC 7748 Section 7: "for each public key, there are several publicly computable public keys
//! that are equivalent to it, i.e., they produce the same shared secrets. Thus using a public
//! key as an identifier and knowledge of a shared secret as proof of ownership (without
//! including the public keys in the key derivation) might lead to subtle vulnerabilities".
//! That is the reason for putting both public keys into the KDF's info, as the example above
//! does and as the DHKEM does by construction.
//!
//! An all-zero `K`, the output for a peer key of small order, is refused as
//! [`KeyAgreementError::AgreementFailed`]: RFC 7748 Section 6.1 makes the check optional
//! ("MAY check ... whether K is the all-zero value and abort if so") and this crate always
//! performs it, in constant time, so the only thing it reveals about `K` is whether it is
//! zero. Such a point "will eliminate any contribution from the other party's private key"
//! (Section 7), so `K` would be the same for every private key and known to whoever chose the
//! peer key.
//!
//! **What step-4-style destruction reaches here, and what it does not.** `K`, the decoded
//! scalar, the ladder's and the inversion's field elements and the DHKEM's intermediates each
//! live in a `Secret` or a self-wiping field element and are cleared at the end of their
//! lifetime, and `agree_out` writes into the caller's buffer. What is not reached: a key pair
//! returned by [`keygen`], [`keygen_from_seed`] or `DeriveKeyPair` is moved out of the frame that
//! built it (one copy of the scalar, as a move does not wipe its source), `encode` returns the
//! clamped scalar as a plain array by the trait's contract, the by-value `agree`, `encaps` and
//! `decaps` of `core` move their result out the same way, and HKDF's frame keeps its copies of
//! `K` and of the PRK's HMAC states in the pairing and the DHKEM (see `bouncycastle_hpke`'s
//! Security Considerations), so use the `_out` forms into a buffer you own where that matters.
//!
//! The pairing's derived key carries the least of X25519's 128 bits, the KDF's and the length's
//! strength, so a `LEN` below 16 bytes is typed `CryptographicRandom` at less than 128 bits.
//!
//! On a 32-bit target every `i128` product of the field arithmetic is a call into the compiler's
//! runtime (`__multi3`), so constant time there rests on that routine, not on this crate.
//!
//! RFC 9180 Section 9.7.4: "HPKE ciphertexts are not forward secret with respect to recipient
//! compromise in any mode". Anyone who later obtains a long-term DHKEM private key can decrypt
//! everything ever sent to it. This equally applies to most uses of the raw agreement unless a
//! suitable protocol is layered on top.

use bouncycastle_core::agreement_key::{AgreementKey, KeyAgreementAlgorithm};
use bouncycastle_core::errors::{KEMError, KeyAgreementError, KeyMaterialError, RNGError};
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::kdf_params::{KdfDescription, KdfParams};
use bouncycastle_core::kem_key::{DecapsulatingKey, EncapsulatingKey, KEMAlgorithm};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterial256, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{
    Algorithm, KDF, KEMDecapsulator, KEMEncapsulator, KEMPrivateKey, KEMPublicKey, KeyAgreement,
    KeyAgreementPrivateKey, KeyAgreementPublicKey, RNG,
};
use bouncycastle_hkdf::HkdfDescription;
use bouncycastle_hpke::dhkem::{DHKEM, DHKEMParams};
use bouncycastle_sha2::SHA256;
use bouncycastle_utils::ct::{Condition, ct_eq_bytes, ct_eq_zero_bytes};
use bouncycastle_utils::secret::{Secret, zeroize_in_place};
use core::fmt::{self, Display, Formatter};

use crate::curve25519::FieldElement25519;

// Only the field arithmetic (`FieldElement25519` in curve25519.rs) is shared with Ed25519. The
// scalar and point types below are X25519's own: an Ed25519 scalar is reduced mod the group order
// and an Ed25519 point is an encoded y-coordinate plus a sign bit (RFC 8032 §5.1.2), so neither
// fits these.

/*** Constants ***/

/// Size in bytes of the encoded representation of a point on curve25519,
/// which are used as public keys.
pub const POINT_LEN: usize = 32;
/// Size in bytes of the encoded representation of a scalar in the curve25519 field,
/// which are used as private keys.
pub const SCALAR_LEN: usize = 32;

/// String name of the X25519 algorithm.
pub const X25519_NAME: &str = "X25519";

/// The base point of curve25519, `U(P) = 9` (Section 4.1 of RFC7748).
const BASE_POINT: X25519PublicKey = {
    let mut u = [0_u8; POINT_LEN];
    u[0] = 9;
    X25519PublicKey(u)
};

/// The coefficient A of curve25519, `v^2 = u^3 + A*u^2 + u` (RFC 7748 §4.1).
const C_A: u32 = 486662;

/// `(A + 2) / 4 = 121666`, the ladder's doubling constant.
///
/// Deviation from the RFC: RFC 7748 §5 uses `a24 = (486662 - 2) / 4 = 121665` in
/// `z_2 = E * (AA + a24 * E)`. Since `E = AA - BB`, `AA + a24 * E = BB + (a24 + 1) * E`, so pairing
/// the constant with BB instead needs `a24 + 1 = (A + 2) / 4`. [`scalar_mult`] and
/// [`ladder_double`] both use that form.
const C_A24: u32 = (C_A + 2) / 4;

/// The X25519 key agreement algorithm of RFC 7748 §5.
pub struct X25519;

impl Algorithm for X25519 {
    const ALG_NAME: &'static str = X25519_NAME;
    // RFC 7748 §7: "the security level ... of curve25519 is slightly under the standard 128-bit
    // level", which it argues is acceptable; it is classed here at the conventional 128 bits.
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

impl KeyAgreementAlgorithm for X25519 {}

/// Generates a key pair from `rng`, which must offer X25519's 128 bits: the 32 bytes it draws
/// are the private key (RFC 7748 Section 6.1; RFC 9180 Section 4: "GenerateKeyPair can be
/// implemented as DeriveKeyPair(random(Nsk))", which for X25519 is the identity).
///
/// # Errors
/// [`KeyAgreementError::RNGError`] if the RNG is weaker than the algorithm or fails to deliver.
pub fn keygen(rng: &mut dyn RNG) -> Result<(X25519PublicKey, X25519PrivateKey), KeyAgreementError> {
    if rng.security_strength() < X25519::MAX_SECURITY_STRENGTH {
        return Err(RNGError::SecurityStrengthInsufficientForAlgorithm.into());
    }
    // The key is built in place: the RNG writes the scalar into the key's own Secret, and the
    // public key is set beside it. What is left is the pair's move out through the Result.
    let mut sk = X25519PrivateKey { k: Secret::new(), pk: X25519PublicKey([0; POINT_LEN]) };
    rng.next_bytes_out(&mut *sk.k)?;
    sk.pk = scalar_mult_base(&sk.k);
    Ok((sk.pk, sk))
}

/// The key pair whose private key is `seed`'s 32 bytes: a [`KeyMaterial256`] typed
/// [`KeyType::Seed`] or [`KeyType::CryptographicRandom`], at [`SecurityStrength::_128bit`] or
/// more. The bytes are kept as given; the clamping of RFC 7748 Section 5 is applied when they
/// are used, and the encoding is the clamped form.
///
/// # Errors
/// [`KeyAgreementError::KeyMaterialError`] for a seed of another type or length, or of too
/// little strength.
pub fn keygen_from_seed(
    seed: &KeyMaterial256,
) -> Result<(X25519PublicKey, X25519PrivateKey), KeyAgreementError> {
    if seed.key_type() == KeyType::Zeroized {
        return Err(KeyMaterialError::ActingOnZeroizedKey.into());
    }
    if !(seed.key_type() == KeyType::Seed || seed.key_type() == KeyType::CryptographicRandom)
        || seed.key_len() != SCALAR_LEN
    {
        return Err(KeyMaterialError::InvalidKeyType(
            "an X25519 seed is 32 bytes of KeyType::Seed or KeyType::CryptographicRandom",
        )
        .into());
    }
    if seed.security_strength() < X25519::MAX_SECURITY_STRENGTH {
        return Err(KeyMaterialError::SecurityStrength(
            "an X25519 seed must carry at least 128 bits of strength",
        )
        .into());
    }

    let mut sk = X25519PrivateKey { k: Secret::new(), pk: X25519PublicKey([0; POINT_LEN]) };
    sk.k.copy_from_slice(seed.ref_to_bytes());
    sk.pk = scalar_mult_base(&sk.k);
    Ok((sk.pk, sk))
}

/// `K = X25519(k, u)` of RFC 7748 Section 6.1, the u-coordinate of the peer's public key
/// multiplied by our scalar, as its 32-byte little-endian encoding, refused when all zero.
///
/// `K = X25519(k, u)` of RFC 7748 Section 6.1 into `out`, the u-coordinate of the peer's public
/// key multiplied by our scalar as its 32-byte little-endian encoding, refused when all zero
/// (and `out` left zeroized then).
///
/// Any 32 bytes are accepted as `pk`: per Section 5, bit 255 is ignored and values `>= p` are
/// processed as if reduced mod p. An all-zero output means `pk` has small order; the check is
/// constant time, ORing the bytes together as Section 6.1 suggests, so the only information it
/// reveals about `K` is whether it is zero.
fn raw_shared_secret(
    sk: &X25519PrivateKey,
    pk: &X25519PublicKey,
    out: &mut Secret<[u8; POINT_LEN]>,
) -> Result<(), KeyAgreementError> {
    scalar_mult_into(&sk.k, pk, out);
    if ct_eq_zero_bytes(&**out) {
        zeroize_in_place(&mut **out);
        return Err(KeyAgreementError::AgreementFailed);
    }
    Ok(())
}

/// The worker an [`X25519PrivateKey`] hands out through [`AgreementKey`] over `()`: the raw
/// `K`, typed [`KeyType::SharedSecret`] at 128 bits. It holds only the key and is reusable.
pub struct X25519Agreement<'k> {
    sk: &'k X25519PrivateKey,
}

impl Algorithm for X25519Agreement<'_> {
    const ALG_NAME: &'static str = X25519::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = X25519::MAX_SECURITY_STRENGTH;
}

impl KeyAgreement<X25519PublicKey, POINT_LEN> for X25519Agreement<'_> {
    /// `K` into the caller's buffer, zeroized first and left so on the error path.
    fn agree_out(
        &self,
        peer_pk: &X25519PublicKey,
        ss: &mut KeyMaterial<POINT_LEN>,
    ) -> Result<usize, KeyAgreementError> {
        ss.zeroize();
        // `K` is computed into this frame's one Secret, which is wiped when it drops; the field
        // elements of the ladder and the inversion below it wipe themselves the same way.
        let mut k = Secret::<[u8; POINT_LEN]>::new();
        raw_shared_secret(self.sk, peer_pk, &mut k)?;
        // `K` is never all zero here, so the buffer's own zero test cannot type it `Zeroized`.
        // A SharedSecret's strength is its producer's to state: X25519's 128 bits.
        if let Err(e) = ss.set_bytes_as_type(&*k, KeyType::SharedSecret).and_then(|()| {
            do_hazardous_operations(ss, |ss| {
                ss.set_security_strength(X25519::MAX_SECURITY_STRENGTH)
            })
        }) {
            ss.zeroize();
            return Err(e.into());
        }
        Ok(POINT_LEN)
    }
}

impl AgreementKey<(), POINT_LEN> for X25519PrivateKey {
    type Algorithm = X25519;
    type PublicKey = X25519PublicKey;
    type Agreement<'k> = X25519Agreement<'k>;

    fn create_agreement<'k>(
        &'k self,
        _params: (),
    ) -> Result<Self::Agreement<'k>, KeyAgreementError> {
        Ok(X25519Agreement { sk: self })
    }
}

/*** The same keys under HKDF-SHA256: the pairing, and the role impl over it ***/

/// X25519 with its shared secret put through HKDF-SHA256, the KDF of RFC 7748 Section 6.1's
/// recommendation ("a key-derivation function that includes K, K_A, and K_B"): the caller's
/// [`KdfParams`] name the HKDF description (its salt, if any) and the fixed info, which should
/// carry both public keys. The derived key is typed by the KDF's accounting,
/// `CryptographicRandom` at the least of X25519's 128 bits, the KDF's and the length's.
#[allow(non_camel_case_types)]
pub struct X25519_HKDF_SHA256;

impl Algorithm for X25519_HKDF_SHA256 {
    const ALG_NAME: &'static str = "X25519-HKDF-SHA256";
    const MAX_SECURITY_STRENGTH: SecurityStrength = X25519::MAX_SECURITY_STRENGTH;
}

impl KeyAgreementAlgorithm for X25519_HKDF_SHA256 {}

/// The most HKDF-SHA256 can derive in one call (RFC 5869 Section 2.3: L <= 255 * HashLen),
/// which bounds the role's `LEN`.
pub const HKDF_SHA256_MAX_LEN: usize = 255 * 32;

/// The worker an [`X25519PrivateKey`] hands out through [`AgreementKey`] over
/// [`KdfParams`] of HKDF-SHA256: `K` from the primitive, then the KDF, built from the
/// description for this derivation, into the caller's buffer. `K` lives in one local of this
/// frame, wiped when it drops; HKDF's own frame below
/// it keeps its copies of `K` and of the PRK's HMAC states, which are that crate's (see the
/// crate docs' Security Considerations).
pub struct X25519KdfAgreement<'k, 'p, 's, const LEN: usize> {
    sk: &'k X25519PrivateKey,
    params: KdfParams<'p, HkdfDescription<'s, SHA256>, LEN>,
}

impl<const LEN: usize> Algorithm for X25519KdfAgreement<'_, '_, '_, LEN> {
    const ALG_NAME: &'static str = X25519_HKDF_SHA256::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = X25519_HKDF_SHA256::MAX_SECURITY_STRENGTH;
}

impl<const LEN: usize> KeyAgreement<X25519PublicKey, LEN> for X25519KdfAgreement<'_, '_, '_, LEN> {
    fn agree_out(
        &self,
        peer_pk: &X25519PublicKey,
        ss: &mut KeyMaterial<LEN>,
    ) -> Result<usize, KeyAgreementError> {
        const {
            assert!(
                LEN > 0 && LEN <= HKDF_SHA256_MAX_LEN,
                "the derived key is from one byte to 255 * 32 bytes long"
            )
        };
        ss.zeroize();
        let mut k = KeyMaterial::<POINT_LEN>::new();
        X25519Agreement { sk: self.sk }.agree_out(peer_pk, &mut k)?;
        // The engine is an HKDF keyed with the description's salt, if any. `derive_key_out`
        // zeroizes `ss` first and leaves it so on its errors.
        let kdf = self.params.kdf().engine()?;
        let written = kdf.derive_key_out(&k, self.params.info(), LEN, ss)?;
        if written != LEN || ss.key_len() != LEN {
            ss.zeroize();
            return Err(KeyAgreementError::GenericError(
                "the KDF derived a key of the wrong length",
            ));
        }
        Ok(LEN)
    }
}

impl<'p, 's, const LEN: usize> AgreementKey<KdfParams<'p, HkdfDescription<'s, SHA256>, LEN>, LEN>
    for X25519PrivateKey
{
    type Algorithm = X25519_HKDF_SHA256;
    type PublicKey = X25519PublicKey;
    type Agreement<'k> = X25519KdfAgreement<'k, 'p, 's, LEN>;

    fn create_agreement<'k>(
        &'k self,
        params: KdfParams<'p, HkdfDescription<'s, SHA256>, LEN>,
    ) -> Result<Self::Agreement<'k>, KeyAgreementError> {
        Ok(X25519KdfAgreement { sk: self, params })
    }
}

/// An X25519 private key: a 32-byte scalar, as defined in Section 5 of RFC7748.
///
/// Any 32 bytes are a valid scalar. The fixed bits `decodeScalar25519` sets and clears
/// ("clamping") are applied each time the scalar is used, so keys that differ only in those bits
/// are the same key, and compare equal. Held in a [`Secret`], so it is zeroized on drop and
/// redacted from `Debug`.
///
/// The public key is computed once, when the private key is created or decoded, and stored with
/// it.
#[derive(Clone)]
pub struct X25519PrivateKey {
    k: Secret<[u8; SCALAR_LEN]>,
    pk: X25519PublicKey,
}

impl X25519PrivateKey {
    /// The public key, `X25519(k, 9)` (RFC 7748 §6.1).
    pub fn pk(&self) -> X25519PublicKey {
        self.pk
    }

    /// The key bytes, [`clamp`]ed.
    /// The key bytes, [`clamp`]ed, into `out`.
    fn clamped_into(&self, out: &mut [u8; SCALAR_LEN]) {
        *out = *self.k;
        clamp(out);
    }
}

/// Applies `decodeScalar25519`'s fixed bits to the key bytes `k` (RFC 7748 §5):
///
/// ```text
/// k_list[0] &= 248
/// k_list[31] &= 127
/// k_list[31] |= 64
/// ```
fn clamp(k: &mut [u8; SCALAR_LEN]) {
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
}

/// The encoding is the 32 key bytes, clamped (the bit operations of `decodeScalar25519`, RFC 7748
/// §5), so keys that compare equal have the same encoding. This is also the DHKEM serialization:
/// RFC 9180 §7.1.2 says "The SerializePrivateKey() function MUST clamp its output and the
/// DeserializePrivateKey() function MUST clamp its input".
impl KeyAgreementPrivateKey<SCALAR_LEN> for X25519PrivateKey {
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

    /// Any 32 bytes are a valid private key; they are clamped on the way in.
    ///
    /// # Errors
    ///
    /// [`KeyAgreementError::DecodingError`] if `bytes` is not 32 bytes.
    fn from_bytes(bytes: &[u8]) -> Result<Self, KeyAgreementError> {
        let bytes: &[u8; SCALAR_LEN] = bytes.try_into().map_err(|_| {
            KeyAgreementError::DecodingError("An X25519 private key must be 32 bytes")
        })?;
        let mut sk = Self { k: Secret::new(), pk: X25519PublicKey([0; POINT_LEN]) };
        *sk.k = *bytes;
        clamp(&mut sk.k);
        sk.pk = scalar_mult_base(&sk.k);
        Ok(sk)
    }
}

/// Constant-time comparison of the clamped scalars.
impl PartialEq for X25519PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        let (mut a, mut b) = (Secret::<[u8; SCALAR_LEN]>::new(), Secret::<[u8; SCALAR_LEN]>::new());
        self.clamped_into(&mut a);
        other.clamped_into(&mut b);
        ct_eq_bytes(&*a, &*b)
    }
}

impl Eq for X25519PrivateKey {}

/// An X25519 public value: the u-coordinate of a point on curve25519, as 32 little-endian bytes
/// (Section 5 of RFC7748).
///
/// Any 32 bytes are accepted: Section 5 requires bit 255 to be ignored and values `>= p` to be
/// processed as if reduced mod p. Public data, so it is `Copy` and its `Debug` shows the bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X25519PublicKey([u8; POINT_LEN]);

impl X25519PublicKey {
    /// The 32 encoded bytes.
    pub const fn as_bytes(&self) -> &[u8; POINT_LEN] {
        &self.0
    }
}

/// The encoding is the 32 bytes of the u-coordinate, as is (RFC 7748 §5).
impl KeyAgreementPublicKey<POINT_LEN> for X25519PublicKey {
    fn encode(&self) -> [u8; POINT_LEN] {
        self.0
    }

    fn encode_out(&self, out: &mut [u8; POINT_LEN]) -> usize {
        out.fill(0);
        *out = self.0;
        POINT_LEN
    }

    /// Any 32 bytes are accepted: RFC 7748 §5 requires bit 255 to be ignored and values `>= p` to
    /// be processed as if reduced mod p.
    ///
    /// # Errors
    ///
    /// [`KeyAgreementError::DecodingError`] if `bytes` is not 32 bytes.
    fn from_bytes(bytes: &[u8]) -> Result<Self, KeyAgreementError> {
        let bytes: &[u8; POINT_LEN] = bytes.try_into().map_err(|_| {
            KeyAgreementError::DecodingError("An X25519 public key must be 32 bytes")
        })?;
        Ok(Self(*bytes))
    }
}

impl AsRef<[u8]> for X25519PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// The 32 bytes in hex.
impl Display for X25519PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "X25519PublicKey {{ ")?;
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        write!(f, " }}")
    }
}

/// `decodeScalar25519(k)` as defined in Section 5 of RFC7748:
///
/// ```text
/// def decodeScalar25519(k):
///     k_list = [ord(b) for b in k]
///     k_list[0] &= 248
///     k_list[31] &= 127
///     k_list[31] |= 64
///     return decodeLittleEndian(k_list, 255)
/// ```
///
/// Section 5 gives the same rule in prose: "set the three least significant bits of the first
/// byte and the most significant bit of the last to zero, set the second most significant bit of
/// the last byte to 1 and, finally, decode as little-endian. This means that the resulting
/// integer is of the form 2^254 plus eight times a value between 0 and 2^251 - 1 (inclusive)."
///
/// That is why the ladder can start at bit 253 against a pre-swapped initial state;
/// the `8 *` is why its last three iterations collapse into three [`ladder_double`] calls with no
/// trailing conditional swap.
///
/// Deviation from the RFC: the RFC masks bytes and then decodes, whereas this decodes into
/// four-byte words first and masks the equivalent word positions. `k_list[0] &= 248` becomes
/// `n[0] &= 0xFFFFFFF8` -- the same low three bits, since `n[0]` is the first four bytes -- and
/// `k_list[31] &= 127` / `|= 64` become `n[7] &= 0x7FFFFFFF` / `|= 0x40000000`, the same top two
/// bits, since `n[7]` is the last four bytes.
///
/// This differs from `decodeScalar448`, which clears two low bits rather than
/// three, and sets bit 447 (Section 5).
///
/// Input: A 32-byte little-endian scalar.
/// Output: The decoded scalar, written to `n` as eight little-endian 32-bit words.
fn decode_scalar_25519(k: &[u8; SCALAR_LEN], n: &mut [u32; 8]) {
    let (words, _) = k.as_chunks::<4>(); // 32 bytes: exactly 8 chunks, no remainder
    for (n_i, w) in n.iter_mut().zip(words) {
        *n_i = u32::from_le_bytes(*w);
    }

    n[0] &= 0xFFFFFFF8_u32;
    n[7] &= 0x7FFFFFFF_u32;
    n[7] |= 0x40000000_u32;
}

/// `decodeUCoordinate(u, 255)` as defined in Section 5 of RFC7748:
///
/// ```text
/// def decodeUCoordinate(u, bits):
///     u_list = [ord(b) for b in u]
///     # Ignore any unused bits.
///     if bits % 8:
///         u_list[-1] &= (1<<(bits%8))-1
///     return decodeLittleEndian(u_list, bits)
/// ```
///
/// With `bits` = 255, `bits % 8` is 7 and the mask clears bit 255, the most significant bit of
/// the final byte. Section 5 requires exactly that: "When receiving such an array,
/// implementations of X25519 (but not X448) MUST mask the most significant bit in the final
/// byte." [`FieldElement25519::decode_255`] does the masking and the little-endian decode.
///
/// The result is not normalized, as Section 5 also requires: "Implementations MUST accept
/// non-canonical values and process them as if they had been reduced modulo the field prime. The
/// non-canonical values are 2^255 - 19 through 2^255 - 1 for X25519".
///
/// Input: A 32-byte little-endian u-coordinate.
/// Output: The u-coordinate as a [`FieldElement25519`], not normalized.
fn decode_u_coordinate(u: &X25519PublicKey) -> FieldElement25519 {
    FieldElement25519::decode_255(&u.0)
}

/// `encodeUCoordinate(u, 255)` as defined in Section 5 of RFC 7748.
/// The RFC's `u = u % p` step is [`FieldElement25519::normalize`]: an X25519 output must be the
/// canonical encoding of its residue class, even though non-canonical values MUST be accepted on
/// the way in (see [`decode_u_coordinate`]). Bit 255 of the final byte is written as zero, since
/// it is unused by X25519.
///
/// Input: A u-coordinate, in any state of reduction; a 32-byte output buffer.
/// Output: The canonical 32-byte little-endian encoding of that value, written to `r`.
fn encode_u_coordinate(u: &FieldElement25519, r: &mut [u8; POINT_LEN]) {
    u.normalize().encode_255(r);
}

/// Doubles one point, held projectively as the pair `(x : z)` representing `u = x / z`
/// Updated in place.
///
/// Keeping u as a fraction is what lets the ladder avoid a field inversion on every step: only
/// multiplications and squarings are needed here, and [`scalar_mult`] divides `x` by `z` once, at
/// the end.
///
/// This is the doubling half of the Montgomery ladder step in Section 5 of RFC7748, used by
/// [`scalar_mult`] for the last three iterations. With `AA = (x + z)^2`, `BB = (x - z)^2` and
/// `E = AA - BB`, it writes `x = AA * BB` and `z = E * (BB + C_A24 * E)`; see [`C_A24`] for the
/// pairing with `BB`.
///
/// X25519 only: it works on curve25519's Montgomery form and depends on its coefficient A.
/// Ed25519 doubles points on the twisted Edwards curve in extended coordinates (Section 5.1.4 of
/// RFC8032), which is a separate function.
fn ladder_double(x: &mut FieldElement25519, z: &mut FieldElement25519) {
    let (mut a, mut b) = x.sum_and_difference(z);
    a = a.sqr();
    b = b.sqr();
    *x = a.mul(&b);

    a = a.sub(&b);
    let t = a.mul_u32(C_A24).add(&b);
    *z = t.mul(&a);
}

/// `X25519(k, u)` as defined in Section 5 of RFC7748: the Montgomery ladder, computing scalar
/// multiplication on curve25519 from a u-coordinate alone.
///
/// The ladder is constant time with respect to `k`: the iteration count is fixed and the only
/// scalar-dependent step is [`FieldElement25519::cswap`].
///
/// # Modifications from the RFC
/// Modified to fold the RFC's first ladder iteration into the initial state, to replace its last
/// three iterations with [`ladder_double`] calls, and to cycle the RFC's named intermediates
/// through a fixed set of registers rather than materialise them.
///
/// # Inputs
/// * `k`, a 32-byte scalar
/// * `u`, a 32-byte little-endian u-coordinate
///
/// Output: The canonical little-endian encoding of the u-coordinate of `k * u`.
fn scalar_mult_into(k: &[u8; SCALAR_LEN], u: &X25519PublicKey, out: &mut [u8; POINT_LEN]) {
    // The decoded scalar is as secret as `k` itself.
    let mut n: Secret<[u32; 8]> = Secret::new();
    decode_scalar_25519(k, &mut n);

    // Pre-condition:
    // The ladder below is only correct for scalars of the form 2^254 + 8m, 0 <= m <= 2^251 - 1
    // which should be enforced by a correct implementation of decode_scalar_25519.
    debug_assert_eq!(1, n[7] >> 30);
    debug_assert_eq!(0, n[0] & 7);

    let x1 = decode_u_coordinate(u);
    let mut x2 = FieldElement25519::zero();
    let mut z2 = FieldElement25519::zero();
    ladder(&n, &x1, &mut x2, &mut z2);

    // Every field element here wipes itself when it drops: the result, the ladder's registers
    // and the inversion chain's. The encoding goes straight into the caller's buffer.
    let r = x2.mul(&z2.inv());
    encode_u_coordinate(&r, out);
}

/// The Montgomery ladder of [`scalar_mult`]: writes the projective u-coordinate of `n * x1` to
/// `(x2, z2)`, for a scalar `n` decoded by [`decode_scalar_25519`].
// #[inline(never)]: so that the ladder's variables live in a different stack frame and can be popped
// before scalar_mult's `z2.inv()` runs (which is the other stack-expensive operation).
#[inline(never)]
fn ladder(
    n: &[u32; 8],
    x1: &FieldElement25519,
    x2: &mut FieldElement25519,
    z2: &mut FieldElement25519,
) {
    *x2 = x1.clone();
    *z2 = FieldElement25519::one();
    let mut x3 = FieldElement25519::one();
    let mut z3 = FieldElement25519::zero();

    let mut t1;
    let mut t2;

    let mut swap = Condition::<i64>::from_bool_const::<true>();

    // Deviation from the RFC:
    // RFC7748 §5 runs `For t = bits-1 down to 0`, i.e. t = 254 down to 0, with the conditional
    // swap at the top of the body and the arithmetic after it. This loop deviates in three ways,
    // all of them consequences of the scalar's form -- see the pre-condition above:
    //
    //  1. Rotated body. The arithmetic comes first here and the swap last.
    //  2. t = 254 is not in the loop because bit 254 is always set, so that iteration's swap is known in
    //     advance: the RFC starts from x_2 = 1, z_2 = 0, x_3 = u, z_3 = 1 and its first swap
    //     exchanges the pairs, so the registers above are seeded with the swapped values,
    //     x_2 = u, z_2 = 1, x_3 = 1, z_3 = 0, and `swap` starts at k_254. So the loop starts at
    //     253 and not 254.
    //  3. t = 2, 1, 0 are not in the loop because bits 0..2 are always clear, so those iterations reduce
    //     to doubling the (x_2, z_2) branch and their swaps are no-ops. They become the three
    //     ladder_double calls after the loop, and the RFC's post-loop cswap is dropped for the same
    //     reason -- the debug_assert below is what checks it would have been a no-op.
    for bit in (2..=253_usize).rev() {
        // This section is the same core algorithm as in RFC7748 §5, but uses a different variable
        // naming convention in order to more efficiently reuse memory.
        // Comment style:
        // <exact line from RFC7748 §5>, -> <register stored to>

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
        // The function `sum_and_difference()` computes `(DA + CB) and (DA - CB)` is a single
        // operation, allowing these lines to be combined.
        // Deviation from the RFC: yields CB - DA, negated. Harmless as both lines below square it.
        (x3, z3) = t1.sum_and_difference(&x3);
        // (completes x_3)
        x3 = x3.sqr();
        // (completes z_3)
        z3 = z3.sqr().mul(x1);

        // This differs from the ladder presentation in the RFC because it implements the
        // constant-time cswap recommendation at the bottom of §5 using an all-ones/all-zeros
        // mask and the Condition<i64> type.

        // k_t = (k >> t) & 1
        //  > Presentation differs due to decoding k into n, and the bit-selecting Condition operator.
        let k_bit = Condition::<i64>::is_bit_set(n[bit >> 5] as i64, (bit & 0x1F) as u32);
        // swap ^= k_t
        swap ^= k_bit;
        // (x_2, x_3) = cswap(swap, x_2, x_3)
        //   > swaps in-place
        FieldElement25519::cswap(swap, x2, &mut x3);
        // (z_2, z_3) = cswap(swap, z_2, z_3)
        //   > swaps in-place
        FieldElement25519::cswap(swap, z2, &mut z3);
        // swap = k_t
        swap = k_bit;
    }

    debug_assert!(!swap.to_bool());

    for _ in 0..3 {
        ladder_double(x2, z2);
    }
}

fn scalar_mult_base(k: &[u8; SCALAR_LEN]) -> X25519PublicKey {
    // The result is public, so it may live in the plain array of the key type. A fixed-base
    // table would make this faster; the variable-base ladder serves for now.
    let mut out = [0u8; POINT_LEN];
    scalar_mult_into(k, &BASE_POINT, &mut out);
    X25519PublicKey(out)
}

/*** DHKEM ***/

// This section provides the machinery to promote x25519 to a KEM via RFC9180's DHKEM construction.

/// The length of the shared secret from [`X25519`]'s KEM: Nsecret for DHKEM(X25519, HKDF-SHA256)
/// (RFC 9180 §7.1).
pub const DHKEM_SS_LEN: usize = 32;

/// DHKEM(X25519, HKDF-SHA256) of RFC 9180 §4.1. Nenc = Npk = Ndh = 32 and Nsk = 32 (§7.1).
type X25519DHKEM = DHKEM<X25519, POINT_LEN, SCALAR_LEN, POINT_LEN, DHKEM_SS_LEN>;

/// DHKEM(X25519, HKDF-SHA256): kem_id 0x0020, with Nenc = Npk = Nsk = 32 (RFC 9180 §7.1).
impl DHKEMParams<POINT_LEN, SCALAR_LEN, POINT_LEN> for X25519 {
    type PublicKey = X25519PublicKey;
    type PrivateKey = X25519PrivateKey;
    type KDFHash = SHA256;
    const KEM_ID: u16 = 0x0020;

    fn generate_key_pair_rng(
        rng: &mut dyn RNG,
    ) -> Result<(X25519PublicKey, X25519PrivateKey), KEMError> {
        // RFC 9180 §4: "GenerateKeyPair can be implemented as DeriveKeyPair(random(Nsk))"; for
        // X25519, 32 random bytes are already a private key (RFC 7748 §6.1), so they are used as is.
        keygen(rng).map_err(|e| match e {
            KeyAgreementError::RNGError(e) => KEMError::RNGError(e),
            KeyAgreementError::KeyMaterialError(e) => KEMError::KeyMaterialError(e),
            _ => KEMError::GenericError("X25519 key generation failed"),
        })
    }

    const DERIVE_KEY_PAIR_BY_EXPAND: bool = true;

    fn private_key_from_bytes(sk: &[u8; SCALAR_LEN]) -> X25519PrivateKey {
        let mut key = X25519PrivateKey { k: Secret::new(), pk: X25519PublicKey([0; POINT_LEN]) };
        *key.k = *sk;
        key.pk = scalar_mult_base(&key.k);
        key
    }

    fn pk(sk: &X25519PrivateKey) -> X25519PublicKey {
        sk.pk()
    }

    fn dh_into(
        sk: &X25519PrivateKey,
        pk: &X25519PublicKey,
        out: &mut Secret<[u8; POINT_LEN]>,
    ) -> Result<(), KeyAgreementError> {
        raw_shared_secret(sk, pk, out)
    }

    // RFC 9180 §7.1.1: "For X25519 and X448, the SerializePublicKey() and DeserializePublicKey()
    // functions are the identity function".
    fn serialize_public_key(pk: &X25519PublicKey) -> [u8; POINT_LEN] {
        pk.0
    }

    fn deserialize_public_key(pkm: &[u8; POINT_LEN]) -> Result<X25519PublicKey, KEMError> {
        Ok(X25519PublicKey(*pkm))
    }
}

impl KEMAlgorithm for X25519 {}

/// The encapsulator an [`X25519PublicKey`] hands out through [`EncapsulatingKey`]:
/// DHKEM(X25519, HKDF-SHA256) of RFC 9180 §4.1, where the ciphertext is an ephemeral public key
/// (`enc`) and the shared secret is derived with HKDF-SHA256 from the X25519 output and both
/// public keys. It borrows the recipient's key.
pub struct X25519Encapsulator<'k> {
    pk: &'k X25519PublicKey,
}

impl Algorithm for X25519Encapsulator<'_> {
    const ALG_NAME: &'static str = X25519::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = X25519::MAX_SECURITY_STRENGTH;
}

impl KEMEncapsulator<POINT_LEN, DHKEM_SS_LEN> for X25519Encapsulator<'_> {
    /// `Encap(pkR)` (RFC 9180 §4.1), drawing the ephemeral key pair from `rng`.
    ///
    /// # Errors
    ///
    /// * [`KEMError::RNGError`] if `rng`'s security strength is below 128 bits.
    /// * [`KEMError::InvalidPublicKey`] if the key gives an all-zero X25519 output, the case the
    ///   agreement role refuses as [`KeyAgreementError::AgreementFailed`].
    fn encaps_out(
        &self,
        rng: &mut dyn RNG,
        ct: &mut [u8; POINT_LEN],
        ss: &mut KeyMaterial<DHKEM_SS_LEN>,
    ) -> Result<usize, KEMError> {
        ct.fill(0);
        ss.zeroize();
        X25519DHKEM::encap_rng_out(self.pk, rng, ct, ss)?;
        Ok(POINT_LEN)
    }
}

/// X25519 public keys encapsulate as DHKEM(X25519, HKDF-SHA256), with `()` as the parameters.
impl EncapsulatingKey<(), POINT_LEN, DHKEM_SS_LEN> for X25519PublicKey {
    type Algorithm = X25519;
    type Encapsulator<'k> = X25519Encapsulator<'k>;

    fn create_encapsulator<'k>(&'k self, _params: ()) -> Result<X25519Encapsulator<'k>, KEMError> {
        Ok(X25519Encapsulator { pk: self })
    }
}

/// The decapsulator an [`X25519PrivateKey`] hands out through [`DecapsulatingKey`]:
/// DHKEM(X25519, HKDF-SHA256) `Decap` of RFC 9180 §4.1. It borrows the recipient's key.
pub struct X25519Decapsulator<'k> {
    sk: &'k X25519PrivateKey,
}

impl Algorithm for X25519Decapsulator<'_> {
    const ALG_NAME: &'static str = X25519::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = X25519::MAX_SECURITY_STRENGTH;
}

impl KEMDecapsulator<POINT_LEN, DHKEM_SS_LEN> for X25519Decapsulator<'_> {
    /// `Decap(enc, skR)` (RFC 9180 §4.1), with the ciphertext `ct` as `enc`.
    ///
    /// # Errors
    ///
    /// [`KEMError::DecapsulationFailed`] if `ct` gives an all-zero X25519 output.
    fn decaps_out(
        &self,
        ct: &[u8; POINT_LEN],
        ss: &mut KeyMaterial<DHKEM_SS_LEN>,
    ) -> Result<usize, KEMError> {
        ss.zeroize();
        X25519DHKEM::decap_out(ct, self.sk, ss)?;
        Ok(DHKEM_SS_LEN)
    }
}

/// X25519 private keys decapsulate as DHKEM(X25519, HKDF-SHA256), with `()` as the parameters.
impl DecapsulatingKey<(), POINT_LEN, DHKEM_SS_LEN> for X25519PrivateKey {
    type Algorithm = X25519;
    type Decapsulator<'k> = X25519Decapsulator<'k>;

    fn create_decapsulator<'k>(&'k self, _params: ()) -> Result<X25519Decapsulator<'k>, KEMError> {
        Ok(X25519Decapsulator { sk: self })
    }
}

/// The same clamped encoding as the [`KeyAgreementPrivateKey`] impl, which RFC 9180 §7.1.2 requires
/// of a DHKEM.
impl KEMPrivateKey<SCALAR_LEN> for X25519PrivateKey {
    fn encode(&self) -> [u8; SCALAR_LEN] {
        <Self as KeyAgreementPrivateKey<SCALAR_LEN>>::encode(self)
    }

    fn encode_out(&self, out: &mut [u8; SCALAR_LEN]) -> usize {
        <Self as KeyAgreementPrivateKey<SCALAR_LEN>>::encode_out(self, out)
    }

    /// # Errors
    ///
    /// [`KEMError::DecodingError`] if `bytes` is not 32 bytes.
    fn from_bytes(bytes: &[u8]) -> Result<Self, KEMError> {
        <Self as KeyAgreementPrivateKey<SCALAR_LEN>>::from_bytes(bytes)
            .map_err(|_| KEMError::DecodingError("An X25519 private key must be 32 bytes"))
    }
}

/// The same encoding as the [`KeyAgreementPublicKey`] impl: RFC 9180 §7.1.1 makes serialization the
/// identity function for X25519.
impl KEMPublicKey<POINT_LEN> for X25519PublicKey {
    fn encode(&self) -> [u8; POINT_LEN] {
        <Self as KeyAgreementPublicKey<POINT_LEN>>::encode(self)
    }

    fn encode_out(&self, out: &mut [u8; POINT_LEN]) -> usize {
        <Self as KeyAgreementPublicKey<POINT_LEN>>::encode_out(self, out)
    }

    /// # Errors
    ///
    /// [`KEMError::DecodingError`] if `bytes` is not 32 bytes.
    fn from_bytes(bytes: &[u8]) -> Result<Self, KEMError> {
        <Self as KeyAgreementPublicKey<POINT_LEN>>::from_bytes(bytes)
            .map_err(|_| KEMError::DecodingError("An X25519 public key must be 32 bytes"))
    }
}
