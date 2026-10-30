//! # Usage Examples
//!
//! ## Generating keys
//!
//! ```rust
//! use bouncycastle_ed::x25519::X25519;
//!
//! let (pk, sk) = X25519::keygen().unwrap();
//! ```
//! That will use the library's default OS-backed RNG. To supply your own randomness, use
//! [`X25519::keygen_from_rng`], or [`X25519::keygen_from_seed`] with a 32-byte seed, which is also
//! how an existing private key is imported.
//!
//! Private keys can also be generated from a 32-byte seed. The only requirement is that they be
//! 32 bytes long (ie a full [`KeyMaterial256`] or equivalent,
//! [`KeyType::Seed`] or [`KeyType::CryptographicRandom`] and be at least [`SecurityStrength::_128bit`].
//!
//! ```rust
//! use bouncycastle_ed::x25519::X25519;
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyMaterialTrait, KeyType};
//! use bouncycastle_core::hazmat::do_hazardous_operations;
//!
//! // Create a seed.
//! // We're using a do_hazardous_operations() closure to prevent the library from complaining
//! // that the key material is week.
//! let mut seed = KeyMaterial256::new();
//! do_hazardous_operations(&mut seed, |seed| {
//!     seed.set_bytes_as_type(&[0x02; 32], KeyType::Seed)
//! }).unwrap();
//!
//! let (pk, sk) = X25519::keygen().unwrap();
//! ```
//!
//! ## X25519 key agreement
//!
//! Alice and Bob each generate a key pair and send each other their public keys. Each then combines
//! their own private key with the other's public key in
//! [`X25519::key_agreement`](X25519#method.key_agreement), and both arrive
//! at the same shared secret `K`.
//!
//! `K` is the 32-byte representation of the U-coordinate of a point on curve25519 -- **its bytes are
//! not uniformly random**, so it should not be used as a key directly: put it through a KDF,
//! along with both public keys (RFC 7748 §6.1). Here that is HKDF-SHA256, with `K` as the input key
//! material and `Alice's public key || Bob's public key` as the context. Both parties must put the
//! public keys in the same order.
//!
//! ```rust
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyMaterialTrait, KeyType};
//! use bouncycastle_core::security_strength::SecurityStrength;
//! use bouncycastle_core::traits::{KDF, KeyAgreement};
//! use bouncycastle_ed::x25519::{X25519, X25519PublicKey};
//! use bouncycastle_sha2::hkdf::HKDF_SHA256;
//!
//! // Alice and Bob each generate a key pair, and exchange public keys.
//! let (alice_pk, alice_sk) = X25519::keygen().unwrap();
//! let (bob_pk, bob_sk) = X25519::keygen().unwrap();
//!
//! // Each performs a key agreement from their own private key and the other's public key,
//! // each arriving at the same k.
//! // Note that k is an X25519PublicKey and could be used again for another key agreement.
//! // But this example will proceed with deriving a shared symmetric key.
//! // An error here means the other party's public key is unusable; abort the exchange.
//! let alice_k = X25519::key_agreement(&bob_pk, &alice_sk).expect("Bad public key");
//! let bob_k = X25519::key_agreement(&alice_pk, &bob_sk).expect("Bad public key");
//!
//! // RFC 7748 §6.1 recommends using a key derivation function (KDF) over K, K_A, and K_B
//! // to derive a symmetric key. This example will use HKDF_SHA256.
//! fn derive_key_rfc7748(
//!     k: &X25519PublicKey,
//!     pk_A: &X25519PublicKey,
//!     pk_B: &X25519PublicKey) -> KeyMaterial256 {
//!     let mut ikm =
//!         KeyMaterial256::from_bytes_as_type(k.as_ref(), KeyType::CryptographicRandom).unwrap();
//!     // X25519 provides 128-bit security, not the 256 bits a 32-byte key would imply.
//!     // This is related to the fact that an X25519PublicKey encodes to 32 bytes,
//!     // but does not contain 32 bytes of entropy.
//!     ikm.set_security_strength(SecurityStrength::_128bit).unwrap();
//!
//!     let mut context = [0u8; 64];
//!     context[..32].copy_from_slice(pk_A.as_ref());
//!     context[32..].copy_from_slice(pk_B.as_ref());
//!
//!     let mut key = KeyMaterial256::new();
//!     HKDF_SHA256::new().derive_key_out(&ikm, &context, &mut key).unwrap();
//!     key
//! }
//!
//! // Each derives the symmetric key independently.
//! // Note that they have to agree on whose key goes in first;
//! // if Alice does `(alice_pk, bob_pk)` and bob does `(bob_pk, alice_pk)` then they will
//! // arrive at different output keys.
//! // Typically, this will be specified unambiguously by the protocol, such as
//! // (sender_pk, recipient_pk) since Alice and Bob are expected to know whether they
//! // are the sender or receiver.
//! let alice_key = derive_key_rfc7748(&alice_k, &alice_pk, &bob_pk);
//! let bob_key   = derive_key_rfc7748(&bob_k, &alice_pk, &bob_pk);
//!
//! // Alice and Bob now hold the same 32-byte KeyMaterial256.
//! assert!(alice_key.equals(&bob_key));
//! assert_eq!(alice_key.key_len(), 32);
//!
//! // Which has been set at 128-bit-strength.
//! assert_eq!(alice_key.key_type(), KeyType::CryptographicRandom);
//! assert_eq!(alice_key.security_strength(), SecurityStrength::_128bit);
//! ```
//!
//! ## X25519 as a KEM
//!
//! [`X25519`] also implements [`KEMEncapsulator`] and [`KEMDecapsulator`] as DHKEM(X25519,
//! HKDF-SHA256) of RFC 9180 §4.1, the KEM used by HPKE. The sender encapsulates against the
//! recipient's public key, and gets a shared secret and a 32-byte ciphertext (an ephemeral public
//! key) to send. The shared secret is already the output of a KDF, ready to use as a key.
//!
//! ```rust
//! use bouncycastle_core::traits::{KEMDecapsulator, KEMEncapsulator};
//! use bouncycastle_ed::x25519::X25519;
//!
//! let (pk, sk) = X25519::keygen().unwrap();
//!
//! // The sender encapsulates against the recipient's public key...
//! let (ss, ct) = X25519::encaps(&pk).unwrap();
//!
//! // ...and the recipient recovers the same shared secret from the ciphertext.
//! let ss1 = X25519::decaps(&sk, &ct).unwrap();
//! assert_eq!(ss, ss1);
//! ```
//!
//! ## Chaining together key agreement operations
//!
//! The output of a Diffie-Hellman key agreement is itself a valid public key, so key agreements can
//! be chained.
//! Below is an example of a simple three-party agreement, in which Alice, Bob and Charlie all arrive
//! at the same shared secret `k`, by combining their private key with public data from the other two.
//! The trick here is that each party does a pairwise key agreement with each other party,
//! and then another agreement with the result of the other two parties' agreements with each other.
//! This is a simple scheme to illustrate the point and obviously does not scale well to large groups.
//!
//! ```rust
//! use bouncycastle_core::traits::KeyAgreement;
//! use bouncycastle_ed::x25519::X25519;
//!
//! let (alice_pk, alice_sk) = X25519::keygen().unwrap();
//! let (bob_pk, bob_sk) = X25519::keygen().unwrap();
//! let (charlie_pk, charlie_sk) = X25519::keygen().unwrap();
//!
//! // Assume that Alice, Bob, and Charlie have all exchanged public keys.
//! // Round 1: each pair computes a pairwise value. Key agreement is symmetric, so `ab_k` is
//! // computed by both Alice and Bob; only one side of each pair is shown.
//! let ab_k = X25519::key_agreement(&bob_pk, &alice_sk).expect("Bad public key");
//! let bc_k = X25519::key_agreement(&charlie_pk, &bob_sk).expect("Bad public key");
//! let ac_k = X25519::key_agreement(&charlie_pk, &alice_sk).expect("Bad public key");
//!
//! // Round 2: each pairwise value is sent, in the clear, to the third party, who combines it with
//! // their own private key.
//! // Since it is no longer secret, `ab_k` must not also be used as a secret key between
//! // Alice and Bob.
//! let alice_k = X25519::key_agreement(&bc_k, &alice_sk).expect("Bad public key");
//! let bob_k = X25519::key_agreement(&ac_k, &bob_sk).expect("Bad public key");
//! let charlie_k = X25519::key_agreement(&ab_k, &charlie_sk).expect("Bad public key");
//!
//! // The computations ran in different orders, but by the magic of
//! // commutative algebra, they all end up with the same shared secret key `k`.
//! assert!(alice_k.eq(&bob_k));
//! assert!(bob_k.eq(&charlie_k));
//!
//! // As in the two-party case, `k` is not uniformly random: run it through a suitable KDF scheme
//! // to derive a usable and secure symmetric key.
//! ```
//!
//! Like any unauthenticated Diffie-Hellman, this resists only passive eavesdroppers. An active
//! attacker who can substitute public keys or pairwise values in transit can sit in the middle, so a
//! real protocol must authenticate them, for example by signing them.

use bouncycastle_core::errors::{KEMError, KeyAgreementError, RNGError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterial256, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{
    Algorithm, KEMDecapsulator, KEMEncapsulator, KEMPrivateKey, KEMPublicKey, KeyAgreement,
    KeyAgreementPrivateKey, KeyAgreementPublicKey, RNG,
};
use bouncycastle_hpke::dhkem::{DHKEM, DHKEMParams};
use bouncycastle_rng::HashDRBG_SHA512;
use bouncycastle_sha2::SHA256;
use bouncycastle_utils::ct::{Condition, ct_eq_bytes, ct_eq_zero_bytes};
use bouncycastle_utils::secret::Secret;
use core::fmt::{self, Display, Formatter};

use crate::curve25519::FieldElement25519;

// Only the field arithmetic (`FieldElement25519` in curve25519.rs) is shared with Ed25519. The
// scalar and point types below are X25519's own: an Ed25519 scalar is reduced mod the group order
// and an Ed25519 point is an encoded y-coordinate plus a sign bit (RFC 8032 §5.1.2), so neither
// fits these.

/*** Constants ***/

pub const POINT_SIZE: usize = 32;
pub const SCALAR_SIZE: usize = 32;

/// String name of the X25519 algorithm.
pub const X25519_NAME: &str = "X25519";

/// The base point of curve25519, `U(P) = 9` (Section 4.1 of RFC7748).
const BASE_POINT: X25519PublicKey = {
    let mut u = [0_u8; POINT_SIZE];
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

impl X25519 {
    /// Generates a fresh key pair using the library's default RNG, seeded from the OS.
    /// In environments where the default OS based RNG is not available, use instead
    /// [`X25519::keygen_from_rng`] and explicitly provide an [`RNG`] implementation, or use
    /// [`X25519::keygen_from_seed`] and provide the private key seed directly.
    pub fn keygen() -> Result<(X25519PublicKey, X25519PrivateKey), KeyAgreementError> {
        let mut os_rng = HashDRBG_SHA512::new_from_os();
        Self::keygen_from_rng(&mut os_rng)
    }

    /// Generates a key pair using the provided RNG implementation.
    pub fn keygen_from_rng(
        rng: &mut dyn RNG,
    ) -> Result<(X25519PublicKey, X25519PrivateKey), KeyAgreementError> {
        if rng.security_strength() < Self::MAX_SECURITY_STRENGTH {
            return Err(RNGError::SecurityStrengthInsufficientForAlgorithm)?;
        }
        let mut seed = KeyMaterial256::new();
        rng.fill_keymaterial_out(&mut seed)?;
        Self::keygen_from_seed(&seed)
    }

    /// Generates a key pair from a 32-byte seed, which must have [`KeyType::Seed`] or
    /// [`KeyType::CryptographicRandom`] and at least [`SecurityStrength::_128bit`].
    ///
    /// RFC 7748 §6.1: "Alice generates 32 random bytes in `a[0]` to `a[31]` and transmits
    /// K_A = X25519(a, 9) to Bob". The seed is used as the private key unchanged, so this is also
    /// how to import an existing private key along with its public key.
    pub fn keygen_from_seed(
        seed: &KeyMaterial256,
    ) -> Result<(X25519PublicKey, X25519PrivateKey), KeyAgreementError> {
        if !(seed.key_type() == KeyType::Seed || seed.key_type() == KeyType::CryptographicRandom)
            || seed.key_len() != SCALAR_SIZE
        {
            return Err(KeyAgreementError::KeyGenError(
                "Seed must be 32 bytes and KeyType::Seed or KeyType::CryptographicRandom.",
            ));
        }

        if seed.security_strength() < Self::MAX_SECURITY_STRENGTH {
            return Err(KeyAgreementError::KeyGenError(
                "Seed SecurityStrength must match algorithm security strength",
            ));
        }

        let mut k: Secret<[u8; SCALAR_SIZE]> = Secret::new();
        // Cannot panic: the length was checked above.
        k.copy_from_slice(seed.ref_to_bytes());
        let sk = X25519PrivateKey(k);

        Ok((sk.pk(), sk))
    }

    /// Checks that `pk` is the public key of `sk`, by deriving it from `sk` and comparing.
    ///
    /// Returns either `()` or [`KeyAgreementError::ConsistencyCheckFailed`].
    pub fn keypair_consistency_check(
        pk: &X25519PublicKey,
        sk: &X25519PrivateKey,
    ) -> Result<(), KeyAgreementError> {
        sk.consistency_check(pk)
    }
}

impl KeyAgreement<X25519PublicKey, X25519PrivateKey, POINT_SIZE, SCALAR_SIZE> for X25519 {
    /// The X25519 Diffie-Hellman of RFC 7748 §6.1: computes the shared secret
    /// `K = X25519(sk, pk)`, the u-coordinate of the scalar multiple of the peer's public key by
    /// our private key, as its canonical 32-byte little-endian encoding.
    ///
    /// Alice computes `X25519(a, K_B)` and Bob `X25519(b, K_A)`, and §6.1 shows both equal
    /// `X25519(a, X25519(b, 9)) = X25519(b, X25519(a, 9))`. §6.1 also says to then "use a
    /// key-derivation function that includes K, K_A, and K_B to derive a symmetric key": `K` is
    /// not uniformly random, so it should not be used as a key directly.
    ///
    /// Any 32 bytes are accepted as `pk`: per RFC 7748 §5, bit 255 is ignored and values `>= p`
    /// are processed as if reduced mod p.
    ///
    /// # Errors
    ///
    /// Returns [`KeyAgreementError::InvalidPublicKey`] if `K` is all zeros. RFC 7748 §6.1: "The
    /// check for the all-zero value results from the fact that the X25519 function produces that
    /// value if it operates on an input corresponding to a point with small order". Such a point
    /// "will eliminate any contribution from the other party's private key" (§7), so `K` is the
    /// same for every private key and is known to whoever chose `pk`.
    ///
    /// RFC 7748 makes the check optional: both parties "MAY check, without leaking extra
    /// information about the value of K, whether K is the all-zero value and abort if so". This
    /// implementation always performs it, as the protocols built on X25519 require:
    ///  * RFC 8446 (TLS 1.3) §7.4.2: "Implementations MUST check whether the computed
    ///    Diffie-Hellman shared secret is the all-zero value and abort if so".
    ///  * RFC 9180 (HPKE) §7.1.4: "recipients MUST check whether the Diffie-Hellman shared secret
    ///    is the all-zero value and abort if so".
    ///
    /// The check is constant time, ORing all the bytes together as §6.1 suggests, so the only
    /// information it reveals about `K` is whether it is zero.
    fn key_agreement(
        pk: &X25519PublicKey,
        sk: &X25519PrivateKey,
    ) -> Result<X25519PublicKey, KeyAgreementError> {
        dh(sk, pk)
    }
}

/// `X25519(sk, pk)`, rejecting an all-zero output; see [`X25519::key_agreement`].
fn dh(sk: &X25519PrivateKey, pk: &X25519PublicKey) -> Result<X25519PublicKey, KeyAgreementError> {
    let r = scalar_mult(sk, pk);
    if r.is_zero() {
        return Err(KeyAgreementError::InvalidPublicKey(
            "Public key has small order: the shared secret is all zeros",
        ));
    }
    Ok(r)
}

/// An X25519 private key: a 32-byte scalar, as defined in Section 5 of RFC7748.
///
/// Any 32 bytes are a valid scalar. The fixed bits `decodeScalar25519` sets and clears
/// ("clamping") are applied each time the scalar is used, so keys that differ only in those bits
/// are the same key, and compare equal. Held in a [`Secret`], so it is zeroized on drop and
/// redacted from `Debug`.
#[derive(Clone)]
pub struct X25519PrivateKey(Secret<[u8; SCALAR_SIZE]>);

impl X25519PrivateKey {
    /// Computes the public key, `X25519(k, 9)` (RFC 7748 §6.1).
    ///
    /// The public key is not stored with the private key, so each call runs a full scalar
    /// multiplication.
    pub fn pk(&self) -> X25519PublicKey {
        scalar_mult_base(self)
    }

    /// Checks that `pk` is this private key's public key, by computing it with [`Self::pk`] and
    /// comparing.
    ///
    /// Returns either `()` or [`KeyAgreementError::ConsistencyCheckFailed`].
    pub fn consistency_check(&self, pk: &X25519PublicKey) -> Result<(), KeyAgreementError> {
        if self.pk() == *pk {
            Ok(())
        } else {
            Err(KeyAgreementError::ConsistencyCheckFailed("Public key does not match private key"))
        }
    }

    /// The key bytes with `decodeScalar25519`'s fixed bits applied (RFC 7748 §5):
    ///
    /// ```text
    /// k_list[0] &= 248
    /// k_list[31] &= 127
    /// k_list[31] |= 64
    /// ```
    fn clamped(&self) -> Secret<[u8; SCALAR_SIZE]> {
        let mut k = self.0.clone();
        k[0] &= 248;
        k[31] &= 127;
        k[31] |= 64;
        k
    }
}

/// The encoding is the 32 key bytes, clamped (the bit operations of `decodeScalar25519`, RFC 7748
/// §5), so keys that compare equal have the same encoding. This is also the DHKEM serialization:
/// RFC 9180 §7.1.2 says "The SerializePrivateKey() function MUST clamp its output and the
/// DeserializePrivateKey() function MUST clamp its input".
impl KeyAgreementPrivateKey<SCALAR_SIZE> for X25519PrivateKey {
    fn encode(&self) -> [u8; SCALAR_SIZE] {
        *self.clamped()
    }

    fn encode_out(&self, out: &mut [u8; SCALAR_SIZE]) -> usize {
        out.fill(0);
        *out = *self.clamped();
        SCALAR_SIZE
    }

    /// Any 32 bytes are a valid private key; they are clamped on the way in.
    ///
    /// # Errors
    ///
    /// [`KeyAgreementError::DecodingError`] if `bytes` is not 32 bytes.
    fn from_bytes(bytes: &[u8]) -> Result<Self, KeyAgreementError> {
        let bytes: &[u8; SCALAR_SIZE] = bytes.try_into().map_err(|_| {
            KeyAgreementError::DecodingError("An X25519 private key must be 32 bytes")
        })?;
        let mut k: Secret<[u8; SCALAR_SIZE]> = Secret::new();
        *k = *bytes;
        Ok(Self(X25519PrivateKey(k).clamped()))
    }
}

/// Constant-time comparison of the clamped scalars.
impl PartialEq for X25519PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        ct_eq_bytes(&*self.clamped(), &*other.clamped())
    }
}

impl Eq for X25519PrivateKey {}

/// An X25519 public value: the u-coordinate of a point on curve25519, as 32 little-endian bytes
/// (Section 5 of RFC7748).
///
/// Any 32 bytes are accepted: Section 5 requires bit 255 to be ignored and values `>= p` to be
/// processed as if reduced mod p. Public data, so it is `Copy` and its `Debug` shows the bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X25519PublicKey([u8; POINT_SIZE]);

impl X25519PublicKey {
    /// Wraps 32 bytes as a u-coordinate.
    pub const fn from_bytes(bytes: [u8; POINT_SIZE]) -> Self {
        Self(bytes)
    }

    /// The 32 encoded bytes.
    pub const fn as_bytes(&self) -> &[u8; POINT_SIZE] {
        &self.0
    }

    /// Constant-time test for all 32 bytes being zero.
    ///
    /// This tests the encoding, not the value: it equals "u = 0" only for canonical encodings,
    /// such as [`scalar_mult`]'s output. A non-canonical encoding of 0 (`p`, or bit 255 set)
    /// returns `false`.
    fn is_zero(&self) -> bool {
        ct_eq_zero_bytes(&self.0)
    }
}

/// The encoding is the 32 bytes of the u-coordinate, as is (RFC 7748 §5).
impl KeyAgreementPublicKey<POINT_SIZE> for X25519PublicKey {
    fn encode(&self) -> [u8; POINT_SIZE] {
        self.0
    }

    fn encode_out(&self, out: &mut [u8; POINT_SIZE]) -> usize {
        out.fill(0);
        *out = self.0;
        POINT_SIZE
    }

    /// Any 32 bytes are accepted: RFC 7748 §5 requires bit 255 to be ignored and values `>= p` to
    /// be processed as if reduced mod p.
    ///
    /// # Errors
    ///
    /// [`KeyAgreementError::DecodingError`] if `bytes` is not 32 bytes.
    fn from_bytes(bytes: &[u8]) -> Result<Self, KeyAgreementError> {
        let bytes: &[u8; POINT_SIZE] = bytes.try_into().map_err(|_| {
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
fn decode_scalar_25519(k: &X25519PrivateKey, n: &mut [u32; 8]) {
    let (words, _) = k.0.as_chunks::<4>(); // 32 bytes: exactly 8 chunks, no remainder
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
/// Verified equal to `decodeUCoordinate(b, 255)` over 20,004 inputs, random plus edge cases.
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
fn encode_u_coordinate(u: &FieldElement25519, r: &mut [u8; POINT_SIZE]) {
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
///  * `k`, a 32-byte scalar
///  * `u`, a 32-byte little-endian u-coordinate
/// Output: The canonical little-endian encoding of the u-coordinate of `k * u`.
fn scalar_mult(k: &X25519PrivateKey, u: &X25519PublicKey) -> X25519PublicKey {
    // The decoded scalar is as secret as `k` itself.
    let mut n: Secret<[u32; 8]> = Secret::new();
    decode_scalar_25519(k, &mut n);

    // Pre-condition:
    // The ladder below is only correct for scalars of the form 2^254 + 8m, 0 <= m <= 2^251 - 1
    // which should be enforced by a correct implementation of decode_scalar_25519.
    debug_assert_eq!(1, n[7] >> 30);
    debug_assert_eq!(0, n[0] & 7);

    let x1 = decode_u_coordinate(u);
    let mut x2 = x1.clone();
    let mut z2 = FieldElement25519::one();
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
    //     advance: the registers above are seeded with the RFC's x_2 = 1, z_2 = 0, x_3 = u,
    //     z_3 = 1 *after* it has been applied, and `swap` starts at k_254. So the loop starts at 253 and not 254.
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
        (z3, x2) = x2.sum_and_difference(&z2);
        // CB = C * B,                  -> t1
        t1 = t1.mul(&x2);
        // DA = D * A,                  -> x3
        x3 = x3.mul(&z3);
        // AA = A^2,                    -> z3
        z3 = z3.sqr();
        // BB = B^2,                    -> x2
        x2 = x2.sqr();

        // E = AA - BB,                 -> t2
        t2 = z3.sub(&x2);
        // z_2 = E * (AA + a24 * E),    -> z2
        // Deviation from the RFC: written as E * (BB + C_A24 * E), an equivalent pairing of the
        // constant with the other operand. See C_A24's declaration.
        // The incoming z_2 died on the `sum_and_difference` above, which is what frees this slot.
        z2 = t2.mul_u32(C_A24).add(&x2).mul(&t2);
        // x_2 = AA * BB,               -> x2
        x2 = x2.mul(&z3);

        // x_3 = (DA + CB)^2,           -> x3
        // z_3 = x_1 * (DA - CB)^2,     -> z3
        // The function `sum_and_difference()` computes `(DA + CB) and (DA - CB)` is a single
        // operation, allowing these lines to be combined.
        // Deviation from the RFC: yields CB - DA, negated. Harmless as both lines below square it.
        (x3, z3) = t1.sum_and_difference(&x3);
        // (completes x_3)
        x3 = x3.sqr();
        // (completes z_3)
        z3 = z3.sqr().mul(&x1);

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
        FieldElement25519::cswap(swap, &mut x2, &mut x3);
        // (z_2, z_3) = cswap(swap, z_2, z_3)
        //   > swaps in-place
        FieldElement25519::cswap(swap, &mut z2, &mut z3);
        // swap = k_t
        swap = k_bit;
    }

    debug_assert!(!swap.to_bool());

    for _ in 0..3 {
        ladder_double(&mut x2, &mut z2);
    }

    x2 = x2.mul(&z2.inv());
    let mut out = [0_u8; POINT_SIZE];
    encode_u_coordinate(&x2, &mut out);
    X25519PublicKey(out)
}

fn scalar_mult_base(k: &X25519PrivateKey) -> X25519PublicKey {
    // Equivalent (but much slower) -- since the BASE_POINT never changes, you can
    //         precompute lookup tables for the multiples of BASE_POINT. TODO
    scalar_mult(k, &BASE_POINT)
}

/*** DHKEM ***/

// This section provides the machinery to promote x25519 to a KEM via RFC9180's DHKEM construction.

/// The length of the shared secret from [`X25519`]'s KEM: Nsecret for DHKEM(X25519, HKDF-SHA256)
/// (RFC 9180 §7.1).
pub const DHKEM_SS_LEN: usize = 32;

/// DHKEM(X25519, HKDF-SHA256) of RFC 9180 §4.1. Nenc = Npk = Ndh = 32 and Nsk = 32 (§7.1).
type X25519DHKEM = DHKEM<X25519, POINT_SIZE, SCALAR_SIZE, POINT_SIZE, DHKEM_SS_LEN>;

/// DHKEM(X25519, HKDF-SHA256): kem_id 0x0020, with Nenc = Npk = Nsk = 32 (RFC 9180 §7.1).
impl DHKEMParams<POINT_SIZE, SCALAR_SIZE, POINT_SIZE> for X25519 {
    type PublicKey = X25519PublicKey;
    type PrivateKey = X25519PrivateKey;
    type KDFHash = SHA256;
    const KEM_ID: u16 = 0x0020;

    fn generate_key_pair_rng(
        rng: &mut dyn RNG,
    ) -> Result<(X25519PublicKey, X25519PrivateKey), KEMError> {
        // RFC 9180 §4: "GenerateKeyPair can be implemented as DeriveKeyPair(random(Nsk))"; for
        // X25519, 32 random bytes are already a private key (RFC 7748 §6.1), so they are used as is.
        Self::keygen_from_rng(rng).map_err(|e| match e {
            KeyAgreementError::RNGError(e) => KEMError::RNGError(e),
            KeyAgreementError::KeyGenError(msg) => KEMError::KeyGenError(msg),
            _ => KEMError::GenericError("X25519 key generation failed"),
        })
    }

    fn private_key_from_bytes(sk: &[u8; SCALAR_SIZE]) -> X25519PrivateKey {
        let mut k: Secret<[u8; SCALAR_SIZE]> = Secret::new();
        *k = *sk;
        X25519PrivateKey(k)
    }

    fn pk(sk: &X25519PrivateKey) -> X25519PublicKey {
        sk.pk()
    }

    fn dh(
        sk: &X25519PrivateKey,
        pk: &X25519PublicKey,
    ) -> Result<Secret<[u8; POINT_SIZE]>, KeyAgreementError> {
        let mut k: Secret<[u8; POINT_SIZE]> = Secret::new();
        *k = dh(sk, pk)?.0;
        Ok(k)
    }

    // RFC 9180 §7.1.1: "For X25519 and X448, the SerializePublicKey() and DeserializePublicKey()
    // functions are the identity function".
    fn serialize_public_key(pk: &X25519PublicKey) -> [u8; POINT_SIZE] {
        pk.0
    }

    fn deserialize_public_key(pkm: &[u8; POINT_SIZE]) -> Result<X25519PublicKey, KEMError> {
        Ok(X25519PublicKey(*pkm))
    }
}

/// X25519 as a KEM: DHKEM(X25519, HKDF-SHA256) of RFC 9180 §4.1, where the ciphertext is an
/// ephemeral public key (`enc`) and the shared secret is derived with HKDF-SHA256 from the X25519
/// output and both public keys.
impl KEMEncapsulator<X25519PublicKey, POINT_SIZE, POINT_SIZE, DHKEM_SS_LEN> for X25519 {
    /// `Encap(pkR)` (RFC 9180 §4.1), drawing the ephemeral key pair from the library's default RNG,
    /// seeded from the OS.
    ///
    /// # Errors
    ///
    /// [`KEMError::InvalidPublicKey`] if `pk` gives an all-zero X25519 output, as for
    /// [`X25519::key_agreement`].
    fn encaps(
        pk: &X25519PublicKey,
    ) -> Result<(KeyMaterial<DHKEM_SS_LEN>, [u8; POINT_SIZE]), KEMError> {
        let mut os_rng = HashDRBG_SHA512::new_from_os();
        Self::encaps_rng(pk, &mut os_rng)
    }

    /// `Encap(pkR)` (RFC 9180 §4.1), drawing the ephemeral key pair from `rng`.
    ///
    /// # Errors
    ///
    /// * [`KEMError::RNGError`] if `rng`'s security strength is below 128 bits.
    /// * [`KEMError::InvalidPublicKey`] if `pk` gives an all-zero X25519 output, as for
    ///   [`X25519::key_agreement`].
    fn encaps_rng(
        pk: &X25519PublicKey,
        rng: &mut dyn RNG,
    ) -> Result<(KeyMaterial<DHKEM_SS_LEN>, [u8; POINT_SIZE]), KEMError> {
        X25519DHKEM::encap_rng(pk, rng)
    }
}

impl KEMDecapsulator<X25519PrivateKey, SCALAR_SIZE, POINT_SIZE, DHKEM_SS_LEN> for X25519 {
    /// `Decap(enc, skR)` (RFC 9180 §4.1), with the ciphertext `ct` as `enc`.
    ///
    /// # Errors
    ///
    /// * [`KEMError::LengthError`] if `ct` is not 32 bytes.
    /// * [`KEMError::DecapsulationFailed`] if `ct` gives an all-zero X25519 output.
    fn decaps(sk: &X25519PrivateKey, ct: &[u8]) -> Result<KeyMaterial<DHKEM_SS_LEN>, KEMError> {
        let enc: &[u8; POINT_SIZE] = ct
            .try_into()
            .map_err(|_| KEMError::LengthError("An X25519 KEM ciphertext must be 32 bytes"))?;
        X25519DHKEM::decap(enc, sk)
    }
}

/// The same clamped encoding as the [`KeyAgreementPrivateKey`] impl, which RFC 9180 §7.1.2 requires
/// of a DHKEM.
impl KEMPrivateKey<SCALAR_SIZE> for X25519PrivateKey {
    fn encode(&self) -> [u8; SCALAR_SIZE] {
        <Self as KeyAgreementPrivateKey<SCALAR_SIZE>>::encode(self)
    }

    fn encode_out(&self, out: &mut [u8; SCALAR_SIZE]) -> usize {
        <Self as KeyAgreementPrivateKey<SCALAR_SIZE>>::encode_out(self, out)
    }

    /// # Errors
    ///
    /// [`KEMError::DecodingError`] if `bytes` is not 32 bytes.
    fn from_bytes(bytes: &[u8]) -> Result<Self, KEMError> {
        <Self as KeyAgreementPrivateKey<SCALAR_SIZE>>::from_bytes(bytes)
            .map_err(|_| KEMError::DecodingError("An X25519 private key must be 32 bytes"))
    }
}

/// The same encoding as the [`KeyAgreementPublicKey`] impl: RFC 9180 §7.1.1 makes serialization the
/// identity function for X25519.
impl KEMPublicKey<POINT_SIZE> for X25519PublicKey {
    fn encode(&self) -> [u8; POINT_SIZE] {
        <Self as KeyAgreementPublicKey<POINT_SIZE>>::encode(self)
    }

    fn encode_out(&self, out: &mut [u8; POINT_SIZE]) -> usize {
        <Self as KeyAgreementPublicKey<POINT_SIZE>>::encode_out(self, out)
    }

    /// # Errors
    ///
    /// [`KEMError::DecodingError`] if `bytes` is not 32 bytes.
    fn from_bytes(bytes: &[u8]) -> Result<Self, KEMError> {
        <Self as KeyAgreementPublicKey<POINT_SIZE>>::from_bytes(bytes)
            .map_err(|_| KEMError::DecodingError("An X25519 public key must be 32 bytes"))
    }
}
