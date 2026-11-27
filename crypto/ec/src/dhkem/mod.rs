//! The DH-Based KEM (DHKEM) of RFC 9180 Section 4.1, the KEM of Hybrid Public Key Encryption.
//!
//! This is a utility module and is not intended to be used directly. [`DHKEM`] is generic over
//! any Diffie-Hellman group that implements [`DHKEMParams`], the extension point through which a
//! group declares its keys, its DH operation and the KDF that the DHKEM pairs it with. Each
//! group's module implements that trait and exposes the result through the
//! [`EncapsulatingKey`](bouncycastle_core::kem_key::EncapsulatingKey) and
//! [`DecapsulatingKey`](bouncycastle_core::kem_key::DecapsulatingKey) roles on its own key types,
//! with [`HpkeKem`] on their algorithm marker, which is what `bouncycastle-hybrid`'s `hpke`
//! module runs HPKE over.
//! `AuthEncap` and `AuthDecap`, the authenticated forms that HPKE's Auth modes need, are
//! [`DHKEM::auth_encap_rng_out`] and [`DHKEM::auth_decap_out`], exposed on the keys through
//! [`AuthEncapsulatingKey`] and [`AuthDecapsulatingKey`].
//!
//! For example:
//!
//! | KEM                        | kem_id | Exposed as                                               |
//! |----------------------------|--------|----------------------------------------------------------|
//! | DHKEM(P-256, HKDF-SHA256)  | 0x0010 | `crate::eccdh`'s keys over `P256`                        |
//! | DHKEM(P-384, HKDF-SHA384)  | 0x0011 | `crate::eccdh`'s keys over `P384`                        |
//! | DHKEM(P-521, HKDF-SHA512)  | 0x0012 | `crate::eccdh`'s keys over `P521`                        |
//! | DHKEM(X25519, HKDF-SHA256) | 0x0020 | `crate::ed::x25519::{X25519PublicKey, X25519PrivateKey}` |
//! | DHKEM(X448, HKDF-SHA512)   | 0x0021 | `crate::ed::x448::{X448PublicKey, X448PrivateKey}`       |
//!
//! Both forms of RFC 9180 Section 7.1.3's `DeriveKeyPair` are implemented
//! ([`DeriveKeyPairForm`]): the expand form of X25519 and X448, and the rejection
//! sampling of the NIST curves.
//!
//! The KDF is HKDF over the hash named by [`DHKEMParams::KDFHash`], computed on
//! [`HMAC`](bouncycastle_digest::hmac::HMAC) as RFC 5869 defines it, so any hash that
//! [`HMAC`](bouncycastle_digest::hmac::HMAC) supports can be used.
//!
//! # Usage Examples
//!
//! A group's keys are the usual way in (`pk.encaps(&mut rng, ())` on an X25519 public key). The
//! generic DHKEM can also be driven directly, here as DHKEM(X25519, HKDF-SHA256):
//!
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait};
//! use bouncycastle_ec::ed::x25519::{X25519, keygen};
//! use bouncycastle_ec::dhkem::DHKEM;
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! // Npk = Nsk = Ndh = Nsecret = 32 (RFC 9180 Section 7.1).
//! type Kem = DHKEM<X25519, 32, 32, 32, 32>;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let (pk_r, sk_r) = keygen(&mut rng).unwrap();
//!
//! // The sender: the shared secret, and `enc` to send.
//! let mut enc = [0u8; 32];
//! let mut sender_secret = KeyMaterial::<32>::new();
//! Kem::encap_rng_out(&pk_r, &mut rng, &mut enc, &mut sender_secret)?;
//!
//! // The recipient recovers the same shared secret from `enc`.
//! let mut recipient_secret = KeyMaterial::<32>::new();
//! Kem::decap_out(&enc, &sk_r, &mut recipient_secret)?;
//! assert_eq!(sender_secret.ref_to_bytes(), recipient_secret.ref_to_bytes());
//! # Ok::<(), bouncycastle_core::errors::KEMError>(())
//! ```
//!
//! # Memory Usage
//!
//! [`DHKEM`] is a set of functions over its group, with no state of its own, no lookup tables
//! and no heap allocation. A call's working memory is on the stack: the DH output (Ndh bytes),
//! one PRK and one HKDF-Expand block, each sized for the largest hash of RFC 9180 Section 7.2
//! (64 bytes), and the HMAC states of the extract and the expand. The per-call stack figures
//! are in the Memory Usage tables of the groups' modules, `crate::ed::x25519`,
//! `crate::ed::x448` and `crate::eccdh`.
//!
//! # 🚨 Security Considerations 🚨
//!
//! * [`DHKEMParams::dh_into`] must perform the group's validation of the DH output (RFC 9180
//!   Section 7.1.4), such as rejecting the all-zero X25519 output. [`DHKEM`] relies on it to
//!   reject unusable public keys.
//! * [`DHKEM::derive_key_pair`] is deterministic: the key pair is only as secret as the
//!   input keying material.
//! * The DH output, the PRKs and the derived values live in `Secret`s here and are wiped at the
//!   end of their lifetime, and the `_out` forms write into the caller's buffers. The salt key,
//!   each labeled HKDF step and `derive_key_pair` run in a frame of their own whose stack is
//!   overwritten afterwards, so the HMAC states keyed by a salt or a PRK and the private key's
//!   moves are not left on the dead stack. What is not reached: the by-value `encap_rng`, `decap` and
//!   `derive_key_pair` move their result out of the frame that built it, and what the group's
//!   own operations leave is the group's (see its module).

mod dhkem;
pub mod hazmat;

pub use dhkem::{
    AuthDecapsulatingKey, AuthEncapsulatingKey, DHKEM, DHKEMParams, DeriveKeyPairForm, HpkeKem,
};
