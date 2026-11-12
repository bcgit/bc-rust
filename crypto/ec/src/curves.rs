//! The curve markers: one unit type per curve this crate implements, naming the curve and
//! nothing else. A crate that builds a role on a curve (signatures, key agreement) implements
//! its extension trait on the marker, so the caller starts from the curve and the trait in
//! scope says what the key pair is for: `P256::generate_signature_key_pair(&mut rng)` from
//! `bouncycastle_ecdsa`, `P256::generate_agreement_key_pair(&mut rng)` from
//! `bouncycastle_eccdh`. The arithmetic stays in [`hazmat`](crate::hazmat); a marker carries no
//! state and no methods of its own.

/// NIST P-256 (secp256r1), SP 800-186 Section 3.2.1.3.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct P256;

/// NIST P-384 (secp384r1), SP 800-186 Section 3.2.1.4.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct P384;

/// NIST P-521 (secp521r1), SP 800-186 Section 3.2.1.5.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct P521;

/// secp256k1, SEC 2 Version 2.0 Section 2.4.1.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Secp256K1;

/// brainpoolP256r1, RFC 5639 Section 3.4.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bp256r1;

/// brainpoolP384r1, RFC 5639 Section 3.6.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bp384r1;

/// brainpoolP512r1, RFC 5639 Section 3.7.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bp512r1;
