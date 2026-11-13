//! The curve markers: one unit type per curve this crate implements, naming the curve and
//! nothing else. A crate that builds a role on a curve (signatures, key agreement) implements
//! its extension trait on the marker, so the caller starts from the curve and the trait in
//! scope says what the key pair is for: `P256::generate_signature_key_pair(&mut rng)` from
//! `bouncycastle_ecdsa`, `P256::generate_agreement_key_pair(&mut rng)` from
//! `bouncycastle_eccdh`. A marker carries no state; its one impl of this crate's is
//! [`Curve`](crate::curve::Curve), the routing table from the marker to the curve's arithmetic in
//! [`hazmat`](crate::hazmat), which is what lets a role crate be written once over `C: Curve`.

mod bp256r1;
mod bp384r1;
mod bp512r1;
mod p256;
mod p256k1;
mod p384;
mod p521;

pub use bp256r1::Bp256r1;
pub use bp384r1::Bp384r1;
pub use bp512r1::Bp512r1;
pub use p256::P256;
pub use p256k1::Secp256K1;
pub use p384::P384;
pub use p521::P521;
