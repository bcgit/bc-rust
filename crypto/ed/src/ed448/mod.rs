//! The core of Ed448 and Ed448ph (RFC 8032 Section 5.2; EdDSA and HashEdDSA over edwards448 in
//! FIPS 186-5 Section 7): scalar arithmetic modulo the group order, the points of edwards448
//! with their base-point tables, and key expansion, signing and verification over octet
//! arrays. Nothing here is public yet; the key objects and the signature roles are built on
//! `scheme`.

mod point;
mod precomp;
mod scalar;
mod scheme;
