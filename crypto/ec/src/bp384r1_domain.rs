//! brainpoolP384r1 domain parameters, RFC 5639 §3.4. `p` lives in [`crate::bp384r1`]; `n` lives in
//! [`crate::bp384r1_scalar`]. This module holds the rest: the curve coefficients `A` and `B` and
//! the base point `G`.
//!
//! Unlike every NIST curve or secp256k1 in this crate, brainpool's `A` is neither `-3` nor `0`, so
//! it has no dedicated doubling-formula shortcut: [`crate::bp384r1_point`] uses the general-`a`
//! "dbl-2007-bl" formula instead.
//!
//! Every value below was extracted directly from a freshly downloaded copy of RFC 5639 §3.4's text
//! (concatenating the line-wrapped hex under `Curve-ID: brainpoolP384r1`, not retyped) and verified
//! in Python before any of this was ported to Rust: `y^2 = x^3 + Ax + B (mod p)` holds for `(G_X,
//! G_Y)`.

/// The curve coefficient `A` in `y^2 = x^3 + Ax + B`, little-endian `u64` limbs.
pub const A_LIMBS: [u64; 6] = [
    0x04a8c7dd22ce2826, 0x8aa5814a503ad4eb, 0x139165efba91f90f, 0xc2bea28e4fb22787,
    0x3c72080ace05afa0, 0x7bc382c63d8c150c,
];

/// The curve coefficient `B` in `y^2 = x^3 + Ax + B`, little-endian `u64` limbs.
pub const B_LIMBS: [u64; 6] = [
    0x3ab78696fa504c11, 0x7cb4390295dbc994, 0x2e880ea53eeb62d5, 0x2fb77de107dcd2a6,
    0x8b39b55416f0447c, 0x04a8c7dd22ce2826,
];

/// The base point `G`'s `x` coordinate, little-endian `u64` limbs.
pub const G_X_LIMBS: [u64; 6] = [
    0xef87b2e247d4af1e, 0xe826e03436d646aa, 0xdb7fcafe0cbd10e8, 0x8847a3e77ef14fe3,
    0xa2a63a81b7c13f6b, 0x1d1c64f068cf45ff,
];

/// The base point `G`'s `y` coordinate, little-endian `u64` limbs.
pub const G_Y_LIMBS: [u64; 6] = [
    0x42820341263c5315, 0x0e46462177918111, 0xe19c054ff9912928, 0x62b70b29feec5864,
    0x5cb1eb8e95cfd552, 0x8abe1d7520f9c2a4,
];
