//! brainpoolP512r1 domain parameters, RFC 5639 §3.4. `p` lives in [`crate::bp512r1`]; `n` lives in
//! [`crate::bp512r1_scalar`]. This module holds the rest: the curve coefficients `A` and `B` and
//! the base point `G`.
//!
//! Unlike every NIST curve or secp256k1 in this crate, brainpool's `A` is neither `-3` nor `0`, so
//! it has no dedicated doubling-formula shortcut: [`crate::bp512r1_point`] uses the general-`a`
//! "dbl-2007-bl" formula instead.
//!
//! Every value below was extracted directly from a freshly downloaded copy of RFC 5639 §3.4's text
//! (concatenating the line-wrapped hex under `Curve-ID: brainpoolP512r1`, not retyped) and verified
//! in Python before any of this was ported to Rust: `y^2 = x^3 + Ax + B (mod p)` holds for `(G_X,
//! G_Y)`.

/// The curve coefficient `A` in `y^2 = x^3 + Ax + B`, little-endian `u64` limbs.
pub const A_LIMBS: [u64; 8] = [
    0xe7c1ac4d77fc94ca, 0x7f1117a72bf2c7b9, 0x0a2ef1c98b9ac8b5, 0x2ded5d5aa8253aa1,
    0xa83441caea9863bc, 0x94cbdd8d3df91610, 0xe2327145ac234cc5, 0x7830a3318b603b89,
];

/// The curve coefficient `B` in `y^2 = x^3 + Ax + B`, little-endian `u64` limbs.
pub const B_LIMBS: [u64; 8] = [
    0x2809bd638016f723, 0x984050b75ebae5dd, 0x77fc94cadc083e67, 0x2bf2c7b9e7c1ac4d,
    0x8b9ac8b57f1117a7, 0xa8253aa10a2ef1c9, 0xea9863bc2ded5d5a, 0x3df91610a83441ca,
];

/// The base point `G`'s `x` coordinate, little-endian `u64` limbs.
pub const G_X_LIMBS: [u64; 8] = [
    0x8b352209bcb9f822, 0x7c6d5047406a5e68, 0x50d1687b93b97d5f, 0xff3b1f78e2d0d48d,
    0xb43b62eef4d0098e, 0x85ed9f70b5d916c1, 0x5a21322e9c4c6a93, 0x81aee4bdd82ed964,
];

/// The base point `G`'s `y` coordinate, little-endian `u64` limbs.
pub const G_Y_LIMBS: [u64; 8] = [
    0x78cd1e0f3ad80892, 0xd1ca2b2fa8f05406, 0x5bca4bd88a2763ae, 0xb2dcde494a5f485e,
    0xa000c55b881f8111, 0xf209f70024a57b1a, 0xc0eabfa9cf7822fd, 0x7dde385d566332ec,
];
