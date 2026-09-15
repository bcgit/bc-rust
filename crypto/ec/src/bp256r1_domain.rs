//! brainpoolP256r1 domain parameters, RFC 5639 §3.4. `p` lives in [`crate::bp256r1`]; `n` lives in
//! [`crate::bp256r1_scalar`]. This module holds the rest: the curve coefficients `A` and `B` and
//! the base point `G`.
//!
//! Unlike every NIST curve or secp256k1 in this crate, brainpool's `A` is neither `-3` nor `0`, so
//! it has no dedicated doubling-formula shortcut: [`crate::bp256r1_point`] uses the general-`a`
//! "dbl-2007-bl" formula instead.
//!
//! Every value below was extracted directly from a freshly downloaded copy of RFC 5639 §3.4's text
//! (concatenating the line-wrapped hex under `Curve-ID: brainpoolP256r1`, not retyped) and verified
//! in Python before any of this was ported to Rust: `y^2 = x^3 + Ax + B (mod p)` holds for `(G_X,
//! G_Y)`.

/// The curve coefficient `A` in `y^2 = x^3 + Ax + B`, little-endian `u64` limbs.
pub const A_LIMBS: [u64; 4] =
    [0xe94a4b44f330b5d9, 0xfb8055c126dc5c6c, 0xeef67530417affe7, 0x7d5a0975fc2c3057];

/// The curve coefficient `B` in `y^2 = x^3 + Ax + B`, little-endian `u64` limbs.
pub const B_LIMBS: [u64; 4] =
    [0x6bccdc18ff8c07b6, 0x958416295cf7e1ce, 0xf330b5d9bbd77cbf, 0x26dc5c6ce94a4b44];

/// The base point `G`'s `x` coordinate, little-endian `u64` limbs.
pub const G_X_LIMBS: [u64; 4] =
    [0x3a4453bd9ace3262, 0xb9de27e1e3bd23c2, 0x2c4b482ffc81b7af, 0x8bd2aeb9cb7e57cb];

/// The base point `G`'s `y` coordinate, little-endian `u64` limbs.
pub const G_Y_LIMBS: [u64; 4] =
    [0x5c1d54c72f046997, 0xc27745132ded8e54, 0x97f8461a14611dc9, 0x547ef835c3dac4fd];
