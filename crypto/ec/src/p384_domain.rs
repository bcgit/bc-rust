//! P-384 domain parameters, NIST SP 800-186 (Feb 2023) §3.2.1.4. `p` and `a = -3` live in
//! [`crate::p384`] (the `a = -3` shortcut is baked directly into
//! [`crate::p384_point::P384JacobianPoint::double`]); `n` lives in [`crate::p384_scalar`]. This
//! module holds the rest: the curve coefficient `b` and the base point `G`.

/// The curve coefficient `b` in `y^2 = x^3 - 3x + b`, little-endian `u64` limbs.
pub const B_LIMBS: [u64; 6] = [
    0x2a85c8edd3ec2aef, 0xc656398d8a2ed19d, 0x0314088f5013875a, 0x181d9c6efe814112,
    0x988e056be3f82d19, 0xb3312fa7e23ee7e4,
];

/// The base point `G`'s `x` coordinate, little-endian `u64` limbs.
pub const G_X_LIMBS: [u64; 6] = [
    0x3a545e3872760ab7, 0x5502f25dbf55296c, 0x59f741e082542a38, 0x6e1d3b628ba79b98,
    0x8eb1c71ef320ad74, 0xaa87ca22be8b0537,
];

/// The base point `G`'s `y` coordinate, little-endian `u64` limbs.
pub const G_Y_LIMBS: [u64; 6] = [
    0x7a431d7c90ea0e5f, 0x0a60b1ce1d7e819d, 0xe9da3113b5f0b8c0, 0xf8f41dbd289a147c,
    0x5d9e98bf9292dc29, 0x3617de4a96262c6f,
];
