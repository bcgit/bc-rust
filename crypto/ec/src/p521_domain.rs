//! P-521 domain parameters, NIST SP 800-186 (Feb 2023) §3.2.1.5. `p` and `a = -3` live in
//! [`crate::p521`] (the `a = -3` shortcut is baked directly into
//! [`crate::p521_point::P521JacobianPoint::double`]); `n` lives in [`crate::p521_scalar`]. This
//! module holds the rest: the curve coefficient `b` and the base point `G`.

/// The curve coefficient `b` in `y^2 = x^3 - 3x + b`, little-endian `u64` limbs.
pub const B_LIMBS: [u64; 9] = [
    0xef451fd46b503f00, 0x3573df883d2c34f1, 0x1652c0bd3bb1bf07, 0x56193951ec7e937b,
    0xb8b489918ef109e1, 0xa2da725b99b315f3, 0x929a21a0b68540ee, 0x953eb9618e1c9a1f,
    0x0000000000000051,
];

/// The base point `G`'s `x` coordinate, little-endian `u64` limbs.
pub const G_X_LIMBS: [u64; 9] = [
    0xf97e7e31c2e5bd66, 0x3348b3c1856a429b, 0xfe1dc127a2ffa8de, 0xa14b5e77efe75928,
    0xf828af606b4d3dba, 0x9c648139053fb521, 0x9e3ecb662395b442, 0x858e06b70404e9cd,
    0x00000000000000c6,
];

/// The base point `G`'s `y` coordinate, little-endian `u64` limbs.
pub const G_Y_LIMBS: [u64; 9] = [
    0x88be94769fd16650, 0x353c7086a272c240, 0xc550b9013fad0761, 0x97ee72995ef42640,
    0x17afbd17273e662c, 0x98f54449579b4468, 0x5c8a5fb42c7d1bd9, 0x39296a789a3bc004,
    0x0000000000000118,
];
