//! This is a from-scratch implementation of RFC7748, not starting from the bc-rust-nursery.
//! TODO -- Unclear if this will end up being better or worse than the bc-rust-nursery version.

///  "The constant a24 is
///    (486662 - 2) / 4 = 121665 for curve25519/X25519"
// Name matches RFC
#[allow(non_upper_case_globals)]
const a24: i32 = 121665;

#[allow(non_upper_case_globals)]
const p:   2^255 - 19

/// From RFC7748 as:
///     def decodeUCoordinate(u, bits):
///        u_list = [ord(b) for b in u]
///        # Ignore any unused bits.
///        if bits % 8:
///            u_list[-1] &= (1<<(bits%8))-1
///        return decodeLittleEndian(u_list, bits)
// todo -- possibly `bits` should be a <BITS: usize>?
fn decode_u_coordinate(u: &[u8], bits: usize) -> UCoordinate25519 {
    let mut u_list = [0u8; 32];
    for (i, &byte) in u.iter().enumerate() {
        u_list[i] = byte;
    }
    // Ignore any unused bits.
    if bits % 8 != 0 {
        u_list[31] &= (1 << (bits % 8)) - 1;
    }

    u_list
}

/// From RFC7748 as:
///     def encodeUCoordinate(u, bits):
///        u = u % p
///        return ''.join([chr((u >> 8*i) & 0xff)
///                        for i in range((bits+7)/8)])
fn encode_u_coordinate(u: UCoordinate25519, bits: usize) -> [u8; 32] {
    let mut encoded = [0u8; 32];
    for i in 0..(bits + 7) / 8 {
        encoded[i] = (u[i] >> (8 * i)) & 0xff;
    }

    encoded
}

/// From RFC7748 as:
///     def decodeScalar25519(k):
///        k_list = [ord(b) for b in k]
///        k_list[0] &= 248
///        k_list[31] &= 127
///        k_list[31] |= 64
///        return decodeLittleEndian(k_list, 255)
///
/// "For X25519, in
///    order to decode 32 random bytes as an integer scalar, set the three
///    least significant bits of the first byte and the most significant bit
///    of the last to zero, set the second most significant bit of the last
///    byte to 1 and, finally, decode as little-endian.  This means that the
///    resulting integer is of the form 2^254 plus eight times a value
///    between 0 and 2^251 - 1 (inclusive)."
fn decode_scalar_25519(k: Scalar25519) -> [u8; 32] {
    let mut k_list = k.clone();
    k_list[0] &= 248;
    k_list[31] &= 127;
    k_list[31] |= 64;

    k_list
}

// "Here, the "bits" parameter should be set to 255 for X25519 and 448 for X448:"

fn x25519(k: Scalar25519, u: UCoordinate25519) -> UCoordinate25519 {
    xdh::<255, Scalar25519, UCoordinate25519>(k, u)
}

// TODO -- need to define arithmetic ops for Scalar25519

#[allow(non_snake_case)]
fn xdh<const bits: usize, Scalar, UCoordinate>(k: Scalar, u: UCoordinate) -> UCoordinate {
    let x_1 = u.clone();
    let mut x_2 = 1;
    let mut z_2 = 0;
    let mut x_3 = u.clone();
    let mut z_3 = 1;
    let mut swap = 0;

    for t in (0..bits - 1).rev() {
        let k_t = (k >> t) & 1;
        swap ^= k_t;

        // Conditional swap
        (x_2, x_3) = cswap(swap, x_2, x_3);
        (z_2, z_3) = cswap(swap, z_2, z_3);
        swap = k_t;

        let A = x_2 + z_2;
        let AA = A ^ 2;
        let B = x_2 - z_2;
        let BB = B ^ 2;
        let E = AA - BB;
        let C = x_3 + z_3;
        let D = x_3 - z_3;
        let DA = D * A;
        let CB = C * B;
        x_3 = (DA + CB) ^ 2;
        z_3 = x_1 * (DA - CB) ^ 2;
        x_2 = AA * BB;
        z_2 = E * (AA + a24 * E);
    }

    // Conditional swap; see text below.
    (x_2, x_3) = cswap(swap, x_2, x_3);
    (z_2, z_3) = cswap(swap, z_2, z_3);

    x_2 * (z_2 ^ (p - 2))
}

fn cswap(swap: i32, x_2: i32, x_3: i32) -> (i32, i32) {
    // "Where mask(swap) is the all-1 or all-0 word of the same length as x_2
    //    and x_3, computed, e.g., as mask(swap) = 0 - swap."
    fn mask(swap: i32) -> i32 {
        0 - swap
    }

    let dummy = mask(swap) & (x_2 ^ x_3);
    (x_2 ^ dummy, x_3 ^ dummy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cswap() {
        assert_eq!(cswap(0, 1, 2), (1, 2));
        assert_eq!(cswap(1, 1, 2), (2, 1));
    }
}
