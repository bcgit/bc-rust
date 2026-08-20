use bouncycastle_utils::ct::Condition;
use rand::RngCore;

use crate::curve25519::CoordField;

// TODO --  I would expect that a bunch of this is shared with Ed25519 and should be moved to curve25519.rs
//          but I'll wait until I get to the Ed25519 implementation and see what's shared.

pub const POINT_SIZE: usize = 32;
pub const SCALAR_SIZE: usize = 32;

// TODO -- what is this?
const C_A: u32 = 486662;
// TODO -- what is this?
const C_A24: u32 = (C_A + 2) / 4;

// TODO -- impl KeyAgreement trait (will need to add to traits.rs), and a KEM trait

fn are_all_zeros(r: &[u8]) -> bool {
    let mut bits = 0;
    for i in r.iter() {
        bits |= i;
    }
    bits == 0
}

// TODO -- what is this and where is it from?
// TODO -- why is it pub and now pub(crate)
pub fn calculate_agreement(
    k: &[u8; SCALAR_SIZE],
    u: &[u8; POINT_SIZE],
    r: &mut [u8; POINT_SIZE],
) -> bool {
    scalar_mult(k, u, r);
    !are_all_zeros(&r[..POINT_SIZE])
}

fn decode_u32(bs: &[u8]) -> u32 {
    (bs[0] as u32) | (bs[1] as u32) << 8 | (bs[2] as u32) << 16 | (bs[3] as u32) << 24
}

fn decode_scalar(k: &[u8; SCALAR_SIZE], n: &mut [u32; 8]) {
    for (i, n_i) in n.iter_mut().enumerate() {
        let pos = i * 4;
        *n_i = decode_u32(&k[pos..(pos + 4)]);
    }

    n[0] &= 0xFFFFFFF8_u32;
    n[7] &= 0x7FFFFFFF_u32;
    n[7] |= 0x40000000_u32;
}

/// `decodeUCoordinate(u, 255)` as defined in Section 5 of RFC 7748.
/// The most significant bit of the final byte is unused by X25519 and MUST be masked off before
/// decoding, so that u-coordinates carrying a sign bit in that position (as Ed25519 encodings do)
/// stay compatible. Non-canonical values -- u >= p, i.e. the encodings of 2^255-19 .. 2^255-1 --
/// MUST be accepted rather than rejected, which is why the result is deliberately left
/// un-normalized here; the ladder in [`scalar_mult`] reduces it as it goes.
/// Input: A 32-byte little-endian u-coordinate.
/// Output: The low 255 bits of that value as a [`CoordField`].
// TODO -- added by Claude; need to check and use.
fn decode_u_coordinate(u: &[u8; POINT_SIZE]) -> CoordField {
    CoordField::decode_255(u)
}

/// `encodeUCoordinate(u, 255)` as defined in Section 5 of RFC 7748.
/// The RFC's `u = u % p` step is [`CoordField::normalize`]: an X25519 output must be the canonical
/// encoding of its residue class, even though non-canonical values MUST be accepted on the way in
/// (see [`decode_u_coordinate`]). Bit 255 of the final byte is written as zero, since it is unused
/// by X25519.
/// Input: A u-coordinate, in any state of reduction; a 32-byte output buffer.
/// Output: The canonical 32-byte little-endian encoding of that value, written to `r`.
// TODO -- added by Claude; need to check and use.
fn encode_u_coordinate(u: &CoordField, r: &mut [u8; POINT_SIZE]) {
    u.normalize().encode_255(r);
}

// TODO make this match the style of MLDSA keygen
pub fn generate_private_key(random: &mut dyn RngCore, k: &mut [u8; SCALAR_SIZE]) {
    random.fill_bytes(&mut k[..]);

    k[0] &= 0xF8;
    k[SCALAR_SIZE - 1] &= 0x7F;
    k[SCALAR_SIZE - 1] |= 0x40;
}

// TODO make this match the style of MLDSA keygen
pub fn generate_public_key(k: &[u8; SCALAR_SIZE], r: &mut [u8; POINT_SIZE]) {
    scalar_mult_base(k, r);
}

// TODO: move to curve25519.rs ?
fn point_double(x: &mut CoordField, z: &mut CoordField) {
    let (mut a, mut b) = x.apm(z);
    a.sqr_mut();
    b.sqr_mut();
    *x = a.mul(&b);

    a = a.sub(&b);
    let t = a.mul_u32(C_A24).add(&b);
    *z = t.mul(&a);
}

// TODO -- precompute what?
pub fn precompute() {
    // TODO (or remove if precomputation inlined to static)
    // curve25519::precompute();
}

// TODO -- "For X25519, the unused, most significant bit MUST be zero."

fn scalar_mult(k: &[u8; SCALAR_SIZE], u: &[u8; POINT_SIZE], r: &mut [u8; POINT_SIZE]) {
    let mut n = [0_u32; 8];
    decode_scalar(k, &mut n);

    let x1 = CoordField::decode_255(u);
    let mut x2 = x1;
    let mut z2 = CoordField::one();
    let mut x3 = CoordField::one();
    let mut z3 = CoordField::zero();

    let mut t1;
    let mut t2;

    debug_assert_eq!(1, n[7] >> 30);

    let mut bit: usize = 253;
    let mut cond_swap = Condition::<i64>::from_bool::<true>();
    loop {
        (t1, x3) = x3.apm(&z3);
        (z3, x2) = x2.apm(&z2);
        t1 = t1.mul(&x2);
        x3 = x3.mul(&z3);
        z3.sqr_mut();
        x2.sqr_mut();

        t2 = z3.sub(&x2);
        z2 = t2.mul_u32(C_A24).add(&x2).mul(&t2);
        x2 = x2.mul(&z3);

        (x3, z3) = t1.apm(&x3);
        x3.sqr_mut();
        z3 = z3.sqr().mul(&x1);

        let cond_bit = Condition::<i64>::is_bit_set(n[bit >> 5] as i64, (bit & 0x1F) as i64);
        cond_swap ^= cond_bit;
        CoordField::cswap(cond_swap, &mut x2, &mut x3);
        CoordField::cswap(cond_swap, &mut z2, &mut z3);
        cond_swap = cond_bit;

        if bit < 3 {
            break;
        };
        bit -= 1;
    }

    debug_assert!(!cond_swap.to_bool_var());

    for _ in 0..3 {
        point_double(&mut x2, &mut z2);
    }

    x2 = x2.mul(&z2.inv());
    x2.normalize().encode_255(r);
}

fn scalar_mult_base(k: &[u8; SCALAR_SIZE], r: &mut [u8; POINT_SIZE]) {
    // Equivalent (but much slower)
    let mut u = [0_u8; POINT_SIZE];
    u[0] = 9;
    scalar_mult(k, &u, r);

    // TODO
    // let (y, z) = curve25519::scalar_mult_base_yz(k);
    // let (t, u) = z.apm(&y);
    // let v = t.mul(&u.inv());
    // v.normalize().encode(r);
}
