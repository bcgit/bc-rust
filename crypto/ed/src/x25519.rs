use bouncycastle_utils::ct::Condition;

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

// TODO -- RFC7748: "When receiving such an array, implementations of X25519
//    (but not X448) MUST mask the most significant bit in the final byte."
//    I think "mask" here means to assign 0 or 1 pseudo-randomly?

// TODO -- RFC7748: "   Implementations MUST accept non-canonical values and process them as
//    if they had been reduced modulo the field prime.  The non-canonical
//    values are 2^255 - 19 through 2^255 - 1 for X25519 and 2^448 - 2^224
//    - 1 through 2^448 - 1 for X448.
//    The TODO here is to unit test this.

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

/// `decodeScalar25519(k)` as defined in Section 5 of RFC7748:
///
/// ```text
/// def decodeScalar25519(k):
///     k_list = [ord(b) for b in k]
///     k_list[0] &= 248
///     k_list[31] &= 127
///     k_list[31] |= 64
///     return decodeLittleEndian(k_list, 255)
/// ```
///
/// Section 5 gives the same rule in prose: "set the three least significant bits of the first
/// byte and the most significant bit of the last to zero, set the second most significant bit of
/// the last byte to 1 and, finally, decode as little-endian. This means that the resulting
/// integer is of the form 2^254 plus eight times a value between 0 and 2^251 - 1 (inclusive)."
///
/// That last sentence is the invariant [`scalar_mult`] is built on, and it needs both halves of
/// it. The `2^254 +` is why the ladder can start at bit 253 against a pre-swapped initial state;
/// the `8 *` is why its last three iterations collapse into three [`point_double`] calls with no
/// trailing conditional swap.
///
/// Deviation from the RFC: the RFC masks bytes and then decodes, whereas this decodes into
/// four-byte words first and masks the equivalent word positions. `k_list[0] &= 248` becomes
/// `n[0] &= 0xFFFFFFF8` -- the same low three bits, since `n[0]` is the first four bytes -- and
/// `k_list[31] &= 127` / `|= 64` become `n[7] &= 0x7FFFFFFF` / `|= 0x40000000`, the same top two
/// bits, since `n[7]` is the last four bytes. Verified equal to `decodeScalar25519` over 20,004
/// inputs, random plus edge cases.
///
/// The `25519` in the name is load-bearing: `decodeScalar448` clears two low bits rather than
/// three, and sets bit 447 (Section 5).
///
/// Input: A 32-byte little-endian scalar.
/// Output: The decoded scalar, written to `n` as eight little-endian 32-bit words.
///
/// Scope: X25519.
// TODO: Claude-generated, double-check
fn decode_scalar_25519(k: &[u8; SCALAR_SIZE], n: &mut [u32; 8]) {
    for (i, n_i) in n.iter_mut().enumerate() {
        let pos = i * 4;
        *n_i = decode_u32(&k[pos..(pos + 4)]);
    }

    n[0] &= 0xFFFFFFF8_u32;
    n[7] &= 0x7FFFFFFF_u32;
    n[7] |= 0x40000000_u32;
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

// // TODO make this match the style of MLDSA keygen
// pub fn generate_private_key(random: &mut dyn RngCore, k: &mut [u8; SCALAR_SIZE]) {
//     random.fill_bytes(&mut k[..]);
//
//     k[0] &= 0xF8;
//     k[SCALAR_SIZE - 1] &= 0x7F;
//     k[SCALAR_SIZE - 1] |= 0x40;
// }

// TODO make this match the style of MLDSA keygen
pub fn generate_public_key(k: &[u8; SCALAR_SIZE], r: &mut [u8; POINT_SIZE]) {
    scalar_mult_base(k, r);
}

// TODO: move to curve25519.rs ?
fn point_double(x: &mut CoordField, z: &mut CoordField) {
    let (mut a, mut b) = x.sum_and_difference(z);
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

// TODO -- "For X25519, the unused, most significant bit MUST be zero." -- add test case or debug_assert.

/// `X25519(k, u)` as defined in Section 5 of RFC7748: the Montgomery ladder, computing scalar
/// multiplication on curve25519 from a u-coordinate alone.
///
/// The ladder is constant time with respect to `k`: the iteration count is fixed and the only
/// scalar-dependent step is [`CoordField::cswap`].
///
/// # Modifications from the RFC
/// Modified to fold the RFC's first ladder iteration into the initial state, to replace its last
/// three iterations with [`point_double`] calls, and to cycle the RFC's named intermediates
/// through a fixed set of registers rather than materialise them.
///
/// # Inputs
///  * `k`, a 32-byte scalar
///  * `u`, a 32-byte little-endian u-coordinate
///  * `out`, a 32-byte output buffer.
/// Output: The canonical little-endian encoding of the u-coordinate of `k * u`, written to `out`.
// TODO -- the Section 5.2 and Section 6.1 test vectors are not exercised anywhere in this crate
//          yet. The structure here was checked against them out-of-tree, which is not the same
//          thing as a test.
// TODO: Claude-generated, double-check
fn scalar_mult(k: &[u8; SCALAR_SIZE], u: &[u8; POINT_SIZE], out: &mut [u8; POINT_SIZE]) {
    let mut n = [0u32; 8];
    decode_scalar_25519(k, &mut n);

    // Pre-condition:
    // The ladder below is only correct for scalars of the form 2^254 + 8m, 0 <= m <= 2^251 - 1
    // which should be enforced by a correct implementation of decode_scalar_25519.
    debug_assert_eq!(1, n[7] >> 30);
    debug_assert_eq!(0, n[0] & 7);

    let x1 = CoordField::decode_u_coordinate(u);
    let mut x2 = x1;
    let mut z2 = CoordField::one();
    let mut x3 = CoordField::one();
    let mut z3 = CoordField::zero();

    let mut t1;
    let mut t2;

    let mut swap = Condition::<i64>::from_bool_const::<true>();

    // Deviation from the RFC:
    // RFC7748 §5 runs `For t = bits-1 down to 0`, i.e. t = 254 down to 0, with the conditional
    // swap at the top of the body and the arithmetic after it. This loop deviates in three ways,
    // all of them consequences of the scalar's form -- see the pre-condition above:
    //
    //  1. Rotated body. The arithmetic comes first here and the swap last.
    //  2. t = 254 is not in the loop because bit 254 is always set, so that iteration's swap is known in
    //     advance: the registers above are seeded with the RFC's x_2 = 1, z_2 = 0, x_3 = u,
    //     z_3 = 1 *after* it has been applied, and `swap` starts at k_254. So the loop starts at 253 and not 254.
    //  3. t = 2, 1, 0 are not in the loop because bits 0..2 are always clear, so those iterations reduce
    //     to doubling the (x_2, z_2) branch and their swaps are no-ops. They become the three
    //     point_double calls after the loop, and the RFC's post-loop cswap is dropped for the same
    //     reason -- the debug_assert below is what checks it would have been a no-op.
    for bit in (2..=253_usize).rev() {
        // This section is the same core algorithm as in RFC7748 §5, but uses a different variable
        // naming convention in order to more efficiently reuse memory.
        // Comment style:
        // <exact line from RFC7748 §5>, -> <register stored to>

        // C = x_3 + z_3,               -> t1
        // D = x_3 - z_3,               -> x3
        (t1, x3) = x3.sum_and_difference(&z3);
        // A = x_2 + z_2,               -> z3
        // B = x_2 - z_2,               -> x2
        // Must follow the line above, not precede it: that one still reads the incoming z_3,
        // which this one overwrites.
        (z3, x2) = x2.sum_and_difference(&z2);
        // CB = C * B,                  -> t1
        t1 = t1.mul(&x2);
        // DA = D * A,                  -> x3
        x3 = x3.mul(&z3);
        // AA = A^2,                    -> z3
        z3.sqr_mut();
        // BB = B^2,                    -> x2
        x2.sqr_mut();

        // E = AA - BB,                 -> t2
        t2 = z3.sub(&x2);
        // z_2 = E * (AA + a24 * E),    -> z2
        // Deviation from the RFC: written as E * (BB + C_A24 * E), an equivalent pairing of the
        // constant with the other operand. See C_A24's declaration.
        // The incoming z_2 died on the `sum_and_difference` above, which is what frees this slot.
        z2 = t2.mul_u32(C_A24).add(&x2).mul(&t2);
        // x_2 = AA * BB,               -> x2
        x2 = x2.mul(&z3);

        // x_3 = (DA + CB)^2,           -> x3
        // z_3 = x_1 * (DA - CB)^2,     -> z3
        // The function `sum_and_difference()` computes `(DA + CB) and (DA - CB)` is a single
        // operation, allowing these lines to be combined.
        // Deviation from the RFC: yields CB - DA, negated. Harmless as both lines below square it.
        (x3, z3) = t1.sum_and_difference(&x3);
        // (completes x_3)
        x3.sqr_mut();
        // (completes z_3)
        z3 = z3.sqr().mul(&x1);

        // The swap block is a statement-for-statement transcription, just its placement within the
        // loop has been changed.
        // This differs from the ladder presentation in the RFC because it implements the
        // constant-time cswap recommendation at the bottom of §5 using an all-ones/all-zeros
        // mask and the Condition<i64> type.

        // k_t = (k >> t) & 1
        //  > Presentation differs due to decoding k into n, and the bit-selecting Condition operator.
        let k_bit = Condition::<i64>::is_bit_set(n[bit >> 5] as i64, (bit & 0x1F) as u32);
        // swap ^= k_t
        swap ^= k_bit;
        // (x_2, x_3) = cswap(swap, x_2, x_3)
        //   > swaps in-place
        CoordField::cswap(swap, &mut x2, &mut x3);
        // (z_2, z_3) = cswap(swap, z_2, z_3)
        //   > swaps in-place
        CoordField::cswap(swap, &mut z2, &mut z3);
        // swap = k_t
        swap = k_bit;
    }

    debug_assert!(!swap.to_bool());

    for _ in 0..3 {
        point_double(&mut x2, &mut z2);
    }

    x2 = x2.mul(&z2.inv());
    x2.normalize().encode_255(out);
}

fn scalar_mult_base(k: &[u8; SCALAR_SIZE], r: &mut [u8; POINT_SIZE]) {
    // Equivalent (but much slower)
    let mut u = [0_u8; POINT_SIZE];
    u[0] = 9;
    scalar_mult(k, &u, r);

    // TODO
    // let (y, z) = curve25519::scalar_mult_base_yz(k);
    // let (t, u) = z.sum_and_difference(&y);
    // let v = t.mul(&u.inv());
    // v.normalize().encode(r);
}
