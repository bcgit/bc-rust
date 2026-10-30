use bouncycastle_utils::ct::Condition;
use bouncycastle_utils::secret::Secret;

use crate::curve25519::FieldElement25519;

// Only the field arithmetic (`FieldElement25519` in curve25519.rs) is shared with Ed25519. The
// scalar and point types below are X25519's own: an Ed25519 scalar is reduced mod the group order
// and an Ed25519 point is an encoded y-coordinate plus a sign bit (RFC 8032 §5.1.2), so neither
// fits these.

pub const POINT_SIZE: usize = 32;
pub const SCALAR_SIZE: usize = 32;

/// An X25519 private key: a 32-byte scalar, as defined in Section 5 of RFC7748.
///
/// Any 32 bytes are a valid scalar. The fixed bits `decodeScalar25519` sets and clears are applied
/// each time the scalar is used, not on construction, so the stored bytes are exactly the ones the
/// caller supplied. Held in a [`Secret`], so it is zeroized on drop and redacted from `Debug`.
pub struct X25519Scalar(Secret<[u8; SCALAR_SIZE]>);

impl X25519Scalar {
    /// Copies 32 bytes into a new scalar. The copy lives in zeroizing storage; the caller's buffer
    /// is not cleared.
    pub fn from_bytes(bytes: &[u8; SCALAR_SIZE]) -> Self {
        let mut k: Secret<[u8; SCALAR_SIZE]> = Secret::new();
        *k = *bytes;
        Self(k)
    }
}

/// An X25519 public value: the u-coordinate of a point on curve25519, as 32 little-endian bytes
/// (Section 5 of RFC7748).
///
/// Any 32 bytes are accepted: Section 5 requires bit 255 to be ignored and values `>= p` to be
/// processed as if reduced mod p. Public data, so it is `Copy` and its `Debug` shows the bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X25519Point([u8; POINT_SIZE]);

impl X25519Point {
    /// Wraps 32 bytes as a u-coordinate.
    pub const fn from_bytes(bytes: [u8; POINT_SIZE]) -> Self {
        Self(bytes)
    }

    /// The 32 encoded bytes.
    pub const fn as_bytes(&self) -> &[u8; POINT_SIZE] {
        &self.0
    }
}

/// The base point of curve25519, `U(P) = 9` (Section 4.1 of RFC7748).
const BASE_POINT: X25519Point = {
    let mut u = [0_u8; POINT_SIZE];
    u[0] = 9;
    X25519Point(u)
};

/// The coefficient A of curve25519, `v^2 = u^3 + A*u^2 + u` (RFC 7748 §4.1).
const C_A: u32 = 486662;

/// `(A + 2) / 4 = 121666`, the ladder's doubling constant.
///
/// Deviation from the RFC: RFC 7748 §5 uses `a24 = (486662 - 2) / 4 = 121665` in
/// `z_2 = E * (AA + a24 * E)`. Since `E = AA - BB`, `AA + a24 * E = BB + (a24 + 1) * E`, so pairing
/// the constant with BB instead needs `a24 + 1 = (A + 2) / 4`. [`scalar_mult`] and
/// [`ladder_double`] both use that form.
const C_A24: u32 = (C_A + 2) / 4;

// TODO -- impl KeyAgreement trait (will need to add to traits.rs), and a KEM trait

fn are_all_zeros(r: &[u8]) -> bool {
    let mut bits = 0;
    for i in r.iter() {
        bits |= i;
    }
    bits == 0
}

// TODO -- remove pub visibility once I have the traits impl'd
// TODO -- the shared secret is still written to bare bytes; Phase 2 decides its type (KeyMaterial).
pub fn calculate_agreement(k: &X25519Scalar, u: &X25519Point, r: &mut [u8; POINT_SIZE]) -> bool {
    scalar_mult(k, u, r);
    !are_all_zeros(&r[..POINT_SIZE])
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
/// That is why the ladder can start at bit 253 against a pre-swapped initial state;
/// the `8 *` is why its last three iterations collapse into three [`ladder_double`] calls with no
/// trailing conditional swap.
///
/// Deviation from the RFC: the RFC masks bytes and then decodes, whereas this decodes into
/// four-byte words first and masks the equivalent word positions. `k_list[0] &= 248` becomes
/// `n[0] &= 0xFFFFFFF8` -- the same low three bits, since `n[0]` is the first four bytes -- and
/// `k_list[31] &= 127` / `|= 64` become `n[7] &= 0x7FFFFFFF` / `|= 0x40000000`, the same top two
/// bits, since `n[7]` is the last four bytes.
///
/// This differs from `decodeScalar448`, which clears two low bits rather than
/// three, and sets bit 447 (Section 5).
///
/// Input: A 32-byte little-endian scalar.
/// Output: The decoded scalar, written to `n` as eight little-endian 32-bit words.
fn decode_scalar_25519(k: &X25519Scalar, n: &mut [u32; 8]) {
    let (words, _) = k.0.as_chunks::<4>(); // 32 bytes: exactly 8 chunks, no remainder
    for (n_i, w) in n.iter_mut().zip(words) {
        *n_i = u32::from_le_bytes(*w);
    }

    n[0] &= 0xFFFFFFF8_u32;
    n[7] &= 0x7FFFFFFF_u32;
    n[7] |= 0x40000000_u32;
}

/// `decodeUCoordinate(u, 255)` as defined in Section 5 of RFC7748:
///
/// ```text
/// def decodeUCoordinate(u, bits):
///     u_list = [ord(b) for b in u]
///     # Ignore any unused bits.
///     if bits % 8:
///         u_list[-1] &= (1<<(bits%8))-1
///     return decodeLittleEndian(u_list, bits)
/// ```
///
/// With `bits` = 255, `bits % 8` is 7 and the mask clears bit 255, the most significant bit of
/// the final byte. Section 5 requires exactly that: "When receiving such an array,
/// implementations of X25519 (but not X448) MUST mask the most significant bit in the final
/// byte." [`FieldElement25519::decode_255`] does the masking and the little-endian decode.
///
/// The result is not normalized, as Section 5 also requires: "Implementations MUST accept
/// non-canonical values and process them as if they had been reduced modulo the field prime. The
/// non-canonical values are 2^255 - 19 through 2^255 - 1 for X25519".
///
/// Verified equal to `decodeUCoordinate(b, 255)` over 20,004 inputs, random plus edge cases.
///
/// Input: A 32-byte little-endian u-coordinate.
/// Output: The u-coordinate as a [`FieldElement25519`], not normalized.
fn decode_u_coordinate(u: &X25519Point) -> FieldElement25519 {
    FieldElement25519::decode_255(&u.0)
}

/// `encodeUCoordinate(u, 255)` as defined in Section 5 of RFC 7748.
/// The RFC's `u = u % p` step is [`FieldElement25519::normalize`]: an X25519 output must be the
/// canonical encoding of its residue class, even though non-canonical values MUST be accepted on
/// the way in (see [`decode_u_coordinate`]). Bit 255 of the final byte is written as zero, since
/// it is unused by X25519.
///
/// Input: A u-coordinate, in any state of reduction; a 32-byte output buffer.
/// Output: The canonical 32-byte little-endian encoding of that value, written to `r`.
fn encode_u_coordinate(u: &FieldElement25519, r: &mut [u8; POINT_SIZE]) {
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
pub fn generate_public_key(k: &X25519Scalar) -> X25519Point {
    let mut u = [0_u8; POINT_SIZE];
    scalar_mult_base(k, &mut u);
    X25519Point(u)
}

/// Doubles one point, held projectively as the pair `(x : z)` representing `u = x / z`
/// Updated in place.
///
/// Keeping u as a fraction is what lets the ladder avoid a field inversion on every step: only
/// multiplications and squarings are needed here, and [`scalar_mult`] divides `x` by `z` once, at
/// the end.
///
/// This is the doubling half of the Montgomery ladder step in Section 5 of RFC7748, used by
/// [`scalar_mult`] for the last three iterations. With `AA = (x + z)^2`, `BB = (x - z)^2` and
/// `E = AA - BB`, it writes `x = AA * BB` and `z = E * (BB + C_A24 * E)`; see [`C_A24`] for the
/// pairing with `BB`.
///
/// X25519 only: it works on curve25519's Montgomery form and depends on its coefficient A.
/// Ed25519 doubles points on the twisted Edwards curve in extended coordinates (Section 5.1.4 of
/// RFC8032), which is a separate function.
fn ladder_double(x: &mut FieldElement25519, z: &mut FieldElement25519) {
    let (mut a, mut b) = x.sum_and_difference(z);
    a = a.sqr();
    b = b.sqr();
    *x = a.mul(&b);

    a = a.sub(&b);
    let t = a.mul_u32(C_A24).add(&b);
    *z = t.mul(&a);
}

/// `X25519(k, u)` as defined in Section 5 of RFC7748: the Montgomery ladder, computing scalar
/// multiplication on curve25519 from a u-coordinate alone.
///
/// The ladder is constant time with respect to `k`: the iteration count is fixed and the only
/// scalar-dependent step is [`FieldElement25519::cswap`].
///
/// # Modifications from the RFC
/// Modified to fold the RFC's first ladder iteration into the initial state, to replace its last
/// three iterations with [`ladder_double`] calls, and to cycle the RFC's named intermediates
/// through a fixed set of registers rather than materialise them.
///
/// # Inputs
///  * `k`, a 32-byte scalar
///  * `u`, a 32-byte little-endian u-coordinate
///  * `out`, a 32-byte output buffer.
/// Output: The canonical little-endian encoding of the u-coordinate of `k * u`, written to `out`.
fn scalar_mult(k: &X25519Scalar, u: &X25519Point, out: &mut [u8; POINT_SIZE]) {
    // The decoded scalar is as secret as `k` itself.
    let mut n: Secret<[u32; 8]> = Secret::new();
    decode_scalar_25519(k, &mut n);

    // Pre-condition:
    // The ladder below is only correct for scalars of the form 2^254 + 8m, 0 <= m <= 2^251 - 1
    // which should be enforced by a correct implementation of decode_scalar_25519.
    debug_assert_eq!(1, n[7] >> 30);
    debug_assert_eq!(0, n[0] & 7);

    let x1 = decode_u_coordinate(u);
    let mut x2 = x1.clone();
    let mut z2 = FieldElement25519::one();
    let mut x3 = FieldElement25519::one();
    let mut z3 = FieldElement25519::zero();

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
    //     ladder_double calls after the loop, and the RFC's post-loop cswap is dropped for the same
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
        z3 = z3.sqr();
        // BB = B^2,                    -> x2
        x2 = x2.sqr();

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
        x3 = x3.sqr();
        // (completes z_3)
        z3 = z3.sqr().mul(&x1);

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
        FieldElement25519::cswap(swap, &mut x2, &mut x3);
        // (z_2, z_3) = cswap(swap, z_2, z_3)
        //   > swaps in-place
        FieldElement25519::cswap(swap, &mut z2, &mut z3);
        // swap = k_t
        swap = k_bit;
    }

    debug_assert!(!swap.to_bool());

    for _ in 0..3 {
        ladder_double(&mut x2, &mut z2);
    }

    x2 = x2.mul(&z2.inv());
    encode_u_coordinate(&x2, out);
}

fn scalar_mult_base(k: &X25519Scalar, r: &mut [u8; POINT_SIZE]) {
    // Equivalent (but much slower) -- since the BASE_POINT never changes, you can
    //         precompute lookup tables for the multiples of BASE_POINT. TODO
    scalar_mult(k, &BASE_POINT, r);
}
