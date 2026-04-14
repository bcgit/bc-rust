

use bouncycastle_core_interface::traits::{Hash, Signature, SignaturePrivateKey, SignaturePublicKey};
use bouncycastle_sha2::SHA512;
use bouncycastle_utils::ct::Condition;
use math::{bits, nat, wnaf};
use bouncycastle_rng::RngCore;
use bouncycastle_core_interface::errors::SignatureError;

use std::sync::LazyLock; // todo -- no std!

use crate::eddsa_keys::{Ed25519PrivateKey, Ed25519PublicKey};
use crate::curve25519::CoordField;



/* Ed25519 params */

#[allow(non_upper_case_globals)]
/// Length of the \[u8] holding a Ed25519 public key.
pub const Ed25519_PK_LEN: usize = 1312;
#[allow(non_upper_case_globals)]
/// Length of the \[u8] holding a Ed25519 private key.
pub const Ed25519_SK_LEN: usize = 2560;
#[allow(non_upper_case_globals)]
/// Length of the \[u8] holding a Ed25519 signature value.
pub const Ed25519_SIG_LEN: usize = 2420;



pub struct Ed255519 {

}

impl<PK: SignaturePublicKey, SK: SignaturePrivateKey> Signature<PK, SK, Ed25519_PK_LEN, Ed25519_SK_LEN, Ed25519_SIG_LEN> for Ed255519 {

}

// todo -- figure out which things are part of private keys and should impl Zeroize

mod codec {
    pub fn decode16(bs: &[u8]) -> u32 {
        let mut n = bs[0] as u32;
        n |= (bs[1] as u32) << 8;
        n
    }

    pub fn decode24(bs: &[u8]) -> u32 {
        let mut n = bs[0] as u32;
        n |= (bs[1] as u32) << 8;
        n |= (bs[2] as u32) << 16;
        n
    }

    pub fn decode32(bs: &[u8]) -> u32 {
        let mut n = bs[0] as u32;
        n |= (bs[1] as u32) << 8;
        n |= (bs[2] as u32) << 16;
        n |= (bs[3] as u32) << 24;
        n
    }

    pub fn decode64(bs: &[u8]) -> u64 {
        let mut n = bs[0] as u64;
        n |= (bs[1] as u64) << 8;
        n |= (bs[2] as u64) << 16;
        n |= (bs[3] as u64) << 24;
        n |= (bs[4] as u64) << 32;
        n |= (bs[5] as u64) << 40;
        n |= (bs[6] as u64) << 48;
        n |= (bs[7] as u64) << 56;
        n
    }

    pub fn decode32_slice(bs: &[u8], n: &mut [u32]) {
        for i in 0..n.len() {
            n[i] = decode32(&bs[(i * 4)..]);
        }
    }

    pub fn decode64_slice(bs: &[u8], n: &mut [u64]) {
        for i in 0..n.len() {
            n[i] = decode64(&bs[(i * 8)..]);
        }
    }

    pub fn encode24(n: u32, bs: &mut [u8]) {
        bs[0] = n as u8;
        bs[1] = (n >> 8) as u8;
        bs[2] = (n >> 16) as u8;
    }

    pub fn encode32(n: u32, bs: &mut [u8]) {
        bs[0] = n as u8;
        bs[1] = (n >> 8) as u8;
        bs[2] = (n >> 16) as u8;
        bs[3] = (n >> 24) as u8;
    }

    pub fn encode64(n: u64, bs: &mut [u8]) {
        bs[0] = n as u8;
        bs[1] = (n >> 8) as u8;
        bs[2] = (n >> 16) as u8;
        bs[3] = (n >> 24) as u8;
        bs[4] = (n >> 32) as u8;
        bs[5] = (n >> 40) as u8;
        bs[6] = (n >> 48) as u8;
        bs[7] = (n >> 56) as u8;
    }

    pub fn encode32_slice(n: &[u32], bs: &mut [u8]) {
        for i in 0..n.len() {
            encode32(n[i], &mut bs[(i * 4)..]);
        }
    }

    pub fn encode56(n: u64, bs: &mut [u8]) {
        encode32(n as u32, bs);
        encode24((n >> 32) as u32, &mut bs[4..]);
    }

    pub fn encode64_slice(n: &[u64], bs: &mut [u8]) {
        for i in 0..n.len() {
            encode64(n[i], &mut bs[(i * 8)..]);
        }
    }
}

mod scalar_25519 {
    use super::{codec, scalar_util};
    use bouncycastle_utils::ct::Condition;
    use math::{nat, wnaf};

    const M28: i64 = (1 << 28) - 1;
    const SIZE: usize = 4;
    const TARGET_LENGTH: usize = 254;

    const L: [u64; SIZE] =
        [0x5812631A5CF5D3ED, 0x14DEF9DEA2F79CD6, 0x0000000000000000, 0x1000000000000000];
    const L_SQ: [u64; SIZE * 2] = [
        0xE2EDF685AB128969, 0x680392762298A31D, 0x3DCEEC73D217F5BE, 0xA1B399411B7C309A,
        0xCB024C634B9EBA7D, 0x029BDF3BD45EF39A, 0x0000000000000000, 0x0100000000000000,
    ];

    const L0: i32 = -0x030A2C13; // L0:26/--
    const L1: i32 = 0x012631A6; // L1:24/22
    const L2: i32 = 0x079CD658; // L2:27/--
    const L3: i32 = -0x006215D1; // L3:23/--
    const L4: i32 = 0x000014DF; // L4:12/11

    pub fn check_var(s: &[u8; 32], n: &mut [u64; SIZE]) -> bool {
        decode(s, n);
        nat::lt_var(SIZE, n, &L)
    }

    pub fn decode(k: &[u8; 32], n: &mut [u64; SIZE]) {
        codec::decode64_slice(k, n);
    }

    pub fn get_order_wnaf_var(width: usize, ws: &mut [i8; 253]) {
        wnaf::get_signed_var(&L, width, ws);
    }

    pub fn multiply_128_var(x: &[u64; SIZE], y128: &[u64; 2]) -> [u64; SIZE] {
        let mut tt = [0_u64; 6];
        nat::mul_slices(x, y128, &mut tt);

        if (y128[1] as i64) < 0 {
            nat::add_to(SIZE, &L, &mut tt[2..], 0);
            nat::sub_from(SIZE, x, &mut tt[2..], 0);
        }

        // TODO Optimize if the platform is little-endian (see bc-csharp version)

        let mut n = [0; 48];
        codec::encode64_slice(&tt, &mut n);

        reduce_384(&n)
    }

    #[rustfmt::skip]
    pub fn reduce_384(n: &[u8]) -> [u64; 4] {
        let mut x00 =  codec::decode32(&n[0 ..])       as i64;  // x00:32/--
        let mut x01 = (codec::decode24(&n[4 ..]) << 4) as i64;  // x01:28/--
        let mut x02 =  codec::decode32(&n[7 ..])       as i64;  // x02:32/--
        let mut x03 = (codec::decode24(&n[11..]) << 4) as i64;  // x03:28/--
        let mut x04 =  codec::decode32(&n[14..])       as i64;  // x04:32/--
        let mut x05 = (codec::decode24(&n[18..]) << 4) as i64;  // x05:28/--
        let mut x06 =  codec::decode32(&n[21..])       as i64;  // x06:32/--
        let mut x07 = (codec::decode24(&n[25..]) << 4) as i64;  // x07:28/--
        let mut x08 =  codec::decode32(&n[28..])       as i64;  // x08:32/--
        let mut x09 = (codec::decode24(&n[32..]) << 4) as i64;  // x09:28/--
        let mut x10 =  codec::decode32(&n[35..])       as i64;  // x10:32/--
        let mut x11 = (codec::decode24(&n[39..]) << 4) as i64;  // x11:28/--
        let mut x12 =  codec::decode32(&n[42..])       as i64;  // x12:32/--
        let mut x13 = (codec::decode16(&n[46..]) << 4) as i64;  // x13:20/--

        // TODO Fix bounds calculations which were copied from reduce_512

        x13 += x12 >> 28; x12 &= M28;                           // x13:28/22, x12:28/--
        x04 -= x13 * L0 as i64;                                 // x04:54/49
        x05 -= x13 * L1 as i64;                                 // x05:54/53
        x06 -= x13 * L2 as i64;                                 // x06:56/--
        x07 -= x13 * L3 as i64;                                 // x07:56/52
        x08 -= x13 * L4 as i64;                                 // x08:56/52

        x12 += x11 >> 28; x11 &= M28;                           // x12:28/24, x11:28/--
        x03 -= x12 * L0 as i64;                                 // x03:54/49
        x04 -= x12 * L1 as i64;                                 // x04:54/51
        x05 -= x12 * L2 as i64;                                 // x05:56/--
        x06 -= x12 * L3 as i64;                                 // x06:56/52
        x07 -= x12 * L4 as i64;                                 // x07:56/53

        x11 += x10 >> 28; x10 &= M28;                           // x11:29/--, x10:28/--
        x02 -= x11 * L0 as i64;                                 // x02:55/32
        x03 -= x11 * L1 as i64;                                 // x03:55/--
        x04 -= x11 * L2 as i64;                                 // x04:56/55
        x05 -= x11 * L3 as i64;                                 // x05:56/52
        x06 -= x11 * L4 as i64;                                 // x06:56/53

        x10 += x09 >> 28; x09 &= M28;                           // x10:29/--, x09:28/--
        x01 -= x10 * L0 as i64;                                 // x01:55/28
        x02 -= x10 * L1 as i64;                                 // x02:55/54
        x03 -= x10 * L2 as i64;                                 // x03:56/55
        x04 -= x10 * L3 as i64;                                 // x04:57/--
        x05 -= x10 * L4 as i64;                                 // x05:56/53

        x08 += x07 >> 28; x07 &= M28;                           // x08:56/53, x07:28/--
        x09 += x08 >> 28; x08 &= M28;                           // x09:29/25, x08:28/--

        let t = x08 >> 27 & 1_i64;
        x09 += t;                                               // x09:29/26

        x00 -= x09 * L0 as i64;                                 // x00:55/53
        x01 -= x09 * L1 as i64;                                 // x01:55/54
        x02 -= x09 * L2 as i64;                                 // x02:57/--
        x03 -= x09 * L3 as i64;                                 // x03:57/--
        x04 -= x09 * L4 as i64;                                 // x04:57/42

        x01 += x00 >> 28; x00 &= M28;
        x02 += x01 >> 28; x01 &= M28;
        x03 += x02 >> 28; x02 &= M28;
        x04 += x03 >> 28; x03 &= M28;
        x05 += x04 >> 28; x04 &= M28;
        x06 += x05 >> 28; x05 &= M28;
        x07 += x06 >> 28; x06 &= M28;
        x08 += x07 >> 28; x07 &= M28;
        x09  = x08 >> 28; x08 &= M28;

        x09 -= t;
        debug_assert!(x09 == 0 || x09 == -1);

        x00 += x09 & L0 as i64;
        x01 += x09 & L1 as i64;
        x02 += x09 & L2 as i64;
        x03 += x09 & L3 as i64;
        x04 += x09 & L4 as i64;

        x01 += x00 >> 28; x00 &= M28;
        x02 += x01 >> 28; x01 &= M28;
        x03 += x02 >> 28; x02 &= M28;
        x04 += x03 >> 28; x03 &= M28;
        x05 += x04 >> 28; x04 &= M28;
        x06 += x05 >> 28; x05 &= M28;
        x07 += x06 >> 28; x06 &= M28;
        x08 += x07 >> 28; x07 &= M28;

        [
            (x00       | x01 << 28 | x02 << 56) as u64,
            (x02 >>  8 | x03 << 20 | x04 << 48) as u64,
            (x04 >> 16 | x05 << 12 | x06 << 40) as u64,
            (x06 >> 24 | x07 <<  4 | x08 << 32) as u64,
        ]
    }

    pub fn reduce_512(n: &[u8]) -> [u8; 32] {
        let mut r = [0; 32];
        reduce_512_to(n, &mut r);
        r
    }

    #[rustfmt::skip]
    pub fn reduce_512_to(n: &[u8], r: &mut [u8; 32]) {
        let mut x00 =  codec::decode32(&n[0 ..])       as i64;  // x00:32/--
        let mut x01 = (codec::decode24(&n[4 ..]) << 4) as i64;  // x01:28/--
        let mut x02 =  codec::decode32(&n[7 ..])       as i64;  // x02:32/--
        let mut x03 = (codec::decode24(&n[11..]) << 4) as i64;  // x03:28/--
        let mut x04 =  codec::decode32(&n[14..])       as i64;  // x04:32/--
        let mut x05 = (codec::decode24(&n[18..]) << 4) as i64;  // x05:28/--
        let mut x06 =  codec::decode32(&n[21..])       as i64;  // x06:32/--
        let mut x07 = (codec::decode24(&n[25..]) << 4) as i64;  // x07:28/--
        let mut x08 =  codec::decode32(&n[28..])       as i64;  // x08:32/--
        let mut x09 = (codec::decode24(&n[32..]) << 4) as i64;  // x09:28/--
        let mut x10 =  codec::decode32(&n[35..])       as i64;  // x10:32/--
        let mut x11 = (codec::decode24(&n[39..]) << 4) as i64;  // x11:28/--
        let mut x12 =  codec::decode32(&n[42..])       as i64;  // x12:32/--
        let mut x13 = (codec::decode24(&n[46..]) << 4) as i64;  // x13:28/--
        let mut x14 =  codec::decode32(&n[49..])       as i64;  // x14:32/--
        let mut x15 = (codec::decode24(&n[53..]) << 4) as i64;  // x15:28/--
        let mut x16 =  codec::decode32(&n[56..])       as i64;  // x16:32/--
        let mut x17 = (codec::decode24(&n[60..]) << 4) as i64;  // x17:28/--
        let     x18 =                   n[63]          as i64;  // x18:08/--

        // x18 += x17 >> 28; x17 &= M28;
        x09 -= x18 * L0 as i64;                                 // x09:34/28
        x10 -= x18 * L1 as i64;                                 // x10:33/30
        x11 -= x18 * L2 as i64;                                 // x11:35/28
        x12 -= x18 * L3 as i64;                                 // x12:32/31
        x13 -= x18 * L4 as i64;                                 // x13:28/21

        x17 += x16 >> 28; x16 &= M28;                           // x17:28/--, x16:28/--
        x08 -= x17 * L0 as i64;                                 // x08:54/32
        x09 -= x17 * L1 as i64;                                 // x09:52/51
        x10 -= x17 * L2 as i64;                                 // x10:55/34
        x11 -= x17 * L3 as i64;                                 // x11:51/36
        x12 -= x17 * L4 as i64;                                 // x12:41/--

        // x16 += x15 >> 28; x15 &= M28;
        x07 -= x16 * L0 as i64;                                 // x07:54/28
        x08 -= x16 * L1 as i64;                                 // x08:54/53
        x09 -= x16 * L2 as i64;                                 // x09:55/53
        x10 -= x16 * L3 as i64;                                 // x10:55/52
        x11 -= x16 * L4 as i64;                                 // x11:51/41

        x15 += x14 >> 28; x14 &= M28;                           // x15:28/--, x14:28/--
        x06 -= x15 * L0 as i64;                                 // x06:54/32
        x07 -= x15 * L1 as i64;                                 // x07:54/53
        x08 -= x15 * L2 as i64;                                 // x08:56/--
        x09 -= x15 * L3 as i64;                                 // x09:55/54
        x10 -= x15 * L4 as i64;                                 // x10:55/53

        // x14 += x13 >> 28; x13 &= M28;
        x05 -= x14 * L0 as i64;                                 // x05:54/28
        x06 -= x14 * L1 as i64;                                 // x06:54/53
        x07 -= x14 * L2 as i64;                                 // x07:56/--
        x08 -= x14 * L3 as i64;                                 // x08:56/51
        x09 -= x14 * L4 as i64;                                 // x09:56/--

        x13 += x12 >> 28; x12 &= M28;                           // x13:28/22, x12:28/--
        x04 -= x13 * L0 as i64;                                 // x04:54/49
        x05 -= x13 * L1 as i64;                                 // x05:54/53
        x06 -= x13 * L2 as i64;                                 // x06:56/--
        x07 -= x13 * L3 as i64;                                 // x07:56/52
        x08 -= x13 * L4 as i64;                                 // x08:56/52

        x12 += x11 >> 28; x11 &= M28;                           // x12:28/24, x11:28/--
        x03 -= x12 * L0 as i64;                                 // x03:54/49
        x04 -= x12 * L1 as i64;                                 // x04:54/51
        x05 -= x12 * L2 as i64;                                 // x05:56/--
        x06 -= x12 * L3 as i64;                                 // x06:56/52
        x07 -= x12 * L4 as i64;                                 // x07:56/53

        x11 += x10 >> 28; x10 &= M28;                           // x11:29/--, x10:28/--
        x02 -= x11 * L0 as i64;                                 // x02:55/32
        x03 -= x11 * L1 as i64;                                 // x03:55/--
        x04 -= x11 * L2 as i64;                                 // x04:56/55
        x05 -= x11 * L3 as i64;                                 // x05:56/52
        x06 -= x11 * L4 as i64;                                 // x06:56/53

        x10 += x09 >> 28; x09 &= M28;                           // x10:29/--, x09:28/--
        x01 -= x10 * L0 as i64;                                 // x01:55/28
        x02 -= x10 * L1 as i64;                                 // x02:55/54
        x03 -= x10 * L2 as i64;                                 // x03:56/55
        x04 -= x10 * L3 as i64;                                 // x04:57/--
        x05 -= x10 * L4 as i64;                                 // x05:56/53

        x08 += x07 >> 28; x07 &= M28;                           // x08:56/53, x07:28/--
        x09 += x08 >> 28; x08 &= M28;                           // x09:29/25, x08:28/--

        let t = (x08 >> 27) & 1;
        x09 += t;                                               // x09:29/26

        x00 -= x09 * L0 as i64;                                 // x00:55/53
        x01 -= x09 * L1 as i64;                                 // x01:55/54
        x02 -= x09 * L2 as i64;                                 // x02:57/--
        x03 -= x09 * L3 as i64;                                 // x03:57/--
        x04 -= x09 * L4 as i64;                                 // x04:57/42

        x01 += x00 >> 28; x00 &= M28;
        x02 += x01 >> 28; x01 &= M28;
        x03 += x02 >> 28; x02 &= M28;
        x04 += x03 >> 28; x03 &= M28;
        x05 += x04 >> 28; x04 &= M28;
        x06 += x05 >> 28; x05 &= M28;
        x07 += x06 >> 28; x06 &= M28;
        x08 += x07 >> 28; x07 &= M28;
        x09  = x08 >> 28; x08 &= M28;

        x09 -= t;

        debug_assert!(x09 == 0 || x09 == -1);

        x00 += x09 & L0 as i64;
        x01 += x09 & L1 as i64;
        x02 += x09 & L2 as i64;
        x03 += x09 & L3 as i64;
        x04 += x09 & L4 as i64;

        x01 += x00 >> 28; x00 &= M28;
        x02 += x01 >> 28; x01 &= M28;
        x03 += x02 >> 28; x02 &= M28;
        x04 += x03 >> 28; x03 &= M28;
        x05 += x04 >> 28; x04 &= M28;
        x06 += x05 >> 28; x05 &= M28;
        x07 += x06 >> 28; x06 &= M28;
        x08 += x07 >> 28; x07 &= M28;

        codec::encode56((x00 | (x01 << 28)) as u64, r);
        codec::encode56((x02 | (x03 << 28)) as u64, &mut r[7..]);
        codec::encode56((x04 | (x05 << 28)) as u64, &mut r[14..]);
        codec::encode56((x06 | (x07 << 28)) as u64, &mut r[21..]);
        codec::encode32(x08 as u32, &mut r[28..]);
    }

    pub fn reduce_basis_var(k: &[u64; 4]) -> Option<([u64; 2], [u64; 2])> {
        /*
         * Split scalar k into two half-size scalars z0 and z1, such that z1 * k == z0 mod L.
         *
         * See https://ia.cr/2020/454 (Pornin).
         */

        let mut nu = &mut L_SQ.clone();

        let mut nv = &mut [0; SIZE * 2];
        nat::square(SIZE, k, nv);
        // NOTE: squares are either 0, 1 or 4 (mod 8), so can add 1 without carry
        debug_assert!(nv[0] & 7 < 7);
        nv[0] += 1;

        let mut p = [0; SIZE * 2];
        nat::mul(SIZE, &L, k, &mut p);

        let mut t = [0; SIZE * 2];

        let mut u0 = &mut [L[0], L[1]];
        let mut u1 = &mut [0, 0];
        let mut v0 = &mut [k[0], k[1]];
        let mut v1 = &mut [1, 0];

        // Conservative upper bound on the number of loop iterations needed
        let mut iterations = TARGET_LENGTH * 4;
        let mut last = SIZE * 2 - 1;
        let mut len_nv = scalar_util::get_bitlength_positive(last, nv);

        while len_nv > TARGET_LENGTH {
            if iterations == 0 {
                return None;
            }
            iterations -= 1;

            let len_p = scalar_util::get_bitlength(last, &p);
            let s = len_p.saturating_sub(len_nv);

            if (p[last] as i64) < 0 {
                scalar_util::add_shifted_np(last, s, nu, nv, &mut p, &mut t);
                scalar_util::add_shifted_uv(1, s, u0, u1, v0, v1);
            } else {
                scalar_util::sub_shifted_np(last, s, nu, nv, &mut p, &mut t);
                scalar_util::sub_shifted_uv(1, s, u0, u1, v0, v1);
            }

            if scalar_util::less_than(last, nu, nv) {
                core::mem::swap(&mut u0, &mut v0);
                core::mem::swap(&mut u1, &mut v1);
                core::mem::swap(&mut nu, &mut nv);

                last = len_nv >> 6;
                len_nv = scalar_util::get_bitlength_positive(last, nv);
            }
        }

        // v1 * k == v0 mod L
        Some((*v0, *v1))
    }

    pub fn to_signed_digits(bits: usize, z: &mut [u64; SIZE]) {
        debug_assert_eq!(256, bits);

        let cond = !Condition::<u64>::is_bit_set(z[0], 0);
        let c1 = nat::cadd_to(SIZE, cond, &L, z);
        debug_assert_eq!(0, c1);

        let c2 = nat::shift_down_bit(SIZE, z, 1_u64);
        debug_assert_eq!(1 << 63, c2);
    }
}

mod scalar_util {
    pub fn add_shifted_np(
        last: usize,
        s: usize,
        nu: &mut [u64],
        nv: &[u64],
        p: &mut [u64],
        t: &mut [u64],
    ) {
        let mut cc_p = 0_u128;
        let mut cc_nu = 0_u128;

        if s == 0 {
            for i in 0..=last {
                let mut p_i = p[i];

                cc_nu += nu[i] as u128;
                cc_nu += p_i as u128;

                cc_p += p_i as u128;
                cc_p += nv[i] as u128;
                p_i = cc_p as u64;
                cc_p >>= 64;
                p[i] = p_i;

                cc_nu += p_i as u128;
                nu[i] = cc_nu as u64;
                cc_nu >>= 64;
            }
        } else if s < 64 {
            let mut prev_p = 0_u64;
            let mut prev_q = 0_u64;
            let mut prev_v = 0_u64;

            for i in 0..=last {
                let mut p_i = p[i];
                let p_s = p_i << s | prev_p >> (64 - s);
                prev_p = p_i;

                cc_nu += nu[i] as u128;
                cc_nu += p_s as u128;

                let next_v = nv[i];
                let v_s = next_v << s | prev_v >> (64 - s);
                prev_v = next_v;

                cc_p += p_i as u128;
                cc_p += v_s as u128;
                p_i = cc_p as u64;
                cc_p >>= 64;
                p[i] = p_i;

                let q_s = p_i << s | prev_q >> (64 - s);
                prev_q = p_i;

                cc_nu += q_s as u128;
                nu[i] = cc_nu as u64;
                cc_nu >>= 64;
            }
        } else {
            // Copy the low limbs of the original p
            t[..last].copy_from_slice(&p[..last]);

            let s_words = s >> 6;
            let s_bits = s & 63;

            if s_bits == 0 {
                for i in s_words..=last {
                    cc_nu += nu[i] as u128;
                    cc_nu += t[i - s_words] as u128;

                    cc_p += p[i] as u128;
                    cc_p += nv[i - s_words] as u128;
                    p[i] = cc_p as u64;
                    cc_p >>= 64;

                    cc_nu += p[i - s_words] as u128;
                    nu[i] = cc_nu as u64;
                    cc_nu >>= 64;
                }
            } else {
                let mut prev_t = 0_u64;
                let mut prev_q = 0_u64;
                let mut prev_v = 0_u64;

                for i in s_words..=last {
                    let next_t = t[i - s_words];
                    let t_s = next_t << s_bits | prev_t >> (64 - s_bits);
                    prev_t = next_t;

                    cc_nu += nu[i] as u128;
                    cc_nu += t_s as u128;

                    let next_v = nv[i - s_words];
                    let v_s = next_v << s_bits | prev_v >> (64 - s_bits);
                    prev_v = next_v;

                    cc_p += p[i] as u128;
                    cc_p += v_s as u128;
                    p[i] = cc_p as u64;
                    cc_p >>= 64;

                    let next_q = p[i - s_words];
                    let q_s = next_q << s_bits | prev_q >> (64 - s_bits);
                    prev_q = next_q;

                    cc_nu += q_s as u128;
                    nu[i] = cc_nu as u64;
                    cc_nu >>= 64;
                }
            }
        }
    }

    pub fn add_shifted_uv(
        last: usize,
        s: usize,
        u0: &mut [u64],
        u1: &mut [u64],
        v0: &[u64],
        v1: &[u64],
    ) {
        let s_words = s >> 6;
        let s_bits = s & 63;

        let mut cc_u0 = 0_u128;
        let mut cc_u1 = 0_u128;

        if s_bits == 0 {
            for i in s_words..=last {
                cc_u0 += u0[i] as u128;
                cc_u1 += u1[i] as u128;
                cc_u0 += v0[i - s_words] as u128;
                cc_u1 += v1[i - s_words] as u128;
                u0[i] = cc_u0 as u64;
                cc_u0 >>= 64;
                u1[i] = cc_u1 as u64;
                cc_u1 >>= 64;
            }
        } else {
            let mut prev_v0 = 0_u64;
            let mut prev_v1 = 0_u64;

            for i in s_words..=last {
                let next_v0 = v0[i - s_words];
                let next_v1 = v1[i - s_words];
                let v0_s = next_v0 << s_bits | prev_v0 >> (64 - s_bits);
                let v1_s = next_v1 << s_bits | prev_v1 >> (64 - s_bits);
                prev_v0 = next_v0;
                prev_v1 = next_v1;

                cc_u0 += u0[i] as u128;
                cc_u1 += u1[i] as u128;
                cc_u0 += v0_s as u128;
                cc_u1 += v1_s as u128;
                u0[i] = cc_u0 as u64;
                cc_u0 >>= 64;
                u1[i] = cc_u1 as u64;
                cc_u1 >>= 64;
            }
        }
    }

    pub fn get_bitlength(last: usize, x: &[u64]) -> usize {
        let mut i = last;
        let sign = ((x[i] as i64) >> 63) as u64;
        while i > 0 && x[i] == sign {
            i -= 1;
        }

        i * 64 + 64 - (x[i] ^ sign).leading_zeros() as usize
    }

    pub fn get_bitlength_positive(last: usize, x: &[u64]) -> usize {
        let mut i = last;
        while i > 0 && x[i] == 0 {
            i -= 1;
        }

        i * 64 + 64 - x[i].leading_zeros() as usize
    }

    pub fn less_than(last: usize, x: &[u64], y: &[u64]) -> bool {
        let mut i = last;
        loop {
            if x[i] < y[i] {
                return true;
            }
            if x[i] > y[i] {
                return false;
            }
            if i == 0 {
                return false;
            }
            i -= 1;
        }
    }

    pub fn sub_shifted_np(
        last: usize,
        s: usize,
        nu: &mut [u64],
        nv: &[u64],
        p: &mut [u64],
        t: &mut [u64],
    ) {
        let mut cc_p = 0_i128;
        let mut cc_nu = 0_i128;

        if s == 0 {
            for i in 0..=last {
                let mut p_i = p[i];

                cc_nu += nu[i] as i128;
                cc_nu -= p_i as i128;

                cc_p += p_i as i128;
                cc_p -= nv[i] as i128;
                p_i = cc_p as u64;
                cc_p >>= 64;
                p[i] = p_i;

                cc_nu -= p_i as i128;
                nu[i] = cc_nu as u64;
                cc_nu >>= 64;
            }
        } else if s < 64 {
            let mut prev_p = 0_u64;
            let mut prev_q = 0_u64;
            let mut prev_v = 0_u64;

            for i in 0..=last {
                let mut p_i = p[i];
                let p_s = p_i << s | prev_p >> (64 - s);
                prev_p = p_i;

                cc_nu += nu[i] as i128;
                cc_nu -= p_s as i128;

                let next_v = nv[i];
                let v_s = next_v << s | prev_v >> (64 - s);
                prev_v = next_v;

                cc_p += p_i as i128;
                cc_p -= v_s as i128;
                p_i = cc_p as u64;
                cc_p >>= 64;
                p[i] = p_i;

                let q_s = p_i << s | prev_q >> (64 - s);
                prev_q = p_i;

                cc_nu -= q_s as i128;
                nu[i] = cc_nu as u64;
                cc_nu >>= 64;
            }
        } else {
            // Copy the low limbs of the original p
            t[..last].copy_from_slice(&p[..last]);

            let s_words = s >> 6;
            let s_bits = s & 63;

            if s_bits == 0 {
                for i in s_words..=last {
                    cc_nu += nu[i] as i128;
                    cc_nu -= t[i - s_words] as i128;

                    cc_p += p[i] as i128;
                    cc_p -= nv[i - s_words] as i128;
                    p[i] = cc_p as u64;
                    cc_p >>= 64;

                    cc_nu -= p[i - s_words] as i128;
                    nu[i] = cc_nu as u64;
                    cc_nu >>= 64;
                }
            } else {
                let mut prev_t = 0_u64;
                let mut prev_q = 0_u64;
                let mut prev_v = 0_u64;

                for i in s_words..=last {
                    let next_t = t[i - s_words];
                    let t_s = next_t << s_bits | prev_t >> (64 - s_bits);
                    prev_t = next_t;

                    cc_nu += nu[i] as i128;
                    cc_nu -= t_s as i128;

                    let next_v = nv[i - s_words];
                    let v_s = next_v << s_bits | prev_v >> (64 - s_bits);
                    prev_v = next_v;

                    cc_p += p[i] as i128;
                    cc_p -= v_s as i128;
                    p[i] = cc_p as u64;
                    cc_p >>= 64;

                    let next_q = p[i - s_words];
                    let q_s = next_q << s_bits | prev_q >> (64 - s_bits);
                    prev_q = next_q;

                    cc_nu -= q_s as i128;
                    nu[i] = cc_nu as u64;
                    cc_nu >>= 64;
                }
            }
        }
    }

    pub fn sub_shifted_uv(
        last: usize,
        s: usize,
        u0: &mut [u64],
        u1: &mut [u64],
        v0: &[u64],
        v1: &[u64],
    ) {
        let s_words = s >> 6;
        let s_bits = s & 63;

        let mut cc_u0 = 0_i128;
        let mut cc_u1 = 0_i128;

        if s_bits == 0 {
            for i in s_words..=last {
                cc_u0 += u0[i] as i128;
                cc_u1 += u1[i] as i128;
                cc_u0 -= v0[i - s_words] as i128;
                cc_u1 -= v1[i - s_words] as i128;
                u0[i] = cc_u0 as u64;
                cc_u0 >>= 64;
                u1[i] = cc_u1 as u64;
                cc_u1 >>= 64;
            }
        } else {
            let mut prev_v0 = 0_u64;
            let mut prev_v1 = 0_u64;

            for i in s_words..=last {
                let next_v0 = v0[i - s_words];
                let next_v1 = v1[i - s_words];
                let v0_s = next_v0 << s_bits | prev_v0 >> (64 - s_bits);
                let v1_s = next_v1 << s_bits | prev_v1 >> (64 - s_bits);
                prev_v0 = next_v0;
                prev_v1 = next_v1;

                cc_u0 += u0[i] as i128;
                cc_u1 += u1[i] as i128;
                cc_u0 -= v0_s as i128;
                cc_u1 -= v1_s as i128;
                u0[i] = cc_u0 as u64;
                cc_u0 >>= 64;
                u1[i] = cc_u1 as u64;
                cc_u1 >>= 64;
            }
        }
    }
}

// todo -- delete?
pub enum Algorithm {
    Ed25519,
    Ed25519ctx,
    Ed25519ph,
}

pub struct PublicPoint {
    x: CoordField,
    y: CoordField,
}

const COORD_UINTS_32: usize = 8;
const COORD_UINTS_64: usize = 4;
const POINT_BYTES: usize = COORD_UINTS_64 * 8;
const SCALAR_UINTS: usize = 4;
const SCALAR_BYTES: usize = SCALAR_UINTS * 8;

pub const CONTEXT_MAX_SIZE: usize = 256;
pub const PREHASH_SIZE: usize = 64;
pub const PUBLIC_KEY_SIZE: usize = POINT_BYTES;
pub const SECRET_KEY_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = POINT_BYTES + SCALAR_BYTES;

// "SigEd25519 no Ed25519 collisions"
const DOM2_PREFIX: [u8; 32] = [
    0x53, 0x69, 0x67, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x20, 0x6E, 0x6F, 0x20, 0x45, 0x64,
    0x32, 0x35, 0x35, 0x31, 0x39, 0x20, 0x63, 0x6F, 0x6C, 0x6C, 0x69, 0x73, 0x69, 0x6F, 0x6E, 0x73,
];

const ORDER8_Y1_32: [u32; 8] = [
    0x706A17C7, 0x4FD84D3D, 0x760B3CBA, 0x0F67100D, 0xFA53202A, 0xC6CC392C, 0x77FDC74E, 0x7A03AC92,
];
const ORDER8_Y1_64: [u64; 4] =
    [0x4FD84D3D706A17C7, 0x0F67100D760B3CBA, 0xC6CC392CFA53202A, 0x7A03AC9277FDC74E];

const ORDER8_Y2_32: [u32; 8] = [
    0x8F95E826, 0xB027B2C2, 0x89F4C345, 0xF098EFF2, 0x05ACDFD5, 0x3933C6D3, 0x880238B1, 0x05FC536D,
];
const ORDER8_Y2_64: [u64; 4] =
    [0xB027B2C28F95E826, 0xF098EFF289F4C345, 0x3933C6D305ACDFD5, 0x05FC536D880238B1];

const B_X: CoordField = CoordField::new(
    0x00062D608F25D51A, 0x000412A4B4F6592A, 0x00075B7171A4B31D, 0x0001FF60527118FE,
    0x000216936D3CD6E5,
);
const B_Y: CoordField = CoordField::new(
    0x0006666666666658, 0x0004CCCCCCCCCCCC, 0x0001999999999999, 0x0003333333333333,
    0x0006666666666666,
);

// 2^128 * B
const B128_X: CoordField = CoordField::new(
    0x000047AE60B7E824, 0x0001385CE47CBF90, 0x000538A682639A17, 0x0001964A969CC270,
    0x0004C27AFFF3C45F,
);
const B128_Y: CoordField = CoordField::new(
    0x0002BD114BF5A66B, 0x0003CA349893CB77, 0x00030A70EA4342F8, 0x00043ECAF88F5B13,
    0x0005F2C99E6526DC,
);

// Edwards curve (where d == -121665/121666 == 0x52036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978A3)
// -x^2 + y^2 == 1 + d * x^2 * y^2

const C_D: CoordField = CoordField::new(
    0x00034DCA135978A3, 0x0001A8283B156EBD, 0x0005E7A26001C029, 0x000739C663A03CBB,
    0x00052036CEE2B6FF,
);
const C_D2: CoordField = C_D.add(&C_D).normalize();
const C_D4: CoordField = C_D2.add(&C_D2).normalize();

// const WNAF_WIDTH: usize = 5;
const WNAF_WIDTH_128: usize = 4;
const WNAF_WIDTH_BASE: usize = 6;

// scalar_mult_base is hard-coded for these values of blocks, teeth, spacing so they can't be freely changed
const PRECOMP_BLOCKS: usize = 8;
const PRECOMP_TEETH: usize = 4;
const PRECOMP_SPACING: usize = 8;
const PRECOMP_RANGE: usize = PRECOMP_BLOCKS * PRECOMP_TEETH * PRECOMP_SPACING; // range == 256
const PRECOMP_POINTS: usize = 1 << (PRECOMP_TEETH - 1);
const PRECOMP_MASK: usize = PRECOMP_POINTS - 1;

const PRECOMP_COMB_POINTS: usize = PRECOMP_BLOCKS * PRECOMP_POINTS;
const PRECOMP_WNAF_POINTS: usize = 1 << (WNAF_WIDTH_BASE - 2);

#[derive(Clone, Default)]
struct PointAccum {
    x: CoordField,
    y: CoordField,
    z: CoordField,
    u: CoordField,
    v: CoordField,
}

impl PointAccum {
    fn neutral_element() -> Self {
        Self {
            x: CoordField::zero(),
            y: CoordField::one(),
            z: CoordField::one(),
            u: CoordField::zero(),
            v: CoordField::one(),
        }
    }
}

#[derive(Clone, Default)]
struct PointAffine {
    x: CoordField,
    y: CoordField,
}

// TODO Can we do without Copy here?
#[derive(Clone, Copy, Default)]
struct PointExtended {
    x: CoordField,
    y: CoordField,
    z: CoordField,
    t: CoordField,
}

// TODO Can we do without Copy here?
#[derive(Clone, Copy, Default)]
struct PointPrecomp {
    ymx_h: CoordField, // (y - x)/2
    ypx_h: CoordField, // (y + x)/2
    xyd: CoordField,   // x.y.d
}

// TODO Can we do without Copy here?
// TODO MikeO: why is copy a problem?
#[derive(Clone, Copy, Default)]
struct PointPrecompZ {
    ymx_h: CoordField, // (y - x)/2
    ypx_h: CoordField, // (y + x)/2
    xyd: CoordField,   // x.y.d
    z: CoordField,
}

struct Precomputation {
    comb_base: [CoordField; PRECOMP_COMB_POINTS * 3],
    wnaf_base: [PointPrecomp; PRECOMP_WNAF_POINTS],
    wnaf_base_128: [PointPrecomp; PRECOMP_WNAF_POINTS],
}

static PRECOMPUTATION: LazyLock<Box<Precomputation>> = LazyLock::new(|| {
    const TOTAL_POINTS: usize = PRECOMP_WNAF_POINTS * 2 + PRECOMP_COMB_POINTS;
    let mut points = vec![PointExtended::default(); TOTAL_POINTS];

    let base = PointAffine { x: B_X, y: B_Y };
    point_precompute(&base, &mut points[0..PRECOMP_WNAF_POINTS]);

    let base128 = PointAffine { x: B128_X, y: B128_Y };
    point_precompute(&base128, &mut points[PRECOMP_WNAF_POINTS..(PRECOMP_WNAF_POINTS * 2)]);

    let mut p = PointAccum { x: B_X, y: B_Y, z: CoordField::one(), u: B_X, v: B_Y };

    let mut points_index = PRECOMP_WNAF_POINTS * 2;
    let mut tooth_powers = [PointExtended::default(); PRECOMP_TEETH];

    let mut u = PointExtended::default();
    for block in 0..PRECOMP_BLOCKS {
        let sum = &mut points[points_index];
        points_index += 1;

        for (tooth, tooth_power) in tooth_powers.iter_mut().enumerate() {
            if tooth == 0 {
                point_copy_accum_extended(&p, sum);
            } else {
                point_copy_accum_extended(&p, &mut u);
                point_accumulate_extended(&u, sum);
            }

            point_double(&mut p);
            point_copy_accum_extended(&p, tooth_power);

            if block + tooth != PRECOMP_BLOCKS + PRECOMP_TEETH - 2 {
                for _ in 1..PRECOMP_SPACING {
                    point_double(&mut p);
                }
            }
        }

        sum.x.negate_mut();
        sum.t.negate_mut();

        for (tooth, tooth_power) in tooth_powers[0..(PRECOMP_TEETH - 1)].iter().enumerate() {
            let size = 1 << tooth;
            for _ in 0..size {
                let v = points[points_index - size];
                point_add_extended(&v, tooth_power, &mut points[points_index]);
                points_index += 1;
            }
        }
    }
    debug_assert_eq!(TOTAL_POINTS, points_index);

    // Set each z coordinate to 1/(2.z) to avoid calculating halves of x, y in the following code
    invert_double_zs(&mut points);

    let mut wnaf_base = [PointPrecomp::default(); PRECOMP_WNAF_POINTS];
    for i in 0..PRECOMP_WNAF_POINTS {
        let q = &mut points[i];
        let r = &mut wnaf_base[i];

        // Calculate x/2 and y/2 (because the z value holds half the inverse; see above).
        q.x = q.x.mul(&q.z);
        q.y = q.y.mul(&q.z);

        // y/2 +/- x/2
        (r.ypx_h, r.ymx_h) = q.y.apm(&q.x);

        // x/2 * y/2 * (4.d) == x.y.d
        r.xyd = q.x.mul(&q.y).mul(&C_D4);

        r.ymx_h.normalize_mut();
        r.ypx_h.normalize_mut();
        r.xyd.normalize_mut();
    }

    let mut wnaf_base_128 = [PointPrecomp::default(); PRECOMP_WNAF_POINTS];
    for i in 0..PRECOMP_WNAF_POINTS {
        let q = &mut points[PRECOMP_WNAF_POINTS + i];
        let r = &mut wnaf_base_128[i];

        // Calculate x/2 and y/2 (because the z value holds half the inverse; see above).
        q.x = q.x.mul(&q.z);
        q.y = q.y.mul(&q.z);

        // y/2 +/- x/2
        (r.ypx_h, r.ymx_h) = q.y.apm(&q.x);

        // x/2 * y/2 * (4.d) == x.y.d
        r.xyd = q.x.mul(&q.y).mul(&C_D4);

        r.ymx_h.normalize_mut();
        r.ypx_h.normalize_mut();
        r.xyd.normalize_mut();
    }

    let mut comb_base = [Default::default(); PRECOMP_COMB_POINTS * 3];
    let mut s = PointPrecomp::default();
    let mut off = 0;
    for q in points[(PRECOMP_WNAF_POINTS * 2)..].iter_mut() {
        // Calculate x/2 and y/2 (because the z value holds half the inverse; see above).
        q.x = q.x.mul(&q.z);
        q.y = q.y.mul(&q.z);

        // y/2 +/- x/2
        (s.ypx_h, s.ymx_h) = q.y.apm(&q.x);

        // x/2 * y/2 * (4.d) == x.y.d
        s.xyd = q.x.mul(&q.y).mul(&C_D4);

        comb_base[off] = s.ymx_h.normalize();
        off += 1;
        comb_base[off] = s.ypx_h.normalize();
        off += 1;
        comb_base[off] = s.xyd.normalize();
        off += 1;
    }
    debug_assert_eq!(comb_base.len(), off);

    Box::new(Precomputation { comb_base, wnaf_base, wnaf_base_128 })
});

#[allow(non_snake_case)]
fn calculate_S(
    r: &[u8; SCALAR_BYTES],
    k: &[u8; SCALAR_BYTES],
    s: &[u8; SCALAR_BYTES],
) -> [u8; SCALAR_BYTES] {
    let mut t = [0_u64; SCALAR_UINTS * 2];
    scalar_25519::decode(r, array_mut_ref![t, 0, SCALAR_UINTS]);

    let mut u = [0_u64; SCALAR_UINTS];
    scalar_25519::decode(k, &mut u);

    let mut v = [0_u64; SCALAR_UINTS];
    scalar_25519::decode(s, &mut v);

    nat::mul_add_to(SCALAR_UINTS, &u, &v, &mut t);

    let mut result = [0; SCALAR_BYTES * 2];
    codec::encode64_slice(&t, &mut result);
    scalar_25519::reduce_512(&result)
}

fn check_context_var(ctx: Option<&[u8]>, phflag: u8) -> bool {
    match ctx {
        None => phflag == 0_u8,
        Some(data) => data.len() < CONTEXT_MAX_SIZE,
    }
}

fn check_point_affine(p: &PointAffine) -> Condition<i64> {
    let (t, u) = (p.x.sqr(), p.y.sqr());
    let lhs = u.sub(&t);
    let rhs = t.mul(&u).mul(&C_D).add_one();
    lhs.sub(&rhs).normalize().is_zero() & !p.y.normalize().is_zero()
}

fn check_point_accum(p: &PointAccum) -> Condition<i64> {
    let (t, u, v) = (p.x.sqr(), p.y.sqr(), p.z.sqr());
    let lhs = u.sub(&t).mul(&v);
    let rhs = t.mul(&u).mul(&C_D).add(&v.sqr());
    lhs.sub(&rhs).normalize().is_zero() & !p.y.normalize().is_zero() & !p.z.normalize().is_zero()
}

fn check_point_full_var(p: &[u8; POINT_BYTES]) -> bool {
    let y7 = codec::decode32(&p[28..]) & 0x7FFFFFFF;

    let mut t0 = y7;
    let mut t1 = y7 ^ curve25519::P32[7];
    let mut t2 = y7 ^ ORDER8_Y1_32[7];
    let mut t3 = y7 ^ ORDER8_Y2_32[7];

    for i in (1..=COORD_UINTS_32 - 2).rev() {
        let yi = codec::decode32(&p[(i * 4)..]);

        t0 |= yi;
        t1 |= yi ^ curve25519::P32[i];
        t2 |= yi ^ ORDER8_Y1_32[i];
        t3 |= yi ^ ORDER8_Y2_32[i];
    }

    let y0 = codec::decode32(p);

    // Reject 0 and 1
    if t0 == 0 && y0 <= 1 {
        return false;
    }

    // Reject P - 1 and non-canonical encodings (i.e. >= P)
    if t1 == 0 && y0 >= (curve25519::P32[0] - 1) {
        return false;
    }

    t2 |= y0 ^ ORDER8_Y1_32[0];
    t3 |= y0 ^ ORDER8_Y2_32[0];

    // Reject order 8 points
    (t2 != 0) & (t3 != 0)
}

fn check_point_order_var(p: &PointAffine) -> bool {
    let r = scalar_mult_order_var(p);
    normalizes_to_neutral_element_var(&r)
}

fn check_point_var(p: &[u8; POINT_BYTES]) -> bool {
    if (codec::decode32(&p[28..]) & 0x7FFFFFFF) < curve25519::P32[7] {
        return true;
    }
    for i in (0..=COORD_UINTS_32 - 2).rev() {
        if codec::decode32(&p[(i * 4)..]) < curve25519::P32[i] {
            return true;
        }
    }
    false
}

fn create_digest() -> Sha512Digest {
    let d = Sha512Digest::new();
    debug_assert_eq!(64, d.result_len());
    d
}

pub fn create_prehash() -> Sha512Digest {
    create_digest()
}

fn decode_point_var(p: &[u8; POINT_BYTES], negate: bool, r: &mut PointAffine) -> bool {
    let x_0 = (p[POINT_BYTES - 1] & 0x80) >> 7;

    r.y = CoordField::decode_255(p);

    let mut u = r.y.sqr();
    let mut v = u.mul(&C_D);

    u.sub_one_mut();
    v.add_one_mut();

    match CoordField::sqrt_ratio_var(&u, &v) {
        None => {
            return false;
        }
        Some(sqrt) => {
            r.x = sqrt.normalize();
        }
    }

    if x_0 == 1 && r.x.is_zero_var() {
        return false;
    }

    if negate ^ (x_0 != r.x.parity()) {
        r.x = r.x.negate().normalize();
    }

    true
}

fn dom2(d: &mut Sha512Digest, phflag: u8, ctx: &[u8]) {
    const N: usize = DOM2_PREFIX.len();
    const ALLOC: usize = N + 2 + CONTEXT_MAX_SIZE;
    let mut buf = [0; ALLOC];
    let t = &mut buf[..N + 2 + ctx.len()];

    t[..N].copy_from_slice(&DOM2_PREFIX);
    t[N] = phflag;
    t[N + 1] = ctx.len() as u8;
    t[N + 2..].copy_from_slice(ctx);

    d.do_update(t);
}

fn encode_point(p: &PointAffine, r: &mut [u8; POINT_BYTES]) {
    CoordField::encode(&p.y, r);
    r[POINT_BYTES - 1] |= p.x.parity() << 7;
}

pub fn encode_public_point(public_point: &PublicPoint, pk: &mut [u8; PUBLIC_KEY_SIZE]) {
    public_point.y.encode(pk);
    pk[POINT_BYTES - 1] |= public_point.x.parity() << 7;
}

fn encode_result(p: &PointAccum, r: &mut [u8; POINT_BYTES]) -> Condition<i64> {
    let q = normalize_to_affine(p);
    let result = check_point_affine(&q);
    encode_point(&q, r);
    result
}

fn export_point(p: &PointAffine) -> PublicPoint {
    PublicPoint { x: p.x, y: p.y }
}

// TODO Revisit randomness source
pub fn generate_private_key(random: &mut dyn RngCore, k: &mut [u8; SECRET_KEY_SIZE]) {
    random.fill_bytes(k);
}

pub fn generate_public_key(sk: &[u8; SECRET_KEY_SIZE], pk: &mut [u8; PUBLIC_KEY_SIZE]) {
    let mut d = create_digest();
    let mut h = [0; 64];

    d.do_update(sk);
    d.do_final(&mut h);

    let mut s = [0; SCALAR_BYTES];
    prune_scalar_half(&h, &mut s);

    scalar_mult_base_encoded(&s, pk);
}

pub fn generate_public_point(sk: &[u8; SECRET_KEY_SIZE]) -> PublicPoint {
    let mut d = create_digest();
    let mut h = [0; 64];

    d.do_update(sk);
    d.do_final(&mut h);

    let mut s = [0; SCALAR_BYTES];
    prune_scalar_half(&h, &mut s);

    let p = scalar_mult_base(&s);
    let q = normalize_to_affine(&p);

    let condition = check_point_affine(&q);
    if !condition.to_bool_var() {
        // TODO Use a proper Result and propagate to callers
        panic!();
    }

    export_point(&q)
}

fn get_window_4(x: &[u64; SCALAR_UINTS], n: usize) -> u64 {
    let w = n >> 4;
    let b = (n & 15) << 2;
    (x[w] >> b) & 15
}

// NOTE that each u64 contains TWO blocks
fn group_comb_bits(n: &mut [u64; SCALAR_UINTS]) {
    /*
     * Because we are using 4 teeth and 8 spacing, each limb of n corresponds to two of the 8 blocks.
     * We can efficiently group the bits for each comb position using a (double) shuffle (within each 32 bits).
     */
    for n_i in n {
        let mut x = *n_i;
        x = bits::bit_permute_step_64(x, 0x0000F0F00000F0F0, 12);
        x = bits::bit_permute_step_64(x, 0x00CC00CC00CC00CC, 6);
        x = bits::bit_permute_step_64(x, 0x2222222222222222, 1);
        x = bits::bit_permute_step_64(x, 0x0C0C0C0C0C0C0C0C, 2);
        *n_i = x;
    }
}

#[allow(clippy::too_many_arguments, non_snake_case)]
fn impl_sign(
    d: &mut Sha512Digest,
    h: &mut [u8; SCALAR_BYTES * 2],
    s: &[u8; SCALAR_BYTES],
    pk: &[u8; POINT_BYTES],
    ctx: Option<&[u8]>,
    phflag: u8,
    m: &[u8],
    sig: &mut [u8; SIGNATURE_SIZE],
) {
    if let Some(data) = ctx {
        dom2(d, phflag, data);
    }
    d.do_update(&h[SCALAR_BYTES..]);
    d.do_update(m);
    d.do_final(h);

    let r = scalar_25519::reduce_512(h);
    let mut R = [0; POINT_BYTES];
    scalar_mult_base_encoded(&r, &mut R);

    if let Some(data) = ctx {
        dom2(d, phflag, data);
    }
    d.do_update(&R);
    d.do_update(pk);
    d.do_update(m);
    d.do_final(h);

    let k = scalar_25519::reduce_512(h);
    let S = calculate_S(&r, &k, s);

    sig[..POINT_BYTES].copy_from_slice(&R);
    sig[POINT_BYTES..].copy_from_slice(&S);
}

fn impl_sign_gen_pk(
    sk: &[u8; SECRET_KEY_SIZE],
    ctx: Option<&[u8]>,
    phflag: u8,
    m: &[u8],
    sig: &mut [u8; SIGNATURE_SIZE],
) {
    if !check_context_var(ctx, phflag) {
        // TODO Use a proper Result and propagate to callers
        panic!();
    }

    let mut d = create_digest();
    let mut h = [0; 64];

    d.do_update(sk);
    d.do_final(&mut h);

    let mut s = [0; SCALAR_BYTES];
    prune_scalar_half(&h, &mut s);

    let mut pk = [0; POINT_BYTES];
    scalar_mult_base_encoded(&s, &mut pk);

    impl_sign(&mut d, &mut h, &s, &pk, ctx, phflag, m, sig);
}

fn impl_sign_have_pk(
    sk: &[u8; SECRET_KEY_SIZE],
    pk: &[u8; PUBLIC_KEY_SIZE],
    ctx: Option<&[u8]>,
    phflag: u8,
    m: &[u8],
    sig: &mut [u8; SIGNATURE_SIZE],
) {
    if !check_context_var(ctx, phflag) {
        // TODO Use a proper Result and propagate to callers
        panic!();
    }

    let mut d = create_digest();
    let mut h = [0; 64];

    d.do_update(sk);
    d.do_final(&mut h);

    let mut s = [0; SCALAR_BYTES];
    prune_scalar_half(&h, &mut s);

    impl_sign(&mut d, &mut h, &s, pk, ctx, phflag, m, sig);
}

#[allow(non_snake_case)]
fn impl_verify_pk(
    sig: &[u8; SIGNATURE_SIZE],
    pk: &[u8; PUBLIC_KEY_SIZE],
    ctx: Option<&[u8]>,
    phflag: u8,
    m: &[u8],
) -> bool {
    if !check_context_var(ctx, phflag) {
        // TODO Use a proper Result and propagate to callers
        panic!();
    }

    let R = array_ref![sig, 0, POINT_BYTES];
    let S = array_ref![sig, POINT_BYTES, SCALAR_BYTES];

    let A = *pk;

    if !check_point_var(R) {
        return false;
    }

    let mut nS = [0_u64; SCALAR_UINTS];
    if !scalar_25519::check_var(S, &mut nS) {
        return false;
    }

    if !check_point_full_var(&A) {
        return false;
    }

    let mut pR = PointAffine::default();
    if !decode_point_var(R, true, &mut pR) {
        return false;
    }

    let mut pA = PointAffine::default();
    if !decode_point_var(&A, true, &mut pA) {
        return false;
    }

    let mut d = create_digest();
    let mut h = [0; 64];

    if let Some(data) = ctx {
        dom2(&mut d, phflag, data);
    }
    d.do_update(R);
    d.do_update(&A);
    d.do_update(m);
    d.do_final(&mut h);

    let k = scalar_25519::reduce_512(&h);

    let mut nA = [0_u64; SCALAR_UINTS];
    scalar_25519::decode(&k, &mut nA);

    let (v0, v1) = scalar_25519::reduce_basis_var(&nA).unwrap();
    nS = scalar_25519::multiply_128_var(&nS, &v1);

    let pZ = scalar_mult_straus_128_var(&nS, &v0, &pA, &v1, &pR);
    normalizes_to_neutral_element_var(&pZ)
}

#[allow(non_snake_case)]
fn impl_verify_public_point(
    sig: &[u8; SIGNATURE_SIZE],
    public_point: &PublicPoint,
    ctx: Option<&[u8]>,
    phflag: u8,
    m: &[u8],
) -> bool {
    if !check_context_var(ctx, phflag) {
        // TODO Use a proper Result and propagate to callers
        panic!();
    }

    let R = array_ref![sig, 0, POINT_BYTES];
    let S = array_ref![sig, POINT_BYTES, SCALAR_BYTES];

    if !check_point_var(R) {
        return false;
    }

    let mut nS = [0_u64; SCALAR_UINTS];
    if !scalar_25519::check_var(S, &mut nS) {
        return false;
    }

    let mut pR = PointAffine::default();
    if !decode_point_var(R, true, &mut pR) {
        return false;
    }

    let pA = PointAffine { x: public_point.x.negate().carry(), y: public_point.y };

    let mut A = [0; PUBLIC_KEY_SIZE];
    encode_public_point(public_point, &mut A);

    let mut d = create_digest();
    let mut h = [0; 64];

    if let Some(data) = ctx {
        dom2(&mut d, phflag, data);
    }
    d.do_update(R);
    d.do_update(&A);
    d.do_update(m);
    d.do_final(&mut h);

    let k = scalar_25519::reduce_512(&h);

    let mut nA = [0_u64; SCALAR_UINTS];
    scalar_25519::decode(&k, &mut nA);

    let (v0, v1) = scalar_25519::reduce_basis_var(&nA).unwrap();
    nS = scalar_25519::multiply_128_var(&nS, &v1);

    let pZ = scalar_mult_straus_128_var(&nS, &v0, &pA, &v1, &pR);
    normalizes_to_neutral_element_var(&pZ)
}

fn invert_double_zs(points: &mut [PointExtended]) {
    let count = points.len();
    debug_assert!(count > 0);
    let mut cs = vec![CoordField::default(); count];

    let mut u = points[0].z;
    cs[0] = u;

    for i in 1..count {
        u = u.mul(&points[i].z);
        cs[i] = u;
    }

    u = u.add(&u).inv_var();

    for j in (1..count).rev() {
        let t = u.mul(&cs[j - 1]);
        u = u.mul(&points[j].z);
        points[j].z = t;
    }

    points[0].z = u;
}

fn normalize_to_affine(p: &PointAccum) -> PointAffine {
    let z_inv = p.z.inv();
    let x = p.x.mul(&z_inv).normalize();
    let y = p.y.mul(&z_inv).normalize();
    PointAffine { x, y }
}

fn normalizes_to_neutral_element_var(p: &PointAccum) -> bool {
    let (x, y, z) = (p.x.normalize(), p.y.normalize(), p.z.normalize());
    x.is_zero_var() && !y.is_zero_var() && CoordField::are_equal_var(&y, &z)
}

fn point_accumulate_extended(p: &PointExtended, r: &mut PointExtended) {
    let (b, a) = r.y.apm(&r.x);
    let (d, c) = p.y.apm(&p.x);
    let a = a.mul(&c);
    let b = b.mul(&d);
    let c = p.t.mul(&r.t).mul(&C_D2);
    let d = r.z.add(&r.z).mul(&p.z);
    let (h, e) = b.apm(&a);
    let (g, f) = d.apm(&c);
    r.x = f.mul(&e);
    r.y = g.mul(&h);
    r.z = f.mul(&g);
    r.t = e.mul(&h);
}

fn point_accumulate_precomp(p: &PointPrecomp, r: &mut PointAccum) {
    let (b, a) = r.y.apm(&r.x);
    let a = a.mul(&p.ymx_h);
    let b = b.mul(&p.ypx_h);
    let c = r.u.mul(&r.v).mul(&p.xyd);
    (r.v, r.u) = b.apm(&a);
    let (g, f) = r.z.apm(&c);
    r.x = f.mul(&r.u);
    r.y = g.mul(&r.v);
    r.z = f.mul(&g);
}

fn point_accumulate_precomp_var(negate: bool, p: &PointPrecomp, r: &mut PointAccum) {
    let (mut b, mut a) = r.y.apm(&r.x);
    if negate {
        a = a.mul(&p.ypx_h);
        b = b.mul(&p.ymx_h);
    } else {
        a = a.mul(&p.ymx_h);
        b = b.mul(&p.ypx_h);
    }
    let c = r.u.mul(&r.v).mul(&p.xyd);
    (r.v, r.u) = b.apm(&a);
    let (f, g);
    if negate {
        (f, g) = r.z.apm(&c);
    } else {
        (g, f) = r.z.apm(&c);
    }
    r.x = f.mul(&r.u);
    r.y = g.mul(&r.v);
    r.z = f.mul(&g);
}

fn point_accumulate_precomp_z(p: &PointPrecompZ, r: &mut PointAccum) {
    let (b, a) = r.y.apm(&r.x);
    let a = a.mul(&p.ymx_h);
    let b = b.mul(&p.ypx_h);
    let c = r.u.mul(&r.v).mul(&p.xyd);
    let d = r.z.mul(&p.z);
    (r.v, r.u) = b.apm(&a);
    let (g, f) = d.apm(&c);
    r.x = f.mul(&r.u);
    r.y = g.mul(&r.v);
    r.z = f.mul(&g);
}

fn point_accumulate_precomp_z_var(negate: bool, p: &PointPrecompZ, r: &mut PointAccum) {
    let (mut b, mut a) = r.y.apm(&r.x);
    if negate {
        a = a.mul(&p.ypx_h);
        b = b.mul(&p.ymx_h);
    } else {
        a = a.mul(&p.ymx_h);
        b = b.mul(&p.ypx_h);
    }
    let c = r.u.mul(&r.v).mul(&p.xyd);
    let d = r.z.mul(&p.z);
    (r.v, r.u) = b.apm(&a);
    let (f, g);
    if negate {
        (f, g) = d.apm(&c);
    } else {
        (g, f) = d.apm(&c);
    }
    r.x = f.mul(&r.u);
    r.y = g.mul(&r.v);
    r.z = f.mul(&g);
}

fn point_add_extended(p: &PointExtended, q: &PointExtended, r: &mut PointExtended) {
    let (b, a) = p.y.apm(&p.x);
    let (d, c) = q.y.apm(&q.x);
    let a = a.mul(&c);
    let b = b.mul(&d);
    let c = p.t.mul(&q.t).mul(&C_D2);
    let d = p.z.add(&p.z).mul(&q.z);
    let (h, e) = b.apm(&a);
    let (g, f) = d.apm(&c);
    r.x = f.mul(&e);
    r.y = g.mul(&h);
    r.z = f.mul(&g);
    r.t = e.mul(&h);
}

fn point_copy_accum_extended(p: &PointAccum, r: &mut PointExtended) {
    r.x = p.x;
    r.y = p.y;
    r.z = p.z;
    r.t = p.u.mul(&p.v);
}

fn point_copy_affine_extended(p: &PointAffine, r: &mut PointExtended) {
    r.x = p.x;
    r.y = p.y;
    r.z = CoordField::one();
    r.t = p.x.mul(&p.y);
}

fn point_copy_extended_precomp_z(p: &PointExtended, r: &mut PointPrecompZ) {
    // To avoid halving x and y, we double t and z instead.
    (r.ypx_h, r.ymx_h) = p.y.apm(&p.x);
    r.xyd = p.t.mul(&C_D2);
    r.z = p.z.add(&p.z);
}

fn point_double(r: &mut PointAccum) {
    let a = r.x.sqr();
    let b = r.y.sqr();
    let c = r.z.sqr();
    let e = r.x.add(&r.y);
    let g;
    (r.v, g) = a.apm(&b);
    r.u = r.v.sub(&e.sqr()).carry();
    let f = g.add(&c).add(&c).carry();
    r.x = f.mul(&r.u);
    r.y = g.mul(&r.v);
    r.z = f.mul(&g);
}

fn point_lookup(
    comb_base: &[CoordField; PRECOMP_COMB_POINTS * 3],
    block: usize,
    index: usize,
    p: &mut PointPrecomp,
) {
    debug_assert!(block < PRECOMP_BLOCKS);
    debug_assert!(index < PRECOMP_POINTS);

    let mut off = block * PRECOMP_POINTS * 3;

    for i in 0..PRECOMP_POINTS {
        let cond_mov = Condition::<i64>::is_zero((i ^ index) as i64);
        p.ymx_h.cmov(cond_mov, &comb_base[off]);
        off += 1;
        p.ypx_h.cmov(cond_mov, &comb_base[off]);
        off += 1;
        p.xyd.cmov(cond_mov, &comb_base[off]);
        off += 1;
    }
}

// TODO This method is currently hard-coded to 4-bit windows and 8 precomputed points
fn point_lookup_z(
    x: &[u64; SCALAR_UINTS],
    n: usize,
    table: &[[CoordField; 4]; 8],
    r: &mut PointPrecompZ,
) {
    let w = get_window_4(x, n);

    let sign = (w >> (4 - 1)) as i64 ^ 1;
    let abs = (w as i64 ^ -sign) & 7;

    debug_assert!(sign == 0 || sign == 1);
    debug_assert!((0..8).contains(&abs));

    for (i, entry) in table.iter().enumerate() {
        let cond_mov = Condition::<i64>::is_zero(i as i64 ^ abs);
        r.ymx_h.cmov(cond_mov, &entry[0]);
        r.ypx_h.cmov(cond_mov, &entry[1]);
        r.xyd.cmov(cond_mov, &entry[2]);
        r.z.cmov(cond_mov, &entry[3]);
    }

    let cond_negate = Condition::<i64>::is_not_zero(sign);
    CoordField::cswap(cond_negate, &mut r.ymx_h, &mut r.ypx_h);
    r.xyd.cnegate(cond_negate);
}

fn point_precompute(p: &PointAffine, points: &mut [PointExtended]) {
    debug_assert!(!points.is_empty());

    point_copy_affine_extended(p, &mut points[0]);

    let mut d = PointExtended::default();
    point_add_extended(&points[0], &points[0], &mut d);

    for i in 1..points.len() {
        let mut t = PointExtended::default();
        point_add_extended(&points[i - 1], &d, &mut t);
        points[i] = t;
    }
}

fn point_precompute_z<const N: usize>(p: &PointAffine) -> [[CoordField; 4]; N] {
    debug_assert!(N > 0);

    let mut q = PointExtended::default();
    point_copy_affine_extended(p, &mut q);

    let mut d = PointExtended::default();
    point_add_extended(&q, &q, &mut d);

    let mut r = PointPrecompZ::default();
    let mut table = [[CoordField::default(); 4]; N];

    let mut i = 0_usize;
    loop {
        point_copy_extended_precomp_z(&q, &mut r);

        table[i][0] = r.ymx_h;
        table[i][1] = r.ypx_h;
        table[i][2] = r.xyd;
        table[i][3] = r.z;

        i += 1;
        if i == N {
            break;
        }

        point_accumulate_extended(&d, &mut q);
    }

    table
}

fn point_precompute_z_var<const N: usize>(p: &PointAffine) -> [PointPrecompZ; N] {
    debug_assert!(N > 0);

    let mut points = [PointPrecompZ::default(); N];

    let mut q = PointExtended::default();
    point_copy_affine_extended(p, &mut q);

    let mut d = PointExtended::default();
    point_add_extended(&q, &q, &mut d);

    let mut i = 0_usize;
    loop {
        point_copy_extended_precomp_z(&q, &mut points[i]);

        i += 1;
        if i == N {
            break;
        }

        point_accumulate_extended(&d, &mut q);
    }

    points
}

pub fn precompute() {
    LazyLock::force(&PRECOMPUTATION);
}

fn prune_scalar(n: &[u8; SCALAR_BYTES], r: &mut [u8; SCALAR_BYTES]) {
    *r = *n;

    r[0] &= 0xF8;
    r[SCALAR_BYTES - 1] &= 0x7F;
    r[SCALAR_BYTES - 1] |= 0x40;
}

// Utility method to simplify case of pruning the first half of a digest result
fn prune_scalar_half(h: &[u8; SCALAR_BYTES * 2], r: &mut [u8; SCALAR_BYTES]) {
    prune_scalar(array_ref!(h, 0, SCALAR_BYTES), r);
}

fn scalar_mult(k: &[u8; SCALAR_BYTES], p: &PointAffine) -> PointAccum {
    let mut n = [0_u64; SCALAR_UINTS];

    scalar_25519::decode(k, &mut n);
    scalar_25519::to_signed_digits(256, &mut n);

    let mut q = PointPrecompZ::default();
    let table = point_precompute_z::<8>(p);

    let mut r = PointAccum::neutral_element();

    let mut w = 63_usize;
    loop {
        point_lookup_z(&n, w, &table, &mut q);
        point_accumulate_precomp_z(&q, &mut r);

        if w == 0 {
            break;
        }
        w -= 1;

        for _ in 0..4 {
            point_double(&mut r);
        }
    }

    r
}

fn scalar_mult_base(k: &[u8; SCALAR_BYTES]) -> PointAccum {
    // Equivalent (but much slower)
    // let p = PointAffine { x: B_X, y: B_Y };
    // scalar_mult(k, &p);

    let precomputation = LazyLock::force(&PRECOMPUTATION);
    let comb_base = &precomputation.comb_base;

    let mut n = [0_u64; SCALAR_UINTS];
    scalar_25519::decode(k, &mut n);
    scalar_25519::to_signed_digits(PRECOMP_RANGE, &mut n);
    group_comb_bits(&mut n);

    let mut p = PointPrecomp::default();
    let mut r = PointAccum::neutral_element();
    let mut result_sign = 0_i64;

    let mut c_off = (PRECOMP_SPACING - 1) * PRECOMP_TEETH;
    loop {
        for block in 0..PRECOMP_BLOCKS {
            let block32 = (n[block >> 1] >> ((block & 1) << 5)) as u32;
            let w: u32 = block32 >> c_off;
            let sign: i32 = (w >> (PRECOMP_TEETH - 1)) as i32 & 1;
            let abs: usize = (((w as i32) ^ -sign) as usize) & PRECOMP_MASK;

            debug_assert!(sign == 0 || sign == 1);
            debug_assert!(abs < PRECOMP_POINTS);

            point_lookup(comb_base, block, abs, &mut p);

            let cond_negate = Condition::<i64>::is_not_zero(result_sign ^ sign as i64);
            r.x.cnegate(cond_negate);
            r.u.cnegate(cond_negate);
            result_sign = sign as i64;

            point_accumulate_precomp(&p, &mut r);
        }

        if c_off == 0 {
            break;
        };
        c_off -= PRECOMP_TEETH;

        point_double(&mut r);
    }

    {
        let cond_negate = Condition::<i64>::is_not_zero(result_sign);
        r.x.cnegate(cond_negate);
        r.u.cnegate(cond_negate);
    }

    r
}

fn scalar_mult_base_encoded(k: &[u8; SCALAR_BYTES], r: &mut [u8; POINT_BYTES]) {
    let p = scalar_mult_base(k);
    let condition = encode_result(&p, r);
    if !condition.to_bool_var() {
        // TODO Use a proper Result and propagate to callers
        panic!();
    }
}

fn scalar_mult_base_yz(k: &[u8; SCALAR_BYTES]) -> (CoordField, CoordField) {
    let mut n = [0; SCALAR_BYTES];
    prune_scalar(k, &mut n);

    let p = scalar_mult_base(&n);

    let condition = check_point_accum(&p);
    if !condition.to_bool_var() {
        // TODO Use a proper Result and propagate to callers
        panic!();
    }

    // TODO Explicit struct for Y/Z coords
    (p.y, p.z)
}

fn scalar_mult_order_var(p: &PointAffine) -> PointAccum {
    let mut ws_p = [0_i8; 253];

    // NOTE: WNAF_WIDTH_128 because of the special structure of the order
    scalar_25519::get_order_wnaf_var(WNAF_WIDTH_128, &mut ws_p);

    const COUNT: usize = 1 << (WNAF_WIDTH_128 - 2);
    let tp = point_precompute_z_var::<COUNT>(p);

    let mut r = PointAccum::neutral_element();

    let mut bit = 252_usize;
    loop {
        let wp = ws_p[bit];
        if wp != 0 {
            let index = (wp >> 1 ^ wp >> 7) as usize;
            point_accumulate_precomp_z_var(wp < 0, &tp[index], &mut r);
        }

        if bit == 0 {
            break;
        }
        bit -= 1;

        point_double(&mut r);
    }

    r
}

fn scalar_mult_straus_128_var(
    nb: &[u64; SCALAR_UINTS],
    np: &[u64; 2],
    p: &PointAffine,
    nq: &[u64; 2],
    q: &PointAffine,
) -> PointAccum {
    debug_assert_eq!(0, nb[SCALAR_UINTS - 1] >> 61);

    let precomputation = LazyLock::force(&PRECOMPUTATION);
    let wnaf_base = &precomputation.wnaf_base;
    let wnaf_base_128 = &precomputation.wnaf_base_128;

    let mut ws_b = [0_i8; 256];
    let mut ws_p = [0_i8; 128];
    let mut ws_q = [0_i8; 128];

    wnaf::get_signed_var(nb, WNAF_WIDTH_BASE, &mut ws_b);
    wnaf::get_signed_var(np, WNAF_WIDTH_128, &mut ws_p);
    wnaf::get_signed_var(nq, WNAF_WIDTH_128, &mut ws_q);

    const COUNT: usize = 1 << (WNAF_WIDTH_128 - 2);
    let tp = point_precompute_z_var::<COUNT>(p);
    let tq = point_precompute_z_var::<COUNT>(q);

    let mut r = PointAccum::neutral_element();

    let mut bit = 127;
    loop {
        if ws_b[bit] | ws_b[128 + bit] | ws_p[bit] | ws_q[bit] != 0 {
            break;
        }
        if bit == 0 {
            break;
        }
        bit -= 1;
    }

    loop {
        let wb = ws_b[bit];
        if wb != 0 {
            let index = (wb >> 1 ^ wb >> 7) as usize;
            point_accumulate_precomp_var(wb < 0, &wnaf_base[index], &mut r);
        }

        let wb128 = ws_b[128 + bit];
        if wb128 != 0 {
            let index = (wb128 >> 1 ^ wb128 >> 7) as usize;
            point_accumulate_precomp_var(wb128 < 0, &wnaf_base_128[index], &mut r);
        }

        let wp = ws_p[bit];
        if wp != 0 {
            let index = (wp >> 1 ^ wp >> 7) as usize;
            point_accumulate_precomp_z_var(wp < 0, &tp[index], &mut r);
        }

        let wq = ws_q[bit];
        if wq != 0 {
            let index = (wq >> 1 ^ wq >> 7) as usize;
            point_accumulate_precomp_z_var(wq < 0, &tq[index], &mut r);
        }

        point_double(&mut r);

        if bit == 0 {
            break;
        }
        bit -= 1;
    }

    // NOTE: Together with the final point_double of the loop, this clears the cofactor of 8
    point_double(&mut r);
    point_double(&mut r);
    r
}

pub fn sign(sk: &[u8; SECRET_KEY_SIZE], m: &[u8], sig: &mut [u8; SIGNATURE_SIZE]) {
    let ctx = None;
    let phflag = 0x00_u8;

    impl_sign_gen_pk(sk, ctx, phflag, m, sig);
}

pub fn sign_pk(
    sk: &[u8; SECRET_KEY_SIZE],
    pk: &[u8; PUBLIC_KEY_SIZE],
    m: &[u8],
    sig: &mut [u8; SIGNATURE_SIZE],
) {
    let ctx = None;
    let phflag = 0x00_u8;

    impl_sign_have_pk(sk, pk, ctx, phflag, m, sig);
}

pub fn sign_ctx(sk: &[u8; SECRET_KEY_SIZE], ctx: &[u8], m: &[u8], sig: &mut [u8; SIGNATURE_SIZE]) {
    let phflag = 0x00_u8;

    impl_sign_gen_pk(sk, Some(ctx), phflag, m, sig);
}

pub fn sign_ctx_pk(
    sk: &[u8; SECRET_KEY_SIZE],
    pk: &[u8; PUBLIC_KEY_SIZE],
    ctx: &[u8],
    m: &[u8],
    sig: &mut [u8; SIGNATURE_SIZE],
) {
    let phflag = 0x00_u8;

    impl_sign_have_pk(sk, pk, Some(ctx), phflag, m, sig);
}

pub fn sign_digest(
    sk: &[u8; SECRET_KEY_SIZE],
    ctx: &[u8],
    ph: &mut Sha512Digest,
    sig: &mut [u8; SIGNATURE_SIZE],
) {
    if PREHASH_SIZE != ph.result_len() {
        // TODO Use a proper Result and propagate to callers
        panic!();
    }

    let mut m = [0; PREHASH_SIZE];
    ph.do_final(&mut m);

    let phflag = 0x01_u8;

    impl_sign_gen_pk(sk, Some(ctx), phflag, &m, sig);
}

pub fn sign_digest_pk(
    sk: &[u8; SECRET_KEY_SIZE],
    pk: &[u8; PUBLIC_KEY_SIZE],
    ctx: &[u8],
    ph: &mut Sha512Digest,
    sig: &mut [u8; SIGNATURE_SIZE],
) {
    if PREHASH_SIZE != ph.result_len() {
        // TODO Use a proper Result and propagate to callers
        panic!();
    }

    let mut m = [0; PREHASH_SIZE];
    ph.do_final(&mut m);

    let phflag = 0x01_u8;

    impl_sign_have_pk(sk, pk, Some(ctx), phflag, &m, sig);
}

pub fn sign_prehash(
    sk: &[u8; SECRET_KEY_SIZE],
    ctx: &[u8],
    ph: &[u8; PREHASH_SIZE],
    sig: &mut [u8; SIGNATURE_SIZE],
) {
    let phflag = 0x01_u8;

    impl_sign_gen_pk(sk, Some(ctx), phflag, ph, sig);
}

pub fn sign_prehash_pk(
    sk: &[u8; SECRET_KEY_SIZE],
    pk: &[u8; PUBLIC_KEY_SIZE],
    ctx: &[u8],
    ph: &[u8; PREHASH_SIZE],
    sig: &mut [u8; SIGNATURE_SIZE],
) {
    let phflag = 0x01_u8;

    impl_sign_have_pk(sk, pk, Some(ctx), phflag, ph, sig);
}

#[allow(non_snake_case)]
pub fn validate_public_key_full(pk: &[u8; PUBLIC_KEY_SIZE]) -> bool {
    let A = *pk;

    if !check_point_full_var(&A) {
        return false;
    }

    let mut pA = PointAffine::default();
    if !decode_point_var(&A, false, &mut pA) {
        return false;
    }

    check_point_order_var(&pA)
}

#[allow(non_snake_case)]
pub fn validate_public_key_full_export(pk: &[u8; PUBLIC_KEY_SIZE]) -> Option<PublicPoint> {
    let A = *pk;

    if !check_point_full_var(&A) {
        return None;
    }

    let mut pA = PointAffine::default();
    if !decode_point_var(&A, false, &mut pA) {
        return None;
    }

    if !check_point_order_var(&pA) {
        return None;
    }

    Some(export_point(&pA))
}

#[allow(non_snake_case)]
pub fn validate_public_key_partial(pk: &[u8; PUBLIC_KEY_SIZE]) -> bool {
    let A = *pk;

    if !check_point_full_var(&A) {
        return false;
    }

    let mut pA = PointAffine::default();
    decode_point_var(&A, false, &mut pA)
}

#[allow(non_snake_case)]
pub fn validate_public_key_partial_export(pk: &[u8; PUBLIC_KEY_SIZE]) -> Option<PublicPoint> {
    let A = *pk;

    if !check_point_full_var(&A) {
        return None;
    }

    let mut pA = PointAffine::default();
    if !decode_point_var(&A, false, &mut pA) {
        return None;
    }

    Some(export_point(&pA))
}

pub fn verify(sig: &[u8; SIGNATURE_SIZE], pk: &[u8; PUBLIC_KEY_SIZE], m: &[u8]) -> bool {
    let ctx = None;
    let phflag = 0x00_u8;

    impl_verify_pk(sig, pk, ctx, phflag, m)
}

pub fn verify_public_point(
    sig: &[u8; SIGNATURE_SIZE],
    public_point: &PublicPoint,
    m: &[u8],
) -> bool {
    let ctx = None;
    let phflag = 0x00_u8;

    impl_verify_public_point(sig, public_point, ctx, phflag, m)
}

pub fn verify_ctx(
    sig: &[u8; SIGNATURE_SIZE],
    pk: &[u8; PUBLIC_KEY_SIZE],
    ctx: &[u8],
    m: &[u8],
) -> bool {
    let phflag = 0x00_u8;

    impl_verify_pk(sig, pk, Some(ctx), phflag, m)
}

pub fn verify_ctx_public_point(
    sig: &[u8; SIGNATURE_SIZE],
    public_point: &PublicPoint,
    ctx: &[u8],
    m: &[u8],
) -> bool {
    let phflag = 0x00_u8;

    impl_verify_public_point(sig, public_point, Some(ctx), phflag, m)
}

pub fn verify_digest(
    sig: &[u8; SIGNATURE_SIZE],
    pk: &[u8; PUBLIC_KEY_SIZE],
    ctx: &[u8],
    ph: &mut Sha512Digest,
) -> bool {
    if PREHASH_SIZE != ph.result_len() {
        // TODO Use a proper Result and propagate to callers
        panic!();
    }

    let mut m = [0; PREHASH_SIZE];
    ph.do_final(&mut m);

    let phflag = 0x01_u8;

    impl_verify_pk(sig, pk, Some(ctx), phflag, &m)
}

pub fn verify_digest_public_point(
    sig: &[u8; SIGNATURE_SIZE],
    public_point: &PublicPoint,
    ctx: &[u8],
    ph: &mut Sha512Digest,
) -> bool {
    if PREHASH_SIZE != ph.result_len() {
        // TODO Use a proper Result and propagate to callers
        panic!();
    }

    let mut m = [0; PREHASH_SIZE];
    ph.do_final(&mut m);

    let phflag = 0x01_u8;

    impl_verify_public_point(sig, public_point, Some(ctx), phflag, &m)
}

pub fn verify_prehash(
    sig: &[u8; SIGNATURE_SIZE],
    pk: &[u8; PUBLIC_KEY_SIZE],
    ctx: &[u8],
    ph: &[u8; PREHASH_SIZE],
) -> bool {
    let phflag = 0x01_u8;

    impl_verify_pk(sig, pk, Some(ctx), phflag, ph)
}

pub fn verify_prehash_public_point(
    sig: &[u8; SIGNATURE_SIZE],
    public_point: &PublicPoint,
    ctx: &[u8],
    ph: &[u8; PREHASH_SIZE],
) -> bool {
    let phflag = 0x01_u8;

    impl_verify_public_point(sig, public_point, Some(ctx), phflag, ph)
}
