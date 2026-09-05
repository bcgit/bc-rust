//! A table-driven reference ARIA, for cross-checking the constant-time engine.
//!
//! This is BC Java's `ARIAEngine` transcribed as directly as Rust allows: the four 256-byte S-box
//! tables of RFC 5794 Sec 2.4.2, the byte-array `A`, `SL1`, `SL2`, `FO`, `FE`, the byte-oriented
//! `keySchedule` with its `keyScheduleRound` rotations and the direction-dependent `reverseKeys` /
//! `A(rks[i])` for decryption, and the `processBlock` of the current engine, which fuses each
//! substitution with the diffusion layer through the "SWAR multiply-broadcast" masks `M_HI` /
//! `M_LO` (each substituted byte, multiplied by a mask of `0x01` bytes, lands on the seven output
//! positions of its column of `A`). It exists only in the tests, where its cache-timing behaviour
//! does not matter, and it is deliberately independent of the crate's own code: byte arrays and
//! 64-bit halves where the engine uses 32-bit row words, class words and bit-planes, so agreement
//! between the two is meaningful.
//!
//! It is itself checked against RFC 5794 Appendix A in `reference_sanity`, so a bug here cannot
//! silently validate a bug in the engine.

#![allow(dead_code)]

/// Sec 2.4.2 `SB1`; identical to BC Java's `SB1_sbox`.
#[rustfmt::skip]
pub const SB1: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// Sec 2.4.2 `SB2`; identical to BC Java's `SB2_sbox`.
#[rustfmt::skip]
pub const SB2: [u8; 256] = [
    0xe2, 0x4e, 0x54, 0xfc, 0x94, 0xc2, 0x4a, 0xcc, 0x62, 0x0d, 0x6a, 0x46, 0x3c, 0x4d, 0x8b, 0xd1,
    0x5e, 0xfa, 0x64, 0xcb, 0xb4, 0x97, 0xbe, 0x2b, 0xbc, 0x77, 0x2e, 0x03, 0xd3, 0x19, 0x59, 0xc1,
    0x1d, 0x06, 0x41, 0x6b, 0x55, 0xf0, 0x99, 0x69, 0xea, 0x9c, 0x18, 0xae, 0x63, 0xdf, 0xe7, 0xbb,
    0x00, 0x73, 0x66, 0xfb, 0x96, 0x4c, 0x85, 0xe4, 0x3a, 0x09, 0x45, 0xaa, 0x0f, 0xee, 0x10, 0xeb,
    0x2d, 0x7f, 0xf4, 0x29, 0xac, 0xcf, 0xad, 0x91, 0x8d, 0x78, 0xc8, 0x95, 0xf9, 0x2f, 0xce, 0xcd,
    0x08, 0x7a, 0x88, 0x38, 0x5c, 0x83, 0x2a, 0x28, 0x47, 0xdb, 0xb8, 0xc7, 0x93, 0xa4, 0x12, 0x53,
    0xff, 0x87, 0x0e, 0x31, 0x36, 0x21, 0x58, 0x48, 0x01, 0x8e, 0x37, 0x74, 0x32, 0xca, 0xe9, 0xb1,
    0xb7, 0xab, 0x0c, 0xd7, 0xc4, 0x56, 0x42, 0x26, 0x07, 0x98, 0x60, 0xd9, 0xb6, 0xb9, 0x11, 0x40,
    0xec, 0x20, 0x8c, 0xbd, 0xa0, 0xc9, 0x84, 0x04, 0x49, 0x23, 0xf1, 0x4f, 0x50, 0x1f, 0x13, 0xdc,
    0xd8, 0xc0, 0x9e, 0x57, 0xe3, 0xc3, 0x7b, 0x65, 0x3b, 0x02, 0x8f, 0x3e, 0xe8, 0x25, 0x92, 0xe5,
    0x15, 0xdd, 0xfd, 0x17, 0xa9, 0xbf, 0xd4, 0x9a, 0x7e, 0xc5, 0x39, 0x67, 0xfe, 0x76, 0x9d, 0x43,
    0xa7, 0xe1, 0xd0, 0xf5, 0x68, 0xf2, 0x1b, 0x34, 0x70, 0x05, 0xa3, 0x8a, 0xd5, 0x79, 0x86, 0xa8,
    0x30, 0xc6, 0x51, 0x4b, 0x1e, 0xa6, 0x27, 0xf6, 0x35, 0xd2, 0x6e, 0x24, 0x16, 0x82, 0x5f, 0xda,
    0xe6, 0x75, 0xa2, 0xef, 0x2c, 0xb2, 0x1c, 0x9f, 0x5d, 0x6f, 0x80, 0x0a, 0x72, 0x44, 0x9b, 0x6c,
    0x90, 0x0b, 0x5b, 0x33, 0x7d, 0x5a, 0x52, 0xf3, 0x61, 0xa1, 0xf7, 0xb0, 0xd6, 0x3f, 0x7c, 0x6d,
    0xed, 0x14, 0xe0, 0xa5, 0x3d, 0x22, 0xb3, 0xf8, 0x89, 0xde, 0x71, 0x1a, 0xaf, 0xba, 0xb5, 0x81,
];

/// `SB3 = SB1^-1`, built as the Java's `SB3_sbox` table would be read: the inverse permutation.
pub fn sb3() -> [u8; 256] {
    let mut t = [0u8; 256];
    for (x, &y) in SB1.iter().enumerate() {
        t[y as usize] = x as u8;
    }
    t
}

/// `SB4 = SB2^-1`.
pub fn sb4() -> [u8; 256] {
    let mut t = [0u8; 256];
    for (x, &y) in SB2.iter().enumerate() {
        t[y as usize] = x as u8;
    }
    t
}

/// `C`: the three constants, as byte arrays as in the Java.
const C: [[u8; 16]; 3] = [
    0x517cc1b727220a94fe13abe8fa9a6ee0u128.to_be_bytes(),
    0x6db14acc9e21c820ff28b1d5ef5de2b0u128.to_be_bytes(),
    0xdb92371d2126e9700324977504e8c90eu128.to_be_bytes(),
];

/// `ARIAEngine.A(byte[] z)`.
fn a(z: &mut [u8; 16]) {
    let x = *z;
    z[0] = x[3] ^ x[4] ^ x[6] ^ x[8] ^ x[9] ^ x[13] ^ x[14];
    z[1] = x[2] ^ x[5] ^ x[7] ^ x[8] ^ x[9] ^ x[12] ^ x[15];
    z[2] = x[1] ^ x[4] ^ x[6] ^ x[10] ^ x[11] ^ x[12] ^ x[15];
    z[3] = x[0] ^ x[5] ^ x[7] ^ x[10] ^ x[11] ^ x[13] ^ x[14];
    z[4] = x[0] ^ x[2] ^ x[5] ^ x[8] ^ x[11] ^ x[14] ^ x[15];
    z[5] = x[1] ^ x[3] ^ x[4] ^ x[9] ^ x[10] ^ x[14] ^ x[15];
    z[6] = x[0] ^ x[2] ^ x[7] ^ x[9] ^ x[10] ^ x[12] ^ x[13];
    z[7] = x[1] ^ x[3] ^ x[6] ^ x[8] ^ x[11] ^ x[12] ^ x[13];
    z[8] = x[0] ^ x[1] ^ x[4] ^ x[7] ^ x[10] ^ x[13] ^ x[15];
    z[9] = x[0] ^ x[1] ^ x[5] ^ x[6] ^ x[11] ^ x[12] ^ x[14];
    z[10] = x[2] ^ x[3] ^ x[5] ^ x[6] ^ x[8] ^ x[13] ^ x[15];
    z[11] = x[2] ^ x[3] ^ x[4] ^ x[7] ^ x[9] ^ x[12] ^ x[14];
    z[12] = x[1] ^ x[2] ^ x[6] ^ x[7] ^ x[9] ^ x[11] ^ x[12];
    z[13] = x[0] ^ x[3] ^ x[6] ^ x[7] ^ x[8] ^ x[10] ^ x[13];
    z[14] = x[0] ^ x[3] ^ x[4] ^ x[5] ^ x[9] ^ x[11] ^ x[14];
    z[15] = x[1] ^ x[2] ^ x[4] ^ x[5] ^ x[8] ^ x[10] ^ x[15];
}

/// `SL1(byte[] z)`.
fn sl1(z: &mut [u8; 16]) {
    let (s3, s4) = (sb3(), sb4());
    for i in 0..16 {
        z[i] = match i % 4 {
            0 => SB1[z[i] as usize],
            1 => SB2[z[i] as usize],
            2 => s3[z[i] as usize],
            _ => s4[z[i] as usize],
        };
    }
}

/// `SL2(byte[] z)`.
fn sl2(z: &mut [u8; 16]) {
    let (s3, s4) = (sb3(), sb4());
    for i in 0..16 {
        z[i] = match i % 4 {
            0 => s3[z[i] as usize],
            1 => s4[z[i] as usize],
            2 => SB1[z[i] as usize],
            _ => SB2[z[i] as usize],
        };
    }
}

fn xor(z: &mut [u8; 16], x: &[u8; 16]) {
    for i in 0..16 {
        z[i] ^= x[i];
    }
}

/// `FO(byte[] D, byte[] RK)`.
fn fo(d: &mut [u8; 16], rk: &[u8; 16]) {
    xor(d, rk);
    sl1(d);
    a(d);
}

/// `FE(byte[] D, byte[] RK)`.
fn fe(d: &mut [u8; 16], rk: &[u8; 16]) {
    xor(d, rk);
    sl2(d);
    a(d);
}

/// `keyScheduleRound(rk, w, wr, n)`: `rk = w ^ (wr >>> n)`, byte by byte as the Java does it.
fn key_schedule_round(rk: &mut [u8; 16], w: &[u8; 16], wr: &[u8; 16], n: u32) {
    let off = (n >> 3) as usize;
    let right = n & 7;
    let left = 8 - right;
    let mut hi = wr[15 - off] as u32;
    for to in 0..16 {
        let lo = wr[(to + 16 - off) & 0xF] as u32;
        let mut b = (hi << left) | (lo >> right);
        b ^= w[to] as u32;
        rk[to] = b as u8;
        hi = lo;
    }
}

/// `keySchedule(forEncryption, K)`.
fn key_schedule(for_encryption: bool, k: &[u8]) -> Vec<[u8; 16]> {
    let key_len = k.len();
    assert!((16..=32).contains(&key_len) && key_len % 8 == 0, "Key length not 128/192/256 bits.");
    let key_len_idx = (key_len >> 3) - 2;
    let ck1 = &C[key_len_idx];
    let ck2 = &C[(key_len_idx + 1) % 3];
    let ck3 = &C[(key_len_idx + 2) % 3];

    let mut kl = [0u8; 16];
    let mut kr = [0u8; 16];
    kl.copy_from_slice(&k[..16]);
    kr[..key_len - 16].copy_from_slice(&k[16..]);

    let w0 = kl;
    let mut w1 = w0;
    fo(&mut w1, ck1);
    xor(&mut w1, &kr);
    let mut w2 = w1;
    fe(&mut w2, ck2);
    xor(&mut w2, &w0);
    let mut w3 = w2;
    fo(&mut w3, ck3);
    xor(&mut w3, &w1);

    let num_rounds = 12 + key_len_idx * 2;
    let mut rks = vec![[0u8; 16]; num_rounds + 1];
    key_schedule_round(&mut rks[0], &w0, &w1, 19);
    key_schedule_round(&mut rks[1], &w1, &w2, 19);
    key_schedule_round(&mut rks[2], &w2, &w3, 19);
    key_schedule_round(&mut rks[3], &w3, &w0, 19);
    key_schedule_round(&mut rks[4], &w0, &w1, 31);
    key_schedule_round(&mut rks[5], &w1, &w2, 31);
    key_schedule_round(&mut rks[6], &w2, &w3, 31);
    key_schedule_round(&mut rks[7], &w3, &w0, 31);
    key_schedule_round(&mut rks[8], &w0, &w1, 67);
    key_schedule_round(&mut rks[9], &w1, &w2, 67);
    key_schedule_round(&mut rks[10], &w2, &w3, 67);
    key_schedule_round(&mut rks[11], &w3, &w0, 67);
    key_schedule_round(&mut rks[12], &w0, &w1, 97);
    if num_rounds > 12 {
        key_schedule_round(&mut rks[13], &w1, &w2, 97);
        key_schedule_round(&mut rks[14], &w2, &w3, 97);
        if num_rounds > 14 {
            key_schedule_round(&mut rks[15], &w3, &w0, 97);
            key_schedule_round(&mut rks[16], &w0, &w1, 109);
        }
    }

    if !for_encryption {
        rks.reverse(); // reverseKeys
        for rk in rks.iter_mut().take(num_rounds).skip(1) {
            a(rk);
        }
    }
    rks
}

/// The Java engine after `init`: round keys as big-endian `long` halves, plus the broadcast masks.
pub struct Reference {
    rk_hi: Vec<u64>,
    rk_lo: Vec<u64>,
    m_hi: [u64; 16],
    m_lo: [u64; 16],
}

impl Reference {
    pub fn new(for_encryption: bool, key: &[u8]) -> Self {
        let rks = key_schedule(for_encryption, key);
        let rk_hi = rks.iter().map(|k| u64::from_be_bytes(k[..8].try_into().unwrap())).collect();
        let rk_lo = rks.iter().map(|k| u64::from_be_bytes(k[8..].try_into().unwrap())).collect();
        // M_HI / M_LO: A applied to each unit byte, as the Java's static initialiser does.
        let mut m_hi = [0u64; 16];
        let mut m_lo = [0u64; 16];
        for i in 0..16 {
            let mut u = [0u8; 16];
            u[i] = 1;
            a(&mut u);
            m_hi[i] = u64::from_be_bytes(u[..8].try_into().unwrap());
            m_lo[i] = u64::from_be_bytes(u[8..].try_into().unwrap());
        }
        Self { rk_hi, rk_lo, m_hi, m_lo }
    }

    /// `applyFO(sh, sl, M)`: SL1 substitution fused with A through the broadcast masks.
    fn apply_fo(sh: u64, sl: u64, m: &[u64; 16]) -> u64 {
        let (s3, s4) = (sb3(), sb4());
        let byte = |w: u64, i: u32| ((w >> (56 - 8 * i)) & 0xFF) as usize;
        let mut out = 0u64;
        for i in 0..8u32 {
            let s = match i % 4 {
                0 => SB1[byte(sh, i)],
                1 => SB2[byte(sh, i)],
                2 => s3[byte(sh, i)],
                _ => s4[byte(sh, i)],
            };
            out ^= (s as u64).wrapping_mul(m[i as usize]);
            let s = match i % 4 {
                0 => SB1[byte(sl, i)],
                1 => SB2[byte(sl, i)],
                2 => s3[byte(sl, i)],
                _ => s4[byte(sl, i)],
            };
            out ^= (s as u64).wrapping_mul(m[8 + i as usize]);
        }
        out
    }

    /// `applyFE(sh, sl, M)`: SL2 substitution fused with A.
    fn apply_fe(sh: u64, sl: u64, m: &[u64; 16]) -> u64 {
        let (s3, s4) = (sb3(), sb4());
        let byte = |w: u64, i: u32| ((w >> (56 - 8 * i)) & 0xFF) as usize;
        let mut out = 0u64;
        for i in 0..8u32 {
            let s = match i % 4 {
                0 => s3[byte(sh, i)],
                1 => s4[byte(sh, i)],
                2 => SB1[byte(sh, i)],
                _ => SB2[byte(sh, i)],
            };
            out ^= (s as u64).wrapping_mul(m[i as usize]);
            let s = match i % 4 {
                0 => s3[byte(sl, i)],
                1 => s4[byte(sl, i)],
                2 => SB1[byte(sl, i)],
                _ => SB2[byte(sl, i)],
            };
            out ^= (s as u64).wrapping_mul(m[8 + i as usize]);
        }
        out
    }

    /// `sl2Word(w)`: SL2 on one 8-byte half, no diffusion.
    fn sl2_word(w: u64) -> u64 {
        let (s3, s4) = (sb3(), sb4());
        let mut out = 0u64;
        for i in 0..8u32 {
            let x = ((w >> (56 - 8 * i)) & 0xFF) as usize;
            let s = match i % 4 {
                0 => s3[x],
                1 => s4[x],
                2 => SB1[x],
                _ => SB2[x],
            };
            out |= (s as u64) << (56 - 8 * i);
        }
        out
    }

    /// `processBlock`.
    pub fn process_block(&self, input: &[u8; 16], out: &mut [u8; 16]) {
        let (kh, kl) = (&self.rk_hi, &self.rk_lo);
        let mut hi = u64::from_be_bytes(input[..8].try_into().unwrap());
        let mut lo = u64::from_be_bytes(input[8..].try_into().unwrap());
        let mut i = 0;
        let rounds = kh.len() - 3;
        while i < rounds {
            let (sh, sl) = (hi ^ kh[i], lo ^ kl[i]);
            hi = Self::apply_fo(sh, sl, &self.m_hi);
            lo = Self::apply_fo(sh, sl, &self.m_lo);
            i += 1;
            let (sh, sl) = (hi ^ kh[i], lo ^ kl[i]);
            hi = Self::apply_fe(sh, sl, &self.m_hi);
            lo = Self::apply_fe(sh, sl, &self.m_lo);
            i += 1;
        }
        // Final FO
        let (sh, sl) = (hi ^ kh[i], lo ^ kl[i]);
        hi = Self::apply_fo(sh, sl, &self.m_hi);
        lo = Self::apply_fo(sh, sl, &self.m_lo);
        i += 1;
        // Add round key, SL2 without A, add round key
        let (sh, sl) = (hi ^ kh[i], lo ^ kl[i]);
        hi = Self::sl2_word(sh);
        lo = Self::sl2_word(sl);
        i += 1;
        hi ^= kh[i];
        lo ^= kl[i];
        out[..8].copy_from_slice(&hi.to_be_bytes());
        out[8..].copy_from_slice(&lo.to_be_bytes());
    }
}

/// Reference encryption of one block: `init(true, key)` then `processBlock`.
pub fn encrypt_block(key: &[u8], block: &mut [u8; 16]) {
    let input = *block;
    Reference::new(true, key).process_block(&input, block);
}

/// Reference decryption of one block: `init(false, key)` then `processBlock`.
pub fn decrypt_block(key: &[u8], block: &mut [u8; 16]) {
    let input = *block;
    Reference::new(false, key).process_block(&input, block);
}

/// Deterministic pseudo-random bytes (xorshift), so the cross-check needs no RNG.
pub fn pseudo_random<const N: usize>(seed: &mut u32) -> [u8; N] {
    core::array::from_fn(|_| {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 17;
        *seed ^= *seed << 5;
        (*seed >> 24) as u8
    })
}

/// Parses hex into a fixed-size array.
pub fn bytes<const N: usize>(hex_str: &str) -> [u8; N] {
    assert!(hex_str.len() == 2 * N, "expected {N} bytes of hex, got {}", hex_str.len() / 2);
    core::array::from_fn(|i| u8::from_str_radix(&hex_str[2 * i..2 * i + 2], 16).expect("valid hex"))
}
