//! A table-driven reference Camellia, for cross-checking the constant-time engine.
//!
//! This is BC Java's `CamelliaLightEngine` transcribed as directly as Rust allows: the 256-byte
//! `SBOX1` table of RFC 3713 Sec 2.4.1 with `sbox2`/`sbox3`/`sbox4` derived from it as the Java
//! does, `SIGMA` as 32-bit halves, the 32-bit-word `camelliaF2` (two rounds per call) and
//! `camelliaFLs`, the `roldq` / `decroldq` / `roldqo32` / `decroldqo32` subkey layout, and the
//! direction-dependent `setKey`. It exists only in the tests, where its cache-timing behaviour does
//! not matter, and it is deliberately independent of the crate's own code: it shares no modules
//! with it and is organised around 32-bit quarters where the engine uses 64-bit halves, so
//! agreement between the two is meaningful.
//!
//! It is itself checked against RFC 3713 Appendix A in `reference_sanity`, so a bug here cannot
//! silently validate a bug in the engine.

#![allow(dead_code)]

/// Sec 2.4.1's `SBOX1`; identical to BC Java's `SBOX1`.
#[rustfmt::skip]
pub const SBOX1: [u8; 256] = [
    112, 130,  44, 236, 179,  39, 192, 229, 228, 133,  87,  53, 234,  12, 174,  65,
     35, 239, 107, 147,  69,  25, 165,  33, 237,  14,  79,  78,  29, 101, 146, 189,
    134, 184, 175, 143, 124, 235,  31, 206,  62,  48, 220,  95,  94, 197,  11,  26,
    166, 225,  57, 202, 213,  71,  93,  61, 217,   1,  90, 214,  81,  86, 108,  77,
    139,  13, 154, 102, 251, 204, 176,  45, 116,  18,  43,  32, 240, 177, 132, 153,
    223,  76, 203, 194,  52, 126, 118,   5, 109, 183, 169,  49, 209,  23,   4, 215,
     20,  88,  58,  97, 222,  27,  17,  28,  50,  15, 156,  22,  83,  24, 242,  34,
    254,  68, 207, 178, 195, 181, 122, 145,  36,   8, 232, 168,  96, 252, 105,  80,
    170, 208, 160, 125, 161, 137,  98, 151,  84,  91,  30, 149, 224, 255, 100, 210,
     16, 196,   0,  72, 163, 247, 117, 219, 138,   3, 230, 218,   9,  63, 221, 148,
    135,  92, 131,   2, 205,  74, 144,  51, 115, 103, 246, 243, 157, 127, 191, 226,
     82, 155, 216,  38, 200,  55, 198,  59, 129, 150, 111,  75,  19, 190,  99,  46,
    233, 121, 167, 140, 159, 110, 188, 142,  41, 245, 249, 182,  47, 253, 180,  89,
    120, 152,   6, 106, 231,  70, 113, 186, 212,  37, 171,  66, 136, 162, 141, 250,
    114,   7, 185,  85, 248, 238, 172,  10,  54,  73,  42, 104,  60,  56, 241, 164,
     64,  40, 211, 123, 187, 201,  67, 193,  21, 227, 173, 244, 119, 199, 128, 158,
];

/// `SIGMA`, as 32-bit halves, as in the Java.
const SIGMA: [u32; 12] = [
    0xa09e667f, 0x3bcc908b, 0xb67ae858, 0x4caa73b2, 0xc6ef372f, 0xe94f82be, 0x54ff53a5, 0xf1d36f1c,
    0x10e527fa, 0xde682d1d, 0xb05688c2, 0xb3e6c1fd,
];

fn right_rotate(x: u32, s: u32) -> u32 {
    x.rotate_right(s)
}
fn left_rotate(x: u32, s: u32) -> u32 {
    x.rotate_left(s)
}

/// `roldq(rot, ki, ioff, ko, ooff)`: rotates the 128-bit `ki[ioff..ioff+4]` left by `rot` (< 32),
/// storing the result at `ko[ooff..ooff+4]` and back into `ki`.
fn roldq(rot: u32, ki: &mut [u32], ioff: usize, ko: &mut [u32], ooff: usize) {
    ko[ooff] = (ki[ioff] << rot) | (ki[1 + ioff] >> (32 - rot));
    ko[1 + ooff] = (ki[1 + ioff] << rot) | (ki[2 + ioff] >> (32 - rot));
    ko[2 + ooff] = (ki[2 + ioff] << rot) | (ki[3 + ioff] >> (32 - rot));
    ko[3 + ooff] = (ki[3 + ioff] << rot) | (ki[ioff] >> (32 - rot));
    ki[ioff] = ko[ooff];
    ki[1 + ioff] = ko[1 + ooff];
    ki[2 + ioff] = ko[2 + ooff];
    ki[3 + ioff] = ko[3 + ooff];
}

/// `decroldq`: as `roldq`, but the two 64-bit halves land swapped in `ko` (decryption order).
fn decroldq(rot: u32, ki: &mut [u32], ioff: usize, ko: &mut [u32], ooff: usize) {
    ko[2 + ooff] = (ki[ioff] << rot) | (ki[1 + ioff] >> (32 - rot));
    ko[3 + ooff] = (ki[1 + ioff] << rot) | (ki[2 + ioff] >> (32 - rot));
    ko[ooff] = (ki[2 + ioff] << rot) | (ki[3 + ioff] >> (32 - rot));
    ko[1 + ooff] = (ki[3 + ioff] << rot) | (ki[ioff] >> (32 - rot));
    ki[ioff] = ko[2 + ooff];
    ki[1 + ioff] = ko[3 + ooff];
    ki[2 + ioff] = ko[ooff];
    ki[3 + ioff] = ko[1 + ooff];
}

/// `roldqo32`: rotation by `rot` in 33..63 -- a word shift plus a bit rotation.
fn roldqo32(rot: u32, ki: &mut [u32], ioff: usize, ko: &mut [u32], ooff: usize) {
    ko[ooff] = (ki[1 + ioff] << (rot - 32)) | (ki[2 + ioff] >> (64 - rot));
    ko[1 + ooff] = (ki[2 + ioff] << (rot - 32)) | (ki[3 + ioff] >> (64 - rot));
    ko[2 + ooff] = (ki[3 + ioff] << (rot - 32)) | (ki[ioff] >> (64 - rot));
    ko[3 + ooff] = (ki[ioff] << (rot - 32)) | (ki[1 + ioff] >> (64 - rot));
    ki[ioff] = ko[ooff];
    ki[1 + ioff] = ko[1 + ooff];
    ki[2 + ioff] = ko[2 + ooff];
    ki[3 + ioff] = ko[3 + ooff];
}

/// `decroldqo32`: as `roldqo32`, halves swapped.
fn decroldqo32(rot: u32, ki: &mut [u32], ioff: usize, ko: &mut [u32], ooff: usize) {
    ko[2 + ooff] = (ki[1 + ioff] << (rot - 32)) | (ki[2 + ioff] >> (64 - rot));
    ko[3 + ooff] = (ki[2 + ioff] << (rot - 32)) | (ki[3 + ioff] >> (64 - rot));
    ko[ooff] = (ki[3 + ioff] << (rot - 32)) | (ki[ioff] >> (64 - rot));
    ko[1 + ooff] = (ki[ioff] << (rot - 32)) | (ki[1 + ioff] >> (64 - rot));
    ki[ioff] = ko[2 + ooff];
    ki[1 + ioff] = ko[3 + ooff];
    ki[2 + ioff] = ko[ooff];
    ki[3 + ioff] = ko[1 + ooff];
}

fn bytes2int(src: &[u8], offset: usize) -> u32 {
    let mut word = 0u32;
    for i in 0..4 {
        word = (word << 8) + src[i + offset] as u32;
    }
    word
}

fn int2bytes(mut word: u32, dst: &mut [u8], offset: usize) {
    for i in 0..4 {
        dst[(3 - i) + offset] = word as u8;
        word >>= 8;
    }
}

fn sbox1(x: u32) -> u32 {
    SBOX1[x as usize] as u32
}
/// `sbox2(x)`: `Bytes.rotateLeft(SBOX1[x], 1) & MASK8`.
fn sbox2(x: u32) -> u32 {
    SBOX1[x as usize].rotate_left(1) as u32
}
/// `sbox3(x)`: `Bytes.rotateLeft(SBOX1[x], 7) & MASK8`.
fn sbox3(x: u32) -> u32 {
    SBOX1[x as usize].rotate_left(7) as u32
}
/// `sbox4(x)`: `SBOX1[rotateLeft((byte)x, 1) & MASK8]`.
fn sbox4(x: u32) -> u32 {
    SBOX1[(x as u8).rotate_left(1) as usize] as u32
}

/// `camelliaF2(s, skey, keyoff)`: two Feistel rounds on the 32-bit-quarter state.
fn camellia_f2(s: &mut [u32; 4], skey: &[u32], keyoff: usize) {
    let mut t1 = s[0] ^ skey[keyoff];
    let mut u = sbox4(t1 & 0xff);
    u |= sbox3((t1 >> 8) & 0xff) << 8;
    u |= sbox2((t1 >> 16) & 0xff) << 16;
    u |= sbox1((t1 >> 24) & 0xff) << 24;

    let mut t2 = s[1] ^ skey[1 + keyoff];
    let mut v = sbox1(t2 & 0xff);
    v |= sbox4((t2 >> 8) & 0xff) << 8;
    v |= sbox3((t2 >> 16) & 0xff) << 16;
    v |= sbox2((t2 >> 24) & 0xff) << 24;

    v = left_rotate(v, 8);
    u ^= v;
    v = left_rotate(v, 8) ^ u;
    u = right_rotate(u, 8) ^ v;
    s[2] ^= left_rotate(v, 16) ^ u;
    s[3] ^= left_rotate(u, 8);

    t1 = s[2] ^ skey[2 + keyoff];
    u = sbox4(t1 & 0xff);
    u |= sbox3((t1 >> 8) & 0xff) << 8;
    u |= sbox2((t1 >> 16) & 0xff) << 16;
    u |= sbox1((t1 >> 24) & 0xff) << 24;

    t2 = s[3] ^ skey[3 + keyoff];
    v = sbox1(t2 & 0xff);
    v |= sbox4((t2 >> 8) & 0xff) << 8;
    v |= sbox3((t2 >> 16) & 0xff) << 16;
    v |= sbox2((t2 >> 24) & 0xff) << 24;

    v = left_rotate(v, 8);
    u ^= v;
    v = left_rotate(v, 8) ^ u;
    u = right_rotate(u, 8) ^ v;
    s[0] ^= left_rotate(v, 16) ^ u;
    s[1] ^= left_rotate(u, 8);
}

/// `camelliaFLs(s, fkey, keyoff)`: FL on the left half, FLINV on the right.
fn camellia_fls(s: &mut [u32; 4], fkey: &[u32], keyoff: usize) {
    s[1] ^= left_rotate(s[0] & fkey[keyoff], 1);
    s[0] ^= fkey[1 + keyoff] | s[1];

    s[2] ^= fkey[3 + keyoff] | s[3];
    s[3] ^= left_rotate(fkey[2 + keyoff] & s[2], 1);
}

/// The Java engine's fields after `setKey`.
pub struct Reference {
    key_size: usize,
    subkey: [u32; 24 * 4],
    kw: [u32; 4 * 2],
    ke: [u32; 6 * 2],
}

impl Reference {
    /// `setKey(forEncryption, key)`.
    pub fn new(for_encryption: bool, key: &[u8]) -> Self {
        let mut k = [0u32; 8];
        let mut ka = [0u32; 4];
        let mut kb = [0u32; 4];
        let mut t = [0u32; 4];
        let mut subkey = [0u32; 24 * 4];
        let mut kw = [0u32; 8];
        let mut ke = [0u32; 12];
        let key_size = key.len();

        match key.len() {
            16 => {
                k[0] = bytes2int(key, 0);
                k[1] = bytes2int(key, 4);
                k[2] = bytes2int(key, 8);
                k[3] = bytes2int(key, 12);
                k[4] = 0;
                k[5] = 0;
                k[6] = 0;
                k[7] = 0;
            }
            24 => {
                k[0] = bytes2int(key, 0);
                k[1] = bytes2int(key, 4);
                k[2] = bytes2int(key, 8);
                k[3] = bytes2int(key, 12);
                k[4] = bytes2int(key, 16);
                k[5] = bytes2int(key, 20);
                k[6] = !k[4];
                k[7] = !k[5];
            }
            32 => {
                for i in 0..8 {
                    k[i] = bytes2int(key, 4 * i);
                }
            }
            _ => panic!("key sizes are only 16/24/32 bytes."),
        }

        for i in 0..4 {
            ka[i] = k[i] ^ k[i + 4];
        }
        /* compute KA */
        camellia_f2(&mut ka, &SIGMA, 0);
        for i in 0..4 {
            ka[i] ^= k[i];
        }
        camellia_f2(&mut ka, &SIGMA, 4);

        if key_size == 16 {
            if for_encryption {
                /* KL dependant keys */
                kw[0] = k[0];
                kw[1] = k[1];
                kw[2] = k[2];
                kw[3] = k[3];
                roldq(15, &mut k, 0, &mut subkey, 4);
                roldq(30, &mut k, 0, &mut subkey, 12);
                roldq(15, &mut k, 0, &mut t, 0);
                subkey[18] = t[2];
                subkey[19] = t[3];
                roldq(17, &mut k, 0, &mut ke, 4);
                roldq(17, &mut k, 0, &mut subkey, 24);
                roldq(17, &mut k, 0, &mut subkey, 32);
                /* KA dependant keys */
                subkey[0] = ka[0];
                subkey[1] = ka[1];
                subkey[2] = ka[2];
                subkey[3] = ka[3];
                roldq(15, &mut ka, 0, &mut subkey, 8);
                roldq(15, &mut ka, 0, &mut ke, 0);
                roldq(15, &mut ka, 0, &mut t, 0);
                subkey[16] = t[0];
                subkey[17] = t[1];
                roldq(15, &mut ka, 0, &mut subkey, 20);
                roldqo32(34, &mut ka, 0, &mut subkey, 28);
                roldq(17, &mut ka, 0, &mut kw, 4);
            } else {
                // decryption
                /* KL dependant keys */
                kw[4] = k[0];
                kw[5] = k[1];
                kw[6] = k[2];
                kw[7] = k[3];
                decroldq(15, &mut k, 0, &mut subkey, 28);
                decroldq(30, &mut k, 0, &mut subkey, 20);
                decroldq(15, &mut k, 0, &mut t, 0);
                subkey[16] = t[0];
                subkey[17] = t[1];
                decroldq(17, &mut k, 0, &mut ke, 0);
                decroldq(17, &mut k, 0, &mut subkey, 8);
                decroldq(17, &mut k, 0, &mut subkey, 0);
                /* KA dependant keys */
                subkey[34] = ka[0];
                subkey[35] = ka[1];
                subkey[32] = ka[2];
                subkey[33] = ka[3];
                decroldq(15, &mut ka, 0, &mut subkey, 24);
                decroldq(15, &mut ka, 0, &mut ke, 4);
                decroldq(15, &mut ka, 0, &mut t, 0);
                subkey[18] = t[2];
                subkey[19] = t[3];
                decroldq(15, &mut ka, 0, &mut subkey, 12);
                decroldqo32(34, &mut ka, 0, &mut subkey, 4);
                roldq(17, &mut ka, 0, &mut kw, 0);
            }
        } else {
            // 192bit or 256bit
            /* compute KB */
            for i in 0..4 {
                kb[i] = ka[i] ^ k[i + 4];
            }
            camellia_f2(&mut kb, &SIGMA, 8);

            if for_encryption {
                /* KL dependant keys */
                kw[0] = k[0];
                kw[1] = k[1];
                kw[2] = k[2];
                kw[3] = k[3];
                roldqo32(45, &mut k, 0, &mut subkey, 16);
                roldq(15, &mut k, 0, &mut ke, 4);
                roldq(17, &mut k, 0, &mut subkey, 32);
                roldqo32(34, &mut k, 0, &mut subkey, 44);
                /* KR dependant keys */
                roldq(15, &mut k, 4, &mut subkey, 4);
                roldq(15, &mut k, 4, &mut ke, 0);
                roldq(30, &mut k, 4, &mut subkey, 24);
                roldqo32(34, &mut k, 4, &mut subkey, 36);
                /* KA dependant keys */
                roldq(15, &mut ka, 0, &mut subkey, 8);
                roldq(30, &mut ka, 0, &mut subkey, 20);
                /* 32bit rotation */
                ke[8] = ka[1];
                ke[9] = ka[2];
                ke[10] = ka[3];
                ke[11] = ka[0];
                roldqo32(49, &mut ka, 0, &mut subkey, 40);

                /* KB dependant keys */
                subkey[0] = kb[0];
                subkey[1] = kb[1];
                subkey[2] = kb[2];
                subkey[3] = kb[3];
                roldq(30, &mut kb, 0, &mut subkey, 12);
                roldq(30, &mut kb, 0, &mut subkey, 28);
                roldqo32(51, &mut kb, 0, &mut kw, 4);
            } else {
                // decryption
                /* KL dependant keys */
                kw[4] = k[0];
                kw[5] = k[1];
                kw[6] = k[2];
                kw[7] = k[3];
                decroldqo32(45, &mut k, 0, &mut subkey, 28);
                decroldq(15, &mut k, 0, &mut ke, 4);
                decroldq(17, &mut k, 0, &mut subkey, 12);
                decroldqo32(34, &mut k, 0, &mut subkey, 0);
                /* KR dependant keys */
                decroldq(15, &mut k, 4, &mut subkey, 40);
                decroldq(15, &mut k, 4, &mut ke, 8);
                decroldq(30, &mut k, 4, &mut subkey, 20);
                decroldqo32(34, &mut k, 4, &mut subkey, 8);
                /* KA dependant keys */
                decroldq(15, &mut ka, 0, &mut subkey, 36);
                decroldq(30, &mut ka, 0, &mut subkey, 24);
                /* 32bit rotation */
                ke[2] = ka[1];
                ke[3] = ka[2];
                ke[0] = ka[3];
                ke[1] = ka[0];
                decroldqo32(49, &mut ka, 0, &mut subkey, 4);

                /* KB dependant keys */
                subkey[46] = kb[0];
                subkey[47] = kb[1];
                subkey[44] = kb[2];
                subkey[45] = kb[3];
                decroldq(30, &mut kb, 0, &mut subkey, 32);
                decroldq(30, &mut kb, 0, &mut subkey, 16);
                roldqo32(51, &mut kb, 0, &mut kw, 0);
            }
        }

        Self { key_size, subkey, kw, ke }
    }

    /// `processBlock`: `processBlock128` or `processBlock192or256` by key size.
    pub fn process_block(&self, input: &[u8; 16], out: &mut [u8; 16]) {
        let mut state = [0u32; 4];
        for i in 0..4 {
            state[i] = bytes2int(input, i * 4) ^ self.kw[i];
        }

        camellia_f2(&mut state, &self.subkey, 0);
        camellia_f2(&mut state, &self.subkey, 4);
        camellia_f2(&mut state, &self.subkey, 8);
        camellia_fls(&mut state, &self.ke, 0);
        camellia_f2(&mut state, &self.subkey, 12);
        camellia_f2(&mut state, &self.subkey, 16);
        camellia_f2(&mut state, &self.subkey, 20);
        camellia_fls(&mut state, &self.ke, 4);
        camellia_f2(&mut state, &self.subkey, 24);
        camellia_f2(&mut state, &self.subkey, 28);
        camellia_f2(&mut state, &self.subkey, 32);
        if self.key_size != 16 {
            camellia_fls(&mut state, &self.ke, 8);
            camellia_f2(&mut state, &self.subkey, 36);
            camellia_f2(&mut state, &self.subkey, 40);
            camellia_f2(&mut state, &self.subkey, 44);
        }

        state[2] ^= self.kw[4];
        state[3] ^= self.kw[5];
        state[0] ^= self.kw[6];
        state[1] ^= self.kw[7];

        int2bytes(state[2], out, 0);
        int2bytes(state[3], out, 4);
        int2bytes(state[0], out, 8);
        int2bytes(state[1], out, 12);
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
