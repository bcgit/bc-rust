//! The key scheduling part (RFC 5794 Sec 2.2), and the parameter sets that distinguish the three
//! key lengths.
//!
//! The schedule is the encryption round keys `ek1 .. ek{n+1}` -- 13, 15 or 17 of them, 16 bytes
//! each (208, 240 or 272 bytes) -- computed once by [`expand`] and stored in a [`Secret`].
//! Decryption round keys are derived from them (Sec 2.2: `dk1 = ek{n+1}`, `dk{i} = A(ek{n+2-i})`
//! for `i = 2 .. n`, `dk{n+1} = ek1`), and this port derives them *at use*: one application of the
//! diffusion layer `A` per round, cheap next to the substitution layer, rather than a second
//! stored schedule. BC Java's `ARIAEngine` instead lays the keys out for the direction requested
//! at `init`.
//!
//! # Layout
//!
//! One flat `[u32; 4 * (ROUNDS + 1)]`: `ek_i` is the four big-endian words at
//! `[4 * (i - 1) .. 4 * i]`. [`ek`] takes the RFC's 1-based index.
//!
//! # Constant-time
//!
//! The schedule routes secret key material through `FO` and `FE` three times, so the expansion
//! needs the same treatment as the cipher: those calls go through the bit-sliced S-box circuits of
//! [`crate::sbox`], not tables. The rest of the schedule is XORs and rotations of 128-bit values
//! by public amounts.

use crate::round::{RoundKey, State, fe1, fo1};
use bouncycastle_utils::secret::{Secret, ZeroizablePrimitive};

/// Sealed: the three parameter sets are the only implementors.
mod sealed {
    pub trait ARIAParamsInternalTrait {}
}
pub(crate) use sealed::ARIAParamsInternalTrait;

/// The parameters that distinguish ARIA-128 from ARIA-192 and ARIA-256 (RFC 5794 Sec 2.2).
///
/// Sealed: implemented by [`ARIA128Params`], [`ARIA192Params`] and [`ARIA256Params`] only, so
/// there is no fourth instantiation.
pub trait ARIAParams: ARIAParamsInternalTrait {
    /// Key length in bytes: 16, 24 or 32.
    const KEY_LEN: usize;
    /// Number of rounds: 12, 14 or 16 (Sec 2.2, "Key size / Number of Rounds").
    const ROUNDS: usize;
    /// `CK1, CK2, CK3` as indices into `C` (Sec 2.2's table: `C1 C2 C3` for 128-bit keys,
    /// `C2 C3 C1` for 192, `C3 C1 C2` for 256).
    const CK: [usize; 3];
    /// The algorithm name, as reported by `Algorithm::ALG_NAME`.
    const ALG_NAME: &'static str;
    /// `[u32; 4 * (ROUNDS + 1)]` -- the encryption round keys. See the module docs for the layout.
    type Schedule: ZeroizablePrimitive + AsRef<[u32]> + AsMut<[u32]>;
}

/// ARIA-128 parameters: 16-byte key, 12 rounds, `CK = (C1, C2, C3)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ARIA128Params;
/// ARIA-192 parameters: 24-byte key, 14 rounds, `CK = (C2, C3, C1)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ARIA192Params;
/// ARIA-256 parameters: 32-byte key, 16 rounds, `CK = (C3, C1, C2)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ARIA256Params;

impl ARIAParamsInternalTrait for ARIA128Params {}
impl ARIAParamsInternalTrait for ARIA192Params {}
impl ARIAParamsInternalTrait for ARIA256Params {}

impl ARIAParams for ARIA128Params {
    const KEY_LEN: usize = 16;
    const ROUNDS: usize = 12;
    const CK: [usize; 3] = [0, 1, 2];
    const ALG_NAME: &'static str = "ARIA-128";
    type Schedule = [u32; 52]; // 4 * (12 + 1)
}

impl ARIAParams for ARIA192Params {
    const KEY_LEN: usize = 24;
    const ROUNDS: usize = 14;
    const CK: [usize; 3] = [1, 2, 0];
    const ALG_NAME: &'static str = "ARIA-192";
    type Schedule = [u32; 60]; // 4 * (14 + 1)
}

impl ARIAParams for ARIA256Params {
    const KEY_LEN: usize = 32;
    const ROUNDS: usize = 16;
    const CK: [usize; 3] = [2, 0, 1];
    const ALG_NAME: &'static str = "ARIA-256";
    type Schedule = [u32; 68]; // 4 * (16 + 1)
}

/// `C1, C2, C3` (Sec 2.2): "the first 128*3 bits of the fractional part of 1/PI". Transcribed from
/// the text of RFC 5794; identical to the `C` array of BC Java's `ARIAEngine`.
pub(crate) const C: [u128; 3] = [
    0x517c_c1b7_2722_0a94_fe13_abe8_fa9a_6ee0,
    0x6db1_4acc_9e21_c820_ff28_b1d5_ef5d_e2b0,
    0xdb92_371d_2126_e970_0324_9775_04e8_c90e,
];

/// A 128-bit value as four big-endian row words.
#[inline(always)]
fn to_state(v: u128) -> State {
    let b = v.to_be_bytes();
    let (words, _) = b.as_chunks::<4>();
    core::array::from_fn(|i| u32::from_be_bytes(words[i]))
}

/// Four big-endian row words as a 128-bit value.
#[inline(always)]
fn to_u128(s: &State) -> u128 {
    let mut b = [0u8; 16];
    for (chunk, w) in b.as_chunks_mut::<4>().0.iter_mut().zip(s.iter()) {
        *chunk = w.to_be_bytes();
    }
    u128::from_be_bytes(b)
}

/// `ek_i`, `i` in `1 ..= ROUNDS + 1`, as a round key.
#[inline(always)]
pub(crate) fn ek(schedule: &[u32], i: usize) -> RoundKey {
    let base = 4 * (i - 1);
    [schedule[base], schedule[base + 1], schedule[base + 2], schedule[base + 3]]
}

/// Expands a key into the encryption round keys (Sec 2.2). `key` is exactly `P::KEY_LEN` bytes --
/// the engine checks that before calling.
///
/// Line by line against Sec 2.2:
///
/// * `KL || KR = K || 0 ... 0` -- `KL` is the leftmost 128 bits of `K`, `KR` the rest,
///   right-padded with zeros to 128 bits;
/// * `W0 = KL; W1 = FO(W0, CK1) ^ KR; W2 = FE(W1, CK2) ^ W0; W3 = FO(W2, CK3) ^ W1` -- the
///   "3-round, 256-bit Feistel cipher" with the constants `CK1 .. CK3` chosen by key length;
/// * `ek1 = W0 ^ (W1 >>> 19)`, `ek2 = W1 ^ (W2 >>> 19)`, `ek3 = W2 ^ (W3 >>> 19)`,
///   `ek4 = (W0 >>> 19) ^ W3`, then the same four pairings with `>>> 31`, `<<< 61`, `<<< 31`,
///   and `ek17 = W0 ^ (W1 <<< 19)` -- of which only the first `ROUNDS + 1` are kept.
///
/// `KL`, `KR` and `W0 .. W3` are held in a `Secret` so they are scrubbed on return.
pub(crate) fn expand<P: ARIAParams>(key: &[u8]) -> Secret<P::Schedule> {
    // KL || KR = K || 0...0: copy the key into a zeroed 32-byte buffer.
    let mut kbuf = Secret::<[u8; 32]>::new();
    kbuf[..key.len()].copy_from_slice(key);
    // [KL, KR, W0, W1, W2, W3]
    let mut w = Secret::<[u128; 6]>::new();
    w[0] = u128::from_be_bytes(kbuf[..16].try_into().expect("16 bytes")); // KL
    w[1] = u128::from_be_bytes(kbuf[16..].try_into().expect("16 bytes")); // KR (zero-padded)
    let ck: [RoundKey; 3] = core::array::from_fn(|i| to_state(C[P::CK[i]]));
    w[2] = w[0]; // W0 = KL
    w[3] = to_u128(&fo1(to_state(w[2]), &ck[0])) ^ w[1]; // W1 = FO(W0, CK1) ^ KR
    w[4] = to_u128(&fe1(to_state(w[3]), &ck[1])) ^ w[2]; // W2 = FE(W1, CK2) ^ W0
    w[5] = to_u128(&fo1(to_state(w[4]), &ck[2])) ^ w[3]; // W3 = FO(W2, CK3) ^ W1
    let (w0, w1, w2, w3) = (w[2], w[3], w[4], w[5]);

    // The 17 candidate round keys, in order; the schedule keeps the first ROUNDS + 1.
    let all: [u128; 17] = [
        w0 ^ w1.rotate_right(19), // ek1  = W0 ^ (W1 >>> 19)
        w1 ^ w2.rotate_right(19), // ek2  = W1 ^ (W2 >>> 19)
        w2 ^ w3.rotate_right(19), // ek3  = W2 ^ (W3 >>> 19)
        w0.rotate_right(19) ^ w3, // ek4  = (W0 >>> 19) ^ W3
        w0 ^ w1.rotate_right(31), // ek5  = W0 ^ (W1 >>> 31)
        w1 ^ w2.rotate_right(31), // ek6  = W1 ^ (W2 >>> 31)
        w2 ^ w3.rotate_right(31), // ek7  = W2 ^ (W3 >>> 31)
        w0.rotate_right(31) ^ w3, // ek8  = (W0 >>> 31) ^ W3
        w0 ^ w1.rotate_left(61),  // ek9  = W0 ^ (W1 <<< 61)
        w1 ^ w2.rotate_left(61),  // ek10 = W1 ^ (W2 <<< 61)
        w2 ^ w3.rotate_left(61),  // ek11 = W2 ^ (W3 <<< 61)
        w0.rotate_left(61) ^ w3,  // ek12 = (W0 <<< 61) ^ W3
        w0 ^ w1.rotate_left(31),  // ek13 = W0 ^ (W1 <<< 31)
        w1 ^ w2.rotate_left(31),  // ek14 = W1 ^ (W2 <<< 31)
        w2 ^ w3.rotate_left(31),  // ek15 = W2 ^ (W3 <<< 31)
        w0.rotate_left(31) ^ w3,  // ek16 = (W0 <<< 31) ^ W3
        w0 ^ w1.rotate_left(19),  // ek17 = W0 ^ (W1 <<< 19)
    ];
    let mut schedule = Secret::<P::Schedule>::new();
    for (i, chunk) in schedule.as_mut().as_chunks_mut::<4>().0.iter_mut().enumerate() {
        *chunk = to_state(all[i]);
    }
    schedule
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schedule_lengths_and_ck_orders() {
        assert_eq!(size_of::<<ARIA128Params as ARIAParams>::Schedule>(), 4 * 4 * 13);
        assert_eq!(size_of::<<ARIA192Params as ARIAParams>::Schedule>(), 4 * 4 * 15);
        assert_eq!(size_of::<<ARIA256Params as ARIAParams>::Schedule>(), 4 * 4 * 17);
        // Sec 2.2's table: 128 -> C1 C2 C3, 192 -> C2 C3 C1, 256 -> C3 C1 C2.
        assert_eq!(ARIA128Params::CK, [0, 1, 2]);
        assert_eq!(ARIA192Params::CK, [1, 2, 0]);
        assert_eq!(ARIA256Params::CK, [2, 0, 1]);
    }

    #[test]
    fn test_constants_match_section_2_2() {
        assert_eq!(C[0], 0x517cc1b727220a94fe13abe8fa9a6ee0);
        assert_eq!(C[1], 0x6db14acc9e21c820ff28b1d5ef5de2b0);
        assert_eq!(C[2], 0xdb92371d2126e9700324977504e8c90e);
    }

    #[test]
    fn test_state_conversions_round_trip() {
        let v = 0x0001_0203_0405_0607_0809_0a0b_0c0d_0e0fu128;
        assert_eq!(to_state(v), [0x0001_0203, 0x0405_0607, 0x0809_0a0b, 0x0c0d_0e0f]);
        assert_eq!(to_u128(&to_state(v)), v);
    }

    /// Appendix A.1 (128-bit key): the round key generators `W0 .. W3` and all thirteen
    /// encryption round keys, transcribed from the RFC.
    #[test]
    fn test_appendix_a_1_round_keys() {
        let key: [u8; 16] = core::array::from_fn(|i| i as u8);
        let s = expand::<ARIA128Params>(&key);
        let expected: [u128; 13] = [
            0xd415a75c794b85c5e0d2a0b3cb793bf6,
            0x369c65e4b11777ab713a3e1e6601b8f4,
            0x0368d4f13d14497b6529ad7ac809e7d0,
            0xc644552b549a263fb8d0b50906229eec,
            0x5f9c434951f2d2ef342787b1a781794c,
            0xafea2c0ce71db6de42a47461f4323c54,
            0x324286db44ba4db6c44ac306f2a84b2c,
            0x7f9fa93574d842b9101a58063771eb7b,
            0xaab9c57731fcd213ad5677458fcfe6d4,
            0x2f4423bb06465abada5694a19eb88459,
            0x9f8772808f5d580d810ef8ddac13abeb,
            0x8684946a155be77ef810744847e35fad,
            0x0f0aa16daee61bd7dfee5a599970fb35,
        ];
        for (i, want) in expected.iter().enumerate() {
            assert_eq!(to_u128(&ek(s.as_ref(), i + 1)), *want, "ek{}", i + 1);
        }
        // W0 .. W3 are not stored, but ek1 = W0 ^ (W1 >>> 19) with W0 = KL pins W1, and so on.
        let w0 = 0x000102030405060708090a0b0c0d0e0fu128;
        let w1 = 0x2afbea741e1746dd55c63ba1afcea0a5u128;
        let w2 = 0x7c8578018bb127e02dfe4e78c288e33cu128;
        let w3 = 0x6785b52b74da46bf181054082763ff6du128;
        assert_eq!(expected[0], w0 ^ w1.rotate_right(19));
        assert_eq!(expected[1], w1 ^ w2.rotate_right(19));
        assert_eq!(expected[2], w2 ^ w3.rotate_right(19));
        assert_eq!(expected[3], w0.rotate_right(19) ^ w3);
        assert_eq!(expected[12], w0 ^ w1.rotate_left(31));
    }

    #[test]
    fn test_longer_keys_use_more_round_keys() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let s128 = expand::<ARIA128Params>(&key[..16]);
        let s192 = expand::<ARIA192Params>(&key[..24]);
        let s256 = expand::<ARIA256Params>(&key);
        assert_eq!(s128.as_ref().len(), 52);
        assert_eq!(s192.as_ref().len(), 60);
        assert_eq!(s256.as_ref().len(), 68);
        // Different CK orders: the schedules differ even where the key bytes agree.
        assert_ne!(ek(s128.as_ref(), 1), ek(s192.as_ref(), 1));
        assert_ne!(ek(s192.as_ref(), 1), ek(s256.as_ref(), 1));
    }
}
