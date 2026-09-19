//! The key scheduling part (RFC 3713 Sec 2.2), and the parameter sets that distinguish the three
//! key lengths.
//!
//! The schedule is the whole set of 64-bit subkeys the data randomizing part reads: the four
//! whitening keys `kw1 .. kw4`, the 18 or 24 round keys `k1 .. k18` / `k1 .. k24`, and the four or
//! six FL/FLINV keys `ke1 .. ke4` / `ke1 .. ke6` -- 26 words (208 bytes) for a 128-bit key, 34
//! words (272 bytes) for 192- and 256-bit keys. It is computed once by [`expand`] and stored in a
//! [`Secret`]. Decryption uses the same words in the swapped order of Sec 2.3.3, so there is no
//! second schedule: this crate stores the encryption order and lets
//! [`crate::Camellia::decrypt_4blocks`] index it the other way, rather than writing the subkeys
//! into decryption positions when initialised for decryption.
//!
//! # Layout
//!
//! One flat `[u64; N]`, in the RFC's numbering: `kw_i` at `[i - 1]`, `k_i` at `[3 + i]`, `ke_i`
//! at `[3 + ROUNDS + i]`. The accessors [`kw`], [`k`] and [`ke`] take the RFC's 1-based index so
//! that the round loop and the Sec 2.3.3 swap can be read against the text.
//!
//! # Constant-time
//!
//! The schedule routes secret key material through the F-function -- six times, with the `Sigma`
//! constants as the keys -- so the expansion needs the same treatment as the cipher: [`f1`] is the
//! bit-sliced circuit of [`crate::sbox`], not a table. The rest of the schedule is rotations of
//! 128-bit values by public amounts.

use crate::round::f1;
use bouncycastle_utils::secret::{Secret, ZeroizablePrimitive};

/// Sealed: the three parameter sets are the only implementors.
mod sealed {
    pub trait CamelliaParamsInternalTrait {}
}
pub(crate) use sealed::CamelliaParamsInternalTrait;

/// The parameters that distinguish Camellia-128 from Camellia-192 and Camellia-256
/// (RFC 3713 Sec 2.2 and Sec 2.3).
///
/// Sealed: implemented by `Camellia128Params`, `Camellia192Params` and `Camellia256Params`
/// only, so there is no fourth instantiation.
pub trait CamelliaParams: CamelliaParamsInternalTrait {
    /// Key length in bytes: 16, 24 or 32.
    const KEY_LEN: usize;
    /// Rounds of the Feistel structure: 18 for 128-bit keys (Sec 2.3.1), 24 otherwise (Sec 2.3.2).
    const ROUNDS: usize;
    /// FL/FLINV subkeys: `ke1 .. ke4` for 18 rounds, `ke1 .. ke6` for 24 -- one pair per FL layer,
    /// a layer every six rounds except after the last.
    const FL_KEYS: usize;
    /// The algorithm name, as reported by `Algorithm::ALG_NAME`.
    const ALG_NAME: &'static str;
    /// `[u64; 4 + ROUNDS + FL_KEYS]` -- the subkeys. See the module docs for the layout.
    type Schedule: ZeroizablePrimitive + AsRef<[u64]> + AsMut<[u64]>;

    /// `KL` and `KR` from the key (Sec 2.2, "128-bit key K:" / "192-bit key K:" / "256-bit key
    /// K:"). `k` is the key as big-endian 64-bit words, `KEY_LEN / 8` of them -- the engine checks
    /// the length before calling, so the indexing here is in bounds by construction.
    fn kl_kr(k: &[u64]) -> (u128, u128);

    /// Fills the schedule from `KL`, `KR`, `KA`, `KB` (Sec 2.2, the subkey tables).
    fn subkeys(kl: u128, kr: u128, ka: u128, kb: u128, schedule: &mut [u64]);
}

/// Camellia-128 parameters: 16-byte key, 18 rounds, `ke1 .. ke4`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Camellia128Params;
/// Camellia-192 parameters: 24-byte key, 24 rounds, `ke1 .. ke6`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Camellia192Params;
/// Camellia-256 parameters: 32-byte key, 24 rounds, `ke1 .. ke6`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Camellia256Params;

impl CamelliaParamsInternalTrait for Camellia128Params {}
impl CamelliaParamsInternalTrait for Camellia192Params {}
impl CamelliaParamsInternalTrait for Camellia256Params {}

/// `(hi << 64) | lo`: joins two 64-bit words into a 128-bit value.
///
/// The two operands occupy disjoint bit ranges, so `|` and `^` compute the same function here;
/// `cargo mutants` reports that `| -> ^` mutant as surviving, and it is an equivalence, not a gap.
#[inline(always)]
fn join(hi: u64, lo: u64) -> u128 {
    ((hi as u128) << 64) | lo as u128
}

impl CamelliaParams for Camellia128Params {
    const KEY_LEN: usize = 16;
    const ROUNDS: usize = 18;
    const FL_KEYS: usize = 4;
    const ALG_NAME: &'static str = "Camellia-128";
    type Schedule = [u64; 26]; // 4 + 18 + 4

    /// `KL = K; KR = 0;`
    fn kl_kr(k: &[u64]) -> (u128, u128) {
        (join(k[0], k[1]), 0)
    }

    fn subkeys(kl: u128, kr: u128, ka: u128, kb: u128, schedule: &mut [u64]) {
        subkeys_128(kl, kr, ka, kb, schedule)
    }
}

impl CamelliaParams for Camellia192Params {
    const KEY_LEN: usize = 24;
    const ROUNDS: usize = 24;
    const FL_KEYS: usize = 6;
    const ALG_NAME: &'static str = "Camellia-192";
    type Schedule = [u64; 34]; // 4 + 24 + 6

    /// `KL = K >> 64; KR = ((K & MASK64) << 64) | (~(K & MASK64));` -- the leftmost 128 bits are
    /// `KL`, and `KR` is the rightmost 64 bits followed by their complement.
    fn kl_kr(k: &[u64]) -> (u128, u128) {
        (join(k[0], k[1]), join(k[2], !k[2]))
    }

    fn subkeys(kl: u128, kr: u128, ka: u128, kb: u128, schedule: &mut [u64]) {
        subkeys_192_256(kl, kr, ka, kb, schedule)
    }
}

impl CamelliaParams for Camellia256Params {
    const KEY_LEN: usize = 32;
    const ROUNDS: usize = 24;
    const FL_KEYS: usize = 6;
    const ALG_NAME: &'static str = "Camellia-256";
    type Schedule = [u64; 34]; // 4 + 24 + 6

    /// `KL = K >> 128; KR = K & MASK128;`
    fn kl_kr(k: &[u64]) -> (u128, u128) {
        (join(k[0], k[1]), join(k[2], k[3]))
    }

    fn subkeys(kl: u128, kr: u128, ka: u128, kb: u128, schedule: &mut [u64]) {
        subkeys_192_256(kl, kr, ka, kb, schedule)
    }
}

/// `Sigma1 .. Sigma6` (Sec 2.2), "used as 'keys' in the F-function" when deriving `KA` and `KB`.
/// Transcribed from the text of RFC 3713.
pub(crate) const SIGMA: [u64; 6] = [
    0xA09E_667F_3BCC_908B, 0xB67A_E858_4CAA_73B2, 0xC6EF_372F_E94F_82BE, 0x54FF_53A5_F1D3_6F1C,
    0x10E5_27FA_DE68_2D1D, 0xB056_88C2_B3E6_C1FD,
];

/// `kw_i`, `i` in `1..=4`.
#[inline(always)]
pub(crate) fn kw(schedule: &[u64], i: usize) -> u64 {
    schedule[i - 1]
}

/// `k_i`, `i` in `1..=ROUNDS`.
#[inline(always)]
pub(crate) fn k(schedule: &[u64], i: usize) -> u64 {
    schedule[3 + i]
}

/// `ke_i`, `i` in `1..=FL_KEYS`.
#[inline(always)]
pub(crate) fn ke<P: CamelliaParams>(schedule: &[u64], i: usize) -> u64 {
    schedule[3 + P::ROUNDS + i]
}

/// `(X <<< rot) >> 64`: the left half of a rotated 128-bit value.
#[inline(always)]
fn left(x: u128, rot: u32) -> u64 {
    (x.rotate_left(rot) >> 64) as u64
}

/// `(X <<< rot) & MASK64`: the right half of a rotated 128-bit value.
#[inline(always)]
fn right(x: u128, rot: u32) -> u64 {
    x.rotate_left(rot) as u64
}

/// Sec 2.2, "For 128-bit keys, 64-bit subkeys kw1, ..., kw4, k1, ..., k18, ke1, ..., ke4 are
/// generated as follows." One line per line of the RFC; `KR` and `KB` are unused, as the text
/// says ("KB is used only if the length of the secret key is 192 or 256 bits").
fn subkeys_128(kl: u128, _kr: u128, ka: u128, _kb: u128, s: &mut [u64]) {
    let mut set_kw = |i: usize, v: u64| s[i - 1] = v;
    set_kw(1, left(kl, 0)); // kw1 = (KL <<<   0) >> 64;
    set_kw(2, right(kl, 0)); // kw2 = (KL <<<   0) & MASK64;
    let mut set_k = |i: usize, v: u64| s[3 + i] = v;
    set_k(1, left(ka, 0)); // k1  = (KA <<<   0) >> 64;
    set_k(2, right(ka, 0)); // k2  = (KA <<<   0) & MASK64;
    set_k(3, left(kl, 15)); // k3  = (KL <<<  15) >> 64;
    set_k(4, right(kl, 15)); // k4  = (KL <<<  15) & MASK64;
    set_k(5, left(ka, 15)); // k5  = (KA <<<  15) >> 64;
    set_k(6, right(ka, 15)); // k6  = (KA <<<  15) & MASK64;
    let mut set_ke = |i: usize, v: u64| s[3 + 18 + i] = v;
    set_ke(1, left(ka, 30)); // ke1 = (KA <<<  30) >> 64;
    set_ke(2, right(ka, 30)); // ke2 = (KA <<<  30) & MASK64;
    let mut set_k = |i: usize, v: u64| s[3 + i] = v;
    set_k(7, left(kl, 45)); // k7  = (KL <<<  45) >> 64;
    set_k(8, right(kl, 45)); // k8  = (KL <<<  45) & MASK64;
    set_k(9, left(ka, 45)); // k9  = (KA <<<  45) >> 64;
    set_k(10, right(kl, 60)); // k10 = (KL <<<  60) & MASK64;
    set_k(11, left(ka, 60)); // k11 = (KA <<<  60) >> 64;
    set_k(12, right(ka, 60)); // k12 = (KA <<<  60) & MASK64;
    let mut set_ke = |i: usize, v: u64| s[3 + 18 + i] = v;
    set_ke(3, left(kl, 77)); // ke3 = (KL <<<  77) >> 64;
    set_ke(4, right(kl, 77)); // ke4 = (KL <<<  77) & MASK64;
    let mut set_k = |i: usize, v: u64| s[3 + i] = v;
    set_k(13, left(kl, 94)); // k13 = (KL <<<  94) >> 64;
    set_k(14, right(kl, 94)); // k14 = (KL <<<  94) & MASK64;
    set_k(15, left(ka, 94)); // k15 = (KA <<<  94) >> 64;
    set_k(16, right(ka, 94)); // k16 = (KA <<<  94) & MASK64;
    set_k(17, left(kl, 111)); // k17 = (KL <<< 111) >> 64;
    set_k(18, right(kl, 111)); // k18 = (KL <<< 111) & MASK64;
    let mut set_kw = |i: usize, v: u64| s[i - 1] = v;
    set_kw(3, left(ka, 111)); // kw3 = (KA <<< 111) >> 64;
    set_kw(4, right(ka, 111)); // kw4 = (KA <<< 111) & MASK64;
}

/// Sec 2.2, "For 192- and 256-bit keys, 64-bit subkeys kw1, ..., kw4, k1, ..., k24, ke1, ...,
/// ke6 are generated as follows." One line per line of the RFC.
fn subkeys_192_256(kl: u128, kr: u128, ka: u128, kb: u128, s: &mut [u64]) {
    let mut set_kw = |i: usize, v: u64| s[i - 1] = v;
    set_kw(1, left(kl, 0)); // kw1 = (KL <<<   0) >> 64;
    set_kw(2, right(kl, 0)); // kw2 = (KL <<<   0) & MASK64;
    let mut set_k = |i: usize, v: u64| s[3 + i] = v;
    set_k(1, left(kb, 0)); // k1  = (KB <<<   0) >> 64;
    set_k(2, right(kb, 0)); // k2  = (KB <<<   0) & MASK64;
    set_k(3, left(kr, 15)); // k3  = (KR <<<  15) >> 64;
    set_k(4, right(kr, 15)); // k4  = (KR <<<  15) & MASK64;
    set_k(5, left(ka, 15)); // k5  = (KA <<<  15) >> 64;
    set_k(6, right(ka, 15)); // k6  = (KA <<<  15) & MASK64;
    let mut set_ke = |i: usize, v: u64| s[3 + 24 + i] = v;
    set_ke(1, left(kr, 30)); // ke1 = (KR <<<  30) >> 64;
    set_ke(2, right(kr, 30)); // ke2 = (KR <<<  30) & MASK64;
    let mut set_k = |i: usize, v: u64| s[3 + i] = v;
    set_k(7, left(kb, 30)); // k7  = (KB <<<  30) >> 64;
    set_k(8, right(kb, 30)); // k8  = (KB <<<  30) & MASK64;
    set_k(9, left(kl, 45)); // k9  = (KL <<<  45) >> 64;
    set_k(10, right(kl, 45)); // k10 = (KL <<<  45) & MASK64;
    set_k(11, left(ka, 45)); // k11 = (KA <<<  45) >> 64;
    set_k(12, right(ka, 45)); // k12 = (KA <<<  45) & MASK64;
    let mut set_ke = |i: usize, v: u64| s[3 + 24 + i] = v;
    set_ke(3, left(kl, 60)); // ke3 = (KL <<<  60) >> 64;
    set_ke(4, right(kl, 60)); // ke4 = (KL <<<  60) & MASK64;
    let mut set_k = |i: usize, v: u64| s[3 + i] = v;
    set_k(13, left(kr, 60)); // k13 = (KR <<<  60) >> 64;
    set_k(14, right(kr, 60)); // k14 = (KR <<<  60) & MASK64;
    set_k(15, left(kb, 60)); // k15 = (KB <<<  60) >> 64;
    set_k(16, right(kb, 60)); // k16 = (KB <<<  60) & MASK64;
    set_k(17, left(kl, 77)); // k17 = (KL <<<  77) >> 64;
    set_k(18, right(kl, 77)); // k18 = (KL <<<  77) & MASK64;
    let mut set_ke = |i: usize, v: u64| s[3 + 24 + i] = v;
    set_ke(5, left(ka, 77)); // ke5 = (KA <<<  77) >> 64;
    set_ke(6, right(ka, 77)); // ke6 = (KA <<<  77) & MASK64;
    let mut set_k = |i: usize, v: u64| s[3 + i] = v;
    set_k(19, left(kr, 94)); // k19 = (KR <<<  94) >> 64;
    set_k(20, right(kr, 94)); // k20 = (KR <<<  94) & MASK64;
    set_k(21, left(ka, 94)); // k21 = (KA <<<  94) >> 64;
    set_k(22, right(ka, 94)); // k22 = (KA <<<  94) & MASK64;
    set_k(23, left(kl, 111)); // k23 = (KL <<< 111) >> 64;
    set_k(24, right(kl, 111)); // k24 = (KL <<< 111) & MASK64;
    let mut set_kw = |i: usize, v: u64| s[i - 1] = v;
    set_kw(3, left(kb, 111)); // kw3 = (KB <<< 111) >> 64;
    set_kw(4, right(kb, 111)); // kw4 = (KB <<< 111) & MASK64;
}

/// Expands a key into the subkeys (Sec 2.2). `key` is exactly `P::KEY_LEN` bytes -- the engine
/// checks that before calling.
///
/// Line by line against Sec 2.2, "The 128-bit variables KA and KB are generated from KL and KR as
/// follows":
///
/// ```text
/// D1 = (KL ^ KR) >> 64;      D2 = (KL ^ KR) & MASK64;
/// D2 = D2 ^ F(D1, Sigma1);   D1 = D1 ^ F(D2, Sigma2);
/// D1 = D1 ^ (KL >> 64);      D2 = D2 ^ (KL & MASK64);
/// D2 = D2 ^ F(D1, Sigma3);   D1 = D1 ^ F(D2, Sigma4);
/// KA = (D1 << 64) | D2;
/// D1 = (KA ^ KR) >> 64;      D2 = (KA ^ KR) & MASK64;
/// D2 = D2 ^ F(D1, Sigma5);   D1 = D1 ^ F(D2, Sigma6);
/// KB = (D1 << 64) | D2;
/// ```
///
/// `KB` is computed for every key length, although Sec 2.2 notes it "is used only if the length of
/// the secret key is 192 or 256 bits": two F-function calls, once per key, buy a single code path
/// with no length-dependent branch. Then the subkey table for the key length fills the schedule.
pub(crate) fn expand<P: CamelliaParams>(key: &[u8]) -> Secret<P::Schedule> {
    // The key as big-endian 64-bit words. KEY_LEN is a multiple of eight, so the remainder is
    // provably empty and ignored.
    let (words, _) = key.as_chunks::<8>();
    let mut k = Secret::<[u64; 4]>::new();
    for (w, bytes) in k.iter_mut().zip(words) {
        *w = u64::from_be_bytes(*bytes);
    }

    // KL, KR, and then KA, KB, held in a Secret so they are scrubbed on return.
    let mut kx = Secret::<[u128; 4]>::new();
    (kx[0], kx[1]) = P::kl_kr(&k[..P::KEY_LEN / 8]);
    let (kl, kr) = (kx[0], kx[1]);

    // D1, D2: 64-bit temporaries, likewise.
    let mut d = Secret::<[u64; 2]>::new();
    d[0] = ((kl ^ kr) >> 64) as u64; // D1 = (KL ^ KR) >> 64;
    d[1] = (kl ^ kr) as u64; // D2 = (KL ^ KR) & MASK64;
    d[1] ^= f1(d[0], SIGMA[0]); // D2 = D2 ^ F(D1, Sigma1);
    d[0] ^= f1(d[1], SIGMA[1]); // D1 = D1 ^ F(D2, Sigma2);
    d[0] ^= (kl >> 64) as u64; // D1 = D1 ^ (KL >> 64);
    d[1] ^= kl as u64; // D2 = D2 ^ (KL & MASK64);
    d[1] ^= f1(d[0], SIGMA[2]); // D2 = D2 ^ F(D1, Sigma3);
    d[0] ^= f1(d[1], SIGMA[3]); // D1 = D1 ^ F(D2, Sigma4);
    kx[2] = join(d[0], d[1]); // KA = (D1 << 64) | D2;
    let ka = kx[2];
    d[0] = ((ka ^ kr) >> 64) as u64; // D1 = (KA ^ KR) >> 64;
    d[1] = (ka ^ kr) as u64; // D2 = (KA ^ KR) & MASK64;
    d[1] ^= f1(d[0], SIGMA[4]); // D2 = D2 ^ F(D1, Sigma5);
    d[0] ^= f1(d[1], SIGMA[5]); // D1 = D1 ^ F(D2, Sigma6);
    kx[3] = join(d[0], d[1]); // KB = (D1 << 64) | D2;

    let mut schedule = Secret::<P::Schedule>::new();
    P::subkeys(kx[0], kx[1], kx[2], kx[3], schedule.as_mut());
    schedule
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schedule_lengths_match_the_layout() {
        // 4 kw + ROUNDS k + FL_KEYS ke, and one FL layer (two keys) per six rounds bar the last.
        assert_eq!(size_of::<<Camellia128Params as CamelliaParams>::Schedule>(), 8 * (4 + 18 + 4));
        assert_eq!(size_of::<<Camellia192Params as CamelliaParams>::Schedule>(), 8 * (4 + 24 + 6));
        assert_eq!(size_of::<<Camellia256Params as CamelliaParams>::Schedule>(), 8 * (4 + 24 + 6));
        assert_eq!(Camellia128Params::FL_KEYS, 2 * (Camellia128Params::ROUNDS / 6 - 1));
        assert_eq!(Camellia192Params::FL_KEYS, 2 * (Camellia192Params::ROUNDS / 6 - 1));
        assert_eq!(Camellia256Params::FL_KEYS, 2 * (Camellia256Params::ROUNDS / 6 - 1));
    }

    #[test]
    fn test_accessors_index_the_documented_layout() {
        let s: [u64; 34] = core::array::from_fn(|i| 1000 + i as u64);
        assert_eq!(kw(&s, 1), 1000);
        assert_eq!(kw(&s, 4), 1003);
        assert_eq!(k(&s, 1), 1004);
        assert_eq!(k(&s, 24), 1027);
        assert_eq!(ke::<Camellia256Params>(&s, 1), 1028);
        assert_eq!(ke::<Camellia256Params>(&s, 6), 1033);
        let s: [u64; 26] = core::array::from_fn(|i| 1000 + i as u64);
        assert_eq!(k(&s, 18), 1021);
        assert_eq!(ke::<Camellia128Params>(&s, 1), 1022);
        assert_eq!(ke::<Camellia128Params>(&s, 4), 1025);
    }

    #[test]
    fn test_kl_kr_for_each_key_length() {
        let key: [u64; 4] = [
            0x0001_0203_0405_0607, 0x0809_0A0B_0C0D_0E0F, 0x1011_1213_1415_1617,
            0x1819_1A1B_1C1D_1E1F,
        ];
        let k0 = 0x0001_0203_0405_0607_0809_0A0B_0C0D_0E0Fu128;
        let k1 = 0x1011_1213_1415_1617_1819_1A1B_1C1D_1E1Fu128;
        // 128-bit key K: KL = K; KR = 0;
        assert_eq!(Camellia128Params::kl_kr(&key[..2]), (k0, 0));
        // 192-bit key K: KL = K >> 64; KR = ((K & MASK64) << 64) | (~(K & MASK64));
        let (kl, kr) = Camellia192Params::kl_kr(&key[..3]);
        assert_eq!(kl, k0);
        assert_eq!(kr, (0x1011_1213_1415_1617u128 << 64) | (!0x1011_1213_1415_1617u64) as u128);
        // 256-bit key K: KL = K >> 128; KR = K & MASK128;
        assert_eq!(Camellia256Params::kl_kr(&key), (k0, k1));
    }

    #[test]
    fn test_whitening_keys_are_the_key_itself() {
        // kw1 = (KL <<< 0) >> 64 and kw2 = (KL <<< 0) & MASK64: the first 16 bytes of every key,
        // unchanged, for all three lengths. A direct consequence of the tables that needs no
        // vectors.
        let key: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
        let (words, _) = key.as_chunks::<8>();
        let (w0, w1) = (u64::from_be_bytes(words[0]), u64::from_be_bytes(words[1]));
        let s = expand::<Camellia128Params>(&key[..16]);
        assert_eq!(kw(s.as_ref(), 1), w0);
        assert_eq!(kw(s.as_ref(), 2), w1);
        let s = expand::<Camellia192Params>(&key[..24]);
        assert_eq!(kw(s.as_ref(), 1), w0);
        let s = expand::<Camellia256Params>(&key);
        assert_eq!(kw(s.as_ref(), 2), w1);
    }

    #[test]
    fn test_rotations_split_as_the_rfc_reads() {
        // (X <<< rot) >> 64 and (X <<< rot) & MASK64, by hand on a value with one bit at each end.
        let x = 0x8000_0000_0000_0000_0000_0000_0000_0001u128;
        assert_eq!(left(x, 0), 0x8000_0000_0000_0000);
        assert_eq!(right(x, 0), 1);
        // <<< 15: bit 127 wraps to bit 14 and bit 0 moves to bit 15, both in the right half.
        assert_eq!(left(x, 15), 0);
        assert_eq!(right(x, 15), (1 << 14) | (1 << 15));
        // <<< 77: bit 127 wraps to bit 76 and bit 0 moves to bit 77, both in the left half, whose
        // bit 0 is bit 64 of the whole.
        assert_eq!(left(x, 77), (1 << 12) | (1 << 13));
        assert_eq!(right(x, 77), 0);
    }

    #[test]
    fn test_sigma_constants_match_section_2_2() {
        assert_eq!(SIGMA[0], 0xA09E667F3BCC908B);
        assert_eq!(SIGMA[1], 0xB67AE8584CAA73B2);
        assert_eq!(SIGMA[2], 0xC6EF372FE94F82BE);
        assert_eq!(SIGMA[3], 0x54FF53A5F1D36F1C);
        assert_eq!(SIGMA[4], 0x10E527FADE682D1D);
        assert_eq!(SIGMA[5], 0xB05688C2B3E6C1FD);
    }
}
