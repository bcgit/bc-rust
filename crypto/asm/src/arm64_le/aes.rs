//! The AES cipher and inverse cipher (FIPS 197 Sec 5) on the Crypto Extensions.
//!
//! [`expand_128`], [`expand_192`] and [`expand_256`] are KEYEXPANSION() (Sec 5.2), producing
//! the round keys as `Nr + 1` blocks of sixteen bytes; [`equivalent_inverse_round_keys`] is
//! the extra step of KEYEXPANSIONEIC() (Sec 5.3.5, Algorithm 5) that turns them into the `dw`
//! array the inverse cipher on `AESD`/`AESIMC` needs. [`encrypt_blocks`] is CIPHER() (Sec 5.1,
//! Algorithm 1) and [`decrypt_blocks`] is EQINVCIPHER() (Sec 5.3.5, Algorithm 4), each on one,
//! two or four independent blocks at once so the instruction pipeline overlaps them.
//!
//! There is no state. The caller owns the round keys and is expected to hold them in a
//! zeroize-on-drop wrapper (`bouncycastle_utils::secret::Secret`), as `bouncycastle-aes`
//! does.

use super::intrinsics::V128;
use crate::aes_common::{RCON, check_rounds};
use crate::{BLOCK_LEN, Block, RoundKeys128, RoundKeys192, RoundKeys256};

/// `ROTWORD([a0, a1, a2, a3]) = [a1, a2, a3, a0]` (Eq. 5.10).
#[inline(always)]
fn rot_word(w: [u8; 4]) -> [u8; 4] {
    [w[1], w[2], w[3], w[0]]
}

/// `SUBWORD([a0, a1, a2, a3]) = [SBOX(a0), SBOX(a1), SBOX(a2), SBOX(a3)]` (Eq. 5.11), with no
/// S-box table: `AESE(x, 0)` computes `SHIFTROWS(SUBBYTES(x))`, and when all four columns of
/// `x` hold the same word, SHIFTROWS moves identical bytes onto each other and is the identity,
/// so lane 0 of the result is SUBWORD of that word. Nothing is indexed by the key.
#[target_feature(enable = "aes,neon")]
#[inline]
fn sub_word(w: [u8; 4]) -> [u8; 4] {
    V128::splat_u32(u32::from_le_bytes(w)).aese(V128::zero()).lane_u32::<0>().to_le_bytes()
}

/// KEYEXPANSION() (Sec 5.2, Algorithm 2), writing `w` straight into the round-key blocks:
/// word `w[i]` is bytes `4 * (i % 4)..` of block `i / 4`. `KEY_LEN` is `4 * Nk` and `N` is
/// `Nr + 1`, both fixed by the three public wrappers.
#[target_feature(enable = "aes,neon")]
fn expand<const KEY_LEN: usize, const N: usize>(key: &[u8; KEY_LEN]) -> [Block; N] {
    const {
        assert!(
            (KEY_LEN == 16 && N == 11) || (KEY_LEN == 24 && N == 13) || (KEY_LEN == 32 && N == 15),
            "FIPS 197 Table 3: Nk = 4, 6, 8 words with Nr = 10, 12, 14 rounds"
        );
    };
    let nk = KEY_LEN / 4;
    let mut w = [[0u8; BLOCK_LEN]; N];
    // The 4 * N words, in order; both remainders are empty, since 16 * N and KEY_LEN are
    // multiples of 4.
    let (words, _) = w.as_flattened_mut().as_chunks_mut::<4>();
    let (key_words, _) = key.as_chunks::<4>();

    // Lines 2-6: the first Nk words are the key itself.
    for (word, key_word) in words.iter_mut().zip(key_words) {
        *word = *key_word;
    }

    // Lines 7-16. `i` runs over `nk..4 * N` with `nk >= 4`, so `i - 1`, `i - nk` and `i` all
    // index within `words`, whose length is `4 * N`.
    for i in nk..4 * N {
        // Line 8: temp <- w[i - 1]
        let mut temp = words[i - 1];
        if i % nk == 0 {
            // Line 10: temp <- SUBWORD(ROTWORD(temp)) XOR Rcon[i / Nk]
            temp = sub_word(rot_word(temp));
            temp[0] ^= RCON[i / nk - 1];
        } else if nk > 6 && i % nk == 4 {
            // Line 12 (AES-256 only): temp <- SUBWORD(temp)
            temp = sub_word(temp);
        }
        // Line 14: w[i] <- w[i - Nk] XOR temp
        let prev = words[i - nk];
        for (b, (p, t)) in words[i].iter_mut().zip(prev.iter().zip(temp)) {
            *b = p ^ t;
        }
    }
    w
}

/// KEYEXPANSION() for a 128-bit key (Sec 5.2): `Nk = 4`, `Nr = 10`.
///
/// # Safety
///
/// Callable only through an [`Aes`](super::Aes) proof, whose existence is the precondition.
#[target_feature(enable = "aes,neon")]
pub fn expand_128(key: &[u8; 16]) -> RoundKeys128 {
    expand(key)
}

/// KEYEXPANSION() for a 192-bit key (Sec 5.2): `Nk = 6`, `Nr = 12`.
///
/// # Safety
///
/// Callable only through an [`Aes`](super::Aes) proof, whose existence is the precondition.
#[target_feature(enable = "aes,neon")]
pub fn expand_192(key: &[u8; 24]) -> RoundKeys192 {
    expand(key)
}

/// KEYEXPANSION() for a 256-bit key (Sec 5.2): `Nk = 8`, `Nr = 14`.
///
/// # Safety
///
/// Callable only through an [`Aes`](super::Aes) proof, whose existence is the precondition.
#[target_feature(enable = "aes,neon")]
pub fn expand_256(key: &[u8; 32]) -> RoundKeys256 {
    expand(key)
}

/// Lines 19-22 of KEYEXPANSIONEIC() (Sec 5.3.5, Algorithm 5): `dw` is `w` with
/// INVMIXCOLUMNS() applied to round keys `1..=Nr-1`; the first and last are unchanged. This is
/// the schedule [`decrypt_blocks`] consumes.
///
/// # Safety
///
/// Callable only through an [`Aes`](super::Aes) proof, whose existence is the precondition.
#[target_feature(enable = "aes,neon")]
pub fn equivalent_inverse_round_keys<const N: usize>(w: &[Block; N]) -> [Block; N] {
    check_rounds::<N>();
    let nr = N - 1;
    let mut dw = *w;
    for round_key in dw.iter_mut().take(nr).skip(1) {
        *round_key = V128::from_bytes(round_key).aesimc().to_bytes();
    }
    dw
}

/// CIPHER() (Sec 5.1, Algorithm 1) on `B` independent blocks in place, `B` being 1, 2 or 4.
///
/// Algorithm 1 is regrouped around what the instructions compute. `AESE(state, k)` is
/// `SHIFTROWS(SUBBYTES(state XOR k))`, so line 3's ADDROUNDKEY() with `w[0]` and the first
/// iteration's lines 5-6 are one `aese`; each later iteration's line 7 is an `aesmc` and its
/// lines 5-6 together with the previous iteration's line 8 are the next `aese`; lines 10-12
/// are the last `aese` followed by a plain XOR with `w[Nr]`. The order of operations on the
/// state is exactly Algorithm 1's, which the FIPS 197 and SP 800-38A vector tests pin.
///
/// The `B` states advance together through each round so that independent `AESE`/`AESMC`
/// chains overlap in the pipeline; the result is indistinguishable from `B` single-block
/// calls.
///
/// # Safety
///
/// Callable only through an [`Aes`](super::Aes) proof, whose existence is the precondition.
#[target_feature(enable = "aes,neon")]
pub fn encrypt_blocks<const N: usize, const B: usize>(w: &[Block; N], blocks: &mut [Block; B]) {
    check_rounds::<N>();
    const {
        assert!(B == 1 || B == 2 || B == 4, "one, two or four blocks per call");
    };
    let nr = N - 1;
    let mut state: [V128; B] = core::array::from_fn(|i| V128::from_bytes(&blocks[i]));

    // Line 3 and the first pass of lines 5-6.
    let k = V128::from_bytes(&w[0]);
    for s in state.iter_mut() {
        *s = s.aese(k);
    }
    // Lines 4-9: line 7, then line 8 of this round with lines 5-6 of the next.
    for round_key in w.iter().take(nr).skip(1) {
        let k = V128::from_bytes(round_key);
        for s in state.iter_mut() {
            *s = s.aesmc().aese(k);
        }
    }
    // Line 12: ADDROUNDKEY() with w[4 * Nr .. 4 * Nr + 3]; lines 10-11 were the last aese.
    let k = V128::from_bytes(&w[nr]);
    for (block, s) in blocks.iter_mut().zip(state) {
        *block = s.eor(k).to_bytes();
    }
}

/// EQINVCIPHER() (Sec 5.3.5, Algorithm 4) on `B` independent blocks in place, `B` being 1, 2
/// or 4, over the `dw` schedule from [`equivalent_inverse_round_keys`].
///
/// Regrouped as [`encrypt_blocks`] is: `AESD(state, k)` is
/// `INVSHIFTROWS(INVSUBBYTES(state XOR k))`, so line 3's ADDROUNDKEY() with `dw[Nr]` and the
/// first iteration's lines 5-6 are one `aesd`; each iteration's line 7 is an `aesimc` and its
/// line 8 together with the next iteration's lines 5-6 is the next `aesd`; lines 10-12 end
/// with a plain XOR with `dw[0]`.
///
/// # Safety
///
/// Callable only through an [`Aes`](super::Aes) proof, whose existence is the precondition.
#[target_feature(enable = "aes,neon")]
pub fn decrypt_blocks<const N: usize, const B: usize>(dw: &[Block; N], blocks: &mut [Block; B]) {
    check_rounds::<N>();
    const {
        assert!(B == 1 || B == 2 || B == 4, "one, two or four blocks per call");
    };
    let nr = N - 1;
    let mut state: [V128; B] = core::array::from_fn(|i| V128::from_bytes(&blocks[i]));

    // Line 3 and the first pass of lines 5-6.
    let k = V128::from_bytes(&dw[nr]);
    for s in state.iter_mut() {
        *s = s.aesd(k);
    }
    // Lines 4-9, round from Nr - 1 down to 1: line 7, then line 8 with the next lines 5-6.
    for round_key in dw.iter().take(nr).skip(1).rev() {
        let k = V128::from_bytes(round_key);
        for s in state.iter_mut() {
            *s = s.aesimc().aesd(k);
        }
    }
    // Line 12: ADDROUNDKEY() with dw[0..3]; lines 10-11 were the last aesd.
    let k = V128::from_bytes(&dw[0]);
    for (block, s) in blocks.iter_mut().zip(state) {
        *block = s.eor(k).to_bytes();
    }
}
