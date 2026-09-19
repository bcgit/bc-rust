//! The Ascon-p permutation family (NIST SP 800-232 §3), shared by all four functions in this
//! crate: Ascon-AEAD128 uses both `Ascon-p[12]` and `Ascon-p[8]`; Ascon-Hash256, Ascon-XOF128, and
//! Ascon-CXOF128 use only `Ascon-p[12]`.
//!
//! These also carry the little-endian load/store helpers, replacing the external `arrayref`
//! crate so that this crate carries no third-party runtime dependencies (per the project's
//! QUALITY_AND_STYLE rules). All callers pass slices that are at least 8 bytes long at the given
//! offset, so `copy_from_slice` is infallible by construction and no fallible conversion is
//! involved.

/// Load the 8 bytes at `src[off..off + 8]` as a little-endian `u64`.
#[inline(always)]
pub(crate) fn load_u64_le(src: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&src[off..off + 8]);
    u64::from_le_bytes(b)
}

/// Store `val` as little-endian into `dst[off..off + 8]`.
#[inline(always)]
pub(crate) fn store_u64_le(dst: &mut [u8], off: usize, val: u64) {
    dst[off..off + 8].copy_from_slice(&val.to_le_bytes());
}

/// The 320-bit Ascon state (SP 800-232 §3.1 Eq. 2): five 64-bit words S0..S4.
pub(crate) type AsconState = [u64; 5];

// The constants const_0..const_15 used to derive the round constants of Ascon-p[r]
// (SP 800-232 Table 5). The round constant for round i (0 <= i <= r-1) of Ascon-p[r] is
// c_i = const_{16-r+i} (SP 800-232 §3.2 Eq. 3).
const ROUND_CONSTS: [u64; 16] = [
    0x3c, 0x2d, 0x1e, 0x0f, 0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b,
];

/// One round p = p_L ∘ p_S ∘ p_C (SP 800-232 §3.2–3.4 Eq. 1): the constant-addition layer p_C
/// (§3.2 Eq. 4), the substitution layer p_S (§3.3 Eqs. 6–7), and the linear diffusion layer p_L
/// (§3.4 Eqs. 8–12) are fused here in their bitsliced form.
#[inline(always)]
pub(crate) fn round(s: &mut AsconState, c: u64) {
    let sx = s[2] ^ c;
    let t0 = s[0] ^ s[1] ^ sx ^ s[3] ^ (s[1] & (s[0] ^ sx ^ s[4]));
    let t1 = s[0] ^ sx ^ s[3] ^ s[4] ^ ((s[1] ^ sx) & (s[1] ^ s[3]));
    let t2 = s[1] ^ sx ^ s[4] ^ (s[3] & s[4]);
    let t3 = s[0] ^ s[1] ^ sx ^ ((!s[0]) & (s[3] ^ s[4]));
    let t4 = s[1] ^ s[3] ^ s[4] ^ ((s[0] ^ s[4]) & s[1]);
    s[0] = t0 ^ t0.rotate_right(19) ^ t0.rotate_right(28);
    s[1] = t1 ^ t1.rotate_right(39) ^ t1.rotate_right(61);
    s[2] = !(t2 ^ t2.rotate_right(1) ^ t2.rotate_right(6));
    s[3] = t3 ^ t3.rotate_right(10) ^ t3.rotate_right(17);
    s[4] = t4 ^ t4.rotate_right(7) ^ t4.rotate_right(41);
}

/// Ascon-p[12] (SP 800-232 §3.2 Eq. 3: c_i = const_{4+i} for i = 0..11, i.e. round constants
/// const_4..const_15 of Table 5).
#[inline(always)]
pub(crate) fn p12(s: &mut AsconState) {
    for &c in &ROUND_CONSTS[4..16] {
        round(s, c);
    }
}

/// Ascon-p[8] (SP 800-232 §3.2 Eq. 3: c_i = const_{8+i} for i = 0..7, i.e. round constants
/// const_8..const_15 of Table 5).
#[inline(always)]
pub(crate) fn p8(s: &mut AsconState) {
    for &c in &ROUND_CONSTS[8..16] {
        round(s, c);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // SP 800-232 Table 14: initial values (before the initialization permutation).
    const HASH256_IV: u64 = 0x0000080100cc0002;
    const XOF128_IV: u64 = 0x0000080000cc0003;
    const CXOF128_IV: u64 = 0x0000080000cc0004;

    // Pins the permutation independently of the KAT sweeps: SP 800-232 Table 12 gives the state
    // at the end of each function's initialization phase, i.e. Ascon-p[12](IV || 0^256).
    #[test]
    fn p12_matches_table_12_precomputed_states() {
        let mut s: AsconState = [HASH256_IV, 0, 0, 0, 0];
        p12(&mut s);
        assert_eq!(
            s,
            [
                0x9b1e5494e934d681, 0x4bc3a01e333751d2, 0xae65396c6b34b81a, 0x3c7fd4a4d56a4db3,
                0x1a5c464906c5976d,
            ]
        );

        let mut s: AsconState = [XOF128_IV, 0, 0, 0, 0];
        p12(&mut s);
        assert_eq!(
            s,
            [
                0xda82ce768d9447eb, 0xcc7ce6c75f1ef969, 0xe7508fd780085631, 0x0ee0ea53416b58cc,
                0xe0547524db6f0bde,
            ]
        );

        let mut s: AsconState = [CXOF128_IV, 0, 0, 0, 0];
        p12(&mut s);
        assert_eq!(
            s,
            [
                0x675527c2a0e8de03, 0x43d12d7dc0377bbc, 0xe9901dec426e81b5, 0x2ab14907720780b6,
                0x8f3f1d02d432bc46,
            ]
        );
    }

    // Pins `AsconCXof128::new()`'s precomputed empty-customization state (see
    // `ascon_cxof128.rs`) by recomputing it from the Table 12 CXOF128 state above, following
    // SP 800-232 Algorithm 7 with |Z| = 0: XOR the length word Z_0 = int64(0) into S[0..63],
    // Ascon-p[12], then XOR the pad-only last customization block (Eq. 77: pad(empty, 64) =
    // 0x01 || 0^63, i.e. byte 0x01 loaded little-endian into S[0..63]) and Ascon-p[12] again.
    #[test]
    fn cxof128_empty_customization_state_matches_algorithm_7() {
        let mut s: AsconState = [
            0x675527c2a0e8de03, 0x43d12d7dc0377bbc, 0xe9901dec426e81b5, 0x2ab14907720780b6,
            0x8f3f1d02d432bc46,
        ];
        s[0] ^= 0u64; // Z_0 = int64(|Z|) = int64(0) = 0 (a no-op XOR, spelled out for clarity)
        p12(&mut s);
        s[0] ^= 0x01u64; // pad(empty, 64) = 0x01 || 0^63, loaded little-endian
        p12(&mut s);
        assert_eq!(
            s,
            [
                0x500cccc894e3c9e8, 0x5bed06f28f71248d, 0x3b03a0f930afd512, 0x112ef093aa5c698b,
                0x00c8356340a347f0,
            ]
        );
    }
}
