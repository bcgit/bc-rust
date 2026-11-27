//! Bit manipulation on a single word, for the scalar recoding of the EdDSA signature schemes.

/// Swaps the bits of `x` selected by the mask `m` with the bits `s` places above them, and
/// leaves every other bit alone. `m` and `m << s` must not overlap, and `m << s` must not lose
/// bits off the top. Constant time in `x`; `m` and `s` are public.
#[inline]
pub(in crate::ed) const fn bit_permute_step_64(x: u64, m: u64, s: usize) -> u64 {
    debug_assert!((m & (m << s)) == 0);
    debug_assert!((m << s) >> s == m);

    let t = (x ^ (x >> s)) & m;
    t ^ (t << s) ^ x
}

#[cfg(test)]
mod tests {
    use super::*;

    // Known answers from the prototype these helpers were ported from
    // (`bits::bit_permute_step_64`), over the four steps its Ed25519 comb recoding applies;
    // printed by the scratch program described in `nat.rs` (`kat-gen nat`).
    // (x, m, s, result)
    const PERMUTE_KATS: &[(u64, u64, usize, u64)] = &[
        (0xEBA7EA1BD263138F, 0x0000F0F00000F0F0, 12, 0xEEA1BA7BD168233F),
        (0xEBA7EA1BD263138F, 0x00CC00CC00CC00CC, 6, 0xE9AFCA9BD06B234F),
        (0xEBA7EA1BD263138F, 0x2222222222222222, 1, 0xEDC7EC1DB465158F),
        (0xEBA7EA1BD263138F, 0x0C0C0C0C0C0C0C0C, 2, 0xEB9BEA27C64B07B3),
        (0xE226F4179AD622DF, 0x0000F0F00000F0F0, 12, 0xEF21246792DDA26F),
        (0xE226F4179AD622DF, 0x00CC00CC00CC00CC, 6, 0xC1AAC5D3B95A339B),
        (0xE226F4179AD622DF, 0x2222222222222222, 1, 0xE446F2179CB644BF),
        (0xE226F4179AD622DF, 0x0C0C0C0C0C0C0C0C, 2, 0xCA1ADC17A6D60AF7),
        (0x412BD660BEF625CE, 0x0000F0F00000F0F0, 12, 0x4D2616B0B2FCE56E),
        (0x412BD660BEF625CE, 0x00CC00CC00CC00CC, 6, 0x4227D468BDFA3786),
        (0x412BD660BEF625CE, 0x2222222222222222, 1, 0x214DB660DEF643AE),
        (0x412BD660BEF625CE, 0x0C0C0C0C0C0C0C0C, 2, 0x412BD648BEDE19F2),
    ];

    #[test]
    fn bit_permute_step_64_matches_the_prototype() {
        for &(x, m, s, expected) in PERMUTE_KATS {
            assert_eq!(bit_permute_step_64(x, m, s), expected, "{x:#x} {m:#x} {s}");
        }
    }

    /// Bit by bit: each bit under the mask changes places with the one `s` above it, and the
    /// rest stay where they are.
    #[test]
    fn bit_permute_step_64_swaps_the_masked_bits_only() {
        for &(x, m, s, _) in PERMUTE_KATS {
            let r = bit_permute_step_64(x, m, s);
            for bit in 0..64 {
                let source = if (m >> bit) & 1 == 1 {
                    bit + s
                } else if bit >= s && (m >> (bit - s)) & 1 == 1 {
                    bit - s
                } else {
                    bit
                };
                assert_eq!((r >> bit) & 1, (x >> source) & 1, "{x:#x} {m:#x} {s} bit {bit}");
            }
        }
    }
}
