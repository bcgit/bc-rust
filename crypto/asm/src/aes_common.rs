//! What every back end's AES key expansion and kernels share: the round constants and the
//! compile-time check on the round-key count.

/// Table 5 (Sec 5.2): the left-most byte of `Rcon[j]` for `1 <= j <= 10`; the other three bytes
/// are zero. Indexed by the public round counter, never by key material.
pub(crate) const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

/// The compile-time check that `N` is one of the three round-key counts of Table 3.
#[inline(always)]
pub(crate) const fn check_rounds<const N: usize>() {
    const {
        assert!(N == 11 || N == 13 || N == 15, "FIPS 197 Table 3: Nr + 1 is 11, 13 or 15");
    };
}
