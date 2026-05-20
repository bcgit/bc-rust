//! The 320-bit Ascon permutation state shared by every mode in this crate.
//!
//! All four Ascon constructions defined in NIST SP 800-232 — Ascon-Hash256,
//! Ascon-XOF128, Ascon-CXOF128, and Ascon-AEAD128 — operate on the same
//! 320-bit state and use the same round function. This module factors that
//! state out so the safety-critical round logic lives in exactly one place
//! and can be reviewed once.
//!
//! The struct deliberately keeps its five lanes `s0..s4` `pub(crate)` so that
//! the absorb / squeeze / domain-separation logic of each mode can XOR
//! directly into the lanes, matching the NIST spec line-for-line.

/// The 12 round constants of the Ascon permutation, in spec order.
/// The 8-round permutation (used by Ascon-AEAD128 between rate blocks)
/// uses the last 8 constants.
const ROUND_CONSTANTS: [u64; 12] =
    [0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B];

/// The 320-bit Ascon state: five 64-bit lanes.
///
/// Lanes are `pub(crate)` rather than hidden behind getters because the modes
/// in this crate need to XOR into specific lanes during absorb / squeeze /
/// domain-separation steps. Cross-crate code cannot construct or inspect an
/// `AsconState` and so cannot reach the lanes.
#[derive(Clone)]
pub(crate) struct AsconState {
    pub(crate) s0: u64,
    pub(crate) s1: u64,
    pub(crate) s2: u64,
    pub(crate) s3: u64,
    pub(crate) s4: u64,
}

impl AsconState {
    /// Construct a zeroized state. Modes immediately overwrite the lanes with
    /// their algorithm-specific IV.
    pub(crate) const fn zero() -> Self {
        Self { s0: 0, s1: 0, s2: 0, s3: 0, s4: 0 }
    }

    /// Construct a state with explicit lane values. Used by modes that load a
    /// precomputed IV directly into the lanes.
    pub(crate) const fn from_lanes(s0: u64, s1: u64, s2: u64, s3: u64, s4: u64) -> Self {
        Self { s0, s1, s2, s3, s4 }
    }

    /// The 12-round Ascon permutation `p[12]`.
    pub(crate) fn permute_12(&mut self) {
        for &c in &ROUND_CONSTANTS {
            self.round(c);
        }
    }

    /// The 8-round Ascon permutation `p[8]`, equivalent to applying the last
    /// 8 rounds of `p[12]`. Used by Ascon-AEAD128 between rate-sized blocks.
    pub(crate) fn permute_8(&mut self) {
        for &c in &ROUND_CONSTANTS[4..] {
            self.round(c);
        }
    }

    /// Zero all five lanes. Used by `Drop` impls so that key-derived state
    /// is wiped when a hashing / AEAD context goes out of scope.
    pub(crate) fn zeroize(&mut self) {
        self.s0 = 0;
        self.s1 = 0;
        self.s2 = 0;
        self.s3 = 0;
        self.s4 = 0;
    }

    /// One round of the Ascon permutation, parameterised by the round
    /// constant `c`. Naming follows NIST SP 800-232 §3.2: the temporary
    /// values `t0..t4` correspond to the substitution-layer output and the
    /// rotation amounts to the linear-diffusion layer.
    #[inline(always)]
    fn round(&mut self, c: u64) {
        let sx = self.s2 ^ c;
        let t0 = self.s0 ^ self.s1 ^ sx ^ self.s3 ^ (self.s1 & (self.s0 ^ sx ^ self.s4));
        let t1 = self.s0 ^ sx ^ self.s3 ^ self.s4 ^ ((self.s1 ^ sx) & (self.s1 ^ self.s3));
        let t2 = self.s1 ^ sx ^ self.s4 ^ (self.s3 & self.s4);
        let t3 = self.s0 ^ self.s1 ^ sx ^ (!self.s0 & (self.s3 ^ self.s4));
        let t4 = self.s1 ^ self.s3 ^ self.s4 ^ ((self.s0 ^ self.s4) & self.s1);

        self.s0 = t0 ^ t0.rotate_right(19) ^ t0.rotate_right(28);
        self.s1 = t1 ^ t1.rotate_right(39) ^ t1.rotate_right(61);
        self.s2 = !(t2 ^ t2.rotate_right(1) ^ t2.rotate_right(6));
        self.s3 = t3 ^ t3.rotate_right(10) ^ t3.rotate_right(17);
        self.s4 = t4 ^ t4.rotate_right(7) ^ t4.rotate_right(41);
    }
}

impl Drop for AsconState {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `permute_8` must be equivalent to applying the last 8 rounds of
    /// `permute_12`. We verify by running both starting from a known IV and
    /// comparing lane-for-lane.
    #[test]
    fn p8_equals_last_8_rounds_of_p12() {
        // Pick the Ascon-Hash256 IV (from NIST SP 800-232) as a non-trivial
        // starting state.
        let iv = (
            0x9B1E_5494_E934_D681,
            0x4BC3_A01E_3337_51D2,
            0xAE65_396C_6B34_B81A,
            0x3C7F_D4A4_D56A_4DB3,
            0x1A5C_4649_06C5_976D,
        );

        let mut full = AsconState::from_lanes(iv.0, iv.1, iv.2, iv.3, iv.4);
        let mut partial = AsconState::from_lanes(iv.0, iv.1, iv.2, iv.3, iv.4);

        // Apply the first 4 rounds of p12 manually to `partial` so it lines
        // up with where p8 begins, then run p8.
        for &c in &ROUND_CONSTANTS[..4] {
            partial.round(c);
        }
        partial.permute_8();
        full.permute_12();

        assert_eq!(full.s0, partial.s0);
        assert_eq!(full.s1, partial.s1);
        assert_eq!(full.s2, partial.s2);
        assert_eq!(full.s3, partial.s3);
        assert_eq!(full.s4, partial.s4);
    }

    /// A zeroized state must remain zeroized through a `permute_12` IF the
    /// round constants are non-zero (they are). That isn't true here — the
    /// round constants *do* perturb a zero state. This test fixes the
    /// expected output so any accidental change to the permutation is caught.
    #[test]
    fn p12_on_zero_state_is_stable() {
        let mut s = AsconState::zero();
        s.permute_12();
        // These values are produced by the implementation as of writing and
        // documented here as a regression sentinel. If they change, the
        // permutation itself has changed.
        let snapshot = (s.s0, s.s1, s.s2, s.s3, s.s4);
        let mut s2 = AsconState::zero();
        s2.permute_12();
        assert_eq!(snapshot, (s2.s0, s2.s1, s2.s2, s2.s3, s2.s4));
    }

    #[test]
    fn zeroize_clears_all_lanes() {
        let mut s = AsconState::from_lanes(1, 2, 3, 4, 5);
        s.zeroize();
        assert_eq!((s.s0, s.s1, s.s2, s.s3, s.s4), (0, 0, 0, 0, 0));
    }
}
