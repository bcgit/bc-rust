//! Bare metal at EL1 or higher: the parser for the ID registers. Nothing reads them yet; the
//! opt-in that does (three `mrs` reads) is not built.

#![deny(unsafe_code)]

use super::AES;

/// Bare metal at EL1 or higher: `ID_AA64PFR0_EL1`, `ID_AA64ISAR0_EL1` and `ID_AA64ZFR0_EL1`,
/// with the field positions of the kernel's `arch/arm64/tools/sysreg`.
#[allow(dead_code, reason = "for the bare-metal opt-in, which reads the registers")]
pub(super) fn features_from_id_registers(pfr0: u64, isar0: u64, _zfr0: u64) -> u32 {
    // PFR0.AdvSIMD [23:20] is signed: 0b1111 is "not implemented", every other value has it.
    let adv_simd = (pfr0 >> 20) & 0xf;
    // ISAR0.AES [7:4]: 0b0001 is AES alone, 0b0010 AES and PMULL.
    let aes = (isar0 >> 4) & 0xf;
    let mut features = 0;
    if adv_simd != 0b1111 && aes >= 0b0010 {
        features |= AES;
    }
    features
}

#[cfg(test)]
mod tests {
    //! Unit tests, because these functions are private and pure, with answers known from the
    //! headers; the words are synthetic, one per class of CPU.

    use super::*;

    #[test]
    fn id_registers_need_pmull_and_advsimd() {
        let aes_only = 0b0001 << 4;
        let aes_pmull = 0b0010 << 4;
        let advsimd_ni = 0b1111 << 20;
        let advsimd_fp16 = 0b0001 << 20;
        assert_eq!(features_from_id_registers(0, aes_pmull, 0), AES);
        assert_eq!(features_from_id_registers(advsimd_fp16, aes_pmull, 0), AES);
        assert_eq!(features_from_id_registers(0, aes_only, 0), 0);
        assert_eq!(features_from_id_registers(advsimd_ni, aes_pmull, 0), 0);
        // A reserved value above PMULL still has it, as the "at least" reading of the field says.
        assert_eq!(features_from_id_registers(0, 0b1111 << 4, 0), AES);
    }

    #[test]
    fn id_registers_all_zero_and_all_ones() {
        assert_eq!(features_from_id_registers(0, 0, 0), 0);
        // All ones has AdvSIMD = 0b1111, not implemented.
        assert_eq!(features_from_id_registers(u64::MAX, u64::MAX, u64::MAX), 0);
        assert_eq!(features_from_id_registers(0, u64::MAX, u64::MAX), AES);
    }

    #[test]
    fn id_registers_read_only_their_fields() {
        // Every bit outside PFR0.AdvSIMD and ISAR0.AES set, those two fields at "absent".
        let pfr0 = !(0xf << 20) | (0b1111 << 20);
        let isar0 = !(0xf << 4);
        assert_eq!(features_from_id_registers(pfr0, isar0, u64::MAX), 0);
    }
}
