use bouncycastle_utils::ct::Condition;

/// These do not validate the constant-time-ness; these are simply basic correctness tests
/// (and example usages)

#[cfg(test)]
mod generic_impl_tests {
    use super::*;

    #[test]
    fn test_bit_and() {
        let ct1 = Condition::<i64>::from_bool::<true>();
        let ct2 = Condition::<i64>::from_bool::<true>();
        let cf1 = Condition::<i64>::from_bool::<false>();
        let cf2 = Condition::<i64>::from_bool::<false>();
        assert_eq!((ct1 & ct2).to_bool(), true);
        assert_eq!((ct1 & cf1).to_bool(), false);
        assert_eq!((cf1 & cf2).to_bool(), false);
    }

    #[test]
    fn test_bit_and_assign() {
        let mut ct1 = Condition::<i64>::from_bool::<true>();
        let ct2 = Condition::<i64>::from_bool::<true>();
        let cf = Condition::<i64>::from_bool::<false>();

        ct1 &= ct2;
        assert_eq!(ct1.to_bool(), true);

        ct1 &= cf;
        assert_eq!(ct1.to_bool(), false);
    }

    #[test]
    fn test_bit_or() {
        let ct1 = Condition::<i64>::from_bool::<true>();
        let ct2 = Condition::<i64>::from_bool::<true>();
        let cf1 = Condition::<i64>::from_bool::<false>();
        let cf2 = Condition::<i64>::from_bool::<false>();

        assert_eq!((ct1 | ct2).to_bool(), true);
        assert_eq!((ct1 | cf1).to_bool(), true);
        assert_eq!((cf1 | cf2).to_bool(), false);
    }

    #[test]
    fn test_bit_or_assign() {
        let mut ct1 = Condition::<i64>::from_bool::<true>();
        let ct2 = Condition::<i64>::from_bool::<true>();
        let mut cf1 = Condition::<i64>::from_bool::<false>();
        let cf2 = Condition::<i64>::from_bool::<false>();

        ct1 |= ct2;
        assert_eq!(ct1.to_bool(), true);

        ct1 |= cf1;
        assert_eq!(ct1.to_bool(), true);

        cf1 |= cf2;
        assert_eq!(cf1.to_bool(), false);
    }

    #[test]
    fn test_bit_xor() {
        let ct1 = Condition::<i64>::from_bool::<true>();
        let ct2 = Condition::<i64>::from_bool::<true>();
        let cf1 = Condition::<i64>::from_bool::<false>();
        let cf2 = Condition::<i64>::from_bool::<false>();

        assert_eq!((ct1 ^ ct2).to_bool(), false);
        assert_eq!((ct1 ^ cf1).to_bool(), true);
        assert_eq!((cf1 ^ cf2).to_bool(), false);
    }

    #[test]
    fn test_bit_xor_assign() {
        let mut ct1 = Condition::<i64>::from_bool::<true>();
        let mut ct2 = Condition::<i64>::from_bool::<true>();
        let mut cf1 = Condition::<i64>::from_bool::<false>();
        let cf2 = Condition::<i64>::from_bool::<false>();

        ct1 ^= ct2;
        assert_eq!(ct1.to_bool(), false);

        ct2 ^= cf1;
        assert_eq!(ct2.to_bool(), true);

        cf1 ^= cf2;
        assert_eq!(cf1.to_bool(), false);
    }

    #[test]
    fn test_not() {
        let c = Condition::<i64>::from_bool::<true>();
        assert_eq!((!c).to_bool(), false);
    }
}

/// One test module per unsigned width, written out by hand like the impls they exercise; the
/// u64 and u32 modules must be edited together so the widths stay at exact behavioural
/// parity. Boundary set: 0, 1, MAX, MAX-1, 1 << (BITS-1) — the values where
/// signed-representation tricks would produce wrong masks if they had leaked into the
/// unsigned constructions.
#[cfg(test)]
mod unsigned_u64_tests {
    use super::*;

    const MSB: u64 = 1 << (u64::BITS - 1);
    const BOUNDARY: [u64; 5] = [0, 1, u64::MAX, u64::MAX - 1, MSB];

    /// A mask must be exactly all-ones or all-zeros: `to_bool` only tests non-zero,
    /// so a constructor returning `1` instead of all-ones would pass it and then
    /// quietly corrupt every select it feeds. The two select operands differ in
    /// every bit, so the assertion holds exactly when the mask is canonical.
    fn assert_canonical(cond: Condition<u64>, expected: bool) {
        const PATTERN: u64 = (0x5555_5555_5555_5555_u64 & (u64::MAX as u64)) as u64;
        let selected = cond.select(PATTERN, !PATTERN);
        assert_eq!(selected, if expected { PATTERN } else { !PATTERN });
        assert_eq!(cond.to_bool(), expected);
    }

    #[test]
    fn consts() {
        assert_canonical(Condition::<u64>::TRUE, true);
        assert_canonical(Condition::<u64>::FALSE, false);
    }

    #[test]
    fn from_bool() {
        assert_canonical(Condition::<u64>::from_bool::<true>(), true);
        assert_canonical(Condition::<u64>::from_bool::<false>(), false);
        assert_canonical(Condition::<u64>::from_bool_var(true), true);
        assert_canonical(Condition::<u64>::from_bool_var(false), false);
    }

    #[test]
    fn from_lsb() {
        for v in BOUNDARY {
            assert_canonical(Condition::<u64>::from_lsb(v), v & 1 == 1);
        }
    }

    #[test]
    fn from_msb() {
        for v in BOUNDARY {
            assert_canonical(Condition::<u64>::from_msb(v), v >> (u64::BITS - 1) == 1);
        }
    }

    /// `from_msb` exists to convert the borrow word of a wrapping subtraction chain
    /// into a mask: `(x - y) >> BITS` of the widening subtraction is all-ones in the
    /// low word iff x < y.
    #[test]
    fn from_msb_as_borrow_adaptor() {
        for x in BOUNDARY {
            for y in BOUNDARY {
                let borrow = ((x as u128).wrapping_sub(y as u128) >> u64::BITS) as u64;
                assert_canonical(Condition::<u64>::from_msb(borrow), x < y);
            }
        }
    }

    #[test]
    fn is_bit_set() {
        // bit 0 agrees with from_lsb on every boundary value
        for v in BOUNDARY {
            assert_eq!(
                Condition::<u64>::is_bit_set(v, 0).to_bool(),
                Condition::<u64>::from_lsb(v).to_bool()
            );
        }
        // each single-bit value reports exactly its own bit
        for k in 0..u64::BITS {
            let v: u64 = 1 << k;
            for bit in 0..u64::BITS {
                assert_canonical(Condition::<u64>::is_bit_set(v, bit), bit == k);
            }
        }
        // the top bit agrees with from_msb
        for v in BOUNDARY {
            assert_eq!(
                Condition::<u64>::is_bit_set(v, u64::BITS - 1).to_bool(),
                Condition::<u64>::from_msb(v).to_bool()
            );
        }
    }

    #[test]
    fn is_zero_is_not_zero() {
        for v in BOUNDARY {
            assert_canonical(Condition::<u64>::is_zero(v), v == 0);
            assert_canonical(Condition::<u64>::is_not_zero(v), v != 0);
        }
    }

    #[test]
    fn is_equal() {
        for x in BOUNDARY {
            for y in BOUNDARY {
                assert_canonical(Condition::<u64>::is_equal(x, y), x == y);
            }
        }
    }

    #[test]
    fn select_preserves_all_bits() {
        // Patterned values (not just MAX/0) so a mask with any wrong bit shows up.
        let a: u64 = (0xDEADBEEFCAFEBABE_u64 & u64::MAX as u64) as u64;
        let b: u64 = (0x0123456789ABCDEF_u64 & u64::MAX as u64) as u64;
        assert_eq!(Condition::<u64>::TRUE.select(a, b), a);
        assert_eq!(Condition::<u64>::FALSE.select(a, b), b);
    }

    #[test]
    fn mov() {
        let src: u64 = 1;
        let mut dst: u64 = 2;
        Condition::<u64>::from_bool::<true>().mov(src, &mut dst);
        assert_eq!(dst, 1);
        dst = 2;
        Condition::<u64>::from_bool::<false>().mov(src, &mut dst);
        assert_eq!(dst, 2);
    }

    #[test]
    fn swap() {
        let (lhs, rhs) = Condition::<u64>::from_bool::<true>().swap(1, 2);
        assert_eq!((lhs, rhs), (2, 1));
        let (lhs, rhs) = Condition::<u64>::from_bool::<false>().swap(1, 2);
        assert_eq!((lhs, rhs), (1, 2));
    }

    #[test]
    fn boolean_operators() {
        let t = Condition::<u64>::TRUE;
        let f = Condition::<u64>::FALSE;
        assert_canonical(!t, false);
        assert_canonical(!f, true);
        assert_canonical(t & f, false);
        assert_canonical(t & t, true);
        assert_canonical(t | f, true);
        assert_canonical(f | f, false);
        assert_canonical(t ^ t, false);
        assert_canonical(t ^ f, true);
    }
}

#[cfg(test)]
mod unsigned_u32_tests {
    use super::*;

    const MSB: u32 = 1 << (u32::BITS - 1);
    const BOUNDARY: [u32; 5] = [0, 1, u32::MAX, u32::MAX - 1, MSB];

    /// A mask must be exactly all-ones or all-zeros: `to_bool` only tests non-zero,
    /// so a constructor returning `1` instead of all-ones would pass it and then
    /// quietly corrupt every select it feeds. The two select operands differ in
    /// every bit, so the assertion holds exactly when the mask is canonical.
    fn assert_canonical(cond: Condition<u32>, expected: bool) {
        const PATTERN: u32 = (0x5555_5555_5555_5555_u64 & (u32::MAX as u64)) as u32;
        let selected = cond.select(PATTERN, !PATTERN);
        assert_eq!(selected, if expected { PATTERN } else { !PATTERN });
        assert_eq!(cond.to_bool(), expected);
    }

    #[test]
    fn consts() {
        assert_canonical(Condition::<u32>::TRUE, true);
        assert_canonical(Condition::<u32>::FALSE, false);
    }

    #[test]
    fn from_bool() {
        assert_canonical(Condition::<u32>::from_bool::<true>(), true);
        assert_canonical(Condition::<u32>::from_bool::<false>(), false);
        assert_canonical(Condition::<u32>::from_bool_var(true), true);
        assert_canonical(Condition::<u32>::from_bool_var(false), false);
    }

    #[test]
    fn from_lsb() {
        for v in BOUNDARY {
            assert_canonical(Condition::<u32>::from_lsb(v), v & 1 == 1);
        }
    }

    #[test]
    fn from_msb() {
        for v in BOUNDARY {
            assert_canonical(Condition::<u32>::from_msb(v), v >> (u32::BITS - 1) == 1);
        }
    }

    /// `from_msb` exists to convert the borrow word of a wrapping subtraction chain
    /// into a mask: `(x - y) >> BITS` of the widening subtraction is all-ones in the
    /// low word iff x < y.
    #[test]
    fn from_msb_as_borrow_adaptor() {
        for x in BOUNDARY {
            for y in BOUNDARY {
                let borrow = ((x as u64).wrapping_sub(y as u64) >> u32::BITS) as u32;
                assert_canonical(Condition::<u32>::from_msb(borrow), x < y);
            }
        }
    }

    #[test]
    fn is_bit_set() {
        // bit 0 agrees with from_lsb on every boundary value
        for v in BOUNDARY {
            assert_eq!(
                Condition::<u32>::is_bit_set(v, 0).to_bool(),
                Condition::<u32>::from_lsb(v).to_bool()
            );
        }
        // each single-bit value reports exactly its own bit
        for k in 0..u32::BITS {
            let v: u32 = 1 << k;
            for bit in 0..u32::BITS {
                assert_canonical(Condition::<u32>::is_bit_set(v, bit), bit == k);
            }
        }
        // the top bit agrees with from_msb
        for v in BOUNDARY {
            assert_eq!(
                Condition::<u32>::is_bit_set(v, u32::BITS - 1).to_bool(),
                Condition::<u32>::from_msb(v).to_bool()
            );
        }
    }

    #[test]
    fn is_zero_is_not_zero() {
        for v in BOUNDARY {
            assert_canonical(Condition::<u32>::is_zero(v), v == 0);
            assert_canonical(Condition::<u32>::is_not_zero(v), v != 0);
        }
    }

    #[test]
    fn is_equal() {
        for x in BOUNDARY {
            for y in BOUNDARY {
                assert_canonical(Condition::<u32>::is_equal(x, y), x == y);
            }
        }
    }

    #[test]
    fn select_preserves_all_bits() {
        // Patterned values (not just MAX/0) so a mask with any wrong bit shows up.
        let a: u32 = (0xDEADBEEFCAFEBABE_u64 & u32::MAX as u64) as u32;
        let b: u32 = (0x0123456789ABCDEF_u64 & u32::MAX as u64) as u32;
        assert_eq!(Condition::<u32>::TRUE.select(a, b), a);
        assert_eq!(Condition::<u32>::FALSE.select(a, b), b);
    }

    #[test]
    fn mov() {
        let src: u32 = 1;
        let mut dst: u32 = 2;
        Condition::<u32>::from_bool::<true>().mov(src, &mut dst);
        assert_eq!(dst, 1);
        dst = 2;
        Condition::<u32>::from_bool::<false>().mov(src, &mut dst);
        assert_eq!(dst, 2);
    }

    #[test]
    fn swap() {
        let (lhs, rhs) = Condition::<u32>::from_bool::<true>().swap(1, 2);
        assert_eq!((lhs, rhs), (2, 1));
        let (lhs, rhs) = Condition::<u32>::from_bool::<false>().swap(1, 2);
        assert_eq!((lhs, rhs), (1, 2));
    }

    #[test]
    fn boolean_operators() {
        let t = Condition::<u32>::TRUE;
        let f = Condition::<u32>::FALSE;
        assert_canonical(!t, false);
        assert_canonical(!f, true);
        assert_canonical(t & f, false);
        assert_canonical(t & t, true);
        assert_canonical(t | f, true);
        assert_canonical(f | f, false);
        assert_canonical(t ^ t, false);
        assert_canonical(t ^ f, true);
    }
}

/// One test module per signed width, written out by hand like the impls they exercise; the
/// i64 and i32 modules must be edited together so the widths stay at exact behavioural
/// parity. Boundary set: 0, +/-1, MIN, MIN+1, MAX, MAX-1: the values where
/// overflow or sign-extension mistakes in the mask constructions would show up.
#[cfg(test)]
mod signed_i64_tests {
    use super::*;

    const BOUNDARY: [i64; 7] = [0, 1, -1, i64::MIN, i64::MIN + 1, i64::MAX, i64::MAX - 1];

    /// A mask must be exactly all-ones or all-zeros: `to_bool` only tests non-zero,
    /// so a constructor returning `1` instead of `-1` would pass it and then
    /// quietly corrupt every select it feeds. The two select operands differ in
    /// every bit, so the assertion holds exactly when the mask is canonical.
    fn assert_canonical(cond: Condition<i64>, expected: bool) {
        const PATTERN: i64 = (0x5555_5555_5555_5555_u64 & (i64::MAX as u64)) as i64;
        let selected = cond.select(PATTERN, !PATTERN);
        assert_eq!(selected, if expected { PATTERN } else { !PATTERN });
        assert_eq!(cond.to_bool(), expected);
    }

    #[test]
    fn consts() {
        assert_canonical(Condition::<i64>::TRUE, true);
        assert_canonical(Condition::<i64>::FALSE, false);
    }

    #[test]
    fn from_bool() {
        assert_canonical(Condition::<i64>::from_bool::<true>(), true);
        assert_canonical(Condition::<i64>::from_bool::<false>(), false);
        assert_canonical(Condition::<i64>::from_bool_var(true), true);
        assert_canonical(Condition::<i64>::from_bool_var(false), false);
    }

    #[test]
    fn from_lsb() {
        for v in BOUNDARY {
            assert_canonical(Condition::<i64>::from_lsb(v), v & 1 == 1);
        }
    }

    #[test]
    fn is_bit_set() {
        // bit 0 agrees with from_lsb on every boundary value
        for v in BOUNDARY {
            assert_eq!(
                Condition::<i64>::is_bit_set(v, 0).to_bool(),
                Condition::<i64>::from_lsb(v).to_bool()
            );
        }
        // each single-bit value reports exactly its own bit
        for k in 0..i64::BITS {
            let v: i64 = (1 as i64) << k;
            for bit in 0..i64::BITS {
                assert_canonical(Condition::<i64>::is_bit_set(v, bit), bit == k);
            }
        }
        // the top bit agrees with is_negative
        for v in BOUNDARY {
            assert_eq!(
                Condition::<i64>::is_bit_set(v, i64::BITS - 1).to_bool(),
                Condition::<i64>::is_negative(v).to_bool()
            );
        }
    }

    #[test]
    fn is_negative() {
        for v in BOUNDARY {
            assert_canonical(Condition::<i64>::is_negative(v), v < 0);
        }
    }

    #[test]
    fn is_zero_is_not_zero() {
        for v in BOUNDARY {
            assert_canonical(Condition::<i64>::is_zero(v), v == 0);
            assert_canonical(Condition::<i64>::is_not_zero(v), v != 0);
        }
    }

    #[test]
    fn is_equal() {
        for x in BOUNDARY {
            for y in BOUNDARY {
                assert_canonical(Condition::<i64>::is_equal(x, y), x == y);
            }
        }
    }

    /// Differential check against the native operators over every boundary pair,
    /// including the far-apart pairs where a subtract-and-check-sign construction
    /// would overflow.
    #[test]
    fn comparisons_match_native_operators() {
        for x in BOUNDARY {
            for y in BOUNDARY {
                assert_canonical(Condition::<i64>::is_lt(x, y), x < y);
                assert_canonical(Condition::<i64>::is_lte(x, y), x <= y);
                assert_canonical(Condition::<i64>::is_gt(x, y), x > y);
                assert_canonical(Condition::<i64>::is_gte(x, y), x >= y);
            }
        }
    }

    /// Regression for the former `is_negative(x - y)` construction, which
    /// overflowed for operands more than half the range apart (debug panic,
    /// opposite answer in release).
    #[test]
    fn is_lt_far_apart_operands() {
        assert_canonical(Condition::<i64>::is_lt(i64::MIN, 1), true);
        assert_canonical(Condition::<i64>::is_lt(1, i64::MIN), false);
        assert_canonical(Condition::<i64>::is_lt(i64::MIN, i64::MAX), true);
        assert_canonical(Condition::<i64>::is_lt(i64::MAX, i64::MIN), false);
    }

    #[test]
    fn is_within_range() {
        assert_canonical(Condition::<i64>::is_within_range(1, 0, 2), true);
        assert_canonical(Condition::<i64>::is_within_range(2, 0, 1), false);
        assert_canonical(Condition::<i64>::is_within_range(1, -5, 2), true);
        assert_canonical(Condition::<i64>::is_within_range(0, -5, 5), true);
        assert_canonical(Condition::<i64>::is_within_range(1, 0, 0), false);
        for v in BOUNDARY {
            for lo in BOUNDARY {
                for hi in BOUNDARY {
                    assert_canonical(
                        Condition::<i64>::is_within_range(v, lo, hi),
                        lo <= v && v <= hi,
                    );
                }
            }
        }
    }

    #[test]
    fn is_in_list() {
        assert_canonical(Condition::<i64>::is_in_list(1, &[1, 2, 3]), true);
        assert_canonical(Condition::<i64>::is_in_list(4, &[1, 2, 3]), false);
        assert_canonical(Condition::<i64>::is_in_list(-3, &[1, 2, 3, 4, -5, -1]), false);
        assert_canonical(Condition::<i64>::is_in_list(3, &[1, 2, 3, 3, 3, 3]), true);
    }

    #[test]
    fn select_preserves_all_bits() {
        // Patterned values (not just -1/0) so a mask with any wrong bit shows up.
        let a: i64 = (0xDEADBEEFCAFEBABE_u64 & (i64::MAX as u64)) as i64;
        let b: i64 = (0x0123456789ABCDEF_u64 & (i64::MAX as u64)) as i64;
        assert_eq!(Condition::<i64>::TRUE.select(a, b), a);
        assert_eq!(Condition::<i64>::FALSE.select(a, b), b);
    }

    #[test]
    fn mov() {
        let src: i64 = 1;
        let mut dst: i64 = 2;
        Condition::<i64>::from_bool::<true>().mov(src, &mut dst);
        assert_eq!(dst, 1);
        dst = 2;
        Condition::<i64>::from_bool::<false>().mov(src, &mut dst);
        assert_eq!(dst, 2);
    }

    #[test]
    fn negate() {
        let t = Condition::<i64>::TRUE;
        assert_eq!(t.negate(1), -1);
        assert_eq!(t.negate(0), 0);
        assert_eq!(t.negate(-1), 1);
        let f = Condition::<i64>::FALSE;
        assert_eq!(f.negate(1), 1);
        assert_eq!(f.negate(0), 0);
        assert_eq!(f.negate(-1), -1);
    }

    #[test]
    fn swap() {
        let (lhs, rhs) = Condition::<i64>::from_bool::<true>().swap(1, 2);
        assert_eq!((lhs, rhs), (2, 1));
        let (lhs, rhs) = Condition::<i64>::from_bool::<false>().swap(1, 2);
        assert_eq!((lhs, rhs), (1, 2));
    }

    #[test]
    fn boolean_operators() {
        let t = Condition::<i64>::TRUE;
        let f = Condition::<i64>::FALSE;
        assert_canonical(!t, false);
        assert_canonical(!f, true);
        assert_canonical(t & f, false);
        assert_canonical(t & t, true);
        assert_canonical(t | f, true);
        assert_canonical(f | f, false);
        assert_canonical(t ^ t, false);
        assert_canonical(t ^ f, true);
    }
}

#[cfg(test)]
mod signed_i32_tests {
    use super::*;

    const BOUNDARY: [i32; 7] = [0, 1, -1, i32::MIN, i32::MIN + 1, i32::MAX, i32::MAX - 1];

    /// A mask must be exactly all-ones or all-zeros: `to_bool` only tests non-zero,
    /// so a constructor returning `1` instead of `-1` would pass it and then
    /// quietly corrupt every select it feeds. The two select operands differ in
    /// every bit, so the assertion holds exactly when the mask is canonical.
    fn assert_canonical(cond: Condition<i32>, expected: bool) {
        const PATTERN: i32 = (0x5555_5555_5555_5555_u64 & (i32::MAX as u64)) as i32;
        let selected = cond.select(PATTERN, !PATTERN);
        assert_eq!(selected, if expected { PATTERN } else { !PATTERN });
        assert_eq!(cond.to_bool(), expected);
    }

    #[test]
    fn consts() {
        assert_canonical(Condition::<i32>::TRUE, true);
        assert_canonical(Condition::<i32>::FALSE, false);
    }

    #[test]
    fn from_bool() {
        assert_canonical(Condition::<i32>::from_bool::<true>(), true);
        assert_canonical(Condition::<i32>::from_bool::<false>(), false);
        assert_canonical(Condition::<i32>::from_bool_var(true), true);
        assert_canonical(Condition::<i32>::from_bool_var(false), false);
    }

    #[test]
    fn from_lsb() {
        for v in BOUNDARY {
            assert_canonical(Condition::<i32>::from_lsb(v), v & 1 == 1);
        }
    }

    #[test]
    fn is_bit_set() {
        // bit 0 agrees with from_lsb on every boundary value
        for v in BOUNDARY {
            assert_eq!(
                Condition::<i32>::is_bit_set(v, 0).to_bool(),
                Condition::<i32>::from_lsb(v).to_bool()
            );
        }
        // each single-bit value reports exactly its own bit
        for k in 0..i32::BITS {
            let v: i32 = (1 as i32) << k;
            for bit in 0..i32::BITS {
                assert_canonical(Condition::<i32>::is_bit_set(v, bit), bit == k);
            }
        }
        // the top bit agrees with is_negative
        for v in BOUNDARY {
            assert_eq!(
                Condition::<i32>::is_bit_set(v, i32::BITS - 1).to_bool(),
                Condition::<i32>::is_negative(v).to_bool()
            );
        }
    }

    #[test]
    fn is_negative() {
        for v in BOUNDARY {
            assert_canonical(Condition::<i32>::is_negative(v), v < 0);
        }
    }

    #[test]
    fn is_zero_is_not_zero() {
        for v in BOUNDARY {
            assert_canonical(Condition::<i32>::is_zero(v), v == 0);
            assert_canonical(Condition::<i32>::is_not_zero(v), v != 0);
        }
    }

    #[test]
    fn is_equal() {
        for x in BOUNDARY {
            for y in BOUNDARY {
                assert_canonical(Condition::<i32>::is_equal(x, y), x == y);
            }
        }
    }

    /// Differential check against the native operators over every boundary pair,
    /// including the far-apart pairs where a subtract-and-check-sign construction
    /// would overflow.
    #[test]
    fn comparisons_match_native_operators() {
        for x in BOUNDARY {
            for y in BOUNDARY {
                assert_canonical(Condition::<i32>::is_lt(x, y), x < y);
                assert_canonical(Condition::<i32>::is_lte(x, y), x <= y);
                assert_canonical(Condition::<i32>::is_gt(x, y), x > y);
                assert_canonical(Condition::<i32>::is_gte(x, y), x >= y);
            }
        }
    }

    /// Regression for the former `is_negative(x - y)` construction, which
    /// overflowed for operands more than half the range apart (debug panic,
    /// opposite answer in release).
    #[test]
    fn is_lt_far_apart_operands() {
        assert_canonical(Condition::<i32>::is_lt(i32::MIN, 1), true);
        assert_canonical(Condition::<i32>::is_lt(1, i32::MIN), false);
        assert_canonical(Condition::<i32>::is_lt(i32::MIN, i32::MAX), true);
        assert_canonical(Condition::<i32>::is_lt(i32::MAX, i32::MIN), false);
    }

    #[test]
    fn is_within_range() {
        assert_canonical(Condition::<i32>::is_within_range(1, 0, 2), true);
        assert_canonical(Condition::<i32>::is_within_range(2, 0, 1), false);
        assert_canonical(Condition::<i32>::is_within_range(1, -5, 2), true);
        assert_canonical(Condition::<i32>::is_within_range(0, -5, 5), true);
        assert_canonical(Condition::<i32>::is_within_range(1, 0, 0), false);
        for v in BOUNDARY {
            for lo in BOUNDARY {
                for hi in BOUNDARY {
                    assert_canonical(
                        Condition::<i32>::is_within_range(v, lo, hi),
                        lo <= v && v <= hi,
                    );
                }
            }
        }
    }

    #[test]
    fn is_in_list() {
        assert_canonical(Condition::<i32>::is_in_list(1, &[1, 2, 3]), true);
        assert_canonical(Condition::<i32>::is_in_list(4, &[1, 2, 3]), false);
        assert_canonical(Condition::<i32>::is_in_list(-3, &[1, 2, 3, 4, -5, -1]), false);
        assert_canonical(Condition::<i32>::is_in_list(3, &[1, 2, 3, 3, 3, 3]), true);
    }

    #[test]
    fn select_preserves_all_bits() {
        // Patterned values (not just -1/0) so a mask with any wrong bit shows up.
        let a: i32 = (0xDEADBEEFCAFEBABE_u64 & (i32::MAX as u64)) as i32;
        let b: i32 = (0x0123456789ABCDEF_u64 & (i32::MAX as u64)) as i32;
        assert_eq!(Condition::<i32>::TRUE.select(a, b), a);
        assert_eq!(Condition::<i32>::FALSE.select(a, b), b);
    }

    #[test]
    fn mov() {
        let src: i32 = 1;
        let mut dst: i32 = 2;
        Condition::<i32>::from_bool::<true>().mov(src, &mut dst);
        assert_eq!(dst, 1);
        dst = 2;
        Condition::<i32>::from_bool::<false>().mov(src, &mut dst);
        assert_eq!(dst, 2);
    }

    #[test]
    fn negate() {
        let t = Condition::<i32>::TRUE;
        assert_eq!(t.negate(1), -1);
        assert_eq!(t.negate(0), 0);
        assert_eq!(t.negate(-1), 1);
        let f = Condition::<i32>::FALSE;
        assert_eq!(f.negate(1), 1);
        assert_eq!(f.negate(0), 0);
        assert_eq!(f.negate(-1), -1);
    }

    #[test]
    fn swap() {
        let (lhs, rhs) = Condition::<i32>::from_bool::<true>().swap(1, 2);
        assert_eq!((lhs, rhs), (2, 1));
        let (lhs, rhs) = Condition::<i32>::from_bool::<false>().swap(1, 2);
        assert_eq!((lhs, rhs), (1, 2));
    }

    #[test]
    fn boolean_operators() {
        let t = Condition::<i32>::TRUE;
        let f = Condition::<i32>::FALSE;
        assert_canonical(!t, false);
        assert_canonical(!f, true);
        assert_canonical(t & f, false);
        assert_canonical(t & t, true);
        assert_canonical(t | f, true);
        assert_canonical(f | f, false);
        assert_canonical(t ^ t, false);
        assert_canonical(t ^ f, true);
    }
}

#[cfg(test)]
mod signed_comparison_sweep {
    use super::*;

    /// Dense sweep of the full i32 range: 256 x 256 pairs stepped 1 << 24 apart, checked
    /// against the native operators. This covers every combination of sign and magnitude
    /// region, not just the BOUNDARY values.
    #[test]
    fn i32_strided_full_range() {
        for a in (i32::MIN..=i32::MAX).step_by(1 << 24) {
            for b in (i32::MIN..=i32::MAX).step_by(1 << 24) {
                assert_eq!(Condition::<i32>::is_lt(a, b).to_bool(), a < b, "{a} {b}");
                assert_eq!(Condition::<i32>::is_lte(a, b).to_bool(), a <= b, "{a} {b}");
                assert_eq!(Condition::<i32>::is_gt(a, b).to_bool(), a > b, "{a} {b}");
                assert_eq!(Condition::<i32>::is_gte(a, b).to_bool(), a >= b, "{a} {b}");
            }
        }
    }
}

#[cfg(test)]
mod ct_bytes_tests {
    #[test]
    fn test_ct_eq_bytes() {
        use bouncycastle_utils::ct::ct_eq_bytes;

        // equal inputs, including the empty slice
        assert!(ct_eq_bytes(&[], &[]));
        assert!(ct_eq_bytes(&[0x42], &[0x42]));
        assert!(ct_eq_bytes(&[0xAA; 32], &[0xAA; 32]));

        // a length mismatch is never equal, even when the shorter is a prefix
        assert!(!ct_eq_bytes(&[], &[0]));
        assert!(!ct_eq_bytes(&[1, 2, 3], &[1, 2]));

        // a differing byte anywhere must be detected: first, last, and single-bit-only
        let a = [0xAA; 32];
        let mut b = [0xAA; 32];
        b[0] = 0xAB;
        assert!(!ct_eq_bytes(&a, &b));
        b[0] = 0xAA;
        b[31] = 0xAB;
        assert!(!ct_eq_bytes(&a, &b));
        b[31] = 0xAA;
        b[15] ^= 0x80;
        assert!(!ct_eq_bytes(&a, &b));
    }

    #[test]
    fn test_ct_eq_zero_bytes() {
        use bouncycastle_utils::ct::ct_eq_zero_bytes;

        // all-zero inputs, including the empty slice
        assert!(ct_eq_zero_bytes(&[]));
        assert!(ct_eq_zero_bytes(&[0]));
        assert!(ct_eq_zero_bytes(&[0; 32]));

        // a nonzero byte anywhere must be detected: first, last, and high-bit-only
        assert!(!ct_eq_zero_bytes(&[1]));
        let mut buf = [0u8; 32];
        buf[0] = 1;
        assert!(!ct_eq_zero_bytes(&buf));
        buf[0] = 0;
        buf[31] = 1;
        assert!(!ct_eq_zero_bytes(&buf));
        buf[31] = 0;
        buf[15] = 0x80;
        assert!(!ct_eq_zero_bytes(&buf));
    }

    #[test]
    fn test_conditional_copy_bytes() {
        use bouncycastle_utils::ct::conditional_copy_bytes;

        let a = [0x01, 0x02, 0x03, 0x04];
        let b = [0x10, 0x11, 0x12, 0x13];
        let mut out = [0u8; 4];

        conditional_copy_bytes(&a, &b, &mut out, true);
        assert_eq!(out, [0x01, 0x02, 0x03, 0x04]);

        conditional_copy_bytes(&a, &b, &mut out, false);
        assert_eq!(out, [0x10, 0x11, 0x12, 0x13]);

        // test wrong-sized array
        // in fact: this won't even compile, so there's nothing to test
        // let c = [0x20, 0x21, 0x22];
        // conditional_copy_bytes(&a, &c, &mut out, false);
    }
}
