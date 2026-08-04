use bouncycastle_utils::ct::Condition;

/// These do not validate the constant-time-ness; these are simply basic correctness tests
/// (and example usages)

#[cfg(test)]
mod i64_tests {
    use super::*;

    #[test]
    fn const_tests() {
        assert_eq!(Condition::<i64>::TRUE.to_bool(), true);
        assert_eq!(Condition::<i64>::FALSE.to_bool(), false);
    }

    #[test]
    fn from_bool() {
        assert_eq!(Condition::<i64>::from_bool::<true>().to_bool(), true);
        assert_eq!(Condition::<i64>::from_bool::<false>().to_bool(), false);

        let btrue: bool = true;
        let bfalse: bool = false;
        assert_eq!(Condition::<i64>::from_bool_var(btrue).to_bool(), true);
        assert_eq!(Condition::<i64>::from_bool_var(bfalse).to_bool(), false);
    }

    #[test]
    fn is_bit_set() {
        assert_eq!(Condition::<i64>::is_bit_set(1, 0).to_bool(), true);
        assert_eq!(Condition::<i64>::is_bit_set(1, 1).to_bool(), false);
        assert_eq!(Condition::<i64>::is_bit_set(8, 3).to_bool(), true);
    }

    #[test]
    fn is_negative() {
        assert_eq!(Condition::<i64>::is_negative(-1).to_bool(), true);
        assert_eq!(Condition::<i64>::is_negative(0).to_bool(), false);
        assert_eq!(Condition::<i64>::is_negative(1).to_bool(), false);
        assert_eq!(Condition::<i64>::is_negative(1 << 12).to_bool(), false);
    }

    #[test]
    fn is_not_zero() {
        assert_eq!(Condition::<i64>::is_not_zero(1).to_bool(), true);
        assert_eq!(Condition::<i64>::is_not_zero(0).to_bool(), false);
        assert_eq!(Condition::<i64>::is_not_zero(1 << 12).to_bool(), true);
        assert_eq!(Condition::<i64>::is_not_zero(-10).to_bool(), true);
    }

    #[test]
    fn is_zero() {
        assert_eq!(Condition::<i64>::is_zero(1).to_bool(), false);
        assert_eq!(Condition::<i64>::is_zero(0).to_bool(), true);
        assert_eq!(Condition::<i64>::is_zero(1 << 12).to_bool(), false);
    }

    #[test]
    fn is_equal() {
        assert_eq!(Condition::<i64>::is_equal(1, 1).to_bool(), true);
        assert_eq!(Condition::<i64>::is_equal(1, 2).to_bool(), false);
        assert_eq!(Condition::<i64>::is_equal(1, -1).to_bool(), false);
    }

    #[test]
    fn is_lt() {
        assert_eq!(Condition::<i64>::is_lt(1, 2).to_bool(), true);
        assert_eq!(Condition::<i64>::is_lt(2, 1).to_bool(), false);
        assert_eq!(Condition::<i64>::is_lt(2, 2).to_bool(), false);
        assert_eq!(Condition::<i64>::is_lt(0, 1).to_bool(), true);
        assert_eq!(Condition::<i64>::is_lt(-100, -99).to_bool(), true);
        assert_eq!(Condition::<i64>::is_lt(-98, 98).to_bool(), true);

        let mut i: i64 = 0;
        assert_eq!(Condition::<i64>::is_lt(i, 1).to_bool(), true);
        assert_eq!(Condition::<i64>::is_lt(i, -1).to_bool(), false);
        i = 1;
        assert_eq!(Condition::<i64>::is_lt(i, 1).to_bool(), false);
    }

    #[test]
    fn is_lte() {
        assert_eq!(Condition::<i64>::is_lte(1, 2).to_bool(), true);
        assert_eq!(Condition::<i64>::is_lte(2, 1).to_bool(), false);
        assert_eq!(Condition::<i64>::is_lte(2, 2).to_bool(), true);
        assert_eq!(Condition::<i64>::is_lte(0, 1).to_bool(), true);
        assert_eq!(Condition::<i64>::is_lte(-100, -99).to_bool(), true);
        assert_eq!(Condition::<i64>::is_lte(-98, 98).to_bool(), true);
    }

    #[test]
    fn is_gt() {
        assert_eq!(Condition::<i64>::is_gt(1, 2).to_bool(), false);
        assert_eq!(Condition::<i64>::is_gt(2, 1).to_bool(), true);
        assert_eq!(Condition::<i64>::is_gt(2, 2).to_bool(), false);
        assert_eq!(Condition::<i64>::is_gt(0, 1).to_bool(), false);
        assert_eq!(Condition::<i64>::is_gt(-100, -99).to_bool(), false);
        assert_eq!(Condition::<i64>::is_gt(-98, 98).to_bool(), false);
    }

    #[test]
    fn is_gte() {
        assert_eq!(Condition::<i64>::is_gte(1, 2).to_bool(), false);
        assert_eq!(Condition::<i64>::is_gte(2, 1).to_bool(), true);
        assert_eq!(Condition::<i64>::is_gte(2, 2).to_bool(), true);
        assert_eq!(Condition::<i64>::is_gte(0, 1).to_bool(), false);
        assert_eq!(Condition::<i64>::is_gte(-100, -99).to_bool(), false);
        assert_eq!(Condition::<i64>::is_gte(-98, 98).to_bool(), false);
    }

    #[test]
    fn is_in_range() {
        assert_eq!(Condition::<i64>::is_within_range(1, 0, 2).to_bool(), true);
        assert_eq!(Condition::<i64>::is_within_range(2, 0, 1).to_bool(), false);
        assert_eq!(Condition::<i64>::is_within_range(1, -5, 2).to_bool(), true);
        assert_eq!(Condition::<i64>::is_within_range(0, -5, 5).to_bool(), true);
        assert_eq!(Condition::<i64>::is_within_range(1, 0, 0).to_bool(), false);
    }

    #[test]
    fn is_in_list() {
        assert_eq!(Condition::<i64>::is_in_list(1, &[1, 2, 3]).to_bool(), true);
        assert_eq!(Condition::<i64>::is_in_list(4, &[1, 2, 3]).to_bool(), false);
        assert_eq!(Condition::<i64>::is_in_list(-3, &[1, 2, 3, 4, -5, -1]).to_bool(), false);
        assert_eq!(Condition::<i64>::is_in_list(3, &[1, 2, 3, 3, 3, 3]).to_bool(), true);
    }

    #[test]
    fn masks_are_canonical() {
        // A mask must be exactly all-ones or all-zeros. Every correct implementation also
        // passes a plain truthiness check; this test exists to catch a mutant that a
        // truthiness check cannot: to_bool() only tests non-zero, so a constructor
        // returning 1 instead of -1 would pass it and then quietly zero the upper 63 bits
        // of every select it feeds. The two select operands below differ in every bit, so
        // select returns PATTERN exactly when the mask is all-ones and !PATTERN exactly
        // when it is all-zeros: any other mask bit pattern fails the assertion.
        const PATTERN: i64 = 0x5555_5555_5555_5555;
        fn assert_canonical(c: Condition<i64>, expected: bool) {
            assert_eq!(c.select(PATTERN, !PATTERN), if expected { PATTERN } else { !PATTERN });
        }
        assert_canonical(Condition::<i64>::from_bool_var(true), true);
        assert_canonical(Condition::<i64>::from_bool_var(false), false);
        assert_canonical(Condition::<i64>::from_bool::<true>(), true);
        assert_canonical(Condition::<i64>::from_bool::<false>(), false);
        assert_canonical(Condition::<i64>::is_bit_set(1, 0), true);
        assert_canonical(Condition::<i64>::is_bit_set(8, 3), true);
        assert_canonical(Condition::<i64>::is_bit_set(8, 2), false);
        assert_canonical(Condition::<i64>::is_negative(-5), true);
        assert_canonical(Condition::<i64>::is_negative(5), false);
        assert_canonical(Condition::<i64>::is_zero(0), true);
        assert_canonical(Condition::<i64>::is_zero(7), false);
        assert_canonical(Condition::<i64>::is_not_zero(7), true);
        assert_canonical(Condition::<i64>::is_equal(3, 3), true);
        assert_canonical(Condition::<i64>::is_equal(3, 4), false);
        assert_canonical(Condition::<i64>::is_lt(3, 4), true);
        assert_canonical(Condition::<i64>::is_lt(4, 3), false);
    }

    #[test]
    fn test_mov() {
        let src = 1;
        let mut dst = 2;
        let c1 = Condition::<i64>::from_bool::<true>();
        c1.mov(src, &mut dst);
        assert_eq!(dst, 1);

        let c2 = Condition::<i64>::from_bool::<false>();
        dst = 2;
        c2.mov(src, &mut dst);
        assert_eq!(dst, 2);
    }

    #[test]
    fn test_negate() {
        let c1 = Condition::<i64>::TRUE;
        assert_eq!(c1.negate(1), -1);
        assert_eq!(c1.negate(0), 0);
        assert_eq!(c1.negate(-1), 1);

        let c2 = Condition::<i64>::FALSE;
        assert_eq!(c2.negate(1), 1);
        assert_eq!(c2.negate(0), 0);
        assert_eq!(c2.negate(-1), -1);
    }

    #[test]
    fn test_select() {
        let c = Condition::<i64>::from_bool::<true>();
        assert_eq!(c.select(1, 2), 1);
        assert_eq!((!c).select(1, 2), 2);

        // or the inverse behaviour if you start with 'false'.
        let cfalse = Condition::<i64>::from_bool::<false>();
        assert_eq!(cfalse.select(1, 2), 2);
        assert_eq!((!cfalse).select(1, 2), 1);
    }

    #[test]
    fn test_swap() {
        let c = Condition::<i64>::from_bool::<true>();
        let (lhs, rhs) = c.swap(1, 2);
        assert_eq!(lhs, 2);
        assert_eq!(rhs, 1);

        // or the inverse behaviour if you start with 'false'.
        let c = Condition::<i64>::from_bool::<false>();
        let (lhs, rhs) = c.swap(1, 2);
        assert_eq!(lhs, 1);
        assert_eq!(rhs, 2);
    }
}

#[cfg(test)]
mod u64_tests {
    use super::*;

    #[test]
    fn const_tests() {
        // Ensure TRUE/FALSE are correctly interpreted as boolean.
        assert_eq!(Condition::<u64>::TRUE.to_bool(), true);
        assert_eq!(Condition::<u64>::FALSE.to_bool(), false);
    }

    #[test]
    fn from_bool() {
        // Compile-time const generics check
        assert_eq!(Condition::<u64>::from_bool::<true>().to_bool(), true);
        assert_eq!(Condition::<u64>::from_bool::<false>().to_bool(), false);
    }

    #[test]
    fn select() {
        let t = Condition::<u64>::TRUE;
        let f = Condition::<u64>::FALSE;

        let val1: u64 = 0xDEADBEEFCAFEBABE;
        let val2: u64 = 0x0000000000000000;

        // This test is CRITICAL.
        //   If TRUE was defined as '1' (like i64), this would fail because 'select' relies on bitwise mask.
        //   It requires TRUE to be u64::MAX (all 1s) to preserve the full bits of val1.
        assert_eq!(t.select(val1, val2), val1);
        assert_eq!(f.select(val1, val2), val2);

        // Cross check with from_bool
        let t_gen = Condition::<u64>::from_bool::<true>();
        assert_eq!(t_gen.select(val1, val2), val1);
    }

    #[test]
    fn bit_ops() {
        let t = Condition::<u64>::TRUE;
        let f = Condition::<u64>::FALSE;

        // NOT
        assert_eq!((!t).to_bool(), false);
        assert_eq!((!f).to_bool(), true);

        // AND
        assert_eq!((t & t).to_bool(), true);
        assert_eq!((t & f).to_bool(), false);
        assert_eq!((f & f).to_bool(), false);

        // OR
        assert_eq!((t | t).to_bool(), true);
        assert_eq!((t | f).to_bool(), true);
        assert_eq!((f | f).to_bool(), false);

        // XOR
        assert_eq!((t ^ t).to_bool(), false);
        assert_eq!((t ^ f).to_bool(), true);
    }
}

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
        assert_eq!((ct1 | cf1).to_bool(), true);
        assert_eq!((cf1 | cf2).to_bool(), false);
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

/// One test module per unsigned width, generated from the same macro so u64 and u32 stay at
/// exact behavioural parity. Boundary set: 0, 1, MAX, MAX-1, 1 << (BITS-1) — the values where
/// signed-representation tricks would produce wrong masks if they had leaked into the
/// unsigned constructions.
macro_rules! unsigned_condition_tests {
    ($mod_name:ident, $t:ty, $wide:ty) => {
        #[cfg(test)]
        mod $mod_name {
            use super::*;

            const MSB: $t = 1 << (<$t>::BITS - 1);
            const BOUNDARY: [$t; 5] = [0, 1, <$t>::MAX, <$t>::MAX - 1, MSB];

            /// A mask must be exactly all-ones or all-zeros: `to_bool` only tests non-zero,
            /// so a constructor returning `1` instead of all-ones would pass it and then
            /// quietly corrupt every select it feeds. The two select operands differ in
            /// every bit, so the assertion holds exactly when the mask is canonical.
            fn assert_canonical(cond: Condition<$t>, expected: bool) {
                const PATTERN: $t = (0x5555_5555_5555_5555_u64 & (<$t>::MAX as u64)) as $t;
                let selected = cond.select(PATTERN, !PATTERN);
                assert_eq!(selected, if expected { PATTERN } else { !PATTERN });
                assert_eq!(cond.to_bool(), expected);
            }

            #[test]
            fn consts() {
                assert_canonical(Condition::<$t>::TRUE, true);
                assert_canonical(Condition::<$t>::FALSE, false);
            }

            #[test]
            fn from_bool() {
                assert_canonical(Condition::<$t>::from_bool::<true>(), true);
                assert_canonical(Condition::<$t>::from_bool::<false>(), false);
                assert_canonical(Condition::<$t>::from_bool_var(true), true);
                assert_canonical(Condition::<$t>::from_bool_var(false), false);
            }

            #[test]
            fn from_lsb() {
                for v in BOUNDARY {
                    assert_canonical(Condition::<$t>::from_lsb(v), v & 1 == 1);
                }
            }

            #[test]
            fn from_msb() {
                for v in BOUNDARY {
                    assert_canonical(Condition::<$t>::from_msb(v), v >> (<$t>::BITS - 1) == 1);
                }
            }

            /// `from_msb` exists to convert the borrow word of a wrapping subtraction chain
            /// into a mask: `(x - y) >> BITS` of the widening subtraction is all-ones in the
            /// low word iff x < y.
            #[test]
            fn from_msb_as_borrow_adaptor() {
                for x in BOUNDARY {
                    for y in BOUNDARY {
                        let borrow = ((x as $wide).wrapping_sub(y as $wide) >> <$t>::BITS) as $t;
                        assert_canonical(Condition::<$t>::from_msb(borrow), x < y);
                    }
                }
            }

            #[test]
            fn is_bit_set() {
                // bit 0 agrees with from_lsb on every boundary value
                for v in BOUNDARY {
                    assert_eq!(
                        Condition::<$t>::is_bit_set(v, 0).to_bool(),
                        Condition::<$t>::from_lsb(v).to_bool()
                    );
                }
                // each single-bit value reports exactly its own bit
                for k in 0..<$t>::BITS {
                    let v: $t = 1 << k;
                    for bit in 0..<$t>::BITS {
                        assert_canonical(Condition::<$t>::is_bit_set(v, bit), bit == k);
                    }
                }
                // the top bit agrees with from_msb
                for v in BOUNDARY {
                    assert_eq!(
                        Condition::<$t>::is_bit_set(v, <$t>::BITS - 1).to_bool(),
                        Condition::<$t>::from_msb(v).to_bool()
                    );
                }
            }

            #[test]
            fn is_zero_is_not_zero() {
                for v in BOUNDARY {
                    assert_canonical(Condition::<$t>::is_zero(v), v == 0);
                    assert_canonical(Condition::<$t>::is_not_zero(v), v != 0);
                }
            }

            #[test]
            fn is_equal() {
                for x in BOUNDARY {
                    for y in BOUNDARY {
                        assert_canonical(Condition::<$t>::is_equal(x, y), x == y);
                    }
                }
            }

            #[test]
            fn select_preserves_all_bits() {
                // Patterned values (not just MAX/0) so a mask with any wrong bit shows up.
                let a: $t = (0xDEADBEEFCAFEBABE_u64 & <$t>::MAX as u64) as $t;
                let b: $t = (0x0123456789ABCDEF_u64 & <$t>::MAX as u64) as $t;
                assert_eq!(Condition::<$t>::TRUE.select(a, b), a);
                assert_eq!(Condition::<$t>::FALSE.select(a, b), b);
            }

            #[test]
            fn mov() {
                let src: $t = 1;
                let mut dst: $t = 2;
                Condition::<$t>::from_bool::<true>().mov(src, &mut dst);
                assert_eq!(dst, 1);
                dst = 2;
                Condition::<$t>::from_bool::<false>().mov(src, &mut dst);
                assert_eq!(dst, 2);
            }

            #[test]
            fn swap() {
                let (lhs, rhs) = Condition::<$t>::from_bool::<true>().swap(1, 2);
                assert_eq!((lhs, rhs), (2, 1));
                let (lhs, rhs) = Condition::<$t>::from_bool::<false>().swap(1, 2);
                assert_eq!((lhs, rhs), (1, 2));
            }

            #[test]
            fn boolean_operators() {
                let t = Condition::<$t>::TRUE;
                let f = Condition::<$t>::FALSE;
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
    };
}

unsigned_condition_tests!(unsigned_u64_tests, u64, u128);
unsigned_condition_tests!(unsigned_u32_tests, u32, u64);

/// One test module per signed width, generated from the same macro so i64 and i32 stay at
/// exact behavioural parity. Boundary set: 0, +/-1, MIN, MIN+1, MAX, MAX-1: the values where
/// overflow or sign-extension mistakes in the mask constructions would show up.
macro_rules! signed_condition_tests {
    ($mod_name:ident, $t:ty) => {
        #[cfg(test)]
        mod $mod_name {
            use super::*;

            const BOUNDARY: [$t; 7] =
                [0, 1, -1, <$t>::MIN, <$t>::MIN + 1, <$t>::MAX, <$t>::MAX - 1];

            /// A mask must be exactly all-ones or all-zeros: `to_bool` only tests non-zero,
            /// so a constructor returning `1` instead of `-1` would pass it and then
            /// quietly corrupt every select it feeds. The two select operands differ in
            /// every bit, so the assertion holds exactly when the mask is canonical.
            fn assert_canonical(cond: Condition<$t>, expected: bool) {
                const PATTERN: $t = (0x5555_5555_5555_5555_u64 & (<$t>::MAX as u64)) as $t;
                let selected = cond.select(PATTERN, !PATTERN);
                assert_eq!(selected, if expected { PATTERN } else { !PATTERN });
                assert_eq!(cond.to_bool(), expected);
            }

            #[test]
            fn consts() {
                assert_canonical(Condition::<$t>::TRUE, true);
                assert_canonical(Condition::<$t>::FALSE, false);
            }

            #[test]
            fn from_bool() {
                assert_canonical(Condition::<$t>::from_bool::<true>(), true);
                assert_canonical(Condition::<$t>::from_bool::<false>(), false);
                assert_canonical(Condition::<$t>::from_bool_var(true), true);
                assert_canonical(Condition::<$t>::from_bool_var(false), false);
            }

            #[test]
            fn from_lsb() {
                for v in BOUNDARY {
                    assert_canonical(Condition::<$t>::from_lsb(v), v & 1 == 1);
                }
            }

            #[test]
            fn is_bit_set() {
                // bit 0 agrees with from_lsb on every boundary value
                for v in BOUNDARY {
                    assert_eq!(
                        Condition::<$t>::is_bit_set(v, 0).to_bool(),
                        Condition::<$t>::from_lsb(v).to_bool()
                    );
                }
                // each single-bit value reports exactly its own bit
                for k in 0..<$t>::BITS {
                    let v: $t = (1 as $t) << k;
                    for bit in 0..<$t>::BITS {
                        assert_canonical(Condition::<$t>::is_bit_set(v, bit), bit == k);
                    }
                }
                // the top bit agrees with is_negative
                for v in BOUNDARY {
                    assert_eq!(
                        Condition::<$t>::is_bit_set(v, <$t>::BITS - 1).to_bool(),
                        Condition::<$t>::is_negative(v).to_bool()
                    );
                }
            }

            #[test]
            fn is_negative() {
                for v in BOUNDARY {
                    assert_canonical(Condition::<$t>::is_negative(v), v < 0);
                }
            }

            #[test]
            fn is_zero_is_not_zero() {
                for v in BOUNDARY {
                    assert_canonical(Condition::<$t>::is_zero(v), v == 0);
                    assert_canonical(Condition::<$t>::is_not_zero(v), v != 0);
                }
            }

            #[test]
            fn is_equal() {
                for x in BOUNDARY {
                    for y in BOUNDARY {
                        assert_canonical(Condition::<$t>::is_equal(x, y), x == y);
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
                        assert_canonical(Condition::<$t>::is_lt(x, y), x < y);
                        assert_canonical(Condition::<$t>::is_lte(x, y), x <= y);
                        assert_canonical(Condition::<$t>::is_gt(x, y), x > y);
                        assert_canonical(Condition::<$t>::is_gte(x, y), x >= y);
                    }
                }
            }

            /// Regression for the former `is_negative(x - y)` construction, which
            /// overflowed for operands more than half the range apart (debug panic,
            /// opposite answer in release).
            #[test]
            fn is_lt_far_apart_operands() {
                assert_canonical(Condition::<$t>::is_lt(<$t>::MIN, 1), true);
                assert_canonical(Condition::<$t>::is_lt(1, <$t>::MIN), false);
                assert_canonical(Condition::<$t>::is_lt(<$t>::MIN, <$t>::MAX), true);
                assert_canonical(Condition::<$t>::is_lt(<$t>::MAX, <$t>::MIN), false);
            }

            #[test]
            fn is_within_range() {
                assert_canonical(Condition::<$t>::is_within_range(1, 0, 2), true);
                assert_canonical(Condition::<$t>::is_within_range(2, 0, 1), false);
                assert_canonical(Condition::<$t>::is_within_range(1, -5, 2), true);
                assert_canonical(Condition::<$t>::is_within_range(0, -5, 5), true);
                assert_canonical(Condition::<$t>::is_within_range(1, 0, 0), false);
                for v in BOUNDARY {
                    for lo in BOUNDARY {
                        for hi in BOUNDARY {
                            assert_canonical(
                                Condition::<$t>::is_within_range(v, lo, hi),
                                lo <= v && v <= hi,
                            );
                        }
                    }
                }
            }

            #[test]
            fn is_in_list() {
                assert_canonical(Condition::<$t>::is_in_list(1, &[1, 2, 3]), true);
                assert_canonical(Condition::<$t>::is_in_list(4, &[1, 2, 3]), false);
                assert_canonical(Condition::<$t>::is_in_list(-3, &[1, 2, 3, 4, -5, -1]), false);
                assert_canonical(Condition::<$t>::is_in_list(3, &[1, 2, 3, 3, 3, 3]), true);
            }

            #[test]
            fn select_preserves_all_bits() {
                // Patterned values (not just -1/0) so a mask with any wrong bit shows up.
                let a: $t = (0xDEADBEEFCAFEBABE_u64 & (<$t>::MAX as u64)) as $t;
                let b: $t = (0x0123456789ABCDEF_u64 & (<$t>::MAX as u64)) as $t;
                assert_eq!(Condition::<$t>::TRUE.select(a, b), a);
                assert_eq!(Condition::<$t>::FALSE.select(a, b), b);
            }

            #[test]
            fn mov() {
                let src: $t = 1;
                let mut dst: $t = 2;
                Condition::<$t>::from_bool::<true>().mov(src, &mut dst);
                assert_eq!(dst, 1);
                dst = 2;
                Condition::<$t>::from_bool::<false>().mov(src, &mut dst);
                assert_eq!(dst, 2);
            }

            #[test]
            fn negate() {
                let t = Condition::<$t>::TRUE;
                assert_eq!(t.negate(1), -1);
                assert_eq!(t.negate(0), 0);
                assert_eq!(t.negate(-1), 1);
                let f = Condition::<$t>::FALSE;
                assert_eq!(f.negate(1), 1);
                assert_eq!(f.negate(0), 0);
                assert_eq!(f.negate(-1), -1);
            }

            #[test]
            fn swap() {
                let (lhs, rhs) = Condition::<$t>::from_bool::<true>().swap(1, 2);
                assert_eq!((lhs, rhs), (2, 1));
                let (lhs, rhs) = Condition::<$t>::from_bool::<false>().swap(1, 2);
                assert_eq!((lhs, rhs), (1, 2));
            }

            #[test]
            fn boolean_operators() {
                let t = Condition::<$t>::TRUE;
                let f = Condition::<$t>::FALSE;
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
    };
}

signed_condition_tests!(signed_i64_tests, i64);
signed_condition_tests!(signed_i32_tests, i32);

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
