use bouncycastle_utils::ct::Condition;

/// These do not validate the constant-time-ness; these are simply basic correctness tests
/// (and example usages)

#[cfg(test)]
mod i64_tests {
    use super::*;

    #[test]
    fn const_tests() {
        assert_eq!(Condition::<i64>::TRUE.to_bool_var(), true);
        assert_eq!(Condition::<i64>::FALSE.to_bool_var(), false);
    }

    #[test]
    fn from_bool() {
        assert_eq!(Condition::<i64>::from_bool::<true>().to_bool_var(), true);
        assert_eq!(Condition::<i64>::from_bool::<false>().to_bool_var(), false);

        let btrue: bool = true;
        let bfalse: bool = false;
        assert_eq!(Condition::<i64>::from_bool_var(btrue).to_bool_var(), true);
        assert_eq!(Condition::<i64>::from_bool_var(bfalse).to_bool_var(), false);
    }

    #[test]
    fn is_bit_set() {
        assert_eq!(Condition::<i64>::is_bit_set(1, 0).to_bool_var(), true);
        assert_eq!(Condition::<i64>::is_bit_set(1, 1).to_bool_var(), false);
        assert_eq!(Condition::<i64>::is_bit_set(8, 3).to_bool_var(), true);
    }

    #[test]
    fn is_negative() {
        assert_eq!(Condition::<i64>::is_negative(-1).to_bool_var(), true);
        assert_eq!(Condition::<i64>::is_negative(0).to_bool_var(), false);
        assert_eq!(Condition::<i64>::is_negative(1).to_bool_var(), false);
        assert_eq!(Condition::<i64>::is_negative(1 << 12).to_bool_var(), false);
    }

    #[test]
    fn is_not_zero() {
        assert_eq!(Condition::<i64>::is_not_zero(1).to_bool_var(), true);
        assert_eq!(Condition::<i64>::is_not_zero(0).to_bool_var(), false);
        assert_eq!(Condition::<i64>::is_not_zero(1 << 12).to_bool_var(), true);
        assert_eq!(Condition::<i64>::is_not_zero(-10).to_bool_var(), true);
    }

    #[test]
    fn is_zero() {
        assert_eq!(Condition::<i64>::is_zero(1).to_bool_var(), false);
        assert_eq!(Condition::<i64>::is_zero(0).to_bool_var(), true);
        assert_eq!(Condition::<i64>::is_zero(1 << 12).to_bool_var(), false);
    }

    #[test]
    fn is_equal() {
        assert_eq!(Condition::<i64>::is_equal(1, 1).to_bool_var(), true);
        assert_eq!(Condition::<i64>::is_equal(1, 2).to_bool_var(), false);
        assert_eq!(Condition::<i64>::is_equal(1, -1).to_bool_var(), false);
    }

    #[test]
    fn is_lt() {
        assert_eq!(Condition::<i64>::is_lt(1, 2).to_bool_var(), true);
        assert_eq!(Condition::<i64>::is_lt(2, 1).to_bool_var(), false);
        assert_eq!(Condition::<i64>::is_lt(2, 2).to_bool_var(), false);
        assert_eq!(Condition::<i64>::is_lt(0, 1).to_bool_var(), true);
        assert_eq!(Condition::<i64>::is_lt(-100, -99).to_bool_var(), true);
        assert_eq!(Condition::<i64>::is_lt(-98, 98).to_bool_var(), true);

        let mut i: i64 = 0;
        assert_eq!(Condition::<i64>::is_lt(i, 1).to_bool_var(), true);
        assert_eq!(Condition::<i64>::is_lt(i, -1).to_bool_var(), false);
        i = 1;
        assert_eq!(Condition::<i64>::is_lt(i, 1).to_bool_var(), false);
    }

    #[test]
    fn is_lte() {
        assert_eq!(Condition::<i64>::is_lte(1, 2).to_bool_var(), true);
        assert_eq!(Condition::<i64>::is_lte(2, 1).to_bool_var(), false);
        assert_eq!(Condition::<i64>::is_lte(2, 2).to_bool_var(), true);
        assert_eq!(Condition::<i64>::is_lte(0, 1).to_bool_var(), true);
        assert_eq!(Condition::<i64>::is_lte(-100, -99).to_bool_var(), true);
        assert_eq!(Condition::<i64>::is_lte(-98, 98).to_bool_var(), true);
    }

    #[test]
    fn is_gt() {
        assert_eq!(Condition::<i64>::is_gt(1, 2).to_bool_var(), false);
        assert_eq!(Condition::<i64>::is_gt(2, 1).to_bool_var(), true);
        assert_eq!(Condition::<i64>::is_gt(2, 2).to_bool_var(), false);
        assert_eq!(Condition::<i64>::is_gt(0, 1).to_bool_var(), false);
        assert_eq!(Condition::<i64>::is_gt(-100, -99).to_bool_var(), false);
        assert_eq!(Condition::<i64>::is_gt(-98, 98).to_bool_var(), false);
    }

    #[test]
    fn is_gte() {
        assert_eq!(Condition::<i64>::is_gte(1, 2).to_bool_var(), false);
        assert_eq!(Condition::<i64>::is_gte(2, 1).to_bool_var(), true);
        assert_eq!(Condition::<i64>::is_gte(2, 2).to_bool_var(), true);
        assert_eq!(Condition::<i64>::is_gte(0, 1).to_bool_var(), false);
        assert_eq!(Condition::<i64>::is_gte(-100, -99).to_bool_var(), false);
        assert_eq!(Condition::<i64>::is_gte(-98, 98).to_bool_var(), false);
    }

    #[test]
    fn is_in_range() {
        assert_eq!(Condition::<i64>::is_within_range(1, 0, 2).to_bool_var(), true);
        assert_eq!(Condition::<i64>::is_within_range(2, 0, 1).to_bool_var(), false);
        assert_eq!(Condition::<i64>::is_within_range(1, -5, 2).to_bool_var(), true);
        assert_eq!(Condition::<i64>::is_within_range(0, -5, 5).to_bool_var(), true);
        assert_eq!(Condition::<i64>::is_within_range(1, 0, 0).to_bool_var(), false);
    }

    #[test]
    fn is_in_list() {
        assert_eq!(Condition::<i64>::is_in_list(1, &[1, 2, 3]).to_bool_var(), true);
        assert_eq!(Condition::<i64>::is_in_list(4, &[1, 2, 3]).to_bool_var(), false);
        assert_eq!(Condition::<i64>::is_in_list(-3, &[1, 2, 3, 4, -5, -1]).to_bool_var(), false);
        assert_eq!(Condition::<i64>::is_in_list(3, &[1, 2, 3, 3, 3, 3]).to_bool_var(), true);
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

    // MikeO: TODO: I don't understand what this function does well enough to test it.
    // MikeO: TODO: is this failing test a real bug?
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

    // MikeO: TODO: I don't understand what this function does well enough to test it.
    //
    // Q. T. Felix - start
    //
    #[test]
    fn test_or_halves() {
        // 0 input -> 0 output
        assert_eq!(Condition::<i64>::or_halves(0), 0);

        // Lower 32 bits should be preserved
        assert_eq!(Condition::<i64>::or_halves(1), 1);
        assert_eq!(Condition::<i64>::or_halves(0x12345678), 0x12345678);

        // Upper 32 bits should be folded into lower 32 bits
        // (1 << 32) OR (1 << 32 >> 32) => 0 OR 1 => 1
        assert_eq!(Condition::<i64>::or_halves(1 << 32), 1);

        // Mixed case: Upper 0x10000000 | Lower 0x00000001 => 0x10000001
        assert_eq!(Condition::<i64>::or_halves(0x10000000_00000001), 0x10000001);

        // Negative number check (-1)
        // -1 is 0xFFFF...FFFF
        // (-1 >> 32) is -1 (Arithmetic shift preserves sign)
        // (-1 | -1) is -1
        // -1 & 0xFFFFFFFF is 0x00000000FFFFFFFF (i64 value: 4294967295)
        assert_eq!(Condition::<i64>::or_halves(-1), 0xFFFFFFFF);

        // i64::MIN check (Only MSB set)
        // i64::MIN = 0x80000000_00000000
        // (val >> 32) = 0xFFFFFFFF_80000000 (Sign extension)
        // (val | shifted) = 0xFFFFFFFF_80000000
        // (& mask) = 0x00000000_80000000
        assert_eq!(Condition::<i64>::or_halves(i64::MIN), 0x80000000);
    }
    //
    // Q. T. Felix - end
    //

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

//
// Q. T. Felix - start
//
#[cfg(test)]
mod u64_tests {
    use super::*;

    #[test]
    fn const_tests() {
        // Q. T. Felix NOTE: Ensure TRUE/FALSE are correctly interpreted as boolean.
        assert_eq!(Condition::<u64>::TRUE.is_true(), true);
        assert_eq!(Condition::<u64>::FALSE.is_true(), false);
    }

    #[test]
    fn from_bool() {
        // Compile-time const generics check
        assert_eq!(Condition::<u64>::from_bool::<true>().is_true(), true);
        assert_eq!(Condition::<u64>::from_bool::<false>().is_true(), false);
    }

    #[test]
    fn select() {
        let t = Condition::<u64>::TRUE;
        let f = Condition::<u64>::FALSE;

        let val1: u64 = 0xDEADBEEFCAFEBABE;
        let val2: u64 = 0x0000000000000000;

        // Q. T. Felix NOTE: This test is CRITICAL.
        //                   If TRUE was defined as '1' (like i64), this would fail because 'select' relies on bitwise mask.
        //                   It requires TRUE to be u64::MAX (all 1s) to preserve the full bits of val1.
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
        assert_eq!((!t).is_true(), false);
        assert_eq!((!f).is_true(), true);

        // AND
        assert_eq!((t & t).is_true(), true);
        assert_eq!((t & f).is_true(), false);
        assert_eq!((f & f).is_true(), false);

        // OR
        assert_eq!((t | t).is_true(), true);
        assert_eq!((t | f).is_true(), true);
        assert_eq!((f | f).is_true(), false);

        // XOR
        assert_eq!((t ^ t).is_true(), false);
        assert_eq!((t ^ f).is_true(), true);
    }
} // AlLpAsS
//
// Q. T. Felix - end
//

// #[cfg(test)]
// mod u64_tests {
//     use super::*;
//
//     #[test]
//     fn const_tests() {
//         assert_eq!(Condition::<u64>::TRUE.to_bool_var(), true);
//         assert_eq!(Condition::<u64>::FALSE.to_bool_var(), false);
//     }
//
//     #[test]
//     fn from_bool() {
//         assert_eq!(Condition::<u64>::new::<true>().to_bool_var(), true);
//         assert_eq!(Condition::<u64>::new::<false>().to_bool_var(), false);
//
//         let btrue: bool = true;
//         let bfalse: bool = false;
//         assert_eq!(Condition::<u64>::from_bool(btrue).to_bool_var(), true);
//         assert_eq!(Condition::<u64>::from_bool(bfalse).to_bool_var(), false);
//     }
//
//     #[test]
//     fn is_bit_set() {
//         assert_eq!(Condition::<u64>::is_bit_set(1, 0).to_bool_var(), true);
//         assert_eq!(Condition::<u64>::is_bit_set(1, 1).to_bool_var(), false);
//         assert_eq!(Condition::<u64>::is_bit_set(8, 3).to_bool_var(), true);
//     }
//
//     // MikeO: TODO ?? What does "negative" mean for an unsigned value?
//     #[test]
//     fn is_negative() {
//         // assert_eq!(Condition::<u64>::is_negative(-1).to_bool_var(), true); // << This doesn't compile, for obvious reasons.
//         assert_eq!(Condition::<u64>::is_negative(0).to_bool_var(), false);
//         assert_eq!(Condition::<u64>::is_negative(1).to_bool_var(), false);
//         assert_eq!(Condition::<u64>::is_negative(1 << 12).to_bool_var(), false);
//     }
//
//     #[test]
//     fn is_not_zero() {
//         assert_eq!(Condition::<u64>::is_not_zero(1).to_bool_var(), true);
//         assert_eq!(Condition::<u64>::is_not_zero(0).to_bool_var(), false);
//         assert_eq!(Condition::<u64>::is_not_zero(1 << 12).to_bool_var(), true);
//     }
//
//     #[test]
//     fn is_zero() {
//         assert_eq!(Condition::<u64>::is_zero(1).to_bool_var(), false);
//         assert_eq!(Condition::<u64>::is_zero(0).to_bool_var(), true);
//         assert_eq!(Condition::<u64>::is_zero(1 << 12).to_bool_var(), false);
//     }
//
//     // TODO: turn this back on once implemented
//     #[test]
//     fn is_lt() {
//         assert_eq!(Condition::<u64>::is_lt(1, 2).to_bool_var(), true);
//         assert_eq!(Condition::<u64>::is_lt(2, 1).to_bool_var(), false);
//         assert_eq!(Condition::<u64>::is_lt(2, 2).to_bool_var(), false);
//         assert_eq!(Condition::<u64>::is_lt(0, 1).to_bool_var(), true);
//
//         let mut i: u64 = 0;
//         assert_eq!(Condition::<u64>::is_lt(i, 1).to_bool_var(), true);
//         i = 1;
//         assert_eq!(Condition::<u64>::is_lt(i, 1).to_bool_var(), false);
//     }
//
//     // TODO: turn this back on once implemented
//     // #[test]
//     // fn is_lte() {
//     //     assert_eq!(Condition::<u64>::is_lte(1, 2).to_bool_var(), true);
//     //     assert_eq!(Condition::<u64>::is_lte(2, 1).to_bool_var(), false);
//     //     assert_eq!(Condition::<u64>::is_lte(2, 2).to_bool_var(), true);
//     //     assert_eq!(Condition::<u64>::is_lte(0, 1).to_bool_var(), true);
//     //     assert_eq!(Condition::<u64>::is_lte(-100, -99).to_bool_var(), true);
//     //     assert_eq!(Condition::<u64>::is_lte(-98, 98).to_bool_var(), true);
//     // }
//
//     // #[test]
//     // fn is_gt() {
//     //     assert_eq!(Condition::<u64>::is_gt(1, 2).to_bool_var(), false);
//     //     assert_eq!(Condition::<u64>::is_gt(2, 1).to_bool_var(), true);
//     //     assert_eq!(Condition::<u64>::is_gt(2, 2).to_bool_var(), false);
//     //     assert_eq!(Condition::<u64>::is_gt(0, 1).to_bool_var(), false);
//     //     assert_eq!(Condition::<u64>::is_gt(-100, -99).to_bool_var(), false);
//     //     assert_eq!(Condition::<u64>::is_gt(-98, 98).to_bool_var(), false);
//     // }
//
//     // #[test]
//     // fn is_gte() {
//     //     assert_eq!(Condition::<u64>::is_gte(1, 2).to_bool_var(), false);
//     //     assert_eq!(Condition::<u64>::is_gte(2, 1).to_bool_var(), true);
//     //     assert_eq!(Condition::<u64>::is_gte(2, 2).to_bool_var(), true);
//     //     assert_eq!(Condition::<u64>::is_gte(0, 1).to_bool_var(), false);
//     //     assert_eq!(Condition::<u64>::is_gte(-100, -99).to_bool_var(), false);
//     //     assert_eq!(Condition::<u64>::is_gte(-98, 98).to_bool_var(), false);
//     // }
//
//     // TODO: turn this back on once implemented
//     // #[test]
//     // fn is_in_range() {
//     //     assert_eq!(Condition::<u64>::is_within_range(1, 0, 2).to_bool_var(), true);
//     //     assert_eq!(Condition::<u64>::is_within_range(2, 0, 1).to_bool_var(), false);
//     //     assert_eq!(Condition::<u64>::is_within_range(1, -5, 2).to_bool_var(), true);
//     //     assert_eq!(Condition::<u64>::is_within_range(0, -5, 5).to_bool_var(), true);
//     //     assert_eq!(Condition::<u64>::is_within_range(1, 0, 0).to_bool_var(), false);
//     // }
//
//     #[test]
//     fn is_in_list() {
//         assert_eq!(Condition::<u64>::is_in_list(1, &[1, 2, 3]).to_bool_var(), true);
//         assert_eq!(Condition::<u64>::is_in_list(4, &[1, 2, 3]).to_bool_var(), false);
//         assert_eq!(Condition::<u64>::is_in_list(3, &[1, 2, 3, 3, 3, 3]).to_bool_var(), true);
//     }
//
//     #[test]
//     fn test_mov() {
//         let src = 1u64;
//         let mut dst = 2u64;
//         let c1 = Condition::<u64>::TRUE;
//         c1.mov(src, &mut dst);
//         assert_eq!(dst, 1);
//
//         let c2 = Condition::<u64>::FALSE;
//         dst = 2;
//         c2.mov(src, &mut dst);
//         assert_eq!(dst, 2);
//     }
//
//     // MikeO: TODO: I don't understand what this function does well enough to test it.
//     // #[test]
//     // fn test_negate() {
//     //     let c1 = Condition::<u64>::TRUE;
//     //     assert_eq!(c1.negate(1), -1);
//     //     assert_eq!(c1.negate(0), 0);
//     //     assert_eq!(c1.negate(-1), 1);
//     //
//     //     let c2 = Condition::<i64>::FALSE;
//     //     assert_eq!(c2.negate(1), 1);
//     //     assert_eq!(c2.negate(0), 0);
//     //     assert_eq!(c2.negate(-1),-1);
//     // }
//
//     // MikeO: TODO: I don't understand what this function does well enough to test it.
//     #[test]
//     fn test_or_halves() {
//         todo!()
//     }
//
//     #[test]
//     fn test_select() {
//         let c = Condition::<u64>::TRUE;
//         assert_eq!(c.select(1, 2), 1);
//         assert_eq!((!c).select(1, 2), 2);
//
//         // or the inverse behaviour if you start with 'false'.
//         let cfalse = Condition::<u64>::FALSE;
//         assert_eq!(cfalse.select(1, 2), 2);
//         assert_eq!((!cfalse).select(1, 2), 1);
//     }
//
//     #[test]
//     fn test_swap() {
//         let c = Condition::<i64>::from_bool::<true>();
//         let (lhs, rhs) = c.swap(1, 2);
//         assert_eq!(lhs, 2);
//         assert_eq!(rhs, 1);
//
//         // or the inverse behaviour if you start with 'false'.
//         let c = Condition::<i64>::from_bool::<false>();
//         let (lhs, rhs) = c.swap(1, 2);
//         assert_eq!(lhs, 1);
//         assert_eq!(rhs, 2);
//     }
// }

#[cfg(test)]
mod generic_impl_tests {
    use super::*;

    #[test]
    fn test_bit_and() {
        let ct1 = Condition::<i64>::from_bool::<true>();
        let ct2 = Condition::<i64>::from_bool::<true>();
        let cf1 = Condition::<i64>::from_bool::<false>();
        let cf2 = Condition::<i64>::from_bool::<false>();
        assert_eq!((ct1 & ct2).to_bool_var(), true);
        assert_eq!((ct1 & cf1).to_bool_var(), false);
        assert_eq!((cf1 & cf2).to_bool_var(), false);
    }

    #[test]
    fn test_bit_and_assign() {
        let mut ct1 = Condition::<i64>::from_bool::<true>();
        let ct2 = Condition::<i64>::from_bool::<true>();
        let cf = Condition::<i64>::from_bool::<false>();

        ct1 &= ct2;
        assert_eq!(ct1.to_bool_var(), true);

        ct1 &= cf;
        assert_eq!(ct1.to_bool_var(), false);
    }

    #[test]
    fn test_bit_or() {
        let ct1 = Condition::<i64>::from_bool::<true>();
        let ct2 = Condition::<i64>::from_bool::<true>();
        let cf1 = Condition::<i64>::from_bool::<false>();
        let cf2 = Condition::<i64>::from_bool::<false>();

        assert_eq!((ct1 | ct2).to_bool_var(), true);
        assert_eq!((ct1 | cf1).to_bool_var(), true);
        assert_eq!((cf1 | cf2).to_bool_var(), false);
    }

    #[test]
    fn test_bit_or_assign() {
        let mut ct1 = Condition::<i64>::from_bool::<true>();
        let ct2 = Condition::<i64>::from_bool::<true>();
        let mut cf1 = Condition::<i64>::from_bool::<false>();
        let cf2 = Condition::<i64>::from_bool::<false>();

        ct1 |= ct2;
        assert_eq!(ct1.to_bool_var(), true);

        ct1 |= cf1;
        assert_eq!(ct1.to_bool_var(), true);

        cf1 |= cf2;
        assert_eq!(cf1.to_bool_var(), false);
    }

    #[test]
    fn test_bit_xor() {
        let ct1 = Condition::<i64>::from_bool::<true>();
        let ct2 = Condition::<i64>::from_bool::<true>();
        let cf1 = Condition::<i64>::from_bool::<false>();
        let cf2 = Condition::<i64>::from_bool::<false>();

        assert_eq!((ct1 ^ ct2).to_bool_var(), false);
        assert_eq!((ct1 | cf1).to_bool_var(), true);
        assert_eq!((cf1 | cf2).to_bool_var(), false);
    }

    #[test]
    fn test_bit_xor_assign() {
        let mut ct1 = Condition::<i64>::from_bool::<true>();
        let mut ct2 = Condition::<i64>::from_bool::<true>();
        let mut cf1 = Condition::<i64>::from_bool::<false>();
        let cf2 = Condition::<i64>::from_bool::<false>();

        ct1 ^= ct2;
        assert_eq!(ct1.to_bool_var(), false);

        ct2 ^= cf1;
        assert_eq!(ct2.to_bool_var(), true);

        cf1 ^= cf2;
        assert_eq!(cf1.to_bool_var(), false);
    }

    #[test]
    fn test_not() {
        let c = Condition::<i64>::from_bool::<true>();
        assert_eq!((!c).to_bool_var(), false);
    }
}
