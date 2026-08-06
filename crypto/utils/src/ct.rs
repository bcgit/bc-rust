//! A set of constant-time helper functions for the following:
//!
//! * Basic arithmetic operations such as less-than(x, y), is_zero(x), etc.
//! * Conditional operations such as select and swap whose output depends on whether the condition is true or false.
//! * Implementing boolean operators for Condition\<T\>: &, &=, |, |=, ^, ^=.

use core::ops::*;

mod sealed {
    pub(super) trait Sealed {}
}

struct MaskType<T>(core::marker::PhantomData<T>);

trait SupportedMaskType: sealed::Sealed {}

macro_rules! supported_mask_type {
    ($($t:ty),+) => {
        $(
            impl sealed::Sealed for MaskType<$t> {}
            impl SupportedMaskType for MaskType<$t> {}
        )+
    };
}

supported_mask_type!(i64, u64, u32, i32);

/// Helper functions for checking some condition on some data using constant-time operations.
#[derive(Clone, Copy)]
#[must_use]
#[repr(transparent)]
pub struct Condition<T>(T)
where
    MaskType<T>: SupportedMaskType;

impl<T> Condition<T> where MaskType<T>: SupportedMaskType {}

// The signed widths share one macro-generated impl, mirroring `unsigned_condition_impl!`
// below, so that `Condition<i64>` and `Condition<i32>` are at exact method parity.
impl Condition<i64> {
    /// TRUE is the bit vector of all 1's
    pub const TRUE: Self = Self(-1);
    /// FALSE is the bit vector of all 0's
    pub const FALSE: Self = Self(0);

    /// Constant-time mask generation from a compile-time boolean.
    ///
    /// Signed types rely on two's complement negation: `-(true as i64)` is `-1`
    /// (all 1s) and `-(false as i64)` is `0` (all 0s).
    pub const fn from_bool<const VALUE: bool>() -> Self {
        Self(-(VALUE as i64))
    }
    /// Constant-time mask generation from a runtime boolean.
    pub const fn from_bool_var(value: bool) -> Self {
        Self(-(value as i64))
    }
    /// Mask from the least-significant bit: TRUE iff bit 0 of `value` is set.
    /// This is the parity test: `from_lsb(x)` is TRUE iff `x` is odd. It is
    /// the `bit = 0` special case of [`Self::is_bit_set`].
    pub const fn from_lsb(value: i64) -> Self {
        Self(-(value & 1))
    }
    /// TRUE iff bit `bit` of `value` is set. The bit index must be public data
    /// (the shift amount is timing-visible on some targets).
    pub const fn is_bit_set(value: i64, bit: u32) -> Self {
        Self::from_lsb(value >> bit)
    }
    /// TRUE iff `value < 0`, i.e. the sign (top) bit is set. The unsigned
    /// counterpart of this mask is `from_msb`, where the top bit carries a
    /// borrow/carry instead of a sign.
    pub const fn is_negative(value: i64) -> Self {
        // Arithmetic shift replicates the sign bit across the whole word.
        Self(value >> (i64::BITS - 1))
    }
    /// TRUE iff `value != 0`.
    ///
    /// For any nonzero `x`, `x | x.wrapping_neg()` is negative (either `x` or its
    /// two's complement has the top bit set); for zero both sides are zero.
    /// `wrapping_neg` is required: plain negation overflows at `MIN`.
    pub const fn is_not_zero(value: i64) -> Self {
        Self::is_negative(value | value.wrapping_neg())
    }
    /// TRUE iff `value == 0`.
    pub const fn is_zero(value: i64) -> Self {
        // Complementing the inner value maps TRUE <-> FALSE (all 1s <-> all 0s).
        Self(!Self::is_not_zero(value).0)
    }
    /// TRUE iff `x == y`.
    pub const fn is_equal(x: i64, y: i64) -> Self {
        Self::is_zero(x ^ y)
    }
    /// TRUE iff `x < y`, for the full signed range.
    ///
    /// The naive `is_negative(x - y)` is wrong whenever `x - y` overflows
    /// (e.g. `MIN < 1`): in debug it panics, in release it wraps to the opposite
    /// answer. This is the standard overflow-free signed-comparison identity: when
    /// the signs of `x` and `y` differ the answer is the sign of `x`; when they
    /// agree the difference cannot overflow, so the answer is the sign of `x - y`.
    pub const fn is_lt(x: i64, y: i64) -> Self {
        Self(((x & !y) | (!(x ^ y) & x.wrapping_sub(y))) >> (i64::BITS - 1))
    }
    /// TRUE iff `x <= y`.
    pub const fn is_lte(x: i64, y: i64) -> Self {
        // Complementing the inner value maps TRUE <-> FALSE (all 1s <-> all 0s).
        Self(!Self::is_gt(x, y).0)
    }
    /// TRUE iff `x > y`.
    pub const fn is_gt(x: i64, y: i64) -> Self {
        Self::is_lt(y, x)
    }
    /// TRUE iff `x >= y`.
    pub const fn is_gte(x: i64, y: i64) -> Self {
        Self(!Self::is_lt(x, y).0)
    }
    /// TRUE iff `min <= value <= max`.
    pub const fn is_within_range(value: i64, min: i64, max: i64) -> Self {
        Self(Self::is_gte(value, min).0 & Self::is_lte(value, max).0)
    }
    /// TRUE iff `value` occurs in `list`. The list contents and length are public.
    pub fn is_in_list(value: i64, list: &[i64]) -> Self {
        // Research question: is this actually constant-time?
        // A clever compiler might turn this into a short-circuiting loop.
        // A quick google search shows that rust doesn't have the ability to annotate specific code blocks
        // as no-optimize; the only option is to insert direct assembly.

        let mut c = Self::FALSE;
        for i in 0..list.len() {
            let diff = value ^ list[i];
            c |= Self::is_zero(diff);
        }

        c
    }

    /// Conditionally move the source value to the destination if the condition is
    /// true, otherwise nothing is moved.
    pub fn mov(self, src: i64, dst: &mut i64) {
        *dst = self.select(src, *dst);
    }

    /// Conditionally negate the value.
    ///
    /// negate(-1) gives -3
    ///
    /// `value` is `-1` (i.e., all bits are `1`, `...1111`)
    ///
    /// Condition `self.0` is 1 (`...0001`) (assuming `TRUE`)
    ///
    /// XOR operation was executed as `value ^ self.0`
    ///
    /// Then `...1111 XOR ...0001 = ...1110` (i.e., `-2`)
    ///
    /// Subtraction operation is `wrapping_sub(self.0)`
    ///
    /// Then `-2 - 1 = -3`
    ///
    /// As a result, `1`, which is the negation of `-1`, should be returned, but `-3` is output.
    ///
    /// Therefore, if the [`Self::TRUE`] constant value of the [`Condition`] implementation is changed to `-1`,
    /// the test also runs normally.
    pub const fn negate(self, value: i64) -> i64 {
        (value ^ self.0).wrapping_sub(self.0)
    }
    /// Conditional selection: return `true_value` if the condition is true, otherwise
    /// return `false_value`.
    pub const fn select(self, true_value: i64, false_value: i64) -> i64 {
        (true_value & self.0) | (false_value & !self.0)
    }
    /// Conditional swap: returns (lhs, rhs) if the condition is true, otherwise
    /// returns (rhs, lhs).
    pub const fn swap(self, lhs: i64, rhs: i64) -> (i64, i64) {
        (self.select(rhs, lhs), self.select(lhs, rhs))
    }
    /// Convert the mask to a runtime boolean. Only use this at genuine public
    /// decision points: branching on the result leaks the condition's value.
    pub const fn to_bool(self) -> bool {
        self.0 != 0
    }
}

impl Condition<i32> {
    /// TRUE is the bit vector of all 1's
    pub const TRUE: Self = Self(-1);
    /// FALSE is the bit vector of all 0's
    pub const FALSE: Self = Self(0);

    /// Constant-time mask generation from a compile-time boolean.
    ///
    /// Signed types rely on two's complement negation: `-(true as i32)` is `-1`
    /// (all 1s) and `-(false as i32)` is `0` (all 0s).
    pub const fn from_bool<const VALUE: bool>() -> Self {
        Self(-(VALUE as i32))
    }
    /// Constant-time mask generation from a runtime boolean.
    pub const fn from_bool_var(value: bool) -> Self {
        Self(-(value as i32))
    }
    /// Mask from the least-significant bit: TRUE iff bit 0 of `value` is set.
    /// This is the parity test: `from_lsb(x)` is TRUE iff `x` is odd. It is
    /// the `bit = 0` special case of [`Self::is_bit_set`].
    pub const fn from_lsb(value: i32) -> Self {
        Self(-(value & 1))
    }
    /// TRUE iff bit `bit` of `value` is set. The bit index must be public data
    /// (the shift amount is timing-visible on some targets).
    pub const fn is_bit_set(value: i32, bit: u32) -> Self {
        Self::from_lsb(value >> bit)
    }
    /// TRUE iff `value < 0`, i.e. the sign (top) bit is set. The unsigned
    /// counterpart of this mask is `from_msb`, where the top bit carries a
    /// borrow/carry instead of a sign.
    pub const fn is_negative(value: i32) -> Self {
        // Arithmetic shift replicates the sign bit across the whole word.
        Self(value >> (i32::BITS - 1))
    }
    /// TRUE iff `value != 0`.
    ///
    /// For any nonzero `x`, `x | x.wrapping_neg()` is negative (either `x` or its
    /// two's complement has the top bit set); for zero both sides are zero.
    /// `wrapping_neg` is required: plain negation overflows at `MIN`.
    pub const fn is_not_zero(value: i32) -> Self {
        Self::is_negative(value | value.wrapping_neg())
    }
    /// TRUE iff `value == 0`.
    pub const fn is_zero(value: i32) -> Self {
        // Complementing the inner value maps TRUE <-> FALSE (all 1s <-> all 0s).
        Self(!Self::is_not_zero(value).0)
    }
    /// TRUE iff `x == y`.
    pub const fn is_equal(x: i32, y: i32) -> Self {
        Self::is_zero(x ^ y)
    }
    /// TRUE iff `x < y`, for the full signed range.
    ///
    /// The naive `is_negative(x - y)` is wrong whenever `x - y` overflows
    /// (e.g. `MIN < 1`): in debug it panics, in release it wraps to the opposite
    /// answer. This is the standard overflow-free signed-comparison identity: when
    /// the signs of `x` and `y` differ the answer is the sign of `x`; when they
    /// agree the difference cannot overflow, so the answer is the sign of `x - y`.
    pub const fn is_lt(x: i32, y: i32) -> Self {
        Self(((x & !y) | (!(x ^ y) & x.wrapping_sub(y))) >> (i32::BITS - 1))
    }
    /// TRUE iff `x <= y`.
    pub const fn is_lte(x: i32, y: i32) -> Self {
        // Complementing the inner value maps TRUE <-> FALSE (all 1s <-> all 0s).
        Self(!Self::is_gt(x, y).0)
    }
    /// TRUE iff `x > y`.
    pub const fn is_gt(x: i32, y: i32) -> Self {
        Self::is_lt(y, x)
    }
    /// TRUE iff `x >= y`.
    pub const fn is_gte(x: i32, y: i32) -> Self {
        Self(!Self::is_lt(x, y).0)
    }
    /// TRUE iff `min <= value <= max`.
    pub const fn is_within_range(value: i32, min: i32, max: i32) -> Self {
        Self(Self::is_gte(value, min).0 & Self::is_lte(value, max).0)
    }
    /// TRUE iff `value` occurs in `list`. The list contents and length are public.
    pub fn is_in_list(value: i32, list: &[i32]) -> Self {
        // Research question: is this actually constant-time?
        // A clever compiler might turn this into a short-circuiting loop.
        // A quick google search shows that rust doesn't have the ability to annotate specific code blocks
        // as no-optimize; the only option is to insert direct assembly.

        let mut c = Self::FALSE;
        for i in 0..list.len() {
            let diff = value ^ list[i];
            c |= Self::is_zero(diff);
        }

        c
    }

    /// Conditionally move the source value to the destination if the condition is
    /// true, otherwise nothing is moved.
    pub fn mov(self, src: i32, dst: &mut i32) {
        *dst = self.select(src, *dst);
    }

    /// Conditionally negate the value.
    ///
    /// negate(-1) gives -3
    ///
    /// `value` is `-1` (i.e., all bits are `1`, `...1111`)
    ///
    /// Condition `self.0` is 1 (`...0001`) (assuming `TRUE`)
    ///
    /// XOR operation was executed as `value ^ self.0`
    ///
    /// Then `...1111 XOR ...0001 = ...1110` (i.e., `-2`)
    ///
    /// Subtraction operation is `wrapping_sub(self.0)`
    ///
    /// Then `-2 - 1 = -3`
    ///
    /// As a result, `1`, which is the negation of `-1`, should be returned, but `-3` is output.
    ///
    /// Therefore, if the [`Self::TRUE`] constant value of the [`Condition`] implementation is changed to `-1`,
    /// the test also runs normally.
    pub const fn negate(self, value: i32) -> i32 {
        (value ^ self.0).wrapping_sub(self.0)
    }
    /// Conditional selection: return `true_value` if the condition is true, otherwise
    /// return `false_value`.
    pub const fn select(self, true_value: i32, false_value: i32) -> i32 {
        (true_value & self.0) | (false_value & !self.0)
    }
    /// Conditional swap: returns (lhs, rhs) if the condition is true, otherwise
    /// returns (rhs, lhs).
    pub const fn swap(self, lhs: i32, rhs: i32) -> (i32, i32) {
        (self.select(rhs, lhs), self.select(lhs, rhs))
    }
    /// Convert the mask to a runtime boolean. Only use this at genuine public
    /// decision points: branching on the result leaks the condition's value.
    pub const fn to_bool(self) -> bool {
        self.0 != 0
    }
}

// TODO: We should do Condition<u8>.
//       then and change Hex and Base64 to use this.
//       (there's probably no noticeable performance difference u8 and u64 bit ops on a 64-bit machine,
//       but there would be on a 8, 16, or 32-bit machine.)
//
// The unsigned widths share one macro-generated impl so that width-generic limb code can be
// written once against identical method names. Ordering comparisons are deliberately omitted:
// multi-word callers derive `lt` from their subtraction borrow chain and convert it with
// `from_msb`.
macro_rules! unsigned_condition_impl {
    ($($t:ty),+) => {
        $(
        impl Condition<$t> {
            /// TRUE is the bit vector of all 1's
            pub const TRUE: Self = Self(<$t>::MAX);
            /// FALSE is the bit vector of all 0's
            pub const FALSE: Self = Self(0);

            /// Constant-time mask generation from a compile-time boolean.
            ///
            /// Unlike signed integers where we can rely on Two's Complement via negation
            /// `-(v as i64)`, for unsigned types we must use wrapping subtraction to achieve
            /// the all-ones bit pattern for true:
            /// true (1) -> `0 - 1` wraps to MAX (all 1s); false (0) -> `0 - 0 = 0` (all 0s).
            pub const fn from_bool<const VALUE: bool>() -> Self {
                Self((0 as $t).wrapping_sub(VALUE as $t))
            }
            /// Constant-time mask generation from a runtime boolean.
            pub const fn from_bool_var(value: bool) -> Self {
                Self((0 as $t).wrapping_sub(value as $t))
            }
            /// Mask from the least-significant bit: TRUE iff bit 0 of `value` is set.
            /// This is the parity test: `from_lsb(x)` is TRUE iff `x` is odd. It is
            /// the `bit = 0` special case of [`Self::is_bit_set`].
            pub const fn from_lsb(value: $t) -> Self {
                Self((0 as $t).wrapping_sub(value & 1))
            }
            /// Mask from the most-significant bit: TRUE iff the top bit of `value` is set.
            /// The signed counterpart of this mask is `is_negative`, where the top bit
            /// carries a sign instead of a borrow/carry.
            ///
            /// This is the borrow/carry adaptor: the borrow word coming out of a wrapping
            /// wide subtraction chain carries its meaning entirely in the top bit, so
            /// `from_msb(borrow)` is the `lt` mask of that comparison with no further work.
            pub const fn from_msb(value: $t) -> Self {
                Self((0 as $t).wrapping_sub(value >> (<$t>::BITS - 1)))
            }
            /// TRUE iff bit `bit` of `value` is set. The bit index must be public data
            /// (the shift amount is timing-visible on some targets).
            pub const fn is_bit_set(value: $t, bit: u32) -> Self {
                Self::from_lsb(value >> bit)
            }
            /// TRUE iff `value != 0`.
            ///
            /// For any nonzero `x`, `x | x.wrapping_neg()` has the top bit set (either `x`
            /// or its two's complement is >= 2^(BITS-1)); for zero both sides are zero.
            pub const fn is_not_zero(value: $t) -> Self {
                Self::from_msb(value | value.wrapping_neg())
            }
            /// TRUE iff `value == 0`.
            pub const fn is_zero(value: $t) -> Self {
                // Complementing the inner value maps TRUE <-> FALSE (all 1s <-> all 0s).
                Self(!Self::is_not_zero(value).0)
            }
            /// TRUE iff `x == y`.
            pub const fn is_equal(x: $t, y: $t) -> Self {
                Self::is_zero(x ^ y)
            }
            /// Conditional selection: return `true_value` if the condition is true, otherwise
            /// return `false_value`.
            pub const fn select(self, true_value: $t, false_value: $t) -> $t {
                (true_value & self.0) | (false_value & !self.0)
            }
            /// Conditionally move the source value to the destination if the condition is
            /// true, otherwise nothing is moved.
            pub fn mov(self, src: $t, dst: &mut $t) {
                *dst = self.select(src, *dst);
            }
            /// Conditional swap: returns (lhs, rhs) if the condition is true, otherwise
            /// returns (rhs, lhs).
            pub const fn swap(self, lhs: $t, rhs: $t) -> ($t, $t) {
                (self.select(rhs, lhs), self.select(lhs, rhs))
            }
            /// Convert the mask to a runtime boolean. Only use this at genuine public
            /// decision points: branching on the result leaks the condition's value.
            pub const fn to_bool(self) -> bool {
                self.0 != 0
            }
        }
        )+
    };
}

unsigned_condition_impl!(u64, u32);

impl<T> BitAnd for Condition<T>
where
    MaskType<T>: SupportedMaskType,
    T: BitAnd<T, Output = T>,
{
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl<T> BitAndAssign for Condition<T>
where
    MaskType<T>: SupportedMaskType,
    T: BitAndAssign<T>,
{
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl<T> BitOr for Condition<T>
where
    MaskType<T>: SupportedMaskType,
    T: BitOr<T, Output = T>,
{
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl<T> BitOrAssign for Condition<T>
where
    MaskType<T>: SupportedMaskType,
    T: BitOrAssign<T>,
{
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl<T> BitXor for Condition<T>
where
    MaskType<T>: SupportedMaskType,
    T: BitXor<T, Output = T>,
{
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }
}

impl<T> BitXorAssign for Condition<T>
where
    MaskType<T>: SupportedMaskType,
    T: BitXorAssign<T>,
{
    fn bitxor_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}

impl<T> Not for Condition<T>
where
    MaskType<T>: SupportedMaskType,
    T: Not<Output = T>,
{
    type Output = Self;
    fn not(self) -> Self {
        Self(!self.0)
    }
}

/// Rust doesn't guarantee that anything can truly be constant-time under all compilation targets
/// and optimization levels. The following presents the standard constant-time shape.
pub fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for i in 0..a.len() {
        result |= core::hint::black_box(a[i] ^ b[i]);
    }
    result == 0
}

/// Rust doesn't guarantee that anything can truly be constant-time under all compilation targets
/// and optimization levels. The following presents the standard constant-time shape.
pub fn ct_eq_zero_bytes(a: &[u8]) -> bool {
    let mut result = 0u8;
    for i in 0..a.len() {
        result |= core::hint::black_box(a[i]);
    }
    result == 0
}

/// Copies either the contents of `a` or `b` into `out` according to `take_a`
/// and it does it in a constant-time manner without branching.
pub fn conditional_copy_bytes<const LEN: usize>(
    a: &[u8; LEN],
    b: &[u8; LEN],
    out: &mut [u8; LEN],
    take_a: bool,
) {
    // we want the behaviour of
    //  if take_a { 0xFF } else { 0x00 }
    // but without using any branches that could leak timing signals
    let mask: u8 = (take_a as u8)
        | (take_a as u8) << 1
        | (take_a as u8) << 2
        | (take_a as u8) << 3
        | (take_a as u8) << 4
        | (take_a as u8) << 5
        | (take_a as u8) << 6
        | (take_a as u8) << 7;

    debug_assert_eq!(mask, if take_a { 0xFF } else { 0x00 });

    for i in 0..LEN {
        out[i] = core::hint::black_box(a[i] & mask) | core::hint::black_box(b[i] & !mask);
    }
}
