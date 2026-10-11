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

impl sealed::Sealed for MaskType<i64> {}
impl SupportedMaskType for MaskType<i64> {}
impl sealed::Sealed for MaskType<u64> {}
impl SupportedMaskType for MaskType<u64> {}
impl sealed::Sealed for MaskType<u32> {}
impl SupportedMaskType for MaskType<u32> {}
impl sealed::Sealed for MaskType<i32> {}
impl SupportedMaskType for MaskType<i32> {}

/// Helper functions for checking some condition on some data using constant-time operations.
#[derive(Clone, Copy)]
#[must_use]
#[repr(transparent)]
pub struct Condition<T>(T)
where
    MaskType<T>: SupportedMaskType;

// ---------------------------------------------------------------------------------------------
// Optimisation barrier
//
// Every constant-time construction in this file is masked arithmetic on a value the optimiser
// could otherwise prove to be one of a small number of constants (a `Condition` mask is all-ones
// or all-zeros; the accumulator of a comparison loop is zero until the first difference). Given
// that knowledge the compiler is free to lower an expression like `(t & m) | (f & !m)` to a branch
// or a conditional move on the secret, or to leave a comparison loop early. To stop that, the value
// is routed through a volatile store and load.
//
// This is still a best-effort, not a guarantee.
// The language guarantees less than is relied on here. The documentation (as of rust 1.99.0) of
// `core::ptr::read_volatile` / `write_volatile` says the accesses "are guaranteed to not be
// elided or reordered" relative to other externally observable events, and that a volatile read
// "will actually access memory and not e.g. be lowered to reusing data from a previous read". It
// says nothing about what the optimiser may still assume about the value stored. That LLVM
// carries no facts across the store/load pair is observed behaviour, verified by inspecting the
// release-build assembly of these functions on x86_64, i686, thumbv7em, riscv32imac, wasm32,
// msp430 and avr; another backend gets no such promise. `core::hint::black_box`, used
// previously, is weaker still: its documentation calls it "best-effort" and says it "does not
// offer any guarantees for cryptographic or security purposes".
// ---------------------------------------------------------------------------------------------

/// Returns `value` unchanged, via a volatile store to a stack slot and a volatile load back. The
/// section comment above says what that does and does not guarantee.
#[inline(always)]
fn value_barrier<T: Copy>(value: T) -> T {
    let mut slot = value;
    // SAFETY:
    //  * `&mut slot` must be a reference to an initialised, aligned `T` local on this stack frame, so
    //    it is valid for reads and writes for the duration of both calls, which is the only
    //    precondition of `write_volatile` and `read_volatile`.
    //  * The reference is exclusive; nothing else can observe `slot` during the two accesses.
    //  * `T: Copy`, so the bitwise copy `read_volatile` makes has no drop glue to run twice and
    //    the value written is a valid `T`, so the value read back is initialised.
    unsafe {
        core::ptr::write_volatile(&mut slot, value);
        core::ptr::read_volatile(&slot)
    }
}

impl<T: Copy> Condition<T>
where
    MaskType<T>: SupportedMaskType,
{
    /// The mask after the optimisation barrier (section comment above), applied at the point of
    /// use by every consumer that does masked arithmetic. Not `const`: volatile accesses are not
    /// allowed in const context.
    #[inline(always)]
    fn barrier(self) -> Self {
        Self(value_barrier(self.0))
    }
}

// Each signed width is written out by hand rather than macro-generated: `cargo mutants`
// cannot see into macro bodies, and these mask identities are the ones most worth
// mutating. The signed widths must be edited together: `Condition<i64>` and `Condition<i32>`
// are copies of each other modulo the width token.
impl Condition<i64> {
    /// TRUE is the bit vector of all 1's
    pub const TRUE: Self = Self(-1);
    /// FALSE is the bit vector of all 0's
    pub const FALSE: Self = Self(0);

    /// Constant-time mask generation from a compile-time boolean.
    ///
    /// Signed types rely on two's complement negation: `-(true as i64)` is `-1`
    /// (all 1s) and `-(false as i64)` is `0` (all 0s).
    pub const fn from_bool_const<const VALUE: bool>() -> Self {
        Self(-(VALUE as i64))
    }
    /// Constant-time mask generation from a runtime boolean.
    pub const fn from_bool(value: bool) -> Self {
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
        // Barrier inside the loop, for the reason given at "Byte-slice comparison helpers".
        let mut c = Self::FALSE;
        for x in list {
            c |= Self::is_equal(value, *x);
            c = c.barrier();
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
    pub fn negate(self, value: i64) -> i64 {
        let mask = self.barrier().0;
        (value ^ mask).wrapping_sub(mask)
    }
    /// Conditional selection: return `true_value` if the condition is true, otherwise
    /// return `false_value`.
    pub fn select(self, true_value: i64, false_value: i64) -> i64 {
        let mask = self.barrier().0;
        (true_value & mask) | (false_value & !mask)
    }
    /// Conditional swap: returns (rhs, lhs) if the condition is true, otherwise (lhs, rhs).
    pub fn swap(self, lhs: i64, rhs: i64) -> (i64, i64) {
        // One barrier serves both outputs: `t` is `lhs ^ rhs` under TRUE and zero under FALSE.
        let t = (lhs ^ rhs) & self.barrier().0;
        (lhs ^ t, rhs ^ t)
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
    pub const fn from_bool_const<const VALUE: bool>() -> Self {
        Self(-(VALUE as i32))
    }
    /// Constant-time mask generation from a runtime boolean.
    pub const fn from_bool(value: bool) -> Self {
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
        // Barrier inside the loop, for the reason given at "Byte-slice comparison helpers".
        let mut c = Self::FALSE;
        for x in list {
            c |= Self::is_equal(value, *x);
            c = c.barrier();
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
    pub fn negate(self, value: i32) -> i32 {
        let mask = self.barrier().0;
        (value ^ mask).wrapping_sub(mask)
    }
    /// Conditional selection: return `true_value` if the condition is true, otherwise
    /// return `false_value`.
    pub fn select(self, true_value: i32, false_value: i32) -> i32 {
        let mask = self.barrier().0;
        (true_value & mask) | (false_value & !mask)
    }
    /// Conditional swap: returns (rhs, lhs) if the condition is true, otherwise (lhs, rhs).
    pub fn swap(self, lhs: i32, rhs: i32) -> (i32, i32) {
        // One barrier serves both outputs: `t` is `lhs ^ rhs` under TRUE and zero under FALSE.
        let t = (lhs ^ rhs) & self.barrier().0;
        (lhs ^ t, rhs ^ t)
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
// Each unsigned width is written out by hand rather than macro-generated: `cargo mutants`
// cannot see into macro bodies, and these mask identities are the ones most worth
// mutating. The unsigned widths must be edited together: `Condition<u64>` and `Condition<u32>`
// are copies of each other modulo the width token. Ordering comparisons are deliberately
// omitted: multi-word callers derive `lt` from their subtraction borrow chain and convert it
// with `from_msb`.
impl Condition<u64> {
    /// TRUE is the bit vector of all 1's
    pub const TRUE: Self = Self(u64::MAX);
    /// FALSE is the bit vector of all 0's
    pub const FALSE: Self = Self(0);

    /// Constant-time mask generation from a compile-time boolean.
    ///
    /// Unlike signed integers where we can rely on Two's Complement via negation
    /// `-(v as i64)`, for unsigned types we must use wrapping subtraction to achieve
    /// the all-ones bit pattern for true:
    /// true (1) -> `0 - 1` wraps to MAX (all 1s); false (0) -> `0 - 0 = 0` (all 0s).
    pub const fn from_bool_const<const VALUE: bool>() -> Self {
        Self(0u64.wrapping_sub(VALUE as u64))
    }
    /// Constant-time mask generation from a runtime boolean.
    pub const fn from_bool(value: bool) -> Self {
        Self(0u64.wrapping_sub(value as u64))
    }
    /// Mask from the least-significant bit: TRUE iff bit 0 of `value` is set.
    /// This is the parity test: `from_lsb(x)` is TRUE iff `x` is odd. It is
    /// the `bit = 0` special case of [`Self::is_bit_set`].
    pub const fn from_lsb(value: u64) -> Self {
        Self(0u64.wrapping_sub(value & 1))
    }
    /// Mask from the most-significant bit: TRUE iff the top bit of `value` is set.
    /// The signed counterpart of this mask is `is_negative`, where the top bit
    /// carries a sign instead of a borrow/carry.
    ///
    /// This is the borrow/carry adaptor: the borrow word coming out of a wrapping
    /// wide subtraction chain carries its meaning entirely in the top bit, so
    /// `from_msb(borrow)` is the `lt` mask of that comparison with no further work.
    pub const fn from_msb(value: u64) -> Self {
        Self(0u64.wrapping_sub(value >> (u64::BITS - 1)))
    }
    /// TRUE iff bit `bit` of `value` is set. The bit index must be public data
    /// (the shift amount is timing-visible on some targets).
    pub const fn is_bit_set(value: u64, bit: u32) -> Self {
        Self::from_lsb(value >> bit)
    }
    /// TRUE iff `value != 0`.
    ///
    /// For any nonzero `x`, `x | x.wrapping_neg()` has the top bit set (either `x`
    /// or its two's complement is >= 2^(BITS-1)); for zero both sides are zero.
    pub const fn is_not_zero(value: u64) -> Self {
        Self::from_msb(value | value.wrapping_neg())
    }
    /// TRUE iff `value == 0`.
    pub const fn is_zero(value: u64) -> Self {
        // Complementing the inner value maps TRUE <-> FALSE (all 1s <-> all 0s).
        Self(!Self::is_not_zero(value).0)
    }
    /// TRUE iff `x == y`.
    pub const fn is_equal(x: u64, y: u64) -> Self {
        Self::is_zero(x ^ y)
    }
    /// Conditional selection: return `true_value` if the condition is true, otherwise
    /// return `false_value`.
    pub fn select(self, true_value: u64, false_value: u64) -> u64 {
        let mask = self.barrier().0;
        (true_value & mask) | (false_value & !mask)
    }
    /// Conditionally move the source value to the destination if the condition is
    /// true, otherwise nothing is moved.
    pub fn mov(self, src: u64, dst: &mut u64) {
        *dst = self.select(src, *dst);
    }
    /// Conditional swap: returns (rhs, lhs) if the condition is true, otherwise (lhs, rhs).
    pub fn swap(self, lhs: u64, rhs: u64) -> (u64, u64) {
        // One barrier serves both outputs: `t` is `lhs ^ rhs` under TRUE and zero under FALSE.
        let t = (lhs ^ rhs) & self.barrier().0;
        (lhs ^ t, rhs ^ t)
    }
    /// Convert the mask to a runtime boolean. Only use this at genuine public
    /// decision points: branching on the result leaks the condition's value.
    pub const fn to_bool(self) -> bool {
        self.0 != 0
    }
}

impl Condition<u32> {
    /// TRUE is the bit vector of all 1's
    pub const TRUE: Self = Self(u32::MAX);
    /// FALSE is the bit vector of all 0's
    pub const FALSE: Self = Self(0);

    /// Constant-time mask generation from a compile-time boolean.
    ///
    /// Unlike signed integers where we can rely on Two's Complement via negation
    /// `-(v as i64)`, for unsigned types we must use wrapping subtraction to achieve
    /// the all-ones bit pattern for true:
    /// true (1) -> `0 - 1` wraps to MAX (all 1s); false (0) -> `0 - 0 = 0` (all 0s).
    pub const fn from_bool_const<const VALUE: bool>() -> Self {
        Self(0u32.wrapping_sub(VALUE as u32))
    }
    /// Constant-time mask generation from a runtime boolean.
    pub const fn from_bool(value: bool) -> Self {
        Self(0u32.wrapping_sub(value as u32))
    }
    /// Mask from the least-significant bit: TRUE iff bit 0 of `value` is set.
    /// This is the parity test: `from_lsb(x)` is TRUE iff `x` is odd. It is
    /// the `bit = 0` special case of [`Self::is_bit_set`].
    pub const fn from_lsb(value: u32) -> Self {
        Self(0u32.wrapping_sub(value & 1))
    }
    /// Mask from the most-significant bit: TRUE iff the top bit of `value` is set.
    /// The signed counterpart of this mask is `is_negative`, where the top bit
    /// carries a sign instead of a borrow/carry.
    ///
    /// This is the borrow/carry adaptor: the borrow word coming out of a wrapping
    /// wide subtraction chain carries its meaning entirely in the top bit, so
    /// `from_msb(borrow)` is the `lt` mask of that comparison with no further work.
    pub const fn from_msb(value: u32) -> Self {
        Self(0u32.wrapping_sub(value >> (u32::BITS - 1)))
    }
    /// TRUE iff bit `bit` of `value` is set. The bit index must be public data
    /// (the shift amount is timing-visible on some targets).
    pub const fn is_bit_set(value: u32, bit: u32) -> Self {
        Self::from_lsb(value >> bit)
    }
    /// TRUE iff `value != 0`.
    ///
    /// For any nonzero `x`, `x | x.wrapping_neg()` has the top bit set (either `x`
    /// or its two's complement is >= 2^(BITS-1)); for zero both sides are zero.
    pub const fn is_not_zero(value: u32) -> Self {
        Self::from_msb(value | value.wrapping_neg())
    }
    /// TRUE iff `value == 0`.
    pub const fn is_zero(value: u32) -> Self {
        // Complementing the inner value maps TRUE <-> FALSE (all 1s <-> all 0s).
        Self(!Self::is_not_zero(value).0)
    }
    /// TRUE iff `x == y`.
    pub const fn is_equal(x: u32, y: u32) -> Self {
        Self::is_zero(x ^ y)
    }
    /// Conditional selection: return `true_value` if the condition is true, otherwise
    /// return `false_value`.
    pub fn select(self, true_value: u32, false_value: u32) -> u32 {
        let mask = self.barrier().0;
        (true_value & mask) | (false_value & !mask)
    }
    /// Conditionally move the source value to the destination if the condition is
    /// true, otherwise nothing is moved.
    pub fn mov(self, src: u32, dst: &mut u32) {
        *dst = self.select(src, *dst);
    }
    /// Conditional swap: returns (rhs, lhs) if the condition is true, otherwise (lhs, rhs).
    pub fn swap(self, lhs: u32, rhs: u32) -> (u32, u32) {
        // One barrier serves both outputs: `t` is `lhs ^ rhs` under TRUE and zero under FALSE.
        let t = (lhs ^ rhs) & self.barrier().0;
        (lhs ^ t, rhs ^ t)
    }
    /// Convert the mask to a runtime boolean. Only use this at genuine public
    /// decision points: branching on the result leaks the condition's value.
    pub const fn to_bool(self) -> bool {
        self.0 != 0
    }
}

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

// ---------------------------------------------------------------------------------------------
// Byte-slice comparison helpers
//
// The accumulator is routed through `value_barrier` on every iteration. That forecloses both of
// the early exits that would otherwise be legal:
//
//   * leaving the loop once the accumulator is non-zero, because the final `== 0` is already
//     decided (only legal if the compiler can see that the zero test is the sole consumer), and
//   * leaving the loop once the accumulator is all-ones, because further ORs cannot change it
//     (legal regardless of the consumer, which is why the barrier must be *inside* the loop).
// ---------------------------------------------------------------------------------------------

/// The slices are compared one machine word at a time, with a byte-wise tail. The word is a
/// `usize`, so it is 2, 4 or 8 bytes according to the target.
type AccWord = usize;
const ACC_BYTES: usize = size_of::<AccWord>();

/// TRUE iff the accumulator of a comparison loop is zero, as a mask rather than a `bool`, so
/// that nothing between the barriered accumulator and the consumer of the mask invites a branch.
fn acc_is_zero(acc: AccWord) -> Condition<u32> {
    // The `is_not_zero` identity (the top bit of `x | -x` is set iff `x != 0`) taken apart with a
    // barrier after each step. Written in one piece the compiler recognises it as `x != 0`, which
    // avr lowers as a compare and branch, and spreading the top bit across a 32-bit word instead
    // (as `Condition::is_zero` does) becomes a branch on msp430. Opaque at each step, it stays
    // or/neg, shift, subtract on every target inspected.
    let top = value_barrier(acc | acc.wrapping_neg());
    let not_zero = value_barrier(top >> (AccWord::BITS - 1));
    // `not_zero` is 0 or 1; subtracting 1 gives all-ones for a zero accumulator, zero otherwise.
    Condition((not_zero as u32).wrapping_sub(1))
}

/// Constant-time equality of two byte slices, as a mask: [`Condition::TRUE`] iff `a == b`.
///
/// The runtime depends on the *lengths* of the inputs, which are treated as public, but not on
/// their contents or on the position of any difference. Slices of different lengths compare
/// unequal immediately.
///
/// Use this form where the result selects data, as in [`conditional_copy_bytes`], so that the
/// comparison and the selection are joined by a mask rather than a `bool`. Rust does not
/// guarantee constant-time execution on every target and optimisation level; the "Optimisation
/// barrier" section comment in this file says what is done about that.
pub fn ct_eq_bytes_mask(a: &[u8], b: &[u8]) -> Condition<u32> {
    if a.len() != b.len() {
        return Condition::<u32>::FALSE;
    }
    // Both slices now have the same length, so the two chunkings line up exactly and the
    // `zip`s below never drop an element.
    let (words_a, tail_a) = a.as_chunks::<ACC_BYTES>();
    let (words_b, tail_b) = b.as_chunks::<ACC_BYTES>();

    let mut acc: AccWord = 0;
    for (x, y) in words_a.iter().zip(words_b) {
        acc = value_barrier(acc | (AccWord::from_ne_bytes(*x) ^ AccWord::from_ne_bytes(*y)));
    }
    for (x, y) in tail_a.iter().zip(tail_b) {
        acc = value_barrier(acc | AccWord::from(x ^ y));
    }
    acc_is_zero(acc)
}

/// Constant-time equality of two byte slices: [`ct_eq_bytes_mask`] as a `bool`, for callers that
/// go on to branch on the result at a public decision point.
pub fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    ct_eq_bytes_mask(a, b).to_bool()
}

/// Constant-time check that every byte of `a` is zero.
///
/// The runtime depends on the length of `a`, which is treated as public, but not on its contents
/// or on the position of the first non-zero byte. Same construction as [`ct_eq_bytes_mask`] with
/// the XOR against the second operand omitted.
pub fn ct_eq_zero_bytes(a: &[u8]) -> bool {
    let (words, tail) = a.as_chunks::<ACC_BYTES>();

    let mut acc: AccWord = 0;
    for x in words {
        acc = value_barrier(acc | AccWord::from_ne_bytes(*x));
    }
    for x in tail {
        acc = value_barrier(acc | AccWord::from(*x));
    }
    acc_is_zero(acc).to_bool()
}

/// Copies `a` into `out` if `take_a` is TRUE, otherwise `b`, without branching on `take_a`.
///
/// Take `take_a` from [`ct_eq_bytes_mask`] or a [`Condition`] constructor. Converting a secret
/// `bool` with [`Condition::from_bool`] puts a value the compiler may branch on between the
/// comparison and the copy.
pub fn conditional_copy_bytes<const LEN: usize>(
    a: &[u8; LEN],
    b: &[u8; LEN],
    out: &mut [u8; LEN],
    take_a: Condition<u32>,
) {
    // One barrier for the whole copy; after it the byte mask is opaque, so the masked
    // arithmetic per byte cannot be turned back into a branch.
    let mask = take_a.barrier().0 as u8;
    for ((o, x), y) in out.iter_mut().zip(a).zip(b) {
        *o = (x & mask) | (y & !mask);
    }
}

/// Conditionally selects between two limb arrays without branching: writes `a` into `out` if
/// `cond` is TRUE, otherwise `b`. Every limb is written under the mask, regardless of `cond`, so
/// the operation takes the same path irrespective of which array is selected.
pub fn conditional_select<const L: usize>(
    cond: Condition<u64>,
    a: &[u64; L],
    b: &[u64; L],
    out: &mut [u64; L],
) {
    for i in 0..L {
        out[i] = cond.select(a[i], b[i]);
    }
}

/// Conditionally swaps two limb arrays in place without branching: if `cond` is TRUE, `a` and
/// `b` are exchanged; otherwise both are left unchanged. Every limb is written either way.
pub fn conditional_swap<const L: usize>(cond: Condition<u64>, a: &mut [u64; L], b: &mut [u64; L]) {
    for i in 0..L {
        let (new_a, new_b) = cond.swap(a[i], b[i]);
        a[i] = new_a;
        b[i] = new_b;
    }
}
