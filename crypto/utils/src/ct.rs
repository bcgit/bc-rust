//! A set of constant-time helper functions for the following:
//!
//! * Basic arithmetic operations such as less-than(x, y), is_zero(x), etc.
//! * Conditional operations such as select and swap whose output depends on whether the condition is true or false.
//! * Implementing boolean operators for Condition\<T\>: &, &=, |, |=, ^, ^=.

use core::ops::*;

mod sealed {
    pub trait Sealed {}
}

pub struct MaskType<T>(core::marker::PhantomData<T>);

pub trait SupportedMaskType: sealed::Sealed {}

macro_rules! supported_mask_type {
    ($($t:ty),+) => {
        $(
            impl sealed::Sealed for MaskType<$t> {}
            impl SupportedMaskType for MaskType<$t> {}
        )+
    };
}

supported_mask_type!(i64, u64);

#[derive(Clone, Copy)]
#[must_use]
#[repr(transparent)]
pub struct Condition<T>(T)
where
    MaskType<T>: SupportedMaskType;

impl<T> Condition<T> where MaskType<T>: SupportedMaskType {}

impl Condition<i64> {
    // MikeO: TODO: there are a bunch of impls in here that seem to be generic and not related to i64,
    // MikeO: TODO: could those be moved to a generic impl<T> for Condition<T> ?

    /// TRUE is the bit vector of all 1's
    pub const TRUE: Self = Self(-1);
    /// FALSE is the bit vector of all 0's
    pub const FALSE: Self = Self(0);

    pub const fn from_bool<const VALUE: bool>() -> Self {
        Self(-(VALUE as i64))
    }

    pub const fn from_bool_var(value: bool) -> Self {
        Self(-(value as i64))
    }

    pub const fn is_bit_set(value: i64, bit: i64) -> Self {
        Self(-((value >> bit) & 1))
    }

    pub const fn is_negative(value: i64) -> Self {
        Self(value >> 63)
    }

    pub const fn is_not_zero(value: i64) -> Self {
        Self::is_negative(-Self::or_halves(value))
    }

    pub const fn is_zero(value: i64) -> Self {
        Self::is_negative(Self::or_halves(value) - 1)
    }

    pub const fn is_equal(x: i64, y: i64) -> Self {
        Self::is_zero(x ^ y)
    }

    pub const fn is_lt(x: i64, y: i64) -> Self {
        Self::is_negative(x - y)
    }

    // Note: haven't found a clever way to make this const, since it either needs a (non-const) not (!) or a boolean OR is_zero.
    pub fn is_lte(x: i64, y: i64) -> Self {
        !Self::is_gt(x, y)
    }

    pub const fn is_gt(x: i64, y: i64) -> Self {
        Self::is_lt(y, x)
    }

    // Note: haven't found a clever way to make this const, since it either needs a (non-const) not (!) or a boolean OR is_zero.
    pub fn is_gte(x: i64, y: i64) -> Self {
        !Self::is_lt(x, y)
    }

    pub fn is_within_range(value: i64, min: i64, max: i64) -> Self {
        Self::is_gte(value, min) & Self::is_lte(value, max)
    }

    pub fn is_in_list(value: i64, list: &[i64]) -> Self {
        // Research question: is this actually constant-time?
        // A clever compiler might turn this into a short-circuiting loop.
        // A quick google search shows that rust doesn't have the ability to annotate specific code blocks
        // as no-optimize; the only option is to insert direct assembly.

        let mut c = Self::FALSE;
        for i in 0..list.len() {
            let diff = value ^ list[i];
            c |= Condition::<i64>::is_zero(diff);
        }

        c
    }

    /// Conditionally move the source value to the destination if the condition is true, otherwise nothing is moved.
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
    /// Therefore, if the [Self::TRUE] constant value of the i64 [Condition] implementation is changed to `-1`,
    /// the test also runs normally.
    pub const fn negate(self, value: i64) -> i64 {
        (value ^ self.0).wrapping_sub(self.0)
    }

    pub const fn or_halves(value: i64) -> i64 {
        (value | (value >> 32)) & 0xFFFFFFFF
    }

    /// Conditional selection: return `true_value` if the condition is true, otherwise return `false_value`.
    pub const fn select(self, true_value: i64, false_value: i64) -> i64 {
        (true_value & self.0) | (false_value & !self.0)
    }

    /// Conditional swap: returns (lhs, rhs) if the condition is true, otherwise returns (rhs, lhs).
    pub const fn swap(self, lhs: i64, rhs: i64) -> (i64, i64) {
        (self.select(rhs, lhs), self.select(lhs, rhs))
    }

    pub const fn to_bool_var(self) -> bool {
        self.0 != 0
    }
}

// TODO: We should do Condition<u8>.
// TODO: then and change Hex and Base64 to use this.
// TODO: (there's probably no noticeable performance difference u8 and u64 bit ops on a 64-bit machine,
// TODO:  but there would be on a 8, 16, or 32-bit machine.)
impl Condition<u64> {
    /// TRUE is the bit vector of all 1's
    pub const TRUE: Self = Self(u64::MAX);
    /// FALSE is the bit vector of all 0's
    pub const FALSE: Self = Self(0);

    // this is the core logic for constant-time mask generation for unsigned integers
    //   Unlike signed integers where we can rely on Two's Complement via negation `-(v as i64)`,
    //   for u64 we must use wrapping subtraction to achieve the all-ones bit pattern (u64::MAX) for true
    pub const fn from_bool<const VALUE: bool>() -> Self {
        // If VALUE is true (1) -> 0 - 1 = u64::MAX (All 1s)
        // If VALUE is false (0) -> 0 - 0 = 0 (All 0s)
        Self(0u64.wrapping_sub(VALUE as u64))
    }

    // the select function manually for u64
    //    although a fully generic impl<T> would be the ultimate long-term goal
    pub fn select(self, a: u64, b: u64) -> u64 {
        let mask = self.0;
        (a & mask) | (b & !mask)
    }

    pub fn is_true(&self) -> bool {
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

/// Rust doesn't guarantee that anything can truly be constant-time under all compilation targets
/// and optimization levels, but we'll try.
pub fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for i in 0..a.len() {
        result |= std::hint::black_box(a[i] ^ b[i]);
    }
    result == 0
}

/// Rust doesn't guarantee that anything can truly be constant-time under all compilation targets
/// and optimization levels, but we'll try.
pub fn ct_eq_zero_bytes(a: &[u8]) -> bool {
    let mut result = 0u8;
    for i in 0..a.len() {
        result |= std::hint::black_box(a[i]);
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
        out[i] = std::hint::black_box(a[i] & mask) | std::hint::black_box(b[i] & !mask);
    }
}
