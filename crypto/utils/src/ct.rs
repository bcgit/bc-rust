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

    //
    // Q. T. Felix - start
    //
    // Q. T. Felix NOTE: For this conditional negation formula to work, the mask value for TRUE must be -1 (Hex: 0xFFFF...), where all bits are set to 1
    pub const TRUE: Self = Self(-1);
    //
    // Q. T. Felix - end
    //
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

    // MikeO: TODO: I have no idea what this does, .negate(-1) seems to give -3 ?? Is that a bug?
    /// ## negate seems to give -3
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
    ///
    /// ---
    ///
    /// kor
    ///
    /// 입력값 `value`가 `-1` (즉 모든 비트가 `1`, `...1111`)
    ///
    /// 조건 `self.0`은 1 (`...0001`) (`TRUE`라고 가정하고)
    ///
    /// XOR 연산은 `value ^ self.0`로 실행하셧음
    ///
    /// 그러면 `...1111 XOR ...0001 = ...1110` (즉 `-2`)
    ///
    /// 뺄셈 연산은 `wrapping_sub(self.0)`
    ///
    /// 그럼? `-2 - 1 = -3`
    ///
    /// 결과적으로 `-1`의 부정인` 1`이 나와야 하는데 `-3`이 출력됩니다
    ///
    /// 그래서 i64 [Condition] 구현체의 [Self::TRUE] 상수 값을 `-1`로 변경하면
    /// 테스트도 정상적으로 수행됩니다.
    ///
    /// ---
    ///
    /// Conditionally negate the value.
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

//
// Q. T. Felix - start
//
/// # PR Condition u64
///
/// Although the [Condition] struct is defined, the actual implementation was only written for `Condition<i64>`.
/// Even though `u64` is included in the `supported_mask_type!` macro, methods for `u64` were missing,
/// making it impossible to perform constant-time operations for the `u64` type.
/// To resolve this issue, this implementation adds support for `u64`.
///
/// ---
///
/// kor
///
/// [Condition] 구조체는 정의되어 있지만 실제 구현체는 `Condition<i64>`에 대해서만 작성되어 있음
/// `supported_mask_type!` 매크로에는 u64가 포함되어 있음에도 불구하고 u64를 위한 메소드들이 누락되어 있어
/// u64 타입의 상수 시간(constant-time) 연산을 수행할 수 없는 상태였음
/// 위 문제를 해결하기 위해 해당 구조체를 구현하여 u64 지원 추가함
impl Condition<u64> {
    // Q. T. Felix NOTE: so strict definition of true/false constants for u64
    //                   While i64 used 1 and 0, for mask generation logic we ensure consistency
    //                   TRUE must be all-ones (u64::MAX) to work correctly with bitwise select logic.
    pub const TRUE: Self = Self(u64::MAX);
    pub const FALSE: Self = Self(0);

    // Q. T. Felix NOTE: so this is the core logic for constant-time mask generation for unsigned integers
    //                   Unlike signed integers where we can rely on Two's Complement via negation `-(v as i64)`,
    //                   for u64 we must use wrapping subtraction to achieve the all-ones bit pattern (u64::MAX) for true
    pub const fn from_bool<const VALUE: bool>() -> Self {
        // If VALUE is true (1) -> 0 - 1 = u64::MAX (All 1s)
        // If VALUE is false (0) -> 0 - 0 = 0 (All 0s)
        Self(0u64.wrapping_sub(VALUE as u64))
    }

    // Q. T. Felix NOTE: so we implement the select function manually for u64
    //                   This resolves the TODO by covering the missing primitive implementation,
    //                   although a fully generic impl<T> would be the ultimate long-term goal
    pub fn select(self, a: u64, b: u64) -> u64 {
        let mask = self.0;
        (a & mask) | (b & !mask)
    }

    // Q. T. Felix NOTE: so we provide a method to check if the condition effectively resolves to true
    //                   by checking the underlying mask value
    pub fn is_true(&self) -> bool {
        self.0 != 0
    }
}
//
// Q. T. Felix - end
//

// TODO: ... this doesn't ... work. We should get this working and then then do u8.
// TODO: then and change Hex and Base64 to use this.
// TODO: (there's probably no noticeable performance difference u8 and u64 bit ops on a 64-bit machine,
// TODO:  but there would be on a 8, 16, or 32-bit machine.)
// impl Condition<u64> {
//     pub const TRUE: Self = Self(1);
//     pub const FALSE: Self = Self(0);
//
//     pub const fn new<const VALUE: bool>() -> Self {
//         Self((VALUE as u64).wrapping_neg())
//     }
//
//     pub const fn from_bool(value: bool) -> Self {
//         Self((value as u64).wrapping_neg())
//     }
//
//     pub const fn is_bit_set(value: u64, bit: u64) -> Self {
//         Self(((value >> bit) & 1).wrapping_neg())
//     }
//
//     // MikeO: TODO ?? What does "negative" mean for an unsigned value?
//     pub const fn is_negative(value: u64) -> Self {
//         Self(((value as i64) >> 63) as u64)
//     }
//
//     pub const fn is_not_zero(value: u64) -> Self {
//         Self::is_negative(Self::or_halves(value).wrapping_neg())
//     }
//
//     pub const fn is_zero(value: u64) -> Self {
//         Self::is_negative(Self::or_halves(value).wrapping_sub(1))
//     }
//
//     // MikeO: TODO: I borrowed this formula from Botan, but rust complains about u64 subtraction overflow if x < y, so this works in C but won't work in rust.
//     // MikeO: TODO: I played with u64.wrapping_sub(y) but that doesn't work either.
//     pub const fn is_lt(x: u64, y: u64) -> Self {
//         Self::is_zero(x ^ ((x ^ y) | (x.wrapping_sub(y)) ^ x))
//     }
//
//     // Note: haven't found a clever way to make this const, since it either needs a (non-const) not (!) or a boolean OR is_zero.
//     // pub fn is_lte(x: i64, y: i64) -> Self { !Self::is_gt(x, y) }
//
//     // pub const fn is_gt(x: i64, y: i64) -> Self { Self::is_lt(y, x) }
//
//     // Note: haven't found a clever way to make this const, since it either needs a (non-const) not (!) or a boolean OR is_zero.
//     // pub fn is_gte(x: i64, y: i64) -> Self { !Self::is_lt(x, y) }
//
//     pub fn is_in_list(value: u64, list: &[u64]) -> Self {
//         // Research question: is this actually constant-time?
//         // A clever compiler might turn this into a short-circuiting loop.
//         // A quick google search shows that rust doesn't have the ability to annotate specific code blocks
//         // as no-optimize; the only option is to insert direct assembly.
//
//         let mut c = Self::FALSE;
//         for i in 0..list.len() {
//             let diff = value ^ list[i];
//             c |= Condition::<u64>::is_zero(diff);
//         }
//
//         c
//     }
//
//     pub fn mov(self, src: u64, dst: &mut u64) {
//         *dst = self.select(src, *dst);
//     }
//
//     // MikeO: TODO: This needs a docstring because I have no idea what this does.
//     pub const fn negate(self, value: u64) -> u64 {
//         (value ^ self.0).wrapping_sub(self.0)
//     }
//
//     const fn or_halves(value: u64) -> u64 {
//         (value & 0xFFFFFFFF) | (value >> 32)
//     }
//
//     pub const fn select(self, true_value: u64, false_value: u64) -> u64 {
//         (true_value & self.0) | (false_value & !self.0)
//     }
//
//     pub const fn swap(self, lhs: u64, rhs: u64) -> (u64, u64) {
//         (self.select(rhs, lhs), self.select(lhs, rhs))
//     }
//
//     pub const fn to_bool_var(self) -> bool {
//         self.0 != 0
//     }
// }

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
