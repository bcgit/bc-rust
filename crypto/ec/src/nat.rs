//! Fixed-width, branch-free arithmetic on little-endian `[u64; L]` limb arrays.
//!
//! `L` is chosen per curve by its bit width (`L = 4` for a 256-bit field, as used by P-256). Every
//! primitive here is total, branch-free, and returns a plain carry/borrow (0 or 1) rather than
//! branching on it, so that callers doing modular arithmetic on secret values can chain these
//! without leaking timing through the carry/borrow chain itself. Comparisons belong to the
//! curve-specific field module (built from these primitives plus [`bouncycastle_utils::ct`]),
//! not here.

/// Adds two `L`-limb little-endian numbers. Returns the sum and the carry out of the top limb (0
/// or 1); the true (unwrapped) sum is `result + carry * 2^(64*L)`.
pub fn add<const L: usize>(a: &[u64; L], b: &[u64; L]) -> ([u64; L], u64) {
    let mut result = [0u64; L];
    let mut carry: u64 = 0;
    for i in 0..L {
        let (s1, c1) = a[i].overflowing_add(b[i]);
        let (s2, c2) = s1.overflowing_add(carry);
        result[i] = s2;
        carry = (c1 as u64) | (c2 as u64);
    }
    (result, carry)
}

/// Subtracts `b` from `a` over `L` limbs. Returns the difference and the borrow out of the top
/// limb (0 or 1); the true (unwrapped) difference is `result - borrow * 2^(64*L)`.
pub fn sub<const L: usize>(a: &[u64; L], b: &[u64; L]) -> ([u64; L], u64) {
    let mut result = [0u64; L];
    let mut borrow: u64 = 0;
    for i in 0..L {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        result[i] = d2;
        borrow = (b1 as u64) | (b2 as u64);
    }
    (result, borrow)
}

/// `a += b` in place over `L` limbs. Returns the carry out of the top limb (0 or 1). The
/// in-place form of [`add`], for a sum that must not be staged in a return value: `a` is the
/// caller's `Secret`, and nothing but the carry leaves it.
pub fn add_assign<const L: usize>(a: &mut [u64; L], b: &[u64; L]) -> u64 {
    let mut carry: u64 = 0;
    for i in 0..L {
        let (s1, c1) = a[i].overflowing_add(b[i]);
        let (s2, c2) = s1.overflowing_add(carry);
        a[i] = s2;
        carry = (c1 as u64) | (c2 as u64);
    }
    carry
}

/// `a -= b` in place over `L` limbs. Returns the borrow out of the top limb (0 or 1). The
/// in-place form of [`sub`], as [`add_assign`] is of [`add`].
pub fn sub_assign<const L: usize>(a: &mut [u64; L], b: &[u64; L]) -> u64 {
    let mut borrow: u64 = 0;
    for i in 0..L {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        a[i] = d2;
        borrow = (b1 as u64) | (b2 as u64);
    }
    borrow
}

/// TRUE iff every limb of `a` is zero.
pub fn is_zero<const L: usize>(a: &[u64; L]) -> bouncycastle_utils::ct::Condition<u64> {
    let mut acc = 0u64;
    for i in 0..L {
        acc |= a[i];
    }
    bouncycastle_utils::ct::Condition::<u64>::is_zero(acc)
}
