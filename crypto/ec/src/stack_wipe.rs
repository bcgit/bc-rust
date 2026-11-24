//! The stack wipe shared by the modules that run a secret-bearing computation in a frame of its
//! own and overwrite the stack it used. How much to overwrite is each caller's, by measurement.

use bouncycastle_utils::secret::{Secret, ZeroizablePrimitive};
use core::marker::PhantomData;

/// Overwrites `WORDS` 64-bit words of the stack that the previous call made from the caller's
/// frame used, by taking a frame of its own over the same memory and wiping it. Never inlined:
/// the frame is the point.
#[inline(never)]
pub(crate) fn wipe_stack_below<const WORDS: usize>() {
    let mut scratch = Secret::<[u64; WORDS]>::new();
    core::hint::black_box(&mut *scratch);
}

/// As [`wipe_stack_below`], for a computation generic over a curve, whose stack grows with the
/// curve's width: `COUNT` values of `T` (the curve's limb array) and `FIXED` words.
#[inline(never)]
fn wipe_stack_below_scaled<T: ZeroizablePrimitive, const COUNT: usize, const FIXED: usize>() {
    let mut scaled = Secret::<[T; COUNT]>::new();
    let mut fixed = Secret::<[u64; FIXED]>::new();
    core::hint::black_box((&mut *scaled, &mut *fixed));
}

/// [`wipe_stack_below_scaled`] when it is dropped.
struct WipeStackBelowScaledOnDrop<T: ZeroizablePrimitive, const COUNT: usize, const FIXED: usize>(
    PhantomData<T>,
);

impl<T: ZeroizablePrimitive, const COUNT: usize, const FIXED: usize> Drop
    for WipeStackBelowScaledOnDrop<T, COUNT, FIXED>
{
    fn drop(&mut self) {
        wipe_stack_below_scaled::<T, COUNT, FIXED>();
    }
}

/// Runs `f` in a frame of its own, never inlined, and then [`wipe_stack_below_scaled`], so that
/// what `f` and its callees leave lies below the caller's frame, where the wipe reaches it. What
/// `f` returns is the only thing that leaves the wiped frame: `f` builds the whole value the
/// caller needs (a key's `Result`, a signature), and the value is written to where the caller
/// keeps it, not staged in a frame above the wiped ones.
pub(crate) fn in_wiped_frame<T: ZeroizablePrimitive, const COUNT: usize, const FIXED: usize, R>(
    f: impl FnOnce() -> R,
) -> R {
    let _wipe = WipeStackBelowScaledOnDrop::<T, COUNT, FIXED>(PhantomData);
    in_own_frame(f)
}

#[inline(never)]
fn in_own_frame<R>(f: impl FnOnce() -> R) -> R {
    f()
}
