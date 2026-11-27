//! The stack wipe shared by the modules that run a secret-bearing computation in a frame of its
//! own and overwrite the stack it used. How much to overwrite is each caller's, by measurement.

use bouncycastle_utils::secret::Secret;

/// Overwrites `WORDS` 64-bit words of the stack that the previous call made from the caller's
/// frame used, by taking a frame of its own over the same memory and wiping it. Never inlined:
/// the frame is the point.
#[inline(never)]
pub(crate) fn wipe_stack_below<const WORDS: usize>() {
    let mut scratch = Secret::<[u64; WORDS]>::new();
    core::hint::black_box(&mut *scratch);
}

/// [`wipe_stack_below`] when it is dropped.
struct WipeStackBelowOnDrop<const WORDS: usize>;

impl<const WORDS: usize> Drop for WipeStackBelowOnDrop<WORDS> {
    fn drop(&mut self) {
        wipe_stack_below::<WORDS>();
    }
}

/// Runs `f` in a frame of its own, never inlined, and then [`wipe_stack_below`], so that what `f`
/// and its callees leave lies below the caller's frame, where the wipe reaches it. An `R` returned
/// through memory (a key, a `Result` holding one) is written straight to where the caller keeps
/// it, not held in this frame across the wipe and then copied, which would leave a copy above the
/// wiped stack. One returned in registers (a `Result<usize, _>`, a 16-byte array on x86-64) is
/// held in them across the wipe, whose prologue may push them into its frame's top slots, which
/// it never clears: a secret `R` must not be one that fits in registers.
pub(crate) fn in_wiped_frame<const WORDS: usize, R>(f: impl FnOnce() -> R) -> R {
    let _wipe = WipeStackBelowOnDrop::<WORDS>;
    in_own_frame(f)
}

#[inline(never)]
fn in_own_frame<R>(f: impl FnOnce() -> R) -> R {
    f()
}
