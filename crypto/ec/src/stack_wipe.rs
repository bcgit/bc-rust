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
