//! Stack wipes for code that runs a secret-bearing computation in a frame of its own and then
//! overwrites the stack that computation used. The caller runs the computation in a
//! never-inlined function, so that everything it and its callees spill or stage lies below the
//! caller's frame, and calls a wipe next.
//!
//! How much to overwrite is each caller's, by measurement, beside its constants. The sizes are
//! for an optimised build: an unoptimised build's frames are larger and are not covered.

use crate::secret::{Secret, ZeroizablePrimitive, zeroize_in_place};
use core::marker::PhantomData;

/// Overwrites `WORDS` 64-bit words of the stack that the previous call made from the caller's
/// frame used, by taking frames of its own over the same memory and wiping them.
///
/// Mutants note: replacing this or [`wipe_stack_below_scaled`]'s body with `()` is missed by
/// `cargo test`; only the stack checks (`dev_scripts/check_*_stack.sh`) see a wipe that does
/// nothing.
#[inline(always)]
pub fn wipe_stack_below<const WORDS: usize>() {
    wipe_stack_below_scaled::<u64, 0, WORDS>();
}

/// As [`wipe_stack_below`], for a computation whose stack grows with a size parameter (a curve's
/// or a modulus's width): `COUNT` values of `T`, the limb array of the size in hand, for the part
/// that scales, and `FIXED` words for the part that does not.
#[inline(always)]
pub fn wipe_stack_below_scaled<T: ZeroizablePrimitive, const COUNT: usize, const FIXED: usize>() {
    // Both calls are made from the caller's frame, at the same stack pointer. `wipe_frame`'s
    // array lies below its return address, the registers it saves and any alignment padding,
    // so it never writes the top few words of the region; `wipe_frame_top` writes those.
    wipe_frame::<T, COUNT, FIXED>();
    wipe_frame_top();
    // Keeps `wipe_frame_top` from being a tail call, which would run it after the caller's frame
    // is released, higher up the stack than `wipe_frame`.
    core::hint::black_box(());
}

/// The array [`wipe_frame`] overwrites, as one local, so that no slot of that frame lies between
/// its parts.
#[derive(Clone, Copy)]
#[repr(C)]
struct Frame<T: ZeroizablePrimitive, const COUNT: usize, const FIXED: usize> {
    scaled: [T; COUNT],
    fixed: [u64; FIXED],
}

impl<T: ZeroizablePrimitive, const COUNT: usize, const FIXED: usize> ZeroizablePrimitive
    for Frame<T, COUNT, FIXED>
{
    const ZEROED: Self = Frame { scaled: [T::ZEROED; COUNT], fixed: [0; FIXED] };
}

/// Takes a frame of [`Frame`] and overwrites it. Never inlined: the frame is the point.
/// Mutants note: a body of `()` is missed by `cargo test`, as [`wipe_stack_below`]'s is.
#[inline(never)]
fn wipe_frame<T: ZeroizablePrimitive, const COUNT: usize, const FIXED: usize>() {
    // No padding between the two arrays.
    const { assert!(size_of::<T>() % 8 == 0) };
    let _frame = Secret::<Frame<T, COUNT, FIXED>>::new();
}

/// How much [`wipe_frame_top`] overwrites, in 64-bit words: more than [`wipe_frame`] keeps above
/// its array, which is at most 40 bytes (aarch64; 16 on x86-64 and thumbv6m, 8 on riscv32i) at
/// every size this workspace wipes.
const TOP_WORDS: usize = 16;

/// Overwrites the `TOP_WORDS` words below the caller's stack pointer. A leaf that saves no
/// callee-saved register, written one word at a time, not through `memcpy`, so that it stays
/// one: its array then starts directly below the return address (x86-64), the frame record (`r7`
/// and `lr` on thumbv6m) or the caller's stack pointer itself (aarch64, riscv32i). Never inlined:
/// the frame is the point. Mutants note: a body of `()` is missed by `cargo test`, as
/// [`wipe_stack_below`]'s is.
#[inline(never)]
fn wipe_frame_top() {
    // The initialiser's stores are not elided before the volatile pass, so each word is written
    // twice; safe Rust has no uninitialised array to write once.
    let mut top = [0u64; TOP_WORDS];
    for word in top.iter_mut() {
        zeroize_in_place(word);
    }
}

/// [`wipe_stack_below`] when it is dropped: declared first in a function, so that the wipe runs
/// after that function's result has been written and its other locals dropped.
pub struct WipeStackBelowOnDrop<const WORDS: usize>;

impl<const WORDS: usize> Drop for WipeStackBelowOnDrop<WORDS> {
    // Inlined, so that the wipe's frames start at the stack pointer of the function holding the
    // guard rather than below a frame of this.
    #[inline(always)]
    fn drop(&mut self) {
        wipe_stack_below::<WORDS>();
    }
}

/// [`wipe_stack_below_scaled`] when it is dropped, for a function whose result is itself the
/// secret and is returned by value. Such a function ends with the call that does the work, so
/// that the result is written to where the function's own caller wants it and not staged in
/// this frame, and declares this first, so that the wipe runs after that call has returned:
///
/// ```text
/// let _wipe = WipeStackBelowScaledOnDrop::<T, COUNT, FIXED>::new();
/// the_work_in_own_frame(..)
/// ```
pub struct WipeStackBelowScaledOnDrop<
    T: ZeroizablePrimitive,
    const COUNT: usize,
    const FIXED: usize,
>(PhantomData<T>);

impl<T: ZeroizablePrimitive, const COUNT: usize, const FIXED: usize>
    WipeStackBelowScaledOnDrop<T, COUNT, FIXED>
{
    /// The guard; the wipe runs when it is dropped.
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<T: ZeroizablePrimitive, const COUNT: usize, const FIXED: usize> Drop
    for WipeStackBelowScaledOnDrop<T, COUNT, FIXED>
{
    // Inlined, as [`WipeStackBelowOnDrop`]'s is.
    #[inline(always)]
    fn drop(&mut self) {
        wipe_stack_below_scaled::<T, COUNT, FIXED>();
    }
}

/// Runs `f` in a frame of its own, never inlined, and then [`wipe_stack_below`], so that what `f`
/// and its callees leave lies below the caller's frame, where the wipe reaches it. An `R` returned
/// through memory (a key, a `Result` holding one) is written straight to where the caller keeps
/// it, not held in this frame across the wipe and then copied, which would leave a copy above the
/// wiped stack. One returned in registers (a `Result<usize, _>`, a 16-byte array on x86-64) is
/// held across the wipe in a callee-saved register or in this frame, above the wiped stack: a
/// secret `R` must not be one that fits in registers.
pub fn in_wiped_frame<const WORDS: usize, R>(f: impl FnOnce() -> R) -> R {
    let _wipe = WipeStackBelowOnDrop::<WORDS>;
    in_own_frame(f)
}

/// [`in_wiped_frame`] with [`wipe_stack_below_scaled`]. What `f` returns is the only thing that
/// leaves the wiped frame: `f` builds the whole value the caller needs (a key's `Result`, a
/// signature), and the value is written to where the caller keeps it, not staged in a frame
/// above the wiped ones.
pub fn in_wiped_frame_scaled<T: ZeroizablePrimitive, const COUNT: usize, const FIXED: usize, R>(
    f: impl FnOnce() -> R,
) -> R {
    let _wipe = WipeStackBelowScaledOnDrop::<T, COUNT, FIXED>::new();
    in_own_frame(f)
}

#[inline(never)]
fn in_own_frame<R>(f: impl FnOnce() -> R) -> R {
    f()
}
