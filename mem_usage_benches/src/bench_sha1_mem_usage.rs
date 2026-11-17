//! Stack usage of the SHA-1 entry points, and the in-memory sizes printed by `print_struct_sizes`,
//! the source of the "Memory Usage" tables in the bouncycastle-sha1 crate docs.
//!
//! As with Ascon, a call needs a few hundred bytes, below the floor of the process's own start-up
//! that `bench_aes_mem_usage` describes, so massif cannot see it. The figures in the crate docs
//! are read from the compiler the way `bench_ascon_mem_usage` describes: `-C remark=prologepilog`
//! gives each function's frame and `--emit=asm` its calls, after LTO, and a figure is the deepest
//! chain of frames below the entry point plus 8 bytes of return address per call, not following
//! the panic paths. With every bench called from `main`:
//!
//! ```text
//! cargo rustc --release -p mem_usage_benches --bin bench_sha1_mem_usage -- -C remark=prologepilog --emit=asm
//! ```
//!
//! Each entry point is called through a `black_box`ed function pointer, which gives it an
//! out-of-line body of its own, so the frame being read is the entry point's and not the
//! harness closure's. The inputs are built in `#[inline(never)]` helpers, so their frames are
//! siblings of the operation's.

#![allow(dead_code)]
#![allow(unused_imports)]

use core::hint::black_box;

use bouncycastle::core::traits::{Hash, HashOneShot, Suspendable};
use bouncycastle::sha1::{SHA1, SUSPENDED_SHA1_STATE_LEN};

/// Two full 64-byte blocks and a partial one.
const MSG_LEN: usize = 150;

/// This exists so /usr/bin/time can measure the base memory footprint of the harness itself.
#[inline(never)]
fn bench_do_nothing() {
    eprintln!("DoNothing");

    print!("{}", 1 + 1);
}

/// Prints the in-memory size of each value a caller holds between calls, and the size of its
/// suspended state. Neither depends on how much data has been processed.
#[inline(never)]
fn print_struct_sizes() {
    use core::mem::size_of;

    println!("size_of<SHA1>: {}", size_of::<SHA1>());
    println!("SUSPENDED_SHA1_STATE_LEN: {}", SUSPENDED_SHA1_STATE_LEN);
}

/// Runs the operation in its own frame. Returns nothing, so no result crosses the boundary.
#[inline(never)]
fn measure(f: impl FnOnce()) {
    f()
}

/// A message filled at run time, so that its contents are not a constant the compiler could fold
/// the whole computation over.
#[inline(never)]
fn message<const N: usize>(fill: u8) -> [u8; N] {
    let mut m = [0u8; N];
    m.fill(black_box(fill));
    m
}

/// An SHA1 that has taken the message, so the final pads a partial block.
#[inline(never)]
fn sha1_after_data() -> SHA1 {
    let mut h = SHA1::new();
    h.do_update(&message::<MSG_LEN>(0xa5));
    h
}

#[inline(never)]
fn bench_sha1_update() {
    eprintln!("SHA1::do_update, {MSG_LEN} B");
    let h = black_box(SHA1::new());
    let msg = black_box(message::<MSG_LEN>(0xa5));
    measure(move || {
        let mut h = h;
        let op = black_box(<SHA1 as Hash>::do_update as fn(&mut SHA1, &[u8]));
        op(&mut h, &msg);
        black_box(&h);
    });
}

#[inline(never)]
fn bench_sha1_final() {
    eprintln!("SHA1::do_final_out");
    let h = black_box(sha1_after_data());
    measure(move || {
        let mut out = [0u8; 20];
        let op = black_box(<SHA1 as Hash>::do_final_out as fn(SHA1, &mut [u8]) -> usize);
        let n = op(h, &mut out);
        print!("{:x?}", &out[..n]);
    });
}

#[inline(never)]
fn bench_sha1_final_partial_bits() {
    eprintln!("SHA1::do_final_partial_bits_out");
    let h = black_box(sha1_after_data());
    measure(move || {
        let mut out = [0u8; 20];
        let op = black_box(
            <SHA1 as Hash>::do_final_partial_bits_out
                as fn(SHA1, u8, usize, &mut [u8]) -> Result<usize, _>,
        );
        let n = op(h, 0xa0, 3, &mut out).unwrap();
        print!("{:x?}", &out[..n]);
    });
}

#[inline(never)]
fn bench_sha1_oneshot() {
    eprintln!("SHA1::hash_out, {MSG_LEN} B");
    let msg = black_box(message::<MSG_LEN>(0xa5));
    measure(move || {
        let mut out = [0u8; 20];
        let op = black_box(<SHA1 as HashOneShot>::hash_out as fn(&[u8], &mut [u8]) -> usize);
        let n = op(&msg, &mut out);
        print!("{:x?}", &out[..n]);
    });
}

#[inline(never)]
fn bench_sha1_suspend() {
    eprintln!("SHA1::suspend");
    let h = black_box(sha1_after_data());
    measure(move || {
        let op = black_box(
            <SHA1 as Suspendable<SUSPENDED_SHA1_STATE_LEN>>::suspend
                as fn(SHA1) -> [u8; SUSPENDED_SHA1_STATE_LEN],
        );
        let state = op(h);
        print!("{:x?}", &state[..]);
    });
}

#[inline(never)]
fn bench_sha1_from_suspended() {
    eprintln!("SHA1::from_suspended");
    let state = black_box(sha1_after_data().suspend());
    measure(move || {
        let op = black_box(
            <SHA1 as Suspendable<SUSPENDED_SHA1_STATE_LEN>>::from_suspended
                as fn([u8; SUSPENDED_SHA1_STATE_LEN]) -> Result<SHA1, _>,
        );
        let h = op(state).unwrap();
        black_box(&h);
    });
}

fn main() {
    print_struct_sizes()
    // bench_do_nothing()
    // bench_sha1_update()
    // bench_sha1_final()
    // bench_sha1_final_partial_bits()
    // bench_sha1_oneshot()
    // bench_sha1_suspend()
    // bench_sha1_from_suspended()
}
