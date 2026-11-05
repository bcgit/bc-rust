//! A single run of one Poly1305 entry point, so that its stack usage can be read. Build in release
//! mode.
//!
//! The figures in the crate docs are read from the compiler as `bench_ascon_mem_usage` and
//! `bench_chacha20_mem_usage` describe: the deepest chain of frames below each `measure` closure
//! after LTO, from `-C remark=prologepilog` and the disassembly, plus 8 bytes of return address
//! per call, x86-64 Linux, with the panic paths not followed.
//!
//! ```text
//! RUSTFLAGS="-C remark=prologepilog" cargo build --release -p mem_usage_benches --bin bench_poly1305_mem_usage 2> remarks.txt
//! ```
//!
//! Each entry point is called through a `black_box`ed function pointer, so its body is its own
//! and not the closure's; the key, the worker and the input are built in `#[inline(never)]`
//! helpers. `main` controls which bench runs; measure one at a time.

#![allow(dead_code)]

use core::hint::black_box;

use bouncycastle::core::errors::MACError;
use bouncycastle::core::traits::MAC;
use bouncycastle::poly1305::hazmat::key_from_bytes;
use bouncycastle::poly1305::{KEY_LEN, Poly1305, Poly1305Key, TAG_LEN};

/// Six whole 16-byte blocks and a partial one.
const MSG_LEN: usize = 100;

const KEY: [u8; KEY_LEN] = [0x42; KEY_LEN];

/// Prints the in-memory size of each value a caller holds between calls.
#[inline(never)]
fn print_struct_sizes() {
    use core::mem::size_of;
    println!("size_of<Poly1305Key>: {}", size_of::<Poly1305Key>());
    println!("size_of<Poly1305>: {}", size_of::<Poly1305>());
}

/// Runs the operation in its own frame. Returns nothing, so no result crosses the boundary.
#[inline(never)]
fn measure(f: impl FnOnce()) {
    f()
}

/// A message filled at run time, so that its contents are not a constant the compiler could fold
/// the computation over.
#[inline(never)]
fn message<const N: usize>(fill: u8) -> [u8; N] {
    let mut m = [0u8; N];
    m.fill(black_box(fill));
    m
}

#[inline(never)]
fn key() -> Poly1305Key {
    key_from_bytes(&message::<KEY_LEN>(KEY[0]))
}

/// A worker that has taken the message, so the final pads a partial block.
#[inline(never)]
fn worker_after_data() -> Poly1305 {
    let mut mac = key().into_mac();
    mac.do_update(&message::<MSG_LEN>(0xa5));
    mac
}

/// The clamp and split of the one-time key.
#[inline(never)]
fn bench_key_from_bytes() {
    eprintln!("hazmat::key_from_bytes");
    let bytes = black_box(message::<KEY_LEN>(KEY[0]));
    measure(move || {
        let op = black_box(key_from_bytes as fn(&[u8; KEY_LEN]) -> Poly1305Key);
        let key = op(&bytes);
        black_box(&key);
    });
}

#[inline(never)]
fn bench_into_mac() {
    eprintln!("Poly1305Key::into_mac");
    let key = black_box(key());
    measure(move || {
        let op = black_box(Poly1305Key::into_mac as fn(Poly1305Key) -> Poly1305);
        let mac = op(key);
        black_box(&mac);
    });
}

#[inline(never)]
fn bench_do_update() {
    eprintln!("Poly1305::do_update, {MSG_LEN} B");
    let mac = black_box(key().into_mac());
    let data = black_box(message::<MSG_LEN>(0xa5));
    measure(move || {
        let mut mac = mac;
        let op = black_box(<Poly1305 as MAC>::do_update as fn(&mut Poly1305, &[u8]));
        op(&mut mac, &data);
        black_box(&mac);
    });
}

/// The last partial block, the final reduction and the addition of `s`.
#[inline(never)]
fn bench_do_final_out() {
    eprintln!("Poly1305::do_final_out");
    let mac = black_box(worker_after_data());
    measure(move || {
        let mut tag = [0u8; TAG_LEN];
        let op = black_box(
            <Poly1305 as MAC>::do_final_out as fn(Poly1305, &mut [u8]) -> Result<usize, MACError>,
        );
        let n = op(mac, &mut tag).unwrap();
        print!("{:x?}", &tag[..n]);
    });
}

#[inline(never)]
fn bench_do_verify_final() {
    eprintln!("Poly1305::do_verify_final");
    let mac = black_box(worker_after_data());
    let tag = black_box(message::<TAG_LEN>(0x3c));
    measure(move || {
        let op = black_box(<Poly1305 as MAC>::do_verify_final as fn(Poly1305, &[u8]) -> bool);
        print!("{}", op(mac, &tag));
    });
}

/// The one-shot: the whole message and the final in one call.
#[inline(never)]
fn bench_mac_out() {
    eprintln!("Poly1305::mac_out, {MSG_LEN} B");
    let mac = black_box(key().into_mac());
    let data = black_box(message::<MSG_LEN>(0xa5));
    measure(move || {
        let mut tag = [0u8; TAG_LEN];
        let op = black_box(
            <Poly1305 as MAC>::mac_out as fn(Poly1305, &[u8], &mut [u8]) -> Result<usize, MACError>,
        );
        let n = op(mac, &data, &mut tag).unwrap();
        print!("{:x?}", &tag[..n]);
    });
}

fn main() {
    print_struct_sizes()
    // bench_key_from_bytes()
    // bench_into_mac()
    // bench_do_update()
    // bench_do_final_out()
    // bench_do_verify_final()
    // bench_mac_out()
}
