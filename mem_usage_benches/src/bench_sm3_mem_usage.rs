//! Stack usage of the SM3 entry points, and the in-memory sizes printed by `print_struct_sizes`,
//! the source of the "Memory Usage" tables in the bouncycastle-sm3 crate docs.
//!
//! As with Ascon, a call needs a few hundred bytes, below the floor of the process's own start-up
//! that `bench_aes_mem_usage` describes, so massif cannot see it. The figures in the crate docs
//! are read from the compiler the way `bench_ascon_mem_usage` describes: `-C remark=prologepilog`
//! gives each function's frame and `--emit=asm` its calls, after LTO, and a figure is the deepest
//! chain of frames below the entry point plus 8 bytes of return address per call, not following
//! the panic paths. With every bench called from `main`:
//!
//! ```text
//! cargo rustc --release -p mem_usage_benches --bin bench_sm3_mem_usage -- -C remark=prologepilog --emit=asm
//! ```
//!
//! Each entry point is called through a `black_box`ed function pointer, which gives it an
//! out-of-line body of its own, so the frame being read is the entry point's and not the
//! harness closure's. The inputs are built in `#[inline(never)]` helpers, so their frames are
//! siblings of the operation's.

#![allow(dead_code)]
#![allow(unused_imports)]

use core::hint::black_box;

use bouncycastle::core::errors::{KDFError, MACError};
use bouncycastle::core::key_material::{KeyMaterial, KeyMaterial256, KeyMaterialTrait, KeyType};
use bouncycastle::core::symmetric_key::{FromAnyKeyMaterial, MacGenerationKey};
use bouncycastle::core::traits::{Hash, HashOneShot, MAC, Suspendable};
use bouncycastle::hmac::HmacKey;
use bouncycastle::sm3::hkdf::HKDF_SM3;
use bouncycastle::sm3::hmac::HMAC_SM3;
use bouncycastle::sm3::{SM3, SUSPENDED_SM3_STATE_LEN};

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

    println!("size_of<SM3>: {}", size_of::<SM3>());
    println!("SUSPENDED_SM3_STATE_LEN: {}", SUSPENDED_SM3_STATE_LEN);
    println!("size_of<HMAC_SM3>: {}", size_of::<HMAC_SM3<'static>>());
    println!("size_of<HmacKey<SM3>>: {}", size_of::<HmacKey<SM3>>());
    println!("size_of<HKDF_SM3>: {}", size_of::<HKDF_SM3>());
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

/// An SM3 that has taken the message, so the final pads a partial block.
#[inline(never)]
fn sm3_after_data() -> SM3 {
    let mut h = SM3::new();
    h.do_update(&message::<MSG_LEN>(0xa5));
    h
}

#[inline(never)]
fn key() -> KeyMaterial256 {
    KeyMaterial256::from_bytes_as_type(&message::<32>(0x0b), KeyType::MACKey).unwrap()
}

// ---- SM3 ----------------------------------------------------------------------------------

#[inline(never)]
fn bench_sm3_update() {
    eprintln!("SM3::do_update, {MSG_LEN} B");
    let h = black_box(SM3::new());
    let msg = black_box(message::<MSG_LEN>(0xa5));
    measure(move || {
        let mut h = h;
        let op = black_box(<SM3 as Hash>::do_update as fn(&mut SM3, &[u8]));
        op(&mut h, &msg);
        black_box(&h);
    });
}

#[inline(never)]
fn bench_sm3_final() {
    eprintln!("SM3::do_final_out");
    let h = black_box(sm3_after_data());
    measure(move || {
        let mut out = [0u8; 32];
        let op = black_box(<SM3 as Hash>::do_final_out as fn(SM3, &mut [u8]) -> usize);
        let n = op(h, &mut out);
        print!("{:x?}", &out[..n]);
    });
}

#[inline(never)]
fn bench_sm3_final_partial_bits() {
    eprintln!("SM3::do_final_partial_bits_out");
    let h = black_box(sm3_after_data());
    measure(move || {
        let mut out = [0u8; 32];
        let op = black_box(
            <SM3 as Hash>::do_final_partial_bits_out
                as fn(SM3, u8, usize, &mut [u8]) -> Result<usize, _>,
        );
        let n = op(h, 0xa0, 3, &mut out).unwrap();
        print!("{:x?}", &out[..n]);
    });
}

#[inline(never)]
fn bench_sm3_oneshot() {
    eprintln!("SM3::hash_out, {MSG_LEN} B");
    let msg = black_box(message::<MSG_LEN>(0xa5));
    measure(move || {
        let mut out = [0u8; 32];
        let op = black_box(<SM3 as HashOneShot>::hash_out as fn(&[u8], &mut [u8]) -> usize);
        let n = op(&msg, &mut out);
        print!("{:x?}", &out[..n]);
    });
}

#[inline(never)]
fn bench_sm3_suspend() {
    eprintln!("SM3::suspend");
    let h = black_box(sm3_after_data());
    measure(move || {
        let op = black_box(
            <SM3 as Suspendable<SUSPENDED_SM3_STATE_LEN>>::suspend
                as fn(SM3) -> [u8; SUSPENDED_SM3_STATE_LEN],
        );
        let state = op(h);
        print!("{:x?}", &state[..]);
    });
}

#[inline(never)]
fn bench_sm3_from_suspended() {
    eprintln!("SM3::from_suspended");
    let state = black_box(sm3_after_data().suspend());
    measure(move || {
        let op = black_box(
            <SM3 as Suspendable<SUSPENDED_SM3_STATE_LEN>>::from_suspended
                as fn([u8; SUSPENDED_SM3_STATE_LEN]) -> Result<SM3, _>,
        );
        let h = op(state).unwrap();
        black_box(&h);
    });
}

// ---- HMAC-SM3 and HKDF-SM3 ----------------------------------------------------------------

#[inline(never)]
fn hmac_sm3_key() -> HmacKey<SM3> {
    HmacKey::<SM3>::from_key_material(&key()).unwrap()
}

#[inline(never)]
fn bench_hmac_sm3_key() {
    eprintln!("HmacKey::<SM3>::from_key_material");
    let key = black_box(key());
    measure(move || {
        let op = black_box(
            <HmacKey<SM3> as FromAnyKeyMaterial>::from_key_material
                as fn(&dyn KeyMaterialTrait) -> Result<HmacKey<SM3>, MACError>,
        );
        let k = op(&key).unwrap();
        black_box(&k);
    });
}

#[inline(never)]
fn bench_hmac_sm3_mac_out() {
    eprintln!("HmacKey::<SM3>::mac_out, {MSG_LEN} B");
    let k = black_box(hmac_sm3_key());
    let msg = black_box(message::<MSG_LEN>(0xa5));
    measure(move || {
        let mut out = [0u8; 32];
        let op = black_box(
            <HmacKey<SM3> as MacGenerationKey>::mac_out
                as fn(&HmacKey<SM3>, &[u8], &mut [u8]) -> Result<usize, MACError>,
        );
        let n = op(&k, &msg, &mut out).unwrap();
        print!("{:x?}", &out[..n]);
    });
}

#[inline(never)]
fn bench_hkdf_sm3_oneshot() {
    eprintln!("HKDF_SM3::extract_and_expand_out, 64 B out");
    let salt = black_box(key());
    let ikm = black_box(key());
    let info = black_box(message::<16>(0x5a));
    measure(move || {
        let mut okm = KeyMaterial::<64>::new();
        let op = black_box(
            HKDF_SM3::extract_and_expand_out
                as fn(
                    &KeyMaterial256,
                    &KeyMaterial256,
                    &[u8],
                    usize,
                    &mut KeyMaterial<64>,
                ) -> Result<usize, KDFError>,
        );
        let n = op(&salt, &ikm, &info, 64, &mut okm).unwrap();
        black_box((n, &okm));
    });
}

fn main() {
    print_struct_sizes()
    // bench_do_nothing()
    // bench_sm3_update()
    // bench_sm3_final()
    // bench_sm3_final_partial_bits()
    // bench_sm3_oneshot()
    // bench_sm3_suspend()
    // bench_sm3_from_suspended()
    // bench_hmac_sm3_key()
    // bench_hmac_sm3_mac_out()
    // bench_hkdf_sm3_oneshot()
}
