//! Stack usage of the RIPEMD entry points, and the in-memory sizes printed by
//! `print_struct_sizes`, the source of the "Memory Usage" tables in the
//! `bouncycastle_digest::ripemd` module docs.
//!
//! As with SM3, a call needs a few hundred bytes, below the floor of the process's own start-up
//! that `bench_aes_mem_usage` describes, so massif cannot see it. The figures in the `ripemd`
//! module docs are read from the compiler the way `bench_ascon_mem_usage` describes:
//! `-C remark=prologepilog` gives each function's frame and `--emit=asm` its calls, after LTO, and
//! a figure is the deepest chain of frames below the entry point plus 8 bytes of return address per
//! call, not following the panic paths. With every bench called from `main`:
//!
//! ```text
//! cargo rustc --release -p mem_usage_benches --bin bench_ripemd_mem_usage -- -C remark=prologepilog --emit=asm
//! ```
//!
//! Each entry point is called through a `black_box`ed function pointer, which gives it an
//! out-of-line body of its own, so the frame being read is the entry point's and not the
//! harness closure's. The inputs are built in `#[inline(never)]` helpers, so their frames are
//! siblings of the operation's.

#![allow(dead_code)]
#![allow(unused_imports)]

use core::hint::black_box;

use bouncycastle::core::direction::Encrypting;
use bouncycastle::core::errors::{KDFError, MACError};
use bouncycastle::core::key_material::{KeyMaterial, KeyMaterial256, KeyMaterialTrait, KeyType};
use bouncycastle::core::symmetric_key::{FromAnyKeyMaterial, MacGenerationKey};
use bouncycastle::core::traits::{Hash, HashOneShot, Suspendable};
use bouncycastle::digest::hkdf::HKDF_RIPEMD160;
use bouncycastle::digest::hmac::HMAC_RIPEMD160;
use bouncycastle::digest::hmac::HmacKey;
use bouncycastle::digest::ripemd::{
    RIPEMD128, RIPEMD160, RIPEMD256, RIPEMD320, SUSPENDED_RIPEMD128_STATE_LEN,
    SUSPENDED_RIPEMD160_STATE_LEN, SUSPENDED_RIPEMD256_STATE_LEN, SUSPENDED_RIPEMD320_STATE_LEN,
};

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

    println!("size_of<RIPEMD128>: {}", size_of::<RIPEMD128>());
    println!("size_of<RIPEMD160>: {}", size_of::<RIPEMD160>());
    println!("size_of<RIPEMD256>: {}", size_of::<RIPEMD256>());
    println!("size_of<RIPEMD320>: {}", size_of::<RIPEMD320>());
    println!("SUSPENDED_RIPEMD128_STATE_LEN: {}", SUSPENDED_RIPEMD128_STATE_LEN);
    println!("SUSPENDED_RIPEMD160_STATE_LEN: {}", SUSPENDED_RIPEMD160_STATE_LEN);
    println!("SUSPENDED_RIPEMD256_STATE_LEN: {}", SUSPENDED_RIPEMD256_STATE_LEN);
    println!("SUSPENDED_RIPEMD320_STATE_LEN: {}", SUSPENDED_RIPEMD320_STATE_LEN);
    println!("size_of<HMAC_RIPEMD160>: {}", size_of::<HMAC_RIPEMD160<'static, Encrypting>>());
    println!("size_of<HmacKey<RIPEMD160>>: {}", size_of::<HmacKey<RIPEMD160>>());
    println!("size_of<HKDF_RIPEMD160>: {}", size_of::<HKDF_RIPEMD160>());
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

#[inline(never)]
fn key() -> KeyMaterial256 {
    KeyMaterial256::from_bytes_as_type(&message::<32>(0x0b), KeyType::MACKey).unwrap()
}

/// The benches of one hash, as a module named for it: `ripemd160::bench_update()` and so on.
/// The four functions share their entry points' shape and differ in the type, its digest length
/// and its suspended-state length.
macro_rules! hash_benches {
    ($module:ident, $hash:ty, $output_len:literal, $state_len:ident) => {
        mod $module {
            use super::*;

            /// A hash that has taken the message, so the final pads a partial block.
            #[inline(never)]
            fn after_data() -> $hash {
                let mut h = <$hash>::new();
                h.do_update(&message::<MSG_LEN>(0xa5));
                h
            }

            #[inline(never)]
            pub(crate) fn bench_update() {
                eprintln!("{}::do_update, {MSG_LEN} B", stringify!($hash));
                let h = black_box(<$hash>::new());
                let msg = black_box(message::<MSG_LEN>(0xa5));
                measure(move || {
                    let mut h = h;
                    let op = black_box(<$hash as Hash>::do_update as fn(&mut $hash, &[u8]));
                    op(&mut h, &msg);
                    black_box(&h);
                });
            }

            #[inline(never)]
            pub(crate) fn bench_final() {
                eprintln!("{}::do_final_out", stringify!($hash));
                let h = black_box(after_data());
                measure(move || {
                    let mut out = [0u8; $output_len];
                    let op =
                        black_box(<$hash as Hash>::do_final_out as fn($hash, &mut [u8]) -> usize);
                    let n = op(h, &mut out);
                    print!("{:x?}", &out[..n]);
                });
            }

            #[inline(never)]
            pub(crate) fn bench_final_partial_bits() {
                eprintln!("{}::do_final_partial_bits_out", stringify!($hash));
                let h = black_box(after_data());
                measure(move || {
                    let mut out = [0u8; $output_len];
                    let op = black_box(
                        <$hash as Hash>::do_final_partial_bits_out
                            as fn($hash, u8, usize, &mut [u8]) -> Result<usize, _>,
                    );
                    let n = op(h, 0xa0, 3, &mut out).unwrap();
                    print!("{:x?}", &out[..n]);
                });
            }

            #[inline(never)]
            pub(crate) fn bench_oneshot() {
                eprintln!("{}::hash_out, {MSG_LEN} B", stringify!($hash));
                let msg = black_box(message::<MSG_LEN>(0xa5));
                measure(move || {
                    let mut out = [0u8; $output_len];
                    let op = black_box(
                        <$hash as HashOneShot>::hash_out as fn(&[u8], &mut [u8]) -> usize,
                    );
                    let n = op(&msg, &mut out);
                    print!("{:x?}", &out[..n]);
                });
            }

            #[inline(never)]
            pub(crate) fn bench_suspend() {
                eprintln!("{}::suspend", stringify!($hash));
                let h = black_box(after_data());
                measure(move || {
                    let op = black_box(
                        <$hash as Suspendable<$state_len>>::suspend
                            as fn($hash) -> [u8; $state_len],
                    );
                    let state = op(h);
                    print!("{:x?}", &state[..]);
                });
            }

            #[inline(never)]
            pub(crate) fn bench_from_suspended() {
                eprintln!("{}::from_suspended", stringify!($hash));
                let state = black_box(after_data().suspend());
                measure(move || {
                    let op = black_box(
                        <$hash as Suspendable<$state_len>>::from_suspended
                            as fn([u8; $state_len]) -> Result<$hash, _>,
                    );
                    let h = op(state).unwrap();
                    black_box(&h);
                });
            }
        }
    };
}

hash_benches!(ripemd128, RIPEMD128, 16, SUSPENDED_RIPEMD128_STATE_LEN);
hash_benches!(ripemd160, RIPEMD160, 20, SUSPENDED_RIPEMD160_STATE_LEN);
hash_benches!(ripemd256, RIPEMD256, 32, SUSPENDED_RIPEMD256_STATE_LEN);
hash_benches!(ripemd320, RIPEMD320, 40, SUSPENDED_RIPEMD320_STATE_LEN);

#[inline(never)]
fn hmac_ripemd160_key() -> HmacKey<RIPEMD160> {
    HmacKey::<RIPEMD160>::from_key_material(&key()).unwrap()
}

#[inline(never)]
fn bench_hmac_ripemd160_key() {
    eprintln!("HmacKey::<RIPEMD160>::from_key_material");
    let key = black_box(key());
    measure(move || {
        let op = black_box(
            <HmacKey<RIPEMD160> as FromAnyKeyMaterial>::from_key_material
                as fn(&dyn KeyMaterialTrait) -> Result<HmacKey<RIPEMD160>, MACError>,
        );
        let k = op(&key).unwrap();
        black_box(&k);
    });
}

#[inline(never)]
fn bench_hmac_ripemd160_mac_out() {
    eprintln!("HmacKey::<RIPEMD160>::mac_out, {MSG_LEN} B");
    let k = black_box(hmac_ripemd160_key());
    let msg = black_box(message::<MSG_LEN>(0xa5));
    measure(move || {
        let mut out = [0u8; 20];
        let op = black_box(
            <HmacKey<RIPEMD160> as MacGenerationKey<20>>::mac_out
                as fn(&HmacKey<RIPEMD160>, &[u8], &mut [u8; 20]) -> usize,
        );
        let n = op(&k, &msg, &mut out);
        print!("{:x?}", &out[..n]);
    });
}

#[inline(never)]
fn bench_hkdf_ripemd160_oneshot() {
    eprintln!("HKDF_RIPEMD160::extract_and_expand_out, 64 B out");
    let salt = black_box(key());
    let ikm = black_box(key());
    let info = black_box(message::<16>(0x5a));
    measure(move || {
        let mut okm = KeyMaterial::<64>::new();
        let op = black_box(
            HKDF_RIPEMD160::extract_and_expand_out
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
    // The same six for ripemd128, ripemd256 and ripemd320:
    // ripemd160::bench_update()
    // ripemd160::bench_final()
    // ripemd160::bench_final_partial_bits()
    // ripemd160::bench_oneshot()
    // ripemd160::bench_suspend()
    // ripemd160::bench_from_suspended()
    // bench_hmac_ripemd160_key()
    // bench_hmac_ripemd160_mac_out()
    // bench_hkdf_ripemd160_oneshot()
}
