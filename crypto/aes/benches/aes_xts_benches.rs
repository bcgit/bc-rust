//! Criterion benchmarks for XTS-AES: one data unit encrypted and decrypted in place, at both key
//! sizes, for a one-block data unit, a 512-byte and a 4 KiB sector, a 64 KiB data unit, and a
//! 4 KiB one a byte short, whose last two blocks are ciphertext-stolen; and key setup.
//!
//! Given their masks, XTS's blocks are independent, so both directions hand the permutation four
//! blocks at a time and should run at close to ECB's throughput in `aes_modes_benches`. What XTS
//! adds is the encryption of the tweak, once per data unit, and a multiplication by α per block,
//! so the one-block figure is the per-data-unit overhead and the larger ones the per-block cost.
//! Decryption runs the inverse cipher, which is slower than the forward one on the bit-sliced AES.
//!
//! The cipher works in place, so each measurement runs on a fresh copy of the data unit made in
//! criterion's untimed setup (`iter_batched`); the copy is not part of the timing.

use bouncycastle_aes::hazmat::{AES128Internal, AES256Internal};
use bouncycastle_aes::{XTS_AES_128, XTS_AES_256};
use bouncycastle_cipher::modes::XTSKey;
use bouncycastle_core::hazmat::BlockPermutation;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::FromKeyMaterial;
use criterion::measurement::WallTime;
use criterion::{
    BatchSize, BenchmarkGroup, Criterion, Throughput, criterion_group, criterion_main,
};
use std::hint::black_box;

const TWEAK: [u8; 16] = [0x5a; 16];

/// `Key_1 | Key_2`, with distinct, non-zero halves.
fn key<const N: usize>() -> KeyMaterial<N> {
    let bytes: [u8; N] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    KeyMaterial::<N>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).unwrap()
}

/// Encryption and decryption of one `N`-byte data unit, reported as `label`.
fn data_unit<P, const KEY_LEN: usize, const N: usize>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    label: &str,
) where
    P: BlockPermutation<16>,
    XTSKey<P, N>: FromKeyMaterial<KEY_LEN>,
{
    let key = XTSKey::<P, N>::from_key_material(&key::<KEY_LEN>()).unwrap();
    let plaintext: Box<[u8; N]> = (0..N)
        .map(|i| (i as u8).wrapping_mul(31))
        .collect::<Vec<u8>>()
        .into_boxed_slice()
        .try_into()
        .unwrap();
    let mut ciphertext = plaintext.clone();
    key.encrypt_inplace(&TWEAK, &mut ciphertext);

    group.throughput(Throughput::Bytes(N as u64));
    group.bench_function(format!("encrypt {label}"), |b| {
        b.iter_batched(
            || plaintext.clone(),
            |mut unit| {
                key.encrypt_inplace(black_box(&TWEAK), &mut unit);
                black_box(&unit);
            },
            BatchSize::SmallInput,
        )
    });
    group.bench_function(format!("decrypt {label}"), |b| {
        b.iter_batched(
            || ciphertext.clone(),
            |mut unit| {
                key.decrypt_inplace(black_box(&TWEAK), &mut unit);
                black_box(&unit);
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_xts_aes_128(c: &mut Criterion) {
    let mut group = c.benchmark_group("modes::xts::XTS_AES_128");
    data_unit::<AES128Internal, 32, 16>(&mut group, "16B (one block)");
    data_unit::<AES128Internal, 32, 512>(&mut group, "512B sector");
    data_unit::<AES128Internal, 32, 4096>(&mut group, "4KiB sector");
    data_unit::<AES128Internal, 32, 4095>(&mut group, "4095B (ciphertext stealing)");
    data_unit::<AES128Internal, 32, 65536>(&mut group, "64KiB");
    group.finish();
}

fn bench_xts_aes_256(c: &mut Criterion) {
    let mut group = c.benchmark_group("modes::xts::XTS_AES_256");
    data_unit::<AES256Internal, 64, 16>(&mut group, "16B (one block)");
    data_unit::<AES256Internal, 64, 512>(&mut group, "512B sector");
    data_unit::<AES256Internal, 64, 4096>(&mut group, "4KiB sector");
    data_unit::<AES256Internal, 64, 4095>(&mut group, "4095B (ciphertext stealing)");
    data_unit::<AES256Internal, 64, 65536>(&mut group, "64KiB");
    group.finish();
}

/// Key setup: splitting `Key_1 | Key_2` and expanding two AES schedules, paid once per key.
fn bench_xts_init(c: &mut Criterion) {
    let mut group = c.benchmark_group("modes::xts::init");
    let material_128 = key::<32>();
    let material_256 = key::<64>();
    group.bench_function("XTS_AES_128 from_key_material (two key schedules)", |b| {
        b.iter(|| black_box(XTS_AES_128::<4096>::from_key_material(black_box(&material_128))))
    });
    group.bench_function("XTS_AES_256 from_key_material (two key schedules)", |b| {
        b.iter(|| black_box(XTS_AES_256::<4096>::from_key_material(black_box(&material_256))))
    });
    group.finish();
}

criterion_group!(benches, bench_xts_aes_128, bench_xts_aes_256, bench_xts_init);
criterion_main!(benches);
