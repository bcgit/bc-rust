//! Criterion benchmarks for the bit-sliced AES permutation.
//!
//! The comparison that matters here is `encrypt_block` against `encrypt_2blocks` over the same
//! number of bytes. The bit-sliced state holds two blocks, so a single-block call does twice the
//! necessary work; the two-block path should be close to twice the throughput. That ratio is the
//! argument for modes of operation using the two-block entry points wherever their blocks are
//! independent (CTR, and the decrypt direction of CBC and CFB).
//!
//! The data benches work in place on one buffer across iterations, so a `clone` never sits inside
//! the timed closure. The permutation is a bijection, so the buffer stays random whichever
//! direction ran last, and the contents never influence the timing of a constant-time cipher.

use bouncycastle_aes::{AES_128, AES_192, AES_256, BLOCK_LEN};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{ElectronicCodeBook, RNG};
use bouncycastle_rng as rng;
use criterion::measurement::WallTime;
use criterion::{BenchmarkGroup, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

/// 16 KiB of data, i.e. 1024 AES blocks.
const NUM_BLOCKS: usize = 1024;
const DATA_LEN: usize = NUM_BLOCKS * BLOCK_LEN;

fn random_blocks() -> Vec<[u8; BLOCK_LEN]> {
    let mut blocks = vec![[0u8; BLOCK_LEN]; NUM_BLOCKS];
    let mut generator = rng::DefaultRNG::default();
    for block in blocks.iter_mut() {
        generator.next_bytes_out(block).unwrap();
    }
    blocks
}

fn key<const N: usize>() -> KeyMaterial<N> {
    let mut bytes = [0u8; N];
    rng::DefaultRNG::default().next_bytes_out(&mut bytes).unwrap();
    KeyMaterial::<N>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).unwrap()
}

fn bench_key_expansion(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes::key expansion");

    let key128 = key::<16>();
    group.throughput(Throughput::Bytes(16));
    group.bench_function("AES_128::new()", |b| {
        b.iter(|| black_box(AES_128::new(black_box(&key128)).unwrap()))
    });

    let key192 = key::<24>();
    group.throughput(Throughput::Bytes(24));
    group.bench_function("AES_192::new()", |b| {
        b.iter(|| black_box(AES_192::new(black_box(&key192)).unwrap()))
    });

    let key256 = key::<32>();
    group.throughput(Throughput::Bytes(32));
    group.bench_function("AES_256::new()", |b| {
        b.iter(|| black_box(AES_256::new(black_box(&key256)).unwrap()))
    });

    group.finish();
}

/// The four data benches every key length gets: 16 KiB through the one-block and two-block entry
/// points, in each direction.
fn bench_data_paths<const KEY_LEN: usize, C: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    aes: &C,
) {
    let mut blocks = random_blocks();
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    group.bench_function("16KiB -- .encrypt_block() x1024", |b| {
        b.iter(|| {
            for block in blocks.iter_mut() {
                aes.encrypt_block(black_box(block));
            }
            black_box(&blocks);
        })
    });

    group.bench_function("16KiB -- .encrypt_2blocks() x512", |b| {
        b.iter(|| {
            for pair in blocks.chunks_exact_mut(2) {
                // `try_into` cannot fail: `chunks_exact_mut(2)` yields slices of length 2.
                let pair: &mut [[u8; BLOCK_LEN]; 2] = pair.try_into().unwrap();
                aes.encrypt_2blocks(black_box(pair));
            }
            black_box(&blocks);
        })
    });

    group.bench_function("16KiB -- .decrypt_block() x1024", |b| {
        b.iter(|| {
            for block in blocks.iter_mut() {
                aes.decrypt_block(black_box(block));
            }
            black_box(&blocks);
        })
    });

    group.bench_function("16KiB -- .decrypt_2blocks() x512", |b| {
        b.iter(|| {
            for pair in blocks.chunks_exact_mut(2) {
                let pair: &mut [[u8; BLOCK_LEN]; 2] = pair.try_into().unwrap();
                aes.decrypt_2blocks(black_box(pair));
            }
            black_box(&blocks);
        })
    });
}

fn bench_aes128(c: &mut Criterion) {
    let aes = AES_128::new(&key::<16>()).unwrap();
    let mut group = c.benchmark_group("aes::AES_128");
    bench_data_paths(&mut group, &aes);
    group.finish();
}

fn bench_aes192(c: &mut Criterion) {
    let aes = AES_192::new(&key::<24>()).unwrap();
    let mut group = c.benchmark_group("aes::AES_192");
    bench_data_paths(&mut group, &aes);
    group.finish();
}

fn bench_aes256(c: &mut Criterion) {
    let aes = AES_256::new(&key::<32>()).unwrap();
    let mut group = c.benchmark_group("aes::AES_256");
    bench_data_paths(&mut group, &aes);
    group.finish();
}

criterion_group!(benches, bench_key_expansion, bench_aes128, bench_aes192, bench_aes256);
criterion_main!(benches);
