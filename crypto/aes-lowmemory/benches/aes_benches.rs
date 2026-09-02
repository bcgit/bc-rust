//! Criterion benchmarks for the bit-sliced AES engine.
//!
//! The comparison that matters here is `encrypt_block` against `encrypt_blocks2` over the same
//! number of bytes. The bit-sliced state holds two blocks, so a single-block call does twice the
//! necessary work; the two-block path should be close to twice the throughput. That ratio is the
//! argument for modes of operation using the two-block entry points wherever their blocks are
//! independent (CTR, and the decrypt direction of CBC and CFB).

use bouncycastle_aes_lowmemory::{Aes128, Aes192, Aes256, BLOCK_LEN};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::RNG;
use bouncycastle_rng as rng;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
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
    let mut group = c.benchmark_group("aes_lowmemory::key expansion");

    let key128 = key::<16>();
    group.bench_function("Aes128::new()", |b| {
        b.iter(|| black_box(Aes128::new(black_box(&key128)).unwrap()))
    });

    let key192 = key::<24>();
    group.bench_function("Aes192::new()", |b| {
        b.iter(|| black_box(Aes192::new(black_box(&key192)).unwrap()))
    });

    let key256 = key::<32>();
    group.bench_function("Aes256::new()", |b| {
        b.iter(|| black_box(Aes256::new(black_box(&key256)).unwrap()))
    });

    group.finish();
}

fn bench_aes128(c: &mut Criterion) {
    let aes = Aes128::new(&key::<16>()).unwrap();
    let blocks = random_blocks();

    let mut group = c.benchmark_group("aes_lowmemory::Aes128");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    group.bench_function("16KiB -- .encrypt_block() x1024", |b| {
        b.iter(|| {
            let mut buf = blocks.clone();
            for block in buf.iter_mut() {
                aes.encrypt_block(black_box(block));
            }
            black_box(&buf);
        })
    });

    group.bench_function("16KiB -- .encrypt_blocks2() x512", |b| {
        b.iter(|| {
            let mut buf = blocks.clone();
            for pair in buf.chunks_exact_mut(2) {
                // `try_into` cannot fail: `chunks_exact_mut(2)` yields slices of length 2.
                let pair: &mut [[u8; BLOCK_LEN]; 2] = pair.try_into().unwrap();
                aes.encrypt_blocks2(black_box(pair));
            }
            black_box(&buf);
        })
    });

    group.bench_function("16KiB -- .decrypt_block() x1024", |b| {
        b.iter(|| {
            let mut buf = blocks.clone();
            for block in buf.iter_mut() {
                aes.decrypt_block(black_box(block));
            }
            black_box(&buf);
        })
    });

    group.bench_function("16KiB -- .decrypt_blocks2() x512", |b| {
        b.iter(|| {
            let mut buf = blocks.clone();
            for pair in buf.chunks_exact_mut(2) {
                let pair: &mut [[u8; BLOCK_LEN]; 2] = pair.try_into().unwrap();
                aes.decrypt_blocks2(black_box(pair));
            }
            black_box(&buf);
        })
    });

    group.finish();
}

fn bench_aes192(c: &mut Criterion) {
    let aes = Aes192::new(&key::<24>()).unwrap();
    let blocks = random_blocks();

    let mut group = c.benchmark_group("aes_lowmemory::Aes192");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    group.bench_function("16KiB -- .encrypt_block() x1024", |b| {
        b.iter(|| {
            let mut buf = blocks.clone();
            for block in buf.iter_mut() {
                aes.encrypt_block(black_box(block));
            }
            black_box(&buf);
        })
    });

    group.bench_function("16KiB -- .encrypt_blocks2() x512", |b| {
        b.iter(|| {
            let mut buf = blocks.clone();
            for pair in buf.chunks_exact_mut(2) {
                let pair: &mut [[u8; BLOCK_LEN]; 2] = pair.try_into().unwrap();
                aes.encrypt_blocks2(black_box(pair));
            }
            black_box(&buf);
        })
    });

    group.finish();
}

fn bench_aes256(c: &mut Criterion) {
    let aes = Aes256::new(&key::<32>()).unwrap();
    let blocks = random_blocks();

    let mut group = c.benchmark_group("aes_lowmemory::Aes256");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    group.bench_function("16KiB -- .encrypt_block() x1024", |b| {
        b.iter(|| {
            let mut buf = blocks.clone();
            for block in buf.iter_mut() {
                aes.encrypt_block(black_box(block));
            }
            black_box(&buf);
        })
    });

    group.bench_function("16KiB -- .encrypt_blocks2() x512", |b| {
        b.iter(|| {
            let mut buf = blocks.clone();
            for pair in buf.chunks_exact_mut(2) {
                let pair: &mut [[u8; BLOCK_LEN]; 2] = pair.try_into().unwrap();
                aes.encrypt_blocks2(black_box(pair));
            }
            black_box(&buf);
        })
    });

    group.bench_function("16KiB -- .decrypt_blocks2() x512", |b| {
        b.iter(|| {
            let mut buf = blocks.clone();
            for pair in buf.chunks_exact_mut(2) {
                let pair: &mut [[u8; BLOCK_LEN]; 2] = pair.try_into().unwrap();
                aes.decrypt_blocks2(black_box(pair));
            }
            black_box(&buf);
        })
    });

    group.finish();
}

criterion_group!(benches, bench_key_expansion, bench_aes128, bench_aes192, bench_aes256);
criterion_main!(benches);
