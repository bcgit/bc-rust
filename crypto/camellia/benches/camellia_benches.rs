//! Criterion benchmarks for the bit-sliced Camellia engine.
//!
//! The comparison that matters is `encrypt_block` against `encrypt_2blocks` and `encrypt_4blocks`
//! over the same number of bytes. The S-box circuit always processes four lanes, so a single-block
//! call does four blocks' worth of work and the four-block path (what the CBC mode's decryption
//! uses) should be close to four times the throughput; the two-block path sits at half. Decryption costs the same as encryption (the same rounds with
//! the subkeys read in the swapped order). Camellia-192
//! and Camellia-256 share the 24-round schedule, so only the 256-bit variant is benchmarked
//! alongside the 18-round Camellia-128.

use bouncycastle_camellia::{BLOCK_LEN, Camellia_128, Camellia_256, LANES};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{ElectronicCodeBook, RNG};
use bouncycastle_rng as rng;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

/// 16 KiB of data, i.e. 1024 Camellia blocks.
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

fn key<const KEY_LEN: usize>() -> KeyMaterial<KEY_LEN> {
    let mut bytes = [0u8; KEY_LEN];
    rng::DefaultRNG::default().next_bytes_out(&mut bytes).unwrap();
    KeyMaterial::<KEY_LEN>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).unwrap()
}

fn bench_key_expansion(c: &mut Criterion) {
    let mut group = c.benchmark_group("camellia::key expansion");

    let key128 = key::<16>();
    group.bench_function("Camellia_128::new()", |b| {
        b.iter(|| black_box(Camellia_128::new(black_box(&key128)).unwrap()))
    });
    let key256 = key::<32>();
    group.bench_function("Camellia_256::new()", |b| {
        b.iter(|| black_box(Camellia_256::new(black_box(&key256)).unwrap()))
    });

    group.finish();
}

fn bench_camellia128(c: &mut Criterion) {
    let camellia = Camellia_128::new(&key::<16>()).unwrap();
    let blocks = random_blocks();

    let mut group = c.benchmark_group("camellia::Camellia_128");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    group.bench_function("16KiB -- .encrypt_block() x1024", |b| {
        b.iter(|| {
            let mut buf = blocks.clone();
            for block in buf.iter_mut() {
                camellia.encrypt_block(black_box(block));
            }
            black_box(&buf);
        })
    });

    group.bench_function("16KiB -- .encrypt_2blocks() x512", |b| {
        b.iter(|| {
            let mut buf = blocks.clone();
            for pair in buf.as_chunks_mut::<2>().0 {
                camellia.encrypt_2blocks(black_box(pair));
            }
            black_box(&buf);
        })
    });

    group.bench_function("16KiB -- .encrypt_4blocks() x256", |b| {
        b.iter(|| {
            let mut buf = blocks.clone();
            for four in buf.as_chunks_mut::<LANES>().0 {
                camellia.encrypt_4blocks(black_box(four));
            }
            black_box(&buf);
        })
    });

    group.bench_function("16KiB -- .decrypt_block() x1024", |b| {
        b.iter(|| {
            let mut buf = blocks.clone();
            for block in buf.iter_mut() {
                camellia.decrypt_block(black_box(block));
            }
            black_box(&buf);
        })
    });

    group.finish();
}

fn bench_camellia256(c: &mut Criterion) {
    let camellia = Camellia_256::new(&key::<32>()).unwrap();
    let blocks = random_blocks();

    let mut group = c.benchmark_group("camellia::Camellia_256");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    group.bench_function("16KiB -- .encrypt_block() x1024", |b| {
        b.iter(|| {
            let mut buf = blocks.clone();
            for block in buf.iter_mut() {
                camellia.encrypt_block(black_box(block));
            }
            black_box(&buf);
        })
    });

    group.bench_function("16KiB -- .encrypt_4blocks() x256", |b| {
        b.iter(|| {
            let mut buf = blocks.clone();
            for four in buf.as_chunks_mut::<LANES>().0 {
                camellia.encrypt_4blocks(black_box(four));
            }
            black_box(&buf);
        })
    });

    group.finish();
}

criterion_group!(benches, bench_key_expansion, bench_camellia128, bench_camellia256);
criterion_main!(benches);
