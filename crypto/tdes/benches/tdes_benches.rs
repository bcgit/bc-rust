//! Criterion benchmarks for the constant-time TDES engine.
//!
//! The permutation processes one block per call and its pair and four-block entry points are
//! single-block loops, so the figures to watch are the single-block throughput in each direction
//! and the cost of key expansion. The `encrypt_4blocks` case is included to confirm that the
//! four-block path costs the same as four single-block calls, i.e. that nothing is lost by a mode
//! preferring it.

use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{ElectronicCodeBook, RNG};
use bouncycastle_rng as rng;
use bouncycastle_tdes::{BLOCK_LEN, KEY_LEN, TDES};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

/// 16 KiB of data, i.e. 2048 TDES blocks.
const NUM_BLOCKS: usize = 2048;
const DATA_LEN: usize = NUM_BLOCKS * BLOCK_LEN;

fn random_blocks() -> Vec<[u8; BLOCK_LEN]> {
    let mut blocks = vec![[0u8; BLOCK_LEN]; NUM_BLOCKS];
    let mut generator = rng::DefaultRNG::default();
    for block in blocks.iter_mut() {
        generator.next_bytes_out(block).unwrap();
    }
    blocks
}

/// A random key bundle. Three random 8-byte keys are distinct and non-weak with overwhelming
/// probability; the loop covers the remainder.
fn key() -> KeyMaterial<KEY_LEN> {
    let mut generator = rng::DefaultRNG::default();
    loop {
        let mut bytes = [0u8; KEY_LEN];
        generator.next_bytes_out(&mut bytes).unwrap();
        let key = KeyMaterial::<KEY_LEN>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey)
            .unwrap();
        if TDES::new(&key).is_ok() {
            return key;
        }
    }
}

fn bench_key_expansion(c: &mut Criterion) {
    let mut group = c.benchmark_group("tdes::key expansion");
    let key = key();
    group.bench_function("TDES::new()", |b| {
        b.iter(|| black_box(TDES::new(black_box(&key)).unwrap()))
    });
    group.finish();
}

fn bench_tdes(c: &mut Criterion) {
    let tdes = TDES::new(&key()).unwrap();
    let blocks = random_blocks();

    let mut group = c.benchmark_group("tdes::TDES");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    group.bench_function("16KiB -- .encrypt_block() x2048", |b| {
        b.iter(|| {
            let mut buf = blocks.clone();
            for block in buf.iter_mut() {
                tdes.encrypt_block(black_box(block));
            }
            black_box(&buf);
        })
    });

    group.bench_function("16KiB -- .decrypt_block() x2048", |b| {
        b.iter(|| {
            let mut buf = blocks.clone();
            for block in buf.iter_mut() {
                tdes.decrypt_block(black_box(block));
            }
            black_box(&buf);
        })
    });

    group.bench_function("16KiB -- .encrypt_4blocks() x512", |b| {
        b.iter(|| {
            let mut buf = blocks.clone();
            for four in buf.as_chunks_mut::<4>().0 {
                tdes.encrypt_4blocks(black_box(four));
            }
            black_box(&buf);
        })
    });

    group.finish();
}

criterion_group!(benches, bench_key_expansion, bench_tdes);
criterion_main!(benches);
