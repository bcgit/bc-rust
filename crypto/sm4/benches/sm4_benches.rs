//! Criterion benchmarks for the bit-sliced SM4 engine.
//!
//! The comparison that matters is `encrypt_block` against `encrypt_2blocks` and `encrypt_4blocks`
//! over the same number of bytes. The S-box circuit always processes four lanes, so a single-block
//! call does four blocks' worth of work and the four-block path (what the CBC mode's decryption
//! uses) should be close to four times the throughput; the two-block path sits at half. Decryption
//! costs the same as encryption (the same loop with the round keys read backwards).

use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::RNG;
use bouncycastle_rng as rng;
use bouncycastle_sm4::{BLOCK_LEN, KEY_LEN, LANES, SM4};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

/// 16 KiB of data, i.e. 1024 SM4 blocks.
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

fn key() -> KeyMaterial<KEY_LEN> {
    let mut bytes = [0u8; KEY_LEN];
    rng::DefaultRNG::default().next_bytes_out(&mut bytes).unwrap();
    KeyMaterial::<KEY_LEN>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).unwrap()
}

fn bench_key_expansion(c: &mut Criterion) {
    let mut group = c.benchmark_group("sm4::key expansion");

    let key = key();
    group
        .bench_function("SM4::new()", |b| b.iter(|| black_box(SM4::new(black_box(&key)).unwrap())));

    group.finish();
}

fn bench_sm4(c: &mut Criterion) {
    let sm4 = SM4::new(&key()).unwrap();
    let blocks = random_blocks();

    let mut group = c.benchmark_group("sm4::SM4");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    group.bench_function("16KiB -- .encrypt_block() x1024", |b| {
        b.iter(|| {
            let mut buf = blocks.clone();
            for block in buf.iter_mut() {
                sm4.encrypt_block(black_box(block));
            }
            black_box(&buf);
        })
    });

    group.bench_function("16KiB -- .encrypt_2blocks() x512", |b| {
        b.iter(|| {
            let mut buf = blocks.clone();
            for pair in buf.as_chunks_mut::<2>().0 {
                sm4.encrypt_2blocks(black_box(pair));
            }
            black_box(&buf);
        })
    });

    group.bench_function("16KiB -- .encrypt_4blocks() x256", |b| {
        b.iter(|| {
            let mut buf = blocks.clone();
            for four in buf.as_chunks_mut::<LANES>().0 {
                sm4.encrypt_4blocks(black_box(four));
            }
            black_box(&buf);
        })
    });

    group.bench_function("16KiB -- .decrypt_block() x1024", |b| {
        b.iter(|| {
            let mut buf = blocks.clone();
            for block in buf.iter_mut() {
                sm4.decrypt_block(black_box(block));
            }
            black_box(&buf);
        })
    });

    group.finish();
}

criterion_group!(benches, bench_key_expansion, bench_sm4);
criterion_main!(benches);
