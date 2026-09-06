//! Criterion benchmarks for the bit-sliced AES engine.

use bouncycastle_aes_lowmemory::{
    AES_128, AES_192, AES_256, AES128Params, AES192Params, AES256Params, AESParams, BLOCK_LEN,
};
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
    group.throughput(Throughput::Bytes(<AES128Params as AESParams>::KEY_LEN as u64));
    group.bench_function("Aes128::new()", |b| {
        b.iter(|| black_box(AES_128::new(black_box(&key128)).unwrap()))
    });

    let key192 = key::<24>();
    group.throughput(Throughput::Bytes(<AES192Params as AESParams>::KEY_LEN as u64));
    group.bench_function("Aes192::new()", |b| {
        b.iter(|| black_box(AES_192::new(black_box(&key192)).unwrap()))
    });

    let key256 = key::<32>();
    group.throughput(Throughput::Bytes(<AES256Params as AESParams>::KEY_LEN as u64));
    group.bench_function("Aes256::new()", |b| {
        b.iter(|| black_box(AES_256::new(black_box(&key256)).unwrap()))
    });

    group.finish();
}

fn bench_aes128(c: &mut Criterion) {
    let aes = AES_128::new(&key::<16>()).unwrap();
    let mut blocks = random_blocks();

    let mut group = c.benchmark_group("aes_lowmemory::Aes128");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    group.bench_function("16KiB -- .encrypt_block() x1024", |b| {
        b.iter(|| {
            // So that we're not making copies within the measured loop, we'll just
            // encrypt the ciphertext over and over again.
            for block in blocks.iter_mut() {
                aes.encrypt_block(black_box(block));
            }
            black_box(&blocks);
        })
    });

    group.bench_function("16KiB -- .encrypt_blocks2() x512", |b| {
        b.iter(|| {
            let mut buf = blocks.clone();
            for pair in buf.chunks_exact_mut(2) {
                // `try_into` cannot fail: `chunks_exact_mut(2)` yields slices of length 2.
                let pair: &mut [[u8; BLOCK_LEN]; 2] = pair.try_into().unwrap();
                aes.encrypt_2blocks(black_box(pair));
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
                aes.decrypt_2blocks(black_box(pair));
            }
            black_box(&buf);
        })
    });

    group.finish();
}

fn bench_aes192(c: &mut Criterion) {
    let aes = AES_192::new(&key::<24>()).unwrap();
    let mut blocks = random_blocks();

    let mut group = c.benchmark_group("aes_lowmemory::Aes192");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    group.bench_function("16KiB -- .encrypt_block() x1024", |b| {
        b.iter(|| {
            // So that we're not making copies within the measured loop, we'll just
            // encrypt the ciphertext over and over again.
            for block in blocks.iter_mut() {
                aes.encrypt_block(black_box(block));
            }
            black_box(&blocks);
        })
    });

    group.bench_function("16KiB -- .encrypt_blocks2() x512", |b| {
        b.iter(|| {
            let mut buf = blocks.clone();
            for pair in buf.chunks_exact_mut(2) {
                let pair: &mut [[u8; BLOCK_LEN]; 2] = pair.try_into().unwrap();
                aes.encrypt_2blocks(black_box(pair));
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
                aes.decrypt_2blocks(black_box(pair));
            }
            black_box(&buf);
        })
    });

    group.finish();
}

fn bench_aes256(c: &mut Criterion) {
    let aes = AES_256::new(&key::<32>()).unwrap();
    let mut blocks = random_blocks();

    let mut group = c.benchmark_group("aes_lowmemory::Aes256");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    group.bench_function("16KiB -- .encrypt_block() x1024", |b| {
        b.iter(|| {
            for block in blocks.iter_mut() {
                aes.encrypt_block(black_box(block));
            }
            black_box(&blocks);
        })
    });

    group.bench_function("16KiB -- .encrypt_blocks2() x512", |b| {
        b.iter(|| {
            let mut buf = blocks.clone();
            for pair in buf.chunks_exact_mut(2) {
                let pair: &mut [[u8; BLOCK_LEN]; 2] = pair.try_into().unwrap();
                aes.encrypt_2blocks(black_box(pair));
            }
            black_box(&buf);
        })
    });

    group.bench_function("16KiB -- .decrypt_blocks2() x512", |b| {
        b.iter(|| {
            let mut buf = blocks.clone();
            for pair in buf.chunks_exact_mut(2) {
                let pair: &mut [[u8; BLOCK_LEN]; 2] = pair.try_into().unwrap();
                aes.decrypt_2blocks(black_box(pair));
            }
            black_box(&buf);
        })
    });

    group.finish();
}

criterion_group!(benches, bench_key_expansion, bench_aes128, bench_aes192, bench_aes256);
criterion_main!(benches);
