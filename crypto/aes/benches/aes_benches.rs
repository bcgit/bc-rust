//! Criterion benchmarks for the AES block cipher engine.
//!
//! There are three things worth measuring separately, because they have genuinely different
//! performance characteristics:
//!
//! * `KeyExpansion` -- [`AES::new`], ie FIPS 197 Algorithm 2. Paid once per key.
//! * `EncryptBlock` -- CIPHER(), Algorithm 1. Paid once per block.
//! * `DecryptBlock` -- INVCIPHER(), Algorithm 3. Slower than encryption, because INVMIXCOLUMNS()
//!   multiplies by {09}, {0b}, {0d} and {0e} rather than MIXCOLUMNS()'s {02} and {03}.
//!
//! The one-shot APIs ([`AES::encrypt_single_block`] and friends) are deliberately not benchmarked
//! separately: they are a key expansion plus a block operation over the same implementation, so
//! their cost is the sum of the two benchmarks above.
//!
//! The block benchmarks run a fixed number of blocks per iteration and report throughput in bytes,
//! so the numbers are directly comparable with the other symmetric primitives in the library, and
//! so that the per-call overhead of criterion does not dominate a ~10ns operation.

use bouncycastle_aes::{
    AES_BLOCK_LEN, AES128, AES128_KEY_LEN, AES128Key, AES192, AES192_KEY_LEN, AES192Key, AES256,
    AES256_KEY_LEN, AES256Key, AESEngine,
};
use bouncycastle_core::key_material::KeyType;
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

/// How many blocks each block-level benchmark iteration processes.
const NUM_BLOCKS: usize = 256;

/// Builds the set of blocks to process. Each block differs from the others so that the CPU cannot
/// cache or branch-predict its way to an unrealistically good result.
fn make_blocks() -> [[u8; AES_BLOCK_LEN]; NUM_BLOCKS] {
    let mut blocks = [[0u8; AES_BLOCK_LEN]; NUM_BLOCKS];
    for (i, block) in blocks.iter_mut().enumerate() {
        for (j, byte) in block.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(31).wrapping_add(j as u8);
        }
    }
    blocks
}

/// The FIPS 197 Appendix A keys, so the benchmarks are keyed with the same material as the tests.
fn keys() -> (AES128Key, AES192Key, AES256Key) {
    const KEY_BYTES: [u8; AES256_KEY_LEN] = [
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77,
        0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14,
        0xdf, 0xf4,
    ];

    let key128 =
        AES128Key::from_bytes_as_type(&KEY_BYTES[..AES128_KEY_LEN], KeyType::SymmetricCipherKey)
            .unwrap();
    let key192 =
        AES192Key::from_bytes_as_type(&KEY_BYTES[..AES192_KEY_LEN], KeyType::SymmetricCipherKey)
            .unwrap();
    let key256 = AES256Key::from_bytes_as_type(&KEY_BYTES, KeyType::SymmetricCipherKey).unwrap();

    (key128, key192, key256)
}

fn bench_key_expansion(c: &mut Criterion) {
    let mut group = c.benchmark_group("KeyExpansion");
    let (key128, key192, key256) = keys();

    group.throughput(criterion::Throughput::Elements(1));

    group.bench_function("AES-128", |b| b.iter(|| black_box(AES128::new(&key128)).unwrap()));
    group.bench_function("AES-192", |b| b.iter(|| black_box(AES192::new(&key192)).unwrap()));
    group.bench_function("AES-256", |b| b.iter(|| black_box(AES256::new(&key256)).unwrap()));

    group.finish();
}

fn bench_encrypt_block(c: &mut Criterion) {
    let mut group = c.benchmark_group("EncryptBlock");
    let (key128, key192, key256) = keys();
    let blocks = make_blocks();

    // Key expansion happens outside the timing loop: this measures CIPHER() only.
    let aes128 = AES128::new(&key128).unwrap();
    let aes192 = AES192::new(&key192).unwrap();
    let aes256 = AES256::new(&key256).unwrap();

    group.throughput(criterion::Throughput::Bytes((NUM_BLOCKS * AES_BLOCK_LEN) as u64));

    group.bench_function("AES-128", |b| {
        b.iter(|| {
            for block in blocks.iter() {
                black_box(aes128.encrypt_block(block));
            }
        })
    });

    group.bench_function("AES-192", |b| {
        b.iter(|| {
            for block in blocks.iter() {
                black_box(aes192.encrypt_block(block));
            }
        })
    });

    group.bench_function("AES-256", |b| {
        b.iter(|| {
            for block in blocks.iter() {
                black_box(aes256.encrypt_block(block));
            }
        })
    });

    group.finish();
}

fn bench_decrypt_block(c: &mut Criterion) {
    let mut group = c.benchmark_group("DecryptBlock");
    let (key128, key192, key256) = keys();
    let blocks = make_blocks();

    let aes128 = AES128::new(&key128).unwrap();
    let aes192 = AES192::new(&key192).unwrap();
    let aes256 = AES256::new(&key256).unwrap();

    group.throughput(criterion::Throughput::Bytes((NUM_BLOCKS * AES_BLOCK_LEN) as u64));

    group.bench_function("AES-128", |b| {
        b.iter(|| {
            for block in blocks.iter() {
                black_box(aes128.decrypt_block(block));
            }
        })
    });

    group.bench_function("AES-192", |b| {
        b.iter(|| {
            for block in blocks.iter() {
                black_box(aes192.decrypt_block(block));
            }
        })
    });

    group.bench_function("AES-256", |b| {
        b.iter(|| {
            for block in blocks.iter() {
                black_box(aes256.decrypt_block(block));
            }
        })
    });

    group.finish();
}

criterion_group!(benches, bench_key_expansion, bench_encrypt_block, bench_decrypt_block);
criterion_main!(benches);
