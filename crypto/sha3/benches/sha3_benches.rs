use bouncycastle_rng as rng;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
use bouncycastle_core::traits::{Hash, HashOneShot, MAC, RNG, XOF};
use bouncycastle_sha3::kmac::KMAC128;
use bouncycastle_sha3::parallelhash::ParallelHash128;
use bouncycastle_sha3::tuplehash::TupleHash128;
use bouncycastle_sha3::{CSHAKE128, SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256};
use core::num::NonZeroUsize;

fn bench_sha3_224_static(c: &mut Criterion) {
    let mut data_block = [0_u8; 1024];
    let mut digest: [u8; 28] = [0u8; 28];
    rng::DefaultRNG::default().next_bytes_out(&mut data_block).unwrap();

    let mut big_data: Vec<u8> = vec![];
    for _ in 0..16 {
        big_data.extend_from_slice(&data_block);
    }

    let mut group = c.benchmark_group("sha3::SHA3_224");
    group.throughput(Throughput::Bytes(big_data.len() as u64));
    group.bench_function(format!("{} bytes -- ::hashes()", big_data.len() as u64), |b| {
        b.iter(|| {
            SHA3_224::hash_out(black_box(&big_data), &mut digest);
            black_box(&digest);
        })
    });
    group.finish();
}

fn bench_sha3_224_do_update(c: &mut Criterion) {
    let mut data = [0_u8; 1024];
    let mut digest: [u8; 28] = [0u8; 28];
    rng::DefaultRNG::default().next_bytes_out(&mut data).unwrap();

    let mut group = c.benchmark_group("sha3::SHA3_224");
    group.throughput(Throughput::Bytes(16 * data.len() as u64));
    group.bench_function("16 * 1KiB -- .do_update()", |b| {
        b.iter(|| {
            let mut md = SHA3_224::new();
            for _ in 0..16 {
                md.do_update(black_box(&data));
            }
            md.do_final_out(&mut digest);
            black_box(&digest);
        })
    });
    group.finish();
}

fn bench_sha3_256(c: &mut Criterion) {
    let mut data_block = [0_u8; 1024];
    let mut digest: [u8; 32] = [0u8; 32];
    rng::DefaultRNG::default().next_bytes_out(&mut data_block).unwrap();

    let mut big_data: Vec<u8> = vec![];
    for _ in 0..16 {
        big_data.extend_from_slice(&data_block);
    }

    let mut group = c.benchmark_group("sha3::SHA3_256");
    group.throughput(Throughput::Bytes(big_data.len() as u64));
    group.bench_function(format!("{} bytes -- ::hashes()", big_data.len()), |b| {
        b.iter(|| {
            SHA3_256::hash_out(black_box(&big_data), &mut digest);
            black_box(&digest);
        })
    });
    group.finish();
}

fn bench_sha3_384(c: &mut Criterion) {
    let mut data_block = [0_u8; 1024];
    let mut digest: [u8; 48] = [0u8; 48];
    rng::DefaultRNG::default().next_bytes_out(&mut data_block).unwrap();

    let mut big_data: Vec<u8> = vec![];
    for _ in 0..16 {
        big_data.extend_from_slice(&data_block);
    }

    let mut group = c.benchmark_group("sha3::SHA3_384");
    group.throughput(Throughput::Bytes(big_data.len() as u64));
    group.bench_function(format!("{} bytes -- ::hashes()", big_data.len()), |b| {
        b.iter(|| {
            SHA3_384::hash_out(black_box(&big_data), &mut digest);
            black_box(&digest);
        })
    });
    group.finish();
}

fn bench_sha3_512(c: &mut Criterion) {
    let mut data_block = [0_u8; 1024];
    let mut digest: [u8; 64] = [0u8; 64];
    rng::DefaultRNG::default().next_bytes_out(&mut data_block).unwrap();

    let mut big_data: Vec<u8> = vec![];
    for _ in 0..16 {
        big_data.extend_from_slice(&data_block);
    }

    let mut group = c.benchmark_group("sha3::SHA3_512");
    group.throughput(Throughput::Bytes(big_data.len() as u64));
    group.bench_function(format!("{} bytes -- ::hashes()", big_data.len()), |b| {
        b.iter(|| {
            SHA3_512::hash_out(black_box(&big_data), &mut digest);
            black_box(&digest);
        })
    });
    group.finish();
}

fn bench_shake128_64b(c: &mut Criterion) {
    let mut data_block = [0_u8; 1024];
    let mut digest: [u8; 64] = [0u8; 64];
    rng::DefaultRNG::default().next_bytes_out(&mut data_block).unwrap();

    let mut big_data: Vec<u8> = vec![];
    for _ in 0..16 {
        big_data.extend_from_slice(&data_block);
    }

    let mut group = c.benchmark_group("sha3::SHAKE128");
    group.throughput(Throughput::Bytes((big_data.len() as u64) + (digest.len() as u64)));
    group.bench_function(
        format!("input: {} bytes, output: {} bytes -- ::hashes()", big_data.len(), digest.len()),
        |b| {
            b.iter(|| {
                SHAKE128::new().xof_out(black_box(&big_data), &mut digest);
                black_box(&digest);
            })
        },
    );
    group.finish();
}

fn bench_shake128_64k(c: &mut Criterion) {
    let mut data_block = [0_u8; 1024];
    let mut digest: [u8; 64 * 1024] = [0u8; 64 * 1024];
    rng::DefaultRNG::default().next_bytes_out(&mut data_block).unwrap();

    let mut big_data: Vec<u8> = vec![];
    for _ in 0..16 {
        big_data.extend_from_slice(&data_block);
    }

    let mut group = c.benchmark_group("sha3::SHAKE128");
    group.throughput(Throughput::Bytes((big_data.len() as u64) + (digest.len() as u64)));
    group.bench_function(
        format!("input: {} bytes, output: {} bytes -- ::hashes()", big_data.len(), digest.len()),
        |b| {
            b.iter(|| {
                SHAKE128::new().xof_out(black_box(&big_data), &mut digest);
                black_box(&digest);
            })
        },
    );
    group.finish();
}

fn bench_shake256_64b(c: &mut Criterion) {
    let mut data_block = [0_u8; 1024];
    let mut digest: [u8; 64] = [0u8; 64];
    rng::DefaultRNG::default().next_bytes_out(&mut data_block).unwrap();

    let mut big_data: Vec<u8> = vec![];
    for _ in 0..16 {
        big_data.extend_from_slice(&data_block);
    }

    let mut group = c.benchmark_group("sha3::SHAKE256");
    group.throughput(Throughput::Bytes((big_data.len() as u64) + (digest.len() as u64)));
    group.bench_function(
        format!("input: {} bytes, output: {} bytes -- ::hashes()", big_data.len(), digest.len()),
        |b| {
            b.iter(|| {
                SHAKE256::new().xof_out(black_box(&big_data), &mut digest);
                black_box(&digest);
            })
        },
    );
    group.finish();
}

fn bench_shake256_64k(c: &mut Criterion) {
    let mut data_block = [0_u8; 1024];
    let mut digest: [u8; 64 * 1024] = [0u8; 64 * 1024];
    rng::DefaultRNG::default().next_bytes_out(&mut data_block).unwrap();

    let mut big_data: Vec<u8> = vec![];
    for _ in 0..16 {
        big_data.extend_from_slice(&data_block);
    }

    let mut group = c.benchmark_group("sha3::SHAKE256");
    group.throughput(Throughput::Bytes((big_data.len() as u64) + (digest.len() as u64)));
    group.bench_function(
        format!("input: {} bytes, output: {} bytes -- ::hashes()", big_data.len(), digest.len()),
        |b| {
            b.iter(|| {
                SHAKE128::new().xof_out(black_box(&big_data), &mut digest);
                black_box(&digest);
            })
        },
    );
    group.finish();
}

/// 16 KiB of random input, the size the SHA-3 benches use.
fn big_data() -> Vec<u8> {
    let mut data_block = [0_u8; 1024];
    rng::DefaultRNG::default().next_bytes_out(&mut data_block).unwrap();
    data_block.repeat(16)
}

fn bench_cshake128(c: &mut Criterion) {
    let big_data = big_data();
    let mut digest = [0u8; 32];
    let mut group = c.benchmark_group("sha3::CSHAKE128");
    group.throughput(Throughput::Bytes(big_data.len() as u64));
    group.bench_function(format!("{} bytes -- .hash_out()", big_data.len()), |b| {
        b.iter(|| {
            CSHAKE128::new(b"", b"Email Signature").hash_out(black_box(&big_data), &mut digest);
            black_box(&digest);
        })
    });
    group.finish();
}

fn bench_kmac128(c: &mut Criterion) {
    let big_data = big_data();
    let key = KeyMaterial256::from_bytes_as_type(&[0x42u8; 32], KeyType::MACKey).unwrap();
    let mut tag = [0u8; 32];
    let mut group = c.benchmark_group("sha3::KMAC128");
    group.throughput(Throughput::Bytes(big_data.len() as u64));
    group.bench_function(format!("{} bytes -- .mac_out()", big_data.len()), |b| {
        b.iter(|| {
            KMAC128::new(&key).unwrap().mac_out(black_box(&big_data), &mut tag).unwrap();
            black_box(&tag);
        })
    });
    group.finish();
}

fn bench_tuplehash128(c: &mut Criterion) {
    let big_data = big_data();
    // Four 4 KiB elements, so the per-element encoding is in the measurement.
    let tuple: Vec<&[u8]> = big_data.chunks(4096).collect();
    let mut group = c.benchmark_group("sha3::TUPLEHASH128");
    group.throughput(Throughput::Bytes(big_data.len() as u64));
    group.bench_function(format!("{} bytes in 4 elements -- .hash_tuple()", big_data.len()), |b| {
        b.iter(|| {
            black_box(TupleHash128::new(b"", 32).hash_tuple(black_box(&tuple)));
        })
    });
    group.finish();
}

fn bench_parallelhash128(c: &mut Criterion) {
    let big_data = big_data();
    let block_size = NonZeroUsize::new(8192).unwrap();
    let mut digest = [0u8; 32];
    let mut group = c.benchmark_group("sha3::PARALLELHASH128");
    group.throughput(Throughput::Bytes(big_data.len() as u64));
    group.bench_function(format!("{} bytes, B = 8192 -- .hash_out()", big_data.len()), |b| {
        b.iter(|| {
            ParallelHash128::new(block_size, b"", 32).hash_out(black_box(&big_data), &mut digest);
            black_box(&digest);
        })
    });
    group.finish();
}

criterion_group!(
    benches, bench_sha3_224_static, bench_sha3_224_do_update, bench_sha3_256, bench_sha3_384,
    bench_sha3_512, bench_shake128_64b, bench_shake128_64k, bench_shake256_64b, bench_shake256_64k,
    bench_cshake128, bench_kmac128, bench_tuplehash128, bench_parallelhash128
);
criterion_main!(benches);
