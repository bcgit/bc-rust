use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use bouncycastle_rng as rng;
use std::hint::black_box;

use bouncycastle_core_interface::traits::{Hash, RNG, XOF};
use bouncycastle_sha3::{SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256};

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
            SHA3_224::new().hash_out(black_box(&big_data), &mut digest);
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
            SHA3_256::new().hash_out(black_box(&big_data), &mut digest);
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
            SHA3_384::new().hash_out(black_box(&big_data), &mut digest);
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
            SHA3_512::new().hash_out(black_box(&big_data), &mut digest);
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
                SHAKE128::new().hash_xof_out(black_box(&big_data), &mut digest);
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
                SHAKE128::new().hash_xof_out(black_box(&big_data), &mut digest);
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
                SHAKE256::new().hash_xof_out(black_box(&big_data), &mut digest);
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
                SHAKE128::new().hash_xof_out(black_box(&big_data), &mut digest);
                black_box(&digest);
            })
        },
    );
    group.finish();
}

criterion_group!(
    benches, bench_sha3_224_static, bench_sha3_224_do_update, bench_sha3_256, bench_sha3_384,
    bench_sha3_512, bench_shake128_64b, bench_shake128_64k, bench_shake256_64b, bench_shake256_64k
);
criterion_main!(benches);
