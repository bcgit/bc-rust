use bouncycastle_core_interface::key_material::{KeyMaterial0, KeyMaterial256, KeyMaterial512, KeyType};
use bouncycastle_core_interface::traits::{RNG, SecurityStrength};
use bouncycastle_core_test_framework::DUMMY_SEED_512;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use bouncycastle_rng::{HashDRBG_SHA256, HashDRBG_SHA512, Sp80090ADrbg};
use std::hint::black_box;

fn bench_hash_drbg_sha256(c: &mut Criterion) {
    let mut rng = HashDRBG_SHA256::new_unititialized();
    let seed = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[..32], KeyType::Seed).unwrap();
    rng.instantiate(false, seed, &KeyMaterial0::new(), &[], SecurityStrength::_128bit).unwrap();
    do_bench(c, &mut rng, "rng::hash_drbg80090a::HashDRBG_SHA256");
}

fn bench_hash_drbg_sha512(c: &mut Criterion) {
    let mut rng = HashDRBG_SHA512::new_unititialized();
    let seed = KeyMaterial512::from_bytes_as_type(&DUMMY_SEED_512[..64], KeyType::Seed).unwrap();
    rng.instantiate(false, seed, &KeyMaterial0::new(), &[], SecurityStrength::_256bit).unwrap();
    do_bench(c, &mut rng, "rng::hash_drbg80090a::HashDRBG_SHA512");
}

fn do_bench(c: &mut Criterion, rng: &mut impl RNG, test_group_name: &str) {
    let mut data_block = [0_u8; 1024];
    let mut big_data = Vec::new();
    let iters = 16;
    for _ in 0..iters {
        big_data.extend_from_slice(&data_block);
    }

    let mut group = c.benchmark_group(test_group_name);
    group.throughput(Throughput::Bytes(big_data.len() as u64));
    group.bench_function(
        format!("Single invocation of {} output bytes", big_data.len() as u64),
        |b| {
            b.iter(|| {
                rng.next_bytes_out(black_box(&mut big_data[..])).unwrap();
                black_box(&big_data[..]);
            })
        },
    );
    group.finish();

    let mut group = c.benchmark_group(test_group_name);
    group.throughput(Throughput::Bytes(big_data.len() as u64));
    group.bench_function(
        format!("{} invocations of {} output bytes", iters, data_block.len() as u64),
        |b| {
            b.iter(|| {
                for _ in 0..iters {
                    rng.next_bytes_out(black_box(&mut data_block)).unwrap();
                    black_box(&data_block);
                }
            })
        },
    );
    group.finish();
}

criterion_group!(benches, bench_hash_drbg_sha256, bench_hash_drbg_sha512);
criterion_main!(benches);
