use std::hint::black_box;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use bouncycastle_rng as rng;
use bouncycastle_core_interface::key_material::{KeyMaterial256, KeyMaterial512, KeyMaterialInternal, KeyType};
use bouncycastle_core_interface::traits::{KeyMaterial, RNG};
use bouncycastle_hkdf::{HKDF_SHA256, HKDF_SHA512};

fn bench_hkdf_sha256(c: &mut Criterion) {
    let mut data_block = [0_u8; 1024];
    let mut output = KeyMaterial256::new();
    rng::DefaultRNG::default().next_bytes_out(&mut data_block).unwrap();

    let key = KeyMaterial256::from_bytes_as_type(&data_block[..32], KeyType::MACKey).unwrap();

    let mut big_data: Vec<u8> = vec![];
    for _ in 0..100 {
        big_data.extend_from_slice(&data_block);
    }

    let mut group = c.benchmark_group("HKDF_SHA256::do_extract_update_key");
    group.throughput(Throughput::Bytes(key.key_len() as u64));
    group.bench_function(format!("{} bytes of IKM data", big_data.len() as u64), |b| {
        let mut hkdf = HKDF_SHA256::default();
        hkdf.do_extract_init(&key).unwrap();
        b.iter(|| {
            let bytes_written = hkdf.do_extract_update_key(&key).unwrap();
            black_box(&bytes_written);
        });
        hkdf.do_extract_final_out(&mut output).unwrap();
        black_box(&output);
    });
    group.finish();

    let mut group = c.benchmark_group("HKDF_SHA256::do_extract_update_bytes");
    group.throughput(Throughput::Bytes(big_data.len() as u64));
    group.bench_function(format!("{} bytes of IKM data", big_data.len() as u64), |b| {
        let mut hkdf = HKDF_SHA256::default();
        hkdf.do_extract_init(&key).unwrap();
        b.iter(|| {
            let bytes_written = hkdf.do_extract_update_bytes(black_box(&big_data)).unwrap();
            black_box(&bytes_written);
        });
        hkdf.do_extract_final_out(&mut output).unwrap();
        black_box(&output);
    });
    group.finish();

    let mut group = c.benchmark_group("HKDF_SHA256::expand_out large info");
    group.throughput(Throughput::Bytes(big_data.len() as u64));
    group.bench_function(format!("{} bytes of additional data", big_data.len() as u64), |b| {
        let mut output_key = KeyMaterial512::new();
        b.iter(|| {
            HKDF_SHA256::expand_out(&key, &big_data, 64, &mut output_key).unwrap();
            black_box(&output_key);
        });
    });
    group.finish();

    let mut group = c.benchmark_group("HKDF_SHA256::expand_out max output size (255*HashLen)");
    group.throughput(Throughput::Bytes(255*32u64));
    group.bench_function(format!("{} bytes of output key material", 255*32u64), |b| {
        let mut output_key = KeyMaterialInternal::<8160>::new();
        b.iter(|| {
            HKDF_SHA256::extract_and_expand_out(&key, &key, &data_block, 255*32, &mut output_key).unwrap();
            black_box(&output_key);
        });
    });
    group.finish();
}

fn bench_hkdf_sha512(c: &mut Criterion) {
    let mut data_block = [0_u8; 1024];
    let mut output = KeyMaterial512::new();
    rng::DefaultRNG::default().next_bytes_out(&mut data_block).unwrap();

    let key = KeyMaterial512::from_bytes_as_type(&data_block[..64], KeyType::MACKey).unwrap();

    let mut big_data: Vec<u8> = vec![];
    for _ in 0..100 {
        big_data.extend_from_slice(&data_block);
    }

    let mut group = c.benchmark_group("HKDF_SHA512::do_extract_update_key");
    group.throughput(Throughput::Bytes(key.key_len() as u64));
    group.bench_function(format!("{} bytes of IKM data", big_data.len() as u64), |b| {
        let mut hkdf = HKDF_SHA512::default();
        hkdf.do_extract_init(&key).unwrap();
        b.iter(|| {
            let bytes_written = hkdf.do_extract_update_key(&key).unwrap();
            black_box(&bytes_written);
        });
        hkdf.do_extract_final_out(&mut output).unwrap();
        black_box(&output);
    });
    group.finish();

    let mut group = c.benchmark_group("HKDF_SHA512::do_extract_update_bytes");
    group.throughput(Throughput::Bytes(big_data.len() as u64));
    group.bench_function(format!("{} bytes of IKM data", big_data.len() as u64), |b| {
        let mut hkdf = HKDF_SHA512::default();
        hkdf.do_extract_init(&key).unwrap();
        b.iter(|| {
            let bytes_written = hkdf.do_extract_update_bytes(black_box(&big_data)).unwrap();
            black_box(&bytes_written);
        });
        hkdf.do_extract_final_out(&mut output).unwrap();
        black_box(&output);
    });
    group.finish();

    let mut group = c.benchmark_group("HKDF_SHA512::expand_out large info");
    group.throughput(Throughput::Bytes(big_data.len() as u64));
    group.bench_function(format!("{} bytes of additional data", big_data.len() as u64), |b| {
        let mut output_key = KeyMaterial512::new();
        b.iter(|| {
            HKDF_SHA512::expand_out(&key, &big_data, 64, &mut output_key).unwrap();
            black_box(&output_key);
        });
    });
    group.finish();

    let mut group = c.benchmark_group("HKDF_SHA512::expand_out max output size (255*HashLen)");
    group.throughput(Throughput::Bytes(255*64u64));
    group.bench_function(format!("{} bytes of output key material", 255*64u64), |b| {
        let mut output_key = KeyMaterialInternal::<16320>::new();
        b.iter(|| {
            HKDF_SHA512::extract_and_expand_out(&key, &key, &data_block, 255*64, &mut output_key).unwrap();
            black_box(&output_key);
        });
    });
    group.finish();
}



criterion_group!(benches, bench_hkdf_sha256, bench_hkdf_sha512);
criterion_main!(benches);
