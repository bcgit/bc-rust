use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use ed25519::*;

fn bench_generate_public_key(c: &mut Criterion) {
    precompute();

    let mut random = rand::rng();

    let mut group = c.benchmark_group("eddsa::generate_public_key");
    group.throughput(Throughput::Elements(1));
    group.bench_function("default", |b| {
        let mut sk = [0u8; SECRET_KEY_SIZE];
        generate_private_key(&mut random, &mut sk);

        let mut pk = [0u8; PUBLIC_KEY_SIZE];

        b.iter(|| {
            generate_public_key(black_box(&sk), &mut pk);
            black_box(&pk);
        })
    });
    group.finish();
}

fn bench_generate_public_point(c: &mut Criterion) {
    precompute();

    let mut random = rand::rng();

    let mut group = c.benchmark_group("eddsa::generate_public_point");
    group.throughput(Throughput::Elements(1));
    group.bench_function("default", |b| {
        let mut sk = [0u8; SECRET_KEY_SIZE];
        generate_private_key(&mut random, &mut sk);

        b.iter(|| {
            black_box(generate_public_point(black_box(&sk)));
        })
    });
    group.finish();
}

fn bench_sign(c: &mut Criterion) {
    precompute();

    let mut random = rand::rng();

    let mut group = c.benchmark_group("eddsa::sign");
    group.throughput(Throughput::Elements(1));
    group.bench_function("default", |b| {
        let msg = [0_u8; 0];

        let mut sk = [0u8; SECRET_KEY_SIZE];
        generate_private_key(&mut random, &mut sk);

        let mut sig = [0u8; SIGNATURE_SIZE];

        b.iter(|| {
            sign(black_box(&sk), black_box(&msg), &mut sig);
            black_box(&sig);
        })
    });
    group.finish();
}

fn bench_sign_pk(c: &mut Criterion) {
    precompute();

    let mut random = rand::rng();

    let mut group = c.benchmark_group("eddsa::sign_pk");
    group.throughput(Throughput::Elements(1));
    group.bench_function("default", |b| {
        let msg = [0_u8; 0];

        let mut sk = [0u8; SECRET_KEY_SIZE];
        generate_private_key(&mut random, &mut sk);

        let mut pk = [0u8; PUBLIC_KEY_SIZE];
        generate_public_key(&sk, &mut pk);

        let mut sig = [0u8; SIGNATURE_SIZE];

        b.iter(|| {
            sign_pk(black_box(&sk), black_box(&pk), black_box(&msg), &mut sig);
            black_box(&sig);
        })
    });
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    precompute();

    let mut random = rand::rng();

    let mut group = c.benchmark_group("eddsa::verify");
    group.throughput(Throughput::Elements(1));
    group.bench_function("default", |b| {
        let msg = [0_u8; 0];

        let mut sk = [0u8; SECRET_KEY_SIZE];
        generate_private_key(&mut random, &mut sk);

        let mut pk = [0u8; PUBLIC_KEY_SIZE];
        generate_public_key(&sk, &mut pk);

        let mut sig = [0u8; SIGNATURE_SIZE];
        sign_pk(&sk, &pk, &msg, &mut sig);

        b.iter(|| {
            black_box(verify(black_box(&sig), black_box(&pk), black_box(&msg)));
        })
    });
    group.finish();
}

fn bench_verify_public_point(c: &mut Criterion) {
    precompute();

    let mut random = rand::rng();

    let mut group = c.benchmark_group("eddsa::verify_public_point");
    group.throughput(Throughput::Elements(1));
    group.bench_function("default", |b| {
        let msg = [0_u8; 0];

        let mut sk = [0u8; SECRET_KEY_SIZE];
        generate_private_key(&mut random, &mut sk);

        let public_point = generate_public_point(&sk);

        let mut pk = [0u8; PUBLIC_KEY_SIZE];
        encode_public_point(&public_point, &mut pk);

        let mut sig = [0u8; SIGNATURE_SIZE];
        sign_pk(&sk, &pk, &msg, &mut sig);

        b.iter(|| {
            black_box(verify_public_point(
                black_box(&sig),
                black_box(&public_point),
                black_box(&msg),
            ));
        })
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_generate_public_key,
    bench_generate_public_point,
    bench_sign,
    bench_sign_pk,
    bench_verify,
    bench_verify_public_point
);
criterion_main!(benches);
