use std::hint::black_box;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use bouncycastle_rng as rng;
use bouncycastle_core_interface::traits::RNG;
use bouncycastle_base64::{Base64Encoder, Base64Decoder};

fn bench_base64_encode(c: &mut Criterion) {
    const INPUT_SIZE: usize = 16 * 1024;
    const ENCODED_SIZE: usize = INPUT_SIZE * 4 / 3 + 2;

    let mut data = [0_u8; 1024];
    rng::DefaultRNG::default().next_bytes_out(&mut data).unwrap();

    let mut output = String::with_capacity(ENCODED_SIZE);

    let mut group = c.benchmark_group("base64::encode");
    group.throughput(Throughput::Bytes(16 * 1024));
    group.bench_function("16KiB", |b| {
        b.iter(|| {
            let mut encoder = Base64Encoder::new();
            for _ in 0..16 {
                output.push_str(&*encoder.do_update(black_box(&data)));
            }
            output.push_str(&*encoder.do_final(&[0u8; 0]));
            black_box(&output);
        })
    });
    group.finish();
}

fn bench_base64_decode(c: &mut Criterion) {
    const INPUT_SIZE: usize = 16 * 1024;
    // const ENCODED_SIZE: usize = INPUT_SIZE * 4 / 3 + 2;

    let mut data = [0_u8; 1024];
    rng::DefaultRNG::default().next_bytes_out(&mut data).unwrap();

    // Generate some base65-encoded data.
    let mut encoder = Base64Encoder::new();
    let input: String = encoder.do_update(&data);  // will be 1024 * 4 / 3 + 2 = 1368 bytes long.

    let mut output = vec![0u8; INPUT_SIZE];

    let mut group = c.benchmark_group("base64::decode");
    group.throughput(Throughput::Bytes(16 * 1024));
    group.bench_function("16KiB", |b| {
        b.iter(|| {
            let mut decoder = Base64Decoder::new(false);
            for _ in 0..16 {
                output.extend_from_slice(&*decoder.do_update(black_box(&input)).expect("TODO: panic message"));
            }
            output.extend_from_slice(decoder.do_final(&str::from_utf8(&[0u8; 0]).expect("TODO: panic message"))
                .expect("TODO: panic message").as_slice());
            black_box(&output);
        })
    });
    group.finish();
}


criterion_group!(benches, bench_base64_encode, bench_base64_decode);
criterion_main!(benches);