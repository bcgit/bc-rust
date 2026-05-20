use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

use bouncycastle_ascon::{AsconAead128, AsconCXof128, AsconHash256, AsconXof128};
use bouncycastle_core_interface::traits::{Hash, XOF};

const DATA_LEN: usize = 1024;
const NUM_BLOCKS: usize = 16;

fn fill_block() -> Vec<u8> {
    // Deterministic, non-zero pattern so different bench runs aren't
    // skewed by branch-predictable zero blocks.
    (0..DATA_LEN).map(|i| (i & 0xFF) as u8).collect()
}

fn bench_hash256(c: &mut Criterion) {
    let block = fill_block();
    let big: Vec<u8> = (0..NUM_BLOCKS).flat_map(|_| block.iter().copied()).collect();

    let mut group = c.benchmark_group("AsconHash256");
    group.throughput(Throughput::Bytes(big.len() as u64));

    let mut digest = [0u8; 32];
    group.bench_function(format!("{} bytes one-shot", big.len()), |b| {
        b.iter(|| {
            AsconHash256::new().hash_out(black_box(&big), &mut digest);
            black_box(&digest);
        })
    });

    group.bench_function(format!("{NUM_BLOCKS} * 1KiB streaming"), |b| {
        b.iter(|| {
            let mut h = AsconHash256::new();
            for _ in 0..NUM_BLOCKS {
                h.do_update(black_box(&block));
            }
            h.do_final_out(&mut digest);
            black_box(&digest);
        })
    });
    group.finish();
}

fn bench_xof128(c: &mut Criterion) {
    let block = fill_block();
    let big: Vec<u8> = (0..NUM_BLOCKS).flat_map(|_| block.iter().copied()).collect();

    let mut group = c.benchmark_group("AsconXof128");
    group.throughput(Throughput::Bytes(big.len() as u64));

    let mut out = vec![0u8; 64];
    group.bench_function(format!("{} bytes one-shot (64B out)", big.len()), |b| {
        b.iter(|| {
            AsconXof128::new().hash_xof_out(black_box(&big), &mut out);
            black_box(&out);
        })
    });
    group.finish();
}

fn bench_cxof128(c: &mut Criterion) {
    let block = fill_block();

    let mut group = c.benchmark_group("AsconCXof128");
    group.throughput(Throughput::Bytes(block.len() as u64));

    let mut out = vec![0u8; 64];
    group.bench_function("1KiB w/ 32B Z one-shot (64B out)", |b| {
        b.iter(|| {
            AsconCXof128::with_customization(black_box(&[0u8; 32]))
                .hash_xof_out(black_box(&block), &mut out);
            black_box(&out);
        })
    });
    group.finish();
}

fn bench_aead128(c: &mut Criterion) {
    let block = fill_block();
    let key = [0u8; 16];
    let nonce = [0u8; 16];

    let mut group = c.benchmark_group("AsconAead128");
    group.throughput(Throughput::Bytes(block.len() as u64));

    let mut out = vec![0u8; block.len() + 16];
    group.bench_function("encrypt 1KiB", |b| {
        b.iter(|| {
            let mut enc = AsconAead128::new(&key, &nonce, None, true);
            let n = enc.encrypt_update(black_box(&block), &mut out);
            let m = enc.encrypt_finalize(&mut out[n..]).unwrap();
            black_box(&out[..n + m]);
        })
    });

    // Pre-compute a single valid ciphertext to bench decrypt.
    let mut ct = vec![0u8; block.len() + 16];
    {
        let mut enc = AsconAead128::new(&key, &nonce, None, true);
        let n = enc.encrypt_update(&block, &mut ct);
        let m = enc.encrypt_finalize(&mut ct[n..]).unwrap();
        ct.truncate(n + m);
    }
    let mut pt = vec![0u8; block.len()];
    group.bench_function("decrypt 1KiB", |b| {
        b.iter(|| {
            let mut dec = AsconAead128::new(&key, &nonce, None, false);
            let n = dec.try_decrypt_update(black_box(&ct), &mut pt).unwrap();
            let m = dec.decrypt_finalize(&mut pt[n..]).unwrap();
            black_box(&pt[..n + m]);
        })
    });
    group.finish();
}

criterion_group!(benches, bench_hash256, bench_xof128, bench_cxof128, bench_aead128);
criterion_main!(benches);
