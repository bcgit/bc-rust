use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_scrypt::{SCrypt, ScryptParams};
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn bench_scrypt(c: &mut Criterion) {
    let password =
        KeyMaterial::<64>::from_bytes_as_type(b"correct horse battery staple", KeyType::Unknown)
            .unwrap();
    let salt = [0x5Au8; 16];

    let mut group = c.benchmark_group("scrypt");
    group.sample_size(10);
    // (log2(N), r, p): RFC 7914 Section 12's second and third parameter sets, and a larger N.
    for (log2_n, r, p) in [(10u8, 8u32, 16u32), (14, 8, 1), (17, 8, 1)] {
        let params = ScryptParams::new(log2_n, r, p).unwrap();
        let kdf = SCrypt::new(&salt, params);
        // The caller's working memory, allocated once: the function itself, not the allocator.
        let mut work = vec![0u8; params.work_len()];
        group.bench_function(format!("N = 2^{log2_n}, r = {r}, p = {p}, 32 bytes"), |b| {
            let mut out = KeyMaterial::<32>::new();
            b.iter(|| {
                kdf.derive_with_memory_out(black_box(&password), 32, &mut work, &mut out).unwrap()
            })
        });
    }
    group.finish();
}

criterion_group!(benches, bench_scrypt);
criterion_main!(benches);
