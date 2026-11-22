use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::KDF;
use bouncycastle_symmetric::kbkdf::{
    CounterSize, IterationCounterPosition, KDF_Counter_CMAC_AES256, KDF_Counter_HMAC_SHA3_256,
    KDF_Counter_HMAC_SHA256, KDF_Counter_HMAC_SHA512, KDF_DoublePipeline_HMAC_SHA256,
    KDF_Feedback_HMAC_SHA256, KDF_KMAC128, KDF_KMAC256,
};
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn bench_kbkdf(c: &mut Criterion) {
    let k_in =
        KeyMaterial::<32>::from_bytes_as_type(&[0x5A; 32], KeyType::CryptographicRandom).unwrap();
    let fixed = b"kbkdf bench: label\0context";
    let counter = (CounterSize::_32bit, IterationCounterPosition::AfterIterationVariable);

    let feedback = KDF_Feedback_HMAC_SHA256::with_counter(b"", counter.0, counter.1);
    let pipeline = KDF_DoublePipeline_HMAC_SHA256::with_counter(counter.0, counter.1);
    let guarded = KDF_Counter_CMAC_AES256::new().with_key_control_guard();
    let kdfs: [(&str, &dyn KDF); 9] = [
        ("counter hmac-sha256", &KDF_Counter_HMAC_SHA256::new()),
        ("counter hmac-sha512", &KDF_Counter_HMAC_SHA512::new()),
        ("counter hmac-sha3-256", &KDF_Counter_HMAC_SHA3_256::new()),
        ("counter cmac-aes256", &KDF_Counter_CMAC_AES256::new()),
        ("counter cmac-aes256, key-control guard", &guarded),
        ("feedback hmac-sha256", &feedback),
        ("double-pipeline hmac-sha256", &pipeline),
        ("kmac128", &KDF_KMAC128::new(b"KDF")),
        ("kmac256", &KDF_KMAC256::new(b"KDF")),
    ];

    let mut group = c.benchmark_group("kbkdf");
    for (name, kdf) in kdfs {
        group.bench_function(format!("{name} 32 bytes"), |b| {
            let mut out = KeyMaterial::<32>::new();
            b.iter(|| kdf.derive_key_out(black_box(&k_in), black_box(fixed), 32, &mut out).unwrap())
        });
        group.bench_function(format!("{name} 1024 bytes"), |b| {
            let mut out = KeyMaterial::<1024>::new();
            b.iter(|| {
                kdf.derive_key_out(black_box(&k_in), black_box(fixed), 1024, &mut out).unwrap()
            })
        });
    }
    group.finish();
}

criterion_group!(benches, bench_kbkdf);
criterion_main!(benches);
