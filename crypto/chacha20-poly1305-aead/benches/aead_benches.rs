use bouncycastle_rng as rng;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

use bouncycastle_chacha20_poly1305_aead::ChaCha20Poly1305Encryptor;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{AEADCipherEncryptor, RNG, SymmetricCipherEncryptor};

const DATA_LEN: usize = 16 * 1024;

fn random_data(len: usize) -> Vec<u8> {
    let mut data = vec![0u8; len];
    rng::DefaultRNG::default().next_bytes_out(&mut data).unwrap();
    data
}

fn bench_encrypt(c: &mut Criterion) {
    let key =
        KeyMaterial::<32>::from_bytes_as_type(&[0x42u8; 32], KeyType::SymmetricCipherKey).unwrap();
    let nonce = [0x24u8; 12];
    let data = random_data(DATA_LEN);
    let mut out = vec![0u8; DATA_LEN];

    let mut group = c.benchmark_group("chacha20_poly1305_aead::ChaCha20Poly1305Encryptor");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    // A fixed nonce keeps OS randomness out of the timing; never do this outside a benchmark.
    group.bench_function(format!("{DATA_LEN} bytes -- .do_encrypt_out()"), |b| {
        b.iter(|| {
            let mut enc = ChaCha20Poly1305Encryptor::new_with_nonce(&key, &nonce).unwrap();
            enc.do_update_aad(b"header").unwrap();
            enc.do_encrypt_out(black_box(&data), &mut out).unwrap();
            black_box(enc.do_final_detached().unwrap());
            black_box(&out);
        })
    });

    group.finish();
}

criterion_group!(benches, bench_encrypt);
criterion_main!(benches);
