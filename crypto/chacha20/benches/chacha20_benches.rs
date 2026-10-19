use bouncycastle_rng as rng;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

use bouncycastle_chacha20::ChaCha20;
use bouncycastle_cipher::Decrypting;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{RNG, StreamCipherDecryptor, SymmetricCipherDecryptor};

const DATA_LEN: usize = 16 * 1024;

fn random_data(len: usize) -> Vec<u8> {
    let mut data = vec![0u8; len];
    rng::DefaultRNG::default().next_bytes_out(&mut data).unwrap();
    data
}

fn bench_chacha20(c: &mut Criterion) {
    let key =
        KeyMaterial::<32>::from_bytes_as_type(&[0x42u8; 32], KeyType::SymmetricCipherKey).unwrap();
    let nonce = [0x24u8; 12];
    let data = random_data(DATA_LEN);
    let mut buf = data.clone();

    let mut group = c.benchmark_group("chacha20::ChaCha20");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    // The decryptor takes the nonce, so each iteration starts a fresh keystream without drawing a
    // nonce from the OS; the XOR is the same in both directions.
    group.bench_function(format!("{DATA_LEN} bytes -- .do_decrypt()"), |b| {
        b.iter(|| {
            let mut cipher = ChaCha20::<Decrypting>::do_decrypt_init(&key, &nonce).unwrap();
            cipher.do_decrypt(black_box(&mut buf)).unwrap();
            black_box(&buf);
        })
    });

    group.finish();
}

criterion_group!(benches, bench_chacha20);
criterion_main!(benches);
