//! Criterion benchmarks for the modes.
//!
//! The number to watch is the **decrypt/encrypt throughput ratio at N >= 2**. CBC encryption is
//! serial by construction (SP 800-38A Sec 6.2: each forward cipher input depends on the previous
//! output), so it can only ever use the single-block path. CBC *decryption* is parallel, and this
//! implementation hands blocks to `decrypt_blocks2` in pairs. With the bit-sliced AES, whose
//! two-block path costs barely more than one block, decryption should therefore run at roughly
//! twice the throughput of encryption. That gap is the entire justification for the pair methods
//! on `BlockPermutation`, so if it disappears, something has stopped taking the pair path.
//!
//! `N = 1` is included to show the effect vanishing: with one block there is no pair to form, so
//! decryption falls back to the single-block path and the ratio should be about 1.
//!
//! The cipher works in place, so each measurement runs on a fresh copy of the data made in
//! criterion's untimed setup (`iter_batched`); the copy is not part of the timing.

use bouncycastle_aes_lowmemory::{Aes128, Aes256};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{
    Algorithm, BlockCipherDecryptor, BlockCipherEncryptor, BlockPermutation, SecurityStrength,
};
use bouncycastle_modes::{Cbc, Decrypting, Encrypting};
use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

const BLOCK_LEN: usize = 16;
/// 16 KiB, i.e. 1024 AES blocks.
const NUM_BLOCKS: usize = 1024;
const DATA_LEN: usize = NUM_BLOCKS * BLOCK_LEN;

type Aes128Cbc<Dir> = Cbc<Aes128, Dir, 16, BLOCK_LEN>;
type Aes256Cbc<Dir> = Cbc<Aes256, Dir, 32, BLOCK_LEN>;

/// AES-128 with the pair methods **not** overridden, so they fall back to the trait defaults of
/// two single-block calls.
///
/// This exists purely to isolate the value of the pair path. Comparing `Cbc<Aes128, ..>` against
/// `Cbc<UnpairedAes128, ..>` at the *same* `N` holds everything else fixed -- same cipher, same
/// call granularity, same amount of data movement -- so the difference is attributable to
/// `decrypt_blocks2` and nothing else.
///
/// Comparing `N = 1` against `N = 8` does *not* isolate it: encryption, which can never pair, also
/// speeds up substantially between those two, so call granularity dominates that comparison.
struct UnpairedAes128(Aes128);

impl Algorithm for UnpairedAes128 {
    const ALG_NAME: &'static str = "AES-128 (unpaired)";
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

impl BlockPermutation<16, BLOCK_LEN> for UnpairedAes128 {
    fn new(key: &KeyMaterial<16>) -> Result<Self, SymmetricCipherError> {
        Ok(Self(<Aes128 as BlockPermutation<16, BLOCK_LEN>>::new(key)?))
    }
    fn encrypt_block(&self, block: &mut [u8; BLOCK_LEN]) {
        <Aes128 as BlockPermutation<16, BLOCK_LEN>>::encrypt_block(&self.0, block)
    }
    fn decrypt_block(&self, block: &mut [u8; BLOCK_LEN]) {
        <Aes128 as BlockPermutation<16, BLOCK_LEN>>::decrypt_block(&self.0, block)
    }
    // encrypt_blocks2 / decrypt_blocks2 deliberately left as the trait defaults.
}

type UnpairedAes128Cbc<Dir> = Cbc<UnpairedAes128, Dir, 16, BLOCK_LEN>;

fn key<const N: usize>() -> KeyMaterial<N> {
    let bytes: [u8; N] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    KeyMaterial::<N>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).unwrap()
}

fn data() -> Vec<[u8; BLOCK_LEN]> {
    (0..NUM_BLOCKS)
        .map(|i| core::array::from_fn(|j| (i.wrapping_mul(31).wrapping_add(j)) as u8))
        .collect()
}

fn bench_aes128(c: &mut Criterion) {
    let k = key::<16>();
    let blocks = data();

    let mut group = c.benchmark_group("modes::cbc::Aes128");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    // ---- encryption: serial, one block at a time is all it can do ----
    group.bench_function("16KiB encrypt -- N=1", |b| {
        b.iter_batched(
            || blocks.clone(),
            |mut scratch| {
                let (mut enc, _) = Aes128Cbc::<Encrypting>::do_encrypt_init(&k).unwrap();
                for block in scratch.iter_mut() {
                    enc.do_encrypt(block).unwrap();
                }
                black_box(&scratch);
            },
            BatchSize::LargeInput,
        )
    });

    group.bench_function("16KiB encrypt -- N=8", |b| {
        b.iter_batched(
            || blocks.clone(),
            |mut scratch| {
                let (mut enc, _) = Aes128Cbc::<Encrypting>::do_encrypt_init(&k).unwrap();
                for chunk in scratch.chunks_exact_mut(8) {
                    let arr: &mut [u8; 8 * BLOCK_LEN] =
                        chunk.as_flattened_mut().try_into().unwrap();
                    enc.do_encrypt(arr).unwrap();
                }
                black_box(&scratch);
            },
            BatchSize::LargeInput,
        )
    });

    // ---- decryption: parallel, uses decrypt_blocks2 for every pair ----
    let (mut enc, iv) = Aes128Cbc::<Encrypting>::do_encrypt_init(&k).unwrap();
    let mut ciphertext = blocks.clone();
    for chunk in ciphertext.chunks_exact_mut(8) {
        let arr: &mut [[u8; BLOCK_LEN]; 8] = chunk.try_into().unwrap();
        enc.do_encrypt_blocks(arr).unwrap();
    }

    // N=1 never forms a pair, so this is the single-block path: the ratio against encrypt should
    // be about 1.
    group.bench_function("16KiB decrypt -- N=1 (no pairing)", |b| {
        b.iter_batched(
            || ciphertext.clone(),
            |mut scratch| {
                let mut dec = Aes128Cbc::<Decrypting>::do_decrypt_init(&k, &iv).unwrap();
                for block in scratch.iter_mut() {
                    dec.do_decrypt(block).unwrap();
                }
                black_box(&scratch);
            },
            BatchSize::LargeInput,
        )
    });

    // N=2 and N=8 are all pairs, so every block goes through decrypt_blocks2.
    group.bench_function("16KiB decrypt -- N=2 (all pairs)", |b| {
        b.iter_batched(
            || ciphertext.clone(),
            |mut scratch| {
                let mut dec = Aes128Cbc::<Decrypting>::do_decrypt_init(&k, &iv).unwrap();
                for chunk in scratch.chunks_exact_mut(2) {
                    let arr: &mut [u8; 2 * BLOCK_LEN] =
                        chunk.as_flattened_mut().try_into().unwrap();
                    dec.do_decrypt(arr).unwrap();
                }
                black_box(&scratch);
            },
            BatchSize::LargeInput,
        )
    });

    group.bench_function("16KiB decrypt -- N=8 (all pairs)", |b| {
        b.iter_batched(
            || ciphertext.clone(),
            |mut scratch| {
                let mut dec = Aes128Cbc::<Decrypting>::do_decrypt_init(&k, &iv).unwrap();
                for chunk in scratch.chunks_exact_mut(8) {
                    let arr: &mut [u8; 8 * BLOCK_LEN] =
                        chunk.as_flattened_mut().try_into().unwrap();
                    dec.do_decrypt(arr).unwrap();
                }
                black_box(&scratch);
            },
            BatchSize::LargeInput,
        )
    });

    // N=9 is four pairs plus a one-block remainder, so it exercises the tail path too.
    group.bench_function("16KiB decrypt -- N=9 (pairs + remainder)", |b| {
        b.iter_batched(
            || ciphertext.clone(),
            |mut scratch| {
                let mut dec = Aes128Cbc::<Decrypting>::do_decrypt_init(&k, &iv).unwrap();
                for chunk in scratch.chunks_exact_mut(9) {
                    let arr: &mut [u8; 9 * BLOCK_LEN] =
                        chunk.as_flattened_mut().try_into().unwrap();
                    dec.do_decrypt(arr).unwrap();
                }
                black_box(&scratch);
            },
            BatchSize::LargeInput,
        )
    });

    // The controlled comparison: identical N, identical cipher, pair methods overridden vs not.
    // This pair of numbers -- and only this pair -- measures what `decrypt_blocks2` buys.
    group.bench_function("16KiB decrypt -- N=8, pair path (blocks2 overridden)", |b| {
        b.iter_batched(
            || ciphertext.clone(),
            |mut scratch| {
                let mut dec = Aes128Cbc::<Decrypting>::do_decrypt_init(&k, &iv).unwrap();
                for chunk in scratch.chunks_exact_mut(8) {
                    let arr: &mut [u8; 8 * BLOCK_LEN] =
                        chunk.as_flattened_mut().try_into().unwrap();
                    dec.do_decrypt(arr).unwrap();
                }
                black_box(&scratch);
            },
            BatchSize::LargeInput,
        )
    });

    group.bench_function("16KiB decrypt -- N=8, no pair path (trait default)", |b| {
        b.iter_batched(
            || ciphertext.clone(),
            |mut scratch| {
                let mut dec = UnpairedAes128Cbc::<Decrypting>::do_decrypt_init(&k, &iv).unwrap();
                for chunk in scratch.chunks_exact_mut(8) {
                    let arr: &mut [u8; 8 * BLOCK_LEN] =
                        chunk.as_flattened_mut().try_into().unwrap();
                    dec.do_decrypt(arr).unwrap();
                }
                black_box(&scratch);
            },
            BatchSize::LargeInput,
        )
    });

    group.finish();
}

fn bench_aes256(c: &mut Criterion) {
    let k = key::<32>();
    let blocks = data();

    let mut group = c.benchmark_group("modes::cbc::Aes256");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    group.bench_function("16KiB encrypt -- N=8", |b| {
        b.iter_batched(
            || blocks.clone(),
            |mut scratch| {
                let (mut enc, _) = Aes256Cbc::<Encrypting>::do_encrypt_init(&k).unwrap();
                for chunk in scratch.chunks_exact_mut(8) {
                    let arr: &mut [u8; 8 * BLOCK_LEN] =
                        chunk.as_flattened_mut().try_into().unwrap();
                    enc.do_encrypt(arr).unwrap();
                }
                black_box(&scratch);
            },
            BatchSize::LargeInput,
        )
    });

    let (mut enc, iv) = Aes256Cbc::<Encrypting>::do_encrypt_init(&k).unwrap();
    let mut ciphertext = blocks.clone();
    for chunk in ciphertext.chunks_exact_mut(8) {
        let arr: &mut [[u8; BLOCK_LEN]; 8] = chunk.try_into().unwrap();
        enc.do_encrypt_blocks(arr).unwrap();
    }

    group.bench_function("16KiB decrypt -- N=8 (all pairs)", |b| {
        b.iter_batched(
            || ciphertext.clone(),
            |mut scratch| {
                let mut dec = Aes256Cbc::<Decrypting>::do_decrypt_init(&k, &iv).unwrap();
                for chunk in scratch.chunks_exact_mut(8) {
                    let arr: &mut [u8; 8 * BLOCK_LEN] =
                        chunk.as_flattened_mut().try_into().unwrap();
                    dec.do_decrypt(arr).unwrap();
                }
                black_box(&scratch);
            },
            BatchSize::LargeInput,
        )
    });

    group.finish();
}

/// `do_*_init` includes a key expansion, and for encryption also an IV draw from the OS-backed
/// DRBG. Worth its own measurement, because for short messages it dominates.
fn bench_init(c: &mut Criterion) {
    let k128 = key::<16>();
    let k256 = key::<32>();
    let iv = [0u8; BLOCK_LEN];

    let mut group = c.benchmark_group("modes::cbc::init");

    group.bench_function("Aes128 do_encrypt_init (key schedule + IV)", |b| {
        b.iter(|| black_box(Aes128Cbc::<Encrypting>::do_encrypt_init(black_box(&k128)).unwrap().1))
    });
    group.bench_function("Aes128 do_decrypt_init (key schedule only)", |b| {
        b.iter(|| {
            black_box(Aes128Cbc::<Decrypting>::do_decrypt_init(black_box(&k128), &iv).unwrap())
        })
    });
    group.bench_function("Aes256 do_decrypt_init (key schedule only)", |b| {
        b.iter(|| {
            black_box(Aes256Cbc::<Decrypting>::do_decrypt_init(black_box(&k256), &iv).unwrap())
        })
    });

    group.finish();
}

criterion_group!(benches, bench_aes128, bench_aes256, bench_init);
criterion_main!(benches);
