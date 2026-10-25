//! Criterion benchmarks for the modes: one measurement per path that costs differently.
//!
//! These benches measure what a mode adds on top of the permutation, so a figure that would equal
//! another one here is not repeated.
//!
//! The number to watch is the **decrypt/encrypt throughput ratio** in CBC, CFB and CFB8.
//! Encryption there is serial by construction (SP 800-38A Sec 6.2 and Sec 6.3: each forward cipher
//! input depends on the previous output), so it runs one `encrypt_block` per block. Decryption is
//! parallel, and this implementation hands it to the permutation in fours: `decrypt_4blocks` for
//! CBC, `encrypt_4blocks` for CFB and CFB8, since those use the forward function in both
//! directions. On the bit-sliced AES a four costs barely more than one block, so decryption should
//! run at roughly three times the throughput of encryption; if that gap closes, something has
//! stopped taking the four path. CFB never calls the inverse cipher, so its decryption should also
//! come out ahead of CBC's.
//!
//! The `modes::gcm::AES_128` group is GCM against CTR: GCM is CTR plus GHASH over the ciphertext
//! and AAD (SP 800-38D Sec 7.1), and its CTR half batches exactly as `modes::ctr::AES_128` does, so
//! the difference between the two groups' 16 KiB encrypt figures is the cost of the table-free
//! GF(2^128) multiply, one per block. The AAD-only measurement is GMAC (Sec 5.2), which is that
//! multiply with no cipher calls at all beyond the two for `H` and `J0`.
//!
//! The cipher works in place, so each measurement runs on a fresh copy of the data made in
//! criterion's untimed setup (`iter_batched`); the copy is not part of the timing.

use bouncycastle_aes::hazmat::{AES_ECB_128_Key, AES128Internal, AES256Internal};
use bouncycastle_aes::{
    AES_CBC_128_Key, AES_CCM_128_Key, AES_CFB_128_Key, AES_CFB8_128_Key, AES_CTR_128_Key,
    AES_GCM_128_Key, AES_GCM_256_Key,
};
use bouncycastle_cipher::modes::hazmat::ecb::Ecb;
use bouncycastle_cipher::modes::{Cbc, CcmPacket, Cfb, Cfb8, Ctr, GCM_NONCE_LEN, Gcm};
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::traits::{
    AEADCipherEncryptor, BlockCipherDecryptor, BlockCipherEncryptor, StreamCipherDecryptor,
    StreamCipherEncryptor, SymmetricCipherEncryptor, SymmetricCipherKey,
};
use bouncycastle_core_test_framework::FixedSeedRNG;
use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

const BLOCK_LEN: usize = 16;
/// 16 KiB, i.e. 1024 AES blocks.
const NUM_BLOCKS: usize = 1024;
const DATA_LEN: usize = NUM_BLOCKS * BLOCK_LEN;

type Aes128Cbc<Dir> = Cbc<AES128Internal, Dir, AES_CBC_128_Key, 16, BLOCK_LEN>;
type Aes128Cfb<Dir> = Cfb<AES128Internal, Dir, AES_CFB_128_Key, 16, BLOCK_LEN>;
type Aes128Cfb8<Dir> = Cfb8<AES128Internal, Dir, AES_CFB8_128_Key, 16, BLOCK_LEN>;

/// CCM at the parameters the ACVP vectors and most protocols use: a 12-byte nonce and a full
/// 16-byte tag.
const CCM_NONCE_LEN: usize = 12;
const CCM_TAG_LEN: usize = 16;
type Aes128CcmEnc = CcmPacket<
    AES128Internal,
    Encrypting,
    AES_CCM_128_Key,
    16,
    BLOCK_LEN,
    CCM_NONCE_LEN,
    CCM_TAG_LEN,
>;
/// GCM with the full 16-byte tag, as the `AES_GCM_*` aliases fix it.
const GCM_TAG_LEN: usize = 16;
type Aes128Gcm<Dir> = Gcm<AES128Internal, Dir, AES_GCM_128_Key, 16, GCM_TAG_LEN>;
type Aes256Gcm<Dir> = Gcm<AES256Internal, Dir, AES_GCM_256_Key, 32, GCM_TAG_LEN>;
type Aes128Ctr<Dir> = Ctr<AES128Internal, Dir, AES_CTR_128_Key, 16, BLOCK_LEN, 12>;
type Aes128Ecb<Dir> = Ecb<AES128Internal, Dir, AES_ECB_128_Key, 16, BLOCK_LEN>;

fn key<K: SymmetricCipherKey<N>, const N: usize>() -> K {
    let bytes: [u8; N] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    K::from_bytes(&bytes).expect("a valid key")
}

fn data() -> Vec<[u8; BLOCK_LEN]> {
    (0..NUM_BLOCKS)
        .map(|i| core::array::from_fn(|j| (i.wrapping_mul(31).wrapping_add(j)) as u8))
        .collect()
}

fn bench_aes128cbc(c: &mut Criterion) {
    let k = key::<AES_CBC_128_Key, 16>();
    let blocks = data();

    let mut group = c.benchmark_group("modes::cbc::AES_128");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    // Serial: one block at a time is all it can do, whatever the call length.
    group.bench_function("16KiB encrypt -- N=8", |b| {
        b.iter_batched(
            || blocks.clone(),
            |mut scratch| {
                let (mut enc, _) = Aes128Cbc::<Encrypting>::do_encrypt_init(&k).unwrap();
                for chunk in scratch.chunks_exact_mut(8) {
                    let arr: &mut [u8; 8 * BLOCK_LEN] =
                        chunk.as_flattened_mut().try_into().unwrap();
                    enc.do_encrypt_blocks_inplace(arr.as_chunks_mut().0).unwrap();
                }
                black_box(&scratch);
            },
            BatchSize::LargeInput,
        )
    });

    let (mut enc, iv) = Aes128Cbc::<Encrypting>::do_encrypt_init(&k).unwrap();
    let mut ciphertext = blocks.clone();
    for chunk in ciphertext.chunks_exact_mut(8) {
        enc.do_encrypt_blocks_inplace(chunk).unwrap();
    }

    // Parallel: N=8 is two fours, so every block goes through decrypt_4blocks.
    group.bench_function("16KiB decrypt -- N=8 (all fours)", |b| {
        b.iter_batched(
            || ciphertext.clone(),
            |mut scratch| {
                let mut dec = Aes128Cbc::<Decrypting>::do_decrypt_init(&k, &iv).unwrap();
                for chunk in scratch.chunks_exact_mut(8) {
                    let arr: &mut [u8; 8 * BLOCK_LEN] =
                        chunk.as_flattened_mut().try_into().unwrap();
                    dec.do_decrypt_blocks_inplace(arr.as_chunks_mut().0).unwrap();
                }
                black_box(&scratch);
            },
            BatchSize::LargeInput,
        )
    });

    group.finish();
}

/// Runs the 16 KiB through a stream-cipher encryptor in `call_len`-byte calls. Used by the CFB,
/// CFB8 and CTR groups: it is generic over the trait, not over the mode.
fn cfb_encrypt_in_calls<
    E: StreamCipherEncryptor<K, KEY_LEN, INIT_DATA_LEN>,
    K: SymmetricCipherKey<KEY_LEN>,
    const KEY_LEN: usize,
    const INIT_DATA_LEN: usize,
>(
    k: &K,
    scratch: &mut [u8],
    call_len: usize,
) {
    let (mut enc, _) = E::do_encrypt_init(k).unwrap();
    for piece in scratch.chunks_mut(call_len) {
        enc.do_encrypt_inplace(piece).unwrap();
    }
}

/// Runs the 16 KiB through a stream-cipher decryptor in `call_len`-byte calls. Shared as above.
fn cfb_decrypt_in_calls<
    D: StreamCipherDecryptor<K, KEY_LEN, INIT_DATA_LEN>,
    K: SymmetricCipherKey<KEY_LEN>,
    const KEY_LEN: usize,
    const INIT_DATA_LEN: usize,
>(
    k: &K,
    iv: &[u8; INIT_DATA_LEN],
    scratch: &mut [u8],
    call_len: usize,
) {
    let mut dec = D::do_decrypt_init(k, iv).unwrap();
    for piece in scratch.chunks_mut(call_len) {
        dec.do_decrypt_inplace(piece).unwrap();
    }
}

fn bench_cfb_aes128(c: &mut Criterion) {
    let k = key::<AES_CFB_128_Key, 16>();
    let flat: Vec<u8> = data().as_flattened().to_vec();

    let mut group = c.benchmark_group("modes::cfb::AES_128");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    // Serial: Oj+1 = CIPH_K(Cj), and Cj is the previous block's output.
    group.bench_function("16KiB encrypt -- N=8", |b| {
        b.iter_batched(
            || flat.clone(),
            |mut scratch| {
                cfb_encrypt_in_calls::<Aes128Cfb<Encrypting>, _, 16, BLOCK_LEN>(
                    &k,
                    &mut scratch,
                    8 * BLOCK_LEN,
                );
                black_box(&scratch);
            },
            BatchSize::LargeInput,
        )
    });

    let (mut enc, iv) = Aes128Cfb::<Encrypting>::do_encrypt_init(&k).unwrap();
    let mut ciphertext = flat.clone();
    enc.do_encrypt_inplace(&mut ciphertext).unwrap();

    // Parallel, through the FORWARD four-block path.
    group.bench_function("16KiB decrypt -- N=8 (all fours)", |b| {
        b.iter_batched(
            || ciphertext.clone(),
            |mut scratch| {
                cfb_decrypt_in_calls::<Aes128Cfb<Decrypting>, _, 16, BLOCK_LEN>(
                    &k,
                    &iv,
                    &mut scratch,
                    8 * BLOCK_LEN,
                );
                black_box(&scratch);
            },
            BatchSize::LargeInput,
        )
    });

    group.finish();
}

/// CFB8: one forward cipher per byte, so ~1/16 of CFB's throughput on a 16-byte block. That is
/// inherent to `s = 8` (Sec 6.3 discards `b - s` bits of every output block).
///
/// Encryption is strictly serial. Decryption builds its input blocks in series and then runs them
/// through `encrypt_4blocks`, so it should still beat encryption by the four path's margin.
fn bench_cfb8_aes128(c: &mut Criterion) {
    let k = key::<AES_CFB8_128_Key, 16>();
    let flat: Vec<u8> = data().as_flattened().to_vec();

    let mut group = c.benchmark_group("modes::cfb8::AES_128");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    group.bench_function("16KiB encrypt -- whole message in one call", |b| {
        b.iter_batched(
            || flat.clone(),
            |mut scratch| {
                cfb_encrypt_in_calls::<Aes128Cfb8<Encrypting>, _, 16, BLOCK_LEN>(
                    &k, &mut scratch, DATA_LEN,
                );
                black_box(&scratch);
            },
            BatchSize::LargeInput,
        )
    });

    let (mut enc, iv) = Aes128Cfb8::<Encrypting>::do_encrypt_init(&k).unwrap();
    let mut ciphertext = flat.clone();
    enc.do_encrypt_inplace(&mut ciphertext).unwrap();

    group.bench_function("16KiB decrypt -- whole message in one call (batched)", |b| {
        b.iter_batched(
            || ciphertext.clone(),
            |mut scratch| {
                cfb_decrypt_in_calls::<Aes128Cfb8<Decrypting>, _, 16, BLOCK_LEN>(
                    &k, &iv, &mut scratch, DATA_LEN,
                );
                black_box(&scratch);
            },
            BatchSize::LargeInput,
        )
    });

    group.finish();
}

/// CTR: parallel in both directions (SP 800-38A Sec 6.5), and both directions are the same
/// keystream function, so one measurement covers it. It should match CFB decryption, not CFB
/// encryption.
fn bench_ctr_aes128(c: &mut Criterion) {
    let k = key::<AES_CTR_128_Key, 16>();
    let flat: Vec<u8> = data().as_flattened().to_vec();

    let mut group = c.benchmark_group("modes::ctr::AES_128");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    group.bench_function("16KiB encrypt -- N=8 (two fours per call)", |b| {
        b.iter_batched(
            || flat.clone(),
            |mut scratch| {
                cfb_encrypt_in_calls::<Aes128Ctr<Encrypting>, _, 16, 12>(
                    &k,
                    &mut scratch,
                    8 * BLOCK_LEN,
                );
                black_box(&scratch);
            },
            BatchSize::LargeInput,
        )
    });

    group.finish();
}

/// ECB is a thin wrapper over the permutation's batch methods, so this measures the permutation's
/// four-block path; it is here to catch a regression in the wrapper.
fn bench_ecb_aes128(c: &mut Criterion) {
    let k = key::<AES_ECB_128_Key, 16>();
    let blocks = data();

    let mut group = c.benchmark_group("modes::ecb::AES_128");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    group.bench_function("16KiB encrypt -- N=8 (fours)", |b| {
        b.iter_batched(
            || blocks.clone(),
            |mut scratch| {
                let (mut enc, _) = Aes128Ecb::<Encrypting>::do_encrypt_init(&k).unwrap();
                for chunk in scratch.chunks_exact_mut(8) {
                    let arr: &mut [u8; 8 * BLOCK_LEN] =
                        chunk.as_flattened_mut().try_into().unwrap();
                    enc.do_encrypt_blocks_inplace(arr.as_chunks_mut().0).unwrap();
                }
                black_box(&scratch);
            },
            BatchSize::LargeInput,
        )
    });

    group.finish();
}

/// `do_encrypt_init` is a key expansion plus an IV draw from the OS-backed DRBG, and for short
/// messages it dominates. Every mode does the same work here, so one is measured.
fn bench_init(c: &mut Criterion) {
    let k128 = key::<AES_CBC_128_Key, 16>();

    let mut group = c.benchmark_group("modes::init");

    group.bench_function("AES_128 do_encrypt_init (key schedule + IV)", |b| {
        b.iter(|| black_box(Aes128Cbc::<Encrypting>::do_encrypt_init(black_box(&k128)).unwrap().1))
    });

    group.finish();
}

/// CCM (SP 800-38C), which costs **two** forward-cipher calls per payload block, only one of which
/// batches.
///
/// Sec 5.2 builds CCM out of CTR for confidentiality and CBC-MAC for authenticity, over the same
/// key. The CBC-MAC half is serial (Sec 6.1 step 3: `Yi` is the cipher of `Bi XOR Yi-1`); the CTR
/// half batches as [`Ctr`] does. So a payload block costs one unbatched call plus one batched one,
/// and the AAD-only measurement is the CBC-MAC alone, one unbatched call per block.
///
/// Decryption does the same work in the opposite order (Sec 6.1 and Sec 6.2), and AAD alongside a
/// payload costs the sum of the two measurements here, so neither is measured separately.
fn bench_ccm_aes128(c: &mut Criterion) {
    let key = key::<AES_CCM_128_Key, 16>();
    let nonce = [0x24u8; CCM_NONCE_LEN];
    let data = [0xA5u8; DATA_LEN];
    let no_aad: [u8; 0] = [];

    let mut group = c.benchmark_group("modes::ccm::AES_128");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    group.bench_function("encrypt 16KiB, no AAD", |b| {
        b.iter_batched_ref(
            || [0u8; DATA_LEN],
            |out| {
                black_box(
                    Aes128CcmEnc::encrypt_detached_out(
                        black_box(&key),
                        &nonce,
                        &no_aad,
                        black_box(&data),
                        out,
                    )
                    .unwrap(),
                )
            },
            BatchSize::LargeInput,
        )
    });

    // AAD only: CCM as a pure authentication mode, which Sec 5.3's footnote calls out as the
    // empty-payload degenerate case.
    group.bench_function("authenticate 16KiB AAD, empty payload", |b| {
        b.iter(|| {
            let mut out: [u8; 0] = [];
            black_box(
                Aes128CcmEnc::encrypt_detached_out(
                    black_box(&key),
                    &nonce,
                    black_box(&data),
                    &no_aad,
                    &mut out,
                )
                .unwrap(),
            )
        })
    });

    group.finish();
}

/// GCM over the same 16 KiB as the CTR and CCM groups; see the module docs for what to compare
/// it against. The nonce comes from a cheap deterministic RNG created outside the timed loop, so
/// the figures measure the mode and not OS entropy or DRBG construction.
///
/// Decryption is the same work in the other order, and AAD alongside a payload costs the sum of
/// the two measurements here, so neither is measured separately.
fn bench_gcm_aes128(c: &mut Criterion) {
    let key = key::<AES_GCM_128_Key, 16>();
    let data = [0xA5u8; DATA_LEN];
    let no_aad: [u8; 0] = [];
    let mut rng = FixedSeedRNG::<GCM_NONCE_LEN>::new([0x24u8; GCM_NONCE_LEN]);

    let mut group = c.benchmark_group("modes::gcm::AES_128");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    group.bench_function("encrypt 16KiB, no AAD", |b| {
        b.iter_batched_ref(
            || [0u8; DATA_LEN],
            |out| {
                black_box(
                    Aes128Gcm::<Encrypting>::encrypt_detached_rng_out(
                        black_box(&key),
                        &mut rng,
                        &no_aad,
                        black_box(&data),
                        out,
                    )
                    .unwrap(),
                )
            },
            BatchSize::LargeInput,
        )
    });

    // AAD only: GMAC (Sec 5.2). GHASH over 16 KiB plus the two cipher calls for `H` and `J0`,
    // which is the GHASH cost on its own and the number the CTR comparison needs.
    group.bench_function("authenticate 16KiB AAD, empty payload (GMAC)", |b| {
        b.iter(|| {
            let mut out: [u8; 0] = [];
            black_box(
                Aes128Gcm::<Encrypting>::encrypt_detached_rng_out(
                    black_box(&key),
                    &mut rng,
                    black_box(&data),
                    &no_aad,
                    &mut out,
                )
                .unwrap(),
            )
        })
    });

    group.finish();
}

/// AES-256 GCM: the one mode-level key-length point. The other modes scale with the round count
/// as the permutation does.
fn bench_gcm_aes256(c: &mut Criterion) {
    let key = key::<AES_GCM_256_Key, 32>();
    let data = [0xA5u8; DATA_LEN];
    let no_aad: [u8; 0] = [];
    let mut rng = FixedSeedRNG::<GCM_NONCE_LEN>::new([0x24u8; GCM_NONCE_LEN]);

    let mut group = c.benchmark_group("modes::gcm::AES_256");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    group.bench_function("encrypt 16KiB, no AAD", |b| {
        b.iter_batched_ref(
            || [0u8; DATA_LEN],
            |out| {
                black_box(
                    Aes256Gcm::<Encrypting>::encrypt_detached_rng_out(
                        black_box(&key),
                        &mut rng,
                        &no_aad,
                        black_box(&data),
                        out,
                    )
                    .unwrap(),
                )
            },
            BatchSize::LargeInput,
        )
    });

    group.finish();
}

criterion_group!(
    benches, bench_aes128cbc, bench_cfb_aes128, bench_cfb8_aes128, bench_ctr_aes128,
    bench_ecb_aes128, bench_ccm_aes128, bench_gcm_aes128, bench_gcm_aes256, bench_init
);
criterion_main!(benches);
