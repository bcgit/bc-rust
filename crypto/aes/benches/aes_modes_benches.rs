//! Criterion benchmarks for the modes: one measurement per path that costs differently.
//!
//! The block-level costs -- `encrypt_block`, the pair and four paths, key expansion, and every key
//! length -- are measured in `aes_benches`. These benches measure only what a mode adds on top, so
//! a figure that would equal an `aes_benches` one, or another one here, is not repeated.
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

use bouncycastle_aes::hazmat::{AES128Internal, AES256Internal};
use bouncycastle_aes::{AES_CMAC_128, AES_CMAC_256, AES128Key, AES256Key};
use bouncycastle_cipher::modes::hazmat::ecb::Ecb;
use bouncycastle_cipher::modes::{CCM, CMAC, Cbc, CcmEncryptor, Cfb, Cfb8, Ctr, GCM_NONCE_LEN, Gcm};
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::hazmat::{AeadPacketEncryptMode, ElectronicCodeBook};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::{FromKeyMaterial, MacGenerationKey};
use bouncycastle_core::traits::{
    AEADCipherEncryptor, BlockCipherDecryptor, BlockCipherEncryptor, MAC, StreamCipherDecryptor,
    StreamCipherEncryptor, SymmetricCipherEncryptor,
};
use bouncycastle_core_test_framework::FixedSeedRNG;
use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

const BLOCK_LEN: usize = 16;
/// 16 KiB, i.e. 1024 AES blocks.
const NUM_BLOCKS: usize = 1024;
const DATA_LEN: usize = NUM_BLOCKS * BLOCK_LEN;

type Aes128Cbc<Dir> = Cbc<AES128Internal, Dir, 16, BLOCK_LEN>;
type Aes128Cfb<Dir> = Cfb<AES128Internal, Dir, 16, BLOCK_LEN>;
type Aes128Cfb8<Dir> = Cfb8<AES128Internal, Dir, 16, BLOCK_LEN>;

/// CCM at the parameters the ACVP vectors and most protocols use: a 12-byte nonce and a full
/// 16-byte tag. The mode's in-place one-shots over the keyed permutation are the direct path;
/// the frame parameters are unused by them.
const CCM_NONCE_LEN: usize = 12;
const CCM_TAG_LEN: usize = 16;
type Aes128CcmMode = CCM<CCM_NONCE_LEN, CCM_TAG_LEN>;

/// The trait adapter takes its frame size at compile time. Its one-shots are not bound by it,
/// but using the same 4 KiB message keeps this comparison representative of the public alias a
/// packet protocol would choose.
const CCM_BUFFER_LEN: usize = 4096;
const CCM_AAD_LEN: usize = 64;
type Aes128CcmEncryptor = CcmEncryptor<
    AES128Internal,
    16,
    BLOCK_LEN,
    CCM_NONCE_LEN,
    CCM_TAG_LEN,
    CCM_AAD_LEN,
    CCM_BUFFER_LEN,
>;
/// GCM with the full 16-byte tag, as the `AES_GCM_*` aliases fix it.
const GCM_TAG_LEN: usize = 16;
type Aes128Gcm<Dir> = Gcm<AES128Internal, Dir, 16, GCM_TAG_LEN>;
type Aes256Gcm<Dir> = Gcm<AES256Internal, Dir, 32, GCM_TAG_LEN>;
type Aes128Ctr<Dir> = Ctr<AES128Internal, Dir, 16, BLOCK_LEN, 12>;
type Aes128Ecb<Dir> = Ecb<AES128Internal, Dir, 16, BLOCK_LEN>;

fn key<const N: usize>() -> KeyMaterial<N> {
    let bytes: [u8; N] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    KeyMaterial::<N>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).unwrap()
}

/// [`key`]'s bytes as a `KeyType::MACKey`, which is what CMAC takes.
fn mac_key<const N: usize>() -> KeyMaterial<N> {
    let bytes: [u8; N] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    KeyMaterial::<N>::from_bytes_as_type(&bytes, KeyType::MACKey).unwrap()
}

fn data() -> Vec<[u8; BLOCK_LEN]> {
    (0..NUM_BLOCKS)
        .map(|i| core::array::from_fn(|j| (i.wrapping_mul(31).wrapping_add(j)) as u8))
        .collect()
}

fn bench_aes128cbc(c: &mut Criterion) {
    let k = key::<16>();
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
    E: StreamCipherEncryptor<KEY_LEN, INIT_DATA_LEN>,
    const KEY_LEN: usize,
    const INIT_DATA_LEN: usize,
>(
    k: &KeyMaterial<KEY_LEN>,
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
    D: StreamCipherDecryptor<KEY_LEN, INIT_DATA_LEN>,
    const KEY_LEN: usize,
    const INIT_DATA_LEN: usize,
>(
    k: &KeyMaterial<KEY_LEN>,
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
    let k = key::<16>();
    let flat: Vec<u8> = data().as_flattened().to_vec();

    let mut group = c.benchmark_group("modes::cfb::AES_128");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    // Serial: Oj+1 = CIPH_K(Cj), and Cj is the previous block's output.
    group.bench_function("16KiB encrypt -- N=8", |b| {
        b.iter_batched(
            || flat.clone(),
            |mut scratch| {
                cfb_encrypt_in_calls::<Aes128Cfb<Encrypting>, 16, BLOCK_LEN>(
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
                cfb_decrypt_in_calls::<Aes128Cfb<Decrypting>, 16, BLOCK_LEN>(
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
    let k = key::<16>();
    let flat: Vec<u8> = data().as_flattened().to_vec();

    let mut group = c.benchmark_group("modes::cfb8::AES_128");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    group.bench_function("16KiB encrypt -- whole message in one call", |b| {
        b.iter_batched(
            || flat.clone(),
            |mut scratch| {
                cfb_encrypt_in_calls::<Aes128Cfb8<Encrypting>, 16, BLOCK_LEN>(
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
                cfb_decrypt_in_calls::<Aes128Cfb8<Decrypting>, 16, BLOCK_LEN>(
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
    let k = key::<16>();
    let flat: Vec<u8> = data().as_flattened().to_vec();

    let mut group = c.benchmark_group("modes::ctr::AES_128");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    group.bench_function("16KiB encrypt -- N=8 (two fours per call)", |b| {
        b.iter_batched(
            || flat.clone(),
            |mut scratch| {
                cfb_encrypt_in_calls::<Aes128Ctr<Encrypting>, 16, 12>(
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

/// ECB is a thin wrapper over the permutation's batch methods, so this should match `aes_benches`'
/// `encrypt_4blocks` figure; it is here to catch a regression in the wrapper.
fn bench_ecb_aes128(c: &mut Criterion) {
    let k = key::<16>();
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
/// messages it dominates. The key expansion alone is `aes_benches`' `key expansion` group, so the
/// difference is the DRBG. Every mode does the same work here, so one is measured.
fn bench_init(c: &mut Criterion) {
    let k128 = key::<16>();

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
/// and the AAD-only measurement -- the CBC-MAC alone, one unbatched call per block -- should sit
/// close to `aes_benches`' `encrypt_block` figure.
///
/// Decryption does the same work in the opposite order (Sec 6.1 and Sec 6.2), and AAD alongside a
/// payload costs the sum of the two measurements here, so neither is measured separately.
fn bench_ccm_aes128(c: &mut Criterion) {
    let perm = AES128Internal::new(&key::<16>()).unwrap();
    let nonce = [0x24u8; CCM_NONCE_LEN];
    let data = [0xA5u8; DATA_LEN];
    let no_aad: [u8; 0] = [];

    let mut group = c.benchmark_group("modes::ccm::AES_128");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    group.bench_function("encrypt 16KiB, no AAD", |b| {
        b.iter_batched_ref(
            || data,
            |buf| {
                black_box(
                    Aes128CcmMode::encrypt_detached_in_place_nonce(
                        black_box(&perm),
                        &nonce,
                        &no_aad,
                        buf,
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
                Aes128CcmMode::encrypt_detached_in_place_nonce(
                    black_box(&perm),
                    &nonce,
                    black_box(&data),
                    &mut out,
                )
                .unwrap(),
            )
        })
    });

    group.finish();
}

/// The [`AEADCipherEncryptor`] one-shot against the mode's in-place one-shot on the same message.
///
/// Both end in the same packet implementation; the trait form copies the message into the
/// caller's output buffer and draws the nonce. A cheap deterministic RNG, created once outside
/// the timed loop, isolates that draw from OS entropy and DRBG construction.
fn bench_ccm_one_shot_pair(c: &mut Criterion) {
    let key = key::<16>();
    let perm = AES128Internal::new(&key).unwrap();
    let data = [0xA5u8; CCM_BUFFER_LEN];
    let no_aad: [u8; 0] = [];
    let nonce = [0x24u8; CCM_NONCE_LEN];
    let mut rng = FixedSeedRNG::<CCM_NONCE_LEN>::new(nonce);

    let mut group = c.benchmark_group("modes::ccm::one_shot");
    group.throughput(Throughput::Bytes(CCM_BUFFER_LEN as u64));

    group.bench_function("AEADCipherEncryptor::encrypt_detached_rng_out 4KiB", |b| {
        b.iter_batched_ref(
            || [0u8; CCM_BUFFER_LEN],
            |out| {
                black_box(
                    Aes128CcmEncryptor::encrypt_detached_rng_out(
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

    // The same 4 KiB and nonce through the mode's in-place one-shot, for the ratio.
    group.bench_function("CCM::encrypt_detached_in_place_nonce 4KiB", |b| {
        b.iter_batched_ref(
            || data,
            |buf| {
                black_box(
                    Aes128CcmMode::encrypt_detached_in_place_nonce(
                        black_box(&perm),
                        &nonce,
                        &no_aad,
                        buf,
                    )
                    .unwrap(),
                )
            },
            BatchSize::LargeInput,
        )
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
    let key = key::<16>();
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
/// as `aes_benches` shows for the permutation itself.
fn bench_gcm_aes256(c: &mut Criterion) {
    let key = key::<32>();
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

/// CMAC is serial like CBC encryption (SP 800-38B Sec 6.2 step 6 chains every block), so it
/// should come out close to `modes::cbc::AES_128` encryption. The key-object route skips the
/// per-message subkey derivation, one block encryption, which is invisible at 16 KiB.
fn bench_cmac(c: &mut Criterion) {
    let data: Vec<u8> = data().concat();
    let mut group = c.benchmark_group("modes::cmac");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    let key128 = mac_key::<16>();
    group.bench_function("AES_128 MAC::new 16KiB", |b| {
        b.iter(|| black_box(AES_CMAC_128::new(&key128).unwrap().mac(black_box(&data))))
    });
    let key_object_128 = AES128Key::<CMAC>::from_key_material(&key128).unwrap();
    group.bench_function("AES_128 key object 16KiB", |b| {
        b.iter(|| black_box(key_object_128.mac(black_box(&data))))
    });
    let key256 = mac_key::<32>();
    group.bench_function("AES_256 MAC::new 16KiB", |b| {
        b.iter(|| black_box(AES_CMAC_256::new(&key256).unwrap().mac(black_box(&data))))
    });
    let key_object_256 = AES256Key::<CMAC>::from_key_material(&key256).unwrap();
    group.bench_function("AES_256 key object 16KiB", |b| {
        b.iter(|| black_box(key_object_256.mac(black_box(&data))))
    });

    group.finish();
}

criterion_group!(
    benches, bench_aes128cbc, bench_cfb_aes128, bench_cfb8_aes128, bench_ctr_aes128,
    bench_ecb_aes128, bench_ccm_aes128, bench_ccm_one_shot_pair, bench_gcm_aes128,
    bench_gcm_aes256, bench_init, bench_cmac
);
criterion_main!(benches);
