//! Criterion benchmarks for the modes.
//!
//! The number to watch is the **decrypt/encrypt throughput ratio at N >= 2**. Encryption in both
//! CBC and CFB is serial by construction (SP 800-38A Sec 6.2 and Sec 6.3: each forward cipher input
//! depends on the previous output), so it can only ever use the single-block path. *Decryption* in
//! both is parallel, and this implementation hands blocks to the permutation's batch methods --
//! eights first, then pairs, then the remainder singly: for CBC that is `decrypt_blocks8` /
//! `decrypt_blocks2`, for CFB it is `encrypt_blocks8` / `encrypt_blocks2`, since CFB uses the
//! forward function in both directions. AES overrides only the pair form, so its eights are four
//! pairs. With the bit-sliced AES, whose two-block path costs barely more than one block,
//! decryption should therefore run at roughly twice the throughput of encryption. That gap is the
//! entire justification for the batch methods on `ElectronicCodeBook`, so if it disappears,
//! something has stopped taking the pair path.
//!
//! `N = 1` is included to show the effect vanishing: with one block there is no pair to form, so
//! decryption falls back to the single-block path and the ratio should be about 1.
//!
//! CFB is a stream cipher (`StreamCipherEncryptor` / `StreamCipherDecryptor`), so `N` there is
//! simply the call length in blocks; the same 16 KiB goes through `do_encrypt` / `do_decrypt` as
//! `16 * N`-byte slices. Two extra CFB measurements use calls that are *not* a whole number of
//! blocks: every such call ends mid-segment and the next one starts by finishing it byte by byte,
//! so they show what the byte path costs relative to the block path at a comparable call length.
//!
//! The `modes::cfb8::Aes128` group measures the other thing worth knowing about CFB8: it spends one
//! full forward cipher per *byte*, so on a 16-byte block it should come out at roughly **1/16** the
//! throughput of CFB over the same 16 KiB. That ratio, against `modes::cfb::Aes128`, is the number
//! to watch; it is inherent to `s = 8` (Sec 6.3 discards `b - s` bits of every output block), not a
//! property of this implementation. Decryption should still beat encryption, because CFB8
//! decryption builds its input blocks in series and then batches the ciphers eight at a time while
//! encryption cannot.
//!
//! The cipher works in place, so each measurement runs on a fresh copy of the data made in
//! criterion's untimed setup (`iter_batched`); the copy is not part of the timing.
//!
//! The `modes::cbc::Aes128` and `modes::cfb::Aes128` groups are directly comparable -- same cipher,
//! same data, same call granularity -- so the difference between them is the cost of the mode. CFB
//! never calls the inverse cipher, so on an engine whose inverse is slower than its forward
//! direction, CFB decryption is expected to come out ahead of CBC decryption.

use bouncycastle_aes_lowmemory::{Aes128, Aes256};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{
    Algorithm, BlockCipherDecryptor, BlockCipherEncryptor, ElectronicCodeBook, SecurityStrength,
    StreamCipherDecryptor, StreamCipherEncryptor,
};
use bouncycastle_modes::{Cbc, Cfb, Cfb8, Decrypting, Ecb, Encrypting};
use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

const BLOCK_LEN: usize = 16;
/// 16 KiB, i.e. 1024 AES blocks.
const NUM_BLOCKS: usize = 1024;
const DATA_LEN: usize = NUM_BLOCKS * BLOCK_LEN;

type Aes128Cbc<Dir> = Cbc<Aes128, Dir, 16, BLOCK_LEN>;
type Aes256Cbc<Dir> = Cbc<Aes256, Dir, 32, BLOCK_LEN>;
type Aes128Cfb<Dir> = Cfb<Aes128, Dir, 16, BLOCK_LEN>;
type Aes256Cfb<Dir> = Cfb<Aes256, Dir, 32, BLOCK_LEN>;
type Aes128Cfb8<Dir> = Cfb8<Aes128, Dir, 16, BLOCK_LEN>;
type Aes128Ecb<Dir> = Ecb<Aes128, Dir, 16, BLOCK_LEN>;

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

impl ElectronicCodeBook<16, BLOCK_LEN> for UnpairedAes128 {
    fn new(key: &KeyMaterial<16>) -> Result<Self, SymmetricCipherError> {
        Ok(Self(<Aes128 as ElectronicCodeBook<16, BLOCK_LEN>>::new(key)?))
    }
    fn encrypt_block(&self, block: &mut [u8; BLOCK_LEN]) {
        <Aes128 as ElectronicCodeBook<16, BLOCK_LEN>>::encrypt_block(&self.0, block)
    }
    fn decrypt_block(&self, block: &mut [u8; BLOCK_LEN]) {
        <Aes128 as ElectronicCodeBook<16, BLOCK_LEN>>::decrypt_block(&self.0, block)
    }
    // encrypt_blocks2 / decrypt_blocks2 deliberately left as the trait defaults.
}

type UnpairedAes128Cbc<Dir> = Cbc<UnpairedAes128, Dir, 16, BLOCK_LEN>;
type UnpairedAes128Cfb<Dir> = Cfb<UnpairedAes128, Dir, 16, BLOCK_LEN>;
type UnpairedAes128Ecb<Dir> = Ecb<UnpairedAes128, Dir, 16, BLOCK_LEN>;

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
        enc.do_encrypt_blocks(chunk).unwrap();
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

    // N=2 is one pair and N=8 one eight (four pairs, for AES), so every block goes through
    // decrypt_blocks2.
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
        enc.do_encrypt_blocks(chunk).unwrap();
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

/// Runs the 16 KiB through a CFB encryptor in `call_len`-byte calls.
fn cfb_encrypt_in_calls<E: StreamCipherEncryptor<KEY_LEN, BLOCK_LEN>, const KEY_LEN: usize>(
    k: &KeyMaterial<KEY_LEN>,
    scratch: &mut [u8],
    call_len: usize,
) {
    let (mut enc, _) = E::do_encrypt_init(k).unwrap();
    for piece in scratch.chunks_mut(call_len) {
        enc.do_encrypt(piece).unwrap();
    }
}

/// Runs the 16 KiB through a CFB decryptor in `call_len`-byte calls.
fn cfb_decrypt_in_calls<D: StreamCipherDecryptor<KEY_LEN, BLOCK_LEN>, const KEY_LEN: usize>(
    k: &KeyMaterial<KEY_LEN>,
    iv: &[u8; BLOCK_LEN],
    scratch: &mut [u8],
    call_len: usize,
) {
    let mut dec = D::do_decrypt_init(k, iv).unwrap();
    for piece in scratch.chunks_mut(call_len) {
        dec.do_decrypt(piece).unwrap();
    }
}

fn bench_cfb_aes128(c: &mut Criterion) {
    let k = key::<16>();
    let blocks = data();
    let flat: Vec<u8> = blocks.as_flattened().to_vec();

    let mut group = c.benchmark_group("modes::cfb::Aes128");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    // ---- encryption: serial. Oj+1 = CIPH_K(Cj), and Cj is the previous call's output ----
    for (name, call_len) in [
        ("16KiB encrypt -- N=1", BLOCK_LEN),
        ("16KiB encrypt -- N=8", 8 * BLOCK_LEN),
        // 125 bytes: 7 blocks and 13 bytes, so every call finishes the segment the previous one
        // left open, then does whole blocks, then opens a new segment. Compare with N=8.
        ("16KiB encrypt -- 125-byte calls (byte path at both ends)", 125),
    ] {
        group.bench_function(name, |b| {
            b.iter_batched(
                || flat.clone(),
                |mut scratch| {
                    cfb_encrypt_in_calls::<Aes128Cfb<Encrypting>, 16>(&k, &mut scratch, call_len);
                    black_box(&scratch);
                },
                BatchSize::LargeInput,
            )
        });
    }

    // ---- decryption: parallel, and uses `encrypt_blocks8` / `encrypt_blocks2` -- the FORWARD
    // batch methods ----
    let (mut enc, iv) = Aes128Cfb::<Encrypting>::do_encrypt_init(&k).unwrap();
    let mut ciphertext = flat.clone();
    enc.do_encrypt(&mut ciphertext).unwrap();

    for (name, call_len) in [
        // N=1 never forms a pair, so this is the single-block path: the ratio against encrypt
        // should be about 1.
        ("16KiB decrypt -- N=1 (no pairing)", BLOCK_LEN),
        // N=2 and N=8 are all pairs (N=8 one eight), so every block goes through a batch method.
        ("16KiB decrypt -- N=2 (all pairs)", 2 * BLOCK_LEN),
        ("16KiB decrypt -- N=8 (all pairs)", 8 * BLOCK_LEN),
        // N=9 is one eight plus a one-block remainder, so it exercises the tail path too.
        ("16KiB decrypt -- N=9 (pairs + remainder)", 9 * BLOCK_LEN),
        // As for encryption: 7 blocks plus 13 bytes per call. Compare with N=8.
        ("16KiB decrypt -- 125-byte calls (byte path at both ends)", 125),
    ] {
        group.bench_function(name, |b| {
            b.iter_batched(
                || ciphertext.clone(),
                |mut scratch| {
                    cfb_decrypt_in_calls::<Aes128Cfb<Decrypting>, 16>(
                        &k, &iv, &mut scratch, call_len,
                    );
                    black_box(&scratch);
                },
                BatchSize::LargeInput,
            )
        });
    }

    // The controlled comparison: identical N, identical cipher, pair methods overridden vs not.
    // This pair of numbers -- and only this pair -- measures what `encrypt_blocks2` buys CFB.
    group.bench_function("16KiB decrypt -- N=8, pair path (blocks2 overridden)", |b| {
        b.iter_batched(
            || ciphertext.clone(),
            |mut scratch| {
                cfb_decrypt_in_calls::<Aes128Cfb<Decrypting>, 16>(
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

    group.bench_function("16KiB decrypt -- N=8, no pair path (trait default)", |b| {
        b.iter_batched(
            || ciphertext.clone(),
            |mut scratch| {
                cfb_decrypt_in_calls::<UnpairedAes128Cfb<Decrypting>, 16>(
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

fn bench_cfb_aes256(c: &mut Criterion) {
    let k = key::<32>();
    let flat: Vec<u8> = data().as_flattened().to_vec();

    let mut group = c.benchmark_group("modes::cfb::Aes256");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    group.bench_function("16KiB encrypt -- N=8", |b| {
        b.iter_batched(
            || flat.clone(),
            |mut scratch| {
                cfb_encrypt_in_calls::<Aes256Cfb<Encrypting>, 32>(&k, &mut scratch, 8 * BLOCK_LEN);
                black_box(&scratch);
            },
            BatchSize::LargeInput,
        )
    });

    let (mut enc, iv) = Aes256Cfb::<Encrypting>::do_encrypt_init(&k).unwrap();
    let mut ciphertext = flat.clone();
    enc.do_encrypt(&mut ciphertext).unwrap();

    group.bench_function("16KiB decrypt -- N=8 (all pairs)", |b| {
        b.iter_batched(
            || ciphertext.clone(),
            |mut scratch| {
                cfb_decrypt_in_calls::<Aes256Cfb<Decrypting>, 32>(
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

/// CFB8: one forward cipher per byte, so ~1/16 of CFB's throughput on a 16-byte block.
///
/// Encryption is strictly serial. Decryption builds its input blocks in series and then runs them
/// through `encrypt_blocks8` / `encrypt_blocks2` (SP 800-38A Sec 6.3's parallel decryption), so it
/// should be substantially faster than encryption -- the same batch effect CBC and CFB show, at
/// byte granularity.
fn bench_cfb8_aes128(c: &mut Criterion) {
    let k = key::<16>();
    let flat: Vec<u8> = data().as_flattened().to_vec();

    let mut group = c.benchmark_group("modes::cfb8::Aes128");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    // Serial by construction: I_{j+1} needs Cj, which this call just produced.
    group.bench_function("16KiB encrypt -- whole message in one call", |b| {
        b.iter_batched(
            || flat.clone(),
            |mut scratch| {
                cfb_encrypt_in_calls::<Aes128Cfb8<Encrypting>, 16>(&k, &mut scratch, DATA_LEN);
                black_box(&scratch);
            },
            BatchSize::LargeInput,
        )
    });

    let (mut enc, iv) = Aes128Cfb8::<Encrypting>::do_encrypt_init(&k).unwrap();
    let mut ciphertext = flat.clone();
    enc.do_encrypt(&mut ciphertext).unwrap();

    for (name, call_len) in [
        // One call: eights, then pairs, then the tail. This is the batched path.
        ("16KiB decrypt -- whole message in one call (batched)", DATA_LEN),
        // 8-byte calls: still exactly one eight-block batch per call.
        ("16KiB decrypt -- 8-byte calls (one batch each)", 8),
        // 1-byte calls: never batches, so this is the cost of the serial path on the decrypt side
        // and the controlled comparison for what batching buys.
        ("16KiB decrypt -- 1-byte calls (no batching)", 1),
    ] {
        group.bench_function(name, |b| {
            b.iter_batched(
                || ciphertext.clone(),
                |mut scratch| {
                    cfb_decrypt_in_calls::<Aes128Cfb8<Decrypting>, 16>(
                        &k, &iv, &mut scratch, call_len,
                    );
                    black_box(&scratch);
                },
                BatchSize::LargeInput,
            )
        });
    }

    group.finish();
}

/// ECB has no chaining, so *both* directions batch (SP 800-38A Sec 6.1: forward and inverse
/// cipher functions "can be computed in parallel"). Encryption should therefore show the same
/// N >= 2 speed-up that only decryption shows for CBC and CFB, and the encrypt/decrypt gap should be
/// just the permutation's own forward/inverse cost difference.
fn bench_ecb_aes128(c: &mut Criterion) {
    let k = key::<16>();
    let blocks = data();

    let mut group = c.benchmark_group("modes::ecb::Aes128");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    group.bench_function("16KiB encrypt -- N=1 (no batching)", |b| {
        b.iter_batched(
            || blocks.clone(),
            |mut scratch| {
                let (mut enc, _) = Aes128Ecb::<Encrypting>::do_encrypt_init(&k).unwrap();
                for block in scratch.iter_mut() {
                    enc.do_encrypt(block).unwrap();
                }
                black_box(&scratch);
            },
            BatchSize::LargeInput,
        )
    });

    group.bench_function("16KiB encrypt -- N=8 (eights)", |b| {
        b.iter_batched(
            || blocks.clone(),
            |mut scratch| {
                let (mut enc, _) = Aes128Ecb::<Encrypting>::do_encrypt_init(&k).unwrap();
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

    group.bench_function("16KiB decrypt -- N=8 (eights)", |b| {
        b.iter_batched(
            || blocks.clone(),
            |mut scratch| {
                let mut dec = Aes128Ecb::<Decrypting>::do_decrypt_init(&k, &[]).unwrap();
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

    // The controlled comparison: identical N, identical cipher, batch methods overridden vs not.
    group.bench_function("16KiB encrypt -- N=8, no pair path (trait default)", |b| {
        b.iter_batched(
            || blocks.clone(),
            |mut scratch| {
                let (mut enc, _) = UnpairedAes128Ecb::<Encrypting>::do_encrypt_init(&k).unwrap();
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

    group.finish();
}

/// `do_*_init` includes a key expansion, and for encryption also an IV draw from the OS-backed
/// DRBG. Worth its own measurement, because for short messages it dominates.
fn bench_init(c: &mut Criterion) {
    let k128 = key::<16>();
    let k256 = key::<32>();
    let iv = [0u8; BLOCK_LEN];

    let mut group = c.benchmark_group("modes::init");

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

    // CFB does exactly the same work here -- one key expansion, plus an IV draw when encrypting --
    // so these should match the CBC numbers. A divergence would mean one mode is doing something
    // extra at construction time.
    group.bench_function("Aes128 do_encrypt_init, CFB (key schedule + IV)", |b| {
        b.iter(|| black_box(Aes128Cfb::<Encrypting>::do_encrypt_init(black_box(&k128)).unwrap().1))
    });
    group.bench_function("Aes128 do_decrypt_init, CFB (key schedule only)", |b| {
        b.iter(|| {
            black_box(Aes128Cfb::<Decrypting>::do_decrypt_init(black_box(&k128), &iv).unwrap())
        })
    });

    group.finish();
}

criterion_group!(
    benches, bench_aes128, bench_aes256, bench_cfb_aes128, bench_cfb_aes256, bench_cfb8_aes128,
    bench_ecb_aes128, bench_init
);
criterion_main!(benches);
