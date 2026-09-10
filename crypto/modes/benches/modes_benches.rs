//! Criterion benchmarks for the modes.
//!
//! The number to watch is the **decrypt/encrypt throughput ratio at N >= 2**. Encryption in both
//! CBC and CFB is serial by construction (SP 800-38A Sec 6.2 and Sec 6.3: each forward cipher input
//! depends on the previous output), so it can only ever use the single-block path. *Decryption* in
//! both is parallel, and this implementation hands blocks to the permutation's batch methods --
//! fours first, then pairs, then the remainder singly: for CBC that is `decrypt_4blocks` /
//! `decrypt_2blocks`, for CFB it is `encrypt_4blocks` / `encrypt_2blocks`, since CFB uses the
//! forward function in both directions. AES overrides only the pair form, so its fours are two
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
//! The `modes::cfb8::AES_128` group measures the other thing worth knowing about CFB8: it spends one
//! full forward cipher per *byte*, so on a 16-byte block it should come out at roughly **1/16** the
//! throughput of CFB over the same 16 KiB. That ratio, against `modes::cfb::AES_128`, is the number
//! to watch; it is inherent to `s = 8` (Sec 6.3 discards `b - s` bits of every output block), not a
//! property of this implementation. Decryption should still beat encryption, because CFB8
//! decryption builds its input blocks in series and then batches the ciphers four at a time while
//! encryption cannot.
//!
//! The cipher works in place, so each measurement runs on a fresh copy of the data made in
//! criterion's untimed setup (`iter_batched`); the copy is not part of the timing.
//!
//! The `modes::cbc::AES_128` and `modes::cfb::AES_128` groups are directly comparable -- same cipher,
//! same data, same call granularity -- so the difference between them is the cost of the mode. CFB
//! never calls the inverse cipher, so on an engine whose inverse is slower than its forward
//! direction, CFB decryption is expected to come out ahead of CBC decryption.

use bouncycastle_aes::{AES_128, AES_256};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{
    AEADCipherEncryptor, Algorithm, BlockCipherDecryptor, BlockCipherEncryptor, ElectronicCodeBook,
    SecurityStrength, StreamCipherDecryptor, StreamCipherEncryptor,
};
use bouncycastle_modes::{Cbc, Ccm, CcmEncryptor, Cfb, Cfb8, Ctr, Decrypting, Ecb, Encrypting};
use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

const BLOCK_LEN: usize = 16;
/// 16 KiB, i.e. 1024 AES blocks.
const NUM_BLOCKS: usize = 1024;
const DATA_LEN: usize = NUM_BLOCKS * BLOCK_LEN;

type Aes128Cbc<Dir> = Cbc<AES_128, Dir, 16, BLOCK_LEN>;
type Aes256Cbc<Dir> = Cbc<AES_256, Dir, 32, BLOCK_LEN>;
type Aes128Cfb<Dir> = Cfb<AES_128, Dir, 16, BLOCK_LEN>;
type Aes256Cfb<Dir> = Cfb<AES_256, Dir, 32, BLOCK_LEN>;
type Aes128Cfb8<Dir> = Cfb8<AES_128, Dir, 16, BLOCK_LEN>;

/// CCM at the parameters the ACVP vectors and most protocols use: a 12-byte nonce and a full
/// 16-byte tag. The direction is in the type as for the other modes, but the two directions are
/// separate aliases here rather than one generic over `Dir`, because CCM's one-shots live on the
/// direction-specific impl blocks.
const CCM_NONCE_LEN: usize = 12;
const CCM_TAG_LEN: usize = 16;
type Aes128CcmEnc = Ccm<AES_128, Encrypting, 16, BLOCK_LEN, CCM_NONCE_LEN, CCM_TAG_LEN>;
type Aes128CcmDec = Ccm<AES_128, Decrypting, 16, BLOCK_LEN, CCM_NONCE_LEN, CCM_TAG_LEN>;

/// The buffering trait adapter needs a compile-time maximum message size. 4 KiB, not the 16 KiB
/// the other groups use, because it is a stack buffer and the trait puts a second one of the same
/// size on the stack at every one-shot call.
const CCM_BUFFER_LEN: usize = 4096;
type Aes128CcmEncryptor =
    CcmEncryptor<AES_128, 16, BLOCK_LEN, CCM_NONCE_LEN, CCM_TAG_LEN, CCM_BUFFER_LEN>;
type Aes128Ctr<Dir> = Ctr<AES_128, Dir, 16, BLOCK_LEN, 12>;
type Aes256Ctr<Dir> = Ctr<AES_256, Dir, 32, BLOCK_LEN, 12>;
type Aes128Ecb<Dir> = Ecb<AES_128, Dir, 16, BLOCK_LEN>;

/// AES-128 with the pair methods **not** overridden, so they fall back to the trait defaults of
/// two single-block calls.
///
/// This exists purely to isolate the value of the pair path. Comparing `Cbc<AES_128, ..>` against
/// `Cbc<UnpairedAes128, ..>` at the *same* `N` holds everything else fixed -- same cipher, same
/// call granularity, same amount of data movement -- so the difference is attributable to
/// `decrypt_2blocks` and nothing else.
///
/// Comparing `N = 1` against `N = 8` does *not* isolate it: encryption, which can never pair, also
/// speeds up substantially between those two, so call granularity dominates that comparison.
struct UnpairedAes128(AES_128);

impl Algorithm for UnpairedAes128 {
    const ALG_NAME: &'static str = "AES-128 (unpaired)";
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

impl ElectronicCodeBook<16, BLOCK_LEN> for UnpairedAes128 {
    fn new(key: &KeyMaterial<16>) -> Result<Self, SymmetricCipherError> {
        Ok(Self(<AES_128 as ElectronicCodeBook<16, BLOCK_LEN>>::new(key)?))
    }
    fn encrypt_block(&self, block: &mut [u8; BLOCK_LEN]) {
        <AES_128 as ElectronicCodeBook<16, BLOCK_LEN>>::encrypt_block(&self.0, block)
    }
    fn decrypt_block(&self, block: &mut [u8; BLOCK_LEN]) {
        <AES_128 as ElectronicCodeBook<16, BLOCK_LEN>>::decrypt_block(&self.0, block)
    }
    // encrypt_2blocks / decrypt_2blocks deliberately left as the trait defaults.
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

    let mut group = c.benchmark_group("modes::cbc::AES_128");
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

    // ---- decryption: parallel, uses decrypt_2blocks for every pair ----
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

    // N=2 is one pair and N=8 two fours (four pairs, for AES), so every block goes through
    // decrypt_2blocks.
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

    group.bench_function("16KiB decrypt -- N=8 (all fours)", |b| {
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
    // This pair of numbers -- and only this pair -- measures what `decrypt_2blocks` buys.
    group.bench_function("16KiB decrypt -- N=8, pair path (2blocks overridden)", |b| {
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

    let mut group = c.benchmark_group("modes::cbc::AES_256");
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

    group.bench_function("16KiB decrypt -- N=8 (all fours)", |b| {
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
        enc.do_encrypt(piece).unwrap();
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
        dec.do_decrypt(piece).unwrap();
    }
}

fn bench_cfb_aes128(c: &mut Criterion) {
    let k = key::<16>();
    let blocks = data();
    let flat: Vec<u8> = blocks.as_flattened().to_vec();

    let mut group = c.benchmark_group("modes::cfb::AES_128");
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
                    cfb_encrypt_in_calls::<Aes128Cfb<Encrypting>, 16, BLOCK_LEN>(
                        &k, &mut scratch, call_len,
                    );
                    black_box(&scratch);
                },
                BatchSize::LargeInput,
            )
        });
    }

    // ---- decryption: parallel, and uses `encrypt_4blocks` / `encrypt_2blocks` -- the FORWARD
    // batch methods ----
    let (mut enc, iv) = Aes128Cfb::<Encrypting>::do_encrypt_init(&k).unwrap();
    let mut ciphertext = flat.clone();
    enc.do_encrypt(&mut ciphertext).unwrap();

    for (name, call_len) in [
        // N=1 never forms a pair, so this is the single-block path: the ratio against encrypt
        // should be about 1.
        ("16KiB decrypt -- N=1 (no pairing)", BLOCK_LEN),
        // N=2 and N=8 are all batches (N=8 two fours), so every block goes through a batch method.
        ("16KiB decrypt -- N=2 (all pairs)", 2 * BLOCK_LEN),
        ("16KiB decrypt -- N=8 (all fours)", 8 * BLOCK_LEN),
        // N=9 is two fours plus a one-block remainder, so it exercises the tail path too.
        ("16KiB decrypt -- N=9 (pairs + remainder)", 9 * BLOCK_LEN),
        // As for encryption: 7 blocks plus 13 bytes per call. Compare with N=8.
        ("16KiB decrypt -- 125-byte calls (byte path at both ends)", 125),
    ] {
        group.bench_function(name, |b| {
            b.iter_batched(
                || ciphertext.clone(),
                |mut scratch| {
                    cfb_decrypt_in_calls::<Aes128Cfb<Decrypting>, 16, BLOCK_LEN>(
                        &k, &iv, &mut scratch, call_len,
                    );
                    black_box(&scratch);
                },
                BatchSize::LargeInput,
            )
        });
    }

    // The controlled comparison: identical N, identical cipher, pair methods overridden vs not.
    // This pair of numbers -- and only this pair -- measures what `encrypt_2blocks` buys CFB.
    group.bench_function("16KiB decrypt -- N=8, pair path (2blocks overridden)", |b| {
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

    group.bench_function("16KiB decrypt -- N=8, no pair path (trait default)", |b| {
        b.iter_batched(
            || ciphertext.clone(),
            |mut scratch| {
                cfb_decrypt_in_calls::<UnpairedAes128Cfb<Decrypting>, 16, BLOCK_LEN>(
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

    let mut group = c.benchmark_group("modes::cfb::AES_256");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    group.bench_function("16KiB encrypt -- N=8", |b| {
        b.iter_batched(
            || flat.clone(),
            |mut scratch| {
                cfb_encrypt_in_calls::<Aes256Cfb<Encrypting>, 32, BLOCK_LEN>(
                    &k,
                    &mut scratch,
                    8 * BLOCK_LEN,
                );
                black_box(&scratch);
            },
            BatchSize::LargeInput,
        )
    });

    let (mut enc, iv) = Aes256Cfb::<Encrypting>::do_encrypt_init(&k).unwrap();
    let mut ciphertext = flat.clone();
    enc.do_encrypt(&mut ciphertext).unwrap();

    group.bench_function("16KiB decrypt -- N=8 (all fours)", |b| {
        b.iter_batched(
            || ciphertext.clone(),
            |mut scratch| {
                cfb_decrypt_in_calls::<Aes256Cfb<Decrypting>, 32, BLOCK_LEN>(
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
/// through `encrypt_4blocks` / `encrypt_2blocks` (SP 800-38A Sec 6.3's parallel decryption), so it
/// should be substantially faster than encryption -- the same batch effect CBC and CFB show, at
/// byte granularity.
fn bench_cfb8_aes128(c: &mut Criterion) {
    let k = key::<16>();
    let flat: Vec<u8> = data().as_flattened().to_vec();

    let mut group = c.benchmark_group("modes::cfb8::AES_128");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    // Serial by construction: I_{j+1} needs Cj, which this call just produced.
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
    enc.do_encrypt(&mut ciphertext).unwrap();

    for (name, call_len) in [
        // One call: fours, then pairs, then the tail. This is the batched path.
        ("16KiB decrypt -- whole message in one call (batched)", DATA_LEN),
        // 8-byte calls: exactly two four-block batches per call.
        ("16KiB decrypt -- 8-byte calls (two batches each)", 8),
        // 1-byte calls: never batches, so this is the cost of the serial path on the decrypt side
        // and the controlled comparison for what batching buys.
        ("16KiB decrypt -- 1-byte calls (no batching)", 1),
    ] {
        group.bench_function(name, |b| {
            b.iter_batched(
                || ciphertext.clone(),
                |mut scratch| {
                    cfb_decrypt_in_calls::<Aes128Cfb8<Decrypting>, 16, BLOCK_LEN>(
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

/// CTR: the only mode here whose **encryption** is parallel too.
///
/// Counter blocks depend on nothing but the nonce and the index (SP 800-38A Sec 6.5), so unlike CBC
/// and CFB there is no serial direction: encryption should show the same `N >= 2` speed-up that only
/// decryption shows for the feedback modes, and the two directions should measure the same, since
/// they are the same operation. That symmetry is the number to watch here.
fn bench_ctr_aes128(c: &mut Criterion) {
    let k = key::<16>();
    let flat: Vec<u8> = data().as_flattened().to_vec();

    let mut group = c.benchmark_group("modes::ctr::AES_128");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    for (name, call_len) in [
        // N=1 never forms a pair: the single-block path, and the baseline for the batch effect.
        ("16KiB encrypt -- N=1 (no batching)", BLOCK_LEN),
        ("16KiB encrypt -- N=2 (all pairs)", 2 * BLOCK_LEN),
        ("16KiB encrypt -- N=8 (two fours per call)", 8 * BLOCK_LEN),
        // Calls that are not a whole number of blocks, so each end goes byte by byte.
        ("16KiB encrypt -- 125-byte calls (byte path at both ends)", 125),
    ] {
        group.bench_function(name, |b| {
            b.iter_batched(
                || flat.clone(),
                |mut scratch| {
                    cfb_encrypt_in_calls::<Aes128Ctr<Encrypting>, 16, 12>(
                        &k, &mut scratch, call_len,
                    );
                    black_box(&scratch);
                },
                BatchSize::LargeInput,
            )
        });
    }

    let (mut enc, nonce) = Aes128Ctr::<Encrypting>::do_encrypt_init(&k).unwrap();
    let mut ciphertext = flat.clone();
    enc.do_encrypt(&mut ciphertext).unwrap();

    for (name, call_len) in [
        ("16KiB decrypt -- N=1 (no batching)", BLOCK_LEN),
        ("16KiB decrypt -- N=8 (two fours per call)", 8 * BLOCK_LEN),
    ] {
        group.bench_function(name, |b| {
            b.iter_batched(
                || ciphertext.clone(),
                |mut scratch| {
                    cfb_decrypt_in_calls::<Aes128Ctr<Decrypting>, 16, 12>(
                        &k, &nonce, &mut scratch, call_len,
                    );
                    black_box(&scratch);
                },
                BatchSize::LargeInput,
            )
        });
    }

    group.finish();
}

/// AES-256 CTR, for the same key-length comparison the other modes carry.
fn bench_ctr_aes256(c: &mut Criterion) {
    let k = key::<32>();
    let flat: Vec<u8> = data().as_flattened().to_vec();

    let mut group = c.benchmark_group("modes::ctr::AES_256");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    group.bench_function("16KiB encrypt -- N=8", |b| {
        b.iter_batched(
            || flat.clone(),
            |mut scratch| {
                cfb_encrypt_in_calls::<Aes256Ctr<Encrypting>, 32, 12>(
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

/// ECB has no chaining, so *both* directions batch (SP 800-38A Sec 6.1: forward and inverse
/// cipher functions "can be computed in parallel"). Encryption should therefore show the same
/// N >= 2 speed-up that only decryption shows for CBC and CFB, and the encrypt/decrypt gap should be
/// just the permutation's own forward/inverse cost difference.
fn bench_ecb_aes128(c: &mut Criterion) {
    let k = key::<16>();
    let blocks = data();

    let mut group = c.benchmark_group("modes::ecb::AES_128");
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

    group.bench_function("16KiB encrypt -- N=8 (fours)", |b| {
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

    group.bench_function("16KiB decrypt -- N=8 (fours)", |b| {
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

    group.bench_function("AES_128 do_encrypt_init (key schedule + IV)", |b| {
        b.iter(|| black_box(Aes128Cbc::<Encrypting>::do_encrypt_init(black_box(&k128)).unwrap().1))
    });
    group.bench_function("AES_128 do_decrypt_init (key schedule only)", |b| {
        b.iter(|| {
            black_box(Aes128Cbc::<Decrypting>::do_decrypt_init(black_box(&k128), &iv).unwrap())
        })
    });
    group.bench_function("AES_256 do_decrypt_init (key schedule only)", |b| {
        b.iter(|| {
            black_box(Aes256Cbc::<Decrypting>::do_decrypt_init(black_box(&k256), &iv).unwrap())
        })
    });

    // CFB does exactly the same work here -- one key expansion, plus an IV draw when encrypting --
    // so these should match the CBC numbers. A divergence would mean one mode is doing something
    // extra at construction time.
    group.bench_function("AES_128 do_encrypt_init, CFB (key schedule + IV)", |b| {
        b.iter(|| black_box(Aes128Cfb::<Encrypting>::do_encrypt_init(black_box(&k128)).unwrap().1))
    });
    group.bench_function("AES_128 do_decrypt_init, CFB (key schedule only)", |b| {
        b.iter(|| {
            black_box(Aes128Cfb::<Decrypting>::do_decrypt_init(black_box(&k128), &iv).unwrap())
        })
    });

    group.finish();
}

/// CCM (SP 800-38C), which is the only authenticated mode here and the only one that costs
/// **two** cipher calls per block.
///
/// Sec 5.2 builds CCM out of CTR for confidentiality and CBC-MAC for authenticity, over the same
/// key, so every payload block goes through the forward cipher twice: once as a counter block and
/// once as a CBC-MAC input. The number to watch is CCM against the CTR group on the same data, and
/// **which** CTR number matters:
///
/// * against `modes::ctr::AES_128/16KiB encrypt -- N=1`, CTR's unbatched single-block path, CCM
///   should be **about half** -- two cipher calls per block instead of one, and nothing else;
/// * against CTR's `N=8` batched path, CCM should be about **a quarter**, because CCM cannot batch
///   at all and CTR's pair path roughly doubles it.
///
/// Measured on the reference machine: 26 MiB/s for CCM against 51 MiB/s for CTR `N=1` and
/// 102 MiB/s for CTR `N=8`, i.e. both ratios as predicted. Materially worse than half of `N=1`
/// would mean something other than the two unavoidable cipher calls is dominating.
///
/// Neither half of CCM can be batched, and that is inherent, not an omission. The CBC-MAC is serial
/// by construction (Sec 6.1 step 3: `Yi` is the cipher of `Bi XOR Yi-1`), so unlike `Ctr` and the
/// decrypt direction of `Cbc`/`Cfb` there is no pair or four path to take, and the counter blocks
/// are generated one at a time to stay interleaved with it. So CCM is deliberately absent from the
/// batch-path comparison the other groups are about.
///
/// Encryption and decryption should be within noise of each other: Sec 6.1 and Sec 6.2 do the same
/// work in the opposite order (MAC-then-XOR versus XOR-then-MAC), and only the forward cipher is
/// ever used, so the inverse cipher's cost never enters.
///
/// The AAD is measured separately, and is the cheap half: it is absorbed into the CBC-MAC only,
/// one cipher call per block rather than two, so AAD-only throughput should be about twice the
/// payload's and about the same as CTR's.
fn bench_ccm_aes128(c: &mut Criterion) {
    let key = key::<16>();
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
                    Aes128CcmEnc::encrypt_detached(
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

    // Encrypt once outside the loop so decryption measures a ciphertext that authenticates: a
    // failing tag check would short-circuit the comparison and measure the wrong thing.
    let mut ciphertext = [0u8; DATA_LEN];
    let (_, tag) =
        Aes128CcmEnc::encrypt_detached(&key, &nonce, &no_aad, &data, &mut ciphertext).unwrap();

    group.bench_function("decrypt 16KiB, no AAD", |b| {
        b.iter_batched_ref(
            || [0u8; DATA_LEN],
            |out| {
                black_box(
                    Aes128CcmDec::decrypt_detached(
                        black_box(&key),
                        &nonce,
                        &no_aad,
                        black_box(&ciphertext),
                        &tag,
                        out,
                    )
                    .unwrap(),
                )
            },
            BatchSize::LargeInput,
        )
    });

    // The same payload with 16 KiB of AAD alongside it. The difference from the no-AAD case is one
    // cipher call per AAD block, so this should cost about 1.5x the no-AAD case for 2x the bytes.
    group.bench_function("encrypt 16KiB with 16KiB AAD", |b| {
        b.iter_batched_ref(
            || [0u8; DATA_LEN],
            |out| {
                black_box(
                    Aes128CcmEnc::encrypt_detached(
                        black_box(&key),
                        &nonce,
                        black_box(&data),
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
    // empty-payload degenerate case. One cipher call per block, so this is the CTR-comparable half.
    group.bench_function("authenticate 16KiB AAD, empty payload", |b| {
        b.iter(|| {
            let mut out: [u8; 0] = [];
            black_box(
                Aes128CcmEnc::encrypt_detached(
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

/// The buffering [`AEADCipherEncryptor`] path against the direct one, on a message that fits the
/// buffer.
///
/// The two do identical cipher work -- the trait path ends in the same `Ccm` -- so the gap is
/// purely the two extra copies `BUFFER_LEN` forces: the caller's plaintext into the encryptor's
/// buffer, and the finalization buffer into the caller's output.
///
/// Measured on the reference machine, that gap is **within noise** (25.5 against 25.7 MiB/s): two
/// `memcpy`s of 4 KiB are nothing beside 512 AES calls. So the reason to prefer `Ccm` directly is
/// the `2 * BUFFER_LEN` of memory and the compile-time message cap, not speed. If this ratio ever
/// moves far from 1, the buffering path has started doing real work it should not be.
fn bench_ccm_buffering_pair(c: &mut Criterion) {
    let key = key::<16>();
    let data = [0xA5u8; CCM_BUFFER_LEN];
    let no_aad: [u8; 0] = [];

    let mut group = c.benchmark_group("modes::ccm::buffering");
    group.throughput(Throughput::Bytes(CCM_BUFFER_LEN as u64));

    group.bench_function("AEADCipherEncryptor::encrypt_out 4KiB", |b| {
        b.iter_batched_ref(
            || [0u8; CCM_BUFFER_LEN],
            |out| {
                black_box(
                    Aes128CcmEncryptor::encrypt_out(
                        black_box(&key),
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

    // The same 4 KiB through `Ccm` directly, for the ratio. This one also draws no nonce, since
    // `Ccm` takes it from the caller, so `bench_ccm_init` covers that difference separately.
    let nonce = [0x24u8; CCM_NONCE_LEN];
    group.bench_function("Ccm::encrypt_detached 4KiB", |b| {
        b.iter_batched_ref(
            || [0u8; CCM_BUFFER_LEN],
            |out| {
                black_box(
                    Aes128CcmEnc::encrypt_detached(
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

    group.finish();
}

criterion_group!(
    benches, bench_aes128, bench_aes256, bench_cfb_aes128, bench_cfb_aes256, bench_cfb8_aes128,
    bench_ctr_aes128, bench_ctr_aes256, bench_ecb_aes128, bench_ccm_aes128,
    bench_ccm_buffering_pair, bench_init
);
criterion_main!(benches);
