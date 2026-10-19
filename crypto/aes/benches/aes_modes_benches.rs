//! Criterion benchmarks for the modes.
//!
//! The number to watch is the **decrypt/encrypt throughput ratio at N >= 2**. Encryption in both
//! CBC and CFB is serial by construction (SP 800-38A Sec 6.2 and Sec 6.3: each forward cipher input
//! depends on the previous output), so it can only ever use the single-block path. *Decryption* in
//! both is parallel, and this implementation hands blocks to the permutation's batch methods --
//! fours first, then pairs, then the remainder singly: for CBC that is `decrypt_4blocks` /
//! `decrypt_2blocks`, for CFB it is `encrypt_4blocks` / `encrypt_2blocks`, since CFB uses the
//! forward function in both directions. AES's natural unit is a pair, so its fours are two
//! pairs. With the bit-sliced AES, whose two-block path costs barely more than one block,
//! decryption should therefore run at roughly twice the throughput of encryption. That gap is the
//! entire justification for the batch methods on `ElectronicCodeBook`, so if it disappears,
//! something has stopped taking the pair path.
//!
//! `N = 1` is included to show the effect vanishing: with one block there is no pair to form, so
//! decryption falls back to the single-block path and the ratio should be about 1.
//!
//! CFB is a stream cipher (`StreamCipherEncryptor` / `StreamCipherDecryptor`), so `N` there is
//! simply the call length in blocks; the same 16 KiB goes through `do_encrypt_inplace` /
//! `do_decrypt_inplace` as `16 * N`-byte slices. Two extra CFB measurements use calls that are
//! *not* a whole number of blocks: every such call ends mid-segment and the next one starts by
//! finishing it byte by byte, so they show what the byte path costs relative to the block path at
//! a comparable call length.
//!
//! The `modes::cfb8::AES_128` group measures the other thing worth knowing about CFB8: it spends one
//! full forward cipher per *byte*, so on a 16-byte block it should come out at roughly **1/16** the
//! throughput of CFB over the same 16 KiB. That ratio, against `modes::cfb::AES_128`, is the number
//! to watch; it is inherent to `s = 8` (Sec 6.3 discards `b - s` bits of every output block), not a
//! property of this implementation. Decryption should still beat encryption, because CFB8
//! decryption builds its input blocks in series and then batches the ciphers four at a time while
//! encryption cannot.
//!
//! The `modes::gcm::AES_128` group is GCM against CTR: GCM is CTR plus GHASH over the ciphertext
//! and AAD (SP 800-38D Sec 7.1), and its CTR half batches exactly as `modes::ctr::AES_128` does, so
//! the difference between the two groups' 16 KiB encrypt figures is the cost of the table-free
//! GF(2^128) multiply, one per block. The AAD-only measurement is GMAC (Sec 5.2), which is that
//! multiply with no cipher calls at all beyond the two for `H` and `J0`.
//!
//! The cipher works in place, so each measurement runs on a fresh copy of the data made in
//! criterion's untimed setup (`iter_batched`); the copy is not part of the timing.
//!
//! The `modes::cbc::AES_128` and `modes::cfb::AES_128` groups are directly comparable -- same cipher,
//! same data, same call granularity -- so the difference between them is the cost of the mode. CFB
//! never calls the inverse cipher, so on an engine whose inverse is slower than its forward
//! direction, CFB decryption is expected to come out ahead of CBC decryption.

use bouncycastle_aes::hazmat::{AES128Internal, AES256Internal};
use bouncycastle_aes::{AES128Key, AES256Key};
use bouncycastle_cipher::modes::hazmat::{ECB, Ecb};
use bouncycastle_cipher::modes::{
    Blocks, CBC, CCM, CCM_Packet, CFB, CFB8, CMAC, CTR, Cbc, Cfb, Cfb8, Ctr, GCM, GCM_NONCE_LEN,
    GMAC, ModeNames,
};
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::hazmat::{
    AeadDeclaredDecryptMode, AeadDeclaredEncryptMode, BlockDecryptMode, BlockPermutation,
    EcbDecryptionKey, EcbEncryptMode, EcbEncryptionKey, ElectronicCodeBook, Mode,
    SymmetricDecryptMode,
};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{
    AeadDecryptionKey, AeadEncryptionKey, BlockDecryptionKey, BlockEncryptionKey, FromKeyMaterial,
    MacGenerationKey, SymmetricDecryptionKey, SymmetricEncryptionKey,
};
use bouncycastle_core::traits::{
    Algorithm, BlockCipherDecryptor, BlockCipherEncryptor, StreamCipherDecryptor,
    StreamCipherEncryptor, SymmetricCipherEncryptor,
};
use bouncycastle_core_test_framework::FixedSeedRNG;
use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

const BLOCK_LEN: usize = 16;
/// 16 KiB, i.e. 1024 AES blocks.
const NUM_BLOCKS: usize = 1024;
const DATA_LEN: usize = NUM_BLOCKS * BLOCK_LEN;

type Aes128Cfb<'k, Dir> = Cfb<'k, AES128Internal, Dir, BLOCK_LEN>;
type Aes256Cfb<'k, Dir> = Cfb<'k, AES256Internal, Dir, BLOCK_LEN>;
type Aes128Cfb8<'k, Dir> = Cfb8<'k, AES128Internal, Dir, BLOCK_LEN>;

/// CCM at the parameters the ACVP vectors and most protocols use: a 12-byte nonce and a full
/// 16-byte tag. The mode's in-place one-shots over the keyed permutation are the direct path;
/// the frame parameters are unused by them.
const CCM_NONCE_LEN: usize = 12;
const CCM_TAG_LEN: usize = 16;
type Aes128CcmMode = CCM<CCM_NONCE_LEN, CCM_TAG_LEN>;

/// The frame key takes its frame size at compile time. Its one-shots are not bound by it, but
/// using the same 4 KiB message keeps this comparison representative of the public alias a
/// packet protocol would choose.
const CCM_BUFFER_LEN: usize = 4096;
const CCM_AAD_LEN: usize = 64;
type Aes128CcmFrameKey =
    AES128Key<CCM_Packet<CCM_NONCE_LEN, CCM_TAG_LEN, CCM_AAD_LEN, CCM_BUFFER_LEN>>;
/// GCM with the full 16-byte tag, as the `AES_GCM_*` aliases fix it.
const GCM_TAG_LEN: usize = 16;
type Aes128GcmKey = AES128Key<GCM<GCM_TAG_LEN>>;
type Aes256GcmKey = AES256Key<GCM<GCM_TAG_LEN>>;
type Aes128Ctr<'k, Dir> = Ctr<'k, AES128Internal, Dir, BLOCK_LEN, 12>;
type Aes256Ctr<'k, Dir> = Ctr<'k, AES256Internal, Dir, BLOCK_LEN, 12>;
type Aes128Ecb<'k, Dir> = Ecb<'k, AES128Internal, Dir, BLOCK_LEN>;

/// AES-128 with the batch methods implemented as single-block loops instead of AES's bit-sliced
/// pair.
///
/// This exists purely to isolate the value of the pair path. Comparing `Cbc<'_, AES128Internal, ..>` against
/// `Cbc<'_, UnpairedAes128, ..>` at the *same* `N` holds everything else fixed -- same cipher, same
/// call granularity, same amount of data movement -- so the difference is attributable to
/// `decrypt_2blocks` and nothing else.
///
/// Comparing `N = 1` against `N = 8` does *not* isolate it: encryption, which can never pair, also
/// speeds up substantially between those two, so call granularity dominates that comparison.
///
/// It is not an `AESParams`, so no `AESKey` can be built over it; its workers come from the
/// mode types' own constructors (`Mode::key_state`, then the mode's `*_init`), which is what the
/// key does internally.
#[derive(Clone)]
struct UnpairedAes128(AES128Internal);

impl Algorithm for UnpairedAes128 {
    const ALG_NAME: &'static str = "AES-128 (unpaired)";
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

impl ModeNames for UnpairedAes128 {
    const CBC_ALG_NAME: &'static str = "AES_CBC_128 (unpaired)";
    const CCM_ALG_NAME: &'static str = "AES_CCM_128 (unpaired)";
    const CFB_ALG_NAME: &'static str = "AES_CFB_128 (unpaired)";
    const CFB8_ALG_NAME: &'static str = "AES_CFB8_128 (unpaired)";
    const CMAC_ALG_NAME: &'static str = "AES_CMAC_128 (unpaired)";
    const CTR_ALG_NAME: &'static str = "AES_CTR_128 (unpaired)";
    const ECB_ALG_NAME: &'static str = "AES_ECB_128 (unpaired)";
    const GCM_ALG_NAME: &'static str = "AES_GCM_128 (unpaired)";
    const GMAC_ALG_NAME: &'static str = "AES_GMAC_128 (unpaired)";
}

impl ElectronicCodeBook<16, BLOCK_LEN> for UnpairedAes128 {
    fn new(key: &KeyMaterial<16>) -> Result<Self, SymmetricCipherError> {
        Ok(Self(<AES128Internal as ElectronicCodeBook<16, BLOCK_LEN>>::new(key)?))
    }
}

impl BlockPermutation<BLOCK_LEN> for UnpairedAes128 {
    fn encrypt_block(&self, block: &mut [u8; BLOCK_LEN]) {
        <AES128Internal as BlockPermutation<BLOCK_LEN>>::encrypt_block(&self.0, block)
    }
    fn decrypt_block(&self, block: &mut [u8; BLOCK_LEN]) {
        <AES128Internal as BlockPermutation<BLOCK_LEN>>::decrypt_block(&self.0, block)
    }
    // Deliberately single-block loops, as a cipher with no unit wider than a block would write
    // them, bypassing AES's bit-sliced pair.
    fn encrypt_2blocks(&self, blocks: &mut [[u8; BLOCK_LEN]; 2]) {
        for block in blocks.iter_mut() {
            self.encrypt_block(block);
        }
    }
    fn decrypt_2blocks(&self, blocks: &mut [[u8; BLOCK_LEN]; 2]) {
        for block in blocks.iter_mut() {
            self.decrypt_block(block);
        }
    }
    fn encrypt_4blocks(&self, blocks: &mut [[u8; BLOCK_LEN]; 4]) {
        for block in blocks.iter_mut() {
            self.encrypt_block(block);
        }
    }
    fn decrypt_4blocks(&self, blocks: &mut [[u8; BLOCK_LEN]; 4]) {
        for block in blocks.iter_mut() {
            self.decrypt_block(block);
        }
    }
}

type UnpairedAes128Cbc<'k, Dir> = Cbc<'k, UnpairedAes128, Dir, BLOCK_LEN>;
type UnpairedAes128Cfb<'k, Dir> = Cfb<'k, UnpairedAes128, Dir, BLOCK_LEN>;
type UnpairedAes128Ecb<'k, Dir> = Ecb<'k, UnpairedAes128, Dir, BLOCK_LEN>;

fn key<const N: usize>() -> KeyMaterial<N> {
    let bytes: [u8; N] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    KeyMaterial::<N>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).unwrap()
}

/// The keyed toy permutation, which is also its key state under every mode here.
fn unpaired() -> UnpairedAes128 {
    UnpairedAes128::new(&key::<16>()).unwrap()
}

/// IVs and nonces for the throughput measurements come from a cheap deterministic RNG created
/// outside the timed loop, so they measure the mode and not OS entropy or DRBG construction.
fn iv_rng() -> FixedSeedRNG<BLOCK_LEN> {
    FixedSeedRNG::<BLOCK_LEN>::new([0x24u8; BLOCK_LEN])
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

fn bench_aes128(c: &mut Criterion) {
    let key = AES128Key::<CBC<Blocks>>::from_key_material(&key::<16>()).unwrap();
    let mut rng = iv_rng();
    let blocks = data();

    let mut group = c.benchmark_group("modes::cbc::AES_128");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    // ---- encryption: serial, one block at a time is all it can do ----
    group.bench_function("16KiB encrypt -- N=1", |b| {
        b.iter_batched(
            || blocks.clone(),
            |mut scratch| {
                let (mut enc, _) = key.create_encryptor(&mut rng).unwrap();
                for block in scratch.iter_mut() {
                    enc.do_encrypt_inplace(block).unwrap();
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
                let (mut enc, _) = key.create_encryptor(&mut rng).unwrap();
                for chunk in scratch.chunks_exact_mut(8) {
                    let arr: &mut [u8; 8 * BLOCK_LEN] =
                        chunk.as_flattened_mut().try_into().unwrap();
                    enc.do_encrypt_inplace(arr).unwrap();
                }
                black_box(&scratch);
            },
            BatchSize::LargeInput,
        )
    });

    // ---- decryption: parallel, uses decrypt_2blocks for every pair ----
    let (mut enc, iv) = key.create_encryptor(&mut rng).unwrap();
    let mut ciphertext = blocks.clone();
    for chunk in ciphertext.chunks_exact_mut(8) {
        enc.do_encrypt_blocks_inplace(chunk).unwrap();
    }

    // N=1 never forms a pair, so this is the single-block path: the ratio against encrypt should
    // be about 1.
    group.bench_function("16KiB decrypt -- N=1 (no pairing)", |b| {
        b.iter_batched(
            || ciphertext.clone(),
            |mut scratch| {
                let mut dec = key.create_decryptor(&iv);
                for block in scratch.iter_mut() {
                    dec.do_decrypt_inplace(block).unwrap();
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
                let mut dec = key.create_decryptor(&iv);
                for chunk in scratch.chunks_exact_mut(2) {
                    let arr: &mut [u8; 2 * BLOCK_LEN] =
                        chunk.as_flattened_mut().try_into().unwrap();
                    dec.do_decrypt_inplace(arr).unwrap();
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
                let mut dec = key.create_decryptor(&iv);
                for chunk in scratch.chunks_exact_mut(8) {
                    let arr: &mut [u8; 8 * BLOCK_LEN] =
                        chunk.as_flattened_mut().try_into().unwrap();
                    dec.do_decrypt_inplace(arr).unwrap();
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
                let mut dec = key.create_decryptor(&iv);
                for chunk in scratch.chunks_exact_mut(9) {
                    let arr: &mut [u8; 9 * BLOCK_LEN] =
                        chunk.as_flattened_mut().try_into().unwrap();
                    dec.do_decrypt_inplace(arr).unwrap();
                }
                black_box(&scratch);
            },
            BatchSize::LargeInput,
        )
    });

    // The controlled comparison: identical N, identical cipher, bit-sliced pair vs single-block loops.
    // This pair of numbers -- and only this pair -- measures what `decrypt_2blocks` buys.
    let unpaired_state = <CBC<Blocks> as Mode<UnpairedAes128>>::key_state(unpaired());
    group.bench_function("16KiB decrypt -- N=8, pair path (2blocks overridden)", |b| {
        b.iter_batched(
            || ciphertext.clone(),
            |mut scratch| {
                let mut dec = key.create_decryptor(&iv);
                for chunk in scratch.chunks_exact_mut(8) {
                    let arr: &mut [u8; 8 * BLOCK_LEN] =
                        chunk.as_flattened_mut().try_into().unwrap();
                    dec.do_decrypt_inplace(arr).unwrap();
                }
                black_box(&scratch);
            },
            BatchSize::LargeInput,
        )
    });

    group.bench_function("16KiB decrypt -- N=8, no pair path (single-block loops)", |b| {
        b.iter_batched(
            || ciphertext.clone(),
            |mut scratch| {
                let mut dec: UnpairedAes128Cbc<Decrypting> = <CBC<Blocks> as BlockDecryptMode<
                    UnpairedAes128,
                    16,
                    BLOCK_LEN,
                    BLOCK_LEN,
                >>::decrypt_init(
                    &unpaired_state, &iv
                );
                for chunk in scratch.chunks_exact_mut(8) {
                    let arr: &mut [u8; 8 * BLOCK_LEN] =
                        chunk.as_flattened_mut().try_into().unwrap();
                    dec.do_decrypt_inplace(arr).unwrap();
                }
                black_box(&scratch);
            },
            BatchSize::LargeInput,
        )
    });

    group.finish();
}

fn bench_aes256(c: &mut Criterion) {
    let key = AES256Key::<CBC<Blocks>>::from_key_material(&key::<32>()).unwrap();
    let mut rng = iv_rng();
    let blocks = data();

    let mut group = c.benchmark_group("modes::cbc::AES_256");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    group.bench_function("16KiB encrypt -- N=8", |b| {
        b.iter_batched(
            || blocks.clone(),
            |mut scratch| {
                let (mut enc, _) = key.create_encryptor(&mut rng).unwrap();
                for chunk in scratch.chunks_exact_mut(8) {
                    let arr: &mut [u8; 8 * BLOCK_LEN] =
                        chunk.as_flattened_mut().try_into().unwrap();
                    enc.do_encrypt_inplace(arr).unwrap();
                }
                black_box(&scratch);
            },
            BatchSize::LargeInput,
        )
    });

    let (mut enc, iv) = key.create_encryptor(&mut rng).unwrap();
    let mut ciphertext = blocks.clone();
    for chunk in ciphertext.chunks_exact_mut(8) {
        enc.do_encrypt_blocks_inplace(chunk).unwrap();
    }

    group.bench_function("16KiB decrypt -- N=8 (all fours)", |b| {
        b.iter_batched(
            || ciphertext.clone(),
            |mut scratch| {
                let mut dec = key.create_decryptor(&iv);
                for chunk in scratch.chunks_exact_mut(8) {
                    let arr: &mut [u8; 8 * BLOCK_LEN] =
                        chunk.as_flattened_mut().try_into().unwrap();
                    dec.do_decrypt_inplace(arr).unwrap();
                }
                black_box(&scratch);
            },
            BatchSize::LargeInput,
        )
    });

    group.finish();
}

/// Runs the 16 KiB through a freshly made stream-cipher encryptor in `call_len`-byte calls. Used
/// by the CFB, CFB8 and CTR groups: it is generic over the trait, not over the mode, and the
/// caller's key (or mode constructor) supplies the worker.
fn stream_encrypt_in_calls<E: StreamCipherEncryptor<INIT_DATA_LEN>, const INIT_DATA_LEN: usize>(
    mut enc: E,
    scratch: &mut [u8],
    call_len: usize,
) {
    for piece in scratch.chunks_mut(call_len) {
        enc.do_encrypt_inplace(piece).unwrap();
    }
}

/// Runs the 16 KiB through a freshly made stream-cipher decryptor in `call_len`-byte calls.
/// Shared as above.
fn stream_decrypt_in_calls<D: StreamCipherDecryptor<INIT_DATA_LEN>, const INIT_DATA_LEN: usize>(
    mut dec: D,
    scratch: &mut [u8],
    call_len: usize,
) {
    for piece in scratch.chunks_mut(call_len) {
        dec.do_decrypt_inplace(piece).unwrap();
    }
}

fn bench_cfb_aes128(c: &mut Criterion) {
    let key = AES128Key::<CFB>::from_key_material(&key::<16>()).unwrap();
    let mut rng = iv_rng();
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
                    let (enc, _): (Aes128Cfb<Encrypting>, _) =
                        key.create_encryptor(&mut rng).unwrap();
                    stream_encrypt_in_calls(enc, &mut scratch, call_len);
                    black_box(&scratch);
                },
                BatchSize::LargeInput,
            )
        });
    }

    // ---- decryption: parallel, and uses `encrypt_4blocks` / `encrypt_2blocks` -- the FORWARD
    // batch methods ----
    let (mut enc, iv) = key.create_encryptor(&mut rng).unwrap();
    let mut ciphertext = flat.clone();
    enc.do_encrypt_inplace(&mut ciphertext).unwrap();

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
                    let dec: Aes128Cfb<Decrypting> = key.create_decryptor(&iv);
                    stream_decrypt_in_calls(dec, &mut scratch, call_len);
                    black_box(&scratch);
                },
                BatchSize::LargeInput,
            )
        });
    }

    // The controlled comparison: identical N, identical cipher, bit-sliced pair vs single-block loops.
    // This pair of numbers -- and only this pair -- measures what `encrypt_2blocks` buys CFB.
    group.bench_function("16KiB decrypt -- N=8, pair path (2blocks overridden)", |b| {
        b.iter_batched(
            || ciphertext.clone(),
            |mut scratch| {
                let dec: Aes128Cfb<Decrypting> = key.create_decryptor(&iv);
                stream_decrypt_in_calls(dec, &mut scratch, 8 * BLOCK_LEN);
                black_box(&scratch);
            },
            BatchSize::LargeInput,
        )
    });

    let unpaired_state = <CFB as Mode<UnpairedAes128>>::key_state(unpaired());
    group.bench_function("16KiB decrypt -- N=8, no pair path (single-block loops)", |b| {
        b.iter_batched(
            || ciphertext.clone(),
            |mut scratch| {
                let dec: UnpairedAes128Cfb<Decrypting> =
                    <CFB as SymmetricDecryptMode<UnpairedAes128, 16, BLOCK_LEN, 0>>::decrypt_init(
                        &unpaired_state, &iv,
                    );
                stream_decrypt_in_calls(dec, &mut scratch, 8 * BLOCK_LEN);
                black_box(&scratch);
            },
            BatchSize::LargeInput,
        )
    });

    group.finish();
}

fn bench_cfb_aes256(c: &mut Criterion) {
    let key = AES256Key::<CFB>::from_key_material(&key::<32>()).unwrap();
    let mut rng = iv_rng();
    let flat: Vec<u8> = data().as_flattened().to_vec();

    let mut group = c.benchmark_group("modes::cfb::AES_256");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    group.bench_function("16KiB encrypt -- N=8", |b| {
        b.iter_batched(
            || flat.clone(),
            |mut scratch| {
                let (enc, _): (Aes256Cfb<Encrypting>, _) = key.create_encryptor(&mut rng).unwrap();
                stream_encrypt_in_calls(enc, &mut scratch, 8 * BLOCK_LEN);
                black_box(&scratch);
            },
            BatchSize::LargeInput,
        )
    });

    let (mut enc, iv) = key.create_encryptor(&mut rng).unwrap();
    let mut ciphertext = flat.clone();
    enc.do_encrypt_inplace(&mut ciphertext).unwrap();

    group.bench_function("16KiB decrypt -- N=8 (all fours)", |b| {
        b.iter_batched(
            || ciphertext.clone(),
            |mut scratch| {
                let dec: Aes256Cfb<Decrypting> = key.create_decryptor(&iv);
                stream_decrypt_in_calls(dec, &mut scratch, 8 * BLOCK_LEN);
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
    let key = AES128Key::<CFB8>::from_key_material(&key::<16>()).unwrap();
    let mut rng = iv_rng();
    let flat: Vec<u8> = data().as_flattened().to_vec();

    let mut group = c.benchmark_group("modes::cfb8::AES_128");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    // Serial by construction: I_{j+1} needs Cj, which this call just produced.
    group.bench_function("16KiB encrypt -- whole message in one call", |b| {
        b.iter_batched(
            || flat.clone(),
            |mut scratch| {
                let (enc, _): (Aes128Cfb8<Encrypting>, _) = key.create_encryptor(&mut rng).unwrap();
                stream_encrypt_in_calls(enc, &mut scratch, DATA_LEN);
                black_box(&scratch);
            },
            BatchSize::LargeInput,
        )
    });

    let (mut enc, iv) = key.create_encryptor(&mut rng).unwrap();
    let mut ciphertext = flat.clone();
    enc.do_encrypt_inplace(&mut ciphertext).unwrap();

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
                    let dec: Aes128Cfb8<Decrypting> = key.create_decryptor(&iv);
                    stream_decrypt_in_calls(dec, &mut scratch, call_len);
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
    let key = AES128Key::<CTR>::from_key_material(&key::<16>()).unwrap();
    let mut rng = FixedSeedRNG::<12>::new([0x24u8; 12]);
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
                    let (enc, _): (Aes128Ctr<Encrypting>, _) =
                        key.create_encryptor(&mut rng).unwrap();
                    stream_encrypt_in_calls(enc, &mut scratch, call_len);
                    black_box(&scratch);
                },
                BatchSize::LargeInput,
            )
        });
    }

    let (mut enc, nonce) = key.create_encryptor(&mut rng).unwrap();
    let mut ciphertext = flat.clone();
    enc.do_encrypt_inplace(&mut ciphertext).unwrap();

    for (name, call_len) in [
        ("16KiB decrypt -- N=1 (no batching)", BLOCK_LEN),
        ("16KiB decrypt -- N=8 (two fours per call)", 8 * BLOCK_LEN),
    ] {
        group.bench_function(name, |b| {
            b.iter_batched(
                || ciphertext.clone(),
                |mut scratch| {
                    let dec: Aes128Ctr<Decrypting> = key.create_decryptor(&nonce);
                    stream_decrypt_in_calls(dec, &mut scratch, call_len);
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
    let key = AES256Key::<CTR>::from_key_material(&key::<32>()).unwrap();
    let mut rng = FixedSeedRNG::<12>::new([0x24u8; 12]);
    let flat: Vec<u8> = data().as_flattened().to_vec();

    let mut group = c.benchmark_group("modes::ctr::AES_256");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    group.bench_function("16KiB encrypt -- N=8", |b| {
        b.iter_batched(
            || flat.clone(),
            |mut scratch| {
                let (enc, _): (Aes256Ctr<Encrypting>, _) = key.create_encryptor(&mut rng).unwrap();
                stream_encrypt_in_calls(enc, &mut scratch, 8 * BLOCK_LEN);
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
    let key = AES128Key::<ECB<Blocks>>::from_key_material(&key::<16>()).unwrap();
    let blocks = data();

    let mut group = c.benchmark_group("modes::ecb::AES_128");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    group.bench_function("16KiB encrypt -- N=1 (no batching)", |b| {
        b.iter_batched(
            || blocks.clone(),
            |mut scratch| {
                let mut enc: Aes128Ecb<Encrypting> = key.create_encryptor();
                for block in scratch.iter_mut() {
                    enc.do_encrypt_inplace(block).unwrap();
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
                let mut enc: Aes128Ecb<Encrypting> = key.create_encryptor();
                for chunk in scratch.chunks_exact_mut(8) {
                    let arr: &mut [u8; 8 * BLOCK_LEN] =
                        chunk.as_flattened_mut().try_into().unwrap();
                    enc.do_encrypt_inplace(arr).unwrap();
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
                let mut dec: Aes128Ecb<Decrypting> = key.create_decryptor();
                for chunk in scratch.chunks_exact_mut(8) {
                    let arr: &mut [u8; 8 * BLOCK_LEN] =
                        chunk.as_flattened_mut().try_into().unwrap();
                    dec.do_decrypt_inplace(arr).unwrap();
                }
                black_box(&scratch);
            },
            BatchSize::LargeInput,
        )
    });

    // The controlled comparison: identical N, identical cipher, bit-sliced pair vs single-block loops.
    let unpaired_state = <ECB<Blocks> as Mode<UnpairedAes128>>::key_state(unpaired());
    group.bench_function("16KiB encrypt -- N=8, no pair path (single-block loops)", |b| {
        b.iter_batched(
            || blocks.clone(),
            |mut scratch| {
                let mut enc: UnpairedAes128Ecb<Encrypting> =
                    <ECB<Blocks> as EcbEncryptMode<UnpairedAes128, 16, BLOCK_LEN>>::encrypt_init(
                        &unpaired_state,
                    );
                for chunk in scratch.chunks_exact_mut(8) {
                    let arr: &mut [u8; 8 * BLOCK_LEN] =
                        chunk.as_flattened_mut().try_into().unwrap();
                    enc.do_encrypt_inplace(arr).unwrap();
                }
                black_box(&scratch);
            },
            BatchSize::LargeInput,
        )
    });

    group.finish();
}

/// What a message pays before its first byte, split as the key path splits it: `from_key_material`
/// is the key expansion, paid once per key; `create_encryptor` is a clone of the stored schedule
/// plus an IV draw, and `create_decryptor` the clone alone, paid per message. The IV comes from
/// the cheap deterministic RNG, so the draw's cost is the copy and not a DRBG. Worth its own
/// measurement, because for short messages construction dominates.
fn bench_init(c: &mut Criterion) {
    let k128 = key::<16>();
    let k256 = key::<32>();
    let iv = [0u8; BLOCK_LEN];
    let mut rng = iv_rng();
    let cbc128 = AES128Key::<CBC<Blocks>>::from_key_material(&k128).unwrap();
    let cfb128 = AES128Key::<CFB>::from_key_material(&k128).unwrap();

    let mut group = c.benchmark_group("modes::init");

    group.bench_function("AES_128 from_key_material, CBC (key schedule)", |b| {
        b.iter(|| black_box(AES128Key::<CBC<Blocks>>::from_key_material(black_box(&k128)).unwrap()))
    });
    group.bench_function("AES_256 from_key_material, CBC (key schedule)", |b| {
        b.iter(|| black_box(AES256Key::<CBC<Blocks>>::from_key_material(black_box(&k256)).unwrap()))
    });
    group.bench_function("AES_128 create_encryptor, CBC (schedule clone + IV draw)", |b| {
        b.iter(|| black_box(black_box(&cbc128).create_encryptor(&mut rng).unwrap().1))
    });
    group.bench_function("AES_128 create_decryptor, CBC (schedule clone)", |b| {
        b.iter(|| black_box(black_box(&cbc128).create_decryptor(&iv)))
    });

    // CFB does exactly the same work here -- one key expansion per key, one clone plus an IV
    // draw per encryptor -- so these should match the CBC numbers. A divergence would mean one
    // mode is doing something extra at construction time.
    group.bench_function("AES_128 from_key_material, CFB (key schedule)", |b| {
        b.iter(|| black_box(AES128Key::<CFB>::from_key_material(black_box(&k128)).unwrap()))
    });
    group.bench_function("AES_128 create_encryptor, CFB (schedule clone + IV draw)", |b| {
        b.iter(|| black_box(black_box(&cfb128).create_encryptor(&mut rng).unwrap().1))
    });
    group.bench_function("AES_128 create_decryptor, CFB (schedule clone)", |b| {
        b.iter(|| black_box(black_box(&cfb128).create_decryptor(&iv)))
    });

    group.finish();
}

/// CCM (SP 800-38C), which is the only authenticated mode here and the only one that costs
/// **two** cipher calls per block -- but only one of the two batches.
///
/// Sec 5.2 builds CCM out of CTR for confidentiality and CBC-MAC for authenticity, over the same
/// key, so every payload block goes through the forward cipher twice: once as a counter block and
/// once as a CBC-MAC input. The CBC-MAC half is serial by construction (Sec 6.1 step 3: `Yi` is
/// the cipher of `Bi XOR Yi-1`), so unlike [`Ctr`] and the decrypt direction of `Cbc`/`Cfb` it has
/// no pair or four path -- but the CTR half has exactly `Ctr`'s parallelism (A.3's `Ctrj` depends
/// only on `j`), and the mode's keystream batches it the same way. So CCM sits *between* CTR's
/// two numbers, not at a fixed fraction of either:
///
/// * against `modes::ctr::AES_128/16KiB encrypt -- N=1`, CTR's unbatched single-block path, CCM
///   should be noticeably better than half -- one full unbatched pass (the MAC) plus a batched
///   pass that costs much less than a second unbatched one would;
/// * against CTR's `N=8` batched path, CCM should be noticeably better than a quarter, for the
///   same reason: only the MAC half pays the unbatched price.
///
/// Measured on the reference machine: 36 MiB/s for CCM against 52 MiB/s for CTR `N=1` (CCM at
/// ~69%, not ~50%) and 103 MiB/s for CTR `N=8` (CCM at ~35%, not ~25%) -- both above the naive
/// "two full unbatched passes" ratios, which is the batched CTR half showing up.
///
/// Encryption and decryption should be within noise of each other: Sec 6.1 and Sec 6.2 do the same
/// work in the opposite order (MAC-then-XOR versus XOR-then-MAC), and only the forward cipher is
/// ever used, so the inverse cipher's cost never enters.
///
/// The AAD is measured separately, and is the cheap half: it is absorbed into the CBC-MAC only,
/// one unbatched cipher call per block, against the payload's one unbatched call plus one batched
/// call. Batching the keystream narrows this gap from the naive "twice the payload's throughput"
/// to about **1.5x** -- measured 52 MiB/s AAD-only against 36 MiB/s for the payload -- and AAD-only
/// throughput should now sit close to CTR's *unbatched* number, since both are exactly one
/// unbatched cipher call per block.
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

    // Encrypt once outside the loop so decryption measures a ciphertext that authenticates: a
    // failing tag check would short-circuit the comparison and measure the wrong thing.
    let mut ciphertext = data;
    let tag =
        Aes128CcmMode::encrypt_detached_in_place_nonce(&perm, &nonce, &no_aad, &mut ciphertext)
            .unwrap();

    group.bench_function("decrypt 16KiB, no AAD", |b| {
        b.iter_batched_ref(
            || ciphertext,
            |buf| {
                black_box(
                    Aes128CcmMode::decrypt_detached_in_place(
                        black_box(&perm),
                        &nonce,
                        &no_aad,
                        buf,
                        &tag,
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
            || data,
            |buf| {
                black_box(
                    Aes128CcmMode::encrypt_detached_in_place_nonce(
                        black_box(&perm),
                        &nonce,
                        black_box(&data),
                        buf,
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

/// The frame key's [`AeadEncryptionKey`] one-shot against the mode's in-place one-shot on the
/// same message.
///
/// Both end in the same `Ccm` implementation; the key form copies the message into the caller's
/// output buffer and draws the nonce. A cheap deterministic RNG, created once outside the timed
/// loop, isolates that draw from OS entropy and DRBG construction.
fn bench_ccm_one_shot_pair(c: &mut Criterion) {
    let material = key::<16>();
    let key = Aes128CcmFrameKey::from_key_material(&material).unwrap();
    let perm = AES128Internal::new(&material).unwrap();
    let data = [0xA5u8; CCM_BUFFER_LEN];
    let no_aad: [u8; 0] = [];
    let nonce = [0x24u8; CCM_NONCE_LEN];
    let mut rng = FixedSeedRNG::<CCM_NONCE_LEN>::new(nonce);

    let mut group = c.benchmark_group("modes::ccm::one_shot");
    group.throughput(Throughput::Bytes(CCM_BUFFER_LEN as u64));

    group.bench_function("AeadEncryptionKey::encrypt_detached_out 4KiB", |b| {
        b.iter_batched_ref(
            || [0u8; CCM_BUFFER_LEN],
            |out| {
                black_box(
                    black_box(&key)
                        .encrypt_detached_out(&mut rng, &no_aad, black_box(&data), out)
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
fn bench_gcm_aes128(c: &mut Criterion) {
    let key = Aes128GcmKey::from_key_material(&key::<16>()).unwrap();
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
                    black_box(&key)
                        .encrypt_detached_out(&mut rng, &no_aad, black_box(&data), out)
                        .unwrap(),
                )
            },
            BatchSize::LargeInput,
        )
    });

    // Encrypt once outside the loop so decryption measures a ciphertext that authenticates: a
    // failing tag check would short-circuit the comparison and measure the wrong thing.
    let mut ciphertext = [0u8; DATA_LEN];
    let (_, nonce, tag) =
        key.encrypt_detached_out(&mut rng, &no_aad, &data, &mut ciphertext).unwrap();

    // The one-shot verifies the tag before it decrypts (SP 800-38D Sec 7's preamble permits the
    // reordering), so this is GHASH over the whole ciphertext and then CTR over it: the same work
    // as encryption in the other order.
    group.bench_function("decrypt 16KiB, no AAD", |b| {
        b.iter_batched_ref(
            || [0u8; DATA_LEN],
            |out| {
                black_box(
                    black_box(&key)
                        .decrypt_detached_out(&nonce, &no_aad, black_box(&ciphertext), &tag, out)
                        .unwrap(),
                )
            },
            BatchSize::LargeInput,
        )
    });

    // The same payload with 16 KiB of AAD alongside it: one extra GHASH multiply per AAD block
    // and no extra cipher calls, so the increment over the no-AAD case is the GHASH half alone.
    group.bench_function("encrypt 16KiB with 16KiB AAD", |b| {
        b.iter_batched_ref(
            || [0u8; DATA_LEN],
            |out| {
                black_box(
                    black_box(&key)
                        .encrypt_detached_out(&mut rng, black_box(&data), black_box(&data), out)
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
                black_box(&key)
                    .encrypt_detached_out(&mut rng, black_box(&data), &no_aad, &mut out)
                    .unwrap(),
            )
        })
    });

    // Streaming in 128-byte pieces, the same call length as the N=8 CTR measurement, so the
    // per-call overhead of the AEAD streaming path shows against the one-shot above.
    group.bench_function("encrypt 16KiB -- N=8 streaming", |b| {
        b.iter_batched(
            || data.to_vec(),
            |plaintext| {
                let (mut enc, _nonce) = black_box(&key).create_encryptor(&mut rng).unwrap();
                let mut out = [0u8; 8 * BLOCK_LEN];
                for piece in plaintext.chunks(8 * BLOCK_LEN) {
                    enc.do_encrypt_out(piece, &mut out).unwrap();
                    black_box(&out);
                }
                black_box(enc.do_encrypt_final().unwrap())
            },
            BatchSize::LargeInput,
        )
    });

    group.finish();
}

/// AES-256 GCM, for the same key-length comparison the other modes carry.
fn bench_gcm_aes256(c: &mut Criterion) {
    let key = Aes256GcmKey::from_key_material(&key::<32>()).unwrap();
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
                    black_box(&key)
                        .encrypt_detached_out(&mut rng, &no_aad, black_box(&data), out)
                        .unwrap(),
                )
            },
            BatchSize::LargeInput,
        )
    });

    group.finish();
}

/// CMAC is serial like CBC encryption (SP 800-38B Sec 6.2 step 6 chains every block), so it
/// should come out close to `modes::cbc::AES_128` encryption. Building the key once skips the
/// per-tag key expansion and subkey derivation, one block encryption, which is invisible at 16
/// KiB; the `from_key_material per tag` arms pay it every time, for the comparison.
fn bench_cmac(c: &mut Criterion) {
    let data: Vec<u8> = data().concat();
    let mut group = c.benchmark_group("modes::cmac");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    let key128 = mac_key::<16>();
    group.bench_function("AES_128 from_key_material per tag 16KiB", |b| {
        b.iter(|| {
            black_box(AES128Key::<CMAC>::from_key_material(&key128).unwrap().mac(black_box(&data)))
        })
    });
    let key_object_128 = AES128Key::<CMAC>::from_key_material(&key128).unwrap();
    group.bench_function("AES_128 key object 16KiB", |b| {
        b.iter(|| black_box(key_object_128.mac(black_box(&data))))
    });
    let key256 = mac_key::<32>();
    group.bench_function("AES_256 from_key_material per tag 16KiB", |b| {
        b.iter(|| {
            black_box(AES256Key::<CMAC>::from_key_material(&key256).unwrap().mac(black_box(&data)))
        })
    });
    let key_object_256 = AES256Key::<CMAC>::from_key_material(&key256).unwrap();
    group.bench_function("AES_256 key object 16KiB", |b| {
        b.iter(|| black_box(key_object_256.mac(black_box(&data))))
    });

    group.finish();
}

/// GMAC is GHASH over the message plus two cipher calls, so it is several times faster than CMAC
/// and the same as GCM's AAD-only measurement.
fn bench_gmac(c: &mut Criterion) {
    let data: Vec<u8> = data().concat();
    let mut group = c.benchmark_group("modes::gmac");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));
    let mut rng = FixedSeedRNG::<GCM_NONCE_LEN>::new([0x24u8; GCM_NONCE_LEN]);

    let key128 = mac_key::<16>();
    let key_object_128 = AES128Key::<GMAC>::from_key_material(&key128).unwrap();
    group.bench_function("AES_128 key object 16KiB", |b| {
        b.iter(|| {
            let (gen_, _) = key_object_128.create_generator(&mut rng).unwrap();
            black_box(gen_.mac(black_box(&data)))
        })
    });
    let key256 = mac_key::<32>();
    let key_object_256 = AES256Key::<GMAC>::from_key_material(&key256).unwrap();
    group.bench_function("AES_256 key object 16KiB", |b| {
        b.iter(|| {
            let (gen_, _) = key_object_256.create_generator(&mut rng).unwrap();
            black_box(gen_.mac(black_box(&data)))
        })
    });

    group.finish();
}

criterion_group!(
    benches, bench_aes128, bench_aes256, bench_cfb_aes128, bench_cfb_aes256, bench_cfb8_aes128,
    bench_ctr_aes128, bench_ctr_aes256, bench_ecb_aes128, bench_ccm_aes128,
    bench_ccm_one_shot_pair, bench_gcm_aes128, bench_gcm_aes256, bench_init, bench_cmac,
    bench_gmac
);
criterion_main!(benches);
