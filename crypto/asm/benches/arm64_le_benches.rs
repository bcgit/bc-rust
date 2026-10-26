//! Criterion benchmarks for the Crypto Extensions kernels on their own, without a mode on top.
//!
//! The AES groups run 16 KiB through `encrypt_blocks` / `decrypt_blocks` at each width, so the
//! gain from keeping two or four `AESE` chains in flight is visible directly. The GHASH group
//! folds 1024 elements with `mul` one at a time and with `mul4` four at a time.
//!
//! On a target or CPU without the instructions this binary does nothing.

#[cfg(all(
    target_arch = "aarch64",
    target_endian = "little",
    target_feature = "neon",
    any(
        target_feature = "aes",
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "windows"
    )
))]
mod arm {
    use bouncycastle_asm::{Aes, BLOCK_LEN, Block, Element};
    use criterion::measurement::WallTime;
    use criterion::{BenchmarkGroup, Criterion, Throughput, criterion_group};
    use std::hint::black_box;

    /// 16 KiB of data, i.e. 1024 blocks.
    const NUM_BLOCKS: usize = 1024;
    const DATA_LEN: usize = NUM_BLOCKS * BLOCK_LEN;

    struct Xorshift(u64);
    impl Xorshift {
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
    }

    fn random_blocks(seed: u64) -> Vec<Block> {
        let mut rng = Xorshift(seed);
        (0..NUM_BLOCKS)
            .map(|_| {
                let mut b = [0u8; BLOCK_LEN];
                for byte in b.iter_mut() {
                    *byte = rng.next_u64() as u8;
                }
                b
            })
            .collect()
    }

    fn random_key<const N: usize>(seed: u64) -> [u8; N] {
        let mut rng = Xorshift(seed);
        let mut k = [0u8; N];
        for byte in k.iter_mut() {
            *byte = rng.next_u64() as u8;
        }
        k
    }

    fn bench_key_expansion(c: &mut Criterion) {
        let Some(cx) = Aes::detect() else { return };
        let mut group = c.benchmark_group("arm::aes::key expansion");
        let (k128, k192, k256) = (random_key::<16>(1), random_key::<24>(2), random_key::<32>(3));
        group.bench_function("expand_128", |b| b.iter(|| cx.expand_128(black_box(&k128))));
        group.bench_function("expand_192", |b| b.iter(|| cx.expand_192(black_box(&k192))));
        group.bench_function("expand_256", |b| b.iter(|| cx.expand_256(black_box(&k256))));
        group.finish();
    }

    /// The data benches work in place on one buffer across iterations, so no copy sits inside
    /// the timed closure; the permutation is a bijection, so the buffer stays random.
    fn bench_data_paths<const N: usize>(
        cx: Aes,
        group: &mut BenchmarkGroup<'_, WallTime>,
        w: &[Block; N],
    ) {
        let dw = cx.equivalent_inverse_round_keys(w);
        let mut data = random_blocks(4);
        group.throughput(Throughput::Bytes(DATA_LEN as u64));

        group.bench_function("16KiB -- encrypt_blocks::<_, 1> x1024", |b| {
            b.iter(|| {
                for block in data.iter_mut() {
                    let mut one = [*block];
                    cx.encrypt_blocks(w, &mut one);
                    *block = one[0];
                }
            })
        });
        group.bench_function("16KiB -- encrypt_blocks::<_, 2> x512", |b| {
            b.iter(|| {
                for pair in data.chunks_exact_mut(2) {
                    let mut two = [pair[0], pair[1]];
                    cx.encrypt_blocks(w, &mut two);
                    pair.copy_from_slice(&two);
                }
            })
        });
        group.bench_function("16KiB -- encrypt_blocks::<_, 4> x256", |b| {
            b.iter(|| {
                for quad in data.chunks_exact_mut(4) {
                    let mut four = [quad[0], quad[1], quad[2], quad[3]];
                    cx.encrypt_blocks(w, &mut four);
                    quad.copy_from_slice(&four);
                }
            })
        });
        group.bench_function("16KiB -- decrypt_blocks::<_, 1> x1024", |b| {
            b.iter(|| {
                for block in data.iter_mut() {
                    let mut one = [*block];
                    cx.decrypt_blocks(&dw, &mut one);
                    *block = one[0];
                }
            })
        });
        group.bench_function("16KiB -- decrypt_blocks::<_, 4> x256", |b| {
            b.iter(|| {
                for quad in data.chunks_exact_mut(4) {
                    let mut four = [quad[0], quad[1], quad[2], quad[3]];
                    cx.decrypt_blocks(&dw, &mut four);
                    quad.copy_from_slice(&four);
                }
            })
        });
    }

    fn bench_aes128(c: &mut Criterion) {
        let Some(cx) = Aes::detect() else { return };
        let w = cx.expand_128(&random_key::<16>(1));
        let mut group = c.benchmark_group("arm::aes::AES-128");
        bench_data_paths(cx, &mut group, &w);
        group.finish();
    }

    fn bench_aes192(c: &mut Criterion) {
        let Some(cx) = Aes::detect() else { return };
        let w = cx.expand_192(&random_key::<24>(2));
        let mut group = c.benchmark_group("arm::aes::AES-192");
        bench_data_paths(cx, &mut group, &w);
        group.finish();
    }

    fn bench_aes256(c: &mut Criterion) {
        let Some(cx) = Aes::detect() else { return };
        let w = cx.expand_256(&random_key::<32>(3));
        let mut group = c.benchmark_group("arm::aes::AES-256");
        bench_data_paths(cx, &mut group, &w);
        group.finish();
    }

    fn bench_ghash(c: &mut Criterion) {
        let Some(cx) = Aes::detect() else { return };
        let mut rng = Xorshift(5);
        let h: Element = [rng.next_u64(), rng.next_u64()];
        let h2 = cx.ghash_mul(&h, &h);
        let h3 = cx.ghash_mul(&h2, &h);
        let h4 = cx.ghash_mul(&h3, &h);
        let powers = [h4, h3, h2, h];
        let data: Vec<Element> =
            (0..NUM_BLOCKS).map(|_| [rng.next_u64(), rng.next_u64()]).collect();

        let mut group = c.benchmark_group("arm::ghash");
        group.throughput(Throughput::Bytes(DATA_LEN as u64));
        group.bench_function("16KiB -- mul x1024, one block per step", |b| {
            b.iter(|| {
                let mut y: Element = [0, 0];
                for x in &data {
                    y = cx.ghash_mul(&[y[0] ^ x[0], y[1] ^ x[1]], &h);
                }
                black_box(y)
            })
        });
        group.bench_function("16KiB -- mul4 x256, four blocks per step", |b| {
            b.iter(|| {
                let mut y: Element = [0, 0];
                for group in data.chunks_exact(4) {
                    let first = [y[0] ^ group[0][0], y[1] ^ group[0][1]];
                    y = cx.ghash_mul4(&[first, group[1], group[2], group[3]], &powers);
                }
                black_box(y)
            })
        });
        group.finish();
    }

    criterion_group!(
        benches, bench_key_expansion, bench_aes128, bench_aes192, bench_aes256, bench_ghash
    );
}

#[cfg(all(
    target_arch = "aarch64",
    target_endian = "little",
    target_feature = "neon",
    any(
        target_feature = "aes",
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "windows"
    )
))]
criterion::criterion_main!(arm::benches);

#[cfg(not(all(
    target_arch = "aarch64",
    target_endian = "little",
    target_feature = "neon",
    any(
        target_feature = "aes",
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "windows"
    )
)))]
fn main() {}
