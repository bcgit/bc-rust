//! Criterion benchmarks for the Crypto Extensions kernels on their own, without a mode on top.
//!
//! The AES groups run 16 KiB through `encrypt_blocks` / `decrypt_blocks` at each width, so the
//! gain from keeping two or four `AESE` chains in flight is visible directly. The GHASH group
//! folds 1024 elements with `mul` one at a time and with `mul4` four at a time.
//!
//! On a target without the instructions the crate is empty and this binary does nothing.

#[cfg(all(
    target_arch = "aarch64",
    target_endian = "little",
    target_feature = "aes",
    target_feature = "neon"
))]
mod arm {
    use bouncycastle_arm::aes::{
        BLOCK_LEN, Block, decrypt_blocks, encrypt_blocks, equivalent_inverse_round_keys,
        expand_128, expand_192, expand_256,
    };
    use bouncycastle_arm::ghash::{Element, mul, mul4};
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
        let mut group = c.benchmark_group("arm::aes::key expansion");
        let (k128, k192, k256) = (random_key::<16>(1), random_key::<24>(2), random_key::<32>(3));
        group.bench_function("expand_128", |b| b.iter(|| expand_128(black_box(&k128))));
        group.bench_function("expand_192", |b| b.iter(|| expand_192(black_box(&k192))));
        group.bench_function("expand_256", |b| b.iter(|| expand_256(black_box(&k256))));
        group.finish();
    }

    /// The data benches work in place on one buffer across iterations, so no copy sits inside
    /// the timed closure; the permutation is a bijection, so the buffer stays random.
    fn bench_data_paths<const N: usize>(group: &mut BenchmarkGroup<'_, WallTime>, w: &[Block; N]) {
        let dw = equivalent_inverse_round_keys(w);
        let mut data = random_blocks(4);
        group.throughput(Throughput::Bytes(DATA_LEN as u64));

        group.bench_function("16KiB -- encrypt_blocks::<_, 1> x1024", |b| {
            b.iter(|| {
                for block in data.iter_mut() {
                    let mut one = [*block];
                    encrypt_blocks(w, &mut one);
                    *block = one[0];
                }
            })
        });
        group.bench_function("16KiB -- encrypt_blocks::<_, 2> x512", |b| {
            b.iter(|| {
                for pair in data.chunks_exact_mut(2) {
                    let mut two = [pair[0], pair[1]];
                    encrypt_blocks(w, &mut two);
                    pair.copy_from_slice(&two);
                }
            })
        });
        group.bench_function("16KiB -- encrypt_blocks::<_, 4> x256", |b| {
            b.iter(|| {
                for quad in data.chunks_exact_mut(4) {
                    let mut four = [quad[0], quad[1], quad[2], quad[3]];
                    encrypt_blocks(w, &mut four);
                    quad.copy_from_slice(&four);
                }
            })
        });
        group.bench_function("16KiB -- decrypt_blocks::<_, 1> x1024", |b| {
            b.iter(|| {
                for block in data.iter_mut() {
                    let mut one = [*block];
                    decrypt_blocks(&dw, &mut one);
                    *block = one[0];
                }
            })
        });
        group.bench_function("16KiB -- decrypt_blocks::<_, 4> x256", |b| {
            b.iter(|| {
                for quad in data.chunks_exact_mut(4) {
                    let mut four = [quad[0], quad[1], quad[2], quad[3]];
                    decrypt_blocks(&dw, &mut four);
                    quad.copy_from_slice(&four);
                }
            })
        });
    }

    fn bench_aes128(c: &mut Criterion) {
        let w = expand_128(&random_key::<16>(1));
        let mut group = c.benchmark_group("arm::aes::AES-128");
        bench_data_paths(&mut group, &w);
        group.finish();
    }

    fn bench_aes192(c: &mut Criterion) {
        let w = expand_192(&random_key::<24>(2));
        let mut group = c.benchmark_group("arm::aes::AES-192");
        bench_data_paths(&mut group, &w);
        group.finish();
    }

    fn bench_aes256(c: &mut Criterion) {
        let w = expand_256(&random_key::<32>(3));
        let mut group = c.benchmark_group("arm::aes::AES-256");
        bench_data_paths(&mut group, &w);
        group.finish();
    }

    fn bench_ghash(c: &mut Criterion) {
        let mut rng = Xorshift(5);
        let h: Element = [rng.next_u64(), rng.next_u64()];
        let h2 = mul(&h, &h);
        let h3 = mul(&h2, &h);
        let h4 = mul(&h3, &h);
        let powers = [h4, h3, h2, h];
        let data: Vec<Element> =
            (0..NUM_BLOCKS).map(|_| [rng.next_u64(), rng.next_u64()]).collect();

        let mut group = c.benchmark_group("arm::ghash");
        group.throughput(Throughput::Bytes(DATA_LEN as u64));
        group.bench_function("16KiB -- mul x1024, one block per step", |b| {
            b.iter(|| {
                let mut y: Element = [0, 0];
                for x in &data {
                    y = mul(&[y[0] ^ x[0], y[1] ^ x[1]], &h);
                }
                black_box(y)
            })
        });
        group.bench_function("16KiB -- mul4 x256, four blocks per step", |b| {
            b.iter(|| {
                let mut y: Element = [0, 0];
                for group in data.chunks_exact(4) {
                    let first = [y[0] ^ group[0][0], y[1] ^ group[0][1]];
                    y = mul4(&[first, group[1], group[2], group[3]], &powers);
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
    target_feature = "aes",
    target_feature = "neon"
))]
criterion::criterion_main!(arm::benches);

#[cfg(not(all(
    target_arch = "aarch64",
    target_endian = "little",
    target_feature = "aes",
    target_feature = "neon"
)))]
fn main() {}
