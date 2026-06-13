use bouncycastle_core::key_material::{KeyMaterial512, KeyType};
use bouncycastle_core::traits::KEMDecapsulator;
use bouncycastle_hex as hex;
use bouncycastle_mlkem_lowmemory::{
    MLKEM_RND_LEN, MLKEM512, MLKEM512_CT_LEN, MLKEM768, MLKEM768_CT_LEN, MLKEM1024,
    MLKEM1024_CT_LEN, MLKEMTrait,
};
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn bench_mlkem_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("KeyGen");

    // set up the seeds outside of the timing loop
    // Doing different seeds so that the CPU doesn't cache them or do too much branch prediction
    let mut seeds = Vec::<KeyMaterial512>::new();
    for dummy_seed in DUMMY_SEED_1024.chunks(64) {
        seeds.extend(KeyMaterial512::from_bytes_as_type(dummy_seed, KeyType::Seed));
    }

    group.throughput(criterion::Throughput::Elements(seeds.len() as u64));

    group.bench_function("ML-KEM-512_lowmemory", |b| {
        b.iter(|| {
            for seed in seeds.iter() {
                black_box(MLKEM512::keygen_from_seed(seed)).unwrap();
            }
        })
    });

    group.bench_function("ML-KEM-768_lowmemory", |b| {
        b.iter(|| {
            for seed in seeds.iter() {
                black_box(MLKEM768::keygen_from_seed(seed)).unwrap();
            }
        })
    });

    group.bench_function("ML-KEM-1024_lowmemory", |b| {
        b.iter(|| {
            for seed in seeds.iter() {
                black_box(MLKEM1024::keygen_from_seed(seed)).unwrap();
            }
        })
    });

    group.finish();
}

fn bench_mlkem_encaps(c: &mut Criterion) {
    let mut group = c.benchmark_group("Encaps");

    // set up the seeds outside of the timing loop
    // Doing different seeds so that the CPU doesn't cache them or do too much branch prediction
    let seed = KeyMaterial512::from_bytes_as_type(
        &hex::decode(
            "000102030405060708090a0b0c0d0e0f
                            101112131415161718191a1b1c1d1e1f
                            202122232425262728292a2b2c2d2e2f
                            303132333435363738393a3b3c3d3e3f",
        )
        .unwrap(),
        KeyType::Seed,
    )
    .unwrap();

    // create a vector of signing nonces so that we're not measuring the time of the RNG
    const NUM_ELEMS: usize = 256;
    let mut nonces = [[0u8; 32]; NUM_ELEMS];
    for i in 0..256 {
        nonces[i].fill(i as u8);
    }

    /*** ML-KEM-512 ***/
    let (pk, _sk) = MLKEM512::keygen_from_seed(&seed).unwrap();

    group.throughput(criterion::Throughput::Elements(NUM_ELEMS as u64));

    group.bench_function("ML-KEM-512_lowmemory", |b| {
        b.iter(|| {
            for i in 0..NUM_ELEMS {
                _ = black_box(MLKEM512::encaps_internal(&pk, nonces[i]));
            }
        })
    });

    /*** ML-KEM-768 ***/
    let (pk, _sk) = MLKEM768::keygen_from_seed(&seed).unwrap();

    group.throughput(criterion::Throughput::Elements(NUM_ELEMS as u64));

    group.bench_function("ML-KEM-768_lowmemory", |b| {
        b.iter(|| {
            for i in 0..NUM_ELEMS {
                _ = black_box(MLKEM768::encaps_internal(&pk, nonces[i]));
            }
        })
    });

    /*** ML-KEM-1024 ***/
    let (pk, _sk) = MLKEM1024::keygen_from_seed(&seed).unwrap();

    group.throughput(criterion::Throughput::Elements(NUM_ELEMS as u64));

    group.bench_function("ML-KEM-1024_lowmemory", |b| {
        b.iter(|| {
            for i in 0..NUM_ELEMS {
                _ = black_box(MLKEM1024::encaps_internal(&pk, nonces[i]));
            }
        })
    });

    group.finish();
}

fn bench_mlkem_decaps(c: &mut Criterion) {
    let mut group = c.benchmark_group("Decaps");

    // set up the seeds outside of the timing loop
    // Doing different seeds so that the CPU doesn't cache them or do too much branch prediction
    let seed = KeyMaterial512::from_bytes_as_type(
        &hex::decode(
            "000102030405060708090a0b0c0d0e0f
                            101112131415161718191a1b1c1d1e1f
                            202122232425262728292a2b2c2d2e2f
                            303132333435363738393a3b3c3d3e3f",
        )
        .unwrap(),
        KeyType::Seed,
    )
    .unwrap();

    const NUM_ELEMS: usize = 256;

    /*** ML-KEM-512 ***/
    let (pk, sk) = MLKEM512::keygen_from_seed(&seed).unwrap();

    // create a bunch of ciphertexts to decaps
    let mut cts = [[0u8; MLKEM512_CT_LEN]; NUM_ELEMS];
    for i in 0..NUM_ELEMS {
        // create each ct with a unique nonce
        // encaps_internal() returns (ss, ct) ... we only want ct, hence the ".1"
        cts[i].copy_from_slice(&MLKEM512::encaps_internal(&pk, [i as u8; MLKEM_RND_LEN]).1);
    }

    group.throughput(criterion::Throughput::Elements(NUM_ELEMS as u64));

    group.bench_function("ML-KEM-512_lowmemory", |b| {
        b.iter(|| {
            for i in 0..NUM_ELEMS {
                _ = black_box(MLKEM512::decaps(&sk, &cts[i]));
            }
        })
    });

    /*** ML-KEM-768 ***/
    let (pk, sk) = MLKEM768::keygen_from_seed(&seed).unwrap();

    // create a bunch of ciphertexts to decaps
    let mut cts = [[0u8; MLKEM768_CT_LEN]; NUM_ELEMS];
    for i in 0..NUM_ELEMS {
        // create each ct with a unique nonce
        // encaps_internal() returns (ss, ct) ... we only want ct, hence the ".1"
        cts[i].copy_from_slice(&MLKEM768::encaps_internal(&pk, [i as u8; MLKEM_RND_LEN]).1);
    }

    group.throughput(criterion::Throughput::Elements(NUM_ELEMS as u64));

    group.bench_function("ML-KEM-768_lowmemory", |b| {
        b.iter(|| {
            for i in 0..NUM_ELEMS {
                _ = black_box(MLKEM768::decaps(&sk, &cts[i]));
            }
        })
    });

    /*** ML-KEM-1024 ***/
    let (pk, sk) = MLKEM1024::keygen_from_seed(&seed).unwrap();

    // create a bunch of ciphertexts to decaps
    let mut cts = [[0u8; MLKEM1024_CT_LEN]; NUM_ELEMS];
    for i in 0..NUM_ELEMS {
        // create each ct with a unique nonce
        // encaps_internal() returns (ss, ct) ... we only want ct, hence the ".1"
        cts[i].copy_from_slice(&MLKEM1024::encaps_internal(&pk, [i as u8; MLKEM_RND_LEN]).1);
    }

    group.throughput(criterion::Throughput::Elements(NUM_ELEMS as u64));

    group.bench_function("ML-KEM-1024_lowmemory", |b| {
        b.iter(|| {
            for i in 0..NUM_ELEMS {
                _ = black_box(MLKEM1024::decaps(&sk, &cts[i]));
            }
        })
    });

    group.finish();
}

criterion_group!(benches, bench_mlkem_keygen, bench_mlkem_encaps, bench_mlkem_decaps);
criterion_main!(benches);

const DUMMY_SEED_1024: &[u8; 1024] = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff";
