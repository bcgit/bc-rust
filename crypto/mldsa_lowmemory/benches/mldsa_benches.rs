use criterion::{Criterion, criterion_group, criterion_main};
use bouncycastle_core_interface::key_material::{KeyMaterial256, KeyType};
use std::hint::black_box;
use bouncycastle_core_interface::traits::Signature;
use bouncycastle_mldsa_lowmemory::{MLDSATrait, MLDSA44, MLDSA65, MLDSA87};
use bouncycastle_hex as hex;

fn bench_mldsa_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("KeyGen");

    // set up the seeds outside of the timing loop
    // Doing different seeds so that the CPU doesn't cache them or do too much branch prediction
    let mut seeds = Vec::<KeyMaterial256>::new();
    for dummy_seed in DUMMY_SEED_1024.chunks(32) {
        seeds.extend(KeyMaterial256::from_bytes_as_type(dummy_seed, KeyType::Seed));
    }

    group.throughput(criterion::Throughput::Elements(seeds.len() as u64));

    group.bench_function("ML-DSA-44_lowmemory", |b| {
       b.iter(|| {
           for seed in seeds.iter() {
               black_box(MLDSA44::keygen_from_seed(seed)).unwrap();
           }
       })
    });

    group.bench_function("ML-DSA-65_lowmemory", |b| {
        b.iter(|| {
            for seed in seeds.iter() {
                black_box(MLDSA65::keygen_from_seed(seed)).unwrap();
            }
        })
    });

    group.bench_function("ML-DSA-87_lowmemory", |b| {
        b.iter(|| {
            for seed in seeds.iter() {
                black_box(MLDSA87::keygen_from_seed(seed)).unwrap();
            }
        })
    });

    group.finish();
}

fn bench_mldsa_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("Sign");

    // set up the seeds outside of the timing loop
    // Doing different seeds so that the CPU doesn't cache them or do too much branch prediction
    let seed = KeyMaterial256::from_bytes_as_type(
        &hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap(),
        KeyType::Seed,
    ).unwrap();

    let msg = b"The quick brown fox jumped over the lazy dog";

    /*** ML-DSA-44 ***/
    let (_mldsa44_pk, mldsa44_sk) = MLDSA44::keygen_from_seed(&seed).unwrap();


    // signing nonce; we'll increment each time
    let mut rnd= [0u8; 32];

    group.throughput(criterion::Throughput::Elements(1_u64));

    group.bench_function("ML-DSA-44_lowmemory", |b| {
        b.iter(|| {
            let mu = MLDSA44::compute_mu_from_sk(&mldsa44_sk, msg, None).unwrap();
            let sig = MLDSA44::sign_mu_deterministic(&mldsa44_sk, &mu, rnd).unwrap();
            black_box(sig);
            rnd[31] = rnd[31].wrapping_add(1);
        })
    });


    /*** ML-DSA-65 ***/
    let (_mldsa65_pk, mldsa65_sk) = MLDSA65::keygen_from_seed(&seed).unwrap();

    group.bench_function("ML-DSA-65_lowmemory", |b| {
        b.iter(|| {
            let mu = MLDSA65::compute_mu_from_sk(&mldsa65_sk, msg, None).unwrap();
            let sig = MLDSA65::sign_mu_deterministic(&mldsa65_sk, &mu, rnd).unwrap();
            black_box(sig);
            rnd[31] = rnd[31].wrapping_add(1);
        })
    });


    /*** ML-DSA-87 ***/

    let (_mldsa87_pk, mldsa87_sk) = MLDSA87::keygen_from_seed(&seed).unwrap();

    group.bench_function("ML-DSA-87_lowmemory", |b| {
        b.iter(|| {
            let mu = MLDSA87::compute_mu_from_sk(&mldsa87_sk, msg, None).unwrap();
            let sig = MLDSA87::sign_mu_deterministic(&mldsa87_sk, &mu, rnd).unwrap();
            black_box(sig);
            rnd[31] = rnd[31].wrapping_add(1);
        })
    });

    group.finish();
}

fn bench_mldsa_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("Verify");

    // set up the seeds outside of the timing loop
    // Doing different seeds so that the CPU doesn't cache them or do too much branch prediction
    let seed = KeyMaterial256::from_bytes_as_type(
        &hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap(),
        KeyType::Seed,
    ).unwrap();

    let msg = b"The quick brown fox jumped over the lazy dog";


    /*** ML-DSA-44 ***/
    let (mldsa44_pk, mldsa44_sk) = MLDSA44::keygen_from_seed(&seed).unwrap();

    // Create a vec of 1000  different signatures to verify
    // use ctx to make them different (in addition to the signing nonce being different)
    let mut sigs = Vec::< (Vec<u8>, u128) >::with_capacity(1000);

    let mut ctx = 0u128;
    for _ in 0..1000 {
        sigs.push( (MLDSA44::sign(&mldsa44_sk, msg, Some(&ctx.to_le_bytes())).unwrap(), ctx) );
        ctx += 1
    }

    group.throughput(criterion::Throughput::Elements(sigs.len() as u64));

    group.bench_function("ML-DSA-44_lowmemory", |b| {
        b.iter(|| {
            for i in 0..sigs.len() {
                let (sig, ctx) = &sigs[i];
                black_box( MLDSA44::verify(&mldsa44_pk, msg, Some(&ctx.to_le_bytes()), &sig).unwrap() )
            }
        })
    });


    /*** ML-DSA-65 ***/
    let (mldsa65_pk, mldsa65_sk) = MLDSA65::keygen_from_seed(&seed).unwrap();

    // Create a vec of 1000  different signatures to verify
    // use ctx to make them different (in addition to the signing nonce being different)
    let mut sigs = Vec::< (Vec<u8>, u128) >::with_capacity(1000);

    let mut ctx = 0u128;
    for _ in 0..1000 {
        sigs.push( (MLDSA65::sign(&mldsa65_sk, msg, Some(&ctx.to_le_bytes())).unwrap(), ctx) );
        ctx += 1
    }

    group.throughput(criterion::Throughput::Elements(sigs.len() as u64));

    group.bench_function("ML-DSA-65_lowmemory", |b| {
        b.iter(|| {
            for i in 0..sigs.len() {
                let (sig, ctx) = &sigs[i];
                black_box( MLDSA65::verify(&mldsa65_pk, msg, Some(&ctx.to_le_bytes()), &sig).unwrap() )
            }
        })
    });


    /*** ML-DSA-87 ***/
    let (mldsa87_pk, mldsa87_sk) = MLDSA87::keygen_from_seed(&seed).unwrap();

    // Create a vec of 1000  different signatures to verify
    // use ctx to make them different (in addition to the signing nonce being different)
    let mut sigs = Vec::< (Vec<u8>, u128) >::with_capacity(1000);

    let mut ctx = 0u128;
    for _ in 0..1000 {
        sigs.push( (MLDSA87::sign(&mldsa87_sk, msg, Some(&ctx.to_le_bytes())).unwrap(), ctx) );
        ctx += 1
    }

    group.throughput(criterion::Throughput::Elements(sigs.len() as u64));

    group.bench_function("ML-DSA-87_lowmemory", |b| {
        b.iter(|| {
            for i in 0..sigs.len() {
                let (sig, ctx) = &sigs[i];
                black_box( MLDSA87::verify(&mldsa87_pk, msg, Some(&ctx.to_le_bytes()), &sig).unwrap() )
            }
        })
    });

    group.finish();
}


criterion_group!(benches, bench_mldsa_keygen, bench_mldsa_sign, bench_mldsa_verify);
criterion_main!(benches);

const DUMMY_SEED_1024: &[u8; 1024] = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff";
