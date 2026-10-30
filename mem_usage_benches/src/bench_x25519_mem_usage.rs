//! The purpose of this binary is to perform a single run of the primitive under test so that
//! its peak memory usage can be measured with:
//!
//! ```text
//! valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_x25519_mem_usage > /dev/null
//!
//! ms_print massif.out.*
//! ```
//!
//! Make sure you build in release mode!
//!
//! Note: print!() forces the compiler not to optimize away the actual code. The name of the bench
//! goes to stderr so that the junk on stdout can be piped to /dev/null.
//!
//! Main is at the bottom, controls which bench is actually run.
//!
//! The keys and the ciphertext are the published test vectors (RFC 7748 Section 6.1 and RFC 9180
//! Appendix A.1.1), hard-coded so that no keygen runs in a bench that does not measure it.

#![allow(dead_code)]
#![allow(unused_imports)]

use bouncycastle::core::key_material::{KeyMaterial256, KeyType};
use bouncycastle::core::traits::{
    KEMDecapsulator, KEMEncapsulator, KeyAgreement, KeyAgreementPrivateKey, KeyAgreementPublicKey,
};
use bouncycastle::ed::x25519::{X25519, X25519PrivateKey, X25519PublicKey};

/// Runs the operation under test in its own stack frame, with the key already loaded by the
/// caller.
///
/// `#[inline(never)]` matters here too: the bench functions inline the whole operation, so
/// without this boundary the operation's frame would be allocated on entry to the bench and the
/// key-load helper's frame would stack on top of it, reporting their sum instead of their max.
/// The closure returns nothing, so no result is copied back across the boundary.
#[inline(never)]
fn measure(f: impl FnOnce()) {
    f()
}

/// This exists so I can use /usr/bin/time to measure the base memory footprint of the harness.
fn bench_do_nothing() {
    eprintln!("DoNothing");

    print!("{}", 1 + 1);
}

/// This prints the in-memory size of the public and private key structs.
fn print_struct_sizes() {
    println!("X25519PublicKey: {}", size_of::<X25519PublicKey>());
    println!("X25519PrivateKey: {}", size_of::<X25519PrivateKey>());
}

/// Loads RFC 7748 Section 6.1's Alice private key. `#[inline(never)]` so its byte array and decode
/// temporaries are popped before the operation runs.
#[inline(never)]
fn load_alice_sk() -> X25519PrivateKey {
    X25519PrivateKey::from_bytes(&[
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66,
        0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9,
        0x2c, 0x2a,
    ])
    .unwrap()
}

/// Loads RFC 7748 Section 6.1's Bob public key.
#[inline(never)]
fn load_bob_pk() -> X25519PublicKey {
    X25519PublicKey::from_bytes(&[
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35,
        0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88,
        0x2b, 0x4f,
    ])
    .unwrap()
}

/// Loads RFC 9180 Appendix A.1.1's skRm.
#[inline(never)]
fn load_sk_rm() -> X25519PrivateKey {
    X25519PrivateKey::from_bytes(&[
        0x46, 0x12, 0xc5, 0x50, 0x26, 0x3f, 0xc8, 0xad, 0x58, 0x37, 0x5d, 0xf3, 0xf5, 0x57, 0xaa,
        0xc5, 0x31, 0xd2, 0x68, 0x50, 0x90, 0x3e, 0x55, 0xa9, 0xf2, 0x3f, 0x21, 0xd8, 0x53, 0x4e,
        0x8a, 0xc8,
    ])
    .unwrap()
}

/// Loads RFC 9180 Appendix A.1.1's pkRm.
#[inline(never)]
fn load_pk_rm() -> X25519PublicKey {
    X25519PublicKey::from_bytes(&[
        0x39, 0x48, 0xcf, 0xe0, 0xad, 0x1d, 0xdb, 0x69, 0x5d, 0x78, 0x0e, 0x59, 0x07, 0x71, 0x95,
        0xda, 0x6c, 0x56, 0x50, 0x6b, 0x02, 0x73, 0x29, 0x79, 0x4a, 0xb0, 0x2b, 0xca, 0x80, 0x81,
        0x5c, 0x4d,
    ])
    .unwrap()
}

/// Key generation from a seed (RFC 7748 Section 6.1's Alice private key): one fixed-base scalar
/// multiplication. The seed is the input, so it is built in the bench body.
fn bench_x25519_keygen() {
    eprintln!("X25519/KeyGen");

    let seed = KeyMaterial256::from_bytes_as_type(
        &[
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ],
        KeyType::Seed,
    )
    .unwrap();

    measure(|| {
        let (pk, _sk) = X25519::keygen_from_seed(&seed).unwrap();
        print!("{:x?}", pk.encode());
    });
}

/// Key agreement: one variable-base scalar multiplication and the all-zero check.
fn bench_x25519_key_agreement() {
    eprintln!("X25519/KeyAgreement");

    let sk = load_alice_sk();
    let pk = load_bob_pk();
    measure(|| {
        let k = X25519::key_agreement(&pk, &sk).unwrap();
        print!("{:x?}", k.encode());
    });
}

/// DHKEM(X25519, HKDF-SHA256) encapsulation, including the OS-seeded DRBG that generates the
/// ephemeral key, since that is part of what an encapsulation costs.
fn bench_x25519_encaps() {
    eprintln!("X25519/Encaps");

    let pk = load_pk_rm();
    measure(|| {
        let (ss, ct) = X25519::encaps(&pk).unwrap();
        print!("{:x?}", ss);
        print!("{:x?}", ct);
    });
}

/// DHKEM(X25519, HKDF-SHA256) decapsulation of RFC 9180 Appendix A.1.1's enc.
fn bench_x25519_decaps() {
    eprintln!("X25519/Decaps");

    let ct: [u8; 32] = [
        0x37, 0xfd, 0xa3, 0x56, 0x7b, 0xdb, 0xd6, 0x28, 0xe8, 0x86, 0x68, 0xc3, 0xc8, 0xd7, 0xe9,
        0x7d, 0x1d, 0x12, 0x53, 0xb6, 0xd4, 0xea, 0x6d, 0x44, 0xc1, 0x50, 0xf7, 0x41, 0xf1, 0xbf,
        0x44, 0x31,
    ];

    let sk = load_sk_rm();
    measure(|| {
        let ss = X25519::decaps(&sk, &ct).unwrap();
        print!("{:x?}", ss);
    });
}

fn main() {
    // print_struct_sizes()
    // bench_do_nothing()
    bench_x25519_keygen()
    // bench_x25519_key_agreement()
    // bench_x25519_encaps()
    // bench_x25519_decaps()
}
