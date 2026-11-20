//! The purpose of this binary is to perform a single run of the primitive under test so that
//! its peak memory usage can be measured with:
//!
//! ```text
//! valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_x448_mem_usage > /dev/null
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
//! The keys are the published test vector (RFC 7748 Section 6.2), hard-coded so that no keygen
//! runs in a bench that does not measure it.

#![allow(dead_code)]
#![allow(unused_imports)]

use bouncycastle::core::agreement_key::AgreementKey;
use bouncycastle::core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle::core::traits::{PrivateKey, PublicKey};
use bouncycastle::ed::x448::{X448PrivateKey, X448PublicKey, keygen_from_seed};

/// RFC 7748 Section 6.2's Alice private key.
const ALICE_SK: [u8; 56] = [
    0x9a, 0x8f, 0x49, 0x25, 0xd1, 0x51, 0x9f, 0x57, 0x75, 0xcf, 0x46, 0xb0, 0x4b, 0x58, 0x00, 0xd4,
    0xee, 0x9e, 0xe8, 0xba, 0xe8, 0xbc, 0x55, 0x65, 0xd4, 0x98, 0xc2, 0x8d, 0xd9, 0xc9, 0xba, 0xf5,
    0x74, 0xa9, 0x41, 0x97, 0x44, 0x89, 0x73, 0x91, 0x00, 0x63, 0x82, 0xa6, 0xf1, 0x27, 0xab, 0x1d,
    0x9a, 0xc2, 0xd8, 0xc0, 0xa5, 0x98, 0x72, 0x6b,
];

/// RFC 7748 Section 6.2's Bob public key.
const BOB_PK: [u8; 56] = [
    0x3e, 0xb7, 0xa8, 0x29, 0xb0, 0xcd, 0x20, 0xf5, 0xbc, 0xfc, 0x0b, 0x59, 0x9b, 0x6f, 0xec, 0xcf,
    0x6d, 0xa4, 0x62, 0x71, 0x07, 0xbd, 0xb0, 0xd4, 0xf3, 0x45, 0xb4, 0x30, 0x27, 0xd8, 0xb9, 0x72,
    0xfc, 0x3e, 0x34, 0xfb, 0x42, 0x32, 0xa1, 0x3c, 0xa7, 0x06, 0xdc, 0xb5, 0x7a, 0xec, 0x3d, 0xae,
    0x07, 0xbd, 0xc1, 0xc6, 0x7b, 0xf3, 0x36, 0x09,
];

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
    println!("X448PublicKey: {}", size_of::<X448PublicKey>());
    println!("X448PrivateKey: {}", size_of::<X448PrivateKey>());
}

/// Loads Alice's private key. `#[inline(never)]` so its decode temporaries are popped before
/// the operation runs.
#[inline(never)]
fn load_alice_sk() -> X448PrivateKey {
    X448PrivateKey::from_bytes(&ALICE_SK).unwrap()
}

/// Loads Bob's public key.
#[inline(never)]
fn load_bob_pk() -> X448PublicKey {
    X448PublicKey::from_bytes(&BOB_PK).unwrap()
}

/// Key generation from a seed (Alice's private key): one fixed-base scalar multiplication. The
/// seed is the input, so it is built in the bench body.
fn bench_x448_keygen() {
    eprintln!("X448/KeyGen");

    let seed = KeyMaterial::<56>::from_bytes_as_type(&ALICE_SK, KeyType::Seed).unwrap();

    measure(|| {
        let (pk, _sk) = keygen_from_seed(&seed).unwrap();
        print!("{:x?}", pk.encode());
    });
}

/// Decoding a private key, which computes its public key: one fixed-base scalar multiplication.
fn bench_x448_from_bytes() {
    eprintln!("X448/FromBytes");

    let bytes = [0x2Au8; 56];
    measure(|| {
        let sk = X448PrivateKey::from_bytes(&bytes).unwrap();
        print!("{:x?}", sk.pk().encode());
    });
}

/// Key agreement: one variable-base scalar multiplication and the all-zero check.
fn bench_x448_key_agreement() {
    eprintln!("X448/KeyAgreement");

    let sk = load_alice_sk();
    let pk = load_bob_pk();
    measure(|| {
        let k = sk.agree(&pk, ()).unwrap();
        print!("{:x?}", k.ref_to_bytes());
    });
}

fn main() {
    // print_struct_sizes()
    // bench_do_nothing()
    bench_x448_keygen()
    // bench_x448_from_bytes()
    // bench_x448_key_agreement()
}
