//! The purpose of this binary is to perform a single run of the primitive under test so that
//! its peak memory usage can be measured with:
//!
//! ```text
//! valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_sm2_mem_usage > /dev/null
//!
//! ms_print massif.out.*
//! ```
//!
//! or, shoved all into one line:
//!
//! ```text
//! clear; clear; valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_sm2_mem_usage > /dev/null; ms_print massif.out.*; rm massif.out.*
//! ```
//!
//! Make sure you build in release mode!
//!
//! The code is using print!() to force the compiler not to optimize away the actual code.
//! It is printing important outputs for benchmarking to stderr so that the rest can be mapped to /dev/null
//! (this is because /usr/bin/time prints useful outputs to stderr as well)
//!
//! Main is at the bottom, controls which this was actually run.

#![allow(dead_code)]
#![allow(unused_imports)]

use bouncycastle::core::signature_key::{OneShotSigningKey, OneShotVerifyingKey};
use bouncycastle::core::traits::{PrivateKey, PublicKey};
use bouncycastle::core::traits::{SignatureSigner, SignatureVerifier};
use bouncycastle::ec::sm2::encryption::{
    C1_LEN, C3_LEN, SM2EncryptionPrivateKey, SM2EncryptionPublicKey,
};
use bouncycastle::ec::sm2::keys::{PK_LEN, SK_LEN, SM2PrivateKey, SM2PublicKey, keygen};
use bouncycastle::ec::sm2::sm2::SM2;
use bouncycastle::rng::DefaultRNG;

/// A fixed message, reused across the sign/verify benches.
const MSG: &[u8] = b"peak stack usage of SM2 sign/verify, held constant across runs";

/// SM2 requires `ctx` to carry the signer's identity `IDA`; this is a fixed placeholder, not a
/// module-provided default (the `sm2` module has none -- see `bouncycastle_ec::sm2::sm2`'s docs).
const ID: &[u8] = b"1234567812345678";

/// This prints the in-memory size of the public and private key structs, plus their on-disk
/// encoded length.
fn print_struct_sizes() {
    use core::mem::size_of;

    println!("\nSM2");
    println!("size_of<SM2PublicKey>: {}", size_of::<SM2PublicKey>());
    println!("PK_LEN (on disk): {}", PK_LEN);
    println!("size_of<SM2PrivateKey>: {}", size_of::<SM2PrivateKey>());
    println!("SK_LEN (on disk): {}", SK_LEN);

    println!("\nSM2 encryption");
    println!("size_of<SM2EncryptionPublicKey>: {}", size_of::<SM2EncryptionPublicKey>());
    println!("PK_LEN (on disk): {}", PK_LEN);
    println!("size_of<SM2EncryptionPrivateKey>: {}", size_of::<SM2EncryptionPrivateKey>());
    println!("SK_LEN (on disk): {}", SK_LEN);
}

/// This exists that /usr/bin/time can be used to measure the base memory footprint of the cargo bench harness
fn bench_do_nothing() {
    eprintln!("DoNothing");

    print!("{}", 1 + 1);
}

fn bench_sm2_keygen() {
    eprintln!("SM2/KeyGen");

    let (pk, _sk) = keygen(&mut DefaultRNG::default()).unwrap();
    println!("{:x?}", pk.encode());
}

fn bench_sm2_sign() {
    eprintln!("SM2/Sign");

    // dA = 42, well within [1, n-1] -- same fixed-key trick the `sm2` module's own tests use, so
    // keygen's own stack cost is not folded into this measurement.
    let mut bytes = [0u8; SK_LEN];
    bytes[SK_LEN - 1] = 0x2A;
    let sk = SM2PrivateKey::from_bytes(&bytes).unwrap();

    let sig = sk.sign(&mut DefaultRNG::default(), MSG, Some(ID)).unwrap();
    println!("{:x?}", sig);
}

fn bench_sm2_verify() {
    eprintln!("SM2/Verify");

    let mut bytes = [0u8; SK_LEN];
    bytes[SK_LEN - 1] = 0x2A;
    let sk = SM2PrivateKey::from_bytes(&bytes).unwrap();
    let pk = sk.pub_key().unwrap();
    let sig = sk.sign(&mut DefaultRNG::default(), MSG, Some(ID)).unwrap();

    if pk.verify(MSG, Some(ID), &sig).is_ok() {
        eprintln!("Verification succeeded!");
    } else {
        panic!("Verification failed! -- figure that out");
    }
}

/// The message the encryption benches use: longer than one SM3 hash value, so the key stream
/// runs to a second block.
const PLAINTEXT: [u8; 48] = [0x4d; 48];

/// dB = 42, as the signing benches use, so that key generation is not part of the measurement.
fn encryption_key_pair() -> (SM2EncryptionPublicKey, SM2EncryptionPrivateKey) {
    let mut bytes = [0u8; SK_LEN];
    bytes[SK_LEN - 1] = 0x2A;
    let sk = SM2EncryptionPrivateKey::from_bytes(&bytes).unwrap();
    (sk.pub_key().unwrap(), sk)
}

fn bench_sm2_encryption_keygen() {
    eprintln!("SM2 encryption/KeyGen");

    let (pk, _sk) = bouncycastle::ec::sm2::encryption::keygen(&mut DefaultRNG::default()).unwrap();
    println!("{:x?}", pk.encode());
}

fn bench_sm2_encrypt() {
    eprintln!("SM2 encryption/Encrypt");

    let (pk, _sk) = encryption_key_pair();
    let mut buf = PLAINTEXT;
    let (c1, c3) = pk.encrypt_detached_inplace(&mut DefaultRNG::default(), &mut buf).unwrap();
    println!("{:x?}{:x?}{:x?}", c1, c3, buf);
}

fn bench_sm2_decrypt() {
    eprintln!("SM2 encryption/Decrypt");

    let (pk, sk) = encryption_key_pair();
    let mut buf = PLAINTEXT;
    let (c1, c3) = pk.encrypt_detached_inplace(&mut DefaultRNG::default(), &mut buf).unwrap();

    sk.decrypt_detached_inplace(&c1, &c3, &mut buf).unwrap();
    println!("{:x?}", buf);
}

fn main() {
    print_struct_sizes()
    // bench_do_nothing()
    // bench_sm2_keygen()
    // bench_sm2_sign()
    // bench_sm2_verify()
    // bench_sm2_encryption_keygen()
    // bench_sm2_encrypt()
    // bench_sm2_decrypt()
}
