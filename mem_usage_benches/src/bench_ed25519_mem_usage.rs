//! The purpose of this binary is to perform a single run of the primitive under test so that
//! its peak memory usage can be measured with:
//!
//! ```text
//! valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_ed25519_mem_usage > /dev/null
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
//! The key, the messages and the signatures are the published test vectors (RFC 8032 Section 7.1,
//! TEST SHA(abc), and Section 7.3), hard-coded so that no keygen or signing runs in a bench that
//! does not measure it.

#![allow(dead_code)]
#![allow(unused_imports)]

use bouncycastle::core::hazmat::FixedSeedRNG;
use bouncycastle::core::signature_key::{
    DeterministicOneShotSigningKey, DeterministicSigningKey, OneShotVerifyingKey, VerifyingKey,
};
use bouncycastle::core::traits::{PrivateKey, PublicKey, SignatureSigner, SignatureVerifier};
use bouncycastle::ec::ed::ed25519::{Ed25519PrivateKey, Ed25519PublicKey, keygen, keygen_out};
use std::hint::black_box;

/// The private key of RFC 8032 Section 7.1's TEST SHA(abc) and Section 7.3's TEST abc.
const SK: [u8; 32] = [
    0x83, 0x3f, 0xe6, 0x24, 0x09, 0x23, 0x7b, 0x9d, 0x62, 0xec, 0x77, 0x58, 0x75, 0x20, 0x91, 0x1e,
    0x9a, 0x75, 0x9c, 0xec, 0x1d, 0x19, 0x75, 0x5b, 0x7d, 0xa9, 0x01, 0xb9, 0x6d, 0xca, 0x3d, 0x42,
];

/// Its public key.
const PK: [u8; 32] = [
    0xec, 0x17, 0x2b, 0x93, 0xad, 0x5e, 0x56, 0x3b, 0xf4, 0x93, 0x2c, 0x70, 0xe1, 0x24, 0x50, 0x34,
    0xc3, 0x54, 0x67, 0xef, 0x2e, 0xfd, 0x4d, 0x64, 0xeb, 0xf8, 0x19, 0x68, 0x34, 0x67, 0xe2, 0xbf,
];

/// The message of TEST SHA(abc), 64 octets.
const MSG: [u8; 64] = [
    0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
    0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
    0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
    0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
];

/// Its Ed25519 signature.
const SIG: [u8; 64] = [
    0xdc, 0x2a, 0x44, 0x59, 0xe7, 0x36, 0x96, 0x33, 0xa5, 0x2b, 0x1b, 0xf2, 0x77, 0x83, 0x9a, 0x00,
    0x20, 0x10, 0x09, 0xa3, 0xef, 0xbf, 0x3e, 0xcb, 0x69, 0xbe, 0xa2, 0x18, 0x6c, 0x26, 0xb5, 0x89,
    0x09, 0x35, 0x1f, 0xc9, 0xac, 0x90, 0xb3, 0xec, 0xfd, 0xfb, 0xc7, 0xc6, 0x64, 0x31, 0xe0, 0x30,
    0x3d, 0xca, 0x17, 0x9c, 0x13, 0x8a, 0xc1, 0x7a, 0xd9, 0xbe, 0xf1, 0x17, 0x73, 0x31, 0xa7, 0x04,
];

/// The message of TEST abc.
const MSG_PH: [u8; 3] = [0x61, 0x62, 0x63];

/// Its Ed25519ph signature, under the empty context.
const SIG_PH: [u8; 64] = [
    0x98, 0xa7, 0x02, 0x22, 0xf0, 0xb8, 0x12, 0x1a, 0xa9, 0xd3, 0x0f, 0x81, 0x3d, 0x68, 0x3f, 0x80,
    0x9e, 0x46, 0x2b, 0x46, 0x9c, 0x7f, 0xf8, 0x76, 0x39, 0x49, 0x9b, 0xb9, 0x4e, 0x6d, 0xae, 0x41,
    0x31, 0xf8, 0x50, 0x42, 0x46, 0x3c, 0x2a, 0x35, 0x5a, 0x20, 0x03, 0xd0, 0x62, 0xad, 0xf5, 0xaa,
    0xa1, 0x0b, 0x8c, 0x61, 0xe6, 0x36, 0x06, 0x2a, 0xaa, 0xd1, 0x1c, 0x2a, 0x26, 0x08, 0x34, 0x06,
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
    println!("Ed25519PublicKey: {}", size_of::<Ed25519PublicKey>());
    println!("Ed25519PrivateKey: {}", size_of::<Ed25519PrivateKey>());
}

/// Loads [`SK`]. `#[inline(never)]` so its decode temporaries are popped before the operation
/// runs.
#[inline(never)]
fn load_sk() -> Ed25519PrivateKey {
    Ed25519PrivateKey::from_bytes(&SK).unwrap()
}

/// Loads [`PK`].
#[inline(never)]
fn load_pk() -> Ed25519PublicKey {
    Ed25519PublicKey::from_bytes(&PK).unwrap()
}

/// Key generation: SHA-512 and one fixed-base scalar multiplication. The RNG only copies its
/// seed out, so the figure is the key generation's own and not a DRBG's.
fn bench_ed25519_keygen() {
    eprintln!("Ed25519/KeyGen");

    measure(|| {
        let (pk, _sk) = keygen(&mut FixedSeedRNG::new(SK)).unwrap();
        print!("{:x?}", pk.encode());
    });
}

/// Key generation into a key the caller holds.
fn bench_ed25519_keygen_out() {
    eprintln!("Ed25519/KeyGenOut");

    let mut sk = Ed25519PrivateKey::zeroized();
    measure(|| {
        keygen_out(&mut FixedSeedRNG::new(SK), &mut sk).unwrap();
        print!("{:x?}", sk.pk().unwrap().encode());
    });
}

/// Decoding a private key, which derives its public key as key generation does.
fn bench_ed25519_sk_from_bytes() {
    eprintln!("Ed25519/PrivateKeyFromBytes");

    measure(|| {
        let sk = Ed25519PrivateKey::from_bytes(&SK).unwrap();
        black_box(&sk);
    });
}

/// Decoding a private key into a key the caller holds.
fn bench_ed25519_sk_from_bytes_out() {
    eprintln!("Ed25519/PrivateKeyFromBytesOut");

    let mut sk = Ed25519PrivateKey::zeroized();
    measure(|| {
        Ed25519PrivateKey::from_bytes_out(&SK, &mut sk).unwrap();
        black_box(&sk);
    });
}

/// Decoding a public key: decompression and the subgroup check, a variable-time multiplication
/// by the group order.
fn bench_ed25519_pk_from_bytes() {
    eprintln!("Ed25519/PublicKeyFromBytes");

    measure(|| {
        let pk = Ed25519PublicKey::from_bytes(&PK).unwrap();
        print!("{:x?}", pk.encode());
    });
}

/// The public key of a private key: a decompression of the stored encoding.
fn bench_ed25519_pk() {
    eprintln!("Ed25519/PublicKeyOfPrivateKey");

    let sk = load_sk();
    measure(|| {
        let pk = sk.pk().unwrap();
        print!("{:x?}", pk.encode());
    });
}

/// Ed25519 signing: two SHA-512 passes and one fixed-base scalar multiplication.
fn bench_ed25519_sign() {
    eprintln!("Ed25519/Sign");

    let sk = load_sk();
    measure(|| {
        let sig = sk.sign_deterministic(&MSG, None).unwrap();
        print!("{:x?}", sig);
    });
}

/// Ed25519 verification: one SHA-512 pass and a variable-time double-scalar multiplication.
fn bench_ed25519_verify() {
    eprintln!("Ed25519/Verify");

    let pk = load_pk();
    measure(|| {
        pk.verify(&MSG, None, &SIG).unwrap();
        print!("ok");
    });
}

/// Ed25519ph signing through the streaming signer, which the one-shot runs too.
fn bench_ed25519ph_sign() {
    eprintln!("Ed25519ph/Sign");

    let sk = load_sk();
    measure(|| {
        let mut signer = sk.as_prehash().create_signer_deterministic(None).unwrap();
        signer.do_update(&MSG_PH);
        let sig = signer.do_final().unwrap();
        print!("{:x?}", sig);
    });
}

/// Ed25519ph verification through the streaming verifier.
fn bench_ed25519ph_verify() {
    eprintln!("Ed25519ph/Verify");

    let pk = load_pk();
    measure(|| {
        let mut verifier = pk.as_prehash().create_verifier(None).unwrap();
        verifier.do_update(&MSG_PH);
        verifier.do_verify_final(&SIG_PH).unwrap();
        print!("ok");
    });
}

fn main() {
    // print_struct_sizes()
    // bench_do_nothing()
    bench_ed25519_keygen()
    // bench_ed25519_keygen_out()
    // bench_ed25519_sk_from_bytes()
    // bench_ed25519_sk_from_bytes_out()
    // bench_ed25519_pk_from_bytes()
    // bench_ed25519_pk()
    // bench_ed25519_sign()
    // bench_ed25519_verify()
    // bench_ed25519ph_sign()
    // bench_ed25519ph_verify()
}
