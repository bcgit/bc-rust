//! The purpose of this binary is to perform a single run of the primitive under test so that
//! its peak memory usage can be measured with:
//!
//! ```text
//! valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_ecdsa_mem_usage > /dev/null
//!
//! ms_print massif.out.*
//! ```
//!
//! or, shoved all into one line:
//!
//! ```text
//! clear; clear; valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_ecdsa_mem_usage > /dev/null; ms_print massif.out.*; rm massif.out.*
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

use bouncycastle::core::traits::{
    SignaturePrivateKey, SignaturePublicKey, SignatureVerifier, Signer,
};
use bouncycastle::ecdsa::keys_common::DerivePublicKey;
use bouncycastle::ecdsa::{
    ecdsa_bp256r1::ECDSABp256r1, ecdsa_bp384r1::ECDSABp384r1, ecdsa_bp512r1::ECDSABp512r1,
    ecdsa_p256::ECDSAP256, ecdsa_p256k1::ECDSASecp256K1, ecdsa_p384::ECDSAP384,
    ecdsa_p521::ECDSAP521,
};
use bouncycastle::ecdsa::{
    keys as keys_p256, keys_bp256r1, keys_bp384r1, keys_bp512r1, keys_p256k1, keys_p384, keys_p521,
};

/// A fixed message, reused across every curve's sign/verify bench so peak stack usage reflects
/// only the signature algorithm, not message size.
const MSG: &[u8] = b"peak stack usage of ECDSA sign/verify, held constant across every curve";

/// This prints the in-memory size of all the public and private key structs, plus their on-disk
/// encoded length, for every curve.
fn print_struct_sizes() {
    use core::mem::size_of;

    println!("\nECDSA P-256");
    println!("size_of<ECDSAP256PublicKey>: {}", size_of::<keys_p256::ECDSAP256PublicKey>());
    println!("PK_LEN (on disk): {}", keys_p256::PK_LEN);
    println!("size_of<ECDSAP256PrivateKey>: {}", size_of::<keys_p256::ECDSAP256PrivateKey>());
    println!("SK_LEN (on disk): {}", keys_p256::SK_LEN);

    println!("\nECDSA P-384");
    println!("size_of<ECDSAP384PublicKey>: {}", size_of::<keys_p384::ECDSAP384PublicKey>());
    println!("PK_LEN (on disk): {}", keys_p384::PK_LEN);
    println!("size_of<ECDSAP384PrivateKey>: {}", size_of::<keys_p384::ECDSAP384PrivateKey>());
    println!("SK_LEN (on disk): {}", keys_p384::SK_LEN);

    println!("\nECDSA P-521");
    println!("size_of<ECDSAP521PublicKey>: {}", size_of::<keys_p521::ECDSAP521PublicKey>());
    println!("PK_LEN (on disk): {}", keys_p521::PK_LEN);
    println!("size_of<ECDSAP521PrivateKey>: {}", size_of::<keys_p521::ECDSAP521PrivateKey>());
    println!("SK_LEN (on disk): {}", keys_p521::SK_LEN);

    println!("\nECDSA secp256k1");
    println!(
        "size_of<ECDSASecp256K1PublicKey>: {}",
        size_of::<keys_p256k1::ECDSASecp256K1PublicKey>()
    );
    println!("PK_LEN (on disk): {}", keys_p256k1::PK_LEN);
    println!(
        "size_of<ECDSASecp256K1PrivateKey>: {}",
        size_of::<keys_p256k1::ECDSASecp256K1PrivateKey>()
    );
    println!("SK_LEN (on disk): {}", keys_p256k1::SK_LEN);

    println!("\nECDSA brainpoolP256r1");
    println!(
        "size_of<ECDSABp256r1PublicKey>: {}",
        size_of::<keys_bp256r1::ECDSABp256r1PublicKey>()
    );
    println!("PK_LEN (on disk): {}", keys_bp256r1::PK_LEN);
    println!(
        "size_of<ECDSABp256r1PrivateKey>: {}",
        size_of::<keys_bp256r1::ECDSABp256r1PrivateKey>()
    );
    println!("SK_LEN (on disk): {}", keys_bp256r1::SK_LEN);

    println!("\nECDSA brainpoolP384r1");
    println!(
        "size_of<ECDSABp384r1PublicKey>: {}",
        size_of::<keys_bp384r1::ECDSABp384r1PublicKey>()
    );
    println!("PK_LEN (on disk): {}", keys_bp384r1::PK_LEN);
    println!(
        "size_of<ECDSABp384r1PrivateKey>: {}",
        size_of::<keys_bp384r1::ECDSABp384r1PrivateKey>()
    );
    println!("SK_LEN (on disk): {}", keys_bp384r1::SK_LEN);

    println!("\nECDSA brainpoolP512r1");
    println!(
        "size_of<ECDSABp512r1PublicKey>: {}",
        size_of::<keys_bp512r1::ECDSABp512r1PublicKey>()
    );
    println!("PK_LEN (on disk): {}", keys_bp512r1::PK_LEN);
    println!(
        "size_of<ECDSABp512r1PrivateKey>: {}",
        size_of::<keys_bp512r1::ECDSABp512r1PrivateKey>()
    );
    println!("SK_LEN (on disk): {}", keys_bp512r1::SK_LEN);
}

/// This exists that /usr/bin/time can be used to measure the base memory footprint of the cargo bench harness
fn bench_do_nothing() {
    eprintln!("DoNothing");

    print!("{}", 1 + 1);
}

fn bench_p256_keygen() {
    eprintln!("ECDSA P-256/KeyGen");

    let (pk, _sk) = keys_p256::keygen().unwrap();
    println!("{:x?}", pk.encode());
}

fn bench_p256_sign() {
    eprintln!("ECDSA P-256/Sign");

    // d = 42, well within [1, n-1] -- same fixed-key trick the crate's own tests use, so keygen's
    // own stack cost is not folded into this measurement.
    let mut bytes = [0u8; keys_p256::SK_LEN];
    bytes[keys_p256::SK_LEN - 1] = 0x2A;
    let sk = keys_p256::ECDSAP256PrivateKey::from_bytes(&bytes).unwrap();

    let sig = ECDSAP256::sign(&sk, MSG, None).unwrap();
    println!("{:x?}", sig);
}

fn bench_p256_verify() {
    eprintln!("ECDSA P-256/Verify");

    let mut bytes = [0u8; keys_p256::SK_LEN];
    bytes[keys_p256::SK_LEN - 1] = 0x2A;
    let sk = keys_p256::ECDSAP256PrivateKey::from_bytes(&bytes).unwrap();
    let pk = sk.derive_pk();
    let sig = ECDSAP256::sign(&sk, MSG, None).unwrap();

    if ECDSAP256::verify(&pk, MSG, None, &sig).is_ok() {
        eprintln!("Verification succeeded!");
    } else {
        panic!("Verification failed! -- figure that out");
    }
}

fn bench_p384_keygen() {
    eprintln!("ECDSA P-384/KeyGen");

    let (pk, _sk) = keys_p384::keygen().unwrap();
    println!("{:x?}", pk.encode());
}

fn bench_p384_sign() {
    eprintln!("ECDSA P-384/Sign");

    let mut bytes = [0u8; keys_p384::SK_LEN];
    bytes[keys_p384::SK_LEN - 1] = 0x2A;
    let sk = keys_p384::ECDSAP384PrivateKey::from_bytes(&bytes).unwrap();

    let sig = ECDSAP384::sign(&sk, MSG, None).unwrap();
    println!("{:x?}", sig);
}

fn bench_p384_verify() {
    eprintln!("ECDSA P-384/Verify");

    let mut bytes = [0u8; keys_p384::SK_LEN];
    bytes[keys_p384::SK_LEN - 1] = 0x2A;
    let sk = keys_p384::ECDSAP384PrivateKey::from_bytes(&bytes).unwrap();
    let pk = sk.derive_pk();
    let sig = ECDSAP384::sign(&sk, MSG, None).unwrap();

    if ECDSAP384::verify(&pk, MSG, None, &sig).is_ok() {
        eprintln!("Verification succeeded!");
    } else {
        panic!("Verification failed! -- figure that out");
    }
}

fn bench_p521_keygen() {
    eprintln!("ECDSA P-521/KeyGen");

    let (pk, _sk) = keys_p521::keygen().unwrap();
    println!("{:x?}", pk.encode());
}

fn bench_p521_sign() {
    eprintln!("ECDSA P-521/Sign");

    let mut bytes = [0u8; keys_p521::SK_LEN];
    bytes[keys_p521::SK_LEN - 1] = 0x2A;
    let sk = keys_p521::ECDSAP521PrivateKey::from_bytes(&bytes).unwrap();

    let sig = ECDSAP521::sign(&sk, MSG, None).unwrap();
    println!("{:x?}", sig);
}

fn bench_p521_verify() {
    eprintln!("ECDSA P-521/Verify");

    let mut bytes = [0u8; keys_p521::SK_LEN];
    bytes[keys_p521::SK_LEN - 1] = 0x2A;
    let sk = keys_p521::ECDSAP521PrivateKey::from_bytes(&bytes).unwrap();
    let pk = sk.derive_pk();
    let sig = ECDSAP521::sign(&sk, MSG, None).unwrap();

    if ECDSAP521::verify(&pk, MSG, None, &sig).is_ok() {
        eprintln!("Verification succeeded!");
    } else {
        panic!("Verification failed! -- figure that out");
    }
}

fn bench_secp256k1_keygen() {
    eprintln!("ECDSA secp256k1/KeyGen");

    let (pk, _sk) = keys_p256k1::keygen().unwrap();
    println!("{:x?}", pk.encode());
}

fn bench_secp256k1_sign() {
    eprintln!("ECDSA secp256k1/Sign");

    let mut bytes = [0u8; keys_p256k1::SK_LEN];
    bytes[keys_p256k1::SK_LEN - 1] = 0x2A;
    let sk = keys_p256k1::ECDSASecp256K1PrivateKey::from_bytes(&bytes).unwrap();

    let sig = ECDSASecp256K1::sign(&sk, MSG, None).unwrap();
    println!("{:x?}", sig);
}

fn bench_secp256k1_verify() {
    eprintln!("ECDSA secp256k1/Verify");

    let mut bytes = [0u8; keys_p256k1::SK_LEN];
    bytes[keys_p256k1::SK_LEN - 1] = 0x2A;
    let sk = keys_p256k1::ECDSASecp256K1PrivateKey::from_bytes(&bytes).unwrap();
    let pk = sk.derive_pk();
    let sig = ECDSASecp256K1::sign(&sk, MSG, None).unwrap();

    if ECDSASecp256K1::verify(&pk, MSG, None, &sig).is_ok() {
        eprintln!("Verification succeeded!");
    } else {
        panic!("Verification failed! -- figure that out");
    }
}

fn bench_bp256r1_keygen() {
    eprintln!("ECDSA brainpoolP256r1/KeyGen");

    let (pk, _sk) = keys_bp256r1::keygen().unwrap();
    println!("{:x?}", pk.encode());
}

fn bench_bp256r1_sign() {
    eprintln!("ECDSA brainpoolP256r1/Sign");

    let mut bytes = [0u8; keys_bp256r1::SK_LEN];
    bytes[keys_bp256r1::SK_LEN - 1] = 0x2A;
    let sk = keys_bp256r1::ECDSABp256r1PrivateKey::from_bytes(&bytes).unwrap();

    let sig = ECDSABp256r1::sign(&sk, MSG, None).unwrap();
    println!("{:x?}", sig);
}

fn bench_bp256r1_verify() {
    eprintln!("ECDSA brainpoolP256r1/Verify");

    let mut bytes = [0u8; keys_bp256r1::SK_LEN];
    bytes[keys_bp256r1::SK_LEN - 1] = 0x2A;
    let sk = keys_bp256r1::ECDSABp256r1PrivateKey::from_bytes(&bytes).unwrap();
    let pk = sk.derive_pk();
    let sig = ECDSABp256r1::sign(&sk, MSG, None).unwrap();

    if ECDSABp256r1::verify(&pk, MSG, None, &sig).is_ok() {
        eprintln!("Verification succeeded!");
    } else {
        panic!("Verification failed! -- figure that out");
    }
}

fn bench_bp384r1_keygen() {
    eprintln!("ECDSA brainpoolP384r1/KeyGen");

    let (pk, _sk) = keys_bp384r1::keygen().unwrap();
    println!("{:x?}", pk.encode());
}

fn bench_bp384r1_sign() {
    eprintln!("ECDSA brainpoolP384r1/Sign");

    let mut bytes = [0u8; keys_bp384r1::SK_LEN];
    bytes[keys_bp384r1::SK_LEN - 1] = 0x2A;
    let sk = keys_bp384r1::ECDSABp384r1PrivateKey::from_bytes(&bytes).unwrap();

    let sig = ECDSABp384r1::sign(&sk, MSG, None).unwrap();
    println!("{:x?}", sig);
}

fn bench_bp384r1_verify() {
    eprintln!("ECDSA brainpoolP384r1/Verify");

    let mut bytes = [0u8; keys_bp384r1::SK_LEN];
    bytes[keys_bp384r1::SK_LEN - 1] = 0x2A;
    let sk = keys_bp384r1::ECDSABp384r1PrivateKey::from_bytes(&bytes).unwrap();
    let pk = sk.derive_pk();
    let sig = ECDSABp384r1::sign(&sk, MSG, None).unwrap();

    if ECDSABp384r1::verify(&pk, MSG, None, &sig).is_ok() {
        eprintln!("Verification succeeded!");
    } else {
        panic!("Verification failed! -- figure that out");
    }
}

fn bench_bp512r1_keygen() {
    eprintln!("ECDSA brainpoolP512r1/KeyGen");

    let (pk, _sk) = keys_bp512r1::keygen().unwrap();
    println!("{:x?}", pk.encode());
}

fn bench_bp512r1_sign() {
    eprintln!("ECDSA brainpoolP512r1/Sign");

    let mut bytes = [0u8; keys_bp512r1::SK_LEN];
    bytes[keys_bp512r1::SK_LEN - 1] = 0x2A;
    let sk = keys_bp512r1::ECDSABp512r1PrivateKey::from_bytes(&bytes).unwrap();

    let sig = ECDSABp512r1::sign(&sk, MSG, None).unwrap();
    println!("{:x?}", sig);
}

fn bench_bp512r1_verify() {
    eprintln!("ECDSA brainpoolP512r1/Verify");

    let mut bytes = [0u8; keys_bp512r1::SK_LEN];
    bytes[keys_bp512r1::SK_LEN - 1] = 0x2A;
    let sk = keys_bp512r1::ECDSABp512r1PrivateKey::from_bytes(&bytes).unwrap();
    let pk = sk.derive_pk();
    let sig = ECDSABp512r1::sign(&sk, MSG, None).unwrap();

    if ECDSABp512r1::verify(&pk, MSG, None, &sig).is_ok() {
        eprintln!("Verification succeeded!");
    } else {
        panic!("Verification failed! -- figure that out");
    }
}

fn main() {
    print_struct_sizes()
    // bench_do_nothing()
    // bench_p256_keygen()
    // bench_p256_sign()
    // bench_p256_verify()
    // bench_p384_keygen()
    // bench_p384_sign()
    // bench_p384_verify()
    // bench_p521_keygen()
    // bench_p521_sign()
    // bench_p521_verify()
    // bench_secp256k1_keygen()
    // bench_secp256k1_sign()
    // bench_secp256k1_verify()
    // bench_bp256r1_keygen()
    // bench_bp256r1_sign()
    // bench_bp256r1_verify()
    // bench_bp384r1_keygen()
    // bench_bp384r1_sign()
    // bench_bp384r1_verify()
    // bench_bp512r1_keygen()
    // bench_bp512r1_sign()
    // bench_bp512r1_verify()
}
