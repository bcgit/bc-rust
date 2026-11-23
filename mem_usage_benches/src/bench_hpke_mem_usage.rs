//! The purpose of this binary is to perform a single run of the primitive under test so that
//! its peak memory usage can be measured with:
//!
//! ```text
//! valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_hpke_mem_usage > /dev/null
//!
//! ms_print massif.out.*
//! ```
//!
//! Make sure you build in release mode!
//!
//! The crate docs' stack table is the deepest frame chain from each [`measure`] instance down,
//! as for the ECC CDH harness; `main` calls every bench for that build so none is dead-stripped.
//!
//! Note: print!() forces the compiler not to optimize away the actual code. The name of the bench
//! goes to stderr so that the junk on stdout can be piped to /dev/null.
//!
//! Main is at the bottom, controls which bench is actually run.
//!
//! The suite is DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, with the recipient key
//! and `enc` of RFC 9180 Appendix A.1.1.

#![allow(dead_code)]
#![allow(unused_imports)]

use bouncycastle::core::key_material::{KeyMaterial, KeyMaterialTrait};
use bouncycastle::core::traits::{PrivateKey, PublicKey};
use bouncycastle::digest::sha2::SHA256;
use bouncycastle::ec::ed::x25519::{X25519PrivateKey, X25519PublicKey};
use bouncycastle::hybrid::hpke::{
    HpkeAuthRecipient, HpkeAuthSender, HpkeContext, HpkeParams, HpkeRecipient, HpkeSender, NT,
    Recipient, Sender,
};
use bouncycastle::rng::HashDRBG_SHA512;
use bouncycastle::symmetric::aes::AES128Key;
use bouncycastle::symmetric::modes::GCM;

type Params<'p> = HpkeParams<'p, SHA256, AES128Key<GCM>>;

/// Runs the operation under measurement out of line, so that its frames sit below one symbol
/// the stack-table method can root a call chain at.
#[inline(never)]
fn measure<T>(f: impl FnOnce() -> T) -> T {
    f()
}

/// This exists so that /usr/bin/time can measure the base memory footprint of the harness.
fn bench_do_nothing() {
    eprintln!("DoNothing");

    print!("{}", 1 + 1);
}

/// RFC 9180 Appendix A.1.1's skRm. `#[inline(never)]` so its decode temporaries are popped
/// before the operation runs.
#[inline(never)]
fn load_sk() -> X25519PrivateKey {
    X25519PrivateKey::from_bytes(&[
        0x46, 0x12, 0xc5, 0x50, 0x26, 0x3f, 0xc8, 0xad, 0x58, 0x37, 0x5d, 0xf3, 0xf5, 0x57, 0xaa,
        0xc5, 0x31, 0xd2, 0x68, 0x50, 0x90, 0x3e, 0x55, 0xa9, 0xf2, 0x3f, 0x21, 0xd8, 0x53, 0x4e,
        0x8a, 0xc8,
    ])
    .unwrap()
}

/// RFC 9180 Appendix A.1.1's enc.
const ENC: [u8; 32] = [
    0x37, 0xfd, 0xa3, 0x56, 0x7b, 0xdb, 0xd6, 0x28, 0xe8, 0x86, 0x68, 0xc3, 0xc8, 0xd7, 0xe9, 0x7d,
    0x1d, 0x12, 0x53, 0xb6, 0xd4, 0xea, 0x6d, 0x44, 0xc1, 0x50, 0xf7, 0x41, 0xf1, 0xbf, 0x44, 0x31,
];

/// A sender's context, made out of line.
#[inline(never)]
fn sender() -> HpkeContext<Sender, SHA256, AES128Key<GCM>> {
    let pk = load_sk().pk();
    pk.setup_sender(&mut HashDRBG_SHA512::new_from_os(), Params::new(b"info")).unwrap().1
}

/// A recipient's context, made out of line.
#[inline(never)]
fn recipient() -> HpkeContext<Recipient, SHA256, AES128Key<GCM>> {
    load_sk().setup_recipient(&ENC, Params::new(b"info")).unwrap()
}

/// `SetupBaseS`, including the encapsulation and its DRBG.
fn bench_hpke_setup_sender() {
    eprintln!("HPKE/SetupSender");

    let pk = load_sk().pk();
    measure(|| {
        let (enc, _context) =
            pk.setup_sender(&mut HashDRBG_SHA512::new_from_os(), Params::new(b"info")).unwrap();
        print!("{:x?}", enc);
    });
}

/// `SetupBaseR`, including the decapsulation.
fn bench_hpke_setup_recipient() {
    eprintln!("HPKE/SetupRecipient");

    let sk = load_sk();
    measure(|| {
        let context = sk.setup_recipient(&ENC, Params::new(b"info")).unwrap();
        let mut out = KeyMaterial::<32>::new();
        context.export_out(b"", &mut out);
        print!("{:x?}", out.ref_to_bytes());
    });
}

/// `SetupAuthS`, with the recipient's key pair standing in for the sender's.
fn bench_hpke_setup_auth_sender() {
    eprintln!("HPKE/SetupAuthSender");

    let sk = load_sk();
    let pk = sk.pk();
    measure(|| {
        let (enc, _context) = pk
            .setup_auth_sender(&mut HashDRBG_SHA512::new_from_os(), &sk, Params::new(b"info"))
            .unwrap();
        print!("{:x?}", enc);
    });
}

/// `SetupAuthR`, with the recipient's public key standing in for the sender's.
fn bench_hpke_setup_auth_recipient() {
    eprintln!("HPKE/SetupAuthRecipient");

    let sk = load_sk();
    let pk = sk.pk();
    measure(|| {
        let context = sk.setup_auth_recipient(&ENC, &pk, Params::new(b"info")).unwrap();
        let mut out = KeyMaterial::<32>::new();
        context.export_out(b"", &mut out);
        print!("{:x?}", out.ref_to_bytes());
    });
}

/// `ContextS.Seal` of a 64-byte message.
fn bench_hpke_seal() {
    eprintln!("HPKE/Seal");

    let mut context = sender();
    let mut ct = [0u8; 64 + NT];
    measure(|| {
        context.seal_out(b"aad", &[0x5A; 64], &mut ct).unwrap();
    });
    print!("{:x?}", ct);
}

/// `ContextR.Open`; the ciphertext is not the sender's, so this is the failing path, which
/// runs the whole decryption before it refuses the tag.
fn bench_hpke_open() {
    eprintln!("HPKE/Open");

    let mut context = recipient();
    let mut pt = [0u8; 64 + NT];
    measure(|| {
        let _ = context.open_out(b"aad", &[0x5A; 64 + NT], &mut pt);
    });
    print!("{:x?}", pt);
}

/// `Context.Export` of 32 bytes.
fn bench_hpke_export() {
    eprintln!("HPKE/Export");

    let context = recipient();
    let mut out = KeyMaterial::<32>::new();
    measure(|| {
        context.export_out(b"exporter context", &mut out);
    });
    print!("{:x?}", out.ref_to_bytes());
}

fn main() {
    bench_hpke_setup_sender()
    // bench_do_nothing()
    // bench_hpke_setup_recipient()
    // bench_hpke_setup_auth_sender()
    // bench_hpke_setup_auth_recipient()
    // bench_hpke_seal()
    // bench_hpke_open()
    // bench_hpke_export()
}
