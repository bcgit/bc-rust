//! The cipher, MAC, KEM, key-agreement and signature worker traits are dyn-compatible: a worker
//! can be held as a trait object (issue #173), as can a hash or XOF, since `Clone` lives on the
//! types rather than on `Hash`.
//! So is the in-place AEAD key role pair, which names no worker type, and so is `RNG`, whose
//! generic draw lives on `RNGExt` for that reason.
//! The functions take trait objects and do nothing; compiling them is the test.
//!
//! A worker held as `Box<dyn ..>` is finished through the `_boxed` twin of its consuming final,
//! a provided method with a `self: Box<Self>` receiver; the `boxed_*` functions pin that each twin
//! is callable on the box. The hash, cipher, AEAD, MAC and signature framework suites run them against
//! the implementors those suites cover.

use bouncycastle_core::errors::{HashError, MACError, SignatureError, SymmetricCipherError};
use bouncycastle_core::hazmat::KeyStream;
use bouncycastle_core::symmetric_key::{AeadInPlaceDecryptionKey, AeadInPlaceEncryptionKey};
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, BlockCipherDecryptor, BlockCipherEncryptor, Hash,
    KEMDecapsulator, KEMEncapsulator, KeyAgreement, KeyUnwrapper, KeyWrapper, MACGenerator,
    MACVerifier, RNG, SignatureSigner, SignatureVerifier, StreamCipherDecryptor,
    StreamCipherEncryptor, SymmetricCipherDecryptor, SymmetricCipherEncryptor, XOF, XOFSqueezer,
};

fn symmetric(
    _: &mut dyn SymmetricCipherEncryptor<16, 16>,
    _: &mut dyn SymmetricCipherDecryptor<16, 16>,
) {
}
fn aead(_: &mut dyn AEADCipherEncryptor<12, 16, 16>, _: &mut dyn AEADCipherDecryptor<12, 16, 16>) {}
/// A key role rather than a worker: a key that takes whole messages only is held as this.
fn aead_in_place(
    _: &dyn AeadInPlaceEncryptionKey<32, 12, 16>,
    _: &dyn AeadInPlaceDecryptionKey<32, 12, 16>,
) {
}
fn stream(_: &mut dyn StreamCipherEncryptor<16>, _: &mut dyn StreamCipherDecryptor<16>) {}
fn block(_: &mut dyn BlockCipherEncryptor<16, 16>, _: &mut dyn BlockCipherDecryptor<16, 16>) {}
fn mac(_: &mut dyn MACGenerator<32>, _: &mut dyn MACVerifier<32>) {}
fn signature(_: &mut dyn SignatureSigner<64>, _: &mut dyn SignatureVerifier) {}
/// The run-time-length half of key wrap; the const-generic one-shots are `Self: Sized`.
fn key_wrap(_: &dyn KeyWrapper, _: &dyn KeyUnwrapper) {}
fn key_stream(_: &mut dyn KeyStream<12, 16>) {}
fn kem(_: &dyn KEMEncapsulator<1088, 32>, _: &dyn KEMDecapsulator<1088, 32>) {}
/// The peer key type is a parameter of the worker trait, so the object type names it.
fn key_agreement(_: &dyn KeyAgreement<[u8; 65], 32>) {}
fn hash(_: &mut dyn Hash) {}
fn rng(_: &mut dyn RNG) {}
/// A XOF names its squeezer type, so the object type is `dyn XOF<Squeezer = S>`.
fn xof<S: XOFSqueezer>(_: &mut dyn XOF<Squeezer = S>, _: &mut dyn XOFSqueezer) {}

type Final = Result<([u8; 16], usize), SymmetricCipherError>;
type StreamFinal = Result<([u8; 0], usize), SymmetricCipherError>;

fn boxed_symmetric(
    enc: Box<dyn SymmetricCipherEncryptor<16, 16>>,
    dec: Box<dyn SymmetricCipherDecryptor<16, 16>>,
) -> (Final, Final) {
    (enc.do_encrypt_final_boxed(), dec.do_decrypt_final_boxed())
}
/// The refinements reach the base trait's twin through their supertrait.
fn boxed_stream(
    enc: Box<dyn StreamCipherEncryptor<16>>,
    dec: Box<dyn StreamCipherDecryptor<16>>,
) -> (StreamFinal, StreamFinal) {
    (enc.do_encrypt_final_boxed(), dec.do_decrypt_final_boxed())
}
fn boxed_aead(
    enc: Box<dyn AEADCipherEncryptor<12, 16, 16>>,
    dec: Box<dyn AEADCipherDecryptor<12, 16, 16>>,
    buf: &mut [u8; 16],
) -> Result<usize, SymmetricCipherError> {
    let (_, tag) = enc.do_encrypt_final_detached_out_boxed(buf)?;
    dec.do_decrypt_final_detached_out_boxed(&tag, buf)
}
fn boxed_mac(
    generator: Box<dyn MACGenerator<32>>,
    verifier: Box<dyn MACVerifier<32>>,
) -> Result<(), MACError> {
    let mut tag = [0u8; 32];
    generator.do_final_out_boxed(&mut tag);
    verifier.do_verify_final_boxed(&tag)
}
fn boxed_signature(
    signer: Box<dyn SignatureSigner<64>>,
    verifier: Box<dyn SignatureVerifier>,
) -> Result<(), SignatureError> {
    let mut sig = [0u8; 64];
    signer.do_final_out_boxed(&mut sig)?;
    verifier.do_verify_final_boxed(&sig)
}
fn boxed_hash(hash: Box<dyn Hash>, out: &mut [u8]) -> usize {
    hash.do_final_out_boxed(out)
}
fn boxed_hash_partial_bits(hash: Box<dyn Hash>, out: &mut [u8]) -> Result<usize, HashError> {
    hash.do_final_partial_bits_out_boxed(0x80, 1, out)
}

#[test]
fn the_boxed_finals_are_callable_on_a_box() {
    // Referenced so the functions are not dead code; the compile is the assertion.
    let _ = (
        boxed_symmetric as fn(_, _) -> _,
        boxed_stream as fn(_, _) -> _,
        boxed_aead as fn(_, _, _) -> _,
        boxed_mac as fn(_, _) -> _,
        boxed_signature as fn(_, _) -> _,
        boxed_hash as fn(_, _) -> _,
        boxed_hash_partial_bits as fn(_, _) -> _,
    );
}

#[test]
fn the_worker_traits_are_dyn_compatible() {
    // Referenced so the functions are not dead code; the compile is the assertion.
    let _ = (
        symmetric as fn(_, _),
        aead as fn(_, _),
        stream as fn(_, _),
        block as fn(_, _),
        mac as fn(_, _),
        signature as fn(_, _),
        key_wrap as fn(_, _),
        key_stream as fn(_),
        kem as fn(_, _),
        key_agreement as fn(_),
        hash as fn(_),
        rng as fn(_),
        aead_in_place as fn(_, _),
    );
    fn reference_xof<S: XOFSqueezer>() {
        let _ = xof::<S> as fn(_, _);
    }
    let _ = reference_xof::<NoSqueezer> as fn();
}

/// A stand-in squeezer, so `reference_xof` has a type to name; never run.
struct NoSqueezer;
impl XOFSqueezer for NoSqueezer {
    fn do_output_out(&mut self, _: &mut [u8]) -> usize {
        0
    }
    fn do_output_final_out(self, _: &mut [u8]) -> usize {
        0
    }
}
