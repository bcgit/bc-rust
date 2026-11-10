//! The cipher, MAC, KEM, key-agreement and signature worker traits are dyn-compatible: a worker
//! can be held as a trait object (issue #173), as can a hash or XOF, since `Clone` lives on the
//! types rather than on `Hash`.
//! The functions take trait objects and do nothing; compiling them is the test.

use bouncycastle_core::hazmat::KeyStream;
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, BlockCipherDecryptor, BlockCipherEncryptor, Hash,
    KEMDecapsulator, KEMEncapsulator, KeyAgreement, KeyUnwrapper, KeyWrapper, MACGenerator,
    MACVerifier, SignatureSigner, SignatureVerifier, StreamCipherDecryptor, StreamCipherEncryptor,
    SymmetricCipherDecryptor, SymmetricCipherEncryptor, XOF, XOFSqueezer,
};

fn symmetric(
    _: &mut dyn SymmetricCipherEncryptor<16, 16>,
    _: &mut dyn SymmetricCipherDecryptor<16, 16>,
) {
}
fn aead(_: &mut dyn AEADCipherEncryptor<12, 16, 16>, _: &mut dyn AEADCipherDecryptor<12, 16, 16>) {}
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
/// A XOF names its squeezer type, so the object type is `dyn XOF<Squeezer = S>`.
fn xof<S: XOFSqueezer>(_: &mut dyn XOF<Squeezer = S>, _: &mut dyn XOFSqueezer) {}

#[test]
fn the_worker_traits_are_dyn_compatible() {
    // Referenced so the functions are not dead code; the compile is the assertion.
    let _ = (
        symmetric as fn(_, _), aead as fn(_, _), stream as fn(_, _), block as fn(_, _),
        mac as fn(_, _), signature as fn(_, _), key_wrap as fn(_, _), key_stream as fn(_),
        kem as fn(_, _), key_agreement as fn(_), hash as fn(_),
    );
    fn reference_xof<S: XOFSqueezer>() {
        let _ = xof::<S> as fn(_, _);
    }
    let _ = reference_xof::<NoSqueezer> as fn();
}

/// A stand-in squeezer, so `reference_xof` has a type to name; never run.
struct NoSqueezer;
impl XOFSqueezer for NoSqueezer {
    fn do_output(&mut self, _: usize) -> Vec<u8> {
        Vec::new()
    }
    fn do_output_out(&mut self, _: &mut [u8]) -> usize {
        0
    }
    fn do_output_final_out(self, _: &mut [u8]) -> usize {
        0
    }
}
