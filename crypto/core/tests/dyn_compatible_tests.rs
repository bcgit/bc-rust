//! The cipher and MAC worker traits are dyn-compatible: a worker can be held as a trait object
//! (issue #173). The functions take trait objects and do nothing; compiling them is the test.

use bouncycastle_core::hazmat::KeyStream;
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, BlockCipherDecryptor, BlockCipherEncryptor, MAC,
    StreamCipherDecryptor, StreamCipherEncryptor, SymmetricCipherDecryptor,
    SymmetricCipherEncryptor,
};

fn symmetric(
    _: &mut dyn SymmetricCipherEncryptor<16, 16, 16>,
    _: &mut dyn SymmetricCipherDecryptor<16, 16, 16>,
) {
}
fn aead(
    _: &mut dyn AEADCipherEncryptor<16, 12, 16, 16>,
    _: &mut dyn AEADCipherDecryptor<16, 12, 16, 16>,
) {
}
fn stream(_: &mut dyn StreamCipherEncryptor<16, 16>, _: &mut dyn StreamCipherDecryptor<16, 16>) {}
fn block(
    _: &mut dyn BlockCipherEncryptor<16, 16, 16>,
    _: &mut dyn BlockCipherDecryptor<16, 16, 16>,
) {
}
fn mac(_: &mut dyn MAC) {}
fn key_stream(_: &mut dyn KeyStream<16, 12, 16>) {}

#[test]
fn the_worker_traits_are_dyn_compatible() {
    // Referenced so the functions are not dead code; the compile is the assertion.
    let _ = (
        symmetric as fn(_, _), aead as fn(_, _), stream as fn(_, _), block as fn(_, _),
        mac as fn(_), key_stream as fn(_),
    );
}
