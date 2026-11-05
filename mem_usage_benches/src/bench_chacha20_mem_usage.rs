//! A single run of one ChaCha20 entry point, so that its stack usage can be read. Build in release
//! mode.
//!
//! ChaCha20 has no interesting stack profile: every call works on one 64-byte block state, so a
//! call needs a few hundred bytes, below the floor of the process's own start-up that massif
//! reports (see `bench_aes_mem_usage`). The figures in the crate docs are read from the compiler
//! as `bench_ascon_mem_usage` describes: the deepest chain of frames below each `measure` closure
//! after LTO, from `-C remark=prologepilog` and the disassembly, plus 8 bytes of return address
//! per call, x86-64 Linux. The panic paths are not followed, and the `&mut dyn RNG` call is to
//! `FixedNonce::next_bytes_out`.
//!
//! ```text
//! RUSTFLAGS="-C remark=prologepilog" cargo build --release -p mem_usage_benches --bin bench_chacha20_mem_usage 2> remarks.txt
//! ```
//!
//! Each entry point is called through a `black_box`ed function pointer, so its body is its own
//! and not the closure's; the key, the worker and the input are built in `#[inline(never)]`
//! helpers, so their frames are siblings of the operation's. A worker borrows its key, so the key
//! is leaked to `'static` to give the pointer a concrete lifetime. `main` controls which bench
//! runs; measure one at a time.

#![allow(dead_code)]

use core::hint::black_box;

use bouncycastle::chacha20::{ChaCha20, ChaCha20Key, KEY_LEN, NONCE_LEN};
use bouncycastle::cipher::{Decrypting, Encrypting};
use bouncycastle::core::errors::{RNGError, SymmetricCipherError};
use bouncycastle::core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle::core::security_strength::SecurityStrength;
use bouncycastle::core::symmetric_key::{
    FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey,
};
use bouncycastle::core::traits::{RNG, StreamCipherDecryptor, StreamCipherEncryptor};

type Enc = ChaCha20<'static, Encrypting>;
type Dec = ChaCha20<'static, Decrypting>;
type CipherErr = SymmetricCipherError;

/// Three whole 64-byte blocks and a partial one.
const MSG_LEN: usize = 200;

const KEY: [u8; KEY_LEN] = [0x42; KEY_LEN];
const NONCE: [u8; NONCE_LEN] = [0x07; NONCE_LEN];

/// Hands back [`NONCE`], so that `create_encryptor` measures the cipher and not a DRBG, whose
/// stack the frame remarks cannot see. Not a random number generator; it exists only for this
/// harness.
struct FixedNonce;

impl RNG for FixedNonce {
    fn add_seed_keymaterial(&mut self, _: &dyn KeyMaterialTrait) -> Result<(), RNGError> {
        Ok(())
    }

    fn next_int(&mut self) -> Result<u32, RNGError> {
        Ok(0)
    }

    fn next_bytes(&mut self, len: usize) -> Result<Vec<u8>, RNGError> {
        let mut out = vec![0u8; len];
        self.next_bytes_out(&mut out)?;
        Ok(out)
    }

    fn next_bytes_out(&mut self, out: &mut [u8]) -> Result<usize, RNGError> {
        for (i, b) in out.iter_mut().enumerate() {
            *b = NONCE[i % NONCE_LEN];
        }
        Ok(out.len())
    }

    fn fill_keymaterial_out(&mut self, _: &mut dyn KeyMaterialTrait) -> Result<usize, RNGError> {
        Err(RNGError::GenericError("FixedNonce only supplies nonces"))
    }

    fn security_strength(&self) -> SecurityStrength {
        SecurityStrength::_256bit
    }
}

/// Prints the in-memory size of each value a caller holds between calls.
#[inline(never)]
fn print_struct_sizes() {
    use core::mem::size_of;
    println!("size_of<ChaCha20Key>: {}", size_of::<ChaCha20Key>());
    println!("size_of<ChaCha20<Encrypting>>: {}", size_of::<Enc>());
    println!("size_of<ChaCha20<Decrypting>>: {}", size_of::<Dec>());
}

/// Runs the operation in its own frame. Returns nothing, so no result crosses the boundary.
#[inline(never)]
fn measure(f: impl FnOnce()) {
    f()
}

#[inline(never)]
fn material() -> KeyMaterial<KEY_LEN> {
    KeyMaterial::<KEY_LEN>::from_bytes_as_type(&KEY, KeyType::SymmetricCipherKey).unwrap()
}

/// The key object, leaked so that the workers it makes are `'static`.
#[inline(never)]
fn key() -> &'static ChaCha20Key {
    Box::leak(Box::new(ChaCha20Key::from_key_material(&material()).unwrap()))
}

/// A message filled at run time, so that its contents are not a constant the compiler could fold
/// the computation over.
#[inline(never)]
fn message<const N: usize>(fill: u8) -> [u8; N] {
    let mut m = [0u8; N];
    m.fill(black_box(fill));
    m
}

#[inline(never)]
fn encryptor() -> Enc {
    key().create_encryptor(&mut FixedNonce).unwrap().0
}

#[inline(never)]
fn decryptor() -> Dec {
    key().create_decryptor(&NONCE)
}

/// The key check and the key words' load, once per key.
#[inline(never)]
fn bench_from_key_material() {
    eprintln!("ChaCha20Key::from_key_material");
    let m = material();
    measure(|| {
        let op = black_box(
            <ChaCha20Key as FromKeyMaterial<KEY_LEN>>::from_key_material
                as fn(&KeyMaterial<KEY_LEN>) -> Result<ChaCha20Key, CipherErr>,
        );
        let key = op(&m).unwrap();
        black_box(&key);
    });
}

/// The nonce draw and the keystream's setup at counter 0.
#[inline(never)]
fn bench_create_encryptor() {
    eprintln!("ChaCha20Key::create_encryptor");
    let k = key();
    measure(|| {
        let op = black_box(
            <ChaCha20Key as SymmetricEncryptionKey<KEY_LEN, NONCE_LEN, 0>>::create_encryptor
                as fn(
                    &'static ChaCha20Key,
                    &mut dyn RNG,
                ) -> Result<(Enc, [u8; NONCE_LEN]), CipherErr>,
        );
        let (enc, nonce) = op(k, &mut FixedNonce).unwrap();
        black_box(&enc);
        print!("{nonce:x?}");
    });
}

#[inline(never)]
fn bench_create_decryptor() {
    eprintln!("ChaCha20Key::create_decryptor");
    let k = key();
    measure(|| {
        let op = black_box(
            <ChaCha20Key as SymmetricDecryptionKey<KEY_LEN, NONCE_LEN, 0>>::create_decryptor
                as fn(&'static ChaCha20Key, &[u8; NONCE_LEN]) -> Dec,
        );
        let dec = op(k, &NONCE);
        black_box(&dec);
    });
}

#[inline(never)]
fn bench_encrypt_inplace() {
    eprintln!("ChaCha20<Encrypting>::do_encrypt_inplace, {MSG_LEN} B");
    let enc = black_box(encryptor());
    let data = black_box(message::<MSG_LEN>(0xa5));
    measure(move || {
        let mut enc = enc;
        let mut data = data;
        let op = black_box(
            <Enc as StreamCipherEncryptor<NONCE_LEN>>::do_encrypt_inplace
                as fn(&mut Enc, &mut [u8]) -> Result<usize, CipherErr>,
        );
        let n = op(&mut enc, &mut data).unwrap();
        print!("{:x?}", &data[..n]);
    });
}

#[inline(never)]
fn bench_decrypt_inplace() {
    eprintln!("ChaCha20<Decrypting>::do_decrypt_inplace, {MSG_LEN} B");
    let dec = black_box(decryptor());
    let data = black_box(message::<MSG_LEN>(0xa5));
    measure(move || {
        let mut dec = dec;
        let mut data = data;
        let op = black_box(
            <Dec as StreamCipherDecryptor<NONCE_LEN>>::do_decrypt_inplace
                as fn(&mut Dec, &mut [u8]) -> Result<usize, CipherErr>,
        );
        let n = op(&mut dec, &mut data).unwrap();
        print!("{:x?}", &data[..n]);
    });
}

/// The one-shot: nonce draw, setup and the whole message in one call.
#[inline(never)]
fn bench_encrypt_oneshot() {
    eprintln!("ChaCha20Key::encrypt_inplace, {MSG_LEN} B");
    let k = key();
    let data = black_box(message::<MSG_LEN>(0xa5));
    measure(move || {
        let mut data = data;
        let op = black_box(
            <ChaCha20Key as SymmetricEncryptionKey<KEY_LEN, NONCE_LEN, 0>>::encrypt_inplace
                as fn(
                    &'static ChaCha20Key,
                    &mut dyn RNG,
                    &mut [u8],
                ) -> Result<(usize, [u8; NONCE_LEN]), CipherErr>,
        );
        let (n, _) = op(k, &mut FixedNonce, &mut data).unwrap();
        print!("{:x?}", &data[..n]);
    });
}

#[inline(never)]
fn bench_decrypt_oneshot() {
    eprintln!("ChaCha20Key::decrypt_inplace, {MSG_LEN} B");
    let k = key();
    let data = black_box(message::<MSG_LEN>(0xa5));
    measure(move || {
        let mut data = data;
        let op = black_box(
            <ChaCha20Key as SymmetricDecryptionKey<KEY_LEN, NONCE_LEN, 0>>::decrypt_inplace
                as fn(
                    &'static ChaCha20Key,
                    &[u8; NONCE_LEN],
                    &mut [u8],
                ) -> Result<usize, CipherErr>,
        );
        let n = op(k, &NONCE, &mut data).unwrap();
        print!("{:x?}", &data[..n]);
    });
}

fn main() {
    print_struct_sizes()
    // bench_from_key_material()
    // bench_create_encryptor()
    // bench_create_decryptor()
    // bench_encrypt_inplace()
    // bench_decrypt_inplace()
    // bench_encrypt_oneshot()
    // bench_decrypt_oneshot()
}
