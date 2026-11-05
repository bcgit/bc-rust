//! A single run of one ChaCha20-Poly1305 entry point, so that its stack usage can be read. Build
//! in release mode.
//!
//! The figures in the crate docs are read from the compiler as `bench_ascon_mem_usage` and
//! `bench_chacha20_mem_usage` describe: the deepest chain of frames below each `measure` closure
//! after LTO, from `-C remark=prologepilog` and the disassembly, plus 8 bytes of return address
//! per call, x86-64 Linux. The panic paths are not followed, and the `&mut dyn RNG` call is to
//! `FixedNonce::next_bytes_out`.
//!
//! ```text
//! RUSTFLAGS="-C remark=prologepilog" cargo build --release -p mem_usage_benches --bin bench_chacha20_poly1305_mem_usage 2> remarks.txt
//! ```
//!
//! Each entry point is called through a `black_box`ed function pointer, so its body is its own
//! and not the closure's; the key, the workers and the inputs are built in `#[inline(never)]`
//! helpers. A worker borrows its key, so the key is leaked to `'static` to give the pointer a
//! concrete lifetime. `main` controls which bench runs; measure one at a time.

#![allow(dead_code)]

use core::hint::black_box;

use bouncycastle::chacha20_poly1305_aead::{
    ChaCha20_Poly1305, ChaCha20Poly1305Key, KEY_LEN, NONCE_LEN, TAG_LEN,
};
use bouncycastle::cipher::{Decrypting, Encrypting};
use bouncycastle::core::errors::{RNGError, SymmetricCipherError};
use bouncycastle::core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle::core::security_strength::SecurityStrength;
use bouncycastle::core::symmetric_key::{AeadDecryptionKey, AeadEncryptionKey, FromKeyMaterial};
use bouncycastle::core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, RNG, SymmetricCipherDecryptor,
    SymmetricCipherEncryptor,
};

type Key = ChaCha20Poly1305Key;
type Enc = ChaCha20_Poly1305<'static, Encrypting>;
type Dec = ChaCha20_Poly1305<'static, Decrypting>;
type CipherErr = SymmetricCipherError;

/// Three whole 64-byte keystream blocks and a partial one.
const MSG_LEN: usize = 200;
/// One whole 16-byte Poly1305 block and a partial one.
const AAD_LEN: usize = 20;
/// The inline layout: ciphertext || tag.
const SEALED_LEN: usize = MSG_LEN + TAG_LEN;

const KEY: [u8; KEY_LEN] = [0x42; KEY_LEN];
const NONCE: [u8; NONCE_LEN] = [0x07; NONCE_LEN];

/// Hands back [`NONCE`], so that `create_encryptor` measures the AEAD and not a DRBG, whose
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
    println!("size_of<ChaCha20Poly1305Key>: {}", size_of::<Key>());
    println!("size_of<ChaCha20_Poly1305<Encrypting>>: {}", size_of::<Enc>());
    println!("size_of<ChaCha20_Poly1305<Decrypting>>: {}", size_of::<Dec>());
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
fn key() -> &'static Key {
    Box::leak(Box::new(Key::from_key_material(&material()).unwrap()))
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

/// An encryptor that has taken the AAD and the message, so the final pads both.
#[inline(never)]
fn encryptor_after_data() -> Enc {
    let mut enc = encryptor();
    enc.do_update_aad(&message::<AAD_LEN>(0x5a)).unwrap();
    let mut ct = [0u8; MSG_LEN];
    enc.do_encrypt_out(&message::<MSG_LEN>(0xa5), &mut ct).unwrap();
    enc
}

#[inline(never)]
fn decryptor() -> Dec {
    key().create_decryptor(&NONCE)
}

/// `MSG_LEN` bytes sealed under [`NONCE`] with the AAD, as ciphertext || tag.
#[inline(never)]
fn sealed() -> [u8; SEALED_LEN] {
    let mut out = [0u8; SEALED_LEN];
    key()
        .encrypt_with_aad_out(
            &mut FixedNonce,
            &message::<AAD_LEN>(0x5a),
            &message::<MSG_LEN>(0xa5),
            &mut out,
        )
        .unwrap();
    out
}

/// A decryptor that has taken the AAD and the whole of [`sealed`], so it is holding back the tag.
#[inline(never)]
fn decryptor_holding_tag() -> Dec {
    let mut dec = decryptor();
    dec.do_update_aad(&message::<AAD_LEN>(0x5a)).unwrap();
    let mut pt = [0u8; SEALED_LEN];
    dec.do_decrypt_out(&sealed(), &mut pt).unwrap();
    dec
}

/// The key check, once per key.
#[inline(never)]
fn bench_from_key_material() {
    eprintln!("ChaCha20Poly1305Key::from_key_material");
    let m = material();
    measure(|| {
        let op = black_box(
            <Key as FromKeyMaterial<KEY_LEN>>::from_key_material
                as fn(&KeyMaterial<KEY_LEN>) -> Result<Key, CipherErr>,
        );
        let key = op(&m).unwrap();
        black_box(&key);
    });
}

/// The nonce draw, then block 0 of the keystream as the one-time Poly1305 key.
#[inline(never)]
fn bench_create_encryptor() {
    eprintln!("ChaCha20Poly1305Key::create_encryptor");
    let k = key();
    measure(|| {
        let op = black_box(
            <Key as AeadEncryptionKey<KEY_LEN, NONCE_LEN, TAG_LEN, TAG_LEN>>::create_encryptor
                as fn(&'static Key, &mut dyn RNG) -> Result<(Enc, [u8; NONCE_LEN]), CipherErr>,
        );
        let (enc, nonce) = op(k, &mut FixedNonce).unwrap();
        black_box(&enc);
        print!("{nonce:x?}");
    });
}

#[inline(never)]
fn bench_create_decryptor() {
    eprintln!("ChaCha20Poly1305Key::create_decryptor");
    let k = key();
    measure(|| {
        let op = black_box(
            <Key as AeadDecryptionKey<KEY_LEN, NONCE_LEN, TAG_LEN, TAG_LEN>>::create_decryptor
                as fn(&'static Key, &[u8; NONCE_LEN]) -> Dec,
        );
        let dec = op(k, &NONCE);
        black_box(&dec);
    });
}

#[inline(never)]
fn bench_update_aad() {
    eprintln!("ChaCha20_Poly1305<Encrypting>::do_update_aad, {AAD_LEN} B");
    let enc = black_box(encryptor());
    let aad = black_box(message::<AAD_LEN>(0x5a));
    measure(move || {
        let mut enc = enc;
        let op = black_box(
            <Enc as AEADCipherEncryptor<NONCE_LEN, TAG_LEN, TAG_LEN>>::do_update_aad
                as fn(&mut Enc, &[u8]) -> Result<(), CipherErr>,
        );
        op(&mut enc, &aad).unwrap();
        black_box(&enc);
    });
}

#[inline(never)]
fn bench_encrypt_out() {
    eprintln!("ChaCha20_Poly1305<Encrypting>::do_encrypt_out, {MSG_LEN} B");
    let enc = black_box(encryptor());
    let pt = black_box(message::<MSG_LEN>(0xa5));
    measure(move || {
        let mut enc = enc;
        let mut ct = [0u8; MSG_LEN];
        let op = black_box(
            <Enc as SymmetricCipherEncryptor<NONCE_LEN, TAG_LEN>>::do_encrypt_out
                as fn(&mut Enc, &[u8], &mut [u8]) -> Result<usize, CipherErr>,
        );
        let n = op(&mut enc, &pt, &mut ct).unwrap();
        print!("{:x?}", &ct[..n]);
    });
}

/// The padding, the two lengths and Poly1305's final.
#[inline(never)]
fn bench_encrypt_final() {
    eprintln!("ChaCha20_Poly1305<Encrypting>::do_encrypt_final");
    let enc = black_box(encryptor_after_data());
    measure(move || {
        let op = black_box(
            <Enc as SymmetricCipherEncryptor<NONCE_LEN, TAG_LEN>>::do_encrypt_final
                as fn(Enc) -> Result<([u8; TAG_LEN], usize), CipherErr>,
        );
        let (tag, n) = op(enc).unwrap();
        print!("{:x?}", &tag[..n]);
    });
}

/// The one-shot with AAD and the tag inline: init, AAD, data and final in one call.
#[inline(never)]
fn bench_encrypt_oneshot() {
    eprintln!("ChaCha20Poly1305Key::encrypt_with_aad_out, {MSG_LEN} B");
    let k = key();
    let aad = black_box(message::<AAD_LEN>(0x5a));
    let pt = black_box(message::<MSG_LEN>(0xa5));
    measure(move || {
        let mut ct = [0u8; SEALED_LEN];
        let op = black_box(
            <Key as AeadEncryptionKey<KEY_LEN, NONCE_LEN, TAG_LEN, TAG_LEN>>::encrypt_with_aad_out
                as fn(
                    &'static Key,
                    &mut dyn RNG,
                    &[u8],
                    &[u8],
                    &mut [u8],
                ) -> Result<(usize, [u8; NONCE_LEN]), CipherErr>,
        );
        let (n, _) = op(k, &mut FixedNonce, &aad, &pt, &mut ct).unwrap();
        print!("{:x?}", &ct[..n]);
    });
}

#[inline(never)]
fn bench_decrypt_out() {
    eprintln!("ChaCha20_Poly1305<Decrypting>::do_decrypt_out, {SEALED_LEN} B");
    let dec = black_box(decryptor());
    let ct = black_box(sealed());
    measure(move || {
        let mut dec = dec;
        let mut pt = [0u8; SEALED_LEN];
        let op = black_box(
            <Dec as SymmetricCipherDecryptor<NONCE_LEN, TAG_LEN>>::do_decrypt_out
                as fn(&mut Dec, &[u8], &mut [u8]) -> Result<usize, CipherErr>,
        );
        let n = op(&mut dec, &ct, &mut pt).unwrap();
        print!("{:x?}", &pt[..n]);
    });
}

/// The tag check against the held-back inline tag.
#[inline(never)]
fn bench_decrypt_final() {
    eprintln!("ChaCha20_Poly1305<Decrypting>::do_decrypt_final");
    let dec = black_box(decryptor_holding_tag());
    measure(move || {
        let op = black_box(
            <Dec as SymmetricCipherDecryptor<NONCE_LEN, TAG_LEN>>::do_decrypt_final
                as fn(Dec) -> Result<([u8; TAG_LEN], usize), CipherErr>,
        );
        print!("{}", op(dec).is_ok());
    });
}

/// The one-shot with AAD and the tag inline, a message that verifies.
#[inline(never)]
fn bench_decrypt_oneshot() {
    eprintln!("ChaCha20Poly1305Key::decrypt_with_aad_out, {SEALED_LEN} B");
    let k = key();
    let aad = black_box(message::<AAD_LEN>(0x5a));
    let ct = black_box(sealed());
    measure(move || {
        let mut pt = [0u8; MSG_LEN];
        let op = black_box(
            <Key as AeadDecryptionKey<KEY_LEN, NONCE_LEN, TAG_LEN, TAG_LEN>>::decrypt_with_aad_out
                as fn(
                    &'static Key,
                    &[u8; NONCE_LEN],
                    &[u8],
                    &[u8],
                    &mut [u8],
                ) -> Result<usize, CipherErr>,
        );
        let n = op(k, &NONCE, &aad, &ct, &mut pt).unwrap();
        print!("{:x?}", &pt[..n]);
    });
}

fn main() {
    print_struct_sizes()
    // bench_from_key_material()
    // bench_create_encryptor()
    // bench_create_decryptor()
    // bench_update_aad()
    // bench_encrypt_out()
    // bench_encrypt_final()
    // bench_encrypt_oneshot()
    // bench_decrypt_out()
    // bench_decrypt_final()
    // bench_decrypt_oneshot()
}
