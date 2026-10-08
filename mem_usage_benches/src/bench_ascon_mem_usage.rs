//! The purpose of this binary is to perform a single run of the primitive under test so that
//! its peak memory usage can be measured with:
//!
//! ```text
//! valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_ascon_mem_usage <bench> > /dev/null
//!
//! ms_print massif.out.*
//! ```
//!
//! or, shoved all into one line:
//!
//! ```text
//! clear; clear; valgrind --tool=massif --heap=no --stacks=yes -- target/release/bench_ascon_mem_usage aead_encrypt_out > /dev/null; ms_print massif.out.*; rm massif.out.*
//! ```
//!
//! Make sure you build in release mode!
//!
//! Note: print!() and `black_box` are used to force the compiler not to optimize away the actual
//! code. The important stuff for benchmarking goes to stderr so the junk can be piped to /dev/null.
//!
//! Main is at the bottom: the first argument names the bench to run (see the `match`), and with
//! none it prints the struct sizes. Measure one at a time, because massif reports the peak across
//! the whole process.
//!
//! # What to expect, and why massif cannot see it
//!
//! As with AES, there is no interesting stack profile: every Ascon function works on the same
//! 40-byte permutation state, so a call needs a few hundred bytes at most -- under 1 KiB even for
//! the AEAD one-shots. That is below the floor of the process's own start-up that
//! `bench_aes_mem_usage` describes, so the massif number is the floor, not a measurement.
//!
//! The numbers in the crate docs come from the compiler instead, read the way
//! `bench_aes_mem_usage` does: `-C remark=prologepilog` gives each function's frame and
//! `--emit=asm` its calls, after LTO, and a figure is the deepest chain of frames below the entry
//! point plus 8 bytes of return address per call. The panic and unwind paths (`unwrap_failed`,
//! `panic_fmt`, `slice_index_fail`, `_Unwind_Resume`) are not followed, since valid input never
//! reaches them. A tail call adds nothing, libc's `memcpy` counts as its return address only, and
//! the `&mut dyn RNG` call is to `FixedNonce::next_bytes_out`. The figures are for x86-64 Linux;
//! the Windows x64 calling convention reserves more per frame, so measure on Linux to compare.
//! Cross-compiling is enough, because the remarks and the asm are written before the link (which
//! then fails without a Linux linker):
//!
//! ```text
//! cargo rustc --release --target x86_64-unknown-linux-gnu -p mem_usage_benches --bin bench_ascon_mem_usage -- -C remark=prologepilog --emit=asm
//! ```
//!
//! Each entry point is called through a `black_box`ed function pointer, which gives it an
//! out-of-line body of its own, so the frame being read is the entry point's and not the harness
//! closure's, whatever LTO decides to inline. The key, the cipher state and the inputs are built
//! in `#[inline(never)]` helpers, so their frames are siblings of the operation's. The persistent
//! cost, the value a caller holds between calls, is what `print_struct_sizes` prints.

#![allow(dead_code)]
#![allow(unused_imports)]

use core::hint::black_box;

use bouncycastle::ascon::Ascon_AEAD128;
use bouncycastle::ascon::ascon_aead128::{
    KEY_LEN, NONCE_LEN, SUSPENDED_ASCON_AEAD128_STATE_LEN, TAG_LEN,
};
use bouncycastle::ascon::ascon_cxof128::{
    AsconCXof128, AsconCXof128Squeezer, SUSPENDED_ASCON_CXOF128_STATE_LEN,
};
use bouncycastle::ascon::ascon_hash256::{AsconHash256, SUSPENDED_ASCON_HASH256_STATE_LEN};
use bouncycastle::ascon::ascon_xof128::{
    AsconXof128, AsconXof128Squeezer, SUSPENDED_ASCON_XOF128_STATE_LEN,
};
use bouncycastle::cipher::{Decrypting, Encrypting};
use bouncycastle::core::errors::{HashError, RNGError, SymmetricCipherError};
use bouncycastle::core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle::core::security_strength::SecurityStrength;
use bouncycastle::core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, Hash, RNG, SymmetricCipherDecryptor,
    SymmetricCipherEncryptor, XOF, XOFSqueezer,
};

type Enc = Ascon_AEAD128<Encrypting>;
type Dec = Ascon_AEAD128<Decrypting>;
type CipherErr = SymmetricCipherError;

/// Two full 16-byte AEAD blocks and a partial one; five full 8-byte sponge blocks.
const MSG_LEN: usize = 40;
/// One full AEAD block and a partial one.
const AAD_LEN: usize = 20;
/// The inline layout: ciphertext || tag.
const SEALED_LEN: usize = MSG_LEN + TAG_LEN;

const KEY: [u8; KEY_LEN] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
const NONCE: [u8; NONCE_LEN] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

/// Stands in for the caller's RNG and hands back [`NONCE`], so that the encrypting init runs
/// Ascon's initialization and nothing else: a DRBG's generate would be the deepest part of that
/// chain, and the default `do_encrypt_init`'s OS entropy call is outside what the frame remarks
/// can see. Not a random number generator; it exists only for this harness.
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
        SecurityStrength::_128bit
    }
}

/// This exists so /usr/bin/time can measure the base memory footprint of the harness itself.
#[inline(never)]
fn bench_do_nothing() {
    eprintln!("DoNothing");

    print!("{}", 1 + 1);
}

/// Prints the in-memory size of each value a caller holds between calls, and the size of its
/// suspended state. Neither depends on how much data has been processed.
#[inline(never)]
fn print_struct_sizes() {
    use core::mem::size_of;

    // The AEAD state is the key (16 B), the permutation state (40 B), the position in the rate
    // block and the call-order/direction state; the decryptor adds the 16 bytes of ciphertext it
    // holds back in case they are the inline tag.
    println!("size_of<Ascon_AEAD128<Encrypting>>: {}", size_of::<Enc>());
    println!("size_of<Ascon_AEAD128<Decrypting>>: {}", size_of::<Dec>());
    println!("SUSPENDED_ASCON_AEAD128_STATE_LEN: {}", SUSPENDED_ASCON_AEAD128_STATE_LEN);

    // The three sponges are the permutation state (40 B), an 8-byte rate buffer, its position
    // and the squeezing flag; a squeezer is the same sponge, moved.
    println!("size_of<AsconHash256>: {}", size_of::<AsconHash256>());
    println!("SUSPENDED_ASCON_HASH256_STATE_LEN: {}", SUSPENDED_ASCON_HASH256_STATE_LEN);
    println!("size_of<AsconXof128>: {}", size_of::<AsconXof128>());
    println!("size_of<AsconXof128Squeezer>: {}", size_of::<AsconXof128Squeezer>());
    println!("SUSPENDED_ASCON_XOF128_STATE_LEN: {}", SUSPENDED_ASCON_XOF128_STATE_LEN);
    println!("size_of<AsconCXof128>: {}", size_of::<AsconCXof128>());
    println!("size_of<AsconCXof128Squeezer>: {}", size_of::<AsconCXof128Squeezer>());
    println!("SUSPENDED_ASCON_CXOF128_STATE_LEN: {}", SUSPENDED_ASCON_CXOF128_STATE_LEN);
}

/// Runs the operation in its own frame. Returns nothing, so no result crosses the boundary.
#[inline(never)]
fn measure(f: impl FnOnce()) {
    f()
}

/// Wraps the hard-coded key. `#[inline(never)]` so the wrapping is a sibling frame of whatever
/// uses the key, not part of it.
#[inline(never)]
fn key() -> KeyMaterial<KEY_LEN> {
    KeyMaterial::<KEY_LEN>::from_bytes_as_type(&KEY, KeyType::SymmetricCipherKey).unwrap()
}

/// A message filled at run time, so that its contents are not a constant the compiler could fold
/// the whole computation over.
#[inline(never)]
fn message<const N: usize>(fill: u8) -> [u8; N] {
    let mut m = [0u8; N];
    m.fill(black_box(fill));
    m
}

// ---- state built ahead of the operation, each in its own frame -----------------------------

#[inline(never)]
fn encryptor() -> Enc {
    Enc::do_encrypt_init_rng(&key(), &mut FixedNonce).unwrap().0
}

/// An encryptor that has taken the AAD and the message, so the final pads a partial block.
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
    Dec::do_decrypt_init(&key(), &NONCE).unwrap()
}

/// `MSG_LEN` bytes sealed under [`NONCE`] with the AAD, as ciphertext || tag.
#[inline(never)]
fn sealed() -> [u8; SEALED_LEN] {
    let mut out = [0u8; SEALED_LEN];
    Enc::encrypt_with_aad_rng_out(
        &key(),
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

/// A decryptor that has taken the AAD and only the ciphertext of [`sealed`], so it is holding
/// back the last 16 bytes of ciphertext for the detached final.
#[inline(never)]
fn decryptor_holding_ciphertext() -> Dec {
    let mut dec = decryptor();
    dec.do_update_aad(&message::<AAD_LEN>(0x5a)).unwrap();
    let mut pt = [0u8; MSG_LEN];
    dec.do_decrypt_out(&sealed()[..MSG_LEN], &mut pt).unwrap();
    dec
}

#[inline(never)]
fn hash256() -> AsconHash256 {
    let mut h = AsconHash256::new();
    h.do_update(&message::<MSG_LEN>(0xa5));
    h
}

#[inline(never)]
fn xof128_squeezer() -> AsconXof128Squeezer {
    let mut x = AsconXof128::new();
    x.do_update(&message::<MSG_LEN>(0xa5));
    x.into_squeezer()
}

#[inline(never)]
fn cxof128() -> AsconCXof128 {
    AsconCXof128::with_customization(&message::<16>(0x3c)).unwrap()
}

#[inline(never)]
fn cxof128_squeezer() -> AsconCXof128Squeezer {
    let mut x = cxof128();
    x.do_update(&message::<MSG_LEN>(0xa5));
    x.into_squeezer()
}

// ---- Ascon-AEAD128, encrypting ------------------------------------------------------------

/// Initialization: the key check, then `IV || K || N` through `Ascon-p[12]`.
#[inline(never)]
fn bench_aead_encrypt_init() {
    eprintln!("Ascon_AEAD128<Encrypting>::do_encrypt_init_rng");
    let k = key();
    measure(|| {
        let op = black_box(
            <Enc as SymmetricCipherEncryptor<KEY_LEN, NONCE_LEN, TAG_LEN>>::do_encrypt_init_rng
                as fn(
                    &KeyMaterial<KEY_LEN>,
                    &mut dyn RNG,
                ) -> Result<(Enc, [u8; NONCE_LEN]), CipherErr>,
        );
        let (enc, nonce) = op(&k, &mut FixedNonce).unwrap();
        black_box(&enc);
        print!("{nonce:x?}");
    });
}

#[inline(never)]
fn bench_aead_encrypt_update_aad() {
    eprintln!("Ascon_AEAD128<Encrypting>::do_update_aad, {AAD_LEN} B");
    let enc = black_box(encryptor());
    let aad = black_box(message::<AAD_LEN>(0x5a));
    measure(move || {
        let mut enc = enc;
        let op = black_box(
            <Enc as AEADCipherEncryptor<KEY_LEN, NONCE_LEN, TAG_LEN, TAG_LEN>>::do_update_aad
                as fn(&mut Enc, &[u8]) -> Result<(), CipherErr>,
        );
        op(&mut enc, &aad).unwrap();
        black_box(&enc);
    });
}

#[inline(never)]
fn bench_aead_encrypt_out() {
    eprintln!("Ascon_AEAD128<Encrypting>::do_encrypt_out, {MSG_LEN} B");
    let enc = black_box(encryptor());
    let pt = black_box(message::<MSG_LEN>(0xa5));
    measure(move || {
        let mut enc = enc;
        let mut ct = [0u8; MSG_LEN];
        let op = black_box(
            <Enc as SymmetricCipherEncryptor<KEY_LEN, NONCE_LEN, TAG_LEN>>::do_encrypt_out
                as fn(&mut Enc, &[u8], &mut [u8]) -> Result<usize, CipherErr>,
        );
        let n = op(&mut enc, &pt, &mut ct).unwrap();
        print!("{:x?}", &ct[..n]);
    });
}

/// The inline-tag final: pads the last block, then finalization's `Ascon-p[12]`.
#[inline(never)]
fn bench_aead_encrypt_final() {
    eprintln!("Ascon_AEAD128<Encrypting>::do_encrypt_final");
    let enc = black_box(encryptor_after_data());
    measure(move || {
        let op = black_box(
            <Enc as SymmetricCipherEncryptor<KEY_LEN, NONCE_LEN, TAG_LEN>>::do_encrypt_final
                as fn(Enc) -> Result<([u8; TAG_LEN], usize), CipherErr>,
        );
        let (tag, n) = op(enc).unwrap();
        print!("{:x?}", &tag[..n]);
    });
}

#[inline(never)]
fn bench_aead_encrypt_final_detached() {
    eprintln!("Ascon_AEAD128<Encrypting>::do_encrypt_final_detachedtag_out");
    let enc = black_box(encryptor_after_data());
    measure(move || {
        let mut last = [0u8; TAG_LEN];
        let op = black_box(
            <Enc as AEADCipherEncryptor<KEY_LEN, NONCE_LEN, TAG_LEN, TAG_LEN>>::do_encrypt_final_detachedtag_out
                as fn(Enc, &mut [u8; TAG_LEN]) -> Result<(usize, [u8; TAG_LEN]), CipherErr>,
        );
        let (_, tag) = op(enc, &mut last).unwrap();
        print!("{tag:x?}");
    });
}

/// The one-shot with AAD and the tag inline: init, AAD, data and final in one call.
#[inline(never)]
fn bench_aead_encrypt_oneshot() {
    eprintln!("Ascon_AEAD128<Encrypting>::encrypt_with_aad_rng_out, {MSG_LEN} B");
    let k = key();
    let aad = black_box(message::<AAD_LEN>(0x5a));
    let pt = black_box(message::<MSG_LEN>(0xa5));
    measure(move || {
        let mut ct = [0u8; SEALED_LEN];
        let op = black_box(
            <Enc as AEADCipherEncryptor<KEY_LEN, NONCE_LEN, TAG_LEN, TAG_LEN>>::encrypt_with_aad_rng_out
                as fn(
                    &KeyMaterial<KEY_LEN>,
                    &mut dyn RNG,
                    &[u8],
                    &[u8],
                    &mut [u8],
                ) -> Result<([u8; NONCE_LEN], usize), CipherErr>,
        );
        let (_, n) = op(&k, &mut FixedNonce, &aad, &pt, &mut ct).unwrap();
        print!("{:x?}", &ct[..n]);
    });
}

// ---- Ascon-AEAD128, decrypting ------------------------------------------------------------

#[inline(never)]
fn bench_aead_decrypt_init() {
    eprintln!("Ascon_AEAD128<Decrypting>::do_decrypt_init");
    let k = key();
    measure(|| {
        let op = black_box(
            <Dec as SymmetricCipherDecryptor<KEY_LEN, NONCE_LEN, TAG_LEN>>::do_decrypt_init
                as fn(&KeyMaterial<KEY_LEN>, &[u8; NONCE_LEN]) -> Result<Dec, CipherErr>,
        );
        let dec = op(&k, &NONCE).unwrap();
        black_box(&dec);
    });
}

#[inline(never)]
fn bench_aead_decrypt_update_aad() {
    eprintln!("Ascon_AEAD128<Decrypting>::do_update_aad, {AAD_LEN} B");
    let dec = black_box(decryptor());
    let aad = black_box(message::<AAD_LEN>(0x5a));
    measure(move || {
        let mut dec = dec;
        let op = black_box(
            <Dec as AEADCipherDecryptor<KEY_LEN, NONCE_LEN, TAG_LEN, TAG_LEN>>::do_update_aad
                as fn(&mut Dec, &[u8]) -> Result<(), CipherErr>,
        );
        op(&mut dec, &aad).unwrap();
        black_box(&dec);
    });
}

/// The data update, which also maintains the decryptor's held-back 16 bytes.
#[inline(never)]
fn bench_aead_decrypt_out() {
    eprintln!("Ascon_AEAD128<Decrypting>::do_decrypt_out, {SEALED_LEN} B");
    let mut dec = black_box(decryptor());
    dec.do_update_aad(&message::<AAD_LEN>(0x5a)).unwrap();
    let ct = black_box(sealed());
    measure(move || {
        let mut dec = dec;
        let mut pt = [0u8; SEALED_LEN];
        let op = black_box(
            <Dec as SymmetricCipherDecryptor<KEY_LEN, NONCE_LEN, TAG_LEN>>::do_decrypt_out
                as fn(&mut Dec, &[u8], &mut [u8]) -> Result<usize, CipherErr>,
        );
        let n = op(&mut dec, &ct, &mut pt).unwrap();
        print!("{:x?}", &pt[..n]);
    });
}

/// The inline-tag final: finalization's `Ascon-p[12]`, then the constant-time tag comparison.
#[inline(never)]
fn bench_aead_decrypt_final() {
    eprintln!("Ascon_AEAD128<Decrypting>::do_decrypt_final");
    let dec = black_box(decryptor_holding_tag());
    measure(move || {
        let op = black_box(
            <Dec as SymmetricCipherDecryptor<KEY_LEN, NONCE_LEN, TAG_LEN>>::do_decrypt_final
                as fn(Dec) -> Result<([u8; TAG_LEN], usize), CipherErr>,
        );
        let (_, n) = op(dec).unwrap();
        print!("{n}");
    });
}

/// The detached final: decrypts the held-back ciphertext, then checks the separate tag.
#[inline(never)]
fn bench_aead_decrypt_final_detached() {
    eprintln!("Ascon_AEAD128<Decrypting>::do_decrypt_final_detachedtag_out");
    let dec = black_box(decryptor_holding_ciphertext());
    let tag: [u8; TAG_LEN] = black_box(sealed()[MSG_LEN..].try_into().unwrap());
    measure(move || {
        let mut last = [0u8; TAG_LEN];
        let op = black_box(
            <Dec as AEADCipherDecryptor<KEY_LEN, NONCE_LEN, TAG_LEN, TAG_LEN>>::do_decrypt_final_detachedtag_out
                as fn(Dec, &[u8; TAG_LEN], &mut [u8; TAG_LEN]) -> Result<usize, CipherErr>,
        );
        let n = op(dec, &tag, &mut last).unwrap();
        print!("{:x?}", &last[..n]);
    });
}

/// The one-shot with AAD and the tag inline.
#[inline(never)]
fn bench_aead_decrypt_oneshot() {
    eprintln!("Ascon_AEAD128<Decrypting>::decrypt_with_aad_out, {SEALED_LEN} B");
    let k = key();
    let aad = black_box(message::<AAD_LEN>(0x5a));
    let ct = black_box(sealed());
    measure(move || {
        let mut pt = [0u8; MSG_LEN];
        let op = black_box(
            <Dec as AEADCipherDecryptor<KEY_LEN, NONCE_LEN, TAG_LEN, TAG_LEN>>::decrypt_with_aad_out
                as fn(
                    &KeyMaterial<KEY_LEN>,
                    &[u8; NONCE_LEN],
                    &[u8],
                    &[u8],
                    &mut [u8],
                ) -> Result<usize, CipherErr>,
        );
        let n = op(&k, &NONCE, &aad, &ct, &mut pt).unwrap();
        print!("{:x?}", &pt[..n]);
    });
}

// ---- Ascon-Hash256 ------------------------------------------------------------------------
//
// `new` copies a precomputed state (SP 800-232 Table 12) and runs no permutation, so it is not
// measured.

#[inline(never)]
fn bench_hash256_update() {
    eprintln!("AsconHash256::do_update, {MSG_LEN} B");
    let h = black_box(AsconHash256::new());
    let msg = black_box(message::<MSG_LEN>(0xa5));
    measure(move || {
        let mut h = h;
        let op = black_box(<AsconHash256 as Hash>::do_update as fn(&mut AsconHash256, &[u8]));
        op(&mut h, &msg);
        black_box(&h);
    });
}

#[inline(never)]
fn bench_hash256_final() {
    eprintln!("AsconHash256::do_final_out");
    let h = black_box(hash256());
    measure(move || {
        let mut out = [0u8; 32];
        let op =
            black_box(<AsconHash256 as Hash>::do_final_out as fn(AsconHash256, &mut [u8]) -> usize);
        let n = op(h, &mut out);
        print!("{:x?}", &out[..n]);
    });
}

#[inline(never)]
fn bench_hash256_oneshot() {
    eprintln!("AsconHash256::hash_out, {MSG_LEN} B");
    let h = black_box(AsconHash256::new());
    let msg = black_box(message::<MSG_LEN>(0xa5));
    measure(move || {
        let mut out = [0u8; 32];
        let op = black_box(
            <AsconHash256 as Hash>::hash_out as fn(AsconHash256, &[u8], &mut [u8]) -> usize,
        );
        let n = op(h, &msg, &mut out);
        print!("{:x?}", &out[..n]);
    });
}

// ---- Ascon-XOF128 -------------------------------------------------------------------------

#[inline(never)]
fn bench_xof128_update() {
    eprintln!("AsconXof128::do_update, {MSG_LEN} B");
    let x = black_box(AsconXof128::new());
    let msg = black_box(message::<MSG_LEN>(0xa5));
    measure(move || {
        let mut x = x;
        let op = black_box(<AsconXof128 as Hash>::do_update as fn(&mut AsconXof128, &[u8]));
        op(&mut x, &msg);
        black_box(&x);
    });
}

#[inline(never)]
fn bench_xof128_output() {
    eprintln!("AsconXof128Squeezer::do_output_out, {MSG_LEN} B");
    let s = black_box(xof128_squeezer());
    measure(move || {
        let mut s = s;
        let mut out = [0u8; MSG_LEN];
        let op = black_box(
            <AsconXof128Squeezer as XOFSqueezer>::do_output_out
                as fn(&mut AsconXof128Squeezer, &mut [u8]) -> usize,
        );
        let n = op(&mut s, &mut out);
        print!("{:x?}", &out[..n]);
    });
}

#[inline(never)]
fn bench_xof128_oneshot() {
    eprintln!("AsconXof128::xof_out, {MSG_LEN} B in, {MSG_LEN} B out");
    let x = black_box(AsconXof128::new());
    let msg = black_box(message::<MSG_LEN>(0xa5));
    measure(move || {
        let mut out = [0u8; MSG_LEN];
        let op =
            black_box(<AsconXof128 as XOF>::xof_out as fn(AsconXof128, &[u8], &mut [u8]) -> usize);
        let n = op(x, &msg, &mut out);
        print!("{:x?}", &out[..n]);
    });
}

// ---- Ascon-CXOF128 ------------------------------------------------------------------------

/// Construction absorbs the customization string, so unlike the other sponges' `new` it is an
/// operation worth measuring.
#[inline(never)]
fn bench_cxof128_with_customization() {
    eprintln!("AsconCXof128::with_customization, 16 B");
    let z = black_box(message::<16>(0x3c));
    measure(move || {
        let op = black_box(
            AsconCXof128::with_customization as fn(&[u8]) -> Result<AsconCXof128, HashError>,
        );
        let x = op(&z).unwrap();
        black_box(&x);
    });
}

#[inline(never)]
fn bench_cxof128_update() {
    eprintln!("AsconCXof128::do_update, {MSG_LEN} B");
    let x = black_box(cxof128());
    let msg = black_box(message::<MSG_LEN>(0xa5));
    measure(move || {
        let mut x = x;
        let op = black_box(<AsconCXof128 as Hash>::do_update as fn(&mut AsconCXof128, &[u8]));
        op(&mut x, &msg);
        black_box(&x);
    });
}

#[inline(never)]
fn bench_cxof128_output() {
    eprintln!("AsconCXof128Squeezer::do_output_out, {MSG_LEN} B");
    let s = black_box(cxof128_squeezer());
    measure(move || {
        let mut s = s;
        let mut out = [0u8; MSG_LEN];
        let op = black_box(
            <AsconCXof128Squeezer as XOFSqueezer>::do_output_out
                as fn(&mut AsconCXof128Squeezer, &mut [u8]) -> usize,
        );
        let n = op(&mut s, &mut out);
        print!("{:x?}", &out[..n]);
    });
}

#[inline(never)]
fn bench_cxof128_oneshot() {
    eprintln!("AsconCXof128::xof_out, {MSG_LEN} B in, {MSG_LEN} B out");
    let x = black_box(cxof128());
    let msg = black_box(message::<MSG_LEN>(0xa5));
    measure(move || {
        let mut out = [0u8; MSG_LEN];
        let op = black_box(
            <AsconCXof128 as XOF>::xof_out as fn(AsconCXof128, &[u8], &mut [u8]) -> usize,
        );
        let n = op(x, &msg, &mut out);
        print!("{:x?}", &out[..n]);
    });
}

fn main() {
    let which = std::env::args().nth(1).unwrap_or_default();
    match which.as_str() {
        "nothing" => bench_do_nothing(),
        "aead_encrypt_init" => bench_aead_encrypt_init(),
        "aead_encrypt_update_aad" => bench_aead_encrypt_update_aad(),
        "aead_encrypt_out" => bench_aead_encrypt_out(),
        "aead_encrypt_final" => bench_aead_encrypt_final(),
        "aead_encrypt_final_detached" => bench_aead_encrypt_final_detached(),
        "aead_encrypt_oneshot" => bench_aead_encrypt_oneshot(),
        "aead_decrypt_init" => bench_aead_decrypt_init(),
        "aead_decrypt_update_aad" => bench_aead_decrypt_update_aad(),
        "aead_decrypt_out" => bench_aead_decrypt_out(),
        "aead_decrypt_final" => bench_aead_decrypt_final(),
        "aead_decrypt_final_detached" => bench_aead_decrypt_final_detached(),
        "aead_decrypt_oneshot" => bench_aead_decrypt_oneshot(),
        "hash256_update" => bench_hash256_update(),
        "hash256_final" => bench_hash256_final(),
        "hash256_oneshot" => bench_hash256_oneshot(),
        "xof128_update" => bench_xof128_update(),
        "xof128_output" => bench_xof128_output(),
        "xof128_oneshot" => bench_xof128_oneshot(),
        "cxof128_with_customization" => bench_cxof128_with_customization(),
        "cxof128_update" => bench_cxof128_update(),
        "cxof128_output" => bench_cxof128_output(),
        "cxof128_oneshot" => bench_cxof128_oneshot(),
        _ => print_struct_sizes(),
    }
}
