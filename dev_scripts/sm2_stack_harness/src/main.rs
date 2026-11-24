//! What SM2 public key encryption and decryption (bouncycastle_ec::sm2::encryption), SM2 signing
//! (bouncycastle_ec::sm2::sm2), and the handling of their private keys, leave on the dead stack,
//! for `../check_sm2_stack.sh`. For each operation the stack below the call is painted, the
//! operation run with its results going to the heap or to a live frame above, the dead stack copied
//! out, and the copy searched for the 8-byte words of every secret the operation handled: the
//! private key `dB` and the RNG's output and `k`, as bytes and as limbs; the shared point's `x2`
//! and `y2`, as bytes, as limbs and as SM3 reads them; the first hash values of the key stream; the
//! message; and the hash a refused decryption computed; for signing, the key's `dA` and
//! `(1 + dA)^-1`, the RNG's output and `k`. The RNG is a fixed one, so the values are computed
//! here, with the crate's public arithmetic, and checked against the operation's own output before
//! they are searched for.
//!
//! Each operation is also run twice, at the same addresses, over different secrets, and the two
//! copies compared: but for the ciphertext and the registers the call's first frames saved,
//! they must be the same.
//!
//! Controls: nothing run must leave nothing, and the same stack twice; a copy of `dB` left in a
//! frame must be found, and copies of two keys must differ.
//!
//!   target/release/sm2_stack_harness
//!
//! One line per operation, `ok` or `FAIL`; the exit status is 1 if anything failed.
use bouncycastle_core::errors::PublicKeyEncryptionError;
use bouncycastle_core::hazmat::FixedSeedRNG;
use bouncycastle_core::signature_key::{OneShotSigningKey, OneShotVerifyingKey, SigningKey};
use bouncycastle_core::traits::{Hash, PrivateKey, PublicKey, SignatureSigner};
use bouncycastle_digest::sm3::SM3;
use bouncycastle_ec::hazmat::sm2_comb::comb_multiply_base_point;
use bouncycastle_ec::hazmat::sm2_mul::multiply_point;
use bouncycastle_ec::hazmat::sm2_scalar::{Sm2Scalar, Sm2ScalarField};
use bouncycastle_ec::hazmat::sm2_sec1;
use bouncycastle_ec::sm2::encryption::{
    C1_LEN, C3_LEN, OVERHEAD_LEN, SM2EncryptionPrivateKey, SM2EncryptionPublicKey, keygen,
};
use bouncycastle_ec::sm2::extra_bits::{
    reduce_wide_bits_mod_n_minus_1, reduce_wide_bits_mod_n_minus_2,
};
use bouncycastle_ec::sm2::keys::{self, SM2PrivateKey, SM2PublicKey};
use bouncycastle_ec::sm2::sm2::SIG_LEN;
use std::collections::HashSet;
use std::hint::black_box;

/// How far below the call the stack is painted and searched. The deepest operation here uses
/// under 8 KiB.
const DEPTH: usize = 256 * 1024;
/// The gap between the frame that takes the copy and the operation's first frame.
const PAD: usize = 16 * 1024;
const PAINT: u8 = 0xA5;
/// How far below the call a difference between two runs is put down to the registers the
/// call's first frames saved, and not counted. The furthest seen is 120 bytes.
const SAVED_REGISTERS: usize = 256;

/// The private key of GM/T 0003.5-2012 Annex C.2.
const DB: [u8; 32] = [
    0x39, 0x45, 0x20, 0x8f, 0x7b, 0x21, 0x44, 0xb1, 0x3f, 0x36, 0xe3, 0x8a, 0xc6, 0xd3, 0x9f, 0x95,
    0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xb5, 0x1a, 0x42, 0xfb, 0x81, 0xef, 0x4d, 0xf7, 0xc5, 0xb8,
];

/// A second private key: SHA-256 of a label, which is below `n - 1`.
const DB_2: [u8; 32] = [
    0x62, 0xa6, 0x7a, 0x18, 0x70, 0x7c, 0xd9, 0xd5, 0x97, 0xd8, 0xfe, 0xd5, 0x0d, 0x8e, 0xde, 0xb3,
    0xc0, 0xc5, 0x8a, 0x1f, 0x60, 0x6b, 0x8b, 0x14, 0xb0, 0xaa, 0x00, 0x86, 0xc5, 0x8f, 0x79, 0xf3,
];

/// Two draws of the RNG, 40 bytes each: SHA-256 of a label, and eight bytes more.
const WIDE_1: [u8; 40] = [
    0x45, 0xeb, 0xbf, 0xaa, 0x32, 0x67, 0x78, 0x30, 0x7e, 0x67, 0x38, 0x36, 0xb6, 0xf7, 0x2b, 0x03,
    0x34, 0xc5, 0x66, 0xe8, 0x4f, 0x09, 0x22, 0x2f, 0x82, 0x41, 0xd2, 0x68, 0xb1, 0x3c, 0xb8, 0x3d,
    0x1f, 0x48, 0x06, 0x63, 0x16, 0x20, 0x95, 0xc6,
];
const WIDE_2: [u8; 40] = [
    0x43, 0x30, 0xed, 0xba, 0xa1, 0xeb, 0xcc, 0x61, 0xfb, 0xd5, 0xad, 0xec, 0x49, 0x80, 0x51, 0xcb,
    0xac, 0x59, 0xbb, 0x00, 0x31, 0xb7, 0x4e, 0x35, 0x01, 0x71, 0xde, 0xb6, 0xe5, 0xad, 0x57, 0xe7,
    0x97, 0x94, 0xb2, 0x93, 0xc3, 0xfa, 0x63, 0xdf,
];
/// A draw whose `k` gives a one-byte message under the annex's public key the key stream `00`,
/// so that encryption draws again (GB/T 32918.4-2016 Section 6.1 step A5). Found by a Python
/// model of the standard, counting up from SHA-256 of a label; `the_retry_draw_gives_a_zero_t`
/// checks it with the crate's arithmetic.
const WIDE_ZERO_T: [u8; 40] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6a, 0x78, 0x2f, 0xa6, 0x7a, 0xe2, 0x22, 0x23,
    0x7a, 0xcc, 0x85, 0xb2, 0x85, 0xae, 0x0f, 0xd3, 0x09, 0x39, 0x72, 0x9c, 0x26, 0xbd, 0xac, 0xdc,
    0x8f, 0xb7, 0xb2, 0x29, 0x92, 0x47, 0xf1, 0xc0,
];

const FAILED: Result<(), PublicKeyEncryptionError> =
    Err(PublicKeyEncryptionError::DecryptionFailed);
const FAILED_OUT: Result<usize, PublicKeyEncryptionError> =
    Err(PublicKeyEncryptionError::DecryptionFailed);

#[inline(never)]
fn paint() {
    let mut frame = [PAINT; DEPTH + PAD];
    black_box(&mut frame);
}

/// Runs `f` with its frames starting `PAD` below this one, so that the frame of [`snapshot`]
/// does not land on them. `f` is the tail call, so that what it returns by value is written
/// straight to where the caller of [`measure`] keeps it, a live frame above everything
/// searched, and is not staged in a frame that is then dead.
#[inline(never)]
fn run_deep<T>(f: impl FnOnce() -> T) -> T {
    let mut pad = [0u8; PAD];
    black_box(&mut pad);
    f()
}

/// Copies the `DEPTH` bytes below this frame into `buf`, lowest address first.
#[inline(never)]
fn snapshot(buf: &mut [u8]) {
    let marker = 0u8;
    let top = black_box(&raw const marker as usize) & !15;
    let base = top - DEPTH;
    for (i, b) in buf.iter_mut().enumerate() {
        // SAFETY: none that Rust would recognise: this reads the stack below the current
        // frame, which no live object owns. It is what this program exists to do. The pages
        // are mapped, `paint` having written every byte of them, and on x86-64 and arm64 Linux
        // nothing else writes below the stack pointer of a thread that takes no signal.
        *b = unsafe { core::ptr::read_volatile((base + i) as *const u8) };
    }
}

#[inline(never)]
fn measure<T>(buf: &mut [u8], f: impl FnOnce() -> T) -> T {
    paint();
    let result = run_deep(f);
    snapshot(buf);
    result
}

/// The leak the second control looks for: a copy of `value` in a frame, left as it is, further
/// below the call than [`SAVED_REGISTERS`].
#[inline(never)]
fn leak(value: &[u64; 4]) {
    let mut pad = [0u8; 2 * SAVED_REGISTERS];
    black_box(&mut pad);
    leak_here(value);
}

#[inline(never)]
fn leak_here(value: &[u64; 4]) {
    let mut local = *value;
    black_box(&mut local);
}

/// A named secret, as the bytes it would be in memory.
type Values = Vec<(String, Vec<u8>)>;

/// A big-endian integer as its limbs lie in memory: the bytes in the other order.
fn limb_image(be: &[u8]) -> Vec<u8> {
    be.iter().rev().copied().collect()
}

/// A byte string as SM3 holds it in its message schedule, and a hash value as SM3 holds it in
/// its state: each 32-bit word's bytes reversed.
fn sm3_words(bytes: &[u8]) -> Vec<u8> {
    bytes.chunks_exact(4).flat_map(|word| word.iter().rev().copied()).collect()
}

/// An integer given as big-endian bytes: as those bytes and as limbs.
fn push_integer(values: &mut Values, name: &str, be: &[u8]) {
    values.push((format!("{name} (bytes)"), be.to_vec()));
    values.push((format!("{name} (limbs)"), limb_image(be)));
}

/// A byte string, as it is and as SM3 has it.
fn push_bytes(values: &mut Values, name: &str, bytes: &[u8]) {
    values.push((name.to_string(), bytes.to_vec()));
    values.push((format!("{name} (SM3 words)"), sm3_words(bytes)));
}

fn sm3(parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = SM3::new();
    for part in parts {
        hash.do_update(part);
    }
    let mut out = [0u8; 32];
    hash.do_final_out(&mut out);
    out
}

/// `x2 || y2` for the shared point `[scalar]point`, and what is searched for of it: the
/// coordinates as integers and as SM3 reads them, and the first hash values of the key stream
/// `KDF(x2 || y2, 8 * len)` (GB/T 32918.4-2016 Section 5.4.3), four at most. Returns the
/// values, `x2 || y2` and the key stream.
fn shared_point_values(
    scalar: &Sm2Scalar,
    point_encoding: &[u8; C1_LEN],
    len: usize,
    tag: &str,
) -> (Values, [u8; 64], Vec<u8>) {
    let point = sm2_sec1::decode_point(point_encoding).unwrap();
    let (x2, y2) = multiply_point(scalar, &point).affine_of_nonidentity();
    let mut z = [0u8; 64];
    z[..32].copy_from_slice(&sm2_sec1::be_bytes_from_limbs(&x2.to_limbs()));
    z[32..].copy_from_slice(&sm2_sec1::be_bytes_from_limbs(&y2.to_limbs()));

    let mut values = Values::new();
    push_integer(&mut values, &format!("x2{tag}"), &z[..32]);
    push_integer(&mut values, &format!("y2{tag}"), &z[32..]);
    values.push((format!("x2 || y2{tag} (SM3 words)"), sm3_words(&z)));
    let mut t = Vec::new();
    for ct in 1..=len.div_ceil(32) as u32 {
        let block = sm3(&[&z, &ct.to_be_bytes()]);
        if ct <= 4 {
            push_bytes(&mut values, &format!("key stream hash value {ct}{tag}"), &block);
        }
        t.extend_from_slice(&block);
    }
    t.truncate(len);
    (values, z, t)
}

/// What one draw of the RNG leads to when encrypting `message` to the public key `pb`, and the
/// ciphertext it gives: the draw, as bytes and as the limbs its reduction reads; `k`; and
/// [`shared_point_values`]. `c1` and `c2` are `None` when the key stream is all zero.
struct Attempt {
    values: Values,
    c1: [u8; C1_LEN],
    c2: Option<Vec<u8>>,
    c3: [u8; C3_LEN],
}

fn attempt(wide: &[u8; 40], pb: &[u8; C1_LEN], message: &[u8], tag: &str) -> Attempt {
    let k = reduce_wide_bits_mod_n_minus_1(wide);
    let mut values = Values::new();
    push_integer(&mut values, &format!("RNG output{tag}"), wide);
    push_integer(&mut values, &format!("k{tag}"), &k.to_be_bytes());
    let (shared, z, t) = shared_point_values(&k, pb, message.len(), tag);
    values.extend(shared);

    let (x1, y1) = comb_multiply_base_point(&k).affine_of_nonidentity();
    let c1 = sm2_sec1::encode_uncompressed(&x1, &y1);
    let c2 =
        t.iter().any(|b| *b != 0).then(|| message.iter().zip(&t).map(|(m, t)| m ^ t).collect());
    let c3 = sm3(&[&z[..32], message, &z[32..]]);
    Attempt { values, c1, c2, c3 }
}

/// The message, as it is and as SM3 has it.
fn message_values(message: &[u8]) -> Values {
    let mut values = Values::new();
    push_bytes(&mut values, "message", message);
    values
}

/// The painted stack's copy, the copy before it, and the count of what failed.
struct Scan {
    buf: Vec<u8>,
    before: Vec<u8>,
    failures: usize,
}

impl Scan {
    fn new() -> Self {
        Self { buf: vec![0u8; DEPTH], before: vec![0u8; DEPTH], failures: 0 }
    }

    /// Paints, runs `f` and copies the stack out. What `f` returns comes back by value.
    fn run<T>(&mut self, f: impl FnOnce() -> T) -> T {
        measure(&mut self.buf, f)
    }

    /// The bytes of stack the last run used, and for each of `values`, how many of its words
    /// were found in them and how many it has.
    fn search(&self, values: &Values) -> (usize, Vec<(String, usize, usize)>) {
        let lowest = self.buf.iter().position(|b| *b != PAINT).unwrap_or(DEPTH);
        let used = (DEPTH - lowest).saturating_sub(PAD);
        // Every 8 bytes of the used region, at every offset: a secret need not lie aligned.
        let mut windows: HashSet<&[u8]> = HashSet::new();
        for i in lowest..DEPTH.saturating_sub(7) {
            windows.insert(&self.buf[i..i + 8]);
        }
        let mut counts = Vec::new();
        for (name, image) in values {
            // The value's 8-byte words, and its last 8 bytes where they are not one of those.
            let mut words: Vec<&[u8]> = image.chunks_exact(8).collect();
            if image.len() > 8 && image.len() % 8 != 0 {
                words.push(&image[image.len() - 8..]);
            }
            // A word of one repeated byte (a zero limb, padding) says nothing when found.
            words.retain(|w| w.iter().any(|b| *b != w[0]));
            let hits = words.iter().filter(|w| windows.contains(*w)).count();
            counts.push((name.clone(), hits, words.len()));
        }
        (used, counts)
    }

    /// After an operation: none of `values` may be on the stack it used.
    fn clean(&mut self, operation: &str, values: &Values) {
        let (used, counts) = self.search(values);
        let found: Vec<String> = counts
            .iter()
            .filter(|(_, hits, _)| *hits > 0)
            .map(|(name, hits, words)| format!("{name}: {hits} of {words} words"))
            .collect();
        if found.is_empty() {
            println!("ok   {operation}: none of its secrets in the {used} bytes of stack it used");
        } else {
            println!(
                "FAIL {operation}: left in the {used} bytes of stack it used: {}",
                found.join(", ")
            );
            self.failures += 1;
        }
    }

    /// After the leak control: every word of `values` must be found.
    fn leaked(&mut self, operation: &str, values: &Values) {
        let (_, counts) = self.search(values);
        if counts.iter().all(|(_, hits, words)| *words > 0 && hits == words) {
            println!("ok   {operation}: found");
        } else {
            println!(
                "FAIL {operation}: not found, so an operation that leaves nothing proves nothing"
            );
            self.failures += 1;
        }
    }

    /// Keeps the last run's copy, to compare the next run's with.
    fn keep(&mut self) {
        self.before.copy_from_slice(&self.buf);
    }

    /// The bytes in which the last run's stack is not the kept run's, leaving out those that
    /// are a part of `public` in the one and the same part of `public_before` in the other,
    /// and how far below the call the furthest of them is.
    fn differences(&self, public_before: &[u8], public: &[u8]) -> (usize, usize) {
        let lowest = |buf: &[u8]| buf.iter().position(|b| *b != PAINT).unwrap_or(DEPTH);
        let start = lowest(&self.before).min(lowest(&self.buf));
        let (mut count, mut furthest) = (0, 0);
        let mut i = start;
        while i < DEPTH {
            if self.before[i] == self.buf[i] {
                i += 1;
                continue;
            }
            let mut end = i;
            while end < DEPTH && self.before[end] != self.buf[end] {
                end += 1;
            }
            let len = end - i;
            let explained = (0..public.len().saturating_sub(len - 1)).any(|at| {
                public_before[at..at + len] == self.before[i..end]
                    && public[at..at + len] == self.buf[i..end]
            });
            // The first frames of a call save the registers they go on to use, and what those
            // held is this program's own: a loop's pointer, a length.
            let below_the_call = (DEPTH - end).saturating_sub(PAD);
            if !explained && below_the_call >= SAVED_REGISTERS {
                count += len;
                furthest = furthest.max((DEPTH - i).saturating_sub(PAD));
            }
            i = end;
        }
        (count, furthest)
    }

    /// After the same operation run twice, at the same addresses, over different secrets: the
    /// stack it used must be the same both times, but for what it handed out, `public_before`
    /// the first time and `public` the second. A known value is not needed for this, so it
    /// reaches the intermediates that [`Self::clean`] has no name for.
    fn same(&mut self, operation: &str, public_before: &[u8], public: &[u8]) {
        assert_eq!(public_before.len(), public.len());
        match self.differences(public_before, public) {
            (0, _) => println!("ok   {operation}: the same stack over different secrets"),
            (count, furthest) => {
                println!(
                    "FAIL {operation}: {count} bytes of stack differ with the secrets, the \
                     furthest {furthest} bytes below the call"
                );
                self.failures += 1;
            }
        }
    }

    /// After the leak control run twice: the two copies must differ.
    fn differs(&mut self, operation: &str) {
        if self.differences(&[], &[]).0 > 0 {
            println!("ok   {operation}: found");
        } else {
            println!(
                "FAIL {operation}: not found, so an operation that leaves the same stack proves \
                 nothing"
            );
            self.failures += 1;
        }
    }
}

/// A message of `len` bytes with no 8-byte word of one repeated byte.
fn message(len: usize) -> Box<[u8]> {
    (0..len).map(|i| (i * 37 + 11) as u8).collect()
}

/// `dB` as what is searched for.
fn key_values(d: &[u8; 32]) -> Values {
    let mut values = Values::new();
    push_integer(&mut values, "dB", d);
    values
}

fn main() {
    let mut scan = Scan::new();
    let pk = Box::new(SM2EncryptionPrivateKey::from_bytes(&DB).unwrap().derive_pk());
    let pb = pk.encode();
    // Everything an operation is handed lives on the heap and is refilled for its second run,
    // so that the two runs differ in their secrets and in no address.
    let mut sk = Box::new(SM2EncryptionPrivateKey::from_bytes(&DB).unwrap());
    let mut rng = Box::new(FixedSeedRNG::new([0u8; 80]));
    let mut limbs = Box::new([0u64; 4]);

    // The controls.
    for _ in 0..2 {
        scan.run(|| {});
        scan.clean("control, nothing run", &key_values(&DB));
        scan.keep();
    }
    scan.same("control, nothing run twice", &[], &[]);
    for d in [&DB, &DB_2] {
        *limbs = sm2_sec1::limbs_from_be_bytes(d);
        scan.keep();
        scan.run(|| leak(&limbs));
        scan.leaked("control, a copy of dB left in a frame", &vec![key_values(d)[1].clone()]);
    }
    scan.differs("control, copies of two keys left in a frame");

    // The handling of the private key: loaded, generated, encoded, copied, and its public key
    // derived. A public key is the one thing these leave that differs with the key: as its
    // encoding and as the limbs of its coordinates.
    let public_of = |pk: &SM2EncryptionPublicKey| {
        let encoded = pk.encode();
        [&encoded[..], &limb_image(&encoded[1..33]), &limb_image(&encoded[33..])].concat()
    };
    let mut encoded = Box::new([0u8; 32]);
    for d in [&DB, &DB_2] {
        scan.keep();
        *encoded = *d;
        let loaded = scan.run(|| SM2EncryptionPrivateKey::from_bytes(&encoded[..]));
        assert_eq!(loaded.unwrap().encode(), *d);
        scan.clean("from_bytes", &key_values(d));
    }
    scan.same("from_bytes", &[], &[]);
    for d in [&DB, &DB_2] {
        scan.keep();
        *sk = SM2EncryptionPrivateKey::from_bytes(d).unwrap();
        let bytes = scan.run(|| sk.encode());
        assert_eq!(bytes, *d);
        scan.clean("encode", &key_values(d));
    }
    scan.same("encode", &[], &[]);
    for d in [&DB, &DB_2] {
        scan.keep();
        *sk = SM2EncryptionPrivateKey::from_bytes(d).unwrap();
        assert_eq!(scan.run(|| sk.encode_out(&mut encoded)), 32);
        assert_eq!(*encoded, *d);
        scan.clean("encode_out", &key_values(d));
    }
    scan.same("encode_out", &[], &[]);
    for d in [&DB, &DB_2] {
        scan.keep();
        *sk = SM2EncryptionPrivateKey::from_bytes(d).unwrap();
        let copy = scan.run(|| (*sk).clone());
        assert_eq!(copy, *sk);
        scan.clean("clone", &key_values(d));
    }
    scan.same("clone", &[], &[]);
    let mut publics = Vec::new();
    for d in [&DB, &DB_2] {
        scan.keep();
        *sk = SM2EncryptionPrivateKey::from_bytes(d).unwrap();
        let derived = scan.run(|| sk.derive_pk());
        scan.clean("derive_pk", &key_values(d));
        publics.push(public_of(&derived));
    }
    scan.same("derive_pk", &publics[0], &publics[1]);
    let mut publics = Vec::new();
    for wide in [WIDE_1, WIDE_2] {
        scan.keep();
        *rng = FixedSeedRNG::new([wide, wide].concat().try_into().unwrap());
        let (generated_pk, generated_sk) = scan.run(|| keygen(&mut *rng)).unwrap();
        let d = reduce_wide_bits_mod_n_minus_2(&wide).to_be_bytes();
        assert_eq!(generated_sk.encode(), d, "not its reduction");
        let mut values = key_values(&d);
        push_integer(&mut values, "RNG output", &wide);
        scan.clean("keygen", &values);
        publics.push(public_of(&generated_pk));
    }
    scan.same("keygen", &publics[0], &publics[1]);

    for len in [19usize, 100] {
        let msg = message(len);
        let mut buf = msg.clone();
        let mut out = vec![0u8; len + OVERHEAD_LEN].into_boxed_slice();
        let mut c1 = Box::new([0u8; C1_LEN]);
        let mut c3 = Box::new([0u8; C3_LEN]);
        let draws = [WIDE_1, WIDE_2].map(|wide| {
            let made = attempt(&wide, &pb, &msg, "");
            let public = [&made.c1[..], &made.c3[..]].concat();
            let mut values = made.values.clone();
            values.extend(message_values(&msg));
            (wide, made, public, values)
        });

        // Encryption, where the message lies: twice, from two draws of the RNG.
        let operation = format!("encrypt_detached_inplace, {len} bytes");
        for (wide, made, _, values) in &draws {
            scan.keep();
            *rng = FixedSeedRNG::new([*wide, *wide].concat().try_into().unwrap());
            buf.copy_from_slice(&msg);
            let parts = scan.run(|| pk.encrypt_detached_inplace(&mut *rng, &mut buf)).unwrap();
            let c2 = made.c2.as_ref().unwrap();
            assert_eq!((parts.0, parts.1, &buf[..]), (made.c1, made.c3, &c2[..]), "not its k");
            scan.clean(&operation, values);
        }
        scan.same(&operation, &draws[0].2, &draws[1].2);

        // Encryption into a buffer, in both orders.
        let operation = format!("encrypt_out, {len} bytes");
        for (wide, made, _, values) in &draws {
            scan.keep();
            *rng = FixedSeedRNG::new([*wide, *wide].concat().try_into().unwrap());
            scan.run(|| pk.encrypt_out(&mut *rng, &msg, &mut out)).unwrap();
            assert_eq!(out[..C1_LEN], made.c1);
            scan.clean(&operation, values);
        }
        scan.same(&operation, &draws[0].2, &draws[1].2);
        let operation = format!("encrypt_c1c2c3_out, {len} bytes");
        for (wide, made, _, values) in &draws {
            scan.keep();
            *rng = FixedSeedRNG::new([*wide, *wide].concat().try_into().unwrap());
            scan.run(|| pk.encrypt_c1c2c3_out(&mut *rng, &msg, &mut out)).unwrap();
            assert_eq!(out[C1_LEN + len..], made.c3);
            scan.clean(&operation, values);
        }
        scan.same(&operation, &draws[0].2, &draws[1].2);

        // Decryption: one C1 under two private keys, each with the C2 and C3 that its shared
        // point gives the message.
        *c1 = draws[0].1.c1;
        let keys = [DB, DB_2].map(|d| {
            let scalar = Sm2Scalar::from_be_bytes(&d);
            let (shared, z, t) = shared_point_values(&scalar, &c1, len, "");
            let c2: Vec<u8> = msg.iter().zip(&t).map(|(m, t)| m ^ t).collect();
            let c3 = sm3(&[&z[..32], &msg, &z[32..]]);
            let mut values = key_values(&d);
            values.extend(shared);
            values.extend(message_values(&msg));
            (d, z, t, c2, c3, values)
        });
        assert_eq!(keys[0].3, *draws[0].1.c2.as_ref().unwrap(), "not the shared point");

        let operation = format!("decrypt_detached_inplace, {len} bytes");
        for (d, _, _, c2, c3_of_key, values) in &keys {
            scan.keep();
            *sk = SM2EncryptionPrivateKey::from_bytes(d).unwrap();
            buf.copy_from_slice(c2);
            *c3 = *c3_of_key;
            scan.run(|| sk.decrypt_detached_inplace(&c1, &c3, &mut buf)).unwrap();
            assert_eq!(buf, msg);
            scan.clean(&operation, values);
        }
        scan.same(&operation, &[], &[]);

        for (operation, c1c2c3) in [("decrypt_out", false), ("decrypt_c1c2c3_out", true)] {
            let operation = format!("{operation}, {len} bytes");
            for (d, _, _, c2, c3_of_key, values) in &keys {
                scan.keep();
                *sk = SM2EncryptionPrivateKey::from_bytes(d).unwrap();
                let parts: [&[u8]; 2] = if c1c2c3 { [c2, c3_of_key] } else { [c3_of_key, c2] };
                out[C1_LEN..].copy_from_slice(&parts.concat());
                out[..C1_LEN].copy_from_slice(&c1[..]);
                let written = scan.run(|| {
                    if c1c2c3 {
                        sk.decrypt_c1c2c3_out(&out, &mut buf)
                    } else {
                        sk.decrypt_out(&out, &mut buf)
                    }
                });
                assert_eq!((written, &buf), (Ok(len), &msg));
                scan.clean(&operation, values);
            }
            scan.same(&operation, &[], &[]);
        }

        // Decryption refused: C3 changed, where what was computed is the message all the same.
        let operation = format!("decrypt_detached_inplace, {len} bytes, C3 changed");
        for (d, _, _, c2, c3_of_key, values) in &keys {
            scan.keep();
            *sk = SM2EncryptionPrivateKey::from_bytes(d).unwrap();
            buf.copy_from_slice(c2);
            *c3 = *c3_of_key;
            c3[5] ^= 1;
            assert_eq!(scan.run(|| sk.decrypt_detached_inplace(&c1, &c3, &mut buf)), FAILED);
            scan.clean(&operation, values);
        }
        scan.same(&operation, &[], &[]);
        let operation = format!("decrypt_out, {len} bytes, C3 changed");
        for (d, _, _, c2, c3_of_key, values) in &keys {
            scan.keep();
            *sk = SM2EncryptionPrivateKey::from_bytes(d).unwrap();
            out[..C1_LEN].copy_from_slice(&c1[..]);
            out[C1_LEN..OVERHEAD_LEN].copy_from_slice(c3_of_key);
            out[OVERHEAD_LEN..].copy_from_slice(c2);
            out[C1_LEN + 5] ^= 1;
            assert_eq!(scan.run(|| sk.decrypt_out(&out, &mut buf)), FAILED_OUT);
            scan.clean(&operation, values);
        }
        scan.same(&operation, &[], &[]);

        // C2 changed: what was computed is another message, and the hash over it is no one's
        // C3.
        let operation = format!("decrypt_detached_inplace, {len} bytes, C2 changed");
        for (d, z, t, c2, c3_of_key, values) in &keys {
            scan.keep();
            *sk = SM2EncryptionPrivateKey::from_bytes(d).unwrap();
            buf.copy_from_slice(c2);
            buf[len - 1] ^= 1;
            *c3 = *c3_of_key;
            let other: Vec<u8> = buf.iter().zip(t).map(|(c, t)| c ^ t).collect();
            let mut values = values.clone();
            push_bytes(&mut values, "the message computed", &other);
            push_bytes(&mut values, "the hash computed", &sm3(&[&z[..32], &other, &z[32..]]));
            assert_eq!(scan.run(|| sk.decrypt_detached_inplace(&c1, &c3, &mut buf)), FAILED);
            scan.clean(&operation, &values);
        }
        scan.same(&operation, &[], &[]);
    }

    // Encryption that draws twice: the first k gives a one-byte message a key stream of 00.
    let msg = [0x4du8];
    let refused = attempt(&WIDE_ZERO_T, &pb, &msg, " (first draw)");
    assert!(refused.c2.is_none(), "the first draw's key stream is not 00");
    let made = attempt(&WIDE_2, &pb, &msg, "");
    let mut values = refused.values.clone();
    values.extend(made.values.clone());
    *rng = FixedSeedRNG::new([WIDE_ZERO_T, WIDE_2].concat().try_into().unwrap());
    let mut buf = Box::new(msg);
    let (c1, c3) = scan.run(|| pk.encrypt_detached_inplace(&mut *rng, &mut *buf)).unwrap();
    assert_eq!((c1, c3, &buf[..]), (made.c1, made.c3, &made.c2.unwrap()[..]), "no second draw");
    scan.clean("encrypt_detached_inplace, 1 byte, two draws", &values);

    // A ciphertext whose key stream is all zero (step B4), which is the first draw's.
    *sk = SM2EncryptionPrivateKey::from_bytes(&DB).unwrap();
    let (shared, ..) = shared_point_values(&Sm2Scalar::from_be_bytes(&DB), &refused.c1, 1, "");
    let mut values = key_values(&DB);
    values.extend(shared);
    *buf = msg;
    let (c1, c3) = (Box::new(refused.c1), Box::new(refused.c3));
    assert_eq!(scan.run(|| sk.decrypt_detached_inplace(&c1, &c3, &mut *buf)), FAILED);
    scan.clean("decrypt_detached_inplace, 1 byte, key stream all zero", &values);

    // A C1 that is not a point is refused before the private key is used.
    let mut not_a_point = c1.clone();
    not_a_point[64] ^= 1;
    assert_eq!(scan.run(|| sk.decrypt_detached_inplace(&not_a_point, &c3, &mut *buf)), FAILED);
    scan.clean("decrypt_detached_inplace, C1 not a point", &key_values(&DB));

    signing(&mut scan);

    std::process::exit(if scan.failures == 0 { 0 } else { 1 });
}

/// The signer's identity `IDA` that `ZA` binds in.
const IDA: &[u8] = b"ALICE123@YAHOO.COM";

/// A public key as what [`Scan::same`] lets differ: its encoding and the limbs of its
/// coordinates.
fn public_image(encoded: &[u8; 65]) -> Vec<u8> {
    [&encoded[..], &limb_image(&encoded[1..33]), &limb_image(&encoded[33..])].concat()
}

/// A signature as what [`Scan::same`] lets differ: its bytes and the limbs of `r` and `s`.
fn signature_image(sig: &[u8; SIG_LEN]) -> Vec<u8> {
    [&sig[..], &limb_image(&sig[..32]), &limb_image(&sig[32..])].concat()
}

fn scalar_field(be: &[u8]) -> Sm2ScalarField {
    Sm2ScalarField::from_limbs(sm2_sec1::limbs_from_be_bytes(be.try_into().unwrap()))
}

/// `dA` and the `(1 + dA)^-1 mod n` a signing key carries, as what is searched for.
fn signing_key_values(d: &[u8; 32]) -> Values {
    let mut values = Values::new();
    push_integer(&mut values, "dA", d);
    let inverse = Sm2ScalarField::ONE.add(&scalar_field(d)).invert();
    push_integer(&mut values, "(1 + dA)^-1", &sm2_sec1::be_bytes_from_limbs(&inverse.to_limbs()));
    values
}

/// What a signature under `d` drawn from `wide` is searched for: the key's values, the draw and
/// `k`. `sig` is checked to be the one that `k` gives: `s (1 + dA) + r dA = k` (GB/T
/// 32918.2-2016 Section 6.1 step A6).
fn signing_values(d: &[u8; 32], wide: &[u8; 40], sig: &[u8; SIG_LEN]) -> Values {
    let k = reduce_wide_bits_mod_n_minus_1(wide).to_be_bytes();
    let (r, s, d_field) = (scalar_field(&sig[..32]), scalar_field(&sig[32..]), scalar_field(d));
    let k_of_sig = s.mul(&Sm2ScalarField::ONE.add(&d_field)).add(&r.mul(&d_field));
    assert_eq!(sm2_sec1::be_bytes_from_limbs(&k_of_sig.to_limbs()), k, "not its k");
    let mut values = signing_key_values(d);
    push_integer(&mut values, "RNG output", wide);
    push_integer(&mut values, "k", &k);
    values
}

/// The signing key of `bouncycastle_ec::sm2::keys` and signing with it, as the encryption key
/// and encryption are run in `main`.
fn signing(scan: &mut Scan) {
    let mut rng = Box::new(FixedSeedRNG::new([0u8; 80]));
    let mut sk = Box::new(SM2PrivateKey::from_bytes(&DB).unwrap());
    let mut encoded = Box::new([0u8; 32]);

    let mut publics = Vec::new();
    for d in [&DB, &DB_2] {
        scan.keep();
        *encoded = *d;
        let loaded = scan.run(|| SM2PrivateKey::from_bytes(&encoded[..])).unwrap();
        assert_eq!(loaded.encode(), *d);
        scan.clean("signing from_bytes", &signing_key_values(d));
        publics.push(public_image(&loaded.derive_pk().encode()));
    }
    scan.same("signing from_bytes", &publics[0], &publics[1]);
    for d in [&DB, &DB_2] {
        scan.keep();
        *sk = SM2PrivateKey::from_bytes(d).unwrap();
        let bytes = scan.run(|| sk.encode());
        // Read after the run, so that no word of the key waits in a register that the run's
        // first frame saves.
        assert_eq!(bytes, *black_box(d));
        scan.clean("signing encode", &signing_key_values(d));
    }
    scan.same("signing encode", &[], &[]);
    for d in [&DB, &DB_2] {
        scan.keep();
        *sk = SM2PrivateKey::from_bytes(d).unwrap();
        assert_eq!(scan.run(|| sk.encode_out(&mut encoded)), 32);
        assert_eq!(*encoded, *d);
        scan.clean("signing encode_out", &signing_key_values(d));
    }
    scan.same("signing encode_out", &[], &[]);
    for d in [&DB, &DB_2] {
        scan.keep();
        *sk = SM2PrivateKey::from_bytes(d).unwrap();
        let copy = scan.run(|| (*sk).clone());
        assert_eq!(copy, *sk);
        scan.clean("signing clone", &signing_key_values(d));
    }
    scan.same("signing clone", &[], &[]);
    let mut publics = Vec::new();
    for d in [&DB, &DB_2] {
        scan.keep();
        *sk = SM2PrivateKey::from_bytes(d).unwrap();
        let derived: SM2PublicKey = scan.run(|| sk.derive_pk());
        scan.clean("signing derive_pk", &signing_key_values(d));
        publics.push(public_image(&derived.encode()));
    }
    scan.same("signing derive_pk", &publics[0], &publics[1]);
    let mut publics = Vec::new();
    for wide in [WIDE_1, WIDE_2] {
        scan.keep();
        *rng = FixedSeedRNG::new([wide, wide].concat().try_into().unwrap());
        let (generated_pk, generated_sk) = scan.run(|| keys::keygen(&mut *rng)).unwrap();
        let d = reduce_wide_bits_mod_n_minus_2(&wide).to_be_bytes();
        assert_eq!(generated_sk.encode(), d, "not its reduction");
        let mut values = signing_key_values(&d);
        push_integer(&mut values, "RNG output", &wide);
        scan.clean("signing keygen", &values);
        publics.push(public_image(&generated_pk.encode()));
    }
    scan.same("signing keygen", &publics[0], &publics[1]);

    // Signing, under one key, twice, from two draws of the RNG.
    *sk = SM2PrivateKey::from_bytes(&DB).unwrap();
    let pk = Box::new(sk.derive_pk());
    let msg = message(100);
    let mut sig = Box::new([0u8; SIG_LEN]);
    let check = |sig: &[u8; SIG_LEN], wide: &[u8; 40]| {
        pk.verify(&msg, Some(IDA), sig).unwrap();
        signing_values(&DB, wide, sig)
    };

    for wide in [WIDE_1, WIDE_2] {
        scan.keep();
        *rng = FixedSeedRNG::new([wide, wide].concat().try_into().unwrap());
        let signer = scan.run(|| sk.create_signer(&mut *rng, Some(IDA))).unwrap();
        let mut boxed: Box<dyn SignatureSigner<SIG_LEN> + '_> = Box::new(signer);
        boxed.do_update(&msg);
        boxed.do_final_out_boxed(&mut sig).unwrap();
        scan.clean("create_signer", &check(&sig, &wide));
    }
    scan.same("create_signer", &[], &[]);

    let mut images = Vec::new();
    for wide in [WIDE_1, WIDE_2] {
        scan.keep();
        *rng = FixedSeedRNG::new([wide, wide].concat().try_into().unwrap());
        assert_eq!(scan.run(|| sk.sign_out(&mut *rng, &msg, Some(IDA), &mut sig)), Ok(SIG_LEN));
        scan.clean("sign_out", &check(&sig, &wide));
        images.push(signature_image(&sig));
    }
    scan.same("sign_out", &images[0], &images[1]);

    let mut images = Vec::new();
    for wide in [WIDE_1, WIDE_2] {
        scan.keep();
        *rng = FixedSeedRNG::new([wide, wide].concat().try_into().unwrap());
        *sig = scan.run(|| sk.sign(&mut *rng, &msg, Some(IDA))).unwrap();
        scan.clean("sign", &check(&sig, &wide));
        images.push(signature_image(&sig));
    }
    scan.same("sign", &images[0], &images[1]);

    // The streaming final, on a signer that sits in a box: nothing is moved out of it.
    let mut images = Vec::new();
    for wide in [WIDE_1, WIDE_2] {
        *rng = FixedSeedRNG::new([wide, wide].concat().try_into().unwrap());
        let mut signer: Box<dyn SignatureSigner<SIG_LEN> + '_> =
            Box::new(sk.create_signer(&mut *rng, Some(IDA)).unwrap());
        signer.do_update(&msg);
        scan.keep();
        assert_eq!(scan.run(|| signer.do_final_out_boxed(&mut sig)), Ok(SIG_LEN));
        scan.clean("do_final_out_boxed", &check(&sig, &wide));
        images.push(signature_image(&sig));
    }
    scan.same("do_final_out_boxed", &images[0], &images[1]);
}
