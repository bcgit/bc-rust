//! What HMAC (bouncycastle_digest::hmac), HKDF (bouncycastle_digest::hkdf), PBKDF2
//! (bouncycastle_digest::pbkdf2), BLAKE3 in its three modes (bouncycastle_digest::blake3) and
//! AES-GCM-SIV (bouncycastle_symmetric::modes::gcm_siv) leave on the dead stack, for
//! `../check_symmetric_stack.sh`. For each operation the stack below the call is painted, the
//! operation run with its results going to the heap or to a live frame above, the dead stack
//! copied out, and the copy searched for the 8-byte words of every secret the operation handled:
//! the key and the message; for HMAC the padded key blocks, the two pad states and the inner
//! hash's state after each block and its digest; for HKDF and PBKDF2 the same over each HMAC they
//! run, with the IKM, the PRK, each `T(i)` and `U_j` and the output; for BLAKE3 every chaining
//! value of the tree, and the derived key; for GCM-SIV the per-nonce keys of RFC 8452 Section 4
//! and the AES blocks they are cut from, each POLYVAL accumulator, POLYVAL's key in the form its
//! multiplier holds it, and the key stream. The values are computed here, by hand from the
//! underlying hash or permutation (RFC 2104, RFC 5869, RFC 8018, RFC 8452 and the BLAKE3 tree,
//! written out below), and checked against the operation's own output before they are searched
//! for.
//!
//! Each operation is also run twice, at the same addresses, over different secrets, and the two
//! copies compared: but for what the operation hands out and an address of this program's that
//! a frame saved from a register, they must be the same. Every key, message, output and worker
//! an operation touches is in one place for both runs, so that the pointers it holds are the
//! same.
//!
//! Controls: nothing run must leave nothing, and the same stack twice; a copy of a key left in a
//! frame must be found, and copies of two keys must differ; and two values of a `u32` left over
//! an address, or of a byte left zero-extended, must differ.
//!
//! Reported and not failed, lines marked `left`: an HMAC worker finished by its by-value final
//! (`do_final`), which is moved into the final and may be copied into its caller's frame, by
//! decision, the in-place finals being what is checked; PBKDF2, which runs its HMACs with no frame
//! of its own to wipe; and an AES key's construction, whose key expansion and the moves of the
//! schedule it returns wipe nothing, as no block cipher key's construction does.
//!
//! With `STACK_DETAIL` set, each finding is also printed with how far below the call it lies,
//! which is what a wipe is sized from.
//!
//!   target/release/symmetric_stack_harness
//!
//! One line per operation, `ok`, `FAIL` or `left`; the exit status is 1 if anything failed.
use bouncycastle_core::hazmat::{BlockPermutation, FixedSeedRNG, KeyExpansion, finish_token};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::symmetric_key::{
    AeadInPlaceDecryptionKey, AeadInPlaceEncryptionKey, FromAnyKeyMaterial, FromKeyMaterial,
    MacGenerationKey, MacVerificationKey,
};
use bouncycastle_core::traits::{
    Hash, HashAlgParams, HashOneShot, KDF, MACGenerator, MACVerifier, Suspendable, XOF, XOFSqueezer,
};
use bouncycastle_digest::blake3::{BLAKE3, BLAKE3DeriveKey, BLAKE3KeyedHashKey, BLAKE3Squeezer};
use bouncycastle_digest::hkdf::{HKDF, HKDFParams, MAX_HMAC_OUTPUT_LEN};
use bouncycastle_digest::hmac::{HMACParams, HmacKey};
use bouncycastle_digest::pbkdf2::PBKDF2;
use bouncycastle_digest::ripemd::RIPEMD160;
use bouncycastle_digest::sha2::{SHA256, SHA512};
use bouncycastle_digest::sha3::SHA3_256;
use bouncycastle_digest::sm3::SM3;
use bouncycastle_symmetric::aes::hazmat::{AES128Internal, AES256Internal};
use bouncycastle_symmetric::aes::{AES128Key, AES256Key};
use bouncycastle_symmetric::modes::GCM_SIV;
use std::collections::{HashMap, HashSet};
use std::hint::black_box;
use std::num::NonZeroU32;

#[path = "../../stack_public_run.rs"]
mod public;

/// How far below the call the stack is painted and searched. The deepest operation here uses
/// under 16 KiB.
const DEPTH: usize = 256 * 1024;
/// The gap between the frame that takes the copy and the operation's first frame.
const PAD: usize = 16 * 1024;
const PAINT: u8 = 0xA5;
/// How far below the call a difference between two runs is put down to the registers the
/// call's first frames saved, and not counted. None is: on x86-64 (rustc 1.100, 1.97 and 1.88)
/// and arm64 (rustc 1.100 and 1.97), the only rows that differ within 256 bytes of the call,
/// beyond what the stale-address rule of [`Scan::differences`] excuses, are rows reported
/// (`left`) anyway, all on x86-64: an AES-GCM-SIV key's construction (key-schedule bytes from
/// 54 bytes down), HMAC-SHA3-256's by-value final (55 bytes down) and PBKDF2 (32 bytes from 184
/// down).
const SAVED_REGISTERS: usize = 0;

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

/// The leak the second control looks for: a copy of `value` in a frame, left as it is.
#[inline(never)]
fn leak(value: &[u8; 32]) {
    let mut local = *value;
    black_box(&mut local);
}

/// The leak the third and fourth controls look for: one word left in a frame, as [`leak`] leaves
/// a key, for a secret narrower than a word that the search, which looks for 8-byte words, cannot
/// name: a `u32` spilled over the low half of a slot holding an address, or a byte spilled
/// zero-extended.
#[inline(never)]
fn leak_word(word: u64) {
    let mut local = word;
    black_box(&mut local);
}

/// A named secret, as the bytes it would be in memory.
type Values = Vec<(String, Vec<u8>)>;

/// The painted stack's copy, the first run's copy of each operation and what it handed out, and
/// the count of what failed.
struct Scan {
    buf: Vec<u8>,
    first_runs: HashMap<String, (Vec<u8>, Vec<u8>)>,
    failures: usize,
    /// Whether what is found is reported without failing the check: for an operation whose
    /// residue is known and documented as left.
    report_only: bool,
}

impl Scan {
    fn new() -> Self {
        Self { buf: vec![0u8; DEPTH], first_runs: HashMap::new(), failures: 0, report_only: false }
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
        for i in lowest..DEPTH - PAD {
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
        if detail() {
            self.where_found(values);
        }
        if found.is_empty() {
            println!("ok   {operation}: none of its secrets in the {used} bytes of stack it used");
        } else {
            println!(
                "{} {operation}: left in the {used} bytes of stack it used: {}",
                self.fail_word(),
                found.join(", ")
            );
            self.fail();
        }
    }

    /// With `STACK_DETAIL` set: how far below the call each word of `values` that was found lies.
    fn where_found(&self, values: &Values) {
        for (name, image) in values {
            for word in image.chunks_exact(8).filter(|w| w.iter().any(|b| *b != w[0])) {
                for at in (0..DEPTH - PAD).filter(|at| self.buf[*at..at + 8] == *word) {
                    println!("       {name}: a word {} bytes below the call", DEPTH - PAD - at);
                }
            }
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

    /// How a finding is reported: `FAIL`, or `left` for an operation run with `report_only`.
    fn fail_word(&self) -> &'static str {
        if self.report_only { "left" } else { "FAIL" }
    }

    fn fail(&mut self) {
        if !self.report_only {
            self.failures += 1;
        }
    }

    /// The bytes in which the last run's stack is not `before`, leaving out those that are
    /// pieces of `public` in the one and the same pieces of `public_before` in the other
    /// ([`public::public_run`]), and how far below the call the furthest of them is.
    fn differences(&self, before: &[u8], public_before: &[u8], public: &[u8]) -> (usize, usize) {
        let lowest = |buf: &[u8]| buf.iter().position(|b| *b != PAINT).unwrap_or(DEPTH);
        let start = lowest(before).min(lowest(&self.buf));
        let (mut count, mut furthest) = (0, 0);
        let mut i = start;
        while i < DEPTH {
            if before[i] == self.buf[i] {
                i += 1;
                continue;
            }
            let mut end = i;
            while end < DEPTH && before[end] != self.buf[end] {
                end += 1;
            }
            let explained = public::public_run(before, &self.buf, i, end, public_before, public);
            // The first frames of a call save the registers they go on to use, and what those
            // held is this program's own: a loop's pointer, a length. Only the bytes of the run
            // within SAVED_REGISTERS of the call are put down to that.
            let deep_end = end.min((DEPTH - PAD).saturating_sub(SAVED_REGISTERS));
            // Below that, only an address this program left in a callee-saved register, which a
            // frame saved: both runs touch the same memory, so their pointers are the same, but
            // the compiler keeps this program's own values (the run's expected outputs, which
            // differ) in registers across the call, and a frame of rustc 1.88's saves one.
            let stale = !explained && deep_end > i && same_mapping(before, &self.buf, i, end);
            if stale && detail() {
                println!("       excused: an address at {} below the call", DEPTH - PAD - i);
            }
            let explained = explained || stale;
            if !explained && deep_end > i {
                if detail() {
                    let (from, to) = (i & !7, (deep_end + 7).min(DEPTH) & !7);
                    println!(
                        "       differ: {} bytes from {} below the call: {:02x?} / {:02x?}",
                        deep_end - i,
                        DEPTH - PAD - i,
                        &before[from..to.max(from + 8)],
                        &self.buf[from..to.max(from + 8)]
                    );
                }
                count += deep_end - i;
                furthest = furthest.max((DEPTH - i).saturating_sub(PAD));
            }
            i = end;
        }
        (count, furthest)
    }

    /// After run `run` (0 or 1) of an operation run twice, at the same addresses, over
    /// different secrets: the first run's stack is kept, and the second's must be the same,
    /// but for what each handed out, `public`. A known value is not needed for this, so it
    /// reaches the intermediates that [`Self::clean`] has no name for.
    fn pair(&mut self, run: usize, operation: &str, public: &[u8]) {
        if run == 0 {
            self.first_runs.insert(operation.to_string(), (self.buf.clone(), public.to_vec()));
            return;
        }
        let (before, public_before) = self.first_runs.remove(operation).expect("a first run");
        assert_eq!(public_before.len(), public.len());
        match self.differences(&before, &public_before, public) {
            (0, _) => println!("ok   {operation}: the same stack over different secrets"),
            (count, furthest) => {
                println!(
                    "{} {operation}: {count} bytes of stack differ with the secrets, the \
                     furthest {furthest} bytes below the call",
                    self.fail_word()
                );
                self.fail();
            }
        }
    }

    /// After run `run` of the leak control: the two copies must differ.
    fn pair_differs(&mut self, run: usize, operation: &str) {
        if run == 0 {
            self.first_runs.insert(operation.to_string(), (self.buf.clone(), Vec::new()));
            return;
        }
        let (before, _) = self.first_runs.remove(operation).expect("a first run");
        if self.differences(&before, &[], &[]).0 > 0 {
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

/// Whether the bytes `i..end` in which `before` and `after` differ lie within one aligned 8-byte
/// word that is, in both, an address inside one and the same mapping of this process
/// (`/proc/self/maps`): a pointer this program left in a register. A secret that only shares a
/// word with an address (a `u32` over its low half) leaves it there with a probability of the
/// mapping's size over 2^32, about 2^-12 for this program's heap, and a byte or small integer
/// never.
fn same_mapping(before: &[u8], after: &[u8], i: usize, end: usize) -> bool {
    let word = i & !7;
    if end > word + 8 {
        return false;
    }
    let read = |bytes: &[u8]| u64::from_le_bytes(bytes.try_into().unwrap());
    let (a, b) = (read(&before[word..word + 8]), read(&after[word..word + 8]));
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap_or_default();
    maps.lines().any(|line| {
        let range = line.split(' ').next().unwrap_or("");
        let Some((start, end)) = range.split_once('-') else { return false };
        let (Ok(start), Ok(end)) = (u64::from_str_radix(start, 16), u64::from_str_radix(end, 16))
        else {
            return false;
        };
        (start..end).contains(&a) && (start..end).contains(&b)
    })
}

/// Whether `STACK_DETAIL` is set: then where each finding lies is printed too, for sizing a wipe.
fn detail() -> bool {
    std::env::var_os("STACK_DETAIL").is_some()
}

/// `len` bytes of SHA-512 in counter mode over `label`: the harness's own source of distinct,
/// fixed secrets.
fn bytes_of(label: &str, len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for counter in 0u32.. {
        if out.len() >= len {
            break;
        }
        let mut hash = SHA512::default();
        hash.do_update(label.as_bytes());
        hash.do_update(&counter.to_be_bytes());
        let mut block = [0u8; 64];
        hash.do_final_out(&mut block);
        out.extend_from_slice(&block);
    }
    out.truncate(len);
    out
}

/// `values` without the 8-byte words that `public` holds, at any offset.
fn without(values: &Values, public: &[u8]) -> Values {
    let held: HashSet<&[u8]> = public.windows(8).collect();
    values
        .iter()
        .map(|(name, image)| {
            let kept: Vec<u8> =
                image.chunks(8).filter(|w| !held.contains(w)).flatten().copied().collect();
            (name.clone(), kept)
        })
        .collect()
}

/// One value, named.
fn named(name: &str, bytes: &[u8]) -> (String, Vec<u8>) {
    (name.to_string(), bytes.to_vec())
}

fn main() {
    let mut scan = Scan::new();
    let mut key = Box::new([0u8; 32]);

    // The controls.
    for i in 0..2 {
        scan.run(|| {});
        scan.clean("control, nothing run", &vec![named("key", &bytes_of("control 0", 32))]);
        scan.pair(i, "control, nothing run twice", &[]);
    }
    for i in 0..2 {
        let k = bytes_of(&format!("control {i}"), 32);
        key.copy_from_slice(&k);
        scan.run(|| leak(&key));
        scan.leaked("control, a copy of a key left in a frame", &vec![named("key", &k)]);
        scan.pair_differs(i, "control, copies of two keys left in a frame");
    }
    // A u32 over the low half of an address that a register held, and a byte zero-extended:
    // the comparison must catch both, the address being of a live heap block, as a pointer this
    // program left in a register would be.
    let address = &*key as *const [u8; 32] as u64;
    for (what, words) in [
        ("a u32 over an address", [0xdead_beef, 0x0bad_f00d].map(|s| address & !0xffff_ffff | s)),
        ("a byte zero-extended", [0x5a, 0xc3]),
    ] {
        let operation = format!("control, two values of {what} left in a frame");
        for (i, word) in words.into_iter().enumerate() {
            scan.run(|| leak_word(word));
            scan.pair_differs(i, &operation);
        }
    }

    hmac::<SHA256, 32>(&mut scan, "SHA-256");
    hmac::<SHA512, 64>(&mut scan, "SHA-512");
    hmac::<SHA3_256, 32>(&mut scan, "SHA3-256");
    hmac::<SM3, 32>(&mut scan, "SM3");
    hmac::<RIPEMD160, 20>(&mut scan, "RIPEMD-160");

    hkdf::<SHA256>(&mut scan, "SHA-256");
    hkdf::<SHA512>(&mut scan, "SHA-512");
    hkdf::<SHA3_256>(&mut scan, "SHA3-256");

    // PBKDF2 runs its HMACs with no frame of its own to wipe: reported.
    scan.report_only = true;
    pbkdf2(&mut scan);
    scan.report_only = false;

    blake3(&mut scan, 100, "one chunk");
    blake3(&mut scan, 3 * B3_CHUNK_LEN + 100, "four chunks");

    assert!(dot_matches_rfc_8452(), "not RFC 8452's dot, POLYVAL or GHASH key");
    gcm_siv::<AES128Key<GCM_SIV>, AES128Internal, 16>(&mut scan, "AES-128");
    gcm_siv::<AES256Key<GCM_SIV>, AES256Internal, 32>(&mut scan, "AES-256");

    std::process::exit(if scan.failures == 0 { 0 } else { 1 });
}

/* ---------------------------------------------------------------------------------------------
 * HMAC (RFC 2104), by hand over the hash
 * ------------------------------------------------------------------------------------------- */

/// A hash HMAC runs over, with its chaining value read out of its suspended state: the bytes
/// that are the state proper, its words little-endian, as they lie in memory.
trait Chaining: HMACParams {
    fn chaining(self) -> Vec<u8>;
}

impl Chaining for SHA256 {
    fn chaining(self) -> Vec<u8> {
        self.suspend()[3..3 + 32].to_vec()
    }
}

impl Chaining for SHA512 {
    fn chaining(self) -> Vec<u8> {
        self.suspend()[3..3 + 64].to_vec()
    }
}

impl Chaining for SHA3_256 {
    /// The 25 lanes, after the version and the variant tag.
    fn chaining(self) -> Vec<u8> {
        self.suspend()[4..4 + 200].to_vec()
    }
}

impl Chaining for SM3 {
    fn chaining(self) -> Vec<u8> {
        self.suspend()[3..3 + 32].to_vec()
    }
}

impl Chaining for RIPEMD160 {
    fn chaining(self) -> Vec<u8> {
        self.suspend()[3..3 + 20].to_vec()
    }
}

/// `H(parts[0] || parts[1] || ...)`.
fn hash_of<H: HashOneShot + HashAlgParams>(parts: &[&[u8]]) -> Vec<u8> {
    let mut hash = H::default();
    for part in parts {
        hash.do_update(part);
    }
    let mut out = vec![0u8; H::OUTPUT_LEN];
    hash.do_final_out(&mut out);
    out
}

/// The chaining value of `H` once `data` and every whole block of it has been compressed: one
/// byte more is absorbed, so that a hash that holds a full block back until it knows whether
/// more is coming compresses it.
fn state_after<H: Chaining>(data: &[&[u8]]) -> Vec<u8> {
    let mut hash = H::default();
    for part in data {
        hash.do_update(part);
    }
    hash.do_update(&[0]);
    hash.chaining()
}

/// An HMAC computed by hand (RFC 2104 Section 2) from the hash, with what it handled: what
/// depends on the key alone, and what depends on the message as well.
struct HmacTrace {
    tag: Vec<u8>,
    key_parts: Values,
    message_parts: Values,
}

fn hmac_trace<H: Chaining>(name: &str, key: &[u8], msg: &[u8]) -> HmacTrace {
    // Section 2: ipad is 0x36 and opad 0x5C, each repeated B times.
    let b = H::BLOCK_LEN;
    let mut key_parts = vec![named(name, key)];
    // Section 3: "keys longer than B bytes are first hashed using H".
    let k0 = if key.len() > b {
        let hashed = hash_of::<H>(&[key]);
        key_parts.push(named(&format!("H({name})"), &hashed));
        hashed
    } else {
        key.to_vec()
    };
    // Steps (1), (2) and (5).
    let (mut ipad, mut opad) = (vec![0x36u8; b], vec![0x5cu8; b]);
    for (i, k) in k0.iter().enumerate() {
        ipad[i] ^= k;
        opad[i] ^= k;
    }
    key_parts.push(named(&format!("{name} xor ipad"), &ipad));
    key_parts.push(named(&format!("{name} xor opad"), &opad));
    key_parts.push(named(&format!("{name}'s inner pad state"), &state_after::<H>(&[&ipad])));
    key_parts.push(named(&format!("{name}'s outer pad state"), &state_after::<H>(&[&opad])));

    // Steps (3) and (4): the inner hash's state after each block of the text, and its digest.
    let mut message_parts = Vec::new();
    for p in (b..msg.len()).step_by(b) {
        let state = state_after::<H>(&[&ipad, &msg[..p]]);
        message_parts.push(named(&format!("{name}'s inner state at byte {p}"), &state));
    }
    let inner = hash_of::<H>(&[&ipad, msg]);
    message_parts.push(named(&format!("{name}'s inner digest"), &inner));
    // Steps (6) and (7).
    let tag = hash_of::<H>(&[&opad, &inner]);
    HmacTrace { tag, key_parts, message_parts }
}

/// A MAC key, as the HMAC and HKDF constructors take it.
fn mac_key(bytes: &[u8]) -> KeyMaterial<256> {
    KeyMaterial::<256>::from_bytes_as_type(bytes, KeyType::MACKey).unwrap()
}

/// HMAC over `H`: the key's construction, from a key of a block or less and from one longer than
/// a block, the one-shots, and the streaming generator and verifier, each update and each
/// in-place final measured on its own; and the by-value final, reported.
fn hmac<H, const N: usize>(scan: &mut Scan, name: &str)
where
    H: Chaining + HMACParams<MACKey = KeyMaterial<N>>,
{
    let op = |what: &str| format!("HMAC-{name} {what}");
    // Long enough to fill several blocks, and not a whole number of them.
    let msgs = [0, 1].map(|i| bytes_of(&format!("HMAC-{name} message {i}"), 300));
    let mut msg: Box<[u8]> = msgs[0].clone().into_boxed_slice();
    let mut material = Box::new(mac_key(&msgs[0][..64]));

    for (what, len) in [("from_key_material", 64), ("from_key_material, a long key", 200)] {
        for i in 0..2 {
            let k = bytes_of(&format!("HMAC-{name} key {len} {i}"), len);
            *material = mac_key(&k);
            let key = scan.run(|| HmacKey::<H>::from_key_material(&*material)).unwrap();
            let trace = hmac_trace::<H>("key", &k, &msgs[i]);
            assert_eq!(key.mac(&msgs[i])[..], trace.tag[..], "not RFC 2104's tag");
            scan.clean(&op(what), &trace.key_parts);
            scan.pair(i, &op(what), &[]);
        }
    }

    let mut key = Box::new(HmacKey::<H>::from_key_material(&*material).unwrap());
    let mut tag = Box::new([0u8; N]);
    for i in 0..2 {
        let raw = bytes_of(&format!("HMAC-{name} key 64 {i}"), 64);
        let trace = hmac_trace::<H>("key", &raw, &msgs[i]);
        let mut values = trace.key_parts.clone();
        values.extend(trace.message_parts.iter().cloned());
        values.push(named("message", &msgs[i]));
        *key = HmacKey::<H>::from_key_material(&mac_key(&raw)).unwrap();
        msg.copy_from_slice(&msgs[i]);

        assert_eq!(scan.run(|| key.mac_out(&msg, &mut tag)), N);
        assert_eq!(tag[..], trace.tag[..], "not RFC 2104's tag");
        scan.clean(&op("mac_out"), &values);
        scan.pair(i, &op("mac_out"), &tag[..]);

        *tag = scan.run(|| key.mac(&msg));
        assert_eq!(tag[..], trace.tag[..], "not RFC 2104's tag");
        scan.clean(&op("mac"), &values);
        scan.pair(i, &op("mac"), &tag[..]);

        scan.run(|| key.verify(&msg, &tag)).unwrap();
        scan.clean(&op("verify"), &values);
        scan.pair(i, &op("verify"), &[]);

        // The streaming generator and verifier, held as `dyn` where they sit so that nothing is
        // moved: the update (which takes the key's inner pad state), then the in-place final
        // that the boxed finals run. They sit in this frame, at the same address both runs.
        let mut generator = key.create_generator();
        let generator: &mut dyn MACGenerator<N> = &mut generator;
        scan.run(|| generator.do_update(&msg));
        scan.clean(&op("generator do_update"), &values);
        scan.pair(i, &op("generator do_update"), &[]);
        assert_eq!(scan.run(|| generator.finish_mac_into(&finish_token(), &mut tag)), N);
        assert_eq!(tag[..], trace.tag[..], "not RFC 2104's tag");
        scan.clean(&op("generator final in place"), &values);
        scan.pair(i, &op("generator final in place"), &tag[..]);

        let mut verifier = key.create_verifier();
        let verifier: &mut dyn MACVerifier<N> = &mut verifier;
        scan.run(|| verifier.do_update(&msg));
        scan.clean(&op("verifier do_update"), &values);
        scan.pair(i, &op("verifier do_update"), &[]);
        scan.run(|| verifier.finish_mac_verify(&finish_token(), &tag)).unwrap();
        scan.clean(&op("verifier final in place"), &values);
        scan.pair(i, &op("verifier final in place"), &[]);

        // A worker moved into its by-value final leaves its state where it was moved from, by
        // decision: reported.
        let report_only = std::mem::replace(&mut scan.report_only, true);
        let mut generator = key.create_generator();
        generator.do_update(&msg);
        *tag = scan.run(move || generator.do_final());
        assert_eq!(tag[..], trace.tag[..], "not RFC 2104's tag");
        scan.clean(&op("generator do_final (by value)"), &values);
        scan.pair(i, &op("generator do_final (by value)"), &tag[..]);
        scan.report_only = report_only;
    }
}

/* ---------------------------------------------------------------------------------------------
 * HKDF (RFC 5869) and PBKDF2 (RFC 8018), by hand over the HMAC above
 * ------------------------------------------------------------------------------------------- */

/// HKDF-Extract and HKDF-Expand (RFC 5869 Sections 2.2 and 2.3) by hand, with what they handled.
/// The salt is public and is not among them.
struct HkdfTrace {
    prk: Vec<u8>,
    okm: Vec<u8>,
    /// What extract handled: the IKM, the inner states and digest of the HMAC over it, the PRK.
    extract: Values,
    /// What expand handled: the PRK, its pads, each block's inner digest, each `T(i)`, the OKM.
    expand: Values,
}

fn hkdf_trace<H: Chaining>(salt: &[u8], ikm: &[u8], info: &[u8], len: usize) -> HkdfTrace {
    // Section 2.2: PRK = HMAC-Hash(salt, IKM). The salt here is given; absent, it would be
    // "a string of HashLen zeros".
    let extract_hmac = hmac_trace::<H>("salt", salt, ikm);
    let prk = extract_hmac.tag;
    let mut extract = vec![named("IKM", ikm)];
    extract.extend(extract_hmac.message_parts.iter().cloned());
    extract.push(named("PRK", &prk));

    let mut expand = Vec::new();
    let mut t: Vec<u8> = Vec::new();
    let mut okm = Vec::new();
    for i in 1..=len.div_ceil(H::OUTPUT_LEN) as u8 {
        // Section 2.3: T(0) = empty string, T(i) = HMAC-Hash(PRK, T(i-1) | info | i)
        let block = hmac_trace::<H>("PRK", &prk, &[&t[..], info, &[i]].concat());
        if i == 1 {
            expand.extend(block.key_parts.iter().cloned());
        }
        expand.extend(block.message_parts.iter().cloned());
        t = block.tag;
        expand.push(named(&format!("T({i})"), &t));
        okm.extend_from_slice(&t);
    }
    // OKM = first L octets of T
    okm.truncate(len);
    expand.push(named("OKM", &okm));
    HkdfTrace { prk, okm, extract, expand }
}

/// HKDF over `H`: extract, expand, the two together, and a derivation through the `KDF` trait,
/// each over two IKMs.
fn hkdf<H: Chaining + HKDFParams>(scan: &mut Scan, name: &str) {
    let op = |what: &str| format!("HKDF-{name} {what}");
    let salt_bytes = bytes_of(&format!("HKDF-{name} salt"), 32);
    let salt = Box::new(mac_key(&salt_bytes));
    let kdf = Box::new(HKDF::<H>::new_with_salt(&*salt).unwrap());
    let info = b"symmetric stack harness";
    // Two and a half blocks of output, so that the last is cut short.
    let len = 2 * H::OUTPUT_LEN + H::OUTPUT_LEN / 2;
    let mut ikm = Box::new(KeyMaterial::<256>::new());
    let mut prk_in = Box::new(KeyMaterial::<MAX_HMAC_OUTPUT_LEN>::new());
    let mut prk = Box::new(KeyMaterial::<MAX_HMAC_OUTPUT_LEN>::new());
    let mut okm = Box::new(KeyMaterial::<256>::new());

    for i in 0..2 {
        // Longer than a block, so that the extract compresses some of it.
        let ikm_bytes = bytes_of(&format!("HKDF-{name} IKM {i}"), 200);
        let trace = hkdf_trace::<H>(&salt_bytes, &ikm_bytes, info, len);
        let both = [trace.extract.clone(), trace.expand.clone()].concat();
        *ikm = mac_key(&ikm_bytes);
        *prk_in = KeyMaterial::from_bytes_as_type(&trace.prk, KeyType::MACKey).unwrap();

        assert_eq!(scan.run(|| HKDF::<H>::extract_out(&*salt, &*ikm, &mut prk)), Ok(H::OUTPUT_LEN));
        assert_eq!(prk.ref_to_bytes(), &trace.prk[..], "not RFC 5869's PRK");
        scan.clean(&op("extract_out"), &trace.extract);
        scan.pair(i, &op("extract_out"), &trace.prk);

        assert_eq!(scan.run(|| HKDF::<H>::expand_out(&*prk_in, info, len, &mut *okm)), Ok(len));
        assert_eq!(okm.ref_to_bytes(), &trace.okm[..], "not RFC 5869's OKM");
        scan.clean(&op("expand_out"), &trace.expand);
        scan.pair(i, &op("expand_out"), &trace.okm);

        assert_eq!(
            scan.run(|| HKDF::<H>::extract_and_expand_out(&*salt, &*ikm, info, len, &mut *okm)),
            Ok(len)
        );
        assert_eq!(okm.ref_to_bytes(), &trace.okm[..], "not RFC 5869's OKM");
        scan.clean(&op("extract_and_expand_out"), &both);
        scan.pair(i, &op("extract_and_expand_out"), &trace.okm);

        assert_eq!(scan.run(|| kdf.derive_key_out(&*ikm, info, len, &mut *okm)), Ok(len));
        assert_eq!(okm.ref_to_bytes(), &trace.okm[..], "not RFC 5869's OKM");
        scan.clean(&op("KDF derive_key_out"), &both);
        scan.pair(i, &op("KDF derive_key_out"), &trace.okm);
    }
}

/// PBKDF2 with HMAC-SHA-256 (RFC 8018 Section 5.2), three iterations, two blocks of output, the
/// second cut short: searched for the password, its pads, each `U_j` and the inner states of the
/// HMAC that made it, each `T_i` and the derived key.
fn pbkdf2(scan: &mut Scan) {
    const ITERATIONS: u32 = 3;
    let len = 48;
    let salt = b"symmetric stack harness salt";
    let mut password_key = Box::new(KeyMaterial::<64>::new());
    let mut dk = Box::new(KeyMaterial::<64>::new());
    for i in 0..2 {
        let password = bytes_of(&format!("PBKDF2 password {i}"), 32);
        // Section 5.2: DK = T_1 || T_2<0..r-1>, T_i = F(P, S, c, i) = U_1 ^ U_2 ^ U_3,
        // U_1 = PRF(P, S || INT(i)), INT(i) four octets most significant first, and
        // U_j = PRF(P, U_{j-1}).
        let mut values = Values::new();
        let mut expected = Vec::new();
        for block in 1u32..=2 {
            let mut u = [&salt[..], &block.to_be_bytes()].concat();
            let mut t = vec![0u8; 32];
            for j in 1..=ITERATIONS {
                let prf = hmac_trace::<SHA256>("password", &password, &u);
                if block == 1 && j == 1 {
                    values.extend(prf.key_parts.iter().cloned());
                }
                values.extend(prf.message_parts.iter().cloned());
                u = prf.tag;
                values.push(named(&format!("U_{j} of T_{block}"), &u));
                t.iter_mut().zip(&u).for_each(|(t, u)| *t ^= u);
            }
            values.push(named(&format!("T_{block}"), &t));
            expected.extend_from_slice(&t);
        }
        expected.truncate(len);
        values.push(named("DK", &expected));
        *password_key = KeyMaterial::from_bytes_as_type(&password, KeyType::Unknown).unwrap();

        let iterations = NonZeroU32::new(ITERATIONS).unwrap();
        assert_eq!(
            scan.run(|| PBKDF2::<SHA256>::derive_out(
                &*password_key, salt, iterations, len, &mut *dk
            )),
            Ok(len)
        );
        assert_eq!(dk.ref_to_bytes(), &expected[..], "not RFC 8018's DK");
        scan.clean("PBKDF2-HMAC-SHA-256 derive_out", &values);
        scan.pair(i, "PBKDF2-HMAC-SHA-256 derive_out", &expected);
    }
}

/* ---------------------------------------------------------------------------------------------
 * BLAKE3, by hand (the BLAKE3 specification, BLAKE3-team/BLAKE3-specs blake3.pdf, s. 2.1-2.6)
 * ------------------------------------------------------------------------------------------- */

/// IV0 ... IV7, s. 2.2 Table 1 (BLAKE2s's).
const B3_IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];
/// The message permutation applied after each round but the last, s. 2.2 Table 2.
const B3_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
// The flags of s. 2.2 Table 3: 2^0 ... 2^6.
const CHUNK_START: u32 = 1;
const CHUNK_END: u32 = 2;
const PARENT: u32 = 4;
const ROOT: u32 = 8;
const KEYED_HASH: u32 = 16;
const DERIVE_KEY_CONTEXT: u32 = 32;
const DERIVE_KEY_MATERIAL: u32 = 64;
/// s. 2.1: "contiguous chunks of 1024 bytes".
const B3_CHUNK_LEN: usize = 1024;

/// The quarter-round `G_i(a, b, c, d)` (s. 2.2), `x` and `y` being `m_{2i}` and `m_{2i+1}`:
/// rotations by 16, 12, 8 and 7.
fn b3_g(s: &mut [u32; 16], [a, b, c, d]: [usize; 4], x: u32, y: u32) {
    s[a] = s[a].wrapping_add(s[b]).wrapping_add(x);
    s[d] = (s[d] ^ s[a]).rotate_right(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_right(12);
    s[a] = s[a].wrapping_add(s[b]).wrapping_add(y);
    s[d] = (s[d] ^ s[a]).rotate_right(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_right(7);
}

/// The compression function (s. 2.2), all 16 output words: the state `h0..h7, IV0..IV3, t0, t1,
/// b, d`, seven rounds of the column then diagonal `G`s with the message permuted between them,
/// and `h'_i = v'_i ^ v'_{i+8}`, `h'_{i+8} = v'_{i+8} ^ h_i`.
fn b3_compress(cv: &[u32; 8], block: &[u32; 16], counter: u64, len: u32, flags: u32) -> [u32; 16] {
    let mut s = [0u32; 16];
    s[..8].copy_from_slice(cv);
    s[8..12].copy_from_slice(&B3_IV[..4]);
    s[12..].copy_from_slice(&[counter as u32, (counter >> 32) as u32, len, flags]);
    let mut m = *block;
    for round in 0..7 {
        b3_g(&mut s, [0, 4, 8, 12], m[0], m[1]);
        b3_g(&mut s, [1, 5, 9, 13], m[2], m[3]);
        b3_g(&mut s, [2, 6, 10, 14], m[4], m[5]);
        b3_g(&mut s, [3, 7, 11, 15], m[6], m[7]);
        b3_g(&mut s, [0, 5, 10, 15], m[8], m[9]);
        b3_g(&mut s, [1, 6, 11, 12], m[10], m[11]);
        b3_g(&mut s, [2, 7, 8, 13], m[12], m[13]);
        b3_g(&mut s, [3, 4, 9, 14], m[14], m[15]);
        if round < 6 {
            m = B3_PERMUTATION.map(|i| m[i]);
        }
    }
    for i in 0..8 {
        s[i] ^= s[i + 8];
        s[i + 8] ^= cv[i];
    }
    s
}

/// Little-endian words of `bytes`, zero-padded, as s. 2.4 parses and pads a block and s. 2.3 a
/// keyed_hash key.
fn b3_words<const N: usize>(bytes: &[u8]) -> [u32; N] {
    let mut padded = vec![0u8; 4 * N];
    padded[..bytes.len()].copy_from_slice(bytes);
    std::array::from_fn(|i| u32::from_le_bytes(padded[4 * i..4 * i + 4].try_into().unwrap()))
}

fn b3_bytes(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}

/// A node's last compression, held back until it is known whether it is the root.
struct B3Output {
    cv: [u32; 8],
    block: [u32; 16],
    counter: u64,
    len: u32,
    flags: u32,
}

impl B3Output {
    fn chaining_value(&self) -> [u32; 8] {
        let out = b3_compress(&self.cv, &self.block, self.counter, self.len, self.flags);
        out[..8].try_into().unwrap()
    }

    /// The first `len` bytes of the root output (s. 2.6): the root compression with `ROOT` set,
    /// repeated with `t` = 0, 1, ..., each full 16-word output in little-endian order.
    fn root_bytes(&self, len: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for t in 0u64.. {
            if out.len() >= len {
                break;
            }
            let block = b3_compress(&self.cv, &self.block, t, self.len, self.flags | ROOT);
            out.extend(b3_bytes(&block));
        }
        out.truncate(len);
        out
    }
}

/// The tree over `input`, every chaining value below the root pushed to `cvs`. s. 2.4: a chunk's
/// blocks are chained from the key words, with the chunk index as `t`, `CHUNK_START` on the
/// first and `CHUNK_END` on the last; an empty input is one empty block. s. 2.5: a parent
/// compresses its children's chaining values from the key words, with `t = 0` and `b = 64`.
fn b3_node(
    input: &[u8],
    first_chunk: u64,
    key: &[u32; 8],
    flags: u32,
    cvs: &mut Vec<[u32; 8]>,
) -> B3Output {
    if input.len() <= B3_CHUNK_LEN {
        let blocks: Vec<&[u8]> =
            if input.is_empty() { vec![&[]] } else { input.chunks(64).collect() };
        let mut cv = *key;
        for (j, block) in blocks.iter().enumerate() {
            let block_flags = flags | if j == 0 { CHUNK_START } else { 0 };
            if j == blocks.len() - 1 {
                return B3Output {
                    cv,
                    block: b3_words(block),
                    counter: first_chunk,
                    len: block.len() as u32,
                    flags: block_flags | CHUNK_END,
                };
            }
            let out = b3_compress(&cv, &b3_words(block), first_chunk, 64, block_flags);
            cv = out[..8].try_into().unwrap();
            cvs.push(cv);
        }
        unreachable!("a chunk has a last block");
    }
    // s. 2.1: the left subtree is the first 2^(10 + floor(log2(floor((n - 1) / 1024)))) bytes,
    // the largest power of two of chunks that leaves the right some.
    let chunks = input.len().div_ceil(B3_CHUNK_LEN);
    let left_chunks = 1usize << (usize::BITS - 1 - (chunks - 1).leading_zeros());
    let split = left_chunks * B3_CHUNK_LEN;
    let left = b3_node(&input[..split], first_chunk, key, flags, cvs).chaining_value();
    cvs.push(left);
    let right_first = first_chunk + left_chunks as u64;
    let right = b3_node(&input[split..], right_first, key, flags, cvs).chaining_value();
    cvs.push(right);
    let mut block = [0u32; 16];
    block[..8].copy_from_slice(&left);
    block[8..].copy_from_slice(&right);
    B3Output { cv: *key, block, counter: 0, len: 64, flags: flags | PARENT }
}

/// BLAKE3 of `input` under `key` and `flags`: the root, and the chaining values as values.
fn b3_trace(input: &[u8], key: &[u32; 8], flags: u32) -> (B3Output, Values) {
    let mut cvs = Vec::new();
    let root = b3_node(input, 0, key, flags, &mut cvs);
    let mut values: Values = cvs
        .iter()
        .enumerate()
        .map(|(i, cv)| named(&format!("chaining value {i}"), &b3_bytes(cv)))
        .collect();
    // A parent root's inputs are the key words and its children's chaining values, both there
    // already; a chunk root's are a chaining value and the message's last block.
    if root.flags & PARENT == 0 {
        values.push(named("root's input chaining value", &b3_bytes(&root.cv)));
        values.push(named("root's block", &b3_bytes(&root.block)));
    }
    (root, values)
}

/// BLAKE3 in its three modes over a message of `len` bytes: the one-shots, streaming in 64-byte
/// updates and in one, the XOF and its squeezer, suspended and resumed, the keyed hash's key and
/// its MAC roles, and derive_key.
fn blake3(scan: &mut Scan, len: usize, size: &str) {
    let op = |what: &str| format!("BLAKE3 {what}, {size}");
    let msgs = [0, 1].map(|i| bytes_of(&format!("BLAKE3 message {len} {i}"), len));
    let mut msg: Box<[u8]> = msgs[0].clone().into_boxed_slice();
    let mut out = Box::new([0u8; 200]);
    let mut tag = Box::new([0u8; 32]);
    let mut material =
        Box::new(KeyMaterial::<32>::from_bytes_as_type(&[1; 32], KeyType::MACKey).unwrap());
    // One key, made over for each run, so that both runs' workers borrow it at one address.
    let mut key = Box::new(BLAKE3KeyedHashKey::from_key_material(&*material).unwrap());
    let context = b"bc-rust symmetric stack harness 2026-11-27 derive_key";
    let (context_root, _) = b3_trace(context, &B3_IV, DERIVE_KEY_CONTEXT);
    let context_key: [u32; 8] = b3_words(&context_root.root_bytes(32));

    for i in 0..2 {
        msg.copy_from_slice(&msgs[i]);
        let (root, mut values) = b3_trace(&msgs[i], &B3_IV, 0);
        values.push(named("message", &msgs[i]));

        // The hash mode's output is public.
        assert_eq!(scan.run(|| BLAKE3::hash_out(&msg, &mut out[..32])), 32);
        assert_eq!(out[..32], root.root_bytes(32)[..], "not BLAKE3's hash");
        scan.clean(&op("hash_out"), &values);
        scan.pair(i, &op("hash_out"), &out[..32]);

        assert_eq!(scan.run(|| BLAKE3::new().xof_out(&msg, &mut out[..])), 200);
        assert_eq!(out[..], root.root_bytes(200)[..], "not BLAKE3's output");
        scan.clean(&op("xof_out"), &values);
        scan.pair(i, &op("xof_out"), &out[..]);

        // Streaming, held as `dyn` where it sits: in 64-byte updates and in one, then the
        // in-place final that the boxed final runs.
        for (what, step) in [("do_update in 64-byte steps", 64), ("do_update", len)] {
            let mut hasher = BLAKE3::new();
            let hasher: &mut dyn Hash = &mut hasher;
            scan.run(|| msg.chunks(step).for_each(|part| hasher.do_update(part)));
            scan.clean(&op(what), &values);
            scan.pair(i, &op(what), &[]);
            let what = format!("final in place after {what}");
            assert_eq!(scan.run(|| hasher.finish_into(&finish_token(), &mut out[..32])), 32);
            assert_eq!(out[..32], root.root_bytes(32)[..], "not BLAKE3's hash");
            scan.clean(&op(&what), &values);
            scan.pair(i, &op(&what), &out[..32]);
        }

        // The squeezer: made where the hasher sits, read across a block boundary, suspended
        // and resumed. Its output is public; its state is the root's inputs.
        let mut hasher = BLAKE3::new();
        hasher.do_update(&msg);
        let mut squeezer = scan.run(|| hasher.finish_squeezer(&finish_token()));
        scan.clean(&op("finish_squeezer"), &values);
        scan.pair(i, &op("finish_squeezer"), &[]);
        assert_eq!(scan.run(|| squeezer.do_output_out(&mut out[..100])), 100);
        assert_eq!(out[..100], root.root_bytes(100)[..], "not BLAKE3's output");
        scan.clean(&op("squeezer do_output_out"), &values);
        scan.pair(i, &op("squeezer do_output_out"), &out[..100]);
        let state = scan.run(move || squeezer.suspend());
        scan.clean(&op("squeezer suspend"), &values);
        // The suspended state is handed out.
        scan.pair(i, &op("squeezer suspend"), &state[..]);
        // Moved into the call from a copy made here, above the stack searched: the copy that
        // passing it by value makes is the caller's, and is not made in the frames searched.
        let state_copy = state;
        let mut resumed = scan.run(move || BLAKE3Squeezer::from_suspended(state_copy)).unwrap();
        // The state is taken by value, and the copy its caller passes, which is a frame searched
        // here, is the caller's to wipe: what the state holds is not searched for, but
        // what it does not hold, and the comparison with the state as public, still are.
        scan.clean(&op("squeezer from_suspended"), &without(&values, &state[..]));
        scan.pair(i, &op("squeezer from_suspended"), &state[..]);
        resumed.do_output_out(&mut out[..50]);
        assert_eq!(out[..50], root.root_bytes(150)[100..], "not where it was suspended");

        // keyed_hash (s. 2.3): the key's 8 words, parsed little-endian, with KEYED_HASH set,
        // and every chaining value under them.
        let raw = bytes_of(&format!("BLAKE3 key {len} {i}"), 32);
        let (root, mut values) = b3_trace(&msgs[i], &b3_words(&raw), KEYED_HASH);
        values.push(named("key", &raw));
        values.push(named("message", &msgs[i]));
        // The root output's second half, which a MAC does not hand out.
        values.push(named("root output's unreleased half", &root.root_bytes(64)[32..]));
        *material = KeyMaterial::from_bytes_as_type(&raw, KeyType::MACKey).unwrap();
        *key = scan.run(|| BLAKE3KeyedHashKey::from_key_material(&*material)).unwrap();
        scan.clean(&op("keyed hash from_key_material"), &vec![named("key", &raw)]);
        scan.pair(i, &op("keyed hash from_key_material"), &[]);
        let expected = root.root_bytes(32);

        assert_eq!(scan.run(|| key.mac_out(&msg, &mut tag)), 32);
        assert_eq!(tag[..], expected[..], "not BLAKE3's keyed hash");
        scan.clean(&op("keyed hash mac_out"), &values);
        scan.pair(i, &op("keyed hash mac_out"), &expected);

        *tag = scan.run(|| key.mac(&msg));
        assert_eq!(tag[..], expected[..], "not BLAKE3's keyed hash");
        scan.clean(&op("keyed hash mac"), &values);
        scan.pair(i, &op("keyed hash mac"), &expected);

        scan.run(|| key.verify(&msg, &tag)).unwrap();
        scan.clean(&op("keyed hash verify"), &values);
        scan.pair(i, &op("keyed hash verify"), &[]);

        let mut generator = key.create_generator();
        let generator: &mut dyn MACGenerator<32> = &mut generator;
        let what = "keyed hash generator do_update in 64-byte steps";
        scan.run(|| msg.chunks(64).for_each(|part| generator.do_update(part)));
        scan.clean(&op(what), &values);
        scan.pair(i, &op(what), &[]);
        assert_eq!(scan.run(|| generator.finish_mac_into(&finish_token(), &mut tag)), 32);
        assert_eq!(tag[..], expected[..], "not BLAKE3's keyed hash");
        scan.clean(&op("keyed hash generator final in place"), &values);
        scan.pair(i, &op("keyed hash generator final in place"), &expected);

        let mut verifier = key.create_verifier();
        let verifier: &mut dyn MACVerifier<32> = &mut verifier;
        verifier.do_update(&msg);
        scan.run(|| verifier.finish_mac_verify(&finish_token(), &tag)).unwrap();
        scan.clean(&op("keyed hash verifier final in place"), &values);
        scan.pair(i, &op("keyed hash verifier final in place"), &[]);

        // derive_key (s. 2.3: the context hashed under DERIVE_KEY_CONTEXT, its first 8 output
        // words keying DERIVE_KEY_MATERIAL): the context is public, the key material and what
        // is derived from it are not. What is searched for is computed after the run, so that
        // no pointer to it is in a register that the run's deep frames save.
        let what = "derive_key hash_out";
        assert_eq!(scan.run(|| BLAKE3DeriveKey::new(context).hash_out(&msg, &mut out[..32])), 32);
        let (root, mut values) = b3_trace(&msgs[i], &context_key, DERIVE_KEY_MATERIAL);
        let derived = root.root_bytes(64);
        values.push(named("key material", &msgs[i]));
        values.push(named("derived key and the rest of its block", &derived));
        assert_eq!(out[..32], derived[..32], "not BLAKE3's derive_key");
        scan.clean(&op(what), &values);
        scan.pair(i, &op(what), &[]);
    }
}

/* ---------------------------------------------------------------------------------------------
 * AES-GCM-SIV (RFC 8452), by hand over the AES permutation
 * ------------------------------------------------------------------------------------------- */

/// POLYVAL's `dot(a, b) = a * b * x^-128` (RFC 8452 Section 3), bit by bit: Horner's rule over
/// the bits of `b`, multiplying by `x^-1` after each (adding the field polynomial
/// `x^128 + x^127 + x^126 + x^121 + 1` when the constant term is set, then dividing by `x`).
/// The strings are little-endian: bit `i` of the integer is the coefficient of `x^i`.
fn dot(a: u128, b: u128) -> u128 {
    let mut acc = 0u128;
    for i in 0..128 {
        if (b >> i) & 1 == 1 {
            acc ^= a;
        }
        acc = if acc & 1 == 1 {
            ((acc ^ (1 << 127) ^ (1 << 126) ^ (1 << 121) ^ 1) >> 1) | (1 << 127)
        } else {
            acc >> 1
        };
    }
    acc
}

/// [`dot`] against RFC 8452 Section 7's field operation example, and POLYVAL over it and
/// [`ghash_form`] against Appendix A's worked example, checked before anything is searched for
/// with them.
fn dot_matches_rfc_8452() -> bool {
    let a = u128::from_le_bytes(hex16("66e94bd4ef8a2c3b884cfa59ca342b2e"));
    let b = u128::from_le_bytes(hex16("ff000000000000000000000000000000"));
    let dot_ok = dot(a, b).to_le_bytes() == hex16("ebe563401e7e91ea3ad6426b8140c394");
    // Appendix A: POLYVAL(H, X_1, X_2) = f7a3..., and mulX_GHASH(ByteReverse(H)) = dcba...
    let h = hex16("25629347589242761d31f826ba4b757b");
    let mut s = 0u128;
    for x in ["4f4f95668c83dfb6401762bb2d01a262", "d1a24ddd2721d006bbe45f20d3c9f362"] {
        s = dot(s ^ u128::from_le_bytes(hex16(x)), u128::from_le_bytes(h));
    }
    let polyval_ok = s.to_le_bytes() == hex16("f7a3b47b846119fae5b7866cf5e5b77e");
    // The GHASH block's words are the halves of the string read big-endian.
    let words = ghash_form(&h);
    let string: Vec<u8> = words.chunks(8).flat_map(|w| w.iter().rev().copied()).collect();
    let ghash_ok = string == hex16("dcbaa5dd137c188ebb21492c23c9b112");
    dot_ok && polyval_ok && ghash_ok
}

fn hex16(s: &str) -> [u8; 16] {
    std::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
}

/// POLYVAL's key as the crate's multiplier holds it: `mulX_GHASH(ByteReverse(H))` (RFC 8452
/// Appendix A), the two words of its GHASH block in memory order.
fn ghash_form(h: &[u8; 16]) -> Vec<u8> {
    let mut v = [
        u64::from_le_bytes(h[8..].try_into().unwrap()),
        u64::from_le_bytes(h[..8].try_into().unwrap()),
    ];
    let reduce = v[1] & 1 == 1;
    v[1] = (v[1] >> 1) | (v[0] << 63);
    v[0] = (v[0] >> 1) ^ if reduce { 0xE1 << 56 } else { 0 };
    [v[0].to_le_bytes(), v[1].to_le_bytes()].concat()
}

/// What a GCM-SIV operation handled, by hand from the key-generating key `kgk`: the tag over
/// `plain`, the key stream from `ctr_tag` (the tag, if `None`), and the secrets on the way.
struct SivTrace {
    tag: [u8; 16],
    keystream: Vec<u8>,
    values: Values,
}

fn siv_trace<P: KeyExpansion<KL> + BlockPermutation<16>, const KL: usize>(
    kgk: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    plain: &[u8],
    ctr_tag: Option<&[u8; 16]>,
) -> SivTrace {
    let perm = |bytes: &[u8]| {
        P::new(&KeyMaterial::from_bytes_as_type(bytes, KeyType::SymmetricCipherKey).unwrap())
            .unwrap()
    };
    let key_generating_key = perm(kgk);
    let mut values = vec![named("key", kgk)];
    // derive_keys (Section 4): AES(key_generating_key, LE32(counter) ++ nonce), the first 8
    // bytes of each kept: counters 0 and 1 for the authentication key, 2 and 3 (and 4 and 5
    // for a 32-byte key) for the encryption key.
    let mut derived = Vec::new();
    for counter in 0u32..(2 + KL as u32 / 8) {
        let mut block = [0u8; 16];
        block[..4].copy_from_slice(&counter.to_le_bytes());
        block[4..].copy_from_slice(nonce);
        key_generating_key.encrypt_block(&mut block);
        values.push(named(&format!("derive_keys block {counter}"), &block));
        derived.extend_from_slice(&block[..8]);
    }
    let mak: [u8; 16] = derived[..16].try_into().unwrap();
    values.push(named("message-authentication key", &mak));
    values.push(named("message-encryption key", &derived[16..]));
    values.push(named("POLYVAL key (GHASH form)", &ghash_form(&mak)));
    let message_key = perm(&derived[16..]);

    // Section 4: S_s = POLYVAL(message_authentication_key,
    //                         padded_ad ++ padded_plaintext ++ length_block)
    let mut length_block = [0u8; 16];
    length_block[..8].copy_from_slice(&(aad.len() as u64 * 8).to_le_bytes());
    length_block[8..].copy_from_slice(&(plain.len() as u64 * 8).to_le_bytes());
    let h = u128::from_le_bytes(mak);
    let mut s = 0u128;
    let blocks = aad.chunks(16).chain(plain.chunks(16)).chain([&length_block[..]]);
    for (j, block) in blocks.enumerate() {
        let mut x = [0u8; 16];
        x[..block.len()].copy_from_slice(block);
        s = dot(s ^ u128::from_le_bytes(x), h);
        values.push(named(&format!("POLYVAL accumulator {j}"), &s.to_le_bytes()));
    }
    // S_s[i] ^= nonce[i] for i < 12; S_s[15] &= 0x7f; tag = AES(message_encryption_key, S_s)
    let mut tag = s.to_le_bytes();
    tag.iter_mut().zip(nonce).for_each(|(t, n)| *t ^= n);
    tag[15] &= 0x7f;
    values.push(named("S_s, masked", &tag));
    message_key.encrypt_block(&mut tag);

    // Section 4, AES_CTR: counter_block = tag, counter_block[15] |= 0x80, the first 32 bits a
    // little-endian counter.
    let mut counter_block = *ctr_tag.unwrap_or(&tag);
    counter_block[15] |= 0x80;
    let counter = u32::from_le_bytes(counter_block[..4].try_into().unwrap());
    let mut keystream = Vec::new();
    for j in 0..plain.len().div_ceil(16) as u32 {
        let mut block = counter_block;
        block[..4].copy_from_slice(&counter.wrapping_add(j).to_le_bytes());
        message_key.encrypt_block(&mut block);
        keystream.extend_from_slice(&block);
    }
    keystream.truncate(plain.len());
    values.push(named("key stream", &keystream));
    SivTrace { tag, keystream, values }
}

/// AES-GCM-SIV under a key of `KL` bytes: the key's construction, encryption in place with a
/// drawn and with a supplied nonce, decryption, and a decryption whose tag does not verify.
fn gcm_siv<K, P, const KL: usize>(scan: &mut Scan, name: &str)
where
    K: FromKeyMaterial<KL>
        + AeadInPlaceEncryptionKey<KL, 12, 16>
        + AeadInPlaceDecryptionKey<KL, 12, 16>,
    P: KeyExpansion<KL> + BlockPermutation<16>,
{
    let op = |what: &str| format!("{name}-GCM-SIV {what}");
    let cipher_key =
        |bytes: &[u8]| KeyMaterial::<KL>::from_bytes_as_type(bytes, KeyType::SymmetricCipherKey);
    let nonce: [u8; 12] = bytes_of(&format!("{name}-GCM-SIV nonce"), 12).try_into().unwrap();
    let aad = bytes_of(&format!("{name}-GCM-SIV aad"), 40);
    let mut material = Box::new(KeyMaterial::<KL>::new());
    // One key, made over for each run, so that both runs use it at one address.
    let mut key = Box::new(K::from_key_material(&cipher_key(&[1; KL]).unwrap()).unwrap());
    // Long enough for the four-block and the two-block key stream, and not a whole block.
    let mut buf = vec![0u8; 100].into_boxed_slice();
    let mut tag = Box::new([0u8; 16]);
    let mut rng = Box::new(FixedSeedRNG::new(nonce));

    for i in 0..2 {
        let raw = bytes_of(&format!("{name}-GCM-SIV key {i}"), KL);
        let pt = bytes_of(&format!("{name}-GCM-SIV plaintext {i}"), 100);
        let trace = siv_trace::<P, KL>(&raw, &nonce, &aad, &pt, None);
        let mut values = trace.values.clone();
        values.push(named("plaintext", &pt));
        let ct: Vec<u8> = pt.iter().zip(&trace.keystream).map(|(p, k)| p ^ k).collect();
        let public = [&trace.tag[..], &ct].concat();

        *material = cipher_key(&raw).unwrap();
        // The key's construction, AES's key expansion and the moves of the schedule it
        // returns, wipes nothing, as no block cipher key's does: reported.
        let report_only = std::mem::replace(&mut scan.report_only, true);
        *key = scan.run(|| K::from_key_material(&material)).unwrap();
        let k = &*key;
        scan.clean(&op("from_key_material"), &vec![named("key", &raw)]);
        scan.pair(i, &op("from_key_material"), &[]);
        scan.report_only = report_only;

        buf.copy_from_slice(&pt);
        *tag = scan.run(|| k.encrypt_detached_inplace_nonce(&nonce, &aad, &mut buf)).unwrap();
        assert_eq!(*tag, trace.tag, "not RFC 8452's tag");
        assert_eq!(buf[..], ct[..], "not RFC 8452's ciphertext");
        scan.clean(&op("encrypt_detached_inplace_nonce"), &values);
        scan.pair(i, &op("encrypt_detached_inplace_nonce"), &public);

        buf.copy_from_slice(&pt);
        *rng = FixedSeedRNG::new(nonce);
        let (drawn, drawn_tag) =
            scan.run(|| k.encrypt_detached_inplace(&mut *rng, &aad, &mut buf)).unwrap();
        assert_eq!((drawn, drawn_tag), (nonce, trace.tag), "not the drawn nonce's tag");
        assert_eq!(buf[..], ct[..], "not RFC 8452's ciphertext");
        scan.clean(&op("encrypt_detached_inplace"), &values);
        scan.pair(i, &op("encrypt_detached_inplace"), &public);

        buf.copy_from_slice(&ct);
        scan.run(|| k.decrypt_detached_inplace(&nonce, &aad, &mut buf, &tag)).unwrap();
        assert_eq!(buf[..], pt[..]);
        scan.clean(&op("decrypt_detached_inplace"), &values);
        scan.pair(i, &op("decrypt_detached_inplace"), &public);

        // A tag that does not verify: the key stream runs from it, and what that decrypts to
        // is unauthenticated plaintext, which is zeroized and must not be left behind either.
        let mut wrong = trace.tag;
        wrong[0] ^= 1;
        let stream = siv_trace::<P, KL>(&raw, &nonce, &aad, &ct, Some(&wrong)).keystream;
        let plain: Vec<u8> = ct.iter().zip(&stream).map(|(c, k)| c ^ k).collect();
        let mut values = siv_trace::<P, KL>(&raw, &nonce, &aad, &plain, Some(&wrong)).values;
        values.push(named("unauthenticated plaintext", &plain));
        buf.copy_from_slice(&ct);
        *tag = wrong;
        let what = "decrypt_detached_inplace, a tag that does not verify";
        assert!(scan.run(|| k.decrypt_detached_inplace(&nonce, &aad, &mut buf, &tag)).is_err());
        assert_eq!(buf[..], [0u8; 100][..], "not zeroized");
        scan.clean(&op(what), &values);
        scan.pair(i, &op(what), &[&wrong[..], &ct].concat());
    }
}
