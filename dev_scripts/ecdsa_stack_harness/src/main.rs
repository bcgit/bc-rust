//! What ECDSA signing and the handling of its private keys (bouncycastle_ec::ecdsa), ECC CDH's
//! private keys and agreement (bouncycastle_ec::eccdh), and DHKEM over the NIST curves, X448 and
//! X25519 with its labeled HKDF steps (bouncycastle_ec::dhkem) leave on the dead stack, for
//! `../check_ecdsa_stack.sh`. For each operation the stack below the call is painted, the
//! operation run with its results going to the heap or to a live frame above, the dead stack
//! copied out, and the copy searched for the 8-byte words of every secret the operation handled:
//! the private keys, the RNG's output, `k`, each Diffie-Hellman product (`x` and `y`), the
//! DHKEM's `eae_prk` and shared secret, and what a KDF derived, as bytes and, for integers, as
//! limbs. The RNG is a fixed one, so the values are computed here, with the crate's public
//! arithmetic, and checked against the operation's own output before they are searched for; the
//! `k` of a signature is recovered from it, `k = s^-1 (e + r d)`, and checked against `r`.
//!
//! Each operation is also run twice, at the same addresses, over different secrets (two keys, and
//! for the random operations two draws of the RNG), and the two copies compared: but for what the
//! operation hands out and the registers the call's first frames saved, they must be the same.
//!
//! Controls: nothing run must leave nothing, and the same stack twice; a copy of `d` left in a
//! frame must be found, and copies of two keys must differ.
//!
//! Reported and not failed: DHKEM over X25519, whose scalar multiplication leaves part of its
//! field inversion (`bouncycastle_ec::ed::x25519`'s Security Considerations), lines marked
//! `left`.
//!
//!   target/release/ecdsa_stack_harness
//!
//! One line per operation, `ok`, `FAIL` or `left`; the exit status is 1 if anything failed.
use bouncycastle_core::agreement_key::AgreementKey;
use bouncycastle_core::errors::KeyAgreementError;
use bouncycastle_core::hazmat::FixedSeedRNG;
use bouncycastle_core::kdf_params::{KdfParams, KeyLen};
use bouncycastle_core::kem_key::{DecapsulatingKey, EncapsulatingKey};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::signature_key::{
    DeterministicOneShotSigningKey, DeterministicSigningKey, OneShotSigningKey,
    OneShotVerifyingKey, SigningKey,
};
use bouncycastle_core::traits::{
    CollisionResistantHash, Hash, PrivateKey, PublicKey, RNG, SignatureSigner, Suspendable,
};
use bouncycastle_digest::concatkdf::ConcatKDF;
use bouncycastle_digest::hmac::HMACParams;
use bouncycastle_digest::sha2::{SHA256, SHA384, SHA512};
use bouncycastle_digest::x963kdf::X963KDF;
use bouncycastle_ec::curve::{
    Array, Curve, FieldElement, JacobianPoint, ScalarFieldElement, SecretScalar,
};
use bouncycastle_ec::dhkem::hazmat::{MAX_NH, labeled_expand, labeled_extract_out, salt_key};
use bouncycastle_ec::dhkem::{AuthDecapsulatingKey, AuthEncapsulatingKey, DHKEMParams};
use bouncycastle_ec::eccdh::dhkem::{DhkemCurve, derive_key_pair};
use bouncycastle_ec::eccdh::eccdh::{ECCDH, MatchedHash};
use bouncycastle_ec::eccdh::keys::{ECCDHPrivateKey, ECCDHPublicKey};
use bouncycastle_ec::eccdh::keys_common::{AgreementKeyPair, DerivePublicKey as EccdhDerive};
use bouncycastle_ec::ecdsa::ecdsa::{ECDSA, EcdsaHash};
use bouncycastle_ec::ecdsa::keys::{ECDSAPrivateKey, ECDSAPublicKey};
use bouncycastle_ec::ecdsa::keys_common::{DerivePublicKey, SignatureKeyPair};
use bouncycastle_ec::ed::x448::{self, X448PrivateKey, X448PublicKey};
use bouncycastle_ec::ed::x25519::{self, X25519PrivateKey, X25519PublicKey};
use bouncycastle_ec::{Bp256r1, Bp384r1, Bp512r1, P256, P384, P521, Secp256K1};
use bouncycastle_utils::secret::ZeroizablePrimitive;
use std::collections::HashSet;
use std::hint::black_box;

/// How far below the call the stack is painted and searched. The deepest operation here uses
/// under 16 KiB.
const DEPTH: usize = 256 * 1024;
/// The gap between the frame that takes the copy and the operation's first frame.
const PAD: usize = 16 * 1024;
const PAINT: u8 = 0xA5;
/// How far below the call a difference between two runs is put down to the registers the
/// call's first frames saved, and not counted: this program's loop index and heap addresses,
/// which the frames above the wiped ones save. The furthest seen is 408 bytes, below the
/// deterministic signer's final, whose frame holds the message hash.
const SAVED_REGISTERS: usize = 512;

/// The fixed RNG's seed: one draw at its start. Every operation here draws once.
const SEED_LEN: usize = 128;
type Rng = FixedSeedRNG<[u8; SEED_LEN]>;

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
fn leak(value: &[u8; 32]) {
    let mut pad = [0u8; 2 * SAVED_REGISTERS];
    black_box(&mut pad);
    leak_here(value);
}

#[inline(never)]
fn leak_here(value: &[u8; 32]) {
    let mut local = *value;
    black_box(&mut local);
}

/// A named secret, as the bytes it would be in memory.
type Values = Vec<(String, Vec<u8>)>;

/// A big-endian integer as its limbs lie in memory: the bytes in the other order.
fn limb_image(be: &[u8]) -> Vec<u8> {
    be.iter().rev().copied().collect()
}

/// An integer given as big-endian bytes: as those bytes and as limbs.
fn push_integer(values: &mut Values, name: &str, be: &[u8]) {
    values.push((format!("{name} (bytes)"), be.to_vec()));
    values.push((format!("{name} (limbs)"), limb_image(be)));
}

/// The painted stack's copy, the copy before it, and the count of what failed.
struct Scan {
    buf: Vec<u8>,
    before: Vec<u8>,
    failures: usize,
    /// Whether what is found is reported without failing the check: for an operation whose
    /// residue is known and documented as left.
    report_only: bool,
}

impl Scan {
    fn new() -> Self {
        Self { buf: vec![0u8; DEPTH], before: vec![0u8; DEPTH], failures: 0, report_only: false }
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
                "{} {operation}: left in the {used} bytes of stack it used: {}",
                self.fail_word(),
                found.join(", ")
            );
            self.fail();
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
            // held is this program's own: a loop's pointer, a length. Only the bytes of the run
            // within SAVED_REGISTERS of the call are put down to that.
            let deep_end = end.min((DEPTH - PAD).saturating_sub(SAVED_REGISTERS));
            if !explained && deep_end > i {
                count += deep_end - i;
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
                    "{} {operation}: {count} bytes of stack differ with the secrets, the \
                     furthest {furthest} bytes below the call",
                    self.fail_word()
                );
                self.fail();
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

/// A fixed RNG whose first draw is `draw`.
fn rng_of(draw: &[u8]) -> Rng {
    let mut seed = [0u8; SEED_LEN];
    seed[..draw.len()].copy_from_slice(draw);
    FixedSeedRNG::new(seed)
}

/// A message of `len` bytes with no 8-byte word of one repeated byte.
fn message(len: usize) -> Box<[u8]> {
    (0..len).map(|i| (i * 37 + 11) as u8).collect()
}

/// A public key as what [`Scan::same`] lets differ: its encoding and the limbs of its
/// coordinates.
fn public_image(encoded: &[u8]) -> Vec<u8> {
    let half = (encoded.len() - 1) / 2;
    [&encoded[..], &limb_image(&encoded[1..1 + half]), &limb_image(&encoded[1 + half..])].concat()
}

/// The encoded public key of the private key `d`, from the curve's arithmetic.
fn public_of<C, const SK: usize, const PK: usize>(d: &[u8; SK]) -> [u8; PK]
where
    C: Curve<ScalarBytes = [u8; SK], PkUncompressed = [u8; PK]>,
{
    let (x, y) = C::public_point(&C::Scalar::from_be_bytes(d));
    C::encode_uncompressed(&x, &y)
}

/// A signature as what [`Scan::same`] lets differ: its bytes and the limbs of `r` and `s`.
fn signature_image(sig: &[u8]) -> Vec<u8> {
    let half = sig.len() / 2;
    [sig, &limb_image(&sig[..half]), &limb_image(&sig[half..])].concat()
}

/// `d` as what is searched for.
fn key_values(d: &[u8]) -> Values {
    let mut values = Values::new();
    push_integer(&mut values, "d", d);
    values
}

/// The scalar field element of a big-endian value below `2n`.
fn field<C: Curve<ScalarBytes = [u8; SK]>, const SK: usize>(be: &[u8]) -> C::ScalarField {
    let bytes: [u8; SK] = be.try_into().unwrap();
    C::ScalarField::from_limbs(C::limbs_from_be_bytes(&bytes))
}

/// The `k` that made `sig` over `msg` under `d`: `k = s^-1 (e + r d)` (FIPS 186-5 Section 6.4.1
/// step 9), checked against `r`, the affine `x` of `[k]G` mod `n` (steps 5-8).
fn k_of_signature<C, H, const SK: usize>(d: &[u8; SK], msg: &[u8], sig: &[u8]) -> [u8; SK]
where
    C: Curve<ScalarBytes = [u8; SK]>,
    H: EcdsaHash,
{
    let mut hash = H::default();
    hash.do_update(msg);
    let mut h = vec![0u8; H::OUTPUT_LEN];
    hash.do_final_out(&mut h);
    // Step 2: the leftmost len(n) bits, which are whole bytes for every pairing run here.
    let take = if 8 * h.len() <= C::ORDER_BITS { h.len() } else { C::ORDER_BITS / 8 };
    let mut e = [0u8; SK];
    e[SK - take..].copy_from_slice(&h[..take]);
    let (r, s) = (field::<C, SK>(&sig[..SK]), field::<C, SK>(&sig[SK..]));
    let k = s.invert().mul(&field::<C, SK>(&e).add(&r.mul(&field::<C, SK>(d))));
    let k = C::be_bytes_from_limbs(&k.to_limbs());
    let (x, _) = C::public_point(&C::Scalar::from_be_bytes(&k));
    let r_of_k = C::ScalarField::from_limbs(x.to_limbs());
    assert!(r_of_k == r, "not the signature's k");
    k
}

fn main() {
    let mut scan = Scan::new();
    let mut key = Box::new([0u8; 32]);

    // The controls.
    for _ in 0..2 {
        scan.run(|| {});
        scan.clean("control, nothing run", &key_values(&bytes_of("control 0", 32)));
        scan.keep();
    }
    scan.same("control, nothing run twice", &[], &[]);
    for i in 0..2 {
        let d = bytes_of(&format!("control {i}"), 32);
        key.copy_from_slice(&d);
        scan.keep();
        scan.run(|| leak(&key));
        scan.leaked("control, a copy of d left in a frame", &vec![key_values(&d)[0].clone()]);
    }
    scan.differs("control, copies of two keys left in a frame");

    ecdsa::<P256, SHA256, 32, 65, 64>(&mut scan, "P-256");
    ecdsa::<P384, SHA384, 48, 97, 96>(&mut scan, "P-384");
    ecdsa::<P521, SHA512, 66, 133, 132>(&mut scan, "P-521");
    ecdsa::<Secp256K1, SHA256, 32, 65, 64>(&mut scan, "secp256k1");
    ecdsa::<Bp256r1, SHA256, 32, 65, 64>(&mut scan, "brainpoolP256r1");
    ecdsa::<Bp384r1, SHA384, 48, 97, 96>(&mut scan, "brainpoolP384r1");
    ecdsa::<Bp512r1, SHA512, 64, 129, 128>(&mut scan, "brainpoolP512r1");

    eccdh::<P256, 32, 65, 32>(&mut scan, "P-256");
    eccdh::<P384, 48, 97, 48>(&mut scan, "P-384");
    eccdh::<P521, 66, 133, 66>(&mut scan, "P-521");
    eccdh::<Secp256K1, 32, 65, 32>(&mut scan, "secp256k1");
    eccdh::<Bp256r1, 32, 65, 32>(&mut scan, "brainpoolP256r1");
    eccdh::<Bp384r1, 48, 97, 48>(&mut scan, "brainpoolP384r1");
    eccdh::<Bp512r1, 64, 129, 64>(&mut scan, "brainpoolP512r1");

    labeled::<SHA256>(&mut scan, "SHA-256");
    labeled::<SHA384>(&mut scan, "SHA-384");
    labeled::<SHA512>(&mut scan, "SHA-512");

    dhkem::<P256, 32, 65, 32, 32>(&mut scan, "P-256");
    dhkem::<P384, 48, 97, 48, 48>(&mut scan, "P-384");
    dhkem::<P521, 66, 133, 66, 64>(&mut scan, "P-521");

    dhkem_x::<X448PrivateKey, X448PublicKey, SHA512, 56, 64>(
        &mut scan,
        "X448",
        0x0021,
        x448::keygen,
    );
    // X25519's scalar multiplication leaves part of its inversion, by decision: reported.
    scan.report_only = true;
    dhkem_x::<X25519PrivateKey, X25519PublicKey, SHA256, 32, 32>(
        &mut scan,
        "X25519",
        0x0020,
        x25519::keygen,
    );
    scan.report_only = false;

    std::process::exit(if scan.failures == 0 { 0 } else { 1 });
}

/// The ECDSA private key over `C` paired with `H`: loaded, copied, re-paired and generated, and
/// signing with it, random and deterministic, through the one-shots, the signer's construction
/// and the streaming final.
fn ecdsa<C, H, const SK: usize, const PK: usize, const SIG: usize>(scan: &mut Scan, curve: &str)
where
    C: Curve<ScalarBytes = [u8; SK], PkUncompressed = [u8; PK], Signature = [u8; SIG]>,
    H: EcdsaHash + CollisionResistantHash,
{
    let draw_len = C::EXTRA_BITS_DRAW_LEN;
    // Two key draws, each giving the key a generation from it makes, and two draws of k.
    let key_draws = [0, 1].map(|i| bytes_of(&format!("{curve} key {i}"), draw_len));
    let keys = key_draws.clone().map(|w| C::reduce_wide_bits_mod_n_minus_1(&w).to_be_bytes());
    let k_draws = [0, 1].map(|i| bytes_of(&format!("{curve} k {i}"), draw_len));
    let mut sk = Box::new(ECDSAPrivateKey::<C, H>::from_bytes(&keys[0]).unwrap());
    let mut encoded = Box::new([0u8; SK]);
    let mut rng = Box::new(rng_of(&k_draws[0]));
    let op = |name: &str| format!("ECDSA {curve} {name}");

    for d in &keys {
        scan.keep();
        *encoded = *d;
        let loaded = scan.run(|| ECDSAPrivateKey::<C, H>::from_bytes(&encoded[..]));
        assert_eq!(loaded.unwrap().encode(), *d);
        scan.clean(&op("from_bytes"), &key_values(d));
    }
    scan.same(&op("from_bytes"), &[], &[]);
    for d in &keys {
        scan.keep();
        *sk = ECDSAPrivateKey::from_bytes(d).unwrap();
        let copy = scan.run(|| (*sk).clone());
        assert!(copy == *sk);
        scan.clean(&op("clone"), &key_values(d));
    }
    scan.same(&op("clone"), &[], &[]);
    for d in &keys {
        scan.keep();
        *sk = ECDSAPrivateKey::from_bytes(d).unwrap();
        let other = scan.run(|| sk.with_hash::<SHA512>());
        assert_eq!(other.encode(), *d);
        scan.clean(&op("with_hash"), &key_values(d));
    }
    scan.same(&op("with_hash"), &[], &[]);
    for (name, generic) in [("keygen", false), ("generate_signature_key_pair", true)] {
        let mut publics = Vec::new();
        for (wide, d) in key_draws.iter().zip(&keys) {
            scan.keep();
            *rng = rng_of(wide);
            let (generated_pk, generated_sk) = scan
                .run(|| {
                    if generic {
                        C::generate_signature_key_pair::<H>(&mut *rng)
                    } else {
                        bouncycastle_ec::ecdsa::keys::keygen::<C, H>(&mut *rng)
                    }
                })
                .unwrap();
            assert_eq!(generated_sk.encode(), *d, "not its reduction");
            let mut values = key_values(d);
            push_integer(&mut values, "RNG output", wide);
            scan.clean(&op(name), &values);
            publics.push(public_image(&generated_pk.encode()));
        }
        scan.same(&op(name), &publics[0], &publics[1]);
    }

    // The encodings write less below the call than SAVED_REGISTERS, which the comparison of two
    // runs excuses, so for them the search is the check.
    for d in &keys {
        *sk = ECDSAPrivateKey::from_bytes(d).unwrap();
        scan.keep();
        *encoded = scan.run(|| sk.encode());
        assert_eq!(*encoded, *d);
        scan.clean(&op("encode"), &key_values(d));
    }
    scan.same(&op("encode"), &[], &[]);
    for d in &keys {
        *sk = ECDSAPrivateKey::from_bytes(d).unwrap();
        scan.keep();
        assert_eq!(scan.run(|| sk.encode_out(&mut encoded)), SK);
        assert_eq!(*encoded, *d);
        scan.clean(&op("encode_out"), &key_values(d));
    }
    scan.same(&op("encode_out"), &[], &[]);
    let mut publics = Vec::new();
    for d in &keys {
        *sk = ECDSAPrivateKey::from_bytes(d).unwrap();
        scan.keep();
        let pk: ECDSAPublicKey<C, H> = scan.run(|| sk.derive_pk());
        assert_eq!(pk.encode(), public_of::<C, SK, PK>(d), "not its public key");
        scan.clean(&op("derive_pk"), &key_values(d));
        publics.push(public_image(&pk.encode()));
    }
    scan.same(&op("derive_pk"), &publics[0], &publics[1]);

    // Signing: twice, under two keys, from two draws of the RNG.
    let msg = message(100);
    let mut sig = Box::new([0u8; SIG]);
    let pks: Vec<ECDSAPublicKey<C, H>> =
        keys.iter().map(|d| ECDSAPrivateKey::<C, H>::from_bytes(d).unwrap().derive_pk()).collect();
    // What a signature under the i-th key is searched for: the key, the k recovered from the
    // signature, and the draw it was to come from, if any.
    let signing_values = |i: usize, sig: &[u8; SIG], wide: Option<&[u8]>| {
        pks[i].verify(&msg, None, sig).unwrap();
        let k = k_of_signature::<C, H, SK>(&keys[i], &msg, sig);
        let mut values = key_values(&keys[i]);
        push_integer(&mut values, "k", &k);
        if let Some(wide) = wide {
            assert_eq!(k, C::reduce_wide_bits_mod_n_minus_1(wide).to_be_bytes(), "not its k");
            push_integer(&mut values, "RNG output", wide);
        }
        values
    };

    for i in 0..2 {
        scan.keep();
        *sk = ECDSAPrivateKey::from_bytes(&keys[i]).unwrap();
        *rng = rng_of(&k_draws[i]);
        let signer = scan
            .run(|| SigningKey::<ECDSA<C, H>, SIG>::create_signer(&*sk, &mut *rng, None))
            .unwrap();
        let mut boxed: Box<dyn SignatureSigner<SIG> + '_> = Box::new(signer);
        boxed.do_update(&msg);
        boxed.do_final_out_boxed(&mut sig).unwrap();
        scan.clean(&op("create_signer"), &signing_values(i, &sig, Some(&k_draws[i])));
    }
    scan.same(&op("create_signer"), &[], &[]);

    let mut images = Vec::new();
    for i in 0..2 {
        scan.keep();
        *sk = ECDSAPrivateKey::from_bytes(&keys[i]).unwrap();
        *rng = rng_of(&k_draws[i]);
        assert_eq!(scan.run(|| sk.sign_out(&mut *rng, &msg, None, &mut sig)), Ok(SIG));
        scan.clean(&op("sign_out"), &signing_values(i, &sig, Some(&k_draws[i])));
        images.push(signature_image(&*sig));
    }
    scan.same(&op("sign_out"), &images[0], &images[1]);

    let mut images = Vec::new();
    for i in 0..2 {
        scan.keep();
        *sk = ECDSAPrivateKey::from_bytes(&keys[i]).unwrap();
        *rng = rng_of(&k_draws[i]);
        *sig = scan.run(|| sk.sign(&mut *rng, &msg, None)).unwrap();
        scan.clean(&op("sign"), &signing_values(i, &sig, Some(&k_draws[i])));
        images.push(signature_image(&*sig));
    }
    scan.same(&op("sign"), &images[0], &images[1]);

    // The streaming final, on a signer that sits in a box: nothing is moved out of it.
    let mut images = Vec::new();
    for i in 0..2 {
        *sk = ECDSAPrivateKey::from_bytes(&keys[i]).unwrap();
        *rng = rng_of(&k_draws[i]);
        let mut signer: Box<dyn SignatureSigner<SIG> + '_> =
            Box::new(SigningKey::<ECDSA<C, H>, SIG>::create_signer(&*sk, &mut *rng, None).unwrap());
        signer.do_update(&msg);
        scan.keep();
        assert_eq!(scan.run(|| signer.do_final_out_boxed(&mut sig)), Ok(SIG));
        scan.clean(&op("final (boxed)"), &signing_values(i, &sig, Some(&k_draws[i])));
        images.push(signature_image(&*sig));
    }
    scan.same(&op("final (boxed)"), &images[0], &images[1]);

    // Deterministic signing (RFC 6979), under two keys.
    for i in 0..2 {
        scan.keep();
        *sk = ECDSAPrivateKey::from_bytes(&keys[i]).unwrap();
        let signer = scan
            .run(|| {
                DeterministicSigningKey::<ECDSA<C, H>, SIG>::create_signer_deterministic(&*sk, None)
            })
            .unwrap();
        let mut boxed: Box<dyn SignatureSigner<SIG> + '_> = Box::new(signer);
        boxed.do_update(&msg);
        boxed.do_final_out_boxed(&mut sig).unwrap();
        scan.clean(&op("create_signer_deterministic"), &signing_values(i, &sig, None));
    }
    scan.same(&op("create_signer_deterministic"), &[], &[]);

    let mut images = Vec::new();
    for i in 0..2 {
        scan.keep();
        *sk = ECDSAPrivateKey::from_bytes(&keys[i]).unwrap();
        assert_eq!(scan.run(|| sk.sign_deterministic_out(&msg, None, &mut sig)), Ok(SIG));
        scan.clean(&op("sign_deterministic_out"), &signing_values(i, &sig, None));
        images.push(signature_image(&*sig));
    }
    scan.same(&op("sign_deterministic_out"), &images[0], &images[1]);

    let mut images = Vec::new();
    for i in 0..2 {
        scan.keep();
        *sk = ECDSAPrivateKey::from_bytes(&keys[i]).unwrap();
        *sig = scan.run(|| sk.sign_deterministic(&msg, None)).unwrap();
        scan.clean(&op("sign_deterministic"), &signing_values(i, &sig, None));
        images.push(signature_image(&*sig));
    }
    scan.same(&op("sign_deterministic"), &images[0], &images[1]);

    let mut images = Vec::new();
    for i in 0..2 {
        *sk = ECDSAPrivateKey::from_bytes(&keys[i]).unwrap();
        let mut signer: Box<dyn SignatureSigner<SIG> + '_> = Box::new(
            DeterministicSigningKey::<ECDSA<C, H>, SIG>::create_signer_deterministic(&*sk, None)
                .unwrap(),
        );
        signer.do_update(&msg);
        scan.keep();
        assert_eq!(scan.run(|| signer.do_final_out_boxed(&mut sig)), Ok(SIG));
        scan.clean(&op("deterministic final (boxed)"), &signing_values(i, &sig, None));
        images.push(signature_image(&*sig));
    }
    scan.same(&op("deterministic final (boxed)"), &images[0], &images[1]);
}

/// `[d]Q`, for the private key `d` and the encoded public key `q`: its `x`, which is the shared
/// secret `Z` of ECC CDH, and its `y`, each as bytes and as limbs.
fn shared_values<C, const SK: usize, const PK: usize, const FE: usize>(
    values: &mut Values,
    name: &str,
    d: &[u8; SK],
    q: &[u8; PK],
) where
    C: Curve<ScalarBytes = [u8; SK], PkUncompressed = [u8; PK], FeBytes = [u8; FE]>,
{
    let (x, y) = C::decode(q).unwrap();
    let p = C::multiply_point(&C::Scalar::from_be_bytes(d), &C::Point::from_affine(x, y));
    let (px, py) = p.to_affine().unwrap();
    push_integer(values, name, &C::fe_be_bytes_from_limbs(&px.to_limbs()));
    push_integer(values, &format!("{name} y"), &C::fe_be_bytes_from_limbs(&py.to_limbs()));
    // Their Montgomery forms, `v * 2^(64 L) mod p`, as the brainpool curves hold them.
    let mut two = C::Limbs::ZEROED;
    two.as_mut()[0] = 2;
    let (two, mut r) = (C::Fe::from_limbs(two), C::Fe::from_limbs(C::Limbs::ZEROED));
    let mut one = C::Limbs::ZEROED;
    one.as_mut()[0] = 1;
    r = r.add(&C::Fe::from_limbs(one));
    for _ in 0..64 * C::Limbs::LEN {
        r = r.mul(&two);
    }
    for (part, v) in [("", px), (" y", py)] {
        let mont = C::fe_be_bytes_from_limbs(&v.mul(&r).to_limbs());
        push_integer(values, &format!("{name}{part} (Montgomery)"), &mont);
    }
}

/// The ECC CDH private key over `C`: loaded, generated, encoded, its public key derived, and
/// agreeing, raw and through the X9.63 and concatenation KDFs.
fn eccdh<C, const SK: usize, const PK: usize, const FE: usize>(scan: &mut Scan, curve: &str)
where
    C: Curve<ScalarBytes = [u8; SK], PkUncompressed = [u8; PK], FeBytes = [u8; FE]> + MatchedHash,
{
    let draw_len = C::EXTRA_BITS_DRAW_LEN;
    let key_draws = [0, 1].map(|i| bytes_of(&format!("{curve} agreement key {i}"), draw_len));
    let keys = key_draws.clone().map(|w| C::reduce_wide_bits_mod_n_minus_1(&w).to_be_bytes());
    let mut encoded = Box::new([0u8; SK]);
    let mut rng = Box::new(rng_of(&key_draws[0]));
    let op = |name: &str| format!("ECCDH {curve} {name}");

    for d in &keys {
        scan.keep();
        *encoded = *d;
        let loaded = scan.run(|| ECCDHPrivateKey::<C>::from_bytes(&encoded[..]));
        assert_eq!(loaded.unwrap().encode(), *d);
        scan.clean(&op("from_bytes"), &key_values(d));
    }
    scan.same(&op("from_bytes"), &[], &[]);
    for (name, generic) in [("keygen", false), ("generate_agreement_key_pair", true)] {
        let mut publics = Vec::new();
        for (wide, d) in key_draws.iter().zip(&keys) {
            scan.keep();
            *rng = rng_of(wide);
            let (generated_pk, generated_sk): (ECCDHPublicKey<C>, ECCDHPrivateKey<C>) = scan
                .run(|| {
                    if generic {
                        C::generate_agreement_key_pair(&mut *rng)
                    } else {
                        bouncycastle_ec::eccdh::keys::keygen::<C>(&mut *rng)
                    }
                })
                .unwrap();
            assert_eq!(generated_sk.encode(), *d, "not its reduction");
            let mut values = key_values(d);
            push_integer(&mut values, "RNG output", wide);
            scan.clean(&op(name), &values);
            publics.push(public_image(&generated_pk.encode()));
        }
        scan.same(&op(name), &publics[0], &publics[1]);
    }

    let mut sk = Box::new(ECCDHPrivateKey::<C>::from_bytes(&keys[0]).unwrap());
    // As for ECDSA's encodings, the search is the check.
    for d in &keys {
        *sk = ECCDHPrivateKey::from_bytes(d).unwrap();
        scan.keep();
        *encoded = scan.run(|| sk.encode());
        assert_eq!(*encoded, *d);
        scan.clean(&op("encode"), &key_values(d));
    }
    scan.same(&op("encode"), &[], &[]);
    for d in &keys {
        *sk = ECCDHPrivateKey::from_bytes(d).unwrap();
        scan.keep();
        assert_eq!(scan.run(|| sk.encode_out(&mut encoded)), SK);
        assert_eq!(*encoded, *d);
        scan.clean(&op("encode_out"), &key_values(d));
    }
    scan.same(&op("encode_out"), &[], &[]);
    let mut publics = Vec::new();
    for d in &keys {
        *sk = ECCDHPrivateKey::from_bytes(d).unwrap();
        scan.keep();
        let pk: ECCDHPublicKey<C> = scan.run(|| EccdhDerive::derive_pk(&*sk));
        assert_eq!(pk.encode(), public_of::<C, SK, PK>(d), "not its public key");
        scan.clean(&op("derive_pk"), &key_values(d));
        publics.push(public_image(&pk.encode()));
    }
    scan.same(&op("derive_pk"), &publics[0], &publics[1]);

    // Agreement: under two keys, with one peer.
    let peer_d = C::reduce_wide_bits_mod_n_minus_1(&bytes_of(&format!("{curve} peer"), draw_len))
        .to_be_bytes();
    let peer_encoded = public_of::<C, SK, PK>(&peer_d);
    let peer = ECCDHPublicKey::<C>::from_bytes(&peer_encoded).unwrap();
    let agree_values = |d: &[u8; SK]| {
        let mut values = key_values(d);
        shared_values::<C, SK, PK, FE>(&mut values, "Z", d, &peer_encoded);
        values
    };
    let mut z = Box::new(KeyMaterial::<FE>::new());
    for d in &keys {
        *sk = ECCDHPrivateKey::from_bytes(d).unwrap();
        scan.keep();
        assert_eq!(scan.run(|| AgreementKey::<(), FE>::agree_out(&*sk, &peer, (), &mut z)), Ok(FE));
        let values = agree_values(d);
        assert_eq!(z.ref_to_bytes(), &values[2].1[..], "not its Z");
        scan.clean(&op("agree_out"), &values);
    }
    scan.same(&op("agree_out"), &[], &[]);

    let kdf = X963KDF::<C::Hash>::new();
    let params = KdfParams::new(&kdf, b"stack harness", KeyLen::<32>);
    let mut key = Box::new(KeyMaterial::<32>::new());
    for d in &keys {
        *sk = ECCDHPrivateKey::from_bytes(d).unwrap();
        scan.keep();
        assert_eq!(scan.run(|| sk.agree_out(&peer, params, &mut key)), Ok(32));
        let mut values = agree_values(d);
        values.push(("derived key".to_string(), key.ref_to_bytes().to_vec()));
        scan.clean(&op("agree_out (X9.63 KDF)"), &values);
    }
    scan.same(&op("agree_out (X9.63 KDF)"), &[], &[]);

    let kdf = ConcatKDF::<C::Hash>::new();
    let params = KdfParams::new(&kdf, b"stack harness", KeyLen::<32>);
    for d in &keys {
        *sk = ECCDHPrivateKey::from_bytes(d).unwrap();
        scan.keep();
        assert_eq!(scan.run(|| sk.agree_out(&peer, params, &mut key)), Ok(32));
        let mut values = agree_values(d);
        values.push(("derived key".to_string(), key.ref_to_bytes().to_vec()));
        scan.clean(&op("agree_out (concatenation KDF)"), &values);
    }
    scan.same(&op("agree_out (concatenation KDF)"), &[], &[]);
}

/// The value of `values` named `name`.
fn value(values: &Values, name: &str) -> Vec<u8> {
    values.iter().find(|(n, _)| n == name).unwrap().1.clone()
}

/// `eae_prk = LabeledExtract("", "eae_prk", dh)` of the DHKEM with `kem_id`, over `H` (RFC
/// 9180 Section 4.1): the PRK its shared secret is expanded from, checked against `ss` by that
/// expansion over `kem_context` before it is searched for.
fn eae_prk<H: HMACParams>(
    kem_id: u16,
    dh: &[&[u8]],
    kem_context: &[&[u8]],
    ss: &[u8],
) -> (String, Vec<u8>) {
    let suite_id = [b"KEM".as_slice(), &kem_id.to_be_bytes()].concat();
    let mut prk = [0u8; MAX_NH];
    let nh = labeled_extract_out::<H>(&suite_id, &salt_key::<H>(&[]), b"eae_prk", dh, &mut prk);
    let prk_key = KeyMaterial::<MAX_NH>::from_bytes_as_type(&prk[..nh], KeyType::MACKey).unwrap();
    let mut expanded = vec![0u8; ss.len()];
    labeled_expand::<H>(&suite_id, &prk_key, b"shared_secret", kem_context, &mut expanded);
    assert_eq!(expanded, ss, "not the PRK of the shared secret");
    ("eae_prk".to_string(), prk[..nh].to_vec())
}

/// DHKEM over `C` (RFC 9180 Section 4.1, on the ECC CDH keys): a private key from bytes as
/// `DeriveKeyPair` tests a candidate, `DeriveKeyPair` itself, and `Encap`, `Decap`, `AuthEncap`
/// and `AuthDecap` through the keys' roles. Searched for the private keys, the RNG's output, each
/// Diffie-Hellman product and the shared secret.
fn dhkem<C, const SK: usize, const PK: usize, const FE: usize, const SS: usize>(
    scan: &mut Scan,
    curve: &str,
) where
    C: DhkemCurve<SharedSecret = KeyMaterial<SS>>
        + Curve<ScalarBytes = [u8; SK], PkUncompressed = [u8; PK], FeBytes = [u8; FE]>,
    ECCDH<C>: DHKEMParams<PK, SK, FE, PrivateKey = ECCDHPrivateKey<C>>,
{
    let draw_len = C::EXTRA_BITS_DRAW_LEN;
    let key_of = |label: &str| {
        C::reduce_wide_bits_mod_n_minus_1(&bytes_of(&format!("{curve} DHKEM {label}"), draw_len))
            .to_be_bytes()
    };
    let keys = [key_of("recipient 0"), key_of("recipient 1")];
    let sender = key_of("sender");
    let e_draws = [0, 1].map(|i| bytes_of(&format!("{curve} DHKEM ephemeral {i}"), draw_len));
    let e_keys = e_draws.clone().map(|w| C::reduce_wide_bits_mod_n_minus_1(&w).to_be_bytes());
    let pks = keys.map(|d| public_of::<C, SK, PK>(&d));
    let sender_pk = ECCDHPublicKey::<C>::from_bytes(&public_of::<C, SK, PK>(&sender)).unwrap();
    let sender_sk = Box::new(ECCDHPrivateKey::<C>::from_bytes(&sender).unwrap());
    let mut rng = Box::new(rng_of(&e_draws[0]));
    let mut sk = Box::new(ECCDHPrivateKey::<C>::from_bytes(&keys[0]).unwrap());
    let mut pk_r = Box::new(ECCDHPublicKey::<C>::from_bytes(&pks[0]).unwrap());
    let mut enc = Box::new([0u8; PK]);
    let mut ss = Box::new(KeyMaterial::<SS>::new());
    let mut cts = Vec::new();
    let op = |name: &str| format!("DHKEM {curve} {name}");

    for d in &keys {
        scan.keep();
        let loaded =
            scan.run(|| <ECCDH<C> as DHKEMParams<PK, SK, FE>>::private_key_from_bytes(d)).unwrap();
        assert_eq!(loaded.encode(), *d);
        scan.clean(&op("private_key_from_bytes"), &key_values(d));
    }
    scan.same(&op("private_key_from_bytes"), &[], &[]);

    let mut publics = Vec::new();
    for i in 0..2 {
        let ikm = Box::new(
            KeyMaterial::<64>::from_bytes_as_type(
                &bytes_of(&format!("{curve} DHKEM ikm {i}"), 64),
                KeyType::Seed,
            )
            .unwrap(),
        );
        scan.keep();
        let (pk, derived) = scan.run(|| derive_key_pair::<C>(&*ikm)).unwrap();
        scan.clean(&op("derive_key_pair"), &key_values(&derived.encode()));
        publics.push(public_image(&pk.encode()));
    }
    scan.same(&op("derive_key_pair"), &publics[0], &publics[1]);

    // Encap to two recipients, from two draws of the RNG.
    let mut images = Vec::new();
    for i in 0..2 {
        *pk_r = ECCDHPublicKey::from_bytes(&pks[i]).unwrap();
        *rng = rng_of(&e_draws[i]);
        scan.keep();
        assert_eq!(scan.run(|| pk_r.encaps_out(&mut *rng, (), &mut enc, &mut ss)), Ok(PK));
        assert_eq!(*enc, public_of::<C, SK, PK>(&e_keys[i]), "not its ephemeral key");
        let mut values = key_values(&e_keys[i]);
        push_integer(&mut values, "RNG output", &e_draws[i]);
        shared_values::<C, SK, PK, FE>(&mut values, "dh", &e_keys[i], &pks[i]);
        let dh = value(&values, "dh (bytes)");
        values.push(eae_prk::<C::KDFHash>(
            C::KEM_ID,
            &[&dh],
            &[&enc[..], &pks[i]],
            ss.ref_to_bytes(),
        ));
        values.push(("shared secret".to_string(), ss.ref_to_bytes().to_vec()));
        scan.clean(&op("encaps_out"), &values);
        images.push([public_image(&*enc), public_image(&pks[i])].concat());
        cts.push((*enc, ss.ref_to_bytes().to_vec()));
    }
    scan.same(&op("encaps_out"), &images[0], &images[1]);

    // Decap of the first, by the two recipients: the same `enc` both times, so that only the
    // secrets differ.
    let mut images = Vec::new();
    for i in 0..2 {
        *sk = ECCDHPrivateKey::from_bytes(&keys[i]).unwrap();
        *enc = cts[0].0;
        scan.keep();
        assert_eq!(scan.run(|| sk.decaps_out(&enc, (), &mut ss)), Ok(SS));
        assert!(i == 1 || ss.ref_to_bytes() == &cts[0].1[..], "not the encapsulated secret");
        let mut values = key_values(&keys[i]);
        shared_values::<C, SK, PK, FE>(&mut values, "dh", &keys[i], &enc);
        let dh = value(&values, "dh (bytes)");
        values.push(eae_prk::<C::KDFHash>(
            C::KEM_ID,
            &[&dh],
            &[&enc[..], &pks[i]],
            ss.ref_to_bytes(),
        ));
        values.push(("shared secret".to_string(), ss.ref_to_bytes().to_vec()));
        scan.clean(&op("decaps_out"), &values);
        images.push([public_image(&*enc), public_image(&pks[i])].concat());
    }
    scan.same(&op("decaps_out"), &images[0], &images[1]);

    // AuthEncap from one sender to two recipients, and AuthDecap of the first by both.
    let mut images = Vec::new();
    let mut cts = Vec::new();
    for i in 0..2 {
        *pk_r = ECCDHPublicKey::from_bytes(&pks[i]).unwrap();
        *rng = rng_of(&e_draws[i]);
        scan.keep();
        assert_eq!(
            scan.run(|| pk_r.auth_encaps_out(&mut *rng, &sender_sk, &mut enc, &mut ss)),
            Ok(PK)
        );
        let mut values = key_values(&e_keys[i]);
        push_integer(&mut values, "sender's d", &sender);
        push_integer(&mut values, "RNG output", &e_draws[i]);
        shared_values::<C, SK, PK, FE>(&mut values, "dh_e", &e_keys[i], &pks[i]);
        shared_values::<C, SK, PK, FE>(&mut values, "dh_s", &sender, &pks[i]);
        let (dh_e, dh_s) = (value(&values, "dh_e (bytes)"), value(&values, "dh_s (bytes)"));
        values.push(eae_prk::<C::KDFHash>(
            C::KEM_ID,
            &[&dh_e, &dh_s],
            &[&enc[..], &pks[i], &sender_pk.encode()],
            ss.ref_to_bytes(),
        ));
        values.push(("shared secret".to_string(), ss.ref_to_bytes().to_vec()));
        scan.clean(&op("auth_encaps_out"), &values);
        images.push([public_image(&*enc), public_image(&pks[i])].concat());
        cts.push((*enc, ss.ref_to_bytes().to_vec()));
    }
    scan.same(&op("auth_encaps_out"), &images[0], &images[1]);
    let mut images = Vec::new();
    for i in 0..2 {
        *sk = ECCDHPrivateKey::from_bytes(&keys[i]).unwrap();
        *enc = cts[0].0;
        scan.keep();
        assert_eq!(scan.run(|| sk.auth_decaps_out(&enc, &sender_pk, &mut ss)), Ok(SS));
        assert!(i == 1 || ss.ref_to_bytes() == &cts[0].1[..], "not the encapsulated secret");
        let mut values = key_values(&keys[i]);
        shared_values::<C, SK, PK, FE>(&mut values, "dh_e", &keys[i], &enc);
        shared_values::<C, SK, PK, FE>(&mut values, "dh_s", &keys[i], &sender_pk.encode());
        let (dh_e, dh_s) = (value(&values, "dh_e (bytes)"), value(&values, "dh_s (bytes)"));
        values.push(eae_prk::<C::KDFHash>(
            C::KEM_ID,
            &[&dh_e, &dh_s],
            &[&enc[..], &pks[i], &sender_pk.encode()],
            ss.ref_to_bytes(),
        ));
        values.push(("shared secret".to_string(), ss.ref_to_bytes().to_vec()));
        scan.clean(&op("auth_decaps_out"), &values);
        images.push([public_image(&*enc), public_image(&pks[i])].concat());
    }
    scan.same(&op("auth_decaps_out"), &images[0], &images[1]);
}

/// What a key of an X25519 or X448 DHKEM is searched for: its bytes as given and as encoded
/// (clamped). Its scalar arithmetic is in limbs of another radix, which the comparison of two
/// runs reaches and the search does not.
fn x_key_values<SKT: PrivateKey<N>, const N: usize>(name: &str, raw: &[u8]) -> Values {
    let encoded = SKT::from_bytes(raw).unwrap().encode();
    vec![(format!("{name} (bytes)"), raw.to_vec()), (format!("{name} (clamped)"), encoded.to_vec())]
}

/// The Diffie-Hellman output of the private key `raw` and `pk`, through the key's agreement.
fn x_dh<SKT, PKT, const N: usize>(raw: &[u8], pk: &PKT) -> Vec<u8>
where
    SKT: PrivateKey<N> + AgreementKey<(), N, PublicKey = PKT>,
{
    let mut z = KeyMaterial::<N>::new();
    SKT::from_bytes(raw).unwrap().agree_out(pk, (), &mut z).unwrap();
    z.ref_to_bytes().to_vec()
}

/// DHKEM over X25519 or X448 (RFC 9180 Section 7.1): `Encap`, `Decap`, `AuthEncap` and
/// `AuthDecap`, searched for the private keys, the RNG's output, each Diffie-Hellman output and
/// the shared secret, as [`dhkem`] does over the NIST curves.
fn dhkem_x<SKT, PKT, H: HMACParams, const N: usize, const SS: usize>(
    scan: &mut Scan,
    name: &str,
    kem_id: u16,
    keygen: fn(&mut dyn RNG) -> Result<(PKT, SKT), KeyAgreementError>,
) where
    SKT: PrivateKey<N>
        + DecapsulatingKey<(), N, SS>
        + AuthDecapsulatingKey<N, SS, SenderPublicKey = PKT>
        + AgreementKey<(), N, PublicKey = PKT>,
    PKT: PublicKey<N>
        + EncapsulatingKey<(), N, SS>
        + AuthEncapsulatingKey<N, SS, SenderPrivateKey = SKT>,
{
    let raw = |label: &str| bytes_of(&format!("{name} DHKEM {label}"), N);
    let pair = |raw: &[u8]| keygen(&mut rng_of(raw)).unwrap();
    let keys = [raw("recipient 0"), raw("recipient 1")];
    let sender = raw("sender");
    let e_draws = [raw("ephemeral 0"), raw("ephemeral 1")];
    let pks = keys.clone().map(|d| pair(&d).0);
    let (sender_pk, sender_sk) = pair(&sender);
    let sender_sk = Box::new(sender_sk);
    let mut rng = Box::new(rng_of(&e_draws[0]));
    // One allocation each, so that the two runs see the same addresses.
    let mut sk = Box::new(SKT::from_bytes(&keys[0]).unwrap());
    let mut pk_r = Box::new(PKT::from_bytes(&pks[0].encode()).unwrap());
    let mut enc = Box::new([0u8; N]);
    let mut ss = Box::new(KeyMaterial::<SS>::new());
    let op = |what: &str| format!("DHKEM {name} {what}");

    let mut cts = Vec::new();
    let mut images = Vec::new();
    for i in 0..2 {
        *pk_r = PKT::from_bytes(&pks[i].encode()).unwrap();
        *rng = rng_of(&e_draws[i]);
        scan.keep();
        assert_eq!(scan.run(|| pk_r.encaps_out(&mut *rng, (), &mut enc, &mut ss)), Ok(N));
        let mut values = x_key_values::<SKT, N>("ephemeral key", &e_draws[i]);
        values.push(("dh".to_string(), x_dh::<SKT, PKT, N>(&e_draws[i], &pks[i])));
        let dh = value(&values, "dh");
        values.push(eae_prk::<H>(kem_id, &[&dh], &[&enc[..], &pks[i].encode()], ss.ref_to_bytes()));
        values.push(("shared secret".to_string(), ss.ref_to_bytes().to_vec()));
        scan.clean(&op("encaps_out"), &values);
        images.push([&enc[..], &pks[i].encode()].concat());
        cts.push((*enc, ss.ref_to_bytes().to_vec()));
    }
    scan.same(&op("encaps_out"), &images[0], &images[1]);
    let mut images = Vec::new();
    for i in 0..2 {
        *sk = SKT::from_bytes(&keys[i]).unwrap();
        *enc = cts[0].0;
        scan.keep();
        assert_eq!(scan.run(|| sk.decaps_out(&enc, (), &mut ss)), Ok(SS));
        assert!(i == 1 || ss.ref_to_bytes() == &cts[0].1[..], "not the encapsulated secret");
        let mut values = x_key_values::<SKT, N>("d", &keys[i]);
        let pk_e = PKT::from_bytes(&enc[..]).unwrap();
        values.push(("dh".to_string(), x_dh::<SKT, PKT, N>(&keys[i], &pk_e)));
        let dh = value(&values, "dh");
        values.push(eae_prk::<H>(kem_id, &[&dh], &[&enc[..], &pks[i].encode()], ss.ref_to_bytes()));
        values.push(("shared secret".to_string(), ss.ref_to_bytes().to_vec()));
        scan.clean(&op("decaps_out"), &values);
        images.push([&enc[..], &pks[i].encode()].concat());
    }
    scan.same(&op("decaps_out"), &images[0], &images[1]);

    let mut cts = Vec::new();
    let mut images = Vec::new();
    for i in 0..2 {
        *pk_r = PKT::from_bytes(&pks[i].encode()).unwrap();
        *rng = rng_of(&e_draws[i]);
        scan.keep();
        assert_eq!(
            scan.run(|| pk_r.auth_encaps_out(&mut *rng, &sender_sk, &mut enc, &mut ss)),
            Ok(N)
        );
        let mut values = x_key_values::<SKT, N>("ephemeral key", &e_draws[i]);
        values.extend(x_key_values::<SKT, N>("sender's key", &sender));
        values.push(("dh_e".to_string(), x_dh::<SKT, PKT, N>(&e_draws[i], &pks[i])));
        values.push(("dh_s".to_string(), x_dh::<SKT, PKT, N>(&sender, &pks[i])));
        let (dh_e, dh_s) = (value(&values, "dh_e"), value(&values, "dh_s"));
        values.push(eae_prk::<H>(
            kem_id,
            &[&dh_e, &dh_s],
            &[&enc[..], &pks[i].encode(), &sender_pk.encode()],
            ss.ref_to_bytes(),
        ));
        values.push(("shared secret".to_string(), ss.ref_to_bytes().to_vec()));
        scan.clean(&op("auth_encaps_out"), &values);
        images.push([&enc[..], &pks[i].encode()].concat());
        cts.push((*enc, ss.ref_to_bytes().to_vec()));
    }
    scan.same(&op("auth_encaps_out"), &images[0], &images[1]);
    let mut images = Vec::new();
    for i in 0..2 {
        *sk = SKT::from_bytes(&keys[i]).unwrap();
        *enc = cts[0].0;
        scan.keep();
        assert_eq!(scan.run(|| sk.auth_decaps_out(&enc, &sender_pk, &mut ss)), Ok(SS));
        assert!(i == 1 || ss.ref_to_bytes() == &cts[0].1[..], "not the encapsulated secret");
        let mut values = x_key_values::<SKT, N>("d", &keys[i]);
        let pk_e = PKT::from_bytes(&enc[..]).unwrap();
        values.push(("dh_e".to_string(), x_dh::<SKT, PKT, N>(&keys[i], &pk_e)));
        values.push(("dh_s".to_string(), x_dh::<SKT, PKT, N>(&keys[i], &sender_pk)));
        let (dh_e, dh_s) = (value(&values, "dh_e"), value(&values, "dh_s"));
        values.push(eae_prk::<H>(
            kem_id,
            &[&dh_e, &dh_s],
            &[&enc[..], &pks[i].encode(), &sender_pk.encode()],
            ss.ref_to_bytes(),
        ));
        values.push(("shared secret".to_string(), ss.ref_to_bytes().to_vec()));
        scan.clean(&op("auth_decaps_out"), &values);
        images.push([&enc[..], &pks[i].encode()].concat());
    }
    scan.same(&op("auth_decaps_out"), &images[0], &images[1]);
}

/// `LabeledExtract` and `LabeledExpand` (`bouncycastle_ec::dhkem::hazmat`), over `H`: the KDF
/// steps of the DHKEMs and of HPKE's key schedule, here with a secret salt, IKM and PRK.
fn labeled<H: PadHash>(scan: &mut Scan, hash: &str) {
    let nh = <H as bouncycastle_core::traits::HashAlgParams>::OUTPUT_LEN;
    let suite_id = b"HPKE\x00\x10\x00\x01\x00\x01";
    let op = |name: &str| format!("DHKEM hazmat {hash} {name}");

    // The HMAC key of a secret salt, as HPKE's key schedule makes it from the shared secret.
    let mut key = Box::new(salt_key::<H>(&[]));
    for i in 0..2 {
        let salt = bytes_of(&format!("{hash} salt key {i}"), nh);
        scan.keep();
        *key = scan.run(|| salt_key::<H>(&salt));
        let mut values = pad_values::<H>("salt", &salt);
        values.push(("salt".to_string(), salt));
        scan.clean(&op("salt_key"), &values);
    }
    scan.same(&op("salt_key"), &[], &[]);

    let mut prk = Box::new([0u8; MAX_NH]);
    for i in 0..2 {
        let salt = bytes_of(&format!("{hash} salt {i}"), nh);
        let ikm = bytes_of(&format!("{hash} ikm {i}"), nh);
        *key = salt_key::<H>(&salt);
        scan.keep();
        let len =
            scan.run(|| labeled_extract_out::<H>(suite_id, &key, b"secret", &[&ikm], &mut prk));
        assert_eq!(len, nh);
        let mut values = pad_values::<H>("salt", &salt);
        values.push(("salt".to_string(), salt));
        values.push(("ikm".to_string(), ikm));
        values.push(("prk".to_string(), prk[..nh].to_vec()));
        scan.clean(&op("labeled_extract_out"), &values);
    }
    scan.same(&op("labeled_extract_out"), &[], &[]);
    let mut okm = Box::new([0u8; 80]);
    for i in 0..2 {
        let prk_bytes = bytes_of(&format!("{hash} prk {i}"), nh);
        let prk = Box::new(
            KeyMaterial::<MAX_NH>::from_bytes_as_type(&prk_bytes, KeyType::MACKey).unwrap(),
        );
        scan.keep();
        assert_eq!(
            scan.run(|| labeled_expand::<H>(suite_id, &prk, b"key", &[b"context"], &mut okm[..])),
            80
        );
        let mut values = pad_values::<H>("prk", &prk_bytes);
        values.push(("prk".to_string(), prk_bytes));
        values.push(("okm".to_string(), okm.to_vec()));
        scan.clean(&op("labeled_expand"), &values);
    }
    scan.same(&op("labeled_expand"), &[], &[]);
}

/// A hash whose HMAC pad states the harness computes: its block length, and its chaining value
/// after one block, read from its suspended state (after the three-byte version prefix, the
/// state words in little-endian order, as they lie in memory here).
trait PadHash: HMACParams {
    const BLOCK: usize;
    fn chaining_value(block: &[u8]) -> Vec<u8>;
}

impl PadHash for SHA256 {
    const BLOCK: usize = 64;
    fn chaining_value(block: &[u8]) -> Vec<u8> {
        let mut hash = SHA256::default();
        hash.do_update(block);
        hash.suspend()[3..3 + 32].to_vec()
    }
}

impl PadHash for SHA384 {
    const BLOCK: usize = 128;
    fn chaining_value(block: &[u8]) -> Vec<u8> {
        let mut hash = SHA384::default();
        hash.do_update(block);
        hash.suspend()[3..3 + 64].to_vec()
    }
}

impl PadHash for SHA512 {
    const BLOCK: usize = 128;
    fn chaining_value(block: &[u8]) -> Vec<u8> {
        let mut hash = SHA512::default();
        hash.do_update(block);
        hash.suspend()[3..3 + 64].to_vec()
    }
}

/// The inner and outer pad states of the HMAC key `key` (RFC 2104 Section 2): what an HMAC
/// key holds, and as good as the key to whoever finds them.
fn pad_values<H: PadHash>(name: &str, key: &[u8]) -> Values {
    let state = |pad: u8| {
        let mut block = vec![pad; H::BLOCK];
        for (b, k) in block.iter_mut().zip(key) {
            *b ^= k;
        }
        H::chaining_value(&block)
    };
    vec![
        (format!("{name}'s inner pad state"), state(0x36)),
        (format!("{name}'s outer pad state"), state(0x5c)),
    ]
}
