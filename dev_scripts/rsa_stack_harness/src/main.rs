//! What the private-key operations of bouncycastle_modexp::rsa leave on the dead stack, for
//! `../check_rsa_stack.sh`. For each operation the stack below the call is painted, the
//! operation run with its results going to the heap or to a live frame above, the dead stack
//! copied out, and the copy searched for the 8-byte words of every secret the operation
//! handled: the key's components as limbs and as encoded bytes, the Montgomery constants of p
//! and q, the intermediates of the CRT, and what a decryption recovers and derives. The key is
//! generated when the program starts, so the values are computed here, with the crate's public
//! arithmetic, and checked against the operation's own output before they are searched for.
//!
//! Two controls: nothing run must leave nothing, and a copy of p left in a frame must be found.
//!
//!   target/release/rsa_stack_harness [2048|3072|4096|8192]
//!
//! One line per operation, `ok` or `FAIL`; the exit status is 1 if anything failed.
use bouncycastle_core::kdf_params::{KdfParams, KeyLen};
use bouncycastle_core::kem_key::{DecapsulatingKey, EncapsulatingKey};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterial0, KeyMaterialTrait};
use bouncycastle_core::key_transport_key::KeyTransportDecryptingKey;
use bouncycastle_core::signature_key::{
    DeterministicOneShotSigningKey, DeterministicSigningKey, OneShotSigningKey, SigningKey,
};
use bouncycastle_core::traits::{PrivateKey, SignatureSigner};
use bouncycastle_digest::hkdf::{HKDF, HkdfDescription};
use bouncycastle_digest::sha2::SHA256;
use bouncycastle_modexp::rsa::keygen::is_probable_prime;
use bouncycastle_modexp::rsa::keys::{RsaPrivateComponents, RsaPrivateKey};
use bouncycastle_modexp::rsa::modexp::{
    MontgomeryContext, mod_pow, mod_pow_public_exponent, mul_mod, reduce_wide, sub_mod,
};
use bouncycastle_modexp::rsa::rsaes_oaep::OaepParams;
use bouncycastle_modexp::rsa::rsassa;
use bouncycastle_modexp::rsa::rsassa_pkcs1_v1_5::RSASSA_PKCS1_v1_5;
use bouncycastle_modexp::rsa::rsassa_pss::RSASSA_PSS;
use bouncycastle_modexp::rsa::rsasve::{RsaKEMPrivateKey, RsaKEMPublicKey};
use bouncycastle_modexp::rsa::size::{KemKeyPair, RsaSigningSize, RsaSize, SignatureKeyPair};
use bouncycastle_modexp::rsa::{RSA2048, RSA3072, RSA4096, RSA8192};
use bouncycastle_rng::DefaultRNG;
use std::collections::HashSet;
use std::hint::black_box;
use std::num::NonZeroUsize;

/// How far below the call the stack is painted and searched. Key generation at RSA-8192, the
/// deepest operation here, uses under 50 KiB.
const DEPTH: usize = 512 * 1024;
/// The gap between the frame that takes the copy and the operation's first frame.
const PAD: usize = 16 * 1024;
const PAINT: u8 = 0xA5;

const MSG: &[u8] = b"what a private-key operation leaves on the stack";
const DIGEST: [u8; 32] = [0x3c; 32];
const SALT: [u8; 32] = [0x71; 32];

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
        // are mapped, `paint` having written every byte of them, and on x86-64 Linux nothing
        // else writes below the stack pointer of a thread that takes no signal.
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
fn leak<const N: usize>(value: &[u64; N]) {
    let mut local = *value;
    black_box(&mut local);
}

/// A named secret, as the bytes it would be in memory.
type Values = Vec<(String, Vec<u8>)>;

/// Limbs as they lie in memory.
fn limb_image(limbs: &[u64]) -> Vec<u8> {
    limbs.iter().flat_map(|limb| limb.to_ne_bytes()).collect()
}

/// Limbs as the big-endian byte string an encoding holds them in.
fn be_of_limbs(limbs: &[u64]) -> Vec<u8> {
    limbs.iter().rev().flat_map(|limb| limb.to_be_bytes()).collect()
}

/// A big-endian byte string of `8 * N` bytes as limbs.
fn limbs_from_be<const N: usize>(bytes: &[u8]) -> [u64; N] {
    assert_eq!(bytes.len(), 8 * N);
    let mut limbs = [0u64; N];
    for (limb, chunk) in limbs.iter_mut().zip(bytes.rchunks_exact(8)) {
        *limb = u64::from_be_bytes(chunk.try_into().unwrap());
    }
    limbs
}

/// A byte string as SHA-256's message schedule holds it: each 32-bit word's bytes reversed.
fn sha256_words(bytes: &[u8]) -> Vec<u8> {
    bytes.chunks_exact(4).flat_map(|word| word.iter().rev().copied()).collect()
}

/// An integer, as limbs and as its big-endian encoding.
fn push_integer(values: &mut Values, name: &str, limbs: &[u64]) {
    values.push((name.to_string(), limb_image(limbs)));
    values.push((format!("{name} (bytes)"), be_of_limbs(limbs)));
}

/// A byte string, as it is and as a hash that reads it has it.
fn push_bytes(values: &mut Values, name: &str, bytes: &[u8]) {
    values.push((name.to_string(), bytes.to_vec()));
    values.push((format!("{name} (SHA-256 words)"), sha256_words(bytes)));
}

/// The five secret components of a private key.
struct Key<const H: usize> {
    p: [u64; H],
    q: [u64; H],
    d_p: [u64; H],
    d_q: [u64; H],
    q_inv: [u64; H],
}

impl<const H: usize> Key<H> {
    /// From the encoding `p || q || dP || dQ || qInv || e`.
    fn from_encoding(encoded: &[u8]) -> Self {
        let field = |i: usize| limbs_from_be::<H>(&encoded[8 * H * i..8 * H * (i + 1)]);
        Self { p: field(0), q: field(1), d_p: field(2), d_q: field(3), q_inv: field(4) }
    }

    /// The components, and the constants of the Montgomery contexts over p and q, `R mod m`
    /// and `R^2 mod m` for `R = 2^(64 * H)`: what every operation is searched for.
    fn values<const H2: usize, const H21: usize>(&self) -> Values {
        let mut values = Values::new();
        push_integer(&mut values, "p", &self.p);
        push_integer(&mut values, "q", &self.q);
        push_integer(&mut values, "dP", &self.d_p);
        push_integer(&mut values, "dQ", &self.d_q);
        push_integer(&mut values, "qInv", &self.q_inv);
        let mut r = [0u64; H2];
        r[H] = 1;
        let mut r2 = [0u64; H21];
        r2[H2] = 1;
        for (name, modulus) in [("p", &self.p), ("q", &self.q)] {
            values.push((format!("R mod {name}"), limb_image(&reduce_wide::<H2, H>(&r, modulus))));
            values.push((
                format!("R^2 mod {name}"),
                limb_image(&reduce_wide::<H21, H>(&r2, modulus)),
            ));
        }
        values
    }

    /// [`Self::values`] and the intermediates of `x^d mod n` by the CRT (RFC 8017 Section
    /// 5.1.2 step 2.b), and the result, which is returned for the caller to check against what
    /// the operation gave and to add to the search where it is a secret.
    fn crt_values<const H2: usize, const H21: usize>(&self, x: &[u64; H2]) -> (Values, [u64; H2]) {
        let ctx_p = MontgomeryContext::<H>::for_secret_modulus(&self.p);
        let ctx_q = MontgomeryContext::<H>::for_secret_modulus(&self.q);
        let x_mod_p = reduce_wide::<H2, H>(x, &self.p);
        let x_mod_q = reduce_wide::<H2, H>(x, &self.q);
        let s1 = mod_pow::<H, H2, H21>(&x_mod_p, &self.d_p, &ctx_p);
        let s2 = mod_pow::<H, H2, H21>(&x_mod_q, &self.d_q, &ctx_q);
        let s2_mod_p = reduce_wide::<H, H>(&s2, &self.p);
        let h = mul_mod::<H, H2, H21>(&self.q_inv, &sub_mod(&s1, &s2_mod_p, &self.p), &ctx_p);
        // q * h, then y = s2 + q * h.
        let mut qh = [0u64; H2];
        for i in 0..H {
            let mut carry = 0u128;
            for j in 0..H {
                let t = u128::from(qh[i + j]) + u128::from(self.q[i]) * u128::from(h[j]) + carry;
                qh[i + j] = t as u64;
                carry = t >> 64;
            }
            qh[i + H] = carry as u64;
        }
        let mut y = qh;
        let mut carry = 0u128;
        for i in 0..H2 {
            let t = u128::from(y[i]) + if i < H { u128::from(s2[i]) } else { 0 } + carry;
            y[i] = t as u64;
            carry = t >> 64;
        }
        let mut values = self.values::<H2, H21>();
        values.push(("x mod p".into(), limb_image(&x_mod_p)));
        values.push(("x mod q".into(), limb_image(&x_mod_q)));
        values.push(("s1".into(), limb_image(&s1)));
        values.push(("s2".into(), limb_image(&s2)));
        values.push(("h".into(), limb_image(&h)));
        // The low half only: the high half is the result's own, give or take a carry, and a
        // signature is not a secret.
        values.push(("q*h (low half)".into(), limb_image(&qh[..H])));
        (values, y)
    }
}

/// The painted stack's copy, and the count of what failed.
struct Scan {
    buf: Vec<u8>,
    failures: usize,
}

impl Scan {
    fn new() -> Self {
        Self { buf: vec![0u8; DEPTH], failures: 0 }
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
            // A word of one repeated byte (a zero limb, padding) says nothing when found.
            let words: Vec<&[u8]> =
                image.chunks_exact(8).filter(|w| w.iter().any(|b| *b != w[0])).collect();
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
}

/// Every operation at one size. `$HALF` is the limbs of a prime; the function returns the
/// count of what failed.
macro_rules! scan_size {
    ($name:ident, $K:ty, $HALF:literal) => {
        fn $name() -> usize {
            const H: usize = $HALF;
            const H2: usize = 2 * H;
            const H21: usize = 2 * H + 1;
            const H4: usize = 4 * H;
            const H41: usize = 4 * H + 1;
            const K_LEN: usize = 16 * H;
            const SK_LEN: usize = 40 * H + 8;
            type V15 = RSASSA_PKCS1_v1_5<$K, SHA256>;
            type Pss = RSASSA_PSS<$K, SHA256>;
            let limbs_of = |bytes: &[u8; K_LEN]| <$K>::limbs_from_be_bytes(bytes);

            let mut scan = Scan::new();
            let mut rng = Box::new(DefaultRNG::default());

            // Key generation, and the key the rest runs over.
            let pair = scan.run(|| <$K>::keygen(&mut *rng));
            let components = Box::new(pair.unwrap().1);
            let sk_v15: Box<RsaPrivateKey<V15>> = Box::new(components.key());
            let sk_pss: Box<RsaPrivateKey<Pss>> = Box::new(components.key());
            let encoded: Box<[u8; SK_LEN]> = Box::new(sk_pss.encode());
            let key = Key::<H>::from_encoding(&encoded[..]);
            let secrets = key.values::<H2, H21>();
            scan.clean("key generation (keygen)", &secrets);

            let pair = scan.run(|| <$K>::generate_pss_signature_key_pair::<SHA256>(&mut *rng));
            let other: Box<[u8; SK_LEN]> = Box::new(pair.unwrap().1.encode());
            scan.clean(
                "key generation (generate_pss_signature_key_pair)",
                &Key::<H>::from_encoding(&other[..]).values::<H2, H21>(),
            );
            let pair = scan.run(|| <$K>::generate_kem_key_pair(&mut *rng));
            let other: Box<[u8; SK_LEN]> = Box::new(pair.unwrap().1.encode());
            scan.clean(
                "key generation (generate_kem_key_pair)",
                &Key::<H>::from_encoding(&other[..]).values::<H2, H21>(),
            );

            // The controls.
            scan.run(|| {});
            scan.clean("control, nothing run", &secrets);
            scan.run(|| leak(&key.p));
            scan.leaked("control, a copy of p left in a frame", &vec![secrets[0].clone()]);

            // Key handling.
            let (p, q, d_p, d_q, q_inv, e) =
                (&key.p, &key.q, &key.d_p, &key.d_q, &key.q_inv, components.e());
            let kept = scan
                .run(|| RsaPrivateComponents::<$K>::from_crt_components(p, q, d_p, d_q, q_inv, e));
            black_box(&kept);
            scan.clean("from_crt_components (components)", &secrets);
            let kept =
                scan.run(|| RsaPrivateKey::<Pss>::from_crt_components(p, q, d_p, d_q, q_inv, e));
            black_box(&kept);
            scan.clean("from_crt_components (signature key)", &secrets);
            let kept =
                scan.run(|| RsaKEMPrivateKey::<$K>::from_crt_components(p, q, d_p, d_q, q_inv, e));
            black_box(&kept);
            scan.clean("from_crt_components (key-establishment key)", &secrets);
            let kept = scan.run(|| RsaPrivateKey::<Pss>::from_bytes(&encoded[..]));
            black_box(&kept);
            scan.clean("from_bytes (signature key)", &secrets);
            let kept = scan.run(|| RsaKEMPrivateKey::<$K>::from_bytes(&encoded[..]));
            let sk_kem = Box::new(kept.unwrap());
            scan.clean("from_bytes (key-establishment key)", &secrets);
            let mut out: Box<[u8; SK_LEN]> = Box::new([0u8; SK_LEN]);
            scan.run(|| {
                sk_pss.encode_out(&mut out);
            });
            scan.clean("encode_out", &secrets);
            let kept = scan.run(|| sk_pss.encode());
            black_box(&kept);
            scan.clean("encode", &secrets);
            let kept = scan.run(|| (*components).clone());
            black_box(&kept);
            scan.clean("clone (components)", &secrets);
            let kept: RsaPrivateKey<Pss> = scan.run(|| components.key());
            black_box(&kept);
            scan.clean("components.key()", &secrets);
            let kept = scan.run(|| (*sk_pss).clone());
            black_box(&kept);
            scan.clean("clone (key)", &secrets);

            // Signing. The representative that was signed is the signature under the public
            // key, and the CRT over it must give the signature back.
            let mut sig: Box<[u8; K_LEN]> = Box::new([0u8; K_LEN]);
            let signed = |sig: &[u8; K_LEN]| {
                let s = limbs_of(sig);
                let (values, y) =
                    key.crt_values::<H2, H21>(&mod_pow_public_exponent::<H2, H4, H41>(
                        &s,
                        e,
                        &MontgomeryContext::<H2>::for_public_modulus(components.n()).unwrap(),
                    ));
                assert_eq!(y, s, "the harness's CRT is not the library's");
                values
            };
            scan.run(|| {
                sk_v15.sign_deterministic_out(MSG, None, &mut sig).unwrap();
            });
            scan.clean("PKCS#1 v1.5 sign_deterministic_out", &signed(&sig));
            scan.run(|| {
                let mut signer = sk_v15.create_signer_deterministic(None).unwrap();
                signer.do_update(MSG);
                signer.do_final_out(&mut sig).unwrap();
            });
            scan.clean("PKCS#1 v1.5 streaming", &signed(&sig));
            let made = scan.run(|| rsassa::sign_from_hash_deterministic(&*sk_v15, &DIGEST));
            scan.clean("PKCS#1 v1.5 sign_from_hash_deterministic", &signed(&made.unwrap()));
            scan.run(|| {
                sk_pss.sign_out(&mut *rng, MSG, None, &mut sig).unwrap();
            });
            scan.clean("PSS sign_out", &signed(&sig));
            scan.run(|| {
                let mut signer = sk_pss.create_signer(&mut *rng, None).unwrap();
                signer.do_update(MSG);
                signer.do_final_out(&mut sig).unwrap();
            });
            scan.clean("PSS streaming", &signed(&sig));
            let made = scan.run(|| rsassa::sign_from_hash_with_salt(&*sk_pss, &DIGEST, &SALT));
            scan.clean("PSS sign_from_hash_with_salt", &signed(&made.unwrap()));

            // RSASVE. What decryption recovers is a secret too: the CRT's result, as limbs and
            // as the bytes handed out.
            let recovered = |ct: &[u8; K_LEN], name: &str| {
                let (mut values, y) = key.crt_values::<H2, H21>(&limbs_of(ct));
                push_integer(&mut values, name, &y);
                (values, y)
            };
            let pk_kem = Box::new(RsaKEMPublicKey::<$K>::new(components.n(), e).unwrap());
            let mut ct: Box<[u8; K_LEN]> = Box::new([0u8; K_LEN]);
            let mut z: Box<KeyMaterial<K_LEN>> = Box::new(KeyMaterial::new());
            pk_kem.encaps_out(&mut *rng, (), &mut ct, &mut z).unwrap();
            scan.run(|| {
                sk_kem.decaps_out(&ct, (), &mut z).unwrap();
            });
            let (mut values, y) = recovered(&ct, "Z");
            assert_eq!(z.ref_to_bytes(), be_of_limbs(&y), "the harness's CRT is not the library's");
            scan.clean("RSASVE decaps_out", &values);

            // RSASVE with HKDF: Z as SHA-256 reads it, the pseudorandom key and the derived key.
            let hkdf = HkdfDescription::<SHA256>::new();
            let mut derived: Box<KeyMaterial<32>> = Box::new(KeyMaterial::new());
            let derivation = |z: &KeyMaterial<K_LEN>, derived: &KeyMaterial<32>| {
                let no_salt = KeyMaterial0::new();
                let prk = HKDF::<SHA256>::extract(&no_salt, z).unwrap();
                let mut okm = KeyMaterial::<32>::new();
                HKDF::<SHA256>::expand_out(&prk, b"info", 32, &mut okm).unwrap();
                assert_eq!(okm.ref_to_bytes(), derived.ref_to_bytes(), "not the library's HKDF");
                let mut values = Values::new();
                push_bytes(&mut values, "Z", z.ref_to_bytes());
                push_bytes(&mut values, "pseudorandom key", prk.ref_to_bytes());
                push_bytes(&mut values, "derived key", derived.ref_to_bytes());
                values
            };
            scan.run(|| {
                let params = KdfParams::new(&hkdf, b"info", KeyLen::<32>);
                sk_kem.decaps_out(&ct, params, &mut derived).unwrap();
            });
            values.extend(derivation(&z, &derived));
            scan.clean("RSASVE with HKDF decaps_out", &values);

            // The one public-key operation here: it derives the same key.
            let mut ct_kdf: Box<[u8; K_LEN]> = Box::new([0u8; K_LEN]);
            scan.run(|| {
                let params = KdfParams::new(&hkdf, b"info", KeyLen::<32>);
                pk_kem.encaps_out(&mut *rng, params, &mut ct_kdf, &mut derived).unwrap();
            });
            let mut z_kdf: Box<KeyMaterial<K_LEN>> = Box::new(KeyMaterial::new());
            sk_kem.decaps_out(&ct_kdf, (), &mut z_kdf).unwrap();
            let mut values = derivation(&z_kdf, &derived);
            push_integer(&mut values, "Z", &limbs_of(z_kdf.ref_to_bytes().try_into().unwrap()));
            scan.clean("RSASVE with HKDF encaps_out", &values);

            // RSAES-OAEP: the encoded message is what the CRT recovers.
            let oaep = || OaepParams::<SHA256>::new(b"");
            let mut ct_oaep: Box<[u8; K_LEN]> = Box::new([0u8; K_LEN]);
            let mut sent: Box<KeyMaterial<32>> = Box::new(KeyMaterial::new());
            pk_kem.encaps_out(&mut *rng, oaep(), &mut ct_oaep, &mut sent).unwrap();
            let (mut values, _) = recovered(&ct_oaep, "EM");
            push_bytes(&mut values, "transported key", sent.ref_to_bytes());
            let mut key32: Box<KeyMaterial<32>> = Box::new(KeyMaterial::new());
            scan.run(|| {
                sk_kem.decaps_out(&ct_oaep, oaep(), &mut key32).unwrap();
            });
            assert_eq!(key32.ref_to_bytes(), sent.ref_to_bytes());
            scan.clean("RSAES-OAEP decaps_out", &values);
            let mut key64: Box<KeyMaterial<64>> = Box::new(KeyMaterial::new());
            scan.run(|| {
                sk_kem.recover_out(&ct_oaep, oaep(), &mut key64).unwrap();
            });
            scan.clean("RSAES-OAEP recover_out", &values);
            // A ciphertext the decoding refuses: RSASVE's, whose "encoded message" is Z.
            scan.run(|| {
                assert!(sk_kem.recover_out(&ct, oaep(), &mut key64).is_err());
            });
            scan.clean("RSAES-OAEP recover_out, ciphertext refused", &recovered(&ct, "EM").0);

            // The primality test, as a caller would run it over an imported key's prime.
            let verdict = scan.run(|| {
                is_probable_prime::<H, H2, H21>(&key.p, NonZeroUsize::new(5).unwrap(), &mut *rng)
            });
            assert_eq!(verdict, Ok(true));
            scan.clean("is_probable_prime (p)", &secrets);

            // Validation of the key pair, as a caller would ask of an imported key.
            let verdict = scan.run(|| components.validate(&mut *rng));
            assert_eq!(verdict, Ok(()));
            scan.clean("validate", &secrets);

            scan.failures
        }
    };
}

scan_size!(scan_2048, RSA2048, 16);
scan_size!(scan_3072, RSA3072, 24);
scan_size!(scan_4096, RSA4096, 32);
scan_size!(scan_8192, RSA8192, 64);

fn main() {
    let size = std::env::args().nth(1).unwrap_or_else(|| "2048".into());
    let failures = match size.as_str() {
        "2048" => scan_2048(),
        "3072" => scan_3072(),
        "4096" => scan_4096(),
        "8192" => scan_8192(),
        _ => panic!("usage: rsa_stack_harness [2048|3072|4096|8192]"),
    };
    std::process::exit(if failures == 0 { 0 } else { 1 });
}
