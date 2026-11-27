//! Ed25519 and Ed448 (`bouncycastle_ec::ed::{ed25519, ed448}`), and X25519 and X448 agreement
//! (`bouncycastle_ec::ed::{x25519, x448}`), run over the painted stack as the rest of the harness
//! runs ECDSA. An EdDSA key is searched for its private key, the digest it is expanded from and
//! the scalar `s` and `prefix` taken from that, and a signature also for the digest of step 2 and
//! the nonce `r` (RFC 8032 Sections 5.1.6 and 5.2.6), each computed here and checked against the
//! signature, `S = r + k s mod L`, before it is searched for. An X25519 or X448 key is searched
//! for its bytes as given and clamped, and an agreement also for `K`.
use crate::{Scan, Values, bytes_of, message, rng_of};
use bouncycastle_core::agreement_key::AgreementKey;
use bouncycastle_core::errors::{KeyAgreementError, KeyDecodingError, SignatureError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::signature_key::{
    DeterministicOneShotSigningKey, DeterministicSigningKey, OneShotVerifyingKey,
};
use bouncycastle_core::traits::{
    Hash, PrivateKey, PublicKey, RNG, SignatureSigner, Suspendable, XOF, XOFSqueezer,
};
use bouncycastle_digest::sha2::SHA512;
use bouncycastle_digest::sha3::SHAKE256;
use bouncycastle_ec::ed::ed448::{self, Ed448, Ed448PrivateKey, Ed448PublicKey, Ed448ph};
use bouncycastle_ec::ed::ed25519::{self, Ed25519, Ed25519PrivateKey, Ed25519PublicKey, Ed25519ph};
use bouncycastle_ec::ed::x448::{self, X448PrivateKey, X448PublicKey};
use bouncycastle_ec::ed::x25519::{self, X25519PrivateKey, X25519PublicKey};

/// Hexadecimal, for the RFC vectors.
fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// A value as a SHA-512 state or message schedule holds it: 64-bit big-endian words, each in
/// the other byte order in memory.
fn word_swapped(bytes: &[u8]) -> Vec<u8> {
    bytes.chunks(8).flat_map(|w| w.iter().rev().copied()).collect()
}

/// The little-endian integer `le` as `count` limbs of `bits` bits, each in a 64-bit word: a
/// field element of the curve25519 (51) or curve448 (56) arithmetic.
fn radix_limbs(le: &[u8], bits: usize, count: usize) -> Vec<u8> {
    let bit = |i: usize| i / 8 < le.len() && le[i / 8] >> (i % 8) & 1 == 1;
    (0..count)
        .flat_map(|l| {
            let limb = (0..bits).fold(0u64, |acc, j| acc | (u64::from(bit(l * bits + j)) << j));
            limb.to_le_bytes()
        })
        .collect()
}

/// Unsigned integers as 32-bit limbs, least significant first: only what the checks need.
type Big = Vec<u32>;

fn big(le: &[u8]) -> Big {
    let mut b: Big = le
        .chunks(4)
        .map(|c| c.iter().rev().fold(0u32, |acc, byte| acc << 8 | u32::from(*byte)))
        .collect();
    trim(&mut b);
    b
}

fn trim(b: &mut Big) {
    while b.last() == Some(&0) {
        b.pop();
    }
}

fn le_bytes(b: &Big, len: usize) -> Vec<u8> {
    let mut out: Vec<u8> = b.iter().flat_map(|l| l.to_le_bytes()).collect();
    assert!(out.iter().skip(len).all(|byte| *byte == 0));
    out.resize(len, 0);
    out
}

fn big_cmp(a: &Big, b: &Big) -> std::cmp::Ordering {
    a.len().cmp(&b.len()).then_with(|| a.iter().rev().cmp(b.iter().rev()))
}

fn big_add(a: &Big, b: &Big) -> Big {
    let mut out = Big::new();
    let mut carry = 0u64;
    for i in 0..a.len().max(b.len()) {
        let sum = u64::from(*a.get(i).unwrap_or(&0)) + u64::from(*b.get(i).unwrap_or(&0)) + carry;
        out.push(sum as u32);
        carry = sum >> 32;
    }
    out.push(carry as u32);
    trim(&mut out);
    out
}

/// `a - b`, for `a >= b`.
fn big_sub(a: &Big, b: &Big) -> Big {
    let mut out = Big::new();
    let mut borrow = 0i64;
    for i in 0..a.len() {
        let diff = i64::from(a[i]) - i64::from(*b.get(i).unwrap_or(&0)) - borrow;
        out.push(diff.rem_euclid(1 << 32) as u32);
        borrow = i64::from(diff < 0);
    }
    assert_eq!(borrow, 0);
    trim(&mut out);
    out
}

fn big_mul(a: &Big, b: &Big) -> Big {
    let mut out = vec![0u32; a.len() + b.len() + 1];
    for (i, x) in a.iter().enumerate() {
        let mut carry = 0u64;
        for (j, y) in b.iter().enumerate() {
            let t = u64::from(*x) * u64::from(*y) + u64::from(out[i + j]) + carry;
            out[i + j] = t as u32;
            carry = t >> 32;
        }
        out[i + b.len()] = carry as u32;
    }
    trim(&mut out);
    out
}

/// `a mod m`, a bit at a time.
fn big_mod(a: &Big, m: &Big) -> Big {
    let mut r = Big::new();
    for i in (0..32 * a.len()).rev() {
        r = big_add(&r, &r);
        if a[i / 32] >> (i % 32) & 1 == 1 {
            r = big_add(&r, &vec![1]);
        }
        if big_cmp(&r, m).is_ge() {
            r = big_sub(&r, m);
        }
    }
    r
}

fn big_dec(s: &str) -> Big {
    s.bytes()
        .fold(Big::new(), |acc, d| big_add(&big_mul(&acc, &vec![10]), &vec![u32::from(d - b'0')]))
}

fn big_pow2(e: usize) -> Big {
    let mut b = vec![0u32; e / 32 + 1];
    b[e / 32] = 1 << (e % 32);
    b
}

/// What the harness needs of an EdDSA scheme over and above the key traits: its keys'
/// inherent functions and roles, and the reference computation of RFC 8032.
pub(crate) trait EdScheme<const SK: usize, const PK: usize, const SIG: usize>:
    PrivateKey<SK> + Clone + PartialEq
{
    type Pk: PublicKey<PK>;
    const NAME: &'static str;
    /// The length of the scalar and of the prefix.
    const HALF: usize;
    /// The bits of a field element's limbs, and how many there are.
    const LIMB_BITS: usize;
    const LIMBS: usize;
    /// RFC 8032's first test vector of the scheme: private key, public key, message, context,
    /// signature.
    const VECTOR: [&'static str; 5];
    /// The context the scheme itself signs with: none for Ed25519 (RFC 8032 Section 5.1).
    const CONTEXT: &'static [u8];

    fn keygen(rng: &mut dyn RNG) -> Result<(Self::Pk, Self), SignatureError>;
    fn keygen_out(rng: &mut dyn RNG, sk: &mut Self) -> Result<(), SignatureError>;
    fn zeroized() -> Self;
    fn from_bytes_out(bytes: &[u8], sk: &mut Self) -> Result<(), KeyDecodingError>;
    fn pk(&self) -> Self::Pk;
    fn consistent(pk: &Self::Pk, sk: &Self) -> bool;
    fn sign_out(&self, msg: &[u8], ctx: Option<&[u8]>, sig: &mut [u8; SIG]) -> usize;
    fn sign(&self, msg: &[u8], ctx: Option<&[u8]>) -> [u8; SIG];
    fn sign_ph_out(&self, msg: &[u8], ctx: Option<&[u8]>, sig: &mut [u8; SIG]) -> usize;
    fn sign_ph(&self, msg: &[u8], ctx: Option<&[u8]>) -> [u8; SIG];
    fn ph_signer<'a>(&'a self, ctx: Option<&[u8]>) -> Box<dyn SignatureSigner<SIG> + 'a>;
    fn verifies(pk: &Self::Pk, msg: &[u8], ctx: Option<&[u8]>, sig: &[u8], ph: bool) -> bool;

    /// `H(x)` of the scheme, over the concatenation of `parts`, without `dom`.
    fn hash(parts: &[&[u8]]) -> Vec<u8>;
    /// The images of a digest as the hash holds it.
    fn digest_images(name: &str, digest: &[u8], values: &mut Values);
    /// The chaining values the hash passes through over `input`, as they lie in memory.
    fn chaining_values(input: &[u8]) -> Vec<u8>;
    /// `PH(M)` of the pre-hash variant.
    fn prehash(msg: &[u8]) -> Vec<u8>;
    /// `dom2(F, C)` or `dom4(F, C)`.
    fn dom(ph: bool, ctx: &[u8]) -> Vec<u8>;
    /// RFC 8032 Section 5.1.5 or 5.2.5, step 2.
    fn prune(s: &mut [u8]);
    fn order() -> Big;
}

impl EdScheme<32, 32, 64> for Ed25519PrivateKey {
    type Pk = Ed25519PublicKey;
    const NAME: &'static str = "Ed25519";
    const HALF: usize = 32;
    const LIMB_BITS: usize = 51;
    const LIMBS: usize = 5;
    const CONTEXT: &'static [u8] = b"";
    // RFC 8032 Section 7.1, TEST 1.
    const VECTOR: [&'static str; 5] = [
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bac\
         c61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ];

    fn keygen(rng: &mut dyn RNG) -> Result<(Self::Pk, Self), SignatureError> {
        ed25519::keygen(rng)
    }
    fn keygen_out(rng: &mut dyn RNG, sk: &mut Self) -> Result<(), SignatureError> {
        ed25519::keygen_out(rng, sk)
    }
    fn zeroized() -> Self {
        Ed25519PrivateKey::zeroized()
    }
    fn from_bytes_out(bytes: &[u8], sk: &mut Self) -> Result<(), KeyDecodingError> {
        Ed25519PrivateKey::from_bytes_out(bytes, sk)
    }
    fn pk(&self) -> Self::Pk {
        Ed25519PrivateKey::pk(self).unwrap()
    }
    fn consistent(pk: &Self::Pk, sk: &Self) -> bool {
        ed25519::keypair_consistency_check(pk, sk).is_ok()
    }
    fn sign_out(&self, msg: &[u8], ctx: Option<&[u8]>, sig: &mut [u8; 64]) -> usize {
        DeterministicOneShotSigningKey::<Ed25519, 64>::sign_deterministic_out(self, msg, ctx, sig)
            .unwrap()
    }
    fn sign(&self, msg: &[u8], ctx: Option<&[u8]>) -> [u8; 64] {
        DeterministicOneShotSigningKey::<Ed25519, 64>::sign_deterministic(self, msg, ctx).unwrap()
    }
    fn sign_ph_out(&self, msg: &[u8], ctx: Option<&[u8]>, sig: &mut [u8; 64]) -> usize {
        DeterministicOneShotSigningKey::<Ed25519ph, 64>::sign_deterministic_out(
            &self.as_prehash(),
            msg,
            ctx,
            sig,
        )
        .unwrap()
    }
    fn sign_ph(&self, msg: &[u8], ctx: Option<&[u8]>) -> [u8; 64] {
        DeterministicOneShotSigningKey::<Ed25519ph, 64>::sign_deterministic(
            &self.as_prehash(),
            msg,
            ctx,
        )
        .unwrap()
    }
    fn ph_signer<'a>(&'a self, ctx: Option<&[u8]>) -> Box<dyn SignatureSigner<64> + 'a> {
        Box::new(self.as_prehash().create_signer_deterministic(ctx).unwrap())
    }
    fn verifies(pk: &Self::Pk, msg: &[u8], ctx: Option<&[u8]>, sig: &[u8], ph: bool) -> bool {
        if ph {
            OneShotVerifyingKey::<Ed25519ph, 64>::verify(&pk.as_prehash(), msg, ctx, sig).is_ok()
        } else {
            OneShotVerifyingKey::<Ed25519, 64>::verify(pk, msg, ctx, sig).is_ok()
        }
    }

    fn hash(parts: &[&[u8]]) -> Vec<u8> {
        let mut hash = SHA512::default();
        for part in parts {
            hash.do_update(part);
        }
        let mut digest = vec![0u8; 64];
        hash.do_final_out(&mut digest);
        digest
    }
    fn digest_images(name: &str, digest: &[u8], values: &mut Values) {
        values.push((name.to_string(), digest.to_vec()));
        values.push((format!("{name} (SHA-512 state)"), word_swapped(digest)));
    }
    fn chaining_values(input: &[u8]) -> Vec<u8> {
        // After each whole block but the last, from the suspended state: after its three-byte
        // version prefix, the state words in little-endian order.
        (1..input.len().div_ceil(128))
            .flat_map(|blocks| {
                let mut hash = SHA512::default();
                hash.do_update(&input[..128 * blocks]);
                hash.suspend()[3..3 + 64].to_vec()
            })
            .collect()
    }
    fn prehash(msg: &[u8]) -> Vec<u8> {
        Self::hash(&[msg])
    }
    fn dom(ph: bool, ctx: &[u8]) -> Vec<u8> {
        // RFC 8032 Section 2: dom2 is blank for Ed25519, and for Ed25519ph "SigEd25519 no
        // Ed25519 collisions" || octet(x) || octet(OLEN(y)) || y.
        if ph {
            [b"SigEd25519 no Ed25519 collisions".as_slice(), &[1, ctx.len() as u8], ctx].concat()
        } else {
            Vec::new()
        }
    }
    fn prune(s: &mut [u8]) {
        // RFC 8032 Section 5.1.5, step 2.
        s[0] &= 0xF8;
        s[31] &= 0x7F;
        s[31] |= 0x40;
    }
    fn order() -> Big {
        // RFC 8032 Section 5.1, Table 1.
        big_add(&big_pow2(252), &big_dec("27742317777372353535851937790883648493"))
    }
}

impl EdScheme<57, 57, 114> for Ed448PrivateKey {
    type Pk = Ed448PublicKey;
    const NAME: &'static str = "Ed448";
    const HALF: usize = 57;
    const LIMB_BITS: usize = 56;
    const LIMBS: usize = 8;
    const CONTEXT: &'static [u8] = b"stack harness";
    // RFC 8032 Section 7.4, "1 octet (with context)".
    const VECTOR: [&'static str; 5] = [
        "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397\
         a659949ef8021e954e0a12274e",
        "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4\
         cb82169c235160627b4c3a9480",
        "03",
        "666f6f",
        "d4f8f6131770dd46f40867d6fd5d5055de43541f8c5e35abbcd001b32a89f7d2151f7647f11d8ca2ae279fb8\
         42d607217fce6e042f6815ea000c85741de5c8da1144a6a1aba7f96de42505d7a7298524fda538fccbbb754f\
         578c1cad10d54d0d5428407e85dcbc98a49155c13764e66c3c00",
    ];

    fn keygen(rng: &mut dyn RNG) -> Result<(Self::Pk, Self), SignatureError> {
        ed448::keygen(rng)
    }
    fn keygen_out(rng: &mut dyn RNG, sk: &mut Self) -> Result<(), SignatureError> {
        ed448::keygen_out(rng, sk)
    }
    fn zeroized() -> Self {
        Ed448PrivateKey::zeroized()
    }
    fn from_bytes_out(bytes: &[u8], sk: &mut Self) -> Result<(), KeyDecodingError> {
        Ed448PrivateKey::from_bytes_out(bytes, sk)
    }
    fn pk(&self) -> Self::Pk {
        Ed448PrivateKey::pk(self).unwrap()
    }
    fn consistent(pk: &Self::Pk, sk: &Self) -> bool {
        ed448::keypair_consistency_check(pk, sk).is_ok()
    }
    fn sign_out(&self, msg: &[u8], ctx: Option<&[u8]>, sig: &mut [u8; 114]) -> usize {
        DeterministicOneShotSigningKey::<Ed448, 114>::sign_deterministic_out(self, msg, ctx, sig)
            .unwrap()
    }
    fn sign(&self, msg: &[u8], ctx: Option<&[u8]>) -> [u8; 114] {
        DeterministicOneShotSigningKey::<Ed448, 114>::sign_deterministic(self, msg, ctx).unwrap()
    }
    fn sign_ph_out(&self, msg: &[u8], ctx: Option<&[u8]>, sig: &mut [u8; 114]) -> usize {
        DeterministicOneShotSigningKey::<Ed448ph, 114>::sign_deterministic_out(
            &self.as_prehash(),
            msg,
            ctx,
            sig,
        )
        .unwrap()
    }
    fn sign_ph(&self, msg: &[u8], ctx: Option<&[u8]>) -> [u8; 114] {
        DeterministicOneShotSigningKey::<Ed448ph, 114>::sign_deterministic(
            &self.as_prehash(),
            msg,
            ctx,
        )
        .unwrap()
    }
    fn ph_signer<'a>(&'a self, ctx: Option<&[u8]>) -> Box<dyn SignatureSigner<114> + 'a> {
        Box::new(self.as_prehash().create_signer_deterministic(ctx).unwrap())
    }
    fn verifies(pk: &Self::Pk, msg: &[u8], ctx: Option<&[u8]>, sig: &[u8], ph: bool) -> bool {
        if ph {
            OneShotVerifyingKey::<Ed448ph, 114>::verify(&pk.as_prehash(), msg, ctx, sig).is_ok()
        } else {
            OneShotVerifyingKey::<Ed448, 114>::verify(pk, msg, ctx, sig).is_ok()
        }
    }

    fn hash(parts: &[&[u8]]) -> Vec<u8> {
        shake256(parts, 114)
    }
    fn digest_images(name: &str, digest: &[u8], values: &mut Values) {
        // The sponge's lanes are little-endian: the digest is its own image.
        values.push((name.to_string(), digest.to_vec()));
    }
    fn chaining_values(_: &[u8]) -> Vec<u8> {
        // The Keccak state is wiped by `bouncycastle_digest::sha3` at each permutation.
        Vec::new()
    }
    fn prehash(msg: &[u8]) -> Vec<u8> {
        // RFC 8032 Section 5.2: "PH being SHAKE256(x, 64)".
        shake256(&[msg], 64)
    }
    fn dom(ph: bool, ctx: &[u8]) -> Vec<u8> {
        // RFC 8032 Section 2: "SigEd448" || octet(x) || octet(OLEN(y)) || y.
        [b"SigEd448".as_slice(), &[u8::from(ph), ctx.len() as u8], ctx].concat()
    }
    fn prune(s: &mut [u8]) {
        // RFC 8032 Section 5.2.5, step 2.
        s[0] &= 0xFC;
        s[56] = 0;
        s[55] |= 0x80;
    }
    fn order() -> Big {
        // RFC 8032 Section 5.2, Table 2.
        big_sub(
            &big_pow2(446),
            &big_dec("13818066809895115352007386748515426880336692474882178609894547503885"),
        )
    }
}

fn shake256(parts: &[&[u8]], len: usize) -> Vec<u8> {
    let mut xof = SHAKE256::default();
    for part in parts {
        xof.do_update(part);
    }
    xof.into_squeezer().do_output(len)
}

/// The expansion of an EdDSA private key (RFC 8032 Section 5.1.5 or 5.2.5).
struct Expanded {
    seed: Vec<u8>,
    h: Vec<u8>,
    s: Vec<u8>,
    prefix: Vec<u8>,
}

impl Expanded {
    fn of<E: EdScheme<SK, PK, SIG>, const SK: usize, const PK: usize, const SIG: usize>(
        seed: &[u8],
    ) -> Self {
        let h = E::hash(&[seed]);
        let mut s = h[..E::HALF].to_vec();
        E::prune(&mut s);
        Self { seed: seed.to_vec(), prefix: h[E::HALF..].to_vec(), h, s }
    }

    /// What a key is searched for: the private key, as bytes and as the SHA-512 words it is
    /// absorbed as, its digest, `s` and `prefix`.
    fn values<E: EdScheme<SK, PK, SIG>, const SK: usize, const PK: usize, const SIG: usize>(
        &self,
    ) -> Values {
        let mut values = vec![
            ("private key".to_string(), self.seed.clone()),
            ("private key (SHA-512 words)".to_string(), word_swapped(&self.seed)),
            ("s".to_string(), self.s.clone()),
            ("prefix".to_string(), self.prefix.clone()),
        ];
        E::digest_images("h", &self.h, &mut values);
        values
    }
}

/// The digest of step 2 and `r`, of the signature `sig` over `msg` under `key`, checked against
/// it: `S = r + k s mod L` (steps 4 and 5), with `k` from `R` and the public key `a`. Returned
/// with the key's values, and with the public values `k` and its digest as an image for the
/// comparison of two runs.
fn signing_values<E: EdScheme<SK, PK, SIG>, const SK: usize, const PK: usize, const SIG: usize>(
    key: &Expanded,
    a: &[u8],
    msg: &[u8],
    ctx: &[u8],
    ph: bool,
    sig: &[u8],
) -> (Values, Vec<u8>) {
    let phm = if ph { E::prehash(msg) } else { msg.to_vec() };
    let dom = E::dom(ph, ctx);
    let l = E::order();
    let r_digest = E::hash(&[&dom, &key.prefix, &phm]);
    let r = big_mod(&big(&r_digest), &l);
    let (big_r, big_s) = sig.split_at(SIG / 2);
    let k_input = [&dom, big_r, a, &phm].concat();
    let k_digest = E::hash(&[&k_input]);
    let k = big_mod(&big(&k_digest), &l);
    let s = big_mod(&big_add(&r, &big_mul(&k, &big(&key.s))), &l);
    assert_eq!(le_bytes(&s, SIG / 2), big_s, "not the signature's r and s");
    let mut values = key.values::<E, SK, PK, SIG>();
    E::digest_images("r digest", &r_digest, &mut values);
    values.push(("r".to_string(), le_bytes(&r, SIG / 2)));
    // `k`, its digest and the hash's states on the way are public, and differ with `R` and `A`.
    let k = le_bytes(&k, SIG / 2);
    let image =
        [sig, &k, &k_digest, &word_swapped(&k_digest), &E::chaining_values(&k_input)].concat();
    (values, image)
}

/// A public key as what the comparison of two runs lets differ: its encoding and its `y` in the
/// field arithmetic's limbs.
fn ed_public_image<E: EdScheme<SK, PK, SIG>, const SK: usize, const PK: usize, const SIG: usize>(
    encoded: &[u8],
) -> Vec<u8> {
    let mut y = encoded.to_vec();
    *y.last_mut().unwrap() &= 0x7F;
    [encoded, &radix_limbs(&y, E::LIMB_BITS, E::LIMBS)].concat()
}

/// The EdDSA private key of `E`: generated, loaded, copied, encoded, its public key read, and
/// signing with it, through the one-shots and the pre-hash variant's streaming final.
pub(crate) fn eddsa<E, const SK: usize, const PK: usize, const SIG: usize>(scan: &mut Scan)
where
    E: EdScheme<SK, PK, SIG>,
{
    let name = E::NAME;
    let op = |what: &str| format!("{name} {what}");

    // The reference computation against RFC 8032's vector, before it is relied on.
    let [seed, pk, msg, ctx, sig] = E::VECTOR.map(hex);
    let sk = E::from_bytes(&seed).unwrap();
    assert_eq!(&sk.pk().encode()[..], &pk[..], "not the RFC's public key");
    assert_eq!(&sk.sign(&msg, Some(&ctx))[..], &sig[..], "not the RFC's signature");
    signing_values::<E, SK, PK, SIG>(
        &Expanded::of::<E, SK, PK, SIG>(&seed),
        &pk,
        &msg,
        &ctx,
        false,
        &sig,
    );

    let seeds = [0, 1].map(|i| bytes_of(&format!("{name} key {i}"), SK));
    let keys = seeds.clone().map(|s| Expanded::of::<E, SK, PK, SIG>(&s));
    let pks: Vec<[u8; PK]> =
        seeds.iter().map(|s| E::from_bytes(s).unwrap().pk().encode()).collect();
    let publics: Vec<Vec<u8>> = pks.iter().map(|p| ed_public_image::<E, SK, PK, SIG>(p)).collect();
    let mut sk = Box::new(E::zeroized());
    let mut other = Box::new(E::zeroized());
    let mut encoded = Box::new([0u8; SK]);
    let mut rng = Box::new(rng_of(&seeds[0]));

    for (i, key) in keys.iter().enumerate() {
        scan.keep();
        *rng = rng_of(&key.seed);
        let (generated_pk, generated_sk) = scan.run(|| E::keygen(&mut *rng)).unwrap();
        assert_eq!(&generated_sk.encode()[..], &key.seed[..], "not the RNG's draw");
        assert_eq!(generated_pk.encode(), pks[i]);
        scan.clean(&op("keygen"), &key.values::<E, SK, PK, SIG>());
    }
    // `keygen` is `keygen_out`, compared below, then `pk`, which decodes the public key: the
    // field elements of its square root are public but differ from key to key, and no image of
    // them is computed here, so two runs are not compared and the search is the check.

    for (i, key) in keys.iter().enumerate() {
        scan.keep();
        *rng = rng_of(&key.seed);
        scan.run(|| E::keygen_out(&mut *rng, &mut sk)).unwrap();
        assert_eq!(&sk.encode()[..], &key.seed[..], "not the RNG's draw");
        assert_eq!(sk.pk().encode(), pks[i]);
        scan.clean(&op("keygen_out"), &key.values::<E, SK, PK, SIG>());
    }
    scan.same(&op("keygen_out"), &publics[0], &publics[1]);

    for (i, key) in keys.iter().enumerate() {
        scan.keep();
        encoded.copy_from_slice(&key.seed);
        let loaded = scan.run(|| E::from_bytes(&encoded[..])).unwrap();
        assert_eq!(loaded.pk().encode(), pks[i]);
        scan.clean(&op("from_bytes"), &key.values::<E, SK, PK, SIG>());
    }
    scan.same(&op("from_bytes"), &publics[0], &publics[1]);
    for (i, key) in keys.iter().enumerate() {
        scan.keep();
        encoded.copy_from_slice(&key.seed);
        scan.run(|| E::from_bytes_out(&encoded[..], &mut sk)).unwrap();
        assert_eq!(sk.pk().encode(), pks[i]);
        scan.clean(&op("from_bytes_out"), &key.values::<E, SK, PK, SIG>());
    }
    scan.same(&op("from_bytes_out"), &publics[0], &publics[1]);

    for key in &keys {
        E::from_bytes_out(&key.seed, &mut sk).unwrap();
        scan.keep();
        let copy = scan.run(|| (*sk).clone());
        assert!(copy == *sk);
        scan.clean(&op("clone"), &key.values::<E, SK, PK, SIG>());
    }
    scan.same(&op("clone"), &[], &[]);
    for key in &keys {
        E::from_bytes_out(&key.seed, &mut sk).unwrap();
        scan.keep();
        scan.run(|| other.clone_from(&sk));
        assert!(*other == *sk);
        scan.clean(&op("clone_from"), &key.values::<E, SK, PK, SIG>());
    }
    scan.same(&op("clone_from"), &[], &[]);
    for key in &keys {
        E::from_bytes_out(&key.seed, &mut sk).unwrap();
        other.clone_from(&sk);
        scan.keep();
        assert!(scan.run(|| *sk == *other));
        scan.clean(&op("=="), &key.values::<E, SK, PK, SIG>());
    }
    scan.same(&op("=="), &[], &[]);

    for key in &keys {
        E::from_bytes_out(&key.seed, &mut sk).unwrap();
        scan.keep();
        *encoded = scan.run(|| sk.encode());
        assert_eq!(&encoded[..], &key.seed[..]);
        scan.clean(&op("encode"), &key.values::<E, SK, PK, SIG>());
    }
    scan.same(&op("encode"), &[], &[]);
    for key in &keys {
        E::from_bytes_out(&key.seed, &mut sk).unwrap();
        scan.keep();
        assert_eq!(scan.run(|| sk.encode_out(&mut encoded)), SK);
        assert_eq!(&encoded[..], &key.seed[..]);
        scan.clean(&op("encode_out"), &key.values::<E, SK, PK, SIG>());
    }
    scan.same(&op("encode_out"), &[], &[]);
    for (i, key) in keys.iter().enumerate() {
        E::from_bytes_out(&key.seed, &mut sk).unwrap();
        scan.keep();
        let pk = scan.run(|| sk.pk());
        assert_eq!(pk.encode(), pks[i]);
        scan.clean(&op("pk"), &key.values::<E, SK, PK, SIG>());
    }
    // `pk` decodes the stored public key and reads nothing secret, so two keys' runs differ in
    // public values alone and are not compared: the search is the check.
    for key in &keys {
        E::from_bytes_out(&key.seed, &mut sk).unwrap();
        let pk = Box::new(sk.pk());
        scan.keep();
        assert!(scan.run(|| E::consistent(&pk, &sk)));
        scan.clean(&op("keypair_consistency_check"), &key.values::<E, SK, PK, SIG>());
    }
    scan.same(&op("keypair_consistency_check"), &[], &[]);

    // Signing, under two keys. Ed25519 takes no context; Ed448 and the pre-hash variants are
    // given one.
    let msg = message(100);
    let ctx = E::CONTEXT;
    let ph_ctx: &[u8] = b"stack harness";
    let mut sig = Box::new([0u8; SIG]);
    let sign_values = |i: usize, sig: &[u8; SIG], ph: bool| {
        let pk = E::from_bytes(&keys[i].seed).unwrap().pk();
        let c = if ph { ph_ctx } else { ctx };
        assert!(E::verifies(&pk, &msg, Some(c), sig, ph), "does not verify");
        signing_values::<E, SK, PK, SIG>(&keys[i], &pks[i], &msg, c, ph, sig)
    };
    let forms: [(&str, bool, fn(&E, &[u8], &[u8], &mut [u8; SIG])); 4] = [
        ("sign_deterministic_out", false, |sk, m, c, sig| {
            sk.sign_out(m, Some(c), sig);
        }),
        ("sign_deterministic", false, |sk, m, c, sig| *sig = sk.sign(m, Some(c))),
        ("ph sign_deterministic_out", true, |sk, m, c, sig| {
            sk.sign_ph_out(m, Some(c), sig);
        }),
        ("ph sign_deterministic", true, |sk, m, c, sig| *sig = sk.sign_ph(m, Some(c))),
    ];
    for (what, ph, form) in forms {
        let c = if ph { ph_ctx } else { ctx };
        let mut images = Vec::new();
        for (i, key) in keys.iter().enumerate() {
            E::from_bytes_out(&key.seed, &mut sk).unwrap();
            scan.keep();
            scan.run(|| form(&sk, &msg, c, &mut sig));
            let (values, image) = sign_values(i, &sig, ph);
            scan.clean(&op(what), &values);
            images.push(image);
        }
        scan.same(&op(what), &images[0], &images[1]);
    }
    // The pre-hash variant's streaming final, on a signer in a box.
    let mut images = Vec::new();
    for (i, key) in keys.iter().enumerate() {
        E::from_bytes_out(&key.seed, &mut sk).unwrap();
        let mut signer = sk.ph_signer(Some(ph_ctx));
        signer.do_update(&msg);
        scan.keep();
        assert_eq!(scan.run(|| signer.do_final_out_boxed(&mut sig)), Ok(SIG));
        let (values, image) = sign_values(i, &sig, true);
        scan.clean(&op("ph final (boxed)"), &values);
        images.push(image);
    }
    scan.same(&op("ph final (boxed)"), &images[0], &images[1]);
}

/// What the harness needs of an XDH scheme over and above the key traits.
pub(crate) trait XScheme<const N: usize>:
    PrivateKey<N> + Clone + PartialEq + AgreementKey<(), N, PublicKey = Self::Pk>
{
    type Pk: PublicKey<N> + Copy;
    const NAME: &'static str;
    /// RFC 7748 Section 6's test vector: Alice's private key, Bob's public key, `K`.
    const VECTOR: [&'static str; 3];
    /// The bits of a field element's limbs, and how many there are.
    const LIMB_BITS: usize;
    const LIMBS: usize;
    fn keygen(rng: &mut dyn RNG) -> Result<(Self::Pk, Self), KeyAgreementError>;
    fn keygen_out(rng: &mut dyn RNG, sk: &mut Self) -> Result<(), KeyAgreementError>;
    fn keygen_from_seed(seed: &KeyMaterial<N>) -> Result<(Self::Pk, Self), KeyAgreementError>;
    fn keygen_from_seed_out(seed: &KeyMaterial<N>, sk: &mut Self) -> Result<(), KeyAgreementError>;
    fn zeroized() -> Self;
    fn from_bytes_out(bytes: &[u8], sk: &mut Self) -> Result<(), KeyDecodingError>;
    fn pk(&self) -> Self::Pk;
    fn clamp(k: &mut [u8; N]);
}

impl XScheme<32> for X25519PrivateKey {
    type Pk = X25519PublicKey;
    const NAME: &'static str = "X25519";
    const LIMB_BITS: usize = 51;
    const LIMBS: usize = 5;
    const VECTOR: [&'static str; 3] = [
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
    ];
    fn keygen(rng: &mut dyn RNG) -> Result<(Self::Pk, Self), KeyAgreementError> {
        x25519::keygen(rng)
    }
    fn keygen_out(rng: &mut dyn RNG, sk: &mut Self) -> Result<(), KeyAgreementError> {
        x25519::keygen_out(rng, sk)
    }
    fn keygen_from_seed(seed: &KeyMaterial<32>) -> Result<(Self::Pk, Self), KeyAgreementError> {
        x25519::keygen_from_seed(seed)
    }
    fn keygen_from_seed_out(
        seed: &KeyMaterial<32>,
        sk: &mut Self,
    ) -> Result<(), KeyAgreementError> {
        x25519::keygen_from_seed_out(seed, sk)
    }
    fn zeroized() -> Self {
        X25519PrivateKey::zeroized()
    }
    fn from_bytes_out(bytes: &[u8], sk: &mut Self) -> Result<(), KeyDecodingError> {
        X25519PrivateKey::from_bytes_out(bytes, sk)
    }
    fn pk(&self) -> Self::Pk {
        X25519PrivateKey::pk(self).unwrap()
    }
    fn clamp(k: &mut [u8; 32]) {
        // RFC 7748 Section 5, decodeScalar25519.
        k[0] &= 248;
        k[31] &= 127;
        k[31] |= 64;
    }
}

impl XScheme<56> for X448PrivateKey {
    type Pk = X448PublicKey;
    const NAME: &'static str = "X448";
    const LIMB_BITS: usize = 56;
    const LIMBS: usize = 8;
    const VECTOR: [&'static str; 3] = [
        "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f\
         127ab1d9ac2d8c0a598726b",
        "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57\
         aec3dae07bdc1c67bf33609",
        "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403\
         085d59a449a5037514a879d",
    ];
    fn keygen(rng: &mut dyn RNG) -> Result<(Self::Pk, Self), KeyAgreementError> {
        x448::keygen(rng)
    }
    fn keygen_out(rng: &mut dyn RNG, sk: &mut Self) -> Result<(), KeyAgreementError> {
        x448::keygen_out(rng, sk)
    }
    fn keygen_from_seed(seed: &KeyMaterial<56>) -> Result<(Self::Pk, Self), KeyAgreementError> {
        x448::keygen_from_seed(seed)
    }
    fn keygen_from_seed_out(
        seed: &KeyMaterial<56>,
        sk: &mut Self,
    ) -> Result<(), KeyAgreementError> {
        x448::keygen_from_seed_out(seed, sk)
    }
    fn zeroized() -> Self {
        X448PrivateKey::zeroized()
    }
    fn from_bytes_out(bytes: &[u8], sk: &mut Self) -> Result<(), KeyDecodingError> {
        X448PrivateKey::from_bytes_out(bytes, sk)
    }
    fn pk(&self) -> Self::Pk {
        X448PrivateKey::pk(self).unwrap()
    }
    fn clamp(k: &mut [u8; 56]) {
        // RFC 7748 Section 5, decodeScalar448.
        k[0] &= 252;
        k[55] |= 128;
    }
}

/// The XDH private key of `X`: generated, from an RNG and from a seed, loaded, encoded, its
/// public key read, and agreeing. `scalar_mult_left` reports, without failing, the comparison
/// of two runs over the operations that multiply by the scalar, for X25519, whose field
/// inversion is left on the stack by decision (its Security Considerations); the search for the
/// key and `K` still fails.
pub(crate) fn xdh<X: XScheme<N>, const N: usize>(scan: &mut Scan, scalar_mult_left: bool) {
    let name = X::NAME;
    let op = |what: &str| format!("{name} {what}");
    let clamped = |raw: &[u8]| {
        let mut k: [u8; N] = raw.try_into().unwrap();
        X::clamp(&mut k);
        k
    };
    // The field arithmetic's limbs of a value: the ladder's, for `K`, and of the clamped scalar,
    // should it pass through a field element.
    let limbs = |v: &[u8]| radix_limbs(v, X::LIMB_BITS, X::LIMBS);
    let key_values = |raw: &[u8]| -> Values {
        vec![
            ("private key (bytes)".to_string(), raw.to_vec()),
            ("private key (clamped)".to_string(), clamped(raw).to_vec()),
            ("private key (clamped, limbs)".to_string(), limbs(&clamped(raw))),
        ]
    };
    // The comparison of two runs over an operation that multiplies by the scalar.
    let same_scalar_mult = |scan: &mut Scan, what: &str, before: &[u8], after: &[u8]| {
        let report_only = scan.report_only;
        scan.report_only = scalar_mult_left;
        scan.same(&op(what), before, after);
        scan.report_only = report_only;
    };

    // The agreement against RFC 7748's vector, before it is relied on.
    let [alice, bob, k] = X::VECTOR.map(hex);
    let mut z = KeyMaterial::<N>::new();
    let bob = X::Pk::from_bytes(&bob).unwrap();
    X::from_bytes(&alice).unwrap().agree_out(&bob, (), &mut z).unwrap();
    assert_eq!(z.ref_to_bytes(), &k[..], "not the RFC's shared secret");

    let raws = [0, 1].map(|i| bytes_of(&format!("{name} key {i}"), N));
    let pks: Vec<X::Pk> = raws.iter().map(|r| X::from_bytes(r).unwrap().pk()).collect();
    let publics: Vec<Vec<u8>> = pks.iter().map(|p| p.encode().to_vec()).collect();
    let mut sk = Box::new(X::zeroized());
    let mut encoded = Box::new([0u8; N]);
    let mut rng = Box::new(rng_of(&raws[0]));

    for (i, raw) in raws.iter().enumerate() {
        scan.keep();
        *rng = rng_of(raw);
        let (pk, generated) = scan.run(|| X::keygen(&mut *rng)).unwrap();
        assert_eq!(generated.encode(), clamped(raw), "not the RNG's draw");
        assert_eq!(pk.encode(), pks[i].encode());
        scan.clean(&op("keygen"), &key_values(raw));
    }
    same_scalar_mult(scan, "keygen", &publics[0], &publics[1]);
    for (i, raw) in raws.iter().enumerate() {
        scan.keep();
        *rng = rng_of(raw);
        scan.run(|| X::keygen_out(&mut *rng, &mut sk)).unwrap();
        assert_eq!(sk.encode(), clamped(raw), "not the RNG's draw");
        assert_eq!(sk.pk().encode(), pks[i].encode());
        scan.clean(&op("keygen_out"), &key_values(raw));
    }
    same_scalar_mult(scan, "keygen_out", &publics[0], &publics[1]);
    let seeds = raws
        .clone()
        .map(|r| Box::new(KeyMaterial::<N>::from_bytes_as_type(&r, KeyType::Seed).unwrap()));
    for (i, raw) in raws.iter().enumerate() {
        scan.keep();
        let (pk, generated) = scan.run(|| X::keygen_from_seed(&seeds[i])).unwrap();
        assert_eq!(generated.encode(), clamped(raw));
        assert_eq!(pk.encode(), pks[i].encode());
        scan.clean(&op("keygen_from_seed"), &key_values(raw));
    }
    same_scalar_mult(scan, "keygen_from_seed", &publics[0], &publics[1]);
    for (i, raw) in raws.iter().enumerate() {
        scan.keep();
        scan.run(|| X::keygen_from_seed_out(&seeds[i], &mut sk)).unwrap();
        assert_eq!(sk.encode(), clamped(raw));
        assert_eq!(sk.pk().encode(), pks[i].encode());
        scan.clean(&op("keygen_from_seed_out"), &key_values(raw));
    }
    same_scalar_mult(scan, "keygen_from_seed_out", &publics[0], &publics[1]);

    for (i, raw) in raws.iter().enumerate() {
        scan.keep();
        encoded.copy_from_slice(raw);
        let loaded = scan.run(|| X::from_bytes(&encoded[..])).unwrap();
        assert_eq!(loaded.pk().encode(), pks[i].encode());
        scan.clean(&op("from_bytes"), &key_values(raw));
    }
    same_scalar_mult(scan, "from_bytes", &publics[0], &publics[1]);
    for (i, raw) in raws.iter().enumerate() {
        scan.keep();
        encoded.copy_from_slice(raw);
        scan.run(|| X::from_bytes_out(&encoded[..], &mut sk)).unwrap();
        assert_eq!(sk.pk().encode(), pks[i].encode());
        scan.clean(&op("from_bytes_out"), &key_values(raw));
    }
    same_scalar_mult(scan, "from_bytes_out", &publics[0], &publics[1]);

    let mut other = Box::new(X::zeroized());
    for raw in &raws {
        X::from_bytes_out(raw, &mut sk).unwrap();
        scan.keep();
        let copy = scan.run(|| (*sk).clone());
        assert!(copy == *sk);
        scan.clean(&op("clone"), &key_values(raw));
    }
    scan.same(&op("clone"), &[], &[]);
    for raw in &raws {
        X::from_bytes_out(raw, &mut sk).unwrap();
        scan.keep();
        scan.run(|| other.clone_from(&sk));
        assert!(*other == *sk);
        scan.clean(&op("clone_from"), &key_values(raw));
    }
    scan.same(&op("clone_from"), &[], &[]);
    for raw in &raws {
        X::from_bytes_out(raw, &mut sk).unwrap();
        scan.keep();
        *encoded = scan.run(|| sk.encode());
        assert_eq!(*encoded, clamped(raw));
        scan.clean(&op("encode"), &key_values(raw));
    }
    scan.same(&op("encode"), &[], &[]);
    for raw in &raws {
        X::from_bytes_out(raw, &mut sk).unwrap();
        scan.keep();
        assert_eq!(scan.run(|| sk.encode_out(&mut encoded)), N);
        assert_eq!(*encoded, clamped(raw));
        scan.clean(&op("encode_out"), &key_values(raw));
    }
    scan.same(&op("encode_out"), &[], &[]);
    for (i, raw) in raws.iter().enumerate() {
        X::from_bytes_out(raw, &mut sk).unwrap();
        scan.keep();
        let pk = scan.run(|| sk.pk());
        assert_eq!(pk.encode(), pks[i].encode());
        scan.clean(&op("pk"), &key_values(raw));
    }
    scan.same(&op("pk"), &publics[0], &publics[1]);

    // Agreement: under two keys, with one peer. `K` is checked by the peer's agreement.
    let peer_raw = bytes_of(&format!("{name} peer"), N);
    let peer_sk = X::from_bytes(&peer_raw).unwrap();
    let peer = Box::new(peer_sk.pk());
    let mut z = Box::new(KeyMaterial::<N>::new());
    for (i, raw) in raws.iter().enumerate() {
        X::from_bytes_out(raw, &mut sk).unwrap();
        scan.keep();
        assert_eq!(scan.run(|| sk.agree_out(&peer, (), &mut z)), Ok(N));
        let mut theirs = KeyMaterial::<N>::new();
        peer_sk.agree_out(&pks[i], (), &mut theirs).unwrap();
        assert_eq!(z.ref_to_bytes(), theirs.ref_to_bytes(), "not their K");
        let mut values = key_values(raw);
        values.push(("K".to_string(), z.ref_to_bytes().to_vec()));
        values.push(("K (limbs)".to_string(), limbs(z.ref_to_bytes())));
        scan.clean(&op("agree_out"), &values);
    }
    same_scalar_mult(scan, "agree_out", &[], &[]);
}
