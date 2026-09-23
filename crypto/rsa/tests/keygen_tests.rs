//! Tests for [`bouncycastle_rsa::keygen`] and the per-size `keygen`/`keygen_from_rng` functions:
//! known-answer checks of the Miller-Rabin test, and FIPS 186-5 Appendix A.1.1's criteria checked
//! on generated RSA-2048 (and, more slowly, RSA-3072) key pairs, plus the failure modes a broken
//! RNG produces.
//!
//! Key generation is randomized, so there is no fixed expected key; the generated pair is checked
//! against the criteria the generator claims to meet -- the candidates' top bits and parity (A.1.3
//! steps 4.2.1/4.3), `e` coprime to `p - 1` and `q - 1` (A.1.1 2(a)), `|p - q| > 2^(nlen/2 - 100)`
//! (2(d)), `n = p * q`, and the primality of `p` and `q` under this crate's own Miller-Rabin,
//! whose known-answer tests are in this file too -- and by signing and verifying with it under
//! both schemes, which exercises every CRT component. The primality facts asserted below (the
//! documented Wycheproof `p`/`q` are prime, `p + 2` has the factor 173, `p + 6` is composite with
//! no factor below 2000, `2^521 - 1` and `2^607 - 1` are prime, `2^521 + 1` is divisible by 3) were
//! confirmed offline in Python before being pinned here; nothing here depends on a bignum crate.
//!
//! The RSA-4096 and RSA-8192 generators are exercised only under `--ignored`: an RSA-8192
//! candidate's Miller-Rabin round is a 4096-bit modular exponentiation and a key needs hundreds of
//! candidates, which is tens of minutes in a debug build (the two together take about half a
//! minute in release). Run them with
//! `cargo test -p bouncycastle-rsa --release --test keygen_tests -- --ignored`.

use bouncycastle_core::errors::{RNGError, SignatureError};
use bouncycastle_core::traits::{
    RNG, SecurityStrength, SignaturePrivateKey, SignatureVerifier, Signer,
};
use bouncycastle_core_test_framework::signature::TestFrameworkSignature;
use bouncycastle_ec::montgomery::widening_mul;
use bouncycastle_rng::DefaultRNG;
use bouncycastle_rsa::keygen::{PUBLIC_EXPONENT, is_probable_prime};
use bouncycastle_rsa::rsa_2048::{
    self, PK_LEN, RSA2048PrivateKey, RSA2048PublicKey, RSASSA_PKCS1_v1_5_SHA256, RSASSA_PSS_SHA256,
    SIG_LEN, SK_LEN,
};
use bouncycastle_rsa::{rsa_3072, rsa_4096, rsa_8192};
use core::num::NonZeroUsize;

/// The documented Wycheproof RSA-2048 key's `p` and `q` (see `rsa_2048_pkcs1_v1_5_tests.rs` for
/// their provenance): two genuine 1024-bit primes.
const P: [u64; 16] = [
    0x0ea36cfb3a5b18f1, 0x48a6e65332119129, 0x110ad9e7b48a1c93, 0x569156b90113e2e9,
    0xe79813a575cfad9c, 0x69d659d143ec6f17, 0xe81e6bab5ddaa783, 0xbff1c5b80a69f788,
    0x978f6c35814f50ee, 0xe6a289ad4cfbf78f, 0x34d5681e5809d415, 0xbb028bda42eeb5d2,
    0x41c56e4de086b0d5, 0x58b8d1e24f3b55d0, 0xfb5248247d98cb7d, 0xdc431050f782e894,
];
const Q: [u64; 16] = [
    0x669f140cfbc20f25, 0xb97bb03677207d95, 0xfd4e06f3ed7299d4, 0x160f90536abc9492,
    0xf5b131f39098f7bc, 0xae8d72c57088d7ab, 0x89b94fbde542aba9, 0x3d3f9880ec47d5e0,
    0x1378a6868af3b7a0, 0x5544070beb057c94, 0x16611debc472fac4, 0xe500ffb79f5b8868,
    0x308a5e32196603b2, 0xea5fb19eb4eabc38, 0x122273ae3222b598, 0xbd1a81e7977f9898,
];

fn small<const N: usize>(v: u64) -> [u64; N] {
    let mut out = [0u64; N];
    out[0] = v;
    out
}

/// `P + k` for a small `k` (no carry out of the low limb for the values used here).
fn p_plus(k: u64) -> [u64; 16] {
    let mut out = P;
    out[0] = out[0].checked_add(k).unwrap();
    out
}

/// `2^bits - 1` as 16 limbs.
fn mersenne(bits: u32) -> [u64; 16] {
    let mut out = [0u64; 16];
    for (i, limb) in out.iter_mut().enumerate() {
        let lo = 64 * i as u32;
        *limb = if bits >= lo + 64 {
            u64::MAX
        } else if bits > lo {
            (1u64 << (bits - lo)) - 1
        } else {
            0
        };
    }
    out
}

fn rounds(n: usize) -> NonZeroUsize {
    NonZeroUsize::new(n).unwrap()
}

fn mr16(w: &[u64; 16], n: usize) -> bool {
    is_probable_prime::<16, 32, 33>(w, rounds(n), &mut DefaultRNG::default()).unwrap()
}

#[test]
fn miller_rabin_accepts_known_primes() {
    assert!(mr16(&P, 5));
    assert!(mr16(&Q, 5));
    assert!(mr16(&mersenne(521), 5), "2^521 - 1 (M521) is prime");
    assert!(mr16(&mersenne(607), 5), "2^607 - 1 (M607) is prime");
}

/// Twenty rounds here: a composite passes one random round with probability at most 1/4, so a
/// false "prime" is a `2^-40` event rather than the `2^-10` five rounds would leave.
#[test]
fn miller_rabin_rejects_known_composites() {
    assert!(!mr16(&p_plus(2), 20), "p + 2 has the factor 173 (trial division)");
    assert!(!mr16(&p_plus(4), 20), "p + 4 is divisible by 3");
    assert!(!mr16(&p_plus(6), 20), "p + 6 is composite with no factor below 2000 (Miller-Rabin)");
    let mut m521_plus_2 = mersenne(521);
    m521_plus_2[0] = m521_plus_2[0].wrapping_add(2); // 2^521 + 1, divisible by 3
    assert!(!mr16(&m521_plus_2, 20));
    let mut even = P;
    even[0] &= !1;
    assert!(!mr16(&even, 20), "even");
    assert!(!mr16(&small(0), 20));
    assert!(!mr16(&small(1), 20));
}

/// Below `2^20` the trial division against the primes below `2^10` is conclusive on its own
/// (Appendix B.7), so these do not touch the RNG-driven Miller-Rabin rounds at all.
#[test]
fn miller_rabin_decides_small_values_by_trial_division() {
    for prime in [2u64, 3, 5, 7, 1021, 65537, 1_048_573] {
        assert!(mr16(&small(prime), 1), "{prime} is prime");
    }
    for composite in [4u64, 9, 15, 561, 1023, 65535, 1_048_575] {
        assert!(!mr16(&small(composite), 1), "{composite} is composite");
    }
}

/// The CRT components of an encoded private key (`p || q || dP || dQ || qInv`, each `8 * HALF`
/// big-endian bytes) as little-endian limbs.
fn crt_components<const HALF: usize>(sk_bytes: &[u8]) -> [[u64; HALF]; 5] {
    let field_len = 8 * HALF;
    let mut out = [[0u64; HALF]; 5];
    for (f, field) in out.iter_mut().enumerate() {
        let bytes = &sk_bytes[f * field_len..(f + 1) * field_len];
        for i in 0..HALF {
            let start = field_len - 8 * (i + 1);
            field[i] = u64::from_be_bytes(bytes[start..start + 8].try_into().unwrap());
        }
    }
    out
}

fn mod_small<const N: usize>(a: &[u64; N], m: u64) -> u64 {
    let mut rem: u128 = 0;
    for limb in a.iter().rev() {
        rem = ((rem << 64) | u128::from(*limb)) % u128::from(m);
    }
    rem as u64
}

/// FIPS 186-5 Appendix A.1.1's criteria, checked on the CRT components of a generated key.
fn assert_fips_186_5_criteria<const HALF: usize, const HALF2: usize, const HALF21: usize>(
    sk_bytes: &[u8],
    n: &[u64; HALF2],
    mr_rounds: usize,
) {
    let [p, q, d_p, d_q, q_inv] = crt_components::<HALF>(sk_bytes);
    let e = u64::from(PUBLIC_EXPONENT);
    let mut rng = DefaultRNG::default();
    for (name, prime) in [("p", &p), ("q", &q)] {
        // A.1.3 step 4.2.1 (two most significant bits set) and 4.3 (odd).
        assert_eq!(prime[HALF - 1] >> 62, 0b11, "{name}: top two bits set");
        assert_eq!(prime[0] & 1, 1, "{name}: odd");
        // A.1.1 2(a): GCD(p - 1, e) = 1, i.e. p mod e != 1 for prime e.
        assert_ne!(mod_small(prime, e), 1, "{name} - 1 must be coprime to e");
        // 2(b)/(c): probably prime.
        assert!(
            is_probable_prime::<HALF, HALF2, HALF21>(prime, rounds(mr_rounds), &mut rng).unwrap(),
            "{name} must be prime"
        );
    }
    assert_ne!(p, q);
    // 2(d): |p - q| > 2^(nlen/2 - 100). nlen/2 - 100 = 64 * (HALF - 2) + 28, so the bits at and
    // above that position are limb HALF - 1 and the top 36 bits of limb HALF - 2; some must be set
    // (the "exactly 2^(nlen/2 - 100)" edge is a 2^-924 event, not worth a test branch).
    let (diff, borrow) = bouncycastle_ec::nat::sub(&p, &q);
    let diff = if borrow == 1 { bouncycastle_ec::nat::sub(&q, &p).0 } else { diff };
    assert!(
        diff[HALF - 1] != 0 || diff[HALF - 2] >> 28 != 0,
        "|p - q| must exceed 2^(nlen/2 - 100)"
    );
    // n = p * q.
    assert_eq!(widening_mul::<HALF, HALF2>(&p, &q), *n);
    // The CRT exponents are reduced (RFC 8017 §3.2) and nonzero.
    assert!(bouncycastle_ec::nat::sub(&d_p, &p).1 == 1 && d_p != [0u64; HALF]);
    assert!(bouncycastle_ec::nat::sub(&d_q, &q).1 == 1 && d_q != [0u64; HALF]);
    assert!(bouncycastle_ec::nat::sub(&q_inv, &p).1 == 1 && q_inv != [0u64; HALF]);
}

#[test]
fn keygen_2048_meets_fips_186_5_criteria_and_signs() {
    let (pk, sk) = rsa_2048::keygen().unwrap();
    assert_eq!(pk.e(), PUBLIC_EXPONENT);
    assert_eq!(pk.n(), sk.n());
    assert_fips_186_5_criteria::<16, 32, 33>(&sk.encode(), pk.n(), 5);

    // Every CRT component takes part in signing, so a round trip under both schemes is a
    // functional check of dP, dQ and qInv against n.
    let msg = b"signed with a freshly generated RSA-2048 key";
    let sig = RSASSA_PKCS1_v1_5_SHA256::sign(&sk, msg, None).unwrap();
    RSASSA_PKCS1_v1_5_SHA256::verify(&pk, msg, None, &sig).unwrap();
    assert!(RSASSA_PKCS1_v1_5_SHA256::verify(&pk, b"other", None, &sig).is_err());
    let sig = RSASSA_PSS_SHA256::sign(&sk, msg, None).unwrap();
    RSASSA_PSS_SHA256::verify(&pk, msg, None, &sig).unwrap();

    // Two generations give two keys.
    let (pk2, _) = rsa_2048::keygen().unwrap();
    assert_ne!(pk2.n(), pk.n());
}

/// The shared conformance suite with the real generator in the `keygen` slot, as the ECDSA tests
/// pass theirs (the fixed-key runs elsewhere in this crate exist because keygen used not to).
#[test]
fn conformance_suite_with_generated_keys() {
    TestFrameworkSignature::new(true, false).test_signature::<
        RSA2048PublicKey,
        RSA2048PrivateKey,
        RSASSA_PKCS1_v1_5_SHA256,
        RSASSA_PKCS1_v1_5_SHA256,
        PK_LEN,
        SK_LEN,
        SIG_LEN,
    >(rsa_2048::keygen, false);
}

#[test]
fn keygen_3072_meets_fips_186_5_criteria_and_signs() {
    let (pk, sk) = rsa_3072::keygen().unwrap();
    assert_fips_186_5_criteria::<24, 48, 49>(&sk.encode(), pk.n(), 4);
    let msg = b"signed with a freshly generated RSA-3072 key";
    let sig = rsa_3072::RSASSA_PKCS1_v1_5_SHA384::sign(&sk, msg, None).unwrap();
    rsa_3072::RSASSA_PKCS1_v1_5_SHA384::verify(&pk, msg, None, &sig).unwrap();
}

#[test]
#[ignore = "tens of minutes in a debug build: run with --release --ignored"]
fn keygen_4096_meets_fips_186_5_criteria_and_signs() {
    let (pk, sk) = rsa_4096::keygen().unwrap();
    assert_fips_186_5_criteria::<32, 64, 65>(&sk.encode(), pk.n(), 4);
    let msg = b"signed with a freshly generated RSA-4096 key";
    let sig = rsa_4096::RSASSA_PSS_SHA512::sign(&sk, msg, None).unwrap();
    rsa_4096::RSASSA_PSS_SHA512::verify(&pk, msg, None, &sig).unwrap();
}

#[test]
#[ignore = "tens of minutes in a debug build: run with --release --ignored"]
fn keygen_8192_meets_fips_186_5_criteria_and_signs() {
    let (pk, sk) = rsa_8192::keygen().unwrap();
    assert_fips_186_5_criteria::<64, 128, 129>(&sk.encode(), pk.n(), 4);
    let msg = b"signed with a freshly generated RSA-8192 key";
    let sig = rsa_8192::RSASSA_PKCS1_v1_5_SHA256::sign(&sk, msg, None).unwrap();
    rsa_8192::RSASSA_PKCS1_v1_5_SHA256::verify(&pk, msg, None, &sig).unwrap();
}

/// An RNG whose every output is the byte `fill`, reporting `strength`.
struct ConstantRng {
    fill: u8,
    strength: SecurityStrength,
}
impl RNG for ConstantRng {
    fn add_seed_keymaterial(
        &mut self,
        _additional_seed: &dyn bouncycastle_core::key_material::KeyMaterialTrait,
    ) -> Result<(), RNGError> {
        Ok(())
    }
    fn next_int(&mut self) -> Result<u32, RNGError> {
        Ok(u32::from_ne_bytes([self.fill; 4]))
    }
    fn next_bytes(&mut self, len: usize) -> Result<Vec<u8>, RNGError> {
        Ok(vec![self.fill; len])
    }
    fn next_bytes_out(&mut self, out: &mut [u8]) -> Result<usize, RNGError> {
        out.fill(self.fill);
        Ok(out.len())
    }
    fn fill_keymaterial_out(
        &mut self,
        _out: &mut dyn bouncycastle_core::key_material::KeyMaterialTrait,
    ) -> Result<usize, RNGError> {
        unimplemented!()
    }
    fn security_strength(&self) -> SecurityStrength {
        self.strength
    }
}

/// A.1.3's preamble: the DRBG must offer the modulus's security strength (SP 800-57 Part 1:
/// 112 bits for RSA-2048).
#[test]
fn keygen_from_rng_rejects_an_rng_below_the_required_strength() {
    let mut weak = ConstantRng { fill: 0x42, strength: SecurityStrength::None };
    assert!(matches!(
        rsa_2048::keygen_from_rng(&mut weak),
        Err(SignatureError::RNGError(RNGError::SecurityStrengthInsufficientForAlgorithm))
    ));
}

/// Steps 4.7/5.8: an RNG that keeps producing the same candidate cannot make progress -- the one
/// candidate is either composite, or equal to `p` and so rejected as too close (5.5) -- and the
/// candidate limits (`5 * nlen`, then `10 * nlen`) turn that into an error instead of a hang.
#[test]
fn keygen_from_rng_gives_up_on_a_stuck_rng() {
    let mut stuck = ConstantRng { fill: 0x42, strength: SecurityStrength::_256bit };
    assert!(matches!(rsa_2048::keygen_from_rng(&mut stuck), Err(SignatureError::GenericError(_))));
}
