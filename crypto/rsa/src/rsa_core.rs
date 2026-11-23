//! RSASP1 and RSAVP1 (RFC 8017 §5.2.1, §5.2.2): the raw signature and verification primitives,
//! and the checked CRT exponentiation RSASP1 and RSADP (§5.1.2) share.
//! [`rsasp1`] and [`rsavp1`] are private to the crate and reached through a padding scheme
//! only. The exponentiations beneath them are public, as
//! [`RsaSize::public_exp`] and [`RsaSigningSize::crt_exp`]: they are methods of the sealed size
//! traits, which is how code generic over a size reaches the arithmetic at one width, and a
//! public trait's methods cannot be less public than it. They are the engine and not a way to
//! sign. RFC 8017's introduction to §5 says why: "\[primitives\] are not intended to provide
//! security apart from a scheme" -- "textbook RSA" (signing a bare integer with no padding) is
//! malleable and vulnerable to existential forgery.
//!
//! Both primitives operate on the two-prime case only (RFC 8017's `u = 2`, no additional
//! `(r_i, d_i, t_i)` triplets): [`crate::keys::RsaPrivateComponents`] has no representation for
//! multi-prime RSA, so there is nothing here to extend to `u > 2`.

use crate::keys::{RsaPrivateComponents, RsaPublicComponents};
use crate::modexp::{
    MontgomeryContext, mod_pow, mod_pow_public_exponent, mul_mod, mul_u64_mod, reduce_wide, sub_mod,
};
use crate::size::{RsaSigningSize, RsaSize};
use bouncycastle_core::errors::SignatureError;
use bouncycastle_ec::montgomery;
use bouncycastle_ec::nat;
use bouncycastle_utils::ct::Condition;
use bouncycastle_utils::secret::{Secret, ZeroizablePrimitive, zeroize_in_place};

/// RSAVP1 (RFC 8017 §5.2.2): `m = s^e mod n`, recovering the message representative from a
/// signature representative under the public key.
///
/// Step 1's range check ("If the signature representative s is not between 0 and n - 1, output
/// 'signature representative out of range'") is `Err(`[`SignatureError::DecodingError`]`)` here.
pub(crate) fn rsavp1<K: RsaSize>(
    pk: &RsaPublicComponents<K>,
    s: &K::Limbs,
) -> Result<K::Limbs, SignatureError> {
    // RFC 8017 §5.2.2 step 1: the representative must be in [0, n - 1].
    if !K::is_less(s, pk.n()) {
        return Err(SignatureError::DecodingError("signature representative out of range"));
    }
    Ok(K::public_exp(pk.n(), pk.e(), s))
}

/// `x^e mod n` for a public exponent, the shared core of RSAVP1 and RSAEP: `x` must already be
/// below `n`. The size marker's `public_exp` forwards here with the size's widths. Variable
/// time in `n` and `e`, which are public, and constant time in `x`, which RSAEP's is not.
pub(crate) fn public_exp<const L: usize, const L2: usize, const L21: usize>(
    n: &[u64; L],
    e: u64,
    x: &[u64; L],
) -> [u64; L] {
    let ctx = MontgomeryContext::<L>::for_public_modulus(n)
        .expect("the modulus is odd: a key's is, by its constructor");
    mod_pow_public_exponent::<L, L2, L21>(x, e, &ctx)
}

/// RSASP1 (RFC 8017 §5.2.1): `s = m^d mod n` by the CRT, released only if `s^e mod n` is `m`
/// again.
///
/// Step 1's range check is `Err(`[`SignatureError::DecodingError`]`)`. A result that fails its
/// check is `Err(`[`SignatureError::ComputationFault`]`)`, with nothing of it returned: the
/// computation went wrong.
pub(crate) fn rsasp1<K: RsaSigningSize>(
    sk: &RsaPrivateComponents<K>,
    m: &K::Limbs,
) -> Result<K::Limbs, SignatureError> {
    // RFC 8017 §5.2.1 step 1: the representative must be in [0, n - 1].
    if !K::is_less(m, sk.n()) {
        return Err(SignatureError::DecodingError("message representative out of range"));
    }
    let mut s = K::Limbs::ZEROED;
    if !K::crt_exp(sk, m, &mut s).to_bool() {
        return Err(SignatureError::ComputationFault);
    }
    Ok(s)
}

/// RFC 8017 §3.2's three conditions on a private key in the CRT form, which make the quintuple
/// and `e` one key, in this order: `e * dP == 1 (mod (p - 1))`, `e * dQ == 1 (mod (q - 1))`
/// and `q * qInv == 1 (mod p)`. They are SP 800-56B Rev. 2 §6.4.1.4.3 step 7's d, e and f, and
/// with them its a, b and c hold: a `dP` of 1 or of `p - 1` satisfies no such congruence for an
/// `e` below `p - 1`, nor does a `qInv` of 1 for a `q` that is not 1 modulo `p`.
///
/// `p` and `q` are odd, which the caller has checked. Constant time in the five components:
/// each residue comes from a bit-serial reduction and is compared over every limb, and none
/// of the three verdicts is branched on here.
pub(crate) fn crt_congruences<const HALF: usize, const HALF2: usize>(
    p: &[u64; HALF],
    q: &[u64; HALF],
    d_p: &[u64; HALF],
    d_q: &[u64; HALF],
    q_inv: &[u64; HALF],
    e: u64,
) -> [Condition<u64>; 3] {
    const { assert!(HALF2 == 2 * HALF, "the double width HALF2 must be 2 * HALF") };
    let mut q_q_inv = montgomery::widening_mul::<HALF, HALF2>(q, q_inv);
    let mut q_q_inv_mod_p = reduce_wide::<HALF2, HALF>(&q_q_inv, p);
    let q_inv_ok = is_one(&q_q_inv_mod_p);
    zeroize_in_place(&mut q_q_inv);
    zeroize_in_place(&mut q_q_inv_mod_p);
    [inverts_e_mod_prime_minus_1(d_p, e, p), inverts_e_mod_prime_minus_1(d_q, e, q), q_inv_ok]
}

/// Whether `e * d == 1 (mod (prime - 1))`, for an odd `prime`.
fn inverts_e_mod_prime_minus_1<const HALF: usize>(
    d: &[u64; HALF],
    e: u64,
    prime: &[u64; HALF],
) -> Condition<u64> {
    // `prime` is odd, so clearing its lowest bit subtracts 1.
    let mut prime_minus_1 = *prime;
    prime_minus_1[0] &= !1;
    let mut residue = mul_u64_mod(d, e, &prime_minus_1);
    let ok = is_one(&residue);
    zeroize_in_place(&mut prime_minus_1);
    zeroize_in_place(&mut residue);
    ok
}

/// Whether `x == 1`, over every limb.
fn is_one<const N: usize>(x: &[u64; N]) -> Condition<u64> {
    let mut diff = x[0] ^ 1;
    for limb in &x[1..] {
        diff |= limb;
    }
    Condition::<u64>::is_zero(diff)
}

/// Overwrites the stack that the previous call made from the caller's frame used, by taking a
/// frame of its own over the same memory and wiping it. Never inlined: the frame is the point.
/// The caller runs its computation in a never-inlined function, so that everything the
/// computation and its callees spill or stage lies below the caller's frame, and calls this
/// next.
///
/// The frame is `COUNT` values of `T`, for the part of the computation's stack that scales
/// with the modulus (`T` is a limb array of the size in hand), and `FIXED` words for the part
/// that does not. Each caller gives the measured figures beside its constants.
///
/// The shape of `wipe_stack_below` in `bouncycastle-ed` (`ed25519/scalar.rs`) and
/// `bouncycastle-sha3` (`keccak.rs`), which are private to those crates and of one fixed size.
/// Like theirs it is sized for an optimised build: an unoptimised build's frames are larger
/// and are not covered.
#[inline(never)]
pub(crate) fn wipe_stack_below<T: ZeroizablePrimitive, const COUNT: usize, const FIXED: usize>() {
    let mut scaled = Secret::<[T; COUNT]>::new();
    let mut fixed = Secret::<[u64; FIXED]>::new();
    core::hint::black_box((&mut *scaled, &mut *fixed));
}

/// [`wipe_stack_below`] when it goes out of scope, for a function whose result is itself the
/// secret and is returned by value. Such a function ends with the call that does the work, so
/// that the result is written to where the function's own caller wants it and not staged in
/// this frame, and declares this first, so that the wipe runs after that call has returned:
///
/// ```text
/// let _wipe = WipeStackBelowOnReturn::<T, COUNT, FIXED>::new();
/// Self::the_work_in_own_frame(..)
/// ```
pub(crate) struct WipeStackBelowOnReturn<
    T: ZeroizablePrimitive,
    const COUNT: usize,
    const FIXED: usize,
>(core::marker::PhantomData<T>);

impl<T: ZeroizablePrimitive, const COUNT: usize, const FIXED: usize>
    WipeStackBelowOnReturn<T, COUNT, FIXED>
{
    pub(crate) fn new() -> Self {
        Self(core::marker::PhantomData)
    }
}

impl<T: ZeroizablePrimitive, const COUNT: usize, const FIXED: usize> Drop
    for WipeStackBelowOnReturn<T, COUNT, FIXED>
{
    fn drop(&mut self) {
        wipe_stack_below::<T, COUNT, FIXED>();
    }
}

/// What [`wipe_stack_below`] overwrites after the checked CRT: this many `[u64; L]` values and
/// this many words. Measured in x86-64 release builds (rustc 1.88 and 1.97), the computation
/// and everything it calls use 8248 bytes at RSA-2048, 10552 at RSA-3072, 13752 at RSA-4096
/// and 27592 at RSA-8192; these cover 9600, 13440, 17280 and 32640, the difference being
/// room for a compiler that lays the frames out less tightly.
const CRT_STACK_PER_LIMB: usize = 30;
const CRT_STACK_FIXED: usize = 240;

/// The CRT exponentiation of RSASP1 and RSADP, [`crt_exp`], with its result checked before any
/// of it leaves: `y = x^d mod n` goes into `out` only if `y^e mod n` is `x` again, which it is
/// whenever both half-exponentiations were computed correctly (that the key's components
/// belong together is its constructor's check). Otherwise `out` is zero and the return is
/// FALSE. A CRT result that is right modulo one prime and wrong modulo the other must not be
/// seen, by a verifier or anyone else.
///
/// `x < n`. Constant time in the key and in `y`: the comparison is over every limb, and `out`
/// is written through a mask either way. The size marker's `crt_exp` forwards here.
///
/// The contexts over `p` and `q`, the two half-size results, `h` and `q * h` pass through
/// locals, return slots and spilled registers of this computation and its callees, where the
/// scrubbing of the named values does not reach. So it runs in a frame of its own and the
/// stack it used is overwritten afterwards.
#[allow(clippy::too_many_arguments)]
pub(crate) fn crt_exp_checked<
    const L: usize,
    const L2: usize,
    const L21: usize,
    const HALF: usize,
    const HALF2: usize,
    const HALF21: usize,
>(
    p: &[u64; HALF],
    q: &[u64; HALF],
    d_p: &[u64; HALF],
    d_q: &[u64; HALF],
    q_inv: &[u64; HALF],
    n: &[u64; L],
    e: u64,
    x: &[u64; L],
    out: &mut [u64; L],
) -> Condition<u64> {
    let ok = crt_exp_checked_in_own_frame::<L, L2, L21, HALF, HALF2, HALF21>(
        p, q, d_p, d_q, q_inv, n, e, x, out,
    );
    wipe_stack_below::<[u64; L], CRT_STACK_PER_LIMB, CRT_STACK_FIXED>();
    ok
}

/// The computation of [`crt_exp_checked`]. Never inlined, so that what it and its callees
/// leave lies below its caller's frame, where [`wipe_stack_below`] reaches it.
#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn crt_exp_checked_in_own_frame<
    const L: usize,
    const L2: usize,
    const L21: usize,
    const HALF: usize,
    const HALF2: usize,
    const HALF21: usize,
>(
    p: &[u64; HALF],
    q: &[u64; HALF],
    d_p: &[u64; HALF],
    d_q: &[u64; HALF],
    q_inv: &[u64; HALF],
    n: &[u64; L],
    e: u64,
    x: &[u64; L],
    out: &mut [u64; L],
) -> Condition<u64> {
    let mut y = crt_exp::<L, L2, L21, HALF, HALF2, HALF21>(p, q, d_p, d_q, q_inv, x);
    // y < n whatever the components hold (y = s_2 + q * h with s_2 < q and h < p), and the
    // public exponentiation is constant time in its base.
    let mut back = public_exp::<L, L2, L21>(n, e, &y);
    let mut diff = 0u64;
    for i in 0..L {
        diff |= back[i] ^ x[i];
    }
    let ok = Condition::<u64>::is_zero(diff);
    for i in 0..L {
        out[i] = ok.select(y[i], 0);
    }
    zeroize_in_place(&mut y);
    zeroize_in_place(&mut back);
    ok
}

/// RFC 8017 §5.2.1 step 2.b, the CRT form of `m^d mod n`, over the five components (RSADP's
/// step 2.b in §5.1.2 is the same computation, its sub-steps numbered i to iv), without the
/// result check [`crt_exp_checked`] wraps it in. Constant time in the key: the two
/// contexts are built by `MontgomeryContext::for_secret_modulus`, every exponentiation is
/// `mod_pow`'s ladder, every reduction `reduce_wide`'s bit-serial loop.
pub(crate) fn crt_exp<
    const L: usize,
    const L2: usize,
    const L21: usize,
    const HALF: usize,
    const HALF2: usize,
    const HALF21: usize,
>(
    p: &[u64; HALF],
    q: &[u64; HALF],
    d_p: &[u64; HALF],
    d_q: &[u64; HALF],
    q_inv: &[u64; HALF],
    m: &[u64; L],
) -> [u64; L] {
    let mut ctx_p = Secret::<MontgomeryContext<HALF>>::new();
    // Odd, as `for_secret_modulus` needs: `RsaPrivateComponents::from_crt_components` checked.
    *ctx_p = MontgomeryContext::<HALF>::for_secret_modulus(p);
    let mut ctx_q = Secret::<MontgomeryContext<HALF>>::new();
    *ctx_q = MontgomeryContext::<HALF>::for_secret_modulus(q);
    // Step 2.b.1: s_1 = m^dP mod p, s_2 = m^dQ mod q, each on m reduced to the prime's width.
    let mut m_mod_p = reduce_wide::<L, HALF>(m, p);
    let mut m_mod_q = reduce_wide::<L, HALF>(m, q);
    let mut s1 = mod_pow::<HALF, HALF2, HALF21>(&m_mod_p, d_p, &ctx_p);
    let mut s2 = mod_pow::<HALF, HALF2, HALF21>(&m_mod_q, d_q, &ctx_q);
    // Step 2.b.3: h = (s_1 - s_2) * qInv mod p, with s_2 reduced mod p first (the primes need
    // not be the same length; see RsaPrivateComponents' docs).
    let mut s2_mod_p = reduce_wide::<HALF, HALF>(&s2, p);
    let mut diff = sub_mod::<HALF>(&s1, &s2_mod_p, p);
    let mut h = mul_mod::<HALF, HALF2, HALF21>(&diff, q_inv, &ctx_p);
    // Step 2.b.4: s = s_2 + q * h.
    let mut q_h = montgomery::widening_mul::<HALF, L>(q, &h);
    let mut s2_wide = [0u64; L];
    s2_wide[..HALF].copy_from_slice(&s2);
    let (s, carry) = nat::add(&s2_wide, &q_h);
    debug_assert_eq!(carry, 0, "CRT recombination must stay within n's width");
    zeroize_in_place(&mut m_mod_p);
    zeroize_in_place(&mut m_mod_q);
    zeroize_in_place(&mut s1);
    zeroize_in_place(&mut s2);
    zeroize_in_place(&mut s2_mod_p);
    zeroize_in_place(&mut diff);
    zeroize_in_place(&mut h);
    zeroize_in_place(&mut q_h);
    zeroize_in_place(&mut s2_wide);
    s
}

#[cfg(test)]
mod tests {
    //! `rsasp1`/`rsavp1` are deliberately crate-private (see the module docs), so they cannot be
    //! reached from `tests/` the way every other primitive in this crate is exercised -- this is
    //! the "high-risk code that ... cannot be reached through the public API" exception
    //! `CLAUDE.md`'s testing notes describe. The key is a genuine RSA-2048 key pair, the first
    //! SHA-256 group of Wycheproof's `rsa_pkcs1_2048_sig_gen_test.json` (`e = 65537`; see
    //! `tests/rsa_2048_pkcs1_v1_5_tests.rs` for its provenance), and every expected signature
    //! was computed in Python and cross-checked two ways before being pasted here: CRT
    //! recombination against plain `pow(m, d, n)`, and `pow(pow(m, d, n), e, n) == m`.

    use super::*;

    use crate::size::RSA2048;

    fn keypair() -> RsaPrivateComponents<RSA2048> {
        let p: [u64; 16] = [
            0x0ea36cfb3a5b18f1, 0x48a6e65332119129, 0x110ad9e7b48a1c93, 0x569156b90113e2e9,
            0xe79813a575cfad9c, 0x69d659d143ec6f17, 0xe81e6bab5ddaa783, 0xbff1c5b80a69f788,
            0x978f6c35814f50ee, 0xe6a289ad4cfbf78f, 0x34d5681e5809d415, 0xbb028bda42eeb5d2,
            0x41c56e4de086b0d5, 0x58b8d1e24f3b55d0, 0xfb5248247d98cb7d, 0xdc431050f782e894,
        ];
        let q: [u64; 16] = [
            0x669f140cfbc20f25, 0xb97bb03677207d95, 0xfd4e06f3ed7299d4, 0x160f90536abc9492,
            0xf5b131f39098f7bc, 0xae8d72c57088d7ab, 0x89b94fbde542aba9, 0x3d3f9880ec47d5e0,
            0x1378a6868af3b7a0, 0x5544070beb057c94, 0x16611debc472fac4, 0xe500ffb79f5b8868,
            0x308a5e32196603b2, 0xea5fb19eb4eabc38, 0x122273ae3222b598, 0xbd1a81e7977f9898,
        ];
        let d_p: [u64; 16] = [
            0x209f33f09515d7c1, 0xb4a9b37656917205, 0x276933bb07e4efb9, 0x8c14019808e00414,
            0x289f96da220711e5, 0xfbbd2923d31532fe, 0xc06b414e61c0e1e7, 0x4c23c4588488961d,
            0x4dc48ae34514759c, 0x9c786961ae3e2c35, 0x497e8d9c650688e0, 0x18bf08472612dbe5,
            0x8885fb161870ee12, 0xf21d7c1479d99d47, 0x9121d91952ffd1c7, 0xa94b528b28f29159,
        ];
        let d_q: [u64; 16] = [
            0xf7597ffb68011d8d, 0x7b3cc538c4bab8c9, 0xa8fa480a81a925af, 0x6d6ede7251a383bf,
            0x8a63f788ce3a0f85, 0x0b920502eb478bc9, 0x7e37e755edfe70d9, 0x9cf9948422a16555,
            0x0d6d9ea1f2ef71fd, 0xf7efa32ea0cb6e00, 0x0629b114ca7f780f, 0xcf51176359654348,
            0x540cdcbd4ad35435, 0x31c02ff1a2bc437c, 0xff2503df78bafed5, 0x3af0e72a933aef09,
        ];
        let q_inv: [u64; 16] = [
            0x552fe4bfce945f7b, 0x67e50c999c67247b, 0xfb54ef17be3b2853, 0x241f5921b5ad3983,
            0x02de5eccd143cf31, 0x74e45f6fcc60f216, 0xafa5428a74f12708, 0x88d42294b6a2759b,
            0xe923e1097c0c562f, 0xc968b48a91c38b5b, 0x933e85179c0320b0, 0x7993d0445f758d51,
            0x9bfc042ee0924b1b, 0x41f956d90fa8a793, 0xee7a87b6483a66ee, 0x2640fbfbcfefb163,
        ];
        RsaPrivateComponents::from_crt_components(&p, &q, &d_p, &d_q, &q_inv, 0x00010001)
            .expect("genuine CRT components must be accepted")
    }

    fn public_key(sk: &RsaPrivateComponents<RSA2048>) -> RsaPublicComponents<RSA2048> {
        RsaPublicComponents::new(sk.n(), 0x00010001).expect("e = 65537 is valid")
    }

    #[test]
    fn rsasp1_matches_python_crt_and_rsavp1_recovers_m() {
        let sk = keypair();
        let pk = public_key(&sk);

        let m: [u64; 32] = [
            0x000000e8d4a50fff, 0x0000000000000000, 0x0000000000000000, 0x7ff3af8ff7be0800,
            0x67ad7342574d2811, 0x4976e38546b81ac1, 0x2b70b32f6c55125e, 0x00cb3167f0fdb915,
            0x370a38a0a48c0523, 0x6a9a91b20989ab70, 0x612d6fd7e2bb4495, 0x0000000000015112,
            0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
            0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
            0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
            0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
            0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
        ];
        let expected_s: [u64; 32] = [
            0xd5bc2d48a83b31e5, 0xd48a52b64b6b96b5, 0xdc4ca2421de42187, 0x4c6118a19591ea09,
            0xe849ca6daac6241f, 0x2678c5b1e6e79065, 0xee29c430e55bc557, 0xf302e3591357ce98,
            0x686f541f63912448, 0x439b31f48f6dc764, 0xf3e71f9194357f28, 0x42de8ac88d93e447,
            0x6827ee7425c4211b, 0x7827dcf7d9dd02e5, 0xcdbd9c101bd7827e, 0xac2df3ab2f1b6d57,
            0x22530d053b2c62c2, 0x97d455fb10d0016f, 0xda0173ac606bf822, 0xde58560afb5b0a77,
            0x0b5863a4b0a2a080, 0x310470fcb7994b88, 0x7edc02bc4dba6d65, 0x62357119beba7486,
            0x6c6680551d7b3fda, 0x085593ca5407542f, 0xd28b00187aea208d, 0x8043e9a53c324baf,
            0x7e10dc6aefa091e0, 0xe23d3889a371d248, 0x01c491dd0a01f0c4, 0x4e47e60636bb4dac,
        ];

        let s = rsasp1::<RSA2048>(&sk, &m).expect("m is in range");
        assert_eq!(s, expected_s);

        let recovered = rsavp1::<RSA2048>(&pk, &s).expect("s is in range");
        assert_eq!(recovered, m);
    }

    #[test]
    fn rsasp1_second_vector_near_n_minus_1() {
        let sk = keypair();
        let pk = public_key(&sk);

        // m2 = n - 12345, exercising a message representative close to the top of the range.
        let m2: [u64; 32] = [
            0xf7820283f742899c, 0x6f453d1f5b4c2e9c, 0x9a02e5a530e77306, 0x5d12569a62807d3b,
            0xc22c4e5ac0f7c1a4, 0xf9f85e7975005d9b, 0x1b4d9cae79d460d8, 0x69816f48698bcbba,
            0x126422f590975a19, 0xfd7afc3e09ada0f1, 0xed5411eb878daf05, 0x4c03145b5d3495d4,
            0x12be82de4d1ece6b, 0x21d0fceca08d945a, 0x7d9658594266f5c0, 0x4c22da610428e09c,
            0x90ed81299615d981, 0x7a1fa26a8dce26f4, 0x3eff8f17e1a02939, 0x254a2fe9765313a0,
            0x3d3e42e46e48c98e, 0xcd20f79c15e8247f, 0x2ed8a7711a1253fa, 0xb5ab393189db9251,
            0x9e89d6eac8845097, 0x1700f65903b46942, 0x1878d80325b6ef5a, 0x37f9746d3f7cafd3,
            0x094fa1fee82224e6, 0x4a8a5b462ebef717, 0x6e45567151355051, 0xa2b451a07d0aa5f9,
        ];
        let expected_s2: [u64; 32] = [
            0x21aaf584e305ddf7, 0x21f3dccf3e5072ee, 0xf5e0eb3cd82ad5d7, 0x1754c77f5c4bd685,
            0x8c396d2e90dd96b8, 0x4535e22014c3503d, 0x0159ab66fe04959d, 0xecfe054486820710,
            0x7a27dbbfe19204e9, 0x02c060ac0fdc597f, 0xd2def08324675a05, 0x28d6ecd14d476bed,
            0xf81f1e10e1198c2d, 0x8d343c8f7f43413c, 0x578f55bc4294e74d, 0x5755f9ad526bce2d,
            0xc9ca96c13523a148, 0x513f3dadc0bb6784, 0xab72f632a4f73988, 0x59005fd0f7af24ef,
            0x4f197c87199b0283, 0x66b27811e159eb5f, 0xfa688afc1b45df99, 0xc07a9c95704d1dde,
            0x52b56f684cd42de3, 0x8c9d4bbaad4fafb8, 0x6954ceced63aa41b, 0x08b40e0ff164edff,
            0x6e93ed6bdb3aa4d0, 0xd95b97bc72531c4e, 0x3bdde22a09aea05c, 0x062ce3e60377e92e,
        ];

        let s2 = rsasp1::<RSA2048>(&sk, &m2).expect("m2 is in range");
        assert_eq!(s2, expected_s2);
        assert_eq!(rsavp1::<RSA2048>(&pk, &s2).expect("s2 is in range"), m2);
    }

    #[test]
    fn rsasp1_rejects_out_of_range_message() {
        let sk = keypair();
        let out_of_range = *sk.n();
        assert!(matches!(
            rsasp1::<RSA2048>(&sk, &out_of_range),
            Err(SignatureError::DecodingError(_))
        ));
    }

    #[test]
    fn rsavp1_rejects_out_of_range_signature() {
        let sk = keypair();
        let pk = public_key(&sk);
        let out_of_range = *pk.n();
        assert!(matches!(
            rsavp1::<RSA2048>(&pk, &out_of_range),
            Err(SignatureError::DecodingError(_))
        ));
    }

    mod damaged_keys {
        //! The result of a private-key operation is checked before it is released (the crate's
        //! `# Security Considerations`). A key's constructor refuses components that do not belong
        //! together, so what the check is for, a fault in the computation, cannot be provoked from
        //! `tests/`: these build the damaged key past the constructor
        //! (`RsaPrivateComponents::unvalidated`, which exists in test builds only) and stand for the
        //! fault. Each private-key operation then returns its error and leaves the caller's buffer
        //! zeroized, under RSASSA-PKCS1-v1_5, RSASSA-PSS, RSASVE (raw and through HKDF) and
        //! RSAES-OAEP (as a KEM and as key transport); the sound key does all of them.

        use crate::keys::{RsaPrivateComponents, RsaPublicComponents};
        use crate::rsa_2048::{
            RSA2048KEMPrivateKey, RSA2048KEMPublicKey, RSASSA_PKCS1_v1_5_SHA256, RSASSA_PSS_SHA256,
        };
        use crate::rsaes_oaep::OaepParams;
        use crate::rsassa;
        use crate::rsasve::RsaKEMPrivateKey;
        use crate::size::{RSA2048, RsaSigningSize, RsaSize};
        use bouncycastle_core::errors::{KEMError, KeyTransportError, SignatureError};
        use bouncycastle_core::kdf_params::{KdfParams, KeyLen};
        use bouncycastle_core::kem_key::{DecapsulatingKey, EncapsulatingKey};
        use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
        use bouncycastle_core::key_transport_key::{
            KeyTransportDecryptingKey, KeyTransportEncryptingKey,
        };
        use bouncycastle_core::signature_key::{
            DeterministicOneShotSigningKey, DeterministicSigningKey, OneShotSigningKey,
            OneShotVerifyingKey, SigningKey,
        };
        use bouncycastle_core::traits::SignatureSigner;
        use bouncycastle_hkdf::HkdfDescription;
        use bouncycastle_rng::DefaultRNG;
        use bouncycastle_sha2::SHA256;

        // A genuine RSA-2048 key: the first SHA-256 group of Wycheproof's
        // `rsa_pkcs1_2048_sig_gen_test.json` (`tests/rsa_2048_pkcs1_v1_5_tests.rs` has the provenance),
        // with e = 65537.
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
        const D_P: [u64; 16] = [
            0x209f33f09515d7c1, 0xb4a9b37656917205, 0x276933bb07e4efb9, 0x8c14019808e00414,
            0x289f96da220711e5, 0xfbbd2923d31532fe, 0xc06b414e61c0e1e7, 0x4c23c4588488961d,
            0x4dc48ae34514759c, 0x9c786961ae3e2c35, 0x497e8d9c650688e0, 0x18bf08472612dbe5,
            0x8885fb161870ee12, 0xf21d7c1479d99d47, 0x9121d91952ffd1c7, 0xa94b528b28f29159,
        ];
        const D_Q: [u64; 16] = [
            0xf7597ffb68011d8d, 0x7b3cc538c4bab8c9, 0xa8fa480a81a925af, 0x6d6ede7251a383bf,
            0x8a63f788ce3a0f85, 0x0b920502eb478bc9, 0x7e37e755edfe70d9, 0x9cf9948422a16555,
            0x0d6d9ea1f2ef71fd, 0xf7efa32ea0cb6e00, 0x0629b114ca7f780f, 0xcf51176359654348,
            0x540cdcbd4ad35435, 0x31c02ff1a2bc437c, 0xff2503df78bafed5, 0x3af0e72a933aef09,
        ];
        const Q_INV: [u64; 16] = [
            0x552fe4bfce945f7b, 0x67e50c999c67247b, 0xfb54ef17be3b2853, 0x241f5921b5ad3983,
            0x02de5eccd143cf31, 0x74e45f6fcc60f216, 0xafa5428a74f12708, 0x88d42294b6a2759b,
            0xe923e1097c0c562f, 0xc968b48a91c38b5b, 0x933e85179c0320b0, 0x7993d0445f758d51,
            0x9bfc042ee0924b1b, 0x41f956d90fa8a793, 0xee7a87b6483a66ee, 0x2640fbfbcfefb163,
        ];

        const E: u64 = 65537;
        const MSG: &[u8] = b"a message";

        /// The sound key and four damaged ones, each named: one bit flipped in `dP`, in `dQ` and in
        /// `qInv`, and the sound components under an exponent that is not theirs.
        fn keys()
        -> (RsaPrivateComponents<RSA2048>, [(&'static str, RsaPrivateComponents<RSA2048>); 4])
        {
            let key = |d_p: &[u64; 16], d_q: &[u64; 16], q_inv: &[u64; 16], e: u64| {
                RsaPrivateComponents::<RSA2048>::unvalidated(&P, &Q, d_p, d_q, q_inv, e)
            };
            let flipped = |x: &[u64; 16], limb: usize, bit: u32| {
                let mut x = *x;
                x[limb] ^= 1 << bit;
                x
            };
            let damaged = [
                ("dP", key(&flipped(&D_P, 0, 1), &D_Q, &Q_INV, E)),
                ("dQ", key(&D_P, &flipped(&D_Q, 7, 40), &Q_INV, E)),
                ("qInv", key(&D_P, &D_Q, &flipped(&Q_INV, 15, 3), E)),
                ("e", key(&D_P, &D_Q, &Q_INV, 65539)),
            ];
            (key(&D_P, &D_Q, &Q_INV, E), damaged)
        }

        /// The key-establishment key over the same components.
        fn kem_key(components: &RsaPrivateComponents<RSA2048>) -> RSA2048KEMPrivateKey {
            RsaKEMPrivateKey(components.clone())
        }

        /// The size's checked exponentiation itself: a sound key gives the value that `e` takes back
        /// to the input, and a damaged one gives FALSE and an output of zero.
        #[test]
        fn the_checked_exponentiation_releases_only_a_result_that_e_inverts() {
            let (sound, damaged) = keys();
            let mut x = [0u64; 32];
            x[0] = 0x0123_4567_89ab_cdef;
            x[17] = 0xfeed_face_cafe_f00d;

            let mut y = [0xFFFF_FFFF_FFFF_FFFFu64; 32];
            assert!(RSA2048::crt_exp(&sound, &x, &mut y).to_bool());
            assert_eq!(RSA2048::public_exp(sound.n(), E, &y), x);

            for (what, sk) in &damaged {
                let mut y = [0xFFFF_FFFF_FFFF_FFFFu64; 32];
                assert!(!RSA2048::crt_exp(sk, &x, &mut y).to_bool(), "{what}");
                assert_eq!(y, [0u64; 32], "{what}");
            }
        }

        #[test]
        fn a_damaged_key_does_not_sign_pkcs1_v1_5() {
            let (sound, damaged) = keys();
            let pk = RsaPublicComponents::<RSA2048>::new(sound.n(), E).unwrap();
            let sig =
                sound.key::<RSASSA_PKCS1_v1_5_SHA256>().sign_deterministic(MSG, None).unwrap();
            pk.key::<RSASSA_PKCS1_v1_5_SHA256>().verify(MSG, None, &sig).unwrap();

            for (what, sk) in damaged {
                let sk = sk.into_key::<RSASSA_PKCS1_v1_5_SHA256>();
                assert_eq!(
                    sk.sign_deterministic(MSG, None),
                    Err(SignatureError::ComputationFault),
                    "{what}"
                );
                let mut out = [0xFFu8; 256];
                assert_eq!(
                    sk.sign_deterministic_out(MSG, None, &mut out),
                    Err(SignatureError::ComputationFault),
                    "{what}"
                );
                assert_eq!(out, [0u8; 256], "{what}");
                // Streaming, and from the hash.
                let mut signer = sk.create_signer_deterministic(None).unwrap();
                signer.do_update(MSG);
                let mut out = [0xFFu8; 256];
                assert_eq!(
                    signer.do_final_out(&mut out),
                    Err(SignatureError::ComputationFault),
                    "{what}"
                );
                assert_eq!(out, [0u8; 256], "{what}");
                assert_eq!(
                    rsassa::sign_from_hash_deterministic(&sk, &[0x11; 32]),
                    Err(SignatureError::ComputationFault),
                    "{what}"
                );
            }
        }

        #[test]
        fn a_damaged_key_does_not_sign_pss() {
            let (sound, damaged) = keys();
            let mut rng = DefaultRNG::default();
            let pk = RsaPublicComponents::<RSA2048>::new(sound.n(), E).unwrap();
            let sig = sound.key::<RSASSA_PSS_SHA256>().sign(&mut rng, MSG, None).unwrap();
            pk.key::<RSASSA_PSS_SHA256>().verify(MSG, None, &sig).unwrap();

            for (what, sk) in damaged {
                let sk = sk.into_key::<RSASSA_PSS_SHA256>();
                assert_eq!(
                    sk.sign(&mut rng, MSG, None),
                    Err(SignatureError::ComputationFault),
                    "{what}"
                );
                let mut out = [0xFFu8; 256];
                assert_eq!(
                    sk.sign_out(&mut rng, MSG, None, &mut out),
                    Err(SignatureError::ComputationFault),
                    "{what}"
                );
                assert_eq!(out, [0u8; 256], "{what}");
                // Streaming with the salt given, from the hash with a salt drawn, and with one given.
                let mut signer = sk.create_signer(&mut rng, None).unwrap();
                signer.set_salt([0x42u8; 32]);
                signer.do_update(MSG);
                let mut out = [0xFFu8; 256];
                assert_eq!(
                    signer.do_final_out(&mut out),
                    Err(SignatureError::ComputationFault),
                    "{what}"
                );
                assert_eq!(out, [0u8; 256], "{what}");
                assert_eq!(
                    rsassa::sign_from_hash(&sk, &[0x11; 32], &mut rng),
                    Err(SignatureError::ComputationFault),
                    "{what}"
                );
                assert_eq!(
                    rsassa::sign_from_hash_with_salt(&sk, &[0x11; 32], &[0x42; 32]),
                    Err(SignatureError::ComputationFault),
                    "{what}"
                );
            }
        }

        /// RSASVE and RSASVE with HKDF: the secret value of a ciphertext made for the sound key is
        /// not handed out by a damaged one.
        #[test]
        fn a_damaged_key_does_not_decapsulate_rsasve() {
            let (sound, damaged) = keys();
            let mut rng = DefaultRNG::default();
            let pk = RSA2048KEMPublicKey::new(sound.n(), E).unwrap();
            let sound = kem_key(&sound);
            let hkdf = HkdfDescription::<SHA256>::new();
            let params = KdfParams::new(&hkdf, b"info", KeyLen::<32>);

            let (z, ct) = pk.encaps(&mut rng, ()).unwrap();
            assert_eq!(sound.decaps(&ct, ()).unwrap(), z);
            let (key, ct_kdf) = pk.encaps(&mut rng, params).unwrap();
            assert_eq!(sound.decaps(&ct_kdf, params).unwrap(), key);

            for (what, sk) in damaged {
                let sk = kem_key(&sk);
                assert!(matches!(sk.decaps(&ct, ()), Err(KEMError::DecapsulationFailed)), "{what}");
                let mut ss = KeyMaterial::<256>::from_bytes(&[0xEE; 256]).unwrap();
                assert_eq!(
                    sk.decaps_out(&ct, (), &mut ss),
                    Err(KEMError::DecapsulationFailed),
                    "{what}"
                );
                assert_eq!(ss.key_type(), KeyType::Zeroized, "{what}");
                assert_eq!(ss.key_len(), 0, "{what}");

                let mut ss = KeyMaterial::<32>::from_bytes(&[0xEE; 32]).unwrap();
                assert_eq!(
                    sk.decaps_out(&ct_kdf, params, &mut ss),
                    Err(KEMError::DecapsulationFailed),
                    "{what}"
                );
                assert_eq!(ss.key_type(), KeyType::Zeroized, "{what}");
            }
        }

        /// RSAES-OAEP: a failed result check is the one decryption error, as a wrong label is, with
        /// the key buffer zeroized, for the KEM and for key transport.
        #[test]
        fn a_damaged_key_does_not_decrypt_oaep() {
            let (sound, damaged) = keys();
            let mut rng = DefaultRNG::default();
            let pk = RSA2048KEMPublicKey::new(sound.n(), E).unwrap();
            let sound = kem_key(&sound);
            let params = OaepParams::<SHA256>::new(b"label");

            let (ss, ct) = pk.encaps(&mut rng, params).unwrap();
            assert_eq!(sound.decaps(&ct, params).unwrap(), ss);
            let sent = KeyMaterial::<48>::from_bytes_as_type(&[0x42; 48], KeyType::MACKey).unwrap();
            let ct_sent = pk.transport(&mut rng, params, &sent).unwrap();
            let mut recovered = KeyMaterial::<64>::new();
            assert_eq!(sound.recover_out(&ct_sent, params, &mut recovered), Ok(48));
            assert_eq!(recovered.ref_to_bytes(), [0x42; 48]);

            // What any other decryption failure looks like: the sound key under the wrong label.
            let wrong = OaepParams::<SHA256>::new(b"another label");
            let mut out = KeyMaterial::<64>::from_bytes(&[0xEE; 64]).unwrap();
            assert_eq!(
                sound.recover_out(&ct_sent, wrong, &mut out),
                Err(KeyTransportError::DecryptionFailed)
            );
            assert_eq!(out.key_type(), KeyType::Zeroized);

            for (what, sk) in damaged {
                let sk = kem_key(&sk);
                assert!(
                    matches!(sk.decaps(&ct, params), Err(KEMError::DecapsulationFailed)),
                    "{what}"
                );
                let mut ss = KeyMaterial::<32>::from_bytes(&[0xEE; 32]).unwrap();
                assert_eq!(
                    sk.decaps_out(&ct, params, &mut ss),
                    Err(KEMError::DecapsulationFailed),
                    "{what}"
                );
                assert_eq!(ss.key_type(), KeyType::Zeroized, "{what}");

                let mut out = KeyMaterial::<64>::from_bytes(&[0xEE; 64]).unwrap();
                assert_eq!(
                    sk.recover_out(&ct_sent, params, &mut out),
                    Err(KeyTransportError::DecryptionFailed),
                    "{what}"
                );
                assert_eq!(out.key_type(), KeyType::Zeroized, "{what}");
                assert_eq!(out.key_len(), 0, "{what}");
            }
        }
    }
}
