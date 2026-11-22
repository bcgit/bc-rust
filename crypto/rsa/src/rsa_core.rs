//! RSASP1 and RSAVP1 (RFC 8017 §5.2.1, §5.2.2): the raw signature and verification primitives.
//! Crate-private -- never exposed directly, only reachable through a padding scheme
//! (RSASSA-PKCS1-v1_5 or RSASSA-PSS, a later addition to this crate). RFC 8017's introduction to
//! §5 is explicit about why: "[primitives] are not intended to provide security apart from a
//! scheme" -- "textbook RSA" (signing a bare integer with no padding) is malleable and vulnerable
//! to existential forgery, so this crate does not let a caller reach [`rsasp1`]/[`rsavp1`] without
//! going through a scheme that fixes that.
//!
//! Both primitives operate on the two-prime case only (RFC 8017's `u = 2`, no additional
//! `(r_i, d_i, t_i)` triplets): [`crate::keys::RsaPrivateComponents`] has no representation for
//! multi-prime RSA, so there is nothing here to extend to `u > 2`.

use crate::keys::{RsaPrivateComponents, RsaPublicComponents};
use crate::modexp::{
    MontgomeryContext, mod_pow, mod_pow_public_exponent, mul_mod, reduce_wide, sub_mod,
};
use crate::size::{RsaSigningSize, RsaSize};
use bouncycastle_core::errors::SignatureError;
use bouncycastle_ec::montgomery;
use bouncycastle_ec::nat;
use bouncycastle_utils::secret::{Secret, zeroize_in_place};

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
    e: u32,
    x: &[u64; L],
) -> [u64; L] {
    let ctx = MontgomeryContext::<L>::for_public_modulus(n)
        .expect("RsaPublicComponents::new already validated n is odd and nonzero");
    mod_pow_public_exponent::<L, L2, L21>(x, u64::from(e), &ctx)
}

pub(crate) fn rsasp1<K: RsaSigningSize>(
    sk: &RsaPrivateComponents<K>,
    m: &K::Limbs,
) -> Result<K::Limbs, SignatureError> {
    // RFC 8017 §5.2.1 step 1: the representative must be in [0, n - 1].
    if !K::is_less(m, sk.n()) {
        return Err(SignatureError::DecodingError("message representative out of range"));
    }
    Ok(K::crt_exp(sk, m))
}

/// RFC 8017 §5.2.1 step 2.b, the CRT form of `m^d mod n`, over the five components: the size
/// marker's `crt_exp` forwards here with the size's widths. Constant time in the key: the two
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
    *ctx_p = MontgomeryContext::<HALF>::for_secret_modulus(p)
        .expect("RsaPrivateComponents::from_crt_components already validated p is odd and nonzero");
    let mut ctx_q = Secret::<MontgomeryContext<HALF>>::new();
    *ctx_q = MontgomeryContext::<HALF>::for_secret_modulus(q)
        .expect("RsaPrivateComponents::from_crt_components already validated q is odd and nonzero");
    // Step 2.b.i: s_1 = m^dP mod p, s_2 = m^dQ mod q, each on m reduced to the prime's width.
    let mut m_mod_p = reduce_wide::<L, HALF>(m, p);
    let mut m_mod_q = reduce_wide::<L, HALF>(m, q);
    let mut s1 = mod_pow::<HALF, HALF2, HALF21>(&m_mod_p, d_p, &ctx_p);
    let mut s2 = mod_pow::<HALF, HALF2, HALF21>(&m_mod_q, d_q, &ctx_q);
    // Step 2.b.iii: h = (s_1 - s_2) * qInv mod p, with s_2 reduced mod p first (the primes need
    // not be the same length; see RsaPrivateComponents' docs).
    let mut s2_mod_p = reduce_wide::<HALF, HALF>(&s2, p);
    let mut diff = sub_mod::<HALF>(&s1, &s2_mod_p, p);
    let mut h = mul_mod::<HALF, HALF2, HALF21>(&diff, q_inv, &ctx_p);
    // Step 2.b.iv: s = s_2 + q * h.
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
        RsaPrivateComponents::from_crt_components(&p, &q, &d_p, &d_q, &q_inv)
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
}
