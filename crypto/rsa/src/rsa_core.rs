//! RSASP1 and RSAVP1 (RFC 8017 §5.2.1, §5.2.2): the raw signature and verification primitives.
//! Crate-private -- never exposed directly, only reachable through a padding scheme
//! (RSASSA-PKCS1-v1_5 or RSASSA-PSS, a later addition to this crate). RFC 8017's introduction to
//! §5 is explicit about why: "[primitives] are not intended to provide security apart from a
//! scheme" -- "textbook RSA" (signing a bare integer with no padding) is malleable and vulnerable
//! to existential forgery, so this crate does not let a caller reach [`rsasp1`]/[`rsavp1`] without
//! going through a scheme that fixes that.
//!
//! Both primitives operate on the two-prime case only (RFC 8017's `u = 2`, no additional
//! `(r_i, d_i, t_i)` triplets): [`crate::keys::RsaPrivateKey`] has no representation for
//! multi-prime RSA, so there is nothing here to extend to `u > 2`.

use crate::keys::{RsaPrivateKey, RsaPublicKey};
use crate::modexp::{MontgomeryContext, mod_pow, mul_mod, reduce_once, reduce_wide, sub_mod};
use bouncycastle_core::errors::SignatureError;
use bouncycastle_ec::montgomery;
use bouncycastle_ec::nat;

/// RSAVP1 (RFC 8017 §5.2.2): `m = s^e mod n`, recovering the message representative from a
/// signature representative under the public key.
///
/// Step 1's range check ("If the signature representative s is not between 0 and n - 1, output
/// 'signature representative out of range'") is `Err(`[`SignatureError::DecodingError`]`)` here.
pub(crate) fn rsavp1<const L: usize, const L2: usize, const L21: usize>(
    pk: &RsaPublicKey<L>,
    s: &[u64; L],
) -> Result<[u64; L], SignatureError> {
    if nat::sub(s, pk.n()).1 != 1 {
        return Err(SignatureError::DecodingError("signature representative out of range"));
    }
    let ctx = MontgomeryContext::<L>::new(pk.n())
        .expect("RsaPublicKey::new already validated n is odd and nonzero");

    let mut e_limbs = [0u64; L];
    e_limbs[0] = pk.e() as u64;

    Ok(mod_pow::<L, L2, L21>(s, &e_limbs, &ctx))
}

/// RSASP1 (RFC 8017 §5.2.1), CRT form (step 2.b, two-prime case): `s1 = m^dP mod p`, `s2 = m^dQ
/// mod q`, `h = (s1 - s2) * qInv mod p`, `s = s2 + q * h`.
///
/// Step 1's range check ("If the message representative m is not between 0 and n - 1, output
/// 'message representative out of range'") is `Err(`[`SignatureError::DecodingError`]`)` here.
pub(crate) fn rsasp1<
    const L: usize,
    const L2: usize,
    const L21: usize,
    const HALF: usize,
    const HALF2: usize,
    const HALF21: usize,
>(
    sk: &RsaPrivateKey<L, HALF>,
    m: &[u64; L],
) -> Result<[u64; L], SignatureError> {
    if nat::sub(m, sk.n()).1 != 1 {
        return Err(SignatureError::DecodingError("message representative out of range"));
    }

    let ctx_p = MontgomeryContext::<HALF>::new(sk.p())
        .expect("RsaPrivateKey::from_crt_components already validated p is odd and nonzero");
    let ctx_q = MontgomeryContext::<HALF>::new(sk.q())
        .expect("RsaPrivateKey::from_crt_components already validated q is odd and nonzero");

    // RFC 8017 §5.2.1 step 2.b.1: reducing `m` (n-width) down to each prime's width is not itself
    // part of the RFC's stated steps, which write "m^dP mod p" as if `m` already fit -- but `m`
    // is as wide as `n = p * q`, so a real implementation must reduce it first. `p`/`q` are
    // private key material, so this uses the constant-time (in the modulus) `reduce_wide`, not
    // `bouncycastle_ec`-style variable-time reduction (which is only safe for RSA's *public* `n`).
    let m_mod_p = reduce_wide::<L, HALF>(m, sk.p());
    let m_mod_q = reduce_wide::<L, HALF>(m, sk.q());

    let s1 = mod_pow::<HALF, HALF2, HALF21>(&m_mod_p, sk.d_p(), &ctx_p);
    let s2 = mod_pow::<HALF, HALF2, HALF21>(&m_mod_q, sk.d_q(), &ctx_q);

    // Step 2.b.3: `h = (s1 - s2) * qInv mod p`. `s2 < q`, and `q < 2p` because
    // `RsaPrivateKey::from_crt_components` requires `p` and `q` to be the same bit length (see
    // that type's docs), so one constant-time conditional subtraction reduces it mod `p`.
    let s2_mod_p = reduce_once::<HALF>(&s2, sk.p());
    let diff = sub_mod::<HALF>(&s1, &s2_mod_p, sk.p());
    let h = mul_mod::<HALF, HALF2, HALF21>(&diff, sk.q_inv(), &ctx_p);

    // Step 2.b.4: `s = s2 + q * h`. `h < p` and `q * h < q * p = n`, and CRT recombination
    // guarantees `s2 + q*h < n` (Garner's algorithm's own correctness property), so this widening
    // multiply-then-add cannot overflow `L` limbs.
    let q_h = montgomery::widening_mul::<HALF, L>(sk.q(), &h);
    let mut s2_wide = [0u64; L];
    s2_wide[..HALF].copy_from_slice(&s2);
    let (s, carry) = nat::add(&s2_wide, &q_h);
    debug_assert_eq!(carry, 0, "CRT recombination must stay within n's width");

    Ok(s)
}

#[cfg(test)]
mod tests {
    //! `rsasp1`/`rsavp1` are deliberately crate-private (see the module docs), so they cannot be
    //! reached from `tests/` the way every other primitive in this crate is exercised -- this is
    //! the "high-risk code that ... cannot be reached through the public API" exception
    //! `CLAUDE.md`'s testing notes describe. Every value below is a genuine 2048-bit RSA keypair
    //! (two independently generated, Miller-Rabin-tested ~1024-bit primes, `e = 65537`), and every
    //! expected signature was cross-checked two ways in Python before being pasted here: CRT
    //! recombination against plain `pow(m, d, n)`, and `pow(pow(m, d, n), e, n) == m`.

    use super::*;

    fn keypair() -> RsaPrivateKey<32, 16> {
        let p: [u64; 16] = [
            0xfec673c1b07d4997, 0x98c9e3737faecc8b, 0x01369d6bebcfd19b, 0x8aadc1799d493a6e,
            0x958ca74fe2a455a1, 0x686e62c9e375661d, 0xbf73814b7bf6fe14, 0x791ffe2d364719e4,
            0xc82e25af581825a1, 0x716d239de20732c7, 0xdb517e266b0c15bc, 0xe92c721464fa1e50,
            0x683e7fcc3898a002, 0xc7f69cb8c57e630f, 0xc467ab3a006acdf7, 0xe189725eddf8ccb3,
        ];
        let q: [u64; 16] = [
            0x7b4cf8c928cc535f, 0x59f055409b91aa89, 0xcd0ba689661c56d5, 0xe4659bfb595039f4,
            0x751842ab04e21054, 0xe2c2655760ebb5fc, 0xb2f71094e48dc76b, 0x2efed995e680919d,
            0x83c35ffcfdb9ee9d, 0xfe4a5fdb9f28a01b, 0x0ebf4a61e23c7524, 0x8cc355a69e45d7e6,
            0x9589828fca436940, 0x4cd1bfe875cddd70, 0x203e0d5e8d4d3acb, 0x86278c27281306ec,
        ];
        let d_p: [u64; 16] = [
            0xa7c48ae44e99dd99, 0xa6794425077c6c01, 0x0f7f8dfabf278380, 0xb481c3d6cf359f60,
            0xa5b5efbc5d9f744a, 0x91b95de874b741a1, 0xea3152a3da97ddf5, 0xe180bda330e9eba0,
            0xbcbfcc51e73a7a34, 0x019d0405e258c3c0, 0x0b08c52c187e3667, 0x84a723999981f7c1,
            0x5e50dc3287b126ff, 0xd0204fd4674f4ac6, 0x6e786ef11d0686f6, 0xa82c39200c1c4d67,
        ];
        let d_q: [u64; 16] = [
            0x0bc1fcecb5c853bf, 0x2000c1caf24e96d2, 0xb423419c07e0736a, 0x90bcb6fb03d68029,
            0xd811d2e24994ff2e, 0x5a89a6b7c7c83737, 0xbdea803dc4157f87, 0xffe93a09240b9b65,
            0xe6f584c8dc80c30a, 0x5e66076e22c91c3c, 0xb41221e6b67af91b, 0x2e3d8c36b1d9d161,
            0x7b1309bb3857cb1f, 0xee8de5186c920235, 0x5e4785a534bec7a3, 0x85883dd007ea907c,
        ];
        let q_inv: [u64; 16] = [
            0xf1be36246c217ae1, 0x079e038ceb7506d7, 0x2021f982bc5f6713, 0x55fa8fdd926a4d0f,
            0xb927b5edab1a24b8, 0xc2a1d37632cfb70e, 0x9ef39b4a3f144e8a, 0x70efa5974ed43d2f,
            0x6ea50741414ce321, 0x7df35889e34d4f38, 0x859106459f51850b, 0xd59e422a92f4a7a2,
            0x0c1e16e70fcbe362, 0xcf95cadb6a1f450d, 0x106a4e948e405012, 0x95a3415bfb9b5ff6,
        ];
        RsaPrivateKey::from_crt_components(&p, &q, &d_p, &d_q, &q_inv)
            .expect("genuine CRT components must be accepted")
    }

    fn public_key(sk: &RsaPrivateKey<32, 16>) -> RsaPublicKey<32> {
        RsaPublicKey::new(sk.n(), 0x00010001).expect("e = 65537 is valid")
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
            0x364cc26d0358bbf4, 0xe66706a5c785ddb2, 0x988d10d740263405, 0x8730f3278e45205e,
            0xaf89fbc49c9a1249, 0x9eb8f7a84273ca48, 0xabaf5851d3f5426c, 0x0ba36a5d9c8c66a3,
            0x4ed17840c5f6e1da, 0x9e2acb65a840fecb, 0x738ba4ec9cdd22f7, 0x9f55aaf16f290bac,
            0x0882623816565d42, 0x0377a272e9477155, 0x479e6d3b5fc7cdf0, 0x982fc26936177b5a,
            0x0b5865236931b18c, 0xf013b20ea0f2a40b, 0xa30f42ffc4e00f37, 0xac385621648ddc31,
            0x1516eadafe0e2d2e, 0xa1241270647a6b51, 0x682d73ffca96c494, 0x6f2ab34339689b72,
            0x9cc67858bfcb237c, 0x3ca10b66cf56d9dc, 0x9e2aecc899fa34b9, 0x87ae32e45faca1d8,
            0xe6407b5fa454d3c9, 0x7c66144074c5739e, 0x72db535464e48005, 0x3e7bf2011ccdf96c,
        ];

        let s = rsasp1::<32, 64, 65, 16, 32, 33>(&sk, &m).expect("m is in range");
        assert_eq!(s, expected_s);

        let recovered = rsavp1::<32, 64, 65>(&pk, &s).expect("s is in range");
        assert_eq!(recovered, m);
    }

    #[test]
    fn rsasp1_second_vector_near_n_minus_1() {
        let sk = keypair();
        let pk = public_key(&sk);

        // m2 = n - 12345, exercising a message representative close to the top of the range.
        let m2: [u64; 32] = [
            0xbc9607fe59ae13d0, 0x33fb0be666401931, 0x29fe66e068d6028b, 0xf4225b99e1483032,
            0x3e05752e447f3448, 0x3621f382f494e49c, 0xb12e1f7bd18e9f62, 0xba911df383b4764d,
            0x206002df096d6863, 0x07e881cdab73cfe3, 0x4e9ca660d04d6b6c, 0xfdd0169786ca06a2,
            0xffc09630c54f5731, 0x79ff3ac5ce73cc72, 0x72dd018024dd28a7, 0x4155291016140929,
            0x21a0943f3500f009, 0xd386df1b9afb0808, 0xd06dca00e14b1311, 0x31ed2137effa6d2a,
            0xb914de4e6361f98f, 0x181ad8797a7574fb, 0x98285be3abda6248, 0xcce5cb7a03c57a7d,
            0x3bdb7daa02c2b084, 0x8bb59db9b76bd95d, 0x95e3a77cea5ff912, 0x841d24a921abd3db,
            0x2895f5b063db401c, 0xe57dc21fc3866988, 0xb88f89afa429e300, 0x7630c947be6e9710,
        ];
        let expected_s2: [u64; 32] = [
            0x279fb473681292dc, 0x90dd3361616e1fba, 0x4be153bf0cc9bc54, 0xc182310ffe516be1,
            0xde08597f0526ba7f, 0x0ecf2548fd2becbd, 0xf100a0d8ab9cac48, 0x7e79521337c90850,
            0x642ecb9c26db1f8b, 0x888c707e26d47319, 0x3fe925626dabfde5, 0x5e374b37fa2875b2,
            0x57afec45ed3a06de, 0xa2184c3a6deb8156, 0x466017505ec5110d, 0x6b462b5d6f8c46f8,
            0x22b90fde8ff49648, 0xe6b9526894cfffba, 0xf5193a402a3c063c, 0xdc2d25c6ec27f87b,
            0x272f960bef731aed, 0xb8d7c2a5e9ef52cf, 0x5e82a247d76a2bbe, 0x018d6155cbc9c0fd,
            0x16f1861e4a32fa83, 0xab553b4f2fe5e561, 0x1c55445d8e2e8530, 0xa08e2522099e36e7,
            0xbcda0d67e80f74f5, 0xe8b549b81d5eb31d, 0xf1d74cf682145c5d, 0x74643dc08434c3e1,
        ];

        let s2 = rsasp1::<32, 64, 65, 16, 32, 33>(&sk, &m2).expect("m2 is in range");
        assert_eq!(s2, expected_s2);
        assert_eq!(rsavp1::<32, 64, 65>(&pk, &s2).expect("s2 is in range"), m2);
    }

    #[test]
    fn rsasp1_rejects_out_of_range_message() {
        let sk = keypair();
        let out_of_range = *sk.n();
        assert!(matches!(
            rsasp1::<32, 64, 65, 16, 32, 33>(&sk, &out_of_range),
            Err(SignatureError::DecodingError(_))
        ));
    }

    #[test]
    fn rsavp1_rejects_out_of_range_signature() {
        let sk = keypair();
        let pk = public_key(&sk);
        let out_of_range = *pk.n();
        assert!(matches!(
            rsavp1::<32, 64, 65>(&pk, &out_of_range),
            Err(SignatureError::DecodingError(_))
        ));
    }
}
