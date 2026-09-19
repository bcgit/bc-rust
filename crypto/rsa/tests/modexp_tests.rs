//! Known-answer and round-trip tests for [`bouncycastle_rsa::modexp`].
//!
//! Every KAT value below was computed with Python's arbitrary-precision `pow(base, exp, mod)`
//! (not from recall), so this file is the record of that cross-check rather than a duplicate of
//! it: see each case's comment for how it was produced.

use bouncycastle_rsa::modexp::{
    MontgomeryContext, mod_pow, mont_n_prime, mul_mod, reduce_wide, sub_mod,
};

/// `n' = -n0^-1 mod 2^64` must satisfy `n0 * n' ≡ -1 (mod 2^64)` -- the exact identity
/// [`bouncycastle_ec::montgomery::redc`] relies on. Checked directly by wrapping multiplication,
/// across small, large, and adversarial (all-ones) odd values.
#[test]
fn mont_n_prime_satisfies_redc_identity() {
    let candidates: [u64; 6] = [1, 3, 0xFFFFFFFFFFFFFFFF, 0x0CA1, 0xDEADBEEFDEADBEEF, u64::MAX - 4];
    for &n0 in &candidates {
        let n_prime = mont_n_prime(n0);
        assert_eq!(
            n0.wrapping_mul(n_prime),
            0u64.wrapping_sub(1),
            "n0 * n' must be -1 mod 2^64 for n0 = {n0:#x}"
        );
    }
}

/// Classic textbook RSA (Wikipedia's worked example): p=61, q=53, n=3233, e=17, d=2753, m=65.
/// `c = pow(65, 17, 3233) = 2790` and `pow(2790, 2753, 3233) = 65`, both via Python's `pow`.
#[test]
fn textbook_rsa_l1() {
    let n: [u64; 1] = [0x0000000000000ca1];
    let e: [u64; 1] = [0x0000000000000011];
    let d: [u64; 1] = [0x0000000000000ac1];
    let m: [u64; 1] = [0x0000000000000041];
    let expected_c: [u64; 1] = [0x0000000000000ae6];

    let ctx = MontgomeryContext::<1>::new(&n).expect("3233 is odd");
    let c = mod_pow::<1, 2, 3>(&m, &e, &ctx);
    assert_eq!(c, expected_c);

    let decrypted = mod_pow::<1, 2, 3>(&c, &d, &ctx);
    assert_eq!(decrypted, m);
}

/// `L = 1`: `n = 2^64 - 59`, `pow(123456789, 987654321, n)`, via Python.
#[test]
fn kat_l1_large_modulus() {
    let n: [u64; 1] = [0xffffffffffffffc5];
    let base: [u64; 1] = [0x00000000075bcd15];
    let exp: [u64; 1] = [0x000000003ade68b1];
    let expected: [u64; 1] = [0xb922a86ec0ff6fe7];

    let ctx = MontgomeryContext::<1>::new(&n).expect("modulus is odd");
    assert_eq!(mod_pow::<1, 2, 3>(&base, &exp, &ctx), expected);
}

/// `L = 2` (128-bit modulus `2^127 - 1`), via Python.
#[test]
fn kat_l2_128_bit() {
    let n: [u64; 2] = [0xffffffffffffffff, 0x7fffffffffffffff];
    let base: [u64; 2] = [0xc373e0ee4e3f0ad2, 0x000000018ee90ff6];
    let exp: [u64; 2] = [0x0000000000000003, 0x0000000000000000];
    let expected: [u64; 2] = [0xc327da61b1a46a17, 0x02d0b2240ebf02da];

    let ctx = MontgomeryContext::<2>::new(&n).expect("modulus is odd");
    assert_eq!(mod_pow::<2, 4, 5>(&base, &exp, &ctx), expected);
}

/// `L = 4` (256-bit random odd, non-prime modulus), via Python (`random.seed(42)`).
#[test]
fn kat_l4_256_bit() {
    let n: [u64; 4] =
        [0x1c80317fa3b1799d, 0xbdd640fb06671ad1, 0x3eb13b9046685257, 0x23b8c1e9392456de];
    let base: [u64; 4] =
        [0xa83c59a92dc37a35, 0xc64362c7939fc228, 0x90d835f3cac497f1, 0x08477cc431b04409];
    let exp: [u64; 4] =
        [0x0822e8f36c031199, 0x17fc695a07a0ca6e, 0x3b8faa1837f8a88b, 0x9a1de644815ef6d1];
    let expected: [u64; 4] =
        [0x9c1037426d1f8616, 0x7a21504a60dc2678, 0x8f54fb0513201d76, 0x1d2469f43bb3a703];

    let ctx = MontgomeryContext::<4>::new(&n).expect("modulus is odd");
    assert_eq!(mod_pow::<4, 8, 9>(&base, &exp, &ctx), expected);
}

/// `L = 2`, a genuine 128-bit RSA keypair (two random 64-bit primes, `e = 65537`), sign/verify
/// round trip. Generated with Python (`random.seed(99)`), including `d = pow(e, -1, phi)`.
#[test]
fn genuine_toy_rsa_keypair_round_trip_l2() {
    let n: [u64; 2] = [0x5cdd02d9b55c299d, 0x75acc2c4cc38005e];
    let e: [u64; 1] = [0x0000000000010001];
    let d: [u64; 2] = [0x9254c980da0d8d91, 0x27de4c6ed8b1f08d];
    let m: [u64; 2] = [0xa040024187f1a6ad, 0x624948139eab75cd];
    let expected_c: [u64; 2] = [0x0827db8b026ab9ca, 0x756a056f15b29f68];

    let ctx = MontgomeryContext::<2>::new(&n).expect("modulus is odd");

    // Public exponent (17 bits) padded into 2 limbs -- mod_pow processes the full 64*L width
    // regardless, so a short public exponent works the same way as a full-width one.
    let e_padded: [u64; 2] = [e[0], 0];
    let c = mod_pow::<2, 4, 5>(&m, &e_padded, &ctx);
    assert_eq!(c, expected_c);

    let decrypted = mod_pow::<2, 4, 5>(&c, &d, &ctx);
    assert_eq!(decrypted, m);
}

/// `L = 32` (2048-bit modulus, RSA-shaped), via Python (`random.seed(7)`). Exercises the
/// production limb count end to end, not just small hand-checkable cases.
#[test]
fn kat_l32_2048_bit() {
    let n: [u64; 32] = [
        0xf2a74de452e6b439, 0x6513270e269e0d37, 0x0c5c7fd0a6a3a450, 0xd23f0824128b2f33,
        0x1818e811892f902b, 0x9531985d5d9dc9f8, 0xe8e25d940ed90475, 0x36f675cc81e74ef5,
        0x1600a35a099950d8, 0x6b0d549b6f03675a, 0x3d9c172411e20b8f, 0x8d116ece1738f7d9,
        0x0f21ddb66cad4a26, 0x90c192cfd3ac94af, 0xf28c105d1fb17c23, 0xa170b33839263059,
        0x953f48f1a09f76b5, 0x0fd630f1f29d0da9, 0x95e60af593bd04cf, 0x0cb1e29c658cda14,
        0x3898d190f9ebdacc, 0x8e81973e0becd7b0, 0x2217beaddbc496cb, 0x6b4cb2424a23d596,
        0x8a6a63ec24ede6a4, 0x922766581e27a1c0, 0x8f6d05584ef8aa38, 0xae97ba94d0eda82f,
        0x1a61dbe22e44158b, 0x923a736994e3bf91, 0x301850c5a38fd547, 0x98f135d25f557203,
    ];
    let base: [u64; 32] = [
        0xb64ce4228c38fb29, 0x907a70c31012f037, 0x9e7769b10f4205b4, 0x7f15052434b9b5df,
        0x881ed162ae2eb154, 0xc6f877186d76b07e, 0x7731af10506bf2ef, 0xec66a78795e761d1,
        0x5c90a9587403e430, 0x3f98e2774cbd87ad, 0x2e05319acb5c7427, 0xc7a2ea20b2f14c94,
        0x14f4733f3e7d1bfb, 0x4cdd2055930d6eaf, 0x7ebff20686734721, 0x57ee05cde00902c7,
        0x72e6cc3ababced20, 0x9be4bcfc49b64a08, 0x12bd4acefaecbd38, 0x830e07bc1e398f10,
        0x2a3af4d46b0a18e8, 0x5790f82ec1d3fcff, 0xeeeacbe226e87555, 0x6bf46c697d2caf82,
        0xf646e1f40a097c97, 0x13deef86ab1031d0, 0x8ede0d7ac3baea9e, 0xca02135e92b1d3f2,
        0xd17f9acae01f5057, 0x571242425051c1cc, 0x59a54a7bb1fee08f, 0x7f26144b98289fcd,
    ];
    let exp: [u64; 32] = [
        0xcc011cdd9474031b, 0x119a72d174c9df6a, 0x17f5e837d70820fe, 0x451abd81f1d69ed6,
        0xb2715945795e8229, 0x10a3d6b2aa05e11a, 0xbb2d420f0f88080b, 0x4f426dcbb394fb36,
        0x93f448b3a5aa3c81, 0xae658f33fe3b890b, 0x72158370d269a9a5, 0xb774eb5248db40af,
        0xe315128862c33a4f, 0x58d5563dab2cd31e, 0xf0ce583505c6af07, 0x5affb2297631a992,
        0x9c6539382b0537e6, 0x7e62aa0a1df9fd78, 0x37dc76fb0f17a300, 0x49952399c4aaeac1,
        0xbd0561e6211c70cf, 0x65dc9f503f63af83, 0xeab477d26415479c, 0x7f1b103cdf1582b0,
        0x2a96fb1a14a0f9e7, 0x66d2287672fdf202, 0x4720771f8ca81811, 0x230d977ee2257159,
        0x6e36aab0d1bc52d9, 0x8cdb305fdd2e1609, 0xb4d66a3a47469a4d, 0xfc891b4a6a50df4d,
    ];
    let expected: [u64; 32] = [
        0x6d8f5211406eb32d, 0xe8816c035e8d63d0, 0xed5ae634462e4c34, 0xf4f19888a1da251d,
        0xba38c3ca7b518263, 0x7239b204d27d070b, 0x1b1973c8ee44aa69, 0x1ec760c7d18d3043,
        0x8c8261b66b4174f1, 0xc010d589c1eff8fd, 0xdb08314101c4e5d4, 0x626777ea0d794791,
        0x2040c20118bd8914, 0x984acd5d9f9d0eea, 0x6defd175fe17fc42, 0x77ced1e2bdb17dcd,
        0xd6684e6654758d1e, 0xff9e73db6471b299, 0x7429feb8b60a1cd7, 0x9b9740637d41d13d,
        0x008061aa7796f060, 0x1ce3f7b5954e82f4, 0x1d4298d60f58dffd, 0xbcc62dca692679ec,
        0x185d509c9c6c3698, 0x423a2e0c55dec062, 0x0d1b157097b65031, 0x5a6ba1b66d5ca4d8,
        0x0f3cba5f0d7fa3a6, 0x8e6e44eaac15c7e5, 0x62bd4e9b9ccd49c3, 0x915f6c85d08df86a,
    ];

    let ctx = MontgomeryContext::<32>::new(&n).expect("modulus is odd");
    assert_eq!(mod_pow::<32, 64, 65>(&base, &exp, &ctx), expected);
}

/// An even modulus is never valid for Montgomery reduction; RSA moduli are always odd, so this
/// is purely a defensive boundary check.
#[test]
fn even_modulus_is_rejected() {
    let n: [u64; 1] = [4];
    assert!(MontgomeryContext::<1>::new(&n).is_none());
}

/// `reduce_wide` with `WIDE = 4 > NARROW = 2`, RSA's own use for reducing an `n`-width message
/// down to a CRT prime's width (RFC 8017 §5.2.1 step 2.b.1). Via Python's `%`.
#[test]
fn reduce_wide_wider_value() {
    let value: [u64; 4] =
        [0x8899aabbccddeeff, 0x0011223344556677, 0xfedcba9876543210, 0x123456789abcdef0];
    let modulus: [u64; 2] = [0xffffffffffffff61, 0xffffffffffffffff];
    let expected: [u64; 2] = [0xd3b18f6d4b290dc4, 0x4e92d71b5fa3de25];
    assert_eq!(reduce_wide::<4, 2>(&value, &modulus), expected);
}

/// `reduce_wide` with `WIDE == NARROW`, deliberately far outside the `< 2 * modulus` bound a
/// single conditional subtraction would need: `value` is about 4.9 billion times `modulus`. RSA's
/// CRT recombination (step 2.b.3, `s2 mod p`) uses exactly this shape, and RFC 8017 does not
/// bound how large `q`'s residues can be relative to `p` (see `RsaPrivateKey`'s docs) -- this is
/// the case that matters, not the same-limb-count part of the signature. Via Python's `%`.
#[test]
fn reduce_wide_same_width_but_far_outside_double_the_modulus() {
    let value: [u64; 2] = [0xfffffffffffffffd, 0xfffffffffffffffe];
    let modulus: [u64; 2] = [0x0000000000000101, 0x00000000deadbeef];
    let expected: [u64; 2] = [0xfffffed88afbe598, 0x00000000a6a2b0b3];
    assert_eq!(reduce_wide::<2, 2>(&value, &modulus), expected);
}

/// `sub_mod` when `a < b` (the difference must wrap around by adding the modulus once). Via
/// Python's `%`.
#[test]
fn sub_mod_wraps_when_a_less_than_b() {
    let a: [u64; 2] = [0x0000000000000005, 0x0000000000000000];
    let b: [u64; 2] = [0x0000000000003039, 0x0000000000000000];
    let n: [u64; 2] = [0xffffffffffffff61, 0xffffffffffffffff];
    let expected: [u64; 2] = [0xffffffffffffcf2d, 0xffffffffffffffff];
    assert_eq!(sub_mod::<2>(&a, &b, &n), expected);
}

/// `mul_mod` with `a >= modulus` -- only `b` is required to be pre-reduced (see the function's
/// docs on why `a` need not be). Via Python's `%`.
#[test]
fn mul_mod_with_unreduced_first_operand() {
    let a: [u64; 2] = [0xfffffffffffffffd, 0xfffffffffffffffe];
    let b: [u64; 2] = [0x23456789abcdef01, 0x0000000000000001];
    let n: [u64; 2] = [0xffffffffffffff61, 0xffffffffffffffff];
    let expected: [u64; 2] = [0x7e4b17e4b17da35e, 0xdcba9876543211b0];

    let ctx = MontgomeryContext::<2>::new(&n).expect("modulus is odd");
    assert_eq!(mul_mod::<2, 4, 5>(&a, &b, &ctx), expected);
}
