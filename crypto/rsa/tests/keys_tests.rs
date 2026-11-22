//! Validation tests for [`bouncycastle_rsa::keys`]'s public API, including the
//! `PrivateKey`/`PublicKey` impls `rsa_2048` gives its aliases of these types
//! (`RsaPrivateComponents<32, 16>` *is* `RsaPrivateComponents<RSA2048>`, so the traits' methods resolve here once
//! imported). The generic boundary conditions every size shares are covered by
//! `core-test-framework`'s `test_keys` in each size's own test file; these pin the layout itself.

use bouncycastle_core::errors::{KeyDecodingError, SignatureError};
use bouncycastle_core::traits::{PrivateKey, PublicKey};
use bouncycastle_rsa::keys::{
    RsaPrivateComponents, RsaPrivateKey, RsaPublicComponents, RsaPublicKey,
};
use bouncycastle_rsa::rsassa_pss::RSASSA_PSS;
use bouncycastle_rsa::size::{RsaSigningSize, RsaSize};
use bouncycastle_rsa::{RSA2048, RSA3072, RSA4096, RSA8192};
use bouncycastle_sha2::SHA256;
use bouncycastle_utils::secret::ZeroizablePrimitive;

/// The scheme the encoding tests type their keys with; the bytes are the same under any.
type Pss256 = RSASSA_PSS<RSA2048, SHA256>;

// A genuine RSA-2048 key: the first SHA-256 group of Wycheproof's
// `rsa_pkcs1_2048_sig_gen_test.json` (`tests/rsa_2048_pkcs1_v1_5_tests.rs` has the provenance),
// with `N = P * Q` by Python's integers.
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
const N: [u64; 32] = [
    0xf7820283f742b9d5, 0x6f453d1f5b4c2e9c, 0x9a02e5a530e77306, 0x5d12569a62807d3b,
    0xc22c4e5ac0f7c1a4, 0xf9f85e7975005d9b, 0x1b4d9cae79d460d8, 0x69816f48698bcbba,
    0x126422f590975a19, 0xfd7afc3e09ada0f1, 0xed5411eb878daf05, 0x4c03145b5d3495d4,
    0x12be82de4d1ece6b, 0x21d0fceca08d945a, 0x7d9658594266f5c0, 0x4c22da610428e09c,
    0x90ed81299615d981, 0x7a1fa26a8dce26f4, 0x3eff8f17e1a02939, 0x254a2fe9765313a0,
    0x3d3e42e46e48c98e, 0xcd20f79c15e8247f, 0x2ed8a7711a1253fa, 0xb5ab393189db9251,
    0x9e89d6eac8845097, 0x1700f65903b46942, 0x1878d80325b6ef5a, 0x37f9746d3f7cafd3,
    0x094fa1fee82224e6, 0x4a8a5b462ebef717, 0x6e45567151355051, 0xa2b451a07d0aa5f9,
];

#[test]
fn from_crt_components_accepts_a_genuine_key_and_derives_n() {
    let sk =
        RsaPrivateComponents::<RSA2048>::from_crt_components(&P, &Q, &D_P, &D_Q, &Q_INV, 0x10001)
            .expect("genuine RSA-2048 CRT components must be accepted");
    assert_eq!(*sk.n(), N);
}

#[test]
fn from_crt_components_rejects_equal_primes() {
    assert!(matches!(
        RsaPrivateComponents::<RSA2048>::from_crt_components(&P, &P, &D_P, &D_Q, &Q_INV, 0x10001),
        Err(SignatureError::DecodingError(_))
    ));
}

#[test]
fn from_crt_components_rejects_even_prime() {
    let mut even_p = P;
    even_p[0] &= !1;
    assert!(matches!(
        RsaPrivateComponents::<RSA2048>::from_crt_components(
            &even_p, &Q, &D_P, &D_Q, &Q_INV, 0x10001
        ),
        Err(SignatureError::DecodingError(_))
    ));
}

#[test]
fn from_crt_components_rejects_even_q() {
    let mut even_q = Q;
    even_q[0] &= !1;
    assert!(matches!(
        RsaPrivateComponents::<RSA2048>::from_crt_components(
            &P, &even_q, &D_P, &D_Q, &Q_INV, 0x10001
        ),
        Err(SignatureError::DecodingError(_))
    ));
}

#[test]
fn from_crt_components_rejects_dp_out_of_range() {
    assert!(matches!(
        RsaPrivateComponents::<RSA2048>::from_crt_components(&P, &Q, &P, &D_Q, &Q_INV, 0x10001),
        Err(SignatureError::DecodingError(_))
    ));
}

#[test]
fn from_crt_components_rejects_qinv_out_of_range() {
    assert!(matches!(
        RsaPrivateComponents::<RSA2048>::from_crt_components(&P, &Q, &D_P, &D_Q, &P, 0x10001),
        Err(SignatureError::DecodingError(_))
    ));
}

#[test]
fn public_key_accepts_e_65537() {
    let pk = RsaPublicComponents::<RSA2048>::new(&N, 0x00010001).expect("e = 65537 is valid");
    assert_eq!(*pk.n(), N);
    assert_eq!(pk.e(), 0x00010001);
}

#[test]
fn public_key_rejects_even_exponent() {
    for e in [0, 2, 4, 65536, 1 << 32, u64::MAX - 1] {
        assert!(matches!(
            RsaPublicComponents::<RSA2048>::new(&N, e),
            Err(SignatureError::DecodingError(_))
        ));
    }
}

#[test]
fn public_key_rejects_exponent_below_three() {
    assert!(matches!(
        RsaPublicComponents::<RSA2048>::new(&N, 1),
        Err(SignatureError::DecodingError(_))
    ));
    assert!(RsaPublicComponents::<RSA2048>::new(&N, 3).is_ok());
}

#[test]
fn public_key_rejects_even_modulus() {
    let mut even_n = N;
    even_n[0] &= !1;
    assert!(matches!(
        RsaPublicComponents::<RSA2048>::new(&even_n, 3),
        Err(SignatureError::DecodingError(_))
    ));
}

#[test]
fn public_key_encode_round_trips() {
    // 65537, a 33-bit and a 56-bit exponent, and the largest there is.
    for e in [0x10001, 0x1_0000_0001, 0x00c0_ffee_1234_5677, u64::MAX] {
        let pk = RsaPublicComponents::<RSA2048>::new(&N, e).unwrap().into_key::<Pss256>();
        let bytes: [u8; 264] = pk.encode();
        assert_eq!(bytes[256..], e.to_be_bytes());
        let decoded = RsaPublicKey::<Pss256>::from_bytes(&bytes).expect("must decode");
        assert_eq!(decoded, pk);
        assert_eq!(decoded.e(), e);
    }
}

/// `PublicKey`'s `n || e` layout, checked field by field rather than only by round
/// trip: `n` big-endian (its most significant limb's top byte first), then `e` big-endian in
/// eight bytes.
#[test]
fn public_key_encode_layout_is_n_then_e_big_endian() {
    let pk = RsaPublicComponents::<RSA2048>::new(&N, 0x10001).unwrap().into_key::<Pss256>();
    let bytes = pk.encode();
    assert_eq!(bytes[..8], N[31].to_be_bytes());
    assert_eq!(bytes[248..256], N[0].to_be_bytes());
    assert_eq!(bytes[256..], [0, 0, 0, 0, 0x00, 0x01, 0x00, 0x01]);

    let mut out = [0xaau8; 264];
    assert_eq!(pk.encode_out(&mut out), 264);
    assert_eq!(out, bytes);
}

#[test]
fn public_key_from_bytes_rejects_even_modulus() {
    let pk = RsaPublicComponents::<RSA2048>::new(&N, 0x10001).unwrap().into_key::<Pss256>();
    let mut bytes: [u8; 264] = pk.encode();
    bytes[255] &= !1; // clear n's low bit (last byte, big-endian)
    assert!(matches!(RsaPublicKey::<Pss256>::from_bytes(&bytes), Err(KeyDecodingError(_))));
}

#[test]
fn public_key_from_bytes_rejects_wrong_lengths() {
    let pk = RsaPublicComponents::<RSA2048>::new(&N, 0x10001).unwrap().into_key::<Pss256>();
    let bytes = pk.encode();
    assert!(matches!(RsaPublicKey::<Pss256>::from_bytes(&bytes[..263]), Err(KeyDecodingError(_))));
    let mut too_long = bytes.to_vec();
    too_long.push(0);
    assert!(matches!(RsaPublicKey::<Pss256>::from_bytes(&too_long), Err(KeyDecodingError(_))));
}

/// `Display` (a `PublicKey` supertrait) prints `n` as one big-endian hex string and `e`
/// in hex, so a printed key can be matched by eye against a hex dump of its encoding.
#[test]
fn public_key_display_prints_big_endian_hex() {
    let pk = RsaPublicComponents::<RSA2048>::new(&N, 0x10001).unwrap().into_key::<Pss256>();
    let shown = format!("{pk}");
    let n_hex: String = pk.encode()[..256].iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        shown,
        format!("RsaPublicKey<RSASSA-PSS-SHA256, RSA-2048> {{ n: {n_hex}, e: 10001 }}")
    );
}

#[test]
fn private_key_encode_round_trips() {
    let sk =
        RsaPrivateComponents::<RSA2048>::from_crt_components(&P, &Q, &D_P, &D_Q, &Q_INV, 0x10001)
            .unwrap()
            .into_key::<Pss256>();
    let bytes: [u8; 648] = sk.encode();
    let decoded = RsaPrivateKey::<Pss256>::from_bytes(&bytes).expect("must decode");
    assert_eq!(decoded, sk);
    assert_eq!(decoded.e(), 0x10001);
    assert_eq!(decoded.components().e(), 0x10001);

    // The exponent is part of the key and of its encoding, at any width: the same components
    // under another `e` are another key, which round trips as itself.
    for e in [3, 0x1_0000_0001, 0x00c0_ffee_1234_5677, u64::MAX] {
        let other =
            RsaPrivateComponents::<RSA2048>::from_crt_components(&P, &Q, &D_P, &D_Q, &Q_INV, e)
                .unwrap()
                .into_key::<Pss256>();
        assert_ne!(other, sk);
        let bytes = other.encode();
        assert_eq!(bytes[640..], e.to_be_bytes());
        let decoded = RsaPrivateKey::<Pss256>::from_bytes(&bytes).expect("must decode");
        assert_eq!(decoded, other);
        assert_eq!(decoded.e(), e);
    }
}

/// The private key's copy of `e` is held to the public key's rule, odd and at least 3 (RFC
/// 8017 Section 3.1), by the constructors and on decoding.
#[test]
fn private_key_rejects_an_even_or_small_exponent() {
    let good =
        RsaPrivateComponents::<RSA2048>::from_crt_components(&P, &Q, &D_P, &D_Q, &Q_INV, 0x10001)
            .unwrap()
            .into_key::<Pss256>();
    for e in [0, 1, 2, 4, 65536, 1 << 32, u64::MAX - 1] {
        let expected =
            SignatureError::DecodingError("RSA public exponent must be odd and at least 3");
        assert_eq!(
            RsaPrivateComponents::<RSA2048>::from_crt_components(&P, &Q, &D_P, &D_Q, &Q_INV, e)
                .unwrap_err(),
            expected
        );
        assert!(matches!(
            RsaPrivateKey::<Pss256>::from_crt_components(&P, &Q, &D_P, &D_Q, &Q_INV, e),
            Err(SignatureError::DecodingError(_))
        ));
        let mut bytes = good.encode();
        bytes[640..].copy_from_slice(&e.to_be_bytes());
        assert_eq!(
            RsaPrivateKey::<Pss256>::from_bytes(&bytes).unwrap_err(),
            KeyDecodingError("RSA public exponent must be odd and at least 3")
        );
    }
}

/// `PrivateKey`'s `p || q || dP || dQ || qInv || e` layout: five fields of 128 bytes
/// big-endian, then `e` big-endian in eight.
#[test]
fn private_key_encode_layout_is_five_big_endian_fields_and_e() {
    let sk =
        RsaPrivateComponents::<RSA2048>::from_crt_components(&P, &Q, &D_P, &D_Q, &Q_INV, 0x10001)
            .unwrap()
            .into_key::<Pss256>();
    let bytes = sk.encode();
    for (i, field) in [P, Q, D_P, D_Q, Q_INV].iter().enumerate() {
        let start = 128 * i;
        assert_eq!(bytes[start..start + 8], field[15].to_be_bytes(), "field {i} MSB");
        assert_eq!(bytes[start + 120..start + 128], field[0].to_be_bytes(), "field {i} LSB");
    }
    assert_eq!(bytes[640..], [0, 0, 0, 0, 0x00, 0x01, 0x00, 0x01]);

    let mut out = [0xaau8; 648];
    assert_eq!(sk.encode_out(&mut out), 648);
    assert_eq!(out, bytes);
}

#[test]
fn private_key_from_bytes_rejects_equal_primes() {
    let sk =
        RsaPrivateComponents::<RSA2048>::from_crt_components(&P, &Q, &D_P, &D_Q, &Q_INV, 0x10001)
            .unwrap()
            .into_key::<Pss256>();
    let mut bytes: [u8; 648] = sk.encode();
    // Overwrite q (the second 128-byte field) with p, making the two primes equal.
    let p_field = bytes[..128].to_vec();
    bytes[128..256].copy_from_slice(&p_field);
    assert!(matches!(RsaPrivateKey::<Pss256>::from_bytes(&bytes), Err(KeyDecodingError(_))));
}

#[test]
fn private_key_from_bytes_rejects_wrong_lengths() {
    let sk =
        RsaPrivateComponents::<RSA2048>::from_crt_components(&P, &Q, &D_P, &D_Q, &Q_INV, 0x10001)
            .unwrap()
            .into_key::<Pss256>();
    let bytes = sk.encode();
    assert!(matches!(RsaPrivateKey::<Pss256>::from_bytes(&bytes[..647]), Err(KeyDecodingError(_))));
    let mut too_long = bytes.to_vec();
    too_long.push(0);
    assert!(matches!(RsaPrivateKey::<Pss256>::from_bytes(&too_long), Err(KeyDecodingError(_))));
}

/// The CRT range checks run through the size's own forwarders: at every signing size a `dP`
/// not below `p` and a `qInv` not below `p` are refused (no primality check, so odd values
/// with their top two bits set, whose product is then full length, stand in for the primes).
fn crt_components_out_of_range_rejected<K: RsaSigningSize>() {
    let mut p = <K as RsaSize>::HalfLimbs::ZEROED;
    p.as_mut()[0] = 7;
    let mut q = <K as RsaSize>::HalfLimbs::ZEROED;
    q.as_mut()[0] = 11;
    let top = p.as_ref().len() - 1;
    p.as_mut()[top] |= 0b11 << 62;
    q.as_mut()[top] |= 0b11 << 62;
    let mut small = <K as RsaSize>::HalfLimbs::ZEROED;
    small.as_mut()[0] = 3;
    assert!(
        RsaPrivateComponents::<K>::from_crt_components(&p, &q, &small, &small, &small, 0x10001)
            .is_ok()
    );
    assert!(matches!(
        RsaPrivateComponents::<K>::from_crt_components(&p, &q, &p, &small, &small, 0x10001),
        Err(SignatureError::DecodingError(_))
    ));
    assert!(matches!(
        RsaPrivateComponents::<K>::from_crt_components(&p, &q, &small, &q, &small, 0x10001),
        Err(SignatureError::DecodingError(_))
    ));
    assert!(matches!(
        RsaPrivateComponents::<K>::from_crt_components(&p, &q, &small, &small, &p, 0x10001),
        Err(SignatureError::DecodingError(_))
    ));
}

#[test]
fn crt_components_out_of_range_rejected_at_every_signing_size() {
    crt_components_out_of_range_rejected::<RSA2048>();
    crt_components_out_of_range_rejected::<RSA3072>();
    crt_components_out_of_range_rejected::<RSA4096>();
    crt_components_out_of_range_rejected::<RSA8192>();
}

// Key material whose modulus is not full length, for the tests below. Both are genuine keys
// (checked with Python 3.12: `p` and `q` pass 40 rounds of Miller-Rabin, and `dP`, `dQ`, `qInv`
// are `pow(e, -1, p - 1)`, `pow(e, -1, q - 1)`, `pow(q, -1, p)` for e = 65537), so every check
// but the modulus's length passes.
//
// SHORT_2047: two 1024-bit primes whose product has 2047 bits. This file's own test key until
// the length was checked.
const SHORT_2047_P: [u64; 16] = [
    0xfec673c1b07d4997, 0x98c9e3737faecc8b, 0x01369d6bebcfd19b, 0x8aadc1799d493a6e,
    0x958ca74fe2a455a1, 0x686e62c9e375661d, 0xbf73814b7bf6fe14, 0x791ffe2d364719e4,
    0xc82e25af581825a1, 0x716d239de20732c7, 0xdb517e266b0c15bc, 0xe92c721464fa1e50,
    0x683e7fcc3898a002, 0xc7f69cb8c57e630f, 0xc467ab3a006acdf7, 0xe189725eddf8ccb3,
];
const SHORT_2047_Q: [u64; 16] = [
    0x7b4cf8c928cc535f, 0x59f055409b91aa89, 0xcd0ba689661c56d5, 0xe4659bfb595039f4,
    0x751842ab04e21054, 0xe2c2655760ebb5fc, 0xb2f71094e48dc76b, 0x2efed995e680919d,
    0x83c35ffcfdb9ee9d, 0xfe4a5fdb9f28a01b, 0x0ebf4a61e23c7524, 0x8cc355a69e45d7e6,
    0x9589828fca436940, 0x4cd1bfe875cddd70, 0x203e0d5e8d4d3acb, 0x86278c27281306ec,
];
const SHORT_2047_D_P: [u64; 16] = [
    0xa7c48ae44e99dd99, 0xa6794425077c6c01, 0x0f7f8dfabf278380, 0xb481c3d6cf359f60,
    0xa5b5efbc5d9f744a, 0x91b95de874b741a1, 0xea3152a3da97ddf5, 0xe180bda330e9eba0,
    0xbcbfcc51e73a7a34, 0x019d0405e258c3c0, 0x0b08c52c187e3667, 0x84a723999981f7c1,
    0x5e50dc3287b126ff, 0xd0204fd4674f4ac6, 0x6e786ef11d0686f6, 0xa82c39200c1c4d67,
];
const SHORT_2047_D_Q: [u64; 16] = [
    0x0bc1fcecb5c853bf, 0x2000c1caf24e96d2, 0xb423419c07e0736a, 0x90bcb6fb03d68029,
    0xd811d2e24994ff2e, 0x5a89a6b7c7c83737, 0xbdea803dc4157f87, 0xffe93a09240b9b65,
    0xe6f584c8dc80c30a, 0x5e66076e22c91c3c, 0xb41221e6b67af91b, 0x2e3d8c36b1d9d161,
    0x7b1309bb3857cb1f, 0xee8de5186c920235, 0x5e4785a534bec7a3, 0x85883dd007ea907c,
];
const SHORT_2047_Q_INV: [u64; 16] = [
    0xf1be36246c217ae1, 0x079e038ceb7506d7, 0x2021f982bc5f6713, 0x55fa8fdd926a4d0f,
    0xb927b5edab1a24b8, 0xc2a1d37632cfb70e, 0x9ef39b4a3f144e8a, 0x70efa5974ed43d2f,
    0x6ea50741414ce321, 0x7df35889e34d4f38, 0x859106459f51850b, 0xd59e422a92f4a7a2,
    0x0c1e16e70fcbe362, 0xcf95cadb6a1f450d, 0x106a4e948e405012, 0x95a3415bfb9b5ff6,
];
const SHORT_2047_N: [u64; 32] = [
    0xbc9607fe59ae4409, 0x33fb0be666401931, 0x29fe66e068d6028b, 0xf4225b99e1483032,
    0x3e05752e447f3448, 0x3621f382f494e49c, 0xb12e1f7bd18e9f62, 0xba911df383b4764d,
    0x206002df096d6863, 0x07e881cdab73cfe3, 0x4e9ca660d04d6b6c, 0xfdd0169786ca06a2,
    0xffc09630c54f5731, 0x79ff3ac5ce73cc72, 0x72dd018024dd28a7, 0x4155291016140929,
    0x21a0943f3500f009, 0xd386df1b9afb0808, 0xd06dca00e14b1311, 0x31ed2137effa6d2a,
    0xb914de4e6361f98f, 0x181ad8797a7574fb, 0x98285be3abda6248, 0xcce5cb7a03c57a7d,
    0x3bdb7daa02c2b084, 0x8bb59db9b76bd95d, 0x95e3a77cea5ff912, 0x841d24a921abd3db,
    0x2895f5b063db401c, 0xe57dc21fc3866988, 0xb88f89afa429e300, 0x7630c947be6e9710,
];
// SHORT_1024: two 512-bit primes, a 1024-bit modulus held in RSA-2048's widths. Generated for
// this file with Python (`random.Random(20261122)`, candidates with their top two bits set).
const SHORT_1024_P: [u64; 16] = [
    0x6ef620d8244eb173, 0xc405f88ed21e8bab, 0x4078517af66e0441, 0x036fcb2eab272e2e,
    0x57f09c6542c341ad, 0x8655e0db4ac425db, 0xdc698685e27377e4, 0xcb9dc67a2e18f929,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
];
const SHORT_1024_Q: [u64; 16] = [
    0xbcf68cf7e0d108c3, 0xb482cc7300abbbe5, 0xd118d4ab1ffa26fe, 0xeb6cc5ba79b7eeca,
    0xc65068d06f2c1194, 0x4b36e61a4ba7bc16, 0x050695b809674898, 0xd89d96cb1d2958b9,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
];
const SHORT_1024_D_P: [u64; 16] = [
    0x507439de1e33939f, 0x0cd5993cb34799c4, 0xcf4386325df05157, 0xef856dc0b69eeb9a,
    0x39358ce56ac1db00, 0x4ac1f2816ff6d7ee, 0x0bec72dd511fa67a, 0xb45edc7e492d9833,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
];
const SHORT_1024_D_Q: [u64; 16] = [
    0x04dbb2eefd45ce41, 0xcaa851093ed448e4, 0x476aff0896b72309, 0xcd8f1478d9bfb8ac,
    0x14ad71efe9532d06, 0x72b90e38ea541108, 0x09ff6630bfaedf41, 0x9e559283a52d33cd,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
];
const SHORT_1024_Q_INV: [u64; 16] = [
    0x5d11de90a81493d9, 0x8a5a13bcd31c8f63, 0xb9713767ed1bec03, 0xfc6236e7ee0221a8,
    0xb718e73a2653ec00, 0x14428a8dc324d06f, 0x7b8178b611797b9e, 0x4c68e71595d411cf,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
];
const SHORT_1024_N: [u64; 32] = [
    0x30365f3e9c5fc299, 0xea89d3517b5001ef, 0x0e1662fd6aff00e2, 0xfaa88695226220ad,
    0x61261165da096479, 0xff857d4c85008a3a, 0xed8cee4bc3cd0936, 0x93dcc09276ea8c4b,
    0xd846665bc425d759, 0x2187cf1d8b30d252, 0xe4c0359865f1981c, 0xcdf3a6d470131436,
    0xc583be54081dfae1, 0xd2439a393fe4795b, 0x56794795de362947, 0xac4a7729cf6d13c3,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
];

/// A modulus with one limb set.
fn small_modulus(value: u64) -> [u64; 32] {
    let mut n = [0u64; 32];
    n[0] = value;
    n
}

const TOP_BIT_CLEAR: &str = "RSA modulus must have its top bit set";

/// A signature public key's modulus has exactly the size's bit length: RFC 8017 Section 8.1.1
/// step 1 encodes to `modBits - 1` bits, which EMSA-PSS here takes as `8 * K_LEN - 1`. `n = 1`,
/// `n = 105`, a 1024-bit modulus and a genuine 2047-bit one are each refused, by the
/// components, by the typed key and on decoding.
#[test]
fn public_key_rejects_a_modulus_that_is_not_full_length() {
    for n in [small_modulus(1), small_modulus(105), SHORT_1024_N, SHORT_2047_N] {
        assert_eq!(
            RsaPublicComponents::<RSA2048>::new(&n, 0x10001),
            Err(SignatureError::DecodingError(TOP_BIT_CLEAR))
        );
        assert!(matches!(
            RsaPublicKey::<Pss256>::new(&n, 0x10001),
            Err(SignatureError::DecodingError(TOP_BIT_CLEAR))
        ));
        // The encoding of what would be that key: n big-endian, then e.
        let mut bytes =
            RsaPublicComponents::<RSA2048>::new(&N, 0x10001).unwrap().key::<Pss256>().encode();
        for (i, limb) in n.iter().enumerate() {
            bytes[256 - 8 * (i + 1)..256 - 8 * i].copy_from_slice(&limb.to_be_bytes());
        }
        assert_eq!(
            RsaPublicKey::<Pss256>::from_bytes(&bytes).unwrap_err(),
            KeyDecodingError(TOP_BIT_CLEAR)
        );
    }
    // The 2047-bit modulus is the largest that is refused: with its top bit set it is taken.
    let mut full = SHORT_2047_N;
    full[31] |= 1 << 63;
    assert!(RsaPublicComponents::<RSA2048>::new(&full, 0x10001).is_ok());
}

/// The private key's check is on `p * q`. The genuine keys pass every other check, so the
/// error names this one; `n = 105` is `15 * 7` and `n = 1` is `1 * 1`, which the distinct-primes
/// check refuses first.
#[test]
fn private_key_rejects_a_modulus_that_is_not_full_length() {
    for (p, q, d_p, d_q, q_inv) in [
        (SHORT_2047_P, SHORT_2047_Q, SHORT_2047_D_P, SHORT_2047_D_Q, SHORT_2047_Q_INV),
        (SHORT_1024_P, SHORT_1024_Q, SHORT_1024_D_P, SHORT_1024_D_Q, SHORT_1024_Q_INV),
    ] {
        assert_eq!(
            RsaPrivateComponents::<RSA2048>::from_crt_components(
                &p, &q, &d_p, &d_q, &q_inv, 0x10001
            )
            .unwrap_err(),
            SignatureError::DecodingError(TOP_BIT_CLEAR)
        );
        assert!(matches!(
            RsaPrivateKey::<Pss256>::from_crt_components(&p, &q, &d_p, &d_q, &q_inv, 0x10001),
            Err(SignatureError::DecodingError(TOP_BIT_CLEAR))
        ));
        // The encoding of what would be that key: five big-endian fields, then e.
        let mut bytes = [0u8; 648];
        for (f, field) in [p, q, d_p, d_q, q_inv].iter().enumerate() {
            for (i, limb) in field.iter().enumerate() {
                let end = 128 * (f + 1) - 8 * i;
                bytes[end - 8..end].copy_from_slice(&limb.to_be_bytes());
            }
        }
        bytes[640..].copy_from_slice(&0x10001u64.to_be_bytes());
        assert_eq!(
            RsaPrivateKey::<Pss256>::from_bytes(&bytes).unwrap_err(),
            KeyDecodingError(TOP_BIT_CLEAR)
        );
    }

    let limb = |value: u64| {
        let mut x = [0u64; 16];
        x[0] = value;
        x
    };
    // 15 * 7 = 105, with dP = dQ = qInv = 1 in range.
    assert_eq!(
        RsaPrivateComponents::<RSA2048>::from_crt_components(
            &limb(15),
            &limb(7),
            &limb(1),
            &limb(1),
            &limb(1),
            0x10001
        )
        .unwrap_err(),
        SignatureError::DecodingError(TOP_BIT_CLEAR)
    );
    assert!(matches!(
        RsaPrivateComponents::<RSA2048>::from_crt_components(
            &limb(1),
            &limb(1),
            &limb(0),
            &limb(0),
            &limb(0),
            0x10001
        ),
        Err(SignatureError::DecodingError(_))
    ));
}

/// A typed key exposes its exponent, names its algorithm in `Debug`, and compares by its
/// material.
#[test]
fn typed_keys_expose_e_debug_names_the_algorithm_and_eq_compares_material() {
    let pk = RsaPublicComponents::<RSA2048>::new(&N, 0x10001).unwrap().into_key::<Pss256>();
    assert_eq!(pk.e(), 0x10001);
    let shown = format!("{pk:?}");
    assert!(shown.starts_with("RsaPublicKey { algorithm: \"RSASSA-PSS-SHA256\", components: "));
    let pk_other_e = RsaPublicComponents::<RSA2048>::new(&N, 0x10003).unwrap().into_key::<Pss256>();
    assert_eq!(pk, pk.clone());
    assert_ne!(pk, pk_other_e);

    let sk =
        RsaPrivateComponents::<RSA2048>::from_crt_components(&P, &Q, &D_P, &D_Q, &Q_INV, 0x10001)
            .unwrap()
            .into_key::<Pss256>();
    let shown = format!("{sk:?}");
    assert!(shown.starts_with("RsaPrivateKey { algorithm: \"RSASSA-PSS-SHA256\", components: "));
    let mut q_inv_other = Q_INV;
    q_inv_other[0] ^= 1;
    let sk_other = RsaPrivateComponents::<RSA2048>::from_crt_components(
        &P, &Q, &D_P, &D_Q, &q_inv_other, 0x10001,
    )
    .unwrap()
    .into_key::<Pss256>();
    assert_eq!(sk, sk.clone());
    assert_ne!(sk, sk_other);
}
