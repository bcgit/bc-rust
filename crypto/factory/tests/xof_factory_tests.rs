//! `XOFFactory` is a pass-through to the concrete XOF implementations, so the oracle for
//! every method is the same call on the underlying type. Each check below runs the factory and the
//! direct type side by side on the same input; nothing here is an expected value written by hand.

use bouncycastle_ascon::ASCON_XOF128_NAME;
use bouncycastle_ascon::AsconXof128;
use bouncycastle_blake3::{BLAKE3, BLAKE3_NAME};
use bouncycastle_core::errors::HashError;
use bouncycastle_core::traits::{Hash, XOF, XOFSqueezer};
use bouncycastle_core_test_framework::xof::TestFrameworkXOF;
use bouncycastle_factory::xof_factory::XOFFactory;
use bouncycastle_factory::{AlgorithmFactory, FactoryError};
use bouncycastle_hex as hex;
use bouncycastle_sha3::{SHAKE128, SHAKE128_NAME, SHAKE256, SHAKE256_NAME};

const MSG: &[u8] = b"The quick brown fox jumps over the lazy dog";

/// Every `Hash`, `XOF` and `XOFSqueezer` method of the factory against the direct type `S`.
fn check_against<S: XOF + Default>(make: impl Fn() -> XOFFactory, ctx: &str) {
    let n = S::default().output_len();

    // metadata
    assert_eq!(make().block_bitlen(), S::default().block_bitlen(), "{ctx}: block_bitlen");
    assert_eq!(make().output_len(), n, "{ctx}: output_len");
    assert_eq!(
        Hash::max_security_strength(&make()),
        Hash::max_security_strength(&S::default()),
        "{ctx}: max_security_strength"
    );

    // the Hash view
    let expected = S::default().hash(MSG);
    assert_eq!(expected.len(), n);
    assert_eq!(make().hash(MSG), expected, "{ctx}: hash");

    let mut out = vec![0u8; n];
    assert_eq!(make().hash_out(MSG, &mut out), n, "{ctx}: hash_out returns the length");
    assert_eq!(out, expected, "{ctx}: hash_out");

    let mut f = make();
    MSG.chunks(5).for_each(|c| f.do_update(c));
    assert_eq!(f.do_final(), expected, "{ctx}: do_update then do_final");

    let mut f = make();
    f.do_update(MSG);
    let mut out = vec![0u8; n];
    assert_eq!(f.do_final_out(&mut out), n, "{ctx}: do_final_out returns the length");
    assert_eq!(out, expected, "{ctx}: do_final_out");

    // partial final byte, which SHAKE accepts
    let mut s = S::default();
    s.do_update(MSG);
    let expected_bits = s.do_final_partial_bits(0x05, 3).unwrap();
    assert_ne!(expected_bits, expected, "three more bits must change the digest");

    let mut f = make();
    f.do_update(MSG);
    assert_eq!(f.do_final_partial_bits(0x05, 3).unwrap(), expected_bits, "{ctx}: partial bits");

    let mut f = make();
    f.do_update(MSG);
    let mut out = vec![0u8; n];
    assert_eq!(f.do_final_partial_bits_out(0x05, 3, &mut out).unwrap(), n, "{ctx}: ..._out length");
    assert_eq!(out, expected_bits, "{ctx}: do_final_partial_bits_out");

    let mut f = make();
    f.do_update(MSG);
    assert!(
        matches!(f.do_final_partial_bits(0xFF, 8), Err(HashError::InvalidLength(_))),
        "{ctx}: eight partial bits is not a partial byte"
    );

    // the XOF view: one stream, of which the Hash view is the first output_len bytes
    let mut s = S::default();
    s.do_update(MSG);
    let long = s.into_squeezer().do_output(3 * n);
    assert_eq!(&long[..n], &expected[..], "the direct type's hash is a prefix of its stream");

    let mut f = make();
    f.do_update(MSG);
    let mut fo = f.into_squeezer();
    assert_eq!(fo.do_output(n), &long[..n], "{ctx}: do_output");

    let mut buf = vec![0u8; 2 * n];
    assert_eq!(fo.do_output_out(&mut buf), 2 * n, "{ctx}: do_output_out returns the length");
    assert_eq!(buf, &long[n..], "{ctx}: do_output_out continues the stream");

    let mut s = S::default();
    s.do_update(MSG);
    let want = s.into_squeezer_partial_bits(0x05, 3).unwrap().do_output(n);

    let mut f = make();
    f.do_update(MSG);
    assert_eq!(
        f.into_squeezer_partial_bits(0x05, 3).unwrap().do_output(n),
        want,
        "{ctx}: into_squeezer_partial_bits"
    );

    let mut f = make();
    f.do_update(MSG);
    assert!(matches!(f.into_squeezer_partial_bits(0xFF, 8), Err(HashError::InvalidLength(_))));

    // the one-shots
    assert_eq!(make().xof(MSG, 3 * n), long, "{ctx}: xof");

    let mut out = vec![0xFFu8; 3 * n];
    assert_eq!(make().xof_out(MSG, &mut out), 3 * n, "{ctx}: xof_out returns the length");
    assert_eq!(out, long, "{ctx}: xof_out");
}

#[test]
fn shake128_by_name_matches_the_direct_type() {
    check_against::<SHAKE128>(|| XOFFactory::new(SHAKE128_NAME).unwrap(), "SHAKE128 by constant");
    check_against::<SHAKE128>(|| XOFFactory::new("SHAKE128").unwrap(), "SHAKE128 by string");
}

#[test]
fn shake256_by_name_matches_the_direct_type() {
    check_against::<SHAKE256>(|| XOFFactory::new(SHAKE256_NAME).unwrap(), "SHAKE256 by constant");
    check_against::<SHAKE256>(|| XOFFactory::new("SHAKE256").unwrap(), "SHAKE256 by string");
}

/// Verify that the Ascon-XOF128 factory registration resolves to the same implementation
/// as constructing Ascon-XOF128 directly.
#[test]
fn ascon_xof128_by_name_matches_the_direct_type() {
    let direct = AsconXof128::new().xof(MSG, 64);

    // Construct using the crate constant.
    assert_eq!(
        XOFFactory::new(ASCON_XOF128_NAME).unwrap().xof(MSG, 64),
        direct,
        "Ascon-XOF128 by constant"
    );

    // Construct using the literal algorithm name.
    assert_eq!(
        XOFFactory::new("Ascon-XOF128").unwrap().xof(MSG, 64),
        direct,
        "Ascon-XOF128 by string"
    );
}

/// The official BLAKE3 vector (test_vectors.json, github.com/BLAKE3-team/BLAKE3) for the
/// 1025-byte input `i % 251` -- one full chunk plus one byte, so the root is a parent node: the
/// 131-byte `hash` output, copied from crypto/blake3/tests/vectors/mod.rs.
const BLAKE3_1025_HASH: &str = "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444f4c4a22b4b399155358a994e52bf255de60035742ec71bd08ac275a1b51cc6bfe332b0ef84b409108cda080e6269ed4b3e2c3f7d722aa4cdc98d16deb554e5627be8f955c98e1d5f9565a9194cad0c4285f93700062d9595adb992ae68ff12800ab67a";

/// BLAKE3 by name: the official extended-output vector through every `Hash`, `XOF` and
/// `XOFSqueezer` pass-through, plus BLAKE3's byte-oriented partial-bit policy (which is why it
/// cannot use `check_against`, whose partial-bit checks assume SHAKE's bit-oriented input).
#[test]
fn blake3_by_name_matches_the_official_vector() {
    let input: Vec<u8> = (0..1025).map(|i| (i % 251) as u8).collect();
    let long = hex::decode(BLAKE3_1025_HASH).unwrap();
    // BLAKE3 spec s. 2.6: "Shorter outputs are prefixes of longer ones." The default-length hash
    // is 32 bytes (s. 2.1), so the Hash view is the first 32 bytes of the stream.
    let n = 32;

    for (name, ctx) in [(BLAKE3_NAME, "BLAKE3 by constant"), ("BLAKE3", "BLAKE3 by string")] {
        let make = || XOFFactory::new(name).unwrap();

        // metadata
        assert_eq!(make().block_bitlen(), 512, "{ctx}: block_bitlen");
        assert_eq!(make().output_len(), n, "{ctx}: output_len");
        assert_eq!(
            Hash::max_security_strength(&make()),
            Hash::max_security_strength(&BLAKE3::new()),
            "{ctx}: max_security_strength"
        );

        // the Hash view
        assert_eq!(make().hash(&input), &long[..n], "{ctx}: hash");
        let mut out = vec![0xFFu8; n];
        assert_eq!(make().hash_out(&input, &mut out), n, "{ctx}: hash_out returns the length");
        assert_eq!(out, &long[..n], "{ctx}: hash_out");

        let mut f = make();
        input.chunks(100).for_each(|c| f.do_update(c));
        assert_eq!(f.do_final(), &long[..n], "{ctx}: do_update then do_final");

        let mut f = make();
        f.do_update(&input);
        let mut out = vec![0xFFu8; n];
        assert_eq!(f.do_final_out(&mut out), n, "{ctx}: do_final_out returns the length");
        assert_eq!(out, &long[..n], "{ctx}: do_final_out");

        // byte-oriented: 0 partial bits is the whole-byte digest, 1..=7 refused, > 7 refused
        let mut f = make();
        f.do_update(&input);
        assert_eq!(f.do_final_partial_bits(0, 0).unwrap(), &long[..n], "{ctx}: 0 bits");

        let mut f = make();
        f.do_update(&input);
        let mut out = vec![0xFFu8; n];
        assert_eq!(f.do_final_partial_bits_out(0, 0, &mut out).unwrap(), n, "{ctx}: ..._out");
        assert_eq!(out, &long[..n], "{ctx}: do_final_partial_bits_out");

        assert!(matches!(make().do_final_partial_bits(0x05, 3), Err(HashError::InvalidInput(_))));
        let mut out = vec![0u8; n];
        assert!(matches!(
            make().do_final_partial_bits_out(0x05, 3, &mut out),
            Err(HashError::InvalidInput(_))
        ));
        assert!(matches!(make().do_final_partial_bits(0xFF, 8), Err(HashError::InvalidLength(_))));

        // the XOF view: one continuous stream across reads
        let mut f = make();
        f.do_update(&input);
        let mut fo = f.into_squeezer();
        assert_eq!(fo.do_output(n), &long[..n], "{ctx}: do_output");
        let mut buf = vec![0u8; long.len() - n];
        assert_eq!(fo.do_output_out(&mut buf), long.len() - n, "{ctx}: do_output_out length");
        assert_eq!(buf, &long[n..], "{ctx}: do_output_out continues the stream");

        let mut f = make();
        f.do_update(&input);
        assert_eq!(
            f.into_squeezer_partial_bits(0, 0).unwrap().do_output(long.len()),
            long,
            "{ctx}: into_squeezer_partial_bits(0, 0)"
        );
        assert!(matches!(
            make().into_squeezer_partial_bits(0x05, 3),
            Err(HashError::InvalidInput(_))
        ));
        assert!(matches!(
            make().into_squeezer_partial_bits(0xFF, 8),
            Err(HashError::InvalidLength(_))
        ));

        // the one-shots
        assert_eq!(make().xof(&input, long.len()), long, "{ctx}: xof");
        let mut out = vec![0xFFu8; long.len()];
        assert_eq!(make().xof_out(&input, &mut out), long.len(), "{ctx}: xof_out length");
        assert_eq!(out, long, "{ctx}: xof_out");
    }
}

/// The configured defaults: SHAKE128 for the general and 128-bit defaults, SHAKE256 for 256-bit.
#[test]
fn defaults() {
    check_against::<SHAKE128>(XOFFactory::default, "default()");
    check_against::<SHAKE128>(XOFFactory::default_128_bit, "default_128_bit()");
    check_against::<SHAKE256>(XOFFactory::default_256_bit, "default_256_bit()");
}

#[test]
fn unknown_names_are_refused() {
    for name in
        ["SHAKE512", "shake128", "", "cSHAKE128", "Ascon-XOF999", "blake3", "BLAKE3-KeyedHash"]
    {
        assert!(
            matches!(XOFFactory::new(name), Err(FactoryError::UnsupportedAlgorithm(_))),
            "{name:?} must not construct a XOF"
        );
    }
}

/// The shared `XOF` conformance suite, with the expected stream taken from the direct type.
#[test]
fn test_framework_xof() {
    let framework = TestFrameworkXOF::new();

    framework.test_xof(
        || XOFFactory::new(SHAKE128_NAME).unwrap(),
        MSG,
        &SHAKE128::new().xof(MSG, 100),
    );

    framework.test_xof(
        || XOFFactory::new(SHAKE256_NAME).unwrap(),
        MSG,
        &SHAKE256::new().xof(MSG, 100),
    );

    // BLAKE3 is byte-oriented, so the suite's partial-byte checks do not apply to it.
    let byte_oriented =
        TestFrameworkXOF { enable_partial_byte_tests: false, do_final_binds_output_length: false };
    byte_oriented.test_xof(
        || XOFFactory::new(BLAKE3_NAME).unwrap(),
        MSG,
        &BLAKE3::new().xof(MSG, 100),
    );
}
