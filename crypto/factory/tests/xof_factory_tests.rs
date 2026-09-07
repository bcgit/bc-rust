//! `XOFFactory` is a pass-through to the SHAKE types in `bouncycastle-sha3`, so the oracle for
//! every method is the same call on the underlying type. Each check below runs the factory and the
//! direct type side by side on the same input; nothing here is an expected value written by hand.

use bouncycastle_core::errors::HashError;
use bouncycastle_core::traits::{Hash, XOF, XofOutput};
use bouncycastle_core_test_framework::xof::TestFrameworkXOF;
use bouncycastle_factory::xof_factory::XOFFactory;
use bouncycastle_factory::{AlgorithmFactory, FactoryError};
use bouncycastle_sha3::{SHAKE128, SHAKE128_NAME, SHAKE256, SHAKE256_NAME};

const MSG: &[u8] = b"The quick brown fox jumps over the lazy dog";

/// Every `Hash`, `XOF` and `XofOutput` method of the factory against the direct type `S`.
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
    let long = s.into_output().do_output(3 * n);
    assert_eq!(&long[..n], &expected[..], "the direct type's hash is a prefix of its stream");

    let mut f = make();
    f.do_update(MSG);
    let mut fo = f.into_output();
    assert_eq!(fo.do_output(n), &long[..n], "{ctx}: do_output");
    let mut buf = vec![0u8; 2 * n];
    assert_eq!(fo.do_output_out(&mut buf), 2 * n, "{ctx}: do_output_out returns the length");
    assert_eq!(buf, &long[n..], "{ctx}: do_output_out continues the stream");

    let mut s = S::default();
    s.do_update(MSG);
    let want = s.into_output_partial_bits(0x05, 3).unwrap().do_output(n);
    let mut f = make();
    f.do_update(MSG);
    assert_eq!(
        f.into_output_partial_bits(0x05, 3).unwrap().do_output(n),
        want,
        "{ctx}: into_output_partial_bits"
    );
    let mut f = make();
    f.do_update(MSG);
    assert!(matches!(f.into_output_partial_bits(0xFF, 8), Err(HashError::InvalidLength(_))));

    // the one-shots
    assert_eq!(make().hash_xof(MSG, 3 * n), long, "{ctx}: hash_xof");
    let mut out = vec![0xFFu8; 3 * n];
    assert_eq!(make().hash_xof_out(MSG, &mut out), 3 * n, "{ctx}: hash_xof_out returns the length");
    assert_eq!(out, long, "{ctx}: hash_xof_out");
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

/// The configured defaults: SHAKE128 for the general and 128-bit defaults, SHAKE256 for 256-bit.
#[test]
fn defaults() {
    check_against::<SHAKE128>(XOFFactory::default, "default()");
    check_against::<SHAKE128>(XOFFactory::default_128_bit, "default_128_bit()");
    check_against::<SHAKE256>(XOFFactory::default_256_bit, "default_256_bit()");
}

#[test]
fn unknown_names_are_refused() {
    for name in ["SHAKE512", "shake128", "", "cSHAKE128"] {
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
        &SHAKE128::new().hash_xof(MSG, 100),
    );
    framework.test_xof(
        || XOFFactory::new(SHAKE256_NAME).unwrap(),
        MSG,
        &SHAKE256::new().hash_xof(MSG, 100),
    );
}
