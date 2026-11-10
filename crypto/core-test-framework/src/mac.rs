//! Generic behaviour tests for any MAC key object, through the [`MACGenerator`] /
//! [`MACVerifier`] workers it hands out; for a key whose tags are bound to a nonce; and for the
//! workers of a one-time MAC, which has no reusable key object.

use bouncycastle_core::errors::MACError;
use bouncycastle_core::symmetric_key::{
    MacGenerationKey, MacVerificationKey, NonceMacGenerationKey, NonceMacVerificationKey,
};
use bouncycastle_core::traits::{AlgorithmInfo, MACGenerator, MACVerifier};
use bouncycastle_rng::FixedSeedRNG;

use crate::FailingRNG;

/// Instance of the test framework.
pub struct TestFrameworkMAC {
    // Put any config options here
}

impl Default for TestFrameworkMAC {
    fn default() -> Self {
        Self::new()
    }
}

impl TestFrameworkMAC {
    ///
    pub fn new() -> Self {
        Self {}
    }

    /// The one-shots and the workers a [`MacGenerationKey`] / [`MacVerificationKey`] hands out,
    /// against the given input-output pair. This gives good baseline test coverage, but is not
    /// exhaustive; the key-policy checks are `TestFrameworkFromAnyKeyMaterial`'s and
    /// `TestFrameworkFromKeyMaterial`'s.
    pub fn test_mac_key<const MAC_LEN: usize, K>(
        &self,
        key: &K,
        input: &[u8],
        expected_output: &[u8; MAC_LEN],
    ) where
        K: MacGenerationKey<MAC_LEN> + MacVerificationKey<MAC_LEN>,
    {
        // the key's one-shots
        assert_eq!(key.mac(input), *expected_output);
        let mut out = [0xA5u8; MAC_LEN];
        assert_eq!(key.mac_out(input, &mut out), MAC_LEN);
        assert_eq!(out, *expected_output);
        assert_eq!(key.verify(input, expected_output), Ok(()));
        assert_eq!(
            key.verify(b"not the input", expected_output),
            Err(MACError::VerificationFailed)
        );
        every_bit_flip_is_refused(|bad| key.verify(input, bad), expected_output);

        // the workers' streaming methods
        let mut generator = key.create_generator();
        generator.do_update(input);
        assert_eq!(generator.do_final(), *expected_output);
        let mut generator = key.create_generator();
        generator.do_update(&[]);
        for chunk in input.chunks(7) {
            generator.do_update(chunk);
            generator.do_update(&[]);
        }
        let mut out = [0xA5u8; MAC_LEN];
        assert_eq!(generator.do_final_out(&mut out), MAC_LEN);
        assert_eq!(out, *expected_output);

        let mut verifier = key.create_verifier();
        verifier.do_update(input);
        assert_eq!(verifier.do_verify_final(expected_output), Ok(()));
        let mut verifier = key.create_verifier();
        for chunk in input.chunks(5) {
            verifier.do_update(chunk);
        }
        assert_eq!(verifier.do_verify_final(expected_output), Ok(()));
        let mut verifier = key.create_verifier();
        verifier.do_update(b"not the input");
        assert_eq!(verifier.do_verify_final(expected_output), Err(MACError::VerificationFailed));

        // the two workers describe the same algorithm
        assert_eq!(key.create_generator().alg_name(), key.create_verifier().alg_name());
        assert_eq!(
            key.create_generator().max_security_strength(),
            key.create_verifier().max_security_strength()
        );

        // several workers in flight from one key, finished in the other order, and the key
        // unchanged by use
        let mut a = key.create_generator();
        let mut b = key.create_generator();
        let mut v = key.create_verifier();
        a.do_update(input);
        b.do_update(b"another message");
        v.do_update(input);
        let tag_b = b.do_final();
        assert_eq!(v.do_verify_final(expected_output), Ok(()));
        let tag_a = a.do_final();
        assert_eq!(tag_a, *expected_output);
        assert_eq!(tag_b, key.mac(b"another message"));
        assert_eq!(key.mac(input), *expected_output);
    }

    /// The one-shots and the workers a [`NonceMacGenerationKey`] / [`NonceMacVerificationKey`]
    /// hands out, against the given nonce and input-output pair. The nonce-drawing forms are
    /// run under a `FixedSeedRNG` seeded with `nonce`, so they must return it and give the same
    /// tag as the supplied-nonce forms.
    pub fn test_nonce_mac_key<const NONCE_LEN: usize, const MAC_LEN: usize, K>(
        &self,
        key: &K,
        nonce: &[u8; NONCE_LEN],
        input: &[u8],
        expected_output: &[u8; MAC_LEN],
    ) where
        K: NonceMacGenerationKey<NONCE_LEN, MAC_LEN> + NonceMacVerificationKey<NONCE_LEN, MAC_LEN>,
    {
        let rng = || FixedSeedRNG::new(*nonce);

        // the key's one-shots, under the supplied nonce and under the drawn one
        assert_eq!(key.mac_nonce(nonce, input), *expected_output);
        let mut out = [0xA5u8; MAC_LEN];
        assert_eq!(key.mac_nonce_out(nonce, input, &mut out), MAC_LEN);
        assert_eq!(out, *expected_output);
        assert_eq!(key.mac(&mut rng(), input).unwrap(), (*nonce, *expected_output));
        let mut out = [0xA5u8; MAC_LEN];
        assert_eq!(key.mac_out(&mut rng(), input, &mut out).unwrap(), (MAC_LEN, *nonce));
        assert_eq!(out, *expected_output);
        // the _out rule holds on the error path: when the nonce cannot be drawn, the buffer
        // comes back zeroized rather than with its stale contents
        let mut out = [0xA5u8; MAC_LEN];
        assert!(matches!(
            key.mac_out(&mut FailingRNG, input, &mut out),
            Err(MACError::RNGError(_))
        ));
        assert_eq!(out, [0u8; MAC_LEN], "mac_out must zeroize the buffer before an RNG error");
        assert!(matches!(key.mac(&mut FailingRNG, input), Err(MACError::RNGError(_))));
        assert!(matches!(key.create_generator(&mut FailingRNG), Err(MACError::RNGError(_))));
        assert_eq!(key.verify(nonce, input, expected_output), Ok(()));
        assert_eq!(
            key.verify(nonce, b"not the input", expected_output),
            Err(MACError::VerificationFailed)
        );
        every_bit_flip_is_refused(|bad| key.verify(nonce, input, bad), expected_output);

        // the tag is bound to the nonce
        let mut other_nonce = *nonce;
        other_nonce[0] ^= 0x80;
        assert_ne!(key.mac_nonce(&other_nonce, input), *expected_output);
        assert_eq!(
            key.verify(&other_nonce, input, expected_output),
            Err(MACError::VerificationFailed)
        );

        // the workers' streaming methods, from both generator constructors
        let (mut generator, drawn) = key.create_generator(&mut rng()).unwrap();
        assert_eq!(drawn, *nonce);
        generator.do_update(input);
        assert_eq!(generator.do_final(), *expected_output);
        let mut generator = key.create_generator_nonce(nonce);
        generator.do_update(&[]);
        for chunk in input.chunks(7) {
            generator.do_update(chunk);
            generator.do_update(&[]);
        }
        let mut out = [0xA5u8; MAC_LEN];
        assert_eq!(generator.do_final_out(&mut out), MAC_LEN);
        assert_eq!(out, *expected_output);

        let mut verifier = key.create_verifier(nonce);
        for chunk in input.chunks(5) {
            verifier.do_update(chunk);
        }
        assert_eq!(verifier.do_verify_final(expected_output), Ok(()));
        let mut verifier = key.create_verifier(nonce);
        verifier.do_update(b"not the input");
        assert_eq!(verifier.do_verify_final(expected_output), Err(MACError::VerificationFailed));

        // the two workers describe the same algorithm
        assert_eq!(
            key.create_generator_nonce(nonce).alg_name(),
            key.create_verifier(nonce).alg_name()
        );
        assert_eq!(
            key.create_generator_nonce(nonce).max_security_strength(),
            key.create_verifier(nonce).max_security_strength()
        );

        // several workers in flight from one key, finished in the other order, and the key
        // unchanged by use
        let mut a = key.create_generator_nonce(nonce);
        let mut b = key.create_generator_nonce(nonce);
        let mut v = key.create_verifier(nonce);
        a.do_update(input);
        b.do_update(b"another message");
        v.do_update(input);
        let tag_b = b.do_final();
        assert_eq!(v.do_verify_final(expected_output), Ok(()));
        assert_eq!(a.do_final(), *expected_output);
        assert_eq!(tag_b, key.mac_nonce(nonce, b"another message"));
        assert_eq!(key.mac_nonce(nonce, input), *expected_output);
    }

    /// The workers of a one-time MAC such as Poly1305, against the given input-output pair. Its
    /// key authenticates one message and is consumed by the worker it makes, so there is no key
    /// object to test: `new_generator` and `new_verifier` make a fresh worker under the same key
    /// on every call.
    pub fn test_one_time_mac<const MAC_LEN: usize, G, V>(
        &self,
        new_generator: impl Fn() -> G,
        new_verifier: impl Fn() -> V,
        input: &[u8],
        expected_output: &[u8; MAC_LEN],
    ) where
        G: MACGenerator<MAC_LEN>,
        V: MACVerifier<MAC_LEN>,
    {
        let mut generator = new_generator();
        generator.do_update(input);
        assert_eq!(generator.do_final(), *expected_output);
        let mut generator = new_generator();
        generator.do_update(&[]);
        for chunk in input.chunks(7) {
            generator.do_update(chunk);
            generator.do_update(&[]);
        }
        let mut out = [0xA5u8; MAC_LEN];
        assert_eq!(generator.do_final_out(&mut out), MAC_LEN);
        assert_eq!(out, *expected_output);

        let mut verifier = new_verifier();
        verifier.do_update(input);
        assert_eq!(verifier.do_verify_final(expected_output), Ok(()));
        let mut verifier = new_verifier();
        verifier.do_update(b"not the input");
        assert_eq!(verifier.do_verify_final(expected_output), Err(MACError::VerificationFailed));
        every_bit_flip_is_refused(
            |bad| {
                let mut verifier = new_verifier();
                verifier.do_update(input);
                verifier.do_verify_final(bad)
            },
            expected_output,
        );

        assert_eq!(new_generator().alg_name(), new_verifier().alg_name());
        assert_eq!(new_generator().max_security_strength(), new_verifier().max_security_strength());
    }
}

/// Every single-bit change to `tag` is refused by `verify`: a verifier that compared a prefix,
/// or ignored a byte, would let one through.
fn every_bit_flip_is_refused<const MAC_LEN: usize>(
    verify: impl Fn(&[u8; MAC_LEN]) -> Result<(), MACError>,
    tag: &[u8; MAC_LEN],
) {
    for bit in 0..MAC_LEN * 8 {
        let mut bad = *tag;
        bad[bit / 8] ^= 1 << (bit % 8);
        assert_eq!(verify(&bad), Err(MACError::VerificationFailed), "tag bit {bit} flipped");
    }
}
