//! Generic behaviour tests for any MAC key object, through the [`MAC`] workers it hands out, and
//! for the worker of a one-time MAC, which has no reusable key object.

use bouncycastle_core::errors::MACError;
use bouncycastle_core::symmetric_key::{MacGenerationKey, MacVerificationKey};
use bouncycastle_core::traits::MAC;

/// Instance of the test framework.
pub struct TestFrameworkMAC {
    // Put any config options here
}

impl TestFrameworkMAC {
    ///
    pub fn new() -> Self {
        Self {}
    }

    /// The one-shots and the workers a [`MacGenerationKey`] / [`MacVerificationKey`] hands out,
    /// against the given input-output pair. This gives good baseline test coverage, but is not
    /// exhaustive; the key-policy checks are `TestFrameworkFromAnyKeyMaterial`'s.
    pub fn test_mac_key<K: MacGenerationKey + MacVerificationKey>(
        &self,
        key: &K,
        input: &[u8],
        expected_output: &[u8],
    ) {
        // the key's one-shots
        assert_eq!(key.mac(input), expected_output);
        let mut out = vec![0u8; expected_output.len()];
        let bytes_written = key.mac_out(input, &mut out).unwrap();
        assert_eq!(bytes_written, expected_output.len());
        assert_eq!(out, expected_output);
        // an output buffer that's too small truncates
        let mut out = vec![0u8; expected_output.len() - 2];
        let bytes_written = key.mac_out(input, &mut out).unwrap();
        assert_eq!(bytes_written, expected_output.len() - 2);
        assert_eq!(out, expected_output[..expected_output.len() - 2]);
        // an output buffer that's too big gets the first L bytes filled and the rest zeroed
        let mut out = vec![0xA5u8; 2 * expected_output.len()];
        let bytes_written = key.mac_out(input, &mut out).unwrap();
        assert_eq!(bytes_written, expected_output.len());
        assert_eq!(&out[..expected_output.len()], expected_output);
        assert_eq!(&out[expected_output.len()..], vec![0u8; expected_output.len()]);
        assert!(key.verify(input, expected_output));
        assert!(!key.verify(input, &expected_output[..expected_output.len() - 1]));
        assert!(!key.verify(b"not the input", expected_output));

        // the workers' streaming methods, and the consuming one-shots on the workers
        let mut generator = key.create_generator();
        let output_len = generator.output_len();
        generator.do_update(input);
        let out = generator.do_final();
        assert_eq!(out, expected_output);
        assert_eq!(output_len, out.len());

        let mut generator = key.create_generator();
        generator.do_update(input);
        let mut out = vec![0u8; generator.output_len()];
        let out_len = generator.do_final_out(&mut *out).unwrap();
        assert_eq!(out, expected_output);
        assert_eq!(out_len, out.len());

        assert_eq!(key.create_generator().mac(input), expected_output);
        let mut out = vec![0u8; expected_output.len()];
        assert_eq!(key.create_generator().mac_out(input, &mut out).unwrap(), out.len());
        assert_eq!(out, expected_output);
        assert!(key.create_verifier().verify(input, expected_output));

        let mut verifier = key.create_verifier();
        verifier.do_update(input);
        assert!(verifier.do_verify_final(expected_output));
        let mut verifier = key.create_verifier();
        verifier.do_update(input);
        assert!(!verifier.do_verify_final(&expected_output[1..]));

        // several workers in flight from one key, finished in the other order, and the key
        // unchanged by use
        let mut a = key.create_generator();
        let mut b = key.create_generator();
        a.do_update(input);
        b.do_update(b"another message");
        let tag_b = b.do_final();
        let tag_a = a.do_final();
        assert_eq!(tag_a, expected_output);
        assert_eq!(tag_b, key.mac(b"another message"));
        assert_eq!(key.mac(input), expected_output);
    }

    /// The [`MAC`] worker of a one-time MAC such as Poly1305, against the given input-output pair.
    /// Its key authenticates one message and is consumed by the worker it makes, so there is no
    /// key object to test: `new_worker` makes a fresh worker under the same key on every call. Its
    /// tag cannot be truncated: an output buffer shorter than the tag must be refused with
    /// [`MACError::InvalidLength`] and left zeroed.
    pub fn test_one_time_mac<W: MAC>(
        &self,
        new_worker: impl Fn() -> W,
        input: &[u8],
        expected_output: &[u8],
    ) {
        // the worker's consuming one-shots
        assert_eq!(new_worker().mac(input), expected_output);
        let mut out = vec![0u8; expected_output.len()];
        assert_eq!(new_worker().mac_out(input, &mut out).unwrap(), expected_output.len());
        assert_eq!(out, expected_output);
        // an output buffer that's too small is refused and left zeroed
        let mut out = vec![0xA5u8; expected_output.len() - 2];
        let result = new_worker().mac_out(input, &mut out);
        assert!(matches!(result, Err(MACError::InvalidLength(_))));
        assert_eq!(out, vec![0u8; expected_output.len() - 2]);
        // an output buffer that's too big gets the first L bytes filled and the rest zeroed
        let mut out = vec![0xA5u8; 2 * expected_output.len()];
        assert_eq!(new_worker().mac_out(input, &mut out).unwrap(), expected_output.len());
        assert_eq!(&out[..expected_output.len()], expected_output);
        assert_eq!(&out[expected_output.len()..], vec![0u8; expected_output.len()]);
        assert!(new_worker().verify(input, expected_output));
        assert!(!new_worker().verify(input, &expected_output[..expected_output.len() - 1]));
        assert!(!new_worker().verify(b"not the input", expected_output));

        // the streaming methods
        let mut worker = new_worker();
        let output_len = worker.output_len();
        worker.do_update(input);
        let out = worker.do_final();
        assert_eq!(out, expected_output);
        assert_eq!(output_len, out.len());

        let mut worker = new_worker();
        worker.do_update(input);
        let mut out = vec![0u8; worker.output_len()];
        let out_len = worker.do_final_out(&mut out).unwrap();
        assert_eq!(out, expected_output);
        assert_eq!(out_len, out.len());

        let mut worker = new_worker();
        worker.do_update(input);
        assert!(worker.do_verify_final(expected_output));
        let mut worker = new_worker();
        worker.do_update(input);
        assert!(!worker.do_verify_final(&expected_output[1..]));
    }
}
