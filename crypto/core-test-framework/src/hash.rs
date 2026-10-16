//! Generic behaviour tests for anything that implements [`Hash`].

use bouncycastle_core::errors::HashError;
use bouncycastle_core::traits::{Hash, HashAlgParams};

/// Instance of the test framework.
pub struct TestFrameworkHash {
    // Put any config options here
    /// Can be disabled for hash functions that don't implement [`Hash::do_final_partial_bits`].
    pub enable_partial_byte_tests: bool,
}

impl TestFrameworkHash {
    ///
    pub fn new() -> Self {
        Self { enable_partial_byte_tests: true }
    }

    /// Checks [`Hash::do_final_out`] and [`Hash::hash_out`] against every buffer length, for a
    /// hash whose output length is bound into the computation.
    ///
    /// [`test_hash`](Self::test_hash) covers this too, but only for a `Default + HashAlgParams`
    /// implementor. The SP 800-185 functions take constructor arguments and so cannot reach it;
    /// `TupleHash` and `ParallelHash` both panicked on a short buffer until this existed.
    ///
    /// Not for XOFs. A XOF's [`Hash::output_len`] is nominal rather than bound, and its
    /// `do_final_out` fills whatever buffer it is handed rather than stopping at `output_len`, so
    /// the over-long case below does not describe one. Use `TestFrameworkXOF` for those.
    pub fn test_hash_output_buffers<H: Hash>(&self, make: impl Fn() -> H, input: &[u8]) {
        let expected = {
            let mut h = make();
            h.do_update(input);
            h.do_final()
        };
        let n = make().output_len();
        assert_eq!(expected.len(), n, "do_final() must produce output_len() bytes");

        // Short: the buffer is filled and the digest truncated to it.
        for length in 1..n {
            let mut buf = vec![0xAA_u8; length];
            let mut h = make();
            h.do_update(input);
            let written = h.do_final_out(&mut buf);
            assert_eq!(written, length, "a {length}-byte buffer must take {length} bytes");
            assert_eq!(buf, expected[..length], "short buffer must truncate the digest");

            // hash_out is the one-shot spelling of the same thing.
            let mut buf = vec![0xAA_u8; length];
            let written = make().hash_out(input, &mut buf);
            assert_eq!(written, length, "hash_out must agree with do_final_out");
            assert_eq!(buf, expected[..length], "hash_out must truncate the digest");
        }

        // Exact.
        let mut buf = vec![0xAA_u8; n];
        let mut h = make();
        h.do_update(input);
        assert_eq!(h.do_final_out(&mut buf), n);
        assert_eq!(buf, expected, "an exactly-sized buffer must take the whole digest");

        // Long: the digest lands in the first output_len bytes and the rest is zeroized.
        for extra in [1, n, 2 * n + 1] {
            let mut buf = vec![0xAA_u8; n + extra];
            let mut h = make();
            h.do_update(input);
            let written = h.do_final_out(&mut buf);
            assert_eq!(written, n, "a long buffer must still write only output_len bytes");
            assert_eq!(&buf[..n], &expected[..], "the digest must land at the start");
            assert!(
                buf[n..].iter().all(|&b| b == 0),
                "bytes past output_len must be zeroized, buffer was {} bytes",
                n + extra
            );
        }
    }

    /// Test all the members of trait Hash against the given input-output pair.
    /// This gives good baseline test coverage, but is not exhaustive; for example it does not test
    /// do_final_partial_bits() or do_final_partial_bits_out()
    /// because those require different input-output pairs.
    pub fn test_hash<H: Hash + HashAlgParams + Default>(
        &self,
        input: &[u8],
        expected_output: &[u8],
    ) {
        /*** fn result_len() -> usize ***/
        assert_eq!(H::default().output_len(), H::OUTPUT_LEN);

        /*** fn hash(self, data: &[u8]) -> Vec<u8> **/
        let output_vec = H::default().hash(input);
        assert_eq!(output_vec, expected_output);

        /*** fn hash_out(self, data: &[u8], output: &mut [u8]) -> Result<usize, HashError> ***/
        let mut output_buf = vec![0_u8; H::OUTPUT_LEN];
        H::default().hash_out(input, &mut output_buf);
        assert_eq!(output_buf, expected_output);

        /*** fn do_update(&mut self, data: &[u8]) -> Result<(), HashError> ***/
        /*** fn do_final(self) -> Result<Vec<u8>, HashError> **/

        let mut message_digest = H::default();
        message_digest.do_update(input);
        let output_buf = message_digest.do_final();
        assert_eq!(expected_output, output_buf, "Incorrect output for input (update_bytes)");

        for length in 1..output_buf.len() {
            let mut truncated = vec![0_u8; length];

            let mut message_digest = H::default();
            message_digest.do_update(input);
            message_digest.do_final_out(&mut truncated);

            assert_eq!(
                &expected_output[0..length],
                &truncated,
                "Incorrect output for input (update_byte) / truncated: {length}"
            );
        }

        /*** Test breaking the message into multiple do_update's ***/
        let mut message_digest = H::default();
        for chunk in input.chunks(16) {
            message_digest.do_update(chunk);
        }
        let output_buf = message_digest.do_final();
        assert_eq!(expected_output, output_buf, "Incorrect output for input (update_bytes)");

        /*** fn do_update(&mut self, data: &[u8]) -> Result<(), HashError> ***/
        /*** fn do_final_out(self, output: &mut [u8]) -> Result<usize, HashError> ***/

        let mut output_buf = vec![0_u8; H::OUTPUT_LEN];

        let mut message_digest = H::default();
        message_digest.do_update(input);
        message_digest.do_final_out(&mut output_buf);
        assert_eq!(&expected_output, &output_buf, "Incorrect output for input (update_bytes)");
        output_buf.fill(0);

        // Test truncation of the output buffer
        for length in 1..output_buf.len() {
            let mut truncated = vec![0_u8; length];

            let mut message_digest = H::default();
            message_digest.do_update(input);
            message_digest.do_final_out(&mut truncated);

            assert_eq!(
                &expected_output[0..length],
                &truncated,
                "Incorrect output for input (update_byte) / truncated: {length}"
            );
        }

        if self.enable_partial_byte_tests {
            /*** Testing: ***/
            /*** fn do_final_partial_bits(self, partial_byte: u8, num_bits: usize)-> Result<Vec<u8>, HashError>; ***/
            /*** fn do_final_partial_bits_out(self, partial_byte: u8, num_bits: usize, output: &mut [u8]) -> Result<usize, HashError>; ***/
            // A known-answer test for these needs a different expected output from the rest of this

            // Helper: the digest of `input` finished with the top `num_bits` bits of `partial_byte`.
            let partial_digest = |partial_byte: u8, num_bits: usize| -> Vec<u8> {
                let mut message_digest = H::default();
                message_digest.do_update(input);
                message_digest
                    .do_final_partial_bits(partial_byte, num_bits)
                    .expect("do_final_partial_bits() must succeed for num_bits in 0..=7")
            };

            // "0 is a valid value and means the message ends on a byte boundary (equivalent to
            //     Hash::do_final())".
            // So, test against the `expected_output` result from above
            for partial_byte in [0x00u8, 0x01, 0x80, 0xA5, 0xFF] {
                assert_eq!(
                    partial_digest(partial_byte, 0),
                    expected_output,
                    "num_bits = 0 must be equivalent to do_final() / partial_byte: {partial_byte:#04X}"
                );
            }

            // "the num_bits message bits are the most significant bits of partial_byte ... and the
            //     low 8 - num_bits bits (the BIT STRING's "unused bits") are ignored": so the unused
            //     low bits are not part of the message, and must not change the output.
            for num_bits in 0..=7 {
                // the used bits are the top num_bits; built in u16 so that num_bits == 0 cannot overflow
                let mask = (0xFF00u16 >> num_bits) as u8;
                for partial_byte in [0x00u8, 0x5A, 0xA5, 0xFF] {
                    assert_eq!(
                        partial_digest(partial_byte, num_bits),
                        partial_digest(partial_byte & mask, num_bits),
                        "the low 8 - num_bits = {} bits must be ignored / partial_byte: {partial_byte:#04X}",
                        8 - num_bits
                    );
                }
            }

            // "num_bits must be in 0..=7; larger values return HashError::InvalidLength."
            //    The range has to be validated before any shift by num_bits, so check well past
            //     the width of the shifted type as well as the 8 / 9 boundary.
            for num_bits in [8usize, 9, 15, 16, 64, usize::MAX] {
                let mut message_digest = H::default();
                message_digest.do_update(input);
                assert!(
                    matches!(
                        message_digest.do_final_partial_bits(0xFF, num_bits),
                        Err(HashError::InvalidLength(_))
                    ),
                    "num_bits = {num_bits} must be rejected with InvalidLength"
                );

                let mut output = vec![0u8; H::OUTPUT_LEN];
                let mut message_digest = H::default();
                message_digest.do_update(input);
                assert!(
                    matches!(
                        message_digest.do_final_partial_bits_out(0xFF, num_bits, &mut *output),
                        Err(HashError::InvalidLength(_))
                    ),
                    "num_bits = {num_bits} must be rejected with InvalidLength (_out variant)"
                );
            }

            // "The same as Hash::do_final_partial_bits, but takes the output buffer as an
            //     argument": the two variants must agree, and the Vec variant must return
            //     output_len() bytes.
            for num_bits in 0..=7 {
                for partial_byte in [0x00u8, 0x5A, 0xA5, 0xFF] {
                    let expected_partial_output = partial_digest(partial_byte, num_bits);
                    assert_eq!(expected_partial_output.len(), H::OUTPUT_LEN);

                    let mut output = vec![0u8; H::OUTPUT_LEN];
                    let mut message_digest = H::default();
                    message_digest.do_update(input);
                    let bytes_written = message_digest
                        .do_final_partial_bits_out(partial_byte, num_bits, &mut *output)
                        .expect("Failed to finalize partial input");
                    assert_eq!(bytes_written, H::OUTPUT_LEN);
                    assert_eq!(
                        output, expected_partial_output,
                        "do_final_partial_bits_out() must agree with do_final_partial_bits() / num_bits: {num_bits}, partial_byte: {partial_byte:#04X}"
                    );
                }
            }

            // Each (num_bits, partial_byte) pair is a distinct message, and so must produce a
            //     distinct digest. This is what catches an implementation that silently drops the
            //     partial bits, or absorbs the wrong number of them. The num_bits message bits are
            //     enumerated in the top bits of the byte (the shift is done in u16 so that
            //     num_bits == 0, an 8-bit shift, cannot overflow).
            let mut partial_outputs: Vec<Vec<u8>> = Vec::new();
            for num_bits in 0..=7 {
                for message_bits in 0..(1u16 << num_bits) {
                    let partial_byte = (message_bits << (8 - num_bits)) as u8;
                    partial_outputs.push(partial_digest(partial_byte, num_bits));
                }
            }
            let num_partial_outputs = partial_outputs.len();
            partial_outputs.sort_unstable();
            partial_outputs.dedup();
            assert_eq!(
                partial_outputs.len(),
                num_partial_outputs,
                "each (num_bits, partial_byte) pair is a distinct message and must hash to a distinct output"
            );
        }

        /*** Clone: a hash mid-stream can be forked ***/
        // A clone continues from the same absorbed prefix, so finishing the two on the same tail
        // must give the same digest, and finishing them on different tails must not.
        let (prefix, tail) = input.split_at(input.len() / 2);
        let mut original = H::default();
        original.do_update(prefix);
        let mut forked = original.clone();
        original.do_update(tail);
        forked.do_update(tail);
        assert_eq!(
            original.do_final(),
            expected_output,
            "the original must be unaffected by cloning"
        );
        assert_eq!(
            forked.do_final(),
            expected_output,
            "a clone must continue from the same absorbed prefix"
        );

        let mut original = H::default();
        original.do_update(prefix);
        let mut forked = original.clone();
        original.do_update(tail);
        forked.do_update(&[0xA5]);
        forked.do_update(tail);
        let original_out = original.do_final();
        assert_eq!(original_out, expected_output);
        assert_ne!(
            forked.do_final(),
            original_out,
            "a clone must have its own state, not share the original's"
        );

        // check that if you feed it an output slice that's bigger than it needs, that it doesn't touch the extra bytes.
        let mut message_digest = H::default();
        let mut buf = vec![0u8; 2 * H::OUTPUT_LEN];
        message_digest.do_update(input);
        let bytes_written = message_digest.do_final_out(&mut buf);
        // check that the result gets truncated to the correct length
        assert_eq!(bytes_written, H::OUTPUT_LEN);
        // check that it didn't write anything past where it should have
        assert_eq!(buf[H::OUTPUT_LEN..], vec![0u8; H::OUTPUT_LEN]);

        // test an output slice that's smaller than the result, that it gets truncated
        let mut out = vec![0; H::OUTPUT_LEN - 2];
        H::default().hash_out(input, out.as_mut_slice());
        assert_eq!(&out, &expected_output[..H::OUTPUT_LEN - 2]);
    }
}
