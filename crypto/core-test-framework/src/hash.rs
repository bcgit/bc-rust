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

            // Helper: the digest of `input` finished with the low `num_bits` bits of `partial_byte`.
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

            // "The num_bits message bits are taken from the least significant bits of
            //     partial_byte": the unused high bits are not part of the message, and so must not
            //     change the output.
            for num_bits in 0..=7 {
                // no overflow: 1u8 << 7 == 0x80
                let mask = (1u8 << num_bits) - 1;
                for partial_byte in [0x00u8, 0x5A, 0xA5, 0xFF] {
                    assert_eq!(
                        partial_digest(partial_byte, num_bits),
                        partial_digest(partial_byte & mask, num_bits),
                        "bits above num_bits = {num_bits} must be ignored / partial_byte: {partial_byte:#04X}"
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
            //     partial bits, or absorbs the wrong number of them.
            let mut partial_outputs: Vec<Vec<u8>> = Vec::new();
            for num_bits in 0..=7 {
                for partial_byte in 0..(1u16 << num_bits) {
                    partial_outputs.push(partial_digest(partial_byte as u8, num_bits));
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
