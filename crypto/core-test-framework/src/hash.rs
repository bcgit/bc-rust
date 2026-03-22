use bouncycastle_core_interface::traits::{Hash, HashAlgParams};

pub struct TestFrameworkHash {
    pub enable_partial_final_input_tests: bool,
}

impl TestFrameworkHash {
    pub fn new() -> Self {
        Self { enable_partial_final_input_tests: true }
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

        if self.enable_partial_final_input_tests {
            /*** fn do_final_partial_bits(self, partial_byte: u8, num_partial_bits: usize)-> Result<Vec<u8>, HashError>; ***/
            /*** fn do_final_partial_bits_out(self, partial_byte: u8, num_partial_bits: usize, output: &mut [u8]) -> Result<usize, HashError>; ***/
            // There's not a lot we can test here because this will require a different expected output from the rest of this test, but we can do something.

            //output slice too small -- should just truncate
            let mut first_output = vec![0u8; H::default().output_len()];
            H::default()
                .do_final_partial_bits_out(0xFF, 7, &mut *first_output)
                .expect("Failed to finalize partial input");
            let len_to_truncate_to = H::default().output_len() - 1;
            let mut output = vec![0u8; len_to_truncate_to];
            let bytes_written =
                H::default().do_final_partial_bits_out(0xFF, 7, &mut *output).unwrap();
            assert_eq!(bytes_written, len_to_truncate_to);
            assert_eq!(first_output[..len_to_truncate_to], output);
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
