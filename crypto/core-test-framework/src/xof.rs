//! Generic behaviour tests for anything that implements [`XOF`].

use bouncycastle_core::errors::HashError;
use bouncycastle_core::traits::{XOF, XOFSqueezer};

/// Instance of the test framework.
pub struct TestFrameworkXOF {
    /// Can be disabled for XOFs that don't implement partial-byte input.
    pub enable_partial_byte_tests: bool,
}

impl TestFrameworkXOF {
    ///
    pub fn new() -> Self {
        Self { enable_partial_byte_tests: true }
    }

    /// Test the members of trait [`XOF`] against the given input and expected output.
    /// `expected_output` is the result of squeezing `expected_output.len()` bytes after absorbing
    /// `input`; since every [`XOF`] has the prefix property, this also doubles as a prefix for
    /// deriving shorter expected outputs by truncation.
    pub fn test_xof<X: XOF + Default>(&self, input: &[u8], expected_output: &[u8]) {
        let n = expected_output.len();

        /*** fn xof(self, data: &[u8], result_len: usize) -> Vec<u8> ***/
        assert_eq!(X::default().xof(input, n), expected_output);

        /*** fn xof_out(self, data: &[u8], output: &mut [u8]) -> usize ***/
        let mut out = vec![0xA5u8; n];
        assert_eq!(X::default().xof_out(input, &mut out), n);
        assert_eq!(out, expected_output);

        /*** fn do_update(&mut self, data: &[u8]) ***/
        /*** fn into_squeezer(self) -> Self::Squeezer ***/
        /*** fn XOFSqueezer::do_output(&mut self, num_bytes: usize) -> Vec<u8> ***/
        let mut x = X::default();
        x.do_update(input);
        let mut squeezer = x.into_squeezer();
        assert_eq!(squeezer.do_output(n), expected_output);

        /*** fn XOFSqueezer::do_output_out(&mut self, output: &mut [u8]) -> usize ***/
        let mut x = X::default();
        x.do_update(input);
        let mut squeezer = x.into_squeezer();
        let mut out = vec![0xA5u8; n];
        assert_eq!(squeezer.do_output_out(&mut out), n);
        assert_eq!(out, expected_output);

        /*** Absorbing in chunks must equal absorbing in one shot. ***/
        let mut x = X::default();
        for chunk in input.chunks(3.max(input.len() / 5)) {
            x.do_update(chunk);
        }
        assert_eq!(x.into_squeezer().do_final(n), expected_output);

        /*** Prefix property: output(k) for k < n must equal a truncation of output(n). ***/
        for k in 0..n {
            let mut x = X::default();
            x.do_update(input);
            assert_eq!(
                x.into_squeezer().do_final(k),
                &expected_output[..k],
                "prefix property failed at k={k}"
            );
        }

        /*** Squeezing in multiple calls must equal squeezing the same total in one call. ***/
        if n >= 2 {
            let mut x = X::default();
            x.do_update(input);
            let mut squeezer = x.into_squeezer();
            let mut piecewise = Vec::with_capacity(n);
            let mut remaining = n;
            let mut call_len = 1usize;
            while remaining > 0 {
                let this_call = call_len.min(remaining);
                piecewise.extend(squeezer.do_output(this_call));
                remaining -= this_call;
                call_len = (call_len % 5) + 1;
            }
            assert_eq!(piecewise, expected_output, "multi-call output must match one-shot");
        }

        /*** Byte-at-a-time output must also match. ***/
        let mut x = X::default();
        x.do_update(input);
        let mut squeezer = x.into_squeezer();
        let mut byte_at_a_time = Vec::with_capacity(n);
        for _ in 0..n {
            byte_at_a_time.extend(squeezer.do_output(1));
        }
        assert_eq!(byte_at_a_time, expected_output, "byte-at-a-time output must match one-shot");

        /*** do_final() continues from wherever do_output() left the stream. ***/
        let split = n / 2;
        let mut x = X::default();
        x.do_update(input);
        let mut squeezer = x.into_squeezer();
        let first_half = squeezer.do_output(split);
        let second_half = squeezer.do_final(n - split);
        assert_eq!(first_half.as_slice(), &expected_output[..split]);
        assert_eq!(second_half.as_slice(), &expected_output[split..]);

        if self.enable_partial_byte_tests {
            for num_bits in 0..=7 {
                let mut x = X::default();
                x.do_update(input);
                let expected_partial_output = x
                    .into_squeezer_partial_bits(0xFF, num_bits)
                    .expect("partial-byte input must succeed for num_bits in 0..=7")
                    .do_final(n);

                let mut x = X::default();
                x.do_update(input);
                assert_eq!(
                    x.into_squeezer_partial_bits(0xFF, num_bits)
                        .expect("partial-byte input must succeed for num_bits in 0..=7")
                        .do_final(n),
                    expected_partial_output,
                    "partial-byte input must be deterministic / num_bits: {num_bits}"
                );
            }

            for partial_byte in [0x00u8, 0x01, 0x80, 0xA5, 0xFF] {
                let mut x = X::default();
                x.do_update(input);
                assert_eq!(
                    x.into_squeezer_partial_bits(partial_byte, 0)
                        .expect("num_bits = 0 must be accepted")
                        .do_final(n),
                    expected_output,
                    "num_bits = 0 must leave the message byte-aligned / partial_byte: {partial_byte:#04X}"
                );
            }

            for num_bits in 0..=7 {
                let mask = (0xFF00u16 >> num_bits) as u8;
                for partial_byte in [0x00u8, 0x5A, 0xA5, 0xFF] {
                    let mut x = X::default();
                    x.do_update(input);
                    let a =
                        x.into_squeezer_partial_bits(partial_byte, num_bits).unwrap().do_final(n);

                    let mut x = X::default();
                    x.do_update(input);
                    let b = x
                        .into_squeezer_partial_bits(partial_byte & mask, num_bits)
                        .unwrap()
                        .do_final(n);

                    assert_eq!(
                        a,
                        b,
                        "the low 8 - num_bits = {} bits must be ignored / partial_byte: {partial_byte:#04X}",
                        8 - num_bits
                    );
                }
            }

            for num_bits in [8usize, 9, 15, 16, 64, usize::MAX] {
                let mut x = X::default();
                x.do_update(input);
                assert!(
                    matches!(
                        x.into_squeezer_partial_bits(0xFF, num_bits),
                        Err(HashError::InvalidLength(_))
                    ),
                    "into_squeezer_partial_bits() must reject num_bits = {num_bits} with InvalidLength"
                );
            }
        }
    }
}
