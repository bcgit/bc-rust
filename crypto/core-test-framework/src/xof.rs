//! Generic behaviour tests for anything that implements [`XOF`].

use bouncycastle_core::errors::HashError;
use bouncycastle_core::traits::{XOF, XofOutput};

/// Instance of the test framework.
pub struct TestFrameworkXOF {
    // Put any config options here
    /// Can be disabled for XOFs that don't support a partial final byte of input.
    pub enable_partial_byte_tests: bool,
}

impl TestFrameworkXOF {
    ///
    pub fn new() -> Self {
        Self { enable_partial_byte_tests: true }
    }

    /// Exercises the trait against a known input-output pair.
    ///
    /// `expected_output` is the result of reading `expected_output.len()` bytes after absorbing
    /// `input`. There is deliberately no absorb-after-squeeze test: [`XOF::into_output`] consumes
    /// the XOF, so absorbing afterwards is not expressible and there is no runtime rule left to
    /// check. That guarantee is asserted instead by `compile_fail` doctests on the implementors.
    pub fn test_xof<X: XOF + Default>(&self, input: &[u8], expected_output: &[u8]) {
        /*** fn do_update(&mut self, data: &[u8]) ***/
        // Feeding the input in pieces must equal feeding it in one go.
        let mut xof = X::default();
        for chunk in input.chunks(16) {
            xof.do_update(chunk);
        }
        assert_eq!(
            xof.into_output().do_output(expected_output.len()),
            expected_output,
            "chunked input must equal a single update"
        );

        /*** fn do_output(&mut self, num_bytes: usize) -> Vec<u8> ***/
        let mut xof = X::default();
        xof.do_update(input);
        assert_eq!(
            xof.into_output().do_output(expected_output.len()),
            expected_output,
            "do_output must produce the expected bytes"
        );

        /*** fn do_output_out(&mut self, output: &mut [u8]) -> usize ***/
        // Pre-filled so that the documented zeroization is observable.
        let mut output = vec![0xFFu8; expected_output.len()];
        let mut xof = X::default();
        xof.do_update(input);
        let n = xof.into_output().do_output_out(&mut output);
        assert_eq!(n, expected_output.len(), "do_output_out must report what it wrote");
        assert_eq!(output, expected_output, "do_output_out must agree with do_output");

        // One output stream: reading it in two goes equals reading it in one.
        let split = expected_output.len() / 2;
        let mut xof = X::default();
        xof.do_update(input);
        let mut out = xof.into_output();
        let first = out.do_output(split);
        let mut second = vec![0u8; expected_output.len() - split];
        out.do_output_out(&mut second);
        assert_eq!(
            [first, second].concat(),
            expected_output,
            "successive reads must continue one stream"
        );

        /*** fn hash_xof(self, data: &[u8], result_len: usize) -> Vec<u8> ***/
        assert_eq!(
            X::default().hash_xof(input, expected_output.len()),
            expected_output,
            "the one-shot must equal update-then-output"
        );

        let mut output = vec![0xFFu8; expected_output.len()];
        let n = X::default().hash_xof_out(input, &mut output);
        assert_eq!(n, expected_output.len());
        assert_eq!(output, expected_output, "hash_xof_out must agree with hash_xof");

        /*** the Hash half: a XOF is a hash ***/
        self.test_xof_as_hash::<X>(input, expected_output);

        if self.enable_partial_byte_tests {
            self.test_xof_partial_bits::<X>(input, expected_output);
        }
    }

    /// The inherited [`Hash`] surface. `XOF: Hash`, so SHAKE can be used wherever a hash is wanted;
    /// these checks pin that the inherited methods agree with the XOF ones.
    fn test_xof_as_hash<X: XOF + Default>(&self, input: &[u8], expected_output: &[u8]) {
        let xof = X::default();
        let output_len = xof.output_len();
        assert!(output_len > 0, "output_len must be positive");
        assert!(xof.block_bitlen() > 0, "block_bitlen must be positive");
        assert!(
            xof.block_bitlen().is_multiple_of(8),
            "block_bitlen must be a whole number of bytes"
        );

        // do_final is do_output at the nominal length: the same stream, truncated.
        let mut a = X::default();
        a.do_update(input);
        let via_hash = a.do_final();
        assert_eq!(via_hash.len(), output_len, "do_final must produce output_len bytes");

        let mut b = X::default();
        b.do_update(input);
        assert_eq!(
            via_hash,
            b.into_output().do_output(output_len),
            "do_final must equal do_output(output_len)"
        );

        // ... and it is a prefix of the longer output, because a XOF cannot diversify by length.
        if expected_output.len() >= output_len {
            assert_eq!(
                &via_hash[..],
                &expected_output[..output_len],
                "do_final must be a prefix of the longer output"
            );
        }

        // do_final_out fills the caller's buffer, zeroizing it first.
        let mut buf = vec![0xFFu8; output_len];
        let mut c = X::default();
        c.do_update(input);
        let n = c.do_final_out(&mut buf);
        assert_eq!(n, output_len);
        assert_eq!(buf, via_hash, "do_final_out must agree with do_final");

        // The one-shot Hash entry points.
        assert_eq!(X::default().hash(input), via_hash, "hash must equal update-then-do_final");
        let mut buf = vec![0xFFu8; output_len];
        assert_eq!(X::default().hash_out(input, &mut buf), output_len);
        assert_eq!(buf, via_hash, "hash_out must agree with hash");
    }

    /// A partial final byte of input, in both the XOF and the Hash spelling.
    fn test_xof_partial_bits<X: XOF + Default>(&self, input: &[u8], expected_output: &[u8]) {
        // num_bits = 0 means the message ended on a byte boundary, so it must match plain input.
        let mut xof = X::default();
        xof.do_update(input);
        assert_eq!(
            xof.into_output_partial_bits(0, 0)
                .expect("0 is in range")
                .do_output(expected_output.len()),
            expected_output,
            "num_bits = 0 must equal a byte-aligned message"
        );

        // A real partial byte must change the output, and both spellings must agree.
        for num_bits in 1..=7usize {
            let mut a = X::default();
            a.do_update(input);
            let with_bits = a
                .into_output_partial_bits(0xFE, num_bits)
                .expect("num_bits is in 1..=7")
                .do_output(expected_output.len());
            assert_ne!(
                with_bits, expected_output,
                "a partial byte must change the output / num_bits: {num_bits}"
            );

            let mut b = X::default();
            b.do_update(input);
            let via_hash = b.do_final_partial_bits(0xFE, num_bits).expect("num_bits is in 1..=7");
            assert_eq!(
                via_hash,
                with_bits[..via_hash.len()],
                "do_final_partial_bits must be the same stream / num_bits: {num_bits}"
            );

            let mut buf = vec![0xFFu8; via_hash.len()];
            let mut c = X::default();
            c.do_update(input);
            let n = c
                .do_final_partial_bits_out(0xFE, num_bits, &mut buf)
                .expect("num_bits is in 1..=7");
            assert_eq!(n, via_hash.len());
            assert_eq!(buf, via_hash, "the _out form must agree / num_bits: {num_bits}");
        }

        // "num_bits must be in 0..=7; larger values return HashError::InvalidLength."
        for num_bits in [8usize, 9, 15, 16, 64, usize::MAX] {
            let mut xof = X::default();
            xof.do_update(input);
            assert!(
                matches!(
                    xof.into_output_partial_bits(0xFF, num_bits),
                    Err(HashError::InvalidLength(_))
                ),
                "into_output_partial_bits must reject num_bits = {num_bits}"
            );

            let mut xof = X::default();
            xof.do_update(input);
            assert!(
                matches!(
                    xof.do_final_partial_bits(0xFF, num_bits),
                    Err(HashError::InvalidLength(_))
                ),
                "do_final_partial_bits must reject num_bits = {num_bits}"
            );
        }
    }
}

impl Default for TestFrameworkXOF {
    fn default() -> Self {
        Self::new()
    }
}
