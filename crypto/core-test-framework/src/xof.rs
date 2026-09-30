//! Generic behaviour tests for anything that implements [`XOF`].

use bouncycastle_core::errors::HashError;
use bouncycastle_core::traits::{XOF, XOFSqueezer};

/// Instance of the test framework.
pub struct TestFrameworkXOF {
    // Put any config options here
    /// Can be disabled for XOFs that don't support a partial final byte of input.
    pub enable_partial_byte_tests: bool,
    /// Set for XOFs whose [`XOFSqueezer::do_final`] binds the length it is asked for when it is
    /// the first read -- the SP 800-185 forms, which then compute their fixed-length counterpart
    /// rather than the XOF stream. The suite cannot know those bytes, so it checks the split
    /// instead and leaves the values to the implementation's own vector tests.
    pub do_final_binds_output_length: bool,
}

impl TestFrameworkXOF {
    ///
    pub fn new() -> Self {
        Self { enable_partial_byte_tests: true, do_final_binds_output_length: false }
    }

    /// Exercises the trait against a known input-output pair.
    ///
    /// `expected_output` is the result of reading `expected_output.len()` bytes after absorbing
    /// `input`. There is deliberately no absorb-after-squeeze test: [`XOF::into_squeezer`] consumes
    /// the XOF, so absorbing afterwards is not expressible and there is no runtime rule left to
    /// check. That guarantee is asserted instead by `compile_fail` doctests on the implementors.
    pub fn test_xof<X: XOF>(&self, make: impl Fn() -> X, input: &[u8], expected_output: &[u8]) {
        /*** fn do_update(&mut self, data: &[u8]) ***/
        // Feeding the input in pieces must equal feeding it in one go.
        let mut xof = make();
        for chunk in input.chunks(16) {
            xof.do_update(chunk);
        }
        assert_eq!(
            xof.into_squeezer().do_output(expected_output.len()),
            expected_output,
            "chunked input must equal a single update"
        );

        /*** fn do_output(&mut self, num_bytes: usize) -> Vec<u8> ***/
        let mut xof = make();
        xof.do_update(input);
        assert_eq!(
            xof.into_squeezer().do_output(expected_output.len()),
            expected_output,
            "do_output must produce the expected bytes"
        );

        /*** fn do_output_out(&mut self, output: &mut [u8]) -> usize ***/
        // Pre-filled so that the documented zeroization is observable.
        let mut output = vec![0xFFu8; expected_output.len()];
        let mut xof = make();
        xof.do_update(input);
        let n = xof.into_squeezer().do_output_out(&mut output);
        assert_eq!(n, expected_output.len(), "do_output_out must report what it wrote");
        assert_eq!(output, expected_output, "do_output_out must agree with do_output");

        // One output stream: reading it in two goes equals reading it in one.
        let split = expected_output.len() / 2;
        let mut xof = make();
        xof.do_update(input);
        let mut out = xof.into_squeezer();
        let first = out.do_output(split);
        let mut second = vec![0u8; expected_output.len() - split];
        out.do_output_out(&mut second);
        assert_eq!(
            [first, second].concat(),
            expected_output,
            "successive reads must continue one stream"
        );

        // do_output_out zeroizes the caller's buffer before writing, so a dirty one still comes
        // back holding exactly the output.
        let mut buf = vec![0xFFu8; expected_output.len()];
        let mut xof = make();
        xof.do_update(input);
        let n = xof.into_squeezer().do_output_out(&mut buf);
        assert_eq!(n, expected_output.len());
        assert_eq!(buf, expected_output, "do_output_out must zeroize before writing");

        /*** fn do_final(self, num_bytes: usize) -> Vec<u8> ***/
        // As the first read, do_final is either the end of this stream or -- for a XOF that binds
        // the length it is asked for -- a different function altogether. Both are pinned here; the
        // second's bytes belong to the implementation's own vector tests.
        let mut xof = make();
        xof.do_update(input);
        let first_read = xof.into_squeezer().do_final(expected_output.len());
        if self.do_final_binds_output_length {
            assert_ne!(
                first_read, expected_output,
                "a length-binding do_final must not reproduce the XOF stream"
            );
        } else {
            assert_eq!(first_read, expected_output, "do_final must produce the expected bytes");
        }

        /*** fn do_final_out(self, output: &mut [u8]) -> usize ***/
        // Pre-filled so that the documented zeroization is observable.
        let mut buf = vec![0xFFu8; expected_output.len()];
        let mut xof = make();
        xof.do_update(input);
        let n = xof.into_squeezer().do_final_out(&mut buf);
        assert_eq!(n, expected_output.len(), "do_final_out must report what it wrote");
        assert_eq!(buf, first_read, "do_final_out must agree with do_final");

        // Once a read has happened there is nothing left to bind, so do_final continues the stream
        // that read began rather than restarting it -- however the two behave as a first read.
        let mut xof = make();
        xof.do_update(input);
        let mut out = xof.into_squeezer();
        let first = out.do_output(split);
        assert_eq!(
            [first, out.do_final(expected_output.len() - split)].concat(),
            expected_output,
            "do_final after a read must continue that stream"
        );

        /*** fn xof(self, data: &[u8], result_len: usize) -> Vec<u8> ***/
        // The one-shots name their length and never come back, so they read as do_final does: for
        // a XOF that binds its output length they produce what do_final produced above, not the
        // stream.
        let one_shot: &[u8] =
            if self.do_final_binds_output_length { &first_read } else { expected_output };
        assert_eq!(
            make().xof(input, expected_output.len()),
            one_shot,
            "the one-shot must equal update-then-do_final"
        );

        let mut output = vec![0xFFu8; expected_output.len()];
        let n = make().xof_out(input, &mut output);
        assert_eq!(n, expected_output.len());
        assert_eq!(output, one_shot, "xof_out must agree with xof");

        /*** Clone: a XOF mid-absorb can be forked ***/
        // The clone continues from the same absorbed prefix and owns its own sponge.
        let (prefix, tail) = input.split_at(input.len() / 2);
        let mut original = make();
        original.do_update(prefix);
        let mut forked = original.clone();
        original.do_update(tail);
        forked.do_update(tail);
        assert_eq!(
            original.into_squeezer().do_output(expected_output.len()),
            expected_output,
            "the original must be unaffected by cloning"
        );
        assert_eq!(
            forked.into_squeezer().do_output(expected_output.len()),
            expected_output,
            "a clone must continue from the same absorbed prefix"
        );

        let mut original = make();
        original.do_update(prefix);
        let mut forked = original.clone();
        original.do_update(tail);
        forked.do_update(&[0xA5]);
        forked.do_update(tail);
        assert_ne!(
            forked.into_squeezer().do_output(expected_output.len()),
            original.into_squeezer().do_output(expected_output.len()),
            "a clone must have its own state, not share the original's"
        );

        /*** the Hash half: a XOF is a hash ***/
        self.test_xof_as_hash(&make, input, expected_output);

        if self.enable_partial_byte_tests {
            self.test_xof_partial_bits(&make, input, expected_output);
        }
    }

    /// The inherited [`Hash`] surface. `XOF: Hash`, so SHAKE can be used wherever a hash is wanted;
    /// these checks pin that the inherited methods agree with the XOF ones.
    fn test_xof_as_hash<X: XOF>(&self, make: impl Fn() -> X, input: &[u8], expected_output: &[u8]) {
        let xof = make();
        let output_len = xof.output_len();
        assert!(output_len > 0, "output_len must be positive");
        assert!(xof.block_bitlen() > 0, "block_bitlen must be positive");
        assert!(
            xof.block_bitlen().is_multiple_of(8),
            "block_bitlen must be a whole number of bytes"
        );

        let mut a = make();
        a.do_update(input);
        let via_hash = a.do_final();
        assert_eq!(via_hash.len(), output_len, "do_final must produce output_len bytes");

        let mut b = make();
        b.do_update(input);
        if self.do_final_binds_output_length {
            // The Hash view is a final read at the nominal length, so it binds that length and is
            // a different function from the stream -- and must agree with the squeezer's own final
            // read at the same length.
            assert_ne!(
                via_hash,
                b.into_squeezer().do_output(output_len),
                "a length-binding Hash::do_final must not be the stream truncated"
            );
            let mut c = make();
            c.do_update(input);
            assert_eq!(
                via_hash,
                c.into_squeezer().do_final(output_len),
                "Hash::do_final must be the squeezer's final read at output_len"
            );
        } else {
            // do_final is do_output at the nominal length: the same stream, truncated.
            assert_eq!(
                via_hash,
                b.into_squeezer().do_output(output_len),
                "do_final must equal do_output(output_len)"
            );

            // ... and a prefix of the longer output, because a XOF cannot diversify by length.
            if expected_output.len() >= output_len {
                assert_eq!(
                    &via_hash[..],
                    &expected_output[..output_len],
                    "do_final must be a prefix of the longer output"
                );
            }
        }

        // do_final_out fills the caller's buffer, zeroizing it first.
        let mut buf = vec![0xFFu8; output_len];
        let mut c = make();
        c.do_update(input);
        let n = c.do_final_out(&mut buf);
        assert_eq!(n, output_len);
        assert_eq!(buf, via_hash, "do_final_out must agree with do_final");

        // The one-shot Hash entry points.
        assert_eq!(make().hash(input), via_hash, "hash must equal update-then-do_final");
        let mut buf = vec![0xFFu8; output_len];
        assert_eq!(make().hash_out(input, &mut buf), output_len);
        assert_eq!(buf, via_hash, "hash_out must agree with hash");
    }

    /// A partial final byte of input, in both the XOF and the Hash spelling.
    fn test_xof_partial_bits<X: XOF>(
        &self,
        make: impl Fn() -> X,
        input: &[u8],
        expected_output: &[u8],
    ) {
        // num_bits = 0 means the message ended on a byte boundary, so it must match plain input.
        let mut xof = make();
        xof.do_update(input);
        assert_eq!(
            xof.into_squeezer_partial_bits(0, 0)
                .expect("0 is in range")
                .do_output(expected_output.len()),
            expected_output,
            "num_bits = 0 must equal a byte-aligned message"
        );

        // A real partial byte must change the output, and both spellings must agree.
        for num_bits in 1..=7usize {
            let mut a = make();
            a.do_update(input);
            let with_bits = a
                .into_squeezer_partial_bits(0xFE, num_bits)
                .expect("num_bits is in 1..=7")
                .do_output(expected_output.len());
            assert_ne!(
                with_bits, expected_output,
                "a partial byte must change the output / num_bits: {num_bits}"
            );

            let mut b = make();
            b.do_update(input);
            let via_hash = b.do_final_partial_bits(0xFE, num_bits).expect("num_bits is in 1..=7");
            assert_eq!(
                via_hash,
                with_bits[..via_hash.len()],
                "do_final_partial_bits must be the same stream / num_bits: {num_bits}"
            );

            let mut buf = vec![0xFFu8; via_hash.len()];
            let mut c = make();
            c.do_update(input);
            let n = c
                .do_final_partial_bits_out(0xFE, num_bits, &mut buf)
                .expect("num_bits is in 1..=7");
            assert_eq!(n, via_hash.len());
            assert_eq!(buf, via_hash, "the _out form must agree / num_bits: {num_bits}");
        }

        // "num_bits must be in 0..=7; larger values return HashError::InvalidLength."
        for num_bits in [8usize, 9, 15, 16, 64, usize::MAX] {
            let mut xof = make();
            xof.do_update(input);
            assert!(
                matches!(
                    xof.into_squeezer_partial_bits(0xFF, num_bits),
                    Err(HashError::InvalidLength(_))
                ),
                "into_squeezer_partial_bits must reject num_bits = {num_bits}"
            );

            let mut xof = make();
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
