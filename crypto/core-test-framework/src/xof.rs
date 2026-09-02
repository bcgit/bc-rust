//! Generic behaviour tests for anything that implements [`XOF`].

use bouncycastle_core::errors::HashError;
use bouncycastle_core::traits::XOF;

/// Instance of the test framework.
pub struct TestFrameworkXOF {
    // Put any config options here
    /// Can be disabled for XOFs that don't implement [`XOF::absorb_last_partial_byte`].
    pub enable_partial_byte_tests: bool,
}

impl TestFrameworkXOF {
    ///
    pub fn new() -> Self {
        Self { enable_partial_byte_tests: true }
    }

    /// Test the absorb-after-squeeze members of trait XOF against the given input-output pair.
    /// This is not exhaustive; it covers the rules laid out in the "State and Absorb-after-Squeeze"
    /// section of the [`XOF`] docs: an XOF is an absorb phase followed by a squeeze phase, once
    /// squeezing has begun any further absorb returns [`HashError::InvalidState`], and a rejected
    /// absorb leaves the object usable for further squeezing.
    /// `expected_output` is the result of squeezing `expected_output.len()` bytes after absorbing
    /// `input`.
    pub fn test_xof<X: XOF + Default>(&self, input: &[u8], expected_output: &[u8]) {
        /*** fn absorb(&mut self, data: &[u8]) -> Result<(), HashError> ***/
        // Absorbing is fine, repeatedly, right up until the first squeeze.
        let mut xof = X::default();
        for chunk in input.chunks(16) {
            xof.absorb(chunk).expect("absorb() before any squeeze must succeed");
        }

        // "once the XOF has begun squeezing, attempting to absorb more will return
        //     HashError::InvalidState"
        // squeeze() begins squeezing ...
        let mut xof = X::default();
        xof.absorb(input).expect("absorb() before any squeeze must succeed");
        let _ = xof.squeeze(expected_output.len());
        assert!(
            matches!(xof.absorb(b"more input"), Err(HashError::InvalidState(_))),
            "absorb() after squeeze() must return InvalidState"
        );

        // ... and so does squeeze_out()
        let mut xof = X::default();
        xof.absorb(input).expect("absorb() before any squeeze must succeed");
        let mut output = vec![0u8; expected_output.len()];
        xof.squeeze_out(&mut output);
        assert!(
            matches!(xof.absorb(b"more input"), Err(HashError::InvalidState(_))),
            "absorb() after squeeze_out() must return InvalidState"
        );

        /*** fn squeeze(&mut self, num_bytes: usize) -> Vec<u8> ***/
        /*** fn squeeze_out(&mut self, output: &mut [u8]) -> usize ***/
        // "... and leave the object usable for further squeezing"
        // So squeezing the output in two halves around a rejected absorb must give exactly the same
        // stream as one clean squeeze: a rejected absorb must not consume, pad, or otherwise
        // disturb the sponge.
        let split = expected_output.len() / 2;

        let mut xof = X::default();
        xof.absorb(input).expect("absorb() before any squeeze must succeed");
        let first_half = xof.squeeze(split);
        assert!(xof.absorb(b"more input").is_err());
        let mut second_half = vec![0u8; expected_output.len() - split];
        xof.squeeze_out(&mut second_half);

        assert_eq!(
            first_half.as_slice(),
            &expected_output[..split],
            "Incorrect output for input / the output stream must be unchanged by a rejected absorb"
        );
        assert_eq!(
            second_half.as_slice(),
            &expected_output[split..],
            "Incorrect output for input / the output stream must continue as if the rejected absorb never happened"
        );

        if self.enable_partial_byte_tests {
            /*** fn absorb_last_partial_byte(&mut self, partial_byte: u8, num_bits: usize) -> Result<(), HashError> ***/
            // The same phase rule applies to absorb_last_partial_byte() once squeezing has begun.
            let mut xof = X::default();
            xof.absorb(input).expect("absorb() before any squeeze must succeed");
            let _ = xof.squeeze(expected_output.len());
            assert!(
                matches!(xof.absorb_last_partial_byte(0x01, 3), Err(HashError::InvalidState(_))),
                "absorb_last_partial_byte() after squeeze() must return InvalidState"
            );

            // "Unlike XOF::absorb, this switches the XOF from Absorbing mode into Squeezing mode
            //     because absorbing more input after absorbing a partial byte is undefined
            //     behaviour."
            // So it leaves the object in the same state a squeeze does, for every valid num_bits,
            // with no squeeze having happened at all.
            for num_bits in 0..=7 {
                let mut xof = X::default();
                xof.absorb(input).expect("absorb() before any squeeze must succeed");
                xof.absorb_last_partial_byte(0xFF, num_bits)
                    .expect("absorb_last_partial_byte() must succeed for num_bits in 0..=7");
                let expected_partial_output = xof.squeeze(expected_output.len());

                let mut xof = X::default();
                xof.absorb(input).expect("absorb() before any squeeze must succeed");
                xof.absorb_last_partial_byte(0xFF, num_bits)
                    .expect("absorb_last_partial_byte() must succeed for num_bits in 0..=7");

                assert!(
                    matches!(xof.absorb(b"more input"), Err(HashError::InvalidState(_))),
                    "absorb() after absorb_last_partial_byte() must return InvalidState / num_bits: {num_bits}"
                );
                assert!(
                    matches!(
                        xof.absorb_last_partial_byte(0xFF, num_bits),
                        Err(HashError::InvalidState(_))
                    ),
                    "a second absorb_last_partial_byte() must return InvalidState / num_bits: {num_bits}"
                );

                // ... and, again, the rejections must leave the object usable for further squeezing.
                assert_eq!(
                    xof.squeeze(expected_output.len()),
                    expected_partial_output,
                    "the output stream must be unchanged by a rejected absorb / num_bits: {num_bits}"
                );
            }

            // Helper: the output stream of `input` finished with the low `num_bits` bits of
            // `partial_byte`.
            let partial_absorb_output = |partial_byte: u8, num_bits: usize| -> Vec<u8> {
                let mut xof = X::default();
                xof.absorb(input).expect("absorb() before any squeeze must succeed");
                xof.absorb_last_partial_byte(partial_byte, num_bits)
                    .expect("absorb_last_partial_byte() must succeed for num_bits in 0..=7");
                xof.squeeze(expected_output.len())
            };

            // "0 is a valid value and means the message ends on a byte boundary (equivalent to
            //     XOF::absorb)."
            // So the message is still just `input`, whatever the discarded bits of partial_byte are.
            for partial_byte in [0x00u8, 0x01, 0x80, 0xA5, 0xFF] {
                assert_eq!(
                    partial_absorb_output(partial_byte, 0),
                    expected_output,
                    "num_bits = 0 must leave the message byte-aligned / partial_byte: {partial_byte:#04X}"
                );
            }

            // "The num_bits message bits are taken from the least significant bits of
            //     partial_byte".
            // So the unused high bits are not part of the message and must not change the output.
            for num_bits in 0..=7 {
                // no overflow: 1u8 << 7 == 0x80
                let mask = (1u8 << num_bits) - 1;
                for partial_byte in [0x00u8, 0x5A, 0xA5, 0xFF] {
                    assert_eq!(
                        partial_absorb_output(partial_byte, num_bits),
                        partial_absorb_output(partial_byte & mask, num_bits),
                        "bits above num_bits = {num_bits} must be ignored / partial_byte: {partial_byte:#04X}"
                    );
                }
            }

            // "num_bits must be in 0..=7; larger values return HashError::InvalidLength."
            // Checked on an absorbing object, so that it is the range check rejecting the call and
            // not the phase check above.
            for num_bits in [8usize, 9, 15, 16, 64, usize::MAX] {
                let mut xof = X::default();
                xof.absorb(input).expect("absorb() before any squeeze must succeed");
                assert!(
                    matches!(
                        xof.absorb_last_partial_byte(0xFF, num_bits),
                        Err(HashError::InvalidLength(_))
                    ),
                    "absorb_last_partial_byte() must reject num_bits = {num_bits} with InvalidLength"
                );
            }

            /*** fn squeeze_partial_byte_final(self, num_bits: usize) -> Result<u8, HashError> ***/
            /*** fn squeeze_partial_byte_final_out(self, num_bits: usize, output: &mut u8) -> Result<(), HashError> ***/
            // "The bits are returned in the least significant num_bits bits of the returned u8, with
            //     the remaining high bits zero."
            // They are the bits of the next byte of the output stream, which `expected_output` gives
            // us: after squeezing `split` bytes, the next byte is expected_output[split].
            let split = expected_output.len() / 2;
            for num_bits in 0..=7 {
                // no overflow: 1u8 << 7 == 0x80
                let mask = (1u8 << num_bits) - 1;

                let mut xof = X::default();
                xof.absorb(input).expect("absorb() before any squeeze must succeed");
                let _ = xof.squeeze(split);
                let partial_byte = xof
                    .squeeze_partial_byte_final(num_bits)
                    .expect("squeeze_partial_byte_final() must succeed for num_bits in 0..=7");

                assert_eq!(
                    partial_byte,
                    expected_output[split] & mask,
                    "the squeezed bits must be the low bits of the next output byte / num_bits: {num_bits}"
                );
                assert_eq!(
                    partial_byte & !mask,
                    0x00,
                    "the unused high bits of the result must be zero / num_bits: {num_bits}"
                );

                // "The same as XOF::squeeze_partial_byte_final, but writes into the provided output
                //     byte. The output byte is zeroized before the result is written."
                // Pre-filled with 0xFF so that the zeroization is observable.
                let mut output_byte = 0xFFu8;
                let mut xof = X::default();
                xof.absorb(input).expect("absorb() before any squeeze must succeed");
                let _ = xof.squeeze(split);
                xof.squeeze_partial_byte_final_out(num_bits, &mut output_byte)
                    .expect("squeeze_partial_byte_final_out() must succeed for num_bits in 0..=7");
                assert_eq!(
                    output_byte, partial_byte,
                    "squeeze_partial_byte_final_out() must agree with squeeze_partial_byte_final() / num_bits: {num_bits}"
                );
            }

            // "num_bits must be in 0..=7; larger values return HashError::InvalidLength."
            for num_bits in [8usize, 9, 15, 16, 64, usize::MAX] {
                let mut xof = X::default();
                xof.absorb(input).expect("absorb() before any squeeze must succeed");
                let _ = xof.squeeze(split);
                assert!(
                    matches!(
                        xof.squeeze_partial_byte_final(num_bits),
                        Err(HashError::InvalidLength(_))
                    ),
                    "squeeze_partial_byte_final() must reject num_bits = {num_bits} with InvalidLength"
                );

                let mut output_byte = 0u8;
                let mut xof = X::default();
                xof.absorb(input).expect("absorb() before any squeeze must succeed");
                let _ = xof.squeeze(split);
                assert!(
                    matches!(
                        xof.squeeze_partial_byte_final_out(num_bits, &mut output_byte),
                        Err(HashError::InvalidLength(_))
                    ),
                    "squeeze_partial_byte_final_out() must reject num_bits = {num_bits} with InvalidLength"
                );
            }
        }
    }
}
