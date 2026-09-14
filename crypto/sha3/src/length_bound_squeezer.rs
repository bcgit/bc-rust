//! The squeezing phase of the SP 800-185 functions that have an output length left to bind.

use crate::SHAKEParams;
use crate::cshake::CSHAKEInternal;
use crate::shake::SHAKESqueezer;
use crate::xof_utils::right_encode;
use bouncycastle_core::traits::{Hash, XOF, XOFSqueezer};

/// The squeezing phase of KMACXOF, TupleHashXOF and ParallelHashXOF, which still has a choice to
/// make.
///
/// Every SP 800-185 function ends its absorbed input with `right_encode(L)`, and the two forms of
/// each function differ only in what goes in there: the fixed-length KMAC, TupleHash and
/// ParallelHash of s. 4.3, 5.3 and 6.3 encode the requested output length, and the XOF forms of
/// s. 4.3.1, 5.3.1 and 6.3.1 encode 0. Nothing else about them differs, so the choice can be left
/// until the caller says how it wants to read -- which is what this type does:
///
/// * [`XOFSqueezer::do_output`] is the XOF reading. It is the caller saying "give me some bytes and
///   I may be back for more", which only `right_encode(0)` can answer, since a length bound into
///   the sponge cannot be revised once output has begun.
/// * [`XOFSqueezer::do_final`], as the **first** read, is the fixed-length reading. It is the
///   caller saying how many bytes it wants and that it will not be back, so `L` is that length in
///   bits and the result is the fixed-length function of s. 4.3, 5.3 or 6.3 -- the same bytes
///   `KMAC128(K, X, L, S)` produces, not a truncation of `KMACXOF128`.
///
/// The first read commits: the encoding is in the sponge from then on, so a `do_final` that
/// follows a `do_output` cannot bind anything and simply continues the `right_encode(0)` stream
/// the earlier read already chose.
pub struct LengthBoundSqueezer<PARAMS: SHAKEParams> {
    phase: Phase<PARAMS>,
}

/// Which side of the first read this squeezer is on.
enum Phase<PARAMS: SHAKEParams> {
    /// Nothing read yet, so `right_encode(L)` is still the caller's to choose.
    Unbound(CSHAKEInternal<PARAMS>),
    /// The encoding has been absorbed and the sponge is producing output.
    Squeezing(SHAKESqueezer<PARAMS>),
    /// Never observed: [`LengthBoundSqueezer::read`] leaves this here only while the value moves
    /// from one of the phases above to the other.
    Binding,
}

impl<PARAMS: SHAKEParams> LengthBoundSqueezer<PARAMS> {
    /// Wraps a cSHAKE with everything but its `right_encode(L)` absorbed.
    pub(crate) fn new(cshake: CSHAKEInternal<PARAMS>) -> Self {
        Self { phase: Phase::Unbound(cshake) }
    }

    /// [`XOFSqueezer::do_final_out`] with `L` given rather than taken from the buffer.
    ///
    /// For the `Hash` view of these functions, whose length is fixed by the type: it binds the
    /// nominal output length and then writes as much of it as the caller's buffer has room for,
    /// which is what [`Hash::do_final_out`] promises. Going through
    /// [`XOFSqueezer::do_final_out`] would bind the buffer's length instead, and a short buffer
    /// would then compute a different function rather than truncating this one.
    pub(crate) fn do_final_out_with_length(mut self, length_bits: u64, output: &mut [u8]) -> usize {
        self.read(length_bits, output)
    }

    /// Fills `output` from the stream, absorbing `right_encode(length_bits)` first if this is the
    /// first read. `output` is zeroized before anything is written to it.
    fn read(&mut self, length_bits: u64, output: &mut [u8]) -> usize {
        self.phase = match core::mem::replace(&mut self.phase, Phase::Binding) {
            Phase::Unbound(mut cshake) => {
                let (buf, len) = right_encode(length_bits);
                cshake.do_update(&buf[..len]);
                Phase::Squeezing(cshake.into_squeezer())
            }
            // An earlier read chose the encoding; this one continues that stream.
            committed => committed,
        };
        match &mut self.phase {
            Phase::Squeezing(squeezer) => squeezer.do_output_out(output),
            // The match above turns `Unbound` into `Squeezing` and puts `Binding` back as it found
            // it, so neither can be live here.
            _ => unreachable!("the first read always leaves the squeezing phase"),
        }
    }
}

impl<PARAMS: SHAKEParams> XOFSqueezer for LengthBoundSqueezer<PARAMS> {
    fn do_output(&mut self, num_bytes: usize) -> Vec<u8> {
        let mut out = vec![0u8; num_bytes];
        self.do_output_out(&mut out);
        out
    }

    /// Reading as a XOF, so `right_encode(0)` if this is the first read (s. 4.3.1, 5.3.1, 6.3.1).
    fn do_output_out(&mut self, output: &mut [u8]) -> usize {
        self.read(0, output)
    }

    fn do_final(self, num_bytes: usize) -> Vec<u8> {
        let mut out = vec![0u8; num_bytes];
        self.do_final_out(&mut out);
        out
    }

    /// The last read, so if it is also the first, `L` is its length in bits and this is the
    /// fixed-length function of s. 4.3, 5.3 or 6.3. After a [`XOFSqueezer::do_output`] the encoding
    /// is already in the sponge and this just continues that stream.
    fn do_final_out(mut self, output: &mut [u8]) -> usize {
        self.read((output.len() as u64) * 8, output)
    }
}
