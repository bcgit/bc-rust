//! cSHAKE, the customizable SHAKE of NIST SP 800-185 Sec 3.

use crate::SHAKEParams;
use crate::keccak::SHA3_FAMILY_STATE_LEN;
use crate::shake::{SHAKEInternal, SHAKESqueezer};
use bouncycastle_core::errors::{HashError, SuspendableError};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, Hash, Suspendable, XOF, XOFSqueezer};
use bouncycastle_utils::suspendable_state::{
    Cursor, CursorMut, LIB_VERSION_LEN, SuspendableComponent, resume_component, suspend_component,
};

/// Length in bytes of the suspended state of cSHAKE.
pub const SUSPENDED_CSHAKE_STATE_LEN: usize = LIB_VERSION_LEN + CSHAKE_COMPONENT_LEN;
/// Length in bytes of the suspended state of a [`LengthBoundSqueezer`].
pub const SUSPENDED_LENGTH_BOUND_SQUEEZER_STATE_LEN: usize = SUSPENDED_CSHAKE_STATE_LEN;
/// The cSHAKE state without its version header: the SHA3-family state, then one byte saying
/// whether `N` or `S` was non-empty. The functions built on cSHAKE write this first, under their
/// own tag, and their own fields after it.
pub(crate) const CSHAKE_COMPONENT_LEN: usize = SHA3_FAMILY_STATE_LEN + 1;

/// The domain separator cSHAKE absorbs in place of SHAKE's `1111`: the `00` of SP 800-185 Sec 3.3,
/// two zero bits, which is what keeps a customized instance separate from plain SHAKE.
const CSHAKE_SUFFIX: (u8, usize) = (0x00, 2);

/// Internal struct for cSHAKE. Use [`crate::CSHAKE128`] or [`crate::CSHAKE256`].
///
/// cSHAKE is SHAKE with two extra inputs bound to the front of the message: a function-name string
/// `N`, reserved for NIST, and a customization string `S`, chosen by the caller. SP 800-185 Sec 3.1
/// puts it as strong typing -- two instances with different `N` or `S` produce unrelated output, so
/// a key fingerprint and an email signature computed over the same bytes cannot collide.
///
/// # The empty case is SHAKE, exactly
///
/// SP 800-185 Sec 3.3 step 1: when `N` and `S` are both empty, cSHAKE *is* SHAKE, including its
/// `1111` domain separator. This is a required special case, not something that falls out of the
/// general construction -- feeding empty strings through the `bytepad` branch would absorb a
/// non-empty prefix and use a different separator, giving a different function. [`Self::new`]
/// branches on it, and there is a test that the two agree.
#[derive(Clone)]
pub struct CSHAKEInternal<PARAMS: SHAKEParams> {
    shake: SHAKEInternal<PARAMS>,
    /// False when `N` and `S` are both empty, in which case this is plain SHAKE.
    customized: bool,
}

impl<PARAMS: SHAKEParams> Algorithm for CSHAKEInternal<PARAMS> {
    const ALG_NAME: &'static str = PARAMS::CSHAKE_ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = PARAMS::MAX_SECURITY_STRENGTH;
}

impl<PARAMS: SHAKEParams> CSHAKEInternal<PARAMS> {
    /// A new cSHAKE bound to the function name `n` and customization string `s`.
    ///
    /// Both may be empty; if both are, this is plain SHAKE (Sec 3.3 step 1).
    ///
    /// `n` is reserved for NIST-defined functions -- Sec 3.4 asks callers not to invent their own,
    /// because a value NIST later assigns would then collide. Customization belongs in `s`.
    pub fn new(n: &[u8], s: &[u8]) -> Self {
        let mut shake = SHAKEInternal::<PARAMS>::new();
        let customized = !n.is_empty() || !s.is_empty();
        if customized {
            // Sec 3.3: bytepad(encode_string(N) || encode_string(S), rate).
            absorb_bytepad(&mut shake, &[n, s]);
        }
        Self { shake, customized }
    }
}

/// Absorbs `bytepad(encode_string(s[0]) || ... || encode_string(s[n]), rate)`, the padding of
/// SP 800-185 Sec 2.3.3 over the string encodings of Sec 2.3.2.
///
/// Absorbed straight into the sponge rather than built in a buffer, so there is no allocation and
/// no bound on the length of the strings.
fn absorb_bytepad<PARAMS: SHAKEParams>(shake: &mut SHAKEInternal<PARAMS>, strings: &[&[u8]]) {
    let rate = PARAMS::RATE_BYTES;
    // Step 1: the encoding of the block size comes first.
    let mut written = absorb_left_encode(shake, rate as u64);
    for s in strings {
        written += absorb_encoded_string(shake, s);
    }
    // Step 3: zero bytes up to a whole number of rate-sized blocks.
    absorb_zeros(shake, written.next_multiple_of(rate) - written);
}

/// [`absorb_bytepad`] against a cSHAKE, for the functions layered on top of it: KMAC binds its key
/// this way (Sec 4.3 step 1) as a second bytepad block inside cSHAKE's message.
pub(crate) fn absorb_bytepad_strings<PARAMS: SHAKEParams>(
    cshake: &mut CSHAKEInternal<PARAMS>,
    strings: &[&[u8]],
) {
    absorb_bytepad(&mut cshake.shake, strings);
}

/// Absorbs `encode_string(s)` into a cSHAKE, for the functions layered on top: TupleHash encodes
/// each tuple element this way (Sec 5.3 step 3), which is what makes the tuple boundaries part of
/// the hash.
pub(crate) fn absorb_encoded_string_into<PARAMS: SHAKEParams>(
    cshake: &mut CSHAKEInternal<PARAMS>,
    s: &[u8],
) {
    absorb_encoded_string(&mut cshake.shake, s);
}

/// Absorbs `left_encode(value)` into a cSHAKE, for the functions layered on top: ParallelHash
/// binds its block size this way (Sec 6.3 step 2).
pub(crate) fn absorb_left_encode_into<PARAMS: SHAKEParams>(
    cshake: &mut CSHAKEInternal<PARAMS>,
    value: u64,
) {
    absorb_left_encode(&mut cshake.shake, value);
}

/// Absorbs `left_encode(value)`, returning how many bytes went in.
fn absorb_left_encode<PARAMS: SHAKEParams>(shake: &mut SHAKEInternal<PARAMS>, value: u64) -> usize {
    let (buf, len) = left_encode(value);
    shake.do_update(&buf[..len]);
    len
}

/// Absorbs `encode_string(s)` -- `left_encode(len(s))` then `s` -- returning how many bytes went
/// in. SP 800-185 Sec 2.3.2 counts the length in bits.
fn absorb_encoded_string<PARAMS: SHAKEParams>(
    shake: &mut SHAKEInternal<PARAMS>,
    s: &[u8],
) -> usize {
    let n = absorb_left_encode(shake, (s.len() as u64) * 8);
    shake.do_update(s);
    n + s.len()
}

/// Absorbs `count` zero bytes, the padding of `bytepad` (Sec 2.3.3 step 3).
fn absorb_zeros<PARAMS: SHAKEParams>(shake: &mut SHAKEInternal<PARAMS>, mut count: usize) {
    const ZEROS: [u8; 64] = [0u8; 64];
    while count > 0 {
        let n = count.min(ZEROS.len());
        shake.do_update(&ZEROS[..n]);
        count -= n;
    }
}

impl<PARAMS: SHAKEParams> CSHAKEInternal<PARAMS> {
    /// Writes the state under `tag` into `out`, which is exactly [`CSHAKE_COMPONENT_LEN`] bytes.
    pub(crate) fn write_tagged(&self, tag: u8, out: &mut [u8]) {
        let (family, rest) = out.split_at_mut(SHA3_FAMILY_STATE_LEN);
        self.shake.write_family_state(tag, family);
        let mut w = CursorMut::new(rest);
        w.u8(self.customized as u8);
        debug_assert!(w.is_done());
    }

    /// The reverse of [`Self::write_tagged`]. A sponge that has begun squeezing is refused: a
    /// cSHAKE a caller can hold is still absorbing, and the squeezing half is a [`SHAKESqueezer`]
    /// or a [`LengthBoundSqueezer`], which resume their own states.
    pub(crate) fn read_tagged(state: &[u8], tag: u8) -> Result<Self, SuspendableError> {
        let (family, rest) = state.split_at(SHA3_FAMILY_STATE_LEN);
        let shake = SHAKEInternal::read_family_state(family, tag)?;
        if shake.is_squeezing() {
            return Err(SuspendableError::InvalidData);
        }
        let mut r = Cursor::new(rest);
        let customized = match r.u8() {
            0 => false,
            1 => true,
            _ => return Err(SuspendableError::InvalidData),
        };
        debug_assert!(r.is_done());
        Ok(Self { shake, customized })
    }

    /// [`Self::read_tagged`] for the functions built on cSHAKE, whose `N` is never empty: a state
    /// claiming otherwise is not one they wrote.
    pub(crate) fn read_tagged_customized(state: &[u8], tag: u8) -> Result<Self, SuspendableError> {
        let cshake = Self::read_tagged(state, tag)?;
        if !cshake.customized {
            return Err(SuspendableError::InvalidData);
        }
        Ok(cshake)
    }
}

impl<PARAMS: SHAKEParams> SuspendableComponent for CSHAKEInternal<PARAMS> {
    const STATE_LEN: usize = CSHAKE_COMPONENT_LEN;
    type Key = ();

    fn write_state(&self, out: &mut [u8]) {
        self.write_tagged(PARAMS::CSHAKE_STATE_TAG, out)
    }

    fn read_state(state: &[u8], _key: &()) -> Result<Self, SuspendableError> {
        Self::read_tagged(state, PARAMS::CSHAKE_STATE_TAG)
    }
}

/// The absorbing phase. Once output begins the sponge is a [`SHAKESqueezer`] -- the domain suffix
/// is in, and nothing cSHAKE-specific remains -- so it suspends and resumes as one.
impl<PARAMS: SHAKEParams> Suspendable<SUSPENDED_CSHAKE_STATE_LEN> for CSHAKEInternal<PARAMS> {
    fn suspend(self) -> [u8; SUSPENDED_CSHAKE_STATE_LEN] {
        suspend_component(&self)
    }

    fn from_suspended(state: [u8; SUSPENDED_CSHAKE_STATE_LEN]) -> Result<Self, SuspendableError> {
        resume_component(&state, &())
    }
}

impl<PARAMS: SHAKEParams> Default for CSHAKEInternal<PARAMS> {
    /// An uncustomized cSHAKE, which by Sec 3.3 step 1 is plain SHAKE.
    fn default() -> Self {
        Self::new(&[], &[])
    }
}

impl<PARAMS: SHAKEParams> Hash for CSHAKEInternal<PARAMS> {
    fn block_bitlen(&self) -> usize {
        self.shake.block_bitlen()
    }

    fn output_len(&self) -> usize {
        self.shake.output_len()
    }

    fn hash(mut self, data: &[u8]) -> Vec<u8> {
        self.do_update(data);
        self.do_final()
    }

    fn hash_out(mut self, data: &[u8], output: &mut [u8]) -> usize {
        self.do_update(data);
        self.do_final_out(output)
    }

    fn do_update(&mut self, data: &[u8]) {
        self.shake.do_update(data);
    }

    /// A final read at the nominal length: [`Hash::output_len`] bytes, 32 for cSHAKE128 and 64 for
    /// cSHAKE256, twice the security strength.
    ///
    /// Like SHAKE and unlike the SP 800-185 functions built on it, cSHAKE has no length to bind --
    /// `L` reaches it as "how much to read", not as absorbed input (Sec 3.3) -- so these are the
    /// same bytes the squeezer produces. What the `Hash` view fixes is how many.
    fn do_final(self) -> Vec<u8> {
        let n = self.output_len();
        self.into_squeezer().do_output_final(n)
    }

    fn do_final_out(self, output: &mut [u8]) -> usize {
        let n = self.output_len();
        // Per Hash::do_final_out: a short buffer is filled and the output truncated, a long one
        // takes it in its first output_len bytes and zeros after. To fill a longer buffer, use the
        // XOF spelling, which takes its length from the buffer.
        let written = n.min(output.len());
        output[written..].fill(0);
        self.into_squeezer().do_output_final_out(&mut output[..written])
    }

    fn do_final_partial_bits(
        self,
        partial_byte: u8,
        num_bits: usize,
    ) -> Result<Vec<u8>, HashError> {
        let mut out = vec![0u8; self.output_len()];
        self.do_final_partial_bits_out(partial_byte, num_bits, &mut out)?;
        Ok(out)
    }

    fn do_final_partial_bits_out(
        self,
        partial_byte: u8,
        num_bits: usize,
        output: &mut [u8],
    ) -> Result<usize, HashError> {
        let n = self.output_len();
        // Validated before anything is written, so a rejected call leaves `output` untouched.
        let squeezer = self.into_squeezer_partial_bits(partial_byte, num_bits)?;
        // The buffer rule of do_final_out applies here too: output_len bytes, then zeros.
        let written = n.min(output.len());
        output[written..].fill(0);
        Ok(squeezer.do_output_final_out(&mut output[..written]))
    }

    fn max_security_strength(&self) -> SecurityStrength {
        Hash::max_security_strength(&self.shake)
    }
}

impl<PARAMS: SHAKEParams> XOF for CSHAKEInternal<PARAMS> {
    type Squeezer = SHAKESqueezer<PARAMS>;

    fn into_squeezer(self) -> Self::Squeezer {
        if self.customized {
            let (suffix, bits) = CSHAKE_SUFFIX;
            self.shake.into_squeezer_with_suffix(suffix, bits)
        } else {
            // Sec 3.3 step 1: with no N and no S this is SHAKE, separator included.
            self.shake.into_squeezer()
        }
    }

    fn into_squeezer_partial_bits(
        self,
        partial_byte: u8,
        num_bits: usize,
    ) -> Result<Self::Squeezer, HashError> {
        if self.customized {
            let (suffix, bits) = CSHAKE_SUFFIX;
            self.shake.into_squeezer_partial_bits_with_suffix(partial_byte, num_bits, suffix, bits)
        } else {
            self.shake.into_squeezer_partial_bits(partial_byte, num_bits)
        }
    }
}

/*** cshake helpers ***/
/// The widest encoding these functions produce: a length byte plus up to eight value bytes.
///
/// SP 800-185 Sec 2.3.1 permits integers up to `2^2040 - 1`, which would need 255 value bytes. A
/// `u64` covers every length this library can be handed -- an input of `2^64` bits is 2 exabytes --
/// so the buffer is sized for that rather than for the spec's theoretical maximum.
pub(crate) const MAX_ENCODED_LEN: usize = 9;

/// `left_encode(x)`: SP 800-185 Sec 2.3.1.
///
/// Encodes `value` so that it can be parsed unambiguously *from the beginning*: the number of
/// value bytes comes first, then the value itself, big-endian. Returns the buffer and how much of
/// it is used.
///
/// The spec's example: `left_encode(0)` is `10000000 00000000`, which in this document's
/// low-order-bit-first notation is the bytes `01 00`.
pub(crate) fn left_encode(value: u64) -> ([u8; MAX_ENCODED_LEN], usize) {
    let mut buf = [0u8; MAX_ENCODED_LEN];
    // Step 1: n is the smallest positive integer with 2^(8n) > value. Zero still takes one byte,
    // which is why the count starts at 1 rather than 0.
    let n = value_bytes(value);
    buf[0] = n as u8;
    // Steps 2-4: the base-256 digits of value, most significant first.
    for i in 0..n {
        buf[1 + i] = (value >> (8 * (n - 1 - i))) as u8;
    }
    (buf, n + 1)
}

/// `right_encode(x)`: SP 800-185 Sec 2.3.1.
///
/// Unused until KMAC and TupleHash land, which bind the requested output length with it.
///
/// As [`left_encode`], but the length byte comes *last*, so the encoding can be parsed from the end
/// of a string. The spec's example: `right_encode(0)` is the bytes `00 01`.
#[allow(dead_code)] // used by KMAC and TupleHash
pub(crate) fn right_encode(value: u64) -> ([u8; MAX_ENCODED_LEN], usize) {
    let mut buf = [0u8; MAX_ENCODED_LEN];
    let n = value_bytes(value);
    for i in 0..n {
        buf[i] = (value >> (8 * (n - 1 - i))) as u8;
    }
    buf[n] = n as u8;
    (buf, n + 1)
}

/// The number of base-256 digits in `value`: the spec's `n`, the smallest positive integer with
/// `2^(8n) > value`. Positive, so zero encodes as one byte.
fn value_bytes(value: u64) -> usize {
    let mut n = 1;
    let mut v = value;
    while {
        v >>= 8;
        v != 0
    } {
        n += 1;
    }
    n
}

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
/// * [`XOFSqueezer::do_output_final`], as the **first** read, is the fixed-length reading. It is
///   the caller saying how many bytes it wants and that it will not be back, so `L` is that length
///   in bits and the result is the fixed-length function of s. 4.3, 5.3 or 6.3 -- the same bytes
///   `KMAC128(K, X, L, S)` produces, not a truncation of `KMACXOF128`.
///
/// The first read commits: the encoding is in the sponge from then on, so a `do_final` that
/// follows a `do_output` cannot bind anything and simply continues the `right_encode(0)` stream
/// the earlier read already chose.
#[derive(Clone)]
pub struct LengthBoundSqueezer<PARAMS: SHAKEParams> {
    phase: Phase<PARAMS>,
}

/// Which side of the first read this squeezer is on.
#[derive(Clone)]
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

    /// [`XOFSqueezer::do_output_final_out`] with `L` given rather than taken from the buffer.
    ///
    /// For the `Hash` view of these functions, whose length is fixed by the type: it binds the
    /// nominal output length and then writes as much of it as the caller's buffer has room for,
    /// which is what [`Hash::do_final_out`] promises. Going through
    /// [`XOFSqueezer::do_output_final_out`] would bind the buffer's length instead, and a short
    /// buffer would then compute a different function rather than truncating this one.
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

/// Both phases suspend. The sponge's own phase flag records which, so the state is the cSHAKE
/// layout under one tag, and a resumed `Unbound` squeezer still has its first read to make.
impl<PARAMS: SHAKEParams> SuspendableComponent for LengthBoundSqueezer<PARAMS> {
    const STATE_LEN: usize = CSHAKE_COMPONENT_LEN;
    type Key = ();

    fn write_state(&self, out: &mut [u8]) {
        let tag = PARAMS::LENGTH_BOUND_SQUEEZER_STATE_TAG;
        match &self.phase {
            Phase::Unbound(cshake) => cshake.write_tagged(tag, out),
            Phase::Squeezing(squeezer) => {
                let (family, rest) = out.split_at_mut(SHA3_FAMILY_STATE_LEN);
                squeezer.write_family_state(tag, family);
                // Every function that reaches this squeezer has a non-empty N.
                let mut w = CursorMut::new(rest);
                w.u8(1);
                debug_assert!(w.is_done());
            }
            Phase::Binding => unreachable!("Binding is never live outside `read`"),
        }
    }

    fn read_state(state: &[u8], _key: &()) -> Result<Self, SuspendableError> {
        let (family, rest) = state.split_at(SHA3_FAMILY_STATE_LEN);
        let shake = SHAKEInternal::<PARAMS>::read_family_state(
            family,
            PARAMS::LENGTH_BOUND_SQUEEZER_STATE_TAG,
        )?;
        let mut r = Cursor::new(rest);
        if r.u8() != 1 {
            return Err(SuspendableError::InvalidData);
        }
        debug_assert!(r.is_done());
        let phase = if shake.is_squeezing() {
            Phase::Squeezing(SHAKESqueezer::from_squeezing(shake))
        } else {
            Phase::Unbound(CSHAKEInternal { shake, customized: true })
        };
        Ok(Self { phase })
    }
}

impl<PARAMS: SHAKEParams> Suspendable<SUSPENDED_LENGTH_BOUND_SQUEEZER_STATE_LEN>
    for LengthBoundSqueezer<PARAMS>
{
    fn suspend(self) -> [u8; SUSPENDED_LENGTH_BOUND_SQUEEZER_STATE_LEN] {
        suspend_component(&self)
    }

    fn from_suspended(
        state: [u8; SUSPENDED_LENGTH_BOUND_SQUEEZER_STATE_LEN],
    ) -> Result<Self, SuspendableError> {
        resume_component(&state, &())
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

    fn do_output_final(self, num_bytes: usize) -> Vec<u8> {
        let mut out = vec![0u8; num_bytes];
        self.do_output_final_out(&mut out);
        out
    }

    /// The last read, so if it is also the first, `L` is its length in bits and this is the
    /// fixed-length function of s. 4.3, 5.3 or 6.3. After a [`XOFSqueezer::do_output`] the encoding
    /// is already in the sponge and this just continues that stream.
    fn do_output_final_out(mut self, output: &mut [u8]) -> usize {
        self.read((output.len() as u64) * 8, output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two worked examples in SP 800-185 Sec 2.3.1, in the byte spelling of Sec 2
    /// ("bytes are written with the low-order bit first" in binary, high-order digit first in hex).
    #[test]
    fn spec_examples() {
        let (b, n) = right_encode(0);
        assert_eq!(&b[..n], &[0x00, 0x01], "right_encode(0) = 00000000 10000000");

        let (b, n) = left_encode(0);
        assert_eq!(&b[..n], &[0x01, 0x00], "left_encode(0) = 10000000 00000000");
    }

    /// The encodings that appear in the NIST cSHAKE sample file: `left_encode(168)` opens the
    /// bytepad block, and `left_encode(120)` prefixes the 15-character "Email Signature".
    #[test]
    fn cshake_sample_encodings() {
        let (b, n) = left_encode(168);
        assert_eq!(&b[..n], &[0x01, 0xA8], "left_encode(168), the cSHAKE128 rate");

        let (b, n) = left_encode(120);
        assert_eq!(&b[..n], &[0x01, 0x78], "left_encode(15 * 8), for \"Email Signature\"");
    }

    /// The length byte grows with the value, and the value is big-endian after it.
    #[test]
    fn multi_byte_values() {
        let (b, n) = left_encode(0x0100);
        assert_eq!(&b[..n], &[0x02, 0x01, 0x00]);
        let (b, n) = right_encode(0x0100);
        assert_eq!(&b[..n], &[0x01, 0x00, 0x02]);

        let (b, n) = left_encode(u64::MAX);
        assert_eq!(&b[..n], &[0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        let (b, n) = right_encode(u64::MAX);
        assert_eq!(&b[..n], &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x08]);
    }

    /// Every boundary where the number of value bytes increases.
    #[test]
    fn byte_count_boundaries() {
        for n in 1..=8u32 {
            let just_under = if n == 8 { u64::MAX } else { (1u64 << (8 * n)) - 1 };
            assert_eq!(left_encode(just_under).1, n as usize + 1, "2^{} - 1", 8 * n);
            assert_eq!(right_encode(just_under).1, n as usize + 1, "2^{} - 1", 8 * n);
            if n < 8 {
                assert_eq!(left_encode(1u64 << (8 * n)).1, n as usize + 2, "2^{}", 8 * n);
            }
        }
    }
}
