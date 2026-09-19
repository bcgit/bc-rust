//! cSHAKE, the customizable SHAKE of NIST SP 800-185 Sec 3.

use crate::SHAKEParams;
use crate::shake::{SHAKEInternal, SHAKESqueezer};
use crate::xof_utils::left_encode;
use bouncycastle_core::errors::HashError;
use bouncycastle_core::traits::{Algorithm, Hash, SecurityStrength, XOF, XOFSqueezer};

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
        self.into_squeezer().do_final(n)
    }

    fn do_final_out(self, output: &mut [u8]) -> usize {
        let n = self.output_len();
        // Per Hash::do_final_out: a short buffer is filled and the output truncated, a long one
        // takes it in its first output_len bytes and zeros after. To fill a longer buffer, use the
        // XOF spelling, which takes its length from the buffer.
        let written = n.min(output.len());
        output[written..].fill(0);
        self.into_squeezer().do_final_out(&mut output[..written])
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
        Ok(squeezer.do_final_out(&mut output[..written]))
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
