//! Ascon-CXOF128 customized extendable-output function (NIST SP 800-232 §5.3).
//!
//! A variant of Ascon-XOF128 that first absorbs a user-supplied customization string `Z`
//! (length-prefixed per SP 800-232 Alg. 7) to provide domain separation. Same sponge parameters as
//! Ascon-XOF128 (rate = 64 bits, capacity = 256 bits, `Ascon-p[12]`).
//!
//! Input absorption and output squeezing are represented by separate Rust types:
//! [`AsconCXof128`] accepts input, while [`AsconCXof128Squeezer`] produces the
//! extendable output stream.

use bouncycastle_core::errors::{HashError, SuspendableError};
use bouncycastle_core::suspendable_state::{add_lib_ver, check_lib_ver};
use bouncycastle_core::traits::{Algorithm, Hash, SecurityStrength, Suspendable, XOF, XOFSqueezer};
use bouncycastle_utils::secret::Secret;

use crate::sponge::{RATE, Sponge};

/// Maximum customization-string length in bytes (2048 bits, per SP 800-232 §5.3).
const MAX_CUSTOMIZATION_BYTES: usize = 256;

/// Nominal hash-view output length for Ascon-CXOF128.
///
/// XOFs do not have an inherent output length. The [`Hash`] view therefore uses
/// twice the 128-bit security strength, matching the convention used for SHAKE128.
const NOMINAL_OUTPUT_LEN: usize = 32;

/// Ascon-CXOF128 customized extendable-output function (NIST SP 800-232 §5.3).
#[derive(Clone)]
pub struct AsconCXof128 {
    sponge: Sponge,
}

impl AsconCXof128 {
    /// Create a new Ascon-CXOF128 instance with no customization string.
    pub fn new() -> Self {
        // Precomputed state after initializing and then absorbing an empty customization string
        // (SP 800-232 Algorithm 7 with |Z| = 0): starting from the Table 12 CXOF128 initialization
        // state, XOR the length word Z_0 = int64(0) into S[0..63], Ascon-p[12], then XOR the
        // pad-only last customization block (Eq. 77: pad(empty, 64) = 0x01 || 0^63) into S[0..63]
        // and Ascon-p[12] again. Recomputed from those raw Table 12 words and pinned by
        // `permutation::tests::cxof128_empty_customization_state_matches_algorithm_7`.
        let mut sponge = Sponge::from_state([
            0x500CCCC894E3C9E8, 0x5BED06F28F71248D, 0x3B03A0F930AFD512, 0x112EF093AA5C698B,
            0x00C8356340A347F0,
        ]);
        sponge.reset_buffer();

        Self { sponge }
    }

    /// Create a new Ascon-CXOF128 instance with the given customization string `z`.
    ///
    /// Returns [`HashError::InvalidInput`] if `z` is longer than 256 bytes (2048 bits, the bound
    /// required by SP 800-232 §5.3).
    pub fn with_customization(z: &[u8]) -> Result<Self, HashError> {
        if z.len() > MAX_CUSTOMIZATION_BYTES {
            return Err(HashError::InvalidInput(
                "Ascon-CXOF128 customization string exceeds 256 bytes",
            ));
        }

        if z.is_empty() {
            return Ok(Self::new());
        }

        // Precomputed state after the initialization permutation (SP 800-232 Table 12).
        let mut sponge = Sponge::from_state([
            0x675527C2A0E8DE03, 0x43D12D7DC0377BBC, 0xE9901DEC426E81B5, 0x2AB14907720780B6,
            0x8F3F1D02D432BC46,
        ]);

        // Z0 = int64(|Z|) in bits, then absorb the parsed/padded customization blocks
        // (SP 800-232 §5.3 Eq. 75-78 / Algorithm 7, "Customization" loop).
        let bit_length = (z.len() as u64) << 3;
        sponge.xor_word0(bit_length);
        sponge.permute();
        sponge.absorb(z);
        sponge.pad_and_absorb();
        sponge.permute();

        // Customization is complete; reset the buffer to begin the message-absorb phase.
        sponge.reset_buffer();

        Ok(Self { sponge })
    }

    /// Produces `output.len()` bytes from the XOF stream.
    ///
    /// The first call ends the message-absorb phase by padding and absorbing the
    /// final message block. Subsequent calls continue the same output stream.
    fn squeeze_into(&mut self, output: &mut [u8]) -> usize {
        output.fill(0);

        if !self.sponge.squeezing() {
            self.sponge.pad_and_absorb();
        }

        self.sponge.squeeze(output);
        output.len()
    }
}

impl Default for AsconCXof128 {
    fn default() -> Self {
        Self::new()
    }
}

impl Algorithm for AsconCXof128 {
    const ALG_NAME: &'static str = "Ascon-CXOF128";
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

/// The output-producing half of [`AsconCXof128`].
///
/// Calling [`XOF::into_squeezer`] consumes the absorbing `AsconCXof128`, so once
/// output begins there is no longer an object on which [`Hash::do_update`] can
/// be called.
#[derive(Clone)]
pub struct AsconCXof128Squeezer {
    xof: AsconCXof128,
}

impl XOFSqueezer for AsconCXof128Squeezer {
    fn do_output(&mut self, num_bytes: usize) -> Vec<u8> {
        let mut out = vec![0u8; num_bytes];
        self.do_output_out(&mut out);
        out
    }

    fn do_output_out(&mut self, output: &mut [u8]) -> usize {
        self.xof.squeeze_into(output)
    }
}

impl Hash for AsconCXof128 {
    /// Ascon-CXOF128 absorbs at a rate of 64 bits.
    fn block_bitlen(&self) -> usize {
        RATE * 8
    }

    /// Nominal digest size used when Ascon-CXOF128 is viewed through [`Hash`].
    fn output_len(&self) -> usize {
        NOMINAL_OUTPUT_LEN
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
        // A caller-visible AsconCXof128 is always in the absorbing phase:
        // into_squeezer() consumes it before output can begin.
        debug_assert!(
            !self.sponge.squeezing(),
            "a reachable AsconCXof128 must not already be squeezing"
        );

        self.sponge.absorb(data);
    }

    fn do_final(self) -> Vec<u8> {
        let output_len = self.output_len();
        self.into_squeezer().do_final(output_len)
    }

    fn do_final_out(self, output: &mut [u8]) -> usize {
        let output_len = self.output_len();
        let written = output_len.min(output.len());

        // Hash::do_final_out requires bytes beyond output_len to be zero.
        output[written..].fill(0);

        self.into_squeezer().do_final_out(&mut output[..written])
    }

    fn do_final_partial_bits(
        self,
        partial_byte: u8,
        num_bits: usize,
    ) -> Result<Vec<u8>, HashError> {
        if num_bits > 7 {
            return Err(HashError::InvalidLength("num_bits must be in the range [0,7]"));
        }

        if num_bits != 0 {
            return Err(HashError::InvalidInput(
                "Ascon-CXOF128 does not support partial byte input",
            ));
        }

        // A zero-bit partial byte means the message is byte-aligned.
        let _ = partial_byte;
        Ok(self.do_final())
    }

    fn do_final_partial_bits_out(
        self,
        partial_byte: u8,
        num_bits: usize,
        output: &mut [u8],
    ) -> Result<usize, HashError> {
        if num_bits > 7 {
            return Err(HashError::InvalidLength("num_bits must be in the range [0,7]"));
        }

        if num_bits != 0 {
            return Err(HashError::InvalidInput(
                "Ascon-CXOF128 does not support partial byte input",
            ));
        }

        // A zero-bit partial byte means the message is byte-aligned.
        let _ = partial_byte;
        Ok(self.do_final_out(output))
    }

    fn max_security_strength(&self) -> SecurityStrength {
        SecurityStrength::_128bit
    }
}

impl XOF for AsconCXof128 {
    type Squeezer = AsconCXof128Squeezer;

    fn into_squeezer(self) -> Self::Squeezer {
        AsconCXof128Squeezer { xof: self }
    }

    fn into_squeezer_partial_bits(
        self,
        partial_byte: u8,
        num_bits: usize,
    ) -> Result<Self::Squeezer, HashError> {
        if num_bits > 7 {
            return Err(HashError::InvalidLength("num_bits must be in the range [0,7]"));
        }

        if num_bits != 0 {
            return Err(HashError::InvalidInput(
                "Ascon-CXOF128 does not support partial byte input",
            ));
        }

        // Per the XOF trait contract, zero partial bits is exactly the
        // byte-aligned into_squeezer() operation.
        let _ = partial_byte;
        Ok(self.into_squeezer())
    }
}

/// Length in bytes of the serialized Ascon-CXOF128 state.
///
/// Layout:
///
/// - 3-byte library version
/// - 1-byte state tag
/// - 40-byte sponge state (`5 × u64`, little endian)
/// - 8-byte rate buffer
/// - 1-byte buffer position
/// - 1-byte squeezing flag
///
/// The customization string is already absorbed during construction, so it
/// does not need to be stored separately in the suspended representation.
pub const SUSPENDED_ASCON_CXOF128_STATE_LEN: usize = 54;

/// Distinguishes an Ascon-CXOF128 serialized state from other Ascon sponge states.
const CXOF128_STATE_TAG: u8 = 0x03;

/// Deserialize the common sponge representation used by both the absorbing
/// [`AsconCXof128`] and squeezing [`AsconCXof128Squeezer`] forms.
fn deserialize_sponge(
    serialized_state: [u8; SUSPENDED_ASCON_CXOF128_STATE_LEN],
) -> Result<Sponge, SuspendableError> {
    // Infallible: check_lib_ver returns exactly 51 bytes after removing
    // the three-byte library-version prefix.
    let input: &[u8; SUSPENDED_ASCON_CXOF128_STATE_LEN - 3] =
        check_lib_ver(&serialized_state, None)?.try_into().unwrap();

    if input[0] != CXOF128_STATE_TAG {
        return Err(SuspendableError::InvalidData);
    }

    let mut state = Secret::<[u64; 5]>::new();

    for i in 0..5 {
        // Each selected slice is exactly eight bytes.
        state[i] = u64::from_le_bytes(input[1 + i * 8..1 + i * 8 + 8].try_into().unwrap());
    }

    let mut buf = Secret::<[u8; RATE]>::new();
    buf.copy_from_slice(&input[41..49]);

    let buf_pos = input[49] as usize;

    let squeezing = match input[50] {
        0 => false,
        1 => true,
        _ => return Err(SuspendableError::InvalidData),
    };

    // While absorbing, a full rate buffer is drained immediately, so the
    // position must be strictly less than RATE. During squeezing, RATE is
    // allowed to represent "no buffered squeezed byte remains".
    let valid_pos = if squeezing { buf_pos <= RATE } else { buf_pos < RATE };

    if !valid_pos {
        return Err(SuspendableError::InvalidData);
    }

    Ok(Sponge::from_parts(state, buf, buf_pos, squeezing))
}

/// Serialize the common sponge representation.
fn serialize_sponge(sponge: &Sponge) -> [u8; SUSPENDED_ASCON_CXOF128_STATE_LEN] {
    let mut out_to_return = [0u8; SUSPENDED_ASCON_CXOF128_STATE_LEN];

    // Infallible: add_lib_ver returns exactly 51 bytes.
    let out: &mut [u8; SUSPENDED_ASCON_CXOF128_STATE_LEN - 3] =
        add_lib_ver(&mut out_to_return).try_into().unwrap();

    out[0] = CXOF128_STATE_TAG;

    let state = sponge.state_words();
    for i in 0..5 {
        out[1 + i * 8..1 + i * 8 + 8].copy_from_slice(&state[i].to_le_bytes());
    }

    out[41..49].copy_from_slice(&sponge.buf_bytes());

    debug_assert!(sponge.buf_pos() <= RATE);
    out[49] = sponge.buf_pos() as u8;
    out[50] = sponge.squeezing() as u8;

    out_to_return
}

impl Suspendable<SUSPENDED_ASCON_CXOF128_STATE_LEN> for AsconCXof128 {
    fn suspend(self) -> [u8; SUSPENDED_ASCON_CXOF128_STATE_LEN] {
        serialize_sponge(&self.sponge)
    }

    fn from_suspended(
        serialized_state: [u8; SUSPENDED_ASCON_CXOF128_STATE_LEN],
    ) -> Result<Self, SuspendableError> {
        let sponge = deserialize_sponge(serialized_state)?;

        // The absorbing type must never contain a state that has already
        // transitioned into squeezing. Such states belong to the squeezer.
        if sponge.squeezing() {
            return Err(SuspendableError::InvalidData);
        }

        Ok(Self { sponge })
    }
}

impl Suspendable<SUSPENDED_ASCON_CXOF128_STATE_LEN> for AsconCXof128Squeezer {
    fn suspend(self) -> [u8; SUSPENDED_ASCON_CXOF128_STATE_LEN] {
        serialize_sponge(&self.xof.sponge)
    }

    fn from_suspended(
        serialized_state: [u8; SUSPENDED_ASCON_CXOF128_STATE_LEN],
    ) -> Result<Self, SuspendableError> {
        let sponge = deserialize_sponge(serialized_state)?;

        // The squeezer is only valid after the phase transition has happened.
        if !sponge.squeezing() {
            return Err(SuspendableError::InvalidData);
        }

        Ok(Self { xof: AsconCXof128 { sponge } })
    }
}
