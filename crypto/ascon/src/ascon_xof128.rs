//! Ascon-XOF128 extendable-output function (NIST SP 800-232 §5.2).
//!
//! Sponge mode over `Ascon-p[12]` with rate = 64 bits and capacity = 256 bits.
//! Input absorption and output squeezing are represented by separate Rust types:
//! [`AsconXof128`] accepts input, while [`AsconXof128Squeezer`] produces the
//! extendable output stream.

use bouncycastle_core::errors::{HashError, SuspendableError};
use bouncycastle_core::suspendable_state::{add_lib_ver, check_lib_ver};
use bouncycastle_core::traits::{Algorithm, Hash, SecurityStrength, Suspendable, XOF, XOFSqueezer};
use bouncycastle_utils::secret::Secret;

use crate::sponge::{RATE, Sponge};

/// Nominal hash-view output length for Ascon-XOF128.
///
/// XOFs do not have an inherent output length. The [`Hash`] view therefore uses
/// twice the 128-bit security strength, matching the convention used for SHAKE128.
const NOMINAL_OUTPUT_LEN: usize = 32;

/// Ascon-XOF128 as specified in NIST SP 800-232.
#[derive(Clone)]
pub struct AsconXof128 {
    sponge: Sponge,
}

impl AsconXof128 {
    /// Creates a new Ascon-XOF128 instance.
    pub fn new() -> Self {
        // Precomputed state after the initialization permutation
        // (SP 800-232 Table 12).
        Self {
            sponge: Sponge::from_state([
                0xDA82CE768D9447EB, 0xCC7CE6C75F1EF969, 0xE7508FD780085631, 0x0EE0EA53416B58CC,
                0xE0547524DB6F0BDE,
            ]),
        }
    }

    /// Produces `output.len()` bytes from the XOF stream.
    ///
    /// The first call ends the absorb phase by padding and absorbing the final
    /// message block. Subsequent calls continue the same output stream.
    fn squeeze_into(&mut self, output: &mut [u8]) -> usize {
        output.fill(0);

        if !self.sponge.squeezing() {
            self.sponge.pad_and_absorb();
        }

        self.sponge.squeeze(output);
        output.len()
    }
}

impl Default for AsconXof128 {
    fn default() -> Self {
        Self::new()
    }
}

impl Algorithm for AsconXof128 {
    const ALG_NAME: &'static str = "Ascon-XOF128";
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

/// The output-producing half of [`AsconXof128`].
///
/// Calling [`XOF::into_squeezer`] consumes the absorbing `AsconXof128`, so once
/// output begins there is no longer an object on which [`Hash::do_update`] can
/// be called.
#[derive(Clone)]
pub struct AsconXof128Squeezer {
    xof: AsconXof128,
}

impl XOFSqueezer for AsconXof128Squeezer {
    fn do_output(&mut self, num_bytes: usize) -> Vec<u8> {
        let mut out = vec![0u8; num_bytes];
        self.do_output_out(&mut out);
        out
    }

    fn do_output_out(&mut self, output: &mut [u8]) -> usize {
        self.xof.squeeze_into(output)
    }
}

impl Hash for AsconXof128 {
    /// Ascon-XOF128 absorbs at a rate of 64 bits.
    fn block_bitlen(&self) -> usize {
        RATE * 8
    }

    /// Nominal digest size used when Ascon-XOF128 is viewed through [`Hash`].
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
        // A caller-visible AsconXof128 is always in the absorbing phase:
        // into_squeezer() consumes it before output can begin.
        debug_assert!(
            !self.sponge.squeezing(),
            "a reachable AsconXof128 must not already be squeezing"
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
                "Ascon-XOF128 does not support partial byte input",
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
                "Ascon-XOF128 does not support partial byte input",
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

impl XOF for AsconXof128 {
    type Squeezer = AsconXof128Squeezer;

    fn into_squeezer(self) -> Self::Squeezer {
        AsconXof128Squeezer { xof: self }
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
                "Ascon-XOF128 does not support partial byte input",
            ));
        }

        // Per the XOF trait contract, zero partial bits is exactly the
        // byte-aligned into_squeezer() operation.
        let _ = partial_byte;
        Ok(self.into_squeezer())
    }
}

/// Length in bytes of the serialized Ascon-XOF128 state.
///
/// Layout:
///
/// - 3-byte library version
/// - 1-byte state tag
/// - 40-byte sponge state (`5 × u64`, little endian)
/// - 8-byte rate buffer
/// - 1-byte buffer position
/// - 1-byte squeezing flag
pub const SUSPENDED_ASCON_XOF128_STATE_LEN: usize = 54;

/// Distinguishes an Ascon-XOF128 serialized state from other Ascon sponge states.
const XOF128_STATE_TAG: u8 = 0x02;

/// Deserialize the common sponge representation used by both the absorbing
/// [`AsconXof128`] and squeezing [`AsconXof128Squeezer`] forms.
fn deserialize_sponge(
    serialized_state: [u8; SUSPENDED_ASCON_XOF128_STATE_LEN],
) -> Result<Sponge, SuspendableError> {
    // Infallible: check_lib_ver returns exactly 51 bytes after removing
    // the three-byte library-version prefix.
    let input: &[u8; SUSPENDED_ASCON_XOF128_STATE_LEN - 3] =
        check_lib_ver(&serialized_state, None)?.try_into().unwrap();

    if input[0] != XOF128_STATE_TAG {
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
fn serialize_sponge(sponge: &Sponge) -> [u8; SUSPENDED_ASCON_XOF128_STATE_LEN] {
    let mut out_to_return = [0u8; SUSPENDED_ASCON_XOF128_STATE_LEN];

    // Infallible: add_lib_ver returns exactly 51 bytes.
    let out: &mut [u8; SUSPENDED_ASCON_XOF128_STATE_LEN - 3] =
        add_lib_ver(&mut out_to_return).try_into().unwrap();

    out[0] = XOF128_STATE_TAG;

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

impl Suspendable<SUSPENDED_ASCON_XOF128_STATE_LEN> for AsconXof128 {
    fn suspend(self) -> [u8; SUSPENDED_ASCON_XOF128_STATE_LEN] {
        serialize_sponge(&self.sponge)
    }

    fn from_suspended(
        serialized_state: [u8; SUSPENDED_ASCON_XOF128_STATE_LEN],
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

impl Suspendable<SUSPENDED_ASCON_XOF128_STATE_LEN> for AsconXof128Squeezer {
    fn suspend(self) -> [u8; SUSPENDED_ASCON_XOF128_STATE_LEN] {
        serialize_sponge(&self.xof.sponge)
    }

    fn from_suspended(
        serialized_state: [u8; SUSPENDED_ASCON_XOF128_STATE_LEN],
    ) -> Result<Self, SuspendableError> {
        let sponge = deserialize_sponge(serialized_state)?;

        // The squeezer is only valid after the phase transition has happened.
        if !sponge.squeezing() {
            return Err(SuspendableError::InvalidData);
        }

        Ok(Self { xof: AsconXof128 { sponge } })
    }
}
