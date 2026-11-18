//! The KDF in Counter Mode, SP 800-108r1 Section 4.1.

use crate::prf::{MAX_PRF_OUTPUT_LEN, Prf};
use crate::{CounterSize, label_output};
use bouncycastle_core::errors::KDFError;
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::kdf_params::KdfDescription;
use bouncycastle_core::key_material::KeyMaterialTrait;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, KDF};
use bouncycastle_utils::const_str::ConstStr;
use bouncycastle_utils::min;
use bouncycastle_utils::secret::Secret;
use core::marker::PhantomData;

/// Where the counter `[i]2` goes in each PRF input of the counter mode, relative to the fixed
/// input data. Section 4.1 writes it first; Section 4 allows that "Alternative orders for the
/// input data fields may be used for different KDFs".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CounterPosition {
    /// `[i]2 || fixed input data`: the order Section 4.1 writes.
    BeforeFixedInput,
    /// `fixed input data || [i]2`.
    AfterFixedInput,
    /// The counter after this many bytes of the fixed input data, and the rest after it.
    InFixedInput(usize),
}

/// The KDF in Counter Mode (SP 800-108r1 Section 4.1) over the PRF `P`:
/// `K(i) = PRF(K_IN, [i]2 || fixed input data)` for `i = 1, 2, ...`, and the keying material
/// the leftmost `L` bits of `K(1) || K(2) || ...`.
///
/// The key-derivation key `K_IN` is the [`KDF`] methods' input key, and their `fixed_info` is
/// the whole fixed input data, laid out as the protocol in use defines it;
/// [`fixed_input_out`](crate::fixed_input_out) writes Section 4's `Label || 0x00 || Context ||
/// [L]2`. An instance holds only the counter's size and position, and whether Section 4.1's
/// guard against key control is applied.
#[allow(non_camel_case_types)]
pub struct KDF_Counter<P: Prf> {
    r: CounterSize,
    position: CounterPosition,
    key_control_guard: bool,
    _prf: PhantomData<P>,
}

// Written out rather than derived: a derive would demand `P: Clone` of the PRF marker.
impl<P: Prf> Clone for KDF_Counter<P> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<P: Prf> Copy for KDF_Counter<P> {}

impl<P: Prf> Default for KDF_Counter<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: Prf> Algorithm for KDF_Counter<P> {
    const ALG_NAME: &'static str = Self::NAME.as_str();
    const MAX_SECURITY_STRENGTH: SecurityStrength = P::MAX_SECURITY_STRENGTH;
}

/// Every parameter is a readable field ([`KDF_Counter::r`], [`KDF_Counter::position`],
/// [`KDF_Counter::key_control_guard`]), so the KDF describes itself: the engine is a copy.
impl<P: Prf> KdfDescription for KDF_Counter<P> {
    type Engine = Self;

    fn engine(&self) -> Result<Self, KDFError> {
        Ok(*self)
    }
}

impl<P: Prf> KDF_Counter<P> {
    const NAME: ConstStr<48> = ConstStr::concat(&["KDF-Counter-", P::NAME]);

    /// The counter mode as Section 4.1 writes it, with a 32-bit counter before the fixed input
    /// data.
    pub fn new() -> Self {
        Self::with_counter(CounterSize::_32bit, CounterPosition::BeforeFixedInput)
    }

    /// The counter mode with a counter of `r` bits at `position`.
    pub fn with_counter(r: CounterSize, position: CounterPosition) -> Self {
        Self { r, position, key_control_guard: false, _prf: PhantomData }
    }

    /// This KDF with Section 4.1's guard against key control: the fixed input data of every
    /// iteration is followed by `K(0) = PRF(K_IN, fixed input data)`. Both parties must apply
    /// it; see the crate's Security Considerations for when it matters.
    pub fn with_key_control_guard(mut self) -> Self {
        self.key_control_guard = true;
        self
    }

    /// `r`, the size of the counter.
    pub fn r(&self) -> CounterSize {
        self.r
    }

    /// Where the counter goes.
    pub fn position(&self) -> CounterPosition {
        self.position
    }

    /// Whether Section 4.1's guard against key control is applied.
    pub fn key_control_guard(&self) -> bool {
        self.key_control_guard
    }

    /// The most bytes one derivation produces: `n` PRF outputs with `n` at most `2^r - 1`
    /// (Section 4.1 step 2), or `usize::MAX` where that does not fit.
    pub fn max_len(&self) -> usize {
        usize::try_from(P::H_LEN as u128 * self.r.max_count() as u128).unwrap_or(usize::MAX)
    }

    /// Section 4.1: `L = 8 * len` bits of keying material from `K_IN`, the concatenation of
    /// `keys`, and the fixed input data, written to the front of `dkm`, which is zeroized
    /// first.
    fn derive_keys_out<K: KeyMaterialTrait + ?Sized>(
        &self,
        keys: &[&K],
        fixed_input: &[u8],
        len: usize,
        dkm: &mut (impl KeyMaterialTrait + ?Sized),
    ) -> Result<usize, KDFError> {
        const { assert!(P::H_LEN <= MAX_PRF_OUTPUT_LEN) };
        const { assert!(P::H_LEN > 0) };

        // The `_out` rule: nothing stale survives, whichever way this returns.
        dkm.zeroize();

        if len == 0 {
            return Err(KDFError::InvalidLength("a zero-length derivation is refused"));
        }
        if keys.is_empty() {
            return Err(KDFError::InvalidLength("a derivation from no keys is refused"));
        }
        // Step 1: n := ceil(L / h). Step 2: "If n > 2^r - 1, then output an error indicator and
        // stop", which keeps the counter values distinct.
        if len > self.max_len() {
            return Err(KDFError::InvalidLength("n must not exceed 2^r - 1"));
        }
        if len > dkm.capacity() {
            return Err(KDFError::InvalidLength("the output buffer cannot hold L bits"));
        }
        // The fixed input data either side of the counter.
        let (before, after): (&[u8], &[u8]) = match self.position {
            CounterPosition::BeforeFixedInput => (&[], fixed_input),
            CounterPosition::AfterFixedInput => (fixed_input, &[]),
            CounterPosition::InFixedInput(at) => {
                if at > fixed_input.len() {
                    return Err(KDFError::InvalidLength(
                        "the counter's position is past the end of the fixed input data",
                    ));
                }
                fixed_input.split_at(at)
            }
        };

        let key = P::key(keys)?;

        // Section 4.1's guard: K(0) = PRF(K_IN, fixed input data), appended to the fixed input
        // data of every iteration. It is keying material, like the K(i).
        let mut k0 = Secret::<[u8; MAX_PRF_OUTPUT_LEN]>::new();
        let k0_len = if self.key_control_guard {
            P::prf_into(&key, &[before, after], &mut k0[..P::H_LEN])
        } else {
            0
        };

        // Steps 3 to 5. K(i) is keying material, so its block zeroizes on drop. Each block is
        // written to `dkm` as it is made; nothing after the checks above fails.
        let mut block = Secret::<[u8; MAX_PRF_OUTPUT_LEN]>::new();
        let n = len.div_ceil(P::H_LEN);
        let r_len = self.r.byte_len();
        let filled = do_hazardous_operations(dkm, |dkm| {
            let out = dkm.ref_to_bytes_mut()?;
            let mut written = 0usize;
            // Step 4: "For i = 1 to n". n fits the counter (step 2), and so a u32.
            for i in 1..=n as u32 {
                // "[i]2 ... is represented as a string of r bits": the low r bits, big-endian.
                let counter = i.to_be_bytes();
                // Step 4.a: K(i) := PRF(K_IN, [i]2 || Label || 0x00 || Context || [L]2), with
                // the counter where this instance puts it and K(0) last when the guard is on.
                let block_len = P::prf_into(
                    &key,
                    &[before, &counter[4 - r_len..], after, &k0[..k0_len]],
                    &mut block[..P::H_LEN],
                );
                // Steps 4.b and 5: result := result || K(i), and K_OUT its leftmost L bits.
                let take = *min(&block_len, &(len - written));
                out[written..written + take].copy_from_slice(&block[..take]);
                written += take;
            }
            Ok(())
        });
        let labelled = filled
            .and_then(|()| label_output(keys, len, P::SEED_LEN, P::MAX_SECURITY_STRENGTH, dkm));
        if labelled.is_err() {
            dkm.zeroize();
        }
        labelled?;
        Ok(len)
    }
}

impl<P: Prf> KDF for KDF_Counter<P> {
    /// Section 4.1 with `K_IN` the key `ikm` and `fixed_info` the fixed input data.
    ///
    /// # Errors
    /// [`KDFError::InvalidLength`] if `len` is zero, needs more than `2^r - 1` PRF outputs
    /// ([`KDF_Counter::max_len`]) or exceeds the buffer's capacity, or if the counter's position
    /// is past the end of `fixed_info`; the buffer is left zeroized.
    fn derive_key_out(
        &self,
        ikm: &dyn KeyMaterialTrait,
        fixed_info: &[u8],
        len: usize,
        output_key: &mut dyn KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        self.derive_keys_out(&[ikm], fixed_info, len, output_key)
    }

    /// [`KDF::derive_key_out`] with `K_IN` the bare concatenation of `ikms`; an empty `ikms` is
    /// [`KDFError::InvalidLength`].
    fn derive_key_from_multiple_out(
        &self,
        ikms: &[&dyn KeyMaterialTrait],
        fixed_info: &[u8],
        len: usize,
        output_key: &mut dyn KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        self.derive_keys_out(ikms, fixed_info, len, output_key)
    }
}
