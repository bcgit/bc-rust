//! The KDF in Feedback Mode, SP 800-108r1 Section 4.2.

use crate::kbkdf::prf::sealed::Token;
use crate::kbkdf::prf::{MAX_PRF_OUTPUT_LEN, Prf};
use crate::kbkdf::{
    CounterSize, IterationCounterPosition, check_request, derive_blocks_out, iteration_input,
    max_len,
};
use bouncycastle_core::errors::KDFError;
use bouncycastle_core::kdf_params::KdfDescription;
use bouncycastle_core::key_material::KeyMaterialTrait;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, KDF};
use bouncycastle_utils::const_str::ConstStr;
use bouncycastle_utils::secret::Secret;
use core::marker::PhantomData;

/// The KDF in Feedback Mode (SP 800-108r1 Section 4.2) over the PRF `P`:
/// `K(i) = PRF(K_IN, K(i-1) {|| [i]2} || fixed input data)` with `K(0) = IV`, and the keying
/// material the leftmost `L` bits of `K(1) || K(2) || ...`.
///
/// The key-derivation key `K_IN` is the [`KDF`] methods' input key and their `fixed_info` the
/// whole fixed input data, as for [`KDF_Counter`](crate::kbkdf::KDF_Counter). An instance holds the
/// IV, which it borrows and which may be empty, and whether and where a counter is used.
#[allow(non_camel_case_types)]
pub struct KDF_Feedback<'iv, P: Prf> {
    /// `None` under Section 4.2's guard against key control, where the IV is derived.
    iv: Option<&'iv [u8]>,
    counter: Option<(CounterSize, IterationCounterPosition)>,
    _prf: PhantomData<P>,
}

// Written out rather than derived: a derive would demand `P: Clone` of the PRF marker.
impl<P: Prf> Clone for KDF_Feedback<'_, P> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<P: Prf> Copy for KDF_Feedback<'_, P> {}

impl<P: Prf> Algorithm for KDF_Feedback<'_, P> {
    const ALG_NAME: &'static str = Self::NAME.as_str();
    const MAX_SECURITY_STRENGTH: SecurityStrength = P::MAX_SECURITY_STRENGTH;
}

/// Every parameter is a readable field ([`KDF_Feedback::iv`], [`KDF_Feedback::counter`],
/// [`KDF_Feedback::key_control_guard`]), so the KDF describes itself: the engine is a copy.
impl<P: Prf> KdfDescription for KDF_Feedback<'_, P> {
    type Engine = Self;

    fn engine(&self) -> Result<Self, KDFError> {
        Ok(*self)
    }
}

impl<'iv, P: Prf> KDF_Feedback<'iv, P> {
    const NAME: ConstStr<48> = ConstStr::concat(&["KDF-Feedback-", P::NAME]);

    /// The feedback mode with `K(0) = iv`, which may be empty, and no counter.
    pub fn new(iv: &'iv [u8]) -> Self {
        Self { iv: Some(iv), counter: None, _prf: PhantomData }
    }

    /// The feedback mode with `K(0) = iv` and a counter of `r` bits at `position`.
    pub fn with_counter(iv: &'iv [u8], r: CounterSize, position: IterationCounterPosition) -> Self {
        Self { iv: Some(iv), counter: Some((r, position)), _prf: PhantomData }
    }

    /// The feedback mode with Section 4.2's guard against key control: the IV is
    /// `PRF(K_IN, fixed input data)` and the counter, of `r` bits at `position`, is not
    /// optional. Both parties must apply it; see the module's Security Considerations.
    pub fn with_key_control_guard(r: CounterSize, position: IterationCounterPosition) -> Self {
        Self { iv: None, counter: Some((r, position)), _prf: PhantomData }
    }

    /// The IV, or `None` under the guard against key control, where it is derived.
    pub fn iv(&self) -> Option<&'iv [u8]> {
        self.iv
    }

    /// The counter's size and position, or `None` if no counter is used.
    pub fn counter(&self) -> Option<(CounterSize, IterationCounterPosition)> {
        self.counter
    }

    /// Whether Section 4.2's guard against key control is applied.
    pub fn key_control_guard(&self) -> bool {
        self.iv.is_none()
    }

    /// The most bytes one derivation produces: `n` PRF outputs with `n` at most `2^32 - 1`
    /// (Section 4.2 step 2) and, with a counter, at most the `2^r - 1` values it takes; or
    /// `usize::MAX` where that does not fit.
    pub fn max_len(&self) -> usize {
        max_len::<P>(self.counter.map(|(r, _)| r))
    }

    /// Section 4.2: `L = 8 * len` bits of keying material from `K_IN`, the concatenation of
    /// `keys`, and the fixed input data, written to the front of `dkm`, which is zeroized
    /// first.
    fn derive_keys_out<K: KeyMaterialTrait + ?Sized>(
        &self,
        keys: &[&K],
        fixed_input: &[u8],
        len: usize,
        dkm: &mut (impl KeyMaterialTrait + ?Sized),
    ) -> Result<usize, KDFError> {
        // Step 1: n := ceil(L / h). Step 2: "If n > 2^32 - 1, output an error indicator and
        // stop". A counter is defined on [1, 2^r - 1] (Section 4), so with one n is held to
        // that as well.
        check_request::<P, K>(
            keys,
            len,
            self.max_len(),
            "n must not exceed 2^32 - 1, or 2^r - 1 with a counter",
            dkm,
        )?;

        let key = P::key(keys, &Token::new())?;

        // Step 3: K(0) := IV. `feedback` holds K(i-1) from the first iteration on, and before
        // it the derived IV of the guard; a given IV is used where it is. K(i) is keying
        // material, so the block zeroizes on drop.
        let mut feedback = Secret::<[u8; MAX_PRF_OUTPUT_LEN]>::new();
        let mut feedback_len = match self.iv {
            Some(_) => 0,
            // The guard: "IV = PRF (K_IN, Label || 0x00 || Context || [L]2)".
            None => P::prf_into(&key, &[fixed_input], &mut feedback[..P::H_LEN], &Token::new()),
        };
        // Step 4.a is here: the loop, steps 4.b and 5 are `derive_blocks_out`'s.
        derive_blocks_out::<P, K>(keys, len, dkm, |i, block| {
            let previous = match (i, self.iv) {
                (1, Some(iv)) => iv,
                _ => &feedback[..feedback_len],
            };
            // Step 4.a: K(i) := PRF(K_IN, K(i-1) {|| [i]2} || Label || 0x00 || Context ||
            // [L]2), with the counter where this instance puts it.
            let counter = i.to_be_bytes();
            let block_len = P::prf_into(
                &key,
                &iteration_input(self.counter, previous, &counter, fixed_input),
                block,
                &Token::new(),
            );
            feedback[..block_len].copy_from_slice(&block[..block_len]);
            feedback_len = block_len;
            block_len
        })
    }
}

impl<P: Prf> KDF for KDF_Feedback<'_, P> {
    /// Section 4.2 with `K_IN` the key `ikm` and `fixed_info` the fixed input data.
    ///
    /// # Errors
    /// [`KDFError::InvalidLength`] if `len` is zero, exceeds [`KDF_Feedback::max_len`] or
    /// exceeds the buffer's capacity; the buffer is left zeroized.
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
