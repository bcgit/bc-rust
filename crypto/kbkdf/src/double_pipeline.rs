//! The KDF in Double-Pipeline Mode, SP 800-108r1 Section 4.3.

use crate::prf::sealed::Token;
use crate::prf::{MAX_PRF_OUTPUT_LEN, Prf};
use crate::{
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

/// The KDF in Double-Pipeline Mode (SP 800-108r1 Section 4.3) over the PRF `P`: a first
/// pipeline `A(i) = PRF(K_IN, A(i-1))` from `A(0)`, the fixed input data, and a second,
/// `K(i) = PRF(K_IN, A(i) {|| [i]2} || fixed input data)`, whose outputs are concatenated and
/// truncated to `L` bits.
///
/// The key-derivation key `K_IN` is the [`KDF`] methods' input key and their `fixed_info` the
/// whole fixed input data, as for [`KDF_Counter`](crate::KDF_Counter). An instance holds only
/// whether and where a counter is used; using one is Section 4.3's guard against key control.
#[allow(non_camel_case_types)]
pub struct KDF_DoublePipeline<P: Prf> {
    counter: Option<(CounterSize, IterationCounterPosition)>,
    _prf: PhantomData<P>,
}

// Written out rather than derived: a derive would demand `P: Clone` of the PRF marker.
impl<P: Prf> Clone for KDF_DoublePipeline<P> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<P: Prf> Copy for KDF_DoublePipeline<P> {}

impl<P: Prf> Default for KDF_DoublePipeline<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: Prf> Algorithm for KDF_DoublePipeline<P> {
    const ALG_NAME: &'static str = Self::NAME.as_str();
    const MAX_SECURITY_STRENGTH: SecurityStrength = P::MAX_SECURITY_STRENGTH;
}

/// The one parameter is a readable field ([`KDF_DoublePipeline::counter`]), so the KDF
/// describes itself: the engine is a copy.
impl<P: Prf> KdfDescription for KDF_DoublePipeline<P> {
    type Engine = Self;

    fn engine(&self) -> Result<Self, KDFError> {
        Ok(*self)
    }
}

impl<P: Prf> KDF_DoublePipeline<P> {
    const NAME: ConstStr<48> = ConstStr::concat(&["KDF-DoublePipeline-", P::NAME]);

    /// The double-pipeline mode with no counter.
    pub fn new() -> Self {
        Self { counter: None, _prf: PhantomData }
    }

    /// The double-pipeline mode with a counter of `r` bits at `position`.
    pub fn with_counter(r: CounterSize, position: IterationCounterPosition) -> Self {
        Self { counter: Some((r, position)), _prf: PhantomData }
    }

    /// The counter's size and position, or `None` if no counter is used.
    pub fn counter(&self) -> Option<(CounterSize, IterationCounterPosition)> {
        self.counter
    }

    /// The most bytes one derivation produces: `n` PRF outputs with `n` at most `2^32 - 1`
    /// (Section 4.3 step 2) and, with a counter, at most the `2^r - 1` values it takes; or
    /// `usize::MAX` where that does not fit.
    pub fn max_len(&self) -> usize {
        max_len::<P>(self.counter.map(|(r, _)| r))
    }

    /// Section 4.3: `L = 8 * len` bits of keying material from `K_IN`, the concatenation of
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

        // The A(i) are "a sequence of secret values", so both blocks zeroize on drop. `a` holds
        // A(i-1) from the second iteration on; A(0) is the fixed input data itself (step 4) and
        // is used where it is.
        let mut a = Secret::<[u8; MAX_PRF_OUTPUT_LEN]>::new();
        let mut a_next = Secret::<[u8; MAX_PRF_OUTPUT_LEN]>::new();
        // Steps 5.a and 5.b are here: the loop, steps 5.c and 6 are `derive_blocks_out`'s.
        derive_blocks_out::<P, K>(keys, len, dkm, |i, block| {
            // Step 5.a: A(i) := PRF(K_IN, A(i-1)).
            let previous = if i == 1 { fixed_input } else { &a[..P::H_LEN] };
            let a_len = P::prf_into(&key, &[previous], &mut a_next[..P::H_LEN], &Token::new());
            a[..a_len].copy_from_slice(&a_next[..a_len]);
            // Step 5.b: K(i) := PRF(K_IN, A(i) {|| [i]2} || Label || 0x00 || Context ||
            // [L]2), with the counter where this instance puts it.
            let counter = i.to_be_bytes();
            P::prf_into(
                &key,
                &iteration_input(self.counter, &a[..a_len], &counter, fixed_input),
                block,
                &Token::new(),
            )
        })
    }
}

impl<P: Prf> KDF for KDF_DoublePipeline<P> {
    /// Section 4.3 with `K_IN` the key `ikm` and `fixed_info` the fixed input data.
    ///
    /// # Errors
    /// [`KDFError::InvalidLength`] if `len` is zero, exceeds [`KDF_DoublePipeline::max_len`] or
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
