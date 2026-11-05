//! The TDEA Key Wrap algorithm, TKW (NIST SP 800-38F Sec 7), over any 64-bit block permutation.
//!
//! TKW is [`Kw`](crate::modes::kw::Kw) at half the width: the same wrapping function over 4-byte
//! semiblocks with a 32-bit step counter (TW, Algorithm 7) and the 32-bit ICV3
//! `0xA6A6A6A6`, wrapping data that is a whole number of 4-byte semiblocks under a TDEA key
//! encryption key. Everything in the [`kw`](crate::modes::kw) module docs -- the key path, the
//! trait shape, the in-place wrapping function, the security notes -- applies here too; this
//! module only documents what differs. SP 800-38F Sec 5.1 fixes the block cipher to TDEA, so the
//! only key type is `bouncycastle_tdes::TDES3Key<TKW>`, whose aliases `TDES_TKW` and the
//! unwrap-only `TDES2_TKW` are in that crate.
//!
//! # Legacy only
//!
//! SP 800-38F Sec 8: TKW-AE and TKW-AD "are approved to support legacy systems but should not be
//! used for new applications". Its forgery probability is 2^-32 per attempt against KW's 2^-64
//! (Appendix A.3), and TDEA itself is a legacy algorithm; see the `bouncycastle-tdes` crate's
//! security considerations. Two-key TDEA may not wrap at all: a permutation that decrypts only
//! ([`BlockPermutation::DECRYPT_ONLY`]) refuses to make a wrapper at compile time, as the
//! encrypting modes refuse their encryptors, while its unwrapper works.
//!
//! # The length limits
//!
//! Table 1: a plaintext of 2 to 2^28 - 1 semiblocks, a ciphertext of 3 to 2^28. The fixed-length
//! API checks them at compile time and the run-time API returns
//! [`SymmetricCipherError::InvalidInputLength`] outside them.

use super::ModeNames;
use super::kw::{w, w_inv};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::hazmat::{
    BlockPermutation, ElectronicCodeBook, KeyUnwrapMode, KeyWrapMode, Mode,
};
use bouncycastle_core::key_material::KeyType;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, KeyUnwrapper, KeyWrapper};
use bouncycastle_utils::ct::ct_eq_bytes;
use bouncycastle_utils::secret::Secret;

/// The block length, in bytes, of the permutation under TKW. SP 800-38F Sec 5.1: "For TKW, the
/// underlying block cipher is specified to be TDEA, and the block size is therefore 64 bits".
pub const TKW_BLOCK_LEN: usize = 8;

/// A TKW semiblock (SP 800-38F Sec 4.1): half the block, 32 bits.
pub const TKW_SEMIBLOCK_LEN: usize = TKW_BLOCK_LEN / 2;

/// ICV3, the integrity check value of TKW (Algorithm 9, step 1): `0xA6A6A6A6`.
const ICV3: [u8; TKW_SEMIBLOCK_LEN] = [0xA6; TKW_SEMIBLOCK_LEN];

/// The most semiblocks of plaintext TKW-AE accepts. Table 1: 2 to 2^28 - 1 semiblocks, the upper
/// bound being a requirement (Sec 5.3.1) motivated in Appendix A.4.
const TKW_MAX_PLAINTEXT_SEMIBLOCKS: u64 = (1u64 << 28) - 1;

/// Whether `len` bytes is a plaintext length TKW is defined on: 2 to 2^28 - 1 whole semiblocks
/// (SP 800-38F Table 1).
pub(crate) const fn tkw_plaintext_len_is_valid(len: usize) -> bool {
    len.is_multiple_of(TKW_SEMIBLOCK_LEN)
        && len >= 2 * TKW_SEMIBLOCK_LEN
        && (len / TKW_SEMIBLOCK_LEN) as u64 <= TKW_MAX_PLAINTEXT_SEMIBLOCKS
}

/// Whether `len` bytes is a ciphertext length TKW-AD is defined on: 3 to 2^28 whole semiblocks
/// (SP 800-38F Table 1).
pub(crate) const fn tkw_ciphertext_len_is_valid(len: usize) -> bool {
    len.is_multiple_of(TKW_SEMIBLOCK_LEN)
        && len >= 3 * TKW_SEMIBLOCK_LEN
        && (len / TKW_SEMIBLOCK_LEN) as u64 <= TKW_MAX_PLAINTEXT_SEMIBLOCKS + 1
}

/// The TKW ciphertext length for a plaintext of `len` bytes: one semiblock longer. Algorithm 9
/// computes `C = TW(ICV3 || P)`, and TW preserves the length of its input.
pub(crate) const fn tkw_wrapped_len(len: usize) -> usize {
    len.saturating_add(TKW_SEMIBLOCK_LEN)
}

/// The TKW mode type, as a key type names it: `TDES3Key<TKW>`. Its key state is the keyed
/// permutation alone, and its workers are [`Tkw`] on both sides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TKW;

impl<P> Mode<P> for TKW
where
    P: BlockPermutation<TKW_BLOCK_LEN> + ModeNames + Clone,
{
    type KeyState = P;
    const KEY_TYPE: KeyType = KeyType::SymmetricCipherKey;

    fn key_state(perm: P) -> Self::KeyState {
        perm
    }
}

impl<P, const KEK_LEN: usize> KeyWrapMode<P, KEK_LEN> for TKW
where
    P: ElectronicCodeBook<KEK_LEN, TKW_BLOCK_LEN> + ModeNames + Clone,
{
    type Wrapper<'k>
        = Tkw<'k, P>
    where
        P: 'k;

    fn wrap_init<'k>(state: &'k Self::KeyState) -> Self::Wrapper<'k> {
        const {
            assert!(
                !P::DECRYPT_ONLY,
                "this permutation decrypts only (BlockPermutation::DECRYPT_ONLY): no wrapper may be made over it"
            )
        };
        Tkw::from_perm(state)
    }
}

impl<P, const KEK_LEN: usize> KeyUnwrapMode<P, KEK_LEN> for TKW
where
    P: ElectronicCodeBook<KEK_LEN, TKW_BLOCK_LEN> + ModeNames + Clone,
{
    type Unwrapper<'k>
        = Tkw<'k, P>
    where
        P: 'k;

    fn unwrap_init<'k>(state: &'k Self::KeyState) -> Self::Unwrapper<'k> {
        Tkw::from_perm(state)
    }
}

/// TKW over any 64-bit permutation that impls [`BlockPermutation`]: the one-shot worker a
/// [`TKW`]-bound key hands out, borrowing the keyed permutation for `'k`, as
/// [`Kw`](super::kw::Kw) does. It reports the permutation's [`ModeNames::KW_ALG_NAME`], since a
/// permutation has one block length and so one key-wrap algorithm. See the module docs.
pub struct Tkw<'k, P>
where
    P: BlockPermutation<TKW_BLOCK_LEN> + ModeNames,
{
    perm: &'k P,
}

impl<'k, P> Tkw<'k, P>
where
    P: BlockPermutation<TKW_BLOCK_LEN> + ModeNames,
{
    /// Over an already-keyed permutation, which the worker borrows: what [`TKW`]'s mode impls
    /// build for a key's roles.
    pub(crate) fn from_perm(perm: &'k P) -> Self {
        Self { perm }
    }
}

impl<'k, P> Algorithm for Tkw<'k, P>
where
    P: BlockPermutation<TKW_BLOCK_LEN> + ModeNames,
{
    /// The permutation's name for its key wrap, [`ModeNames::KW_ALG_NAME`].
    const ALG_NAME: &'static str = P::KW_ALG_NAME;
    /// TKW does not change the strength of the underlying cipher.
    const MAX_SECURITY_STRENGTH: SecurityStrength = P::MAX_SECURITY_STRENGTH;
}

impl<'k, P> KeyWrapper for Tkw<'k, P>
where
    P: BlockPermutation<TKW_BLOCK_LEN> + ModeNames,
{
    /// TKW-AE with the lengths fixed at compile time. `KEY_LEN` must be a valid TKW plaintext
    /// length and `CT_LEN` one semiblock more; anything else fails to compile.
    fn wrap_key_out<const KEY_LEN: usize, const CT_LEN: usize>(
        &self,
        key: &[u8; KEY_LEN],
        ciphertext: &mut [u8; CT_LEN],
    ) -> Result<usize, SymmetricCipherError> {
        const {
            assert!(
                tkw_plaintext_len_is_valid(KEY_LEN),
                "TKW wraps 2 to 2^28 - 1 whole 4-byte semiblocks (SP 800-38F Table 1)"
            );
            assert!(
                CT_LEN == tkw_wrapped_len(KEY_LEN),
                "a TKW ciphertext is exactly one 4-byte semiblock longer than its plaintext"
            );
        }
        self.wrap_out(key, ciphertext)
    }

    /// One semiblock more than the plaintext.
    fn wrap_out_len(&self, plaintext_len: usize) -> usize {
        tkw_wrapped_len(plaintext_len)
    }

    /// TKW-AE (SP 800-38F Algorithm 9).
    fn wrap_out(
        &self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        // Nothing stale may survive a failure, so the whole buffer starts from zero.
        ciphertext.fill(0);
        let ct_len = tkw_wrapped_len(plaintext.len());
        if ciphertext.len() < ct_len {
            return Err(SymmetricCipherError::OutputBufferTooSmall(ct_len));
        }
        if !tkw_plaintext_len_is_valid(plaintext.len()) {
            return Err(SymmetricCipherError::InvalidInputLength(
                "TKW wraps 2 to 2^28 - 1 whole 4-byte semiblocks (SP 800-38F Table 1)",
            ));
        }

        // Steps 1-2: S = ICV3 || P, assembled in the caller's buffer so that the plaintext is
        // copied exactly once and TW can run on it in place.
        let (a, r) = ciphertext[..ct_len].split_at_mut(TKW_SEMIBLOCK_LEN);
        let (a, _) = a.as_chunks_mut::<TKW_SEMIBLOCK_LEN>();
        let a = &mut a[0];
        *a = ICV3;
        r.copy_from_slice(plaintext);
        let (r, _) = r.as_chunks_mut::<TKW_SEMIBLOCK_LEN>();
        // Step 3: C = TW(S).
        w::<P, TKW_BLOCK_LEN, TKW_SEMIBLOCK_LEN>(self.perm, a, r);
        Ok(ct_len)
    }
}

impl<'k, P> KeyUnwrapper for Tkw<'k, P>
where
    P: BlockPermutation<TKW_BLOCK_LEN> + ModeNames,
{
    /// TKW-AD with the lengths fixed at compile time; the same pairs as
    /// [`wrap_key_out`](KeyWrapper::wrap_key_out) are accepted.
    fn unwrap_key_out<const KEY_LEN: usize, const CT_LEN: usize>(
        &self,
        ciphertext: &[u8; CT_LEN],
        key: &mut Secret<[u8; KEY_LEN]>,
    ) -> Result<usize, SymmetricCipherError> {
        const {
            assert!(
                tkw_plaintext_len_is_valid(KEY_LEN),
                "TKW unwraps to 2 to 2^28 - 1 whole 4-byte semiblocks (SP 800-38F Table 1)"
            );
            assert!(
                CT_LEN == tkw_wrapped_len(KEY_LEN),
                "a TKW ciphertext is exactly one 4-byte semiblock longer than its plaintext"
            );
        }
        // `key` is exactly the n-1 semiblocks the run-time method writes into, and that method
        // scrubs the buffer on every failure it can reach from here.
        self.unwrap_out(ciphertext, &mut key[..])
    }

    /// One semiblock less than the ciphertext: exact for TKW.
    fn unwrap_out_max_len(&self, ciphertext_len: usize) -> usize {
        ciphertext_len.saturating_sub(TKW_SEMIBLOCK_LEN)
    }

    /// TKW-AD (SP 800-38F Algorithm 10).
    fn unwrap_out(
        &self,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        // Nothing this function writes may survive a failure, so start from zero and only ever
        // return `Ok` with the buffer fully written.
        plaintext.fill(0);
        let pt_len = self.unwrap_out_max_len(ciphertext.len());
        if plaintext.len() < pt_len {
            return Err(SymmetricCipherError::OutputBufferTooSmall(pt_len));
        }
        if !tkw_ciphertext_len_is_valid(ciphertext.len()) {
            return Err(SymmetricCipherError::InvalidInputLength(
                "a TKW ciphertext is 3 to 2^28 whole 4-byte semiblocks (SP 800-38F Table 1)",
            ));
        }

        // Step 3: S = TW⁻¹(C). C1 goes to a scratch semiblock that is scrubbed on return; C2..Cn
        // go straight into the caller's buffer, which is exactly n-1 semiblocks, so TW⁻¹ runs
        // in place and the recovered plaintext is never copied.
        let mut a: Secret<[u8; TKW_SEMIBLOCK_LEN]> = Secret::new();
        a.copy_from_slice(&ciphertext[..TKW_SEMIBLOCK_LEN]);
        let r = &mut plaintext[..pt_len];
        r.copy_from_slice(&ciphertext[TKW_SEMIBLOCK_LEN..]);
        let (r, _) = r.as_chunks_mut::<TKW_SEMIBLOCK_LEN>();
        w_inv::<P, TKW_BLOCK_LEN, TKW_SEMIBLOCK_LEN>(self.perm, &mut a, r);

        // Step 4: if MSB32(S) != ICV3, FAIL. Compared in constant time, and the buffer is
        // scrubbed so that a caller who ignores the `Result` is not left holding the
        // unauthenticated bytes.
        if !ct_eq_bytes(&*a, &ICV3) {
            plaintext.fill(0);
            return Err(SymmetricCipherError::DecryptionFailed);
        }
        // Step 5: P = LSB32(n-1)(S), which is already in place.
        Ok(pt_len)
    }
}

#[cfg(test)]
mod tests {
    //! The 2^28 upper bounds of SP 800-38F Table 1, which no buffer can reach: the last valid
    //! plaintext is 2^28 - 1 semiblocks, the last valid ciphertext 2^28. The lower bounds and
    //! the alignment rule are pinned through the key in `bouncycastle-tdes`.

    use super::*;

    #[test]
    fn the_table_1_upper_bounds() {
        const MAX_PT: usize = ((1usize << 28) - 1) * TKW_SEMIBLOCK_LEN;
        assert!(tkw_plaintext_len_is_valid(MAX_PT));
        assert!(!tkw_plaintext_len_is_valid(MAX_PT + TKW_SEMIBLOCK_LEN / 2));
        assert!(!tkw_plaintext_len_is_valid(MAX_PT + TKW_SEMIBLOCK_LEN));
        assert!(tkw_ciphertext_len_is_valid(MAX_PT + TKW_SEMIBLOCK_LEN));
        assert!(!tkw_ciphertext_len_is_valid(MAX_PT + 2 * TKW_SEMIBLOCK_LEN));
    }
}
