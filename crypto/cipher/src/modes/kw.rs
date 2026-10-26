//! The Key Wrap algorithm, KW (NIST SP 800-38F Sec 6.2; RFC 3394), over any 128-bit block
//! permutation.
//!
//! KW is a deterministic, authenticated, one-shot encryption of a *key* -- or any other data that
//! is a whole number of 8-byte semiblocks -- under a key encryption key (KEK). There is no IV: the
//! integrity check value ICV1 stands in for one, and wrapping the same data under the same KEK
//! always gives the same ciphertext, which is one semiblock longer than the plaintext. For data
//! of any other length, use [`Kwp`](crate::modes::kwp::Kwp).
//!
//! The way onto it is a mode-bound key, built with `from_key_material`, whose state is the keyed
//! permutation and which hands out the one-shot worker [`Kw`] through [`KW`], the marker a key type
//! such as `bouncycastle_aes::AES128Key<KW>` is bound to. The key's roles,
//! [`KeyWrappingKey`] / [`KeyUnwrappingKey`], carry the one-shots; the worker implements
//! [`KeyWrapper`] / [`KeyUnwrapper`] over any [`ElectronicCodeBook`] whose block is 128 bits
//! (SP 800-38F Sec 5.1 requires that for KW and KWP, and AES is currently the only *approved*
//! cipher that fits). The ready-made `AES_KW_128` / `AES_KW_192` / `AES_KW_256` aliases are in
//! `bouncycastle-aes`.
//!
//! # Usage Examples
//!
//! From a key state -- what a mode-bound key holds -- over `ToyBlockCipher` (see the
//! [module docs](super) for why):
//!
//! ```
//! # mod toy { include!("../../tests/common/toy_block_cipher.rs"); }
//! # use toy::ToyBlockCipher;
//! use bouncycastle_cipher::modes::Kw;
//! use bouncycastle_core::hazmat::ElectronicCodeBook;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::{KeyUnwrapper, KeyWrapper};
//!
//! let kek = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//! let state = ToyBlockCipher::new(&kek).unwrap();
//! let kw = Kw::from_perm(&state);
//! let key_to_wrap = [0x5Au8; 32];
//!
//! // Lengths fixed at compile time: a 32-byte key wraps to 40 bytes, and any other pair of
//! // lengths is a compile error, not a runtime one.
//! let wrapped: [u8; 40] = kw.wrap_key(&key_to_wrap).expect("wrapping");
//! let recovered = kw.unwrap_key::<32, 40>(&wrapped).expect("unwrapping");
//! assert_eq!(*recovered, key_to_wrap);
//!
//! // Lengths known only at run time: the caller sizes the buffers with the length helpers.
//! let mut wrapped_out = [0u8; 64];
//! let n = kw.wrap_out(&key_to_wrap, &mut wrapped_out).expect("wrapping");
//! assert_eq!(n, kw.wrap_out_len(key_to_wrap.len()));
//! assert_eq!(wrapped_out[..n], wrapped);
//! ```
//!
//! A modified ciphertext, or the wrong KEK, is rejected rather than unwrapped to garbage. (The
//! toy has no diffusion, so only a change to the first semiblock reaches its integrity check;
//! under a real cipher any change does.)
//!
//! ```
//! # mod toy { include!("../../tests/common/toy_block_cipher.rs"); }
//! # use toy::ToyBlockCipher;
//! # use bouncycastle_cipher::modes::Kw;
//! # use bouncycastle_core::hazmat::ElectronicCodeBook;
//! # use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! # use bouncycastle_core::traits::{KeyUnwrapper, KeyWrapper};
//! use bouncycastle_core::errors::SymmetricCipherError;
//! # let kek = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//! #     .expect("a 16-byte symmetric cipher key");
//! # let state = ToyBlockCipher::new(&kek).unwrap();
//! # let kw = Kw::from_perm(&state);
//! # let mut wrapped: [u8; 40] = kw.wrap_key(&[0x5Au8; 32]).expect("wrapping");
//! wrapped[3] ^= 0x01;
//! assert!(matches!(
//!     kw.unwrap_key::<32, 40>(&wrapped),
//!     Err(SymmetricCipherError::DecryptionFailed)
//! ));
//! ```
//!
//! # No direction marker
//!
//! Unlike [`Ecb`](crate::modes::hazmat::ecb::Ecb) and the other modes, [`Kw`] has no `Dir`
//! parameter. The wrapping and unwrapping halves are already separate traits ([`KeyWrapper`] /
//! [`KeyUnwrapper`]), so a policy can import one trait and not the other, and there is no
//! per-direction state for a marker type to select.
//!
//! # The wrapping function runs in place, without the shift register
//!
//! Step 2 of Algorithm 1 (and of Algorithm 2) is written as a shift register: at each step the
//! block cipher takes `A || R2`, the upper half of the output (XORed with the step counter)
//! becomes the new `A`, every `R` moves up one place, and the lower half of the output becomes the
//! new last register. Each step therefore consumes the register at the front and pushes a value
//! onto the back, so after `n - 1` steps every register has been through the cipher exactly once,
//! in the order `R2, ..., Rn`, and holds its replacement in its original position. The private
//! `w` and `w_inv` leave the registers where they are and visit them in that order instead -- the
//! index-based form of RFC 3394 Sec 2.2.1, which the RFC states is equivalent -- so the only
//! difference from the literal steps is that no semiblocks are copied between them. The step
//! counter `t` and the values of `A` and every `R` at every step are identical.
//!
//! # 🚨 Security Considerations 🚨
//!
//! ## KW is for keys, and for data that behaves like one
//!
//! KW is deterministic and has no IV, which is fine for wrapping a key -- a fresh random key never
//! repeats -- but means that wrapping the same data twice under the same KEK is visible as two
//! equal ciphertexts. Use an AEAD for data that may repeat, and use KW where the format calls for
//! it (CMS, JOSE, PKCS#11 and the like).
//!
//! ## The KEK should be at least as strong as what it protects
//!
//! SP 800-38F Appendix A.2: "the generation and management of the KEK should be at least as
//! strong cryptographically as any key that it protects". The wrapped data is plain bytes with no
//! security strength attached, so this mode cannot check it; it is the caller's responsibility.
//! The KEK itself must be a `SymmetricCipherKey` at least as strong as the permutation's
//! `MAX_SECURITY_STRENGTH`, which the key's constructor enforces.
//!
//! ## The length limits are part of the security argument
//!
//! Table 1 limits a KW plaintext to fewer than 2^54 semiblocks so that the forgery probability
//! stays below 2^-64 (Appendix A.4). The fixed-length API checks the limits at compile time and
//! the run-time API returns [`SymmetricCipherError::InvalidInputLength`] outside them.
//!
//! [`KeyWrappingKey`]: bouncycastle_core::symmetric_key::KeyWrappingKey
//! [`KeyUnwrappingKey`]: bouncycastle_core::symmetric_key::KeyUnwrappingKey

use super::ModeNames;
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::hazmat::{
    BlockPermutation, ElectronicCodeBook, KeyUnwrapMode, KeyWrapMode, Mode,
};
use bouncycastle_core::key_material::KeyType;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, KeyUnwrapper, KeyWrapper};
use bouncycastle_utils::ct::ct_eq_bytes;
use bouncycastle_utils::secret::Secret;

/// The block length, in bytes, of the permutation under KW and KWP. SP 800-38F Sec 5.1: "For KW
/// and KWP, the underlying block cipher shall be approved, and the block size shall be 128 bits."
pub const KW_BLOCK_LEN: usize = 16;

/// A semiblock (SP 800-38F Sec 4.1): "a bit string whose length is half of the block size".
pub const SEMIBLOCK_LEN: usize = KW_BLOCK_LEN / 2;

/// ICV1, the integrity check value of KW (Algorithm 3, step 1): `0xA6A6A6A6A6A6A6A6`.
const ICV1: [u8; SEMIBLOCK_LEN] = [0xA6; SEMIBLOCK_LEN];

/// The most semiblocks of plaintext KW-AE accepts. Table 1: 2 to 2^54 - 1 semiblocks, the upper
/// bound being a requirement (Sec 5.3.1) motivated in Appendix A.4. Held as a `u64` because a
/// 32-bit `usize` cannot represent it.
const KW_MAX_PLAINTEXT_SEMIBLOCKS: u64 = (1u64 << 54) - 1;

/// Whether `len` bytes is a plaintext length KW is defined on: 2 to 2^54 - 1 whole semiblocks
/// (SP 800-38F Table 1).
pub const fn kw_plaintext_len_is_valid(len: usize) -> bool {
    len.is_multiple_of(SEMIBLOCK_LEN)
        && len >= 2 * SEMIBLOCK_LEN
        && (len / SEMIBLOCK_LEN) as u64 <= KW_MAX_PLAINTEXT_SEMIBLOCKS
}

/// Whether `len` bytes is a ciphertext length KW-AD is defined on: 3 to 2^54 whole semiblocks
/// (SP 800-38F Table 1).
pub const fn kw_ciphertext_len_is_valid(len: usize) -> bool {
    len.is_multiple_of(SEMIBLOCK_LEN)
        && len >= 3 * SEMIBLOCK_LEN
        && (len / SEMIBLOCK_LEN) as u64 <= KW_MAX_PLAINTEXT_SEMIBLOCKS + 1
}

/// The KW ciphertext length for a plaintext of `len` bytes: one semiblock longer. Algorithm 3
/// computes `C = W(ICV1 || P)`, and W preserves the length of its input.
pub const fn kw_wrapped_len(len: usize) -> usize {
    len.saturating_add(SEMIBLOCK_LEN)
}

/// The wrapping function W (SP 800-38F Algorithm 1), in place over `S = a || r`.
///
/// `a` holds `S1` and `r` holds `S2 .. Sn`, so `r.len() == n - 1`, which must be at least 2
/// (Algorithm 1 is defined for `n >= 3`). On return `a` holds `C1` and `r` holds `C2 .. Cn`.
///
/// Runs in place rather than through the shift register of the spec's step 2; see the module
/// docs for why the two are the same computation.
pub(crate) fn w<P>(perm: &P, a: &mut [u8; SEMIBLOCK_LEN], r: &mut [[u8; SEMIBLOCK_LEN]])
where
    P: BlockPermutation<KW_BLOCK_LEN>,
{
    debug_assert!(r.len() >= 2, "Algorithm 1 is defined on n >= 3 semiblocks");
    // Everything that passes through `block` is derived from the key being wrapped, so it is
    // scrubbed when this function returns.
    let mut block: Secret<[u8; KW_BLOCK_LEN]> = Secret::new();
    // Step 1a: s = 6(n-1) steps, indexed by t = 1, ..., s.
    let mut t: u64 = 0;
    for _ in 0..6 {
        for r_i in r.iter_mut() {
            t += 1;
            // Step 2: CIPH_K(A_{t-1} || R2_{t-1}), where R2_{t-1} is this register (module docs).
            let (halves, _) = block.as_chunks_mut::<SEMIBLOCK_LEN>();
            halves[0] = *a;
            halves[1] = *r_i;
            perm.encrypt_block(&mut block);
            let (halves, _) = block.as_chunks::<SEMIBLOCK_LEN>();
            // Step 2a: A_t = MSB64(CIPH_K(...)) xor [t]64.
            for (a_byte, (c_byte, t_byte)) in
                a.iter_mut().zip(halves[0].iter().zip(t.to_be_bytes()))
            {
                *a_byte = c_byte ^ t_byte;
            }
            // Step 2c: R_n_t = LSB64(CIPH_K(...)), which lands back in this register.
            *r_i = halves[1];
        }
    }
    debug_assert_eq!(t as usize, 6 * r.len(), "Algorithm 1 step 1a: s = 6(n-1)");
}

/// The unwrapping function W⁻¹ (SP 800-38F Algorithm 2), in place over `C = a || r`.
///
/// `a` holds `C1` and `r` holds `C2 .. Cn`, with `r.len() == n - 1 >= 2`. On return `a` holds
/// `S1` and `r` holds `S2 .. Sn`. The registers are visited in the reverse of the order [`w`]
/// visits them, so that step `t` here undoes step `t` there.
pub(crate) fn w_inv<P>(perm: &P, a: &mut [u8; SEMIBLOCK_LEN], r: &mut [[u8; SEMIBLOCK_LEN]])
where
    P: BlockPermutation<KW_BLOCK_LEN>,
{
    debug_assert!(r.len() >= 2, "Algorithm 2 is defined on n >= 3 semiblocks");
    let mut block: Secret<[u8; KW_BLOCK_LEN]> = Secret::new();
    // Step 1a: s = 6(n-1); step 2 runs t = s, s-1, ..., 1.
    let mut t: u64 = 6 * r.len() as u64;
    for _ in 0..6 {
        for r_i in r.iter_mut().rev() {
            // Steps 2a/2b: CIPH⁻¹_K((A_t xor [t]64) || R_n_t), where R_n_t is this register.
            let (halves, _) = block.as_chunks_mut::<SEMIBLOCK_LEN>();
            for (b, (a_byte, t_byte)) in halves[0].iter_mut().zip(a.iter().zip(t.to_be_bytes())) {
                *b = a_byte ^ t_byte;
            }
            halves[1] = *r_i;
            perm.decrypt_block(&mut block);
            let (halves, _) = block.as_chunks::<SEMIBLOCK_LEN>();
            // Step 2a: A_{t-1} = MSB64(...).
            *a = halves[0];
            // Step 2b: R2_{t-1} = LSB64(...), which lands back in this register.
            *r_i = halves[1];
            t -= 1;
        }
    }
    debug_assert_eq!(t, 0, "Algorithm 2 step 2 ends at t = 1");
}

/// The KW mode type, as a key type names it: `AES128Key<KW>`. Its key state is the keyed
/// permutation alone, and its workers are [`Kw`] on both sides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KW;

impl<P> Mode<P> for KW
where
    P: BlockPermutation<KW_BLOCK_LEN> + ModeNames + Clone,
{
    type KeyState = P;
    const KEY_TYPE: KeyType = KeyType::SymmetricCipherKey;

    fn key_state(perm: P) -> Self::KeyState {
        perm
    }
}

impl<P, const KEK_LEN: usize> KeyWrapMode<P, KEK_LEN> for KW
where
    P: ElectronicCodeBook<KEK_LEN, KW_BLOCK_LEN> + ModeNames + Clone,
{
    type Wrapper<'k>
        = Kw<'k, P>
    where
        P: 'k;

    fn wrap_init<'k>(state: &'k Self::KeyState) -> Self::Wrapper<'k> {
        Kw::from_perm(state)
    }
}

impl<P, const KEK_LEN: usize> KeyUnwrapMode<P, KEK_LEN> for KW
where
    P: ElectronicCodeBook<KEK_LEN, KW_BLOCK_LEN> + ModeNames + Clone,
{
    type Unwrapper<'k>
        = Kw<'k, P>
    where
        P: 'k;

    fn unwrap_init<'k>(state: &'k Self::KeyState) -> Self::Unwrapper<'k> {
        Kw::from_perm(state)
    }
}

/// KW over any 128-bit permutation that impls [`BlockPermutation`]: the one-shot worker a
/// [`KW`]-bound key hands out, borrowing the keyed permutation for `'k`.
///
/// There is no state beyond the borrow and no direction marker: both halves of the algorithm are
/// the [`KeyWrapper`] and [`KeyUnwrapper`] traits, which this type implements together. See the
/// module docs for usage and the security notes.
pub struct Kw<'k, P>
where
    P: BlockPermutation<KW_BLOCK_LEN> + ModeNames,
{
    perm: &'k P,
}

impl<'k, P> Kw<'k, P>
where
    P: BlockPermutation<KW_BLOCK_LEN> + ModeNames,
{
    /// Over an already-keyed permutation, which the worker borrows: what a [`KW`]-bound key's
    /// roles build.
    pub fn from_perm(perm: &'k P) -> Self {
        Self { perm }
    }
}

impl<'k, P> Algorithm for Kw<'k, P>
where
    P: BlockPermutation<KW_BLOCK_LEN> + ModeNames,
{
    /// The permutation's name for this mode, [`ModeNames::KW_ALG_NAME`].
    const ALG_NAME: &'static str = P::KW_ALG_NAME;
    /// KW does not change the strength of the underlying cipher.
    const MAX_SECURITY_STRENGTH: SecurityStrength = P::MAX_SECURITY_STRENGTH;
}

impl<'k, P> KeyWrapper for Kw<'k, P>
where
    P: BlockPermutation<KW_BLOCK_LEN> + ModeNames,
{
    /// KW-AE with the lengths fixed at compile time. `KEY_LEN` must be a valid KW plaintext
    /// length and `CT_LEN` one semiblock more; anything else fails to compile.
    fn wrap_key_out<const KEY_LEN: usize, const CT_LEN: usize>(
        &self,
        key: &[u8; KEY_LEN],
        ciphertext: &mut [u8; CT_LEN],
    ) -> Result<usize, SymmetricCipherError> {
        const {
            assert!(
                kw_plaintext_len_is_valid(KEY_LEN),
                "KW wraps 2 to 2^54 - 1 whole 8-byte semiblocks (SP 800-38F Table 1); use KWP for other lengths"
            );
            assert!(
                CT_LEN == kw_wrapped_len(KEY_LEN),
                "a KW ciphertext is exactly one 8-byte semiblock longer than its plaintext"
            );
        }
        self.wrap_out(key, ciphertext)
    }

    /// One semiblock more than the plaintext.
    fn wrap_out_len(&self, plaintext_len: usize) -> usize {
        kw_wrapped_len(plaintext_len)
    }

    /// KW-AE (SP 800-38F Algorithm 3).
    fn wrap_out(
        &self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        let ct_len = kw_wrapped_len(plaintext.len());
        if ciphertext.len() < ct_len {
            return Err(SymmetricCipherError::OutputBufferTooSmall(ct_len));
        }
        if !kw_plaintext_len_is_valid(plaintext.len()) {
            return Err(SymmetricCipherError::InvalidInputLength(
                "KW wraps 2 to 2^54 - 1 whole 8-byte semiblocks (SP 800-38F Table 1); use KWP for other lengths",
            ));
        }

        // Steps 1-2: S = ICV1 || P, assembled in the caller's buffer so that the plaintext is
        // copied exactly once and W can run on it in place.
        let (a, r) = ciphertext[..ct_len].split_at_mut(SEMIBLOCK_LEN);
        let (a, _) = a.as_chunks_mut::<SEMIBLOCK_LEN>();
        let a = &mut a[0];
        *a = ICV1;
        r.copy_from_slice(plaintext);
        let (r, _) = r.as_chunks_mut::<SEMIBLOCK_LEN>();
        // Step 3: C = W(S).
        w(self.perm, a, r);
        Ok(ct_len)
    }
}

impl<'k, P> KeyUnwrapper for Kw<'k, P>
where
    P: BlockPermutation<KW_BLOCK_LEN> + ModeNames,
{
    /// KW-AD with the lengths fixed at compile time; the same pairs as
    /// [`wrap_key_out`](KeyWrapper::wrap_key_out) are accepted.
    fn unwrap_key_out<const KEY_LEN: usize, const CT_LEN: usize>(
        &self,
        ciphertext: &[u8; CT_LEN],
        key: &mut Secret<[u8; KEY_LEN]>,
    ) -> Result<usize, SymmetricCipherError> {
        const {
            assert!(
                kw_plaintext_len_is_valid(KEY_LEN),
                "KW unwraps to 2 to 2^54 - 1 whole 8-byte semiblocks (SP 800-38F Table 1); use KWP for other lengths"
            );
            assert!(
                CT_LEN == kw_wrapped_len(KEY_LEN),
                "a KW ciphertext is exactly one 8-byte semiblock longer than its plaintext"
            );
        }
        // `key` is exactly the n-1 semiblocks the run-time method writes into, and that method
        // scrubs the buffer on every failure it can reach from here.
        self.unwrap_out(ciphertext, &mut key[..])
    }

    /// One semiblock less than the ciphertext: exact for KW.
    fn unwrap_out_max_len(&self, ciphertext_len: usize) -> usize {
        ciphertext_len.saturating_sub(SEMIBLOCK_LEN)
    }

    /// KW-AD (SP 800-38F Algorithm 4).
    fn unwrap_out(
        &self,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        let pt_len = self.unwrap_out_max_len(ciphertext.len());
        if plaintext.len() < pt_len {
            return Err(SymmetricCipherError::OutputBufferTooSmall(pt_len));
        }
        // Nothing this function writes may survive a failure, so start from zero and only ever
        // return `Ok` with the buffer fully written.
        plaintext.fill(0);
        if !kw_ciphertext_len_is_valid(ciphertext.len()) {
            return Err(SymmetricCipherError::InvalidInputLength(
                "a KW ciphertext is 3 to 2^54 whole 8-byte semiblocks (SP 800-38F Table 1)",
            ));
        }

        // Step 2: S = W⁻¹(C). C1 goes to a scratch semiblock that is scrubbed on return; C2..Cn
        // go straight into the caller's buffer, which is exactly n-1 semiblocks, so W⁻¹ runs in
        // place and the recovered plaintext is never copied.
        let mut a: Secret<[u8; SEMIBLOCK_LEN]> = Secret::new();
        a.copy_from_slice(&ciphertext[..SEMIBLOCK_LEN]);
        let r = &mut plaintext[..pt_len];
        r.copy_from_slice(&ciphertext[SEMIBLOCK_LEN..]);
        let (r, _) = r.as_chunks_mut::<SEMIBLOCK_LEN>();
        w_inv(self.perm, &mut a, r);

        // Step 3: if MSB64(S) != ICV1, FAIL. Compared in constant time, and the buffer is scrubbed
        // so that a caller who ignores the `Result` is not left holding the unauthenticated bytes.
        if !ct_eq_bytes(&*a, &ICV1) {
            plaintext.fill(0);
            return Err(SymmetricCipherError::DecryptionFailed);
        }
        // Step 4: P = LSB64(n-1)(S), which is already in place.
        Ok(pt_len)
    }
}
