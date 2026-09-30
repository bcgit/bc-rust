//! The Key Wrap with Padding algorithm, KWP (NIST SP 800-38F Sec 6.3; RFC 5649), over any
//! 128-bit block permutation.
//!
//! KWP is [`Kw`](crate::kw::Kw) for data of any length from 1 byte up to 2^32 - 1 bytes: the
//! plaintext is prefixed with a 4-byte integrity check value and its 4-byte length, padded with
//! zeros to a whole number of 8-byte semiblocks, and then put through the same wrapping function.
//! The ciphertext is the plaintext rounded up to a multiple of 8, plus 8. Everything in the
//! [`kw`](crate::kw) module docs -- the trait shape, the in-place wrapping function, the security
//! notes -- applies here too; this module only documents what differs.
//!
//! The `AES_KWP_128` / `AES_KWP_192` / `AES_KWP_256` aliases are in `bouncycastle-aes`.
//!
//! # Usage Examples
//!
//! ```
//! use bouncycastle_aes::aes_internal::AES128Internal;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::{KeyUnwrapper, KeyWrapper};
//! use bouncycastle_modes::Kwp;
//!
//! type Aes128Kwp = Kwp<AES128Internal, 16>;
//!
//! let kek = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//!
//! // 20 bytes pad to 24, plus the 8-byte header: 32 bytes of ciphertext.
//! let data = [0x5Au8; 20];
//! let wrapped: [u8; 32] = Aes128Kwp::wrap_key(&kek, &data).expect("wrapping");
//! let recovered = Aes128Kwp::unwrap_key::<20, 32>(&kek, &wrapped).expect("unwrapping");
//! assert_eq!(*recovered, data);
//!
//! // Up to 8 bytes fit in a single block with the header, which is enciphered directly
//! // (Algorithm 5, step 5) rather than through the wrapping function.
//! let short = *b"short";
//! let wrapped: [u8; 16] = Aes128Kwp::wrap_key(&kek, &short).expect("wrapping");
//! assert_eq!(*Aes128Kwp::unwrap_key::<5, 16>(&kek, &wrapped).expect("unwrapping"), short);
//! ```
//!
//! # The recovered length is inside the ciphertext
//!
//! A KW ciphertext's length says exactly how long its plaintext is. A KWP ciphertext's length
//! only bounds it: the exact length is the 32-bit field the wrapper put in the header, and is
//! known only after unwrapping. So [`KeyUnwrapper::unwrap_out_max_len`] is an upper bound,
//! [`KeyUnwrapper::unwrap_out`] returns the real length, and the fixed-length
//! [`KeyUnwrapper::unwrap_key`] treats a recovered length other than the `KEY_LEN` it was asked
//! for as an authenticity failure, indistinguishable from a bad ICV.
//!
//! # Every check is the same FAIL
//!
//! Algorithm 6 returns FAIL for a wrong ICV (step 4), a length field that does not fit the
//! ciphertext (step 7) and non-zero padding (step 8). All three are made unconditionally, combined
//! bitwise, and reported as one [`SymmetricCipherError::DecryptionFailed`], so that neither the
//! error nor the control flow says which check failed. (The number of padding bytes compared does
//! depend on the length field, but that field is public once unwrapping succeeds and never more
//! than 7 bytes; there is no padding oracle to protect because the failure is the same either way.)

use crate::kw::{KW_BLOCK_LEN, SEMIBLOCK_LEN, w, w_inv};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::key_material::KeyMaterial;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, ElectronicCodeBook, KeyUnwrapper, KeyWrapper};
use bouncycastle_utils::ct::{ct_eq_bytes, ct_eq_zero_bytes};
use bouncycastle_utils::secret::Secret;
use core::marker::PhantomData;

/// ICV2, the integrity check value of KWP (Algorithm 5, step 1): `0xA65959A6`.
const ICV2: [u8; 4] = [0xA6, 0x59, 0x59, 0xA6];

/// The longest plaintext KWP-AE accepts: Table 1 gives 1 to 2^32 - 1 octets, the bound being the
/// range of the 32-bit length field in the header (Algorithm 5, step 4).
const KWP_MAX_PLAINTEXT_LEN: u64 = (1u64 << 32) - 1;

/// The most semiblocks in a KWP ciphertext: Table 1 gives 2 to 2^29 semiblocks.
const KWP_MAX_CIPHERTEXT_SEMIBLOCKS: u64 = 1u64 << 29;

/// Whether `len` bytes is a plaintext length KWP is defined on: 1 to 2^32 - 1 octets (SP 800-38F
/// Table 1).
pub const fn kwp_plaintext_len_is_valid(len: usize) -> bool {
    len >= 1 && len as u64 <= KWP_MAX_PLAINTEXT_LEN
}

/// Whether `len` bytes is a ciphertext length KWP-AD is defined on: 2 to 2^29 whole semiblocks
/// (SP 800-38F Table 1).
pub const fn kwp_ciphertext_len_is_valid(len: usize) -> bool {
    len.is_multiple_of(SEMIBLOCK_LEN)
        && len >= 2 * SEMIBLOCK_LEN
        && (len / SEMIBLOCK_LEN) as u64 <= KWP_MAX_CIPHERTEXT_SEMIBLOCKS
}

/// The KWP ciphertext length for a plaintext of `len` bytes: `len` rounded up to a whole number
/// of semiblocks (Algorithm 5, steps 2-3: `padlen = 8 * ceil(len / 8) - len` zero bytes), plus the
/// one-semiblock header of step 4.
pub const fn kwp_wrapped_len(len: usize) -> usize {
    len.div_ceil(SEMIBLOCK_LEN).saturating_mul(SEMIBLOCK_LEN).saturating_add(SEMIBLOCK_LEN)
}

/// KWP over any 128-bit permutation that impls [`ElectronicCodeBook`].
///
/// As [`Kw`](crate::kw::Kw): no state, no direction marker, `KEK_LEN` is the permutation's key
/// length. See the module docs.
pub struct Kwp<P, const KEK_LEN: usize>
where
    P: ElectronicCodeBook<KEK_LEN, KW_BLOCK_LEN>,
{
    _perm: PhantomData<P>,
}

impl<P, const KEK_LEN: usize> Algorithm for Kwp<P, KEK_LEN>
where
    P: ElectronicCodeBook<KEK_LEN, KW_BLOCK_LEN>,
{
    /// The underlying permutation's name; the mode is in the type, as for [`Ecb`](crate::Ecb).
    const ALG_NAME: &'static str = P::ALG_NAME;
    /// KWP does not change the strength of the underlying cipher.
    const MAX_SECURITY_STRENGTH: SecurityStrength = P::MAX_SECURITY_STRENGTH;
}

impl<P, const KEK_LEN: usize> KeyWrapper<KEK_LEN> for Kwp<P, KEK_LEN>
where
    P: ElectronicCodeBook<KEK_LEN, KW_BLOCK_LEN>,
{
    /// KWP-AE with the lengths fixed at compile time. `KEY_LEN` may be anything from 1 to
    /// 2^32 - 1 and `CT_LEN` must be [`kwp_wrapped_len`] of it; anything else fails to compile.
    fn wrap_key_out<const KEY_LEN: usize, const CT_LEN: usize>(
        kek: &KeyMaterial<KEK_LEN>,
        key: &[u8; KEY_LEN],
        ciphertext: &mut [u8; CT_LEN],
    ) -> Result<usize, SymmetricCipherError> {
        const {
            assert!(
                kwp_plaintext_len_is_valid(KEY_LEN),
                "KWP wraps 1 to 2^32 - 1 bytes (SP 800-38F Table 1)"
            );
            assert!(
                CT_LEN == kwp_wrapped_len(KEY_LEN),
                "a KWP ciphertext is the plaintext rounded up to a multiple of 8 bytes, plus 8"
            );
        }
        Self::wrap_out(kek, key, ciphertext)
    }

    /// The plaintext rounded up to a whole number of semiblocks, plus one.
    fn wrap_out_len(plaintext_len: usize) -> usize {
        kwp_wrapped_len(plaintext_len)
    }

    /// KWP-AE (SP 800-38F Algorithm 5).
    fn wrap_out(
        kek: &KeyMaterial<KEK_LEN>,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        let ct_len = kwp_wrapped_len(plaintext.len());
        if ciphertext.len() < ct_len {
            return Err(SymmetricCipherError::OutputBufferTooSmall(ct_len));
        }
        if !kwp_plaintext_len_is_valid(plaintext.len()) {
            return Err(SymmetricCipherError::InvalidInputLength(
                "KWP wraps 1 to 2^32 - 1 bytes (SP 800-38F Table 1)",
            ));
        }
        let perm = P::new(kek)?;

        // Steps 1-4: S = ICV2 || [len(P)/8]32 || P || PAD, assembled in the caller's buffer so the
        // plaintext is copied exactly once. The length is in octets and fits 32 bits: checked above.
        let s = &mut ciphertext[..ct_len];
        s[..ICV2.len()].copy_from_slice(&ICV2);
        s[ICV2.len()..SEMIBLOCK_LEN].copy_from_slice(&(plaintext.len() as u32).to_be_bytes());
        s[SEMIBLOCK_LEN..SEMIBLOCK_LEN + plaintext.len()].copy_from_slice(plaintext);
        // Step 3: PAD is padlen zero bytes, padlen being whatever rounds P up to a whole number of
        // semiblocks (step 2).
        s[SEMIBLOCK_LEN + plaintext.len()..].fill(0);

        // Step 5: a plaintext of at most one semiblock makes S a single block, which is enciphered
        // directly; a longer one goes through W.
        if plaintext.len() <= SEMIBLOCK_LEN {
            let (blocks, _) = s.as_chunks_mut::<KW_BLOCK_LEN>();
            perm.encrypt_block(&mut blocks[0]);
        } else {
            let (a, r) = s.split_at_mut(SEMIBLOCK_LEN);
            let (a, _) = a.as_chunks_mut::<SEMIBLOCK_LEN>();
            let (r, _) = r.as_chunks_mut::<SEMIBLOCK_LEN>();
            w(&perm, &mut a[0], r);
        }
        Ok(ct_len)
    }
}

impl<P, const KEK_LEN: usize> KeyUnwrapper<KEK_LEN> for Kwp<P, KEK_LEN>
where
    P: ElectronicCodeBook<KEK_LEN, KW_BLOCK_LEN>,
{
    /// KWP-AD with the lengths fixed at compile time; the same pairs as
    /// [`wrap_key_out`](KeyWrapper::wrap_key_out) are accepted.
    ///
    /// A ciphertext that unwraps to any length other than `KEY_LEN` -- which a valid `CT_LEN`
    /// allows, since up to eight plaintext lengths share one ciphertext length -- is reported as
    /// [`SymmetricCipherError::DecryptionFailed`], exactly as a forgery would be.
    fn unwrap_key_out<const KEY_LEN: usize, const CT_LEN: usize>(
        kek: &KeyMaterial<KEK_LEN>,
        ciphertext: &[u8; CT_LEN],
        key: &mut Secret<[u8; KEY_LEN]>,
    ) -> Result<usize, SymmetricCipherError> {
        const {
            assert!(
                kwp_plaintext_len_is_valid(KEY_LEN),
                "KWP unwraps to 1 to 2^32 - 1 bytes (SP 800-38F Table 1)"
            );
            assert!(
                CT_LEN == kwp_wrapped_len(KEY_LEN),
                "a KWP ciphertext is the plaintext rounded up to a multiple of 8 bytes, plus 8"
            );
        }
        // The padded plaintext can be up to 7 bytes longer than `key`, so unwrap into scratch
        // that is scrubbed on drop, and only copy out once the recovered length is the expected one.
        let mut padded: Secret<[u8; CT_LEN]> = Secret::new();
        match Self::unwrap_out(kek, ciphertext, &mut padded[..CT_LEN - SEMIBLOCK_LEN]) {
            Ok(recovered_len) if recovered_len == KEY_LEN => {
                key.copy_from_slice(&padded[..KEY_LEN]);
                Ok(KEY_LEN)
            }
            Ok(_) => {
                key.zeroize();
                Err(SymmetricCipherError::DecryptionFailed)
            }
            Err(e) => {
                key.zeroize();
                Err(e)
            }
        }
    }

    /// One semiblock less than the ciphertext: the padded plaintext, of which up to 7 bytes are
    /// padding, so this is an upper bound (module docs).
    fn unwrap_out_max_len(ciphertext_len: usize) -> usize {
        ciphertext_len.saturating_sub(SEMIBLOCK_LEN)
    }

    /// KWP-AD (SP 800-38F Algorithm 6).
    fn unwrap_out(
        kek: &KeyMaterial<KEK_LEN>,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        // 8(n-1) bytes: the padded plaintext.
        let padded_len = Self::unwrap_out_max_len(ciphertext.len());
        if plaintext.len() < padded_len {
            return Err(SymmetricCipherError::OutputBufferTooSmall(padded_len));
        }
        // Nothing this function writes may survive a failure, so start from zero.
        plaintext.fill(0);
        if !kwp_ciphertext_len_is_valid(ciphertext.len()) {
            return Err(SymmetricCipherError::InvalidInputLength(
                "a KWP ciphertext is 2 to 2^29 whole 8-byte semiblocks (SP 800-38F Table 1)",
            ));
        }
        let perm = P::new(kek)?;

        // Step 1: n, the number of semiblocks in C.
        let n = ciphertext.len() / SEMIBLOCK_LEN;
        // The header semiblock S1 goes to scratch that is scrubbed on return; S2..Sn -- the padded
        // plaintext -- go straight into the caller's buffer.
        let mut a: Secret<[u8; SEMIBLOCK_LEN]> = Secret::new();
        let r = &mut plaintext[..padded_len];
        // Step 3: a two-semiblock ciphertext is a single block, deciphered directly; a longer one
        // goes through W⁻¹.
        if n == 2 {
            let mut block: Secret<[u8; KW_BLOCK_LEN]> = Secret::new();
            block.copy_from_slice(ciphertext);
            perm.decrypt_block(&mut block);
            let (halves, _) = block.as_chunks::<SEMIBLOCK_LEN>();
            *a = halves[0];
            r.copy_from_slice(&halves[1]);
        } else {
            a.copy_from_slice(&ciphertext[..SEMIBLOCK_LEN]);
            r.copy_from_slice(&ciphertext[SEMIBLOCK_LEN..]);
            let (r, _) = r.as_chunks_mut::<SEMIBLOCK_LEN>();
            w_inv(&perm, &mut a, r);
        }

        // Steps 4-8: every check is made, and the verdicts combined with `&` rather than `&&`, so
        // that which one failed shows in neither the error nor the control flow (module docs).
        let (header, _) = a.as_chunks::<4>();
        // Step 4: MSB32(S) = ICV2, in constant time.
        let icv_ok = ct_eq_bytes(&header[0], &ICV2);
        // Step 5: Plen = int(LSB32(MSB64(S))).
        let plen = u32::from_be_bytes(header[1]) as usize;
        // Steps 6-7: padlen = 8(n-1) - Plen must be 0 to 7. Written so that no Plen can underflow.
        let len_ok = (plen <= padded_len) & (padded_len.wrapping_sub(plen) < SEMIBLOCK_LEN);
        // Step 8: LSB_{8 padlen}(S) = 0^{8 padlen}. Plen is clamped so an out-of-range value still
        // gives a well-defined (and, via `len_ok`, failing) check rather than a panic.
        let pad_ok = ct_eq_zero_bytes(&plaintext[plen.min(padded_len)..padded_len]);
        if !(icv_ok & len_ok & pad_ok) {
            plaintext.fill(0);
            return Err(SymmetricCipherError::DecryptionFailed);
        }
        // Step 9: P = MSB_{8 Plen}(LSB_{64(n-1)}(S)), already in place, followed by padding that
        // step 8 has just confirmed is zero.
        Ok(plen)
    }
}
