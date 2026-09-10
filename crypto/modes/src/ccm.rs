//! The CCM mode of operation: Counter with Cipher Block Chaining-Message Authentication Code
//! (NIST SP 800-38C, May 2004, errata update 07-20-2007).
//!
//! CCM is the one mode in this crate that is *authenticated*: it produces a tag as well as a
//! ciphertext, and decryption either returns the plaintext or refuses. It is built from two
//! mechanisms this crate already has, under a single key (Sec 5.2: "The same key, K, is used for
//! both the CTR and CBC-MAC mechanisms within CCM"):
//!
//! * **CTR** for confidentiality, over the counter blocks of Appendix A.3;
//! * **CBC-MAC** for authenticity, over the formatted blocks of Appendix A.2.
//!
//! Only the forward cipher function is ever used, in both directions (Sec 3: "Only the forward
//! cipher function of the block cipher algorithm is used within these primitives"), so a
//! permutation that implements nothing but `encrypt_block` works here.
//!
//! # The specification
//!
//! Sec 6.1, the generation-encryption process, quoted verbatim:
//!
//! ```text
//! 1.  Apply the formatting function to (N, A, P) to produce the blocks B0, B1, ..., Br.
//! 2.  Set Y0 = CIPH_K(B0).
//! 3.  For i = 1 to r, do Yi = CIPH_K(Bi XOR Yi-1).
//! 4.  Set T = MSB_Tlen(Yr).
//! 5.  Apply the counter generation function to generate the counter blocks Ctr0, Ctr1,
//!     ..., Ctrm, where m = ceil(Plen/128).
//! 6.  For j = 0 to m, do Sj = CIPH_K(Ctrj).
//! 7.  Set S = S1 || S2 || ... || Sm.
//! 8.  Return C = (P XOR MSB_Plen(S)) || (T XOR MSB_Tlen(S0)).
//! ```
//!
//! Sec 6.2, the decryption-verification process, quoted verbatim:
//!
//! ```text
//! 1.  If Clen <= Tlen, then return INVALID.
//! 2.  Apply the counter generation function to generate the counter blocks Ctr0, Ctr1,
//!     ..., Ctrm, where m = ceil((Clen - Tlen)/128).
//! 3.  For j = 0 to m, do Sj = CIPH_K(Ctrj).
//! 4.  Set S = S1 || S2 || ... || Sm.
//! 5.  Set P = MSB_Clen-Tlen(C) XOR MSB_Clen-Tlen(S).
//! 6.  Set T = LSB_Tlen(C) XOR MSB_Tlen(S0).
//! 7.  If N, A, or P is not valid, as discussed in Section 5.4, then return INVALID, else
//!     apply the formatting function to (N, A, P) to produce the blocks B0, B1, ..., Br.
//! 8.  Set Y0 = CIPH_K(B0).
//! 9.  For i = 1 to r, do Yj = CIPH_K(Bi XOR Yi-1).
//! 10. If T != MSB_Tlen(Yr), then return INVALID, else return P.
//! ```
//!
//! Note step 8's `T XOR MSB_Tlen(S0)`: the tag CCM transmits is the CBC-MAC value **encrypted**
//! under the counter block `Ctr0`, which is reserved for exactly that and never used for payload
//! keystream -- step 7 starts the payload at `S1`.
//!
//! ## Where the ciphertext ends and the tag begins
//!
//! Step 8 returns a single string, `ciphertext || tag`. This type offers both layouts: the inherent
//! [`Ccm::encrypt`] / [`Ccm::decrypt`] produce and consume the spec's own inline string, and the
//! detached pair [`Ccm::encrypt_detached`] / [`Ccm::decrypt_detached`] keeps the tag separate,
//! which is the shape [`AEADCipherEncryptor`] / [`AEADCipherDecryptor`] use.
//!
//! # Formatting: the parameters are the const generics
//!
//! Appendix A gives "an example of a formatting function and counter generation function"; Sec 5.4
//! permits others, but A's is the one every deployment of CCM uses -- it is what makes this
//! "essentially equivalent to the specification of CCM in the draft amendment to the IEEE Standard
//! 802.11" (Appendix A) -- and it is the only one implemented here. Its length conditions (A.1),
//! quoted verbatim:
//!
//! ```text
//! * t is an element of {4, 6, 8, 10, 12, 14, 16};
//! * q is an element of {2, 3, 4, 5, 6, 7, 8};
//! * n is an element of {7, 8, 9, 10, 11, 12, 13}
//! * n+q=15;
//! * a<2^64.
//! ```
//!
//! `t` is `TAG_LEN` and `n` is `NONCE_LEN`, so **`q` is not a parameter**: `n + q = 15` fixes it at
//! `15 - NONCE_LEN`, and A.1 says as much ("a choice for q determines the value of n, namely,
//! n=15-q"). All four of the first conditions are therefore properties of the const parameters and
//! are `const` assertions in the constructor: a `NONCE_LEN` or `TAG_LEN` A.1 does not permit is a
//! **compile** error at the call site, not a runtime `Err`. The fifth, `a < 2^64`, cannot be
//! violated by a `&[u8]` whose length is a `usize`, so there is nothing to check.
//!
//! ## `q` trades nonce space against payload size
//!
//! Because `n + q = 15`, a longer nonce means a shorter length field, and `q` bounds the payload:
//! A.1's "by definition, p<2^8q". A.1 calls this "a tradeoff between the maximum number of
//! invocations of CCM under a given key and the maximum payload length for those invocations":
//!
//! | `NONCE_LEN` (n) | q | max payload |
//! |---|---|---|
//! | 7 | 8 | 2^64 - 1 bytes (no bound in practice) |
//! | 11 | 4 | 4 GiB - 1 |
//! | 12 | 3 | 16 MiB - 1 |
//! | 13 | 2 | 64 KiB - 1 |
//!
//! A payload past that limit is refused with [`SymmetricCipherError::GenericError`]: both the
//! counter and the length field `Q` would overflow, and `Q` is what the MAC commits to.
//!
//! # CCM is not a streaming mode, and what this crate does about it
//!
//! Sec 3 is explicit:
//!
//! > CCM is intended for use in a packet environment, i.e., when all of the data is available in
//! > storage before CCM is applied; CCM is not designed to support partial processing or stream
//! > processing.
//!
//! The reason is `B0`. Appendix A.2.1 puts `Q`, the payload's octet length, *inside the first block
//! the CBC-MAC absorbs*, so nothing at all can be authenticated until the total payload length is
//! known. [`Ctr`](crate::Ctr) and [`Cfb`](crate::Cfb) can hash as they go; CCM structurally cannot.
//!
//! There are exactly two honest ways to live with that, and this module provides both:
//!
//! 1. **Declare the length up front.** [`Ccm::new`] takes the whole AAD and the payload length, so
//!    `B0` is formed at construction and everything after it streams with **no buffering at all**:
//!    each byte is MACed and XORed as it arrives, and the payload may be any length up to the `q`
//!    limit. This is the efficient path and the one the one-shots use.
//! 2. **Buffer.** [`CcmEncryptor`] / [`CcmDecryptor`] implement [`AEADCipherEncryptor`] /
//!    [`AEADCipherDecryptor`], whose `do_encrypt_init` is handed a key and nothing else, so they
//!    have no length from which to form `B0`. They accumulate the message in a fixed
//!    `BUFFER_LEN`-byte array and do all the work at finalization. That is a real cost -- see
//!    those types' docs -- and it is the price of the generic AEAD API, not of CCM.
//!
//! A caller who reaches for CCM at all is in Sec 3's packet environment and knows the length, so
//! (1) is the one to use; (2) exists so that CCM composes with code written against the trait.
//!
//! # Security considerations
//!
//! **The nonce must never repeat under one key.** Sec 5.3: "any two distinct data pairs to be
//! protected by CCM during the lifetime of the key shall be assigned distinct nonces". A repeat is
//! worse here than in an unauthenticated mode: it reuses the CTR keystream, and Appendix B.1's
//! footnote describes the resulting forgery -- an attacker who can "induce the
//! decryption-verification process to reuse the nonce" can flip any chosen bit of the payload. The
//! nonce is *not* required to be random ("The nonce is not required to be random"), only unique, so
//! a counter is a valid and often better choice; every deterministic entry point here takes the
//! nonce from the caller, and the entry points that generate one draw it from the library's DRBG.
//!
//! **`TAG_LEN` is a security parameter.** Sec B.2: "a value of Tlen that is less than 64 shall not
//! be used without a careful analysis of the risks of accepting inauthentic data as authentic", and
//! it gives the bound `Tlen >= lg(MaxErrs / Risk)`. A `TAG_LEN` of 4 or 6 is permitted by A.1 and
//! accepted here, because protocols and the ACVP vectors use short tags; prefer 16.
//!
//! **The key is for CCM only.** Sec 5.1: "The key shall be kept secret and shall only be used for
//! the CCM mode", and "The total number of invocations of the block cipher algorithm during the
//! lifetime of the key shall be limited to 2^61".
//!
//! **A failed tag check reveals nothing.** Sec 6.2: "the payload P and the MAC T shall not be
//! revealed", and an unauthorized party must not be able to distinguish a step 7 failure from a
//! step 10 failure, "for example, from the timing of the error message". Step 7 cannot fail here --
//! the const parameters and the declared length make `N`, `A` and `P` valid by construction -- so
//! there is only one failure path, the constant-time comparison in [`Ccm::do_decrypt_final`]. The
//! one-shots zeroize the plaintext buffer before returning the error. The streaming API cannot; see
//! [`AEADCipherDecryptor`]'s own warning that what `do_update_out` released is not authenticated
//! until the final call returns `Ok`.

use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, Algorithm, ElectronicCodeBook, RNG, SecurityStrength,
};
use bouncycastle_rng::HashDRBG_SHA512;
use bouncycastle_utils::ct::ct_eq_bytes;
use bouncycastle_utils::secret::Secret;
use core::marker::PhantomData;

use crate::{Decrypting, Encrypting};

/// CCM (SP 800-38C) over any [`ElectronicCodeBook`] with a 128-bit block.
///
/// `NONCE_LEN` is the spec's `n` and `TAG_LEN` its `t`; `q`, the width of the length field, is
/// `15 - NONCE_LEN`, because A.1 requires `n + q = 15`. See the module docs for the permitted
/// values -- all checked at compile time -- and for the payload limit `q` implies.
///
/// `Dir` is [`Encrypting`] or [`Decrypting`], exactly as for the other modes in this crate:
/// `Ccm<P, Encrypting, ..>` has Sec 6.1's methods and nothing else, and `Ccm<P, Decrypting, ..>`
/// has Sec 6.2's. Using the wrong direction is a compile error rather than a runtime one, and there
/// is no state to police: pointing a decryptor at a plaintext is not a mistake this type can be
/// asked to make.
///
/// [`CcmEncryptor`] and [`CcmDecryptor`] wrap these for the generic
/// [`AEADCipherEncryptor`] / [`AEADCipherDecryptor`] traits, at the cost of buffering; see the
/// module docs.
///
/// Asking an encryptor to verify a tag does not compile -- `do_decrypt_final` exists only on
/// `Ccm<P, Decrypting, ..>`:
///
/// ```compile_fail
/// use bouncycastle_aes::AES_128;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_modes::{Ccm, Encrypting};
///
/// let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
///     .unwrap();
/// let ccm = Ccm::<AES_128, Encrypting, 16, 16, 12, 16>::new(&key, &[0u8; 12], &[], 0).unwrap();
/// ccm.do_decrypt_final(&[0u8; 16]).unwrap();
/// ```
///
/// And nor does the reverse -- a decryptor has no `do_encrypt_final`, so it cannot be tricked into
/// producing a tag over data it never encrypted:
///
/// ```compile_fail
/// use bouncycastle_aes::AES_128;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_modes::{Ccm, Decrypting};
///
/// let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
///     .unwrap();
/// let ccm = Ccm::<AES_128, Decrypting, 16, 16, 12, 16>::new(&key, &[0u8; 12], &[], 0).unwrap();
/// let _tag = ccm.do_encrypt_final().unwrap();
/// ```
///
/// A nonce length A.1 does not permit does not compile:
///
/// ```compile_fail
/// use bouncycastle_aes::AES_128;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_modes::{Ccm, Encrypting};
///
/// let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
///     .unwrap();
/// // n = 6 is not in {7, ..., 13}: it would make q = 9, which A.1 does not allow.
/// let _ = Ccm::<AES_128, Encrypting, 16, 16, 6, 16>::new(&key, &[0u8; 6], &[], 0);
/// ```
///
/// Nor does an odd tag length:
///
/// ```compile_fail
/// use bouncycastle_aes::AES_128;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_modes::{Ccm, Encrypting};
///
/// let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
///     .unwrap();
/// // t = 15 is not in {4, 6, 8, 10, 12, 14, 16}.
/// let _ = Ccm::<AES_128, Encrypting, 16, 16, 12, 15>::new(&key, &[0u8; 12], &[], 0);
/// ```
pub struct Ccm<
    P,
    Dir,
    const KEY_LEN: usize,
    const BLOCK_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
> where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    perm: P,
    // The CBC-MAC chaining value: `Y0` once the constructor has absorbed `B0` (Sec 6.1 step 2),
    // then `Yi` as further blocks arrive (step 3). Bytes are XORed into it in place, so part-way
    // through a block it holds `Yi-1 XOR (the part of Bi seen so far)`.
    y: [u8; BLOCK_LEN],
    // How many bytes of the current CBC-MAC input block have been XORed into `y`.
    mac_pos: usize,
    // `Ctr_i` with its counter field zeroed (A.3, Table 3): the flags octet and the nonce, which
    // are the same in every counter block. Public data -- flags and nonce travel in the clear --
    // so deliberately not a `Secret`.
    ctr_template: [u8; BLOCK_LEN],
    // The current keystream block `Sj` and how much of it has been consumed. Live keystream for
    // the payload bytes still to come, so it is zeroized on drop for the same reason `Ctr`'s is.
    ks: Secret<[u8; BLOCK_LEN]>,
    ks_pos: usize,
    // The index `j` of the next keystream block. Starts at 1: step 7 sets `S = S1 || ... || Sm`,
    // and `S0` is reserved for the tag.
    next_ctr: u64,
    // How much of the payload length declared to `new` has not yet been supplied. That length is
    // committed to inside `B0`, so supplying a different amount would authenticate a message no
    // verifier could reproduce; both directions refuse instead of doing it.
    owed: usize,
    // Which of the two Sec 6 processes this value runs. Zero-sized: the direction costs no memory.
    _dir: PhantomData<Dir>,
}

impl<
    P,
    Dir,
    const KEY_LEN: usize,
    const BLOCK_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
> Ccm<P, Dir, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    /// The spec's `q`: the octet length of the payload-length field `Q`. A.1 requires `n + q = 15`.
    const Q_LEN: usize = 15 - NONCE_LEN;

    /// The largest payload this parameterization can carry, from A.1's "by definition, p<2^8q".
    ///
    /// `q = 8` would make `2^8q` exactly `2^64`, which does not fit a `u64`; there the bound is
    /// `p <= 2^64 - 1`, i.e. `u64::MAX`, which is no bound at all on a `usize` length.
    const MAX_PAYLOAD_LEN: u64 =
        if Self::Q_LEN >= 8 { u64::MAX } else { (1u64 << (8 * Self::Q_LEN)) - 1 };

    /// The compile-time shape check, from Appendix A.1 and Sec 5.1; run from the constructor.
    ///
    /// Every one of these is a property of the const parameters alone, so each is a compile error
    /// at the call site. `q` is not checked separately: `NONCE_LEN` in `7..=13` with `q = 15 - n`
    /// gives exactly A.1's `q` in `2..=8`.
    #[inline]
    fn check_shape() {
        const {
            // Sec 5.1: "For CCM, the block size of the block cipher algorithm shall be 128 bits".
            assert!(
                BLOCK_LEN == 16,
                "CCM requires a 128-bit block cipher (SP 800-38C Sec 5.1): BLOCK_LEN must be 16"
            );
            // A.1: "n is an element of {7, 8, 9, 10, 11, 12, 13}".
            assert!(
                NONCE_LEN >= 7 && NONCE_LEN <= 13,
                "CCM nonce length must be 7..=13 bytes (SP 800-38C A.1)"
            );
            // A.1: "t is an element of {4, 6, 8, 10, 12, 14, 16}", i.e. even and in 4..=16. Sec 5.4
            // gives the same lower bound from the other side: "No value of Tlen smaller than 32
            // shall be valid".
            assert!(
                TAG_LEN >= 4 && TAG_LEN <= 16 && TAG_LEN % 2 == 0,
                "CCM tag length must be one of 4, 6, 8, 10, 12, 14, 16 bytes (SP 800-38C A.1)"
            );
        };
    }

    /// Validates a [`KeyMaterial`] and expands it into the permutation's key schedule.
    ///
    /// The strength check is [`ElectronicCodeBook::new`]'s; this adds the [`KeyType`] check that
    /// the trait leaves to the mode.
    fn checked_perm(key: &KeyMaterial<KEY_LEN>) -> Result<P, SymmetricCipherError> {
        if key.key_type() != KeyType::SymmetricCipherKey {
            return Err(
                KeyMaterialError::InvalidKeyType("CCM requires a SymmetricCipherKey").into()
            );
        }
        P::new(key)
    }

    /// Draws a nonce from `rng`, for [`CcmEncryptor`]'s constructors.
    ///
    /// Sec 5.3 requires uniqueness, not randomness, but a CSPRNG draw is the only way to be unique
    /// without state the trait's `do_encrypt_init` does not have. Every entry point that takes the
    /// nonce from the caller instead is the better one where the caller can guarantee uniqueness
    /// itself; see the module's security considerations.
    fn nonce_from_rng(rng: &mut dyn RNG) -> Result<[u8; NONCE_LEN], SymmetricCipherError> {
        let mut nonce = [0u8; NONCE_LEN];
        rng.next_bytes_out(&mut nonce)?;
        Ok(nonce)
    }

    /// Begins a CCM flow: formats `B0`, absorbs it and all of `A` into the CBC-MAC, and readies the
    /// counter blocks. Everything after this streams without buffering.
    ///
    /// The whole AAD is taken here, and `payload_len` declared here, because Appendix A.2.1 puts the
    /// payload length inside `B0` and A.2.2 puts the AAD length in front of the AAD: neither can be
    /// encoded incrementally. See the module docs.
    ///
    /// * `key` must be a [`KeyType::SymmetricCipherKey`] of at least the permutation's strength.
    /// * `nonce` **must not** repeat under `key`; see the module's security considerations.
    /// * `aad` is authenticated but not encrypted, and may be empty.
    /// * `payload_len` is the exact number of payload bytes that will follow. Supplying any other
    ///   amount is refused, at the update or at finalization.
    ///
    /// # Errors
    /// [`SymmetricCipherError::KeyMaterialError`] for a key of the wrong type or strength, and
    /// [`SymmetricCipherError::GenericError`] if `payload_len` exceeds A.1's `2^8q - 1`; see
    /// [`Ccm`] for the table.
    pub fn new(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        payload_len: usize,
    ) -> Result<Self, SymmetricCipherError> {
        // The shape check and the payload-limit check both belong to `from_perm`, which is the one
        // path every construction goes through; duplicating them here would be two more `Err`
        // sites that could drift apart from it.
        let perm = Self::checked_perm(key)?;
        Self::from_perm(perm, nonce, aad, payload_len)
    }

    /// As [`Self::new`], from a key schedule that has already been expanded and a payload length
    /// that has already been checked against [`Self::MAX_PAYLOAD_LEN`].
    ///
    /// This is what [`CcmEncryptor`] / [`CcmDecryptor`] call at finalization: they expand the key
    /// once in their own constructor, long before they know the payload length, and hand the
    /// schedule over here rather than storing the [`KeyMaterial`] and re-expanding it.
    fn from_perm(
        perm: P,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        payload_len: usize,
    ) -> Result<Self, SymmetricCipherError> {
        Self::check_shape();
        if payload_len as u64 > Self::MAX_PAYLOAD_LEN {
            return Err(SymmetricCipherError::GenericError(
                "CCM payload longer than 2^8q - 1, the limit the nonce length implies (A.1)",
            ));
        }

        // A.3, Tables 3 and 4: `Ctr_i` is `Flags || N || [i]_8q`, and its flags octet has both
        // reserved bits and bits 3, 4 and 5 zero -- "to ensure that all the counter blocks are
        // distinct from B0", whose bits 3..5 encode `t` and so cannot all be zero -- leaving bits
        // 0..2 to hold "the same encoding of q as in B0".
        let mut ctr_template = [0u8; BLOCK_LEN];
        ctr_template[0] = (Self::Q_LEN - 1) as u8;
        ctr_template[1..1 + NONCE_LEN].copy_from_slice(nonce);

        let mut ccm = Self {
            perm,
            // Sec 6.1 step 2 is `Y0 = CIPH_K(B0)`, with no XOR, unlike step 3's `Bi XOR Yi-1`.
            // Starting the chaining value at zero unifies the two: `B0 XOR 0 = B0`, so absorbing
            // `B0` through the same path as every other block yields exactly `Y0`.
            y: [0u8; BLOCK_LEN],
            mac_pos: 0,
            ctr_template,
            ks: Secret::new(),
            // Nothing buffered; the first payload byte forces a refill.
            ks_pos: BLOCK_LEN,
            next_ctr: 1,
            owed: payload_len,
            _dir: PhantomData,
        };

        ccm.mac_absorb(&Self::format_b0(nonce, !aad.is_empty(), payload_len as u64));

        // A.2.2: if `a > 0`, "the encoding of a is concatenated with the associated data A,
        // followed by the minimum number of '0' bits, possibly none, such that the resulting string
        // can be partitioned into 16-octet blocks". If `a = 0` there are no AAD blocks at all, so
        // nothing is absorbed and nothing is padded.
        if !aad.is_empty() {
            let (encoded, encoded_len) = Self::encode_aad_len(aad.len() as u64);
            ccm.mac_absorb(&encoded[..encoded_len]);
            ccm.mac_absorb(aad);
            // The AAD's own blocks `B1 ... Bu` end on a block boundary, and A.2.3's payload blocks
            // are `Bu+1 ...`. So the zero pad happens *here*, not once at the very end.
            ccm.mac_pad();
        }

        Ok(ccm)
    }

    /// The encoding of `a`, the AAD's octet length, which A.2.2 places in front of the AAD.
    ///
    /// Returns the bytes and how many of them are used; the buffer is sized for the longest case.
    /// A.2.2 gives three, quoted verbatim:
    ///
    /// ```text
    /// * If 0 < a < 2^16-2^8, then a is encoded as [a]_16, i.e., two octets.
    /// * If 2^16-2^8 <= a < 2^32, then a is encoded as 0xff || 0xfe || [a]_32, i.e., six octets.
    /// * If 2^32 <= a < 2^64, then a is encoded as 0xff || 0xff || [a]_64, i.e., ten octets.
    /// ```
    ///
    /// The first boundary is `2^16 - 2^8` (65280), **not** `2^16`: A.2.2 reserves the encodings
    /// whose first octet is `0xff` so that the three cases can be told apart, and `[a]_16` for
    /// `a >= 65280` would collide with them ("in the first case, the first octet will not be 0xff
    /// as it will for the second and third cases"). Getting that bound wrong is the kind of error
    /// that only shows up on a 64 KiB AAD, which is why this is a separate function with its own
    /// tests rather than three inline branches: the third case's `2^32` boundary is not reachable
    /// through the public API at all without a 4 GiB allocation, but it is trivially reachable here.
    ///
    /// `a` is a `usize` at every call site, so A.1's `a < 2^64` holds for free and there is nothing
    /// to reject; the third case is reachable in practice only on a target with a >32-bit `usize`.
    #[inline]
    fn encode_aad_len(a: u64) -> ([u8; 10], usize) {
        let mut out = [0u8; 10];
        if a < (1 << 16) - (1 << 8) {
            out[..2].copy_from_slice(&(a as u16).to_be_bytes());
            (out, 2)
        } else if a < (1u64 << 32) {
            out[0] = 0xff;
            out[1] = 0xfe;
            out[2..6].copy_from_slice(&(a as u32).to_be_bytes());
            (out, 6)
        } else {
            out[0] = 0xff;
            out[1] = 0xff;
            out[2..10].copy_from_slice(&a.to_be_bytes());
            (out, 10)
        }
    }

    /// `B0`, the first block of the formatted input (A.2.1).
    ///
    /// Table 1 gives the flags octet:
    ///
    /// ```text
    /// Bit number  7         6      5   4   3   2   1   0
    /// Contents    Reserved  Adata  [(t-2)/2]_3    [q-1]_3
    /// ```
    ///
    /// with the Reserved bit "reserved to enable future extensions of the formatting; it shall be
    /// set to '0'", and A.2.2's rule for the other flag: "The Adata bit is '0' if a=0 and '1' if
    /// a>0", which is what `has_aad` carries. Table 2 gives the rest:
    ///
    /// ```text
    /// Octet number  0      1 ... 15-q  16-q ... 15
    /// Contents      Flags  N           Q
    /// ```
    ///
    /// Neither three-bit field can be zero -- A.1 notes "the encoding 000 in both cases does not
    /// correspond to a permitted value of t or q" -- which is what [`Self::check_shape`] enforces
    /// and what keeps `B0` distinct from every counter block (A.3).
    #[inline]
    fn format_b0(nonce: &[u8; NONCE_LEN], has_aad: bool, payload_len: u64) -> [u8; BLOCK_LEN] {
        let mut b0 = [0u8; BLOCK_LEN];
        // The three fields occupy disjoint bit ranges -- bit 6, bits 5-3, bits 2-0 -- and
        // `check_shape` bounds the two encoded values so neither can overflow its field. So these
        // `|`s are exactly equivalent to `^`, and `cargo mutants` reports that substitution as a
        // surviving mutant; it is one of the OR/XOR equivalences CLAUDE.md calls acceptable, not a
        // gap in the tests. `|` is written because these are field assignments, not a combination.
        b0[0] = (u8::from(has_aad) << 6)
            | ((((TAG_LEN - 2) / 2) as u8) << 3)
            | ((Self::Q_LEN - 1) as u8);
        b0[1..1 + NONCE_LEN].copy_from_slice(nonce);
        Self::put_q_field(&mut b0, payload_len);
        b0
    }

    /// Writes `[x]_8q` into the trailing `Q_LEN` octets of `block`: the `Q` field of `B0` (A.2.1,
    /// Table 2) and the counter field of `Ctr_i` (A.3, Table 3), which occupy the same octets.
    ///
    /// `Q_LEN <= 8`, so the low `Q_LEN` bytes of a big-endian `u64` are exactly `[x]_8q`. Nothing
    /// is ever truncated in a way that matters: [`Self::new`] refuses a payload above
    /// [`Self::MAX_PAYLOAD_LEN`], and the counter cannot pass that either, since there is one
    /// counter block per `BLOCK_LEN` payload bytes.
    #[inline]
    fn put_q_field(block: &mut [u8; BLOCK_LEN], x: u64) {
        let be = x.to_be_bytes();
        block[BLOCK_LEN - Self::Q_LEN..].copy_from_slice(&be[8 - Self::Q_LEN..]);
    }

    /// Absorbs `data` into the CBC-MAC as the next bytes of the formatted block string.
    ///
    /// Implements Sec 6.1 steps 2 and 3 together, incrementally: bytes are XORed into `y` at
    /// `mac_pos`, and each time a whole block has gone in, `CIPH_K` is applied. Since `y` holds
    /// `Yi-1` when a block starts, XORing `Bi` in byte by byte and then enciphering is exactly
    /// `Yi = CIPH_K(Bi XOR Yi-1)`, whatever chunking `data` arrives in.
    #[inline]
    fn mac_absorb(&mut self, data: &[u8]) {
        let mut rest = data;
        while !rest.is_empty() {
            let take = core::cmp::min(BLOCK_LEN - self.mac_pos, rest.len());
            let (now, later) = rest.split_at(take);
            for (slot, b) in self.y[self.mac_pos..].iter_mut().zip(now) {
                *slot ^= *b;
            }
            self.mac_pos += take;
            if self.mac_pos == BLOCK_LEN {
                self.perm.encrypt_block(&mut self.y);
                self.mac_pos = 0;
            }
            rest = later;
        }
    }

    /// Finishes a partly-filled CBC-MAC block by zero-padding it: A.2.2 for the AAD and A.2.3 for
    /// the payload, both "concatenated with the minimum number of '0' bits, possibly none".
    ///
    /// The pad itself is free. [`Self::mac_absorb`] XORs into `y`, and XORing zero changes nothing,
    /// so all that is left to do is apply `CIPH_K` to the block already sitting there. "Possibly
    /// none" is the `mac_pos == 0` case, where the string already ends on a block boundary and
    /// adding a whole block of zeros would be wrong.
    #[inline]
    fn mac_pad(&mut self) {
        if self.mac_pos != 0 {
            self.perm.encrypt_block(&mut self.y);
            self.mac_pos = 0;
        }
    }

    /// Generates the next keystream block, `Sj = CIPH_K(Ctrj)` for the current `j` (Sec 6.1
    /// steps 5-6), and advances `j`.
    #[inline]
    fn refill_keystream(&mut self) {
        let mut ctr = self.ctr_template;
        Self::put_q_field(&mut ctr, self.next_ctr);
        *self.ks = ctr;
        self.perm.encrypt_block(&mut self.ks);
        self.next_ctr += 1;
        self.ks_pos = 0;
    }

    /// XORs `data` in place with the next `data.len()` bytes of `S1 || S2 || ...`.
    ///
    /// This is step 8's `P XOR MSB_Plen(S)` and Sec 6.2 step 5's `MSB(C) XOR MSB(S)` -- the same
    /// operation, which is why one function serves both directions. A call may start and end
    /// part-way through a keystream block, so the caller's chunking is invisible in the output, and
    /// only the tail of the very last block is ever discarded.
    #[inline]
    fn apply_keystream(&mut self, data: &mut [u8]) {
        let mut rest = data;
        while !rest.is_empty() {
            if self.ks_pos == BLOCK_LEN {
                self.refill_keystream();
            }
            let take = core::cmp::min(BLOCK_LEN - self.ks_pos, rest.len());
            let (now, later) = rest.split_at_mut(take);
            for (b, k) in now.iter_mut().zip(self.ks[self.ks_pos..].iter()) {
                *b ^= *k;
            }
            self.ks_pos += take;
            rest = later;
        }
    }

    /// Debits `len` bytes from the payload length declared to [`Self::new`].
    #[inline]
    fn take_owed(&mut self, len: usize) -> Result<(), SymmetricCipherError> {
        if len > self.owed {
            return Err(SymmetricCipherError::StateError(
                "CCM was given more payload than the length declared to `new`, which B0 commits to",
            ));
        }
        self.owed -= len;
        Ok(())
    }

    /// Completes the CBC-MAC and returns the transmitted tag: step 4's `T = MSB_Tlen(Yr)`,
    /// encrypted as step 8's `T XOR MSB_Tlen(S0)`.
    ///
    /// `S0 = CIPH_K(Ctr0)` is computed here rather than at construction because `Ctr0` is used
    /// exactly once, at the end; the payload keystream starts at `S1` (step 7).
    fn finish_mac(mut self) -> [u8; TAG_LEN] {
        // A.2.3: the payload's own blocks are zero-padded to a block boundary.
        self.mac_pad();

        let mut s0 = self.ctr_template;
        Self::put_q_field(&mut s0, 0);
        self.perm.encrypt_block(&mut s0);

        // `MSB_Tlen` of a byte-aligned value is its first `TAG_LEN` bytes; A.1 makes `t` an octet
        // count, so `Tlen` is always a multiple of 8 here.
        let mut tag = [0u8; TAG_LEN];
        for (t, (y, s)) in tag.iter_mut().zip(self.y.iter().zip(s0.iter())) {
            *t = *y ^ *s;
        }
        tag
    }
}

/// Sec 6.1, the generation-encryption process. Present only on the encrypting direction, so a
/// decryptor cannot be asked to produce a tag.
impl<P, const KEY_LEN: usize, const BLOCK_LEN: usize, const NONCE_LEN: usize, const TAG_LEN: usize>
    Ccm<P, Encrypting, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    /// Encrypts `data` in place and authenticates it.
    ///
    /// Step 8 XORs the *plaintext* with the keystream, and step 1 formats the *plaintext* into the
    /// blocks the MAC covers, so the plaintext is absorbed before it is overwritten.
    ///
    /// # Errors
    /// [`SymmetricCipherError::StateError`] if `data` would take the total past the declared
    /// payload length.
    pub fn do_encrypt_update(&mut self, data: &mut [u8]) -> Result<(), SymmetricCipherError> {
        self.take_owed(data.len())?;
        self.mac_absorb(data);
        self.apply_keystream(data);
        Ok(())
    }

    /// Finishes an encryption and returns the tag (Sec 6.1 steps 4 and 8).
    ///
    /// # Errors
    /// [`SymmetricCipherError::StateError`] if less payload was supplied than the length declared
    /// to [`Self::new`] -- `B0` commits to that length, so a short message would produce a tag no
    /// verifier could reproduce.
    pub fn do_encrypt_final(self) -> Result<[u8; TAG_LEN], SymmetricCipherError> {
        if self.owed != 0 {
            return Err(SymmetricCipherError::StateError(
                "CCM was given less payload than the length declared to `new`, which B0 commits to",
            ));
        }
        Ok(self.finish_mac())
    }

    /// One-shot generation-encryption with a **detached** tag (Sec 6.1).
    ///
    /// Writes `plaintext.len()` bytes of ciphertext into `ciphertext` and returns that count with
    /// the tag. For the spec's own inline `ciphertext || tag` string, use [`Self::encrypt`].
    ///
    /// # Errors
    /// [`SymmetricCipherError::IncorrectOutputBufferLength`] if `ciphertext` is too short, plus
    /// [`Self::new`]'s errors.
    pub fn encrypt_detached(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<(usize, [u8; TAG_LEN]), SymmetricCipherError> {
        if ciphertext.len() < plaintext.len() {
            return Err(SymmetricCipherError::IncorrectOutputBufferLength(
                "ciphertext",
                plaintext.len(),
            ));
        }
        let mut ccm = Self::new(key, nonce, aad, plaintext.len())?;
        let out = &mut ciphertext[..plaintext.len()];
        out.copy_from_slice(plaintext);
        ccm.do_encrypt_update(out)?;
        let tag = ccm.do_encrypt_final()?;
        Ok((plaintext.len(), tag))
    }

    /// One-shot generation-encryption producing the spec's own output string (Sec 6.1 step 8):
    /// `C = (P XOR MSB_Plen(S)) || (T XOR MSB_Tlen(S0))`, i.e. `ciphertext || tag` inline.
    ///
    /// `ciphertext` needs `plaintext.len() + TAG_LEN` bytes; the return is how many were written.
    ///
    /// # Errors
    /// As [`Self::encrypt_detached`].
    pub fn encrypt(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        let needed = plaintext.len() + TAG_LEN;
        if ciphertext.len() < needed {
            return Err(SymmetricCipherError::IncorrectOutputBufferLength("ciphertext", needed));
        }
        let (data, tag_out) = ciphertext[..needed].split_at_mut(plaintext.len());
        let (_, tag) = Self::encrypt_detached(key, nonce, aad, plaintext, data)?;
        tag_out.copy_from_slice(&tag);
        Ok(needed)
    }
}

/// Sec 6.2, the decryption-verification process. Present only on the decrypting direction, so an
/// encryptor cannot be asked to verify a tag.
impl<P, const KEY_LEN: usize, const BLOCK_LEN: usize, const NONCE_LEN: usize, const TAG_LEN: usize>
    Ccm<P, Decrypting, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    /// Decrypts `data` in place and authenticates the recovered plaintext.
    ///
    /// The mirror of [`Self::do_encrypt_update`] with the two steps swapped: Sec 6.2 recovers `P` in
    /// step 5 and only then formats `(N, A, P)` in step 7, so the MAC is fed the plaintext here too,
    /// never the ciphertext.
    ///
    /// The bytes this writes are **not authenticated** until [`Self::do_decrypt_final`] returns
    /// `Ok`.
    ///
    /// # Errors
    /// [`SymmetricCipherError::StateError`] if `data` would take the total past the declared
    /// payload length.
    pub fn do_decrypt_update(&mut self, data: &mut [u8]) -> Result<(), SymmetricCipherError> {
        self.take_owed(data.len())?;
        self.apply_keystream(data);
        self.mac_absorb(data);
        Ok(())
    }

    /// Finishes a decryption by checking `tag`: Sec 6.2 step 10, "If T != MSB_Tlen(Yr), then return
    /// INVALID, else return P".
    ///
    /// The comparison is [`ct_eq_bytes`], so it does not leak how much of the tag matched. Sec 6.2
    /// also requires that a caller cannot tell step 7's failure from step 10's; step 7 cannot fail
    /// here, so there is nothing to distinguish -- see the module's security considerations.
    ///
    /// # Errors
    /// [`SymmetricCipherError::AEADTagCheckFailed`] if the tag does not verify, and
    /// [`SymmetricCipherError::StateError`] if less ciphertext was supplied than the length declared
    /// to [`Self::new`].
    pub fn do_decrypt_final(self, tag: &[u8; TAG_LEN]) -> Result<(), SymmetricCipherError> {
        if self.owed != 0 {
            return Err(SymmetricCipherError::StateError(
                "CCM was given less ciphertext than the length declared to `new`, which B0 commits to",
            ));
        }
        if ct_eq_bytes(&self.finish_mac(), tag) {
            Ok(())
        } else {
            Err(SymmetricCipherError::AEADTagCheckFailed)
        }
    }

    /// One-shot decryption-verification with a **detached** tag (Sec 6.2).
    ///
    /// On failure `plaintext` is zeroized before the error is returned, so Sec 6.2's "the payload P
    /// and the MAC T shall not be revealed" holds even for a caller who ignores the `Result`.
    ///
    /// # Errors
    /// [`SymmetricCipherError::AEADTagCheckFailed`] if the tag does not verify,
    /// [`SymmetricCipherError::IncorrectOutputBufferLength`] if `plaintext` is too short, plus
    /// [`Self::new`]'s errors.
    pub fn decrypt_detached(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; TAG_LEN],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        if plaintext.len() < ciphertext.len() {
            return Err(SymmetricCipherError::IncorrectOutputBufferLength(
                "plaintext",
                ciphertext.len(),
            ));
        }
        let mut ccm = Self::new(key, nonce, aad, ciphertext.len())?;
        let out = &mut plaintext[..ciphertext.len()];
        out.copy_from_slice(ciphertext);
        ccm.do_decrypt_update(out)?;
        match ccm.do_decrypt_final(tag) {
            Ok(()) => Ok(ciphertext.len()),
            Err(e) => {
                // Sec 6.2: on INVALID the payload "shall not be revealed". A plain `fill` because
                // this crate is `#![forbid(unsafe_code)]`; the store is to the caller's own buffer,
                // which the caller may read after this returns, so it is not a dead store the
                // optimizer is entitled to drop.
                out.fill(0);
                Err(e)
            }
        }
    }

    /// One-shot decryption-verification of the spec's own output string (Sec 6.2), splitting the
    /// trailing `TAG_LEN` bytes off `ciphertext` as the tag -- step 6's `LSB_Tlen(C)`.
    ///
    /// # Errors
    /// [`SymmetricCipherError::GenericError`] for Sec 6.2 step 1, "If Clen <= Tlen, then return
    /// INVALID", which is a malformed input rather than a failed check; otherwise as
    /// [`Self::decrypt_detached`].
    pub fn decrypt(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        // Sec 6.2 step 1, "If Clen <= Tlen, then return INVALID", and the split of step 6's
        // `LSB_Tlen(C)` off the end, in one operation: `split_last_chunk` is `None` exactly when
        // the string is too short to contain a tag, and otherwise hands back the tag already typed
        // as `&[u8; TAG_LEN]`. Doing it in two steps would leave an arithmetic split followed by an
        // array conversion that cannot fail but still has to be handled.
        //
        // Note the spec's `Clen <= Tlen` is on the *bit* lengths of a string that also carries the
        // payload; a `C` of exactly `TAG_LEN` octets is an empty payload plus its tag, which is
        // valid -- Sec 5.3's footnote, "The payload may also be empty". So the octet test here
        // admits equality, which is what `split_last_chunk` does.
        let Some((data, tag)) = ciphertext.split_last_chunk::<TAG_LEN>() else {
            return Err(SymmetricCipherError::GenericError(
                "CCM ciphertext shorter than the tag (SP 800-38C Sec 6.2 step 1)",
            ));
        };
        Self::decrypt_detached(key, nonce, aad, data, tag, plaintext)
    }
}

impl<
    P,
    Dir,
    const KEY_LEN: usize,
    const BLOCK_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
> Algorithm for Ccm<P, Dir, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    /// The underlying permutation's name. The mode is not appended: `&'static str`s cannot be
    /// concatenated in a `const`, and the mode is already in the type.
    const ALG_NAME: &'static str = P::ALG_NAME;
    /// A mode does not change the strength of the underlying cipher.
    const MAX_SECURITY_STRENGTH: SecurityStrength = P::MAX_SECURITY_STRENGTH;
}

/// Adapts [`Ccm`] to [`AEADCipherEncryptor`] by buffering the whole message.
///
/// [`AEADCipherEncryptor::do_encrypt_init`] is handed a key and nothing else, but CCM cannot form
/// `B0` -- and so cannot authenticate anything at all -- until it knows the total payload length
/// (Appendix A.2.1; see the module docs). This type therefore accumulates the AAD and the payload
/// in two `BUFFER_LEN`-byte arrays and runs the whole of Sec 6.1 in
/// [`do_encrypt_final`](AEADCipherEncryptor::do_encrypt_final), which is why `FINAL_LEN` is
/// `BUFFER_LEN`: every ciphertext byte is "flushed at finalization", and
/// [`update_out_len`](AEADCipherEncryptor::update_out_len) is identically `0`.
///
/// A message or an AAD longer than `BUFFER_LEN` is refused with
/// [`SymmetricCipherError::GenericError`]. Pick `BUFFER_LEN` from the largest packet the protocol
/// allows -- CCM is a packet mode (Sec 3), so there is such a number.
///
/// # Memory
///
/// `2 * BUFFER_LEN` bytes in the value itself, plus the `FINAL_LEN`-byte buffer the trait's
/// provided one-shots put on the stack: about `3 * BUFFER_LEN` in total through
/// [`encrypt_out`](AEADCipherEncryptor::encrypt_out). The inherent [`Ccm`] API costs one block of
/// each of chaining value, counter template and keystream regardless of message size, so **prefer
/// it** unless you specifically need the trait.
pub struct CcmEncryptor<
    P,
    const KEY_LEN: usize,
    const BLOCK_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const BUFFER_LEN: usize,
> where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    // The key schedule, expanded once here and handed to `Ccm::from_perm` at finalization, so no
    // second copy of the key material is kept.
    perm: P,
    nonce: [u8; NONCE_LEN],
    // Associated data is authenticated but not encrypted, and travels in the clear, so it is not
    // secret and is not wrapped.
    aad: [u8; BUFFER_LEN],
    aad_len: usize,
    // The plaintext, held until finalization; wrapped so it is zeroized on drop.
    data: Secret<[u8; BUFFER_LEN]>,
    data_len: usize,
    // Set by the first `do_update_out`, which closes the AAD phase (see `do_update_aad`).
    data_started: bool,
}

impl<
    P,
    const KEY_LEN: usize,
    const BLOCK_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const BUFFER_LEN: usize,
> Algorithm for CcmEncryptor<P, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN, BUFFER_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    const ALG_NAME: &'static str = P::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = P::MAX_SECURITY_STRENGTH;
}

impl<
    P,
    const KEY_LEN: usize,
    const BLOCK_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const BUFFER_LEN: usize,
> AEADCipherEncryptor<KEY_LEN, NONCE_LEN, TAG_LEN, BUFFER_LEN>
    for CcmEncryptor<P, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN, BUFFER_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    fn do_encrypt_init(
        key: &KeyMaterial<KEY_LEN>,
    ) -> Result<(Self, [u8; NONCE_LEN]), SymmetricCipherError> {
        let mut rng = HashDRBG_SHA512::new_from_os();
        Self::do_encrypt_init_rng(key, &mut rng)
    }

    fn do_encrypt_init_rng(
        key: &KeyMaterial<KEY_LEN>,
        rng: &mut dyn RNG,
    ) -> Result<(Self, [u8; NONCE_LEN]), SymmetricCipherError> {
        // The shape check belongs here too: this type never calls `Ccm::new`, and without it a
        // `NONCE_LEN` or `TAG_LEN` A.1 forbids would not be caught until `do_encrypt_final`.
        Ccm::<P, Encrypting, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN>::check_shape();
        let perm = Ccm::<P, Encrypting, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN>::checked_perm(key)?;
        let nonce =
            Ccm::<P, Encrypting, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN>::nonce_from_rng(rng)?;
        Ok((
            Self {
                perm,
                nonce,
                aad: [0u8; BUFFER_LEN],
                aad_len: 0,
                data: Secret::new(),
                data_len: 0,
                data_started: false,
            },
            nonce,
        ))
    }

    /// Buffers `aad`. A sequence of calls is equivalent to one call over the concatenation, which
    /// is what A.2.2 needs: the AAD is length-prefixed, so it can only be encoded once all of it
    /// is in hand.
    ///
    /// # Errors
    /// [`SymmetricCipherError::StateError`] for a non-empty `aad` after the first
    /// `do_update_out`, and [`SymmetricCipherError::GenericError`] if the total would exceed
    /// `BUFFER_LEN`.
    fn do_update_aad(&mut self, aad: &[u8]) -> Result<(), SymmetricCipherError> {
        if aad.is_empty() {
            return Ok(());
        }
        if self.data_started {
            return Err(SymmetricCipherError::StateError("CCM: do_update_aad after do_update_out"));
        }
        let end = self.aad_len + aad.len();
        if end > BUFFER_LEN {
            return Err(SymmetricCipherError::GenericError(
                "CCM: associated data longer than BUFFER_LEN",
            ));
        }
        self.aad[self.aad_len..end].copy_from_slice(aad);
        self.aad_len = end;
        Ok(())
    }

    /// Identically `0`: nothing can be released before the payload length is known, so the whole
    /// ciphertext comes out of `do_encrypt_final`.
    fn update_out_len(&self, _input_len: usize) -> usize {
        0
    }

    /// Buffers `plaintext` and writes nothing, per [`Self::update_out_len`]. `ciphertext` is
    /// untouched and may be empty.
    ///
    /// # Errors
    /// [`SymmetricCipherError::GenericError`] if the total would exceed `BUFFER_LEN`. Nothing is
    /// consumed in that case.
    fn do_update_out(
        &mut self,
        plaintext: &[u8],
        _ciphertext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        // Set before the length check so that a refused oversized call still closes the AAD phase:
        // the phase order is about call history, and this call happened.
        self.data_started = true;
        let end = self.data_len + plaintext.len();
        if end > BUFFER_LEN {
            return Err(SymmetricCipherError::GenericError("CCM: payload longer than BUFFER_LEN"));
        }
        self.data[self.data_len..end].copy_from_slice(plaintext);
        self.data_len = end;
        Ok(0)
    }

    /// Runs the whole of Sec 6.1 over the buffered message: writes the ciphertext to `output` and
    /// returns its length with the tag.
    fn do_encrypt_final(
        mut self,
        output: &mut [u8; BUFFER_LEN],
    ) -> Result<(usize, [u8; TAG_LEN]), SymmetricCipherError> {
        let len = self.data_len;
        // Move the schedule out rather than cloning it; `self` is consumed either way. `Secret`'s
        // `Default` gives a zeroed placeholder, so nothing sensitive is left behind in `self.perm`
        // -- `P` holds its own schedule in a `Secret` that is dropped with the `Ccm` below.
        let mut ccm = Ccm::<P, Encrypting, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN>::from_perm(
            self.perm,
            &self.nonce,
            &self.aad[..self.aad_len],
            len,
        )?;
        output[..len].copy_from_slice(&self.data[..len]);
        // Scrub the plaintext copy as soon as the ciphertext is in `output`; `self` is dropped at
        // the end of this call anyway, but the buffer is large and this keeps the window short.
        ccm.do_encrypt_update(&mut output[..len])?;
        self.data.zeroize();
        let tag = ccm.do_encrypt_final()?;
        Ok((len, tag))
    }
}

/// Adapts [`Ccm`] to [`AEADCipherDecryptor`] by buffering the whole message; the mirror of
/// [`CcmEncryptor`], and see it for why the buffering is unavoidable and what it costs.
pub struct CcmDecryptor<
    P,
    const KEY_LEN: usize,
    const BLOCK_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const BUFFER_LEN: usize,
> where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    perm: P,
    nonce: [u8; NONCE_LEN],
    aad: [u8; BUFFER_LEN],
    aad_len: usize,
    // Ciphertext rather than plaintext, so not secret in itself; wrapped anyway, because
    // `do_decrypt_final` decrypts in place before the tag is checked.
    data: Secret<[u8; BUFFER_LEN]>,
    data_len: usize,
    data_started: bool,
}

impl<
    P,
    const KEY_LEN: usize,
    const BLOCK_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const BUFFER_LEN: usize,
> Algorithm for CcmDecryptor<P, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN, BUFFER_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    const ALG_NAME: &'static str = P::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = P::MAX_SECURITY_STRENGTH;
}

impl<
    P,
    const KEY_LEN: usize,
    const BLOCK_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const BUFFER_LEN: usize,
> AEADCipherDecryptor<KEY_LEN, NONCE_LEN, TAG_LEN, BUFFER_LEN>
    for CcmDecryptor<P, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN, BUFFER_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    fn do_decrypt_init(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Self, SymmetricCipherError> {
        Ccm::<P, Decrypting, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN>::check_shape();
        let perm = Ccm::<P, Decrypting, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN>::checked_perm(key)?;
        Ok(Self {
            perm,
            nonce: *nonce,
            aad: [0u8; BUFFER_LEN],
            aad_len: 0,
            data: Secret::new(),
            data_len: 0,
            data_started: false,
        })
    }

    /// As [`CcmEncryptor::do_update_aad`](AEADCipherEncryptor::do_update_aad); the concatenation
    /// must match the encryptor's byte for byte or the tag check fails.
    fn do_update_aad(&mut self, aad: &[u8]) -> Result<(), SymmetricCipherError> {
        if aad.is_empty() {
            return Ok(());
        }
        if self.data_started {
            return Err(SymmetricCipherError::StateError("CCM: do_update_aad after do_update_out"));
        }
        let end = self.aad_len + aad.len();
        if end > BUFFER_LEN {
            return Err(SymmetricCipherError::GenericError(
                "CCM: associated data longer than BUFFER_LEN",
            ));
        }
        self.aad[self.aad_len..end].copy_from_slice(aad);
        self.aad_len = end;
        Ok(())
    }

    /// Identically `0`. This is the one thing a CCM decryptor gets *right* by being forced to
    /// buffer: it releases no plaintext at all before the tag has been checked, so
    /// [`AEADCipherDecryptor`]'s warning about unauthenticated output cannot bite a caller here.
    fn update_out_len(&self, _input_len: usize) -> usize {
        0
    }

    /// Buffers `ciphertext` and writes nothing, per [`Self::update_out_len`].
    ///
    /// # Errors
    /// [`SymmetricCipherError::GenericError`] if the total would exceed `BUFFER_LEN`.
    fn do_update_out(
        &mut self,
        ciphertext: &[u8],
        _plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        self.data_started = true;
        let end = self.data_len + ciphertext.len();
        if end > BUFFER_LEN {
            return Err(SymmetricCipherError::GenericError(
                "CCM: ciphertext longer than BUFFER_LEN",
            ));
        }
        self.data[self.data_len..end].copy_from_slice(ciphertext);
        self.data_len = end;
        Ok(0)
    }

    /// Runs the whole of Sec 6.2 over the buffered message.
    ///
    /// On failure `output` is zeroized before the error is returned: Sec 6.2's "the payload P and
    /// the MAC T shall not be revealed".
    ///
    /// # Errors
    /// [`SymmetricCipherError::AEADTagCheckFailed`] if the tag does not verify.
    fn do_decrypt_final(
        mut self,
        tag: &[u8; TAG_LEN],
        output: &mut [u8; BUFFER_LEN],
    ) -> Result<usize, SymmetricCipherError> {
        let len = self.data_len;
        let mut ccm = Ccm::<P, Decrypting, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN>::from_perm(
            self.perm,
            &self.nonce,
            &self.aad[..self.aad_len],
            len,
        )?;
        output[..len].copy_from_slice(&self.data[..len]);
        ccm.do_decrypt_update(&mut output[..len])?;
        self.data.zeroize();
        match ccm.do_decrypt_final(tag) {
            Ok(()) => Ok(len),
            Err(e) => {
                output[..len].fill(0);
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Tests for the private formatting helpers, which are what a reviewer with SP 800-38C open
    //! most needs to check and which no public API exposes directly.
    //!
    //! The expected values are the `B` and `Ctr_i` strings printed in the spec's own Appendix C
    //! examples, transcribed from the errata-updated PDF. Appendix C gives the formatted block
    //! string for each example, so these pin the flags octet, the placement of `N` and `Q`, and
    //! the AAD length encoding against the document rather than against this implementation.

    use super::*;
    use bouncycastle_core::key_material::KeyType;

    /// A stand-in permutation: the identity. `B0` and `Ctr_i` are formatted *before* any cipher
    /// call, so the identity is enough to read them back out of the state, and it keeps these
    /// tests about the formatting function rather than about AES.
    struct Identity;

    impl Algorithm for Identity {
        const ALG_NAME: &'static str = "identity";
        const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
    }

    impl ElectronicCodeBook<16, 16> for Identity {
        fn new(_key: &KeyMaterial<16>) -> Result<Self, SymmetricCipherError> {
            Ok(Identity)
        }
        fn encrypt_block(&self, _block: &mut [u8; 16]) {}
        fn decrypt_block(&self, _block: &mut [u8; 16]) {}
    }

    fn key() -> KeyMaterial<16> {
        KeyMaterial::<16>::from_bytes_as_type(
            &[
                0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
                0x4e, 0x4f,
            ],
            KeyType::SymmetricCipherKey,
        )
        .expect("Appendix C's 128-bit key")
    }

    /// Appendix C.1: `Tlen=32, Nlen=56, Alen=64, Plen=32`, so `t = 4`, `n = 7`, `q = 8`.
    ///
    /// The spec prints `B` as
    /// `4f101112 13141516 00000000 00000004 | 00080001 02030405 06070000 00000000 | ...`,
    /// so `B0` is `4f` then the 7-byte nonce then `[4]_64`, and `B1` is `[8]_16` then the 8-byte
    /// AAD then six zero bytes of pad.
    ///
    /// C.1's AAD is 8 bytes, so its Adata bit is set.
    #[test]
    fn c1_b0_matches_the_spec() {
        let nonce = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16];
        assert_eq!(
            Ccm::<Identity, Encrypting, 16, 16, 7, 4>::format_b0(&nonce, true, 4),
            [0x4f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0, 0, 0, 0, 0, 0, 0, 4],
            "C.1 B0: flags 0x4f = Adata 1 | [(4-2)/2]_3 = 001 | [8-1]_3 = 111, then Q = [4]_64"
        );
    }

    /// A.2.2: the Adata bit is "'0' if a=0 and '1' if a>0", and it is bit 6 -- so clearing it must
    /// take C.1's `0x4f` to `0x0f` and change nothing else in the block.
    #[test]
    fn adata_flag_is_bit_6_of_the_flags_octet() {
        let nonce = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16];
        let with = Ccm::<Identity, Encrypting, 16, 16, 7, 4>::format_b0(&nonce, true, 4);
        let without = Ccm::<Identity, Encrypting, 16, 16, 7, 4>::format_b0(&nonce, false, 4);
        assert_eq!(without[0], 0x0f, "a = 0 clears bit 6, leaving the t and q fields alone");
        assert_eq!(with[0] ^ without[0], 1 << 6, "Adata is bit 6 and nothing else");
        assert_eq!(with[1..], without[1..], "the flag must not disturb N or Q");
    }

    /// The constructor really does absorb the `B0` that [`Ccm::format_b0`] built. With the identity
    /// permutation the CBC-MAC chaining value after one block is that block itself, so a
    /// no-AAD, no-payload construction leaves `B0` sitting in `y`.
    ///
    /// Without this, `format_b0` could be correct and unused.
    #[test]
    fn the_constructor_absorbs_b0() {
        let nonce = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16];
        let ccm = Ccm::<Identity, Encrypting, 16, 16, 7, 4>::new(&key(), &nonce, &[], 4).unwrap();
        assert_eq!(ccm.y, Ccm::<Identity, Encrypting, 16, 16, 7, 4>::format_b0(&nonce, false, 4));
        assert_eq!(ccm.mac_pos, 0, "a whole block was absorbed, so nothing is part-filled");
    }

    /// Appendix C.4: `Tlen=112, Nlen=104, Plen=256`, so `t = 14`, `n = 13`, `q = 2`; the spec
    /// prints `B0` as `71101112 13141516 1718191a 1b1c0020`.
    ///
    /// This is the other end of the `q` range from C.1, so between them the two tests pin the
    /// `[q-1]_3` encoding and the fact that `Q` is `q` octets wide, not a fixed width.
    #[test]
    fn c4_b0_matches_the_spec() {
        let nonce = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c];
        assert_eq!(
            Ccm::<Identity, Encrypting, 16, 16, 13, 14>::format_b0(&nonce, true, 32),
            [
                0x71, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
                0x00, 0x20
            ],
            "C.4 B0: flags 0x71 = Adata 1 | [(14-2)/2]_3 = 110 | [2-1]_3 = 001, then Q = [32]_16"
        );
    }

    /// Appendix C.1 prints `Ctr0` as `07101112 13141516 00000000 00000000` and `Ctr1` as the same
    /// with a trailing `01`; C.4's are `01101112 ... 1b1c0000` and `... 1b1c0001`.
    ///
    /// Table 4 makes the counter flags `[q-1]_3` alone, with every other bit zero -- which is what
    /// keeps them distinct from `B0`, whose `t` field cannot be zero.
    #[test]
    fn counter_blocks_match_the_spec() {
        let nonce_c1 = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16];
        let mut ccm =
            Ccm::<Identity, Encrypting, 16, 16, 7, 4>::new(&key(), &nonce_c1, &[], 4).unwrap();
        // `Ctr0` is the template with a zero counter field.
        let mut ctr0 = ccm.ctr_template;
        Ccm::<Identity, Encrypting, 16, 16, 7, 4>::put_q_field(&mut ctr0, 0);
        assert_eq!(
            ctr0,
            [0x07, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0, 0, 0, 0, 0, 0, 0, 0],
            "C.1 Ctr0"
        );
        // The first payload keystream block is `S1`, so one refill must produce `Ctr1`.
        ccm.refill_keystream();
        let mut ctr1 = ctr0;
        ctr1[15] = 1;
        assert_eq!(*ccm.ks, ctr1, "C.1 Ctr1 (the identity permutation leaves S1 = Ctr1)");

        let nonce_c4 =
            [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c];
        let ccm4 =
            Ccm::<Identity, Encrypting, 16, 16, 13, 14>::new(&key(), &nonce_c4, &[], 32).unwrap();
        let mut ctr0_c4 = ccm4.ctr_template;
        Ccm::<Identity, Encrypting, 16, 16, 13, 14>::put_q_field(&mut ctr0_c4, 0);
        assert_eq!(
            ctr0_c4,
            [
                0x01, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
                0x00, 0x00
            ],
            "C.4 Ctr0"
        );
    }

    /// A.2.2's three AAD length encodings, at and around both boundaries.
    ///
    /// Two of these values come from the spec itself: C.1's `a = 8` is printed as `0008`, and
    /// C.4's `a = 65536` (`Alen = 524288` bits) is printed as
    /// `11111111 11111110 00000000 00000001 00000000 00000000`, i.e. `ff fe 00 01 00 00`.
    ///
    /// The rest pin the boundaries, which is the part no end-to-end test can reach: the first is
    /// `2^16 - 2^8` = 65280 rather than the obvious-but-wrong `2^16`, and the second is `2^32`,
    /// which through the public API would need a 4 GiB AAD.
    #[test]
    fn aad_length_encoding_matches_a_2_2() {
        type Mode = Ccm<Identity, Encrypting, 16, 16, 7, 4>;

        // Case 1: 0 < a < 2^16 - 2^8, two octets, `[a]_16`.
        assert_eq!(
            Mode::encode_aad_len(8),
            ([0x00, 0x08, 0, 0, 0, 0, 0, 0, 0, 0], 2),
            "C.1's a = 8"
        );
        assert_eq!(Mode::encode_aad_len(1).1, 2);
        // 65279 = 2^16 - 2^8 - 1 is the largest value still in the first case.
        assert_eq!(
            Mode::encode_aad_len(65279),
            ([0xfe, 0xff, 0, 0, 0, 0, 0, 0, 0, 0], 2),
            "65279 is still [a]_16"
        );

        // Case 2: 2^16 - 2^8 <= a < 2^32, six octets, `0xff || 0xfe || [a]_32`. 65280 is the first.
        assert_eq!(
            Mode::encode_aad_len(65280),
            ([0xff, 0xfe, 0x00, 0x00, 0xff, 0x00, 0, 0, 0, 0], 6),
            "65280 crosses into the six-octet case; a two-octet 0xff00 would be ambiguous"
        );
        assert_eq!(
            Mode::encode_aad_len(65536),
            ([0xff, 0xfe, 0x00, 0x01, 0x00, 0x00, 0, 0, 0, 0], 6),
            "C.4's a = 65536"
        );
        // 2^32 - 1 is the largest value still in the second case.
        assert_eq!(
            Mode::encode_aad_len(u32::MAX as u64),
            ([0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0], 6),
            "2^32 - 1 is still the six-octet case"
        );

        // Case 3: 2^32 <= a < 2^64, ten octets, `0xff || 0xff || [a]_64`.
        assert_eq!(
            Mode::encode_aad_len(1u64 << 32),
            ([0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00], 10),
            "2^32 is the first ten-octet case"
        );
        assert_eq!(
            Mode::encode_aad_len(u64::MAX),
            ([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 10)
        );

        // A.2.2's whole point: the three cases are distinguishable by their leading octets, so no
        // two distinct lengths can encode to the same prefix. The first octet is 0xff only in the
        // second and third cases, and the second octet separates those.
        for a in [1u64, 8, 65279] {
            assert_ne!(Mode::encode_aad_len(a).0[0], 0xff, "case 1 must not lead with 0xff");
        }
    }

    /// The constructor really uses [`Ccm::encode_aad_len`], and puts it *before* the AAD.
    ///
    /// With the identity permutation the CBC-MAC is `y = B0 ^ B1 ^ ... ^ Br`, so with a one-block
    /// all-zero AAD the only nonzero contributions are `B0` and the length encoding. That makes the
    /// encoding readable back out, which is what pins the ordering rather than just the value.
    #[test]
    fn the_constructor_prefixes_the_aad_with_its_length() {
        type Mode = Ccm<Identity, Encrypting, 16, 16, 7, 4>;
        let nonce = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16];
        // 14 zero bytes of AAD: the 2-byte length plus 14 bytes is exactly one 16-byte block, so
        // there is no padding to reason about.
        let ccm = Mode::new(&key(), &nonce, &[0u8; 14], 0).unwrap();

        let b0 = Mode::format_b0(&nonce, true, 0);
        let mut b1 = [0u8; 16];
        b1[..2].copy_from_slice(&14u16.to_be_bytes());
        let expected: [u8; 16] = core::array::from_fn(|i| b0[i] ^ b1[i]);
        assert_eq!(ccm.y, expected, "y must be B0 ^ B1, with B1 starting with [14]_16");
    }

    /// A.1's `p < 2^8q`. With `n = 13`, `q = 2`, so the limit is 65535 and 65536 must be refused.
    #[test]
    fn payload_longer_than_the_q_limit_is_refused() {
        let nonce = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c];
        assert!(
            Ccm::<Identity, Encrypting, 16, 16, 13, 14>::new(&key(), &nonce, &[], 65535).is_ok(),
            "2^16 - 1 is the largest payload q = 2 can encode"
        );
        assert!(
            matches!(
                Ccm::<Identity, Encrypting, 16, 16, 13, 14>::new(&key(), &nonce, &[], 65536),
                Err(SymmetricCipherError::GenericError(_))
            ),
            "2^16 does not fit [p]_16"
        );
    }

    /// The declared payload length is inside `B0`, so neither direction may be finalized with the
    /// wrong amount of data.
    #[test]
    fn a_short_or_long_payload_is_refused() {
        let nonce = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16];
        let mut ccm =
            Ccm::<Identity, Encrypting, 16, 16, 7, 4>::new(&key(), &nonce, &[], 8).unwrap();
        let mut too_much = [0u8; 9];
        assert!(
            matches!(
                ccm.do_encrypt_update(&mut too_much),
                Err(SymmetricCipherError::StateError(_))
            ),
            "9 bytes against a declared 8"
        );
        let mut some = [0u8; 4];
        ccm.do_encrypt_update(&mut some).expect("4 of the 8 declared bytes");
        assert!(
            matches!(ccm.do_encrypt_final(), Err(SymmetricCipherError::StateError(_))),
            "finalizing 4 bytes short"
        );
    }

    /// The two directions absorb the *plaintext* into the CBC-MAC, in both cases: Sec 6.1 step 1
    /// formats `P` and Sec 6.2 step 7 formats the recovered `P`, never the ciphertext. So an
    /// encryptor and a decryptor over the same message must reach the same `Yr`, and therefore the
    /// same tag, even though they apply the keystream and the MAC in the opposite order.
    ///
    /// This is the property the wrong-direction runtime check used to guard; the `Dir` parameter
    /// now makes the misuse a compile error (see the `compile_fail` examples on `Ccm`), so what is
    /// left worth testing is that the two orders genuinely agree.
    #[test]
    fn both_directions_mac_the_plaintext() {
        let nonce = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16];
        let plaintext = [0xDEu8, 0xAD, 0xBE, 0xEF, 0x01, 0x02];

        let mut enc =
            Ccm::<Identity, Encrypting, 16, 16, 7, 4>::new(&key(), &nonce, b"h", plaintext.len())
                .unwrap();
        let mut data = plaintext;
        enc.do_encrypt_update(&mut data).unwrap();
        let tag = enc.do_encrypt_final().unwrap();

        // The decryptor is handed the ciphertext, recovers the plaintext, and must agree on the tag.
        let mut dec =
            Ccm::<Identity, Decrypting, 16, 16, 7, 4>::new(&key(), &nonce, b"h", plaintext.len())
                .unwrap();
        dec.do_decrypt_update(&mut data).unwrap();
        dec.do_decrypt_final(&tag).expect("the two directions must reach the same Yr");
        assert_eq!(data, plaintext);
    }
}
