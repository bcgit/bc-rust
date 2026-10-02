//! The CCM mode of operation: Counter with Cipher Block Chaining-Message Authentication Code
//! (NIST SP 800-38C, May 2004, errata update 07-20-2007).
//! Sec 6.1, the generation-encryption process, and Sec 6.2, the decryption-verification process.
//!
//! CCM is an *authenticated* mode: it produces a tag as well as a ciphertext, and decryption either
//! returns the plaintext or a [`SymmetricCipherError::AEADTagCheckFailed`].
//! It is built from two mechanisms under a single key: (Sec 5.2):
//! "The same key, K, is used for both the CTR and CBC-MAC mechanisms within CCM".
//!
//! Only the forward cipher function is ever used, in both directions, so a
//! permutation that implements nothing but `encrypt_block` works here.
//!
//! # Usage Examples
//! The nonce is supplied rather than generated, and there is an extra input (the AAD, authenticated but
//! not encrypted) and an extra output (the tag).
//!
//! Decryption either returns the plaintext or fails with [`SymmetricCipherError::AEADTagCheckFailed`]
//! -- it never returns plausible-looking rubbish the way the unauthenticated modes do when the
//! ciphertext has been altered.
//!
//! ```
//! use bouncycastle_core_test_framework::ToyBlockCipher;
//! use bouncycastle_core::errors::SymmetricCipherError;
//! use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
//! use bouncycastle_cipher::modes::Ccm;
//! use bouncycastle_cipher::{Decrypting, Encrypting};
//!
//! type ToyCcm<Dir> = Ccm<ToyBlockCipher, Dir, 16, 16, 12, 16>;
//!
//! let key = KeyMaterial128::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//!
//! // Supplied, not generated
//! // It is the caller's responsibility that it never repeat under this key.
//! let nonce = [0x01u8; 12];
//!
//! let header = b"authenticated, not encrypted";
//! let message = b"any length: CCM pads internally";
//!
//! // The spec's own layout (SP 800-38C Sec 6.1 step 8): `ciphertext || tag`.
//! let mut ct_and_tag = vec![0u8; message.len() + 16];
//! ToyCcm::<Encrypting>::encrypt_out(&key, &nonce, header, message, &mut ct_and_tag).expect("encryption");
//!
//! let mut recovered_plaintext = vec![0u8; message.len()];
//! let n = ToyCcm::<Decrypting>::decrypt_out(&key, &nonce, header, &ct_and_tag, &mut recovered_plaintext).expect("decryption");
//! assert_eq!(&recovered_plaintext[..n], message);
//!
//! // If we tamper with any byte of the ciphertext, then this fails with a SymmetricCipherError::AEADTagCheckFailed
//! let mut tampered = ct_and_tag.clone();
//! tampered[0] ^= 1;
//! assert_eq!(ToyCcm::<Decrypting>::decrypt_out(&key, &nonce, header, &tampered, &mut recovered_plaintext).unwrap_err(),
//!             SymmetricCipherError::AEADTagCheckFailed);
//!
//! // Same if we provide the correct ciphertext and tag, but change the authenticated data
//! assert_eq!(ToyCcm::<Decrypting>::decrypt_out(&key, &nonce, b"other header", &ct_and_tag, &mut recovered_plaintext).unwrap_err(),
//!             SymmetricCipherError::AEADTagCheckFailed);
//! ```
//!
//! # CCM is not a stream cipher
//!
//! It does not have an indefinite-length streaming mode.
//! The reason is `B0`. Appendix A.2.1 puts `Q`, the payload's octet length, *inside the first block
//! the CBC-MAC absorbs*, so nothing at all can be authenticated until the total payload length is
//! known.
//!
//! Sec 3 is explicit:
//!
//! > CCM is intended for use in a packet environment, i.e., when all of the data is available in
//! > storage before CCM is applied; CCM is not designed to support partial processing or stream
//! > processing.
//!
//! This is different from the `do_encrypt()` mode, often referred to as a "streaming mode" where
//! the content is processed in batches; so long as the total expected length is known up-front.
//! The AAD can be processed in batches the same way, if its length is declared up-front too; see
//! [`Ccm::new_with_lengths`].
//!
//! # Suspending and resuming execution
//!
//! [`Ccm`] implements [`SuspendableKeyed`], so a message in progress can be suspended to a byte
//! array and resumed later with the re-supplied key. The state is the CTR half, the CBC-MAC
//! chaining value and the AAD and payload still owed; the permutation is rebuilt from the key. The
//! array length is `Ccm::SUSPENDED_STATE_LEN`; see [the crate
//! docs](crate#suspending-and-resuming-execution) for an example.
//!
//! # 🚨 Security Considerations 🚨
//!
//! **The nonce must never repeat under one key.**
//! Sec 5.3: "any two distinct data pairs to be
//! protected by CCM during the lifetime of the key shall be assigned distinct nonces".
//! A repeat is worse here than in an unauthenticated mode: it reuses the CTR keystream, and Appendix B.1's
//! footnote describes the resulting forgery -- an attacker who can "induce the
//! decryption-verification process to reuse the nonce" can flip any chosen bit of the payload. The
//! nonce is *not* required to be random, only unique, so
//! a counter is a valid and often better choice; every deterministic entry point here takes the
//! nonce from the caller, and should be drawn from the library's DRBG.
//!
//! **`TAG_LEN` is a security parameter.** Sec B.2: "a value of Tlen that is less than 64 shall not
//! be used without a careful analysis of the risks of accepting inauthentic data as authentic", and
//! it gives the bound `Tlen >= lg(MaxErrs / Risk)`. A `TAG_LEN` of 4 or 6 bytes is permitted by A.1 and
//! accepted here: the spec's own Appendix C.1 and C.2 examples use `Tlen=32` and `Tlen=48`.
//!
//! **The key is for CCM only.** Sec 5.1: "The key shall be kept secret and shall only be used for
//! the CCM mode", and "The total number of invocations of the block cipher algorithm during the
//! lifetime of the key shall be limited to 2^61".

use crate::modes::ctr::apply_counter_blocks;
use crate::modes::iv::random_iv;
use crate::stream::StreamCipher;
use bouncycastle_core::errors::{SuspendableError, SymmetricCipherError};
use bouncycastle_core::hazmat::{ElectronicCodeBook, KeyStream};
use bouncycastle_core::key_material::KeyMaterial;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, Algorithm, RNG, StreamCipherDecryptor,
    StreamCipherEncryptor, SuspendableKeyed, SymmetricCipherDecryptor, SymmetricCipherEncryptor,
};
use bouncycastle_rng::HashDRBG_SHA512;
use bouncycastle_utils::ct::ct_eq_bytes;
use bouncycastle_utils::secret::Secret;
use bouncycastle_utils::suspendable_state::{
    Cursor, CursorMut, LIB_VERSION_LEN, SuspendableComponent, bounded_usize, resume_component,
    suspend_component,
};
use core::marker::PhantomData;

use crate::{Decrypting, Encrypting};

/// CCM (SP 800-38C) over any [`ElectronicCodeBook`] with a 128-bit block.
///
/// `Dir` is [`Encrypting`] or [`Decrypting`], `Ccm<P, Encrypting, ..>` has Sec 6.1's methods and
/// nothing else, and `Ccm<P, Decrypting, ..>` has Sec 6.2's.
///
/// Asking an encryptor to verify a tag does not compile -- `do_decrypt_final` exists only on
/// `Ccm<P, Decrypting, ..>`:
///
/// A nonce length A.1 does not permit does not compile:
///
/// ```compile_fail
/// use bouncycastle_core_test_framework::ToyBlockCipher;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_cipher::modes::Ccm;
/// use bouncycastle_cipher::Encrypting;
///
/// let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
///     .unwrap();
/// // n = 6 is not in {7, ..., 13}: it would make q = 9, which A.1 does not allow.
/// let _ = Ccm::<ToyBlockCipher, Encrypting, 16, 16, 6, 16>::new(&key, &[0u8; 6], &[], 0);
/// ```
///
/// Nor does an odd tag length:
///
/// ```compile_fail
/// use bouncycastle_core_test_framework::ToyBlockCipher;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_cipher::modes::Ccm;
/// use bouncycastle_cipher::Encrypting;
///
/// let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
///     .unwrap();
/// // t = 15 is not in {4, 6, 8, 10, 12, 14, 16}.
/// let _ = Ccm::<ToyBlockCipher, Encrypting, 16, 16, 12, 15>::new(&key, &[0u8; 12], &[], 0);
/// ```
#[derive(Clone)]
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
    // The CTR half (Sec 6.1 steps 5-8): the payload keystream `S1 || S2 || ...`, and the key
    // schedule, which the CBC-MAC half below shares (Sec 5.2).
    ctr: StreamCipher<
        CcmKeyStream<P, KEY_LEN, BLOCK_LEN, NONCE_LEN>,
        Dir,
        KEY_LEN,
        NONCE_LEN,
        BLOCK_LEN,
    >,
    // The CBC-MAC chaining value: `Y0` once the constructor has absorbed `B0` (Sec 6.1 step 2),
    // then `Yi` as further blocks arrive (step 3). Bytes are XORed into it in place, so part-way
    // through a block it holds `Yi-1 XOR (the part of Bi seen so far)`.
    //
    // `Yr`'s low `TAG_LEN` bytes are the raw tag `T` before it is masked with `S0` (`finish_mac`),
    // and every intermediate `Yi` is key-dependent CBC-MAC state, so this gets the same treatment
    // as the keystream rather than a plain array.
    y: Secret<[u8; BLOCK_LEN]>,
    // How many bytes of the current CBC-MAC input block have been XORed into `y`.
    mac_pos: usize,
    // How much of the AAD length declared at construction has not yet been supplied. The length is
    // encoded in front of the AAD (A.2.2), so, as for the payload below, a different amount is
    // refused. While it is non-zero the AAD phase is open and no payload is accepted: A.2.3 puts
    // the payload blocks after the AAD blocks.
    aad_owed: usize,
    // How much of the payload length declared at construction has not yet been supplied. That
    // length is committed to inside `B0`, so supplying a different amount would authenticate a
    // message no verifier could reproduce; both directions refuse instead of doing it.
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
    const Q_LEN: usize = CcmKeyStream::<P, KEY_LEN, BLOCK_LEN, NONCE_LEN>::Q_LEN;

    /// The `N` of this type's [`SuspendableKeyed<N>`] impl: the version header, the CTR state,
    /// the CBC-MAC chaining block and three counts as `u64`s. See [`bouncycastle_utils::suspendable_state`].
    pub const SUSPENDED_STATE_LEN: usize =
        LIB_VERSION_LEN + <Self as SuspendableComponent>::STATE_LEN;

    /// The CTR half's share of the suspended state.
    const CTR_STATE_LEN: usize = <StreamCipher<
        CcmKeyStream<P, KEY_LEN, BLOCK_LEN, NONCE_LEN>,
        Dir,
        KEY_LEN,
        NONCE_LEN,
        BLOCK_LEN,
    > as SuspendableComponent>::STATE_LEN;

    /// The largest payload this parameterization can carry, from A.1's "by definition, p<2^8q".
    ///
    /// `q = 8` would make `2^8q` exactly `2^64`, which does not fit a `u64`; there the bound is
    /// `p <= 2^64 - 1`, i.e. `u64::MAX`, which is no bound at all on a `usize` length. Public so a
    /// caller choosing a `DATA_LEN` for [`CcmEncryptor`] / [`CcmDecryptor`], or reporting the
    /// limit in an error message, has the real number instead of re-deriving it.
    pub const MAX_PAYLOAD_LEN: u64 =
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

    /// Begins a CCM flow: formats `B0`, absorbs it and all of `A` into the CBC-MAC, and readies the
    /// counter blocks. Everything after this streams without buffering.
    ///
    /// `payload_len` is declared here because Appendix A.2.1 puts the payload length inside `B0`,
    /// the first block the CBC-MAC absorbs. For an AAD that is not all in hand at once, see
    /// [`Self::new_with_lengths`], which declares its length instead and takes it in pieces.
    ///
    /// * `key` must be a [`KeyType::SymmetricCipherKey`](bouncycastle_core::key_material::KeyType::SymmetricCipherKey)
    ///   of at least the permutation's strength.
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
        // The shape check and the payload-limit check both belong to `from_perm_with_lengths`,
        // which is the one path every construction goes through; duplicating them here would be
        // two more `Err` sites that could drift apart from it. `P::new`'s own `KeyType`/strength
        // checks are the only key validation needed, exactly as for every other mode in this crate.
        let perm = P::new(key)?;
        Self::from_perm(perm, nonce, aad, payload_len)
    }

    /// As [`Self::new`], but with the AAD's length declared rather than the AAD itself, so that the
    /// AAD can then be supplied in pieces through [`Self::do_update_aad`].
    ///
    /// Both lengths are needed up front, and only the lengths. `B0` carries the payload length
    /// (A.2.1), and A.2.2 formats the AAD as "the encoding of a [...] concatenated with the
    /// associated data A", so the CBC-MAC cannot absorb the first AAD byte until it has absorbed
    /// `B0` and the encoding of `a`. The AAD bytes themselves then go through the CBC-MAC as they
    /// arrive, in any chunking.
    ///
    /// The flow is: this constructor, exactly `aad_len` bytes of AAD through
    /// [`Self::do_update_aad`], then exactly `payload_len` bytes of payload, then the final. The
    /// AAD must be complete before any payload: A.2.3 puts the payload blocks after the AAD blocks.
    ///
    /// ```
    /// use bouncycastle_core_test_framework::ToyBlockCipher;
    /// use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
    /// use bouncycastle_cipher::modes::Ccm;
    /// use bouncycastle_cipher::Encrypting;
    ///
    /// type ToyCcm<Dir> = Ccm<ToyBlockCipher, Dir, 16, 16, 12, 16>;
    ///
    /// let key = KeyMaterial128::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
    ///     .expect("a 16-byte symmetric cipher key");
    /// let nonce = [0x01u8; 12];
    /// let header: [&[u8]; 2] = [b"version: 1; ", b"route: a->b"];
    /// let mut message = *b"attack at dawn";
    ///
    /// let aad_len = header.iter().map(|part| part.len()).sum();
    /// let mut ccm =
    ///     ToyCcm::<Encrypting>::new_with_lengths(&key, &nonce, aad_len, message.len()).unwrap();
    /// for part in header {
    ///     ccm.do_update_aad(part).unwrap();
    /// }
    /// ccm.do_encrypt(&mut message).unwrap();
    /// let tag = ccm.do_encrypt_final().unwrap();
    ///
    /// // The same as supplying the AAD whole.
    /// let mut whole = *b"attack at dawn";
    /// let mut ccm = ToyCcm::<Encrypting>::new(&key, &nonce, b"version: 1; route: a->b", 14).unwrap();
    /// ccm.do_encrypt(&mut whole).unwrap();
    /// assert_eq!((message, tag), (whole, ccm.do_encrypt_final().unwrap()));
    /// ```
    ///
    /// # Errors
    /// As [`Self::new`].
    pub fn new_with_lengths(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
        aad_len: usize,
        payload_len: usize,
    ) -> Result<Self, SymmetricCipherError> {
        let perm = P::new(key)?;
        Self::from_perm_with_lengths(perm, nonce, aad_len, payload_len)
    }

    /// Supplies the next piece of the AAD declared to [`Self::new_with_lengths`]. A sequence of
    /// calls is equivalent to one call over the concatenation. An empty `aad` is a no-op.
    ///
    /// When the last declared byte arrives, the AAD is zero-padded to a block boundary (A.2.2's
    /// "minimum number of '0' bits"), which is what opens the payload phase.
    ///
    /// # Errors
    /// [`SymmetricCipherError::StateError`] if `aad` would take the total past the declared AAD
    /// length -- which includes any non-empty AAD once the declared amount is complete, and so any
    /// after [`Self::new`], which declares exactly the AAD it is given. Nothing is absorbed in that
    /// case.
    pub fn do_update_aad(&mut self, aad: &[u8]) -> Result<(), SymmetricCipherError> {
        if aad.len() > self.aad_owed {
            return Err(SymmetricCipherError::StateError(
                "CCM was given more AAD than the length declared to `new_with_lengths`, which the \
                 AAD length encoding commits to",
            ));
        }
        if aad.is_empty() {
            return Ok(());
        }
        self.mac_absorb(aad);
        self.aad_owed -= aad.len();
        if self.aad_owed == 0 {
            // The AAD's own blocks `B1 ... Bu` end on a block boundary, and A.2.3's payload blocks
            // are `Bu+1 ...`. So the zero pad happens *here*, not once at the very end.
            self.mac_pad();
        }
        Ok(())
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
        let mut ccm = Self::from_perm_with_lengths(perm, nonce, aad.len(), payload_len)?;
        // Exactly the declared length, so this cannot be refused.
        ccm.do_update_aad(aad)?;
        Ok(ccm)
    }

    /// As [`Self::new_with_lengths`], from a key schedule that has already been expanded: formats
    /// and absorbs `B0` and, if there is any AAD, the encoding of its length, leaving the AAD
    /// itself to [`Self::do_update_aad`].
    fn from_perm_with_lengths(
        perm: P,
        nonce: &[u8; NONCE_LEN],
        aad_len: usize,
        payload_len: usize,
    ) -> Result<Self, SymmetricCipherError> {
        Self::check_shape();
        if payload_len as u64 > Self::MAX_PAYLOAD_LEN {
            return Err(SymmetricCipherError::GenericError(
                "CCM payload longer than 2^8q - 1, the limit the nonce length implies (A.1)",
            ));
        }

        let mut ccm = Self {
            ctr: StreamCipher::from_keystream(CcmKeyStream::from_perm(perm, nonce)),
            // Sec 6.1 step 2 is `Y0 = CIPH_K(B0)`, with no XOR, unlike step 3's `Bi XOR Yi-1`.
            // Starting the chaining value at zero unifies the two: `B0 XOR 0 = B0`, so absorbing
            // `B0` through the same path as every other block yields exactly `Y0`.
            y: Secret::new(),
            mac_pos: 0,
            aad_owed: aad_len,
            owed: payload_len,
            _dir: PhantomData,
        };

        ccm.mac_absorb(&Self::format_b0(nonce, aad_len > 0, payload_len as u64));

        // A.2.2: if `a > 0`, "the encoding of a is concatenated with the associated data A,
        // followed by the minimum number of '0' bits, possibly none, such that the resulting string
        // can be partitioned into 16-octet blocks". The encoding goes in now; `A` and the pad
        // follow through `do_update_aad`. If `a = 0` there are no AAD blocks at all, so nothing is
        // absorbed and nothing is padded, and `B0` has already ended on a block boundary.
        if aad_len > 0 {
            let (encoded, encoded_len) = Self::encode_aad_len(aad_len as u64);
            ccm.mac_absorb(&encoded[..encoded_len]);
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
        CcmKeyStream::<P, KEY_LEN, BLOCK_LEN, NONCE_LEN>::put_q_field(&mut b0, payload_len);
        b0
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
                self.ctr.keystream().perm.encrypt_block(&mut self.y);
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
            self.ctr.keystream().perm.encrypt_block(&mut self.y);
            self.mac_pos = 0;
        }
    }

    /// Debits `len` bytes from the payload length declared to [`Self::new`], refusing any payload
    /// while declared AAD is still outstanding.
    #[inline]
    fn take_owed(&mut self, len: usize) -> Result<(), SymmetricCipherError> {
        if len > 0 && self.aad_owed != 0 {
            return Err(SymmetricCipherError::StateError(
                "CCM was given payload before all of the AAD declared to `new_with_lengths`; A.2.3 \
                 puts the payload after the AAD",
            ));
        }
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

        // A keystream block of exactly the kind the payload keystream produces, so it gets the same `Secret` treatment
        // rather than a plain local that outlives this function's stack frame unzeroed.
        let keystream = self.ctr.keystream();
        let mut s0: Secret<[u8; BLOCK_LEN]> = Secret::new();
        *s0 = CcmKeyStream::<P, KEY_LEN, BLOCK_LEN, NONCE_LEN>::counter_block(
            &keystream.ctr_template, 0,
        );
        keystream.perm.encrypt_block(&mut s0);

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
    /// payload length, or if it is non-empty while AAD declared to [`Self::new_with_lengths`] is
    /// still outstanding. Nothing is consumed in either case.
    pub fn do_encrypt(&mut self, data: &mut [u8]) -> Result<(), SymmetricCipherError> {
        self.take_owed(data.len())?;
        self.mac_absorb(data);
        self.ctr.do_encrypt(data)?;
        Ok(())
    }

    /// Finishes an encryption and returns the tag (Sec 6.1 steps 4 and 8).
    ///
    /// # Errors
    /// [`SymmetricCipherError::StateError`] if less payload was supplied than the length declared
    /// to [`Self::new`] -- `B0` commits to that length, so a short message would produce a tag no
    /// verifier could reproduce -- or less AAD than declared to [`Self::new_with_lengths`], for the
    /// same reason.
    pub fn do_encrypt_final(self) -> Result<[u8; TAG_LEN], SymmetricCipherError> {
        if self.aad_owed != 0 {
            return Err(SymmetricCipherError::StateError(
                "CCM was given less AAD than the length declared to `new_with_lengths`",
            ));
        }
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
    /// the tag. For the spec's own inline `ciphertext || tag` string, use [`Self::encrypt_out`].
    ///
    /// # Errors
    /// [`SymmetricCipherError::OutputBufferTooSmall`] if `ciphertext` is too short, plus
    /// [`Self::new`]'s errors.
    pub fn encrypt_out_detached(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<(usize, [u8; TAG_LEN]), SymmetricCipherError> {
        if ciphertext.len() < plaintext.len() {
            return Err(SymmetricCipherError::OutputBufferTooSmall(plaintext.len()));
        }
        let mut ccm = Self::new(key, nonce, aad, plaintext.len())?;
        let out = &mut ciphertext[..plaintext.len()];
        out.copy_from_slice(plaintext);
        ccm.do_encrypt(out)?;
        let tag = ccm.do_encrypt_final()?;
        Ok((plaintext.len(), tag))
    }

    /// One-shot generation-encryption producing the spec's own output string (Sec 6.1 step 8):
    /// `C = (P XOR MSB_Plen(S)) || (T XOR MSB_Tlen(S0))`, i.e. `ciphertext || tag` inline.
    ///
    /// `ciphertext` needs `plaintext.len() + TAG_LEN` bytes; the return is how many were written.
    ///
    /// # Errors
    /// As [`Self::encrypt_out_detached`].
    pub fn encrypt_out(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        let needed = plaintext.len() + TAG_LEN;
        if ciphertext.len() < needed {
            return Err(SymmetricCipherError::OutputBufferTooSmall(needed));
        }
        let (data, tag_out) = ciphertext[..needed].split_at_mut(plaintext.len());
        let (_, tag) = Self::encrypt_out_detached(key, nonce, aad, plaintext, data)?;
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
    /// The mirror of [`Self::do_encrypt`] with the two steps swapped: Sec 6.2 recovers `P` in
    /// step 5 and only then formats `(N, A, P)` in step 7, so the MAC is fed the plaintext here too,
    /// never the ciphertext.
    ///
    /// The bytes this writes are **not authenticated** until [`Self::do_decrypt_final`] returns
    /// `Ok`.
    ///
    /// # Errors
    /// [`SymmetricCipherError::StateError`] if `data` would take the total past the declared
    /// payload length, or if it is non-empty while AAD declared to [`Self::new_with_lengths`] is
    /// still outstanding. Nothing is consumed in either case.
    pub fn do_decrypt_update(&mut self, data: &mut [u8]) -> Result<(), SymmetricCipherError> {
        self.take_owed(data.len())?;
        self.ctr.do_decrypt(data)?;
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
    /// to [`Self::new`], or less AAD than declared to [`Self::new_with_lengths`].
    pub fn do_decrypt_final(self, tag: &[u8; TAG_LEN]) -> Result<(), SymmetricCipherError> {
        if self.aad_owed != 0 {
            return Err(SymmetricCipherError::StateError(
                "CCM was given less AAD than the length declared to `new_with_lengths`",
            ));
        }
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
    /// [`SymmetricCipherError::OutputBufferTooSmall`] if `plaintext` is too short, plus
    /// [`Self::new`]'s errors.
    pub fn decrypt_out_detached(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; TAG_LEN],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        if plaintext.len() < ciphertext.len() {
            return Err(SymmetricCipherError::OutputBufferTooSmall(ciphertext.len()));
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
    /// [`SymmetricCipherError::DecryptionFailed`] for Sec 6.2 step 1, "If Clen <= Tlen, then
    /// return INVALID": a malformed input rather than a failed check, reported with the variant
    /// [`SymmetricCipherDecryptor::do_final`] specifies for a malformed ciphertext so that every
    /// inline entry point -- this one, [`CcmDecryptor::do_final`] and
    /// [`CcmDecryptor::decrypt_out_with_aad`](AEADCipherDecryptor::decrypt_out_with_aad) -- agrees
    /// on the same input. Otherwise as [`Self::decrypt_out_detached`].
    pub fn decrypt_out(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        let Some((data, tag)) = ciphertext.split_last_chunk::<TAG_LEN>() else {
            return Err(SymmetricCipherError::DecryptionFailed);
        };
        Self::decrypt_out_detached(key, nonce, aad, data, tag, plaintext)
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

/// The CTR half of CCM: the keystream `Sj = CIPH_K(Ctrj)` for `j = 1, 2, ...` (Sec 6.1 steps 5-7),
/// over counter blocks formatted as A.3 specifies.
///
/// Crate-private: CCM's CTR half alone is an unauthenticated cipher, and is only reachable
/// through [`Ccm`]. It shares its key schedule with the CBC-MAC half, which reaches it through
/// [`StreamCipher::keystream`].
#[derive(Clone)]
struct CcmKeyStream<P, const KEY_LEN: usize, const BLOCK_LEN: usize, const NONCE_LEN: usize>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    perm: P,
    // `Ctr_i` with its counter field zeroed (A.3, Table 3): the flags octet and the nonce, which
    // are the same in every counter block. Public data -- flags and nonce travel in the clear --
    // so deliberately not a `Secret`.
    ctr_template: [u8; BLOCK_LEN],
    // The index `j` of the next keystream block. Starts at 1: step 7 sets `S = S1 || ... || Sm`,
    // and `S0` is reserved for the tag.
    next_ctr: u64,
}

impl<P, const KEY_LEN: usize, const BLOCK_LEN: usize, const NONCE_LEN: usize>
    CcmKeyStream<P, KEY_LEN, BLOCK_LEN, NONCE_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    /// The spec's `q`: the octet length of the payload-length field `Q`, which is also the width
    /// of the counter field. A.1 requires `n + q = 15`.
    const Q_LEN: usize = 15 - NONCE_LEN;

    /// The largest counter value the `q`-octet counter field can hold, `2^8q - 1`; `q = 8` makes
    /// that `u64::MAX`.
    const MAX_COUNTER: u64 =
        if Self::Q_LEN >= 8 { u64::MAX } else { (1u64 << (8 * Self::Q_LEN)) - 1 };

    /// Formats the counter template and positions the keystream at `S1`.
    fn from_perm(perm: P, nonce: &[u8; NONCE_LEN]) -> Self {
        // A.3, Tables 3 and 4: `Ctr_i` is `Flags || N || [i]_8q`, and its flags octet has both
        // reserved bits and bits 3, 4 and 5 zero -- "to ensure that all the counter blocks are
        // distinct from B0", whose bits 3..5 encode `t` and so cannot all be zero -- leaving bits
        // 0..2 to hold "the same encoding of q as in B0".
        let mut ctr_template = [0u8; BLOCK_LEN];
        ctr_template[0] = (Self::Q_LEN - 1) as u8;
        ctr_template[1..1 + NONCE_LEN].copy_from_slice(nonce);
        Self { perm, ctr_template, next_ctr: 1 }
    }

    /// Writes `[x]_8q` into the trailing `Q_LEN` octets of `block`: the `Q` field of `B0` (A.2.1,
    /// Table 2) and the counter field of `Ctr_i` (A.3, Table 3), which occupy the same octets.
    ///
    /// `Q_LEN <= 8`, so the low `Q_LEN` bytes of a big-endian `u64` are exactly `[x]_8q`. Nothing
    /// is ever truncated in a way that matters: [`Ccm::new`] refuses a payload above
    /// [`Ccm::MAX_PAYLOAD_LEN`], and the counter cannot pass that either, since there is one
    /// counter block per `BLOCK_LEN` payload bytes.
    #[inline]
    fn put_q_field(block: &mut [u8; BLOCK_LEN], x: u64) {
        let be = x.to_be_bytes();
        block[BLOCK_LEN - Self::Q_LEN..].copy_from_slice(&be[8 - Self::Q_LEN..]);
    }

    /// Builds `Ctrj` (A.3, Table 3) for counter index `j` from the template, without encrypting
    /// it. An associated function rather than a method so that [`KeyStream::apply_blocks`] can call
    /// it while it holds the counter mutably.
    #[inline]
    fn counter_block(template: &[u8; BLOCK_LEN], j: u64) -> [u8; BLOCK_LEN] {
        let mut ctr = *template;
        Self::put_q_field(&mut ctr, j);
        ctr
    }
}

impl<P, const KEY_LEN: usize, const BLOCK_LEN: usize, const NONCE_LEN: usize> Algorithm
    for CcmKeyStream<P, KEY_LEN, BLOCK_LEN, NONCE_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    const ALG_NAME: &'static str = P::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = P::MAX_SECURITY_STRENGTH;
}

impl<P, const KEY_LEN: usize, const BLOCK_LEN: usize, const NONCE_LEN: usize>
    KeyStream<KEY_LEN, NONCE_LEN, BLOCK_LEN> for CcmKeyStream<P, KEY_LEN, BLOCK_LEN, NONCE_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    fn new(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Self, SymmetricCipherError> {
        Ok(Self::from_perm(P::new(key)?, nonce))
    }

    /// Every counter value from `next_ctr` to `2^8q - 1`. Never the binding limit in practice:
    /// [`Ccm::new`] caps the payload at `2^8q - 1` bytes, far fewer than that many blocks.
    fn remaining_blocks(&self) -> u64 {
        Self::MAX_COUNTER - self.next_ctr + 1
    }

    /// Step 8's `P XOR MSB_Plen(S)` and Sec 6.2 step 5's `MSB(C) XOR MSB(S)` -- the same operation
    /// -- over whole blocks; see [`apply_counter_blocks`].
    fn apply_blocks(&mut self, blocks: &mut [[u8; BLOCK_LEN]]) {
        let template = &self.ctr_template;
        apply_counter_blocks(
            &self.perm,
            &mut self.next_ctr,
            |j| Self::counter_block(template, j),
            blocks,
        );
    }
}

/// The largest `AAD_LEN` or `DATA_LEN` [`CcmEncryptor`] / [`CcmDecryptor`] accept, 512 KiB,
/// checked at compile time.
///
/// The adapters hold the whole message on the stack -- `AAD_LEN + FINAL_LEN` in the value, and
/// the `[u8; FINAL_LEN]` their final calls return by value -- so a large buffer overflows the
/// stack rather than failing cleanly. The inherent [`Ccm`] API streams with no buffering and has
/// no such limit.
pub const CCM_MAX_BUFFER_LEN: usize = 512 * 1024;

/// Shared buffering state for [`CcmEncryptor`] / [`CcmDecryptor`]: everything Sec 6 needs before
/// it can run, factored out once because the two adapters need it in the identical shape (see
/// [`CcmEncryptor`] for why buffering is here at all). The direction-specific parts -- what the
/// buffered bytes are called, how many of them there may be, and which `Ccm` process finalization
/// runs -- stay on the two newtypes that wrap this.
///
/// The AAD array is `AAD_LEN` long and the data array `FINAL_LEN = DATA_LEN + TAG_LEN`. The
/// encryptor's payload may use `DATA_LEN` of it; the decryptor may fill all of it, since with the
/// tag inline the last `TAG_LEN` bytes it buffers are the tag.
struct CcmBuffer<
    P,
    const KEY_LEN: usize,
    const BLOCK_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const AAD_LEN: usize,
    const DATA_LEN: usize,
    const FINAL_LEN: usize,
> where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    // The key schedule, expanded once here and handed to `Ccm::from_perm` at finalization, so no
    // second copy of the key material is kept.
    perm: P,
    nonce: [u8; NONCE_LEN],
    // Associated data is authenticated but not encrypted, and travels in the clear, so it is not
    // secret and is not wrapped.
    aad: [u8; AAD_LEN],
    aad_len: usize,
    // Plaintext for the encryptor, ciphertext (and possibly the inline tag) for the decryptor;
    // either way held until finalization, so wrapped so it is zeroized on drop.
    data: Secret<[u8; FINAL_LEN]>,
    data_len: usize,
    // Set by the first non-empty `do_update_out`, which closes the AAD phase (see
    // `do_update_aad`).
    data_started: bool,
}

impl<
    P,
    const KEY_LEN: usize,
    const BLOCK_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const AAD_LEN: usize,
    const DATA_LEN: usize,
    const FINAL_LEN: usize,
> CcmBuffer<P, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN, FINAL_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    /// The compile-time checks for the trait adapters, run from every entry point of both
    /// [`CcmEncryptor`] and [`CcmDecryptor`], one-shots included: the nonce-length floor, the
    /// buffer lengths' consistency with one another and with A.1's payload limit, and the
    /// [`CCM_MAX_BUFFER_LEN`] cap.
    ///
    /// The encrypting side draws its nonce at random, and the random-collision bound is only
    /// useful from 96 bits up. The decrypting side is given its nonce, so it has no such need of
    /// its own; it carries the same floor so that the pair stays symmetric -- a `NONCE_LEN` for
    /// which `CcmDecryptor` compiles but `CcmEncryptor` does not would be a trap for code written
    /// against the generic traits, which instantiates both with one set of parameters. The
    /// inherent [`Ccm`] API supports every A.1 length from 7 through 13 under a caller-managed
    /// nonce.
    ///
    /// `FINAL_LEN` is the traits' parameter and is always `DATA_LEN + TAG_LEN`, the inline
    /// `ciphertext || tag`. It is a separate parameter only because computing it from the other two
    /// needs the unstable `generic_const_exprs` feature; the first assertion is what keeps the
    /// three consistent.
    ///
    /// The checks apply to the one-shots too, although they never build the buffer, so that a
    /// parameter set either names a usable adapter or does not compile at all.
    #[inline]
    fn check_adapter_shape() {
        const {
            assert!(
                FINAL_LEN == DATA_LEN + TAG_LEN,
                "CCM: FINAL_LEN must be DATA_LEN + TAG_LEN, the length of the inline ciphertext || tag"
            );
            assert!(
                NONCE_LEN >= 12,
                "CCM: the random-nonce AEAD adapters require NONCE_LEN >= 12; use Ccm directly with a caller-managed unique nonce for shorter lengths"
            );
            // Without this, a `DATA_LEN` beyond what `NONCE_LEN` allows compiles fine and only
            // fails at finalization, after the whole message has been buffered for nothing.
            assert!(
                DATA_LEN as u64
                    <= Ccm::<P, Encrypting, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN>::MAX_PAYLOAD_LEN,
                "CCM: DATA_LEN exceeds the payload limit 2^8q - 1 that NONCE_LEN implies (A.1)"
            );
            assert!(
                AAD_LEN <= CCM_MAX_BUFFER_LEN && DATA_LEN <= CCM_MAX_BUFFER_LEN,
                "CCM: AAD_LEN and DATA_LEN must each be at most CCM_MAX_BUFFER_LEN (512 KiB); use Ccm directly for larger messages"
            );
        }
    }

    // `inline(always)` in optimized builds, as on the adapters' `do_*_init`: the value is
    // `AAD_LEN + FINAL_LEN` bytes, and without it the value is built here and then copied out through
    // each constructor's return -- `bench_ccm_mem_usage` measured the streaming encryptor at twice
    // the stack. Inlined, it is built in the caller's slot. Not in debug builds, which elide no
    // copies either way, and where inlining keeps every callee's temporaries live at once: a
    // `CCM_MAX_BUFFER_LEN` streaming round trip needed twice the stack with it.
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn new(perm: P, nonce: [u8; NONCE_LEN]) -> Self {
        Self::check_adapter_shape();
        Self {
            perm,
            nonce,
            aad: [0u8; AAD_LEN],
            aad_len: 0,
            data: Secret::new(),
            data_len: 0,
            data_started: false,
        }
    }

    /// Buffers `aad`. A sequence of calls is equivalent to one call over the concatenation, which
    /// is what A.2.2 needs: the AAD is length-prefixed, so it can only be encoded once all of it
    /// is in hand.
    ///
    /// # Errors
    /// [`SymmetricCipherError::StateError`] for a non-empty `aad` after the first
    /// `do_update_out`, and [`SymmetricCipherError::GenericError`] if the total would exceed
    /// `AAD_LEN`.
    fn do_update_aad(&mut self, aad: &[u8]) -> Result<(), SymmetricCipherError> {
        if aad.is_empty() {
            return Ok(());
        }
        if self.data_started {
            return Err(SymmetricCipherError::StateError("CCM: do_update_aad after do_update_out"));
        }
        let end = self.aad_len + aad.len();
        if end > AAD_LEN {
            return Err(SymmetricCipherError::GenericError(
                "CCM: associated data longer than AAD_LEN",
            ));
        }
        self.aad[self.aad_len..end].copy_from_slice(aad);
        self.aad_len = end;
        Ok(())
    }

    /// Buffers `data`, up to `limit` bytes in all, and writes nothing: nothing can be released
    /// before the payload length is known, so the whole ciphertext or plaintext comes out at
    /// finalization.
    ///
    /// An empty `data` is a no-op, and in particular does **not** close the AAD phase: the trait
    /// makes an empty `aad` a no-op "at any point" so that a generic caller can pass one
    /// unconditionally, and a caller looping over a reader that returns an empty first chunk
    /// deserves the same on this side. Only a non-empty call is the start of the data phase.
    ///
    /// # Errors
    /// [`SymmetricCipherError::GenericError`], carrying `too_long`, if the total would exceed
    /// `limit`. Nothing is consumed in that case. The two callers have different limits -- the
    /// encryptor's is `DATA_LEN`, the decryptor's `FINAL_LEN` -- so each supplies the message that
    /// names its own bound.
    fn do_update_out(
        &mut self,
        data: &[u8],
        limit: usize,
        too_long: &'static str,
    ) -> Result<(), SymmetricCipherError> {
        if data.is_empty() {
            return Ok(());
        }
        // Set before the length check so that a refused oversized call still closes the AAD phase:
        // the phase order is about call history, and this call happened.
        self.data_started = true;
        let end = self.data_len + data.len();
        if end > limit {
            return Err(SymmetricCipherError::GenericError(too_long));
        }
        self.data[self.data_len..end].copy_from_slice(data);
        self.data_len = end;
        Ok(())
    }
}

/// Adapts [`Ccm`] to [`AEADCipherEncryptor`] and, through it, [`SymmetricCipherEncryptor`],
/// buffering only genuinely streaming use.
///
/// [`SymmetricCipherEncryptor::do_encrypt_init`] is handed a key and nothing else, but CCM cannot
/// form `B0` -- and so cannot authenticate anything at all -- until it knows the total payload
/// length (Appendix A.2.1; see the module docs). This type therefore accumulates up to `AAD_LEN`
/// bytes of AAD and `DATA_LEN` bytes of payload and runs the whole of Sec 6.1 at finalization, so
/// [`update_out_len`](SymmetricCipherEncryptor::do_encrypt_out_len) is identically `0` and every
/// ciphertext byte comes out of the final call.
///
/// # Nonce length
///
/// The trait generates a random nonce rather than accepting a caller-managed counter. To keep the
/// random-collision bound useful, `NONCE_LEN` must therefore be at least 12 here, and
/// [`CcmDecryptor`] carries the same floor so that the pair stays symmetric. The inherent [`Ccm`]
/// API still supports every A.1 nonce length from 7 through 13 when the caller guarantees
/// uniqueness.
///
/// The decryptor is given its nonce rather than drawing one, but refuses the same lengths, so a
/// parameter set that compiles for one side compiles for the other
///
/// See [`AEADCipherEncryptor`]'s "A length-dependent construction still has to buffer" section for
/// why this trait was not reshaped to avoid the buffering instead.
///
/// # Buffer sizes
///
/// `AAD_LEN` and `DATA_LEN` are the streaming capacities for the AAD and the payload. `FINAL_LEN`
/// is the traits' final-buffer length, the inline `ciphertext || tag`, and must be exactly
/// `DATA_LEN + TAG_LEN`; it is a separate parameter only because computing it needs the unstable
/// `generic_const_exprs` feature, and any other value is a compile error.
///
/// # Memory
///
/// A streaming value holds `AAD_LEN + FINAL_LEN` bytes. The one-shots bypass that value and use the
/// fixed-size inherent [`Ccm`] state directly, so their stack use is independent of the buffer
/// sizes, and their AAD and payload are not limited by them.
///
/// `AAD_LEN` and `DATA_LEN` are each capped at [`CCM_MAX_BUFFER_LEN`], at compile time. The cap
/// itself is accepted:
///
/// ```no_run
/// use bouncycastle_core_test_framework::ToyBlockCipher;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::traits::SymmetricCipherEncryptor;
/// use bouncycastle_cipher::modes::{CCM_MAX_BUFFER_LEN, CcmEncryptor};
///
/// let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap();
/// type Largest = CcmEncryptor<
///     ToyBlockCipher, 16, 16, 12, 16, 64, CCM_MAX_BUFFER_LEN, { CCM_MAX_BUFFER_LEN + 16 }>;
/// let _ = Largest::do_encrypt_init(&key);
/// ```
///
/// ...but one byte more does not compile:
///
/// ```compile_fail
/// use bouncycastle_core_test_framework::ToyBlockCipher;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::traits::SymmetricCipherEncryptor;
/// use bouncycastle_cipher::modes::{CCM_MAX_BUFFER_LEN, CcmEncryptor};
///
/// let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap();
/// type TooLarge = CcmEncryptor<
///     ToyBlockCipher, 16, 16, 12, 16, 64, { CCM_MAX_BUFFER_LEN + 1 }, { CCM_MAX_BUFFER_LEN + 17 }>;
/// let _ = TooLarge::do_encrypt_init(&key);
/// ```
///
/// Nor does a `FINAL_LEN` that is not `DATA_LEN + TAG_LEN`:
///
/// ```compile_fail
/// use bouncycastle_core_test_framework::ToyBlockCipher;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::traits::SymmetricCipherEncryptor;
/// use bouncycastle_cipher::modes::CcmEncryptor;
///
/// let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap();
/// // DATA_LEN 256 with a 16-byte tag needs FINAL_LEN 272.
/// type Inconsistent = CcmEncryptor<ToyBlockCipher, 16, 16, 12, 16, 64, 256, 256>;
/// let _ = Inconsistent::do_encrypt_init(&key);
/// ```
pub struct CcmEncryptor<
    P,
    const KEY_LEN: usize,
    const BLOCK_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const AAD_LEN: usize,
    const DATA_LEN: usize,
    const FINAL_LEN: usize,
>(CcmBuffer<P, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN, FINAL_LEN>)
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>;

impl<
    P,
    const KEY_LEN: usize,
    const BLOCK_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const AAD_LEN: usize,
    const DATA_LEN: usize,
    const FINAL_LEN: usize,
> Algorithm
    for CcmEncryptor<P, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN, FINAL_LEN>
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
    const AAD_LEN: usize,
    const DATA_LEN: usize,
    const FINAL_LEN: usize,
> CcmEncryptor<P, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN, FINAL_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    /// Every one-shot comes here: they already have both lengths, so they skip the buffer and run
    /// the inherent non-buffering [`Ccm::encrypt_out_detached`] under a freshly drawn nonce.
    fn one_shot(
        key: &KeyMaterial<KEY_LEN>,
        rng: &mut dyn RNG,
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<([u8; NONCE_LEN], usize, [u8; TAG_LEN]), SymmetricCipherError> {
        if ciphertext.len() < plaintext.len() {
            return Err(SymmetricCipherError::OutputBufferTooSmall(plaintext.len()));
        }
        Ccm::<P, Encrypting, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN>::check_shape();
        CcmBuffer::<P, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN, FINAL_LEN>::check_adapter_shape();
        let nonce = random_iv::<NONCE_LEN>(rng)?;
        let (written, tag) =
            Ccm::<P, Encrypting, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN>::encrypt_out_detached(
                key, &nonce, aad, plaintext, ciphertext,
            )?;
        Ok((nonce, written, tag))
    }

    /// [`Self::one_shot`] into the inline `ciphertext || tag` layout.
    fn one_shot_inline(
        key: &KeyMaterial<KEY_LEN>,
        rng: &mut dyn RNG,
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<([u8; NONCE_LEN], usize), SymmetricCipherError> {
        let needed = plaintext.len() + TAG_LEN;
        if ciphertext.len() < needed {
            return Err(SymmetricCipherError::OutputBufferTooSmall(needed));
        }
        let (data, tag_out) = ciphertext[..needed].split_at_mut(plaintext.len());
        let (nonce, written, tag) = Self::one_shot(key, rng, aad, plaintext, data)?;
        tag_out.copy_from_slice(&tag);
        Ok((nonce, written + TAG_LEN))
    }

    /// Runs the whole of Sec 6.1 over the buffered payload: writes the ciphertext to
    /// `ciphertext[..len]` and returns the tag.
    ///
    /// Every final comes here, and it takes the buffer's fields rather than the value itself on
    /// purpose. The value is `AAD_LEN + FINAL_LEN` bytes, and handing it from one consuming method to
    /// another by value is a copy of all of it that the optimizer is free not to elide --
    /// `bench_ccm_mem_usage` measured the finals at several times the size of the arrays before
    /// they were written this way. Only the key schedule is moved, into the [`Ccm`] that does the
    /// work.
    fn seal(
        perm: P,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        data: &mut Secret<[u8; FINAL_LEN]>,
        len: usize,
        ciphertext: &mut [u8],
    ) -> Result<[u8; TAG_LEN], SymmetricCipherError> {
        ciphertext[..len].copy_from_slice(&data[..len]);
        let mut ccm = Ccm::<P, Encrypting, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN>::from_perm(
            perm, nonce, aad, len,
        )?;
        ccm.do_encrypt(&mut ciphertext[..len])?;
        // Scrub the plaintext copy as soon as the ciphertext is in `ciphertext`, rather than
        // waiting for `data` to drop: the buffer is large and this keeps the window short.
        data.zeroize();
        ccm.do_encrypt_final()
    }
}

impl<
    P,
    const KEY_LEN: usize,
    const BLOCK_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const AAD_LEN: usize,
    const DATA_LEN: usize,
    const FINAL_LEN: usize,
> SymmetricCipherEncryptor<KEY_LEN, NONCE_LEN, FINAL_LEN>
    for CcmEncryptor<P, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN, FINAL_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    // `inline(always)`: see `CcmBuffer::new`.
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn do_encrypt_init(
        key: &KeyMaterial<KEY_LEN>,
    ) -> Result<(Self, [u8; NONCE_LEN]), SymmetricCipherError> {
        let mut rng = HashDRBG_SHA512::new_from_os();
        Self::do_encrypt_init_rng(key, &mut rng)
    }

    // `inline(always)`: see `CcmBuffer::new`.
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn do_encrypt_init_rng(
        key: &KeyMaterial<KEY_LEN>,
        rng: &mut dyn RNG,
    ) -> Result<(Self, [u8; NONCE_LEN]), SymmetricCipherError> {
        // The shape check belongs here too: this type never calls `Ccm::new`, and without it a
        // `NONCE_LEN` or `TAG_LEN` A.1 forbids would not be caught until finalization. The
        // random-nonce floor and the buffer-length checks are `CcmBuffer::new`'s.
        Ccm::<P, Encrypting, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN>::check_shape();
        // `P::new`'s own checks are the only key validation needed, exactly as for `Ccm` itself
        // and every other mode in this crate; `random_iv` is CBC/CFB's same OS-backed draw --
        // Sec 5.3 asks only for uniqueness, not CBC/CFB's unpredictability, but a CSPRNG draw is
        // the only way to be unique without state `do_encrypt_init` does not have.
        let perm = P::new(key)?;
        let nonce = random_iv::<NONCE_LEN>(rng)?;
        Ok((Self(CcmBuffer::new(perm, nonce)), nonce))
    }

    /// Identically `0`: nothing can be released before the payload length is known, so the whole
    /// ciphertext comes out of the final call.
    fn do_encrypt_out_len(&self, _input_len: usize) -> usize {
        0
    }

    /// Buffers `plaintext` and writes nothing, per [`CcmDecryptor::do_decrypt_out_len`]. `ciphertext` is
    /// untouched and may be empty. An empty `plaintext` is a no-op and leaves the AAD phase open.
    ///
    /// # Errors
    /// [`SymmetricCipherError::GenericError`] if the total would exceed `DATA_LEN`.
    fn do_encrypt_out(
        &mut self,
        plaintext: &[u8],
        _ciphertext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        self.0.do_update_out(
            plaintext,
            DATA_LEN,
            "CCM: plaintext longer than DATA_LEN, the streaming capacity",
        )?;
        Ok(0)
    }

    /// Runs the whole of Sec 6.1 over the buffered message and returns the spec's own output
    /// string, `ciphertext || tag` (step 8), with its length.
    ///
    /// # Errors
    /// As [`AEADCipherEncryptor::do_final_out_detached`].
    fn do_final(mut self) -> Result<([u8; FINAL_LEN], usize), SymmetricCipherError> {
        let mut out = [0u8; FINAL_LEN];
        let len = self.0.data_len;
        let tag = Self::seal(
            self.0.perm,
            &self.0.nonce,
            &self.0.aad[..self.0.aad_len],
            &mut self.0.data,
            len,
            &mut out,
        )?;
        // `do_update_out` held the payload to `DATA_LEN = FINAL_LEN - TAG_LEN`, so the tag fits
        // after it.
        out[len..len + TAG_LEN].copy_from_slice(&tag);
        Ok((out, len + TAG_LEN))
    }

    /// As [`Self::do_final`], written straight into `ciphertext` rather than built and copied, so
    /// the caller's buffer is the only `FINAL_LEN` array the call adds. Bytes past the returned
    /// length are zeroed, as the provided method's copy of a zero-initialized buffer leaves them.
    fn do_final_out(
        mut self,
        ciphertext: &mut [u8; FINAL_LEN],
    ) -> Result<usize, SymmetricCipherError> {
        let len = self.0.data_len;
        let tag = Self::seal(
            self.0.perm,
            &self.0.nonce,
            &self.0.aad[..self.0.aad_len],
            &mut self.0.data,
            len,
            ciphertext,
        )?;
        ciphertext[len..len + TAG_LEN].copy_from_slice(&tag);
        ciphertext[len + TAG_LEN..].fill(0);
        Ok(len + TAG_LEN)
    }

    /// The ciphertext, which is as long as the plaintext, followed by the tag.
    fn encrypt_out_len(plaintext_len: usize) -> usize {
        plaintext_len + TAG_LEN
    }

    fn encrypt_out(
        key: &KeyMaterial<KEY_LEN>,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<([u8; NONCE_LEN], usize), SymmetricCipherError> {
        let mut rng = HashDRBG_SHA512::new_from_os();
        Self::one_shot_inline(key, &mut rng, &[], plaintext, ciphertext)
    }

    fn encrypt_out_rng(
        key: &KeyMaterial<KEY_LEN>,
        rng: &mut dyn RNG,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<([u8; NONCE_LEN], usize), SymmetricCipherError> {
        Self::one_shot_inline(key, rng, &[], plaintext, ciphertext)
    }
}

impl<
    P,
    const KEY_LEN: usize,
    const BLOCK_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const AAD_LEN: usize,
    const DATA_LEN: usize,
    const FINAL_LEN: usize,
> AEADCipherEncryptor<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>
    for CcmEncryptor<P, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN, FINAL_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    /// Buffers `aad`. A sequence of calls is equivalent to one call over the concatenation, which
    /// is what A.2.2 needs: the AAD is length-prefixed, so it can only be encoded once all of it
    /// is in hand.
    ///
    /// # Errors
    /// `SymmetricCipherError::StateError` for a non-empty `aad` after the first `do_update_out`,
    /// and `SymmetricCipherError::GenericError` if the total would exceed `AAD_LEN`.
    fn do_update_aad(&mut self, aad: &[u8]) -> Result<(), SymmetricCipherError> {
        self.0.do_update_aad(aad)
    }

    /// Runs the whole of Sec 6.1 over the buffered message: writes the ciphertext to `ciphertext`
    /// and returns its length with the tag.
    ///
    /// # Errors
    /// None, in practice: the `const` assertion in construction already guarantees
    /// `DATA_LEN <= `[`Ccm::MAX_PAYLOAD_LEN`], the only thing [`Ccm::new`]'s equivalent
    /// construction path can fail on, and `do_update_out` already guarantees the payload it
    /// buffered is no more than `DATA_LEN`. The `Result` return exists to satisfy the trait's
    /// signature.
    fn do_final_out_detached(
        mut self,
        ciphertext: &mut [u8; FINAL_LEN],
    ) -> Result<(usize, [u8; TAG_LEN]), SymmetricCipherError> {
        let len = self.0.data_len;
        let tag = Self::seal(
            self.0.perm,
            &self.0.nonce,
            &self.0.aad[..self.0.aad_len],
            &mut self.0.data,
            len,
            ciphertext,
        )?;
        Ok((len, tag))
    }

    fn encrypt_out_detached(
        key: &KeyMaterial<KEY_LEN>,
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<([u8; NONCE_LEN], usize, [u8; TAG_LEN]), SymmetricCipherError> {
        let mut rng = HashDRBG_SHA512::new_from_os();
        Self::one_shot(key, &mut rng, aad, plaintext, ciphertext)
    }

    fn encrypt_out_rng_detached(
        key: &KeyMaterial<KEY_LEN>,
        rng: &mut dyn RNG,
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<([u8; NONCE_LEN], usize, [u8; TAG_LEN]), SymmetricCipherError> {
        Self::one_shot(key, rng, aad, plaintext, ciphertext)
    }

    fn encrypt_out_with_aad(
        key: &KeyMaterial<KEY_LEN>,
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<([u8; NONCE_LEN], usize), SymmetricCipherError> {
        let mut rng = HashDRBG_SHA512::new_from_os();
        Self::one_shot_inline(key, &mut rng, aad, plaintext, ciphertext)
    }

    fn encrypt_out_rng_with_aad(
        key: &KeyMaterial<KEY_LEN>,
        rng: &mut dyn RNG,
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<([u8; NONCE_LEN], usize), SymmetricCipherError> {
        Self::one_shot_inline(key, rng, aad, plaintext, ciphertext)
    }
}

/// Adapts [`Ccm`] to [`AEADCipherDecryptor`] and, through it, [`SymmetricCipherDecryptor`], by
/// buffering the whole message; the mirror of [`CcmEncryptor`], and see it for why the buffering
/// is unavoidable, what it costs, and what `AAD_LEN`, `DATA_LEN` and `FINAL_LEN` mean.
///
/// The decryptor buffers up to `FINAL_LEN` bytes of ciphertext -- a `DATA_LEN`-byte ciphertext
/// and, with the tag inline, the tag after it -- because until the final call it cannot know which
/// layout it is being given. With the tag detached the ciphertext is still held to `DATA_LEN`,
/// the same limit the encryptor applies.
///
/// `NONCE_LEN` must be at least 12, as for [`CcmEncryptor`]: the nonce is supplied here rather
/// than drawn, but the pair is kept symmetric so that a parameter set which compiles for one side
/// compiles for the other. See "Random nonce length" on [`CcmEncryptor`].
pub struct CcmDecryptor<
    P,
    const KEY_LEN: usize,
    const BLOCK_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const AAD_LEN: usize,
    const DATA_LEN: usize,
    const FINAL_LEN: usize,
>(CcmBuffer<P, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN, FINAL_LEN>)
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>;

impl<
    P,
    const KEY_LEN: usize,
    const BLOCK_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const AAD_LEN: usize,
    const DATA_LEN: usize,
    const FINAL_LEN: usize,
> Algorithm
    for CcmDecryptor<P, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN, FINAL_LEN>
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
    const AAD_LEN: usize,
    const DATA_LEN: usize,
    const FINAL_LEN: usize,
> CcmDecryptor<P, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN, FINAL_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    /// Runs the whole of Sec 6.2 over the first `len` buffered bytes as ciphertext, checking `tag`,
    /// with the plaintext written to `plaintext[..len]`. On failure that is zeroized before the
    /// error is returned: Sec 6.2's "the payload P and the MAC T shall not be revealed".
    ///
    /// Takes the buffer's fields rather than the value, for the reason given on
    /// [`CcmEncryptor`]'s `seal`: only the key schedule is moved.
    fn open(
        perm: P,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        data: &mut Secret<[u8; FINAL_LEN]>,
        len: usize,
        tag: &[u8; TAG_LEN],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        plaintext[..len].copy_from_slice(&data[..len]);
        let mut ccm = Ccm::<P, Decrypting, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN>::from_perm(
            perm, nonce, aad, len,
        )?;
        ccm.do_decrypt_update(&mut plaintext[..len])?;
        data.zeroize();
        match ccm.do_decrypt_final(tag) {
            Ok(()) => Ok(len),
            Err(e) => {
                plaintext[..len].fill(0);
                Err(e)
            }
        }
    }

    /// The inline layout's tag split, shared by [`SymmetricCipherDecryptor::do_final`] and
    /// [`SymmetricCipherDecryptor::do_final_out`]: the payload length and a copy of the tag.
    ///
    /// # Errors
    /// [`SymmetricCipherError::DecryptionFailed`] if fewer than `TAG_LEN` bytes were buffered,
    /// Sec 6.2 step 1.
    fn split_inline_tag(&self) -> Result<(usize, [u8; TAG_LEN]), SymmetricCipherError> {
        let Some(len) = self.0.data_len.checked_sub(TAG_LEN) else {
            return Err(SymmetricCipherError::DecryptionFailed);
        };
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&self.0.data[len..len + TAG_LEN]);
        Ok((len, tag))
    }
}

impl<
    P,
    const KEY_LEN: usize,
    const BLOCK_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const AAD_LEN: usize,
    const DATA_LEN: usize,
    const FINAL_LEN: usize,
> SymmetricCipherDecryptor<KEY_LEN, NONCE_LEN, FINAL_LEN>
    for CcmDecryptor<P, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN, FINAL_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    // `inline(always)`: see `CcmBuffer::new`.
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn do_decrypt_init(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Self, SymmetricCipherError> {
        Ccm::<P, Decrypting, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN>::check_shape();
        // `P::new`'s own checks are the only key validation needed; see the encryptor's identical
        // reasoning. `CcmBuffer::new` carries the buffer-length assertions and the nonce floor.
        let perm = P::new(key)?;
        Ok(Self(CcmBuffer::new(perm, *nonce)))
    }

    /// Identically `0`. This is the one thing a CCM decryptor gets *right* by being forced to
    /// buffer: it releases no plaintext at all before the tag has been checked, so
    /// [`AEADCipherDecryptor`]'s warning about unauthenticated output cannot bite a caller here.
    fn do_decrypt_out_len(&self, _input_len: usize) -> usize {
        0
    }

    /// Buffers `ciphertext` and writes nothing, per [`Self::do_decrypt_out_len`]. An empty
    /// `ciphertext` is a no-op and leaves the AAD phase open.
    ///
    /// # Errors
    /// [`SymmetricCipherError::GenericError`] if the total would exceed `FINAL_LEN`, i.e.
    /// `DATA_LEN` of ciphertext and an inline tag.
    fn do_decrypt_out(
        &mut self,
        ciphertext: &[u8],
        _plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        self.0.do_update_out(
            ciphertext,
            FINAL_LEN,
            "CCM: ciphertext longer than DATA_LEN + TAG_LEN, the streaming capacity",
        )?;
        Ok(0)
    }

    /// The inline layout: the last `TAG_LEN` buffered bytes are the tag (Sec 6.2 step 6's
    /// `LSB_Tlen(C)`), and Sec 6.2 runs over the rest.
    ///
    /// # Errors
    /// [`SymmetricCipherError::DecryptionFailed`] if fewer than `TAG_LEN` bytes were buffered,
    /// Sec 6.2 step 1; [`SymmetricCipherError::AEADTagCheckFailed`] if the tag does not verify.
    fn do_final(mut self) -> Result<([u8; FINAL_LEN], usize), SymmetricCipherError> {
        let (len, tag) = self.split_inline_tag()?;
        let mut plaintext = [0u8; FINAL_LEN];
        let n = Self::open(
            self.0.perm,
            &self.0.nonce,
            &self.0.aad[..self.0.aad_len],
            &mut self.0.data,
            len,
            &tag,
            &mut plaintext,
        )?;
        Ok((plaintext, n))
    }

    /// As [`Self::do_final`], written straight into `plaintext` rather than built and copied.
    /// Bytes past the returned length are zeroed, as the provided method's copy of a
    /// zero-initialized buffer leaves them.
    ///
    /// # Errors
    /// As [`Self::do_final`]; on a failed tag check `plaintext[..len]` has been zeroized too.
    fn do_final_out(
        mut self,
        plaintext: &mut [u8; FINAL_LEN],
    ) -> Result<usize, SymmetricCipherError> {
        let (len, tag) = self.split_inline_tag()?;
        let n = Self::open(
            self.0.perm,
            &self.0.nonce,
            &self.0.aad[..self.0.aad_len],
            &mut self.0.data,
            len,
            &tag,
            plaintext,
        )?;
        plaintext[n..].fill(0);
        Ok(n)
    }

    /// Everything but the trailing tag.
    fn decrypt_out_max_len(ciphertext_len: usize) -> usize {
        ciphertext_len.saturating_sub(TAG_LEN)
    }

    fn decrypt_out(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        Self::decrypt_out_with_aad(key, nonce, &[], ciphertext, plaintext)
    }
}

impl<
    P,
    const KEY_LEN: usize,
    const BLOCK_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const AAD_LEN: usize,
    const DATA_LEN: usize,
    const FINAL_LEN: usize,
> AEADCipherDecryptor<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>
    for CcmDecryptor<P, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN, FINAL_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    /// As [`CcmEncryptor::do_update_aad`](AEADCipherEncryptor::do_update_aad); the concatenation
    /// must match the encryptor's byte for byte or the tag check fails.
    fn do_update_aad(&mut self, aad: &[u8]) -> Result<(), SymmetricCipherError> {
        self.0.do_update_aad(aad)
    }

    /// The detached layout: every buffered byte is ciphertext, and Sec 6.2 runs over all of it
    /// against `tag`. On failure `plaintext` is zeroized before the error is returned.
    ///
    /// # Errors
    /// [`SymmetricCipherError::GenericError`] if more than `DATA_LEN` bytes were
    /// buffered -- room the decryptor keeps only for an inline tag;
    /// [`SymmetricCipherError::AEADTagCheckFailed`] if the tag does not verify.
    fn do_final_out_detached(
        mut self,
        tag: &[u8; TAG_LEN],
        plaintext: &mut [u8; FINAL_LEN],
    ) -> Result<usize, SymmetricCipherError> {
        let len = self.0.data_len;
        if len > DATA_LEN {
            return Err(SymmetricCipherError::GenericError(
                "CCM: detached ciphertext longer than DATA_LEN",
            ));
        }
        Self::open(
            self.0.perm,
            &self.0.nonce,
            &self.0.aad[..self.0.aad_len],
            &mut self.0.data,
            len,
            tag,
            plaintext,
        )
    }

    fn decrypt_out_detached(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; TAG_LEN],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        // The one-shots never construct a `CcmBuffer`, so the nonce floor and the buffer-length
        // checks are asserted here, as the encryptor's `one_shot` does.
        CcmBuffer::<P, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN, FINAL_LEN>::check_adapter_shape();
        Ccm::<P, Decrypting, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN>::decrypt_out_detached(
            key, nonce, aad, ciphertext, tag, plaintext,
        )
    }

    /// Splits the trailing `TAG_LEN` bytes off as the tag and runs the non-buffering
    /// [`Ccm::decrypt_out_detached`], checking the output buffer first so that a short one is reported
    /// before a short ciphertext.
    ///
    /// # Errors
    /// [`SymmetricCipherError::OutputBufferTooSmall`] if `plaintext` is too short;
    /// [`SymmetricCipherError::DecryptionFailed`] if `ciphertext` is shorter than the tag;
    /// otherwise as [`Ccm::decrypt_out_detached`].
    fn decrypt_out_with_aad(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        let needed = Self::decrypt_out_max_len(ciphertext.len());
        if plaintext.len() < needed {
            return Err(SymmetricCipherError::OutputBufferTooSmall(needed));
        }
        let Some((data, tag)) = ciphertext.split_last_chunk::<TAG_LEN>() else {
            return Err(SymmetricCipherError::DecryptionFailed);
        };
        Self::decrypt_out_detached(key, nonce, aad, data, tag, plaintext)
    }
}

/// The suspended state is the CTR half, the CBC-MAC chaining value, how much of its current
/// block has gone in, and how much AAD and payload are still owed. The chaining value is
/// key-dependent MAC state, which is why the state must be protected; see [`bouncycastle_utils::suspendable_state`].
impl<
    P,
    Dir,
    const KEY_LEN: usize,
    const BLOCK_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
> SuspendableComponent for Ccm<P, Dir, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    const STATE_LEN: usize = Self::CTR_STATE_LEN + BLOCK_LEN + 8 + 8 + 8;
    type Key = KeyMaterial<KEY_LEN>;

    fn write_state(&self, out: &mut [u8]) {
        let (ctr, rest) = out.split_at_mut(Self::CTR_STATE_LEN);
        self.ctr.write_state(ctr);
        let mut w = CursorMut::new(rest);
        w.bytes(&*self.y);
        w.u64(self.mac_pos as u64);
        w.u64(self.aad_owed as u64);
        w.u64(self.owed as u64);
        debug_assert!(w.is_done());
    }

    fn read_state(state: &[u8], key: &Self::Key) -> Result<Self, SuspendableError> {
        Self::check_shape();
        let (ctr, rest) = state.split_at(Self::CTR_STATE_LEN);
        let ctr = StreamCipher::read_state(ctr, key)?;
        let mut r = Cursor::new(rest);
        let mut y: Secret<[u8; BLOCK_LEN]> = Secret::new();
        (*y).copy_from_slice(r.bytes(BLOCK_LEN));
        // A whole block is enciphered as soon as it is full, so `mac_pos` is always below
        // `BLOCK_LEN`; the owed payload cannot exceed what `B0` could have committed to.
        let mac_pos = bounded_usize(r.u64(), BLOCK_LEN - 1)?;
        let aad_owed = bounded_usize(r.u64(), usize::MAX)?;
        let owed = bounded_usize(r.u64(), usize::MAX)?;
        if owed as u64 > Self::MAX_PAYLOAD_LEN {
            return Err(SuspendableError::InvalidData);
        }
        debug_assert!(r.is_done());
        Ok(Self { ctr, y, mac_pos, aad_owed, owed, _dir: PhantomData })
    }
}

/// `N` must be [`Ccm::SUSPENDED_STATE_LEN`]; anything else is a compile error.
impl<
    P,
    Dir,
    const KEY_LEN: usize,
    const BLOCK_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const N: usize,
> SuspendableKeyed<N> for Ccm<P, Dir, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    type Key = KeyMaterial<KEY_LEN>;

    fn suspend(self) -> [u8; N] {
        suspend_component(&self)
    }

    fn from_suspended(state: [u8; N], key: &Self::Key) -> Result<Self, SuspendableError> {
        resume_component(&state, key)
    }
}

/// The suspended state is the counter template and the next counter index; the permutation is
/// rebuilt from the re-supplied key. Crate-private like the type, reachable only through
/// [`Ccm`]'s state.
impl<P, const KEY_LEN: usize, const BLOCK_LEN: usize, const NONCE_LEN: usize> SuspendableComponent
    for CcmKeyStream<P, KEY_LEN, BLOCK_LEN, NONCE_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    const STATE_LEN: usize = BLOCK_LEN + 8;
    type Key = KeyMaterial<KEY_LEN>;

    fn write_state(&self, out: &mut [u8]) {
        let mut w = CursorMut::new(out);
        w.bytes(&self.ctr_template);
        w.u64(self.next_ctr);
        debug_assert!(w.is_done());
    }

    fn read_state(state: &[u8], key: &Self::Key) -> Result<Self, SuspendableError> {
        let perm = P::new(key).map_err(|_| SuspendableError::InvalidData)?;
        let mut r = Cursor::new(state);
        let ctr_template = r.array::<BLOCK_LEN>();
        // A.3: the flags octet is `[q-1]_3` and nothing else, and the counter field is zero in
        // the template; `next_ctr` starts at 1 (`S0` is the tag mask) and stops at `MAX_COUNTER`.
        let next_ctr = r.u64();
        let flags_ok = ctr_template[0] == (Self::Q_LEN - 1) as u8;
        let counter_field_zero = ctr_template[BLOCK_LEN - Self::Q_LEN..].iter().all(|&b| b == 0);
        let ctr_ok = next_ctr >= 1 && next_ctr - 1 <= Self::MAX_COUNTER;
        if !(flags_ok && counter_field_zero && ctr_ok) {
            return Err(SuspendableError::InvalidData);
        }
        debug_assert!(r.is_done());
        Ok(Self { perm, ctr_template, next_ctr })
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
        fn encrypt_2blocks(&self, _blocks: &mut [[u8; 16]; 2]) {}
        fn decrypt_2blocks(&self, _blocks: &mut [[u8; 16]; 2]) {}
        fn encrypt_4blocks(&self, _blocks: &mut [[u8; 16]; 4]) {}
        fn decrypt_4blocks(&self, _blocks: &mut [[u8; 16]; 4]) {}
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
        assert_eq!(*ccm.y, Ccm::<Identity, Encrypting, 16, 16, 7, 4>::format_b0(&nonce, false, 4));
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
        let mut ks = CcmKeyStream::<Identity, 16, 16, 7>::from_perm(Identity, &nonce_c1);
        // `Ctr0` is the template with a zero counter field.
        let ctr0 = CcmKeyStream::<Identity, 16, 16, 7>::counter_block(&ks.ctr_template, 0);
        assert_eq!(
            ctr0,
            [0x07, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0, 0, 0, 0, 0, 0, 0, 0],
            "C.1 Ctr0"
        );
        // The first payload keystream block is `S1`, so the first block the keystream XORs in must
        // be `Ctr1`: under the identity permutation, XORed into zeros, that is `Ctr1` itself.
        let mut s1 = [[0u8; 16]];
        ks.apply_blocks(&mut s1);
        let mut ctr1 = ctr0;
        ctr1[15] = 1;
        assert_eq!(s1[0], ctr1, "C.1 Ctr1 (the identity permutation leaves S1 = Ctr1)");

        let nonce_c4 =
            [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c];
        let ks4 = CcmKeyStream::<Identity, 16, 16, 13>::from_perm(Identity, &nonce_c4);
        assert_eq!(
            CcmKeyStream::<Identity, 16, 16, 13>::counter_block(&ks4.ctr_template, 0),
            [
                0x01, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
                0x00, 0x00
            ],
            "C.4 Ctr0"
        );
    }

    /// A fresh keystream has every counter value but `Ctr0` left: step 7's `S1 || S2 || ...` runs
    /// from `j = 1` to the largest `q`-octet counter, `2^8q - 1`, and `S0` is the tag mask. Pinned
    /// absolutely because the limit can never bind through the public API -- A.1 caps the payload
    /// at `2^8q - 1` bytes, far fewer than that many blocks -- so nothing else would notice an
    /// off-by-one here.
    #[test]
    fn a_fresh_keystream_has_every_counter_but_ctr0_left() {
        // n = 13, so q = 2: counters 1 ..= 65535.
        let ks = CcmKeyStream::<Identity, 16, 16, 13>::from_perm(Identity, &[0u8; 13]);
        assert_eq!(ks.remaining_blocks(), 65535);
        // n = 7, so q = 8: counters 1 ..= 2^64 - 1, which is `u64::MAX` of them.
        let ks = CcmKeyStream::<Identity, 16, 16, 7>::from_perm(Identity, &[0u8; 7]);
        assert_eq!(ks.remaining_blocks(), u64::MAX);
    }

    /// CCM's keystream against the shared [`KeyStream`] conformance suite. A unit test rather than
    /// an integration test because `CcmKeyStream` is crate-private. Over the framework's keyed
    /// toy rather than the identity, which ignores the key and so could not pass the key-policy
    /// checks.
    #[test]
    fn ccm_keystream_conforms_to_the_key_stream_framework() {
        use bouncycastle_core_test_framework::ToyBlockCipher;
        use bouncycastle_core_test_framework::key_stream::TestFrameworkKeyStream;
        let framework = TestFrameworkKeyStream::new();
        framework.test::<16, 7, 16, CcmKeyStream<ToyBlockCipher, 16, 16, 7>>();
        framework.test::<16, 13, 16, CcmKeyStream<ToyBlockCipher, 16, 16, 13>>();
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
        assert_eq!(*ccm.y, expected, "y must be B0 ^ B1, with B1 starting with [14]_16");
    }
}
