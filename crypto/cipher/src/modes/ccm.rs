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
        let mut ccm = Self::from_perm_with_lengths(perm, nonce, aad.len(), payload_len)?;
        // Exactly the length just declared, so nothing is left owed.
        ccm.absorb_aad(aad);
        Ok(ccm)
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
                "CCM was given more AAD than the declared AAD length, which the AAD length \
                 encoding commits to",
            ));
        }
        self.absorb_aad(aad);
        Ok(())
    }

    /// [`Self::do_update_aad`] without its check: `aad` must be at most the AAD still owed, which
    /// the caller has established. An empty `aad` is a no-op.
    fn absorb_aad(&mut self, aad: &[u8]) {
        if aad.is_empty() {
            return;
        }
        self.mac_absorb(aad);
        self.aad_owed -= aad.len();
        if self.aad_owed == 0 {
            // The AAD's own blocks `B1 ... Bu` end on a block boundary, and A.2.3's payload blocks
            // are `Bu+1 ...`. So the zero pad happens *here*, not once at the very end.
            self.mac_pad();
        }
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
        let mut ccm = Self::from_perm_unformatted(perm, nonce, payload_len);
        ccm.format_header(aad_len);
        Ok(ccm)
    }

    /// The state *before* Sec 6.1 step 1: the keystream is positioned at `S1` and `payload_len`
    /// is owed, but nothing has been absorbed into the CBC-MAC, not even `B0`.
    ///
    /// Crate-private, for [`CcmEncryptor`] / [`CcmDecryptor`]: the trait constructor they
    /// implement is handed a key and no AAD, and `B0`'s Adata bit (A.2.2: "'0' if a=0 and '1' if
    /// a>0") cannot be set until the AAD is complete. They call [`Self::format_header`] when it
    /// is, and nothing else may touch the MAC before that. `payload_len` must already be at most
    /// [`Self::MAX_PAYLOAD_LEN`]; the adapters assert theirs at compile time.
    fn from_perm_unformatted(perm: P, nonce: &[u8; NONCE_LEN], payload_len: usize) -> Self {
        Self::check_shape();
        Self {
            ctr: StreamCipher::from_keystream(CcmKeyStream::from_perm(perm, nonce)),
            // Sec 6.1 step 2 is `Y0 = CIPH_K(B0)`, with no XOR, unlike step 3's `Bi XOR Yi-1`.
            // Starting the chaining value at zero unifies the two: `B0 XOR 0 = B0`, so absorbing
            // `B0` through the same path as every other block yields exactly `Y0`.
            y: Secret::new(),
            mac_pos: 0,
            aad_owed: 0,
            owed: payload_len,
            _dir: PhantomData,
        }
    }

    /// Sec 6.1 step 1's formatting of `N`, `a` and `Plen`: absorbs `B0` (A.2.1) and, if `a > 0`,
    /// the encoding of `a` (A.2.2), and opens the AAD phase for `aad_len` bytes. Called exactly
    /// once, on a value from [`Self::from_perm_unformatted`] that has absorbed nothing yet, which
    /// is why `B0`'s payload length is simply what is still owed.
    fn format_header(&mut self, aad_len: usize) {
        self.aad_owed = aad_len;
        let nonce = self.ctr.keystream().nonce();
        self.mac_absorb(&Self::format_b0(&nonce, aad_len > 0, self.owed as u64));

        // A.2.2: if `a > 0`, "the encoding of a is concatenated with the associated data A,
        // followed by the minimum number of '0' bits, possibly none, such that the resulting string
        // can be partitioned into 16-octet blocks". The encoding goes in now; `A` and the pad
        // follow through `do_update_aad`. If `a = 0` there are no AAD blocks at all, so nothing is
        // absorbed and nothing is padded, and `B0` has already ended on a block boundary.
        if aad_len > 0 {
            let (encoded, encoded_len) = Self::encode_aad_len(aad_len as u64);
            self.mac_absorb(&encoded[..encoded_len]);
        }
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
                "CCM was given payload before all of the declared AAD; A.2.3 puts the payload \
                 after the AAD",
            ));
        }
        if len > self.owed {
            return Err(SymmetricCipherError::StateError(
                "CCM was given more payload than the declared payload length, which B0 commits to",
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
        self.ctr.do_encrypt_inplace(data)?;
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
                "CCM was given less AAD than the declared AAD length",
            ));
        }
        if self.owed != 0 {
            return Err(SymmetricCipherError::StateError(
                "CCM was given less payload than the declared payload length, which B0 commits to",
            ));
        }
        Ok(self.finish_mac())
    }

    /// One-shot generation-encryption with a **detached** tag (Sec 6.1).
    ///
    /// Writes `plaintext.len()` bytes of ciphertext into `ciphertext` and returns that count with
    /// the tag. The entire output buffer is zeroized before the ciphertext is written, so any bytes
    /// past that count will be 0. For the spec's own inline `ciphertext || tag` string, use
    /// [`Self::encrypt_out`].
    ///
    /// # Errors
    /// [`SymmetricCipherError::OutputBufferTooSmall`] if `ciphertext` is too short, plus
    /// [`Self::new`]'s errors.
    pub fn encrypt_detached_out(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<(usize, [u8; TAG_LEN]), SymmetricCipherError> {
        ciphertext.fill(0);
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
    /// The entire output buffer is zeroized before the output is written, so any bytes past that
    /// count will be 0.
    ///
    /// # Errors
    /// As [`Self::encrypt_detached_out`].
    pub fn encrypt_out(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        ciphertext.fill(0);
        let needed = plaintext.len() + TAG_LEN;
        if ciphertext.len() < needed {
            return Err(SymmetricCipherError::OutputBufferTooSmall(needed));
        }
        let (data, tag_out) = ciphertext[..needed].split_at_mut(plaintext.len());
        let (_, tag) = Self::encrypt_detached_out(key, nonce, aad, plaintext, data)?;
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
        self.ctr.do_decrypt_inplace(data)?;
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
                "CCM was given less AAD than the declared AAD length",
            ));
        }
        if self.owed != 0 {
            return Err(SymmetricCipherError::StateError(
                "CCM was given less ciphertext than the declared payload length, which B0 commits to",
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
    /// Returns the number of plaintext bytes written. The entire output buffer is zeroized before
    /// the plaintext is written, so any bytes past that count will be 0. On failure `plaintext` is zeroized before the error is returned, so Sec 6.2's "the payload P
    /// and the MAC T shall not be revealed" holds even for a caller who ignores the `Result`.
    ///
    /// # Errors
    /// [`SymmetricCipherError::AEADTagCheckFailed`] if the tag does not verify,
    /// [`SymmetricCipherError::OutputBufferTooSmall`] if `plaintext` is too short, plus
    /// [`Self::new`]'s errors.
    pub fn decrypt_detached_out(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; TAG_LEN],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        plaintext.fill(0);
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
    /// trailing `TAG_LEN` bytes off `ciphertext` as the tag -- step 6's `LSB_Tlen(C)`. Returns the
    /// number of plaintext bytes written. The entire output buffer is zeroized before the plaintext
    /// is written, so any bytes past that count will be 0.
    ///
    /// # Errors
    /// [`SymmetricCipherError::DecryptionFailed`] for Sec 6.2 step 1, "If Clen <= Tlen, then
    /// return INVALID": a malformed input rather than a failed check, reported with the variant
    /// [`SymmetricCipherDecryptor::do_decrypt_final`] specifies for a malformed ciphertext so that
    /// every inline entry point -- this one, [`CcmDecryptor::do_decrypt_final`] and
    /// [`CcmDecryptor::decrypt_with_aad_out`](AEADCipherDecryptor::decrypt_with_aad_out) -- agrees
    /// on the same input. Otherwise as [`Self::decrypt_detached_out`].
    pub fn decrypt_out(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        plaintext.fill(0);
        let Some((data, tag)) = ciphertext.split_last_chunk::<TAG_LEN>() else {
            return Err(SymmetricCipherError::DecryptionFailed);
        };
        Self::decrypt_detached_out(key, nonce, aad, data, tag, plaintext)
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

    /// The nonce `N`, read back out of the counter template: A.3 Table 3 puts it in octets
    /// `1 ... 15-q`, which is `1 ... NONCE_LEN` since `n + q = 15`. It is the same `N` that
    /// `B0` carries (A.2.1 Table 2), so [`Ccm::format_header`] needs no second copy of it.
    fn nonce(&self) -> [u8; NONCE_LEN] {
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&self.ctr_template[1..1 + NONCE_LEN]);
        nonce
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

/// What [`CcmEncryptor`] and [`CcmDecryptor`] share: the [`Ccm`] state, which the trait
/// constructor builds before it has seen any AAD, and the AAD itself, held back until it is
/// complete.
///
/// The trait's AAD is optional and open-ended, and A.2.2 puts the encoding of its length `a` in
/// front of it -- and `B0`'s Adata bit before that -- so no AAD byte can reach the CBC-MAC until
/// the last one has arrived. The first non-empty payload update, or the final, is what says so;
/// [`Self::begin_data`] then runs Sec 6.1 step 1 over the whole of it at once. That is the only
/// buffer in either adapter, and `AAD_LEN` is its capacity: header-sized, by the caller's choice.
///
/// `DATA_LEN` is an exact length, not a capacity, and is committed to `B0` here: the payload
/// then streams through [`Ccm`]'s own `owed` accounting, which refuses more and whose finals
/// refuse less.
#[derive(Clone)]
struct CcmAdapter<
    P,
    Dir,
    const KEY_LEN: usize,
    const BLOCK_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const AAD_LEN: usize,
    const DATA_LEN: usize,
> where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    ccm: Ccm<P, Dir, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN>,
    // Associated data is authenticated but not encrypted, and travels in the clear, so it is not
    // secret and is not wrapped.
    aad: [u8; AAD_LEN],
    aad_len: usize,
    // Whether `begin_data` has run: Sec 6.1 step 1 has been absorbed and the AAD phase is over.
    formatted: bool,
}

impl<
    P,
    Dir,
    const KEY_LEN: usize,
    const BLOCK_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const AAD_LEN: usize,
    const DATA_LEN: usize,
> CcmAdapter<P, Dir, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    /// The compile-time checks for the trait adapters, run from both [`CcmEncryptor`]'s and
    /// [`CcmDecryptor`]'s constructors, which every entry point goes through, so that a parameter
    /// set either names a usable adapter or does not compile at all. [`Ccm::check_shape`]'s own checks run
    /// as well, from the [`Ccm`] constructor underneath.
    ///
    /// The encrypting side draws its nonce at random, and the random-collision bound is only
    /// useful from 96 bits up. The decrypting side is given its nonce, so it has no such need of
    /// its own; it carries the same floor so that the pair stays symmetric -- a `NONCE_LEN` for
    /// which `CcmDecryptor` compiles but `CcmEncryptor` does not would be a trap for code written
    /// against the generic traits, which instantiates both with one set of parameters. The
    /// inherent [`Ccm`] API supports every A.1 length from 7 through 13 under a caller-managed
    /// nonce.
    #[inline]
    fn check_shape() {
        const {
            assert!(
                NONCE_LEN >= 12,
                "CCM: the random-nonce AEAD adapters require NONCE_LEN >= 12; use Ccm directly with a caller-managed unique nonce for shorter lengths"
            );
            // `B0` could not carry it (A.1's `p < 2^8q`), and this is the one place the length is
            // known at compile time, so it is a compile error rather than `Ccm::new`'s `Err`.
            assert!(
                DATA_LEN as u64
                    <= Ccm::<P, Dir, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN>::MAX_PAYLOAD_LEN,
                "CCM: DATA_LEN exceeds the payload limit 2^8q - 1 that NONCE_LEN implies (A.1)"
            );
        }
    }

    /// Readies the keystream and commits `DATA_LEN` as the payload length; the CBC-MAC absorbs
    /// nothing until [`Self::begin_data`].
    fn new(perm: P, nonce: &[u8; NONCE_LEN]) -> Self {
        Self::check_shape();
        Self {
            ccm: Ccm::from_perm_unformatted(perm, nonce, DATA_LEN),
            aad: [0u8; AAD_LEN],
            aad_len: 0,
            formatted: false,
        }
    }

    /// Holds back `aad`. A sequence of calls is equivalent to one call over the concatenation,
    /// which is what A.2.2 needs: the AAD is length-prefixed, so it can only be absorbed once all
    /// of it is in hand. An empty `aad` is a no-op at any point.
    ///
    /// # Errors
    /// [`SymmetricCipherError::StateError`] for a non-empty `aad` once the payload has begun, and
    /// [`SymmetricCipherError::GenericError`] if the total would exceed `AAD_LEN`. Nothing is
    /// held in either case.
    fn do_update_aad(&mut self, aad: &[u8]) -> Result<(), SymmetricCipherError> {
        if aad.is_empty() {
            return Ok(());
        }
        if self.formatted {
            return Err(SymmetricCipherError::StateError(
                "CCM: do_update_aad after the payload has begun; A.2.3 puts the AAD before the \
                 payload",
            ));
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

    /// Ends the AAD phase, the first time it is called: runs Sec 6.1 step 1 -- `B0`, the encoding
    /// of `a`, the AAD and its zero pad -- over the AAD held so far, which is now known to be all
    /// of it. Called before any payload byte goes through [`Ccm`], and from every final, so a
    /// message with no payload at all still gets its header. Later calls do nothing.
    fn begin_data(&mut self) {
        if !self.formatted {
            self.formatted = true;
            self.ccm.format_header(self.aad_len);
            // Exactly the length just declared, so nothing is left owed.
            self.ccm.absorb_aad(&self.aad[..self.aad_len]);
        }
    }
}

/// Adapts [`Ccm`] to [`AEADCipherEncryptor`] and, through it, [`SymmetricCipherEncryptor`], for a
/// payload of exactly `DATA_LEN` bytes.
///
/// [`SymmetricCipherEncryptor::do_encrypt_init`] is handed a key and nothing else, but CCM cannot
/// form `B0` -- and so cannot authenticate anything -- until it knows the payload length
/// (Appendix A.2.1; see the module docs). Rather than hold the message until the final call
/// reveals that length, this type fixes the payload length as the const parameter `DATA_LEN`.
/// The streaming
/// methods then stream: every ciphertext byte is released by the call that produces it,
/// [`do_encrypt_out_len`](SymmetricCipherEncryptor::do_encrypt_out_len) is the identity, and
/// `FINAL_LEN` is `TAG_LEN`, exactly as for GCM. The price is that they accept exactly
/// `DATA_LEN` bytes of payload -- the fixed frame of SP 800-38C Sec 3's "packet environment" --
/// and refuse any other amount, more at the update that would exceed it and less at the final.
/// The one-shots are the trait's own, provided over those methods, so they take exactly
/// `DATA_LEN` bytes too: a frame of any other length is a `Ccm` one-shot's job, with the lengths
/// supplied per message.
///
/// `AAD_LEN` is a capacity, not an exact length: the trait's AAD is optional and open-ended, and
/// the inherited [`SymmetricCipherEncryptor`] methods are this AEAD with none at all. Up to
/// `AAD_LEN` bytes of it are held until the first payload byte, or the final, marks it complete;
/// see `CcmAdapter`. More is refused.
///
/// ```
/// use bouncycastle_core_test_framework::ToyBlockCipher;
/// use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
/// use bouncycastle_core::traits::{AEADCipherDecryptor, AEADCipherEncryptor, SymmetricCipherDecryptor, SymmetricCipherEncryptor};
/// use bouncycastle_cipher::modes::{CcmDecryptor, CcmEncryptor};
///
/// // Frames of exactly 40 payload bytes, with up to 16 bytes of header.
/// type Enc = CcmEncryptor<ToyBlockCipher, 16, 16, 12, 16, 16, 40>;
/// type Dec = CcmDecryptor<ToyBlockCipher, 16, 16, 12, 16, 16, 40>;
///
/// let key = KeyMaterial128::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
///     .expect("a 16-byte symmetric cipher key");
/// let header = b"frame 7";
/// let frame = [0x5Au8; 40];
///
/// let (mut enc, nonce) = Enc::do_encrypt_init(&key).expect("init");
/// enc.do_update_aad(header).expect("within AAD_LEN");
/// let mut ct = [0u8; 40];
/// // Every byte comes straight out; the chunking is the caller's business.
/// let mut written = 0;
/// for piece in frame.chunks(7) {
///     written += enc.do_encrypt_out(piece, &mut ct[written..]).expect("within DATA_LEN");
/// }
/// assert_eq!(written, 40);
/// let (_, _, tag) = enc.do_encrypt_final_detachedtag().expect("exactly DATA_LEN was supplied");
///
/// let mut dec = Dec::do_decrypt_init(&key, &nonce).expect("init");
/// dec.do_update_aad(header).expect("within AAD_LEN");
/// let mut pt = [0u8; 40];
/// dec.do_decrypt_out(&ct, &mut pt).expect("released, but not yet authenticated");
/// dec.do_decrypt_final_detachedtag(&tag).expect("...until the tag verifies");
/// assert_eq!(pt, frame);
///
/// // 39 bytes is not a frame: the final refuses rather than authenticate a length `B0` did not commit to.
/// let (mut short, _) = Enc::do_encrypt_init(&key).expect("init");
/// short.do_encrypt_out(&frame[..39], &mut ct).expect("within DATA_LEN");
/// assert!(short.do_encrypt_final().is_err());
/// ```
///
/// # Nonce length
///
/// The trait generates a random nonce rather than accepting a caller-managed counter. To keep the
/// random-collision bound useful, `NONCE_LEN` must therefore be at least 12 here, and
/// [`CcmDecryptor`] carries the same floor so that the pair stays symmetric. The inherent [`Ccm`]
/// API still supports every A.1 nonce length from 7 through 13 when the caller guarantees
/// uniqueness. A shorter nonce does not compile:
///
/// ```compile_fail
/// use bouncycastle_core_test_framework::ToyBlockCipher;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::traits::SymmetricCipherEncryptor;
/// use bouncycastle_cipher::modes::CcmEncryptor;
///
/// let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap();
/// // n = 8 is permitted by A.1, but too short for a random draw.
/// let _ = CcmEncryptor::<ToyBlockCipher, 16, 16, 8, 16, 64, 256>::do_encrypt_init(&key);
/// ```
///
/// Nor does a `DATA_LEN` that `B0` could not carry under this `NONCE_LEN` (A.1's `p < 2^8q`):
///
/// ```compile_fail
/// use bouncycastle_core_test_framework::ToyBlockCipher;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::traits::SymmetricCipherEncryptor;
/// use bouncycastle_cipher::modes::CcmEncryptor;
///
/// let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap();
/// // n = 13 leaves q = 2, so the payload is at most 65535 bytes.
/// let _ = CcmEncryptor::<ToyBlockCipher, 16, 16, 13, 16, 64, 65536>::do_encrypt_init(&key);
/// ```
///
/// # Memory
///
/// A value is the fixed-size [`Ccm`] state, the `AAD_LEN`-byte AAD buffer and two words of
/// bookkeeping, independent of `DATA_LEN`; the finals return and write only the tag. Nothing
/// scales with the message.
#[derive(Clone)]
pub struct CcmEncryptor<
    P,
    const KEY_LEN: usize,
    const BLOCK_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const AAD_LEN: usize,
    const DATA_LEN: usize,
>(CcmAdapter<P, Encrypting, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN>)
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
> Algorithm for CcmEncryptor<P, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN>
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
> CcmEncryptor<P, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    /// Every final comes here: Sec 6.1 steps 4 and 8, the tag. The header goes in first if no
    /// payload call put it there, which is the `DATA_LEN = 0` message.
    ///
    /// # Errors
    /// [`SymmetricCipherError::StateError`] if fewer than `DATA_LEN` payload bytes were supplied:
    /// `B0` committed to `DATA_LEN`, so a shorter message would get a tag no verifier could
    /// reproduce, and [`Ccm::do_encrypt_final`] refuses to produce one.
    fn finish(mut self) -> Result<[u8; TAG_LEN], SymmetricCipherError> {
        self.0.begin_data();
        self.0.ccm.do_encrypt_final()
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
> SymmetricCipherEncryptor<KEY_LEN, NONCE_LEN, TAG_LEN>
    for CcmEncryptor<P, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN>
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
        // `P::new`'s own checks are the only key validation needed, exactly as for `Ccm` itself
        // and every other mode in this crate; `random_iv` is CBC/CFB's same OS-backed draw --
        // Sec 5.3 asks only for uniqueness, not CBC/CFB's unpredictability, but a CSPRNG draw is
        // the only way to be unique without state `do_encrypt_init` does not have.
        let perm = P::new(key)?;
        let nonce = random_iv::<NONCE_LEN>(rng)?;
        Ok((Self(CcmAdapter::new(perm, &nonce)), nonce))
    }

    /// The identity: nothing is held back, since `B0` is already committed to `DATA_LEN`.
    fn do_encrypt_out_len(&self, input_len: usize) -> usize {
        input_len
    }

    /// Sec 6.1 steps 3 and 8 over `plaintext`, written to `ciphertext`: the plaintext goes
    /// through the CBC-MAC and the CTR keystream, and every byte comes out. A non-empty call ends
    /// the AAD phase; an empty one is a no-op that leaves it open.
    ///
    /// # Errors
    /// [`SymmetricCipherError::OutputBufferTooSmall`] if `ciphertext` is shorter than
    /// `plaintext`, and [`SymmetricCipherError::StateError`] if `plaintext` would take the total
    /// past `DATA_LEN`. Nothing is consumed in either case and `ciphertext` is left zeroed, as on
    /// every call, though a non-empty call refused for its length has still ended the AAD phase.
    fn do_encrypt_out(
        &mut self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        ciphertext.fill(0);
        if plaintext.is_empty() {
            return Ok(0);
        }
        if ciphertext.len() < plaintext.len() {
            return Err(SymmetricCipherError::OutputBufferTooSmall(plaintext.len()));
        }
        // Before the length check, so that a refused oversized call still closes the AAD phase:
        // the phase order is about call history, and this call happened.
        self.0.begin_data();
        // `Ccm::do_encrypt` would refuse this too, but only after the plaintext had been copied
        // into the caller's output buffer, and a refused call must not leave plaintext there.
        if plaintext.len() > self.0.ccm.owed {
            return Err(SymmetricCipherError::StateError(
                "CCM: plaintext longer than DATA_LEN, the payload length the type declares",
            ));
        }
        let out = &mut ciphertext[..plaintext.len()];
        out.copy_from_slice(plaintext);
        self.0.ccm.do_encrypt(out)?;
        Ok(plaintext.len())
    }

    /// The tag, and nothing else: all of the ciphertext has already been released.
    ///
    /// # Errors
    /// As [`AEADCipherEncryptor::do_encrypt_final_detachedtag_out`].
    fn do_encrypt_final(self) -> Result<([u8; TAG_LEN], usize), SymmetricCipherError> {
        Ok((self.finish()?, TAG_LEN))
    }

    /// The ciphertext, which is as long as the plaintext, followed by the tag.
    fn encrypt_out_len(plaintext_len: usize) -> usize {
        plaintext_len + TAG_LEN
    }
}

/// The AEAD view, with `FINAL_LEN = TAG_LEN`: the encryptor holds nothing back, so the detached
/// final flushes nothing and returns only the tag.
impl<
    P,
    const KEY_LEN: usize,
    const BLOCK_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const AAD_LEN: usize,
    const DATA_LEN: usize,
> AEADCipherEncryptor<KEY_LEN, NONCE_LEN, TAG_LEN, TAG_LEN>
    for CcmEncryptor<P, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    /// Holds back `aad` until the payload begins; see `CcmAdapter`.
    ///
    /// # Errors
    /// [`SymmetricCipherError::StateError`] for a non-empty `aad` after the first non-empty
    /// [`do_encrypt_out`](SymmetricCipherEncryptor::do_encrypt_out), and
    /// [`SymmetricCipherError::GenericError`] if the total would exceed `AAD_LEN`.
    fn do_update_aad(&mut self, aad: &[u8]) -> Result<(), SymmetricCipherError> {
        self.0.do_update_aad(aad)
    }

    /// Sec 6.1 steps 4 and 8: the tag. Nothing is held back, so `ciphertext` is left zeroed.
    ///
    /// # Errors
    /// [`SymmetricCipherError::StateError`] if fewer than `DATA_LEN` payload bytes were supplied.
    fn do_encrypt_final_detachedtag_out(
        self,
        ciphertext: &mut [u8; TAG_LEN],
    ) -> Result<(usize, [u8; TAG_LEN]), SymmetricCipherError> {
        ciphertext.fill(0);
        Ok((0, self.finish()?))
    }
}

/// Adapts [`Ccm`] to [`AEADCipherDecryptor`] and, through it, [`SymmetricCipherDecryptor`], for
/// a payload of exactly `DATA_LEN` bytes; the mirror of [`CcmEncryptor`], and see it for the
/// parameters, the nonce floor and the memory.
///
/// Knowing the payload length has a consequence no other decryptor in this crate enjoys: there is
/// nothing to guess about where the tag starts. The first `DATA_LEN` bytes of the stream are
/// ciphertext and are decrypted and released by the call that brings them; anything after them
/// can only be an inline tag (Sec 6.2 step 6's `LSB_Tlen(C)`), and only those bytes -- at most
/// `TAG_LEN` -- are held back for the final to check. A `C` of any other length than `DATA_LEN`
/// (detached) or `DATA_LEN + TAG_LEN` (inline) is refused as malformed.
///
/// # 🚨 Security Considerations 🚨
///
/// **The plaintext this releases is not authenticated until the final call returns `Ok`.** Sec 6.2
/// recovers `P` (step 5) before it can verify it (step 10), and this type releases `P` as it is
/// recovered rather than hold the whole frame back, so a forged ciphertext yields attacker-chosen
/// bytes that only the final's [`SymmetricCipherError::AEADTagCheckFailed`] disowns. That is
/// [`AEADCipherDecryptor`]'s general streaming caveat, and the inherent
/// [`Ccm::do_decrypt_update`] has it too. Sec 6.2's "the payload P and the MAC T shall not be
/// revealed" on INVALID is honoured by the one-shots, which zeroize what they wrote before
/// returning the error.
#[derive(Clone)]
pub struct CcmDecryptor<
    P,
    const KEY_LEN: usize,
    const BLOCK_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const AAD_LEN: usize,
    const DATA_LEN: usize,
> where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    inner: CcmAdapter<P, Decrypting, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN>,
    // The bytes past the `DATA_LEN`th, as they arrive: an inline tag, if the final says the
    // layout is inline, and excess ciphertext if it says detached. Public either way (the tag
    // travels in the clear), so not wrapped.
    tag: [u8; TAG_LEN],
    tag_len: usize,
}

impl<
    P,
    const KEY_LEN: usize,
    const BLOCK_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const AAD_LEN: usize,
    const DATA_LEN: usize,
> Algorithm for CcmDecryptor<P, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN>
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
> CcmDecryptor<P, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    /// Every final comes here once it has settled which bytes are the tag: Sec 6.2 step 10,
    /// through [`Ccm::do_decrypt_final`]. The header goes in first if no payload call put it
    /// there, which is the `DATA_LEN = 0` message.
    ///
    /// # Errors
    /// [`SymmetricCipherError::AEADTagCheckFailed`] if the tag does not verify. The callers have
    /// already refused a short payload, so [`Ccm::do_decrypt_final`]'s own refusal of one is not
    /// reachable from here; it stays as the backstop it is for the inherent API.
    fn finish(mut self, tag: &[u8; TAG_LEN]) -> Result<(), SymmetricCipherError> {
        self.inner.begin_data();
        self.inner.ccm.do_decrypt_final(tag)
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
> SymmetricCipherDecryptor<KEY_LEN, NONCE_LEN, TAG_LEN>
    for CcmDecryptor<P, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    fn do_decrypt_init(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Self, SymmetricCipherError> {
        // `P::new`'s own checks are the only key validation needed; see the encryptor.
        let perm = P::new(key)?;
        Ok(Self { inner: CcmAdapter::new(perm, nonce), tag: [0u8; TAG_LEN], tag_len: 0 })
    }

    /// Every byte of `input_len` that is still inside the declared payload; the rest can only be
    /// the tag, and is held back.
    fn do_decrypt_out_len(&self, input_len: usize) -> usize {
        input_len.min(self.inner.ccm.owed)
    }

    /// Sec 6.2 steps 5 and 7 over the payload part of `ciphertext`, written to `plaintext`
    /// **unauthenticated** (see the type's security considerations), with whatever follows the
    /// `DATA_LEN`th byte held back as the possible tag. A non-empty call ends the AAD phase; an
    /// empty one is a no-op that leaves it open.
    ///
    /// # Errors
    /// [`SymmetricCipherError::OutputBufferTooSmall`] if `plaintext` is shorter than
    /// [`do_decrypt_out_len`](Self::do_decrypt_out_len), and [`SymmetricCipherError::StateError`]
    /// if `ciphertext` would take the total past `DATA_LEN + TAG_LEN`, more than either layout
    /// can be. Nothing is consumed in either case and `plaintext` is left zeroed, as on every
    /// call, though a non-empty call refused for its length has still ended the AAD phase.
    fn do_decrypt_out(
        &mut self,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        plaintext.fill(0);
        if ciphertext.is_empty() {
            return Ok(0);
        }
        let release = self.do_decrypt_out_len(ciphertext.len());
        if plaintext.len() < release {
            return Err(SymmetricCipherError::OutputBufferTooSmall(release));
        }
        // Before the length check, as on the encryptor: a refused oversized call still closes the
        // AAD phase.
        self.inner.begin_data();
        let (data, tail) = ciphertext.split_at(release);
        if tail.len() > TAG_LEN - self.tag_len {
            return Err(SymmetricCipherError::StateError(
                "CCM: ciphertext longer than DATA_LEN + TAG_LEN, the payload length the type \
                 declares plus an inline tag",
            ));
        }
        // `release` is within what is owed, so `Ccm` cannot refuse it.
        plaintext[..release].copy_from_slice(data);
        self.inner.ccm.do_decrypt_update(&mut plaintext[..release])?;
        self.tag[self.tag_len..self.tag_len + tail.len()].copy_from_slice(tail);
        self.tag_len += tail.len();
        Ok(release)
    }

    /// The inline layout: the `TAG_LEN` bytes held back after the payload are the tag (Sec 6.2
    /// step 6's `LSB_Tlen(C)`), and Sec 6.2 runs over everything before them. Releases nothing:
    /// every plaintext byte went out as it was recovered.
    ///
    /// # Errors
    /// [`SymmetricCipherError::DecryptionFailed`] if fewer than `DATA_LEN + TAG_LEN` bytes were
    /// supplied -- Sec 6.2 step 1's "If Clen <= Tlen, then return INVALID", for a `C` whose
    /// length is fixed; [`SymmetricCipherError::AEADTagCheckFailed`] if the tag does not verify.
    fn do_decrypt_final(self) -> Result<([u8; TAG_LEN], usize), SymmetricCipherError> {
        // Tag bytes are only held once the whole payload has been released, so a full tag means
        // a full payload too; a short payload shows up here as no tag at all.
        if self.tag_len < TAG_LEN {
            return Err(SymmetricCipherError::DecryptionFailed);
        }
        let tag = self.tag;
        self.finish(&tag)?;
        Ok(([0u8; TAG_LEN], 0))
    }

    /// The payload, which is `DATA_LEN` whatever `ciphertext_len` claims. For the one `C` the
    /// inline layout accepts that is `ciphertext_len - TAG_LEN`, as for any AEAD; for a shorter
    /// `C` it is still what [`do_decrypt_out`](Self::do_decrypt_out) releases, so a one-shot that
    /// sizes its buffer by this reaches the final and reports the short `C` as malformed, rather
    /// than refusing the buffer first.
    fn decrypt_out_len(ciphertext_len: usize) -> usize {
        ciphertext_len.min(DATA_LEN)
    }
}

/// The AEAD view, with `FINAL_LEN = TAG_LEN`. The one-shots are the trait's own, so a `C` of
/// any length but the frame's is refused like any other wrong-length stream.
impl<
    P,
    const KEY_LEN: usize,
    const BLOCK_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const AAD_LEN: usize,
    const DATA_LEN: usize,
> AEADCipherDecryptor<KEY_LEN, NONCE_LEN, TAG_LEN, TAG_LEN>
    for CcmDecryptor<P, KEY_LEN, BLOCK_LEN, NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    /// As [`CcmEncryptor::do_update_aad`](AEADCipherEncryptor::do_update_aad); the concatenation
    /// must match the encryptor's byte for byte or the tag check fails.
    fn do_update_aad(&mut self, aad: &[u8]) -> Result<(), SymmetricCipherError> {
        self.inner.do_update_aad(aad)
    }

    /// The detached layout: every byte of `C` is ciphertext, so `C` is exactly `DATA_LEN` long
    /// and Sec 6.2 runs over all of it against `tag`. Releases nothing, so `plaintext` is left
    /// zeroed: every plaintext byte went out as it was recovered.
    ///
    /// # Errors
    /// [`SymmetricCipherError::DecryptionFailed`] if `C` was not exactly `DATA_LEN` bytes -- a
    /// payload still owed, or bytes held back as a possible inline tag that this layout has no
    /// place for; [`SymmetricCipherError::AEADTagCheckFailed`] if the tag does not verify.
    fn do_decrypt_final_detachedtag_out(
        self,
        tag: &[u8; TAG_LEN],
        plaintext: &mut [u8; TAG_LEN],
    ) -> Result<usize, SymmetricCipherError> {
        plaintext.fill(0);
        if self.tag_len != 0 || self.inner.ccm.owed != 0 {
            return Err(SymmetricCipherError::DecryptionFailed);
        }
        self.finish(tag)?;
        Ok(0)
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
