//! CBC with ciphertext stealing: CBC-CS1, CBC-CS2 and CBC-CS3, the three variants of the Addendum
//! to NIST SP 800-38A (October 2010), "Three Variants of Ciphertext Stealing for CBC Mode", over
//! any 128-bit block permutation.
//!
//! The variants take a message of any length of at least one block and produce a ciphertext of
//! exactly its length (Addendum Sec 1: "these variants avoid ciphertext expansion"). CBC runs over
//! the message with its last, possibly partial, block padded with zero bits, and the padding's
//! ciphertext, the end of the second-to-last ciphertext block, is not sent: decryption recovers it
//! from the last block. The variants "differ only in the ordering of the ciphertext bits", that is,
//! of the last two portions. With `d` the length of the last block, from 1 to 16 bytes, `Cn` the
//! last ciphertext block and `Cn-1*` the first `d` bytes of the one before it:
//!
//! | Mode type | Last two portions | When the message is whole blocks |
//! |---|---|---|
//! | [`CBC_CS1`] (Sec 2) | `Cn-1* \|\| Cn` | CBC |
//! | [`CBC_CS2`] (Sec 3) | `Cn \|\| Cn-1*` when `d < 16` | CBC |
//! | [`CBC_CS3`] (Sec 4) | `Cn \|\| Cn-1*` | CBC with the last two blocks swapped |
//!
//! [`CTS`] is CBC-CS3, the ciphertext stealing of RFC 2040 Sec 8 and of RFC 3962: the same type
//! under another name.
//!
//! Each mode type is the `M` of a mode-bound key, such as
//! `bouncycastle_symmetric::aes::AES128Key<CBC_CS3>`, which hands out [`CbcCs`] workers through the
//! [`SymmetricEncryptionKey`] / [`SymmetricDecryptionKey`] pair. The init data is a 16-byte IV,
//! drawn by `create_encryptor` or supplied to `create_encryptor_nonce`.
//!
//! # Lengths
//!
//! A message is at least one block, 16 bytes, in both directions; a shorter one is refused at the
//! final with [`SymmetricCipherError::InvalidInputLength`]. A message of exactly one block is its
//! CBC encryption under every variant: there is no second-to-last block to steal from or to swap
//! with. RFC 3962 Sec 5 differs: it encrypts such a block in ECB mode, without the IV, and pads a
//! shorter message; neither applies here. Lengths are in bytes, the restriction to multiples of 8
//! bits that Sec 1 allows an implementation.
//!
//! When streaming, a call writes every block that more than one further block of the message
//! follows, and the final writes the rest: the last two portions, 17 to 32 bytes, or a single
//! block. So `FINAL_LEN` is [`CBC_CS_FINAL_LEN`], 32 bytes.
//!
//! # Usage Examples
//!
//! Over `ToyBlockCipher` (see the [module docs](super) for why); the
//! `bouncycastle_symmetric::aes` aliases carry examples over AES, with published vectors:
//!
//! ```
//! # mod toy { include!("../../../tests/common/toy_block_cipher.rs"); }
//! # use toy::ToyBlockCipher;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey};
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_symmetric::BlockCipherKey;
//! use bouncycastle_symmetric::modes::CBC_CS3;
//!
//! let material = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//! let key = BlockCipherKey::<ToyBlockCipher, CBC_CS3>::from_key_material(&material).expect("a key");
//! let mut rng = HashDRBG_SHA512::new_from_os();
//!
//! // 50 bytes: three whole blocks and two bytes, encrypted to exactly 50 bytes.
//! let plaintext = [0x5Au8; 50];
//! let (iv, ciphertext) = key.encrypt(&mut rng, &plaintext).expect("encryption");
//! assert_eq!(ciphertext.len(), plaintext.len());
//! assert_eq!(key.decrypt(&iv, &ciphertext).expect("decryption"), plaintext);
//!
//! // A message shorter than a block is refused.
//! assert!(key.encrypt(&mut rng, &[0x5Au8; 15]).is_err());
//! ```
//!
//! # 🚨 Security Considerations 🚨
//!
//! ## Confidentiality only
//!
//! These are CBC, and like CBC they authenticate nothing: a modified ciphertext decrypts to
//! modified plaintext, not to an error, and someone who can submit ciphertexts for decryption
//! controls how. There is no padding to check, so no padding oracle either, but that does not make
//! the ciphertext safe to decrypt unauthenticated. Authenticate the ciphertext and the IV, or use an
//! AEAD such as GCM.
//!
//! ## The IV
//!
//! Sec 1: "Each variant inherits the relevant requirements of Ref. \[1\], e.g., on the underlying
//! block cipher, the key, and the initialization vector." The IV must be unpredictable, as for
//! CBC (SP 800-38A Appendix C); `create_encryptor` draws it from the RNG, and a caller who supplies
//! it through the `_nonce` forms takes that on. See the [`cbc`](super::cbc) notes on the IV's
//! integrity.
//!
//! ## The length is not hidden
//!
//! The ciphertext is exactly as long as the plaintext, so it gives the message's length to the
//! byte, where a padding scheme rounds it up to a block.
//!
//! ## The variants do not interoperate
//!
//! A ciphertext decrypts correctly only under the variant that produced it, and the name "CTS" is
//! not used for the same one everywhere. Here it is CBC-CS3; agree on the variant, by its NIST name,
//! with the other side.

use crate::modes::ModeNames;
use crate::modes::cbc::Cbc;
use crate::modes::iv::random_iv;
use crate::{Decrypting, Encrypting};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::hazmat::{
    BlockPermutation, ElectronicCodeBook, Mode, SymmetricDecryptMode, SymmetricEncryptMode,
};
use bouncycastle_core::key_material::KeyType;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{
    Algorithm, BlockCipherDecryptor, BlockCipherEncryptor, FinishToken, RNG,
    SymmetricCipherDecryptor, SymmetricCipherEncryptor,
};
use bouncycastle_utils::secret::Secret;
use core::marker::PhantomData;

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_core::symmetric_key::{SymmetricDecryptionKey, SymmetricEncryptionKey};
// end of imports needed for docs

/// The block length `b` the variants are implemented over: 128 bits.
const BLOCK_LEN: usize = 16;

/// The length of a final's buffer, two blocks: the last two portions of a message are `b + d`
/// bytes, with `d` from 1 to `b`.
pub const CBC_CS_FINAL_LEN: usize = 2 * BLOCK_LEN;

/// The mode type of CBC with ciphertext stealing: the `M` of a mode-bound key such as
/// `AES128Key<CBC_CS3>`. `V` is the variant, [`CS1`], [`CS2`] or [`CS3`], and the mode is
/// named through the aliases [`CBC_CS1`], [`CBC_CS2`], [`CBC_CS3`] and [`CTS`]. Its key state is the
/// keyed permutation alone: as CBC, it derives nothing from the key.
///
/// Over a permutation that decrypts only ([`BlockPermutation::DECRYPT_ONLY`]) a key makes no
/// encryptor, which is a compile error:
///
/// ```compile_fail
/// # mod toy { include!("../../../tests/common/toy_block_cipher.rs"); }
/// # use toy::ToyBlockCipher;
/// # use bouncycastle_core::errors::SymmetricCipherError;
/// # use bouncycastle_core::hazmat::{BlockPermutation, KeyExpansion};
/// # use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// # use bouncycastle_core::security_strength::SecurityStrength;
/// # use bouncycastle_core::traits::Algorithm;
/// # use bouncycastle_symmetric::modes::ModeNames;
/// use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricEncryptionKey};
/// use bouncycastle_symmetric::BlockCipherKey;
/// use bouncycastle_symmetric::modes::CBC_CS3;
///
/// #[derive(Clone)]
/// struct DecryptOnly(ToyBlockCipher);
///
/// impl BlockPermutation<16> for DecryptOnly {
///     const DECRYPT_ONLY: bool = true;
/// #   fn encrypt_block(&self, block: &mut [u8; 16]) { self.0.encrypt_block(block) }
/// #   fn decrypt_block(&self, block: &mut [u8; 16]) { self.0.decrypt_block(block) }
/// #   fn encrypt_2blocks(&self, blocks: &mut [[u8; 16]; 2]) { self.0.encrypt_2blocks(blocks) }
/// #   fn decrypt_2blocks(&self, blocks: &mut [[u8; 16]; 2]) { self.0.decrypt_2blocks(blocks) }
/// #   fn encrypt_4blocks(&self, blocks: &mut [[u8; 16]; 4]) { self.0.encrypt_4blocks(blocks) }
/// #   fn decrypt_4blocks(&self, blocks: &mut [[u8; 16]; 4]) { self.0.decrypt_4blocks(blocks) }
/// }
/// # impl Algorithm for DecryptOnly {
/// #     const ALG_NAME: &'static str = "DecryptOnly";
/// #     const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
/// # }
/// # impl KeyExpansion<16> for DecryptOnly {
/// #     fn new(key: &KeyMaterial<16>) -> Result<Self, SymmetricCipherError> {
/// #         ToyBlockCipher::new(key).map(Self)
/// #     }
/// # }
/// # impl ModeNames for DecryptOnly {
/// #     const CBC_ALG_NAME: &'static str = "";
/// #     const CBC_CS1_ALG_NAME: &'static str = "";
/// #     const CBC_CS2_ALG_NAME: &'static str = "";
/// #     const CBC_CS3_ALG_NAME: &'static str = "DecryptOnly_CBC_CS3";
/// #     const CCM_ALG_NAME: &'static str = "";
/// #     const CFB_ALG_NAME: &'static str = "";
/// #     const CFB8_ALG_NAME: &'static str = "";
/// #     const CMAC_ALG_NAME: &'static str = "";
/// #     const CTR_ALG_NAME: &'static str = "";
/// #     const ECB_ALG_NAME: &'static str = "";
/// #     const GCM_ALG_NAME: &'static str = "";
/// #     const GMAC_ALG_NAME: &'static str = "";
/// #     const KW_ALG_NAME: &'static str = "";
/// #     const KWP_ALG_NAME: &'static str = "";
/// #     const OFB_ALG_NAME: &'static str = "";
/// # }
///
/// let material = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
///     .expect("a 16-byte symmetric cipher key");
/// let key = BlockCipherKey::<DecryptOnly, CBC_CS3>::from_key_material(&material).expect("a key");
/// // Refused when the program is built: the permutation decrypts only.
/// let _ = key.create_encryptor_nonce(&[0u8; 16]);
/// ```
///
/// The same key does decrypt:
///
/// ```
/// # mod toy { include!("../../../tests/common/toy_block_cipher.rs"); }
/// # use toy::ToyBlockCipher;
/// # use bouncycastle_core::errors::SymmetricCipherError;
/// # use bouncycastle_core::hazmat::{BlockPermutation, KeyExpansion};
/// # use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// # use bouncycastle_core::security_strength::SecurityStrength;
/// # use bouncycastle_core::traits::Algorithm;
/// # use bouncycastle_symmetric::modes::ModeNames;
/// use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey};
/// use bouncycastle_symmetric::BlockCipherKey;
/// use bouncycastle_symmetric::modes::CBC_CS3;
///
/// #[derive(Clone)]
/// struct DecryptOnly(ToyBlockCipher);
///
/// impl BlockPermutation<16> for DecryptOnly {
///     const DECRYPT_ONLY: bool = true;
/// #   fn encrypt_block(&self, block: &mut [u8; 16]) { self.0.encrypt_block(block) }
/// #   fn decrypt_block(&self, block: &mut [u8; 16]) { self.0.decrypt_block(block) }
/// #   fn encrypt_2blocks(&self, blocks: &mut [[u8; 16]; 2]) { self.0.encrypt_2blocks(blocks) }
/// #   fn decrypt_2blocks(&self, blocks: &mut [[u8; 16]; 2]) { self.0.decrypt_2blocks(blocks) }
/// #   fn encrypt_4blocks(&self, blocks: &mut [[u8; 16]; 4]) { self.0.encrypt_4blocks(blocks) }
/// #   fn decrypt_4blocks(&self, blocks: &mut [[u8; 16]; 4]) { self.0.decrypt_4blocks(blocks) }
/// }
/// # impl Algorithm for DecryptOnly {
/// #     const ALG_NAME: &'static str = "DecryptOnly";
/// #     const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
/// # }
/// # impl KeyExpansion<16> for DecryptOnly {
/// #     fn new(key: &KeyMaterial<16>) -> Result<Self, SymmetricCipherError> {
/// #         ToyBlockCipher::new(key).map(Self)
/// #     }
/// # }
/// # impl ModeNames for DecryptOnly {
/// #     const CBC_ALG_NAME: &'static str = "";
/// #     const CBC_CS1_ALG_NAME: &'static str = "";
/// #     const CBC_CS2_ALG_NAME: &'static str = "";
/// #     const CBC_CS3_ALG_NAME: &'static str = "DecryptOnly_CBC_CS3";
/// #     const CCM_ALG_NAME: &'static str = "";
/// #     const CFB_ALG_NAME: &'static str = "";
/// #     const CFB8_ALG_NAME: &'static str = "";
/// #     const CMAC_ALG_NAME: &'static str = "";
/// #     const CTR_ALG_NAME: &'static str = "";
/// #     const ECB_ALG_NAME: &'static str = "";
/// #     const GCM_ALG_NAME: &'static str = "";
/// #     const GMAC_ALG_NAME: &'static str = "";
/// #     const KW_ALG_NAME: &'static str = "";
/// #     const KWP_ALG_NAME: &'static str = "";
/// #     const OFB_ALG_NAME: &'static str = "";
/// # }
///
/// let material = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
///     .expect("a 16-byte symmetric cipher key");
/// let key = BlockCipherKey::<DecryptOnly, CBC_CS3>::from_key_material(&material).expect("a key");
/// // Decryption is not gated.
/// let _ = key.create_decryptor(&[0u8; 16]);
/// ```
#[allow(non_camel_case_types)]
pub struct CBC_CS<V>(PhantomData<V>);

/// CBC-CS1 (Addendum to NIST SP 800-38A Sec 2): the last two portions in CBC's order,
/// `Cn-1* || Cn`, so a message of whole blocks is its CBC encryption.
#[allow(non_camel_case_types)]
pub type CBC_CS1 = CBC_CS<CS1>;

/// CBC-CS2 (Addendum to NIST SP 800-38A Sec 3): `Cn || Cn-1*` when the last block is partial, and
/// CBC's order when it is whole, so a message of whole blocks is its CBC encryption.
#[allow(non_camel_case_types)]
pub type CBC_CS2 = CBC_CS<CS2>;

/// CBC-CS3 (Addendum to NIST SP 800-38A Sec 4): `Cn || Cn-1*` always, so a message of two or more
/// whole blocks is its CBC encryption with the last two blocks swapped.
#[allow(non_camel_case_types)]
pub type CBC_CS3 = CBC_CS<CS3>;

/// Ciphertext stealing as RFC 2040 Sec 8 defines it, in which the last block "could in fact be a
/// complete block" and is swapped all the same: CBC-CS3, of which this is another name, not
/// another mode.
pub type CTS = CBC_CS3;

/// The variant of [`CBC_CS1`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CS1;

/// The variant of [`CBC_CS2`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CS2;

/// The variant of [`CBC_CS3`] and [`CTS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CS3;

mod sealed {
    /// Private supertrait of [`CsVariant`](super::CsVariant): only [`CS1`](super::CS1),
    /// [`CS2`](super::CS2) and [`CS3`](super::CS3) implement it.
    pub trait Sealed {}
}

impl sealed::Sealed for CS1 {}
impl sealed::Sealed for CS2 {}
impl sealed::Sealed for CS3 {}

/// What sets the three variants apart: the order of the last two portions, and the name under a
/// permutation `P`. Sealed: [`CS1`], [`CS2`] and [`CS3`] are the only implementors.
pub trait CsVariant<P: ModeNames>: sealed::Sealed {
    /// The permutation's name for the mode under this variant, one of [`ModeNames`]'
    /// `CBC_CS*_ALG_NAME`.
    const ALG_NAME: &'static str;

    /// Whether the variant writes the last two portions as `Cn || Cn-1*` rather than
    /// `Cn-1* || Cn`, given whether the last block is partial (`d < b`).
    fn swaps(partial: bool) -> bool;
}

impl<P: ModeNames> CsVariant<P> for CS1 {
    const ALG_NAME: &'static str = P::CBC_CS1_ALG_NAME;

    /// Never: Sec 2, CBC-CS1-Encrypt step 5, "Return C1||C2||…||Cn-2||Cn-1*||Cn".
    fn swaps(_partial: bool) -> bool {
        false
    }
}

impl<P: ModeNames> CsVariant<P> for CS2 {
    const ALG_NAME: &'static str = P::CBC_CS2_ALG_NAME;

    /// When the last block is partial: Sec 3, CBC-CS2-Encrypt step 3, "If d=b, return
    /// C1||C2||…||Cn-2 ||Cn-1*||Cn; if d<b, return C1||C2||…||Cn-2||Cn||Cn-1*".
    fn swaps(partial: bool) -> bool {
        partial
    }
}

impl<P: ModeNames> CsVariant<P> for CS3 {
    const ALG_NAME: &'static str = P::CBC_CS3_ALG_NAME;

    /// Always: Sec 4, CBC-CS3-Encrypt step 2, "Return C1||C2||…||Cn-2||Cn||Cn-1*", where "Cn-1* and
    /// Cn are unconditionally swapped, i.e., even when Cn-1* is a complete block".
    fn swaps(_partial: bool) -> bool {
        true
    }
}

impl<P: Clone + ModeNames, V: CsVariant<P>> Mode<P> for CBC_CS<V> {
    type KeyState = P;
    const KEY_TYPE: KeyType = KeyType::SymmetricCipherKey;
    const ALG_NAME: &'static str = V::ALG_NAME;

    fn key_state(perm: P) -> Self::KeyState {
        perm
    }
}

impl<P, V, const KEY_LEN: usize> SymmetricEncryptMode<P, KEY_LEN, BLOCK_LEN, CBC_CS_FINAL_LEN>
    for CBC_CS<V>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN> + ModeNames + Clone,
    V: CsVariant<P>,
{
    type Encryptor<'k>
        = CbcCs<'k, P, Encrypting, V>
    where
        P: 'k;

    fn encrypt_init<'k>(
        state: &'k Self::KeyState,
        rng: &mut dyn RNG,
    ) -> Result<(Self::Encryptor<'k>, [u8; BLOCK_LEN]), SymmetricCipherError> {
        const {
            assert!(
                !P::DECRYPT_ONLY,
                "this permutation decrypts only (BlockPermutation::DECRYPT_ONLY): no encrypting worker may be made over it"
            )
        };
        let iv = random_iv::<BLOCK_LEN>(rng)?;
        Ok((CbcCs::from_perm(state, iv), iv))
    }

    fn encrypt_init_nonce<'k>(
        state: &'k Self::KeyState,
        iv: &[u8; BLOCK_LEN],
    ) -> Self::Encryptor<'k> {
        const {
            assert!(
                !P::DECRYPT_ONLY,
                "this permutation decrypts only (BlockPermutation::DECRYPT_ONLY): no encrypting worker may be made over it"
            )
        };
        CbcCs::from_perm(state, *iv)
    }
}

impl<P, V, const KEY_LEN: usize> SymmetricDecryptMode<P, KEY_LEN, BLOCK_LEN, CBC_CS_FINAL_LEN>
    for CBC_CS<V>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN> + ModeNames + Clone,
    V: CsVariant<P>,
{
    type Decryptor<'k>
        = CbcCs<'k, P, Decrypting, V>
    where
        P: 'k;

    fn decrypt_init<'k>(
        state: &'k Self::KeyState,
        init_data: &[u8; BLOCK_LEN],
    ) -> Self::Decryptor<'k> {
        CbcCs::from_perm(state, *init_data)
    }
}

/// CBC with ciphertext stealing over any 128-bit [`BlockPermutation`], under the variant `V`,
/// with the direction in the type: [`SymmetricCipherEncryptor`] is implemented for
/// `Dir` = [`Encrypting`] alone and [`SymmetricCipherDecryptor`] for [`Decrypting`] alone.
///
/// The worker of every [`CBC_CS`] key; see the [module docs](self) for the variants, the lengths
/// and the security considerations. A call releases every block that more than one further block
/// of the message follows, so `do_*_out_len` is a whole number of blocks; the final writes the
/// rest, 16 to 32 bytes, or refuses a message shorter than one block with
/// [`SymmetricCipherError::InvalidInputLength`]. Plaintext held between calls is kept in a
/// [`Secret`].
pub struct CbcCs<'k, P, Dir, V>
where
    P: BlockPermutation<BLOCK_LEN> + ModeNames,
{
    /// CBC itself, which every block goes through and which carries the chaining value.
    cbc: Cbc<'k, P, Dir, BLOCK_LEN>,
    /// The permutation, for the one inverse cipher call that is not CBC's, `CIPH^-1_K(Cn)`
    /// (CBC-CS1-Decrypt step 2). Unused when encrypting.
    perm: &'k P,
    /// The end of the message so far, not yet released: plaintext when encrypting, ciphertext
    /// when decrypting. At most the last two portions.
    held: Secret<[u8; CBC_CS_FINAL_LEN]>,
    /// How many bytes of `held` are message; the bytes after them may be stale.
    held_len: usize,
    _variant: PhantomData<V>,
}

impl<'k, P, Dir, V> CbcCs<'k, P, Dir, V>
where
    P: BlockPermutation<BLOCK_LEN> + ModeNames,
{
    /// `C0 = IV`, over an already-keyed permutation: what the [`CBC_CS`] mode impls build.
    fn from_perm(perm: &'k P, iv: [u8; BLOCK_LEN]) -> Self {
        Self {
            cbc: Cbc::from_perm(perm, iv),
            perm,
            held: Secret::new(),
            held_len: 0,
            _variant: PhantomData,
        }
    }

    /// How many bytes the next call releases given `input_len` more: the whole blocks of
    /// `held || input` that more than one further block of the message follows.
    ///
    /// The last two portions, `d` bytes and the `b` before them with `1 <= d <= b`, are written in
    /// an order and to a length that depend on where the message ends. A block is outside them
    /// for certain only once more than `b` bytes follow it, so of `c = held_len + input_len`
    /// bytes, `ceil(c / b) - 2` blocks go and the last 17 to 32 bytes stay (all of them while
    /// `c <= 32`). `held_len` is at most 32 and `input_len` a slice's length, so the sum cannot
    /// overflow.
    fn release_len(&self, input_len: usize) -> usize {
        (self.held_len + input_len).div_ceil(BLOCK_LEN).saturating_sub(2) * BLOCK_LEN
    }

    /// Moves the first `out.len()` bytes of `held || input` into `out` and keeps the rest in
    /// `held`. `out.len()` is [`release_len`](Self::release_len) of `input.len()`, which leaves at
    /// most 32 bytes to keep and takes at most `input.len()` from `input`.
    fn release(&mut self, input: &[u8], out: &mut [u8]) {
        let from_held = self.held_len.min(out.len());
        let (from_held_out, from_input_out) = out.split_at_mut(from_held);
        from_held_out.copy_from_slice(&self.held[..from_held]);
        let (released, kept) = input.split_at(from_input_out.len());
        from_input_out.copy_from_slice(released);

        // What is kept: the rest of `held`, moved to its front, then the rest of `input`.
        let kept_from_held = self.held_len - from_held;
        self.held.copy_within(from_held..self.held_len, 0);
        self.held[kept_from_held..kept_from_held + kept.len()].copy_from_slice(kept);
        self.held_len = kept_from_held + kept.len();
    }
}

/// The refusal of a message shorter than one block. Addendum Sec 1: the variants "accept any
/// plaintext input whose bit length is greater than or equal to the block size".
fn shorter_than_a_block() -> SymmetricCipherError {
    SymmetricCipherError::InvalidInputLength(
        "CBC-CS takes a message of at least one block, 16 bytes (SP 800-38A Addendum Sec 1)",
    )
}

impl<'k, P, Dir, V> Algorithm for CbcCs<'k, P, Dir, V>
where
    P: BlockPermutation<BLOCK_LEN> + ModeNames,
    V: CsVariant<P>,
{
    /// The permutation's name for the mode under this variant.
    const ALG_NAME: &'static str = V::ALG_NAME;
    /// A mode does not change the strength of the underlying cipher.
    const MAX_SECURITY_STRENGTH: SecurityStrength = P::MAX_SECURITY_STRENGTH;
}

// The comments below follow the Addendum's algorithms: CBC-CS1-Encrypt and -Decrypt (Sec 2), and
// the reorderings of CBC-CS2 (Sec 3) and CBC-CS3 (Sec 4), which are written as CBC-CS1 on the
// blocks put back in its order. The CBC steps run as the message streams; the finals do the rest.

impl<'k, P, V> SymmetricCipherEncryptor<BLOCK_LEN, CBC_CS_FINAL_LEN> for CbcCs<'k, P, Encrypting, V>
where
    P: BlockPermutation<BLOCK_LEN> + ModeNames,
    V: CsVariant<P>,
{
    /// The whole blocks that more than one further block of the message follows.
    fn do_encrypt_out_len(&self, input_len: usize) -> usize {
        self.release_len(input_len)
    }

    /// CBC-CS1-Encrypt step 3 for the blocks outside the last two portions: `C1`, `C2`, ... are
    /// plain CBC ciphertext blocks, written as soon as they are known not to be `Cn-1` or `Cn`.
    fn do_encrypt_out(
        &mut self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        ciphertext.fill(0);
        let out_len = self.release_len(plaintext.len());
        if ciphertext.len() < out_len {
            return Err(SymmetricCipherError::OutputBufferTooSmall(out_len));
        }
        let out = &mut ciphertext[..out_len];
        // The released plaintext is copied into the output and encrypted there, in place.
        self.release(plaintext, out);
        let (blocks, _) = out.as_chunks_mut::<BLOCK_LEN>();
        self.cbc.do_encrypt_blocks_inplace(blocks)
    }

    /// The last two portions, `Pn-1` and `Pn*`, or a message of exactly one block.
    fn finish_encrypt(
        &mut self,
        _token: &FinishToken,
    ) -> Result<([u8; CBC_CS_FINAL_LEN], usize), SymmetricCipherError> {
        let len = self.held_len;
        if len < BLOCK_LEN {
            return Err(shorter_than_a_block());
        }
        let mut out = [0u8; CBC_CS_FINAL_LEN];
        if len == BLOCK_LEN {
            // n = 1: the CBC encryption of the one block, under every variant. Step 4's Cn-1 does
            // not exist, so there is nothing to truncate or to swap; the ACVP vectors' one-block
            // cases agree, for all three variants.
            let (blocks, _) = self.held.as_chunks_mut::<BLOCK_LEN>();
            self.cbc.do_encrypt_blocks_inplace(&mut blocks[..1])?;
            out[..BLOCK_LEN].copy_from_slice(&blocks[0]);
            return Ok((out, BLOCK_LEN));
        }

        // Step 1: the held bytes are Pn-1, a complete block, and Pn*, of d = len - b bytes.
        let d = len - BLOCK_LEN;
        // Step 2: Pn = Pn* || PAD, PAD being b - d '0' bits. The bytes past the message may be
        // left from earlier calls, so they are cleared, not assumed zero.
        self.held[len..].fill(0);
        // Step 3: CBC encryption of Pn-1 and Pn, chained from Cn-2 (or the IV), to Cn-1 and Cn.
        let (blocks, _) = self.held.as_chunks_mut::<BLOCK_LEN>();
        self.cbc.do_encrypt_blocks_inplace(blocks)?;
        let (c_nm1, c_n) = (&blocks[0], &blocks[1]);
        // Step 4: Cn-1* = MSB_d(Cn-1). Step 5 (CS1), Sec 3 step 3 (CS2), Sec 4 step 2 (CS3): the
        // order of Cn-1* and Cn.
        if V::swaps(d < BLOCK_LEN) {
            out[..BLOCK_LEN].copy_from_slice(c_n);
            out[BLOCK_LEN..len].copy_from_slice(&c_nm1[..d]);
        } else {
            out[..d].copy_from_slice(&c_nm1[..d]);
            out[d..len].copy_from_slice(c_n);
        }
        Ok((out, len))
    }

    /// The ciphertext is exactly as long as the plaintext (a message shorter than one block is
    /// refused at the final).
    fn encrypt_out_len(plaintext_len: usize) -> usize {
        plaintext_len
    }
}

impl<'k, P, V> SymmetricCipherDecryptor<BLOCK_LEN, CBC_CS_FINAL_LEN> for CbcCs<'k, P, Decrypting, V>
where
    P: BlockPermutation<BLOCK_LEN> + ModeNames,
    V: CsVariant<P>,
{
    /// The whole blocks that more than one further block of the message follows.
    fn do_decrypt_out_len(&self, input_len: usize) -> usize {
        self.release_len(input_len)
    }

    /// CBC-CS1-Decrypt step 4 for the blocks outside the last two portions: `P1`, `P2`, ... are
    /// the plain CBC decryption of `C1`, `C2`, ..., which every variant writes in CBC's order.
    fn do_decrypt_out(
        &mut self,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        plaintext.fill(0);
        let out_len = self.release_len(ciphertext.len());
        if plaintext.len() < out_len {
            return Err(SymmetricCipherError::OutputBufferTooSmall(out_len));
        }
        let out = &mut plaintext[..out_len];
        // The released ciphertext is copied into the output and decrypted there, in place.
        self.release(ciphertext, out);
        let (blocks, _) = out.as_chunks_mut::<BLOCK_LEN>();
        self.cbc.do_decrypt_blocks_inplace(blocks)
    }

    /// The last two portions, `Cn-1*` and `Cn` in the variant's order, or a message of exactly
    /// one block.
    fn finish_decrypt_into(
        &mut self,
        _token: &FinishToken,
        out: &mut [u8; CBC_CS_FINAL_LEN],
    ) -> Result<usize, SymmetricCipherError> {
        out.fill(0);
        let len = self.held_len;
        if len < BLOCK_LEN {
            return Err(shorter_than_a_block());
        }
        let (out_blocks, _) = out.as_chunks_mut::<BLOCK_LEN>();
        if len == BLOCK_LEN {
            // n = 1: the CBC decryption of the one block, as encryption is its CBC encryption.
            out_blocks[0].copy_from_slice(&self.held[..BLOCK_LEN]);
            self.cbc.do_decrypt_blocks_inplace(&mut out_blocks[..1])?;
            return Ok(BLOCK_LEN);
        }

        // Step 1: the held bytes are the last two portions, Cn-1* of d = len - b bytes and the
        // complete block Cn. CBC-CS2-Decrypt step 3 and CBC-CS3-Decrypt step 2 put a swapped pair
        // back in CBC-CS1's order, Cn-1* then Cn, before CBC-CS1-Decrypt.
        let d = len - BLOCK_LEN;
        let (c_nm1_star, c_n) = if V::swaps(d < BLOCK_LEN) {
            (&self.held[BLOCK_LEN..len], &self.held[..BLOCK_LEN])
        } else {
            (&self.held[..d], &self.held[d..len])
        };
        // Step 2: Z = CIPH^-1_K(Cn), whose first d bytes are Z* and the rest Z**. Z* is Pn* masked
        // by Cn-1*, so Z is kept in a `Secret`.
        let mut z: Secret<[u8; BLOCK_LEN]> = Secret::new();
        z.copy_from_slice(c_n);
        self.perm.decrypt_block(&mut z);
        // Step 3: Cn-1 = Cn-1* || Z**, built where Pn-1 goes. When d = b, Z** is empty and Cn-1 is
        // Cn-1*.
        let (first, second) = out_blocks.split_at_mut(1);
        first[0][..d].copy_from_slice(c_nm1_star);
        first[0][d..].copy_from_slice(&z[d..]);
        // Step 4: CBC decryption of Cn-1, chained from Cn-2 (or the IV), to Pn-1.
        self.cbc.do_decrypt_blocks_inplace(first)?;
        // Step 5: Pn* = Cn-1* XOR Z*.
        for ((p, c), z_byte) in second[0][..d].iter_mut().zip(c_nm1_star).zip(z.iter()) {
            *p = c ^ z_byte;
        }
        // Step 6: Pn-1 || Pn*.
        Ok(len)
    }

    /// The plaintext is exactly as long as the ciphertext (a ciphertext shorter than one block is
    /// refused at the final).
    fn decrypt_out_len(ciphertext_len: usize) -> usize {
        ciphertext_len
    }
}
