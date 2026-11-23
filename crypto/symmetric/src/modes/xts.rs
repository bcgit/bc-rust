//! XTS, the "XEX Tweakable Block Cipher with Ciphertext Stealing" (SP 800-38E Sec 3), as IEEE Std
//! 1619-2007 Sec 5 specifies it for AES and NIST SP 800-38E approves it, over any 128-bit block
//! permutation.
//!
//! XTS encrypts one *data unit* -- a disk sector, say -- under a key and a 128-bit *tweak* that
//! names the data unit's position, and the ciphertext is exactly as long as the plaintext: there
//! is no IV, no nonce, no padding and no tag. A data unit is at least one block, 16 bytes
//! (IEEE 1619-2007 Sec 5.1), and at most 2^20 blocks, 16 MiB, a limit that Sec 5.1 recommends and
//! SP 800-38E Sec 4 requires: "The length of the data unit for any instance of an implementation
//! of XTS-AES shall not exceed 2^20 AES blocks". A data unit that is not a whole number of blocks
//! is encrypted with ciphertext stealing, so its ciphertext is as long as it is. IEEE 1619
//! measures a data unit in bits; this implementation takes whole bytes, a restriction that
//! SP 800-38E Sec 4 allows an implementation to make.
//!
//! The key is [`XTSKey`], built with `from_key_material` from the XTS key `Key = Key_1 | Key_2`
//! (IEEE 1619-2007 Sec 5.3.1): two keys for the permutation, `Key_1` encrypting the data and
//! `Key_2` the tweak, so 32 bytes over a permutation with a 16-byte key and 64 over one with a
//! 32-byte key, the 256- and 512-bit keys of XTS-AES-128 and XTS-AES-256 (Sec 6). Each call takes
//! one data unit of any length in that range and refuses one outside it; keeping every data unit
//! under a key to one length is the caller's to do (see the security considerations). The
//! ready-made `XTS_AES_128` / `XTS_AES_256` aliases are in `bouncycastle_symmetric::aes`. IEEE 1619 specifies
//! XTS for AES only, and AES is the only cipher SP 800-38E approves it for.
//!
//! # The tweak
//!
//! The tweak value `i` is the data unit's position, a non-negative integer; the data units under
//! a key take consecutive values from any first one, typically the logical block address of the
//! first sector (IEEE 1619-2007 Sec 5.1, Sec 6). The methods take `i` as the 16 bytes that are
//! encrypted under `Key_2`, which Sec 5.1 makes its little-endian encoding: `i.to_le_bytes()` for
//! a `u128` `i`, so sector 255's tweak is `FF 00 .. 00`.
//!
//! # Usage Examples
//!
//! Over `ToyBlockCipher` (see the [module docs](super) for why); `bouncycastle_symmetric::aes`'s aliases
//! carry examples over AES with published vectors:
//!
//! ```
//! # mod toy { include!("../../tests/common/toy_block_cipher.rs"); }
//! # use toy::ToyBlockCipher;
//! use bouncycastle_symmetric::modes::XTSKey;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::symmetric_key::FromKeyMaterial;
//!
//! // Key = Key_1 | Key_2: 32 bytes over a permutation with a 16-byte key, the two halves distinct.
//! let key_bytes: [u8; 32] = core::array::from_fn(|i| i as u8 + 1);
//! let material = KeyMaterial::<32>::from_bytes_as_type(&key_bytes, KeyType::SymmetricCipherKey)
//!     .expect("a 32-byte symmetric cipher key");
//!
//! let key = XTSKey::<ToyBlockCipher>::from_key_material(&material).expect("an XTS key");
//!
//! // A 512-byte sector, under its sequence number.
//! let mut sector = [0x5Au8; 512];
//! let tweak = 7u128.to_le_bytes();
//! assert_eq!(key.encrypt_inplace(&tweak, &mut sector), Ok(512));
//! assert_ne!(sector, [0x5Au8; 512]);
//! assert_eq!(key.decrypt_inplace(&tweak, &mut sector), Ok(512));
//! assert_eq!(sector, [0x5Au8; 512]);
//! ```
//!
//! # 🚨 Security Considerations 🚨
//!
//! ## XTS provides confidentiality only
//!
//! SP 800-38E's abstract: "The mode does not provide authentication of the data or its source." A
//! changed ciphertext block decrypts to an unpredictable plaintext block rather than to an error,
//! and an older ciphertext of a data unit decrypts to the older plaintext. Each 16-byte block is
//! encrypted on its own under its position's mask, so someone who sees two versions of a data
//! unit learns which of its blocks changed, and the same plaintext under the same key and tweak
//! always gives the same ciphertext; IEEE 1619-2007 Annex D.2 and D.3 discuss these limits. Where
//! any of that matters, authenticate the data, or use an AEAD, which a format that can store a
//! nonce and a tag should.
//!
//! ## XTS is for storage
//!
//! SP 800-38E Sec 3: "The XTS-AES mode was not designed for other purposes, such as the
//! encryption of data in transit", and FIPS 140-3 IG C.I: "AES-XTS is only approved for storage
//! purposes."
//!
//! ## One key scope per key
//!
//! IEEE 1619-2007 Sec 6 allows a key only one *key scope*: a run of data units of one length
//! under consecutive tweak values, so every data unit under the key has its own tweak. SP 800-38E
//! Sec 4 likewise defines an instance of XTS-AES by "a secret key" and "a single, fixed length for
//! the data units that the key protects". Two data units encrypted under one key and one tweak are
//! encrypted under the same masks, so a block that is equal in both, at the same offset, has an
//! equal ciphertext in both, and a ciphertext block of one can be pasted into the other. The key
//! takes a data unit of any valid length at every call, so keeping all of its data units to one
//! length, each under its own tweak, is the caller's obligation: a second length, or a second
//! disk, under the same key steps outside the key scope.
//!
//! ## A bounded amount of data per key
//!
//! The proof that IEEE 1619-2007 Annex D.4.3 (informative) cites gives a strong guarantee while a
//! key encrypts not much more than a terabyte, 2^36 blocks, and a weakening one beyond it; Annex
//! D.6 warns that a few hundred terabytes under one key make attacks possible. The bound comes
//! from the 128-bit block, so a longer key does not raise it. Nothing here counts the blocks a key
//! has encrypted.
//!
//! ## `Key_1` and `Key_2` must be independent
//!
//! FIPS 140-3 IG C.I requires `Key_1` and `Key_2` to be "generated and/or established
//! independently", and a module to "check explicitly that Key_1 ≠ Key_2": with equal halves, XTS
//! falls to a chosen-ciphertext attack. The key's constructor refuses equal halves, and one of
//! all zeros, but it cannot check independence. Draw the whole key from an RNG, with
//! `FromKeyMaterial::generate`, rather than deriving one half from the other.

use crate::{Decrypting, Encrypting};
use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::hazmat::{BlockPermutation, KeyExpansion};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::FromKeyMaterial;
use bouncycastle_utils::ct::ct_eq_bytes;
use bouncycastle_utils::min;
use bouncycastle_utils::secret::Secret;

/// The block length XTS is defined on: 128 bits, the width of the field GF(2^128) in which the
/// tweak's mask is multiplied by α from one block to the next.
const BLOCK_LEN: usize = 16;

/// A 128-bit block.
type Block = [u8; BLOCK_LEN];

/// The length of the tweak, in bytes: the 128-bit tweak value `i`.
pub const XTS_TWEAK_LEN: usize = 16;

/// The shortest data unit, in bytes: one block, 128 bits (IEEE 1619-2007 Sec 5.1).
pub const XTS_MIN_DATA_UNIT_LEN: usize = BLOCK_LEN;

/// The longest data unit, in bytes: 2^20 blocks, 16 MiB (SP 800-38E Sec 4).
pub const XTS_MAX_DATA_UNIT_LEN: usize = (1 << 20) * BLOCK_LEN;

/// An XTS key over the permutation `P`: `Key_1` and `Key_2`, each expanded once, when the key is
/// made.
///
/// Built with [`FromKeyMaterial`] from `Key = Key_1 | Key_2`, which is 32 bytes over a permutation
/// with a 16-byte key and 64 over one with a 32-byte key, tagged [`KeyType::SymmetricCipherKey`].
/// It encrypts and decrypts one data unit at a time, in place, under the data unit's tweak; see
/// the [module docs](self) for the tweak, and for the security considerations.
///
/// # Construction
///
/// `from_key_material` refuses the key, as a [`SymmetricCipherError::KeyMaterialError`], with:
/// * [`KeyMaterialError::InvalidKeyType`] if it is not tagged [`KeyType::SymmetricCipherKey`],
///   or if either half is all zeros, which the permutation refuses as it does an all-zero key;
/// * [`KeyMaterialError::InvalidLength`] if it holds fewer bytes than the full key length;
/// * [`KeyMaterialError::GenericError`] if `Key_1` and `Key_2` are equal (FIPS 140-3 IG C.I);
/// * [`KeyMaterialError::SecurityStrength`] if it is tagged below the permutation's strength.
///   Each half carries the key's strength, capped at what the half's length can carry.
pub struct XTSKey<P> {
    // Nothing but the two expanded keys, which the permutation holds and wipes on drop (AES keeps
    // its schedule in a `Secret`).
    /// `Key_1`, which encrypts the data.
    key1: P,
    /// `Key_2`, which encrypts the tweak.
    key2: P,
}

impl<P: BlockPermutation<BLOCK_LEN>> XTSKey<P> {
    /// Encrypts one data unit in place under its tweak, and returns the number of bytes written,
    /// `data_unit.len()`: the ciphertext is as long as the plaintext. Over a permutation that
    /// decrypts only ([`BlockPermutation::DECRYPT_ONLY`]) it does not compile:
    ///
    /// ```compile_fail,E0080
    /// # mod toy { include!("../../tests/common/toy_block_cipher.rs"); }
    /// # use toy::ToyBlockCipher;
    /// use bouncycastle_symmetric::modes::XTSKey;
    /// use bouncycastle_core::hazmat::BlockPermutation;
    /// # use bouncycastle_core::errors::SymmetricCipherError;
    /// # use bouncycastle_core::hazmat::KeyExpansion;
    /// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
    /// # use bouncycastle_core::security_strength::SecurityStrength;
    /// use bouncycastle_core::symmetric_key::FromKeyMaterial;
    /// # use bouncycastle_core::traits::Algorithm;
    ///
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
    ///
    /// let key_bytes: [u8; 32] = core::array::from_fn(|i| i as u8 + 1);
    /// let material = KeyMaterial::<32>::from_bytes_as_type(&key_bytes, KeyType::SymmetricCipherKey)
    ///     .expect("a 32-byte symmetric cipher key");
    /// let key = XTSKey::<DecryptOnly>::from_key_material(&material).expect("an XTS key");
    /// let mut sector = [0x5Au8; 512];
    /// // Refused when the program is built: the permutation decrypts only.
    /// let _ = key.encrypt_inplace(&[0u8; 16], &mut sector);
    /// ```
    ///
    /// The same key does decrypt:
    ///
    /// ```
    /// # mod toy { include!("../../tests/common/toy_block_cipher.rs"); }
    /// # use toy::ToyBlockCipher;
    /// use bouncycastle_symmetric::modes::XTSKey;
    /// use bouncycastle_core::hazmat::BlockPermutation;
    /// # use bouncycastle_core::errors::SymmetricCipherError;
    /// # use bouncycastle_core::hazmat::KeyExpansion;
    /// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
    /// # use bouncycastle_core::security_strength::SecurityStrength;
    /// use bouncycastle_core::symmetric_key::FromKeyMaterial;
    /// # use bouncycastle_core::traits::Algorithm;
    ///
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
    ///
    /// let key_bytes: [u8; 32] = core::array::from_fn(|i| i as u8 + 1);
    /// let material = KeyMaterial::<32>::from_bytes_as_type(&key_bytes, KeyType::SymmetricCipherKey)
    ///     .expect("a 32-byte symmetric cipher key");
    /// let key = XTSKey::<DecryptOnly>::from_key_material(&material).expect("an XTS key");
    /// let mut sector = [0x5Au8; 512];
    /// // Decryption is not gated.
    /// assert_eq!(key.decrypt_inplace(&[0u8; 16], &mut sector), Ok(512));
    /// ```
    ///
    /// # Errors
    ///
    /// A data unit shorter than [`XTS_MIN_DATA_UNIT_LEN`] is refused with
    /// [`SymmetricCipherError::InvalidInputLength`], and one longer than
    /// [`XTS_MAX_DATA_UNIT_LEN`] with [`SymmetricCipherError::DataLimitExceeded`]; a refused data
    /// unit is left as it was.
    pub fn encrypt_inplace(
        &self,
        tweak: &[u8; XTS_TWEAK_LEN],
        data_unit: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        const {
            assert!(
                !P::DECRYPT_ONLY,
                "this permutation decrypts only (BlockPermutation::DECRYPT_ONLY): no data unit may be encrypted over it"
            )
        };
        check_data_unit_len(data_unit.len())?;
        encrypt(&self.key1, &self.key2, tweak, data_unit);
        Ok(data_unit.len())
    }

    /// Decrypts one data unit in place under the tweak it was encrypted under, and returns the
    /// number of bytes written, `data_unit.len()`. There is nothing to verify: any data unit of a
    /// valid length decrypts, a modified one to unpredictable plaintext.
    ///
    /// # Errors
    ///
    /// As for [`encrypt_inplace`](Self::encrypt_inplace): a data unit shorter than
    /// [`XTS_MIN_DATA_UNIT_LEN`] or longer than [`XTS_MAX_DATA_UNIT_LEN`] is refused, and left as
    /// it was.
    pub fn decrypt_inplace(
        &self,
        tweak: &[u8; XTS_TWEAK_LEN],
        data_unit: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        check_data_unit_len(data_unit.len())?;
        decrypt(&self.key1, &self.key2, tweak, data_unit);
        Ok(data_unit.len())
    }
}

/// The bounds on a data unit's length, checked before the data unit is touched, so that the
/// private functions below are never handed one outside them.
fn check_data_unit_len(len: usize) -> Result<(), SymmetricCipherError> {
    if len < XTS_MIN_DATA_UNIT_LEN {
        return Err(SymmetricCipherError::InvalidInputLength(
            "an XTS data unit is at least one block, 16 bytes (IEEE 1619-2007 Sec 5.1)",
        ));
    }
    if len > XTS_MAX_DATA_UNIT_LEN {
        return Err(SymmetricCipherError::DataLimitExceeded);
    }
    Ok(())
}

// One impl per key length, because the XTS key's length, twice the permutation's, cannot be
// written as an expression over the permutation's on stable Rust.

impl<P> FromKeyMaterial<32> for XTSKey<P>
where
    P: KeyExpansion<16> + BlockPermutation<BLOCK_LEN>,
{
    const KEY_TYPE: KeyType = KeyType::SymmetricCipherKey;

    /// Splits the 32-byte `Key_1 | Key_2` into two 16-byte keys and expands each; see
    /// [`XTSKey`] for when it refuses.
    fn from_key_material(key: &KeyMaterial<32>) -> Result<Self, SymmetricCipherError> {
        let (key1, key2) = expand_halves::<P, 16, 32>(key)?;
        Ok(Self { key1, key2 })
    }
}

impl<P> FromKeyMaterial<64> for XTSKey<P>
where
    P: KeyExpansion<32> + BlockPermutation<BLOCK_LEN>,
{
    const KEY_TYPE: KeyType = KeyType::SymmetricCipherKey;

    /// Splits the 64-byte `Key_1 | Key_2` into two 32-byte keys and expands each; see
    /// [`XTSKey`] for when it refuses.
    fn from_key_material(key: &KeyMaterial<64>) -> Result<Self, SymmetricCipherError> {
        let (key1, key2) = expand_halves::<P, 32, 64>(key)?;
        Ok(Self { key1, key2 })
    }
}

/// Parses `key` as `Key_1 | Key_2` and expands each half for `P`, after the checks that belong to
/// the XTS key as a whole: its type, its length, and `Key_1 != Key_2`. The permutation then checks
/// each half as it would any key of its own.
fn expand_halves<P, const HALF: usize, const FULL: usize>(
    key: &KeyMaterial<FULL>,
) -> Result<(P, P), SymmetricCipherError>
where
    P: KeyExpansion<HALF>,
{
    const { assert!(FULL == 2 * HALF, "an XTS key is two keys for the permutation") };

    // The halves are retagged for the permutation below, so the XTS key's own type is checked
    // here; otherwise a MAC key, say, would pass as a cipher key.
    if key.key_type() != KeyType::SymmetricCipherKey {
        return Err(KeyMaterialError::InvalidKeyType(
            "XTS requires a key of type KeyType::SymmetricCipherKey.",
        )
        .into());
    }
    // A `KeyMaterial<FULL>` can hold fewer than FULL bytes. Splitting a short key would hand the
    // permutation a short second half, or none; refuse it rather than take the buffer's zeros.
    if key.key_len() != FULL {
        return Err(KeyMaterialError::InvalidLength.into());
    }

    // Key = Key_1 | Key_2, two halves of equal size (IEEE 1619-2007 Sec 5.3.1).
    let (key1, key2) = key.ref_to_bytes().split_at(HALF);

    // FIPS 140-3 IG C.I: "The module shall check explicitly that Key_1 ≠ Key_2, regardless of how
    // Key_1 and Key_2 are obtained." In constant time; only the outcome, a refusal, is public.
    if ct_eq_bytes(key1, key2) {
        return Err(KeyMaterialError::GenericError(
            "XTS requires Key_1 != Key_2 (FIPS 140-3 IG C.I).",
        )
        .into());
    }

    let strength = key.security_strength();
    Ok((P::new(&half(key1, strength)?)?, P::new(&half(key2, strength)?)?))
}

/// One half of the XTS key as a key for the permutation: `bytes` tagged
/// [`KeyType::SymmetricCipherKey`], at the XTS key's `strength` capped at what `HALF` bytes carry.
///
/// `from_bytes_as_type` credits a key with its full length, which for an XTS key tagged below
/// that would raise its strength in the halves; lowering it again needs no hazardous-operations
/// window. An all-zero half comes back [`KeyType::Zeroized`], at no strength, for the permutation
/// to refuse.
fn half<const HALF: usize>(
    bytes: &[u8],
    strength: SecurityStrength,
) -> Result<KeyMaterial<HALF>, SymmetricCipherError> {
    let mut half = KeyMaterial::<HALF>::from_bytes_as_type(bytes, KeyType::SymmetricCipherKey)?;
    let capped = *min(&strength, &half.security_strength());
    half.set_security_strength(capped)?;
    Ok(half)
}

// The algorithm is IEEE 1619-2007 Sec 5, and the comments use its procedure names and step
// numbers: XTS-AES-blockEnc (Sec 5.3.1) and -blockDec (Sec 5.4.1) on one block, XTS-AES-Enc
// (Sec 5.3.2) and -Dec (Sec 5.4.2) on a data unit, and the multiplication by α (Sec 5.2). Sec
// 5.4.2 letters the sub-steps of its steps 3 and 4 continuously, b) to h), and the comments keep
// those letters. The NIST ACVP and Wycheproof vectors in `bouncycastle_symmetric::aes` pin the conventions
// that interoperability rests on: the order of the key halves, the byte order of the tweak and of
// the multiplication by α, and the order of the two blocks that ciphertext stealing produces.

/// Step 3 of XTS-AES-blockEnc and XTS-AES-blockDec, the only step in which the two directions
/// differ: the forward cipher under `Key_1` when encrypting, the inverse when decrypting. The
/// mask, and its XOR on either side of the cipher, are the same in both.
trait CipherStep<P> {
    fn one(key1: &P, block: &mut Block);
    fn two(key1: &P, blocks: &mut [Block; 2]);
    fn four(key1: &P, blocks: &mut [Block; 4]);
}

impl<P: BlockPermutation<BLOCK_LEN>> CipherStep<P> for Encrypting {
    fn one(key1: &P, block: &mut Block) {
        key1.encrypt_block(block);
    }

    fn two(key1: &P, blocks: &mut [Block; 2]) {
        key1.encrypt_2blocks(blocks);
    }

    fn four(key1: &P, blocks: &mut [Block; 4]) {
        key1.encrypt_4blocks(blocks);
    }
}

impl<P: BlockPermutation<BLOCK_LEN>> CipherStep<P> for Decrypting {
    fn one(key1: &P, block: &mut Block) {
        key1.decrypt_block(block);
    }

    fn two(key1: &P, blocks: &mut [Block; 2]) {
        key1.decrypt_2blocks(blocks);
    }

    fn four(key1: &P, blocks: &mut [Block; 4]) {
        key1.decrypt_4blocks(blocks);
    }
}

/// `T ⊗ α` (IEEE 1619-2007 Sec 5.2): multiplication by the primitive element α = x of GF(2^128),
/// modulo x^128 + x^7 + x^2 + x + 1 (Sec 4.2). Byte 0 is the first byte of the AES block, and
/// bit k of byte j is the coefficient of x^(8j + k).
///
/// Sec 5.2's recurrence is a one-bit shift towards the top across the bytes, from byte 0 up:
/// byte k, for k from 1 to 15, becomes 2 (t[k] mod 128) ^ floor(t[k - 1] / 128), and byte 0
/// becomes 2 (t[0] mod 128) ^ 135 floor(t[15] / 128). When the bit shifted out of byte 15, the
/// coefficient of x^127, is set, x^128 reduces to x^7 + x^2 + x + 1, and 135 = 0x87 is XORed into
/// byte 0. The reduction is selected with a mask rather than a branch, since `T` is secret (it is
/// the tweak encrypted under `Key_2`), as CMAC's doubling does.
fn mul_alpha(t: &mut Block) {
    // The carry out of x^127, floor(t[15] / 128), read before byte 15 is overwritten.
    let carry = t[BLOCK_LEN - 1] >> 7;
    // From the top byte down, so that byte k - 1 still holds its old value when byte k takes its
    // top bit. On a byte, 2 (t[k] mod 128) is `t[k] << 1`, and floor(t[k - 1] / 128) is
    // `t[k - 1] >> 7`. The two operands of `|` have no bit in common, so `|` and `^` agree here.
    for k in (1..BLOCK_LEN).rev() {
        t[k] = (t[k] << 1) | (t[k - 1] >> 7);
    }
    t[0] = (t[0] << 1) ^ (0x87 & 0u8.wrapping_sub(carry));
}

/// `block ^= mask`.
fn xor_into(block: &mut Block, mask: &Block) {
    for (b, m) in block.iter_mut().zip(mask) {
        *b ^= m;
    }
}

/// XTS-AES-blockEnc (`D = Encrypting`, IEEE 1619-2007 Sec 5.3.1) or -blockDec (`D = Decrypting`,
/// Sec 5.4.1) of one block in place, under the mask `t`, which is `T = AES-enc(Key_2, i) ⊗ α^j`
/// for the block's index `j` (step 1): step 2 XORs `T` in, step 3 runs the cipher under `Key_1`,
/// step 4 XORs `T` in again.
fn xex<P, D: CipherStep<P>>(key1: &P, t: &Block, block: &mut Block) {
    xor_into(block, t); // step 2: PP = P ^ T (CC = C ^ T)
    D::one(key1, block); // step 3: CC = AES-enc(Key_1, PP) (PP = AES-dec(Key_1, CC))
    xor_into(block, t); // step 4: C = CC ^ T (P = PP ^ T)
}

/// [`xex`] on each of `blocks` in turn, with consecutive indices: the first under the mask in `t`
/// and each later one under the mask before it times α. Returns with `t` holding the mask for the
/// index after the last block.
///
/// Given its mask, each block is independent of the others, so they go through the permutation
/// four at a time, then two, then one; the masks are the same sequence whatever the grouping.
fn xex_blocks<P, D: CipherStep<P>>(key1: &P, t: &mut Block, blocks: &mut [Block]) {
    // The masks of the blocks in flight. Declared once, before the loops, so that they are
    // zeroized once, after them.
    let mut masks: Secret<[Block; 4]> = Secret::new();

    let (fours, rest) = blocks.as_chunks_mut::<4>();
    for four in fours {
        for (block, mask) in four.iter_mut().zip(masks.iter_mut()) {
            *mask = *t;
            xor_into(block, mask);
            mul_alpha(t);
        }
        D::four(key1, four);
        for (block, mask) in four.iter_mut().zip(masks.iter()) {
            xor_into(block, mask);
        }
    }

    // At most three blocks are left: a pair and a single, or one of them, or none.
    let (twos, ones) = rest.as_chunks_mut::<2>();
    for two in twos {
        for (block, mask) in two.iter_mut().zip(masks.iter_mut()) {
            *mask = *t;
            xor_into(block, mask);
            mul_alpha(t);
        }
        D::two(key1, two);
        for (block, mask) in two.iter_mut().zip(masks.iter()) {
            xor_into(block, mask);
        }
    }
    for one in ones {
        xex::<P, D>(key1, t, one);
        mul_alpha(t);
    }
}

/// Sets `t` to the mask of block 0 of a data unit under the tweak `i`: `T = AES-enc(Key_2, i) ⊗
/// α^0`, the tweak encrypted under `Key_2` in both directions (step 1 of Sec 5.3.1 and of Sec
/// 5.4.1).
///
/// The mask is written into the caller's `Secret`, which wipes it on drop; returned by value, it
/// would be moved out of a local here that nothing wipes.
fn first_mask<P: BlockPermutation<BLOCK_LEN>>(key2: &P, i: &Block, t: &mut Block) {
    *t = *i;
    key2.encrypt_block(t);
}

/// XTS-AES-Enc (IEEE 1619-2007 Sec 5.3.2) of the data unit `data`, in place, under the tweak
/// `i`. `data` is from [`XTS_MIN_DATA_UNIT_LEN`] to [`XTS_MAX_DATA_UNIT_LEN`] bytes long, which
/// the callers check.
fn encrypt<P: BlockPermutation<BLOCK_LEN>>(key1: &P, key2: &P, i: &Block, data: &mut [u8]) {
    let mut t: Secret<Block> = Secret::new();
    first_mask(key2, i, &mut t);

    // `blocks` are P_0 .. P_{m-1}, the whole blocks, and `tail` is P_m, the b < 16 bytes after
    // them, which is empty when the data unit is a whole number of blocks.
    let (blocks, tail) = data.as_chunks_mut::<BLOCK_LEN>();

    // Step 1, and step 3a or 4a for the last whole block: XTS-AES-blockEnc(P_q, i, q) for every
    // whole block. Without a partial block that is the whole data unit; with one, the last result
    // is step 4a's CC, which ciphertext stealing takes apart.
    xex_blocks::<P, Encrypting>(key1, &mut t, blocks);

    // Ciphertext stealing, steps 4b to 4e. Swapping CC's first b bytes with the tail puts them,
    // C_m, in the tail (4b), after C_{m-1} as step 5 orders them, and leaves PP = P_m | CP in the
    // block, CP being the rest of CC (4c, 4d); PP is then encrypted under index m -- the mask now
    // in `t` -- to C_{m-1} (4e). Every index here depends on the length alone.
    if !tail.is_empty()
        && let Some(last) = blocks.last_mut()
    {
        last[..tail.len()].swap_with_slice(tail);
        xex::<P, Encrypting>(key1, &t, last);
    }
}

/// XTS-AES-Dec (IEEE 1619-2007 Sec 5.4.2) of the data unit `data`, in place, under the tweak
/// `i`. The length is as for [`encrypt`].
fn decrypt<P: BlockPermutation<BLOCK_LEN>>(key1: &P, key2: &P, i: &Block, data: &mut [u8]) {
    let mut t: Secret<Block> = Secret::new();
    first_mask(key2, i, &mut t);
    let (blocks, tail) = data.as_chunks_mut::<BLOCK_LEN>();

    // With a partial block, ciphertext stealing undoes the encryption's last two block
    // operations, which used indices m - 1 and m, in the reverse order: C_{m-1} first, under m.
    if !tail.is_empty()
        && let Some((last, head)) = blocks.split_last_mut()
    {
        // Step 1, P_q = XTS-AES-blockDec(C_q, i, q) for q < m - 1, leaves the mask of m - 1 in `t`.
        xex_blocks::<P, Decrypting>(key1, &mut t, head);

        // Step 4d: PP = XTS-AES-blockDec(C_{m-1}, i, m) = P_m | CP, under the mask after `t`'s.
        let mut t_m: Secret<Block> = Secret::new();
        *t_m = *t;
        mul_alpha(&mut t_m);
        xex::<P, Decrypting>(key1, &t_m, last);

        // Swapping the first b bytes back puts P_m in the tail (4e) and CC = C_m | CP in the
        // block (4f, 4g), and P_{m-1} = XTS-AES-blockDec(CC, i, m - 1) (4h).
        last[..tail.len()].swap_with_slice(tail);
        xex::<P, Decrypting>(key1, &t, last);
    } else {
        // Steps 1 and 3b: P_q = XTS-AES-blockDec(C_q, i, q) for every block.
        xex_blocks::<P, Decrypting>(key1, &mut t, blocks);
    }
}
