//! AES-GCM-SIV (RFC 8452), the nonce misuse-resistant authenticated encryption mode.
//!
//! The tag is computed over the plaintext and is also the counter mode's initial counter block,
//! so encryption reads the whole plaintext before it writes the first ciphertext byte, and
//! decryption has the whole plaintext before it can check the tag. Neither direction can stream.
//! A key bound to [`GCM_SIV`] therefore has the in-place one-shots of
//! [`AeadInPlaceEncryptionKey`] / [`AeadInPlaceDecryptionKey`] and nothing else: no worker, and no
//! form that takes a separate output buffer.
//!
//! The nonce is 12 bytes ([`GCM_SIV_NONCE_LEN`]) and the tag 16 ([`GCM_SIV_TAG_LEN`]); RFC 8452
//! Section 6 fixes both. The mode exists over AES-128 and AES-256 only, the two AEADs that
//! section defines (`AEAD_AES_128_GCM_SIV`, `AEAD_AES_256_GCM_SIV`); see [`GCM_SIV`].
//!
//! # Usage Examples
//!
//! The mode is defined over AES only, so the runnable example is in `bouncycastle_symmetric::aes`, on
//! `AES_GCM_SIV_128`. The shape:
//!
//! ```text
//! let key = AES256Key::<GCM_SIV>::from_key_material(&material)?;                  // once
//! let (nonce, tag) = key.encrypt_detached_inplace(&mut rng, aad, &mut buf)?;      // buf: plaintext -> ciphertext
//! key.decrypt_detached_inplace(&nonce, aad, &mut buf, &tag)?;                     // buf: ciphertext -> plaintext
//! ```
//!
//! # 🚨 Security Considerations 🚨
//!
//! ## A repeated nonce is survivable, not free
//!
//! RFC 8452 Section 9: "if a nonce repeats, then the only security loss is that identical
//! plaintexts will produce identical ciphertexts". That holds for messages under the same
//! additional data as well as the same nonce, and it tells an observer that the two messages were
//! equal. The same section goes on: "we do not recommend using a fixed nonce as a policy", and "it
//! is RECOMMENDED that AES-GCM-SIV nonces be randomly generated". `encrypt_detached_inplace` draws
//! the nonce from the caller's RNG; the `_nonce` form leaves the choice to the caller.
//!
//! ## The whole message is in memory
//!
//! Decryption produces the plaintext before it can authenticate it, and Section 9 requires that
//! "implementations MUST NOT release unauthenticated plaintext". `decrypt_detached_inplace` holds
//! to that: when the tag does not verify the buffer is zeroized before the error is returned.
//! The cost is that a message must fit in memory whole, in both directions; size messages
//! accordingly.
//!
//! ## Length and usage limits
//!
//! Plaintext and additional data are each limited to 2^36 bytes (Section 6, `P_MAX` and
//! `A_MAX`); a longer input is refused with [`SymmetricCipherError::InvalidInputLength`] before
//! anything is processed. How many messages of what size one key may protect is the caller's to
//! keep to: Section 9 gives example bounds for random nonces and for bounded nonce reuse. No
//! count is kept here.
//!
//! ## Cost per message
//!
//! Every message derives its own keys from the nonce (Section 4): four block encryptions for
//! AES-128 or six for AES-256, then an AES key expansion, before the first byte is processed.
//! For short messages that is half the work or more: in `bouncycastle_symmetric::aes`'s benches on x86-64 a
//! 64-byte message takes 2.0 times (AES-128) or 2.4 times (AES-256) as long as under GCM; at
//! 16 KiB the two take the same time.

use crate::modes::hazmat::gcm_siv::GcmSivPermutation;
use crate::modes::iv::random_iv;
use crate::modes::polyval::Polyval;
use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::hazmat::{
    AeadInPlaceDecryptMode, AeadInPlaceEncryptMode, BlockPermutation, ElectronicCodeBook, Mode,
    do_hazardous_operations,
};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::RNG;
use bouncycastle_utils::ct::ct_eq_bytes;
use bouncycastle_utils::secret::{Secret, zeroize_in_place};

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_core::symmetric_key::{AeadInPlaceDecryptionKey, AeadInPlaceEncryptionKey};
// end of imports needed for docs

/// The nonce length: 12 bytes. RFC 8452 Section 6: "N_MIN and N_MAX are 12".
pub const GCM_SIV_NONCE_LEN: usize = 12;

/// The tag length: 16 bytes, the one block RFC 8452 Section 4 produces.
pub const GCM_SIV_TAG_LEN: usize = 16;

/// RFC 8452 Section 6: "P_MAX is 2^36, A_MAX is 2^36", in bytes.
const MAX_LEN: u64 = 1 << 36;

/// The AES-GCM-SIV mode type: the `M` of a mode-bound key such as
/// `bouncycastle_symmetric::aes::AES256Key<GCM_SIV>`, which then carries [`AeadInPlaceEncryptionKey`] and
/// [`AeadInPlaceDecryptionKey`] with a 12-byte nonce and a 16-byte tag.
///
/// RFC 8452 defines the mode for AES with a 16- or 32-byte key and for nothing else, so the mode
/// traits are implemented only over a permutation that carries
/// [`GcmSivPermutation`], which `bouncycastle_symmetric::aes` implements for
/// AES-128 and AES-256. A key over any other permutation is not a type that can be made:
///
/// ```compile_fail,E0277
/// # mod toy { include!("../../tests/common/toy_block_cipher.rs"); }
/// # use toy::ToyBlockCipher;
/// use bouncycastle_symmetric::BlockCipherKey;
/// use bouncycastle_symmetric::modes::GCM_SIV;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::symmetric_key::FromKeyMaterial;
///
/// let material = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
///     .expect("a 16-byte symmetric cipher key");
/// // The same line with `GCM` in place of `GCM_SIV` compiles: the toy is not AES.
/// let key = BlockCipherKey::<ToyBlockCipher, GCM_SIV>::from_key_material(&material);
/// ```
#[allow(non_camel_case_types)]
pub struct GCM_SIV;

impl<P> Mode<P> for GCM_SIV
where
    P: BlockPermutation<16> + GcmSivPermutation + Clone,
{
    /// The permutation keyed with the key-generating key. Everything else is derived per nonce.
    type KeyState = P;
    const KEY_TYPE: KeyType = KeyType::SymmetricCipherKey;
    const ALG_NAME: &'static str = P::GCM_SIV_ALG_NAME;

    fn key_state(perm: P) -> Self::KeyState {
        perm
    }
}

impl<P, const KEY_LEN: usize> AeadInPlaceEncryptMode<P, KEY_LEN, GCM_SIV_NONCE_LEN, GCM_SIV_TAG_LEN>
    for GCM_SIV
where
    P: ElectronicCodeBook<KEY_LEN, 16> + GcmSivPermutation + Clone,
{
    /// `buf` is untouched if the nonce draw fails or the lengths are refused; the lengths are
    /// checked first, so a refused request draws nothing.
    fn encrypt_detached_inplace(
        state: &Self::KeyState,
        rng: &mut dyn RNG,
        aad: &[u8],
        buf: &mut [u8],
    ) -> Result<([u8; GCM_SIV_NONCE_LEN], [u8; GCM_SIV_TAG_LEN]), SymmetricCipherError> {
        check_lengths(aad.len(), buf.len())?;
        let nonce = random_iv::<GCM_SIV_NONCE_LEN>(rng)?;
        let tag = encrypt(state, &nonce, aad, buf)?;
        Ok((nonce, tag))
    }

    /// `buf` is untouched if the lengths are refused.
    fn encrypt_detached_inplace_nonce(
        state: &Self::KeyState,
        nonce: &[u8; GCM_SIV_NONCE_LEN],
        aad: &[u8],
        buf: &mut [u8],
    ) -> Result<[u8; GCM_SIV_TAG_LEN], SymmetricCipherError> {
        encrypt(state, nonce, aad, buf)
    }
}

impl<P, const KEY_LEN: usize> AeadInPlaceDecryptMode<P, KEY_LEN, GCM_SIV_NONCE_LEN, GCM_SIV_TAG_LEN>
    for GCM_SIV
where
    P: ElectronicCodeBook<KEY_LEN, 16> + GcmSivPermutation + Clone,
{
    /// `buf` is untouched if the lengths are refused, and zeroized if the tag does not verify.
    fn decrypt_detached_inplace(
        state: &Self::KeyState,
        nonce: &[u8; GCM_SIV_NONCE_LEN],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; GCM_SIV_TAG_LEN],
    ) -> Result<(), SymmetricCipherError> {
        decrypt(state, nonce, aad, buf, tag)
    }
}

// The functions below are the mode. They bound on the `core` permutation traits alone, not on
// `GcmSivPermutation`, which gates the trait impls above; the unit tests reach them over
// `bouncycastle_symmetric::aes`'s permutations.

/// The first two lines of `encrypt` and `decrypt` (RFC 8452 Sections 4 and 5): "if
/// bytelen(plaintext) > 2^36 { fail() }", "if bytelen(additional_data) > 2^36 { fail() }". The
/// lengths are public.
///
/// Decryption's "bytelen(ciphertext) < 16 || bytelen(ciphertext) > 2^36 + 16" is the same bound
/// on the plaintext length, the tag being detached here and its length fixed by its type.
fn check_lengths(aad_len: usize, data_len: usize) -> Result<(), SymmetricCipherError> {
    // `usize` is at most 64 bits wide, so the widening is lossless and the comparison cannot
    // overflow; on a 32-bit target neither length can reach the limit.
    if data_len as u64 > MAX_LEN {
        return Err(SymmetricCipherError::InvalidInputLength(
            "AES-GCM-SIV takes at most 2^36 bytes of plaintext (RFC 8452 Section 6)",
        ));
    }
    if aad_len as u64 > MAX_LEN {
        return Err(SymmetricCipherError::InvalidInputLength(
            "AES-GCM-SIV takes at most 2^36 bytes of additional data (RFC 8452 Section 6)",
        ));
    }
    Ok(())
}

/// Sixteen bytes of `derive_keys` output (RFC 8452 Section 4), written to `out`:
///
/// ```text
/// AES(key = key_generating_key, block = little_endian_uint32(counter) ++ nonce)[:8] ++
/// AES(key = key_generating_key, block = little_endian_uint32(counter + 1) ++ nonce)[:8]
/// ```
///
/// The two blocks are independent, so they go through the permutation as one pair. Both whole
/// ciphertext blocks are key material, the discarded halves included, and are wiped on return.
fn derive_half<P: BlockPermutation<16>>(
    key_generating_key: &P,
    nonce: &[u8; GCM_SIV_NONCE_LEN],
    counter: u32,
    out: &mut [u8; 16],
) {
    let mut blocks: Secret<[[u8; 16]; 2]> = Secret::new();
    blocks[0][..4].copy_from_slice(&counter.to_le_bytes());
    blocks[0][4..].copy_from_slice(nonce);
    blocks[1][..4].copy_from_slice(&counter.wrapping_add(1).to_le_bytes());
    blocks[1][4..].copy_from_slice(nonce);
    key_generating_key.encrypt_2blocks(&mut blocks);
    out[..8].copy_from_slice(&blocks[0][..8]);
    out[8..].copy_from_slice(&blocks[1][..8]);
}

/// `derive_keys` (RFC 8452 Section 4): the per-nonce message-authentication key, from counters 0
/// and 1, and message-encryption key, from counters 2 and 3 and, "if
/// bytelen(key_generating_key) == 32", 4 and 5. Both are written where they will be used, so no
/// copy of either is made on the way.
///
/// The encryption key is built as the `SymmetricCipherKey` the permutation's constructor asks
/// for, at the permutation's own strength, which the key-generating key had to carry to be
/// accepted. The bytes and the tags are set inside one hazardous-operations window, so an
/// all-zero derived key is tagged like any other rather than `Zeroized`.
///
/// # Errors
/// None for a permutation whose strength its own key length can carry, which every permutation
/// is; the `KeyMaterial` setters are fallible in general.
fn derive_keys<P, const KEY_LEN: usize>(
    key_generating_key: &P,
    nonce: &[u8; GCM_SIV_NONCE_LEN],
    message_authentication_key: &mut Secret<[u8; 16]>,
    message_encryption_key: &mut KeyMaterial<KEY_LEN>,
) -> Result<(), KeyMaterialError>
where
    P: ElectronicCodeBook<KEY_LEN, 16>,
{
    // The key-generating key is 16 or 32 bytes (Section 4), so the encryption key is one or two
    // halves with nothing over. A 24-byte key does not get this far.
    const {
        assert!(
            KEY_LEN == 16 || KEY_LEN == 32,
            "RFC 8452 defines AES-GCM-SIV for 16- and 32-byte keys only"
        );
    };

    derive_half(key_generating_key, nonce, 0, message_authentication_key);
    do_hazardous_operations(message_encryption_key, |key| {
        let (halves, _) = key.ref_to_bytes_mut()?.as_chunks_mut::<16>();
        let mut counter = 2;
        for half in halves {
            derive_half(key_generating_key, nonce, counter, half);
            counter += 2;
        }
        key.set_key_len(KEY_LEN)?;
        key.set_key_type(KeyType::SymmetricCipherKey)?;
        key.set_security_strength(P::MAX_SECURITY_STRENGTH)
    })
}

/// `derive_keys`, then the key expansion of the message-encryption key: the authentication key
/// is written to `message_authentication_key` and the permutation keyed for this nonce is
/// returned. The key bytes themselves are wiped when this returns.
///
/// # Errors
/// As [`derive_keys`], and whatever the permutation's constructor refuses. AES's refuses a key
/// type, length or strength, none of which a derived key gets wrong, and has no weak keys.
fn message_keys<P, const KEY_LEN: usize>(
    key_generating_key: &P,
    nonce: &[u8; GCM_SIV_NONCE_LEN],
    message_authentication_key: &mut Secret<[u8; 16]>,
) -> Result<P, SymmetricCipherError>
where
    P: ElectronicCodeBook<KEY_LEN, 16>,
{
    let mut message_encryption_key = KeyMaterial::<KEY_LEN>::new();
    derive_keys(
        key_generating_key,
        nonce,
        message_authentication_key,
        &mut message_encryption_key,
    )?;
    P::new(&message_encryption_key)
}

/// The tag over `additional_data` and `plaintext` (RFC 8452 Section 4, the same steps as
/// Section 5's `expected_tag`), written to `tag`, which holds `S_s` on the way.
fn compute_tag<P: BlockPermutation<16>>(
    message_encryption_key: &P,
    message_authentication_key: &[u8; 16],
    nonce: &[u8; GCM_SIV_NONCE_LEN],
    additional_data: &[u8],
    plaintext: &[u8],
    tag: &mut Secret<[u8; 16]>,
) {
    // length_block = little_endian_uint64(bytelen(additional_data) * 8) ++
    //                little_endian_uint64(bytelen(plaintext) * 8)
    // Neither product overflows: `check_lengths` held both to 2^36 bytes.
    let mut length_block = [0u8; 16];
    length_block[..8].copy_from_slice(&(additional_data.len() as u64 * 8).to_le_bytes());
    length_block[8..].copy_from_slice(&(plaintext.len() as u64 * 8).to_le_bytes());

    // S_s = POLYVAL(key = message_authentication_key,
    //               input = padded_ad ++ padded_plaintext ++ length_block)
    let mut polyval = Polyval::new(message_authentication_key);
    polyval.update_padded(additional_data);
    polyval.update_padded(plaintext);
    polyval.update_block(&length_block);
    polyval.finish(tag);

    // for i = 0; i < 12; i++ { S_s[i] ^= nonce[i] }
    for (s, n) in tag.iter_mut().zip(nonce) {
        *s ^= n;
    }
    // S_s[15] &= 0x7f
    tag[15] &= 0x7f;
    // tag = AES(key = message_encryption_key, block = S_s)
    message_encryption_key.encrypt_block(tag);
}

/// `AES_CTR` (RFC 8452 Section 4) over `data` in place, from the counter block the tag gives:
/// "counter_block = tag", "counter_block[15] |= 0x80". "The counter advances by incrementing the
/// first 32 bits interpreted as an unsigned, little-endian integer, wrapping at 2^32"; this is
/// not SP 800-38A's big-endian counter in the last bytes, which is why the crate's `Ctr` is not
/// used.
///
/// The keystream is generated four blocks at a time while 64 bytes of data remain and two at a
/// time for the rest, as the crate's `Ctr` does, where the pseudocode generates one; a block
/// the data does not reach is unused. The counter block is the tag, which travels with the
/// ciphertext, so only the keystream is held as a secret.
fn aes_ctr<P: BlockPermutation<16>>(
    message_encryption_key: &P,
    tag: &[u8; GCM_SIV_TAG_LEN],
    data: &mut [u8],
) {
    let mut counter_block = *tag;
    counter_block[15] |= 0x80;
    let mut counter = u32::from_le_bytes([tag[0], tag[1], tag[2], tag[3]]);

    // keystream_block = AES(key = key, block = block), by the callers below;
    // block[0:4] = little_endian_uint32(read_little_endian_uint32(block[0:4]) + 1)
    let mut next_counter_block = |block: &mut [u8; 16]| {
        *block = counter_block;
        block[..4].copy_from_slice(&counter.to_le_bytes());
        counter = counter.wrapping_add(1);
    };

    let mut fours = data.chunks_exact_mut(64);
    let mut keystream4: Secret<[[u8; 16]; 4]> = Secret::new();
    for chunk in &mut fours {
        keystream4.iter_mut().for_each(&mut next_counter_block);
        message_encryption_key.encrypt_4blocks(&mut keystream4);
        for (byte, k) in chunk.iter_mut().zip(keystream4.as_flattened()) {
            *byte ^= k;
        }
    }
    let mut keystream2: Secret<[[u8; 16]; 2]> = Secret::new();
    for chunk in fours.into_remainder().chunks_mut(32) {
        keystream2.iter_mut().for_each(&mut next_counter_block);
        message_encryption_key.encrypt_2blocks(&mut keystream2);
        for (byte, k) in chunk.iter_mut().zip(keystream2.as_flattened()) {
            *byte ^= k;
        }
    }
}

/// `encrypt` (RFC 8452 Section 4) with the plaintext in `buf`, which holds the encrypted
/// plaintext on return; the tag is returned rather than appended.
///
/// # Errors
/// [`SymmetricCipherError::InvalidInputLength`] if either input is over 2^36 bytes, with `buf`
/// untouched. See [`message_keys`] for the errors the key derivation is typed to return; `buf`
/// is untouched after those too.
fn encrypt<P, const KEY_LEN: usize>(
    key_generating_key: &P,
    nonce: &[u8; GCM_SIV_NONCE_LEN],
    additional_data: &[u8],
    buf: &mut [u8],
) -> Result<[u8; GCM_SIV_TAG_LEN], SymmetricCipherError>
where
    P: ElectronicCodeBook<KEY_LEN, 16>,
{
    check_lengths(additional_data.len(), buf.len())?;

    // message_encryption_key, message_authentication_key = derive_keys(key_generating_key, nonce)
    let mut message_authentication_key: Secret<[u8; 16]> = Secret::new();
    let message_encryption_key =
        message_keys(key_generating_key, nonce, &mut message_authentication_key)?;

    // The tag is taken over the plaintext, so before `buf` is encrypted.
    let mut tag: Secret<[u8; 16]> = Secret::new();
    compute_tag(
        &message_encryption_key,
        &message_authentication_key,
        nonce,
        additional_data,
        buf,
        &mut tag,
    );

    // return AES_CTR(key = message_encryption_key, initial_counter_block = counter_block,
    //                in = plaintext) ++ tag
    aes_ctr(&message_encryption_key, &tag, buf);
    // The finished tag is public: it is copied out of the `Secret` that held `S_s`.
    Ok(*tag)
}

/// `decrypt` (RFC 8452 Section 5) with the encrypted plaintext in `buf` and the tag beside it.
/// On success `buf` holds the plaintext.
///
/// # Errors
/// [`SymmetricCipherError::InvalidInputLength`] if either input is over 2^36 bytes, and the
/// errors [`message_keys`] is typed to return, all with `buf` untouched.
/// [`SymmetricCipherError::AEADTagCheckFailed`] if the tag does not verify, with `buf` zeroized.
fn decrypt<P, const KEY_LEN: usize>(
    key_generating_key: &P,
    nonce: &[u8; GCM_SIV_NONCE_LEN],
    additional_data: &[u8],
    buf: &mut [u8],
    tag: &[u8; GCM_SIV_TAG_LEN],
) -> Result<(), SymmetricCipherError>
where
    P: ElectronicCodeBook<KEY_LEN, 16>,
{
    check_lengths(additional_data.len(), buf.len())?;

    // message_encryption_key, message_authentication_key = derive_keys(key_generating_key, nonce)
    let mut message_authentication_key: Secret<[u8; 16]> = Secret::new();
    let message_encryption_key =
        message_keys(key_generating_key, nonce, &mut message_authentication_key)?;

    // plaintext = AES_CTR(key = message_encryption_key, initial_counter_block = counter_block,
    //                     in = ciphertext[:bytelen(ciphertext)-16])
    // "At this point, the plaintext is unauthenticated and MUST NOT be output until the following
    // tag confirmation is complete".
    aes_ctr(&message_encryption_key, tag, buf);

    let mut expected_tag: Secret<[u8; 16]> = Secret::new();
    compute_tag(
        &message_encryption_key,
        &message_authentication_key,
        nonce,
        additional_data,
        buf,
        &mut expected_tag,
    );

    // "Compare the provided and expected tag values in constant time. Fail the decryption if
    // they do not match (and do not release the plaintext)". The outcome is public once known.
    if ct_eq_bytes(&*expected_tag, tag) {
        Ok(())
    } else {
        // A volatile write per byte, which the compiler may not drop as a plain fill of a buffer
        // the caller then discards could be.
        for byte in buf.iter_mut() {
            zeroize_in_place(byte);
        }
        Err(SymmetricCipherError::AEADTagCheckFailed)
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests because the values RFC 8452 Appendix C gives for the derived keys are not
    //! reachable from the public API, nor are the counter's wrap as such and the length limits,
    //! which no buffer can reach. They run over `bouncycastle_symmetric::aes`'s permutations:
    //! the mode is defined over AES only, and a toy permutation has no known answers. The public
    //! API is tested from that module's integration tests.

    use super::*;
    use crate::aes::hazmat::{AES128Internal, AES256Internal};
    use alloc::vec;
    use alloc::vec::Vec;
    use bouncycastle_core::hazmat::KeyExpansion;
    use bouncycastle_core::security_strength::SecurityStrength;
    use bouncycastle_core::traits::Algorithm;

    // BEGIN values lifted from RFC 8452.
    //
    // Generated by a script, not typed: it reads https://www.rfc-editor.org/rfc/rfc8452.txt and
    // takes each field of each Appendix C record by its label there ("Key =", "Record
    // authentication key =", "Result (48 bytes) =" and so on), checking the byte counts the
    // labels give. To regenerate, run `dev_scripts/rfc8452_vectors/lift_gcm_siv_vectors.py
    // <rfc8452.txt> unit`; a value is never edited by hand.

    /// RFC 8452 Appendix C: (section, key, nonce, plaintext, AAD, record authentication key,
    /// record encryption key, result) of every vector, in the RFC's order.
    #[rustfmt::skip]
    #[allow(clippy::type_complexity)]
    const APPENDIX_C: &[(&str, &str, &str, &str, &str, &str, &str, &str)] = &[
        ("C.1", "01000000000000000000000000000000", "030000000000000000000000",
         "",
         "",
         "d9b360279694941ac5dbc6987ada7377", "4004a0dcd862f2a57360219d2d44ef6c",
         "dc20e2d83f25705bb49e439eca56de25"),
        ("C.1", "01000000000000000000000000000000", "030000000000000000000000",
         "0100000000000000",
         "",
         "d9b360279694941ac5dbc6987ada7377", "4004a0dcd862f2a57360219d2d44ef6c",
         "b5d839330ac7b786578782fff6013b815b287c22493a364c"),
        ("C.1", "01000000000000000000000000000000", "030000000000000000000000",
         "010000000000000000000000",
         "",
         "d9b360279694941ac5dbc6987ada7377", "4004a0dcd862f2a57360219d2d44ef6c",
         "7323ea61d05932260047d942a4978db357391a0bc4fdec8b0d106639"),
        ("C.1", "01000000000000000000000000000000", "030000000000000000000000",
         "01000000000000000000000000000000",
         "",
         "d9b360279694941ac5dbc6987ada7377", "4004a0dcd862f2a57360219d2d44ef6c",
         "743f7c8077ab25f8624e2e948579cf77303aaf90f6fe21199c6068577437a0c4"),
        ("C.1", "01000000000000000000000000000000", "030000000000000000000000",
         "0100000000000000000000000000000002000000000000000000000000000000",
         "",
         "d9b360279694941ac5dbc6987ada7377", "4004a0dcd862f2a57360219d2d44ef6c",
         "84e07e62ba83a6585417245d7ec413a9fe427d6315c09b57ce45f2e3936a94451a8e45dcd4578c667cd86847bf6155ff"),
        ("C.1", "01000000000000000000000000000000", "030000000000000000000000",
         "010000000000000000000000000000000200000000000000000000000000000003000000000000000000000000000000",
         "",
         "d9b360279694941ac5dbc6987ada7377", "4004a0dcd862f2a57360219d2d44ef6c",
         "3fd24ce1f5a67b75bf2351f181a475c7b800a5b4d3dcf70106b1eea82fa1d64df42bf7226122fa92e17a40eeaac1201b5e6e311dbf395d35b0fe39c2714388f8"),
        ("C.1", "01000000000000000000000000000000", "030000000000000000000000",
         "01000000000000000000000000000000020000000000000000000000000000000300000000000000000000000000000004000000000000000000000000000000",
         "",
         "d9b360279694941ac5dbc6987ada7377", "4004a0dcd862f2a57360219d2d44ef6c",
         "2433668f1058190f6d43e360f4f35cd8e475127cfca7028ea8ab5c20f7ab2af02516a2bdcbc08d521be37ff28c152bba36697f25b4cd169c6590d1dd39566d3f8a263dd317aa88d56bdf3936dba75bb8"),
        ("C.1", "01000000000000000000000000000000", "030000000000000000000000",
         "0200000000000000",
         "01",
         "d9b360279694941ac5dbc6987ada7377", "4004a0dcd862f2a57360219d2d44ef6c",
         "1e6daba35669f4273b0a1a2560969cdf790d99759abd1508"),
        ("C.1", "01000000000000000000000000000000", "030000000000000000000000",
         "020000000000000000000000",
         "01",
         "d9b360279694941ac5dbc6987ada7377", "4004a0dcd862f2a57360219d2d44ef6c",
         "296c7889fd99f41917f4462008299c5102745aaa3a0c469fad9e075a"),
        ("C.1", "01000000000000000000000000000000", "030000000000000000000000",
         "02000000000000000000000000000000",
         "01",
         "d9b360279694941ac5dbc6987ada7377", "4004a0dcd862f2a57360219d2d44ef6c",
         "e2b0c5da79a901c1745f700525cb335b8f8936ec039e4e4bb97ebd8c4457441f"),
        ("C.1", "01000000000000000000000000000000", "030000000000000000000000",
         "0200000000000000000000000000000003000000000000000000000000000000",
         "01",
         "d9b360279694941ac5dbc6987ada7377", "4004a0dcd862f2a57360219d2d44ef6c",
         "620048ef3c1e73e57e02bb8562c416a319e73e4caac8e96a1ecb2933145a1d71e6af6a7f87287da059a71684ed3498e1"),
        ("C.1", "01000000000000000000000000000000", "030000000000000000000000",
         "020000000000000000000000000000000300000000000000000000000000000004000000000000000000000000000000",
         "01",
         "d9b360279694941ac5dbc6987ada7377", "4004a0dcd862f2a57360219d2d44ef6c",
         "50c8303ea93925d64090d07bd109dfd9515a5a33431019c17d93465999a8b0053201d723120a8562b838cdff25bf9d1e6a8cc3865f76897c2e4b245cf31c51f2"),
        ("C.1", "01000000000000000000000000000000", "030000000000000000000000",
         "02000000000000000000000000000000030000000000000000000000000000000400000000000000000000000000000005000000000000000000000000000000",
         "01",
         "d9b360279694941ac5dbc6987ada7377", "4004a0dcd862f2a57360219d2d44ef6c",
         "2f5c64059db55ee0fb847ed513003746aca4e61c711b5de2e7a77ffd02da42feec601910d3467bb8b36ebbaebce5fba30d36c95f48a3e7980f0e7ac299332a80cdc46ae475563de037001ef84ae21744"),
        ("C.1", "01000000000000000000000000000000", "030000000000000000000000",
         "02000000",
         "010000000000000000000000",
         "d9b360279694941ac5dbc6987ada7377", "4004a0dcd862f2a57360219d2d44ef6c",
         "a8fe3e8707eb1f84fb28f8cb73de8e99e2f48a14"),
        ("C.1", "01000000000000000000000000000000", "030000000000000000000000",
         "0300000000000000000000000000000004000000",
         "010000000000000000000000000000000200",
         "d9b360279694941ac5dbc6987ada7377", "4004a0dcd862f2a57360219d2d44ef6c",
         "6bb0fecf5ded9b77f902c7d5da236a4391dd029724afc9805e976f451e6d87f6fe106514"),
        ("C.1", "01000000000000000000000000000000", "030000000000000000000000",
         "030000000000000000000000000000000400",
         "0100000000000000000000000000000002000000",
         "d9b360279694941ac5dbc6987ada7377", "4004a0dcd862f2a57360219d2d44ef6c",
         "44d0aaf6fb2f1f34add5e8064e83e12a2adabff9b2ef00fb47920cc72a0c0f13b9fd"),
        ("C.1", "e66021d5eb8e4f4066d4adb9c33560e4", "f46e44bb3da0015c94f70887",
         "",
         "",
         "036ee1fe2d7926af68898095e54e7b3c", "5e46482396008223b5c1d25173d87539",
         "a4194b79071b01a87d65f706e3949578"),
        ("C.1", "36864200e0eaf5284d884a0e77d31646", "bae8e37fc83441b16034566b",
         "7a806c",
         "46bb91c3c5",
         "3e28de1120b2981a0155795ca2812af6", "6d4b78b31a4c9c03d8db0f42f7507fae",
         "af60eb711bd85bc1e4d3e0a462e074eea428a8"),
        ("C.1", "aedb64a6c590bc84d1a5e269e4b47801", "afc0577e34699b9e671fdd4f",
         "bdc66f146545",
         "fc880c94a95198874296",
         "43b8de9cea62330d15cccfc84a33e8c8", "8e54631607e431e095b54852868e3a27",
         "bb93a3e34d3cd6a9c45545cfc11f03ad743dba20f966"),
        ("C.1", "d5cc1fd161320b6920ce07787f86743b", "275d1ab32f6d1f0434d8848c",
         "1177441f195495860f",
         "046787f3ea22c127aaf195d1894728",
         "8a51df64d93eaf667c2c09bd454ce5c5", "43ab276c2b4a473918ca73f2dd85109c",
         "4f37281f7ad12949d01d02fd0cd174c84fc5dae2f60f52fd2b"),
        ("C.1", "b3fed1473c528b8426a582995929a149", "9e9ad8780c8d63d0ab4149c0",
         "9f572c614b4745914474e7c7",
         "c9882e5386fd9f92ec489c8fde2be2cf97e74e93",
         "22f50707a95dd416df069d670cb775e8", "f674a5584ee21fe97b4cebc468ab61e4",
         "f54673c5ddf710c745641c8bc1dc2f871fb7561da1286e655e24b7b0"),
        ("C.1", "2d4ed87da44102952ef94b02b805249b", "ac80e6f61455bfac8308a2d4",
         "0d8c8451178082355c9e940fea2f58",
         "2950a70d5a1db2316fd568378da107b52b0da55210cc1c1b0a",
         "0b00a29a83e7e95b92e3a0783b29f140", "a430c27f285aed913005975c42eed5f3",
         "c9ff545e07b88a015f05b274540aa183b3449b9f39552de99dc214a1190b0b"),
        ("C.1", "bde3b2f204d1e9f8b06bc47f9745b3d1", "ae06556fb6aa7890bebc18fe",
         "6b3db4da3d57aa94842b9803a96e07fb6de7",
         "1860f762ebfbd08284e421702de0de18baa9c9596291b08466f37de21c7f",
         "21c874a8bad3603d1c3e8784df5b3f9f", "d1c16d72651c3df504eae27129d818e8",
         "6298b296e24e8cc35dce0bed484b7f30d5803e377094f04709f64d7b985310a4db84"),
        ("C.1", "f901cfe8a69615a93fdf7a98cad48179", "6245709fb18853f68d833640",
         "e42a3c02c25b64869e146d7b233987bddfc240871d",
         "7576f7028ec6eb5ea7e298342a94d4b202b370ef9768ec6561c4fe6b7e7296fa859c21",
         "3724f55f1d22ac0ab830da0b6a995d74", "75ac87b70c05db287de779006105a344",
         "391cc328d484a4f46406181bcd62efd9b3ee197d052d15506c84a9edd65e13e9d24a2a6e70"),
        ("C.2", "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000",
         "",
         "",
         "b5d3c529dfafac43136d2d11be284d7f", "b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222",
         "07f5f4169bbf55a8400cd47ea6fd400f"),
        ("C.2", "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000",
         "0100000000000000",
         "",
         "b5d3c529dfafac43136d2d11be284d7f", "b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222",
         "c2ef328e5c71c83b843122130f7364b761e0b97427e3df28"),
        ("C.2", "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000",
         "010000000000000000000000",
         "",
         "b5d3c529dfafac43136d2d11be284d7f", "b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222",
         "9aab2aeb3faa0a34aea8e2b18ca50da9ae6559e48fd10f6e5c9ca17e"),
        ("C.2", "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000",
         "01000000000000000000000000000000",
         "",
         "b5d3c529dfafac43136d2d11be284d7f", "b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222",
         "85a01b63025ba19b7fd3ddfc033b3e76c9eac6fa700942702e90862383c6c366"),
        ("C.2", "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000",
         "0100000000000000000000000000000002000000000000000000000000000000",
         "",
         "b5d3c529dfafac43136d2d11be284d7f", "b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222",
         "4a6a9db4c8c6549201b9edb53006cba821ec9cf850948a7c86c68ac7539d027fe819e63abcd020b006a976397632eb5d"),
        ("C.2", "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000",
         "010000000000000000000000000000000200000000000000000000000000000003000000000000000000000000000000",
         "",
         "b5d3c529dfafac43136d2d11be284d7f", "b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222",
         "c00d121893a9fa603f48ccc1ca3c57ce7499245ea0046db16c53c7c66fe717e39cf6c748837b61f6ee3adcee17534ed5790bc96880a99ba804bd12c0e6a22cc4"),
        ("C.2", "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000",
         "01000000000000000000000000000000020000000000000000000000000000000300000000000000000000000000000004000000000000000000000000000000",
         "",
         "b5d3c529dfafac43136d2d11be284d7f", "b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222",
         "c2d5160a1f8683834910acdafc41fbb1632d4a353e8b905ec9a5499ac34f96c7e1049eb080883891a4db8caaa1f99dd004d80487540735234e3744512c6f90ce112864c269fc0d9d88c61fa47e39aa08"),
        ("C.2", "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000",
         "0200000000000000",
         "01",
         "b5d3c529dfafac43136d2d11be284d7f", "b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222",
         "1de22967237a813291213f267e3b452f02d01ae33e4ec854"),
        ("C.2", "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000",
         "020000000000000000000000",
         "01",
         "b5d3c529dfafac43136d2d11be284d7f", "b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222",
         "163d6f9cc1b346cd453a2e4cc1a4a19ae800941ccdc57cc8413c277f"),
        ("C.2", "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000",
         "02000000000000000000000000000000",
         "01",
         "b5d3c529dfafac43136d2d11be284d7f", "b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222",
         "c91545823cc24f17dbb0e9e807d5ec17b292d28ff61189e8e49f3875ef91aff7"),
        ("C.2", "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000",
         "0200000000000000000000000000000003000000000000000000000000000000",
         "01",
         "b5d3c529dfafac43136d2d11be284d7f", "b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222",
         "07dad364bfc2b9da89116d7bef6daaaf6f255510aa654f920ac81b94e8bad365aea1bad12702e1965604374aab96dbbc"),
        ("C.2", "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000",
         "020000000000000000000000000000000300000000000000000000000000000004000000000000000000000000000000",
         "01",
         "b5d3c529dfafac43136d2d11be284d7f", "b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222",
         "c67a1f0f567a5198aa1fcc8e3f21314336f7f51ca8b1af61feac35a86416fa47fbca3b5f749cdf564527f2314f42fe2503332742b228c647173616cfd44c54eb"),
        ("C.2", "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000",
         "02000000000000000000000000000000030000000000000000000000000000000400000000000000000000000000000005000000000000000000000000000000",
         "01",
         "b5d3c529dfafac43136d2d11be284d7f", "b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222",
         "67fd45e126bfb9a79930c43aad2d36967d3f0e4d217c1e551f59727870beefc98cb933a8fce9de887b1e40799988db1fc3f91880ed405b2dd298318858467c895bde0285037c5de81e5b570a049b62a0"),
        ("C.2", "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000",
         "02000000",
         "010000000000000000000000",
         "b5d3c529dfafac43136d2d11be284d7f", "b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222",
         "22b3f4cd1835e517741dfddccfa07fa4661b74cf"),
        ("C.2", "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000",
         "0300000000000000000000000000000004000000",
         "010000000000000000000000000000000200",
         "b5d3c529dfafac43136d2d11be284d7f", "b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222",
         "43dd0163cdb48f9fe3212bf61b201976067f342bb879ad976d8242acc188ab59cabfe307"),
        ("C.2", "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000",
         "030000000000000000000000000000000400",
         "0100000000000000000000000000000002000000",
         "b5d3c529dfafac43136d2d11be284d7f", "b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222",
         "462401724b5ce6588d5a54aae5375513a075cfcdf5042112aa29685c912fc2056543"),
        ("C.2", "e66021d5eb8e4f4066d4adb9c33560e4f46e44bb3da0015c94f7088736864200", "e0eaf5284d884a0e77d31646",
         "",
         "",
         "e40d26f82774aa27f47b047b608b9585", "7c7c3d9a542cef53dde0e6de9b5800400f82e73ec5f7ee41b7ba8dcb9ba078c3",
         "169fbb2fbf389a995f6390af22228a62"),
        ("C.2", "bae8e37fc83441b16034566b7a806c46bb91c3c5aedb64a6c590bc84d1a5e269", "e4b47801afc0577e34699b9e",
         "671fdd",
         "4fbdc66f14",
         "b546f5a850d0a90adfe39e95c2510fc6", "b9d1e239d62cbb5c49273ddac8838bdcc53bca478a770f07087caa4e0a924a55",
         "0eaccb93da9bb81333aee0c785b240d319719d"),
        ("C.2", "6545fc880c94a95198874296d5cc1fd161320b6920ce07787f86743b275d1ab3", "2f6d1f0434d8848c1177441f",
         "195495860f04",
         "6787f3ea22c127aaf195",
         "e156e1f9b0b07b780cbe30f259e3c8da", "6fc1c494519f944aae52fcd8b14e5b171b5a9429d3b76e430d49940c0021d612",
         "a254dad4f3f96b62b84dc40c84636a5ec12020ec8c2c"),
        ("C.2", "d1894728b3fed1473c528b8426a582995929a1499e9ad8780c8d63d0ab4149c0", "9f572c614b4745914474e7c7",
         "c9882e5386fd9f92ec",
         "489c8fde2be2cf97e74e932d4ed87d",
         "0533fd71f4119257361a3ff1469dd4e5", "4feba89799be8ac3684fa2bb30ade0ea51390e6d87dcf3627d2ee44493853abe",
         "0df9e308678244c44bc0fd3dc6628dfe55ebb0b9fb2295c8c2"),
        ("C.2", "a44102952ef94b02b805249bac80e6f61455bfac8308a2d40d8c845117808235", "5c9e940fea2f582950a70d5a",
         "1db2316fd568378da107b52b",
         "0da55210cc1c1b0abde3b2f204d1e9f8b06bc47f",
         "64779ab10ee8a280272f14cc8851b727", "25f40fc63f49d3b9016a8eeeb75846e0d72ca36ddbd312b6f5ef38ad14bd2651",
         "8dbeb9f7255bf5769dd56692404099c2587f64979f21826706d497d5"),
        ("C.2", "9745b3d1ae06556fb6aa7890bebc18fe6b3db4da3d57aa94842b9803a96e07fb", "6de71860f762ebfbd08284e4",
         "21702de0de18baa9c9596291b08466",
         "f37de21c7ff901cfe8a69615a93fdf7a98cad481796245709f",
         "27c2959ed4daea3b1f52e849478de376", "307a38a5a6cf231c0a9af3b527f23a62e9a6ff09aff8ae669f760153e864fc93",
         "793576dfa5c0f88729a7ed3c2f1bffb3080d28f6ebb5d3648ce97bd5ba67fd"),
        ("C.2", "b18853f68d833640e42a3c02c25b64869e146d7b233987bddfc240871d7576f7", "028ec6eb5ea7e298342a94d4",
         "b202b370ef9768ec6561c4fe6b7e7296fa85",
         "9c2159058b1f0fe91433a5bdc20e214eab7fecef4454a10ef0657df21ac7",
         "670b98154076ddb59b7a9137d0dcc0f0", "78116d78507fbe69d4a820c350f55c7cb36c3c9287df0e9614b142b76a587c3f",
         "857e16a64915a787637687db4a9519635cdd454fc2a154fea91f8363a39fec7d0a49"),
        ("C.2", "3c535de192eaed3822a2fbbe2ca9dfc88255e14a661b8aa82cc54236093bbc23", "688089e55540db1872504e1c",
         "ced532ce4159b035277d4dfbb7db62968b13cd4eec",
         "734320ccc9d9bbbb19cb81b2af4ecbc3e72834321f7aa0f70b7282b4f33df23f167541",
         "cb8c3aa3f8dbaeb4b28a3e86ff6625f8", "02426ce1aa3ab31313b0848469a1b5fc6c9af9602600b195b04ad407026bc06d",
         "626660c26ea6612fb17ad91e8e767639edd6c9faee9d6c7029675b89eaf4ba1ded1a286594"),
        ("C.3", "0000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000",
         "000000000000000000000000000000004db923dc793ee6497c76dcc03a98e108",
         "",
         "dc95c078a24089895275f3d86b4fb868", "779b38d15bffb63d39d6e9ae76a9b2f375d11b0e3a68c422845c7d4690fa594f",
         "f3f80f2cf0cb2dd9c5984fcda908456cc537703b5ba70324a6793a7bf218d3eaffffffff000000000000000000000000"),
        ("C.3", "0000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000",
         "eb3640277c7ffd1303c7a542d02d3e4c0000000000000000",
         "",
         "dc95c078a24089895275f3d86b4fb868", "779b38d15bffb63d39d6e9ae76a9b2f375d11b0e3a68c422845c7d4690fa594f",
         "18ce4f0b8cb4d0cac65fea8f79257b20888e53e72299e56dffffffff000000000000000000000000"),
    ];
    // END values lifted from RFC 8452.

    fn hex(s: &str) -> Vec<u8> {
        bouncycastle_core::hex::decode(s).expect("the lifted values are hex")
    }

    fn nonce_of(s: &str) -> [u8; GCM_SIV_NONCE_LEN] {
        hex(s).try_into().expect("a 12-byte nonce")
    }

    /// The permutation keyed with `key`, as a key object would hold it. The key is typed inside a
    /// hazardous-operations window because C.3's is all zeros, which `KeyMaterial` otherwise tags
    /// `Zeroized`.
    fn keyed<P: KeyExpansion<KEY_LEN>, const KEY_LEN: usize>(key: &[u8]) -> P {
        let mut material = KeyMaterial::<KEY_LEN>::new();
        do_hazardous_operations(&mut material, |m| {
            m.set_bytes_as_type(key, KeyType::SymmetricCipherKey)
        })
        .unwrap();
        P::new(&material).expect("a valid key")
    }

    /// One Appendix C vector through `derive_keys`, `encrypt` and `decrypt` over `P`.
    fn check_vector<P, const KEY_LEN: usize>(
        (section, key, nonce, plaintext, aad, auth_key, enc_key, result): &(
            &str,
            &str,
            &str,
            &str,
            &str,
            &str,
            &str,
            &str,
        ),
    ) where
        P: ElectronicCodeBook<KEY_LEN, 16>,
    {
        let what = alloc::format!("{section}, plaintext {plaintext}, AAD {aad}");
        let key_generating_key: P = keyed(&hex(key));
        let nonce = nonce_of(nonce);
        let (plaintext, aad, result) = (hex(plaintext), hex(aad), hex(result));
        let (ciphertext, tag) = result.split_at(plaintext.len());

        // "Record authentication key" and "Record encryption key".
        let mut message_authentication_key: Secret<[u8; 16]> = Secret::new();
        let mut message_encryption_key = KeyMaterial::<KEY_LEN>::new();
        derive_keys(
            &key_generating_key,
            &nonce,
            &mut message_authentication_key,
            &mut message_encryption_key,
        )
        .unwrap();
        assert_eq!(message_authentication_key[..], hex(auth_key)[..], "{what}");
        assert_eq!(message_encryption_key.ref_to_bytes(), &hex(enc_key)[..], "{what}");
        assert_eq!(message_encryption_key.key_type(), KeyType::SymmetricCipherKey, "{what}");
        assert_eq!(message_encryption_key.security_strength(), P::MAX_SECURITY_STRENGTH);

        // "Result": the encrypted plaintext, then the tag.
        let mut buf = plaintext.clone();
        let got_tag = encrypt(&key_generating_key, &nonce, &aad, &mut buf).unwrap();
        assert_eq!(buf, ciphertext, "{what}");
        assert_eq!(got_tag[..], *tag, "{what}");

        decrypt(&key_generating_key, &nonce, &aad, &mut buf, &got_tag).unwrap();
        assert_eq!(buf, plaintext, "{what}");
    }

    /// Every Appendix C vector: C.1 over AES-128, C.2 and C.3 over AES-256.
    #[test]
    fn appendix_c_derived_keys_results_and_round_trips() {
        let mut counts = [0usize; 3];
        for vector in APPENDIX_C {
            match vector.0 {
                "C.1" => {
                    check_vector::<AES128Internal, 16>(vector);
                    counts[0] += 1;
                }
                "C.2" => {
                    check_vector::<AES256Internal, 32>(vector);
                    counts[1] += 1;
                }
                "C.3" => {
                    check_vector::<AES256Internal, 32>(vector);
                    counts[2] += 1;
                }
                other => panic!("unexpected section {other}"),
            }
        }
        assert_eq!(counts, [24, 24, 2]);
    }

    /// `AES_CTR` as the RFC's pseudocode writes it, one block at a time, with the counter held in
    /// the block.
    fn aes_ctr_reference<P: BlockPermutation<16>>(key: &P, tag: &[u8; 16], data: &mut [u8]) {
        let mut block = *tag;
        block[15] |= 0x80;
        for chunk in data.chunks_mut(16) {
            let mut keystream_block = block;
            key.encrypt_block(&mut keystream_block);
            let counter = u32::from_le_bytes(block[..4].try_into().unwrap()).wrapping_add(1);
            block[..4].copy_from_slice(&counter.to_le_bytes());
            for (byte, k) in chunk.iter_mut().zip(keystream_block) {
                *byte ^= k;
            }
        }
    }

    /// The counter wraps from `2^32 - 1` to `0` without carrying into the fifth byte, wherever in
    /// a keystream four or pair the wrap falls, and bytes 4 to 15 of the counter block are the
    /// tag's with the top bit of the last one set.
    #[test]
    fn the_counter_is_32_bits_little_endian_and_wraps() {
        let key: AES256Internal = keyed(&[0x5Au8; 32]);
        // Eleven blocks from each: the wrap falls inside the first four (the first three), on
        // the boundary between the fours, on the handover to the pair, inside the pair, and
        // between the pair and the last block.
        for first in [
            0xFFFF_FFFFu32, 0xFFFF_FFFE, 0xFFFF_FFFD, 0xFFFF_FFFC, 0xFFFF_FFF8, 0xFFFF_FFF7,
            0xFFFF_FFF6, 0x0000_00FF, 0x00FF_FFFF,
        ] {
            let mut tag = [0x11u8; 16];
            tag[..4].copy_from_slice(&first.to_le_bytes());

            // Eleven blocks of zeros, so that the output is the keystream itself: two fours, a
            // pair and a single block.
            let mut keystream = [0u8; 176];
            aes_ctr(&key, &tag, &mut keystream);
            for (i, got) in keystream.chunks(16).enumerate() {
                let mut block = [0x11u8; 16];
                block[..4].copy_from_slice(&first.wrapping_add(i as u32).to_le_bytes());
                block[15] = 0x91;
                key.encrypt_block(&mut block);
                assert_eq!(got, block, "first counter {first:#x}, block {i}");
            }
        }
    }

    /// The keystream loops agree with the pseudocode's at every length across a few fours and
    /// the pairs after them, the ends that fall inside each block of a pair included.
    #[test]
    fn aes_ctr_matches_the_pseudocode_at_every_length() {
        let key: AES128Internal = keyed(&[0xC3u8; 16]);
        let mut tag = [0xA5u8; 16];
        tag[..4].copy_from_slice(&0xFFFF_FFFEu32.to_le_bytes());
        for len in 0..=200usize {
            let data: Vec<u8> =
                (0..len).map(|i| (i as u8).wrapping_mul(29).wrapping_add(3)).collect();
            let mut got = data.clone();
            aes_ctr(&key, &tag, &mut got);
            let mut want = data.clone();
            aes_ctr_reference(&key, &tag, &mut want);
            assert_eq!(got, want, "length {len}");
            if len > 0 {
                assert_ne!(got, data, "length {len}");
            }
        }
    }

    /// Section 6's `P_MAX` and `A_MAX`: 2^36 bytes is accepted and one more is refused, for each
    /// input separately. A 32-bit target cannot express the limit, so nothing there is refused.
    #[test]
    fn the_length_limits_are_two_to_the_36_bytes() {
        assert!(check_lengths(0, 0).is_ok());
        assert!(check_lengths(u32::MAX as usize, 0).is_ok());
        assert!(check_lengths(0, u32::MAX as usize).is_ok());

        #[cfg(target_pointer_width = "64")]
        {
            let max = 1usize << 36;
            assert!(check_lengths(max, max).is_ok());
            assert!(check_lengths(max - 1, max - 1).is_ok());
            for over in [max + 1, usize::MAX] {
                assert!(matches!(
                    check_lengths(over, 0),
                    Err(SymmetricCipherError::InvalidInputLength(m)) if m.contains("additional data")
                ));
                assert!(matches!(
                    check_lengths(0, over),
                    Err(SymmetricCipherError::InvalidInputLength(m)) if m.contains("plaintext")
                ));
                assert!(check_lengths(over, over).is_err());
            }
        }
    }

    /// A tag that does not verify leaves zeros in the buffer, not the plaintext the counter mode
    /// recovered and not the ciphertext, whichever input was wrong.
    #[test]
    fn a_failed_decrypt_leaves_the_buffer_zeroized() {
        let key: AES128Internal = keyed(&[0x07u8; 16]);
        let nonce = [0x24u8; GCM_SIV_NONCE_LEN];
        let aad = b"header";
        for len in [1usize, 15, 16, 17, 33, 100] {
            let plaintext = vec![0x41u8; len];
            let mut ciphertext = plaintext.clone();
            let tag = encrypt(&key, &nonce, aad, &mut ciphertext).unwrap();

            let mut bad_tag = tag;
            bad_tag[7] ^= 0x01;
            let mut buf = ciphertext.clone();
            assert_eq!(
                decrypt(&key, &nonce, aad, &mut buf, &bad_tag),
                Err(SymmetricCipherError::AEADTagCheckFailed)
            );
            assert_eq!(buf, vec![0u8; len], "length {len}, tag");

            let mut buf = ciphertext.clone();
            assert_eq!(
                decrypt(&key, &nonce, b"headex", &mut buf, &tag),
                Err(SymmetricCipherError::AEADTagCheckFailed)
            );
            assert_eq!(buf, vec![0u8; len], "length {len}, AAD");

            let mut buf = ciphertext.clone();
            decrypt(&key, &nonce, aad, &mut buf, &tag).unwrap();
            assert_eq!(buf, plaintext, "length {len}");
        }
    }

    /// A permutation whose every output block is zero, so that the keys derived under it are
    /// all-zero bytes. Not a permutation at all; it stands in for the key-generating key and
    /// nonce, one in 2^128 or 2^256, under which AES would derive such a key.
    #[derive(Clone)]
    struct ZeroOutput;

    impl Algorithm for ZeroOutput {
        const ALG_NAME: &'static str = "ZeroOutput";
        const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
    }

    impl KeyExpansion<32> for ZeroOutput {
        fn new(_: &KeyMaterial<32>) -> Result<Self, SymmetricCipherError> {
            Ok(Self)
        }
    }

    impl BlockPermutation<16> for ZeroOutput {
        fn encrypt_block(&self, block: &mut [u8; 16]) {
            block.fill(0);
        }
        fn decrypt_block(&self, block: &mut [u8; 16]) {
            block.fill(0);
        }
        fn encrypt_2blocks(&self, blocks: &mut [[u8; 16]; 2]) {
            blocks.as_flattened_mut().fill(0);
        }
        fn decrypt_2blocks(&self, blocks: &mut [[u8; 16]; 2]) {
            blocks.as_flattened_mut().fill(0);
        }
        fn encrypt_4blocks(&self, blocks: &mut [[u8; 16]; 4]) {
            blocks.as_flattened_mut().fill(0);
        }
        fn decrypt_4blocks(&self, blocks: &mut [[u8; 16]; 4]) {
            blocks.as_flattened_mut().fill(0);
        }
    }

    /// An all-zero derived key is a `SymmetricCipherKey` at full strength like any other, not the
    /// `Zeroized` key `KeyMaterial` makes of zero bytes outside a hazardous-operations window,
    /// and AES's key expansion accepts it: no message fails for what its derived key happens to
    /// be.
    #[test]
    fn an_all_zero_derived_key_is_still_a_cipher_key() {
        let mut message_authentication_key: Secret<[u8; 16]> = Secret::new();
        *message_authentication_key = [0xEE; 16];
        let mut message_encryption_key = KeyMaterial::<32>::new();
        derive_keys(
            &ZeroOutput,
            &[0x24u8; GCM_SIV_NONCE_LEN],
            &mut message_authentication_key,
            &mut message_encryption_key,
        )
        .unwrap();
        assert_eq!(*message_authentication_key, [0u8; 16]);
        assert_eq!(message_encryption_key.ref_to_bytes(), &[0u8; 32][..]);
        assert_eq!(message_encryption_key.key_type(), KeyType::SymmetricCipherKey);
        assert_eq!(message_encryption_key.security_strength(), SecurityStrength::_256bit);
        assert!(AES256Internal::new(&message_encryption_key).is_ok());
    }
}
