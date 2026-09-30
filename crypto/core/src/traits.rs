//! Provides simplified abstracted APIs over classes of cryptographic primitives, such as Hash, KDF, etc.

// Objects in this file should be sorted alphabetically, regardless of whether they are a trait, struct, or enum.

use crate::errors::*;
use crate::key_material::KeyMaterialTrait;
use crate::security_strength::SecurityStrength;
use bouncycastle_utils::secret::Secret;
use core::fmt::{Debug, Display};
use core::marker::Sized;

// Imports needed for docs
#[allow(unused_imports)]
use crate::key_material::KeyMaterial;
#[allow(unused_imports)]
use crate::key_material::KeyType;
// end of imports needed for docs

/// What an AEAD key's allocating one-shot with a detached tag hands back:
/// `(nonce, ciphertext, tag)`
#[cfg(feature = "std")]
pub type AEADEncryptedTuple<const NONCE_LEN: usize, const TAG_LEN: usize> =
    ([u8; NONCE_LEN], Vec<u8>, [u8; TAG_LEN]);

/// The decryption half of an AEAD cipher's streaming API; see [`AEADCipherEncryptor`], whose notes
/// on the AAD phase, the two tag layouts, buffering, and the `Result` all apply here too.
///
/// This extends [`SymmetricCipherDecryptor`], whose methods are the AEAD with no associated data
/// and the tag inline -- the last `TAG_LEN` bytes of the ciphertext. A decryptor may therefore
/// hold back up to the last `TAG_LEN` bytes it has seen, since until the stream ends they may be
/// the tag; [`SymmetricCipherDecryptor::do_decrypt_out_len`] says exactly how many bytes each
/// call releases. With the tag detached those held-back bytes turn out to be ciphertext, and
/// [`do_decrypt_final_detached_out`](Self::do_decrypt_final_detached_out) decrypts them; with
/// it inline, [`SymmetricCipherDecryptor::do_decrypt_final`] checks them as the tag. So `FINAL_LEN`
/// is at least `TAG_LEN`, plus whatever else the cipher holds back of its own accord.
///
/// # The plaintext is not authenticated until the final call returns `Ok`
///
/// This is the one thing a streaming AEAD API cannot hide from its caller.
/// [`SymmetricCipherDecryptor::do_decrypt_out`] releases plaintext as soon as it can, long before
/// there is a tag to check it against, so a caller that *uses* those bytes before
/// [`do_decrypt_final_detached_out`](Self::do_decrypt_final_detached_out) or
/// [`SymmetricCipherDecryptor::do_decrypt_final`] has returned `Ok` is acting on unauthenticated
/// plaintext -- bytes an attacker may have chosen. Preventing exactly that is what the tag is for.
/// A streaming caller must therefore treat everything `do_update_out` produces as untrusted until
/// the final call succeeds, and scrub it if it does not.
///
/// The key's one-shots have no such caveat: each owns the whole message, so it zeroizes the
/// buffer itself before returning the error.
pub trait AEADCipherDecryptor<const NONCE_LEN: usize, const TAG_LEN: usize, const FINAL_LEN: usize>:
    SymmetricCipherDecryptor<NONCE_LEN, FINAL_LEN>
{
    /// Absorbs additional authenticated data; see [`AEADCipherEncryptor::do_update_aad`] for the
    /// rules, which are the same on both sides. The concatenation of what a decryptor absorbs must
    /// be byte-for-byte the concatenation the encryptor absorbed, or the tag check fails.
    ///
    /// # Errors
    /// [`SymmetricCipherError::StateError`] if called with a non-empty `aad` after
    /// [`SymmetricCipherDecryptor::do_decrypt_out`].
    fn do_update_aad(&mut self, aad: &[u8]) -> Result<(), SymmetricCipherError>;

    /// Finishes the decryption with the tag detached, consuming the decryptor: decrypts whatever
    /// ciphertext was held back into `plaintext` -- including the last `TAG_LEN` bytes, which with
    /// the tag carried separately are ciphertext like the rest -- computes the tag over the AAD and
    /// ciphertext it has seen, and compares it against `tag`. Returns the number of plaintext bytes
    /// written. The entire output buffer is zeroized before the plaintext is written, so any bytes
    /// past that count will be 0. `Ok` is the only thing that makes those bytes -- or anything
    /// already released by [`SymmetricCipherDecryptor::do_decrypt_out`] -- trustworthy.
    ///
    /// # Errors
    /// [`SymmetricCipherError::AEADTagCheckFailed`] if the tag does not verify. Implementors must
    /// compare in constant time, and the caller learns only that the check failed.
    fn do_decrypt_final_detached_out(
        self,
        tag: &[u8; TAG_LEN],
        plaintext: &mut [u8; FINAL_LEN],
    ) -> Result<usize, SymmetricCipherError>;

    /// As [`do_decrypt_final_detached_out`](Self::do_decrypt_final_detached_out), returning
    /// the final buffer together with the number of leading bytes of it that are plaintext, the
    /// shape of [`SymmetricCipherDecryptor::do_decrypt_final`]. The two are provided the other way
    /// round from the base trait's pair -- the `_out` form is the one an implementor writes --
    /// because that is the form that lets an implementor decrypt the held-back bytes straight into
    /// the caller's buffer. On failure no buffer is returned, so nothing unauthenticated is left
    /// behind by this call.
    ///
    /// # Errors
    /// As [`do_decrypt_final_detached_out`](Self::do_decrypt_final_detached_out).
    fn do_decrypt_final_detached(
        self,
        tag: &[u8; TAG_LEN],
    ) -> Result<([u8; FINAL_LEN], usize), SymmetricCipherError> {
        let mut plaintext = [0u8; FINAL_LEN];
        let data_len = self.do_decrypt_final_detached_out(tag, &mut plaintext)?;
        Ok((plaintext, data_len))
    }

    /// An upper bound on the plaintext recovered from `ciphertext_len` bytes of ciphertext with
    /// the tag detached, i.e. the buffer the key's `decrypt_detached_out`
    /// requires. The default returns `ciphertext_len` itself, which is exact for every conformant
    /// AEAD: unlike a padding scheme, an AEAD never expands or shrinks the data it is given, only
    /// adds the separate `tag`.
    fn decrypt_detached_out_len(ciphertext_len: usize) -> usize {
        ciphertext_len
    }
}

/// The encryption half of an AEAD cipher's streaming API. This extends
/// [`SymmetricCipherEncryptor`] -- the same separate-output, init-data-generating,
/// possibly-buffering shape -- with the two things authentication adds.
///
/// # Two tag layouts
///
/// * **SymmetricCipher: `ciphertext || tag`**: The inherited [`SymmetricCipherEncryptor`] methods
///     allow a caller to use an AEAD cipher, with the added security of the authentication, without
///     concerning themselves with the details of the AEAD interface.
///     Specifically, there is no way to provide associated data, and
///     [`SymmetricCipherEncryptor::do_encrypt_final`] appends the tag to the ciphertext, so the
///     output is `ciphertext || tag`.
///
/// * **AEADCipher: `(ciphertext, tag)`**: The methods ending in `_detached` hand the tag back separately,
///     for callers whose protocol carries it in a separate field.
///
/// # Associated data
///
/// An AEAD can additionally authenticate data it does not encrypt -- called additional authenticated data (AAD),
/// or sometimes associated data -- typically a header that has to travel in the clear but must still
/// be protected against tampering. Every AEAD construction absorbs that AAD *before* the plaintext.
/// This leads to a stateful API flow:
///
/// * The key's `create_encryptor` constructs the instance under a nonce.
/// * [`do_update_aad`](Self::do_update_aad) may be called any number of times, including zero if
///   there is no AAD.
/// * The first [`do_encrypt_out`](SymmetricCipherEncryptor::do_encrypt_out) switches to encrypting,
///   after which additional calls to `do_update_aad` will fail with a
///   [`SymmetricCipherError::StateError`].
///
/// (An empty `aad` slice is a no-op and is accepted at any point.)
///
/// # The nonce is drawn by default
///
/// The key's `create_encryptor` and the one-shots provided over it draw the nonce from the RNG
/// they are given and return it for transmission alongside the ciphertext, so a caller cannot
/// repeat one by mistake. A protocol that manages its own nonces -- a counter, or the
/// construction its specification prescribes -- uses the key's `create_encryptor_nonce` and the
/// `_nonce` one-shots instead, and then carries the obligation itself: **a nonce must never
/// repeat under one key.** For every
/// AEAD here a repeat exposes the XOR of the two plaintexts, and for GCM the authentication key
/// as well.
///
/// # A cipher may buffer
///
/// Some AEADs release each ciphertext byte as soon as they see the plaintext byte; others hold
/// part of the input back, until a block is complete or until they can tell whether trailing
/// bytes are the tag. So a call to [`do_encrypt_out`](SymmetricCipherEncryptor::do_encrypt_out)
/// may produce less output than input, or none, which can be told in one of two ways:
///
/// * The `Ok(usize)` that `do_encrypt_out` returns is `0`.
/// * Prior to the call, call [`do_encrypt_out_len`](SymmetricCipherEncryptor::do_encrypt_out_len)
///   to see how much output will be produced for the given amount of input. Doing it this way has
///   the advantage of being able to correctly size the output buffer for a subsequent
///   [`do_encrypt_out`](SymmetricCipherEncryptor::do_encrypt_out) call.
pub trait AEADCipherEncryptor<const NONCE_LEN: usize, const TAG_LEN: usize, const FINAL_LEN: usize>:
    SymmetricCipherEncryptor<NONCE_LEN, FINAL_LEN>
{
    /// Absorbs `aad`: data that is authenticated by the tag but not encrypted. May be called
    /// repeatedly before the first [`SymmetricCipherEncryptor::do_encrypt_out`]; a sequence of calls
    /// is equivalent to one call over the concatenation. An empty `aad` is a no-op.
    ///
    /// # Errors
    /// [`SymmetricCipherError::StateError`] if called with a non-empty `aad` after
    /// [`SymmetricCipherEncryptor::do_encrypt_out`] -- see the trait docs for why the AAD comes
    /// first. An implementor whose AAD buffer has a fixed capacity may also return
    /// [`SymmetricCipherError::GenericError`] if `aad` would exceed it; that is a property of the
    /// implementor, not of this trait, so it is not listed as a general contract here.
    fn do_update_aad(&mut self, aad: &[u8]) -> Result<(), SymmetricCipherError>;

    /// Finishes the encryption with the tag detached, consuming the encryptor: flushes whatever
    /// plaintext was held back, encrypted, into `ciphertext`, and returns how many leading bytes of
    /// it are ciphertext together with the tag over the AAD and plaintext it has seen. The tag must
    /// be transmitted with the ciphertext; the recipient passes it to
    /// [`AEADCipherDecryptor::do_decrypt_final_detached_out`].
    ///
    /// `ciphertext` is `FINAL_LEN` long so that both final methods share one buffer size; the
    /// flush written here is at most `FINAL_LEN - TAG_LEN` of it, the tag not being part of it.
    /// The entire output buffer is zeroized before the ciphertext is written, so any bytes past
    /// the returned count will be 0.
    fn do_encrypt_final_detached_out(
        self,
        ciphertext: &mut [u8; FINAL_LEN],
    ) -> Result<(usize, [u8; TAG_LEN]), SymmetricCipherError>;

    /// As [`do_encrypt_final_detached_out`](Self::do_encrypt_final_detached_out), returning
    /// the final buffer, the number of leading bytes of it that are ciphertext, and the tag -- the
    /// shape of [`SymmetricCipherEncryptor::do_encrypt_final`] with the tag alongside. Provided
    /// over the `_out` form, the other way round from the base trait's pair; see
    /// [`AEADCipherDecryptor::do_decrypt_final_detached`].
    fn do_encrypt_final_detached(
        self,
    ) -> Result<([u8; FINAL_LEN], usize, [u8; TAG_LEN]), SymmetricCipherError> {
        let mut ciphertext = [0u8; FINAL_LEN];
        let (out_len, tag) = self.do_encrypt_final_detached_out(&mut ciphertext)?;
        Ok((ciphertext, out_len, tag))
    }

    /// The exact ciphertext length for a `plaintext_len`-byte plaintext with the tag detached, i.e.
    /// the buffer the key's `encrypt_detached_out` requires and the number of
    /// bytes it writes (the tag is returned separately, not counted here). The default returns
    /// `plaintext_len` itself, which holds for every conformant AEAD: unlike a padding scheme, an
    /// AEAD never expands or shrinks the data it is given.
    fn encrypt_detached_out_len(plaintext_len: usize) -> usize {
        plaintext_len
    }
}

/// Metadata about a cryptographic algorithm.
pub trait Algorithm {
    /// String name for the algorithm, used consistently across the library.
    const ALG_NAME: &'static str;
    /// Maximum security strength supported by the algorithm.
    /// In other words, this algorithm can produce outputs up to this security strength,
    /// but may produce outputs with lower security strength, for example, if asked to truncate.
    const MAX_SECURITY_STRENGTH: SecurityStrength;
}

/// Some algorithms have an assigned OID.
pub trait AlgorithmOID {
    /// The OID in component form -- each u32 is one OID component.
    const OID: &'static [u32];
    /// The OID in its DER-encoded form.
    const OID_DER: &'static [u8];
}

/// The decryption half of a block cipher's streaming API; see [`BlockCipherEncryptor`], whose
/// notes on in-place operation, lengths and the `Result` all apply here too.
pub trait BlockCipherDecryptor<const INIT_DATA_LEN: usize, const BLOCK_LEN: usize>:
    Algorithm + Sized
{
    /// The implementor hook: decrypts consecutive whole blocks in place. See
    /// [`BlockCipherEncryptor::do_encrypt_blocks_inplace`]. Returns the number of bytes written, which is
    /// always `blocks.len() * BLOCK_LEN` since a block cipher mode never changes the length of its
    /// data, but the count is still returned for consistency with the rest of the library's
    /// output-buffer APIs.
    fn do_decrypt_blocks_inplace(
        &mut self,
        blocks: &mut [[u8; BLOCK_LEN]],
    ) -> Result<usize, SymmetricCipherError>;
}

/// The encryption half of a block cipher's API.
///
/// Strictly block-aligned: whole blocks in, whole
/// blocks out, no finalization step. Padding of non-block-aligned data is handled by a separate layer
/// (`PaddedBlockCipherEncryptor` / `PaddedBlockCipherDecryptor`) built on top of this trait.
///
/// Encryption and decryption are separate traits so that a policy can permit decryption of existing
/// data while forbidding new encryptions.
///
/// This trait allows for a block cipher to generate initialization data, such as an Initialization
/// Vector (IV) or Counter (CTR) which is not technically part of the ciphertext, but must be
/// transmitted along with the ciphertext in order for the recipient to perform successful decryption.
/// The length of the initialization data is specified by the implementing struct via the
/// `INIT_DATA_LEN` constant.
///
/// In order for these APIs to be usable securely in all contexts, the init data will be generated
/// securely by the block cipher implementation and returned along with the ciphertext, and there is no API for the
/// user to provide the init data to the encryptor.
/// If you require this functionality, see the documentation for the underlying implementation.
///
/// # Everything is in place
///
/// Every data method here transforms its buffer in place: the plaintext goes in, the ciphertext
/// comes out in the same bytes. A block cipher mode never changes the length of its data, so a
/// separate output buffer would only ever be a copy, and a copy of plaintext is one more thing to
/// scrub. Callers that need to keep the plaintext copy it first.
///
/// # Block alignment
///
/// The streaming methods take whole blocks, `&mut [[u8; BLOCK_LEN]]`, so a partial block cannot be
/// expressed. The one-shots take a `&mut [u8]` and refuse one that is not a whole number of blocks
/// with [`SymmetricCipherError::DataNotBlockAligned`], before doing any work. Data of any length
/// goes through the padding layer.
///
/// # Why the data methods still return `Result`
///
/// Nothing about a whole-blocks buffer can go wrong, and a constructed value is always ready to
/// use, so a mode like CBC never returns `Err` from the streaming methods. The `Result` is for modes with a per-initialization
/// data limit -- a counter-based mode must refuse to encrypt past the point where its counter would
/// repeat -- which a streaming API cannot check any earlier than the call that would cross it.
pub trait BlockCipherEncryptor<const INIT_DATA_LEN: usize, const BLOCK_LEN: usize>:
    Algorithm + Sized
{
    /// The implementor hook: encrypts consecutive whole blocks in place. A sequence of calls is
    /// equivalent to one call over the concatenation.
    ///
    /// This is the only method an implementor writes besides the two `_init` constructors; the
    /// block shape is what guarantees it never sees a partial block. It takes a slice rather than
    /// a `[[u8; BLOCK_LEN]; N]` array because every whole number of blocks is valid, so there is
    /// no length invariant for a const parameter to carry, and because how to batch the blocks --
    /// singly, in pairs, in fours -- is the mode's decision, not the caller's: a mode whose
    /// permutation processes several blocks at once (CBC decryption, CTR) chunks the slice itself.
    /// Returns the number of bytes written, which is always `blocks.len() * BLOCK_LEN` since a
    /// block cipher mode never changes the length of its data, but the count is still returned for
    /// consistency with the rest of the library's output-buffer APIs.
    fn do_encrypt_blocks_inplace(
        &mut self,
        blocks: &mut [[u8; BLOCK_LEN]],
    ) -> Result<usize, SymmetricCipherError>;
}

/// A hash function is a cryptographic primitive that takes an input of any length and produces a fixed-size output.
/// Formally: `H: {0,1}^* -> {0,1}^n`.
/// A cryptographic hash function will typically satisfy several security properties, including:
/// * Collision resistance: finding two inputs that yield the same output is computationally difficult.
/// * Preimage resistance: from a given output, finding an input that generates it is computationally difficult.
/// * Second preimage resistance: given an input, finding another input that yields the same output is computationally difficult.
///
/// # Construction is not part of this trait
///
/// There is deliberately no `Default` supertrait. Feeding bytes in and finalising is one concern;
/// making an instance is another, and not every implementor has a canonical zero-argument one --
/// a keyed construction such as KMAC (SP 800-185 Sec 4) has no meaningful default, and requiring
/// one would exclude it from this trait and from [`XOF`] with it.
///
/// Generic code that needs to *build* a hasher asks for it: `fn digest<H: Hash + Default>(..)`.
/// That is what `HMAC` and the shared test framework already do, so the bound sits where the
/// requirement actually is rather than on every implementor.
///
/// # Forking is part of this trait
///
/// `Clone` *is* a supertrait: a hash mid-stream can be copied, and the copy continues independently
/// from the same absorbed prefix. That is how a running hash of a common prefix is finished several
/// ways -- a transcript hash checkpointed at each handshake message, HMAC's inner and outer states
/// held ready across many MACs under one key, or a Merkle node whose prefix is shared by its
/// siblings -- without re-absorbing the prefix each time. Every implementor is a fixed-size state
/// plus a small buffer, so the derive is the right implementation; the shared test framework checks
/// that a clone and its original finish to the same digest, and diverge once fed different input.
pub trait Hash: Algorithm + Clone {
    /// The size of the internal block in bits -- needed by functions such as HMAC to compute security parameters.
    fn block_bitlen(&self) -> usize;

    /// The size of the output in bytes.
    ///
    /// # This is not always part of the function's identity
    ///
    /// For most hashes the length is bound into the computation, so asking for a different length
    /// gives a different function rather than more or fewer bytes of the same one. TupleHash and
    /// KMAC are built that way deliberately -- SP 800-185 absorbs `right_encode(L)` before
    /// squeezing.
    ///
    /// A [`XOF`] is the exception. Its length is chosen at the point of output and is *not* an
    /// input to the computation, so this returns a nominal length only -- 32 bytes for SHAKE128 --
    /// and two outputs of different lengths share their leading bytes. Generic code over `Hash`
    /// must therefore not infer "different `output_len` implies unrelated output"; see the
    /// discussion on [`XOF`].
    fn output_len(&self) -> usize;

    /// A static one-shot API that hashes the provided data.
    /// `data` can be of any length, including zero bytes.
    fn hash(self, data: &[u8]) -> Vec<u8>;

    /// A static one-shot API that hashes the provided data into the provided output slice.
    /// `data` can be of any length, including zero bytes.
    /// The entire output buffer is zeroized before the hash output is written.
    /// The return value is the number of bytes written.
    fn hash_out(self, data: &[u8], output: &mut [u8]) -> usize;

    /// Provide a chunk of data to be absorbed into the hashes.
    /// `data` can be of any length, including zero bytes.
    /// do_update() is intended to be used as part of a streaming interface, and so may by called multiple times.
    fn do_update(&mut self, data: &[u8]);

    /// Finish absorbing input and produce the hashes output.
    /// Consumes self, so this must be the final call to this object.
    fn do_final(self) -> Vec<u8>;

    /// Finish absorbing input and produce the hashes output.
    /// Consumes self, so this must be the final call to this object.
    ///
    /// If the provided buffer is smaller than the hash's output length, the output will be truncated.
    /// If the provided buffer is larger than the hash's output length, the output  will be placed in
    /// the first [`Hash::output_len`] bytes.
    /// The entire output buffer is zeroized before the hash output is written, so any bytes past
    /// [`Hash::output_len`] will be 0.
    ///
    /// The output byte is zeroized before the result is written.
    /// The return value is the number of bytes written.
    fn do_final_out(self, output: &mut [u8]) -> usize;

    /// The same as [`Hash::do_final`], but allows for supplying a partial byte as the last input.
    ///
    /// The partial byte is taken as it arrives in the final octet of an ASN.1 BIT STRING
    /// (X.690 s. 8.6.2.1: the bits are placed "commencing with the leading bit ... in bits 8 to 1"):
    /// the `num_bits` message bits are the most significant bits of `partial_byte`, leading bit first,
    /// and the low `8 - num_bits` bits (the BIT STRING's "unused bits", X.690 s. 8.6.2.2) are ignored.
    /// So for a BIT STRING whose initial octet is `unused` (1..=7), pass its final content octet with
    /// `num_bits = 8 - unused`. The convention is the same for every hash family in this library;
    /// implementations whose native bit order differs (SHA-3, which absorbs a byte LSB-first per
    /// FIPS 202 Appendix B.1) convert internally.
    ///
    /// Note on test vectors: the NIST CAVP SHAVS (SHA-2) bit-oriented files pack trailing bits
    /// left-justified and can be passed here directly; the SHA3VS files use the FIPS 202 B.1 packing
    /// (first bit in the LSB) and must be bit-reversed (`u8::reverse_bits`) first.
    ///
    /// 0 is a valid value and means the message ends on a byte boundary (equivalent to [`Hash::do_final`]).
    /// `num_bits` must be in `0..=7`; larger values return [`HashError::InvalidLength`].
    fn do_final_partial_bits(self, partial_byte: u8, num_bits: usize)
    -> Result<Vec<u8>, HashError>;

    /// The same as [`Hash::do_final_partial_bits`], but takes the output buffer as an argument.
    /// The output byte is zeroized before the result is written.
    /// The return value is the number of bytes written.
    fn do_final_partial_bits_out(
        self,
        partial_byte: u8,
        num_bits: usize,
        output: &mut [u8],
    ) -> Result<usize, HashError>;

    /// Returns the maximum security strength that this KDF is capable of supporting, based on the underlying primitives.
    fn max_security_strength(&self) -> SecurityStrength;
}

/// Standard parameters for a hash function.
pub trait HashAlgParams: Algorithm {
    /// The fixed output length of the hash function.
    const OUTPUT_LEN: usize;
    /// The internal block length of the hash function, which is often used as a meta-parameter for
    /// determining the security strength of the hash function since this limits the internal
    /// collision resistance of the hash function.
    const BLOCK_LEN: usize;
}

/// A Key Derivation Function (KDF) is a function that takes in one or more input key and some unstructured
/// additional input, and uses them to produces a derived key.
pub trait KDF: Default {
    /// Implementations of this function are capable of deriving an output key from an input key,
    /// assuming that they have been properly initialized.
    ///
    /// # Entropy Conversion rules
    /// Implementations SHOULD act on a KeyMaterial of any [`KeyType`] and will generally
    /// return a KeyMaterial of the same type
    ///
    /// ex.:
    ///
    ///   * [`KeyType::Unknown`] -> [`KeyType::Unknown`])
    ///   * [`KeyType::CryptographicRandom`] -> [`KeyType::CryptographicRandom`])
    ///   * [`KeyType::SymmetricCipherKey`] -> [`KeyType::SymmetricCipherKey`])
    ///
    /// If provided with an input key, even if it is [`KeyType::CryptographicRandom`], but that
    /// contains less key material than the internal block size of the KDF, then the KDF
    /// will not be considered properly seeded, and the output [`KeyMaterial`] will be set to
    /// [`KeyType::Unknown`] -- for example, seeding SHA3-256 with a [`KeyMaterial`] containing
    /// only 128 bits of key material.
    ///
    /// An implementation can, and in most cases SHOULD, return a [`HashError`] if provided
    /// with a [`KeyMaterial`] of type [`KeyType::Zeroized`].
    ///
    /// # Additional Input
    /// The `additional_input` parameter is used in deriving the key, but is not credited with any entropy,
    /// and therefore does not affect the type of the output [`KeyMaterial`].
    /// This corresponds directly to `FixedInfo` as defined in NIST SP 800-56C.
    /// The `additional_input` parameter can be empty by passing in `&[0u8; 0]`.
    ///
    /// Output length: this function will create a KeyMaterial populated with the default output length
    /// of the underlying hash primitive.
    fn derive_key(
        self,
        key: &impl KeyMaterialTrait,
        additional_input: &[u8],
    ) -> Result<Box<dyn KeyMaterialTrait>, KDFError>;

    /// Same as [`KDF::derive_key`], but fills the provided output [`KeyMaterial`].
    ///
    /// Output length: this function will behave differently depending on the underlying hash primitive;
    /// some, such as SHA2 or SHA3 will produce a fixed-length output, while others, such as SHAKE or HKDF,
    /// will fill the provided KeyMaterial to capacity and require you to truncate it afterward
    /// using [`KeyMaterialTrait::set_key_len`].
    fn derive_key_out(
        self,
        key: &impl KeyMaterialTrait,
        additional_input: &[u8],
        output_key: &mut impl KeyMaterialTrait,
    ) -> Result<usize, KDFError>;

    /// Meant to be used for hybrid key establishment schemes or other spit-key scenarios where multiple
    /// keys need to be combined into a single key of the same length.
    ///
    /// This function can also be used to mix a KeyMaterial of low entropy with one of full entropy to
    /// produce a new full entropy key. For the purposes of determining whether enough input key material
    /// was provided, the lengths of all full-entropy input keys are added together.
    ///
    /// Implementations that are not safe to be used as a split-key PRF MAY still implement this function
    /// and return a result, but SHOULD set the entropy level of the returned key appropriately; for example
    /// a KDF that is only full-entropy when keyed in the first input SHOULD return a full entropy key
    /// only if the first input is full entropy.
    ///
    /// Implementations can, and in most cases SHOULD, return a [`KeyMaterial`] of the same type as the
    /// strongest key, and SHOULD throw a [`HashError`] if all input keys are zeroized.
    /// For example output a [`KeyType::CryptographicRandom`] key whenever any one of
    /// the input keys is a [`KeyType::CryptographicRandom`] key.
    /// As another example, combining a [`KeyType::Unknown`] key with a [`KeyType::MACKey`] key
    /// should return a [`KeyType::MACKey`].
    ///
    /// Output length: this function will create a KeyMaterial populated with the default output length
    /// of the underlying hash primitive.
    fn derive_key_from_multiple(
        self,
        keys: &[&impl KeyMaterialTrait],
        additional_input: &[u8],
    ) -> Result<Box<dyn KeyMaterialTrait>, KDFError>;

    /// Same as [`KDF::derive_key`], but fills the provided output [`KeyMaterial`].
    ///
    /// Output length: this function will behave differently depending on the underlying hash primitive;
    /// some, such as SHA2 or SHA3 will produce a fixed-length output, while others, such as SHAKE or HKDF,
    /// will fill the provided KeyMaterial to capacity and require you to truncate it afterward
    /// by using [`KeyMaterialTrait::set_key_len`].
    fn derive_key_from_multiple_out(
        self,
        keys: &[&impl KeyMaterialTrait],
        additional_input: &[u8],
        output_key: &mut impl KeyMaterialTrait,
    ) -> Result<usize, KDFError>;

    /// Returns the maximum security strength that this KDF is capable of supporting, based on the underlying primitives.
    fn max_security_strength(&self) -> SecurityStrength;
}

/// A Key Encapsulation Mechanism (KEM) is defined as a set of three operations:
/// key generation, encapsulation, and decapsulation.
///
/// This trait represents the decapsulation operation performed by the holder of the private key.
/// Encapsulation operations are performed by the corresponding [`KEMEncapsulator`] trait, and key
/// generation is provided as an inherent associated function directly on the algorithm struct.
/// There are several reasons for this split: first is architectural; some complex algorithms may
/// benefit from having the encapsulation and decapsulation implementations split into separate modules.
/// Second is for compliance: sometimes a policy soft-deprecates an algorithm so that new ciphertexts
/// can no longer be created, but existing ciphertexts can still be decapsulated. Splitting the traits
/// makes this policy easier to enforce.
///
/// The arrays used to encode private keys, ciphertexts, and shared secrets are statically-sized
/// because this allows us to safely remove runtime checks for array lengths, which overall reduces
/// the fallibility of the library. This design choice could make this trait complicated to apply
/// to a KEM algorithm that does not have fixed sizes for the encodings of these objects.
pub trait KEMDecapsulator<
    SK: KEMPrivateKey<SK_LEN>,
    const SK_LEN: usize,
    const CT_LEN: usize,
    const SS_LEN: usize,
>: Sized
{
    /// Performs a decapsulation of the given ciphertext.
    /// Returns the derived shared secret.
    fn decaps(sk: &SK, ct: &[u8]) -> Result<KeyMaterial<SS_LEN>, KEMError>;
}

/// A Key Encapsulation Mechanism (KEM) is defined as a set of three operations:
/// key generation, encapsulation, and decapsulation.
///
/// This trait represents the encapsulation operation performed by the holder of the public key.
/// Decapsulation operations are performed by the corresponding [`KEMDecapsulator`] trait, and key
/// generation is provided as an inherent associated function directly on the algorithm struct.
/// There are several reasons for this split: first is architectural; some complex algorithms may
/// benefit from having the encapsulation and decapsulation implementations split into separate modules.
/// Second is for compliance: sometimes a policy soft-deprecates an algorithm so that new ciphertexts
/// can no longer be created, but existing ciphertexts can still be decapsulated. Splitting the traits
/// makes this policy easier to enforce.
///
/// The arrays used to encode public keys, ciphertexts, and shared secrets are statically-sized
/// because this allows us to safely remove runtime checks for array lengths, which overall reduces
/// the fallibility of the library. This design choice could make this trait complicated to apply
/// to a KEM algorithm that does not have fixed sizes for the encodings of these objects.
pub trait KEMEncapsulator<
    PK: KEMPublicKey<PK_LEN>,
    const PK_LEN: usize,
    const CT_LEN: usize,
    const SS_LEN: usize,
>: Sized
{
    /// Performs an encapsulation against the given public key.
    /// Sources randomness from the library's default OS-backed RNG.
    /// Returns the ciphertext and derived shared secret.
    fn encaps(pk: &PK) -> Result<(KeyMaterial<SS_LEN>, [u8; CT_LEN]), KEMError>;
    /// Performs an encapsulation against the given public key.
    /// Sources randomness from the provided RNG.
    /// Returns the ciphertext and derived shared secret.
    fn encaps_rng(
        pk: &PK,
        rng: &mut dyn RNG,
    ) -> Result<(KeyMaterial<SS_LEN>, [u8; CT_LEN]), KEMError>;
}

// todo: could the public and private key types impl Into<T: AsRef<[u8]>> and From<T: AsRef<[u8]>>
//       that automatically call the encode and from_bytes() ?

/// A private key for a KEM algorithm, often denoted "sk" (for "secret key").
pub trait KEMPrivateKey<const SK_LEN: usize>: PartialEq + Eq + Clone + Sized {
    /// Write it out to bytes in its standard encoding.
    fn encode(&self) -> [u8; SK_LEN];
    /// Write it out to bytes in its standard encoding.
    /// The entire output buffer is zeroized before the encoding is written.
    fn encode_out(&self, out: &mut [u8; SK_LEN]) -> usize;
    /// Read it in from bytes in its standard encoding.
    fn from_bytes(bytes: &[u8]) -> Result<Self, KEMError>;
}

/// A public key for a KEM algorithm, often denoted "pk".
pub trait KEMPublicKey<const PK_LEN: usize>:
    PartialEq + Eq + Clone + Debug + Display + Sized
{
    /// Write it out to bytes in its standard encoding.
    fn encode(&self) -> [u8; PK_LEN];
    /// Write it out to bytes in its standard encoding.
    /// The entire output buffer is zeroized before the encoding is written.
    fn encode_out(&self, out: &mut [u8; PK_LEN]) -> usize;
    /// Read it in from bytes in its standard encoding.
    fn from_bytes(bytes: &[u8]) -> Result<Self, KEMError>;
}

/// A keyed keystream generator: the raw primitive under a stream cipher, as
/// The unwrapping (authenticated-decryption) half of a key-wrap algorithm, such as KW, KWP or TKW
/// from NIST SP 800-38F (also specified as RFC 3394 and RFC 5649).
///
/// Wrapping is performed by the corresponding [`KeyWrapper`] trait. The two are separate traits so
/// that a policy can permit unwrapping of existing ciphertexts while forbidding new wrappings, as
/// with the other `*Encryptor` / `*Decryptor` pairs.
///
/// Key wrap is a one-shot operation over the whole input, so there is no streaming API: the
/// underlying wrapping function (SP 800-38F, Algorithm 2 (W⁻¹)) makes several passes over all
/// of the data.
///
/// # The KEK
///
/// The KEK (key encryption key) is a [`KeyMaterial`] and must be of type
/// [`KeyType::SymmetricCipherKey`], tagged at a security strength of at least
/// [`Algorithm::MAX_SECURITY_STRENGTH`]; otherwise a [`SymmetricCipherError::KeyMaterialError`] is
/// returned.
///
/// # The recovered plaintext is a `Secret`, not a `KeyMaterial`
///
/// Unwrapping says nothing about the type or provenance of the data, so the caller must decide
/// explicitly what it is, for example by constructing a [`KeyMaterial`] of the appropriate
/// [`KeyType`] from it. It is returned as a [`Secret`] so that it is still zeroized on drop and
/// redacted from debug output.
///
/// # Every authenticity failure is the same error
///
/// A wrong KEK, a modified ciphertext, an integrity-check value mismatch, invalid padding, and (for
/// [`KeyUnwrapper::unwrap_key`]) a recovered plaintext whose length is not `KEY_LEN` must all be
/// reported as [`SymmetricCipherError::DecryptionFailed`], so that the error does not tell an
/// attacker which check failed. SP 800-38F reports all of these as a single FAIL; see, for example,
/// Algorithm 6 (KWP-AD), steps 4, 7 and 8. On any error, the output buffer is zeroized.
pub trait KeyUnwrapper<const KEK_LEN: usize>: Algorithm + Sized {
    /// One-shot: unwraps a ciphertext whose length is fixed at compile time, returning the
    /// recovered plaintext.
    ///
    /// Provided over [`KeyUnwrapper::unwrap_key_out`].
    fn unwrap_key<const KEY_LEN: usize, const CT_LEN: usize>(
        kek: &KeyMaterial<KEK_LEN>,
        ciphertext: &[u8; CT_LEN],
    ) -> Result<Secret<[u8; KEY_LEN]>, SymmetricCipherError> {
        let mut key = Secret::<[u8; KEY_LEN]>::new();
        let bytes_written = Self::unwrap_key_out(kek, ciphertext, &mut key)?;
        debug_assert_eq!(bytes_written, KEY_LEN);
        Ok(key)
    }

    /// One-shot: unwraps a ciphertext whose length is fixed at compile time, writing the recovered
    /// plaintext directly into `key`. Returns the number of bytes written, which is always
    /// `KEY_LEN`.
    ///
    /// Implementations must reject any `(KEY_LEN, CT_LEN)` pair the algorithm does not define with
    /// an inline `const` assertion, so that it is a compile error at the call site; see
    /// [`KeyWrapper::wrap_key_out`].
    ///
    /// # Errors
    /// [`SymmetricCipherError::KeyMaterialError`] for an unsuitable KEK, and
    /// [`SymmetricCipherError::DecryptionFailed`] for any authenticity failure. `key` is zeroized
    /// on error.
    fn unwrap_key_out<const KEY_LEN: usize, const CT_LEN: usize>(
        kek: &KeyMaterial<KEK_LEN>,
        ciphertext: &[u8; CT_LEN],
        key: &mut Secret<[u8; KEY_LEN]>,
    ) -> Result<usize, SymmetricCipherError>;

    /// An upper bound on the plaintext length for a ciphertext of `ciphertext_len` bytes: the
    /// buffer [`KeyUnwrapper::unwrap_out`] requires. This is `ciphertext_len` minus one semiblock
    /// (half the block cipher's block length), saturating at zero. It is exact for KW and TKW; for
    /// KWP the exact length is only known after unwrapping, since up to 7 bytes are padding.
    ///
    /// Must not panic for any `ciphertext_len`.
    fn unwrap_out_max_len(ciphertext_len: usize) -> usize;

    /// One-shot: unwraps a ciphertext whose length is only known at run time into `plaintext`,
    /// which needs [`KeyUnwrapper::unwrap_out_max_len`] bytes. Returns the number of plaintext
    /// bytes written.
    ///
    /// On success the caller is responsible for zeroizing `plaintext` once done with it; prefer
    /// [`KeyUnwrapper::unwrap_key`] where the length is known at compile time.
    ///
    /// # Errors
    /// [`SymmetricCipherError::OutputBufferTooSmall`] if `plaintext` is too short, checked before
    /// any work is done; [`SymmetricCipherError::InvalidInputLength`] for a ciphertext length the
    /// algorithm is not defined on; [`SymmetricCipherError::KeyMaterialError`] for an unsuitable
    /// KEK; and [`SymmetricCipherError::DecryptionFailed`] for any authenticity failure. The whole
    /// `plaintext` buffer is zeroized on error.
    fn unwrap_out(
        kek: &KeyMaterial<KEK_LEN>,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError>;
}

/// The wrapping (authenticated-encryption) half of a key-wrap algorithm, such as KW, KWP or TKW
/// from NIST SP 800-38F (also specified as RFC 3394 and RFC 5649).
///
/// Unwrapping is performed by the corresponding [`KeyUnwrapper`] trait, whose notes on the KEK
/// apply here too.
///
/// # The data being wrapped is plain bytes
///
/// It is taken as bytes rather than as a [`KeyMaterial`] because wrapping strips the key type and
/// security strength anyway, and because key-wrap algorithms (particularly KWP) are also used to
/// protect data that is not a symmetric key, such as encoded private keys. A [`Secret`] can be
/// passed in by dereferencing it: `&*secret`.
///
/// SP 800-38F, Appendix A.2 says the KEK *should* be at least as strong as any key it protects.
/// Since the wrapped data carries no security strength, this trait cannot enforce that; it is the
/// caller's responsibility.
///
/// Key wrapping is deterministic: wrapping the same data under the same KEK always produces the
/// same ciphertext.
pub trait KeyWrapper<const KEK_LEN: usize>: Algorithm + Sized {
    /// One-shot: wraps data whose length is fixed at compile time, returning the ciphertext.
    ///
    /// Provided over [`KeyWrapper::wrap_key_out`].
    fn wrap_key<const KEY_LEN: usize, const CT_LEN: usize>(
        kek: &KeyMaterial<KEK_LEN>,
        key: &[u8; KEY_LEN],
    ) -> Result<[u8; CT_LEN], SymmetricCipherError> {
        let mut ciphertext = [0u8; CT_LEN];
        let bytes_written = Self::wrap_key_out(kek, key, &mut ciphertext)?;
        debug_assert_eq!(bytes_written, CT_LEN);
        Ok(ciphertext)
    }

    /// One-shot: wraps data whose length is fixed at compile time into `ciphertext`. Returns the
    /// number of bytes written, which is always `CT_LEN`.
    ///
    /// `CT_LEN` is a function of `KEY_LEN` that depends on the algorithm (for example
    /// `KEY_LEN + 8` for KW), which Rust cannot yet express in the signature. Implementations must
    /// therefore reject any `(KEY_LEN, CT_LEN)` pair the algorithm does not define -- including
    /// lengths outside the limits of SP 800-38F, Section 5.3.1 (Table 1) -- with an inline `const`
    /// assertion, so that it is a compile error at the call site, not a runtime `Err`.
    ///
    /// # Errors
    /// [`SymmetricCipherError::KeyMaterialError`] for an unsuitable KEK.
    fn wrap_key_out<const KEY_LEN: usize, const CT_LEN: usize>(
        kek: &KeyMaterial<KEK_LEN>,
        key: &[u8; KEY_LEN],
        ciphertext: &mut [u8; CT_LEN],
    ) -> Result<usize, SymmetricCipherError>;

    /// The exact ciphertext length for a plaintext of `plaintext_len` bytes: the buffer
    /// [`KeyWrapper::wrap_out`] requires. For example `plaintext_len + 8` for KW, and
    /// `plaintext_len` rounded up to a multiple of 8, plus 8, for KWP.
    ///
    /// Must not panic for any `plaintext_len`; for a length the algorithm is not defined on, the
    /// value is unspecified and [`KeyWrapper::wrap_out`] returns
    /// [`SymmetricCipherError::InvalidInputLength`].
    fn wrap_out_len(plaintext_len: usize) -> usize;

    /// One-shot: wraps data whose length is only known at run time into `ciphertext`, which needs
    /// [`KeyWrapper::wrap_out_len`] bytes. Returns the number of bytes written.
    ///
    /// # Errors
    /// [`SymmetricCipherError::OutputBufferTooSmall`] if `ciphertext` is too short, checked before
    /// any work is done; [`SymmetricCipherError::InvalidInputLength`] for a plaintext length the
    /// algorithm is not defined on; and [`SymmetricCipherError::KeyMaterialError`] for an
    /// unsuitable KEK.
    fn wrap_out(
        kek: &KeyMaterial<KEK_LEN>,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError>;
}

/// A Message Authentication Code algorithm is a keyed hash function that behaves somewhat like a symmetric signature function.
/// A MAC algorithm takes in a key and some data, and produces a MAC (message authentication code) that
/// can be used to verify the integrity of data.
///
/// This trait provides one-shot functions [`MAC::mac`], [`MAC::mac_out`], and [`MAC::verify`].
/// It also provides streaming functions [`MAC::do_update`], [`MAC::do_final`], [`MAC::do_final_out`],
/// and [`MAC::do_verify_final`].
/// The workflow is that a MAC object is obtained from a key object (`HmacKey`, `KMAC128Key`,
/// `AES128Key<CMAC>` and the like, through `create_generator` / `create_verifier`), then data is
/// processed into one or more calls to [`MAC::do_update`],
/// after that the object can either create a MAC with [`MAC::do_final`] or [`MAC::do_final_out`] (which are final functions, and so consume the object),
/// or the object can be used to verify a MAC.
///
/// For varifying an existing MAC, it is functionally equivalent to use the provided [`MAC::verify`] and [`MAC::do_verify_final`]
/// function or to compute a new MAC and compare it to the existing MAC, however the provided verification functions
/// use constant-time comparison to avoid cryptographic timing attacks whereby an attacker could learn
/// the bytes of the MAC value under some conditions. Therefore, it is highly recommended to use the provided verification functions.
///
/// Note that the MAC key is not represented in this trait because it belongs to the key object
/// that makes the worker.
///
/// MACs do not implement Default because they do not have a sensible no-args constructor.
pub trait MAC: Sized {
    /// The size of the output in bytes.
    fn output_len(&self) -> usize;

    /// One-shot API that computes a MAC for the provided data.
    /// `data` can be of any length, including zero bytes.
    ///
    /// Note about the security strength of the provided key:
    /// If the provided key is tagged at a lower [`SecurityStrength`] than the instantiated MAC algorithm,
    /// this will fail with an error:
    /// ```text
    /// MACError::KeyMaterialError(KeyMaterialError::SecurityStrength("HMAC::init(): provided key has a lower security strength than the instantiated HMAC")
    /// ```
    fn mac(self, data: &[u8]) -> Vec<u8>;

    /// One-shot API that computes a MAC for the provided data and writes it into the provided output slice.
    /// `data` can be of any length, including zero bytes.
    ///
    /// Depending on the underlying MAC implementation, NIST may require that the library enforce
    /// a minimum length on the mac output value. See documentation for the underlying implementation
    /// to see conditions under which it throws [`MACError::InvalidLength`].
    ///
    /// The entire output buffer is zeroized before the MAC value is written.
    fn mac_out(self, data: &[u8], out: &mut [u8]) -> Result<usize, MACError>;

    /// One-shot API that verifies a MAC for the provided data.
    /// `data` can be of any length, including zero bytes.
    ///
    /// Internally, this will re-compute the MAC value and then compare it to the provided mac value
    /// using constant-time comparison. It is highly encouraged to use this utility function instead of
    /// comparing mac values for equality yourself.
    ///
    /// Returns a bool to indicate successful verification of the provided mac value.
    /// The provided mac value must be an exact match, including length; for example a mac value
    /// which has been truncated, or which contains extra bytes at the end is considered to not be a match
    /// and will return false.
    fn verify(self, data: &[u8], mac: &[u8]) -> bool;

    /// Provide a chunk of data to be absorbed into the MAC.
    /// `data` can be of any length, including zero bytes.
    /// do_update() is intended to be used as part of a streaming interface, and so may by called multiple times.
    fn do_update(&mut self, data: &[u8]);

    /// Finish absorbing input and produce the MAC value.
    fn do_final(self) -> Vec<u8>;

    /// Depending on the underlying MAC implementation, NIST may require that the library enforce
    /// a minimum length on the mac output value. See documentation for the underlying implementation
    /// to see conditions under which it throws [`MACError::InvalidLength`].
    ///
    /// The entire output buffer is zeroized before the MAC value is written.
    fn do_final_out(self, out: &mut [u8]) -> Result<usize, MACError>;

    /// Internally, this will re-compute the MAC value and then compare it to the provided mac value
    /// using constant-time comparison. It is highly encouraged to use this utility function instead of
    /// comparing mac values for equality yourself.
    ///
    /// Returns a bool to indicate successful verification of the provided mac value.
    /// The provided mac value must be an exact match, including length; for example a mac value
    /// which has been truncated, or which contains extra bytes at the end is considered to not be a match
    /// and will return false.
    fn do_verify_final(self, mac: &[u8]) -> bool;

    /// Returns the maximum security strength that this KDF is capable of supporting, based on the underlying primitives.
    fn max_security_strength(&self) -> SecurityStrength;
}

/// A block padding scheme, used to extend arbitrary-length data to a whole number of blocks so that it
/// can be processed by a [`BlockCipherEncryptor`]. Implementations are pure functions of the block
/// contents: no key, no state.
///
/// Only the final, partial block of a message is ever padded; the padding layer sitting between the
/// caller and the block cipher is responsible for routing whole blocks straight through.
pub trait BlockCipherPadding<const BLOCK_LEN: usize> {
    /// Whether the scheme appends a whole block of padding to data that is already a whole number
    /// of blocks. `true` for a scheme like PKCS7, which must always add at least one byte so that
    /// unpadding is unambiguous; a caller then finishes an aligned message with `pad(block, 0)`.
    /// `false` for a scheme that never adds bytes (`NoPadding`): an aligned message is finished with
    /// no final block, and `pad` is called only for a partial one -- where such a scheme errors.
    const ALWAYS_PADS: bool;
    /// Pads `block` in place: bytes `0..data_len` are data and are left untouched, bytes
    /// `data_len..BLOCK_LEN` are overwritten with padding. `data_len` must be less than `BLOCK_LEN`
    /// (a full block of data requires a whole additional block of padding, which the caller supplies
    /// as `data_len = 0` -- only when [`ALWAYS_PADS`](Self::ALWAYS_PADS) is `true`).
    ///
    /// # Errors
    /// [`PaddingError::DataLengthTooLong`] if `data_len >= BLOCK_LEN`;
    /// [`PaddingError::PaddingNotPermitted`] from a scheme that adds no bytes and was asked to.
    fn pad(block: &mut [u8; BLOCK_LEN], data_len: usize) -> Result<(), PaddingError>;
    /// Returns the number of data bytes in a padded `block`, or [`PaddingError::InvalidPadding`].
    /// Implementations must run in constant time with respect to the block contents, so that a
    /// decryptor built on them does not leak a padding oracle.
    fn unpad(block: &[u8; BLOCK_LEN]) -> Result<usize, PaddingError>;
}

/// Pre-Hashed Signature Verifier is an extension to [`SignatureVerifier`] that adds functionality specific to signature
/// primatives that can operate on a pre-hashed message instead of the full message.
pub trait PHSignatureVerifier<
    PK: SignaturePublicKey<PK_LEN>,
    const PK_LEN: usize,
    const SIG_LEN: usize,
    const PH_LEN: usize,
>: SignatureVerifier<PK, PK_LEN, SIG_LEN>
{
    /// On success, returns Ok(())
    /// On failure, returns Err([`SignatureError::SignatureVerificationFailed`]); may also return other types of [`SignatureError`] as appropriate (such as for invalid-length inputs).
    fn verify_ph(
        pk: &PK,
        ph: &[u8; PH_LEN],
        ctx: Option<&[u8]>,
        sig: &[u8],
    ) -> Result<(), SignatureError>;
}

/// Pre-Hashed Signer is an extension to [`Signer`] that adds functionality specific to signature
/// primatives that can operate on a pre-hashed message instead of the full message.
pub trait PHSigner<
    PK: SignaturePublicKey<PK_LEN>,
    SK: SignaturePrivateKey<SK_LEN>,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const SIG_LEN: usize,
    const PH_LEN: usize,
>: Signer<SK, SK_LEN, SIG_LEN>
{
    /// Produce a signature for the provided pre-hashed message and context.
    ///
    /// `ctx` accepts a zero-length byte array.
    ///
    /// A note about the `ctx` context parameter:
    /// This is a newer addition to cryptographic signature primitives. It allows for binding the
    /// signature to some external property of the application so that a signature will fail to validate
    /// if removed from its intended context.
    /// This is particularly useful at preventing content confusion attacks between data formats that
    /// have very similar data structures, for example S/MIME emails, signed PDFs, and signed executables
    /// that all use the Cryptographic Message Syntax (CMS) data format, or multiple data objects that
    /// all use the JWS data format.
    /// To be properly effective, the ctx value must not be under the control of the attacker, which generally
    /// means that it needs to be a value that is never transmitted over the wire, but rather is something
    /// known to the application by context.
    /// For example, "email" vs "pdf" would be a good choice since the application should know what it is
    /// attempting to sign or verify.
    /// The `ctx` param can also be used to bind the signed content to a transaction ID or a username,
    /// but care should be taken to ensure that an attacker attempting a
    /// content confusion attack not also cause the signed / verifier to use an incorrect transaction ID or username.
    ///
    /// Not all signature primitives will support a context value, so you may need to consult the
    /// documentation for the underlying primitive for how it handles a ctx in that case, for example, it
    /// might throw an error, ignore the provided ctx value, or append the ctx to the msg in a non-standard way.
    fn sign_ph(
        sk: &SK,
        ph: &[u8; PH_LEN],
        ctx: Option<&[u8]>,
    ) -> Result<[u8; SIG_LEN], SignatureError>;
    /// Returns the number of bytes written to the output buffer. Can be called with an oversized buffer.
    /// The entire output buffer is zeroized before the signature is written.
    fn sign_ph_out(
        sk: &SK,
        ph: &[u8; PH_LEN],
        ctx: Option<&[u8]>,
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError>;
}

/// An interface for random number generation.
/// This interface is meant to be simpler and more ergonomic than the interfaces provided by the
/// `rng` crate, but that one should
/// be used by applications that intend to submit to FIPS certification as it more closely aligns with the
/// requirements of SP 800-90A.
/// Note: this interface produces bytes. If you want a [`KeyMaterialTrait`], then use [`KeyMaterial::from_rng`].
///
/// Implementors are expected to also implement [`Default`] (default-construction should produce a
/// securely OS-seeded instance), but this is intentionally *not* a supertrait bound: requiring
/// `Default` would make `RNG` not dyn-compatible, and `&mut dyn RNG` is needed so RNG instances
/// can be handed around as trait objects.
pub trait RNG {
    // TODO: add back once we figure out streaming interaction with entropy sources.
    // fn add_seed_bytes(&mut self, additional_seed: &[u8]) -> Result<(), RNGError>;

    /// Provide additional key material to be mixed in to the existing RNG instance.
    /// The exact behaviour will be implementation-specific, but this is intended for injecting
    /// additional entropy, not as the primary method of seeding the RNG.
    fn add_seed_keymaterial(
        &mut self,
        additional_seed: &dyn KeyMaterialTrait,
    ) -> Result<(), RNGError>;
    /// Returns the next random 32-bit integer.
    fn next_int(&mut self) -> Result<u32, RNGError>;

    /// Returns the number of requested bytes.
    fn next_bytes(&mut self, len: usize) -> Result<Vec<u8>, RNGError>;

    /// Returns the number of bytes written.
    /// The entire output buffer is zeroized before the random bytes are written.
    fn next_bytes_out(&mut self, out: &mut [u8]) -> Result<usize, RNGError>;

    /// Fill the provided [`KeyMaterial`] with random bytes.
    fn fill_keymaterial_out(&mut self, out: &mut dyn KeyMaterialTrait) -> Result<usize, RNGError>;

    /// Returns the Security Strength of this RNG.
    // todo: we should do a refactor to make [Algorithm] be a `security_strength()` function instead of constant,
    //      then have `RNG: Algorithm`, then delete this function.
    fn security_strength(&self) -> SecurityStrength;
}

// todo: could the public and private key types impl Into<T: AsRef<[u8]>> and From<T: AsRef<[u8]>>
// todo: that automatically call the encode and from_bytes() ?

/// A private key for a signature algorithm, often denoted "sk" (for "secret key").
pub trait SignaturePrivateKey<const SK_LEN: usize>: PartialEq + Eq + Clone + Sized {
    /// Write it out to bytes in its standard encoding.
    fn encode(&self) -> [u8; SK_LEN];
    /// Write it out to bytes in its standard encoding.
    /// The entire output buffer is zeroized before the encoding is written.
    fn encode_out(&self, out: &mut [u8; SK_LEN]) -> usize;
    /// Read it in from bytes in its standard encoding.
    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError>;
}

/// A public key for a signature algorithm, often denoted "pk".
pub trait SignaturePublicKey<const PK_LEN: usize>:
    PartialEq + Eq + Clone + Debug + Display + Sized
{
    /// Write it out to bytes in its standard encoding.
    fn encode(&self) -> [u8; PK_LEN];
    /// Write it out to bytes in its standard encoding.
    /// The entire output buffer is zeroized before the encoding is written.
    fn encode_out(&self, out: &mut [u8; PK_LEN]) -> usize;
    /// Read it in from bytes in its standard encoding.
    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError>;
}

/// A digital signature algorithm is defined as a set of three operations:
/// key generation, signing, and verification.
///
/// This trait represents the verification operations performed by the holder of the verification public key.
/// Keygen and signing operations are performed by the corresponding [`Signer`] trait.
/// There are several reasons for this split: first is architectural; some complex algorithms may
/// benefit from having the signature generation and verification implementations split into separate modules.
/// Second is for compliance: sometimes a policy soft-deprecates an algorithm so that new signatures
/// can no longer be created, but existing signatures can still be verified. Splitting the traits
/// makes this policy easier to enforce.
///
/// Here we statically-size the arrays used to encode public keys, private keys, and signature values
/// because this allows us to safely remove runtime checks for array lengths, which overall reduces
/// the fallibility of the library. This design choice could make this trait complicated to apply
/// to a signature algorithm that do not have fixed sizes for the encodings of these objects.
pub trait SignatureVerifier<
    PK: SignaturePublicKey<PK_LEN>,
    const PK_LEN: usize,
    const SIG_LEN: usize,
>: Sized
{
    /// On success, returns Ok(())
    /// On failure, returns Err([`SignatureError::SignatureVerificationFailed`]); may also return other types of [`SignatureError`] as appropriate (such as for invalid-length inputs).
    fn verify(pk: &PK, msg: &[u8], ctx: Option<&[u8]>, sig: &[u8]) -> Result<(), SignatureError>;

    /// streaming verification API
    fn do_verify_init(pk: &PK, ctx: Option<&[u8]>) -> Result<Self, SignatureError>;

    // todo: make this a AsRef<[u8]> ?
    /// Update the verifier with the next chunk of data.
    /// This can be called multiple times.
    fn do_verify_update(&mut self, msg_chunk: &[u8]);

    /// On success, returns Ok(())
    /// On failure, returns Err([`SignatureError::SignatureVerificationFailed`]); may also return other types of [`SignatureError`] as appropriate (such as for invalid-length inputs).
    fn do_verify_final(self, sig: &[u8]) -> Result<(), SignatureError>;
}

/// A digital signature algorithm is defined as a set of three operations:
/// key generation, signing, and verification.
///
/// This trait represents the operations performed by the holder of the signing private key:
/// which include signing and key generation. Verification operations are performed by the corresponding
/// [`SignatureVerifier`] trait.
/// There are several reasons for this split: first is architectural; some complex algorithms may
/// benefit from having the signature generation and verification implementations split into separate modules.
/// Second is for compliance: sometimes a policy soft-deprecates an algorithm so that new signatures
/// can no longer be created, but existing signatures can still be verified. Splitting the traits
/// makes this policy easier to enforce.
///
/// This high-level trait defines the operations over a generic signature algorithm that is assumed
/// to source all its randomness from bouncycastle's default os-backed RNG.
/// The underlying signature primitives will expose APIs that allow for specifying a specific RNG
/// or deterministic seed values.
///
/// The arrays used to encode public keys, private keys, and signature values are statically-sized
/// because this allows us to safely remove runtime checks for array lengths, which overall reduces
/// the fallibility of the library. This design choice could make this trait complicated to apply
/// to a signature algorithm that do not have fixed sizes for the encodings of these objects.
pub trait Signer<SK: SignaturePrivateKey<SK_LEN>, const SK_LEN: usize, const SIG_LEN: usize>:
    Sized
{
    /// Produce a signature for the provided message and context.
    /// Both the `msg` and `ctx` accept zero-length byte arrays.
    ///
    /// A note about the `ctx` context parameter:
    /// This is a newer addition to cryptographic signature primitives. It allows for binding the
    /// signature to some external property of the application so that a signature will fail to validate
    /// if removed from its intended context.
    /// This is particularly useful at preventing content confusion attacks between data formats that
    /// have very similar data structures, for example S/MIME emails, signed PDFs, and signed executables
    /// that all use the Cryptographic Message Syntax (CMS) data format, or multiple data objects that
    /// all use the JWS data format.
    /// To be properly effective, the ctx value must not be under the control of the attacker, which generally
    /// means that it needs to be a value that is never transmitted over the wire, but rather is something
    /// known to the application by context.
    /// For example, "email" vs "pdf" would be a good choice since the application should know what it is
    /// attempting to sign or verify.
    /// The `ctx` param can also be used to bind the signed content to a transaction ID or a username,
    /// but care should be taken to ensure that an attacker attempting a
    /// content confusion attack not also cause the signed / verifier to use an incorrect transaction ID or username.
    ///
    /// Not all signature primitives will support a context value, so you may need to consult the
    /// documentation for the underlying primitive for how it handles a ctx in that case, for example, it
    /// might throw an error, ignore the provided ctx value, or append the ctx to the msg in a non-standard way.
    fn sign(sk: &SK, msg: &[u8], ctx: Option<&[u8]>) -> Result<[u8; SIG_LEN], SignatureError>;

    /// Returns the number of bytes written to the output buffer. Can be called with an oversized buffer.
    /// The entire output buffer is zeroized before the signature is written.
    fn sign_out(
        sk: &SK,
        msg: &[u8],
        ctx: Option<&[u8]>,
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError>;

    /* streaming signing API */
    /// Initialize a signer for streaming mode with the provided private key.
    fn do_sign_init(sk: &SK, ctx: Option<&[u8]>) -> Result<Self, SignatureError>;

    // todo: make this a AsRef<[u8]> ?
    /// Update the signer with the next chunk of data.
    /// This can be called multiple times.
    fn do_sign_update(&mut self, msg_chunk: &[u8]);

    /// Complete the signing operation. Consumes self.
    fn do_sign_final(self) -> Result<[u8; SIG_LEN], SignatureError>;

    /// Returns the number of bytes written to the output buffer. Can be called with an oversized buffer.
    /// The entire output buffer is zeroized before the signature is written.
    fn do_sign_final_out(self, output: &mut [u8; SIG_LEN]) -> Result<usize, SignatureError>;
}

/// The decryption half of a stream cipher's streaming API; see [`StreamCipherEncryptor`], whose
/// notes on in-place operation, arbitrary lengths and the `Result` all apply here too.
pub trait StreamCipherDecryptor<const INIT_DATA_LEN: usize>:
    SymmetricCipherDecryptor<INIT_DATA_LEN, 0>
{
    /// Streaming: decrypts `data`, of any length, in place. A sequence of calls is equivalent to
    /// one call over the concatenation, whatever the chunking, exactly as for
    /// [`StreamCipherEncryptor::do_encrypt_inplace`]. Returns the number of bytes written, which is always
    /// `data.len()` since a stream cipher never buffers or changes the length of its data, but the
    /// count is still returned for consistency with the rest of the library's output-buffer APIs.
    fn do_decrypt_inplace(&mut self, data: &mut [u8]) -> Result<usize, SymmetricCipherError>;
}

/// The encryption half of a stream cipher's streaming API: the in-place view of a
/// [`SymmetricCipherEncryptor`] with `FINAL_LEN = 0`.
/// A stream cipher applies its keystream byte by byte, so the data methods take a
/// `&mut [u8]` of any length, and there is no finalization step.
///
/// Encryption and decryption are separate traits so that policy can permit decryption of an
/// existing data while forbidding new encryptions.
///
/// # Init data (a nonce or IV)
///
/// Init data (a nonce or IV) is generated securely by the implementation in the constructor and
/// returned for transmission alongside the ciphertext; there is no API for the user to supply it.
///
/// # Everything is in place
///
/// Since a stream cipher, by definition, hos no ciphertext expansion, every data method here
/// transforms its buffer in place: the plaintext goes in, the ciphertext
/// comes out in the same buffer.
/// Callers that need to keep the plaintext copy it first, or use the supertrait's `encrypt_out`.
///
/// # Any length is valid
///
/// The data is a `&mut [u8]` because every length is valid, including zero.
/// How the keystream is produced internally -- in 64-byte blocks, in words, a bit
/// at a time -- is the cipher's business and must not leak to the caller.
pub trait StreamCipherEncryptor<const INIT_DATA_LEN: usize>:
    SymmetricCipherEncryptor<INIT_DATA_LEN, 0>
{
    /// Streaming: encrypts `data`, of any length, in place; on top of the generic APIs offered by
    /// [`SymmetricCipherEncryptor`], a stream cipher can offer `_inplace()` versions since a stream
    /// cipher's ciphertext always has exactly the same length as its plaintext.
    ///
    /// A sequence of calls is equivalent to
    /// one call over the concatenation, whatever the chunking. Returns the number of bytes
    /// written, which is always `data.len()` since a stream cipher never buffers or changes the
    /// length of its data, but the count is still returned for consistency with the rest of the
    /// library's output-buffer APIs.
    ///
    /// # Errors
    /// [`SymmetricCipherError::DataLimitExceeded`] if this call would run past the cipher's
    /// per-initialization data limit. Nothing about the buffer can go wrong, and a constructed
    /// value is always ready to use; the `Result` is there because a counter-driven keystream must
    /// refuse to run past the point where its counter would wrap and the keystream repeat, and a
    /// streaming API cannot check that any earlier than the call that would cross it.
    fn do_encrypt_inplace(&mut self, data: &mut [u8]) -> Result<usize, SymmetricCipherError>;
}

/// Allows a stateful object to suspend its operation by serializing its state into a byte array
///so that it can be resumed later, potentially from a different host.
///
/// This is intended for situations where an object is being used through its streaming API
/// (do_update, do_final) and the operation wants to be paused to a cache, for example while waiting
/// for network IO.
///
/// This is not intended as a mechanism to clone the state of an object since in most cases `.clone()`
/// will be more straightforward.
///
/// The serialized state MAY contain short-term sensitive values such as nonces or IVs,
/// but it MUST NOT include a serialized private key.
/// Keyed algorithms MUST instead impl
/// [`SuspendableKeyed`] which requires the key to be supplied independently at the time of deserialization.
pub trait Suspendable<const SERIALIZED_STATE_LEN: usize>: Sized {
    /// Suspend operation by serializing out the state of the object.
    ///
    /// Note that this consumes `self` to prevent accidentally continuing to use the object after serialization.
    /// If you want to do this intentionally, then you will need to clone the object before serializing it.
    ///
    /// The serialized state MUST include a prefix indicating the version of the library that serialized it.
    fn suspend(self) -> [u8; SERIALIZED_STATE_LEN];

    /// Resume operation from a serialized state.
    ///
    /// Deserializers SHOULD check the version and reject serialized states from incompatible versions
    /// (including rejecting serializations from a future version of the library).
    /// For example, if a given object made a breaking change to its serialization in version 1.2.3, then its
    /// deserializer should reject serialized states from that version or older.
    fn from_suspended(state: [u8; SERIALIZED_STATE_LEN]) -> Result<Self, SuspendableError>;
}

/// Similar to [`Suspendable`] in that it allows a stateful object to suspend its operation by
/// serializing its state into a byte array so that it can be resumed later, potentially from a different host.
///
/// The difference is that this trait is for keyed algorithms -- MACs, symmetric ciphers, signatures, etc --
/// which require a private key in order to resume successfully.
/// For security reasons, the private key is not included in the serialized state
/// and must be provided separately as part of the deserialization process.
pub trait SuspendableKeyed<'k, const SERIALIZED_STATE_LEN: usize>: Sized {
    /// The type of key that must be re-supplied to resume this object. A worker that borrows its
    /// key for `'k` names the key's type (the mode's key state, for a cipher mode) and is resumed
    /// over the reference it is given; one that owns a copy of its key ignores the lifetime.
    type Key: ?Sized;

    /// Suspend operation by serializing out the state of the object.
    ///
    /// Note that this consumes `self` to prevent accidentally continuing to use the object after serialization.
    /// If you want to do this intentionally, then you will need to clone the object before serializing it.
    ///
    /// The serialized state MUST include a prefix indicating the version of the library that serialized it.
    fn suspend(self) -> [u8; SERIALIZED_STATE_LEN];

    /// Resume operation from a serialized state and the key.
    ///
    /// Deserializers SHOULD check the version and reject serialized states from incompatible versions
    /// (including rejecting serializations from a future version of the library).
    /// For example, if a given object made a breaking change to its serialization in version 1.2.3, then its
    /// deserializer should reject serialized states from that version or older.
    fn from_suspended(
        state: [u8; SERIALIZED_STATE_LEN],
        key: &'k Self::Key,
    ) -> Result<Self, SuspendableError>;
}

/// The decryption half of a symmetric cipher's arbitrary-length API. See
/// [`SymmetricCipherEncryptor`] for the shape of the API and the meaning of `FINAL_LEN`; this is
/// its mirror image, and the two are implemented by paired types.
///
/// Decryption is not the exact mirror of encryption in one respect: the last `FINAL_LEN` bytes a
/// decryptor releases may be only partly data. A padding scheme's final block carries
/// `data_len < BLOCK_LEN` bytes of plaintext and the rest padding, and an authenticated cipher may
/// release nothing at all once it has checked the tag. So
/// [`do_decrypt_final`](Self::do_decrypt_final) returns the buffer *and* how much of it is data,
/// and the one-shot length helper is an upper bound rather than an exact count.
///
/// The one-shots are the key's, provided over these streaming methods. An implementor writes
/// only [`update_out_len`](Self::do_decrypt_out_len), [`do_update_out`](Self::do_decrypt_out),
/// [`do_decrypt_final`](Self::do_decrypt_final) and [`decrypt_out_len`](Self::decrypt_out_len);
/// the constructor is the key's, and never part of the trait.
pub trait SymmetricCipherDecryptor<const INIT_DATA_LEN: usize, const FINAL_LEN: usize>:
    Algorithm + Sized
{
    /// The exact number of bytes the next [`do_update_out`](Self::do_decrypt_out) will write if
    /// given `input_len` more bytes of ciphertext, so a caller can size the `plaintext` buffer for
    /// that call before making it.
    ///
    /// It is not simply `input_len`: a decryptor holds back the tail of what it has seen -- the
    /// block that might carry the padding, the bytes that might be the tag -- so how much a call
    /// releases depends on what is already buffered, which is why this takes `&self` rather than
    /// being a function of the length alone.
    ///
    /// Calling it is optional. A caller that would rather not compute lengths can pass whatever
    /// buffer it has: if that buffer is too small the call fails with
    /// [`SymmetricCipherError::OutputBufferTooSmall`] carrying the same number, having consumed
    /// nothing, so retrying with a buffer at least that long produces exactly what the refused
    /// call would have. This is for the caller who wants to allocate once up front -- one buffer
    /// of `update_out_len(CHUNK)` bytes for a loop feeding fixed-size chunks -- rather than
    /// discover the size from a failure. For the whole message in one call, see
    /// [`decrypt_out_len`](Self::decrypt_out_len).
    fn do_decrypt_out_len(&self, input_len: usize) -> usize;

    /// Streaming: consumes `ciphertext`, writing every plaintext byte that can be released so far
    /// into `plaintext` and buffering the rest. Returns the number of bytes written, which is
    /// exactly [`update_out_len`](Self::do_decrypt_out_len) of `ciphertext.len()`.
    ///
    /// A decryptor may have to hold back the tail of what it has seen -- the last block, which
    /// might carry the padding, or the bytes that might be the tag -- so a sequence of calls
    /// releases data later than the corresponding encryptor produced it, but the concatenation of
    /// everything released plus the data part of [`do_decrypt_final`](Self::do_decrypt_final) is
    /// the plaintext.
    ///
    /// The entire output buffer is zeroized before the plaintext is written, so any bytes past
    /// `written` will be 0. In particular a call whose whole input is held back returns 0 and
    /// leaves the whole buffer zeroed.
    ///
    /// # Errors
    /// [`SymmetricCipherError::OutputBufferTooSmall`] if `plaintext` is shorter than
    /// [`update_out_len`](Self::do_decrypt_out_len), carrying the required length, and
    /// [`SymmetricCipherError::DataLimitExceeded`] if `ciphertext` would take the total past the
    /// amount the cipher may process under one key and init data -- a limit a streaming API can
    /// check no earlier than the call that would cross it. Nothing is consumed in either case. An
    /// implementor whose message length is fixed by its type may also return
    /// [`SymmetricCipherError::StateError`] if the input would exceed it; that is a property of
    /// the implementor, not of this trait, so it is not listed as a general contract here.
    fn do_decrypt_out(
        &mut self,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError>;

    /// Streaming, allocating: as [`do_decrypt_out`](Self::do_decrypt_out), returning the
    /// plaintext released by this call as a `Vec<u8>` of exactly
    /// [`do_decrypt_out_len`](Self::do_decrypt_out_len) bytes -- which may be empty, if the whole
    /// of `ciphertext` was held back. Only available with the `std` feature.
    ///
    /// # Errors
    /// As [`do_decrypt_out`](Self::do_decrypt_out), except that the buffer is always large enough.
    #[cfg(feature = "std")]
    fn do_decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, SymmetricCipherError> {
        let needed = self.do_decrypt_out_len(ciphertext.len());
        let mut plaintext = vec![0u8; needed];
        let written = self.do_decrypt_out(ciphertext, &mut plaintext)?;
        debug_assert_eq!(written, needed);
        Ok(plaintext)
    }

    /// Finishes the decryption, consuming the decryptor: processes whatever was held back, checks
    /// it -- padding, tag -- and returns the final buffer together with the number of leading
    /// bytes of it that are plaintext. The remainder of the buffer is not data and must not be
    /// used.
    ///
    /// # Errors
    /// [`SymmetricCipherError::DataNotBlockAligned`] if a block cipher's ciphertext was not a whole
    /// number of blocks; [`SymmetricCipherError::DecryptionFailed`] if it was otherwise malformed
    /// (empty, or not the length an implementor's type fixes);
    /// [`SymmetricCipherError::PaddingError`] or
    /// [`SymmetricCipherError::AEADTagCheckFailed`] if the check fails. In every error case the
    /// caller learns only that decryption failed, not where.
    fn do_decrypt_final(self) -> Result<([u8; FINAL_LEN], usize), SymmetricCipherError>;

    /// As [`do_decrypt_final`](Self::do_decrypt_final), writing the data part of the final buffer
    /// into `plaintext`. Returns the number of bytes written. The entire output buffer is zeroized
    /// before the plaintext is written, so any bytes past that count will be 0.
    fn do_decrypt_final_out(
        self,
        plaintext: &mut [u8; FINAL_LEN],
    ) -> Result<usize, SymmetricCipherError> {
        plaintext.fill(0);
        let (buffer, data_len) = self.do_decrypt_final()?;
        plaintext[..data_len].copy_from_slice(&buffer[..data_len]);
        Ok(data_len)
    }

    /// An upper bound on the plaintext recovered from `ciphertext_len` bytes of ciphertext, i.e.
    /// the buffer the key's `decrypt_out` requires. Exact for ciphers with no padding;
    /// for a padding scheme the exact length is only known after decryption.
    fn decrypt_out_len(ciphertext_len: usize) -> usize;
}

/// The encryption half of a symmetric cipher's arbitrary-length API: streaming `do_update_out` /
/// `do_encrypt_final`. The one-shots, and the constructor, are the key's.
///
/// This is the layer a caller with *data* uses, as opposed to the block-aligned
/// [`BlockCipherEncryptor`] a mode implements. Its shape is that of the padding adapters in
/// `bouncycastle_cipher::padding`, which are its first implementors: an authenticated cipher or a stream
/// cipher fits the same shape, with the tag or nothing in place of the final padded block.
///
/// `FINAL_LEN` is the fixed length of what [`do_encrypt_final`](Self::do_encrypt_final) produces
/// after the last byte of plaintext has been consumed: one block for a padding scheme, the tag
/// length for an authenticated cipher, zero for a stream cipher. Everything else about the output
/// length is answered exactly, before the fact, by [`update_out_len`](Self::do_encrypt_out_len) and
/// [`encrypt_out_len`](Self::encrypt_out_len), so a caller can size buffers without guessing.
///
/// Init data (an IV or nonce) is drawn by the key's `create_encryptor` and returned, never
/// supplied, for the same reason as in [`BlockCipherEncryptor`]. Everything is `no_std`-friendly
/// except the allocating [`do_encrypt`](Self::do_encrypt), which sits behind the `std` feature.
///
/// An implementor writes only [`update_out_len`](Self::do_encrypt_out_len),
/// [`do_update_out`](Self::do_encrypt_out), [`do_encrypt_final`](Self::do_encrypt_final) and
/// [`encrypt_out_len`](Self::encrypt_out_len).
pub trait SymmetricCipherEncryptor<const INIT_DATA_LEN: usize, const FINAL_LEN: usize>:
    Algorithm + Sized
{
    /// The exact number of bytes the next [`do_update_out`](Self::do_encrypt_out) will write if
    /// given `input_len` more bytes of plaintext, so a caller can size the `ciphertext` buffer for
    /// that call before making it.
    ///
    /// It is not simply `input_len`: a cipher that works a block at a time buffers a partial block
    /// until it is full, so how much a call emits depends on what is already buffered, which is
    /// why this takes `&self` rather than being a function of the length alone.
    ///
    /// Calling it is optional. A caller that would rather not compute lengths can pass whatever
    /// buffer it has: if that buffer is too small the call fails with
    /// [`SymmetricCipherError::OutputBufferTooSmall`] carrying the same number, having consumed
    /// nothing, so retrying with a buffer at least that long produces exactly what the refused
    /// call would have. This is for the caller who wants to allocate once up front -- one buffer
    /// of `update_out_len(CHUNK)` bytes for a loop feeding fixed-size chunks -- rather than
    /// discover the size from a failure. For the whole message in one call, see
    /// [`encrypt_out_len`](Self::encrypt_out_len).
    fn do_encrypt_out_len(&self, input_len: usize) -> usize;

    /// Streaming: consumes `plaintext`, writing every ciphertext byte that can be produced so far
    /// into `ciphertext` and buffering the rest. Returns the number of bytes written, which is
    /// exactly [`update_out_len`](Self::do_encrypt_out_len) of `plaintext.len()`. A sequence of calls
    /// is equivalent to one call over the concatenation.
    ///
    /// The entire output buffer is zeroized before the ciphertext is written, so any bytes past
    /// `written` will be 0. In particular a call that has to buffer all of its input -- a piece
    /// that does not complete a block, say -- returns 0 and leaves the whole buffer zeroed.
    ///
    /// # Errors
    /// [`SymmetricCipherError::OutputBufferTooSmall`] if `ciphertext` is shorter than
    /// [`update_out_len`](Self::do_encrypt_out_len), carrying the required length, and
    /// [`SymmetricCipherError::DataLimitExceeded`] if `plaintext` would take the total past the
    /// amount the cipher may process under one key and init data -- a limit a streaming API can
    /// check no earlier than the call that would cross it. Nothing is consumed in either case. An
    /// implementor whose message length is fixed by its type may also return
    /// [`SymmetricCipherError::StateError`] if the input would exceed it; that is a property of
    /// the implementor, not of this trait, so it is not listed as a general contract here.
    fn do_encrypt_out(
        &mut self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError>;

    /// Streaming, allocating: as [`do_encrypt_out`](Self::do_encrypt_out), returning the
    /// ciphertext released by this call as a `Vec<u8>` of exactly
    /// [`do_encrypt_out_len`](Self::do_encrypt_out_len) bytes -- which may be empty, if the whole
    /// of `plaintext` was buffered. Only available with the `std` feature.
    ///
    /// # Errors
    /// As [`do_encrypt_out`](Self::do_encrypt_out), except that the buffer is always large enough.
    #[cfg(feature = "std")]
    fn do_encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, SymmetricCipherError> {
        let needed = self.do_encrypt_out_len(plaintext.len());
        let mut ciphertext = vec![0u8; needed];
        let written = self.do_encrypt_out(plaintext, &mut ciphertext)?;
        debug_assert_eq!(written, needed);
        Ok(ciphertext)
    }

    /// Finishes the encryption, consuming the encryptor: pads and encrypts whatever was buffered,
    /// or computes the tag, and returns the final buffer together with the number of leading bytes
    /// of it that are ciphertext -- the last bytes of the message. For most ciphers that is always
    /// `FINAL_LEN` (the padded block, the tag); a padding scheme that adds nothing to aligned data
    /// returns 0 for an aligned message. The remainder of the buffer is not output.
    ///
    /// # Errors
    /// [`SymmetricCipherError::PaddingError`] if the buffered data cannot be finished -- with a
    /// scheme that adds no padding, a message that is not a whole number of blocks -- and
    /// [`SymmetricCipherError::StateError`] from an implementor whose message length is fixed by
    /// its type (see [`AEADCipherEncryptor`]) that was given less than it.
    fn do_encrypt_final(self) -> Result<([u8; FINAL_LEN], usize), SymmetricCipherError>;

    /// As [`do_encrypt_final`](Self::do_encrypt_final), writing the output part of the final
    /// buffer into `ciphertext`. Returns the number of bytes written. The entire output buffer is
    /// zeroized before the ciphertext is written, so any bytes past that count will be 0.
    fn do_encrypt_final_out(
        self,
        ciphertext: &mut [u8; FINAL_LEN],
    ) -> Result<usize, SymmetricCipherError> {
        ciphertext.fill(0);
        let (buffer, out_len) = self.do_encrypt_final()?;
        ciphertext[..out_len].copy_from_slice(&buffer[..out_len]);
        Ok(out_len)
    }

    /// The exact ciphertext length for a `plaintext_len`-byte plaintext that the cipher accepts,
    /// i.e. the buffer the key's `encrypt_out` requires and the number of bytes it writes. (A length the cipher rejects -- unaligned data under a scheme that adds no padding --
    /// fails in [`do_encrypt_final`](Self::do_encrypt_final) instead.)
    fn encrypt_out_len(plaintext_len: usize) -> usize;
}

/// The squeezing phase of an [`XOF`]: a value that produces output and can no longer take input,
/// as a typestate object. This is the type [`XOF::into_squeezer`] hands back.
///
/// Output is one continuous stream: successive calls continue where the last left off, so reading
/// 16 bytes twice gives the same 32 bytes as reading 32 once.
///
/// [`do_output_final`](Self::do_output_final) means something weaker than `do_final` does on
/// [`Hash`] and [`MAC`]. There it is load-bearing -- the only way to get output, and it must
/// consume the value because finalizing pads the state. An XOF squeeze has nothing to finalize, so
/// it produces exactly the bytes [`do_output`](Self::do_output) would and differs only in taking
/// ownership: it is how a caller says "this read is my last", and it ends the stream at the point
/// of the call rather than leaving a `mut` binding alive for the rest of the scope.
pub trait XOFSqueezer {
    /// Produces the next `num_bytes` bytes of the output stream.
    fn do_output(&mut self, num_bytes: usize) -> Vec<u8>;

    /// As [`do_output`](Self::do_output), filling the caller's buffer, which is zeroized first.
    /// Returns the number of bytes written.
    fn do_output_out(&mut self, output: &mut [u8]) -> usize;

    /// Produces the last `num_bytes` bytes of the output stream and ends the object.
    ///
    /// Consumes self, so this must be the final call to this object. The default is a plain last
    /// read -- the bytes [`do_output`](Self::do_output) would give, continuing from wherever
    /// earlier reads left the stream. An implementation with an output length still to bind
    /// overrides it to bind `num_bytes` when nothing has been read yet; see the trait docs.
    fn do_output_final(mut self, num_bytes: usize) -> Vec<u8>
    where
        Self: Sized,
    {
        self.do_output(num_bytes)
    }

    /// As [`do_output_final`](Self::do_output_final), filling the caller's buffer, which is
    /// zeroized first. Returns the number of bytes written.
    ///
    /// Defaulted as [`do_output_final`](Self::do_output_final) is.
    fn do_output_final_out(mut self, output: &mut [u8]) -> usize
    where
        Self: Sized,
    {
        self.do_output_out(output)
    }
}

/// Extendable-Output Functions (XOFs): A hash function with a variable-length output.
/// This relationship is captured by the type bound `XOF: Hash`. The instantiation that wraps an XOF
/// in a [`Hash`], specifies a fi~xed output length -- [`Hash::output_len`], often related to the
/// internal security parameters of the XOF. Often, other instantiantions are possible and the
/// provided one(s) are only a default.
///
/// # Absorb, then squeeze
///
/// All XOFs operate in two phases: accepting input, and producing output. When speaking specifically
/// about sponge constructions, these are referred to as "absorbing" and "squeezing", respectively.
///
/// The underlying primitives of some XOFs, such as sponge functions, are capable of arbitrarily
/// interleaving absorbs and squeezes, however this XOF trait enforces absorb, then squeeze via a
/// typestate transition via the hard boundary [`into_squeezer`](Self::into_squeezer)
/// which consumes the [`XOF`] and returns an [`XOFSqueezer`].
///
/// # 🚨 Security Considerations 🚨
/// ## A XOF is not a hash, cryptographically
///
/// The reason that an XOF itself is not (usually) considered to be a hash function is related outputs.
/// Two XOFs given the same input, one read for 32 bytes and one for 1 KiB will be identical on their
/// first 32 bytes.
/// In many contexts, this breaks the Preimage properties that hash functions guarantee since it
/// becomes trivial for an attacker to tell that these two different outputs came from the same input.
///
/// These security properties can be restored at the application layer by diversifying the inputs.
/// For example, by appending the output length to the input message, the following two invocation
/// will now produce un-correlated outputs even on the same `message`:
///
/// ```text
/// xof(message || 0x32, 32)
/// xof(message || 0x64, 64)
/// ```
pub trait XOF: Hash {
    /// The squeezing state this XOF turns into.
    type Squeezer: XOFSqueezer;

    /// Ends the input phase and begins producing output.
    ///
    /// The phase change is in the type: what comes back takes no more input.
    fn into_squeezer(self) -> Self::Squeezer;

    /// As [`into_squeezer`](Self::into_squeezer), with a final partial **byte** of input.
    ///
    /// The partial byte arrives as the final octet of an ASN.1 BIT STRING (X.690 s. 8.6.2.1): the
    /// `num_bits` message bits are the most significant bits of `partial_byte`, leading bit first,
    /// and the low `8 - num_bits` "unused" bits are ignored. Same convention as
    /// [`Hash::do_final_partial_bits`]. `num_bits` of 0 means the message ended on a byte boundary
    /// and is equivalent to [`into_squeezer`](Self::into_squeezer).
    ///
    /// # Errors
    /// [`HashError::InvalidLength`] if `num_bits` is not in `0..=7`.
    fn into_squeezer_partial_bits(
        self,
        partial_byte: u8,
        num_bits: usize,
    ) -> Result<Self::Squeezer, HashError>;

    /// One-shot: absorbs `data` and produces `result_len` bytes.
    ///
    /// A one-shot names its length and never comes back, so this is
    /// [`XOFSqueezer::do_output_final`]'s reading of the stream, not
    /// [`do_output`](XOFSqueezer::do_output)'s: where an implementation binds the length it is
    /// asked for, this binds `result_len`. For SHAKE and cSHAKE the two are the same bytes.
    ///
    /// The default absorbs and reads in the obvious way; override it only where the type can do
    /// better, as SHAKE does.
    fn xof(mut self, data: &[u8], result_len: usize) -> Vec<u8>
    where
        Self: Sized,
    {
        self.do_update(data);
        self.into_squeezer().do_output_final(result_len)
    }

    /// One-shot: absorbs `data` and fills `output`, which is zeroized first. Returns the number of
    /// bytes written.
    ///
    /// A final read of `output.len()` bytes, and defaulted as [`xof`](Self::xof) is.
    fn xof_out(mut self, data: &[u8], output: &mut [u8]) -> usize
    where
        Self: Sized,
    {
        self.do_update(data);
        self.into_squeezer().do_output_final_out(output)
    }
}
