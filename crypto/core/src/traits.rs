//! Provides simplified abstracted APIs over classes of cryptographic primitives, such as Hash, KDF, etc.

// Objects in this file should be sorted alphabetically, regardless of whether they are a trait, struct, or enum.

use crate::errors::*;
use crate::key_material::KeyMaterialTrait;
use crate::security_strength::SecurityStrength;
use crate::signature_key::PreHashStrengthRule;
use bouncycastle_utils::secret::{Secret, zeroize_in_place};
use core::fmt::{Debug, Display};
use core::marker::Sized;

#[cfg(feature = "alloc")]
use alloc::{boxed::Box, vec, vec::Vec};

// Imports needed for docs
#[allow(unused_imports)]
use crate::key_material::KeyMaterial;
#[allow(unused_imports)]
use crate::key_material::KeyType;
// end of imports needed for docs

/// What an AEAD key's allocating one-shot with a detached tag hands back:
/// `(nonce, ciphertext, tag)`
#[cfg(feature = "alloc")]
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
    /// [`SymmetricCipherError::StateError`] if called with a non-empty `aad` after the first
    /// non-empty [`SymmetricCipherDecryptor::do_decrypt_out`]; an empty data call is a no-op that
    /// leaves the AAD phase open, as on the encrypting side.
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
        mut self,
        tag: &[u8; TAG_LEN],
        plaintext: &mut [u8; FINAL_LEN],
    ) -> Result<usize, SymmetricCipherError>
    where
        Self: Sized,
    {
        zeroize_on_err(
            self.finish_decrypt_detached_into(&FinishToken::new(), tag, plaintext),
            plaintext,
        )
    }

    /// [`do_decrypt_final_detached_out`](Self::do_decrypt_final_detached_out) for a worker held
    /// as `Box<dyn AEADCipherDecryptor>`. The box is consumed, and nothing is moved out of it:
    /// the worker is wiped where it sits.
    ///
    /// Only available with the `alloc` feature.
    #[cfg(feature = "alloc")]
    fn do_decrypt_final_detached_out_boxed(
        mut self: Box<Self>,
        tag: &[u8; TAG_LEN],
        plaintext: &mut [u8; FINAL_LEN],
    ) -> Result<usize, SymmetricCipherError> {
        zeroize_on_err(
            self.finish_decrypt_detached_into(&FinishToken::new(), tag, plaintext),
            plaintext,
        )
    }

    /// Finishes the decryption with the tag detached, where the worker sits: the one detached
    /// finishing method an implementor writes, with
    /// [`do_decrypt_final_detached_out`](Self::do_decrypt_final_detached_out)'s contract.
    /// Callable only by the provided finals; see [`FinishToken`].
    fn finish_decrypt_detached_into(
        &mut self,
        token: &FinishToken,
        tag: &[u8; TAG_LEN],
        plaintext: &mut [u8; FINAL_LEN],
    ) -> Result<usize, SymmetricCipherError>;

    /// As [`do_decrypt_final_detached_out`](Self::do_decrypt_final_detached_out), returning
    /// the final buffer together with the number of leading bytes of it that are plaintext, the
    /// shape of [`SymmetricCipherDecryptor::do_decrypt_final`]. On failure no buffer is returned,
    /// so nothing unauthenticated is left behind by this call. On success the plaintext is
    /// returned by value, as from [`SymmetricCipherDecryptor::do_decrypt_final`];
    /// [`do_decrypt_final_detached_out`](Self::do_decrypt_final_detached_out) leaves no copy.
    ///
    /// # Errors
    /// As [`do_decrypt_final_detached_out`](Self::do_decrypt_final_detached_out).
    ///
    /// A provided method that takes `self` by value, so not callable on a trait object; the
    /// `_boxed` form is. The same holds for the other `final` conveniences.
    fn do_decrypt_final_detached(
        mut self,
        tag: &[u8; TAG_LEN],
    ) -> Result<([u8; FINAL_LEN], usize), SymmetricCipherError>
    where
        Self: Sized,
    {
        let mut plaintext = [0u8; FINAL_LEN];
        let data_len =
            self.finish_decrypt_detached_into(&FinishToken::new(), tag, &mut plaintext)?;
        Ok((plaintext, data_len))
    }

    /// An upper bound on the plaintext recovered from `ciphertext_len` bytes of ciphertext with
    /// the tag detached, i.e. the buffer the key's `decrypt_detached_out`
    /// requires. The default returns `ciphertext_len` itself, which is exact for every conformant
    /// AEAD: unlike a padding scheme, an AEAD never expands or shrinks the data it is given, only
    /// adds the separate `tag`.
    ///
    /// Not callable on a trait object: the length is a property of the type.
    fn decrypt_detached_out_len(ciphertext_len: usize) -> usize
    where
        Self: Sized,
    {
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
    /// [`SymmetricCipherError::StateError`] if called with a non-empty `aad` after the first
    /// non-empty [`SymmetricCipherEncryptor::do_encrypt_out`] -- see the trait docs for why the AAD
    /// comes first. An empty data call is a no-op that leaves the AAD phase open; the test
    /// framework's AEAD suite holds every implementor to both halves of this rule. An implementor whose AAD buffer has a fixed capacity may also return
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
        mut self,
        ciphertext: &mut [u8; FINAL_LEN],
    ) -> Result<(usize, [u8; TAG_LEN]), SymmetricCipherError>
    where
        Self: Sized,
    {
        self.finish_encrypt_detached_into(&FinishToken::new(), ciphertext)
    }

    /// [`do_encrypt_final_detached_out`](Self::do_encrypt_final_detached_out) for a worker held
    /// as `Box<dyn AEADCipherEncryptor>`. The box is consumed, and nothing is moved out of it:
    /// the worker is wiped where it sits.
    ///
    /// Only available with the `alloc` feature.
    #[cfg(feature = "alloc")]
    fn do_encrypt_final_detached_out_boxed(
        mut self: Box<Self>,
        ciphertext: &mut [u8; FINAL_LEN],
    ) -> Result<(usize, [u8; TAG_LEN]), SymmetricCipherError> {
        self.finish_encrypt_detached_into(&FinishToken::new(), ciphertext)
    }

    /// Finishes the encryption with the tag detached, where the worker sits: the one detached
    /// finishing method an implementor writes, with
    /// [`do_encrypt_final_detached_out`](Self::do_encrypt_final_detached_out)'s contract.
    /// Callable only by the provided finals; see [`FinishToken`].
    fn finish_encrypt_detached_into(
        &mut self,
        token: &FinishToken,
        ciphertext: &mut [u8; FINAL_LEN],
    ) -> Result<(usize, [u8; TAG_LEN]), SymmetricCipherError>;

    /// As [`do_encrypt_final_detached_out`](Self::do_encrypt_final_detached_out), returning
    /// the final buffer, the number of leading bytes of it that are ciphertext, and the tag -- the
    /// shape of [`SymmetricCipherEncryptor::do_encrypt_final`] with the tag alongside. Provided
    /// over the `_out` form, the other way round from the base trait's pair; see
    /// [`AEADCipherDecryptor::do_decrypt_final_detached`].
    fn do_encrypt_final_detached(
        mut self,
    ) -> Result<([u8; FINAL_LEN], usize, [u8; TAG_LEN]), SymmetricCipherError>
    where
        Self: Sized,
    {
        let mut ciphertext = [0u8; FINAL_LEN];
        let (out_len, tag) =
            self.finish_encrypt_detached_into(&FinishToken::new(), &mut ciphertext)?;
        Ok((ciphertext, out_len, tag))
    }

    /// The exact ciphertext length for a `plaintext_len`-byte plaintext with the tag detached, i.e.
    /// the buffer the key's `encrypt_detached_out` requires and the number of
    /// bytes it writes (the tag is returned separately, not counted here). The default returns
    /// `plaintext_len` itself, which holds for every conformant AEAD: unlike a padding scheme, an
    /// AEAD never expands or shrinks the data it is given.
    ///
    /// Not callable on a trait object: the length is a property of the type.
    fn encrypt_detached_out_len(plaintext_len: usize) -> usize
    where
        Self: Sized,
    {
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

/// What a worker can say about itself at run time: the name and maximum strength
/// [`Algorithm`] carries as constants, as methods, so that a trait object can be asked.
/// Every `Algorithm` implements it; a type that is not one algorithm (a signature worker
/// generic over its curve and hash, say) implements it directly.
pub trait AlgorithmInfo {
    /// [`Algorithm::ALG_NAME`] of the algorithm this value runs.
    fn alg_name(&self) -> &'static str;
    /// [`Algorithm::MAX_SECURITY_STRENGTH`] of the algorithm this value runs.
    fn max_security_strength(&self) -> SecurityStrength;
}

impl<T: Algorithm> AlgorithmInfo for T {
    fn alg_name(&self) -> &'static str {
        T::ALG_NAME
    }
    fn max_security_strength(&self) -> SecurityStrength {
        T::MAX_SECURITY_STRENGTH
    }
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
    AlgorithmInfo
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
    AlgorithmInfo
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

/// Proof that a worker is being finished by one of its consuming finals.
///
/// Every worker trait's required finishing method (`finish_into` and its relatives) takes
/// `&mut self`, so that a final can run where the worker sits and the worker's `Secret` fields
/// are wiped there when it is dropped. That holds for a worker inside a `Box`, which the
/// `_boxed` finals never move out of, and for a worker the library's own code finishes; a
/// by-value final (`do_final_out(self, ..)`) is still handed the worker by a move, which the
/// compiler may or may not turn into a copy.
///
/// A method on `&mut self` could be called twice, or followed by more input, which for a MAC, an
/// AEAD or a signer repeats a nonce or a one-time key. So each of those methods takes a
/// `&FinishToken`, whose constructor is private to this crate: the callers are the provided
/// consuming finals, which drop the worker as they return, and the provided one-shots, which
/// build a worker, finish it where it sits and drop it. An implementor receives the token and passes it
/// to a worker it owns and is finishing with itself (HMAC to its hash). The one other source is
/// [`crate::hazmat::finish_token`], for code that owns a worker without implementing a worker
/// trait, which takes on what the consuming finals guarantee; so a token shows that a final was
/// asked for on purpose, not that a consuming final is the caller.
///
/// # 🚨 Security Considerations 🚨
///
/// The token guards against finishing a worker twice by accident, not against an implementor
/// that sets out to: a worker type written to hold `&mut W` and hand its token to `W` finishes a
/// worker it does not own, which can then be used again. Pass the token only to a worker the
/// implementing type owns.
///
/// A token cannot be constructed outside this crate, only asked for through `hazmat`:
///
/// ```compile_fail
/// let token = bouncycastle_core::traits::FinishToken(());
/// ```
pub struct FinishToken(());

impl FinishToken {
    /// For the provided consuming finals and one-shots in this crate and
    /// [`crate::hazmat::finish_token`].
    pub(crate) fn new() -> Self {
        Self(())
    }
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
/// # Forking is on the types, not the trait
///
/// Every hash in this library is `Clone`: a hash mid-stream can be copied, and the copy continues
/// independently from the same absorbed prefix. That is how a running hash of a common prefix is
/// finished several ways -- a transcript hash checkpointed at each handshake message, HMAC's inner
/// and outer states held ready across many MACs under one key, or a Merkle node whose prefix is
/// shared by its siblings -- without re-absorbing the prefix each time. Every implementor is a
/// fixed-size state plus a small buffer, so the derive is the right implementation, and the shared
/// test framework checks that a clone and its original finish to the same digest, and diverge once
/// fed different input.
///
/// `Clone` is not a supertrait, though, because `Clone` implies `Sized` and would stop this trait
/// from ever being a trait object. Code that forks a hash says so: `HMACParams` and the test
/// framework bound on `Hash + Clone`.
pub trait Hash: AlgorithmInfo {
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

    /// Provide a chunk of data to be absorbed into the hashes.
    /// `data` can be of any length, including zero bytes.
    /// do_update() is intended to be used as part of a streaming interface, and so may by called multiple times.
    fn do_update(&mut self, data: &[u8]);

    /// Finishes absorbing input and writes the hash output into `output`, where the worker sits:
    /// the one method an implementor writes for the whole-byte finals, all of which are provided
    /// over it. Callable only by those finals; see [`FinishToken`].
    ///
    /// The buffer contract is [`Hash::do_final_out`]'s.
    fn finish_into(&mut self, token: &FinishToken, output: &mut [u8]) -> usize;

    /// As [`finish_into`](Self::finish_into), with a trailing partial byte: the one
    /// method an implementor writes for the partial-bits finals. The contract is
    /// [`Hash::do_final_partial_bits_out`]'s.
    fn finish_partial_bits_into(
        &mut self,
        token: &FinishToken,
        partial_byte: u8,
        num_bits: usize,
        output: &mut [u8],
    ) -> Result<usize, HashError>;

    /// Finish absorbing input and produce the hashes output.
    /// Consumes self, so this must be the final call to this object.
    ///
    /// Only available with the `alloc` feature.
    #[cfg(feature = "alloc")]
    fn do_final(mut self) -> Vec<u8>
    where
        Self: Sized,
    {
        let mut output = vec![0u8; self.output_len()];
        self.finish_into(&FinishToken::new(), &mut output);
        output
    }

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
    fn do_final_out(mut self, output: &mut [u8]) -> usize
    where
        Self: Sized,
    {
        self.finish_into(&FinishToken::new(), output)
    }

    /// [`do_final_out`](Self::do_final_out) for a hash held as `Box<dyn Hash>`, which cannot call
    /// a method that takes `self` by value. The box is consumed, so a stored hash is finished
    /// exactly once, and nothing is moved out of it: the state is wiped where it sits.
    ///
    /// Only available with the `alloc` feature.
    #[cfg(feature = "alloc")]
    fn do_final_out_boxed(mut self: Box<Self>, output: &mut [u8]) -> usize {
        self.finish_into(&FinishToken::new(), output)
    }

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
    ///
    /// Only available with the `alloc` feature.
    #[cfg(feature = "alloc")]
    fn do_final_partial_bits(
        mut self,
        partial_byte: u8,
        num_bits: usize,
    ) -> Result<Vec<u8>, HashError>
    where
        Self: Sized,
    {
        let mut output = vec![0u8; self.output_len()];
        self.finish_partial_bits_into(&FinishToken::new(), partial_byte, num_bits, &mut output)?;
        Ok(output)
    }

    /// The same as [`Hash::do_final_partial_bits`], but takes the output buffer as an argument.
    /// The output byte is zeroized before the result is written.
    /// The return value is the number of bytes written.
    fn do_final_partial_bits_out(
        mut self,
        partial_byte: u8,
        num_bits: usize,
        output: &mut [u8],
    ) -> Result<usize, HashError>
    where
        Self: Sized,
    {
        self.finish_partial_bits_into(&FinishToken::new(), partial_byte, num_bits, output)
    }

    /// [`do_final_partial_bits_out`](Self::do_final_partial_bits_out) for a hash held as
    /// `Box<dyn Hash>`; see [`do_final_out_boxed`](Self::do_final_out_boxed).
    ///
    /// Only available with the `alloc` feature.
    #[cfg(feature = "alloc")]
    fn do_final_partial_bits_out_boxed(
        mut self: Box<Self>,
        partial_byte: u8,
        num_bits: usize,
        output: &mut [u8],
    ) -> Result<usize, HashError> {
        self.finish_partial_bits_into(&FinishToken::new(), partial_byte, num_bits, output)
    }
}

/// The one-shot form of a hash that takes no parameters: `SHA256::hash(msg)`.
///
/// Both functions run [`Hash::do_update`] then [`Hash::finish_into`] on a [`Default`] instance,
/// which is finished where it sits rather than moved into a consuming final after it has
/// absorbed the message.
/// Implemented by the hashes whose `Default` is the function itself (SHA-2, SHA-3, SHAKE, SM3,
/// Ascon); the parameterised ones (cSHAKE, KMAC, TupleHash, ParallelHash, Ascon-CXOF) and the
/// factories offer an instance method `hash(self, data)` instead. Kept off [`Hash`] because
/// receiver-less functions would stop it ever being a trait object.
pub trait HashOneShot: Hash + Default {
    /// Hashes `data` into `output`, which is zeroized first, and returns the number of bytes
    /// written. A buffer shorter than the digest takes a truncated digest; a longer one takes
    /// the digest at its start and zeros after, as [`Hash::do_final_out`] does.
    fn hash_out(data: &[u8], output: &mut [u8]) -> usize {
        let mut h = Self::default();
        h.do_update(data);
        h.finish_into(&FinishToken::new(), output)
    }

    /// Hashes `data` and returns the digest.
    ///
    /// Only available with the `alloc` feature.
    #[cfg(feature = "alloc")]
    fn hash(data: &[u8]) -> Vec<u8> {
        let mut h = Self::default();
        h.do_update(data);
        let mut output = vec![0u8; h.output_len()];
        h.finish_into(&FinishToken::new(), &mut output);
        output
    }
}

/// A hash function whose collision resistance stands: no practical way is known of finding two
/// inputs with the same digest.
///
/// A signature is made over a digest of the message, so whoever can find two messages with one
/// digest can have one of them signed and present the signature with the other. The signing roles
/// of the schemes whose keys are paired with a hash of the caller's choice (ECDSA, HashML-DSA)
/// therefore require this marker of the hash, and a hash without it cannot be used to produce a
/// signature. The verifying roles do not require it, so a signature made over such a hash can
/// still be checked; neither do MACs or KDFs, which do not rest on collision resistance.
///
/// Implemented by each hash in the library that has a fixed digest length, takes no key or
/// parameter, and reports a security strength ([`Algorithm::MAX_SECURITY_STRENGTH`] other than
/// `SecurityStrength::None`); not by a type whose function or output length is chosen at run
/// time. A caller who must sign with a hash that lacks the marker names it as
/// [`hazmat::WithoutCollisionResistance<H>`](crate::hazmat::WithoutCollisionResistance).
///
/// The marker governs the roles that take the hash as a type. An interface that takes a value
/// the caller hashed elsewhere (ML-DSA's external mu) is outside its reach.
pub trait CollisionResistantHash: Hash {}

/// Standard parameters for a hash function.
pub trait HashAlgParams: Algorithm {
    /// The fixed output length of the hash function.
    const OUTPUT_LEN: usize;
    /// The internal block length of the hash function, which is often used as a meta-parameter for
    /// determining the security strength of the hash function since this limits the internal
    /// collision resistance of the hash function.
    const BLOCK_LEN: usize;
    /// Whether a signature scheme that requires its pre-hash to be at least as strong as its
    /// parameter set holds this type to that. A hash function leaves the default; see
    /// [`PreHashStrengthRule`] for the one other value and where it comes from.
    const PRE_HASH_STRENGTH_RULE: PreHashStrengthRule = PreHashStrengthRule::ENFORCED;
}

/// The most keying material the provided one-shots [`KDF::derive_key`] and
/// [`KDF::derive_key_from_multiple`] return at once; the `_out` methods take any length the
/// function and the buffer allow.
pub const KDF_ONE_SHOT_MAX_LEN: usize = 1024;

/// A key derivation function that already holds whatever parameters it has (HKDF its salt; the
/// X9.63 KDF none), deriving keying material of a requested length from input
/// keying material and a context string, SP 800-56C's `FixedInfo`. Every method takes `&self`,
/// so one instance serves any number of derivations and the trait is usable as `dyn KDF`.
///
/// # Entropy accounting
/// The output is typed from what went in. Library policy, not a rule of any standard: the
/// output is [`KeyType::CryptographicRandom`] once the full-entropy input keys (those for which
/// [`KeyMaterialTrait::is_full_entropy`] holds and whose [`KeyMaterialTrait::security_strength`]
/// is not [`SecurityStrength::None`]) together carry at least as many bytes as the function's
/// own strength bound, half a hash output for a hash-based KDF, and otherwise
/// [`KeyType::Unknown`] with no strength; its strength is the least of the inputs' strongest,
/// the function's and the length's, so a `CryptographicRandom` output carries a strength
/// whenever its length can hold one, 14 bytes for the least; a shorter one carries none, and
/// neither does the output of a function that claims no strength (one over a legacy hash). A key
/// with no strength (a [`KeyType::SharedSecret`] whose producer set none, a key
/// too short to carry 112 bits) credits nothing. The count is of the keys as given: the same key
/// passed twice in `ikms` counts twice, which is the caller's to avoid. `fixed_info` is context
/// and credits nothing. A [`KeyType::Zeroized`] or [`KeyType::Unknown`] input is derived from
/// and yields `Unknown` output rather than an error, since a KDF cannot tell such bytes from
/// random ones. [`crate::hazmat::label_kdf_output`] is the rule as code, for an implementation
/// to call, and [`crate::hazmat::KdfCredit`] the same for one that takes its keys one at a time.
///
/// An instance holds only what it was made from (an HKDF's salt): one that has also absorbed
/// input through a streaming API is refused by the derivations. A zero-length derivation is
/// refused, and so is one from no keys, whose output would be a function of the info alone.
/// An algorithm that derives its output through a KDF is made from a description of it rather
/// than an instance, [`KdfDescription`](crate::kdf_params::KdfDescription), which builds the
/// instance.
pub trait KDF: AlgorithmInfo {
    /// Derives `len` bytes of keying material from `ikm` and `fixed_info` into the front of
    /// `output_key`, which is zeroized first, and returns `len`.
    ///
    /// # Errors
    /// [`KDFError::InvalidLength`] if `len` is zero or exceeds what the function produces
    /// (`255 * HashLen` for HKDF) or `output_key`'s capacity; `output_key` is left zeroized.
    fn derive_key_out(
        &self,
        ikm: &dyn KeyMaterialTrait,
        fixed_info: &[u8],
        len: usize,
        output_key: &mut dyn KeyMaterialTrait,
    ) -> Result<usize, KDFError>;

    /// As [`derive_key_out`](Self::derive_key_out) with the input keying material the
    /// concatenation of `ikms` in order: a hybrid shared secret, or a key mixed with a weaker one.
    /// Every full-entropy key is credited, so the output's type is what the sum gives.
    ///
    /// # Errors
    /// As [`derive_key_out`](Self::derive_key_out); [`KDFError::InvalidLength`] if `ikms` is
    /// empty.
    fn derive_key_from_multiple_out(
        &self,
        ikms: &[&dyn KeyMaterialTrait],
        fixed_info: &[u8],
        len: usize,
        output_key: &mut dyn KeyMaterialTrait,
    ) -> Result<usize, KDFError>;

    /// One-shot: `len` bytes, at most [`KDF_ONE_SHOT_MAX_LEN`], as new key material. Provided
    /// over [`derive_key_out`](Self::derive_key_out). Only available with the `alloc` feature.
    ///
    /// # Errors
    /// [`KDFError::InvalidLength`] if `len` exceeds [`KDF_ONE_SHOT_MAX_LEN`], else as
    /// [`derive_key_out`](Self::derive_key_out).
    #[cfg(feature = "alloc")]
    fn derive_key(
        &self,
        ikm: &dyn KeyMaterialTrait,
        fixed_info: &[u8],
        len: usize,
    ) -> Result<Box<dyn KeyMaterialTrait>, KDFError> {
        if len > KDF_ONE_SHOT_MAX_LEN {
            return Err(KDFError::InvalidLength(ONE_SHOT_TOO_LONG));
        }
        // Derived into the box, so that no copy of the key is left where it was made.
        let mut output_key = Box::new(KeyMaterial::<KDF_ONE_SHOT_MAX_LEN>::new());
        self.derive_key_out(ikm, fixed_info, len, &mut *output_key)?;
        Ok(output_key)
    }

    /// One-shot over [`derive_key_from_multiple_out`](Self::derive_key_from_multiple_out). Only
    /// available with the `alloc` feature.
    ///
    /// # Errors
    /// As [`derive_key`](Self::derive_key).
    #[cfg(feature = "alloc")]
    fn derive_key_from_multiple(
        &self,
        ikms: &[&dyn KeyMaterialTrait],
        fixed_info: &[u8],
        len: usize,
    ) -> Result<Box<dyn KeyMaterialTrait>, KDFError> {
        if len > KDF_ONE_SHOT_MAX_LEN {
            return Err(KDFError::InvalidLength(ONE_SHOT_TOO_LONG));
        }
        // Derived into the box, as in `derive_key`.
        let mut output_key = Box::new(KeyMaterial::<KDF_ONE_SHOT_MAX_LEN>::new());
        self.derive_key_from_multiple_out(ikms, fixed_info, len, &mut *output_key)?;
        Ok(output_key)
    }
}

/// The one-shots' refusal of a length past [`KDF_ONE_SHOT_MAX_LEN`]; the `_out` forms take any
/// length the function and the buffer allow.
#[cfg(feature = "alloc")]
const ONE_SHOT_TOO_LONG: &str =
    "the KDF one-shots derive at most KDF_ONE_SHOT_MAX_LEN bytes; use the _out form for more";

/// The decapsulating half of a KEM: the worker a decapsulating key hands out through
/// [`DecapsulatingKey`](crate::kem_key::DecapsulatingKey). The key and any parameters the
/// algorithm takes (a KDF, say) were fixed when the worker was made, so the ciphertext is the only
/// input left. It is a separate trait from [`KEMEncapsulator`] so that a key, or a policy, can
/// allow existing ciphertexts to be decapsulated while forbidding new ones.
///
/// The ciphertext and shared secret are fixed-length arrays, so a ciphertext of the wrong length
/// is a compile error rather than a run-time one.
pub trait KEMDecapsulator<const CT_LEN: usize, const SS_LEN: usize>: AlgorithmInfo {
    /// Decapsulates `ct` into `ss`, which is zeroized first, and returns the number of bytes
    /// written, always `SS_LEN`. The worker is reusable: a static key decapsulates many
    /// ciphertexts. The caller's buffer is where the secret lives, so a long derived key costs
    /// the caller's frame, not the worker's.
    ///
    /// # Errors
    /// [`KEMError::DecapsulationFailed`] for an explicitly rejecting KEM whose check fails; an
    /// implicitly rejecting KEM (ML-KEM) returns a key for every ciphertext and errs only if the
    /// shared secret cannot be built. `ss` is left zeroized on every error.
    fn decaps_out(
        &self,
        ct: &[u8; CT_LEN],
        ss: &mut KeyMaterial<SS_LEN>,
    ) -> Result<usize, KEMError>;

    /// As [`decaps_out`](Self::decaps_out), returning the shared secret.
    fn decaps(&self, ct: &[u8; CT_LEN]) -> Result<KeyMaterial<SS_LEN>, KEMError> {
        let mut ss = KeyMaterial::new();
        self.decaps_out(ct, &mut ss)?;
        Ok(ss)
    }
}

/// The encapsulating half of a KEM: the worker an encapsulating key hands out through
/// [`EncapsulatingKey`](crate::kem_key::EncapsulatingKey). The key and any parameters the
/// algorithm takes were fixed when the worker was made; each call draws fresh randomness from the
/// caller's RNG, so the worker is reusable.
pub trait KEMEncapsulator<const CT_LEN: usize, const SS_LEN: usize>: AlgorithmInfo {
    /// Encapsulates to the key: writes the ciphertext into `ct` and the shared secret into
    /// `ss`, both zeroized first, and returns the number of ciphertext bytes written, always
    /// `CT_LEN`. The caller's buffer is where the secret lives, so a long derived key costs the
    /// caller's frame, not the worker's.
    ///
    /// # Errors
    /// [`KEMError::RNGError`] if `rng` is weaker than the algorithm or fails to deliver;
    /// [`KEMError::KeyMaterialError`] if the shared secret cannot be built. Both buffers are
    /// left zeroized on every error.
    fn encaps_out(
        &self,
        rng: &mut dyn RNG,
        ct: &mut [u8; CT_LEN],
        ss: &mut KeyMaterial<SS_LEN>,
    ) -> Result<usize, KEMError>;

    /// As [`encaps_out`](Self::encaps_out), returning the shared secret and the ciphertext.
    fn encaps(&self, rng: &mut dyn RNG) -> Result<(KeyMaterial<SS_LEN>, [u8; CT_LEN]), KEMError> {
        let mut ct = [0u8; CT_LEN];
        let mut ss = KeyMaterial::new();
        self.encaps_out(rng, &mut ct, &mut ss)?;
        Ok((ss, ct))
    }
}

/// A two-party key agreement in progress: the worker an agreement key hands out through
/// [`AgreementKey`](crate::agreement_key::AgreementKey). The own key and any parameters the
/// algorithm takes were fixed when the worker was made, so the peer's public key is the only
/// input left. `PK` is the peer key type the algorithm agrees with.
///
/// The shared secret `Z` is the primitive's raw output, typed [`KeyType::SharedSecret`]: secret
/// keying material that is not uniformly distributed, to be used only as the input of a KDF
/// (SP 800-56Ar3 Section 5.8) and never as a key itself.
pub trait KeyAgreement<PK, const SS_LEN: usize>: AlgorithmInfo {
    /// Computes the shared secret with `peer_pk` into `ss`, which is zeroized first, and
    /// returns the number of bytes written, always `SS_LEN`. The worker is reusable: a static
    /// key agrees with many peers. The caller's buffer is where the secret lives, so a long
    /// derived key costs the caller's frame, not the worker's.
    ///
    /// # Errors
    /// [`KeyAgreementError::AgreementFailed`] if the primitive produces no secret (ECC CDH:
    /// the computed point is the point at infinity, SP 800-56Ar3 Section 5.7.1.2 step 2). `ss`
    /// is left zeroized on every error.
    fn agree_out(
        &self,
        peer_pk: &PK,
        ss: &mut KeyMaterial<SS_LEN>,
    ) -> Result<usize, KeyAgreementError>;

    /// As [`agree_out`](Self::agree_out), returning the shared secret.
    fn agree(&self, peer_pk: &PK) -> Result<KeyMaterial<SS_LEN>, KeyAgreementError> {
        let mut ss = KeyMaterial::new();
        self.agree_out(peer_pk, &mut ss)?;
        Ok(ss)
    }
}

/// The unwrapping half of a key-wrap algorithm -- KW, KWP or TKW of NIST SP 800-38F (RFC 3394 and
/// RFC 5649) -- as the worker a key object hands out through
/// [`KeyUnwrappingKey`](crate::symmetric_key::KeyUnwrappingKey). Wrapping is [`KeyWrapper`]. The
/// two are separate traits so that a policy can permit unwrapping existing ciphertexts while
/// forbidding new wrappings, as with the other `*Encryptor` / `*Decryptor` pairs.
///
/// Key wrap is a one-shot operation over the whole input, so there is no streaming API: the
/// underlying wrapping function (SP 800-38F Algorithm 2, W⁻¹) makes several passes over all of
/// the data. The KEK (key encryption key) belongs to the key object, which validated it once; the
/// worker borrows the keyed permutation and never sees the material.
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
pub trait KeyUnwrapper: AlgorithmInfo {
    /// One-shot: unwraps a ciphertext whose length is fixed at compile time, returning the
    /// recovered plaintext.
    ///
    /// Provided over [`KeyUnwrapper::unwrap_key_out`].
    /// Not callable on a trait object: the lengths are properties of the call site.
    fn unwrap_key<const KEY_LEN: usize, const CT_LEN: usize>(
        &self,
        ciphertext: &[u8; CT_LEN],
    ) -> Result<Secret<[u8; KEY_LEN]>, SymmetricCipherError>
    where
        Self: Sized,
    {
        let mut key = Secret::<[u8; KEY_LEN]>::new();
        let bytes_written = self.unwrap_key_out(ciphertext, &mut key)?;
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
    /// [`SymmetricCipherError::DecryptionFailed`] for any authenticity failure. `key` is zeroized
    /// on error.
    /// Not callable on a trait object: the lengths are properties of the call site.
    fn unwrap_key_out<const KEY_LEN: usize, const CT_LEN: usize>(
        &self,
        ciphertext: &[u8; CT_LEN],
        key: &mut Secret<[u8; KEY_LEN]>,
    ) -> Result<usize, SymmetricCipherError>
    where
        Self: Sized;

    /// An upper bound on the plaintext length for a ciphertext of `ciphertext_len` bytes: the
    /// buffer [`KeyUnwrapper::unwrap_out`] requires. This is `ciphertext_len` minus one semiblock
    /// (half the block cipher's block length), saturating at zero. It is exact for KW and TKW; for
    /// KWP the exact length is only known after unwrapping, since up to 7 bytes are padding.
    ///
    /// Must not panic for any `ciphertext_len`.
    fn unwrap_out_max_len(&self, ciphertext_len: usize) -> usize;

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
    /// algorithm is not defined on; and [`SymmetricCipherError::DecryptionFailed`] for any
    /// authenticity failure. The whole `plaintext` buffer is zeroized before anything else, so
    /// nothing stale survives an error.
    fn unwrap_out(
        &self,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError>;
}

/// The wrapping half of a key-wrap algorithm -- KW, KWP or TKW of NIST SP 800-38F (RFC 3394 and
/// RFC 5649) -- as the worker a key object hands out through
/// [`KeyWrappingKey`](crate::symmetric_key::KeyWrappingKey). Unwrapping is [`KeyUnwrapper`],
/// whose notes on the KEK and the one-shot shape apply here too.
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
pub trait KeyWrapper: AlgorithmInfo {
    /// One-shot: wraps data whose length is fixed at compile time, returning the ciphertext.
    ///
    /// Provided over [`KeyWrapper::wrap_key_out`].
    /// Not callable on a trait object: the lengths are properties of the call site.
    fn wrap_key<const KEY_LEN: usize, const CT_LEN: usize>(
        &self,
        key: &[u8; KEY_LEN],
    ) -> Result<[u8; CT_LEN], SymmetricCipherError>
    where
        Self: Sized,
    {
        let mut ciphertext = [0u8; CT_LEN];
        let bytes_written = self.wrap_key_out(key, &mut ciphertext)?;
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
    /// None for a valid pair of lengths; the signature carries the `Result` for the run-time
    /// form's sake.
    /// Not callable on a trait object: the lengths are properties of the call site.
    fn wrap_key_out<const KEY_LEN: usize, const CT_LEN: usize>(
        &self,
        key: &[u8; KEY_LEN],
        ciphertext: &mut [u8; CT_LEN],
    ) -> Result<usize, SymmetricCipherError>
    where
        Self: Sized;

    /// The exact ciphertext length for a plaintext of `plaintext_len` bytes: the buffer
    /// [`KeyWrapper::wrap_out`] requires. For example `plaintext_len + 8` for KW, and
    /// `plaintext_len` rounded up to a multiple of 8, plus 8, for KWP.
    ///
    /// Must not panic for any `plaintext_len`; for a length the algorithm is not defined on, the
    /// value is unspecified and [`KeyWrapper::wrap_out`] returns
    /// [`SymmetricCipherError::InvalidInputLength`].
    fn wrap_out_len(&self, plaintext_len: usize) -> usize;

    /// One-shot: wraps data whose length is only known at run time into `ciphertext`, which needs
    /// [`KeyWrapper::wrap_out_len`] bytes. Returns the number of bytes written.
    ///
    /// # Errors
    /// [`SymmetricCipherError::OutputBufferTooSmall`] if `ciphertext` is too short, checked before
    /// any work is done, and [`SymmetricCipherError::InvalidInputLength`] for a plaintext length
    /// the algorithm is not defined on. `ciphertext` is zeroized before anything else, so nothing
    /// stale survives an error.
    fn wrap_out(
        &self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError>;
}

/// The generating half of a MAC in progress: the streaming worker a MAC key hands out through
/// [`MacGenerationKey`](crate::symmetric_key::MacGenerationKey) or, under a nonce,
/// [`NonceMacGenerationKey`](crate::symmetric_key::NonceMacGenerationKey). The key, and any
/// nonce, were fixed when the worker was made, so the message is the only input left. The tag is
/// `MAC_LEN` bytes, the construction's full output; a protocol that truncates its tags does so on
/// the array it gets back. It is a separate trait from [`MACVerifier`] so that a key, or a policy,
/// can allow verification without generation.
pub trait MACGenerator<const MAC_LEN: usize>: AlgorithmInfo {
    /// Absorbs the next chunk of the message. May be called any number of times with chunks of
    /// any size, including zero; a sequence of calls is equivalent to one call over the
    /// concatenation.
    fn do_update(&mut self, data: &[u8]);

    /// Produces the tag into `out` where the worker sits: the one finishing method an
    /// implementor writes, with [`do_final_out`](Self::do_final_out)'s contract. Callable only by
    /// the provided finals; see [`FinishToken`].
    fn finish_mac_into(&mut self, token: &FinishToken, out: &mut [u8; MAC_LEN]) -> usize;

    /// Produces the tag into `out`, written in full, and returns the number of bytes written,
    /// always `MAC_LEN`. Consumes the worker.
    fn do_final_out(mut self, out: &mut [u8; MAC_LEN]) -> usize
    where
        Self: Sized,
    {
        self.finish_mac_into(&FinishToken::new(), out)
    }

    /// [`do_final_out`](Self::do_final_out) for a worker held as `Box<dyn MACGenerator>`. The box
    /// is consumed, and nothing is moved out of it: the worker is wiped where it sits.
    ///
    /// Only available with the `alloc` feature.
    #[cfg(feature = "alloc")]
    fn do_final_out_boxed(mut self: Box<Self>, out: &mut [u8; MAC_LEN]) -> usize {
        self.finish_mac_into(&FinishToken::new(), out)
    }

    /// Produces the tag. Consumes the worker.
    fn do_final(mut self) -> [u8; MAC_LEN]
    where
        Self: Sized,
    {
        let mut out = [0u8; MAC_LEN];
        self.finish_mac_into(&FinishToken::new(), &mut out);
        out
    }
}

/// The verifying half of a MAC in progress: the streaming worker a MAC key hands out through
/// [`MacVerificationKey`](crate::symmetric_key::MacVerificationKey) or, under a nonce,
/// [`NonceMacVerificationKey`](crate::symmetric_key::NonceMacVerificationKey). The comparison is
/// in constant time, so recomputing the tag and comparing it with `==`, which leaks how many
/// leading bytes matched, is never needed.
pub trait MACVerifier<const MAC_LEN: usize>: AlgorithmInfo {
    /// Absorbs the next chunk of the message, as [`MACGenerator::do_update`] does.
    fn do_update(&mut self, data: &[u8]);

    /// Checks `mac` against the message absorbed so far. Consumes the worker.
    ///
    /// # Errors
    /// [`MACError::VerificationFailed`] if `mac` is not the tag of the message under the key.
    fn do_verify_final(mut self, mac: &[u8; MAC_LEN]) -> Result<(), MACError>
    where
        Self: Sized,
    {
        self.finish_mac_verify(&FinishToken::new(), mac)
    }

    /// [`do_verify_final`](Self::do_verify_final) for a worker held as `Box<dyn MACVerifier>`.
    /// The box is consumed, and nothing is moved out of it: the worker is wiped where it sits.
    ///
    /// Only available with the `alloc` feature.
    #[cfg(feature = "alloc")]
    fn do_verify_final_boxed(mut self: Box<Self>, mac: &[u8; MAC_LEN]) -> Result<(), MACError> {
        self.finish_mac_verify(&FinishToken::new(), mac)
    }

    /// Checks `mac` where the worker sits: the one finishing method an implementor writes, with
    /// [`do_verify_final`](Self::do_verify_final)'s contract. Callable only by the provided
    /// finals; see [`FinishToken`].
    fn finish_mac_verify(
        &mut self,
        token: &FinishToken,
        mac: &[u8; MAC_LEN],
    ) -> Result<(), MACError>;
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

/// A private key with a standard encoding of `SK_LEN` bytes, often denoted "sk" (for "secret
/// key"). One trait for every role: a key that serves more than one (X25519, in key agreement
/// and as a KEM) implements it once, and what the key does is said by the role traits of
/// [`kem_key`](crate::kem_key), [`agreement_key`](crate::agreement_key) and
/// [`signature_key`](crate::signature_key).
pub trait PrivateKey<const SK_LEN: usize>: PartialEq + Eq + Clone + Sized {
    /// Write it out to bytes in its standard encoding.
    fn encode(&self) -> [u8; SK_LEN];
    /// Write it out to bytes in its standard encoding.
    /// The entire output buffer is zeroized before the encoding is written.
    fn encode_out(&self, out: &mut [u8; SK_LEN]) -> usize;
    /// Read it in from bytes in its standard encoding.
    fn from_bytes(bytes: &[u8]) -> Result<Self, KeyDecodingError>;
}

/// A public key with a standard encoding of `PK_LEN` bytes, often denoted "pk". Decoding it
/// validates it as the algorithm requires, so a key that exists has passed the checks its use
/// relies on. One trait for every role, as [`PrivateKey`] is.
pub trait PublicKey<const PK_LEN: usize>: PartialEq + Eq + Clone + Debug + Display + Sized {
    /// Write it out to bytes in its standard encoding.
    fn encode(&self) -> [u8; PK_LEN];
    /// Write it out to bytes in its standard encoding.
    /// The entire output buffer is zeroized before the encoding is written.
    fn encode_out(&self, out: &mut [u8; PK_LEN]) -> usize;
    /// Read it in from bytes in its standard encoding.
    fn from_bytes(bytes: &[u8]) -> Result<Self, KeyDecodingError>;
}

/// An interface for random number generation.
/// This interface is meant to be simpler and more ergonomic than the interfaces provided by the
/// `rng` crate, but that one should
/// be used by applications that intend to submit to FIPS certification as it more closely aligns with the
/// requirements of SP 800-90A.
/// Note: this interface produces bytes. If you want a [`KeyMaterialTrait`], then use [`KeyMaterial::from_rng`].
///
/// Where an operating system is available, implementors are expected to also implement
/// [`Default`], default-construction producing a securely OS-seeded instance.
// `Default` is not a supertrait: it would make `RNG` not dyn-compatible, and `&mut dyn RNG` is
// how RNG instances are handed around.
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

/// Draws from any [`RNG`] that refuse a short one: a fixed-length array returned by value, or
/// the whole of a caller's buffer.
///
/// Implemented for every `RNG`, a `dyn RNG` included, so `rng.next_array::<12>()` works on a
/// `&mut dyn RNG`.
///
/// # 🚨 Security Considerations 🚨
/// The array is returned by value: it is moved, may be copied on the way, and is never wiped.
/// Use it for public values such as nonces, salts, IVs and test data, never for a secret. A secret
/// is drawn into a [`KeyMaterial`] with [`RNG::fill_keymaterial_out`], or into a [`Secret`] with
/// [`next_bytes_exact_out`](Self::next_bytes_exact_out).
// A trait of its own because a generic method on `RNG` would make that trait not dyn-compatible.
pub trait RNGExt: RNG {
    /// Returns `N` bytes from one call to [`RNG::next_bytes_out`]. The array is built on the
    /// caller's stack, so a large `N` costs that much stack.
    ///
    /// # Errors
    /// The RNG's own error; [`RNGError::GenericError`] if it reports fewer than `N` bytes
    /// written. A short draw never returns a partly filled array.
    fn next_array<const N: usize>(&mut self) -> Result<[u8; N], RNGError> {
        let mut out = [0u8; N];
        self.next_bytes_exact_out(&mut out)?;
        Ok(out)
    }

    /// Fills the whole of `out` from one call to [`RNG::next_bytes_out`]. Returns `out.len()`.
    ///
    /// # Errors
    /// The RNG's own error; [`RNGError::GenericError`] if it reports fewer bytes written than
    /// `out` holds. `out` is zeroized on either, so a short draw never leaves a partial one.
    fn next_bytes_exact_out(&mut self, out: &mut [u8]) -> Result<usize, RNGError> {
        out.fill(0);
        let result = match self.next_bytes_out(out) {
            Ok(written) if written == out.len() => return Ok(written),
            Ok(_) => Err(RNGError::GenericError("the RNG wrote fewer bytes than it was asked for")),
            Err(e) => Err(e),
        };
        for byte in out.iter_mut() {
            zeroize_in_place(byte);
        }
        result
    }
}

impl<T: RNG + ?Sized> RNGExt for T {}

/// The signing half of a signature in progress: the streaming worker a signing key hands out
/// through [`SigningKey`](crate::signature_key::SigningKey) or
/// [`DeterministicSigningKey`](crate::signature_key::DeterministicSigningKey). The key and any
/// randomness the algorithm needs were fixed when the worker was made, so the message is the only
/// input left.
pub trait SignatureSigner<const SIG_LEN: usize>: AlgorithmInfo {
    /// Absorbs the next chunk of the message. May be called any number of times with chunks of
    /// any size; a sequence of calls is equivalent to one call over the concatenation.
    fn do_update(&mut self, msg_chunk: &[u8]);

    /// Produces the signature. Consumes the worker.
    ///
    /// # Errors
    /// [`SignatureError::RejectionLimitExceeded`] for an algorithm that bounds its rejection loop,
    /// and whatever else its signing step can fail with; the key, the context and any randomness
    /// were checked when the worker was made.
    fn do_final(mut self) -> Result<[u8; SIG_LEN], SignatureError>
    where
        Self: Sized,
    {
        let mut output = [0u8; SIG_LEN];
        self.finish_signature_into(&FinishToken::new(), &mut output)?;
        Ok(output)
    }

    /// As [`do_final`](Self::do_final), into `output`, which is zeroized first; returns
    /// the number of bytes written, always `SIG_LEN`.
    fn do_final_out(mut self, output: &mut [u8; SIG_LEN]) -> Result<usize, SignatureError>
    where
        Self: Sized,
    {
        self.finish_signature_into(&FinishToken::new(), output)
    }

    /// [`do_final_out`](Self::do_final_out) for a worker held as `Box<dyn SignatureSigner>`. The
    /// box is consumed, and nothing is moved out of it: the worker is wiped where it sits.
    ///
    /// Only available with the `alloc` feature.
    #[cfg(feature = "alloc")]
    fn do_final_out_boxed(
        mut self: Box<Self>,
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError> {
        self.finish_signature_into(&FinishToken::new(), output)
    }

    /// Produces the signature into `output` where the worker sits: the one finishing method an
    /// implementor writes, with [`do_final_out`](Self::do_final_out)'s contract. Callable only by
    /// the provided finals; see [`FinishToken`].
    fn finish_signature_into(
        &mut self,
        token: &FinishToken,
        output: &mut [u8; SIG_LEN],
    ) -> Result<usize, SignatureError>;
}

/// The verifying half of a signature in progress: the streaming worker a verifying key hands out
/// through [`VerifyingKey`](crate::signature_key::VerifyingKey). It is a separate trait from
/// [`SignatureSigner`] so that a key, or a policy, can allow verification without signing.
pub trait SignatureVerifier: AlgorithmInfo {
    /// Absorbs the next chunk of the message. May be called any number of times with chunks of
    /// any size; a sequence of calls is equivalent to one call over the concatenation.
    fn do_update(&mut self, msg_chunk: &[u8]);

    /// Checks `sig` against the message absorbed so far. Consumes the worker.
    ///
    /// # Errors
    /// [`SignatureError::SignatureVerificationFailed`] if the signature does not verify;
    /// [`SignatureError::LengthError`] if `sig` is not the algorithm's signature length.
    fn do_verify_final(mut self, sig: &[u8]) -> Result<(), SignatureError>
    where
        Self: Sized,
    {
        self.finish_signature_verify(&FinishToken::new(), sig)
    }

    /// [`do_verify_final`](Self::do_verify_final) for a worker held as
    /// `Box<dyn SignatureVerifier>`. The box is consumed, and nothing is moved out of it.
    ///
    /// Only available with the `alloc` feature.
    #[cfg(feature = "alloc")]
    fn do_verify_final_boxed(mut self: Box<Self>, sig: &[u8]) -> Result<(), SignatureError> {
        self.finish_signature_verify(&FinishToken::new(), sig)
    }

    /// Checks `sig` where the worker sits: the one finishing method an implementor writes, with
    /// [`do_verify_final`](Self::do_verify_final)'s contract. Callable only by the provided
    /// finals; see [`FinishToken`].
    fn finish_signature_verify(
        &mut self,
        token: &FinishToken,
        sig: &[u8],
    ) -> Result<(), SignatureError>;
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
/// but it MUST NOT include a serialized private key. A keyed worker (a MAC, a cipher, HKDF with
/// its salt) does not suspend: it could not be rebuilt without the key, and its state is
/// key-derived material in any case. A message in progress is paused by holding the worker, and a
/// new one comes from the key object.
pub trait Suspendable<const SERIALIZED_STATE_LEN: usize>: Sized {
    /// Suspend operation by serializing out the state of the object.
    ///
    /// Note that this consumes `self` to prevent accidentally continuing to use the object after serialization.
    /// The state is bytes, so nothing stops a caller resuming it twice; two objects resumed from
    /// one checkpoint continue identically. Treat a checkpoint as single-use.
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

/// The decryption half of a symmetric cipher's arbitrary-length API. See
/// [`SymmetricCipherEncryptor`] for the shape of the API and the meaning of `FINAL_LEN`; this is
/// its mirror image, and the two are implemented by paired types.
///
/// Decryption is not the exact mirror of encryption in one respect: the last `FINAL_LEN` bytes a
/// decryptor releases may be only partly data. A padding scheme's final block carries
/// `data_len < BLOCK_LEN` bytes of plaintext and the rest padding, and an authenticated cipher may
/// release nothing at all once it has checked the tag. So
/// [`do_decrypt_final_out`](Self::do_decrypt_final_out) returns how much of the final buffer is
/// data, and the one-shot length helper is an upper bound rather than an exact count.
///
/// The one-shots are the key's, provided over these streaming methods. An implementor writes
/// only [`update_out_len`](Self::do_decrypt_out_len), [`do_update_out`](Self::do_decrypt_out),
/// [`finish_decrypt_into`](Self::finish_decrypt_into) and
/// [`decrypt_out_len`](Self::decrypt_out_len); the constructor is the key's, and never part of
/// the trait.
pub trait SymmetricCipherDecryptor<const INIT_DATA_LEN: usize, const FINAL_LEN: usize>:
    AlgorithmInfo
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
    /// of `ciphertext` was held back. Only available with the `alloc` feature.
    ///
    /// # Errors
    /// As [`do_decrypt_out`](Self::do_decrypt_out), except that the buffer is always large enough.
    #[cfg(feature = "alloc")]
    fn do_decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, SymmetricCipherError> {
        let needed = self.do_decrypt_out_len(ciphertext.len());
        let mut plaintext = vec![0u8; needed];
        let written = self.do_decrypt_out(ciphertext, &mut plaintext)?;
        debug_assert_eq!(written, needed);
        Ok(plaintext)
    }

    /// Finishes the decryption, consuming the decryptor: processes whatever was held back, checks
    /// it -- padding, tag -- and writes the plaintext part of the final buffer into `plaintext`.
    /// Returns the number of bytes written. The entire output buffer is zeroized before the
    /// plaintext is written, so any bytes past that count will be 0, and it is left zeroized on
    /// every error.
    ///
    /// # Errors
    /// [`SymmetricCipherError::DataNotBlockAligned`] if a block cipher's ciphertext was not a whole
    /// number of blocks; [`SymmetricCipherError::DecryptionFailed`] if it was otherwise malformed
    /// (empty, or not the length an implementor's type fixes);
    /// [`SymmetricCipherError::PaddingError`] or
    /// [`SymmetricCipherError::AEADTagCheckFailed`] if the check fails. In every error case the
    /// caller learns only that decryption failed, not where.
    fn do_decrypt_final_out(
        mut self,
        plaintext: &mut [u8; FINAL_LEN],
    ) -> Result<usize, SymmetricCipherError>
    where
        Self: Sized,
    {
        zeroize_on_err(self.finish_decrypt_into(&FinishToken::new(), plaintext), plaintext)
    }

    /// [`do_decrypt_final_out`](Self::do_decrypt_final_out) for a worker held as
    /// `Box<dyn SymmetricCipherDecryptor>`. The box is consumed, and nothing is moved out of it:
    /// the worker is wiped where it sits.
    ///
    /// Only available with the `alloc` feature.
    #[cfg(feature = "alloc")]
    fn do_decrypt_final_out_boxed(
        mut self: Box<Self>,
        plaintext: &mut [u8; FINAL_LEN],
    ) -> Result<usize, SymmetricCipherError> {
        zeroize_on_err(self.finish_decrypt_into(&FinishToken::new(), plaintext), plaintext)
    }

    /// Finishes the decryption where the worker sits, writing into `out`: the one finishing
    /// method an implementor writes, with [`do_decrypt_final_out`](Self::do_decrypt_final_out)'s
    /// contract. Callable only by the provided finals; see [`FinishToken`].
    fn finish_decrypt_into(
        &mut self,
        token: &FinishToken,
        out: &mut [u8; FINAL_LEN],
    ) -> Result<usize, SymmetricCipherError>;

    /// As [`do_decrypt_final_out`](Self::do_decrypt_final_out), returning the final buffer
    /// together with the number of leading bytes of it that are plaintext; the rest is 0.
    ///
    /// The plaintext is returned by value, so the copies of it the move leaves on the stack are
    /// not wiped. [`do_decrypt_final_out`](Self::do_decrypt_final_out) writes straight into the
    /// caller's buffer and leaves no copy.
    ///
    /// # Errors
    /// As [`do_decrypt_final_out`](Self::do_decrypt_final_out).
    fn do_decrypt_final(mut self) -> Result<([u8; FINAL_LEN], usize), SymmetricCipherError>
    where
        Self: Sized,
    {
        let mut plaintext = [0u8; FINAL_LEN];
        let data_len = self.finish_decrypt_into(&FinishToken::new(), &mut plaintext)?;
        Ok((plaintext, data_len))
    }

    /// [`do_decrypt_final`](Self::do_decrypt_final) for a worker held as
    /// `Box<dyn SymmetricCipherDecryptor>`, which cannot call a method that takes `self` by
    /// value. The box is consumed, so a stored worker is finished exactly once, and nothing is
    /// moved out of it: the worker is wiped where it sits. The plaintext is returned by value, as
    /// from [`do_decrypt_final`](Self::do_decrypt_final);
    /// [`do_decrypt_final_out_boxed`](Self::do_decrypt_final_out_boxed) leaves no copy.
    ///
    /// Only available with the `alloc` feature.
    #[cfg(feature = "alloc")]
    fn do_decrypt_final_boxed(
        mut self: Box<Self>,
    ) -> Result<([u8; FINAL_LEN], usize), SymmetricCipherError> {
        let mut plaintext = [0u8; FINAL_LEN];
        let data_len = self.finish_decrypt_into(&FinishToken::new(), &mut plaintext)?;
        Ok((plaintext, data_len))
    }

    /// An upper bound on the plaintext recovered from `ciphertext_len` bytes of ciphertext, i.e.
    /// the buffer the key's `decrypt_out` requires. Exact for ciphers with no padding;
    /// for a padding scheme the exact length is only known after decryption.
    ///
    /// Not callable on a trait object: the length is a property of the type.
    fn decrypt_out_len(ciphertext_len: usize) -> usize
    where
        Self: Sized;
}

/// The encryption half of a symmetric cipher's arbitrary-length API: streaming `do_update_out` /
/// `do_encrypt_final`. The one-shots, and the constructor, are the key's.
///
/// This is the layer a caller with *data* uses, as opposed to the block-aligned
/// [`BlockCipherEncryptor`] a mode implements. Its shape is that of the padding adapters in
/// `bouncycastle_symmetric::padding`, which are its first implementors: an authenticated cipher or a stream
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
/// except the allocating [`do_encrypt`](Self::do_encrypt), which sits behind the `alloc` feature.
///
/// An implementor writes only [`update_out_len`](Self::do_encrypt_out_len),
/// [`do_update_out`](Self::do_encrypt_out),
/// [`finish_encrypt`](Self::finish_encrypt) and
/// [`encrypt_out_len`](Self::encrypt_out_len).
pub trait SymmetricCipherEncryptor<const INIT_DATA_LEN: usize, const FINAL_LEN: usize>:
    AlgorithmInfo
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
    /// of `plaintext` was buffered. Only available with the `alloc` feature.
    ///
    /// # Errors
    /// As [`do_encrypt_out`](Self::do_encrypt_out), except that the buffer is always large enough.
    #[cfg(feature = "alloc")]
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
    fn do_encrypt_final(mut self) -> Result<([u8; FINAL_LEN], usize), SymmetricCipherError>
    where
        Self: Sized,
    {
        self.finish_encrypt(&FinishToken::new())
    }

    /// [`do_encrypt_final`](Self::do_encrypt_final) for a worker held as
    /// `Box<dyn SymmetricCipherEncryptor>`, which cannot call a method that takes `self` by
    /// value. The box is consumed, so a stored worker is finished exactly once, and nothing is
    /// moved out of it: the worker is wiped where it sits.
    ///
    /// Only available with the `alloc` feature.
    #[cfg(feature = "alloc")]
    fn do_encrypt_final_boxed(
        mut self: Box<Self>,
    ) -> Result<([u8; FINAL_LEN], usize), SymmetricCipherError> {
        self.finish_encrypt(&FinishToken::new())
    }

    /// Finishes the encryption where the worker sits: the one finishing method an implementor
    /// writes, with [`do_encrypt_final`](Self::do_encrypt_final)'s contract. Callable only by
    /// the provided finals; see [`FinishToken`].
    fn finish_encrypt(
        &mut self,
        token: &FinishToken,
    ) -> Result<([u8; FINAL_LEN], usize), SymmetricCipherError>;

    /// As [`do_encrypt_final`](Self::do_encrypt_final), writing the output part of the final
    /// buffer into `ciphertext`. Returns the number of bytes written. The entire output buffer is
    /// zeroized before the ciphertext is written, so any bytes past that count will be 0.
    fn do_encrypt_final_out(
        mut self,
        ciphertext: &mut [u8; FINAL_LEN],
    ) -> Result<usize, SymmetricCipherError>
    where
        Self: Sized,
    {
        ciphertext.fill(0);
        let (buffer, out_len) = self.finish_encrypt(&FinishToken::new())?;
        ciphertext[..out_len].copy_from_slice(&buffer[..out_len]);
        Ok(out_len)
    }

    /// The exact ciphertext length for a `plaintext_len`-byte plaintext that the cipher accepts,
    /// i.e. the buffer the key's `encrypt_out` requires and the number of bytes it writes. (A length the cipher rejects -- unaligned data under a scheme that adds no padding --
    /// fails in [`do_encrypt_final`](Self::do_encrypt_final) instead.)
    ///
    /// Not callable on a trait object: the length is a property of the type.
    fn encrypt_out_len(plaintext_len: usize) -> usize
    where
        Self: Sized;
}

/// The squeezing phase of an [`XOF`]: a value that produces output and can no longer take input,
/// as a typestate object. This is the type [`XOF::into_squeezer`] hands back.
///
/// Output is one continuous stream: successive calls continue where the last left off, so reading
/// 16 bytes twice gives the same 32 bytes as reading 32 once.
///
/// [`do_output_final`](Self::do_output_final) means something weaker than `do_final` does on
/// [`Hash`] and [`MACGenerator`]. There it is load-bearing -- the only way to get output, and it must
/// consume the value because finalizing pads the state. An XOF squeeze has nothing to finalize, so
/// it produces the bytes [`do_output`](Self::do_output) would and differs in taking ownership: it
/// is how a caller says "this read is my last", and it ends the stream at the point of the call
/// rather than leaving a `mut` binding alive for the rest of the scope. The exception is an XOF
/// that encodes its output length, as SP 800-185's KMACXOF, TupleHashXOF and ParallelHashXOF do:
/// there a final read that is also the first binds its length, and so differs from the stream.
pub trait XOFSqueezer {
    /// Produces the next `num_bytes` bytes of the output stream.
    ///
    /// Provided over [`do_output_out`](Self::do_output_out). Only available with the `alloc`
    /// feature.
    #[cfg(feature = "alloc")]
    fn do_output(&mut self, num_bytes: usize) -> Vec<u8> {
        let mut out = vec![0u8; num_bytes];
        self.do_output_out(&mut out);
        out
    }

    /// As [`do_output`](Self::do_output), filling the caller's buffer, which is zeroized first.
    /// Returns the number of bytes written.
    fn do_output_out(&mut self, output: &mut [u8]) -> usize;

    /// Produces the last `num_bytes` bytes of the output stream and ends the object.
    ///
    /// Consumes self, so this must be the final call to this object. Provided over
    /// [`do_output_final_out`](Self::do_output_final_out).
    ///
    /// Only available with the `alloc` feature.
    #[cfg(feature = "alloc")]
    fn do_output_final(self, num_bytes: usize) -> Vec<u8>
    where
        Self: Sized,
    {
        let mut out = vec![0u8; num_bytes];
        self.do_output_final_out(&mut out);
        out
    }

    /// As [`do_output_final`](Self::do_output_final), filling the caller's buffer, which is
    /// zeroized first. Returns the number of bytes written.
    ///
    /// The default is a plain last read -- the bytes [`do_output_out`](Self::do_output_out)
    /// would give, continuing from wherever earlier reads left the stream. An implementation with
    /// an output length still to bind overrides it to bind `output.len()` when nothing has been
    /// read yet, as the trait docs describe.
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

    /// Ends the input where the value sits and makes the final read of `output.len()` bytes, the
    /// bytes [`into_squeezer`](Self::into_squeezer) and then
    /// [`XOFSqueezer::do_output_final_out`] would give: the one method an implementor writes for
    /// the one-shots, which are provided over it. `output` is zeroized first; returns the number
    /// of bytes written. Callable only by those one-shots; see [`FinishToken`].
    fn finish_xof_into(&mut self, token: &FinishToken, output: &mut [u8]) -> usize;

    /// One-shot: absorbs `data` and produces `result_len` bytes.
    ///
    /// A one-shot names its length and never comes back, so this is
    /// [`XOFSqueezer::do_output_final`]'s reading of the stream, not
    /// [`do_output`](XOFSqueezer::do_output)'s: where an implementation binds the length it is
    /// asked for, this binds `result_len`. For SHAKE and cSHAKE the two are the same bytes.
    ///
    /// Provided over [`finish_xof_into`](Self::finish_xof_into), so the value that has absorbed
    /// `data` is finished where it sits, not moved into a squeezer.
    ///
    /// Only available with the `alloc` feature.
    #[cfg(feature = "alloc")]
    fn xof(mut self, data: &[u8], result_len: usize) -> Vec<u8>
    where
        Self: Sized,
    {
        self.do_update(data);
        let mut output = vec![0u8; result_len];
        self.finish_xof_into(&FinishToken::new(), &mut output);
        output
    }

    /// One-shot: absorbs `data` and fills `output`, which is zeroized first. Returns the number of
    /// bytes written.
    ///
    /// A final read of `output.len()` bytes, provided as [`xof`](Self::xof) is.
    fn xof_out(mut self, data: &[u8], output: &mut [u8]) -> usize
    where
        Self: Sized,
    {
        self.do_update(data);
        self.finish_xof_into(&FinishToken::new(), output)
    }
}

/// Zeroizes `out` if `result` is an error, behind the `finish_` method that should already have:
/// a decrypting final releases nothing on failure even from an implementor that left data there.
fn zeroize_on_err<T, E>(result: Result<T, E>, out: &mut [u8]) -> Result<T, E> {
    if result.is_err() {
        out.fill(0);
    }
    result
}
