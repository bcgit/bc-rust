//! Provides simplified abstracted APIs over classes of cryptigraphic primitives, such as Hash, KDF, etc.

use std::fmt::{Debug, Display};
use crate::errors::{HashError, KDFError, MACError, RNGError, SignatureError};
pub use crate::key_material::KeyMaterial;

// Imports needed for docs
#[allow(unused_imports)]
use crate::key_material::KeyMaterialSized;
#[allow(unused_imports)]
use crate::key_material::KeyType;
// end of imports needed for docs

pub trait Algorithm {
    const ALG_NAME: &'static str;
    const MAX_SECURITY_STRENGTH: SecurityStrength;
}

pub trait Hash : Default {
    /// The size of the internal block in bits -- needed by functions such as HMAC to compute security parameters.
    fn block_bitlen(&self) -> usize;

    /// The size of the output in bytes.
    fn output_len(&self) -> usize;

    /// A static one-shot API that hashes the provided data.
    /// `data` can be of any length, including zero bytes.
    fn hash(self, data: &[u8]) -> Vec<u8>;

    /// A static one-shot API that hashes the provided data into the provided output slice.
    /// `data` can be of any length, including zero bytes.
    /// The return value is the number of bytes written.
    fn hash_out(self, data: &[u8], output: &mut [u8]) -> usize;

    /// Provide a chunk of data to be absorbed into the hashes.
    /// `data` can be of any length, including zero bytes.
    /// do_update() is intended to be used as part of a streaming interface, and so may by called multiple times.
    // fn do_update(&mut self, data: &[u8]) -> Result<(), HashError>;
    fn do_update(&mut self, data: &[u8]);

    /// Finish absorbing input and produce the hashes output.
    /// Consumes self, so this must be the final call to this object.
    // fn do_final(self) -> Result<Vec<u8>, HashError>;
    fn do_final(self) -> Vec<u8>;

    /// Finish absorbing input and produce the hashes output.
    /// Consumes self, so this must be the final call to this object.
    ///
    /// If the provided buffer is smaller than the hash's output length, the output will be truncated.
    /// If the provided buffor is larger than the hash's output length, the output  will be placed in
    /// the first [Hash::output_len] bytes.
    ///
    /// The return value is the number of bytes written.
    fn do_final_out(self, output: &mut [u8]) -> usize;

    /// The same as [Hash::do_final], but allows for supplying a partial byte as the last input.
    /// Assumes that the input is in the least significant bits (big endian).
    fn do_final_partial_bits(
        self,
        partial_byte: u8,
        num_partial_bits: usize,
    ) -> Result<Vec<u8>, HashError>;

    /// The same as [Hash::do_final_out], but allows for supplying a partial byte as the last input.
    /// Assumes that the input is in the least significant bits (big endian).
    /// will be placed in the first [Hash::output_len] bytes.
    /// The return value is the number of bytes written.
    fn do_final_partial_bits_out(
        self,
        partial_byte: u8,
        num_partial_bits: usize,
        output: &mut [u8],
    ) -> Result<usize, HashError>;

    /// Returns the maximum security strength that this KDF is capable of supporting, based on the underlying primitives.
    fn max_security_strength(&self) -> SecurityStrength;
}

pub trait HashAlgParams: Algorithm {
    const OUTPUT_LEN: usize;
    const BLOCK_LEN: usize;
}

/// A Key Derivation Function (KDF) is a function that takes in one or more input key and some unstructured
/// additional input, and uses them to produces a derived key.
pub trait KDF : Default {
    /// Implementations of this function are capable of deriving an output key from an input key,
    /// assuming that they have been properly initialized.
    ///
    /// # Entropy Conversion rules
    /// Implementations SHOULD act on a KeyMaterial of any [KeyType] and will generally
    /// return a KeyMaterial of the same type
    ///
    /// ex.:
    ///
    ///   * [KeyType::BytesLowEntropy] -> [KeyType::BytesLowEntropy])
    ///   * [KeyType::BytesFullEntropy] -> [KeyType::BytesFullEntropy])
    ///   * [KeyType::SymmetricCipherKey] -> [KeyType::SymmetricCipherKey])
    ///
    /// If provided with an input key, even if it is [KeyType::BytesFullEntropy], but that
    /// contains less key material than the internal block size of the KDF, then the KDF
    /// will not be considered properly seeded, and the output [KeyMaterialSized] will be set to
    /// [KeyType::BytesLowEntropy] -- for example, seeding SHA3-256 with a [KeyMaterialSized] containing
    /// only 128 bits of key material.
    ///
    /// An implement can, and in most cases SHOULD, return a [HashError] if provided
    /// with a [KeyMaterialSized] of type [KeyType::Zeroized].
    ///
    /// # Additional Input
    /// The `additional_input` parameter is used in deriving the key, but is not credited with any entropy,
    /// and therefore does not affect the type of the output [KeyMaterialSized].
    /// This corresponds directly to `FixedInfo` as defined in NIST SP 800-56C.
    /// The `additional_input` parameter can be empty by passing in `&[0u8; 0]`.
    ///
    /// Output length: this function will create a KeyMaterial populated with the default output length
    /// of the underlying hash primitive.
    fn derive_key(
        self,
        key: &impl KeyMaterial,
        additional_input: &[u8],
    ) -> Result<Box<dyn KeyMaterial>, KDFError>;

    /// Same as [KDF::derive_key], but fills the provided output [KeyMaterialSized].
    ///
    /// Output length: this function will behave differently depending on the underlying hash primitive;
    /// some, such as SHA2 or SHA3 will produce a fixed-length output, while others, such as SHAKE or HKDF,
    /// will fill the provided KeyMaterial to capacity and require you to truncate it afterwards
    /// using [KeyMaterial::truncate].
    fn derive_key_out(
        self,
        key: &impl KeyMaterial,
        additional_input: &[u8],
        output_key: &mut impl KeyMaterial,
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
    /// Implementations can, and in most cases SHOULD, return a [KeyMaterialSized] of the same type as the
    /// strongest key, and SHOULD throw a [HashError] if all input keys are zeroized.
    /// For example output a [KeyType::BytesFullEntropy] key whenever any one of
    /// the input keys is a [KeyType::BytesFullEntropy] key.
    /// As another example, combining a [KeyType::BytesLowEntropy] key with a [KeyType::MACKey] key
    /// should return a [KeyType::MACKey].
    ///
    /// Output length: this function will create a KeyMaterial populated with the default output length
    /// of the underlying hash primitive.
    fn derive_key_from_multiple(
        self,
        keys: &[&impl KeyMaterial],
        additional_input: &[u8],
    ) -> Result<Box<dyn KeyMaterial>, KDFError>;

    /// Same as [KDF::derive_key], but fills the provided output [KeyMaterialSized].
    ///
    /// Output length: this function will behave differently depending on the underlying hash primitive;
    /// some, such as SHA2 or SHA3 will produce a fixed-length output, while others, such as SHAKE or HKDF,
    /// will fill the provided KeyMaterial to capacity and require you to truncate it afterwards
    /// by using [KeyMaterial::truncate].
    fn derive_key_from_multiple_out(
        self,
        keys: &[&impl KeyMaterial],
        additional_input: &[u8],
        output_key: &mut impl KeyMaterial,
    ) -> Result<usize, KDFError>;

    /// Returns the maximum security strength that this KDF is capable of supporting, based on the underlying primitives.
    fn max_security_strength(&self) -> SecurityStrength;
}

/// A Message Authentication Code algorithm is a keyed hash function that behaves somewhat like a symmetric signature function.
/// A MAC algorithm takes in a key and some data, and produces a MAC (message authentication code) that
/// can be used to verify the integrity of data.
///
/// This trait provides one-shot functions [MAC::mac], [MAC::mac_out], and [MAC::verify].
/// It also provides streaming functions [MAC::do_update], [MAC::do_final], [MAC::do_final_out],
/// and [MAC::do_verify_final].
/// The workflow is that a MAC object is initialized with a key with [MAC::new] -- or [MAC::new_allow_weak_key] if you
/// need to disable the library's safety mechanism to prevent the use of weak keys -- then data is
/// processed into one or more calls to [MAC::do_update],
/// after that the object can either create a MAC with [MAC::do_final] or [MAC::do_final_out] (which are final functions, and so consume the object),
/// or the object can be used to verify a MAC.
///
/// For varifying an existing MAC, it is functionally equivalent to use the provided [MAC::verify] and [MAC::do_verify_final]
/// function or to compute a new MAC and compare it to the existing MAC, however the provided verification functions
/// use constant-time comparison to avoid cryptographic timing attacks whereby an attacker could learn
/// the bytes of the MAC value under some conditions. Therefore, it is highly recommended to use the provided verification functions.
///
/// Note that the MAC key is not represented in this trait because it is provided to the MAC algorithm
/// as part of its new functions.
///
/// MACs do not implement Default because they do not have a sensible no-args constructor.
pub trait MAC: Sized {

    /// Create a new MAC instance with the given key.
    ///
    /// This is a common constructor whether creating or verifying a MAC value.
    ///
    /// Key / Salt is optional, which is indicated by providing an uninitialized KeyMaterial object of length zero,
    /// the capacity is irrelevant, so KeyMateriol256::new() or KeyMaterial_internal::<0>::new() would both count as an absent salt.
    ///
    /// # Note about the security strength of the provided key:
    /// If you initialize the MAC with a key that is tagged at a lower [SecurityStrength] than the
    /// underlying hash function then [MAC::new] will fail with the following error:
    /// ```text
    /// MACError::KeyMaterialError(KeyMaterialError::SecurityStrength("HMAC::init(): provided key has a lower security strength than the instantiated HMAC")
    /// ```
    /// There are situations in which it is completely reasonable and secure to provide low-entropy
    /// (and sometimes all-zero) keys / salts; for these cases we have provided [MAC::new_allow_weak_key].
    fn new(key: &impl KeyMaterial) -> Result<Self, MACError>;

    /// Create a new HMAC instance with the given key.
    ///
    /// This constructor completely ignores the [SecurityStrength] tag on the input key and will "just work".
    /// This should be used if you really do need to use a weak key, such as an all-zero salt,
    /// but use of this constructor is discouraged and you should really be asking yourself why you need it;
    /// in most cases it indicates that your key is not long enough to support the security level of this
    /// HMAC instance, or the key was derived using algorithms at a lower security level, etc.
    fn new_allow_weak_key(key: &impl KeyMaterial) -> Result<Self, MACError>;

    /// The size of the output in bytes.
    fn output_len(&self) -> usize;

    /// One-shot API that computes a MAC for the provided data.
    /// `data` can be of any length, including zero bytes.
    ///
    /// Note about the security strength of the provided key:
    /// If the provided key is tagged at a lower [SecurityStrength] than the instantiated MAC algorithm,
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
    /// to see conditions under which it throws [MACError::InvalidLength].
    fn mac_out(self, data: &[u8],out: &mut [u8]) -> Result<usize, MACError>;

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

    fn do_final(self) -> Vec<u8>;

    /// Depending on the underlying MAC implementation, NIST may require that the library enforce
    /// a minimum length on the mac output value. See documentation for the underlying implementation
    /// to see conditions under which it throws [MACError::InvalidLength].
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

#[derive(Eq, PartialEq, PartialOrd, Clone, Debug)]
pub enum SecurityStrength {
    None,
    _112bit,
    _128bit,
    _192bit,
    _256bit,
}

impl SecurityStrength {
    /// Rounds down to the closest supported security strength.
    /// For example, 120-bits is rounded down to 112-bit.
    pub fn from_bits(bits: usize) -> Self {
        if bits < 112 {
            Self::None
        } else if bits < 128 {
            Self::_112bit
        } else if bits < 192 {
            Self::_128bit
        } else if bits < 256 {
            Self::_192bit
        } else {
            Self::_256bit
        }
    }

    pub fn from_bytes(bytes: usize) -> Self {
        Self::from_bits(bytes * 8)
    }

    pub fn as_int(&self) -> u32 {
        match self {
            Self::None => 0,
            Self::_112bit => 112,
            Self::_128bit => 128,
            Self::_192bit => 192,
            Self::_256bit => 256,
        }
    }
}

/// An interface for random number generation.
/// This interface is meant to be simpler and more ergonomic than the interfaces provided by the
/// `rng` crate, but that one should
/// be used by applications that intend to submit to FIPS certification as it more closely aligns with the
/// requirements of SP 800-90A.
/// Note: this interface produces bytes. If you want a [KeyMaterial], then use [KeyMaterialSized::from_rng].
pub trait RNG : Default {
    // TODO: add back once we figure out streaming interaction with entropy sources.
    // fn add_seed_bytes(&mut self, additional_seed: &[u8]) -> Result<(), RNGError>;

    fn add_seed_keymaterial(&mut self, additional_seed: impl KeyMaterial) -> Result<(), RNGError>;
    fn next_int(&mut self) -> Result<u32, RNGError>;

    /// Returns the number of requested bytes.
    fn next_bytes(&mut self, len: usize) -> Result<Vec<u8>, RNGError>;

    /// Returns the number of bytes written.
    fn next_bytes_out(&mut self, out: &mut [u8]) -> Result<usize, RNGError>;

    fn fill_keymaterial_out(&mut self, out: &mut impl KeyMaterial) -> Result<usize, RNGError>;

    /// Returns the Security Strength of this RNG.
    fn security_strength(&self) -> SecurityStrength;
}

/// A trait that forces an object to implement a zeroizing Drop() as well as Debug and Display that
/// will not log the sensitive contents, even in error or crash-dump scenarios.
#[allow(drop_bounds)] // Since rust auto-implements Drop, there's a lint that explicitly bounding on Drop is useless.
                      // I disagree because I want to force things that are secrets to manually implement Drop that zeroizes the data.
                      // So I'm turning off this lint.
pub trait Secret : Drop + Debug + Display {}

/// Pre-Hashed Signature is mostly a mirror of the [Signature] trait, but it applies to signature
/// algorithms that can accept a pre-hashed message instead of the full message, and therefore the
/// public API of a PHSigsature is slightly different.
///
/// A PHSignature algorithm can also be used like a normal signature algorithm via the usual [PHSignature::sign] and [PHSignature::verify] functions.
///
/// This trait appears simpler than [Signature] because it does not have streaming modes; and that's the whole point!
/// Instead of handling streaming on the signature primitive, you get to use an external hash function.
/// Just be careful to use the same hash function that the signature primitive is expecting you to use.
/// (with great power comes great responsibility)
pub trait PHSignature<PK: SignaturePublicKey, SK: SignaturePrivateKey, const PH_LEN: usize>: Sized {
    /// Generate a keypair.
    /// Error condition: Basically only on RNG failures
    fn keygen() -> Result<(PK, SK), SignatureError>;

    /// Produce a signature for the provided full message and context.
    /// Even though this interface accepts the full message, it will pre-hash it internally so that
    /// the signature produced is compatible with a ph_verify.
    ///
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
    fn sign(sk: &SK, msg: &[u8], ctx: Option<&[u8]>) -> Result<Vec<u8>, SignatureError>;

    /// Returns the number of bytes written to the output buffer. Can be called with an oversized buffer.
    fn sign_out(sk: &SK, msg: &[u8], ctx: Option<&[u8]>, output: &mut [u8]) -> Result<usize, SignatureError>;

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
    fn sign_ph(sk: &SK, ph: &[u8; PH_LEN], ctx: Option<&[u8]>) -> Result<Vec<u8>, SignatureError>;

    /// Returns the number of bytes written to the output buffer. Can be called with an oversized buffer.
    fn sign_ph_out(sk: &SK, ph: &[u8; PH_LEN], ctx: Option<&[u8]>, output: &mut [u8]) -> Result<usize, SignatureError>;

    /// On success, returns Ok(())
    /// On failure, returns Err([SignatureError::SignatureVerificationFailed]); may also return other types of [SignatureError] as appropriate (such as for invalid-length inputs).
    fn verify(pk: &PK, msg: &[u8], ctx: Option<&[u8]>, sig: &[u8]) -> Result<(), SignatureError>;

    /// On success, returns Ok(())
    /// On failure, returns Err([SignatureError::SignatureVerificationFailed]); may also return other types of [SignatureError] as appropriate (such as for invalid-length inputs).
    fn verify_ph(pk: &PK, ph: &[u8; PH_LEN], ctx: Option<&[u8]>, sig: &[u8]) -> Result<(), SignatureError>;
}

/// A digital signature algorithm is defined as a set of three operations:
/// key generation, signing, and verification.
///
/// To avoid the use of dyn, this trait does not include key generation; you'll have to consult the
/// documentation for the underlying signature primitive for how to generate a key pair.
///
/// This high-level trait defines the operations over a generic signature algorithm that is assumed
/// to source all its randomness from bouncycastle's default os-backed RNG.
/// The underlying signature primitives will expose APIs that allow for specifying a specific RNG
/// or deterministic seed values.
// Note to future maintainers: this could have had a SIG_LEN a param and then done [u8; SIG_LEN] throughout and removed a whole bunch of Results,
// but in general there exist signature algs with non-fixed-length signature values.
pub trait Signature<PK: SignaturePublicKey, SK: SignaturePrivateKey>: Sized {
    /// Generate a keypair.
    /// Error condition: Basically only on RNG failures
    fn keygen() -> Result<(PK, SK), SignatureError>;

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
    fn sign(sk: &SK, msg: &[u8], ctx: Option<&[u8]>) -> Result<Vec<u8>, SignatureError>;

    /// Returns the number of bytes written to the output buffer. Can be called with an oversized buffer.
    fn sign_out(sk: &SK, msg: &[u8], ctx: Option<&[u8]>, output: &mut [u8]) -> Result<usize, SignatureError>;

    /* streaming signing API */
    /// Initialize a signer for streaming mode with the provided private key.
    fn sign_init(sk: &SK, ctx: Option<&[u8]>) -> Result<Self, SignatureError>;

    fn sign_update(&mut self, msg_chunk: &[u8]);

    /// Complete the signing operation. Consumes self.
    fn sign_final(self) -> Result<Vec<u8>, SignatureError>;

    /// Returns the number of bytes written to the output buffer. Can be called with an oversized buffer.
    fn sign_final_out(self, output: &mut [u8]) -> Result<usize, SignatureError>;

    /// On success, returns Ok(())
    /// On failure, returns Err([SignatureError::SignatureVerificationFailed]); may also return other types of [SignatureError] as appropriate (such as for invalid-length inputs).
    fn verify(pk: &PK, msg: &[u8], ctx: Option<&[u8]>, sig: &[u8]) -> Result<(), SignatureError>;

    /* streaming verification API */
    fn verify_init(pk: &PK, ctx: Option<&[u8]>) -> Result<Self, SignatureError>;

    fn verify_update(&mut self, msg_chunk: &[u8]);

    /// On success, returns Ok(())
    /// On failure, returns Err([SignatureError::SignatureVerificationFailed]); may also return other types of [SignatureError] as appropriate (such as for invalid-length inputs).
    fn verify_final(self, sig: &[u8]) -> Result<(), SignatureError>;
}

/// A public key for a signature algorithm, often denoted "pk".
pub trait SignaturePublicKey : PartialEq + Eq + Clone + Debug + Display + Sized {
    /// Write it out to bytes in its standard encoding.
    fn encode(&self) -> Vec<u8>;

    /// Write it out to bytes in its standard encoding.
    fn encode_out(&self, out: &mut [u8]) -> Result<usize, SignatureError>;

    /// Read it in from bytes in its standard encoding.
    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError>;
}

/// A private key for a signature algorithm, often denoted "sk" (for "secret key").
pub trait SignaturePrivateKey: PartialEq + Eq + Clone + Debug + Display + Sized {
    /// Write it out to bytes in its standard encoding.
    fn encode(&self) -> Vec<u8>;

    /// Write it out to bytes in its standard encoding.
    fn encode_out(&self, out: &mut [u8]) -> Result<usize, SignatureError>;

    /// Read it in from bytes in its standard encoding.
    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError>;
}

/// Extensible Output Functions (XOFs) are similar to hash functions, except that they can produce output of arbitrary length.
/// The naming used for the functions of this trait are borrowed from the SHA3-style sponge constructions that split XOF operation
/// into two phases: an absorb phase in which an arbitrary amount of input is provided to the XOF,
/// and then a squeeze phase in which an arbitrary amount of output is extracted.
/// Once squeezing begins, no more input can be absorbed.
///
/// XOFs are _similar to_ hash functions, but are not hash functions for one technical but important reason:
/// since the amount of output to produce is not provided to the XOF in advance, it cannot be used to
/// diversify the XOF output streams.
/// In other words, the overlapping parts of their outputs will be the same!
/// For example, consider two XOFs that absorb the same input data, one that is squeezed to produce 32 bytes,
/// and the other to produce 1 kb; both outputs will be identical in their first 32 bytes.
/// This could lead to loss of security in a number of ways, for example distinguishing attacks where
/// it is sufficient for the attacker to know that two values came from the same input, even if the
/// attacker cannot learn what that input was. This is attack is often sufficient, for example,
/// to break anonymity-preserving technology.
/// Applications that require the arbitrary-length output of an XOF, but also care about these
/// distinguishing attacks should consider adding a cryptographic salt to diversify the inputs.
pub trait XOF : Default {
    /// A static one-shot API that digests the input data and produces `result_len` bytes of output.
    fn hash_xof(self, data: &[u8], result_len: usize) -> Vec<u8>;

    /// A static one-shot API that digests the input data and produces `result_len` bytes of output.
    /// Fills the provided output slice.
    fn hash_xof_out(self, data: &[u8], output: &mut [u8]) -> usize;

    fn absorb(&mut self, data: &[u8]);

    /// Switches to squeezing.
    fn absorb_last_partial_byte(
        &mut self,
        partial_byte: u8,
        num_partial_bits: usize,
    ) -> Result<(), HashError>;

    /// Can be called multiple times.
    fn squeeze(&mut self, num_bytes: usize) -> Vec<u8>;

    /// Can be called multiple times.
    /// Fills the provided output slice.
    fn squeeze_out(&mut self, output: &mut [u8]) -> usize;

    /// Squeezes a partial byte from the XOF.
    /// Output will be in the top `num_bits` bits of the returned u8 (ie Big Endian).
    /// This is a final call and consumes self.
    fn squeeze_partial_byte_final(self, num_bits: usize) -> Result<u8, HashError>;

    fn squeeze_partial_byte_final_out(
        self,
        num_bits: usize,
        output: &mut u8,
    ) -> Result<(), HashError>;

    /// Returns the maximum security strength that this KDF is capable of supporting, based on the underlying primitives.
    fn max_security_strength(&self) -> SecurityStrength;
}
