//! The generic Hash-Based Message Authentication Code (HMAC) construction, as specified in RFC 2104,
//! taking into account NIST Implementation Guidance in FIPS 140-3 IG C.L.
//!
//! This is a utility crate and is not intended to be used directly. It provides [`HmacKey`] -- the
//! key object, which holds the two precomputed pad states RFC 2104 Section 4 describes and hands
//! out workers -- and [`HMAC`] -- the worker, one per message, which borrows the key it came from
//! and generates (`HMAC<'k, H, Encrypting>`) or verifies (`HMAC<'k, H, Decrypting>`) a tag.
//! Both are generic over any struct that implements [`Hash`] and [`HMACParams`], the extension
//! point through which a hash declares the metadata from which the HMAC instance is built. The
//! library provides the following concrete instantiations of HMAC:
//!
//! | Hash family | Instantiations                                                               |
//! |-------------|------------------------------------------------------------------------------|
//! | SHA-2       | `bouncycastle_sha2::hmac` -- `HMAC_SHA224`, `HMAC_SHA256`, `HMAC_SHA384`, `HMAC_SHA512`, `HMAC_SHA512_224`, `HMAC_SHA512_256` |
//! | SHA-3       | `bouncycastle_sha3::hmac` -- `HMAC_SHA3_224`, `HMAC_SHA3_256`, `HMAC_SHA3_384`, `HMAC_SHA3_512` |
//! | SM3         | `bouncycastle_sm3::hmac` -- `HMAC_SM3`                                       |
//!
//! Although users are free to implement [`Hash`] and [`HMACParams`] for a a hash function not included with the library,
//! and will then be able to instantiate [`HMAC`] for it as well.
//!
//! # Usage Examples
//!
//! A key is built once, from key material of any length, and used for any number of messages:
//!
//! ```
//! use bouncycastle_core::symmetric_key::{FromAnyKeyMaterial, MacGenerationKey, MacVerificationKey};
//! use bouncycastle_core::traits::{MACGenerator, MACVerifier};
//! use bouncycastle_hmac::HmacKey;
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_sha2::SHA256;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let key = HmacKey::<SHA256>::generate(&mut rng).expect("a 32-byte MAC key from the RNG");
//!
//! let mut generator = key.create_generator();          // infallible, any number of times
//! generator.do_update(b"part one");
//! generator.do_update(b"part two");
//! let tag: [u8; 32] = generator.do_final();
//!
//! let mut verifier = key.create_verifier();
//! verifier.do_update(b"part onepart two");
//! assert!(verifier.do_verify_final(&tag).is_ok());
//! assert!(key.verify(b"part onepart two", &tag).is_ok());   // one-shot, same path underneath
//! ```
//!
//! # Instantiating HMAC over a Hash
//!
//! HMAC works with any hash: [`HMAC<HASH>`](HMAC) needs only [`Hash`]. What HMAC cannot
//! derive on its own is the *metadata* of the resulting construction -- the name "HMAC-SHA256" is not
//! mechanically obtainable from "SHA256", and RFC 4231 assigns each hash/HMAC combination its own OID
//! rather than deriving it from the hash's OID. Supplying that metadata is what makes an HMAC a
//! first-class algorithm in this library rather than an anonymous `HMAC<H>`.
//!
//! There are three steps, of which only the second is mandatory:
//!
//! 1. Have a hash type that implements [`Hash`] + [`HashAlgParams`] + [`Default`]. Implementing
//!    [`Hash`] is documented in `bouncycastle-core`; nothing about it is HMAC-specific.
//! 2. Implement [`HMACParams`] for that hash type, supplying the HMAC's name, claimed security
//!    strength and OID, plus `KeyMaterial<{OUTPUT_LEN}>` as the key type that
//!    [`HmacKey::keygen_from_rng`] returns, which is also what fixes the tag length of the MAC
//!    roles. This allows this crate to provide blanket [`Algorithm`], [`AlgorithmOID`] and role
//!    impls.
//! 3. Publish a type alias for the instantiation, `HMAC<SHA256, Dir>`.
//!
//! ## Worked example
//!
//! As an example, the `bouncycastle-sha2` crate follows exactly the recipe above; its entry for SHA-256 reduces to:
//!
//! ```rust,ignore
//! pub type HMAC_SHA256<'k, Dir> = HMAC<'k, SHA256, Dir>;
//!
//! impl HMACParams for SHA256 {
//!     type MACKey = KeyMaterial<{ <SHA256 as HashAlgParams>::OUTPUT_LEN }>;
//!     const HMAC_ALG_NAME: &'static str = "HMAC-SHA256";
//!     const HMAC_MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
//!     /// Defined in RFC 4231: id-hmacWithSHA256 { digestAlgorithm 9 }
//!     const HMAC_OID: &'static [u32] = &[1, 2, 840, 113549, 2, 9];
//!     const HMAC_OID_DER: &'static [u8] =
//!         &[0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09];
//! }
//! ```
//!
//! [`HMACParams`] is deliberately **not** sealed, so the same recipe works for a hash function
//! defined in any other crate. Simply follow the recipe above!
//!
//! # 🚨 Security Considerations 🚨
//!
//! These apply to every instantiation; the hash crates' `hmac` modules repeat the ones that matter
//! most in day-to-day use.
//!
//! * [`HMACParams::HMAC_MAX_SECURITY_STRENGTH`] is a claim that
//!   [`FromAnyKeyMaterial::from_key_material`] enforces against the key's tagged strength, and
//!   that [`HmacKey::keygen_from_rng`] enforces against the RNG's. Declaring a strength the
//!   underlying hash cannot support does not make the construction stronger, it just makes the
//!   check wrong. NIST SP 800-107-r1 Section 5.3.4 gives the ceiling: the effective strength is
//!   `min(strength of K, 2C)` for an internal chaining value of `C` bits.
//! * [`FromAnyKeyMaterial::from_key_material_allow_weak`] deliberately skips the key-strength
//!   check. It exists for protocols that call for a weak or all-zero key -- an all-zero HKDF salt,
//!   for example -- and should not be used to silence an error from
//!   [`FromAnyKeyMaterial::from_key_material`].
//! * Verification via [`MacVerificationKey::verify`] / [`MACVerifier::do_verify_final`] uses a
//!   constant-time comparison. Recomputing the MAC and comparing it with `==` leaks how many
//!   leading bytes matched.
//! * The tag is the hash's full output. A protocol that truncates it does so on the array it
//!   gets back and takes on the rules: RFC 2104 Section 5 recommends that the output length "be
//!   not less than half the length of the hash output ... and not less than 80 bits", and FIPS
//!   140-3 IG C.L Resolution C.4 (formerly NIST SP 800-107r1 Section 5.3.3) sets the floor at
//!   32 bits. A truncated tag cannot go through the verifier, which takes the full length.
//! * The two pad states are key-equivalent, as RFC 2104 Section 4 says ("the stored intermediate
//!   values need to be treated and protected the same as secret keys"). [`HmacKey`] and the worker
//!   hold them as hash states, which the hash crates zeroize on drop; neither has a `Debug` that
//!   prints them. The padded key block they are built from is a [`Secret`] scratch, zeroized when
//!   construction returns.
//!
//! [`Secret`]: bouncycastle_utils::secret::Secret
//! [`MacVerificationKey::verify`]: bouncycastle_core::symmetric_key::MacVerificationKey::verify
//! [`MACVerifier::do_verify_final`]: bouncycastle_core::traits::MACVerifier::do_verify_final

#![forbid(unsafe_code)]
#![forbid(missing_docs)]

pub mod hazmat;

use bouncycastle_core::direction::{Decrypting, Encrypting};
use bouncycastle_core::errors::{KeyMaterialError, MACError, RNGError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{FromAnyKeyMaterial, MacGenerationKey, MacVerificationKey};
use bouncycastle_core::traits::{
    Algorithm, AlgorithmOID, HashAlgParams, HashOneShot, MACGenerator, MACVerifier, RNG,
};
use bouncycastle_utils::{ct, secret::Secret};
use core::fmt::{Debug, Display, Formatter};
use core::marker::PhantomData;

/*** Parameters ***/

/// The HMAC-specific parameters for one underlying hash function.
///
/// [`HMAC`] itself is fully generic: it works with any [`Hash`], including hashes supplied by crates
/// outside this library. What HMAC cannot derive on its own is the *metadata* of the resulting
/// construction -- this trait supplies exactly that metadata, so the blanket [`Algorithm`], [`AlgorithmOID`] and
/// [`HmacKey::keygen_from_rng`] can be impl'd generically rather than being written out once
/// per hash.
///
/// Each hash crate is expected to implement this trait for its own hash types and publishes the resulting type
/// alias. For example,`HMAC_SHA256` lives in `bouncycastle_sha2::hmac` and `HMAC_SHA3_256` in
/// `bouncycastle_sha3::hmac`.
///
/// The block length and the generated-key length do not need to be restated here since they are already
/// carried by the hash itself as [`HashAlgParams::BLOCK_LEN`] and [`HashAlgParams::OUTPUT_LEN`].
pub trait HMACParams: HashOneShot + HashAlgParams + Clone {
    /// The key type produced by [`HmacKey::keygen_from_rng`] and drawn by
    /// [`FromAnyKeyMaterial::generate`], sized to this hash's output length, which is also the
    /// tag length: the MAC role impls are generic over `N` and bound on
    /// `MACKey = KeyMaterial<N>`, which is how the output length reaches a const parameter.
    ///
    /// Implementors must set this to `KeyMaterial<{Self::OUTPUT_LEN}>`; any other length fails to
    /// compile at the first tag. The check is evaluated when the worker's `finish` is
    /// monomorphised, so `cargo build` and `cargo test` report it and `cargo check` does not.
    ///
    // todo: once rust stabilizes generic_const_exprs, delete this and use
    //     `Self::OUTPUT_LEN` as the role impls' MAC_LEN instead.
    type MACKey: KeyMaterialTrait + Default;

    /// The name of the HMAC over this hash, as reported by [`Algorithm::ALG_NAME`].
    const HMAC_ALG_NAME: &'static str;
    /// The name of HKDF (RFC 5869) over this hash, as reported by `bouncycastle_hkdf::HKDF`'s
    /// [`Algorithm::ALG_NAME`].
    const HKDF_ALG_NAME: &'static str;
    /// The strength claimed by the HMAC over this hash, as reported by
    /// [`Algorithm::MAX_SECURITY_STRENGTH`].
    const HMAC_MAX_SECURITY_STRENGTH: SecurityStrength;
    /// The OID of the HMAC over this hash in component form, as reported by [`AlgorithmOID::OID`].
    const HMAC_OID: &'static [u32];
    /// The DER encoding of [`HMACParams::HMAC_OID`], as reported by [`AlgorithmOID::OID_DER`].
    const HMAC_OID_DER: &'static [u8];
}

impl<HASH: HMACParams, Dir> Algorithm for HMAC<'_, HASH, Dir> {
    const ALG_NAME: &'static str = HASH::HMAC_ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = HASH::HMAC_MAX_SECURITY_STRENGTH;
}

impl<HASH: HMACParams, Dir> AlgorithmOID for HMAC<'_, HASH, Dir> {
    const OID: &'static [u32] = HASH::HMAC_OID;
    const OID_DER: &'static [u8] = HASH::HMAC_OID_DER;
}

/// The largest block length, in bytes, of any hash HMAC is instantiated with (SHA3-224's 144).
///
/// The scratch the pad blocks are built in must hold one block of the underlying hash: per RFC 2104
/// Section 2 step (1) the key is zero-padded to B bytes, and only a key longer than B is pre-hashed
/// first (Section 3). The scratch is sliced to the hash's own block. HKDF sizes the MAC-key copies
/// it hands this crate from the same constant.
pub const LARGEST_HASHER_BLOCK_LEN: usize = 144;

/// The largest output length across the supported hashes (SHA-512, SHA3-512), which sizes the key
/// [`FromAnyKeyMaterial::generate`] draws before trimming it to the hash's own output length, and
/// the scratch the inner digest is finished into.
const LARGEST_HASHER_OUTPUT_LEN: usize = 64;

/*** Key ***/

/// An HMAC key: the two intermediate hash states of RFC 2104 Section 4, `H` after absorbing
/// `K XOR ipad` and after absorbing `K XOR opad`, computed once from key material of any length.
///
/// Every worker the key hands out starts from a clone of the inner state and borrows the key for
/// the outer one, so the per-message cost of the key is one clone and no hashing. The key holds
/// no key bytes: a caller who needs the material again keeps the `KeyMaterial`. Construction is
/// [`FromAnyKeyMaterial`]; the workers come from [`MacGenerationKey`] and [`MacVerificationKey`],
/// whose tag length is the hash's output length.
pub struct HmacKey<HASH: HMACParams> {
    /// `H` after absorbing `K XOR ipad`: the start of RFC 2104 Section 2 step (4).
    inner: HASH,
    /// `H` after absorbing `K XOR opad`: the start of step (7).
    outer: HASH,
}

// `Clone` is written out rather than derived so that it has no bound beyond the struct's own.
impl<HASH: HMACParams> Clone for HmacKey<HASH> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone(), outer: self.outer.clone() }
    }
}

impl<HASH: HMACParams> HmacKey<HASH> {
    /// RFC 2104 Section 2 steps (1), (2) and (5), plus Section 3's pre-hash of a key longer than
    /// the block, with both pad blocks absorbed so that the states are ready for steps (4) and (7).
    /// No key checks: the callers do those.
    fn from_key_bytes(key_bytes: &[u8]) -> Self {
        // The pad scratch and the output scratch are sized for the library's hashes; a foreign
        // `HMACParams` hash past either bound is a compile error, not a panic at the first key.
        const { assert!(HASH::BLOCK_LEN <= LARGEST_HASHER_BLOCK_LEN) };
        const { assert!(HASH::OUTPUT_LEN <= LARGEST_HASHER_OUTPUT_LEN) };
        let block_len = HASH::BLOCK_LEN;

        // Step (1): "append zeros to the end of K to create a B byte string". The scratch is
        // already zero, so only K (or, per Section 3, H(K) when K is "longer than B bytes") is
        // written.
        let mut k: Secret<[u8; LARGEST_HASHER_BLOCK_LEN]> = Secret::new();
        if key_bytes.len() > block_len {
            let output_len = HASH::default().output_len();
            HASH::hash_out(key_bytes, &mut k[..output_len]);
        } else {
            k[..key_bytes.len()].copy_from_slice(key_bytes);
        }

        // Step (2): "XOR ... the B byte string computed in step (1) with ipad", absorbed into the
        // inner hash; step (5): the same with opad, absorbed into the outer hash. Section 4: these
        // two block compressions are what the key saves on every message.
        let mut inner = HASH::default();
        let mut outer = HASH::default();
        for byte in k[..block_len].iter_mut() {
            *byte ^= IPAD_BYTE;
        }
        inner.do_update(&k[..block_len]);
        for byte in k[..block_len].iter_mut() {
            *byte ^= IPAD_BYTE ^ OPAD_BYTE; // undo ipad, apply opad
        }
        outer.do_update(&k[..block_len]);

        Self { inner, outer }
    }

    /// The key-type check and, unless `allow_weak_keys`, the strength check, then the pads.
    fn from_key_material_checked(
        key: &dyn KeyMaterialTrait,
        allow_weak_keys: bool,
    ) -> Result<Self, MACError> {
        if !(key.key_type() == KeyType::Zeroized || key.key_type() == KeyType::MACKey) {
            return Err(MACError::KeyMaterialError(KeyMaterialError::InvalidKeyType(
                "Key type must be a MAC key.",
            )));
        }
        if !allow_weak_keys && key.security_strength() < HASH::MAX_SECURITY_STRENGTH {
            return Err(MACError::KeyMaterialError(KeyMaterialError::SecurityStrength(
                "HmacKey: provided key has a lower security strength than the instantiated HMAC",
            )));
        }
        Ok(Self::from_key_bytes(key.ref_to_bytes()))
    }

    /// Generates a fresh key for this HMAC from `rng`: [`HMACParams::MACKey`] bytes (the hash's
    /// output length), tagged [`KeyType::MACKey`]. [`FromAnyKeyMaterial::generate`] draws the
    /// same key and builds the key object from it in one step.
    ///
    /// # Errors
    /// [`RNGError::SecurityStrengthInsufficientForAlgorithm`] if `rng` is instantiated below
    /// [`HMACParams::HMAC_MAX_SECURITY_STRENGTH`], or whatever the RNG returns.
    pub fn keygen_from_rng(rng: &mut dyn RNG) -> Result<HASH::MACKey, RNGError> {
        if rng.security_strength() < HASH::HMAC_MAX_SECURITY_STRENGTH {
            return Err(RNGError::SecurityStrengthInsufficientForAlgorithm);
        }
        let mut key = HASH::MACKey::default();
        rng.fill_keymaterial_out(&mut key)?;
        key.set_key_type(KeyType::MACKey)?;
        Ok(key)
    }
}

impl<HASH: HMACParams> FromAnyKeyMaterial for HmacKey<HASH> {
    /// Builds the key from material tagged [`KeyType::MACKey`] (or [`KeyType::Zeroized`], for an
    /// all-zero key) whose security strength is at least the HMAC's.
    ///
    /// # Errors
    /// [`MACError::KeyMaterialError`] with [`KeyMaterialError::InvalidKeyType`] or
    /// [`KeyMaterialError::SecurityStrength`].
    fn from_key_material(key: &dyn KeyMaterialTrait) -> Result<Self, MACError> {
        Self::from_key_material_checked(key, false)
    }

    /// As [`from_key_material`](Self::from_key_material) without the strength check.
    ///
    /// # Errors
    /// [`MACError::KeyMaterialError`] with [`KeyMaterialError::InvalidKeyType`].
    fn from_key_material_allow_weak(key: &dyn KeyMaterialTrait) -> Result<Self, MACError> {
        Self::from_key_material_checked(key, true)
    }

    /// Draws a key of the hash's output length (RFC 2104 Section 3's recommended minimum) from
    /// `rng`, tagged [`KeyType::MACKey`] at the RNG's strength capped at what that length can
    /// carry, and builds the key from it.
    ///
    /// # Errors
    /// [`MACError::KeyMaterialError`] if the RNG fails, or with
    /// [`KeyMaterialError::SecurityStrength`] if its strength is below the HMAC's.
    fn generate(rng: &mut dyn RNG) -> Result<Self, MACError> {
        // A hash output's worth of key, at the RNG's strength capped by the length: a 28-byte
        // HMAC-SHA224 key from a 256-bit DRBG is a 192-bit key.
        let key = KeyMaterial::<LARGEST_HASHER_OUTPUT_LEN>::from_rng_as_type(
            rng,
            HASH::default().output_len(),
            KeyType::MACKey,
        )?;
        Self::from_key_material(&key)
    }
}

impl<HASH: HMACParams> HmacKey<HASH> {
    /// `H` after absorbing `K XOR ipad`, ready for the text: the start of RFC 2104 Section 2
    /// step (4). What a worker's updates feed; `finish_out` is its other half. The pair is
    /// reachable outside the crate only through [`hazmat`].
    pub(crate) fn inner_state(&self) -> HASH {
        self.inner.clone()
    }

    /// RFC 2104 Section 2 steps (4), (6) and (7) over an inner hash that has absorbed the text:
    /// finishes it, feeds the result to the outer pad state, and finishes that into `out` as
    /// [`Hash::do_final_out`] does, the whole buffer zeroized first and the tag in its first
    /// [`HashAlgParams::OUTPUT_LEN`] bytes. Returns the number of bytes written.
    pub(crate) fn finish_out(&self, inner: HASH, out: &mut [u8]) -> usize {
        // The inner hash is keying material in flight; a stack scratch, zeroized on drop.
        let mut ihash: Secret<[u8; LARGEST_HASHER_OUTPUT_LEN]> = Secret::new();
        let n = inner.do_final_out(&mut ihash[..HASH::OUTPUT_LEN]); // step (4)
        let mut outer = self.outer.clone();
        outer.do_update(&ihash[..n]); // step (6)
        outer.do_final_out(out) // step (7)
    }
}

// The role impls are generic over the tag length and bound through `MACKey = KeyMaterial<N>`,
// which the solver resolves from the hash: stable Rust cannot name `HASH::OUTPUT_LEN` as a
// const-generic argument, and this is the one place the parameters already spell it as a type.
impl<HASH, const MAC_LEN: usize> MacGenerationKey<MAC_LEN> for HmacKey<HASH>
where
    HASH: HMACParams<MACKey = KeyMaterial<MAC_LEN>>,
{
    type Generator<'k>
        = HMAC<'k, HASH, Encrypting>
    where
        Self: 'k;

    fn create_generator<'k>(&'k self) -> Self::Generator<'k> {
        HMAC::new(self)
    }
}

impl<HASH, const MAC_LEN: usize> MacVerificationKey<MAC_LEN> for HmacKey<HASH>
where
    HASH: HMACParams<MACKey = KeyMaterial<MAC_LEN>>,
{
    type Verifier<'k>
        = HMAC<'k, HASH, Decrypting>
    where
        Self: 'k;

    fn create_verifier<'k>(&'k self) -> Self::Verifier<'k> {
        HMAC::new(self)
    }
}

/*** Worker ***/

/// The HMAC worker for one message: the inner hash, absorbing the message, and the key it was made
/// from, borrowed for `'k`, whose outer pad state it is finished through. Obtained from an
/// [`HmacKey`]: `Dir` is [`Encrypting`] for the generator, which implements [`MACGenerator`],
/// and [`Decrypting`] for the verifier, which implements [`MACVerifier`]. Not `Clone`: a second
/// worker comes from the key.
///
/// ```compile_fail
/// # use bouncycastle_core::direction::Encrypting;
/// # use bouncycastle_hmac::HMAC;
/// # use bouncycastle_sha2::SHA256;
/// fn cloneable<T: Clone>() {}
/// cloneable::<HMAC<'static, SHA256, Encrypting>>();
/// ```
pub struct HMAC<'k, HASH: HMACParams, Dir> {
    /// RFC 2104 Section 2 steps (3)-(4): `H(K XOR ipad, text)` in progress.
    hasher: HASH,
    /// The key, for `H` after absorbing `K XOR opad` at step (7).
    key: &'k HmacKey<HASH>,
    dir: PhantomData<Dir>,
}

impl<HASH: HMACParams, Dir> Debug for HMAC<'_, HASH, Dir> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} instance", HASH::HMAC_ALG_NAME)
    }
}

impl<HASH: HMACParams, Dir> Display for HMAC<'_, HASH, Dir> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} instance", HASH::HMAC_ALG_NAME)
    }
}

// See definitions in RFC 2104 Section 2.
const IPAD_BYTE: u8 = 0x36;
const OPAD_BYTE: u8 = 0x5C;

impl<'k, HASH: HMACParams, Dir> HMAC<'k, HASH, Dir> {
    /// A worker at the start of step (3), over a clone of the key's inner pad state.
    fn new(key: &'k HmacKey<HASH>) -> Self {
        Self { hasher: key.inner.clone(), key, dir: PhantomData }
    }

    /// Step (3): the text, in pieces.
    fn absorb(&mut self, data: &[u8]) {
        self.hasher.do_update(data)
    }

    /// Steps (4), (6) and (7), through the key: [`HmacKey::finish_out`] into a buffer of the
    /// hash's output length. `MAC_LEN` is that length by the role impls' bound; the check makes
    /// a foreign `HMACParams` whose `MACKey` says otherwise fail to compile.
    fn finish<const MAC_LEN: usize>(self, out: &mut [u8; MAC_LEN]) -> usize {
        const {
            assert!(
                MAC_LEN == HASH::OUTPUT_LEN,
                "HMACParams::MACKey must be KeyMaterial<OUTPUT_LEN>"
            )
        };
        self.key.finish_out(self.hasher, out)
    }
}

impl<HASH, const MAC_LEN: usize> MACGenerator<MAC_LEN> for HMAC<'_, HASH, Encrypting>
where
    HASH: HMACParams<MACKey = KeyMaterial<MAC_LEN>>,
{
    fn do_update(&mut self, data: &[u8]) {
        self.absorb(data)
    }

    fn do_final_out(self, out: &mut [u8; MAC_LEN]) -> usize {
        self.finish(out)
    }
}

impl<HASH, const MAC_LEN: usize> MACVerifier<MAC_LEN> for HMAC<'_, HASH, Decrypting>
where
    HASH: HMACParams<MACKey = KeyMaterial<MAC_LEN>>,
{
    fn do_update(&mut self, data: &[u8]) {
        self.absorb(data)
    }

    /// Recomputes the tag and compares it in constant time.
    fn do_verify_final(self, mac: &[u8; MAC_LEN]) -> Result<(), MACError> {
        // The recomputed tag is the valid tag of whatever message was absorbed, so it is kept
        // off the stack's leftovers.
        let mut computed: Secret<[u8; MAC_LEN]> = Secret::new();
        self.finish(&mut computed);
        if ct::ct_eq_bytes(&*computed, mac) { Ok(()) } else { Err(MACError::VerificationFailed) }
    }
}
