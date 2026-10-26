//! The generic Hash-Based Message Authentication Code (HMAC) construction, as specified in RFC 2104,
//! taking into account NIST Implementation Guidance in FIPS 140-2 IG A.8 and NIST SP 800-107-r1.
//!
//! This is a utility crate and is not intended to be used directly. It provides [`HmacKey`] -- the
//! key object, which holds the two precomputed pad states RFC 2104 Section 4 describes and hands
//! out workers -- and [`HMAC`] -- the worker, one per message. Both are generic over any struct
//! that implements [`Hash`] and [`HMACParams`], the extension point through which a hash declares
//! the metadata from which the HMAC instance is built. The library provides the following concrete
//! instantiations of HMAC:
//!
//! | Hash family | Instantiations                                                               |
//! |-------------|------------------------------------------------------------------------------|
//! | SHA-2       | `bouncycastle_sha2::hmac` -- `HMAC_SHA224` .. `HMAC_SHA512_256`              |
//! | SHA-3       | `bouncycastle_sha3::hmac` -- `HMAC_SHA3_224` .. `HMAC_SHA3_512`              |
//!
//! Although users are free to implement [`Hash`] and [`HMACParams`] for a a hash function not included with the library,
//! and will then be able to instantiate [`HMAC`] for it as well.
//!
//! # Usage
//!
//! A key is built once, from key material of any length, and used for any number of messages:
//!
//! ```
//! use bouncycastle_core::symmetric_key::{FromAnyKeyMaterial, MacGenerationKey, MacVerificationKey};
//! use bouncycastle_core::traits::MAC;
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
//! let mut tag = [0u8; 32];
//! let n = generator.do_final_out(&mut tag).expect("32 bytes is above the truncation floor");
//!
//! let mut verifier = key.create_verifier();
//! verifier.do_update(b"part onepart two");
//! assert!(verifier.do_verify_final(&tag[..n]));
//! assert!(key.verify(b"part onepart two", &tag[..n]));   // one-shot, same path underneath
//! ```
//!
//! [`MAC::new`] and [`MAC::new_allow_weak_key`] on the worker build the same key internally and
//! take one worker from it, so they cost the pad computation per message; a key that will
//! authenticate more than one message is better held as an [`HmacKey`].
//!
//! # Instantiating HMAC over a Hash
//!
//! HMAC works with any hash: [`HMAC<HASH>`](HMAC) needs only [`Hash`]. What HMAC cannot
//! derive on its own is the *metadata* of the resulting construction -- the name "HMAC-SHA256" is not
//! mechanically obtainable from "SHA256", and RFC 4231 assigns each hash/HMAC combination its own OID
//! rather than deriving it from the hash's OID. Supplying that metadata is what makes an HMAC a
//! first-class algorithm in this library rather than an anonymous `HMAC<H>`.
//!
//! There are four steps, of which only the second is mandatory:
//!
//! 1. Have a hash type that implements [`Hash`] + [`HashAlgParams`] + [`Default`]. Implementing
//!    [`Hash`] is documented in `bouncycastle-core`; nothing about it is HMAC-specific.
//! 2. Implement [`HMACParams`] for that hash type, supplying the HMAC's name, claimed security
//!    strength and OID, plus the key type that [`HMAC::keygen_from_rng`] should return (typically a
//!    `KeyMaterial<L>` for an L that matches the size of the underlying hash function. This allows
//!    this crate to provide blanket [`Algorithm`], [`AlgorithmOID`] and [`HMAC::keygen_from_rng`] impls.
//! 3. Publish a type alias for the instantiation, `HMAC<SHA256>`.
//! 4. Optionally publish the suspended-state length as a constant. [`SuspendableKeyed`] is
//!    implemented automatically for any hash that implements [`Suspendable`], and HMAC's suspended
//!    state is exactly the inner hash's -- the key is deliberately excluded -- so the constant is
//!    just an alias for the hash's own.
//!
//! ## Worked example
//!
//! As an example, the `bouncycastle-sha2` crate follows exactly the recipe above; its entry for SHA-256 reduces to:
//!
//! ```rust,ignore
//! pub type HMAC_SHA256 = HMAC<SHA256>;
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
//!
//! pub const SUSPENDED_HMAC_SHA256_STATE_LEN: usize = SUSPENDED_SHA256_STATE_LEN;
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
//! * [`HMACParams::HMAC_MAX_SECURITY_STRENGTH`] is a claim that [`MAC::new`] enforces against the
//!   key's tagged strength, and that [`HMAC::keygen_from_rng`] enforces against the RNG's. Declaring
//!   a strength the underlying hash cannot support does not make the construction stronger, it just
//!   makes the check wrong. NIST SP 800-107-r1 Section 5.3.4 gives the ceiling: the effective
//!   strength is `min(strength of K, 2C)` for an internal chaining value of `C` bits.
//! * [`MAC::new_allow_weak_key`] deliberately skips the key-strength check. It exists for protocols
//!   that call for a weak or all-zero key -- an all-zero HKDF salt, for example -- and should not be
//!   used to silence an error from [`MAC::new`].
//! * Verification via [`MAC::verify`] / [`MAC::do_verify_final`] uses a constant-time comparison.
//!   Recomputing the MAC and comparing it with `==` leaks how many leading bytes matched.
//! * [`MIN_FIPS_DIGEST_LEN`] (4 bytes) is the shortest truncation this crate will produce, per
//!   FIPS 140-2 IG A.8 / NIST SP 800-107-r1 Section 5.3.3. It is a floor, not a recommendation:
//!   RFC 2104 Section 5 recommends that the output length "be not less than half the length of the
//!   hash output ... and not less than 80 bits".
//! * The key is deliberately excluded from the suspended state and must be re-supplied on resume.
//!   Resuming with the wrong key cannot be detected and silently produces a wrong MAC, computed with
//!   different keys in the inner and outer pad.
//! * The two pad states are key-equivalent, as RFC 2104 Section 4 says ("the stored intermediate
//!   values need to be treated and protected the same as secret keys"). [`HmacKey`] and the worker
//!   hold them as hash states, which the hash crates zeroize on drop; neither has a `Debug` that
//!   prints them. The padded key block they are built from is a [`Secret`] scratch, zeroized when
//!   construction returns.
//!
//! [`Secret`]: bouncycastle_utils::secret::Secret

#![forbid(unsafe_code)]
#![forbid(missing_docs)]

use bouncycastle_core::errors::{KeyMaterialError, MACError, RNGError, SuspendableError};
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{FromAnyKeyMaterial, MacGenerationKey, MacVerificationKey};
use bouncycastle_core::traits::{
    Algorithm, AlgorithmOID, Hash, HashAlgParams, MAC, RNG, Suspendable, SuspendableKeyed,
};
use bouncycastle_utils::{ct, secret::Secret};
use core::fmt::{Debug, Display, Formatter};

/*** Parameters ***/

/// The HMAC-specific parameters for one underlying hash function.
///
/// [`HMAC`] itself is fully generic: it works with any [`Hash`], including hashes supplied by crates
/// outside this library. What HMAC cannot derive on its own is the *metadata* of the resulting
/// construction -- this trait supplies exactly that metadata, so the blanket [`Algorithm`], [`AlgorithmOID`] and
/// [`HMAC::keygen_from_rng`] can be impl'd generically rather than being written out once
/// per hash.
///
/// Each hash crate is expected to implement this trait for its own hash types and publishes the resulting type
/// alias. For example,`HMAC_SHA256` lives in `bouncycastle_sha2::hmac` and `HMAC_SHA3_256` in
/// `bouncycastle_sha3::hmac`.
///
/// The block length and the generated-key length do not need to be restated here since they are already
/// carried by the hash itself as [`HashAlgParams::BLOCK_LEN`] and [`HashAlgParams::OUTPUT_LEN`].
pub trait HMACParams: Hash + HashAlgParams + Default {
    /// The key type produced by [`HMAC::keygen_from_rng`] and drawn by
    /// [`FromAnyKeyMaterial::generate`], sized to this hash's output length.
    ///
    /// Implementors should set this to `KeyMaterial<{Self::OUTPUT_LEN}>`.
    ///
    // todo: once rust stabilizes generic_const_exprs, delete this and return
    //     `KeyMaterial<{Self::OUTPUT_LEN}>` from `keygen_from_rng` instead.
    type MACKey: KeyMaterialTrait + Default;

    /// The name of the HMAC over this hash, as reported by [`Algorithm::ALG_NAME`].
    const HMAC_ALG_NAME: &'static str;
    /// The strength claimed by the HMAC over this hash, as reported by
    /// [`Algorithm::MAX_SECURITY_STRENGTH`].
    const HMAC_MAX_SECURITY_STRENGTH: SecurityStrength;
    /// The OID of the HMAC over this hash in component form, as reported by [`AlgorithmOID::OID`].
    const HMAC_OID: &'static [u32];
    /// The DER encoding of [`HMACParams::HMAC_OID`], as reported by [`AlgorithmOID::OID_DER`].
    const HMAC_OID_DER: &'static [u8];
}

impl<HASH: HMACParams> Algorithm for HMAC<HASH> {
    const ALG_NAME: &'static str = HASH::HMAC_ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = HASH::HMAC_MAX_SECURITY_STRENGTH;
}

impl<HASH: HMACParams> AlgorithmOID for HMAC<HASH> {
    const OID: &'static [u32] = HASH::HMAC_OID;
    const OID_DER: &'static [u8] = HASH::HMAC_OID_DER;
}

// The scratch the pad blocks are built in must hold one block of the underlying hash: per RFC 2104
// Section 2 step (1) the key is zero-padded to B bytes, and only a key longer than B is pre-hashed
// first (Section 3). This is the largest block length across the supported hashes (SHA3-224's 144),
// and the scratch is sliced to the hash's own block.
const LARGEST_HASHER_BLOCK_LEN: usize = 144;

/// The largest output length across the supported hashes (SHA-512, SHA3-512), which sizes the key
/// [`FromAnyKeyMaterial::generate`] draws before trimming it to the hash's own output length.
const LARGEST_HASHER_OUTPUT_LEN: usize = 64;

/*** Key ***/

/// An HMAC key: the two intermediate hash states of RFC 2104 Section 4, `H` after absorbing
/// `K XOR ipad` and after absorbing `K XOR opad`, computed once from key material of any length.
///
/// Every worker the key hands out starts from clones of the two states, so the per-message cost
/// of the key is a clone and no hashing. The key holds no key bytes: a caller who needs the
/// material again keeps the `KeyMaterial`. Construction is [`FromAnyKeyMaterial`]; the workers
/// come from [`MacGenerationKey`] and [`MacVerificationKey`].
pub struct HmacKey<HASH: Hash + Default> {
    /// `H` after absorbing `K XOR ipad`: the start of RFC 2104 Section 2 step (4).
    inner: HASH,
    /// `H` after absorbing `K XOR opad`: the start of step (7).
    outer: HASH,
}

// `Clone` is written out rather than derived so that it has no bound beyond the struct's own.
impl<HASH: Hash + Default> Clone for HmacKey<HASH> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone(), outer: self.outer.clone() }
    }
}

impl<HASH: Hash + Default> HmacKey<HASH> {
    /// RFC 2104 Section 2 steps (1), (2) and (5), plus Section 3's pre-hash of a key longer than
    /// the block, with both pad blocks absorbed so that the states are ready for steps (4) and (7).
    /// No key checks: the callers do those.
    fn from_key_bytes(key_bytes: &[u8]) -> Self {
        let block_len = HASH::default().block_bitlen() / 8;
        assert!(
            block_len <= LARGEST_HASHER_BLOCK_LEN,
            "Fatal error: hash block length exceeds HMAC's pad scratch"
        );

        // Step (1): "append zeros to the end of K to create a B byte string". The scratch is
        // already zero, so only K (or, per Section 3, H(K) when K is "longer than B bytes") is
        // written.
        let mut k: Secret<[u8; LARGEST_HASHER_BLOCK_LEN]> = Secret::new();
        if key_bytes.len() > block_len {
            let output_len = HASH::default().output_len();
            HASH::default().hash_out(key_bytes, &mut k[..output_len]);
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
        if !allow_weak_keys && key.security_strength() < HASH::default().max_security_strength() {
            return Err(MACError::KeyMaterialError(KeyMaterialError::SecurityStrength(
                "HmacKey: provided key has a lower security strength than the instantiated HMAC",
            )));
        }
        Ok(Self::from_key_bytes(key.ref_to_bytes()))
    }
}

impl<HASH: Hash + Default> FromAnyKeyMaterial for HmacKey<HASH> {
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
    /// `rng`, tagged [`KeyType::MACKey`] at the RNG's strength, and builds the key from it.
    ///
    /// # Errors
    /// [`MACError::KeyMaterialError`] if the RNG fails, or with
    /// [`KeyMaterialError::SecurityStrength`] if its strength is below the HMAC's.
    fn generate(rng: &mut dyn RNG) -> Result<Self, MACError> {
        let output_len = HASH::default().output_len();
        let mut key = KeyMaterial::<LARGEST_HASHER_OUTPUT_LEN>::new();
        do_hazardous_operations(&mut key, |key| {
            rng.next_bytes_out(&mut key.ref_to_bytes_mut()?[..output_len])
                .map_err(|_| KeyMaterialError::GenericError("RNG failed."))?;
            key.set_key_len(output_len)?;
            key.set_key_type(KeyType::MACKey)?;
            key.set_security_strength(rng.security_strength())
        })?;
        Self::from_key_material(&key)
    }
}

impl<HASH: Hash + Default> MacGenerationKey for HmacKey<HASH> {
    type Generator = HMAC<HASH>;

    fn create_generator(&self) -> Self::Generator {
        HMAC { hasher: self.inner.clone(), outer: self.outer.clone() }
    }
}

impl<HASH: Hash + Default> MacVerificationKey for HmacKey<HASH> {
    type Verifier = HMAC<HASH>;

    fn create_verifier(&self) -> Self::Verifier {
        self.create_generator()
    }
}

/*** Worker ***/

/// The HMAC worker for one message: the inner hash, absorbing the message, and the outer pad state
/// it is finished through. Obtained from an [`HmacKey`], or built with its own key for one message
/// by [`MAC::new`].
#[derive(Clone)]
pub struct HMAC<HASH: Hash + Default> {
    /// RFC 2104 Section 2 steps (3)-(4): `H(K XOR ipad, text)` in progress.
    hasher: HASH,
    /// `H` after absorbing `K XOR opad`, for step (7).
    outer: HASH,
}

impl<HASH: Hash + Default> Debug for HMAC<HASH> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "HMAC-{} instance", HASH::ALG_NAME,)
    }
}

impl<HASH: Hash + Default> Display for HMAC<HASH> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "HMAC-{} instance", HASH::ALG_NAME,)
    }
}

// See definitions in RFC 2104 Section 2.
const IPAD_BYTE: u8 = 0x36;
const OPAD_BYTE: u8 = 0x5C;

/// Per FIPS 140-2 IG A.8 Use of a truncated HMAC (matching NIST SP 800-107-r1
/// Section 5.3.3. Truncation of HMAC), says that the minimum truncation of a
/// HMAC for tagging should be 32 bits; this exceeds the lower bound set by
/// IETF RFC 2104 Section 5 Truncated output, which sets the lower bound to be
/// half of the hash's length and no fewer than 80 bits.
///
/// However, as we feel there should be a minimum limit (and have an author
/// work around this via explicit truncation manually afterwards), but not
/// be too strict about it,
/// = 32 bits / 8 = 4 bytes;
pub const MIN_FIPS_DIGEST_LEN: usize = 4;

impl<HASH: Hash + Default> HMAC<HASH> {
    /// RFC 2104 Section 2 steps (4), (6) and (7): finish the inner hash, feed its result to the
    /// outer pad state, and finish that into `out`.
    fn do_final_internal_out(self, out: &mut [u8]) -> Result<usize, MACError> {
        if out.len() < MIN_FIPS_DIGEST_LEN {
            return Err(MACError::InvalidLength(
                "HMAC truncation too short for FIPS 140-2 guidelines",
            ));
        }
        out.fill(0);

        let Self { hasher, mut outer } = self;
        let mut ihash = vec![0u8; hasher.output_len()];
        hasher.do_final_out(&mut ihash); // step (4)
        outer.do_update(&ihash); // step (6)
        Ok(outer.do_final_out(out)) // step (7)
    }
}

impl<HASH: Hash + Default> MAC for HMAC<HASH> {
    fn new(key: &impl KeyMaterialTrait) -> Result<Self, MACError> {
        Ok(HmacKey::<HASH>::from_key_material_checked(key, false)?.create_generator())
    }

    fn new_allow_weak_key(key: &impl KeyMaterialTrait) -> Result<Self, MACError> {
        Ok(HmacKey::<HASH>::from_key_material_checked(key, true)?.create_generator())
    }

    fn output_len(&self) -> usize {
        self.hasher.output_len()
    }

    fn mac(self, data: &[u8]) -> Vec<u8> {
        let mut out = vec![0_u8; self.hasher.output_len()];
        let bytes_written = self.mac_out(data, &mut out).expect("HMAC::mac(): should not have failed because we gave it a sufficiently large output buffer to meet FIPS rules.");
        out[..bytes_written].to_vec()
    }

    fn mac_out(mut self, data: &[u8], mut out: &mut [u8]) -> Result<usize, MACError> {
        out.fill(0);
        self.do_update(data);
        self.do_final_out(&mut out)
    }

    fn verify(mut self, data: &[u8], mac: &[u8]) -> bool {
        self.do_update(data);
        self.do_verify_final(mac)
    }

    fn do_update(&mut self, data: &[u8]) {
        self.hasher.do_update(data)
    }

    fn do_final(self) -> Vec<u8> {
        let mut out = vec![0_u8; self.hasher.output_len()];
        self.do_final_internal_out(&mut out).expect("HMAC::do_final(): should not have failed because we gave it a sufficiently large output buffer to meet FIPS rules.");
        out
    }

    fn do_final_out(self, mut out: &mut [u8]) -> Result<usize, MACError> {
        out.fill(0);
        self.do_final_internal_out(&mut out)
    }

    fn do_verify_final(self, mac: &[u8]) -> bool {
        let mut out = vec![0_u8; HASH::default().output_len()];
        let output_len = self.do_final_internal_out(&mut out).expect("HMAC::do_final(): should not have failed because we gave it a sufficiently large output buffer to meet FIPS rules.");
        if mac.len() != output_len {
            return false;
        }
        ct::ct_eq_bytes(mac, &out[..output_len])
    }

    fn max_security_strength(&self) -> SecurityStrength {
        HASH::default().max_security_strength()
    }
}

/* SerializedState */

/// Suspend / resume for `HMAC`.
///
/// The suspended state is exactly the inner hash's: the outer pad state is a function of the key
/// alone and is rebuilt from the re-supplied key on resume, so the state carries one secret fewer.
/// The key is *not* authenticated against the state: resuming with the wrong key cannot be
/// detected and produces a wrong MAC.
impl<const HASH_STATE_LEN: usize, HASH: Hash + Default + Suspendable<HASH_STATE_LEN>>
    SuspendableKeyed<HASH_STATE_LEN> for HMAC<HASH>
{
    type Key = dyn KeyMaterialTrait;

    fn suspend(self) -> [u8; HASH_STATE_LEN] {
        self.hasher.suspend()
    }

    fn from_suspended(
        state: [u8; HASH_STATE_LEN],
        key: &Self::Key,
    ) -> Result<Self, SuspendableError> {
        let hasher = HASH::from_suspended(state)?;
        let HmacKey { outer, .. } = HmacKey::<HASH>::from_key_bytes(key.ref_to_bytes());
        Ok(HMAC { hasher, outer })
    }
}

/* KeyGen functions */

impl<HASH: HMACParams> HMAC<HASH> {
    /// Generates a fresh key for this HMAC from `rng`: [`HMACParams::MACKey`] bytes (the hash's
    /// output length), tagged [`KeyType::MACKey`]. [`FromAnyKeyMaterial::generate`] on
    /// [`HmacKey`] draws the same key and builds the key object from it in one step.
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
