//! The generic Hash-Based Message Authentication Code (HMAC) construction, as specified in RFC 2104,
//! taking into account NIST Implementation Guidance in FIPS 140-3 IG C.L.
//!
//! This is a utility module and is not intended to be used directly. It provides [`HmacKey`] -- the
//! key object, which holds the two precomputed pad states RFC 2104 Section 4 describes and hands
//! out workers -- and [`HMAC`] -- the worker, one per message, which borrows the key it came from
//! and generates (`HMAC<'k, H, Encrypting>`) or verifies (`HMAC<'k, H, Decrypting>`) a tag.
//! Both are generic over any struct that implements [`Hash`] and [`HMACParams`], the extension
//! point through which a hash declares the metadata from which the HMAC instance is built. The
//! library provides the following concrete instantiations of HMAC:
//!
//! | Hash family | Instantiations                                                               |
//! |-------------|------------------------------------------------------------------------------|
//! | SHA-2       | `bouncycastle_digest::sha2::hmac` -- `HMAC_SHA224`, `HMAC_SHA256`, `HMAC_SHA384`, `HMAC_SHA512`, `HMAC_SHA512_224`, `HMAC_SHA512_256` |
//! | SHA-3       | `bouncycastle_digest::sha3::hmac` -- `HMAC_SHA3_224`, `HMAC_SHA3_256`, `HMAC_SHA3_384`, `HMAC_SHA3_512` |
//! | SM3         | `bouncycastle_digest::sm3::hmac` -- `HMAC_SM3`                                       |
//! | RIPEMD      | `bouncycastle_digest::ripemd::hmac` -- `HMAC_RIPEMD160`                              |
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
//! use bouncycastle_digest::hmac::HmacKey;
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_digest::sha2::SHA256;
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
//!    roles. This allows this module to provide blanket [`Algorithm`], [`AlgorithmOID`] and role
//!    impls.
//! 3. Publish a type alias for the instantiation, `HMAC<SHA256, Dir>`.
//!
//! ## Worked example
//!
//! As an example, the [`sha2`](crate::sha2) module follows exactly the recipe above; its entry for SHA-256 reduces to:
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
//! # Memory Usage
//!
//! HMAC allocates nothing. The sizes of a key and of a worker depend on the hash, and are tabulated
//! with the instantiations: see the Memory Usage sections of [`crate::sha2::hmac`] and
//! [`crate::sha3::hmac`].
//!
//! # 🚨 Security Considerations 🚨
//!
//! These apply to every instantiation; the hash modules' `hmac` modules repeat the ones that matter
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
//!   hold them as hash states, which the hash modules zeroize on drop; neither has a `Debug` that
//!   prints them. The padded key block they are built from is a [`Secret`] scratch, zeroized when
//!   construction returns, and the stack a worker uses to take the inner state and to finish a
//!   tag is overwritten before it returns.
//!
//! [`Secret`]: bouncycastle_utils::secret::Secret
//! [`MacVerificationKey::verify`]: bouncycastle_core::symmetric_key::MacVerificationKey::verify
//! [`MACVerifier::do_verify_final`]: bouncycastle_core::traits::MACVerifier::do_verify_final

pub mod hazmat;

use crate::stack_wipe::{in_wiped_frame, wipe_stack_below};
use bouncycastle_core::direction::{Decrypting, Encrypting};
use bouncycastle_core::errors::{KeyMaterialError, MACError, RNGError};
use bouncycastle_core::hazmat::{WithoutCollisionResistance, do_hazardous_operations};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{FromAnyKeyMaterial, MacGenerationKey, MacVerificationKey};
use bouncycastle_core::traits::{
    Algorithm, AlgorithmOID, FinishToken, HashAlgParams, HashOneShot, MACGenerator, MACVerifier,
    RNG,
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
/// Each hash module is expected to implement this trait for its own hash types and publishes the
/// resulting type alias. For example,`HMAC_SHA256` lives in `bouncycastle_digest::sha2::hmac` and
/// `HMAC_SHA3_256` in `bouncycastle_digest::sha3::hmac`.
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
    /// The strength claimed by the HMAC over this hash, as reported by
    /// [`Algorithm::MAX_SECURITY_STRENGTH`].
    const HMAC_MAX_SECURITY_STRENGTH: SecurityStrength;
    /// The OID of the HMAC over this hash in component form, as reported by [`AlgorithmOID::OID`].
    const HMAC_OID: &'static [u32];
    /// The DER encoding of [`HMACParams::HMAC_OID`], as reported by [`AlgorithmOID::OID_DER`].
    const HMAC_OID_DER: &'static [u8];
}

/// HMAC over [`WithoutCollisionResistance<H>`] is HMAC over `H`: every parameter is `H`'s. The
/// wrapper needs them because RFC 6979 keys an HMAC on a deterministic signature's hash.
impl<H: HMACParams> HMACParams for WithoutCollisionResistance<H> {
    type MACKey = H::MACKey;
    const HMAC_ALG_NAME: &'static str = H::HMAC_ALG_NAME;
    const HMAC_MAX_SECURITY_STRENGTH: SecurityStrength = H::HMAC_MAX_SECURITY_STRENGTH;
    const HMAC_OID: &'static [u32] = H::HMAC_OID;
    const HMAC_OID_DER: &'static [u8] = H::HMAC_OID_DER;
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
/// it hands this module from the same constant.
pub const LARGEST_HASHER_BLOCK_LEN: usize = 144;

/// The largest output length across the supported hashes (SHA-512, SHA3-512), which sizes the key
/// [`FromAnyKeyMaterial::generate`] draws before trimming it to the hash's own output length, and
/// the scratch the inner digest is finished into.
const LARGEST_HASHER_OUTPUT_LEN: usize = 64;

/// How much stack [`wipe_stack_below`] overwrites when an [`HmacKey`] is made, and again after a
/// key longer than the block is hashed, in 64-bit words: more than either leaves written below
/// the frame that wipes, with room for a compiler that lays the frames out less tightly. In the
/// x86-64 release build the key's own frame is 1448 bytes for HMAC-SHA3 (1032 for SHA-512, 632
/// for SHA-256), the absorbing below it adds little (the permutation and the compressions wipe
/// their own frames), and the deepest write that differs between two keys is about 1320 bytes
/// down; hashing a long key writes up to 1504 bytes below the key's frame, and is wiped where it
/// ends. An unoptimised build's frames are not covered.
const KEY_WIPED_STACK_WORDS: usize = 256;

/// How much stack [`wipe_stack_below`] overwrites after a worker takes the key's inner pad
/// state, in 64-bit words. In the x86-64 release build the clone's frame is at most 216 bytes
/// (SHA-512's), and 16 words clear every hash.
const LOAD_WIPED_STACK_WORDS: usize = 32;

/// How much stack [`wipe_stack_below`] overwrites after a tag is finished, in 64-bit words. In
/// the x86-64 release build 48 clear RIPEMD-160 (40 leave four bytes in its final's frame, below
/// the 312 of the finishing frame) and 32 clear SHA-2 and SM3; SHA-3 leaves nothing.
const FINISH_WIPED_STACK_WORDS: usize = 64;

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
    /// the block, absorbed into the key's two states where they sit, so that they are ready for
    /// steps (4) and (7). No key checks: the callers do those.
    fn absorb_pads(&mut self, key_bytes: &[u8]) {
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
            // The hash of the key is the key: the stack hashing it used is overwritten here,
            // where it ends, and not left to the caller's wipe, which is sized for the pads.
            wipe_stack_below::<KEY_WIPED_STACK_WORDS>();
        } else {
            k[..key_bytes.len()].copy_from_slice(key_bytes);
        }

        // Step (2): "XOR ... the B byte string computed in step (1) with ipad", absorbed into the
        // inner hash; step (5): the same with opad, absorbed into the outer hash. Section 4: these
        // two block compressions are what the key saves on every message.
        for byte in k[..block_len].iter_mut() {
            *byte ^= IPAD_BYTE;
        }
        self.inner.do_update(&k[..block_len]);
        for byte in k[..block_len].iter_mut() {
            *byte ^= IPAD_BYTE ^ OPAD_BYTE; // undo ipad, apply opad
        }
        self.outer.do_update(&k[..block_len]);
    }

    /// The key-type check and, unless `allow_weak_keys`, the strength check, then the pads.
    ///
    /// The pad states are key-equivalent (RFC 2104 Section 4). They are built, and the result
    /// made, in [`Self::checked_in_own_frame`], which leaves copies of them in its frame and its
    /// callees'; that stack is overwritten here. The result is written straight to the
    /// caller's, not held in this frame across the wipe, which would leave a copy of both pad
    /// states above the stack the wipe reaches.
    fn from_key_material_checked(
        key: &dyn KeyMaterialTrait,
        allow_weak_keys: bool,
    ) -> Result<Self, MACError> {
        in_wiped_frame::<KEY_WIPED_STACK_WORDS, _>(|| {
            Self::checked_in_own_frame(key, allow_weak_keys)
        })
    }

    /// [`Self::from_key_material_checked`] without its wipe, for HKDF, whose operations each run
    /// in a frame of their own and overwrite the stack below it afterwards, which covers this.
    /// Only for such a caller: elsewhere the pad states' copies are left on the stack.
    pub(crate) fn from_key_material_unwiped(
        key: &dyn KeyMaterialTrait,
        allow_weak_keys: bool,
    ) -> Result<Self, MACError> {
        Self::checked_in_own_frame(key, allow_weak_keys)
    }

    /// [`Self::from_key_material_checked`]'s work. Never inlined, so that its frame lies below
    /// its caller's, where the caller's wipe reaches it.
    #[inline(never)]
    fn checked_in_own_frame(
        key: &dyn KeyMaterialTrait,
        allow_weak_keys: bool,
    ) -> Result<Self, MACError> {
        if !(key.key_type() == KeyType::Zeroized || key.key_type() == KeyType::MACKey) {
            return Err(MACError::KeyMaterialError(KeyMaterialError::InvalidKeyType(
                "Key type must be a MAC key.",
            )));
        }
        // The bar is the HMAC's own claim, as `keygen_from_rng`'s is, not the hash's collision
        // strength: SP 800-107r1 Section 5.3.4 bounds an HMAC key's effective strength by 2C, twice
        // the chaining value's length, so the two are separate claims. A key of no security strength is
        // refused whatever the HMAC claims: for an HMAC that itself claims none (a legacy hash),
        // `<` alone would accept every key.
        if !allow_weak_keys
            && (key.security_strength() < HASH::HMAC_MAX_SECURITY_STRENGTH
                || key.security_strength() == SecurityStrength::None)
        {
            return Err(MACError::KeyMaterialError(KeyMaterialError::SecurityStrength(
                "HmacKey: provided key has a lower security strength than the instantiated HMAC",
            )));
        }
        let mut key_states = Self { inner: HASH::default(), outer: HASH::default() };
        key_states.absorb_pads(key.ref_to_bytes());
        Ok(key_states)
    }

    /// Generates a fresh key for this HMAC from `rng`: [`HMACParams::MACKey`] bytes (the hash's
    /// output length), tagged [`KeyType::MACKey`]. [`FromAnyKeyMaterial::generate`] draws the
    /// same key and builds the key object from it in one step.
    ///
    /// # Errors
    /// [`RNGError::SecurityStrengthInsufficientForAlgorithm`] if `rng` is instantiated below
    /// [`HMACParams::HMAC_MAX_SECURITY_STRENGTH`]; [`RNGError::GenericError`] if it fills less
    /// than the whole key; or whatever the RNG returns.
    pub fn keygen_from_rng(rng: &mut dyn RNG) -> Result<HASH::MACKey, RNGError> {
        if rng.security_strength() < HASH::HMAC_MAX_SECURITY_STRENGTH {
            return Err(RNGError::SecurityStrengthInsufficientForAlgorithm);
        }
        let mut key = HASH::MACKey::default();
        // The count is the key's length, so a short one is a short key, which HMAC would take.
        if rng.fill_keymaterial_out(&mut key)? != key.capacity() {
            return Err(RNGError::GenericError("the RNG wrote fewer bytes than it was asked for"));
        }
        // An RNG types its draw as it likes (`FixedSeedRNG`'s is a `Seed`), and turning one key
        // type into another is a hazardous operation; drawn for this purpose, it is a MAC key.
        do_hazardous_operations(&mut key, |key| key.set_key_type(KeyType::MACKey))?;
        Ok(key)
    }
}

impl<HASH: HMACParams> FromAnyKeyMaterial for HmacKey<HASH> {
    /// Builds the key from material tagged [`KeyType::MACKey`] (or [`KeyType::Zeroized`], for an
    /// all-zero key) whose security strength is at least
    /// [`HMACParams::HMAC_MAX_SECURITY_STRENGTH`] and is not [`SecurityStrength::None`].
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
    /// step (4), returned for [`hazmat`]; `finish_out` is its other half. A worker takes it
    /// through [`Self::load_inner_state`] instead.
    pub(in crate::hmac) fn inner_state(&self) -> HASH {
        self.inner.clone()
    }

    /// [`Self::inner_state`] written over `hasher` where it sits, rather than returned: the
    /// pad state is key-equivalent (RFC 2104 Section 4), and a returned one leaves copies in the
    /// caller's frame. The clone is made in [`Self::load_inner_state_in_own_frame`], and the
    /// stack it used is overwritten here.
    fn load_inner_state(&self, hasher: &mut HASH) {
        self.load_inner_state_in_own_frame(hasher);
        wipe_stack_below::<LOAD_WIPED_STACK_WORDS>();
    }

    /// [`Self::load_inner_state`]'s clone. Never inlined, so that the copy of the pad state the
    /// clone passes through lies below its caller's frame, where the caller's wipe reaches it.
    #[inline(never)]
    fn load_inner_state_in_own_frame(&self, hasher: &mut HASH) {
        hasher.clone_from(&self.inner);
    }

    /// RFC 2104 Section 2 steps (4), (6) and (7) over an inner hash that has absorbed the text:
    /// finishes it where it sits, feeds the result to the outer pad state, and finishes that into
    /// `out` as [`Hash::do_final_out`] does, the whole buffer zeroized first and the tag in its
    /// first [`HashAlgParams::OUTPUT_LEN`] bytes. Returns the number of bytes written. Neither
    /// hash is moved; `token` is the one a worker's final was given, or [`hazmat`]'s.
    pub(in crate::hmac) fn finish_out(
        &self,
        token: &FinishToken,
        inner: &mut HASH,
        out: &mut [u8],
    ) -> usize {
        let n = self.finish_out_in_own_frame(token, inner, out);
        wipe_stack_below::<FINISH_WIPED_STACK_WORDS>();
        n
    }

    /// [`Self::finish_out`]'s work. Never inlined, so that the copies of the outer pad state and
    /// of the inner digest that it and the hashes' finals leave lie below its caller's frame,
    /// where the caller's wipe reaches them.
    #[inline(never)]
    fn finish_out_in_own_frame(
        &self,
        token: &FinishToken,
        inner: &mut HASH,
        out: &mut [u8],
    ) -> usize {
        // The inner hash is keying material in flight; a stack scratch, zeroized on drop.
        let mut ihash: Secret<[u8; LARGEST_HASHER_OUTPUT_LEN]> = Secret::new();
        let n = inner.finish_into(token, &mut ihash[..HASH::OUTPUT_LEN]); // step (4)
        let mut outer = self.outer.clone();
        outer.do_update(&ihash[..n]); // step (6)
        outer.finish_into(token, out) // step (7)
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
/// # use bouncycastle_digest::hmac::HMAC;
/// # use bouncycastle_digest::sha2::SHA256;
/// fn cloneable<T: Clone>() {}
/// cloneable::<HMAC<'static, SHA256, Encrypting>>();
/// ```
pub struct HMAC<'k, HASH: HMACParams, Dir> {
    /// RFC 2104 Section 2 steps (3)-(4): `H(K XOR ipad, text)` in progress, once `keyed`; the
    /// hash's initial state until then.
    hasher: HASH,
    /// Whether `hasher` holds the key's inner pad state. The worker is returned by value, and
    /// moved by its callers; it takes the pad state at its first update or at its final, where
    /// it sits, so that a move before then copies no key-equivalent state. A move after the
    /// first update (a consuming `do_final`, say) does copy it, into the caller's frame.
    keyed: bool,
    /// The key, for `H` after absorbing `K XOR opad` at step (7).
    key: &'k HmacKey<HASH>,
    dir: PhantomData<Dir>,
}

impl<HASH: HMACParams, Dir> Debug for HMAC<'_, HASH, Dir> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} instance", HASH::HMAC_ALG_NAME)
    }
}

impl<HASH: HMACParams, Dir> Display for HMAC<'_, HASH, Dir> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} instance", HASH::HMAC_ALG_NAME)
    }
}

// See definitions in RFC 2104 Section 2.
const IPAD_BYTE: u8 = 0x36;
const OPAD_BYTE: u8 = 0x5C;

impl<'k, HASH: HMACParams, Dir> HMAC<'k, HASH, Dir> {
    /// A worker at the start of step (3), not yet holding the key's inner pad state.
    fn new(key: &'k HmacKey<HASH>) -> Self {
        Self { hasher: HASH::default(), keyed: false, key, dir: PhantomData }
    }

    /// Puts the key's inner pad state in `hasher`, the first time it is called.
    fn ensure_keyed(&mut self) {
        if !self.keyed {
            self.key.load_inner_state(&mut self.hasher);
            self.keyed = true;
        }
    }

    /// Step (3): the text, in pieces.
    fn absorb(&mut self, data: &[u8]) {
        self.ensure_keyed();
        self.hasher.do_update(data)
    }

    /// Steps (4), (6) and (7), through the key: [`HmacKey::finish_out`] into a buffer of the
    /// hash's output length. `MAC_LEN` is that length by the role impls' bound; the check makes
    /// a foreign `HMACParams` whose `MACKey` says otherwise fail to compile.
    fn finish<const MAC_LEN: usize>(
        &mut self,
        token: &FinishToken,
        out: &mut [u8; MAC_LEN],
    ) -> usize {
        const {
            assert!(
                MAC_LEN == HASH::OUTPUT_LEN,
                "HMACParams::MACKey must be KeyMaterial<OUTPUT_LEN>"
            )
        };
        self.ensure_keyed();
        self.key.finish_out(token, &mut self.hasher, out)
    }
}

impl<HASH, const MAC_LEN: usize> MACGenerator<MAC_LEN> for HMAC<'_, HASH, Encrypting>
where
    HASH: HMACParams<MACKey = KeyMaterial<MAC_LEN>>,
{
    fn do_update(&mut self, data: &[u8]) {
        self.absorb(data)
    }

    fn finish_mac_into(&mut self, token: &FinishToken, out: &mut [u8; MAC_LEN]) -> usize {
        self.finish(token, out)
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
    fn finish_mac_verify(
        &mut self,
        token: &FinishToken,
        mac: &[u8; MAC_LEN],
    ) -> Result<(), MACError> {
        // The recomputed tag is the valid tag of whatever message was absorbed, so it is kept
        // off the stack's leftovers.
        let mut computed: Secret<[u8; MAC_LEN]> = Secret::new();
        self.finish(token, &mut computed);
        if ct::ct_eq_bytes(&*computed, mac) { Ok(()) } else { Err(MACError::VerificationFailed) }
    }
}
