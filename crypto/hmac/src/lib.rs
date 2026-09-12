//! The generic Hash-Based Message Authentication Code (HMAC) construction, as specified in RFC 2104,
//! taking into account NIST Implementation Guidance in FIPS 140-2 IG A.8 and NIST SP 800-107-r1.
//!
//! This is a utility crate and is not intended to be used directly. It provides [`HMAC`] -- the
//! construction, generic over any struct that implements [`Hash`], paired with an [`HMACParams`]
//! marker type that carries the metadata the resulting instantiation reports about itself.
//! The library provides the following concrete instantiations of HMAC:
//!
//! | Hash family | Instantiations                                                               |
//! |-------------|------------------------------------------------------------------------------|
//! | SHA-2       | `bouncycastle_sha2::hmac` -- `HMAC_SHA224` .. `HMAC_SHA512_256`              |
//! | SHA-3       | `bouncycastle_sha3::hmac` -- `HMAC_SHA3_224` .. `HMAC_SHA3_512`              |
//!
//! Users are free to implement [`Hash`] for a hash function not included with the library and
//! declare their own [`HMACParams`] marker type for it, and will then be able to instantiate
//! [`HMAC`] over it as well.
//!
//! # Instantiating HMAC over a Hash
//!
//! HMAC works with any hash: [`HMAC<HASH>`](HMAC) needs only [`Hash`]. What HMAC cannot
//! derive on its own is the *metadata* of the resulting construction -- the name "HMAC-SHA256" is not
//! mechanically obtainable from "SHA256", and RFC 4231 assigns each hash/HMAC combination its own OID
//! rather than deriving it from the hash's OID. Supplying that metadata is what makes an HMAC a
//! first-class algorithm in this library rather than an anonymous `HMAC<H>`.
//!
//! That metadata is supplied by a *params marker type*.
//!
//! There are four steps to implementing a new HMAC type:
//!
//! 1. Have a hash type that implements [`Hash`] + [`HashAlgParams`] + [`Default`]. Implementing
//!    [`Hash`] is documented in `bouncycastle-core`; nothing about it is HMAC-specific.
//! 2. Declare a params type for the instantiation and give it [`Algorithm`] (the name and claimed
//!    strength), [`AlgorithmOID`] (the OID and its DER encoding) and [`HMACParams`] (the key type
//!    that [`HMAC::keygen_from_rng`] should return, and the internal key buffer). This crate then
//!    provides the blanket [`Algorithm`], [`AlgorithmOID`] and [`HMAC::keygen_from_rng`] impls for
//!    any [`HMAC`]. Take the buffer from [`HashAlgParams::BLOCK_LEN`] rather than writing a literal,
//!    so it cannot drift away from the hash it has to hold a block of.
//! 3. Optionally, publish a type alias pairing the hash with the params.
//! 4. Optionally, publish the suspended-state length as a convenience constant. [`SuspendableKeyed`] is
//!    implemented automatically for any hash that implements [`Suspendable`], and HMAC's suspended
//!    state is exactly the inner hash's -- the key is deliberately excluded -- so the constant is
//!    just an alias for the hash's own.
//!
//! ## Worked example
//!
//! As an example, the `bouncycastle-sha2` crate follows exactly the recipe above; its entry for SHA-256 reduces to:
//!
//! ```rust,ignore
//! /// The parameters for HMAC-SHA256.
//! #[derive(Clone)]
//! pub struct HMAC_SHA256Params;
//!
//! impl Algorithm for HMAC_SHA256Params {
//!     const ALG_NAME: &'static str = "HMAC-SHA256";
//!     const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
//! }
//!
//! /// Defined in RFC 4231: id-hmacWithSHA256 { digestAlgorithm 9 }
//! impl AlgorithmOID for HMAC_SHA256Params {
//!     const OID: &'static [u32] = &[1, 2, 840, 113549, 2, 9];
//!     const OID_DER: &'static [u8] =
//!         &[0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09];
//! }
//!
//! impl HMACParams for HMAC_SHA256Params {
//!     type MACKey = KeyMaterial<{ <SHA256 as HashAlgParams>::OUTPUT_LEN }>;
//!     type KeyBuf = [u8; <SHA256 as HashAlgParams>::BLOCK_LEN];
//! }
//!
//! pub type HMAC_SHA256 = HMAC<SHA256, HMAC_SHA256Params>;
//!
//! pub const SUSPENDED_HMAC_SHA256_STATE_LEN: usize = SUSPENDED_SHA256_STATE_LEN;
//! ```
//!
//! [`HMACParams`] is deliberately **not** sealed, so the same recipe works for a hash function
//! defined in any other crate. Simply follow the recipe above!
//!
//! Every [`HMAC`] carries a params type; there is no anonymous form. That includes an HMAC used as
//! an internal construction step: HKDF's extract phase is `PRK = HMAC-Hash(salt, IKM)` (RFC 5869
//! Section 2.2), so the HMAC inside `HKDF_SHA256` really is HMAC-SHA256 and names
//! `HMAC_SHA256Params` accordingly rather than hiding behind a placeholder.
//!
//! # Security Considerations
//!
//! These apply to every instantiation; the hash crates' `hmac` modules repeat the ones that matter
//! most in day-to-day use.
//!
//! * The strength an HMAC claims is declared by its params, and is enforced in two places:
//!   [`MAC::new`] checks it against the key's tagged strength, and [`HMAC::keygen_from_rng`]
//!   checks it against the RNG's. It is not the underlying hash's strength: HMAC does not rest on
//!   collision resistance, so the figures are independent. NIST SP 800-107-r1 Section 5.3.4 gives
//!   the ceiling: the effective strength is `min(strength of K, 2C)` for an internal chaining value
//!   of `C` bits. Declaring a strength the construction cannot support does not make it stronger,
//!   it just makes both checks wrong.
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
//! * The key buffer is held in [`bouncycastle_utils::secret::Secret`] and zeroized on drop. The
//!   `K ⊕ ipad` / `K ⊕ opad` blocks are transient stack allocations and are not zeroized.

#![forbid(unsafe_code)]
#![forbid(missing_docs)]

use bouncycastle_core::errors::{KeyMaterialError, MACError, RNGError, SuspendableError};
use bouncycastle_core::key_material::{KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{
    Algorithm, AlgorithmOID, Hash, MAC, RNG, SecurityStrength, Suspendable, SuspendableKeyed,
};
use bouncycastle_utils::secret::ZeroizablePrimitive;
use bouncycastle_utils::{ct, secret::Secret};
use core::fmt::{Debug, Display, Formatter};
use core::marker::PhantomData;

/*** Imports needed for docs ***/
#[allow(unused_imports)]
use bouncycastle_core::traits::HashAlgParams;

/*** Parameters ***/

/// The metadata of one concrete HMAC instantiation, supplied as a marker type.
pub trait HMACParams: Algorithm + AlgorithmOID {
    /// The type of key that this HMAC instance needs, sized to the underlying hash's output length.
    ///
    /// Implementors should set this to `KeyMaterial<{ <H as HashAlgParams>::OUTPUT_LEN }>`.
    ///
    // todo: once rust stabilizes generic_const_exprs, delete this and return
    //     `KeyMaterial<{Self::OUTPUT_LEN}>` from `keygen_from_rng` instead.
    type MACKey: KeyMaterialTrait + Default;

    /// The internal key buffer.
    ///
    /// It must be able to hold a key up to the *block length* of the underlying hash: per RFC 2104
    /// a key no longer than the block is used verbatim, and only longer keys are pre-hashed down to
    /// the output length, so the buffer has to fit a whole block.
    ///
    /// Implementors should set this to `[u8; { <H as HashAlgParams>::BLOCK_LEN }]`.
    type KeyBuf: ZeroizablePrimitive + AsRef<[u8]> + AsMut<[u8]>;
}

/// Internal struct for HKDF.
/// HMAC implements RFC 2104.
/// Can, in theory, be instantiated with hash functions other than the ones provided by this crate (even custom ones).
#[derive(Clone)]
pub struct HMAC<HASH: Hash + Default, PARAMS: HMACParams> {
    _phantom_params: PhantomData<PARAMS>,
    hasher: HASH,
    // Sized by the params ([`HMACParams::KeyBuf`]), which take it from the hash's block length, so
    // the caller cannot pick a buffer that does not fit the hash.
    key: Secret<PARAMS::KeyBuf>,
    key_len: Secret<usize>, // Doing it this way to avoid needing a vec, so that this can be made no_std friendly.
}

impl<HASH: Hash + Default, PARAMS: HMACParams> Debug for HMAC<HASH, PARAMS> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} instance", PARAMS::ALG_NAME,)
    }
}

impl<HASH: Hash + Default, PARAMS: HMACParams> Display for HMAC<HASH, PARAMS> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} instance", PARAMS::ALG_NAME,)
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

impl<HASH: Hash + Default, PARAMS: HMACParams> HMAC<HASH, PARAMS> {
    fn pad_key_into_hasher(&mut self, padding: u8) {
        // TODO: it would be nice to be able to statically extract the length of HASH and not need a Vec or over-sized array here.
        // TODO: make this no_std-friendly
        let mut padded = vec![0u8; self.hasher.block_bitlen() / 8];

        padded[..*self.key_len].copy_from_slice(&self.key.as_ref()[..*self.key_len]);

        // XXX: easier way to xor over Vec?
        for entry in &mut padded {
            *entry ^= padding;
        }

        // Per RFC 2104 Section 2, write the padded key into the stream prior
        // to any other data.
        self.hasher.do_update(&padded)
    }

    /// Per RFC 2104 Section 2, if the application key exceeds the block
    /// length of the underlying hashes algorithm, we apply a hash invocation
    /// over the key first.
    /// This does NOT absorb the key into the hasher; that is done separately via [`HMAC::pad_key_into_hasher`].
    fn load_key_material(&mut self, key_bytes: &[u8]) {
        if key_bytes.len() > self.hasher.block_bitlen() / 8 {
            // then we have to pre-hash it -- use a new instance of the hasher rather than the internal one
            HASH::default().hash_out(key_bytes, &mut self.key.as_mut()[..self.hasher.output_len()]);
            *self.key_len = self.hasher.output_len();
        } else {
            self.key.as_mut()[..key_bytes.len()].copy_from_slice(key_bytes);
            *self.key_len = key_bytes.len();
        }

        // Just as a sanity-check.
        assert!(
            *self.key_len <= self.key.as_ref().len(),
            "Fatal error: Key length exceeds HMAC internal buffer length"
        );
    }

    /// Private init so that users are forced to go through one of the public new methods and thus we
    /// don't need to track state errors.
    fn init(&mut self, key: &impl KeyMaterialTrait, allow_weak_keys: bool) -> Result<(), MACError> {
        // check that the key is of type KeyMaterial::MACKey
        // Make an exception for all-zero keys, which is allowed (which can be zero-length or non-zero-length,
        // because it's just a nuisance to force users to set KeyType::MACKey for an all-zero key.
        if !(key.key_type() == KeyType::Zeroized || key.key_type() == KeyType::MACKey) {
            return Err(MACError::KeyMaterialError(KeyMaterialError::InvalidKeyType(
                "Key type must be a MAC key.",
            )));
        }

        // import the key material as bytes.
        // Per RFC 2104 Section 2, if the application key exceeds the block
        // length of the underlying hashes algorithm, we apply a hash invocation
        // over the key first.

        self.load_key_material(key.ref_to_bytes());

        self.pad_key_into_hasher(IPAD_BYTE);

        // check that the key had enough security level
        if !allow_weak_keys && key.security_strength() < PARAMS::MAX_SECURITY_STRENGTH {
            Err(KeyMaterialError::SecurityStrength(
                "HMAC::init(): provided key has a lower security strength than the instantiated HMAC",
            ))?
        } else {
            Ok(())
        }
    }

    /// the out buffer can be oversized, but not less than the MIN_FIPS_DIGEST_LENGTH
    /// Returns the number of bytes written.
    fn do_final_internal_out(mut self, out: &mut [u8]) -> Result<usize, MACError> {
        if out.len() < MIN_FIPS_DIGEST_LEN {
            return Err(MACError::InvalidLength(
                "HMAC truncation too short for FIPS 140-2 guidelines",
            ));
        }

        out.fill(0);

        // Per RFC 2104 Section 2, save our inner digest to calculate our
        // outer digest. Note that we can't (necessarily) reuse out as a
        // scratch pad here: if we're truncating the output but not
        // truncating the underlying hashes, we'd lose bytes and compute an
        // invalid outer hashes.
        // TODO: rework this to be no_std friendly (ie no vec!)
        let mut ihash = vec![0u8; self.hasher.output_len()];
        // `HMAC` implements `Drop` (required by `Secret`), so we cannot move `self.hasher` out
        // directly. Swap in a fresh default and consume the taken-out hasher instead.
        core::mem::take(&mut self.hasher).do_final_out(&mut ihash);

        // ohash
        self.hasher = HASH::default();
        self.pad_key_into_hasher(OPAD_BYTE);
        self.hasher.do_update(&ihash);
        Ok(core::mem::take(&mut self.hasher).do_final_out(out))
    }
}

// TODO: potential feature: add an interface that pre-computes the intermediate values (K XOR ipad) and (K XOR opad)
// TODO for a given key as described in RFC2104 section 4.
// TODO: This is essentially a "batch mode" where you want to perform many MACs or Verifications with the same key
// TODO: against different data.

impl<HASH: Hash + Default, PARAMS: HMACParams> MAC for HMAC<HASH, PARAMS> {
    fn new(key: &impl KeyMaterialTrait) -> Result<Self, MACError> {
        let mut hmac = Self {
            _phantom_params: PhantomData,
            hasher: HASH::default(),
            key: Secret::new(),
            key_len: Secret::new(),
        };
        hmac.init(key, false)?;
        Ok(hmac)
    }

    fn new_allow_weak_key(key: &impl KeyMaterialTrait) -> Result<Self, MACError> {
        let mut hmac = Self {
            _phantom_params: PhantomData,
            hasher: HASH::default(),
            key: Secret::new(),
            key_len: Secret::new(),
        };
        hmac.init(key, true)?;
        Ok(hmac)
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
        // Same source as the key check in `init()`, so the strength this reports and the strength
        // that gets enforced cannot drift apart.
        PARAMS::MAX_SECURITY_STRENGTH
    }
}

/* SerializedState */

/// HMAC is a keyed algorithm, so it implements [`SuspendableKeyed`] (rather than
/// [`Suspendable`]) for suspending and resuming in-progress operations.
/// The key is deliberately NOT written into the serialized
/// bytes and must be re-supplied at deserialization.
///
/// The serialized state is exactly the inner hasher's state (which has already absorbed `K ⊕ ipad`
/// and any message chunks provided so far) — so this is a straight passthrough to the underlying hash's
/// [`Suspendable`] impl. The re-supplied key is needed to reconstruct the material for the outer
/// (`K ⊕ opad`) step at finalization.
///
/// There is no way to detect a mismatched key on
/// resume: the caller MUST supply the same key the HMAC was created with, otherwise the resumed
/// operation will silently produce an incorrect MAC.
impl<
    const HASH_STATE_LEN: usize,
    HASH: Hash + Default + Suspendable<HASH_STATE_LEN>,
    PARAMS: HMACParams,
> SuspendableKeyed<HASH_STATE_LEN> for HMAC<HASH, PARAMS>
{
    // HMAC accepts any key material, so the key type is the trait object `dyn KeyMaterialTrait`
    // rather than a single concrete key type. The key is only used (by reference) to reload the key
    // bytes at from_serialized_state, so dynamic dispatch here is negligible.
    type Key = dyn KeyMaterialTrait;

    fn suspend(mut self) -> [u8; HASH_STATE_LEN] {
        // The key is intentionally excluded; the resumable state is just the inner hasher, which
        // already carries the library version header from the hash's own SerializableState impl.
        // `HMAC` implements `Drop` (required by `Secret`), so move the hasher out via `mem::take`
        // rather than a direct partial move.
        core::mem::take(&mut self.hasher).suspend()
    }

    fn from_suspended(
        state: [u8; HASH_STATE_LEN],
        key: &Self::Key,
    ) -> Result<Self, SuspendableError> {
        // Rebuild the inner hasher (version-compatibility is validated by the hash's impl).
        let hasher = HASH::from_suspended(state)?;

        // Re-load the key material exactly as `new()` did (pre-hashing an over-length key), but do
        // NOT re-absorb `K ⊕ ipad` — the deserialized hasher already contains it. The key is only
        // needed for the outer `K ⊕ opad` step at finalization.
        let mut hmac = HMAC {
            _phantom_params: PhantomData,
            hasher,
            key: Secret::new(),
            key_len: Secret::new(),
        };
        hmac.load_key_material(key.ref_to_bytes());

        Ok(hmac)
    }
}

/* KeyGen functions */

impl<HASH: Hash + Default, PARAMS: HMACParams> HMAC<HASH, PARAMS> {
    /// Generates a key of the appropriate length for this HMAC from the provided RNG, tagged
    /// [`KeyType::MACKey`] and ready to hand to [`MAC::new`].
    ///
    /// The key length is the underlying hash's output length ([`HashAlgParams::OUTPUT_LEN`], carried
    /// as [`HMACParams::MACKey`]); see that associated type for why.
    ///
    // Dev note: done this way to avoid this crate needing a dependency on the `bouncycastle-rng` crate,
    //           which itself has a dependency on `bouncycastle-sha2` which depends on this hmac crate,
    //           which creates a circular cargo dependency.
    pub fn keygen_from_rng(rng: &mut dyn RNG) -> Result<PARAMS::MACKey, RNGError> {
        // Refuse to generate a key from an RNG that cannot back the strength this HMAC claims;
        // otherwise the key's tagged security strength would overstate its true entropy.
        if rng.security_strength() < PARAMS::MAX_SECURITY_STRENGTH {
            return Err(RNGError::SecurityStrengthInsufficientForAlgorithm);
        }

        let mut key = PARAMS::MACKey::default();
        rng.fill_keymaterial_out(&mut key)?;
        key.set_key_type(KeyType::MACKey)?;
        Ok(key)
    }
}

impl<HASH: Hash + Default, PARAMS: HMACParams> Algorithm for HMAC<HASH, PARAMS> {
    const ALG_NAME: &'static str = PARAMS::ALG_NAME;
    // An HMAC claims the security strength of the hash underneath it. Reading it off the hash rather
    // than restating it per instantiation keeps the advertised strength identical to the one
    // `HMAC::init` enforces against the key, which it takes from `P::max_security_strength`.
    const MAX_SECURITY_STRENGTH: SecurityStrength = PARAMS::MAX_SECURITY_STRENGTH;
}

impl<HASH: Hash + Default, PARAMS: HMACParams> AlgorithmOID for HMAC<HASH, PARAMS> {
    const OID: &'static [u32] = PARAMS::OID;
    const OID_DER: &'static [u8] = PARAMS::OID_DER;
}
