//! KMAC, the Keccak Message Authentication Code of NIST SP 800-185 Sec 4.
//!
//! # KMAC
//! KMAC is a [`MAC`], reached through a [`KMAC128Key`] / [`KMAC256Key`]. The key takes material
//! tagged [`KeyType::MACKey`]; `from_key_material` gives the nominal output length and
//! [`KMACKeyInternal::with_params`] chooses `S` and the output length, which is bound into the
//! function rather than a truncation of it (see [`KMAC128`]):
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::symmetric_key::{FromAnyKeyMaterial, MacGenerationKey, MacVerificationKey};
//! use bouncycastle_core::traits::MAC;
//! use bouncycastle_sha3::kmac::KMAC128Key;
//!
//! let material = KeyMaterial256::from_bytes_as_type(&[0x42u8; 32], KeyType::MACKey).unwrap();
//! let key = KMAC128Key::from_key_material(&material).unwrap();
//!
//! let tag: Vec<u8> = key.mac(b"Hello, world!");
//! assert!(key.verify(b"Hello, world!", &tag));
//!
//! // 16-byte tags, under a customization string: a different function, so a different key.
//! let short = KMAC128Key::with_params(&material, b"My Tagged Application", 16).unwrap();
//! let mut kmac = short.create_generator();
//! kmac.do_update(b"Hello, ");
//! kmac.do_update(b"world!");
//! assert_eq!(kmac.do_final().len(), 16);
//! ```
//!
//! # KMACXOF
//! KMACXOF, is an arbitrary-output-length form of KMAC and it implements the [`XOF`] trait.
//! It is a separate function from its fixed-length counterpart since its *final* read ([`XOF::xof`],
//! [`XOFSqueezer::do_output_final`]) binds its output length so that outputs of different lengths,
//! even over the same input, are completely unrelated (ie they don't have the problem that one is
//! a prefix of the other).
//!
//! See [`KMACXOF128`] for detail.
//!
//! Example of `KMACXOF128`:
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::symmetric_key::{FromAnyKeyMaterial, MacGenerationKey};
//! use bouncycastle_core::traits::{Hash, XOF, XOFSqueezer};
//! use bouncycastle_sha3::kmac::{KMAC128Key, KMACXOF128};
//!
//! let key = KeyMaterial256::from_bytes_as_type(&[0x42u8; 32], KeyType::MACKey).unwrap();
//!
//! let mut kmac = KMACXOF128::new(&key, b"", false).unwrap();
//! kmac.do_update(b"Hello, world!");
//! let mut squeezer = kmac.into_squeezer();
//! let first: Vec<u8> = squeezer.do_output(16);
//! let more: Vec<u8> = squeezer.do_output(1024);
//!
//! // A final read of 32 bytes is KMAC128 at its nominal length, not a prefix of the stream above.
//! let bound: Vec<u8> = KMACXOF128::new(&key, b"", false).unwrap().xof(b"Hello, world!", 32);
//! assert_eq!(bound, KMAC128Key::from_key_material(&key).unwrap().mac(b"Hello, world!"));
//! assert_ne!(bound[..16], first[..]);
//! ```

use crate::cshake::{CSHAKE_COMPONENT_LEN, CSHAKEInternal, CSHAKESqueezer, right_encode};
use crate::{SHAKE128Params, SHAKE256Params, SHAKEParams};
use bouncycastle_core::errors::{HashError, KeyMaterialError, MACError, SuspendableError};
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{FromAnyKeyMaterial, MacGenerationKey, MacVerificationKey};
use bouncycastle_core::traits::{Algorithm, Hash, MAC, RNG, Suspendable, XOF, XOFSqueezer};
use bouncycastle_utils::ct;
use bouncycastle_utils::suspendable_state::{
    Cursor, CursorMut, LIB_VERSION_LEN, SuspendableComponent, bounded_usize, resume_component,
    suspend_component,
};

/// The name of the KMAC128 algorithm (NIST SP 800-185 Sec 4).
pub const KMAC128_NAME: &str = "KMAC128";
/// The name of the KMAC256 algorithm (NIST SP 800-185 Sec 4).
pub const KMAC256_NAME: &str = "KMAC256";
/// The name of the KMACXOF128 algorithm (NIST SP 800-185 Sec 4.3.1).
pub const KMACXOF128_NAME: &str = "KMACXOF128";
/// The name of the KMACXOF256 algorithm (NIST SP 800-185 Sec 4.3.1).
pub const KMACXOF256_NAME: &str = "KMACXOF256";

/// The shortest KMAC output, in bytes. SP 800-185 Sec 8.4.2: applications "shall not select an
/// output length L that is less than 32 bits".
pub const KMAC_MIN_OUTPUT_LEN: usize = 4;
/// The longest KMAC output, in bytes: `8 * n` is what `right_encode` absorbs (Sec 4.3 step 1),
/// and it is a `u64` here.
pub const KMAC_MAX_OUTPUT_LEN: usize = (u64::MAX / 8) as usize;

/// KMAC128: the Keccak MAC of NIST SP 800-185 Sec 4, at a 128-bit security strength.
///
/// The worker a [`KMAC128Key`] hands out: `from_key_material` gives the common case -- no
/// customization, 32-byte output -- and [`KMACKeyInternal::with_params`] chooses the
/// customization string and output length. [`KMACXOF128`] is the separate arbitrary-length
/// function of Sec 4.3.1.
pub type KMAC128 = KMACInternal<SHAKE128Params>;
/// KMAC256: the Keccak MAC of NIST SP 800-185 Sec 4, at a 256-bit security strength.
///
/// See [`KMAC128`]. The nominal output length is 64 bytes.
pub type KMAC256 = KMACInternal<SHAKE256Params>;

/// KMACXOF128: the arbitrary-output-length KMAC of NIST SP 800-185 Sec 4.3.1.
///
/// A keyed [`XOF`]. Distinct from [`KMAC128`], and not a longer
/// view of it: over the same inputs the two produce unrelated output.
pub type KMACXOF128 = KMACXOFInternal<SHAKE128Params>;
/// KMACXOF256: the arbitrary-output-length KMAC of NIST SP 800-185 Sec 4.3.1.
///
/// See [`KMACXOF128`].
pub type KMACXOF256 = KMACXOFInternal<SHAKE256Params>;

/// Length in bytes of the suspended state of KMAC.
pub const SUSPENDED_KMAC_STATE_LEN: usize = LIB_VERSION_LEN + CSHAKE_COMPONENT_LEN + 8;
/// Length in bytes of the suspended state of KMACXOF.
pub const SUSPENDED_KMACXOF_STATE_LEN: usize = LIB_VERSION_LEN + CSHAKE_COMPONENT_LEN;

/// The function-name string every KMAC binds, per SP 800-185 Sec 4.3. Fixed by the specification:
/// it is what separates KMAC from any other cSHAKE-derived function.
const KMAC_FUNCTION_NAME: &[u8] = b"KMAC";

/// Internal struct for the KMAC key. Use [`KMAC128Key`] or [`KMAC256Key`].
///
/// The key is the cSHAKE state after the key binding of Sec 4.3 step 1, `bytepad(encode_string(K),
/// rate)`, plus the customization and the output length chosen for it, so every worker starts
/// from that state and absorbs only its message. A different `S` or `L` is a different KMAC
/// function (Sec 1), and so a different key object over the same material.
#[derive(Clone)]
pub struct KMACKeyInternal<PARAMS: SHAKEParams> {
    cshake: CSHAKEInternal<PARAMS>,
    output_len: usize,
    strength: SecurityStrength,
}

/// A KMAC128 key: see [`KMACKeyInternal`].
pub type KMAC128Key = KMACKeyInternal<SHAKE128Params>;
/// A KMAC256 key: see [`KMACKeyInternal`].
pub type KMAC256Key = KMACKeyInternal<SHAKE256Params>;

impl<PARAMS: SHAKEParams> KMACKeyInternal<PARAMS> {
    /// The nominal output length: 32 bytes for KMAC128 and 64 for KMAC256.
    const NOMINAL_OUTPUT_LEN: usize = (PARAMS::SIZE as usize) / 4;

    /// A key for KMAC under a customization string and an output length of the caller's
    /// choosing. `output_len` is `L` in bytes, from [`KMAC_MIN_OUTPUT_LEN`] to
    /// [`KMAC_MAX_OUTPUT_LEN`], and is bound into the computation, so it must be the length the
    /// verifier will use; `customization` may be empty.
    ///
    /// Sec 8.4.1 requires the key to be at least as long as the security strength for approved
    /// use; that is enforced through the key's [`SecurityStrength`] tag, exactly as HMAC does,
    /// and [`Self::with_params_allow_weak`] is the escape hatch.
    ///
    /// # Errors
    /// [`MACError::InvalidLength`] if `output_len` is outside the bounds above;
    /// [`MACError::KeyMaterialError`] if the key is not tagged as a MAC key, or is tagged below
    /// this KMAC's security strength.
    pub fn with_params(
        key: &dyn KeyMaterialTrait,
        customization: &[u8],
        output_len: usize,
    ) -> Result<Self, MACError> {
        Self::check_output_len(output_len)?;
        Self::with_params_checked(key, customization, output_len, false)
    }

    /// As [`with_params`](Self::with_params) without the strength check.
    ///
    /// # Errors
    /// [`MACError::InvalidLength`] if `output_len` is outside the bounds;
    /// [`MACError::KeyMaterialError`] if the key is not tagged as a MAC key.
    pub fn with_params_allow_weak(
        key: &dyn KeyMaterialTrait,
        customization: &[u8],
        output_len: usize,
    ) -> Result<Self, MACError> {
        Self::check_output_len(output_len)?;
        Self::with_params_checked(key, customization, output_len, true)
    }

    /// The MAC's bounds on `L`. KMACXOF is the `L = 0` form (Sec 4.3.1) and does not pass here.
    fn check_output_len(output_len: usize) -> Result<(), MACError> {
        if output_len < KMAC_MIN_OUTPUT_LEN {
            return Err(MACError::InvalidLength(
                "KMAC output length is below the 32-bit floor of SP 800-185 Sec 8.4.2",
            ));
        }
        if output_len > KMAC_MAX_OUTPUT_LEN {
            return Err(MACError::InvalidLength("KMAC output length in bits does not fit a u64"));
        }
        Ok(())
    }

    /// The key binding shared with KMACXOF, which passes `output_len == 0`.
    fn with_params_checked(
        key: &dyn KeyMaterialTrait,
        customization: &[u8],
        output_len: usize,
        allow_weak_key: bool,
    ) -> Result<Self, MACError> {
        // Same stance as HMAC: an all-zero key is Zeroized rather than MACKey, and is allowed
        // through so callers are not forced to re-tag it.
        if !(key.key_type() == KeyType::Zeroized || key.key_type() == KeyType::MACKey) {
            return Err(MACError::KeyMaterialError(KeyMaterialError::InvalidKeyType(
                "Key type must be a MAC key.",
            )));
        }
        let strength = SecurityStrength::from_bits(PARAMS::SIZE as usize);
        if !allow_weak_key && key.security_strength() < strength {
            Err(KeyMaterialError::SecurityStrength(
                "KMAC: provided key has a lower security strength than the instantiated KMAC",
            ))?
        }

        let mut cshake = CSHAKEInternal::<PARAMS>::new(KMAC_FUNCTION_NAME, customization);
        // Sec 4.3 step 1: bytepad(encode_string(K), rate), absorbed rather than materialised.
        crate::cshake::absorb_bytepad_strings(&mut cshake, &[key.ref_to_bytes()]);

        Ok(Self { cshake, output_len, strength })
    }
}

impl<PARAMS: SHAKEParams> FromAnyKeyMaterial for KMACKeyInternal<PARAMS> {
    /// No customization string and the nominal output length, 32 bytes for KMAC128 and 64 for
    /// KMAC256; the errors are [`with_params`](Self::with_params)'s.
    fn from_key_material(key: &dyn KeyMaterialTrait) -> Result<Self, MACError> {
        Self::with_params(key, &[], Self::NOMINAL_OUTPUT_LEN)
    }

    /// As [`from_key_material`](Self::from_key_material) without the strength check.
    fn from_key_material_allow_weak(key: &dyn KeyMaterialTrait) -> Result<Self, MACError> {
        Self::with_params_allow_weak(key, &[], Self::NOMINAL_OUTPUT_LEN)
    }

    /// Draws a key of the security strength's length (Sec 8.4.1: 16 bytes for KMAC128, 32 for
    /// KMAC256) from `rng`, tagged [`KeyType::MACKey`] at the RNG's strength capped at what that
    /// length can carry, and builds the key from it with no customization and the nominal
    /// output length.
    ///
    /// # Errors
    /// [`MACError::KeyMaterialError`] if the RNG fails, or with
    /// [`KeyMaterialError::SecurityStrength`] if its strength is below the KMAC's.
    fn generate(rng: &mut dyn RNG) -> Result<Self, MACError> {
        let key_len = (PARAMS::SIZE as usize) / 8;
        let mut key = KeyMaterial::<32>::new();
        do_hazardous_operations(&mut key, |key| {
            rng.next_bytes_out(&mut key.ref_to_bytes_mut()?[..key_len])
                .map_err(|_| KeyMaterialError::GenericError("RNG failed."))?;
            key.set_key_len(key_len)?;
            key.set_key_type(KeyType::MACKey)?;
            // The RNG's strength, capped at what the length carries, as KeyMaterial::from_rng
            // does: a 16-byte KMAC128 key from a 256-bit DRBG is a 128-bit key.
            let by_len = SecurityStrength::from_bits(key_len * 8);
            let by_rng = rng.security_strength();
            key.set_security_strength(if by_rng < by_len { by_rng } else { by_len })
        })?;
        Self::from_key_material(&key)
    }
}

impl<PARAMS: SHAKEParams> MacGenerationKey for KMACKeyInternal<PARAMS> {
    type Generator<'k>
        = KMACInternal<PARAMS>
    where
        Self: 'k;

    fn create_generator<'k>(&'k self) -> Self::Generator<'k> {
        KMACInternal {
            cshake: self.cshake.clone(),
            output_len: self.output_len,
            strength: self.strength,
        }
    }
}

impl<PARAMS: SHAKEParams> MacVerificationKey for KMACKeyInternal<PARAMS> {
    type Verifier<'k>
        = KMACInternal<PARAMS>
    where
        Self: 'k;

    fn create_verifier<'k>(&'k self) -> Self::Verifier<'k> {
        self.create_generator()
    }
}

/// Internal struct for KMAC. Use [`KMAC128`] or [`KMAC256`].
///
/// KMAC is cSHAKE with the function name `"KMAC"`, the key bound to the front of the message and
/// the requested output length bound to the end (Sec 4.3):
///
/// ```text
/// KMAC128(K, X, L, S) = cSHAKE128(bytepad(encode_string(K), 168) || X || right_encode(L),
///                                 L, "KMAC", S)
/// ```
///
/// # Two functions, not one function truncated
///
/// The output length is *absorbed*, so KMAC at one length is unrelated to KMAC at another --
/// Sec 1 puts it as "any change in the requested output length completely changes the function".
/// That is why [`KMACKeyInternal::with_params`] takes the length up front and [`MAC::do_final`]
/// produces exactly that many bytes.
///
/// [`KMACXOFInternal`] is the separate function of Sec 4.3.1, KMACXOF, which binds
/// `right_encode(0)` instead and produces as much output as asked for. Its bytes are *not* a
/// prefix of the fixed-length KMAC over the same inputs, and are not meant to be.
#[derive(Clone)]
pub struct KMACInternal<PARAMS: SHAKEParams> {
    cshake: CSHAKEInternal<PARAMS>,
    output_len: usize,
    strength: SecurityStrength,
}

impl<PARAMS: SHAKEParams> Algorithm for KMACInternal<PARAMS> {
    const ALG_NAME: &'static str = PARAMS::KMAC_ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = PARAMS::MAX_SECURITY_STRENGTH;
}

impl<PARAMS: SHAKEParams> KMACInternal<PARAMS> {
    /// Absorbs `right_encode(value)`, the length binding of Sec 4.3 step 1.
    fn absorb_right_encode(&mut self, value: u64) {
        let (buf, len) = right_encode(value);
        self.cshake.do_update(&buf[..len]);
    }
}

impl<'k, PARAMS: SHAKEParams> SuspendableComponent<'k> for KMACInternal<PARAMS> {
    const STATE_LEN: usize = CSHAKE_COMPONENT_LEN + 8;
    type Key = ();

    fn write_state(&self, out: &mut [u8]) {
        let (cshake, rest) = out.split_at_mut(CSHAKE_COMPONENT_LEN);
        self.cshake.write_tagged(PARAMS::KMAC_STATE_TAG, cshake);
        let mut w = CursorMut::new(rest);
        w.u64(self.output_len as u64);
        debug_assert!(w.is_done());
    }

    fn read_state(state: &[u8], _key: &'k ()) -> Result<Self, SuspendableError> {
        let (cshake, rest) = state.split_at(CSHAKE_COMPONENT_LEN);
        let cshake = CSHAKEInternal::read_tagged_customized(cshake, PARAMS::KMAC_STATE_TAG)?;
        let mut r = Cursor::new(rest);
        // The bounds `with_params` applies: a state claiming a length outside them was never
        // written by this type.
        let output_len = bounded_usize(r.u64(), KMAC_MAX_OUTPUT_LEN)?;
        if output_len < KMAC_MIN_OUTPUT_LEN {
            return Err(SuspendableError::InvalidData);
        }
        debug_assert!(r.is_done());
        // The strength is fixed by the parameter set (see `with_params`), not stored.
        Ok(Self {
            cshake,
            output_len,
            strength: SecurityStrength::from_bits(PARAMS::SIZE as usize),
        })
    }
}

// `Suspendable` rather than `SuspendableKeyed`, keyed though KMAC is. `SuspendableKeyed` lets a
// state omit the key because the key is wanted again at resume -- HMAC needs it for the outer
// `K xor opad` step. KMAC's key goes into the sponge in `with_params` and is never touched
// again, so a re-supplied key could neither rebuild anything nor be checked.
/// The suspended state is not key-free: Keccak-f is a permutation, so anyone holding the state
/// and the data absorbed so far can invert it back to the key. Store it as securely as the key.
impl<PARAMS: SHAKEParams> Suspendable<SUSPENDED_KMAC_STATE_LEN> for KMACInternal<PARAMS> {
    fn suspend(self) -> [u8; SUSPENDED_KMAC_STATE_LEN] {
        suspend_component(&self)
    }

    fn from_suspended(state: [u8; SUSPENDED_KMAC_STATE_LEN]) -> Result<Self, SuspendableError> {
        resume_component(&state, &())
    }
}

impl<PARAMS: SHAKEParams> MAC for KMACInternal<PARAMS> {
    fn output_len(&self) -> usize {
        self.output_len
    }

    fn mac(mut self, data: &[u8]) -> Vec<u8> {
        self.do_update(data);
        self.do_final()
    }

    fn mac_out(mut self, data: &[u8], out: &mut [u8]) -> Result<usize, MACError> {
        out.fill(0);
        self.do_update(data);
        self.do_final_out(out)
    }

    fn verify(mut self, data: &[u8], mac: &[u8]) -> bool {
        self.do_update(data);
        self.do_verify_final(mac)
    }

    fn do_update(&mut self, data: &[u8]) {
        self.cshake.do_update(data);
    }

    fn do_final(mut self) -> Vec<u8> {
        let n = self.output_len;
        // Sec 4.3 step 1: the requested length is bound into the input before any output.
        self.absorb_right_encode((n as u64) * 8);
        self.cshake.into_squeezer().do_output(n)
    }

    fn do_final_out(mut self, out: &mut [u8]) -> Result<usize, MACError> {
        if out.len() < self.output_len {
            return Err(MACError::InvalidLength(
                "output buffer is smaller than the KMAC output length",
            ));
        }
        let n = self.output_len;
        self.absorb_right_encode((n as u64) * 8);
        // MAC::do_final_out zeroizes the entire buffer, as HMAC does, so a longer one comes back
        // with zeros after the MAC rather than whatever the caller left there.
        out[n..].fill(0);
        Ok(self.cshake.into_squeezer().do_output_out(&mut out[..n]))
    }

    /// Compares in constant time, and only against the full output length: a caller must not be
    /// able to pass verification by supplying a shorter prefix.
    fn do_verify_final(self, mac: &[u8]) -> bool {
        if mac.len() != self.output_len {
            return false;
        }
        let computed = self.do_final();
        ct::ct_eq_bytes(&computed, mac)
    }

    fn max_security_strength(&self) -> SecurityStrength {
        self.strength
    }
}

/// Internal struct for KMACXOF. Use [`KMACXOF128`] or [`KMACXOF256`].
///
/// KMACXOF is the arbitrary-output-length function of SP 800-185 Sec 4.3.1: KMAC with
/// `right_encode(0)` bound in place of the output length.
///
/// ```text
/// KMACXOF128(K, X, L, S) = cSHAKE128(bytepad(encode_string(K), 168) || X || right_encode(0),
///                                    L, "KMAC", S)
/// ```
///
/// # Why this is a separate type from [`KMACInternal`]
///
/// The Recommendation defines them as two functions, and they are: over identical inputs KMAC and
/// KMACXOF produce unrelated output, which the published sample values demonstrate directly. They
/// also want different traits -- KMAC's length is fixed at construction and bound into the
/// computation, which is `MAC`; KMACXOF's is not bound at all, which is `XOF`. Since `MAC` and
/// `Hash` share five method names (`do_update`, `do_final`, `output_len` and two more), one type
/// implementing both would make every one of those calls ambiguous, so they are separate types.
///
/// Read as a stream -- [`XOFSqueezer::do_output`] -- the length really is not bound, so output at
/// one length is a prefix of output at a longer one, the opposite of fixed-length KMAC.
///
/// Read as a *final* read, it is bound, because a caller that names a length and will not be back
/// has said what `L` is: [`XOFSqueezer::do_output_final`] and [`XOF::xof`] absorb
/// `right_encode(8n)` and so produce `KMAC(K, X, 8n, S)` exactly (see [`CSHAKESqueezer`]), and
/// the [`Hash`] view -- [`Hash::do_final`], [`Hash::hash`] and [`Hash::hash_out`] -- does the same
/// at the nominal [`Hash::output_len`], since a hash's output length is fixed by its type.
#[derive(Clone)]
pub struct KMACXOFInternal<PARAMS: SHAKEParams> {
    cshake: CSHAKEInternal<PARAMS>,
    strength: SecurityStrength,
}

impl<PARAMS: SHAKEParams> Algorithm for KMACXOFInternal<PARAMS> {
    const ALG_NAME: &'static str = PARAMS::KMACXOF_ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = PARAMS::MAX_SECURITY_STRENGTH;
}

impl<PARAMS: SHAKEParams> KMACXOFInternal<PARAMS> {
    /// A new KMACXOF under `key`, optionally customized by `customization`.
    ///
    /// The key requirements are [`KMACKeyInternal::with_params`]'s: tagged as a MAC key, and at
    /// least the security strength unless `allow_weak_key`.
    ///
    /// # Errors
    /// [`MACError::KeyMaterialError`] if the key is not a MAC key, or is tagged too weak.
    pub fn new(
        key: &impl KeyMaterialTrait,
        customization: &[u8],
        allow_weak_key: bool,
    ) -> Result<Self, MACError> {
        // The key binding is identical to KMAC's; only the length encoding differs, and that is
        // applied when output begins.
        let kmac =
            KMACKeyInternal::<PARAMS>::with_params_checked(key, customization, 0, allow_weak_key)?;
        Ok(Self { cshake: kmac.cshake, strength: kmac.strength })
    }
}

impl<'k, PARAMS: SHAKEParams> SuspendableComponent<'k> for KMACXOFInternal<PARAMS> {
    const STATE_LEN: usize = CSHAKE_COMPONENT_LEN;
    type Key = ();

    fn write_state(&self, out: &mut [u8]) {
        self.cshake.write_tagged(PARAMS::KMACXOF_STATE_TAG, out)
    }

    fn read_state(state: &[u8], _key: &'k ()) -> Result<Self, SuspendableError> {
        let cshake = CSHAKEInternal::read_tagged_customized(state, PARAMS::KMACXOF_STATE_TAG)?;
        Ok(Self { cshake, strength: SecurityStrength::from_bits(PARAMS::SIZE as usize) })
    }
}

/// The absorbing phase; the squeezing half is a [`CSHAKESqueezer`], which suspends on its
/// own. The state inverts to the key exactly as [`KMACInternal`]'s does: store it as the key.
impl<PARAMS: SHAKEParams> Suspendable<SUSPENDED_KMACXOF_STATE_LEN> for KMACXOFInternal<PARAMS> {
    fn suspend(self) -> [u8; SUSPENDED_KMACXOF_STATE_LEN] {
        suspend_component(&self)
    }

    fn from_suspended(state: [u8; SUSPENDED_KMACXOF_STATE_LEN]) -> Result<Self, SuspendableError> {
        resume_component(&state, &())
    }
}

impl<PARAMS: SHAKEParams> Hash for KMACXOFInternal<PARAMS> {
    fn block_bitlen(&self) -> usize {
        self.cshake.block_bitlen()
    }

    /// The nominal length, 32 or 64 bytes: twice the security strength of this KMAC, which is the
    /// length at which the output carries that strength in full. Reading as a XOF does not bind
    /// it; the [`Hash`] view does, because a hash has one output length and it is this one.
    fn output_len(&self) -> usize {
        self.cshake.output_len()
    }

    fn hash(mut self, data: &[u8]) -> Vec<u8> {
        self.do_update(data);
        self.do_final()
    }

    fn hash_out(mut self, data: &[u8], output: &mut [u8]) -> usize {
        self.do_update(data);
        self.do_final_out(output)
    }

    fn do_update(&mut self, data: &[u8]) {
        self.cshake.do_update(data);
    }

    /// A final read at the nominal length, so `L` is bound: this is `KMAC(K, X, 8n, S)` for
    /// `n = ` [`Hash::output_len`] -- the fixed-length KMAC of Sec 4.3, not a prefix of the
    /// KMACXOF stream.
    fn do_final(self) -> Vec<u8> {
        let n = self.output_len();
        self.into_squeezer().do_output_final(n)
    }

    fn do_final_out(self, output: &mut [u8]) -> usize {
        let n = self.output_len();
        // Per Hash::do_final_out: a short buffer is filled and the output truncated, a long one
        // takes it in its first output_len bytes and zeros after. `n` is what reaches
        // right_encode either way, so a truncated read is this KMAC cut short rather than the
        // KMAC of the buffer's length.
        let written = n.min(output.len());
        output[written..].fill(0);
        self.into_squeezer().do_final_out_with_length((n as u64) * 8, &mut output[..written])
    }

    /// # Errors
    /// Always [`HashError::InvalidLength`] for a non-zero `num_bits`: `right_encode(0)` has to
    /// follow the message, and a partial final byte would leave the sponge unable to absorb it
    /// byte-aligned. `num_bits` of 0 means the message ended on a byte boundary and is accepted.
    fn do_final_partial_bits(
        self,
        partial_byte: u8,
        num_bits: usize,
    ) -> Result<Vec<u8>, HashError> {
        let n = self.output_len();
        let mut out = vec![0u8; n];
        self.do_final_partial_bits_out(partial_byte, num_bits, &mut out)?;
        Ok(out)
    }

    fn do_final_partial_bits_out(
        self,
        _partial_byte: u8,
        num_bits: usize,
        output: &mut [u8],
    ) -> Result<usize, HashError> {
        if num_bits != 0 {
            return Err(HashError::InvalidLength(
                "KMACXOF cannot take a partial final byte: right_encode(0) must follow the message",
            ));
        }
        Ok(self.do_final_out(output))
    }

    fn max_security_strength(&self) -> SecurityStrength {
        self.strength
    }
}

impl<PARAMS: SHAKEParams> XOF for KMACXOFInternal<PARAMS> {
    type Squeezer = CSHAKESqueezer<PARAMS>;

    /// The `right_encode(L)` of Sec 4.3.1 step 1 is not absorbed here: which `L` it carries depends
    /// on how the first output is read, so [`CSHAKESqueezer`] decides it.
    fn into_squeezer(self) -> Self::Squeezer {
        CSHAKESqueezer::new(self.cshake)
    }

    fn into_squeezer_partial_bits(
        self,
        _partial_byte: u8,
        num_bits: usize,
    ) -> Result<Self::Squeezer, HashError> {
        if num_bits != 0 {
            return Err(HashError::InvalidLength(
                "KMACXOF cannot take a partial final byte: right_encode(0) must follow the message",
            ));
        }
        Ok(self.into_squeezer())
    }
}
