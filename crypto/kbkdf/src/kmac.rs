//! The KDF Using KMAC, SP 800-108r1 Section 4.4.

use crate::label_output;
use bouncycastle_core::errors::KDFError;
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::kdf_params::KdfDescription;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, Hash, KDF, XOF, XOFSqueezer};
use bouncycastle_sha3::kmac::KMACXOFInternal;
use bouncycastle_sha3::{SHAKE128Params, SHAKE256Params, SHAKEParams};
use bouncycastle_utils::secret::Secret;
use core::marker::PhantomData;

/// The longest key-derivation key, in bytes, the KMAC KDF takes: the key is copied once, into a
/// buffer of this length, to be handed to KMAC as the MAC key it is.
pub const MAX_KMAC_KDK_LEN: usize = 512;

/// The name of the KDF Using KMAC128.
pub const KDF_KMAC128_NAME: &str = "KDF-KMAC128";
/// The name of the KDF Using KMAC256.
pub const KDF_KMAC256_NAME: &str = "KDF-KMAC256";

mod sealed {
    pub trait Sealed {}
}

/// The two KMAC functions of SP 800-185 as the KDF uses them: "KMAC# indicates the use of
/// either KMAC128 or KMAC256" (SP 800-108r1 Section 4.4). Sealed.
pub trait KmacKdfParams: SHAKEParams + sealed::Sealed {
    /// The KDF's name.
    const KDF_ALG_NAME: &'static str;
    /// Section 6.2: "KMAC128 and KMAC256 provide security strengths of no more than 128 and 256
    /// bits, respectively".
    const KDF_MAX_SECURITY_STRENGTH: SecurityStrength;
    /// The bytes of full-entropy keying material a key-derivation key must carry for the output
    /// to be typed `CryptographicRandom`: the strength, in bytes.
    const SEED_LEN: usize;
}

impl sealed::Sealed for SHAKE128Params {}
impl KmacKdfParams for SHAKE128Params {
    const KDF_ALG_NAME: &'static str = KDF_KMAC128_NAME;
    const KDF_MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
    const SEED_LEN: usize = 16;
}

impl sealed::Sealed for SHAKE256Params {}
impl KmacKdfParams for SHAKE256Params {
    const KDF_ALG_NAME: &'static str = KDF_KMAC256_NAME;
    const KDF_MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
    const SEED_LEN: usize = 32;
}

/// The KDF Using KMAC (SP 800-108r1 Section 4.4): `K_OUT = KMAC#(K_IN, Context, L, Label)`, one
/// call, with the output length `L` part of what is derived, so outputs at two lengths are
/// unrelated. Named through [`KDF_KMAC128`] and [`KDF_KMAC256`].
///
/// The key-derivation key `K_IN` is the [`KDF`] methods' input key and their `fixed_info` is
/// the Context, KMAC's main input. An instance holds the Label, KMAC's customization string,
/// which it borrows and which may be empty.
#[allow(non_camel_case_types)]
pub struct KDF_KMAC<'l, PARAMS: KmacKdfParams> {
    label: &'l [u8],
    _params: PhantomData<PARAMS>,
}

/// The KDF Using KMAC128.
#[allow(non_camel_case_types)]
pub type KDF_KMAC128<'l> = KDF_KMAC<'l, SHAKE128Params>;
/// The KDF Using KMAC256.
#[allow(non_camel_case_types)]
pub type KDF_KMAC256<'l> = KDF_KMAC<'l, SHAKE256Params>;

// Written out rather than derived: a derive would demand `PARAMS: Copy` of the marker.
impl<PARAMS: KmacKdfParams> Clone for KDF_KMAC<'_, PARAMS> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<PARAMS: KmacKdfParams> Copy for KDF_KMAC<'_, PARAMS> {}

impl<PARAMS: KmacKdfParams> Default for KDF_KMAC<'_, PARAMS> {
    /// The KDF with an empty Label.
    fn default() -> Self {
        Self::new(&[])
    }
}

impl<PARAMS: KmacKdfParams> Algorithm for KDF_KMAC<'_, PARAMS> {
    const ALG_NAME: &'static str = PARAMS::KDF_ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = PARAMS::KDF_MAX_SECURITY_STRENGTH;
}

/// The one parameter is a readable field ([`KDF_KMAC::label`]), so the KDF describes itself:
/// the engine is a copy.
impl<PARAMS: KmacKdfParams> KdfDescription for KDF_KMAC<'_, PARAMS> {
    type Engine = Self;

    fn engine(&self) -> Result<Self, KDFError> {
        Ok(*self)
    }
}

impl<'l, PARAMS: KmacKdfParams> KDF_KMAC<'l, PARAMS> {
    /// The KDF with `label` as the Label, "an optional customization bit string; for example,
    /// Label can be an encoding of the characters "KDF" or "KDF4X" in 8-bit ASCII".
    pub fn new(label: &'l [u8]) -> Self {
        Self { label, _params: PhantomData }
    }

    /// The Label.
    pub fn label(&self) -> &'l [u8] {
        self.label
    }

    /// Section 4.4: `L = 8 * len` bits of keying material from `K_IN`, the concatenation of
    /// `keys`, and the Context, written to the front of `dkm`, which is zeroized first.
    fn derive_keys_out<K: KeyMaterialTrait + ?Sized>(
        &self,
        keys: &[&K],
        context: &[u8],
        len: usize,
        dkm: &mut (impl KeyMaterialTrait + ?Sized),
    ) -> Result<usize, KDFError> {
        // The `_out` rule: nothing stale survives, whichever way this returns.
        dkm.zeroize();

        if len == 0 {
            return Err(KDFError::InvalidLength("a zero-length derivation is refused"));
        }
        if keys.is_empty() {
            return Err(KDFError::InvalidLength("a derivation from no keys is refused"));
        }
        // Step 1, "If L > 2^1040 - 1, output an error indicator", cannot arise: a length in
        // bytes held in a usize is far below it.
        if len > dkm.capacity() {
            return Err(KDFError::InvalidLength("the output buffer cannot hold L bits"));
        }
        let total = keys.iter().fold(0usize, |n, k| n.saturating_add(k.key_len()));
        if total > MAX_KMAC_KDK_LEN {
            return Err(KDFError::InvalidLength(
                "the key-derivation key is longer than this KDF takes",
            ));
        }

        // KMAC takes one `MACKey`, so K_IN is copied and re-typed as the MAC key it is here; a
        // key of any strength derives, and what the output may claim is settled from the keys'
        // own types.
        let mut k_in = Secret::<[u8; MAX_KMAC_KDK_LEN]>::new();
        let mut at = 0;
        for key in keys {
            let bytes = key.ref_to_bytes();
            k_in[at..at + bytes.len()].copy_from_slice(bytes);
            at += bytes.len();
        }
        let mac_key =
            KeyMaterial::<MAX_KMAC_KDK_LEN>::from_bytes_as_type(&k_in[..at], KeyType::MACKey)?;

        // Step 2: K_OUT = KMAC#(K_IN, Context, L, Label). The length is bound by making the
        // squeezer's only read its final one, which is the fixed-length KMAC of SP 800-185
        // Section 4.3 at that length and not a prefix of the KMACXOF stream, as Section 4.4
        // requires: "KMAC128 or KMAC256 shall be used for the key-derivation function".
        let mut kmac = KMACXOFInternal::<PARAMS>::new(&mac_key, self.label, true)?;
        kmac.do_update(context);
        let filled = do_hazardous_operations(dkm, |dkm| {
            let out = dkm.ref_to_bytes_mut()?;
            kmac.into_squeezer().do_output_final_out(&mut out[..len]);
            Ok(())
        });
        let labelled = filled.and_then(|()| {
            label_output(keys, len, PARAMS::SEED_LEN, PARAMS::KDF_MAX_SECURITY_STRENGTH, dkm)
        });
        if labelled.is_err() {
            dkm.zeroize();
        }
        labelled?;
        Ok(len)
    }
}

impl<PARAMS: KmacKdfParams> KDF for KDF_KMAC<'_, PARAMS> {
    /// Section 4.4 with `K_IN` the key `ikm` and `fixed_info` the Context.
    ///
    /// # Errors
    /// [`KDFError::InvalidLength`] if `len` is zero or exceeds the buffer's capacity, or if
    /// the key is longer than [`MAX_KMAC_KDK_LEN`]; the buffer is left zeroized.
    fn derive_key_out(
        &self,
        ikm: &dyn KeyMaterialTrait,
        fixed_info: &[u8],
        len: usize,
        output_key: &mut dyn KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        self.derive_keys_out(&[ikm], fixed_info, len, output_key)
    }

    /// [`KDF::derive_key_out`] with `K_IN` the bare concatenation of `ikms`; an empty `ikms` is
    /// [`KDFError::InvalidLength`].
    fn derive_key_from_multiple_out(
        &self,
        ikms: &[&dyn KeyMaterialTrait],
        fixed_info: &[u8],
        len: usize,
        output_key: &mut dyn KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        self.derive_keys_out(ikms, fixed_info, len, output_key)
    }
}
