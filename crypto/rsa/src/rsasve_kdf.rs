//! RSASVE with its secret value derived through HKDF, over [`KdfParams`]: the KEM roles the
//! key-establishment keys of [`crate::rsasve`] carry a second time, with the KDF's description,
//! the fixed info and the derived key's length as the parameters, so that the key handed out
//! is a key and not SP 800-56B Rev. 2's secret value `Z`, which the standard passes through a
//! key-derivation method (its Section 5.5) before any use. The algorithm is
//! [`RSASVE_HKDF<K, H>`], `RSASVE-2048-HKDF-SHA256` and so on, for any modulus size and any
//! HMAC hash, at the lesser of the two strengths.
//!
//! The derived key is HKDF-Hash(salt, Z, info) over RSASVE's `Z`, the salt the description's
//! ([`HkdfDescription`]), the info and the length the caller's [`KdfParams`], the length from
//! one byte to 255 hash outputs (RFC 5869 Section 2.3), checked at compile time where a worker
//! is made. The length is part of the protocol's agreement as the info is, and it does not
//! separate keys: the key at one length is a prefix of the key at a longer one under the same
//! info, so two keys from one encapsulation take two infos. The ciphertext is not fed into the
//! info: `Z` is what the ciphertext encrypts, so it is bound to the ciphertext already, and the
//! public key is the protocol's to bind through the info if it wants it. The description is
//! readable, so a key held in a token that runs RSASVE and HKDF inside the device can be handed
//! the same parameters; see the crate's `# Scope`.

use crate::rsasve::{RsaKEMPrivateKey, RsaKEMPublicKey};
use crate::size::{RsaSigningSize, RsaSize, min_strength};
use bouncycastle_core::errors::KEMError;
use bouncycastle_core::kdf_params::{KdfDescription, KdfParams};
use bouncycastle_core::kem_key::{DecapsulatingKey, EncapsulatingKey, KEMAlgorithm};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, KDF, KEMDecapsulator, KEMEncapsulator, RNG};
use bouncycastle_hkdf::HkdfDescription;
use bouncycastle_hmac::HMACParams;
use bouncycastle_utils::const_str::ConstStr;
use core::marker::PhantomData;

/// RSASVE at the modulus size `K` with the secret value derived through HKDF over `H`: the
/// algorithm the key-establishment keys run when made into a worker from
/// `KdfParams<'p, HkdfDescription<'s, H>, LEN>`. Named `RSASVE-<bits>-HKDF-<hash>`, at the
/// lesser of the size's and the hash's strength (HKDF-SHA256 caps a key at 128 bits, so
/// RSA-2048 with it is 112 and RSA-4096 with it 128).
#[allow(non_camel_case_types)]
pub struct RSASVE_HKDF<K: RsaSize, H: HMACParams> {
    _params: PhantomData<(K, H)>,
}

impl<K: RsaSize, H: HMACParams> RSASVE_HKDF<K, H> {
    const NAME: ConstStr<32> = ConstStr::concat(&["RSASVE-", K::BITS_NAME, "-", H::HKDF_ALG_NAME]);

    /// The most bytes one derivation produces: 255 hash outputs (RFC 5869 Section 2.3).
    pub const MAX_LEN: usize = 255 * H::OUTPUT_LEN;
}

impl<K: RsaSize, H: HMACParams> Algorithm for RSASVE_HKDF<K, H> {
    const ALG_NAME: &'static str = Self::NAME.as_str();
    const MAX_SECURITY_STRENGTH: SecurityStrength =
        min_strength(K::STRENGTH, H::MAX_SECURITY_STRENGTH);
}

impl<K: RsaSize, H: HMACParams> KEMAlgorithm for RSASVE_HKDF<K, H> {}

/// The length check, a compile-time error where it is evaluated: `SS_LEN` is from one byte to
/// [`RSASVE_HKDF::MAX_LEN`]. The role impls evaluate it when a worker is made, and `derive`
/// does, so no worker exists at a length no derivation accepts.
const fn len_check<H: HMACParams, const SS_LEN: usize>() {
    assert!(
        SS_LEN > 0 && SS_LEN <= 255 * H::OUTPUT_LEN,
        "the derived key is from one byte to the KDF's MAX_LEN long"
    );
}

/// HKDF(Z, info) into `out`, zeroized first: a key of `SS_LEN` bytes, labelled at no more than
/// the algorithm's strength. The engine is built from the description for this derivation, an
/// HKDF keyed with the salt.
///
/// # Errors
/// [`KEMError::KDFError`] with what HKDF refused, building the engine or deriving;
/// [`KEMError::GenericError`] if it writes anything but `SS_LEN` bytes. `out` is left zeroized.
#[allow(non_snake_case)]
fn derive<K: RsaSize, H: HMACParams, const N: usize, const SS_LEN: usize>(
    params: KdfParams<'_, HkdfDescription<'_, H>, SS_LEN>,
    Z: &KeyMaterial<N>,
    out: &mut KeyMaterial<SS_LEN>,
) -> Result<(), KEMError> {
    const { len_check::<H, SS_LEN>() };
    out.zeroize();
    let kdf = params.kdf().engine().map_err(KEMError::KDFError)?;
    // `derive_key_out` zeroizes `out` first and leaves it so on its errors.
    let written = kdf.derive_key_out(Z, params.info(), SS_LEN, out).map_err(KEMError::KDFError)?;
    if written != SS_LEN || out.key_len() != SS_LEN {
        out.zeroize();
        return Err(KEMError::GenericError("the KDF derived a key of the wrong length"));
    }
    // The label is the pairing's: HKDF credits a secret salt and would label the key above the
    // modulus's strength, which this algorithm does not claim. Lowering needs no window.
    let strength =
        min_strength(out.security_strength(), RSASVE_HKDF::<K, H>::MAX_SECURITY_STRENGTH);
    if out.set_security_strength(strength).is_err() {
        out.zeroize();
        return Err(KEMError::GenericError("the derived key's strength could not be set"));
    }
    Ok(())
}

/// The encapsulator [`EncapsulatingKey::create_encapsulator`] hands out over [`KdfParams`]: it
/// borrows the key, holds the parameters, and derives the key from each encapsulation's `Z`.
pub struct RsasveKdfEncapsulator<'k, 'p, 's, K: RsaSize, H: HMACParams, const SS_LEN: usize> {
    pk: &'k RsaKEMPublicKey<K>,
    params: KdfParams<'p, HkdfDescription<'s, H>, SS_LEN>,
}

impl<K: RsaSize, H: HMACParams, const SS_LEN: usize> Algorithm
    for RsasveKdfEncapsulator<'_, '_, '_, K, H, SS_LEN>
{
    const ALG_NAME: &'static str = RSASVE_HKDF::<K, H>::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = RSASVE_HKDF::<K, H>::MAX_SECURITY_STRENGTH;
}

impl<K, H, const N: usize, const SS_LEN: usize> KEMEncapsulator<N, SS_LEN>
    for RsasveKdfEncapsulator<'_, '_, '_, K, H, SS_LEN>
where
    K: RsaSize<Modulus = [u8; N]>,
    H: HMACParams,
{
    /// RSASVE.GENERATE for `Z` and the ciphertext, then HKDF over `Z`. `Z` lives in one local,
    /// zeroized when it drops; a ciphertext for a key the caller never gets is not left in the
    /// buffer.
    #[allow(non_snake_case)]
    fn encaps_out(
        &self,
        rng: &mut dyn RNG,
        ct: &mut [u8; N],
        ss: &mut KeyMaterial<SS_LEN>,
    ) -> Result<usize, KEMError> {
        ss.zeroize();
        let mut Z = KeyMaterial::<N>::new();
        self.pk.create_encapsulator(())?.encaps_out(rng, ct, &mut Z)?;
        if let Err(e) = derive::<K, H, N, SS_LEN>(self.params, &Z, ss) {
            ct.fill(0);
            return Err(e);
        }
        Ok(N)
    }
}

/// The decapsulator [`DecapsulatingKey::create_decapsulator`] hands out over [`KdfParams`]: it
/// borrows the key, holds the parameters, and derives the key from each ciphertext's `Z`.
pub struct RsasveKdfDecapsulator<'k, 'p, 's, K: RsaSize, H: HMACParams, const SS_LEN: usize> {
    sk: &'k RsaKEMPrivateKey<K>,
    params: KdfParams<'p, HkdfDescription<'s, H>, SS_LEN>,
}

impl<K: RsaSize, H: HMACParams, const SS_LEN: usize> Algorithm
    for RsasveKdfDecapsulator<'_, '_, '_, K, H, SS_LEN>
{
    const ALG_NAME: &'static str = RSASVE_HKDF::<K, H>::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = RSASVE_HKDF::<K, H>::MAX_SECURITY_STRENGTH;
}

impl<K, H, const N: usize, const SS_LEN: usize> KEMDecapsulator<N, SS_LEN>
    for RsasveKdfDecapsulator<'_, '_, '_, K, H, SS_LEN>
where
    K: RsaSigningSize + RsaSize<Modulus = [u8; N]>,
    H: HMACParams,
{
    /// RSASVE.RECOVER for `Z`, then HKDF over it; a ciphertext RSASVE refuses is refused here
    /// with the caller's buffer zeroized.
    #[allow(non_snake_case)]
    fn decaps_out(&self, ct: &[u8; N], ss: &mut KeyMaterial<SS_LEN>) -> Result<usize, KEMError> {
        ss.zeroize();
        let mut Z = KeyMaterial::<N>::new();
        self.sk.create_decapsulator(())?.decaps_out(ct, &mut Z)?;
        derive::<K, H, N, SS_LEN>(self.params, &Z, ss)?;
        Ok(SS_LEN)
    }
}

impl<'p, 's, K, H, const N: usize, const SS_LEN: usize>
    EncapsulatingKey<KdfParams<'p, HkdfDescription<'s, H>, SS_LEN>, N, SS_LEN>
    for RsaKEMPublicKey<K>
where
    K: RsaSize<Modulus = [u8; N]>,
    H: HMACParams,
{
    type Algorithm = RSASVE_HKDF<K, H>;
    type Encapsulator<'k>
        = RsasveKdfEncapsulator<'k, 'p, 's, K, H, SS_LEN>
    where
        Self: 'k;

    /// The length is checked at compile time; the description validated its salt when it was
    /// made, so this cannot fail.
    fn create_encapsulator<'k>(
        &'k self,
        params: KdfParams<'p, HkdfDescription<'s, H>, SS_LEN>,
    ) -> Result<Self::Encapsulator<'k>, KEMError> {
        const { len_check::<H, SS_LEN>() };
        Ok(RsasveKdfEncapsulator { pk: self, params })
    }
}

impl<'p, 's, K, H, const N: usize, const SS_LEN: usize>
    DecapsulatingKey<KdfParams<'p, HkdfDescription<'s, H>, SS_LEN>, N, SS_LEN>
    for RsaKEMPrivateKey<K>
where
    K: RsaSigningSize + RsaSize<Modulus = [u8; N]>,
    H: HMACParams,
{
    type Algorithm = RSASVE_HKDF<K, H>;
    type Decapsulator<'k>
        = RsasveKdfDecapsulator<'k, 'p, 's, K, H, SS_LEN>
    where
        Self: 'k;

    /// As [`EncapsulatingKey::create_encapsulator`]: cannot fail.
    fn create_decapsulator<'k>(
        &'k self,
        params: KdfParams<'p, HkdfDescription<'s, H>, SS_LEN>,
    ) -> Result<Self::Decapsulator<'k>, KEMError> {
        const { len_check::<H, SS_LEN>() };
        Ok(RsasveKdfDecapsulator { sk: self, params })
    }
}
