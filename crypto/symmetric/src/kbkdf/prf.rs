//! The pseudorandom functions the iterated KDFs are instantiated over (SP 800-108r1 Section 3):
//! "this Recommendation approves the use of the keyed-Hash Message Authentication Code (HMAC)
//! ..., the Cipher-based Message Authentication Code (CMAC) ..., and the Keccak-based Message
//! Authentication Code (KMAC) ... as pseudorandom functions". KMAC is not iterated (Section 4.4)
//! and so is not a [`Prf`].

use crate::BlockCipherKey;
use crate::aes::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use crate::kbkdf::{k_in_into, k_in_len};
use crate::modes::CMAC;
use bouncycastle_core::errors::KDFError;
use bouncycastle_core::hazmat::KeyExpansion;
use bouncycastle_core::hazmat::Mode;
use bouncycastle_core::hazmat::{do_hazardous_operations, finish_token};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{FromAnyKeyMaterial, FromKeyMaterial, MacGenerationKey};
use bouncycastle_core::traits::{Algorithm, MACGenerator};
use bouncycastle_digest::hmac::{
    HMACParams, HmacKey, LARGEST_HASHER_BLOCK_LEN, hazmat as hmac_hazmat,
};
use bouncycastle_utils::secret::Secret;
use core::marker::PhantomData;

/// The largest PRF output, in bytes, the KDFs' block buffers hold: 64, HMAC-SHA512's. A PRF with
/// a longer output is refused at compile time.
pub(in crate::kbkdf) const MAX_PRF_OUTPUT_LEN: usize = 64;

pub(in crate::kbkdf) mod sealed {
    use bouncycastle_core::errors::KDFError;
    use bouncycastle_core::key_material::KeyMaterialTrait;
    use bouncycastle_core::security_strength::SecurityStrength;

    /// What the two keyed methods of [`PrfInternal`] take: only this module can make one, so only
    /// this module can call them. A bound `P: Prf` reaches a supertrait's items from outside,
    /// and without this they would be a raw keyed PRF over a key built without its checks.
    pub struct Token(());

    impl Token {
        pub(in crate::kbkdf) const fn new() -> Self {
            Self(())
        }
    }

    /// What the KDFs use of a PRF and a caller does not. As a supertrait that cannot be named
    /// outside the module, it seals [`Prf`](super::Prf); its constants and `Key` can still be
    /// read through a `P: Prf` bound, its methods cannot be called (see [`Token`]).
    pub trait PrfInternal {
        /// The most a derivation over this PRF claims for its output.
        const MAX_SECURITY_STRENGTH: SecurityStrength;
        /// The bytes of full-entropy keying material a key-derivation key must carry for the
        /// output to be typed `CryptographicRandom`.
        const SEED_LEN: usize;
        /// The PRF's name, as it appears in the KDFs' algorithm names.
        const NAME: &'static str;

        /// The PRF keyed with a key-derivation key.
        type Key;

        /// Keys the PRF with `K_IN`, the concatenation of `keys`.
        fn key<K: KeyMaterialTrait + ?Sized>(
            keys: &[&K],
            token: &Token,
        ) -> Result<Self::Key, KDFError>;

        /// `PRF(K_IN, parts[0] || parts[1] || ...)` into the front of `out`, which must hold
        /// [`Prf::H_LEN`](super::Prf::H_LEN) bytes; returns `H_LEN`.
        fn prf_into(key: &Self::Key, parts: &[&[u8]], out: &mut [u8], token: &Token) -> usize;
    }

    /// Seals [`KmacKdfParams`](crate::kbkdf::KmacKdfParams).
    pub trait Sealed {}
}

/// A pseudorandom function `PRF(K_IN, x)` of SP 800-108r1 Section 3, as the iterated KDFs use
/// one: keyed once with the key-derivation key, then run over each iteration's input. Sealed:
/// the implementations are this module's.
pub trait Prf: sealed::PrfInternal {
    /// `h`, "the length of the output of a single invocation of the PRF", in bytes.
    const H_LEN: usize;
}

/// HMAC over the hash `H` as the PRF: "When HMAC is used as the PRF, K_IN is used as the HMAC
/// key, and the other input data is used as the value of text" (SP 800-108r1 Section 4).
#[allow(non_camel_case_types)]
pub struct PRF_HMAC<H: HMACParams> {
    _hash: PhantomData<H>,
}

impl<H: HMACParams> Prf for PRF_HMAC<H> {
    const H_LEN: usize = H::OUTPUT_LEN;
}

impl<H: HMACParams> sealed::PrfInternal for PRF_HMAC<H> {
    const MAX_SECURITY_STRENGTH: SecurityStrength = H::HMAC_MAX_SECURITY_STRENGTH;
    /// The library's rule for a hash-based KDF, HKDF's: half a hash output.
    const SEED_LEN: usize = H::OUTPUT_LEN / 2;
    const NAME: &'static str = H::HMAC_ALG_NAME;

    type Key = HmacKey<H>;

    fn key<K: KeyMaterialTrait + ?Sized>(
        keys: &[&K],
        _: &sealed::Token,
    ) -> Result<Self::Key, KDFError> {
        const { assert!(H::BLOCK_LEN <= LARGEST_HASHER_BLOCK_LEN) };
        const { assert!(H::OUTPUT_LEN <= MAX_PRF_OUTPUT_LEN) };

        // [`HmacKey`] takes one `MACKey`, so K_IN is copied and re-typed as the MAC key it is
        // here. RFC 2104 Section 3 replaces a key longer than a block by its hash, which is
        // done over the keys in order when their concatenation is that long, so the copy keys
        // HMAC exactly as the concatenation would and never outgrows a block.
        let mut k_in = Secret::<[u8; LARGEST_HASHER_BLOCK_LEN]>::new();
        let k_in_len = if k_in_len(keys) > H::BLOCK_LEN {
            let mut hash = H::default();
            for key in keys {
                hash.do_update(key.ref_to_bytes());
            }
            hash.finish_into(&finish_token(), &mut k_in[..H::OUTPUT_LEN])
        } else {
            k_in_into(keys, &mut k_in[..])
        };
        let mac_key = KeyMaterial::<LARGEST_HASHER_BLOCK_LEN>::from_bytes_as_type(
            &k_in[..k_in_len],
            KeyType::MACKey,
        )?;
        // A key-derivation key of any strength derives; what the output may claim is settled
        // by the KDF from the keys' own types, not here.
        Ok(HmacKey::<H>::from_key_material_allow_weak(&mac_key)?)
    }

    fn prf_into(key: &Self::Key, parts: &[&[u8]], out: &mut [u8], _: &sealed::Token) -> usize {
        // The HMAC as its two hazmat halves: the role traits name the tag length as a const,
        // which `H: HMACParams` alone does not give.
        let mut inner = hmac_hazmat::inner_state(key);
        for part in parts {
            inner.do_update(part);
        }
        hmac_hazmat::finish_out(key, &mut inner, &mut out[..H::OUTPUT_LEN])
    }
}

/// CMAC over the block cipher `P` as the PRF: "When CMAC is used as the PRF, K_IN is used as
/// the block cipher key, and the other input data is used as the message M" (SP 800-108r1
/// Section 4). A [`Prf`] for the three AES key lengths, [`PRF_CMAC_AES128`], [`PRF_CMAC_AES192`]
/// and [`PRF_CMAC_AES256`].
///
/// The key-derivation key must be exactly the cipher's key length (Section 6.2: "an
/// implementation should check whether the key-derivation key length is consistent with the
/// length required by the PRF"); any other length is refused, a zero-length key included.
///
/// See the module's Security Considerations on key control before choosing CMAC.
#[allow(non_camel_case_types)]
pub struct PRF_CMAC<P> {
    _cipher: PhantomData<P>,
}

/// AES's block length, which is CMAC's output length over it.
const AES_BLOCK_LEN: usize = 16;

/// The CMAC key for `K_IN`, the concatenation of `keys`, which must be `KEY_LEN` bytes.
fn cmac_key<P, K, const KEY_LEN: usize>(keys: &[&K]) -> Result<BlockCipherKey<P, CMAC>, KDFError>
where
    P: KeyExpansion<KEY_LEN>,
    CMAC: Mode<P>,
    K: KeyMaterialTrait + ?Sized,
{
    if k_in_len(keys) != KEY_LEN {
        return Err(KDFError::InvalidLength(
            "the key-derivation key must be the block cipher's key length",
        ));
    }
    // The key object takes one `MACKey` of the cipher's length, so K_IN is copied and re-typed
    // as the MAC key it is here; what the output may claim is settled by the KDF from the
    // keys' own types.
    let mut k_in = Secret::<[u8; KEY_LEN]>::new();
    k_in_into(keys, &mut k_in[..]);
    let mut mac_key = KeyMaterial::<KEY_LEN>::from_bytes_as_type(&k_in[..], KeyType::MACKey)?;
    // An all-zero K_IN comes back typed `Zeroized` with no strength, which the cipher's key
    // object refuses; the `KDF` trait derives from such a key (and types the output `Unknown`),
    // so the copy is typed as what a key of this length is.
    do_hazardous_operations(&mut mac_key, |k| {
        k.set_key_type(KeyType::MACKey)?;
        k.set_security_strength(SecurityStrength::from_bytes(KEY_LEN))
    })?;
    // With the type, the length and the strength settled above, the key object has nothing
    // left to refuse.
    BlockCipherKey::<P, CMAC>::from_key_material(&mac_key)
        .map_err(|_| KDFError::GenericError("the block cipher refused the key-derivation key"))
}

/// CMAC under `key` over the concatenation of `parts`, into the front of `out`.
fn cmac_into<Key: MacGenerationKey<AES_BLOCK_LEN>>(
    key: &Key,
    parts: &[&[u8]],
    out: &mut [u8],
) -> usize {
    let mut generator = key.create_generator();
    for part in parts {
        generator.do_update(part);
    }
    // The KDFs hand every PRF a buffer of its own H_LEN, which is one block here.
    // A shorter one is a defect in this module, and a silent zero-length block would derive from
    // nothing: the panic is the louder of the two failures.
    let tag = out.first_chunk_mut::<AES_BLOCK_LEN>().expect("the buffer holds one block");
    generator.do_final_out(tag)
}

/// CMAC over AES-128 as the PRF.
#[allow(non_camel_case_types)]
pub type PRF_CMAC_AES128 = PRF_CMAC<AES128Internal>;
/// CMAC over AES-192 as the PRF.
#[allow(non_camel_case_types)]
pub type PRF_CMAC_AES192 = PRF_CMAC<AES192Internal>;
/// CMAC over AES-256 as the PRF.
#[allow(non_camel_case_types)]
pub type PRF_CMAC_AES256 = PRF_CMAC<AES256Internal>;

impl Prf for PRF_CMAC_AES128 {
    const H_LEN: usize = AES_BLOCK_LEN;
}
impl Prf for PRF_CMAC_AES192 {
    const H_LEN: usize = AES_BLOCK_LEN;
}
impl Prf for PRF_CMAC_AES256 {
    const H_LEN: usize = AES_BLOCK_LEN;
}

impl sealed::PrfInternal for PRF_CMAC_AES128 {
    const MAX_SECURITY_STRENGTH: SecurityStrength = AES128Internal::MAX_SECURITY_STRENGTH;
    /// The whole key.
    const SEED_LEN: usize = 16;
    const NAME: &'static str = "CMAC-AES128";

    type Key = BlockCipherKey<AES128Internal, CMAC>;

    fn key<K: KeyMaterialTrait + ?Sized>(
        keys: &[&K],
        _: &sealed::Token,
    ) -> Result<Self::Key, KDFError> {
        cmac_key::<AES128Internal, K, 16>(keys)
    }

    fn prf_into(key: &Self::Key, parts: &[&[u8]], out: &mut [u8], _: &sealed::Token) -> usize {
        cmac_into(key, parts, out)
    }
}

impl sealed::PrfInternal for PRF_CMAC_AES192 {
    const MAX_SECURITY_STRENGTH: SecurityStrength = AES192Internal::MAX_SECURITY_STRENGTH;
    /// The whole key.
    const SEED_LEN: usize = 24;
    const NAME: &'static str = "CMAC-AES192";

    type Key = BlockCipherKey<AES192Internal, CMAC>;

    fn key<K: KeyMaterialTrait + ?Sized>(
        keys: &[&K],
        _: &sealed::Token,
    ) -> Result<Self::Key, KDFError> {
        cmac_key::<AES192Internal, K, 24>(keys)
    }

    fn prf_into(key: &Self::Key, parts: &[&[u8]], out: &mut [u8], _: &sealed::Token) -> usize {
        cmac_into(key, parts, out)
    }
}

impl sealed::PrfInternal for PRF_CMAC_AES256 {
    const MAX_SECURITY_STRENGTH: SecurityStrength = AES256Internal::MAX_SECURITY_STRENGTH;
    /// The whole key.
    const SEED_LEN: usize = 32;
    const NAME: &'static str = "CMAC-AES256";

    type Key = BlockCipherKey<AES256Internal, CMAC>;

    fn key<K: KeyMaterialTrait + ?Sized>(
        keys: &[&K],
        _: &sealed::Token,
    ) -> Result<Self::Key, KDFError> {
        cmac_key::<AES256Internal, K, 32>(keys)
    }

    fn prf_into(key: &Self::Key, parts: &[&[u8]], out: &mut [u8], _: &sealed::Token) -> usize {
        cmac_into(key, parts, out)
    }
}
