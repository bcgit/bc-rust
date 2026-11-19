//! The generic HMAC-based Extract-and-Expand Key Derivation Function (HKDF) construction, as per
//! RFC 5869, which NIST SP 800-56Cr2 Section 5.1 describes as "a version of the above
//! extraction-then-expansion key-derivation procedure using HMAC for both the extraction and
//! expansion steps".
//!
//! This is a utility crate and is not intended to be used directly. It provides [`HKDF`] -- the
//! construction, generic over any hash that implements [`HMACParams`], the extension point through
//! which a hash declares the metadata from which the HMAC and HKDF instances are built.
//! The library provides the following concrete instantiations of HKDF:
//!
//! | Hash family | Instantiations                                                           |
//! |-------------|--------------------------------------------------------------------------|
//! | SHA-2       | `bouncycastle_sha2::hkdf` -- `HKDF_SHA256`, `HKDF_SHA384`, `HKDF_SHA512` |
//!
//! An algorithm that derives its output through HKDF (a KEM such as ML-KEM-512-HKDF-SHA256) is
//! made from an [`HkdfDescription`], the hash and the salt as readable fields, as the KDF of a
//! `bouncycastle_core::kdf_params::KdfParams`; the pairing builds an instance keyed with the
//! salt from it for each derivation, and a key held in a token reads the fields instead.
//!
//! # Instantiating HKDF over a hash
//!
//! HKDF uses HMAC as its underlying primitive, so it works with exactly the hashes HMAC works with:
//! [`HKDF`] needs [`HMACParams`], which also carries the HKDF name ([`HMACParams::HKDF_ALG_NAME`]).
//! There is no separate HKDF params trait -- HKDF has no per-hash OIDs -- so an instantiation is just
//! a type alias.
//!
//!
//! One limitation to be aware of when instantiating over a hash of your own: the extract phase
//! writes its pseudorandom key into a [`MAX_HMAC_OUTPUT_LEN`]-byte buffer, so the hash's output
//! length must not exceed that (64 bytes). See the note on that constant.
//!
//! ## Worked example
//!
//! As an example, the `bouncycastle-sha2` crate instantiates HKDF-SHA256, HKDF-SHA384 and
//! HKDF-SHA512 this way. The library does not ship HKDF-SHA224, so that makes a good illustration of
//! adding one -- for a hash in this library or for a hash of your own, the shape is identical:
//!
//!
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::traits::KDF;
//! use bouncycastle_hkdf::HKDF;
//! use bouncycastle_sha2::SHA224;
//!
//! #[allow(non_camel_case_types)]
//! pub type HKDF_SHA224 = HKDF<SHA224>;
//!
//! pub const HKDF_SHA224_NAME: &str = "HKDF-SHA224";
//!
//! // That is all it takes: the KDF trait and the extract/expand API are now available.
//! let ikm = KeyMaterial256::from_bytes_as_type(
//!             b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
//!             KeyType::Seed).unwrap();
//! let okm = HKDF_SHA224::new().derive_key(&ikm, b"extra input", 28).unwrap();
//! ```
//!
//! # 🚨 Security Considerations 🚨
//!
//! These apply to every instantiation; `bouncycastle_sha2::hkdf` repeats the ones that matter most in
//! day-to-day use.
//!
//! * Entropy is credited only for input supplied via [`HKDF::do_extract_update_key`], and for a
//!   salt typed [`KeyType::MACKey`], which is how a caller marks it as the secret salt of SP
//!   800-56Cr2 Section 5.1. A salt of any other type is RFC 5869 Section 2.2's "non-secret random
//!   value" and credits nothing: anyone who knows it can compute the PRK from the IKM. Bytes supplied
//!   via [`HKDF::do_extract_update_bytes`] are treated as uncredited context, so a PRK derived only
//!   from raw bytes will not be tagged as full-entropy key material even if those bytes were random.
//!   [`HKDF::do_extract_update_key`] is rejected after the first call to
//!   [`HKDF::do_extract_update_bytes`], so that the input matches the ordering of the key-extraction
//!   method in NIST SP 800-133r2 Section 6.3, `K = T(HMAC-hash(salt, K1 || ... || Kn || D1 || ...
//!   || Dm), kLen)`, in which the component keys precede the other data. Note (h) of that method
//!   permits other orderings, so this is a deliberate restriction of this API rather than a
//!   requirement of the specification.
//! * HKDF stretches key material but does not create entropy. The output key inherits the
//!   [`SecurityStrength`] of its inputs: 200 bytes expanded from a 128-bit seed is 200 bytes at a
//!   128-bit security level, not a 1600-bit key.
//! * The output is labelled full-entropy only once the credited input carries half a hash output
//!   of bytes, so the hash sets the bar: a 16-byte `CryptographicRandom` key seeds HKDF-SHA256
//!   and derives a `CryptographicRandom` key at 128 bits, but through HKDF-SHA512 the same key
//!   derives `Unknown` output. Choosing the stronger hash does not strengthen the label.
//! * RFC 5869 Section 3.1 recommends a random salt where one is available. SP 800-56Cr2 permits an
//!   all-zero salt, and the extract phase accepts one, but a salt that the caller believes to be
//!   random and is not provides none of the benefit the recommendation is aimed at.
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

use bouncycastle_core::errors::{KDFError, KeyMaterialError, MACError};
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::kdf_params::KdfDescription;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterial0, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::FromAnyKeyMaterial;
use bouncycastle_core::traits::{Algorithm, KDF};
use bouncycastle_hmac::hazmat as hmac_hazmat;
use bouncycastle_hmac::{HMACParams, HmacKey, LARGEST_HASHER_BLOCK_LEN};
use bouncycastle_utils::secret::Secret;
use bouncycastle_utils::{max, min};
use std::marker::PhantomData;
// Imports needed only for docs
#[allow(unused_imports)]
use bouncycastle_core::traits::XOF;
// end doc-only imports

/*** Constants ***/
/// The size of the output key material from the HKDF-Extract phase `prk`, in bytes.
/// This has been sized so that the output KeyMaterial has enough capacity to accommodate the
/// underlying hash primitive with the largest output size.
/// If the given hash function has a smaller output size, then the output KeyMaterial will be
/// under-full (ie have a key_len that does not use its full capacity).
/// TODO: This is a dirty dirty hack because correctly sizing the output key
///       really requires the generic_const_exprs feature, which is currently only available on
///       nightly Rust, and not on stable. Once they merge that feature, we will be able to get rid of this
///       and declare `prk: &mut KeyMaterial<H::OUTPUT_LEN>` instead of this hack.
pub const MAX_HMAC_OUTPUT_LEN: usize = 64;

/*** Types ***/
/// The generic HKDF construction (RFC 5869).
///
/// Can be instantiated with hash functions other than the ones provided by this library (even custom
/// ones). The concrete instantiations over the library's own hashes, along with their name constants,
/// live in the hash crates -- see `bouncycastle_sha2::hkdf::HKDF_SHA256` and
/// `bouncycastle_sha2::hkdf::HKDF_SHA512`.
#[derive(Clone)]
pub struct HKDF<H: HMACParams> {
    // Optional because the extract-phase HMAC cannot be keyed until the salt is provided.
    // None must correspond to a state of Uninitialized.
    hmac: Option<HkdfExtract<H>>,
    entropy: HkdfEntropyTracker<H>,
    state: HkdfStates,
    /// Whether the extract phase has absorbed input keying material through the streaming API,
    /// which `Initialized` alone does not say: the [`KDF`] derivations refuse such an instance.
    ikm_absorbed: bool,
}

/// The extract phase's HMAC, held as its two halves: the salt key and the inner hash absorbing
/// the IKM. An `HMAC` worker borrows its key, and a struct cannot borrow from itself, so the
/// phase is run through `bouncycastle_hmac::hazmat`'s `inner_state` and `finish_out` instead.
#[derive(Clone)]
struct HkdfExtract<H: HMACParams> {
    key: HmacKey<H>,
    inner: H,
}

// No Drop impl of its own: the sensitive state is the salt-keyed pad states inside `hmac` (RFC
// 2104 Section 4 says they "need to be treated and protected the same as secret keys"), and the
// hash types zeroize those in their own Drop.

#[derive(Clone, Debug, PartialOrd, PartialEq)]
enum HkdfStates {
    /// waiting for salt
    Uninitialized,

    /// Salt set, waiting for IKMs or do_final
    Initialized,

    /// [`HKDF::do_extract_update_key`] has been called, after which no more credited IKMs can be given.
    /// This keeps the input in the order used by the key-extraction method of NIST SP 800-133r2
    /// Section 6.3, `K = T(HMAC-hash(salt, K1 || ... || Kn || D1 || ... || Dm), kLen)`, in which the
    /// component keys precede the other data. Note (h) of that method explicitly permits alternative
    /// orderings ("including interleaving the keys and data"), so this ordering is conformant but is
    /// a restriction this API chooses, not one the specification imposes.
    TakingAdditionalInfo,
}

#[derive(Clone)]
struct HkdfEntropyTracker<H: HMACParams> {
    _phantomhash: PhantomData<H>,
    entropy: usize,
    security_strength: SecurityStrength,
}

impl<H: HMACParams> HkdfEntropyTracker<H> {
    /// The most the label can say: the hash's collision strength, half its output, which is
    /// also [`Algorithm::MAX_SECURITY_STRENGTH`] of the hash, the HMAC and this HKDF. Library
    /// policy: SP 800-56Cr2 Table 4 allows HMAC-hash extraction up to the full output length
    /// (112 <= s <= 256 for SHA-256), so this is the conservative choice, and it is why a
    /// 192- or 256-bit secret is paired with HKDF-SHA512. No input raises the label past it.
    const MAX_STRENGTH: SecurityStrength = SecurityStrength::from_bytes(H::OUTPUT_LEN / 2);

    fn new() -> Self {
        Self { _phantomhash: PhantomData, entropy: 0, security_strength: SecurityStrength::None }
    }

    /// Takes in a KeyMaterial that is being mixed and figures out how much entropy to credit.
    /// Returns the amount of entropy credited: the key's bytes when it is full-entropy material
    /// with a strength, nothing otherwise (see [`KDF`]'s entropy accounting).
    fn credit_entropy(&mut self, key: &(impl KeyMaterialTrait + ?Sized)) -> usize {
        if !key.is_full_entropy() || key.security_strength() == SecurityStrength::None {
            return 0;
        }
        let additional_entropy = key.key_len();
        // Saturating: the counter is bookkeeping.
        self.entropy = self.entropy.saturating_add(additional_entropy);
        self.security_strength = *max(&self.security_strength, &key.security_strength());
        self.security_strength = *min(&self.security_strength, &Self::MAX_STRENGTH);
        additional_entropy
    }

    pub fn get_entropy(&self) -> usize {
        self.entropy
    }

    // Library policy, not a rule from a standard: the output is credited as CryptographicRandom
    // once at least OUTPUT_LEN / 2 bytes of typed key material with a strength have gone in, the
    // bytes that carry the most this label can say (`MAX_STRENGTH`). SP 800-133r2 Section 6.3
    // (method 3, note (g)) asks that the component keys' min-entropies sum to at least the
    // min-entropy the output needs; this counts bytes of material typed as key rather than
    // min-entropy, and the same key given twice counts twice. The threshold is the strength
    // bound rather than the full output length so that one 32-byte key, a KEM shared secret say,
    // seeds HKDF-SHA512 as it does HKDF-SHA256; the output's own strength stays capped by what
    // was credited, as `credit_entropy` records, and is never None once seeded.
    pub fn is_fully_seeded(&self) -> bool {
        self.entropy >= H::OUTPUT_LEN / 2
    }

    /// [`KeyType::CryptographicRandom`] once at least `OUTPUT_LEN / 2` bytes of typed key material
    /// have been credited (see [`Self::is_fully_seeded`]), else [`KeyType::Unknown`].
    fn get_output_key_type(&self) -> KeyType {
        if self.is_fully_seeded() { KeyType::CryptographicRandom } else { KeyType::Unknown }
    }

    /// For the expand phase, whose only input is the PRK: [`KeyType::CryptographicRandom`] when
    /// the PRK was credited at all (it is HashLen bytes, so any credit is a full seeding), else
    /// [`KeyType::Unknown`].
    fn get_output_key_type_of_prk(&self) -> KeyType {
        if self.entropy > 0 { KeyType::CryptographicRandom } else { KeyType::Unknown }
    }
}

/// The name is [`HMACParams::HKDF_ALG_NAME`]; the strength is the hash's, which the extract
/// and expand HMACs cannot exceed.
impl<H: HMACParams> Algorithm for HKDF<H> {
    const ALG_NAME: &'static str = H::HKDF_ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = H::MAX_SECURITY_STRENGTH;
}

impl<H: HMACParams> Default for HKDF<H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<H: HMACParams> HKDF<H> {
    /// Get a new, uninstantiated HKDF object.
    pub fn new() -> Self {
        Self {
            hmac: None,
            entropy: HkdfEntropyTracker::new(),
            state: HkdfStates::Uninitialized,
            ikm_absorbed: false,
        }
    }

    /// An instance keyed with `salt` for the [`KDF`] trait's derivations, which then run
    /// extract-then-expand with it: RFC 5869 Section 2.2's salt, of any [`KeyType`] but
    /// [`KeyType::Unknown`], credited as keying material only when typed [`KeyType::MACKey`]
    /// (see [`HKDF::do_extract_init`]).
    ///
    /// # Errors
    /// [`KeyMaterialError::InvalidKeyType`], as a [`MACError`], for a salt typed `Unknown`.
    pub fn new_with_salt(salt: &(impl KeyMaterialTrait + ?Sized)) -> Result<Self, MACError> {
        let mut hkdf = Self::new();
        hkdf.do_extract_init(salt)?;
        Ok(hkdf)
    }

    /// Returns the amount of entropy currently credited from the keys inputted so far.
    pub fn get_entropy(&self) -> usize {
        self.entropy.get_entropy()
    }

    /// Check whether the entropy input so far met the threshold for this object to be considered fully seeded
    pub fn is_fully_seeded(&self) -> bool {
        self.entropy.is_fully_seeded()
    }

    /// RFC 5869 Section 2.2:
    ///
    /// HKDF-Extract(salt, IKM) -> PRK
    ///    Options:
    ///       Hash     a hash function; HashLen denotes the length of the
    ///                hash function output in octets
    ///
    ///    Inputs:
    ///       salt     optional salt value (a non-secret random value);
    ///                if not provided, it is set to a string of HashLen zeros.
    ///       IKM      input keying material
    ///
    ///    Output:
    ///       PRK      a pseudorandom key (of HashLen octets)
    ///
    /// The salt can be of any [`KeyType`] but [`KeyType::Unknown`], which is refused as
    /// [`KeyMaterialError::InvalidKeyType`]; the IKM can be of any type, and credits entropy only
    /// when it is a full-entropy one. The salt credits entropy only when it is typed
    /// [`KeyType::MACKey`], a secret salt; see the crate's Security Considerations. The type of the
    /// output is set from what was credited.
    /// The output KeyMaterial will be of fixed size, with a capacity large enough to cover any
    /// underlying hash function, but the actual key length will be appropriate to the underlying hash function.
    ///
    /// Salt is optional, which is indicated by providing an uninitialized KeyMaterial object of length zero,
    /// the capacity is irrelevant, so KeyMaterial256::new() or KeyMaterial0::new() would both count as an absent salt.
    /// An algorithm that derives through HKDF holds the salt in an instance instead, from
    /// [`HKDF::new_with_salt`] or, for the absent salt, [`HKDF::new`], and derives through [`KDF`].
    pub fn extract(
        salt: &(impl KeyMaterialTrait + ?Sized),
        ikm: &(impl KeyMaterialTrait + ?Sized),
    ) -> Result<impl KeyMaterialTrait, MACError> {
        let mut prk = KeyMaterial::<MAX_HMAC_OUTPUT_LEN>::new();
        Self::extract_out(salt, ikm, &mut prk)?;
        Ok(prk)
    }

    /// Same as [`HKDF::extract`], but writes the output to a provided KeyMaterial buffer.
    /// Note that the provided KeyMaterial must be correctly sized to the hash function output length.
    pub fn extract_out(
        salt: &(impl KeyMaterialTrait + ?Sized),
        ikm: &(impl KeyMaterialTrait + ?Sized),
        prk: &mut KeyMaterial<MAX_HMAC_OUTPUT_LEN>,
    ) -> Result<usize, MACError> {
        // The `_out` rule: nothing stale survives, whichever way this returns.
        prk.zeroize();
        // PRK = HMAC-Hash(salt, IKM)

        let mut hkdf = Self::new();
        hkdf.do_extract_init(salt)?;
        hkdf.do_extract_update_key(ikm)?;
        let bytes_written = hkdf.do_extract_final_out(prk)?;

        Ok(bytes_written)
    }

    /// The definition of HKDF-Expand from RFC5869 is as follows:
    /// HKDF-Expand(PRK, info, L) -> OKM
    ///    Options:
    ///       Hash     a hash function; HashLen denotes the length of the
    ///                hash function output in octets
    ///    Inputs:
    ///       PRK      a pseudorandom key of at least HashLen octets
    ///                (usually, the output from the extract step)
    ///       info     optional context and application specific information
    ///                (can be a zero-length string)
    ///       L        length of output keying material in octets
    ///                (<= 255*HashLen)
    ///
    ///   Output:
    ///       OKM      output keying material (of L octets)
    ///
    /// Due to the details of the KeyMaterial object needing to compile to a known size, there is (currently)
    /// no way (within a no_std context) to dynamically allocate a KeyMaterial object according to the given 'L',
    /// therefore this function is provided only as expand_out(), filling the provided KeyMaterial object,
    /// and no analogous expand() is provided.
    ///
    /// The salt can be of any [`KeyType`] but [`KeyType::Unknown`], which is refused as
    /// [`KeyMaterialError::InvalidKeyType`]; the IKM can be of any type. The type of the output is
    /// set from what was credited, as [`Self::extract_out`] says.
    ///
    /// The output is typed [`KeyType::CryptographicRandom`] when the PRK is full-entropy material
    /// with a strength, whatever its own type, and [`KeyType::Unknown`] otherwise, at the least of
    /// the PRK's strength, this HKDF's and the length's.
    ///
    /// L is the output length. [`KDFError::InvalidLength`] is returned if L is zero, exceeds
    /// 255 * HashLen, if `okm` cannot hold L bytes, or if `prk` is shorter than HashLen (RFC 5869
    /// Section 2.3).
    /// There is no upper bound on the PRK: one longer than the hash block is hashed first, as HMAC
    /// does with a long key (RFC 2104 Section 3), so the output is what HMAC keyed with it gives.
    ///
    /// Returns the number of bytes written.
    #[allow(non_snake_case)] // for L
    pub fn expand_out(
        prk: &(impl KeyMaterialTrait + ?Sized),
        info: &[u8],
        L: usize,
        okm: &mut (impl KeyMaterialTrait + ?Sized),
    ) -> Result<usize, KDFError> {
        // The `_out` rule: nothing stale survives, whichever way this returns.
        okm.zeroize();
        // RFC 5869 Section 2.3:
        //    N = ceil(L/HashLen)
        //    T = T(1) | T(2) | T(3) | ... | T(N)
        //    OKM = first L octets of T
        //
        //    where:
        //    T(0) = empty string (zero length)
        //    T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
        //    T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
        //    T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
        //    ...
        //
        //    (where the constant concatenated to the end of each T(n) is a
        //    single octet.)

        let hash_len = H::OUTPUT_LEN;
        if L == 0 {
            return Err(KDFError::InvalidLength("HKDF-Expand: a zero-length output is refused"));
        }
        if L > 255 * hash_len {
            return Err(KDFError::InvalidLength(
                "HKDF-Expand cannot produce more than 255*HashLen bytes of output",
            ));
        }

        if L > okm.capacity() {
            return Err(KDFError::InvalidLength(
                "Provided KeyMaterial is too small to hold the requested output length.",
            ));
        }

        // RFC 5869 Section 2.3: "PRK  a pseudorandom key of at least HashLen octets".
        if prk.key_len() < hash_len {
            return Err(KDFError::InvalidLength(
                "HKDF-Expand: PRK must be at least HashLen bytes (RFC 5869 Sec 2.3)",
            ));
        }

        let mut entropy = HkdfEntropyTracker::<H>::new();
        entropy.credit_entropy(prk);

        #[allow(non_snake_case)]
        let N = L.div_ceil(hash_len) as u8;
        let mut bytes_written: usize = 0;

        // Could potentially speed this up by unrolling T(0) and T(1)

        // The PRK, re-typed as the MAC key it is (see mac_key_copy). One key object for the whole
        // expansion: the pads are computed once here, before any byte of `okm` is written, and each
        // block's HMAC starts from a clone of them.
        let prk_key = HmacKey::<H>::from_key_material(&Self::mac_key_copy(prk.ref_to_bytes())?)?;

        // T(i) is output key material, so it zeroizes on drop.
        #[allow(non_snake_case)]
        let mut T: Secret<[u8; MAX_HMAC_OUTPUT_LEN]> = Secret::new();
        let mut t_len: usize = 0;
        let mut i = 1u8;

        let filled: Result<(), KDFError> = (|| {
            do_hazardous_operations(okm, |okm| {
                let out = okm.ref_to_bytes_mut()?;
                while i < N {
                    // The HMAC as its two hazmat halves, generic over the hash: the role impls
                    // name the tag length as a const, which `H: HMACParams` alone does not give.
                    let mut hmac = hmac_hazmat::inner_state(&prk_key);
                    hmac.do_update(&T[..t_len]);
                    hmac.do_update(info);
                    hmac.do_update(&[i]);

                    t_len = hmac_hazmat::finish_out(&prk_key, hmac, &mut T[..hash_len]);
                    debug_assert_eq!(t_len, hash_len); // this will be true for every iteration after T(0) / T(1)
                    out[bytes_written..bytes_written + t_len].copy_from_slice(&T[..t_len]);
                    bytes_written += t_len;
                    i += 1;
                }
                Ok(())
            })?;

            // Part of the output is not taken on the last iteration. "OKM = first L octets of T", so the
            // last block T(N) is computed in full and only its first `remaining` octets are kept.
            let remaining = L - bytes_written;
            let mut hmac = hmac_hazmat::inner_state(&prk_key);
            hmac.do_update(&T[..t_len]);
            hmac.do_update(info);
            hmac.do_update(&[i]);

            t_len = hmac_hazmat::finish_out(&prk_key, hmac, &mut T[..hash_len]);
            debug_assert_eq!(t_len, hash_len);

            do_hazardous_operations(okm, |okm| {
                let out = okm.ref_to_bytes_mut()?;
                out[bytes_written..bytes_written + remaining].copy_from_slice(&T[..remaining]);
                Ok(())
            })?;
            bytes_written += remaining;
            Ok(())
        })();
        // A partly written OKM is key material: on any failure above, none of it is left behind.
        if filled.is_err() {
            okm.zeroize();
        }
        filled?;

        // The output is the KDF's, not the PRK's: fresh pseudorandom keying material when the PRK
        // was credited (full-entropy with a strength), else Unknown, since computation happened
        // even when the PRK was zeroized.
        do_hazardous_operations(okm, |okm| {
            okm.set_key_type(entropy.get_output_key_type_of_prk())?;
            okm.set_key_len(bytes_written)?;
            if okm.key_type() <= KeyType::Unknown {
                okm.set_security_strength(SecurityStrength::None)
            } else {
                okm.set_security_strength(*min(
                    &SecurityStrength::from_bytes(okm.key_len()),
                    &entropy.security_strength,
                ))
            }
        })?;

        Ok(bytes_written)
    }

    /// Salt is optional, which is indicated by providing an uninitialized KeyMaterial object of length zero,
    /// the capacity is irrelevant, so KeyMaterial256::new() or KeyMaterial0::new() would both count as an absent salt.
    #[allow(non_snake_case)]
    pub fn extract_and_expand_out(
        salt: &(impl KeyMaterialTrait + ?Sized),
        ikm: &(impl KeyMaterialTrait + ?Sized),
        info: &[u8],
        L: usize,
        okm: &mut (impl KeyMaterialTrait + ?Sized),
    ) -> Result<usize, KDFError> {
        // The `_out` rule: nothing stale survives, whichever way this returns.
        okm.zeroize();
        let prk = Self::extract(salt, ikm)?;
        Self::expand_out(&prk, info, L, okm)
    }

    /// The salt as the MAC key it is: RFC 5869 Section 2.2, `PRK = HMAC-Hash(salt, IKM)`.
    ///
    /// [`HmacKey`] accepts only [`KeyType::MACKey`] or [`KeyType::Zeroized`] material, while a salt
    /// may carry any `KeyType` (a nonce drawn from an RNG is `CryptographicRandom`), so it is
    /// copied and re-typed here through [`Self::mac_key_copy`], as [`Self::expand_out`] does for
    /// the PRK. The exception is [`KeyType::Unknown`]: bytes of unknown provenance are promoted to
    /// a key only inside [`do_hazardous_operations`], never here, so they are refused. The empty
    /// salt stays an empty `Zeroized` key, which HMAC zero-pads
    /// to a block (RFC 2104 Section 2 step (1)): that is both RFC 5869 Section 2.2's "string of
    /// HashLen zeros" and SP 800-56Cr2 Section 5.1's "all-zero byte string whose length is equal to
    /// that of a single input block", so all three default salts key HMAC the same way.
    fn salt_as_mac_key(
        salt: &(impl KeyMaterialTrait + ?Sized),
    ) -> Result<KeyMaterial<LARGEST_HASHER_BLOCK_LEN>, MACError> {
        if salt.key_type() == KeyType::Unknown {
            return Err(MACError::KeyMaterialError(KeyMaterialError::InvalidKeyType(
                "HKDF salt must not be KeyType::Unknown",
            )));
        }
        Ok(Self::mac_key_copy(salt.ref_to_bytes())?)
    }

    /// `bytes` as a [`KeyType::MACKey`] of [`LARGEST_HASHER_BLOCK_LEN`] capacity, HMAC's own bound.
    ///
    /// HMAC replaces a key "longer than B bytes" by its hash (RFC 2104 Section 3), so bytes longer
    /// than the hash block are hashed here first: the copy then keys HMAC identically to `bytes`
    /// and never overflows. The salt and the PRK both go through this.
    fn mac_key_copy(
        bytes: &[u8],
    ) -> Result<KeyMaterial<LARGEST_HASHER_BLOCK_LEN>, KeyMaterialError> {
        const { assert!(H::BLOCK_LEN <= LARGEST_HASHER_BLOCK_LEN) };
        const { assert!(H::OUTPUT_LEN <= MAX_HMAC_OUTPUT_LEN) };
        if bytes.len() <= H::BLOCK_LEN {
            return KeyMaterial::from_bytes_as_type(bytes, KeyType::MACKey);
        }
        let mut digest: Secret<[u8; MAX_HMAC_OUTPUT_LEN]> = Secret::new();
        let written = H::hash_out(bytes, &mut digest[..H::OUTPUT_LEN]);
        KeyMaterial::from_bytes_as_type(&digest[..written], KeyType::MACKey)
    }

    /// This, together with [`HKDF::do_extract_update_key`], [`HKDF::do_extract_update_bytes`] and [`HKDF::do_extract_final`]
    /// provide a streaming interface for very long values of `ikm`.
    /// In this mode, entropy is credited for the keys given to [`HKDF::do_extract_update_key`] and
    /// for a salt typed [`KeyType::MACKey`] (a secret salt); a salt of any other type credits
    /// nothing, since RFC 5869 Section 2.2's salt is "a non-secret random value".
    /// The salt can be of any [`KeyType`] but [`KeyType::Unknown`], which is refused as
    /// [`KeyMaterialError::InvalidKeyType`]; the type of the output is set from what was credited.
    /// The output KeyMaterial will be of fixed size, with a capacity large enough to cover any
    /// underlying hash function, but the actual key length will be appropriate to the underlying hash function.
    ///
    /// Salt is optional; to omit it, provide a KeyMaterial0, which will cause HKDF to use the default all-zero salt.
    ///
    /// Returns the number of bytes of entropy credited to this input key material.
    pub fn do_extract_init(
        &mut self,
        salt: &(impl KeyMaterialTrait + ?Sized),
    ) -> Result<usize, MACError> {
        if self.state >= HkdfStates::Initialized {
            return Err(MACError::InvalidState("Initialized twice"));
        };

        // The salt is often empty or short, so HMAC's key-strength check is skipped; the entropy
        // tracker below accounts for it.
        let salt_key = Self::salt_as_mac_key(salt)?;
        let key = HmacKey::<H>::from_key_material_allow_weak(&salt_key)?;
        let inner = hmac_hazmat::inner_state(&key);
        self.hmac = Some(HkdfExtract { key, inner });

        // RFC 5869 Section 2.2 defines the salt as "a non-secret random value", and SP 800-133r2
        // Section 6.3 note (g) counts the component keys' entropy, not the salt's: a salt the
        // caller has not marked as a key credits nothing, or a public salt alone would label the
        // PRK full-entropy key material. A MACKey salt is SP 800-56Cr2 Section 5.1's secret salt.
        let additional_entropy =
            if salt.key_type() == KeyType::MACKey { self.entropy.credit_entropy(salt) } else { 0 };
        self.state = HkdfStates::Initialized;

        Ok(additional_entropy)
    }

    /// An update function that allows adding an IKM as a [`KeyMaterialTrait`].
    /// Credits the entropy contained in the IKM.
    /// This function may be called zero or more times in a workflow.
    /// In particular, this function may be called multiple times to add more than one IKM.
    ///
    /// Returns the number of bytes of entropy credited to this input key material.
    pub fn do_extract_update_key(
        &mut self,
        ikm: &(impl KeyMaterialTrait + ?Sized),
    ) -> Result<usize, MACError> {
        if self.state == HkdfStates::Uninitialized {
            return Err(MACError::InvalidState(
                "Must call do_extract_init() before calling do_extract_update_key()",
            ));
        };

        if self.state == HkdfStates::TakingAdditionalInfo {
            return Err(MACError::InvalidState(
                "Cannot accept more credited IKMs via do_extract_update_key(&KeyMaterial) after an uncredited key has been provided via do_extract_update(&[u8])",
            ));
        }
        debug_assert_eq!(self.state, HkdfStates::Initialized);
        debug_assert!(self.hmac.is_some());

        let additional_entropy = self.entropy.credit_entropy(ikm);
        self.hmac.as_mut().unwrap().inner.do_update(ikm.ref_to_bytes());
        self.ikm_absorbed = true;

        Ok(additional_entropy)
    }

    /// An update function that allows streaming of the IKM as bytes.
    /// Note that since this interface takes the IKM as raw bytes, it cannot track its entropy
    /// and therefore any IKM material provided through this interface will not count towards
    /// the entropy of the output key.
    ///
    /// State machine: this function must be called after [`HKDF::do_extract_init`], followed by
    /// zero or more calls of [`HKDF::do_extract_update_key`], and before [`HKDF::do_extract_final`].
    ///
    /// Returns the number of bytes of entropy credited to this input key material, which is always 0 for this function.
    pub fn do_extract_update_bytes(&mut self, ikm_chunk: &[u8]) -> Result<usize, MACError> {
        if self.state == HkdfStates::Uninitialized {
            return Err(MACError::InvalidState(
                "Must call do_extract_init() before calling do_extract_update()",
            ));
        };
        self.state = HkdfStates::TakingAdditionalInfo;

        self.hmac.as_mut().unwrap().inner.do_update(ikm_chunk);
        self.ikm_absorbed = true;
        Ok(0)
    }

    /// Finish the HKDF-Extract phase and produce the output `prk`.
    #[allow(non_snake_case)]
    pub fn do_extract_final(self) -> Result<KeyMaterial<MAX_HMAC_OUTPUT_LEN>, MACError> {
        let mut prk = KeyMaterial::<MAX_HMAC_OUTPUT_LEN>::new();
        self.do_extract_final_out(&mut prk)?;
        Ok(prk)
    }

    /// Finish the HKDF-Extract phase and fill the provided `prk`.
    /// The PRK is `HashLen` bytes (RFC 5869 Section 2.2), which the provided KeyMaterial always holds.
    #[allow(non_snake_case)]
    pub fn do_extract_final_out(
        self,
        prk: &mut KeyMaterial<MAX_HMAC_OUTPUT_LEN>,
    ) -> Result<usize, MACError> {
        // The `_out` rule: nothing stale survives, whichever way this returns.
        prk.zeroize();
        if self.state == HkdfStates::Uninitialized {
            return Err(MACError::InvalidState(
                "Must call do_extract_init() before calling do_extract_final().",
            ));
        };
        debug_assert!(self.hmac.is_some());

        let output_key_type = self.entropy.get_output_key_type(); // need to do this above self.hmac.do_final_out, which will consume self.

        let mut bytes_written = 0;
        let HkdfExtract { key, inner } = self.hmac.unwrap();
        do_hazardous_operations(prk, |okm| {
            bytes_written = hmac_hazmat::finish_out(&key, inner, okm.ref_to_bytes_mut()?);
            okm.set_key_len(bytes_written)?;
            okm.set_key_type(output_key_type)?;
            if output_key_type <= KeyType::Unknown {
                okm.set_security_strength(SecurityStrength::None)
            } else {
                okm.set_security_strength(*min(
                    &SecurityStrength::from_bytes(okm.key_len()),
                    &self.entropy.security_strength,
                ))
            }
        })?;
        // By RFC5869, the output size of prk is HashLen denotes the length of the
        //                hash function output in octets
        debug_assert_eq!(prk.key_len(), H::OUTPUT_LEN);
        Ok(bytes_written)
    }
}

/// HKDF's extract-then-expand is RFC 5869's, which NIST SP 800-56Cr2 Section 5.1 names as "a
/// version of" its two-step key derivation "using HMAC for both the extraction and expansion
/// steps"; the expansion step's input layout (`T(i-1) || info || i`) is RFC 5869's own rather than
/// SP 800-108r1 Section 4.2's feedback mode. The default salt is empty: RFC 5869 Section 2.2 sets an absent salt
/// to "a string of HashLen zeros", SP 800-56Cr2 Section 5.1 to an all-zero string of one hash input
/// block, and HMAC zero-pads its key to a block, so the three key HMAC identically (see
/// `salt_as_mac_key`). All key material and additional_input is mapped to HKDF's ikm input.
/// While this is not the only mode in which HKDF can be used as a KDF, this is considered the default mode
/// that is exposed through [`KDF::derive_key`] and [`KDF::derive_key_out`].
/// More advanced control of the inputs to HKDF can be achieved by using [`KDF::derive_key_from_multiple`] and
/// [`KDF::derive_key_from_multiple_out`], or by using the [`HKDF`] impl directly.
///
/// Entropy tracking: this implementation will map entropy from the input keys to the output key.
impl<H: HMACParams> KDF for HKDF<H> {
    /// Extract-then-expand with the salt this instance was made with ([`HKDF::new_with_salt`]),
    /// or RFC 5869 Section 2.2's absent salt for one from [`HKDF::new`]: `ikm` is the IKM,
    /// `fixed_info` the expand phase's `info`.
    fn derive_key_out(
        &self,
        ikm: &dyn KeyMaterialTrait,
        fixed_info: &[u8],
        len: usize,
        output_key: &mut dyn KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        self.derive_key_from_multiple_out(&[ikm], fixed_info, len, output_key)
    }

    /// As [`KDF::derive_key_out`] with the IKM the concatenation of `ikms`, each credited (the
    /// same key twice is credited twice).
    ///
    /// # Errors
    /// As [`KDF::derive_key_out`]; [`KDFError::InvalidLength`] if `ikms` is empty; and
    /// [`KDFError::MACError`] with [`MACError::InvalidState`] if this instance has absorbed
    /// input keying material through the streaming API, since the derivation would then be over
    /// that material too.
    fn derive_key_from_multiple_out(
        &self,
        ikms: &[&dyn KeyMaterialTrait],
        fixed_info: &[u8],
        len: usize,
        output_key: &mut dyn KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        output_key.zeroize();
        if ikms.is_empty() {
            return Err(KDFError::InvalidLength("a derivation from no keys is refused"));
        }
        if self.ikm_absorbed {
            return Err(KDFError::MACError(MACError::InvalidState(
                "a KDF instance holds its salt and nothing else; this HKDF has absorbed input keying material",
            )));
        }
        // The extract runs on a copy, so the instance and its salt serve every derivation.
        let mut hkdf = self.clone();
        if hkdf.state == HkdfStates::Uninitialized {
            hkdf.do_extract_init(&KeyMaterial0::new())?;
        }
        for ikm in ikms {
            hkdf.do_extract_update_key(*ikm)?;
        }
        let prk = hkdf.do_extract_final()?;
        Self::expand_out(&prk, fixed_info, len, output_key)
    }
}

/// What an HKDF derivation is made from, as a KDF's description
/// ([`KdfDescription`]): the hash `H` and the salt, RFC 5869 Section 2.2's optional
/// `salt`, borrowed for `'s` and readable through [`salt`](Self::salt), absent for the
/// "string of HashLen zeros". An algorithm that derives through HKDF is made from one of these
/// as the KDF of `bouncycastle_core::kdf_params::KdfParams`; a software pairing keys an
/// [`HKDF`] with the salt through [`engine`](KdfDescription::engine) for each derivation, as
/// [`HKDF::new_with_salt`] does, and a key held where the secret must not leave reads the salt
/// and hands the device the same derivation. The salt is typed as the caller's material is: a
/// [`KeyType::MACKey`] salt is the secret salt the crate's Security Considerations describe,
/// credited by the engine; any other type but [`KeyType::Unknown`], which is refused, is RFC
/// 5869's non-secret random value.
pub struct HkdfDescription<'s, H: HMACParams> {
    salt: Option<&'s dyn KeyMaterialTrait>,
    _hash: PhantomData<H>,
}

impl<'s, H: HMACParams> HkdfDescription<'s, H> {
    /// HKDF over `H` with the salt absent: RFC 5869 Section 2.2's "string of HashLen zeros".
    pub const fn new() -> Self {
        Self { salt: None, _hash: PhantomData }
    }

    /// HKDF over `H` keyed with `salt`, of any [`KeyType`] but [`KeyType::Unknown`]; a
    /// zero-length salt is the absent one.
    ///
    /// # Errors
    /// [`KeyMaterialError::InvalidKeyType`] for a salt typed `Unknown`, the refusal
    /// [`HKDF::new_with_salt`] makes, so that a description an engine cannot be built from does
    /// not exist.
    pub fn with_salt(salt: &'s dyn KeyMaterialTrait) -> Result<Self, KeyMaterialError> {
        if salt.key_type() == KeyType::Unknown {
            return Err(KeyMaterialError::InvalidKeyType("HKDF salt must not be KeyType::Unknown"));
        }
        Ok(Self { salt: Some(salt), _hash: PhantomData })
    }

    /// The salt, or `None` for the absent one.
    pub fn salt(&self) -> Option<&'s dyn KeyMaterialTrait> {
        self.salt
    }
}

impl<H: HMACParams> Default for HkdfDescription<'_, H> {
    fn default() -> Self {
        Self::new()
    }
}

// Written out rather than derived: a derive would demand `H: Clone` of the hash.
impl<H: HMACParams> Clone for HkdfDescription<'_, H> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<H: HMACParams> Copy for HkdfDescription<'_, H> {}

/// The engine's name and strength, [`HKDF`]'s.
impl<H: HMACParams> Algorithm for HkdfDescription<'_, H> {
    const ALG_NAME: &'static str = H::HKDF_ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = H::MAX_SECURITY_STRENGTH;
}

impl<H: HMACParams> KdfDescription for HkdfDescription<'_, H> {
    type Engine = HKDF<H>;

    /// [`HKDF::new_with_salt`] with the salt, or [`HKDF::new`] without one.
    fn engine(&self) -> Result<HKDF<H>, KDFError> {
        match self.salt {
            Some(salt) => HKDF::new_with_salt(salt).map_err(KDFError::MACError),
            None => Ok(HKDF::new()),
        }
    }
}

// Because this struct is not public, the tests have to go here.
#[cfg(test)]
mod tests {
    use super::*;
    use bouncycastle_core::key_material::KeyMaterial512;
    use bouncycastle_sha2::{SHA256, SHA512};

    #[test]
    fn test_entropy_tracker() {
        let mut entropy = HkdfEntropyTracker::<SHA256>::new();

        assert_eq!(entropy.get_entropy(), 0);
        assert_eq!(entropy.get_output_key_type(), KeyType::Unknown);

        // A key too short to carry a strength (8 bytes is 64 bits, below 112) credits nothing.
        let key = KeyMaterial512::from_bytes_as_type(
            b"\x00\x01\x02\x03\x04\x05\x06\x07",
            KeyType::CryptographicRandom,
        )
        .unwrap();
        assert_eq!(key.security_strength(), SecurityStrength::None);
        assert_eq!(entropy.credit_entropy(&key), 0);
        assert_eq!(entropy.get_entropy(), 0);
        assert_eq!(entropy.get_output_key_type(), KeyType::Unknown);

        // The threshold is half the hash output: 16 bytes for SHA-256, 32 for SHA-512; two
        // distinct 14-byte keys (112 bits each) reach it.
        let key1 =
            KeyMaterial512::from_bytes_as_type(&[0x5A; 14], KeyType::CryptographicRandom).unwrap();
        let key2 =
            KeyMaterial512::from_bytes_as_type(&[0xA5; 14], KeyType::CryptographicRandom).unwrap();
        assert_eq!(entropy.credit_entropy(&key1), 14);
        assert_eq!(entropy.get_entropy(), 14);
        assert_eq!(entropy.is_fully_seeded(), false);
        assert_eq!(entropy.get_output_key_type(), KeyType::Unknown);

        assert_eq!(entropy.credit_entropy(&key2), 14);
        assert_eq!(entropy.get_entropy(), 28);
        assert_eq!(entropy.is_fully_seeded(), true);
        assert_eq!(entropy.get_output_key_type(), KeyType::CryptographicRandom);
        assert_eq!(entropy.security_strength, SecurityStrength::_112bit);

        let mut entropy = HkdfEntropyTracker::<SHA512>::new();
        let key1 =
            KeyMaterial512::from_bytes_as_type(&[0x5A; 16], KeyType::CryptographicRandom).unwrap();
        let key2 =
            KeyMaterial512::from_bytes_as_type(&[0xA5; 16], KeyType::CryptographicRandom).unwrap();
        entropy.credit_entropy(&key1);
        assert_eq!(entropy.get_entropy(), 16);
        assert_eq!(entropy.is_fully_seeded(), false);
        assert_eq!(entropy.get_output_key_type(), KeyType::Unknown);

        entropy.credit_entropy(&key2);
        assert_eq!(entropy.get_entropy(), 32);
        assert_eq!(entropy.is_fully_seeded(), true);
        assert_eq!(entropy.get_output_key_type(), KeyType::CryptographicRandom);
    }
}
