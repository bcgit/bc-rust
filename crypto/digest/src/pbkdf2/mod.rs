//! PBKDF2, the password-based key derivation function of RFC 8018 (PKCS #5 v2.1) Section 5.2,
//! over HMAC: `DK = PBKDF2(P, S, c, dkLen)`, a derived key of any length from a password, a
//! salt and an iteration count.
//!
//! [`PBKDF2<H>`] is the function over any hash that implements
//! [`HMACParams`]; the aliases [`PBKDF2_HMAC_SHA256`] and the like name the instantiations over
//! the SHA-2 and SHA-3 hashes. An instance holds the salt and the iteration count, which are
//! PKCS #5's `PBKDF2-params`, and the password is the key it is given.
//!
//! # Usage Examples
//!
//! A key from a password, [`PBKDF2::derive_out`]:
//!
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
//! use bouncycastle_digest::pbkdf2::PBKDF2_HMAC_SHA256;
//! use core::num::NonZeroU32;
//!
//! // A password is bytes of unknown entropy, and is typed so.
//! let password = KeyMaterial::<64>::from_bytes_as_type(b"correct horse battery staple", KeyType::Unknown).unwrap();
//! let salt = [0x5Au8; 16]; // from an RNG, stored beside what the key protects
//! let iterations = NonZeroU32::new(600_000).unwrap();
//!
//! let mut key = KeyMaterial::<32>::new();
//! let written = PBKDF2_HMAC_SHA256::derive_out(&password, &salt, iterations, 32, &mut key).unwrap();
//! assert_eq!(written, 32);
//! // The library cannot vouch for a password's entropy, so it does not vouch for the key's.
//! assert_eq!(key.key_type(), KeyType::Unknown);
//! ```
//!
//! Through the [`KDF`] trait, on an instance that holds the salt and the iteration count:
//!
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
//! use bouncycastle_core::traits::KDF;
//! use bouncycastle_digest::pbkdf2::PBKDF2_HMAC_SHA512;
//! use core::num::NonZeroU32;
//!
//! let password = KeyMaterial::<64>::from_bytes_as_type(b"correct horse battery staple", KeyType::Unknown).unwrap();
//! let salt = [0x5Au8; 16];
//! let kdf = PBKDF2_HMAC_SHA512::new(&salt, NonZeroU32::new(210_000).unwrap());
//! let key = kdf.derive_key(&password, &[], 64).unwrap();
//! assert_eq!(key.key_len(), 64);
//! ```
//!
//! # Memory Usage
//!
//! The function holds its parameters only. A derivation keys HMAC once with the password and
//! keeps two hash-output blocks of 64 bytes in [`Secret`]s on the stack,
//! writing straight into the caller's buffer. Peak stack, in bytes, whatever the iteration
//! count (x86-64, release, rustc 1.97.0-nightly, the deepest frame chain of
//! `bench_pbkdf2_mem_usage`):
//!
//! | PRF | Stack |
//! |---|---|
//! | HMAC-SHA256 | 2728 |
//! | HMAC-SHA512 | 4232 |
//! | HMAC-SHA3-256 | 6088 |
//!
//! [`Secret`]: bouncycastle_utils::secret::Secret
//!
//! # 🚨 Security Considerations 🚨
//!
//! - **A password is not a key.** The derived key is typed `Unknown`, with no strength, unless
//!   what went in was full-entropy keying material: iterating does not add entropy, it raises
//!   the cost of each guess (RFC 8018 Section 4.2: "an iteration count of c will increase the
//!   security strength of a password by log2(c) bits against trial-based attacks"). A caller
//!   who uses the result as a cipher key vouches for the password, through
//!   `bouncycastle_core::hazmat::do_hazardous_operations`.
//! - **The salt and the iteration count are the caller's to choose, and nothing here enforces
//!   a minimum.** NIST SP 800-132 Section 5.1: "The length of the randomly-generated portion of
//!   the salt shall be at least 128 bits"; Section 5.2: "The iteration count shall be selected
//!   as large as possible, as long as the time required to generate the key using the entered
//!   password is acceptable for the users"; Section 5: "The kLen value shall be at least 112
//!   bits in length". A new salt for each key is what stops one dictionary serving every user.
//! - **A long password gains nothing.** RFC 8018 Appendix B.1.1: a password longer than the
//!   hash's block is hashed first, so the search space for the derived key is bounded by the
//!   hash output, whatever `dkLen` is.
//! - **A derived key longer than one hash output costs the attacker no more than one block**:
//!   each block is computed independently, so a guess is checked against the first.
//! - The password's encoding is the caller's: the function takes octets.

use crate::hmac::{HMACParams, HmacKey, LARGEST_HASHER_BLOCK_LEN, hazmat as hmac_hazmat};
use crate::sha2::{SHA224, SHA256, SHA384, SHA512};
use crate::sha3::{SHA3_224, SHA3_256, SHA3_384, SHA3_512};
use bouncycastle_core::errors::KDFError;
use bouncycastle_core::hazmat::{do_hazardous_operations, finish_token, label_kdf_output};
use bouncycastle_core::kdf_params::KdfDescription;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::FromAnyKeyMaterial;
use bouncycastle_core::traits::{Algorithm, KDF};
use bouncycastle_utils::const_str::ConstStr;
use bouncycastle_utils::secret::Secret;
use core::marker::PhantomData;
use core::num::NonZeroU32;

/// The largest HMAC output this module's block buffers hold: 64 bytes, HMAC-SHA512's. A hash
/// with a longer output is refused at compile time.
pub(in crate::pbkdf2) const MAX_HMAC_OUTPUT_LEN: usize = 64;

/// PBKDF2 over HMAC-SHA224.
#[allow(non_camel_case_types)]
pub type PBKDF2_HMAC_SHA224<'s> = PBKDF2<'s, SHA224>;
/// PBKDF2 over HMAC-SHA256.
#[allow(non_camel_case_types)]
pub type PBKDF2_HMAC_SHA256<'s> = PBKDF2<'s, SHA256>;
/// PBKDF2 over HMAC-SHA384.
#[allow(non_camel_case_types)]
pub type PBKDF2_HMAC_SHA384<'s> = PBKDF2<'s, SHA384>;
/// PBKDF2 over HMAC-SHA512.
#[allow(non_camel_case_types)]
pub type PBKDF2_HMAC_SHA512<'s> = PBKDF2<'s, SHA512>;
/// PBKDF2 over HMAC-SHA3-224.
#[allow(non_camel_case_types)]
pub type PBKDF2_HMAC_SHA3_224<'s> = PBKDF2<'s, SHA3_224>;
/// PBKDF2 over HMAC-SHA3-256.
#[allow(non_camel_case_types)]
pub type PBKDF2_HMAC_SHA3_256<'s> = PBKDF2<'s, SHA3_256>;
/// PBKDF2 over HMAC-SHA3-384.
#[allow(non_camel_case_types)]
pub type PBKDF2_HMAC_SHA3_384<'s> = PBKDF2<'s, SHA3_384>;
/// PBKDF2 over HMAC-SHA3-512.
#[allow(non_camel_case_types)]
pub type PBKDF2_HMAC_SHA3_512<'s> = PBKDF2<'s, SHA3_512>;

/// PBKDF2 (RFC 8018 Section 5.2) with HMAC over the hash `H` as the pseudorandom function,
/// holding the salt `S`, which it borrows, and the iteration count `c`.
///
/// The password `P` is the [`KDF`] methods' input key. PBKDF2 has no input beyond the
/// password, the salt and the count, so the trait's `fixed_info` must be empty.
pub struct PBKDF2<'s, H: HMACParams> {
    salt: &'s [u8],
    iterations: NonZeroU32,
    _hash: PhantomData<H>,
}

// Written out rather than derived: a derive would demand `H: Copy` of the hash.
impl<H: HMACParams> Clone for PBKDF2<'_, H> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<H: HMACParams> Copy for PBKDF2<'_, H> {}

impl<H: HMACParams> Algorithm for PBKDF2<'_, H> {
    const ALG_NAME: &'static str = Self::NAME.as_str();
    /// HMAC's over the hash: the function cannot exceed what its PRF provides.
    const MAX_SECURITY_STRENGTH: SecurityStrength = H::HMAC_MAX_SECURITY_STRENGTH;
}

/// Both parameters are readable fields ([`PBKDF2::salt`], [`PBKDF2::iterations`]), so the KDF
/// describes itself: the engine is a copy.
impl<H: HMACParams> KdfDescription for PBKDF2<'_, H> {
    type Engine = Self;

    fn engine(&self) -> Result<Self, KDFError> {
        Ok(*self)
    }
}

impl<'s, H: HMACParams> PBKDF2<'s, H> {
    const NAME: ConstStr<40> = ConstStr::concat(&["PBKDF2-", H::HMAC_ALG_NAME]);

    /// The most bytes one derivation produces: `(2^32 - 1) * hLen` (RFC 8018 Section 5.2 step
    /// 1), or `usize::MAX` where that does not fit.
    pub const MAX_LEN: usize = {
        let max = H::OUTPUT_LEN as u128 * 0xFFFF_FFFF;
        if max > usize::MAX as u128 { usize::MAX } else { max as usize }
    };

    /// The scratch buffers are sized for the library's hashes; a foreign `HMACParams` hash past
    /// either bound is a compile error.
    const CHECKS: () = {
        assert!(H::BLOCK_LEN <= LARGEST_HASHER_BLOCK_LEN);
        assert!(H::OUTPUT_LEN <= MAX_HMAC_OUTPUT_LEN);
        assert!(H::OUTPUT_LEN > 0);
    };

    /// PBKDF2 with the salt `salt` and the iteration count `iterations`; "c, a positive
    /// integer" is the type's.
    pub fn new(salt: &'s [u8], iterations: NonZeroU32) -> Self {
        Self { salt, iterations, _hash: PhantomData }
    }

    /// The salt `S`.
    pub fn salt(&self) -> &'s [u8] {
        self.salt
    }

    /// The iteration count `c`.
    pub fn iterations(&self) -> NonZeroU32 {
        self.iterations
    }

    /// RFC 8018 Section 5.2: `dkLen = len` bytes of derived key from the password, the salt
    /// and the iteration count, written to the front of `dk`, which is zeroized first. Returns
    /// the number of bytes written, `len`.
    ///
    /// The output is typed as the module docs' Security Considerations say: `Unknown` unless
    /// `password` is full-entropy keying material of at least half a hash output, in which
    /// case it is `CryptographicRandom` at the least of its strength, HMAC's and the length's.
    ///
    /// # Errors
    /// [`KDFError::InvalidLength`] if `len` is zero, exceeds [`PBKDF2::MAX_LEN`] ("derived key
    /// too long", step 1) or exceeds `dk`'s capacity; `dk` is left zeroized.
    pub fn derive_out(
        password: &(impl KeyMaterialTrait + ?Sized),
        salt: &[u8],
        iterations: NonZeroU32,
        len: usize,
        dk: &mut (impl KeyMaterialTrait + ?Sized),
    ) -> Result<usize, KDFError> {
        PBKDF2::<H>::new(salt, iterations).derive_keys_out(&[password], len, dk)
    }

    /// [`PBKDF2::derive_out`] with the password the concatenation of `keys`, as the [`KDF`]
    /// trait's multi-key methods define their input.
    fn derive_keys_out<K: KeyMaterialTrait + ?Sized>(
        &self,
        keys: &[&K],
        len: usize,
        dk: &mut (impl KeyMaterialTrait + ?Sized),
    ) -> Result<usize, KDFError> {
        let () = Self::CHECKS;
        let h_len = H::OUTPUT_LEN;

        // The `_out` rule: nothing stale survives, whichever way this returns.
        dk.zeroize();

        if len == 0 {
            return Err(KDFError::InvalidLength("a zero-length derivation is refused"));
        }
        if keys.is_empty() {
            return Err(KDFError::InvalidLength("a derivation from no keys is refused"));
        }
        // Step 1: "If dkLen > (2^32 - 1) * hLen, output "derived key too long" and stop."
        if len > Self::MAX_LEN {
            return Err(KDFError::InvalidLength("derived key too long"));
        }
        if len > dk.capacity() {
            return Err(KDFError::InvalidLength("the output buffer cannot hold dkLen bytes"));
        }

        let key = Self::prf_key(keys)?;
        // Each block is written to `dk` as it is finished; nothing after the checks above fails.
        let filled = do_hazardous_operations(dk, |dk| {
            let out = dk.ref_to_bytes_mut()?;
            Self::fill(&key, self.salt, self.iterations, &mut out[..len]);
            Ok(())
        });
        // What the output can claim is the [`KDF`] trait's rule, applied once it is in place.
        let labelled = filled.and_then(|()| {
            label_kdf_output(keys, len, h_len / 2, H::HMAC_MAX_SECURITY_STRENGTH, dk)
        });
        if labelled.is_err() {
            dk.zeroize();
        }
        labelled?;
        Ok(len)
    }

    /// The PRF, HMAC, keyed with the password, the concatenation of `keys` (Appendix B.1.1).
    fn prf_key<K: KeyMaterialTrait + ?Sized>(keys: &[&K]) -> Result<HmacKey<H>, KDFError> {
        let h_len = H::OUTPUT_LEN;
        let total = keys.iter().fold(0usize, |n, k| n.saturating_add(k.key_len()));
        // [`HmacKey`] takes one `MACKey`, so the password is copied and re-typed here; RFC 2104
        // Section 3 replaces a key longer than a block by its hash, which is done over the keys
        // in order when their concatenation is that long, so the copy keys HMAC exactly as the
        // password would.
        let mut p = Secret::<[u8; LARGEST_HASHER_BLOCK_LEN]>::new();
        let p_len = if total > H::BLOCK_LEN {
            let mut hash = H::default();
            for key in keys {
                hash.do_update(key.ref_to_bytes());
            }
            hash.finish_into(&finish_token(), &mut p[..h_len])
        } else {
            let mut at = 0;
            for key in keys {
                let bytes = key.ref_to_bytes();
                p[at..at + bytes.len()].copy_from_slice(bytes);
                at += bytes.len();
            }
            at
        };
        let mac_key = KeyMaterial::<LARGEST_HASHER_BLOCK_LEN>::from_bytes_as_type(
            &p[..p_len],
            KeyType::MACKey,
        )?;
        // The pads are absorbed once, here; each PRF call costs two compressions.
        Ok(HmacKey::<H>::from_key_material_allow_weak(&mac_key)?)
    }

    /// Steps 2 to 4 of Section 5.2: `out`, all of it, with `dkLen = out.len()` octets of derived
    /// key under `key`, the PRF keyed with the password.
    fn fill(key: &HmacKey<H>, salt: &[u8], iterations: NonZeroU32, out: &mut [u8]) {
        let h_len = H::OUTPUT_LEN;
        // T_i and U_j are key material, so both blocks zeroize on drop.
        #[allow(non_snake_case)]
        let mut T = Secret::<[u8; MAX_HMAC_OUTPUT_LEN]>::new();
        #[allow(non_snake_case)]
        let mut U = Secret::<[u8; MAX_HMAC_OUTPUT_LEN]>::new();
        // Step 2: l = CEIL(dkLen / hLen) blocks, the last giving r = dkLen - (l - 1) * hLen
        // octets. Step 3: T_i = F(P, S, c, i) for i = 1 to l; l fits a u32 (step 1).
        // The callers refuse a longer `out` ("derived key too long"); the counter would stop there.
        debug_assert!(out.len().div_ceil(h_len) <= u32::MAX as usize);
        for (i, block) in (1u32..=u32::MAX).zip(out.chunks_mut(h_len)) {
            // U_1 = PRF(P, S || INT(i)), "INT (i) is a four-octet encoding of the integer i,
            // most significant octet first".
            let mut hmac = hmac_hazmat::inner_state(key);
            hmac.do_update(salt);
            hmac.do_update(&i.to_be_bytes());
            hmac_hazmat::finish_out(key, &mut hmac, &mut U[..h_len]);
            T[..h_len].copy_from_slice(&U[..h_len]);
            // U_j = PRF(P, U_{j-1}) for j = 2 to c, and F = U_1 xor U_2 xor ... xor U_c.
            for _ in 1..iterations.get() {
                let mut hmac = hmac_hazmat::inner_state(key);
                hmac.do_update(&U[..h_len]);
                hmac_hazmat::finish_out(key, &mut hmac, &mut U[..h_len]);
                for (t, u) in T[..h_len].iter_mut().zip(U[..h_len].iter()) {
                    *t ^= u;
                }
            }
            // Step 4: DK = T_1 || T_2 || ... || T_l<0..r-1>.
            block.copy_from_slice(&T[..block.len()]);
        }
    }

    /// PBKDF2 has no fixed info: a caller who supplies some has mistaken it for another KDF,
    /// and dropping it silently would hide that.
    fn check_fixed_info(
        fixed_info: &[u8],
        dk: &mut (impl KeyMaterialTrait + ?Sized),
    ) -> Result<(), KDFError> {
        if !fixed_info.is_empty() {
            dk.zeroize();
            return Err(KDFError::InvalidLength("PBKDF2 takes no fixed info"));
        }
        Ok(())
    }
}

impl<H: HMACParams> KDF for PBKDF2<'_, H> {
    /// RFC 8018 Section 5.2 with the password `ikm`, under this instance's salt and iteration
    /// count.
    ///
    /// # Errors
    /// [`KDFError::InvalidLength`] if `fixed_info` is not empty, or if `len` is zero, exceeds
    /// [`PBKDF2::MAX_LEN`] or exceeds the buffer's capacity; the buffer is left zeroized.
    fn derive_key_out(
        &self,
        ikm: &dyn KeyMaterialTrait,
        fixed_info: &[u8],
        len: usize,
        output_key: &mut dyn KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        Self::check_fixed_info(fixed_info, output_key)?;
        self.derive_keys_out(&[ikm], len, output_key)
    }

    /// [`KDF::derive_key_out`] with the password the bare concatenation of `ikms`; an empty
    /// `ikms` is [`KDFError::InvalidLength`].
    fn derive_key_from_multiple_out(
        &self,
        ikms: &[&dyn KeyMaterialTrait],
        fixed_info: &[u8],
        len: usize,
        output_key: &mut dyn KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        Self::check_fixed_info(fixed_info, output_key)?;
        self.derive_keys_out(ikms, len, output_key)
    }
}

pub mod hazmat {
    //! PBKDF2 into a plain byte buffer, for a construction that uses it as a step and holds
    //! the result itself: scrypt's first step fills its working memory this way (RFC 7914
    //! Section 6). See [`bouncycastle_core::hazmat`] for what the path means.
    //!
    //! # 🚨 Security Considerations 🚨
    //!
    //! The output of [`pbkdf2_into`] is key material in a buffer that carries no type, no
    //! strength and no zeroization: the caller wipes it. Use [`PBKDF2`] unless
    //! a `KeyMaterial` cannot hold what is being derived.

    use super::{KDFError, PBKDF2};
    use crate::hmac::HMACParams;
    use bouncycastle_core::key_material::KeyMaterialTrait;
    use core::num::NonZeroU32;

    /// RFC 8018 Section 5.2 over HMAC with `H`: `out`, all of it, with `dkLen = out.len()`
    /// octets of derived key from the password, the concatenation of `keys`, the salt and the
    /// iteration count. `out` is cleared first. Returns the number of bytes written,
    /// `out.len()`.
    ///
    /// # Errors
    /// [`KDFError::InvalidLength`] if `out` is empty or longer than `(2^32 - 1) * hLen`, or if
    /// `keys` is empty; `out` is left cleared.
    pub fn pbkdf2_into<H: HMACParams>(
        keys: &[&dyn KeyMaterialTrait],
        salt: &[u8],
        iterations: NonZeroU32,
        out: &mut [u8],
    ) -> Result<usize, KDFError> {
        let () = PBKDF2::<H>::CHECKS;
        out.fill(0);
        if out.is_empty() {
            return Err(KDFError::InvalidLength("a zero-length derivation is refused"));
        }
        if keys.is_empty() {
            return Err(KDFError::InvalidLength("a derivation from no keys is refused"));
        }
        if out.len() > PBKDF2::<H>::MAX_LEN {
            return Err(KDFError::InvalidLength("derived key too long"));
        }
        let key = PBKDF2::<H>::prf_key(keys)?;
        PBKDF2::<H>::fill(&key, salt, iterations, out);
        Ok(out.len())
    }
}
