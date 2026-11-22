//! scrypt, the memory-hard password-based key derivation function of RFC 7914:
//! `DK = scrypt(P, S, N, r, p, dkLen)`, a derived key from a password, a salt and three cost
//! parameters.
//!
//! [`SCrypt`] holds the salt and the [`ScryptParams`], and the password is the key it is
//! given. The derivation needs `128 * r * N` bytes of working memory and more besides
//! ([`ScryptParams::work_len`]); [`SCrypt::derive_with_memory_out`] takes that memory from the
//! caller, and with the `std` feature the [`KDF`] trait impl allocates it, up to a limit the
//! instance carries.
//!
//! # Usage Examples
//!
//! With working memory the caller owns:
//!
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
//! use bouncycastle_digest::scrypt::{SCrypt, ScryptParams};
//!
//! // A password is bytes of unknown entropy, and is typed so.
//! let password = KeyMaterial::<64>::from_bytes_as_type(b"correct horse battery staple", KeyType::Unknown).unwrap();
//! let salt = [0x5Au8; 16]; // from an RNG, stored beside what the key protects
//! let params = ScryptParams::new(10, 8, 1).unwrap(); // N = 2^10, r = 8, p = 1
//!
//! let mut work = vec![0u8; params.work_len()];
//! let mut key = KeyMaterial::<32>::new();
//! let written = SCrypt::new(&salt, params)
//!     .derive_with_memory_out(&password, 32, &mut work, &mut key)
//!     .unwrap();
//! assert_eq!(written, 32);
//! // The library cannot vouch for a password's entropy, so it does not vouch for the key's.
//! assert_eq!(key.key_type(), KeyType::Unknown);
//! ```
//!
//! Through the [`KDF`] trait, which allocates:
//!
//! ```
//! # #[cfg(feature = "std")] {
//! use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
//! use bouncycastle_core::traits::KDF;
//! use bouncycastle_digest::scrypt::{SCrypt, ScryptParams};
//!
//! let password = KeyMaterial::<64>::from_bytes_as_type(b"correct horse battery staple", KeyType::Unknown).unwrap();
//! let salt = [0x5Au8; 16];
//! let kdf = SCrypt::new(&salt, ScryptParams::new(10, 8, 1).unwrap());
//! let key = kdf.derive_key(&password, &[], 32).unwrap();
//! assert_eq!(key.key_len(), 32);
//! # }
//! ```
//!
//! # Memory Usage
//!
//! The working memory is [`ScryptParams::work_len`] bytes, `128 * r * (N + p + 1)`: 16 MiB at
//! `N = 2^14, r = 8, p = 1`. It is the caller's buffer, or with the [`KDF`] impl a heap
//! allocation; either way it is wiped before the derivation returns. Beside it the peak stack
//! is 2312 bytes, whatever the parameters (x86-64, release, rustc 1.97.0-nightly, the deepest
//! frame chain of `bench_scrypt_mem_usage`).
//!
//! # 🚨 Security Considerations 🚨
//!
//! - **A password is not a key.** As with PBKDF2, the derived key is typed `Unknown`, with no
//!   strength, unless what went in was full-entropy keying material: the cost parameters raise
//!   the price of each guess and add no entropy.
//! - **The parameters decide the cost to an attacker and to you.** RFC 7914 Section 14: "Poor
//!   parameter choices can be harmful for security; for example, if you tune the parameters so
//!   that memory use is reduced to small amounts that will affect the properties of the
//!   algorithm." Nothing here enforces a minimum.
//! - **Parameters from an untrusted source are a denial of service.** Section 14: "Systems
//!   should protect against a denial-of-service attack resulting from attackers presenting
//!   unreasonably large parameters." With caller-supplied memory the buffer is the bound; the
//!   [`KDF`] impl refuses parameters needing more than its instance's limit
//!   ([`DEFAULT_MAX_WORK_LEN`] unless set).
//! - **Which memory is read depends on the password.** ROMix indexes its table by a value
//!   derived from the password and the salt; that is the function's design, and it is visible
//!   to an attacker who can observe the cache.
//! - The salt is the caller's to choose and should be random and unique (Section 2: "The salt
//!   is normally uniquely and randomly generated"). The password's encoding is the caller's:
//!   the function takes octets.

use crate::pbkdf2::{PBKDF2_HMAC_SHA256, hazmat::pbkdf2_into};
use bouncycastle_core::errors::KDFError;
#[cfg(feature = "std")]
use bouncycastle_core::kdf_params::KdfDescription;
use bouncycastle_core::key_material::KeyMaterialTrait;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, KDF};
use bouncycastle_sha2::SHA256;
use bouncycastle_utils::secret::{Secret, zeroize_in_place};
use core::num::NonZeroU32;

/// The name of the algorithm.
pub const SCRYPT_NAME: &str = "scrypt";

/// The working memory the [`KDF`] impl allocates at most, unless an instance is given another
/// limit: 256 MiB, which admits `N` up to `2^17` at `r = 8`.
pub const DEFAULT_MAX_WORK_LEN: usize = 1 << 28;

/// A Salsa20/8 block, in bytes.
const BLOCK_LEN: usize = 64;

/// The one iteration scrypt runs PBKDF2 for (RFC 7914 Section 6 steps 1 and 3).
const ONE: NonZeroU32 = NonZeroU32::MIN;

/// scrypt's cost parameters (RFC 7914 Section 2): the CPU/memory cost `N`, a power of two held
/// as its logarithm, the block size `r` and the parallelization `p`, checked against the
/// RFC's rules when made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScryptParams {
    log2_n: u8,
    r: u32,
    p: u32,
    work_len: usize,
}

impl ScryptParams {
    /// The parameters `N = 2^log2_n`, `r` and `p`.
    ///
    /// # Errors
    /// [`KDFError::InvalidLength`] unless `N` is "larger than 1, a power of 2, and less than
    /// 2^(128 * r / 8)", `r` is at least 1 and `p` is "a positive integer less than or equal to
    /// ((2^32-1) * 32) / (128 * r)" (Section 2), or if the working memory they need,
    /// [`ScryptParams::work_len`], does not fit a `usize`.
    pub fn new(log2_n: u8, r: u32, p: u32) -> Result<Self, KDFError> {
        if r == 0 {
            return Err(KDFError::InvalidLength("r must be at least 1"));
        }
        // N > 1 and N < 2^(128 * r / 8) = 2^(16 * r), with N = 2^log2_n.
        if log2_n == 0 || u64::from(log2_n) >= 16 * u64::from(r) {
            return Err(KDFError::InvalidLength(
                "N must be larger than 1 and less than 2^(128 * r / 8)",
            ));
        }
        // p <= ((2^32 - 1) * 32) / (128 * r).
        let p_max = (u64::from(u32::MAX) * 32) / (128 * u64::from(r));
        if p == 0 || u64::from(p) > p_max {
            return Err(KDFError::InvalidLength(
                "p must be at least 1 and at most ((2^32-1) * 32) / (128 * r)",
            ));
        }
        // V is N blocks of 128 * r octets, B is p of them, and ROMix needs one more.
        let work_len = 1u128
            .checked_shl(u32::from(log2_n))
            .and_then(|n| n.checked_add(u128::from(p) + 1))
            .and_then(|blocks| blocks.checked_mul(128 * u128::from(r)))
            .and_then(|len| usize::try_from(len).ok())
            .ok_or(KDFError::InvalidLength("the working memory does not fit this platform"))?;
        Ok(Self { log2_n, r, p, work_len })
    }

    /// `log2(N)`.
    pub fn log2_n(&self) -> u8 {
        self.log2_n
    }

    /// The block size parameter `r`.
    pub fn r(&self) -> u32 {
        self.r
    }

    /// The parallelization parameter `p`.
    pub fn p(&self) -> u32 {
        self.p
    }

    /// The bytes of working memory a derivation under these parameters needs:
    /// `128 * r * (N + p + 1)`.
    pub fn work_len(&self) -> usize {
        self.work_len
    }

    /// `128 * r`, the length of one of ROMix's blocks.
    fn block_len(&self) -> usize {
        // Fits: work_len, a multiple of it, does.
        128 * self.r as usize
    }
}

/// scrypt (RFC 7914), holding the salt `S`, which it borrows, and the cost parameters.
///
/// The password `P` is the input key. scrypt has no input beyond the password, the salt and
/// the parameters, so the [`KDF`] trait's `fixed_info` must be empty.
#[derive(Clone, Copy)]
pub struct SCrypt<'s> {
    salt: &'s [u8],
    params: ScryptParams,
    max_work_len: usize,
}

impl Algorithm for SCrypt<'_> {
    const ALG_NAME: &'static str = SCRYPT_NAME;
    /// HMAC-SHA256's, which the first and last steps run through.
    const MAX_SECURITY_STRENGTH: SecurityStrength =
        <PBKDF2_HMAC_SHA256<'static> as Algorithm>::MAX_SECURITY_STRENGTH;
}

/// Every parameter is a readable field ([`SCrypt::salt`], [`SCrypt::params`],
/// [`SCrypt::max_work_len`]), so the KDF describes itself: the engine is a copy. With the `KDF`
/// impl it names, this needs `std`.
#[cfg(feature = "std")]
impl KdfDescription for SCrypt<'_> {
    type Engine = Self;

    fn engine(&self) -> Result<Self, KDFError> {
        Ok(*self)
    }
}

impl<'s> SCrypt<'s> {
    /// scrypt with the salt `salt` and the cost parameters `params`.
    pub fn new(salt: &'s [u8], params: ScryptParams) -> Self {
        Self { salt, params, max_work_len: DEFAULT_MAX_WORK_LEN }
    }

    /// This instance with `max_work_len` as the most working memory the [`KDF`] impl will
    /// allocate, in place of [`DEFAULT_MAX_WORK_LEN`]. It does not bound
    /// [`SCrypt::derive_with_memory_out`], whose memory is the caller's.
    pub fn with_max_work_len(mut self, max_work_len: usize) -> Self {
        self.max_work_len = max_work_len;
        self
    }

    /// The salt `S`.
    pub fn salt(&self) -> &'s [u8] {
        self.salt
    }

    /// The cost parameters.
    pub fn params(&self) -> ScryptParams {
        self.params
    }

    /// The most working memory the [`KDF`] impl will allocate.
    pub fn max_work_len(&self) -> usize {
        self.max_work_len
    }

    /// RFC 7914 Section 6: `dkLen = len` bytes of derived key from the password, written to
    /// the front of `dk`, which is zeroized first, using `work` as the working memory. Returns
    /// the number of bytes written, `len`.
    ///
    /// `work` must be at least [`ScryptParams::work_len`] bytes; that much of it is used, and
    /// wiped before this returns, whichever way it returns. The output is typed as PBKDF2's is:
    /// `Unknown` unless `password` is full-entropy keying material.
    ///
    /// # Errors
    /// [`KDFError::InvalidLength`] if `work` is too short, or if `len` is zero, exceeds
    /// `(2^32 - 1) * 32` or exceeds `dk`'s capacity; `dk` is left zeroized.
    pub fn derive_with_memory_out(
        &self,
        password: &dyn KeyMaterialTrait,
        len: usize,
        work: &mut [u8],
        dk: &mut dyn KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        self.derive_keys_out(&[password], len, work, dk)
    }

    fn derive_keys_out(
        &self,
        keys: &[&dyn KeyMaterialTrait],
        len: usize,
        work: &mut [u8],
        dk: &mut dyn KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        // The `_out` rule: nothing stale survives, whichever way this returns.
        dk.zeroize();

        let Some(work) = work.get_mut(..self.params.work_len) else {
            return Err(KDFError::InvalidLength("the working memory is shorter than work_len"));
        };
        let derived = self.derive_in(keys, len, work, dk);
        // B, V and X are derived from the password, so the memory is wiped on every path.
        for byte in work.iter_mut() {
            zeroize_in_place(byte);
        }
        if derived.is_err() {
            dk.zeroize();
        }
        derived
    }

    /// The derivation over working memory of exactly `work_len` bytes, which the caller wipes.
    fn derive_in(
        &self,
        keys: &[&dyn KeyMaterialTrait],
        len: usize,
        work: &mut [u8],
        dk: &mut dyn KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        let block_len = self.params.block_len();
        let b_len = block_len * self.params.p as usize;
        let (b, rest) = work.split_at_mut(b_len);
        let (t, v) = rest.split_at_mut(block_len);

        // Step 1: B[0] || B[1] || ... || B[p - 1] = PBKDF2-HMAC-SHA256 (P, S, 1, p * 128 * r).
        // A bad request is refused here, before any work is done, by the final step's own rules.
        Self::check_request(keys, len, dk)?;
        pbkdf2_into::<SHA256>(keys, self.salt, ONE, b)?;

        // Step 2: for i = 0 to p - 1 do B[i] = scryptROMix (r, B[i], N).
        for block in b.chunks_exact_mut(block_len) {
            ro_mix(block, self.params.log2_n, t, v);
        }

        // Step 3: DK = PBKDF2-HMAC-SHA256 (P, B[0] || B[1] || ... || B[p - 1], 1, dkLen).
        PBKDF2_HMAC_SHA256::new(b, ONE).derive_key_from_multiple_out(keys, &[], len, dk)
    }

    /// The checks that need no work done, in the order PBKDF2 makes them: `dkLen` not zero,
    /// within PBKDF2-HMAC-SHA256's bound (the final step's) and within the output buffer, and at
    /// least one key.
    fn check_request(
        keys: &[&dyn KeyMaterialTrait],
        len: usize,
        dk: &dyn KeyMaterialTrait,
    ) -> Result<(), KDFError> {
        if len == 0 {
            return Err(KDFError::InvalidLength("a zero-length derivation is refused"));
        }
        if len > PBKDF2_HMAC_SHA256::MAX_LEN {
            return Err(KDFError::InvalidLength("derived key too long"));
        }
        if len > dk.capacity() {
            return Err(KDFError::InvalidLength("the output buffer cannot hold dkLen bytes"));
        }
        if keys.is_empty() {
            return Err(KDFError::InvalidLength("a derivation from no keys is refused"));
        }
        Ok(())
    }

    /// scrypt has no fixed info: a caller who supplies some has mistaken it for another KDF,
    /// and dropping it silently would hide that.
    #[cfg(feature = "std")]
    fn derive_allocating(
        &self,
        keys: &[&dyn KeyMaterialTrait],
        fixed_info: &[u8],
        len: usize,
        dk: &mut dyn KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        dk.zeroize();
        if !fixed_info.is_empty() {
            return Err(KDFError::InvalidLength("scrypt takes no fixed info"));
        }
        if self.params.work_len > self.max_work_len {
            return Err(KDFError::InvalidLength(
                "the parameters need more working memory than this instance allows",
            ));
        }
        // Before the allocation, which a request that will be refused should not cost.
        Self::check_request(keys, len, dk)?;
        // Fallibly: `vec![0; n]` aborts the process when the memory is not there, and the limit
        // is the caller's to raise.
        let mut work = std::vec::Vec::new();
        work.try_reserve_exact(self.params.work_len)
            .map_err(|_| KDFError::GenericError("the working memory could not be allocated"))?;
        work.resize(self.params.work_len, 0u8);
        self.derive_keys_out(keys, len, &mut work, dk)
    }
}

#[cfg(feature = "std")]
impl KDF for SCrypt<'_> {
    /// RFC 7914 Section 6 with the password `ikm`, under this instance's salt and parameters,
    /// in working memory allocated for the call and wiped after it.
    ///
    /// # Errors
    /// [`KDFError::InvalidLength`] if `fixed_info` is not empty, if the parameters need more
    /// than [`SCrypt::max_work_len`] bytes of working memory, or if `len` is zero, exceeds
    /// `(2^32 - 1) * 32` or exceeds the buffer's capacity; [`KDFError::GenericError`] if the
    /// working memory cannot be allocated. The buffer is left zeroized.
    fn derive_key_out(
        &self,
        ikm: &dyn KeyMaterialTrait,
        fixed_info: &[u8],
        len: usize,
        output_key: &mut dyn KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        self.derive_allocating(&[ikm], fixed_info, len, output_key)
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
        self.derive_allocating(ikms, fixed_info, len, output_key)
    }
}

/// The Salsa20/8 core (RFC 7914 Section 3) on a 64-octet block, in place: the block as sixteen
/// little-endian words through four double rounds, then added to the input.
fn salsa20_8(block: &mut [u8; BLOCK_LEN]) {
    // The words are derived from the password; `Secret` wipes them on drop.
    let mut input = Secret::<[u32; 16]>::new();
    for (word, bytes) in input.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    }
    let mut x = Secret::<[u32; 16]>::new();
    x.copy_from_slice(&input[..]);

    // "#define R(a,b) (((a) << (b)) | ((a) >> (32 - (b))))", and one line of the RFC's listing:
    // x[a] ^= R(x[b] + x[c], n).
    #[inline(always)]
    fn step(x: &mut [u32; 16], a: usize, b: usize, c: usize, n: u32) {
        x[a] ^= x[b].wrapping_add(x[c]).rotate_left(n);
    }
    // "for (i = 8;i > 0;i -= 2)": four double rounds, the listing's 32 steps in its order.
    for _ in 0..4 {
        step(&mut x, 4, 0, 12, 7);
        step(&mut x, 8, 4, 0, 9);
        step(&mut x, 12, 8, 4, 13);
        step(&mut x, 0, 12, 8, 18);
        step(&mut x, 9, 5, 1, 7);
        step(&mut x, 13, 9, 5, 9);
        step(&mut x, 1, 13, 9, 13);
        step(&mut x, 5, 1, 13, 18);
        step(&mut x, 14, 10, 6, 7);
        step(&mut x, 2, 14, 10, 9);
        step(&mut x, 6, 2, 14, 13);
        step(&mut x, 10, 6, 2, 18);
        step(&mut x, 3, 15, 11, 7);
        step(&mut x, 7, 3, 15, 9);
        step(&mut x, 11, 7, 3, 13);
        step(&mut x, 15, 11, 7, 18);
        step(&mut x, 1, 0, 3, 7);
        step(&mut x, 2, 1, 0, 9);
        step(&mut x, 3, 2, 1, 13);
        step(&mut x, 0, 3, 2, 18);
        step(&mut x, 6, 5, 4, 7);
        step(&mut x, 7, 6, 5, 9);
        step(&mut x, 4, 7, 6, 13);
        step(&mut x, 5, 4, 7, 18);
        step(&mut x, 11, 10, 9, 7);
        step(&mut x, 8, 11, 10, 9);
        step(&mut x, 9, 8, 11, 13);
        step(&mut x, 10, 9, 8, 18);
        step(&mut x, 12, 15, 14, 7);
        step(&mut x, 13, 12, 15, 9);
        step(&mut x, 14, 13, 12, 13);
        step(&mut x, 15, 14, 13, 18);
    }
    // "for (i = 0;i < 16;++i) out[i] = x[i] + in[i];"
    for ((bytes, x), input) in block.chunks_exact_mut(4).zip(x.iter()).zip(input.iter()) {
        bytes.copy_from_slice(&x.wrapping_add(*input).to_le_bytes());
    }
}

/// scryptBlockMix (RFC 7914 Section 4): `input` and `output` are `128 * r` octets, `2 * r`
/// blocks of 64, and do not overlap.
fn block_mix(input: &[u8], output: &mut [u8]) {
    let half = input.len() / 2;
    // Step 1: X = B[2 * r - 1].
    let mut x = Secret::<[u8; BLOCK_LEN]>::new();
    x.copy_from_slice(&input[input.len() - BLOCK_LEN..]);
    // Step 2: for i = 0 to 2 * r - 1 do T = X xor B[i]; X = Salsa (T); Y[i] = X.
    for (i, block) in input.chunks_exact(BLOCK_LEN).enumerate() {
        for (x, b) in x.iter_mut().zip(block) {
            *x ^= b;
        }
        salsa20_8(&mut x);
        // Step 3: B' = (Y[0], Y[2], ..., Y[2 * r - 2], Y[1], Y[3], ..., Y[2 * r - 1]): the
        // even-numbered Y fill the first half in order and the odd-numbered the second.
        let at = (i / 2) * BLOCK_LEN + (i % 2) * half;
        output[at..at + BLOCK_LEN].copy_from_slice(&x[..]);
    }
}

/// scryptROMix (RFC 7914 Section 5) on the block `b` of `128 * r` octets, in place, with
/// `N = 2^log2_n`; `t` is one block of scratch and `v` holds `N` blocks.
fn ro_mix(b: &mut [u8], log2_n: u8, t: &mut [u8], v: &mut [u8]) {
    let block_len = b.len();
    // Step 1: X = B; `b` is X throughout.
    // Step 2: for i = 0 to N - 1 do V[i] = X; X = scryptBlockMix (X).
    for v_i in v.chunks_exact_mut(block_len) {
        v_i.copy_from_slice(b);
        block_mix(b, t);
        b.copy_from_slice(t);
    }
    // Step 3: for i = 0 to N - 1 do j = Integerify (X) mod N; T = X xor V[j];
    // X = scryptBlockMix (T).
    let mask = (1u64 << log2_n) - 1;
    for _ in 0..(1u64 << log2_n) {
        // "Integerify (B[0] ... B[2 * r - 1]) is defined as the result of interpreting
        // B[2 * r - 1] as a little-endian integer": N is below 2^64 here, so its low eight
        // octets are all that mod N can see.
        let last = &b[block_len - BLOCK_LEN..];
        let low = [last[0], last[1], last[2], last[3], last[4], last[5], last[6], last[7]];
        let j = (u64::from_le_bytes(low) & mask) as usize;
        for ((t, x), v) in t.iter_mut().zip(b.iter()).zip(&v[j * block_len..(j + 1) * block_len]) {
            *t = x ^ v;
        }
        block_mix(t, b);
    }
    // Step 4: B' = X.
}

#[cfg(test)]
mod tests {
    //! RFC 7914's own vectors for the three inner functions (Sections 8, 9 and 10). They are
    //! private, and their known answers cannot be reached through `scrypt` itself.
    extern crate std;
    use super::*;
    use std::vec;
    use std::vec::Vec;

    fn hex(s: &str) -> Vec<u8> {
        let digits: Vec<u8> = s.bytes().filter(|b| b.is_ascii_hexdigit()).collect();
        digits
            .chunks_exact(2)
            .map(|d| u8::from_str_radix(core::str::from_utf8(d).unwrap(), 16).unwrap())
            .collect()
    }

    const SALSA_IN: &str = "\
        7e879a214f3ec9867ca940e641718f26baee555b8c61c1b50df846116dcd3b1d \
        ee24f319df9b3d8514121e4b5ac5aa3276021d2909c74829edebc68db8b8c25e";
    const SALSA_OUT: &str = "\
        a41f859c6608cc993b81cacb020cef05044b2181a2fd337dfd7b1c6396682f29 \
        b4393168e3c9e6bcfe6bc5b7a06d96bae424cc102c91745c24ad673dc7618f81";
    const BLOCK_MIX_IN: &str = "\
        f7ce0b653d2d72a4108cf5abe912ffdd777616dbbb27a70e8204f3ae2d0f6fad \
        89f68f4811d1e87bcc3bd7400a9ffd29094f0184639574f39ae5a1315217bcd7 \
        894991447213bb226c25b54da86370fbcd984380374666bb8ffcb5bf40c254b0 \
        67d27c51ce4ad5fed829c90b505a571b7f4d1cad6a523cda770e67bceaaf7e89";
    const BLOCK_MIX_OUT: &str = "\
        a41f859c6608cc993b81cacb020cef05044b2181a2fd337dfd7b1c6396682f29 \
        b4393168e3c9e6bcfe6bc5b7a06d96bae424cc102c91745c24ad673dc7618f81 \
        20edc975323881a80540f64c162dcd3c21077cfe5f8d5fe2b1a4168f953678b7 \
        7d3b3d803b60e4ab920996e59b4d53b65d2a225877d5edf5842cb9f14eefe425";
    const RO_MIX_OUT: &str = "\
        79ccc193629debca047f0b70604bf6b62ce3dd4a9626e355fafc6198e6ea2b46 \
        d58413673b99b029d665c357601fb426a0b2f4bba200ee9f0a43d19b571a9c71 \
        ef1142e65d5a266fddca832ce59faa7cac0b9cf1be2bffca300d01ee387619c4 \
        ae12fd4438f203a0e4e1c47ec314861f4e9087cb33396a6873e8f9d2539a4b8e";

    /// Section 8.
    #[test]
    fn salsa20_8_core() {
        let mut block: [u8; 64] = hex(SALSA_IN).try_into().unwrap();
        salsa20_8(&mut block);
        assert_eq!(&block[..], &hex(SALSA_OUT)[..]);
    }

    /// Section 9, with r = 1.
    #[test]
    fn scrypt_block_mix() {
        let input = hex(BLOCK_MIX_IN);
        let mut output = vec![0u8; 128];
        block_mix(&input, &mut output);
        assert_eq!(output, hex(BLOCK_MIX_OUT));
    }

    /// Section 10, with r = 1 and N = 16; its input is Section 9's.
    #[test]
    fn scrypt_ro_mix() {
        let mut b = hex(BLOCK_MIX_IN);
        let mut t = vec![0u8; 128];
        let mut v = vec![0u8; 16 * 128];
        ro_mix(&mut b, 4, &mut t, &mut v);
        assert_eq!(b, hex(RO_MIX_OUT));
    }
}
