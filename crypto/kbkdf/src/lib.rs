//! Key derivation using pseudorandom functions, NIST SP 800-108r1 (with the 2024 errata
//! update): keying material of a requested length from a key-derivation key `K_IN` and the
//! fixed input data a protocol defines.
//!
//! [`KDF_Counter<P>`], [`KDF_Feedback<P>`] and [`KDF_DoublePipeline<P>`] are the KDFs in Counter
//! Mode, Feedback Mode and Double-Pipeline Mode (Sections 4.1 to 4.3) over a PRF `P`, which is
//! [`PRF_HMAC<H>`] for HMAC over a hash or [`PRF_CMAC<P>`] for CMAC over AES. The aliases
//! [`KDF_Counter_HMAC_SHA256`], [`KDF_Counter_CMAC_AES256`] and the like name the instantiations
//! over the SHA-2 and SHA-3 hashes and the three AES key lengths. [`KDF_KMAC128`] and
//! [`KDF_KMAC256`] are the KDF Using KMAC (Section 4.4), a single KMAC call.
//!
//! # Usage Examples
//!
//! Through the [`KDF`](bouncycastle_core::traits::KDF) trait, with the fixed input data in the
//! layout Section 4 writes, `Label || 0x00 || Context || [L]2`:
//!
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
//! use bouncycastle_core::traits::KDF;
//! use bouncycastle_kbkdf::{KDF_Counter_HMAC_SHA256, fixed_input_out};
//!
//! let k_in = KeyMaterial::<32>::from_bytes_as_type(&[0x5A; 32], KeyType::CryptographicRandom).unwrap();
//!
//! let mut fixed = [0u8; 64];
//! let n = fixed_input_out(b"session keys", b"alice|bob|session 7", 32, &mut fixed).unwrap();
//!
//! let key = KDF_Counter_HMAC_SHA256::new().derive_key(&k_in, &fixed[..n], 32).unwrap();
//! assert_eq!(key.key_len(), 32);
//! assert_eq!(key.key_type(), KeyType::CryptographicRandom);
//! ```
//!
//! A protocol that lays the input out differently passes its own bytes as the fixed input data
//! and says where the counter goes:
//!
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::KDF;
//! use bouncycastle_kbkdf::{CounterPosition, CounterSize, KDF_Counter_HMAC_SHA512};
//!
//! let k_in = KeyMaterial::<32>::from_bytes_as_type(&[0x5A; 32], KeyType::CryptographicRandom).unwrap();
//! let kdf = KDF_Counter_HMAC_SHA512::with_counter(CounterSize::_8bit, CounterPosition::AfterFixedInput);
//! let key = kdf.derive_key(&k_in, b"the protocol's own encoding", 48).unwrap();
//! ```
//!
//! The KDF Using KMAC takes the Label when it is made and the Context as the fixed input data:
//!
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
//! use bouncycastle_core::traits::KDF;
//! use bouncycastle_kbkdf::KDF_KMAC256;
//!
//! let k_in = KeyMaterial::<32>::from_bytes_as_type(&[0x5A; 32], KeyType::CryptographicRandom).unwrap();
//! let key = KDF_KMAC256::new(b"KDF").derive_key(&k_in, b"alice|bob|session 7", 32).unwrap();
//! assert_eq!(key.key_len(), 32);
//! ```
//!
//! # Memory Usage
//!
//! The KDFs hold their parameters only: a derivation keys the PRF once, keeps its working
//! blocks in [`Secret`]s on the stack and writes straight into the caller's buffer. Peak stack
//! for 64 bytes from a 32-byte key, in bytes (x86-64, release, rustc 1.97.0-nightly, the deepest
//! frame chain of `bench_kbkdf_mem_usage`):
//!
//! | PRF | Counter | Feedback | Double-Pipeline |
//! |---|---|---|---|
//! | HMAC-SHA256 | 2632 | 2824 | 2856 |
//! | HMAC-SHA512 | 4312 | 4696 | 4728 |
//! | HMAC-SHA3-256 | 6472 | | |
//! | CMAC-AES256 | 2848 | | |
//!
//! [`KDF_KMAC128`] and [`KDF_KMAC256`]: 5992, of which [`MAX_KMAC_KDK_LEN`] bytes are the copy
//! of the key-derivation key.
//!
//! [`Secret`]: bouncycastle_utils::secret::Secret
//!
//! # 🚨 Security Considerations 🚨
//!
//! - **The key-derivation key is for key derivation only.** Section 5: key-derivation keys
//!   "shall not be used for any purpose other than key derivation". It is credited as keying
//!   material only when it is typed full-entropy material with a strength; the output is then
//!   `CryptographicRandom` at the least of the key's, the PRF's and the output length's
//!   strengths, and otherwise `Unknown`. The KDF expands keying material and creates none.
//! - **The fixed input data must be unambiguous and must differ between derivations.** Section
//!   6.4 requires an encoding that maps each set of inputs to a unique string; Section 6.5
//!   requires that "different input data strings ... shall be used for different executions of
//!   the KDF using the same K_IN". Neither can be checked here: the layout is the caller's.
//!   Without `[L]2` in it, outputs at two lengths are prefixes of each other in the iterated
//!   modes; the KMAC KDF binds the length itself.
//! - **An all-zero key is not refused** by any of these KDFs, nor an empty one by the HMAC and
//!   KMAC KDFs; the output is then `Unknown`, with no strength.
//! - **Several keys from one output come from disjoint segments** (Section 6.3), and using the
//!   output as a key stream "is not recommended".
//! - **Key control.** A party who knows `K_IN` and chooses part of the fixed input data can
//!   steer the output when the PRF is CMAC (Section 6.7, Appendix B), which is why Section 3
//!   advises HMAC or KMAC unless AES is all the platform has. [`KDF_Counter::with_key_control_guard`]
//!   and [`KDF_Feedback::with_key_control_guard`] apply the guards of Sections 4.1 and 4.2, and
//!   a counter is Section 4.3's for [`KDF_DoublePipeline`]; a guard changes the output, so both
//!   parties must use it.
//! - **A long HMAC key gains nothing.** Section 6.2: a key-derivation key longer than the
//!   hash's input block is hashed first, so the strength "may be decreased by increasing the
//!   length of the KDK beyond the length of an input block".
//! - **CMAC takes a key of the cipher's length only** (Section 6.2), and the KMAC KDF one of at
//!   most [`MAX_KMAC_KDK_LEN`] bytes. The counter is a whole number of bytes (8, 16, 24 or 32
//!   bits), where Section 4 allows any size from 1 to 32 bits; with a counter of `r` bits a
//!   derivation is held to `2^r - 1` PRF outputs in every mode; and `L` is a whole number of
//!   bytes.

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

mod counter;
mod double_pipeline;
mod feedback;
mod kmac;
mod prf;

pub use counter::{CounterPosition, KDF_Counter};
pub use double_pipeline::KDF_DoublePipeline;
pub use feedback::KDF_Feedback;
pub use kmac::{
    KDF_KMAC, KDF_KMAC128, KDF_KMAC128_NAME, KDF_KMAC256, KDF_KMAC256_NAME, KmacKdfParams,
    MAX_KMAC_KDK_LEN,
};
pub use prf::{MAX_PRF_OUTPUT_LEN, PRF_CMAC, PRF_HMAC, Prf};

use bouncycastle_aes::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle_core::errors::{KDFError, KeyMaterialError};
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::key_material::{KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_sha2::{SHA224, SHA256, SHA384, SHA512};
use bouncycastle_sha3::{SHA3_224, SHA3_256, SHA3_384, SHA3_512};
use bouncycastle_utils::{max, min};

/// `r`, "the length of the binary representation of the counter i" (SP 800-108r1 Section 4),
/// in whole bytes. The counter takes the values `1` to `2^r - 1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CounterSize {
    /// An 8-bit counter: at most 255 PRF outputs.
    _8bit,
    /// A 16-bit counter.
    _16bit,
    /// A 24-bit counter.
    _24bit,
    /// A 32-bit counter.
    _32bit,
}

impl CounterSize {
    /// The counter's length in bytes.
    pub const fn byte_len(&self) -> usize {
        match self {
            Self::_8bit => 1,
            Self::_16bit => 2,
            Self::_24bit => 3,
            Self::_32bit => 4,
        }
    }

    /// `r`, the counter's size in bits.
    pub const fn bits(&self) -> u32 {
        self.byte_len() as u32 * 8
    }

    /// `2^r - 1`, the largest value the counter takes.
    pub const fn max_count(&self) -> u32 {
        u32::MAX >> (32 - self.bits())
    }
}

/// Where the counter `[i]2` goes in each PRF input of the feedback and double-pipeline modes,
/// relative to the iteration variable (`K(i-1)` or `A(i)`) and the fixed input data. Sections
/// 4.2 and 4.3 write it after the iteration variable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IterationCounterPosition {
    /// `[i]2 || iteration variable || fixed input data`.
    BeforeIterationVariable,
    /// `iteration variable || [i]2 || fixed input data`: the order Sections 4.2 and 4.3 write.
    AfterIterationVariable,
    /// `iteration variable || fixed input data || [i]2`.
    AfterFixedInput,
}

/// One PRF input of the feedback or double-pipeline mode, as the pieces to feed in order: the
/// iteration variable and the fixed input data, with the low `r` bits of `counter` where
/// `config` puts them, if it uses a counter at all.
pub(crate) fn iteration_input<'a>(
    config: Option<(CounterSize, IterationCounterPosition)>,
    iteration_variable: &'a [u8],
    counter: &'a [u8; 4],
    fixed_input: &'a [u8],
) -> [&'a [u8]; 3] {
    match config {
        None => [iteration_variable, fixed_input, &[]],
        Some((r, position)) => {
            let counter = &counter[4 - r.byte_len()..];
            match position {
                IterationCounterPosition::BeforeIterationVariable => {
                    [counter, iteration_variable, fixed_input]
                }
                IterationCounterPosition::AfterIterationVariable => {
                    [iteration_variable, counter, fixed_input]
                }
                IterationCounterPosition::AfterFixedInput => {
                    [iteration_variable, fixed_input, counter]
                }
            }
        }
    }
}

/// The most bytes a feedback or double-pipeline derivation produces over `P`: `2^32 - 1` PRF
/// outputs, or `2^r - 1` with a counter of `r` bits; `usize::MAX` where that does not fit.
pub(crate) fn max_len<P: Prf>(config: Option<(CounterSize, IterationCounterPosition)>) -> usize {
    let n = match config {
        None => u32::MAX,
        Some((r, _)) => r.max_count(),
    };
    usize::try_from(P::H_LEN as u128 * n as u128).unwrap_or(usize::MAX)
}

/// The fixed input data as SP 800-108r1 Section 4 writes it, `Label || 0x00 || Context ||
/// [L]2`, into the front of `out`, which is zeroized first; returns the number of bytes
/// written, [`fixed_input_out_len`]. `derived_len` is the length in bytes that will be asked of
/// `derive_key`, so that `L`, its length in bits, is the one the derivation uses; it is encoded
/// as 32 bits, big-endian: the standard leaves the encoding of `[L]2`, like the rest of the
/// layout, to the protocol.
///
/// The layout is not self-delimiting: a label holding a zero byte reads as a shorter label and
/// a longer context, so (`a\0b`, `c`) and (`a`, `b\0c`) give the same data and the same key.
/// Keep zero bytes out of the label, or fix its length, where the two must not collide (the
/// crate's Security Considerations).
///
/// # Errors
/// [`KDFError::InvalidLength`] if `out` is shorter than [`fixed_input_out_len`], or if
/// `derived_len` in bits does not fit 32 bits.
pub fn fixed_input_out(
    label: &[u8],
    context: &[u8],
    derived_len: usize,
    out: &mut [u8],
) -> Result<usize, KDFError> {
    out.fill(0);
    let l_bits = derived_len
        .checked_mul(8)
        .and_then(|bits| u32::try_from(bits).ok())
        .ok_or(KDFError::InvalidLength("the derived length in bits does not fit [L]2"))?;
    let len = fixed_input_out_len(label, context);
    if out.len() < len {
        return Err(KDFError::InvalidLength("the buffer cannot hold the fixed input data"));
    }
    out[..label.len()].copy_from_slice(label);
    // out[label.len()] is the separator 0x00, already there.
    let context_at = label.len() + 1;
    out[context_at..context_at + context.len()].copy_from_slice(context);
    out[context_at + context.len()..len].copy_from_slice(&l_bits.to_be_bytes());
    Ok(len)
}

/// The length of what [`fixed_input_out`] writes: the label, one separator byte, the context
/// and four bytes of `[L]2`.
pub fn fixed_input_out_len(label: &[u8], context: &[u8]) -> usize {
    label.len() + 1 + context.len() + 4
}

/// Types the derived keying material in `dkm`, `len` bytes of it, by the
/// [`KDF`](bouncycastle_core::traits::KDF) trait's rule: `CryptographicRandom` when the
/// full-entropy keys with a strength carry at least `seed_len` bytes between them, at the least
/// of the strongest key's strength, `max_strength` and the length's, and otherwise `Unknown`.
pub(crate) fn label_output<K: KeyMaterialTrait + ?Sized>(
    keys: &[&K],
    len: usize,
    seed_len: usize,
    max_strength: SecurityStrength,
    dkm: &mut (impl KeyMaterialTrait + ?Sized),
) -> Result<(), KeyMaterialError> {
    let mut credited = 0usize;
    let mut strength = SecurityStrength::None;
    for key in keys {
        if key.is_full_entropy() && key.security_strength() != SecurityStrength::None {
            credited = credited.saturating_add(key.key_len());
            strength = *max(&strength, &key.security_strength());
        }
    }
    do_hazardous_operations(dkm, |dkm| {
        dkm.set_key_len(len)?;
        if credited >= seed_len {
            dkm.set_key_type(KeyType::CryptographicRandom)?;
            let by_len = SecurityStrength::from_bytes(len);
            dkm.set_security_strength(*min(min(&strength, &max_strength), &by_len))
        } else {
            dkm.set_key_type(KeyType::Unknown)?;
            dkm.set_security_strength(SecurityStrength::None)
        }
    })
}

// Names exist for the instantiations `bouncycastle-factory` registers, which are these six; the
// other aliases are reached by type.
/// The name of the KDF in Counter Mode over HMAC-SHA256.
pub const KDF_COUNTER_HMAC_SHA256_NAME: &str = "KDF-Counter-HMAC-SHA256";
/// The name of the KDF in Counter Mode over HMAC-SHA384.
pub const KDF_COUNTER_HMAC_SHA384_NAME: &str = "KDF-Counter-HMAC-SHA384";
/// The name of the KDF in Counter Mode over HMAC-SHA512.
pub const KDF_COUNTER_HMAC_SHA512_NAME: &str = "KDF-Counter-HMAC-SHA512";
/// The name of the KDF in Counter Mode over CMAC-AES256.
pub const KDF_COUNTER_CMAC_AES256_NAME: &str = "KDF-Counter-CMAC-AES256";

/// The KDF in Counter Mode over HMAC-SHA224.
#[allow(non_camel_case_types)]
pub type KDF_Counter_HMAC_SHA224 = KDF_Counter<PRF_HMAC<SHA224>>;
/// The KDF in Counter Mode over HMAC-SHA256.
#[allow(non_camel_case_types)]
pub type KDF_Counter_HMAC_SHA256 = KDF_Counter<PRF_HMAC<SHA256>>;
/// The KDF in Counter Mode over HMAC-SHA384.
#[allow(non_camel_case_types)]
pub type KDF_Counter_HMAC_SHA384 = KDF_Counter<PRF_HMAC<SHA384>>;
/// The KDF in Counter Mode over HMAC-SHA512.
#[allow(non_camel_case_types)]
pub type KDF_Counter_HMAC_SHA512 = KDF_Counter<PRF_HMAC<SHA512>>;
/// The KDF in Counter Mode over HMAC-SHA3-224.
#[allow(non_camel_case_types)]
pub type KDF_Counter_HMAC_SHA3_224 = KDF_Counter<PRF_HMAC<SHA3_224>>;
/// The KDF in Counter Mode over HMAC-SHA3-256.
#[allow(non_camel_case_types)]
pub type KDF_Counter_HMAC_SHA3_256 = KDF_Counter<PRF_HMAC<SHA3_256>>;
/// The KDF in Counter Mode over HMAC-SHA3-384.
#[allow(non_camel_case_types)]
pub type KDF_Counter_HMAC_SHA3_384 = KDF_Counter<PRF_HMAC<SHA3_384>>;
/// The KDF in Counter Mode over HMAC-SHA3-512.
#[allow(non_camel_case_types)]
pub type KDF_Counter_HMAC_SHA3_512 = KDF_Counter<PRF_HMAC<SHA3_512>>;
/// The KDF in Counter Mode over CMAC-AES128.
#[allow(non_camel_case_types)]
pub type KDF_Counter_CMAC_AES128 = KDF_Counter<PRF_CMAC<AES128Internal>>;
/// The KDF in Counter Mode over CMAC-AES192.
#[allow(non_camel_case_types)]
pub type KDF_Counter_CMAC_AES192 = KDF_Counter<PRF_CMAC<AES192Internal>>;
/// The KDF in Counter Mode over CMAC-AES256.
#[allow(non_camel_case_types)]
pub type KDF_Counter_CMAC_AES256 = KDF_Counter<PRF_CMAC<AES256Internal>>;

/// The KDF in Feedback Mode over HMAC-SHA224.
#[allow(non_camel_case_types)]
pub type KDF_Feedback_HMAC_SHA224<'iv> = KDF_Feedback<'iv, PRF_HMAC<SHA224>>;
/// The KDF in Feedback Mode over HMAC-SHA256.
#[allow(non_camel_case_types)]
pub type KDF_Feedback_HMAC_SHA256<'iv> = KDF_Feedback<'iv, PRF_HMAC<SHA256>>;
/// The KDF in Feedback Mode over HMAC-SHA384.
#[allow(non_camel_case_types)]
pub type KDF_Feedback_HMAC_SHA384<'iv> = KDF_Feedback<'iv, PRF_HMAC<SHA384>>;
/// The KDF in Feedback Mode over HMAC-SHA512.
#[allow(non_camel_case_types)]
pub type KDF_Feedback_HMAC_SHA512<'iv> = KDF_Feedback<'iv, PRF_HMAC<SHA512>>;
/// The KDF in Feedback Mode over HMAC-SHA3-224.
#[allow(non_camel_case_types)]
pub type KDF_Feedback_HMAC_SHA3_224<'iv> = KDF_Feedback<'iv, PRF_HMAC<SHA3_224>>;
/// The KDF in Feedback Mode over HMAC-SHA3-256.
#[allow(non_camel_case_types)]
pub type KDF_Feedback_HMAC_SHA3_256<'iv> = KDF_Feedback<'iv, PRF_HMAC<SHA3_256>>;
/// The KDF in Feedback Mode over HMAC-SHA3-384.
#[allow(non_camel_case_types)]
pub type KDF_Feedback_HMAC_SHA3_384<'iv> = KDF_Feedback<'iv, PRF_HMAC<SHA3_384>>;
/// The KDF in Feedback Mode over HMAC-SHA3-512.
#[allow(non_camel_case_types)]
pub type KDF_Feedback_HMAC_SHA3_512<'iv> = KDF_Feedback<'iv, PRF_HMAC<SHA3_512>>;
/// The KDF in Feedback Mode over CMAC-AES128.
#[allow(non_camel_case_types)]
pub type KDF_Feedback_CMAC_AES128<'iv> = KDF_Feedback<'iv, PRF_CMAC<AES128Internal>>;
/// The KDF in Feedback Mode over CMAC-AES192.
#[allow(non_camel_case_types)]
pub type KDF_Feedback_CMAC_AES192<'iv> = KDF_Feedback<'iv, PRF_CMAC<AES192Internal>>;
/// The KDF in Feedback Mode over CMAC-AES256.
#[allow(non_camel_case_types)]
pub type KDF_Feedback_CMAC_AES256<'iv> = KDF_Feedback<'iv, PRF_CMAC<AES256Internal>>;

/// The KDF in Double-Pipeline Mode over HMAC-SHA224.
#[allow(non_camel_case_types)]
pub type KDF_DoublePipeline_HMAC_SHA224 = KDF_DoublePipeline<PRF_HMAC<SHA224>>;
/// The KDF in Double-Pipeline Mode over HMAC-SHA256.
#[allow(non_camel_case_types)]
pub type KDF_DoublePipeline_HMAC_SHA256 = KDF_DoublePipeline<PRF_HMAC<SHA256>>;
/// The KDF in Double-Pipeline Mode over HMAC-SHA384.
#[allow(non_camel_case_types)]
pub type KDF_DoublePipeline_HMAC_SHA384 = KDF_DoublePipeline<PRF_HMAC<SHA384>>;
/// The KDF in Double-Pipeline Mode over HMAC-SHA512.
#[allow(non_camel_case_types)]
pub type KDF_DoublePipeline_HMAC_SHA512 = KDF_DoublePipeline<PRF_HMAC<SHA512>>;
/// The KDF in Double-Pipeline Mode over HMAC-SHA3-224.
#[allow(non_camel_case_types)]
pub type KDF_DoublePipeline_HMAC_SHA3_224 = KDF_DoublePipeline<PRF_HMAC<SHA3_224>>;
/// The KDF in Double-Pipeline Mode over HMAC-SHA3-256.
#[allow(non_camel_case_types)]
pub type KDF_DoublePipeline_HMAC_SHA3_256 = KDF_DoublePipeline<PRF_HMAC<SHA3_256>>;
/// The KDF in Double-Pipeline Mode over HMAC-SHA3-384.
#[allow(non_camel_case_types)]
pub type KDF_DoublePipeline_HMAC_SHA3_384 = KDF_DoublePipeline<PRF_HMAC<SHA3_384>>;
/// The KDF in Double-Pipeline Mode over HMAC-SHA3-512.
#[allow(non_camel_case_types)]
pub type KDF_DoublePipeline_HMAC_SHA3_512 = KDF_DoublePipeline<PRF_HMAC<SHA3_512>>;
/// The KDF in Double-Pipeline Mode over CMAC-AES128.
#[allow(non_camel_case_types)]
pub type KDF_DoublePipeline_CMAC_AES128 = KDF_DoublePipeline<PRF_CMAC<AES128Internal>>;
/// The KDF in Double-Pipeline Mode over CMAC-AES192.
#[allow(non_camel_case_types)]
pub type KDF_DoublePipeline_CMAC_AES192 = KDF_DoublePipeline<PRF_CMAC<AES192Internal>>;
/// The KDF in Double-Pipeline Mode over CMAC-AES256.
#[allow(non_camel_case_types)]
pub type KDF_DoublePipeline_CMAC_AES256 = KDF_DoublePipeline<PRF_CMAC<AES256Internal>>;
