//! Implements the RIPEMD family of hash functions: RIPEMD-128, RIPEMD-160 and their optional
//! extensions RIPEMD-256 and RIPEMD-320, as specified by their designers (Dobbertin, Bosselaers,
//! Preneel).
//!
//! The specification the comments in this crate cite is the designers' pseudo-code, published at
//! <https://homes.esat.kuleuven.be/~bosselae/ripemd160.html> ("the designers' page") as
//! `rmd128.txt`, `rmd160.txt`, `rmd256.txt` and `rmd320.txt`. The pseudo-code defers the padding
//! to MD4, so RFC 1320 is cited for that. RIPEMD-160 and RIPEMD-128 are also standardised in
//! ISO/IEC 10118-3, which was not consulted.
//!
//! # Usage Examples
//! ## Hash
//! Hash functionality is accessed via the [`Hash`] trait, which is implemented by [`RIPEMD128`],
//! [`RIPEMD160`], [`RIPEMD256`] and [`RIPEMD320`].
//!
//! The simplest usage is via the one-shot functions.
//! ```
//! use bouncycastle_core::traits::HashOneShot;
//! use bouncycastle_ripemd::RIPEMD160;
//!
//! let output: Vec<u8> = RIPEMD160::hash(b"abc");
//! assert_eq!(output, b"\x8e\xb2\x08\xf7\xe0\x5d\x98\x7a\x9b\x04\x4a\x8e\x98\xc6\xb0\x87\xf1\x5a\x0b\xfc");
//! ```
//!
//! It also has a streaming API that can accept input in chunks of any size.
//!
//! ```
//! use bouncycastle_core::traits::Hash;
//! use bouncycastle_ripemd::RIPEMD160;
//!
//! let data = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
//! let mut ripemd = RIPEMD160::new();
//!
//! for chunk in data.chunks(16) {
//!     ripemd.do_update(chunk);
//! }
//!
//! let output: Vec<u8> = ripemd.do_final();
//! assert_eq!(output, b"\x12\xa0\x53\x38\x4a\x9c\x0c\x88\xe4\x05\xa0\x6c\x27\xdc\xf4\x9a\xda\x62\xeb\x2b");
//! ```
//!
//! A final byte holding fewer than 8 bits of data is taken as [`Hash::do_final_partial_bits`]
//! describes: MD4's padding is defined for any bit length (RFC 1320 Sec 3.1). The following
//! hashes 16 bytes plus the 3 bits `101`:
//! ```
//! use bouncycastle_core::traits::Hash;
//! use bouncycastle_ripemd::RIPEMD160;
//!
//! let data: &[u8] = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\xA0";
//! let mut ripemd = RIPEMD160::new();
//! ripemd.do_update(&data[..16]);
//! let output: Vec<u8> = ripemd.do_final_partial_bits(data[16], 3).expect("num_partial_bits is in 0..=7");
//! ```
//!
//! ## HMAC
//! See [hmac].
//!
//! # Memory Usage
//!
//! No heap memory is used by the algorithm itself; the `Vec<u8>`-returning convenience methods
//! allocate only the output buffer, and the `*_out` variants allocate nothing.
//!
//! | Object      | Size (bytes) | Suspended state (bytes) |
//! |-------------|--------------|-------------------------|
//! | `RIPEMD128` | 96           | 92                      |
//! | `RIPEMD160` | 104          | 96                      |
//! | `RIPEMD256` | 112          | 108                     |
//! | `RIPEMD320` | 120          | 116                     |
//!
//! Per-call stack usage does not depend on the data length. Measured as the deepest frame chain
//! from the call into each entry point in the release build (x86-64 Linux, rustc 1.97.0-nightly,
//! return addresses included; see `mem_usage_benches/src/bench_ripemd_mem_usage.rs`), in bytes:
//!
//! | Entry point                                   | RIPEMD-128 | RIPEMD-160 | RIPEMD-256 | RIPEMD-320 |
//! |-----------------------------------------------|------------|------------|------------|------------|
//! | `do_update`                                   | 248        | 264        | 248        | 264        |
//! | `do_final_out`                                | 256        | 272        | 256        | 320        |
//! | `do_final_partial_bits_out`                   | 256        | 272        | 256        | 320        |
//! | `hash_out` (one-shot)                         | 560        | 512        | 608        | 608        |
//! | `suspend` / `from_suspended`                  | 8 / 144    | 8 / 8      | 8 / 192    | 8 / 8      |
//! | `HmacKey::from_key_material` / `mac_out`      |            | 880 / 816  |            |            |
//!
//! # 🚨 Security Considerations 🚨
//!
//! * **These are legacy hash functions**, here for the protocols that require them, not for new
//!   designs. RIPEMD-128 offers at most 64 bits of collision resistance and RIPEMD-160 80 bits,
//!   both below the smallest strength this library models, and the designers guarantee the 256-
//!   and 320-bit extensions only the security level of the function each extends. All four
//!   therefore report [`Algorithm::MAX_SECURITY_STRENGTH`] as [`SecurityStrength::None`].
//! * **None of them signs without the hazmat wrapper.** They do not carry
//!   [`CollisionResistantHash`](bouncycastle_core::traits::CollisionResistantHash), which the
//!   library's signing roles require, so ECDSA over RIPEMD-160 verifies and does not sign. A
//!   caller who must make such a signature names the hash as
//!   [`WithoutCollisionResistance<RIPEMD160>`](bouncycastle_core::hazmat::WithoutCollisionResistance).
//! * All four are Merkle-Damgard constructions and so are subject to length extension:
//!   `H(k || m)` is not a secure MAC. Use HMAC ([`ripemd::hmac`](crate::hmac)) for keyed hashing.
//! * The chaining variable and input buffer are held in [`bouncycastle_utils::secret::Secret`] and
//!   zeroized on drop. Transient copies (the line variables and message words) in registers and
//!   stack locals during compression are not zeroized.
//! * The implementation contains no data-dependent branches or table lookups.
//! * Message length: a message of 2^61 bytes or more is hashed with its bit length reduced
//!   modulo 2^64, as RFC 1320 Sec 3.2 specifies.
//!
//! # Suspending and resuming execution
//!
//! All four functions impl [`Suspendable`], so that a hash in progress can be written to a cache
//! and resumed later:
//!
//! ```rust
//! use bouncycastle_ripemd::RIPEMD160;
//! use bouncycastle_core::traits::{Hash, HashOneShot, Suspendable};
//!
//! let mut ripemd = RIPEMD160::new();
//! ripemd.do_update(b"The quick brown fox");
//! let serialized_state = ripemd.suspend();
//!
//! // ... later, possibly on another host:
//! let mut resumed = RIPEMD160::from_suspended(serialized_state).unwrap();
//! resumed.do_update(b" jumped over the lazy dog");
//! let digest: Vec<u8> = resumed.do_final();
//! assert_eq!(digest, RIPEMD160::hash(b"The quick brown fox jumped over the lazy dog"));
//! ```

// todo #![no_std]
//      waiting for the no_std refactor that removes the `-> Vec<u8>` from core::traits::Hash

#![forbid(unsafe_code)]
#![forbid(missing_docs)]

mod common;
mod ripemd128;
mod ripemd160;

pub mod hmac;

use self::common::BLOCK_LEN;
pub use self::common::RIPEMDInternal;
pub use self::ripemd128::{SUSPENDED_RIPEMD128_STATE_LEN, SUSPENDED_RIPEMD256_STATE_LEN};
pub use self::ripemd160::{SUSPENDED_RIPEMD160_STATE_LEN, SUSPENDED_RIPEMD320_STATE_LEN};
use bouncycastle_core::errors::SuspendableError;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, AlgorithmOID, HashAlgParams, Suspendable};

/*** Imports needed for docs ***/
#[allow(unused_imports)]
use bouncycastle_core::traits::Hash;

/*** String constants ***/
/// Algorithm name string for RIPEMD-128, as used by the factories.
pub const RIPEMD128_NAME: &str = "RIPEMD128";
/// Algorithm name string for RIPEMD-160, as used by the factories.
pub const RIPEMD160_NAME: &str = "RIPEMD160";
/// Algorithm name string for RIPEMD-256, as used by the factories.
pub const RIPEMD256_NAME: &str = "RIPEMD256";
/// Algorithm name string for RIPEMD-320, as used by the factories.
pub const RIPEMD320_NAME: &str = "RIPEMD320";

/*** pub types ***/
/// Public type for RIPEMD-128.
pub type RIPEMD128 = RIPEMDInternal<RIPEMD128Params>;
/// Public type for RIPEMD-160.
pub type RIPEMD160 = RIPEMDInternal<RIPEMD160Params>;
/// Public type for RIPEMD-256, the 256-bit extension of RIPEMD-128.
pub type RIPEMD256 = RIPEMDInternal<RIPEMD256Params>;
/// Public type for RIPEMD-320, the 320-bit extension of RIPEMD-160.
pub type RIPEMD320 = RIPEMDInternal<RIPEMD320Params>;

/*** Param traits ***/
mod sealed {
    use crate::common::BLOCK_LEN;
    use bouncycastle_core::traits::HashAlgParams;
    use bouncycastle_utils::secret::ZeroizablePrimitive;

    /// What distinguishes the four parameter sets. The module is private, so the trait cannot be
    /// named outside this crate: no parameter set can be defined there, the four marker types in
    /// `lib.rs` being the only implementations, and nothing here is reachable from there.
    pub trait RIPEMDFamily: HashAlgParams + Clone {
        /// The chaining variable: four, five, eight or ten 32-bit words.
        type State: ZeroizablePrimitive + AsRef<[u32]> + AsMut<[u32]>;
        /// The initial value `h0, h1, ...` of the pseudo-code.
        const H0: Self::State;
        /// One application of the compression function to the chaining variable and one block.
        fn compress(h: &mut [u32], block: &[u8; BLOCK_LEN]);
    }
}

/// The public hash types expose the same parameters as their `*Params` marker, so the constants
/// are defined exactly once (on the params struct) and forwarded here.
impl<PARAMS: sealed::RIPEMDFamily> HashAlgParams for RIPEMDInternal<PARAMS> {
    const OUTPUT_LEN: usize = PARAMS::OUTPUT_LEN;
    const BLOCK_LEN: usize = PARAMS::BLOCK_LEN;
}

/*** RIPEMD-128 ***/
/// The parameters for RIPEMD-128.
#[derive(Clone)]
pub struct RIPEMD128Params;
impl Algorithm for RIPEMD128Params {
    const ALG_NAME: &'static str = RIPEMD128_NAME;
    /// 64-bit collision resistance: below the library's smallest modelled strength.
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::None;
}
impl HashAlgParams for RIPEMD128Params {
    const OUTPUT_LEN: usize = 16;
    const BLOCK_LEN: usize = 64;
}
impl sealed::RIPEMDFamily for RIPEMD128Params {
    type State = [u32; 4];
    /// `rmd128.txt`: `h0 = 0x67452301; h1 = 0xEFCDAB89; h2 = 0x98BADCFE; h3 = 0x10325476;`
    const H0: [u32; 4] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476];
    #[inline(always)]
    fn compress(h: &mut [u32], block: &[u8; BLOCK_LEN]) {
        ripemd128::compress(h, block, false);
    }
}
/// TeleTrusT: `{ 1.3.36.3.2.2 } ripemd128` (designers' page, "Patents, Object Identifiers").
impl AlgorithmOID for RIPEMD128 {
    const OID: &'static [u32] = &[1, 3, 36, 3, 2, 2];
    const OID_DER: &'static [u8] = &[0x06, 0x05, 0x2b, 0x24, 0x03, 0x02, 0x02];
}

/*** RIPEMD-160 ***/
/// The parameters for RIPEMD-160.
#[derive(Clone)]
pub struct RIPEMD160Params;
impl Algorithm for RIPEMD160Params {
    const ALG_NAME: &'static str = RIPEMD160_NAME;
    /// 80-bit collision resistance: below the library's smallest modelled strength.
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::None;
}
impl HashAlgParams for RIPEMD160Params {
    const OUTPUT_LEN: usize = 20;
    const BLOCK_LEN: usize = 64;
}
impl sealed::RIPEMDFamily for RIPEMD160Params {
    type State = [u32; 5];
    /// `rmd160.txt`: `h0 = 0x67452301; h1 = 0xEFCDAB89; h2 = 0x98BADCFE; h3 = 0x10325476;
    /// h4 = 0xC3D2E1F0;`
    const H0: [u32; 5] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];
    #[inline(always)]
    fn compress(h: &mut [u32], block: &[u8; BLOCK_LEN]) {
        ripemd160::compress(h, block, false);
    }
}
/// TeleTrusT: `{ 1.3.36.3.2.1 } ripemd160` (designers' page, "Patents, Object Identifiers").
impl AlgorithmOID for RIPEMD160 {
    const OID: &'static [u32] = &[1, 3, 36, 3, 2, 1];
    const OID_DER: &'static [u8] = &[0x06, 0x05, 0x2b, 0x24, 0x03, 0x02, 0x01];
}

/*** RIPEMD-256 ***/
/// The parameters for RIPEMD-256.
#[derive(Clone)]
pub struct RIPEMD256Params;
impl Algorithm for RIPEMD256Params {
    const ALG_NAME: &'static str = RIPEMD256_NAME;
    /// No more than RIPEMD-128's, which it extends (designers' page).
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::None;
}
impl HashAlgParams for RIPEMD256Params {
    const OUTPUT_LEN: usize = 32;
    const BLOCK_LEN: usize = 64;
}
impl sealed::RIPEMDFamily for RIPEMD256Params {
    type State = [u32; 8];
    /// `rmd256.txt`: `h0 = 0x67452301; h1 = 0xEFCDAB89; h2 = 0x98BADCFE; h3 = 0x10325476;
    /// h4 = 0x76543210; h5 = 0xFEDCBA98; h6 = 0x89ABCDEF; h7 = 0x01234567;`
    const H0: [u32; 8] = [
        0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0x7654_3210, 0xFEDC_BA98, 0x89AB_CDEF,
        0x0123_4567,
    ];
    #[inline(always)]
    fn compress(h: &mut [u32], block: &[u8; BLOCK_LEN]) {
        ripemd128::compress(h, block, true);
    }
}
/// TeleTrusT: `{ 1.3.36.3.2.3 } ripemd256` (designers' page, "Patents, Object Identifiers").
/// RIPEMD-320 has no assigned identifier.
impl AlgorithmOID for RIPEMD256 {
    const OID: &'static [u32] = &[1, 3, 36, 3, 2, 3];
    const OID_DER: &'static [u8] = &[0x06, 0x05, 0x2b, 0x24, 0x03, 0x02, 0x03];
}

/*** RIPEMD-320 ***/
/// The parameters for RIPEMD-320.
#[derive(Clone)]
pub struct RIPEMD320Params;
impl Algorithm for RIPEMD320Params {
    const ALG_NAME: &'static str = RIPEMD320_NAME;
    /// "Remark that the security level of the 320-bit extension of RIPEMD-160 is only guaranteed
    /// to be the same as that of RIPEMD-160 itself" (designers' page).
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::None;
}
impl HashAlgParams for RIPEMD320Params {
    const OUTPUT_LEN: usize = 40;
    const BLOCK_LEN: usize = 64;
}
impl sealed::RIPEMDFamily for RIPEMD320Params {
    type State = [u32; 10];
    /// `rmd320.txt`: `h0 = 0x67452301; h1 = 0xEFCDAB89; h2 = 0x98BADCFE; h3 = 0x10325476;
    /// h4 = 0xC3D2E1F0; h5 = 0x76543210; h6 = 0xFEDCBA98; h7 = 0x89ABCDEF; h8 = 0x01234567;
    /// h9 = 0x3C2D1E0F;`
    const H0: [u32; 10] = [
        0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0, 0x7654_3210, 0xFEDC_BA98,
        0x89AB_CDEF, 0x0123_4567, 0x3C2D_1E0F,
    ];
    #[inline(always)]
    fn compress(h: &mut [u32], block: &[u8; BLOCK_LEN]) {
        ripemd160::compress(h, block, true);
    }
}

/*** Suspendable ***/
// The serialized length differs between the two members of each family, so the impls are per
// concrete type, over shared helpers.

impl Suspendable<SUSPENDED_RIPEMD128_STATE_LEN> for RIPEMD128 {
    fn suspend(self) -> [u8; SUSPENDED_RIPEMD128_STATE_LEN] {
        self.suspend_state()
    }
    fn from_suspended(
        serialized_state: [u8; SUSPENDED_RIPEMD128_STATE_LEN],
    ) -> Result<Self, SuspendableError> {
        Self::resume_state(&serialized_state)
    }
}

impl Suspendable<SUSPENDED_RIPEMD256_STATE_LEN> for RIPEMD256 {
    fn suspend(self) -> [u8; SUSPENDED_RIPEMD256_STATE_LEN] {
        self.suspend_state()
    }
    fn from_suspended(
        serialized_state: [u8; SUSPENDED_RIPEMD256_STATE_LEN],
    ) -> Result<Self, SuspendableError> {
        Self::resume_state(&serialized_state)
    }
}

impl Suspendable<SUSPENDED_RIPEMD160_STATE_LEN> for RIPEMD160 {
    fn suspend(self) -> [u8; SUSPENDED_RIPEMD160_STATE_LEN] {
        self.suspend_state()
    }
    fn from_suspended(
        serialized_state: [u8; SUSPENDED_RIPEMD160_STATE_LEN],
    ) -> Result<Self, SuspendableError> {
        Self::resume_state(&serialized_state)
    }
}

impl Suspendable<SUSPENDED_RIPEMD320_STATE_LEN> for RIPEMD320 {
    fn suspend(self) -> [u8; SUSPENDED_RIPEMD320_STATE_LEN] {
        self.suspend_state()
    }
    fn from_suspended(
        serialized_state: [u8; SUSPENDED_RIPEMD320_STATE_LEN],
    ) -> Result<Self, SuspendableError> {
        Self::resume_state(&serialized_state)
    }
}
