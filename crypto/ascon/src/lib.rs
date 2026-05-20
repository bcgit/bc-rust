//! Implementations of the Ascon family of lightweight cryptographic
//! algorithms from NIST SP 800-232.
//!
//! All four constructions share the same 320-bit Ascon permutation, which
//! is factored into the internal [`state`] module:
//!
//! * [`ascon_hash256::AsconHash256`] — 256-bit cryptographic hash
//!   (sponge with rate 8 / capacity 32 bytes).
//! * [`ascon_xof128::AsconXof128`] — extendable-output function (XOF) at
//!   128-bit security.
//! * [`ascon_cxof128::AsconCXof128`] — customized XOF (CXOF). Identical to
//!   `AsconXof128` but parametrised by an optional 256-byte customization
//!   string `Z` that domain-separates the output.
//! * [`ascon_aead128::AsconAead128`] — authenticated encryption with
//!   associated data (AEAD) at 128-bit security.
//!
//! # no_std
//! This crate is `#![no_std]`. The Vec-returning methods of the
//! [`bouncycastle_core_interface::traits::Hash`],
//! [`bouncycastle_core_interface::traits::XOF`], and
//! [`bouncycastle_core_interface::traits::AeadCipher`] trait impls pull in
//! the `alloc` crate. Callers in a `no_alloc` setting can use the `_out`
//! twins everywhere — every Vec-returning trait method has a
//! slice-writing twin, including
//! [`bouncycastle_core_interface::traits::AeadCipher::get_mac_out`], and
//! this crate holds no heap allocations in its own state.
//!
//! # Quick examples (no_std-friendly paths)
//!
//! Hash, writing into a caller-provided buffer:
//! ```
//! use bouncycastle_core_interface::traits::Hash;
//! use bouncycastle_ascon::AsconHash256;
//! let mut digest = [0u8; 32];
//! let n = AsconHash256::new().hash_out(b"hello", &mut digest);
//! assert_eq!(n, 32);
//! ```
//!
//! XOF squeezing into a caller-provided buffer:
//! ```
//! use bouncycastle_core_interface::traits::XOF;
//! use bouncycastle_ascon::AsconXof128;
//! let mut out = [0u8; 64];
//! let n = AsconXof128::new().hash_xof_out(b"hello", &mut out);
//! assert_eq!(n, 64);
//! ```
//!
//! AEAD encrypt with stack-allocated buffers:
//! ```
//! use bouncycastle_ascon::AsconAead128;
//! let key   = [0u8; 16];
//! let nonce = [1u8; 16];
//! let pt    = b"plaintext";
//! let mut ct = [0u8; 9 + 16]; // plaintext.len() + tag_len
//! let mut enc = AsconAead128::new(&key, &nonce, None, true);
//! let n = enc.encrypt_update(pt, &mut ct);
//! let m = enc.encrypt_finalize(&mut ct[n..]).unwrap();
//! assert_eq!(n + m, ct.len());
//! ```

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod ascon_aead128;
pub mod ascon_cxof128;
pub mod ascon_hash256;
pub mod ascon_xof128;

mod state;

pub use ascon_aead128::{AsconAead128, AsconAeadError};
pub use ascon_cxof128::AsconCXof128;
pub use ascon_hash256::AsconHash256;
pub use ascon_xof128::AsconXof128;
