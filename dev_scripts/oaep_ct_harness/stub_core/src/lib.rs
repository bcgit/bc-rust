//! The two `bouncycastle_core::traits` names `crypto/rsa/src/eme_oaep.rs` imports, reduced to
//! what that file uses of them.
#![no_std]
#![forbid(unsafe_code)]

pub mod traits {
    pub trait HashAlgParams {
        const OUTPUT_LEN: usize;
    }
    pub trait HashOneShot: Default {
        fn hash_out(data: &[u8], out: &mut [u8]) -> usize;
    }
}
