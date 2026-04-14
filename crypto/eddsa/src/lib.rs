//! todo -- docs

// #![no_std] // todo

#![allow(dead_code)] // todo remove

#![forbid(unsafe_code)]
// #![forbid(missing_docs)] // todo


/*** Public exports ***/

pub use eddsa_keys::{Ed25519PrivateKey, Ed25519PublicKey};



mod ed25519;
mod eddsa_keys;
mod curve25519;


/*** Exported types ***/
pub use ed25519::{Ed25519_PK_LEN, Ed25519_SK_LEN, Ed25519_SIG_LEN};
