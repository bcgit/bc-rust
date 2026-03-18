//! todo -- docs -- turn this back on:
// #![forbid(missing_docs)]

#![allow(unused_variables)] // todo - remove
#![allow(dead_code)] // todo - remove

#![forbid(unsafe_code)]
#![allow(incomplete_features)] // needed because currently generic_const_exprs is experimental
#![feature(generic_const_exprs)]
#![feature(int_roundings)]
#![feature(inherent_associated_types)]
#![feature(adt_const_params)]
// These are because I'm matching variable names exactly against FIPS 204, for example both 'K' and 'k',
// or 'A' and 'a' are used and have specific meanings.
// But need to tell the rust linter to not care.
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

// so I can use private traits to hide internal stuff that needs to be generic within the
// MLDSA implentation, but I don't want accessed from outside, such FIPS-internal functions.
#![allow(private_bounds)]

// Used in HashMLDSA
#![feature(unsized_const_params)]

mod mldsa;
mod hashmldsa;
mod mldsa_keys;
mod polynomial;
mod aux_functions;
mod matrix;


/*** Exported types ***/
pub use mldsa::{MLDSA, MLDSA44, MLDSA65, MLDSA87};
pub use mldsa_keys::{MLDSAPrivateKeyTrait, MLDSAPublicKeyTrait};
pub use mldsa_keys::{MLDSAPublicKey, MLDSA44PublicKey, MLDSA65PublicKey, MLDSA87PublicKey};
pub use mldsa_keys::{MLDSAPrivateKey, MLDSA44PrivateKey, MLDSA65PrivateKey, MLDSA87PrivateKey};
pub use mldsa::{MuBuilder};

// todo
// pub use hashmldsa::HashMLDSA;

/*** Exported constants ***/
pub const ML_DSA_44_NAME: &str = "ML-DSA-44";
pub const ML_DSA_65_NAME: &str = "ML-DSA-65";
pub const ML_DSA_87_NAME: &str = "ML-DSA-87";

pub use mldsa::{MLDSA44_PK_LEN, MLDSA44_SK_LEN, MLDSA44_SIG_LEN};
pub use mldsa::{MLDSA65_PK_LEN, MLDSA65_SK_LEN, MLDSA65_SIG_LEN};
pub use mldsa::{MLDSA87_PK_LEN, MLDSA87_SK_LEN, MLDSA87_SIG_LEN};

/*** pub types ***/


// TODO: I'm gonna need to duplicate all these types for HashML-DSA.
// TODO: probably with an extra param <HASH: Hash> to the HashML_DSA struct definition.
// TODO: Need to decide whether to also add this to public and private keys for no other reason than to
// TODO:   make it hard to cross-use keys between ML-DSA and HashML-DSA.



// todo -- impl bouncycastle_core_interface::traits::Algorithm with the security strengths from Table 1
