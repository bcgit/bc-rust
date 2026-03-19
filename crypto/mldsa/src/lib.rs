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

/* todo -- note from an implementor that I should digest and see what I can apply
<quote>
First I stop generating both keys. At keygen I only derive what is needed for the public key and its
hash, and I do that row by row instead of expanding the full secret and public vector state up front.
I also avoid keeping large vectors in memory by working row by row to keep peak usage down.
I stop storing fully expanded secret polynomials like s1, s2, and t0, and instead reconstruct the
needed rows or polynomials on demand from seed.

For signing i stop it from building full y, w, z, and h vectors in memory, and instead recompute
w, z, w0-cs2, and ct0 row by row or component by component to keep peak usage down.
I also hash w1 incrementally and write packed z and hint bytes straight into the output buffer
instead of staging large temporary vectors first.For signature verification I do a similar change.
I fix use_hint() for both gamma2 families, and I avoid building a full temporary w1 vector in memory
by reconstructing and hashing it incrementally instead.
</quote>
 */

mod mldsa;
mod hash_mldsa;
mod mldsa_keys;
mod polynomial;
mod aux_functions;
mod matrix;


/*** Exported types ***/
pub use mldsa::{MLDSA, MLDSA44, MLDSA65, MLDSA87};
pub use hash_mldsa::{HashMLDSA44_with_SHA256, HashMLDSA65_with_SHA256, HashMLDSA87_with_SHA256};
pub use hash_mldsa::{HashMLDSA44_with_SHA512, HashMLDSA65_with_SHA512, HashMLDSA87_with_SHA512};
pub use mldsa_keys::{MLDSAPrivateKeyTrait, MLDSAPublicKeyTrait};
pub use mldsa_keys::{MLDSAPublicKey, MLDSA44PublicKey, MLDSA65PublicKey, MLDSA87PublicKey};
pub use mldsa_keys::{MLDSAPrivateKey, MLDSA44PrivateKey, MLDSA65PrivateKey, MLDSA87PrivateKey};
pub use mldsa::{MuBuilder};

/*** Exported constants ***/
pub use mldsa::ML_DSA_44_NAME;
pub use mldsa::ML_DSA_65_NAME;
pub use mldsa::ML_DSA_87_NAME;

pub use hash_mldsa::Hash_ML_DSA_44_with_SHA256_NAME;
pub use hash_mldsa::Hash_ML_DSA_65_with_SHA256_NAME;
pub use hash_mldsa::Hash_ML_DSA_87_with_SHA256_NAME;

pub use hash_mldsa::Hash_ML_DSA_44_with_SHA512_NAME;
pub use hash_mldsa::Hash_ML_DSA_65_with_SHA512_NAME;
pub use hash_mldsa::Hash_ML_DSA_87_with_SHA512_NAME;

pub use mldsa::{MLDSA44_PK_LEN, MLDSA44_SK_LEN, MLDSA44_SIG_LEN};
pub use mldsa::{MLDSA65_PK_LEN, MLDSA65_SK_LEN, MLDSA65_SIG_LEN};
pub use mldsa::{MLDSA87_PK_LEN, MLDSA87_SK_LEN, MLDSA87_SIG_LEN};

/*** pub types ***/


// TODO: I'm gonna need to duplicate all these types for HashML-DSA.
// TODO: probably with an extra param <HASH: Hash> to the HashML_DSA struct definition.
// TODO: Need to decide whether to also add this to public and private keys for no other reason than to
// TODO:   make it hard to cross-use keys between ML-DSA and HashML-DSA.



// todo -- impl bouncycastle_core_interface::traits::Algorithm with the security strengths from Table 1
