//! The traits a caller needs in scope to call the library's methods, for a glob import:
//! `use bouncycastle_core::prelude::*;`.
//!
//! It holds the key role traits (a key's constructors, one-shots and `create_*` methods), the
//! worker traits those hand out, key encoding, key material, RNG and the algorithm metadata.
//! Each is imported as `_`, so its methods resolve without its name being taken; a bound that
//! names a trait imports it from its module. Types, errors, marker traits, parameter traits other
//! than the algorithm metadata, and everything under [`hazmat`](crate::hazmat) are left out. Each family crate's `prelude`
//! re-exports this one and adds that crate's own traits.

pub use crate::agreement_key::AgreementKey as _;
pub use crate::kdf_params::KdfDescription as _;
pub use crate::kem_key::{DecapsulatingKey as _, EncapsulatingKey as _};
pub use crate::key_material::KeyMaterialTrait as _;
pub use crate::key_transport_key::{
    KeyTransportDecryptingKey as _, KeyTransportEncryptingKey as _,
};
pub use crate::signature_key::{
    DeterministicOneShotSigningKey as _, DeterministicPreHashSigningKey as _,
    DeterministicSigningKey as _, OneShotSigningKey as _, OneShotVerifyingKey as _,
    PreHashSigningKey as _, PreHashVerifyingKey as _, SigningKey as _, VerifyingKey as _,
};
pub use crate::symmetric_key::{
    AeadDeclaredDecryptionKey as _, AeadDeclaredEncryptionKey as _, AeadDecryptionKey as _,
    AeadEncryptionKey as _, AeadInPlaceDecryptionKey as _, AeadInPlaceEncryptionKey as _,
    BlockDecryptionKey as _, BlockEncryptionKey as _, FromAnyKeyMaterial as _,
    FromKeyMaterial as _, KeyUnwrappingKey as _, KeyWrappingKey as _, MacGenerationKey as _,
    MacVerificationKey as _, NonceMacGenerationKey as _, NonceMacVerificationKey as _,
    SymmetricDecryptionKey as _, SymmetricEncryptionKey as _,
};
pub use crate::traits::{
    AEADCipherDecryptor as _, AEADCipherEncryptor as _, Algorithm as _, AlgorithmInfo as _,
    AlgorithmOID as _, BlockCipherDecryptor as _, BlockCipherEncryptor as _, Hash as _,
    HashAlgParams as _, HashOneShot as _, KDF as _, KEMDecapsulator as _, KEMEncapsulator as _,
    KeyAgreement as _, KeyPairGenerator as _, KeyUnwrapper as _, KeyWrapper as _,
    MACGenerator as _, MACVerifier as _, PrivateKey as _, PublicKey as _, RNG as _, RNGExt as _,
    SeekableStreamCipher as _, SignatureSigner as _, SignatureVerifier as _,
    StreamCipherDecryptor as _, StreamCipherEncryptor as _, Suspendable as _,
    SymmetricCipherDecryptor as _, SymmetricCipherEncryptor as _, XOF as _, XOFSqueezer as _,
};
