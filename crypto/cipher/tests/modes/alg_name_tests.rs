//! Each mode reports the [`ModeNames`] constant for *its* mode, and the wrappers forward it.
//!
//! The toy gives every mode a different name, so a mode that read another mode's constant -- CFB's
//! for CFB8, say -- or fell back to the permutation's own `ALG_NAME` fails here, independently of
//! any real cipher. Strength is not a mode's to change; it stays the permutation's.

mod common;

use bouncycastle_cipher::modes::hazmat::{CtrKeyStream, Ecb};
use bouncycastle_cipher::modes::{
    Cbc, Ccm, CcmDecryptor, CcmEncryptor, Cfb, Cfb8, Ctr, Gcm, ModeNames,
};
use bouncycastle_cipher::padding::{
    NoPadding, PKCS7, PaddedBlockCipherDecryptor, PaddedBlockCipherEncryptor,
};
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::traits::Algorithm;
use common::Toy;

fn check<A: Algorithm>(name: &str) {
    assert_eq!(A::ALG_NAME, name);
    assert_eq!(A::MAX_SECURITY_STRENGTH, Toy::MAX_SECURITY_STRENGTH, "{name}");
}

#[test]
fn the_toy_names_every_mode_differently() {
    let names = [
        Toy::ALG_NAME,
        Toy::CBC_ALG_NAME,
        Toy::CCM_ALG_NAME,
        Toy::CFB_ALG_NAME,
        Toy::CFB8_ALG_NAME,
        Toy::CTR_ALG_NAME,
        Toy::ECB_ALG_NAME,
        Toy::GCM_ALG_NAME,
    ];
    for (i, a) in names.iter().enumerate() {
        for b in &names[i + 1..] {
            assert_ne!(a, b, "the checks below could not tell these two apart");
        }
    }
}

#[test]
fn each_mode_reports_its_own_name() {
    check::<Cbc<Toy, Encrypting, 16, 16>>(Toy::CBC_ALG_NAME);
    check::<Cbc<Toy, Decrypting, 16, 16>>(Toy::CBC_ALG_NAME);
    check::<Ecb<Toy, Encrypting, 16, 16>>(Toy::ECB_ALG_NAME);
    check::<Ecb<Toy, Decrypting, 16, 16>>(Toy::ECB_ALG_NAME);
    check::<Cfb<Toy, Encrypting, 16, 16>>(Toy::CFB_ALG_NAME);
    check::<Cfb<Toy, Decrypting, 16, 16>>(Toy::CFB_ALG_NAME);
    check::<Cfb8<Toy, Encrypting, 16, 16>>(Toy::CFB8_ALG_NAME);
    check::<Cfb8<Toy, Decrypting, 16, 16>>(Toy::CFB8_ALG_NAME);
    check::<CtrKeyStream<Toy, 16, 16, 12>>(Toy::CTR_ALG_NAME);
    check::<Gcm<Toy, Encrypting, 16, 16>>(Toy::GCM_ALG_NAME);
    check::<Gcm<Toy, Decrypting, 16, 16>>(Toy::GCM_ALG_NAME);
    check::<Ccm<Toy, Encrypting, 16, 16, 12, 16>>(Toy::CCM_ALG_NAME);
    check::<Ccm<Toy, Decrypting, 16, 16, 12, 16>>(Toy::CCM_ALG_NAME);
    check::<CcmEncryptor<Toy, 16, 16, 12, 16, 16, 32>>(Toy::CCM_ALG_NAME);
    check::<CcmDecryptor<Toy, 16, 16, 12, 16, 16, 32>>(Toy::CCM_ALG_NAME);
}

/// The padding layer and the stream-cipher wrapper add no name of their own.
#[test]
fn the_wrappers_forward_the_inner_name() {
    check::<Ctr<Toy, Encrypting, 16, 16, 12>>(Toy::CTR_ALG_NAME);
    check::<Ctr<Toy, Decrypting, 16, 16, 12>>(Toy::CTR_ALG_NAME);
    check::<PaddedBlockCipherEncryptor<Cbc<Toy, Encrypting, 16, 16>, PKCS7, 16, 16, 16>>(
        Toy::CBC_ALG_NAME,
    );
    check::<PaddedBlockCipherDecryptor<Cbc<Toy, Decrypting, 16, 16>, PKCS7, 16, 16, 16>>(
        Toy::CBC_ALG_NAME,
    );
    check::<PaddedBlockCipherEncryptor<Ecb<Toy, Encrypting, 16, 16>, NoPadding, 16, 0, 16>>(
        Toy::ECB_ALG_NAME,
    );
    check::<PaddedBlockCipherDecryptor<Ecb<Toy, Decrypting, 16, 16>, NoPadding, 16, 0, 16>>(
        Toy::ECB_ALG_NAME,
    );
}
