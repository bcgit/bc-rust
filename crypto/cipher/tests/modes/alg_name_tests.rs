//! Each mode reports the [`ModeNames`] constant for *its* mode, and the wrappers forward it.
//!
//! The toy gives every mode a different name, so a mode that read another mode's constant -- CFB's
//! for CFB8, say -- or fell back to the permutation's own `ALG_NAME` fails here, independently of
//! any real cipher. Strength is not a mode's to change; it stays the permutation's.

mod common;

use bouncycastle_cipher::modes::hazmat::{CtrKeyStream, ECB, Ecb};
use bouncycastle_cipher::modes::{
    Blocks, CBC, CCM, CCM_Packet, CFB, CFB8, CTR, Cbc, CcmPacketDecryptor, CcmPacketEncryptor, Cfb,
    Cfb8, Cmac, Ctr, Gcm, Gmac, ModeNames,
};
use bouncycastle_cipher::padding::{
    NoPadding, PKCS7, PaddedBlockCipherDecryptor, PaddedBlockCipherEncryptor,
};
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::hazmat::Mode;
use bouncycastle_core::key_material::KeyType;
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
        Toy::CMAC_ALG_NAME,
        Toy::CTR_ALG_NAME,
        Toy::ECB_ALG_NAME,
        Toy::GCM_ALG_NAME,
        Toy::GMAC_ALG_NAME,
    ];
    for (i, a) in names.iter().enumerate() {
        for b in &names[i + 1..] {
            assert_ne!(a, b, "the checks below could not tell these two apart");
        }
    }
}

#[test]
fn each_mode_reports_its_own_name() {
    check::<Cbc<'_, Toy, Encrypting, 16, 16>>(Toy::CBC_ALG_NAME);
    check::<Cbc<'_, Toy, Decrypting, 16, 16>>(Toy::CBC_ALG_NAME);
    check::<Ecb<'_, Toy, Encrypting, 16, 16>>(Toy::ECB_ALG_NAME);
    check::<Ecb<'_, Toy, Decrypting, 16, 16>>(Toy::ECB_ALG_NAME);
    check::<Cfb<'_, Toy, Encrypting, 16, 16>>(Toy::CFB_ALG_NAME);
    check::<Cfb<'_, Toy, Decrypting, 16, 16>>(Toy::CFB_ALG_NAME);
    check::<Cfb8<'_, Toy, Encrypting, 16, 16>>(Toy::CFB8_ALG_NAME);
    check::<Cfb8<'_, Toy, Decrypting, 16, 16>>(Toy::CFB8_ALG_NAME);
    check::<CtrKeyStream<'_, Toy, 16, 16, 12>>(Toy::CTR_ALG_NAME);
    check::<Gcm<'_, Toy, Encrypting, 16, 16>>(Toy::GCM_ALG_NAME);
    check::<Gcm<'_, Toy, Decrypting, 16, 16>>(Toy::GCM_ALG_NAME);
    check::<CcmPacketEncryptor<'_, Toy, 16, 16, 12, 16, 16, 32>>(Toy::CCM_ALG_NAME);
    check::<CcmPacketDecryptor<'_, Toy, 16, 16, 12, 16, 16, 32>>(Toy::CCM_ALG_NAME);
    check::<Cmac<'_, Toy, 16, 16>>(Toy::CMAC_ALG_NAME);
    check::<Gmac<'_, Toy, Encrypting, 16, 16>>(Toy::GMAC_ALG_NAME);
    check::<Gmac<'_, Toy, Decrypting, 16, 16>>(Toy::GMAC_ALG_NAME);
}

/// The padding layer and the stream-cipher wrapper add no name of their own.
#[test]
fn the_wrappers_forward_the_inner_name() {
    check::<Ctr<'_, Toy, Encrypting, 16, 16, 12>>(Toy::CTR_ALG_NAME);
    check::<Ctr<'_, Toy, Decrypting, 16, 16, 12>>(Toy::CTR_ALG_NAME);
    check::<PaddedBlockCipherEncryptor<Cbc<'_, Toy, Encrypting, 16, 16>, PKCS7, 16, 16, 16>>(
        Toy::CBC_ALG_NAME,
    );
    check::<PaddedBlockCipherDecryptor<Cbc<'_, Toy, Decrypting, 16, 16>, PKCS7, 16, 16, 16>>(
        Toy::CBC_ALG_NAME,
    );
    check::<PaddedBlockCipherEncryptor<Ecb<'_, Toy, Encrypting, 16, 16>, NoPadding, 16, 0, 16>>(
        Toy::ECB_ALG_NAME,
    );
    check::<PaddedBlockCipherDecryptor<Ecb<'_, Toy, Decrypting, 16, 16>, NoPadding, 16, 0, 16>>(
        Toy::ECB_ALG_NAME,
    );
}

/// A mode type's key reports the mode's name and asks for a cipher key, whatever the padding or
/// frame parameters.
#[test]
fn each_mode_type_reports_its_mode_name() {
    fn check<M: Mode<Toy>>(name: &str) {
        assert_eq!(M::ALG_NAME, name);
        assert_eq!(M::KEY_TYPE, KeyType::SymmetricCipherKey, "{name}");
    }
    check::<CBC<Blocks>>(Toy::CBC_ALG_NAME);
    check::<CBC<PKCS7>>(Toy::CBC_ALG_NAME);
    check::<CBC<NoPadding>>(Toy::CBC_ALG_NAME);
    check::<ECB<Blocks>>(Toy::ECB_ALG_NAME);
    check::<ECB<PKCS7>>(Toy::ECB_ALG_NAME);
    check::<CFB>(Toy::CFB_ALG_NAME);
    check::<CFB8>(Toy::CFB8_ALG_NAME);
    check::<CTR>(Toy::CTR_ALG_NAME);
    check::<CTR<15>>(Toy::CTR_ALG_NAME);
    check::<CCM<12, 16>>(Toy::CCM_ALG_NAME);
    check::<CCM_Packet<12, 16, 16, 32>>(Toy::CCM_ALG_NAME);
}
