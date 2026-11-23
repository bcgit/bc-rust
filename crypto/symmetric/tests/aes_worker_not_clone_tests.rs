//! No worker of `bouncycastle_symmetric::modes` is `Clone` (issue #173): two copies of an encryptor would go on
//! from one nonce, counter or keystream position and encrypt two messages under the same
//! keystream. A second worker is made from the key instead. Workers that live in their own modules
//! (Ascon, ChaCha20, Poly1305) are asserted there.
//!
//! The check is at compile time. `NotClone<A>` has one impl for every type and a second for
//! every `Clone` type, so `<T as NotClone<_>>` can be inferred only for a `T` that is not
//! `Clone`; for one that is, this file does not compile. The last test shows the same line
//! compiling for a key, which is `Clone`, once the impl is named.
//!
//! The padded workers and `StreamCipher` wrap another worker, so a derived `Clone` on them would
//! be conditional on it. They are therefore also named over `CloneInner`, an inner worker that is
//! `Clone`: over a real one, which is not, the line would pass whatever the wrapper derived.

use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::hazmat::KeyStream;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{AlgorithmInfo, BlockCipherDecryptor, BlockCipherEncryptor};
use bouncycastle_symmetric::aes::AES128Key;
use bouncycastle_symmetric::aes::hazmat::AES128Internal;
use bouncycastle_symmetric::modes::hazmat::ecb::Ecb;
use bouncycastle_symmetric::modes::{
    CBC, Cbc, CcmDecryptor, CcmEncryptor, CcmPacketDecryptor, CcmPacketEncryptor, Cfb, Cfb8, Cmac,
    Ctr, Gcm, Gmac, Kw, Kwp, Ofb,
};
use bouncycastle_symmetric::padding::{
    PKCS7, PaddedBlockCipherDecryptor, PaddedBlockCipherEncryptor,
};
use bouncycastle_symmetric::stream::StreamCipher;
use bouncycastle_symmetric::{Decrypting, Encrypting};

trait NotClone<A> {
    fn witness() {}
}
impl<T: ?Sized> NotClone<()> for T {}
impl<T: ?Sized + Clone> NotClone<u8> for T {}

type P = AES128Internal;

/// An inner worker that is `Clone`, for the wrappers. Never run.
#[derive(Clone)]
struct CloneInner;

impl AlgorithmInfo for CloneInner {
    fn alg_name(&self) -> &'static str {
        "CloneInner"
    }
    fn max_security_strength(&self) -> SecurityStrength {
        SecurityStrength::None
    }
}
impl BlockCipherEncryptor<16, 16> for CloneInner {
    fn do_encrypt_blocks_inplace(
        &mut self,
        blocks: &mut [[u8; 16]],
    ) -> Result<usize, SymmetricCipherError> {
        Ok(blocks.len() * 16)
    }
}
impl BlockCipherDecryptor<16, 16> for CloneInner {
    fn do_decrypt_blocks_inplace(
        &mut self,
        blocks: &mut [[u8; 16]],
    ) -> Result<usize, SymmetricCipherError> {
        Ok(blocks.len() * 16)
    }
}
impl KeyStream<12, 16> for CloneInner {
    fn remaining_blocks(&self) -> u64 {
        0
    }
    fn apply_blocks(&mut self, _blocks: &mut [[u8; 16]]) {}
}

macro_rules! not_clone {
    ($($t:ty),+ $(,)?) => {
        $( <$t as NotClone<_>>::witness(); )+
    };
}

#[test]
fn cipher_workers_are_not_clone() {
    not_clone!(
        Cbc<'static, P, Encrypting, 16>,
        Cbc<'static, P, Decrypting, 16>,
        PaddedBlockCipherEncryptor<Cbc<'static, P, Encrypting, 16>, PKCS7, 16, 16>,
        PaddedBlockCipherDecryptor<Cbc<'static, P, Decrypting, 16>, PKCS7, 16, 16>,
        Cfb<'static, P, Encrypting, 16>,
        Cfb<'static, P, Decrypting, 16>,
        Cfb8<'static, P, Encrypting, 16>,
        Cfb8<'static, P, Decrypting, 16>,
        Ctr<'static, P, Encrypting, 16, 12>,
        Ctr<'static, P, Decrypting, 16, 12>,
        Ofb<'static, P, Encrypting, 16>,
        Ofb<'static, P, Decrypting, 16>,
        Ecb<'static, P, Encrypting, 16>,
        Ecb<'static, P, Decrypting, 16>,
        Gcm<'static, P, Encrypting, 16>,
        Gcm<'static, P, Decrypting, 16>,
        CcmEncryptor<'static, P, 12, 16>,
        CcmDecryptor<'static, P, 12, 16>,
        CcmPacketEncryptor<'static, P, 16, 12, 16, 64, 1024>,
        CcmPacketDecryptor<'static, P, 16, 12, 16, 64, 1024>,
    );
}

#[test]
fn wrappers_are_not_clone_over_a_clone_inner_worker() {
    not_clone!(
        PaddedBlockCipherEncryptor<CloneInner, PKCS7, 16, 16>,
        PaddedBlockCipherDecryptor<CloneInner, PKCS7, 16, 16>,
        StreamCipher<CloneInner, Encrypting, 12, 16>,
        StreamCipher<CloneInner, Decrypting, 12, 16>,
    );
}

#[test]
fn mac_and_key_wrap_workers_are_not_clone() {
    not_clone!(
        Cmac<'static, P, Encrypting, 16>,
        Cmac<'static, P, Decrypting, 16>,
        Gmac<'static, P, Encrypting, 16>,
        Gmac<'static, P, Decrypting, 16>,
        Kw<'static, P, Encrypting>,
        Kw<'static, P, Decrypting>,
        Kwp<'static, P, Encrypting>,
        Kwp<'static, P, Decrypting>,
    );
}

/// The control: a key is `Clone`, so both impls apply to it and the impl has to be named.
#[test]
fn a_key_is_clone() {
    <AES128Key<CBC<PKCS7>> as NotClone<u8>>::witness();
    <AES128Key<CBC<PKCS7>> as NotClone<()>>::witness();
}
