//! The GMAC known-answer suites' second route: each case through `AES*Key<GMAC<T>>`, beside the
//! `Gcm` route `acvp_gcm_helpers.rs` runs. A valid case is generated under the vector's nonce, by
//! the pinned-RNG and the supplied-nonce constructors alike, and verified; an invalid one must
//! fail verification.

#![allow(dead_code)]

#[path = "cmac_helpers.rs"]
mod cmac_helpers;

use bouncycastle_aes::{AES128Key, AES192Key, AES256Key};
use bouncycastle_cipher::modes::{GCM_NONCE_LEN, GMAC};
use bouncycastle_core::symmetric_key::FromKeyMaterial;
use bouncycastle_core_test_framework::FixedSeedRNG;
use cmac_helpers::mac_key;

pub fn run_key_object_case(
    key_bytes: &[u8],
    nonce: [u8; GCM_NONCE_LEN],
    msg: &[u8],
    tag: &[u8],
    valid: bool,
) {
    // One body per (key length, tag length): the key type and the tag array are both in the type.
    macro_rules! run {
        ($key:ty, $klen:literal, $tlen:literal) => {{
            let key = <$key>::from_key_material(&mac_key::<$klen>(key_bytes)).expect("a MAC key");
            let tag: [u8; $tlen] = tag.try_into().expect("tag length matches TAG_LEN");
            assert_eq!(key.create_verifier(&nonce).verify(msg, &tag), valid, "key object verify");
            if valid {
                let (gen_, got) =
                    key.create_generator(&mut FixedSeedRNG::<GCM_NONCE_LEN>::new(nonce)).unwrap();
                assert_eq!(got, nonce, "the pinned RNG should give the vector's IV");
                assert_eq!(gen_.mac(msg), tag, "key object generate");
                assert_eq!(key.create_generator_nonce(&nonce).mac(msg), tag, "supplied nonce");
            }
        }};
    }
    macro_rules! by_tag {
        ($key:ident, $klen:literal) => {
            match tag.len() {
                12 => run!($key<GMAC<12>>, $klen, 12),
                13 => run!($key<GMAC<13>>, $klen, 13),
                14 => run!($key<GMAC<14>>, $klen, 14),
                15 => run!($key<GMAC<15>>, $klen, 15),
                16 => run!($key<GMAC<16>>, $klen, 16),
                other => panic!("unsupported tag length {other} bytes"),
            }
        };
    }
    match key_bytes.len() {
        16 => by_tag!(AES128Key, 16),
        24 => by_tag!(AES192Key, 24),
        32 => by_tag!(AES256Key, 32),
        other => panic!("unexpected AES key length {other}"),
    }
}
