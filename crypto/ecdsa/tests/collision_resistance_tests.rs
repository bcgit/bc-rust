//! ECDSA over a hash without `CollisionResistantHash` (RIPEMD-160): the public key verifies,
//! and the private key signs only when re-paired with `hazmat::WithoutCollisionResistance<H>`,
//! which is the same algorithm and gives the same bytes. That signing and key-pair generation
//! over the bare hash do not compile is checked by `compile_fail` doctests on `ECDSA`,
//! `keys::keygen` and `SignatureKeyPair`.

use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::hazmat::WithoutCollisionResistance;
use bouncycastle_core::hex::decode as hex_decode;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::signature_key::{
    DeterministicOneShotSigningKey, DeterministicSigningKey, OneShotSigningKey,
    OneShotVerifyingKey, SigningKey, VerifyingKey,
};
use bouncycastle_core::traits::{
    Algorithm, AlgorithmInfo, PrivateKey, PublicKey, SignatureSigner, SignatureVerifier,
};
use bouncycastle_digest::ripemd::RIPEMD160;
use bouncycastle_digest::sha2::SHA256;
use bouncycastle_ec::P256;
use bouncycastle_ecdsa::ecdsa::ECDSA;
use bouncycastle_ecdsa::keys::{ECDSAPrivateKey, ECDSAPublicKey, keygen};
use bouncycastle_ecdsa::keys_common::{DerivePublicKey, SignatureKeyPair};
use bouncycastle_rng::DefaultRNG;

type Unsafe<H> = WithoutCollisionResistance<H>;

const MSG: &[u8] = b"The quick brown fox jumped over the lazy dog";

// A P-256 key pair and an ECDSA signature of MSG over RIPEMD-160, made with OpenSSL 3.0.13:
//   openssl ecparam -name prime256v1 -genkey -noout -out k.pem
//   openssl dgst -ripemd160 -sign k.pem -out sig.der msg
// `r` and `s` are the two INTEGERs of sig.der.
const D: &str = "a9512b3347abcb5c6a496ada2f906413c810536b80fb387da5c60a86fe7be51e";
const Q: &str = "04bf6a00499687dadfa0e88b81f682891ff97860d8744b936c7f48bd14c512cc80\
                 b31bd8a0c9d5aa7d5fe7d253028cfba3a5aa6f283309f800c5f2078dad165106";
const OPENSSL_R: &str = "177365CBADFA0C9F34DC87F7F525D8ACD381985957AB884EEACB038369E1BBFD";
const OPENSSL_S: &str = "7AF7EA1A7FE8E62E524F34D9708D99CEABDB44BDD7EA1FA4EED38706E3AE614F";

// The RFC 6979 signature of MSG under D over RIPEMD-160. RFC 6979 has no RIPEMD-160 vectors:
// this value was reproduced by an independent model of RFC 6979 Section 3.2 (Python, `hmac` and
// `hashlib` with textbook affine arithmetic), and `openssl dgst -ripemd160 -verify` accepts it.
const DETERMINISTIC_SIG: &str = "68e45c64025892e1e36325377b71d91816dc3c6b5628d3507d3f50f5dfee3a18\
                                 be94cad93d57af89ffd08cd5041749c246643bb368919ddf1c0d7d5e1ef1fd7a";

fn openssl_sig() -> Vec<u8> {
    [hex_decode(OPENSSL_R).unwrap(), hex_decode(OPENSSL_S).unwrap()].concat()
}

fn public_key() -> ECDSAPublicKey<P256, RIPEMD160> {
    ECDSAPublicKey::from_bytes(&hex_decode(Q).unwrap()).unwrap()
}

/// Decoding a private key asks nothing of the hash; only signing does.
fn private_key() -> ECDSAPrivateKey<P256, RIPEMD160> {
    ECDSAPrivateKey::from_bytes(&hex_decode(D).unwrap()).unwrap()
}

#[test]
fn verification_over_ripemd160_needs_no_wrapper() {
    let pk = public_key();
    let sig = openssl_sig();
    pk.verify(MSG, None, &sig).unwrap();

    let mut verifier = pk.create_verifier(None).unwrap();
    assert_eq!(verifier.alg_name(), "ECDSA-P256-RIPEMD160");
    assert_eq!(verifier.max_security_strength(), SecurityStrength::None);
    verifier.do_update(&MSG[..7]);
    verifier.do_update(&MSG[7..]);
    verifier.do_verify_final(&sig).unwrap();

    // it is a verification, and one over RIPEMD-160
    assert_eq!(
        pk.verify(b"another message", None, &sig),
        Err(SignatureError::SignatureVerificationFailed)
    );
    assert_eq!(
        pk.with_hash::<SHA256>().verify(MSG, None, &sig),
        Err(SignatureError::SignatureVerificationFailed)
    );

    // the wrapper is the same algorithm on the verifying side too
    pk.with_hash::<Unsafe<RIPEMD160>>().verify(MSG, None, &sig).unwrap();
}

#[test]
fn a_key_over_ripemd160_does_everything_but_sign() {
    let sk = private_key();
    assert_eq!(sk.encode()[..], hex_decode(D).unwrap()[..]);
    let pk: ECDSAPublicKey<P256, RIPEMD160> = sk.derive_pk();
    assert_eq!(pk, public_key());
    assert_eq!(sk.clone(), sk);
    assert_eq!(ECDSA::<P256, RIPEMD160>::ALG_NAME, "ECDSA-P256-RIPEMD160");
    assert_eq!(ECDSA::<P256, RIPEMD160>::MAX_SECURITY_STRENGTH, SecurityStrength::None);
}

#[test]
fn the_wrapper_signs_and_the_bare_hash_verifies() {
    let pk = public_key();
    let sk = private_key().with_hash::<Unsafe<RIPEMD160>>();

    // RFC 6979: the known answer, and the streaming signer agrees
    let det = sk.sign_deterministic(MSG, None).unwrap();
    assert_eq!(det[..], hex_decode(DETERMINISTIC_SIG).unwrap()[..]);
    pk.verify(MSG, None, &det).unwrap();
    let mut signer = sk.create_signer_deterministic(None).unwrap();
    assert_eq!(signer.alg_name(), "ECDetDSA-P256-RIPEMD160");
    assert_eq!(signer.max_security_strength(), SecurityStrength::None);
    signer.do_update(&MSG[..11]);
    signer.do_update(&MSG[11..]);
    assert_eq!(signer.do_final().unwrap(), det);

    // a random k
    let mut rng = DefaultRNG::default();
    let random = sk.sign(&mut rng, MSG, None).unwrap();
    assert_ne!(random, det);
    pk.verify(MSG, None, &random).unwrap();
    let mut signer = sk.create_signer(&mut rng, None).unwrap();
    assert_eq!(signer.alg_name(), "ECDSA-P256-RIPEMD160");
    signer.do_update(MSG);
    pk.verify(MSG, None, &signer.do_final().unwrap()).unwrap();

    // and the algorithm the wrapped key names is the bare one
    assert_eq!(ECDSA::<P256, Unsafe<RIPEMD160>>::ALG_NAME, ECDSA::<P256, RIPEMD160>::ALG_NAME);
    assert_eq!(
        ECDSA::<P256, Unsafe<RIPEMD160>>::DETERMINISTIC_ALG_NAME,
        ECDSA::<P256, RIPEMD160>::DETERMINISTIC_ALG_NAME
    );
}

/// With the wrapper named, a pair can be generated; its public half is re-paired with the bare
/// hash to verify.
#[test]
fn a_key_pair_is_generated_under_the_wrapper() {
    let mut rng = DefaultRNG::default();
    let (pk, sk) = keygen::<P256, Unsafe<RIPEMD160>>(&mut rng).unwrap();
    let sig = sk.sign(&mut rng, MSG, None).unwrap();
    pk.verify(MSG, None, &sig).unwrap();
    pk.with_hash::<RIPEMD160>().verify(MSG, None, &sig).unwrap();

    let (pk, sk) = P256::generate_signature_key_pair::<Unsafe<RIPEMD160>>(&mut rng).unwrap();
    let sig = sk.sign_deterministic(MSG, None).unwrap();
    pk.with_hash::<RIPEMD160>().verify(MSG, None, &sig).unwrap();
}

/// Over a hash that has the marker the wrapper changes nothing: RFC 6979 Appendix A.2.5's key
/// and its SHA-256 signature of "sample", the values `rfc6979_p256_vectors_tests.rs` checks.
#[test]
fn the_wrapper_changes_no_signature() {
    let x = hex_decode("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721").unwrap();
    let expected = [
        hex_decode("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716").unwrap(),
        hex_decode("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8").unwrap(),
    ]
    .concat();

    let bare = ECDSAPrivateKey::<P256, SHA256>::from_bytes(&x).unwrap();
    let pk: ECDSAPublicKey<P256, SHA256> = bare.derive_pk();
    assert_eq!(bare.sign_deterministic(b"sample", None).unwrap()[..], expected[..]);

    let wrapped = bare.with_hash::<Unsafe<SHA256>>();
    let sig = wrapped.sign_deterministic(b"sample", None).unwrap();
    assert_eq!(sig[..], expected[..]);
    pk.verify(b"sample", None, &sig).unwrap();
    assert_eq!(ECDSA::<P256, Unsafe<SHA256>>::ALG_NAME, "ECDSA-P256-SHA256");
    assert_eq!(ECDSA::<P256, Unsafe<SHA256>>::MAX_SECURITY_STRENGTH, SecurityStrength::_128bit);
}
