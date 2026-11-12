//! The key types as types: equality is over the key's coordinates alone (a public key and its
//! negation share `x` and differ), `Debug` names the type, and a pairing's strength is the
//! lesser of the curve's and the hash's, whichever side is weaker.

use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, SignaturePublicKey};
use bouncycastle_ec::{P256, P384};
use bouncycastle_ecdsa::ecdsa::ECDSA;
use bouncycastle_ecdsa::keys::{ECDSAPublicKey, keygen};
use bouncycastle_rng::DefaultRNG;
use bouncycastle_sha2::{SHA256, SHA384};

#[test]
fn strength_is_the_lesser_side_whichever_it_is() {
    assert_eq!(ECDSA::<P256, SHA384>::MAX_SECURITY_STRENGTH, SecurityStrength::_128bit);
    assert_eq!(ECDSA::<P384, SHA256>::MAX_SECURITY_STRENGTH, SecurityStrength::_128bit);
    assert_eq!(ECDSA::<P384, SHA384>::MAX_SECURITY_STRENGTH, SecurityStrength::_192bit);
}

#[test]
fn distinct_keys_are_unequal_and_debug_names_the_type() {
    let mut rng = DefaultRNG::default();
    let (pk_a, sk_a) = keygen::<P256, SHA256>(&mut rng).unwrap();
    let (pk_b, sk_b) = keygen::<P256, SHA256>(&mut rng).unwrap();
    assert_ne!(sk_a, sk_b);
    assert_ne!(pk_a, pk_b);
    assert_eq!(sk_a, sk_a.clone());
    assert_eq!(pk_a, pk_a);

    assert!(format!("{sk_a:?}").starts_with("ECDSAPrivateKey"));
    assert!(format!("{pk_a:?}").starts_with("ECDSAPublicKey { x: "));
}

#[test]
fn a_public_key_and_its_negation_share_x_and_differ() {
    let (pk, _) = keygen::<P256, SHA256>(&mut DefaultRNG::default()).unwrap();
    let encoded = pk.encode();
    // SEC 1 Section 2.3.4: `02 || X` and `03 || X` decode to (x, y) and (x, p - y).
    let mut even = [0u8; 33];
    even[1..].copy_from_slice(&encoded[1..33]);
    let mut odd = even;
    even[0] = 0x02;
    odd[0] = 0x03;
    let pk_even = ECDSAPublicKey::<P256, SHA256>::from_bytes(&even).unwrap();
    let pk_odd = ECDSAPublicKey::<P256, SHA256>::from_bytes(&odd).unwrap();
    assert_ne!(pk_even, pk_odd);
    assert!(pk_even == pk || pk_odd == pk);
    assert_eq!(pk_even.encode()[1..33], pk_odd.encode()[1..33]);
}
