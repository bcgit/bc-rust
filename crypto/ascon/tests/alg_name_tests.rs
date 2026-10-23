//! Each Ascon type reports its own algorithm through `Algorithm`, and the exported name constants
//! the factories match on are those same names. The direction of `Ascon_AEAD128` is a type
//! parameter of one algorithm, not a different algorithm, so both directions report the same name.

use bouncycastle_ascon::{
    ASCON_AEAD128_NAME, ASCON_CXOF128_NAME, ASCON_HASH256_NAME, ASCON_XOF128_NAME, Ascon_AEAD128,
    AsconCXof128, AsconHash256, AsconXof128,
};
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::Algorithm;

/// `A` reports `name` and `strength`, and `constant` is that same name.
fn check<A: Algorithm>(name: &str, constant: &str, strength: SecurityStrength) {
    assert_eq!(A::ALG_NAME, name);
    assert_eq!(constant, name, "the exported constant is the reported name");
    assert_eq!(A::MAX_SECURITY_STRENGTH, strength, "{name}");
}

#[test]
fn aead128() {
    use SecurityStrength::_128bit;
    check::<Ascon_AEAD128<Encrypting>>("Ascon-AEAD128", ASCON_AEAD128_NAME, _128bit);
    check::<Ascon_AEAD128<Decrypting>>("Ascon-AEAD128", ASCON_AEAD128_NAME, _128bit);
}

#[test]
fn hash256_xof128_cxof128() {
    use SecurityStrength::_128bit;
    check::<AsconHash256>("Ascon-Hash256", ASCON_HASH256_NAME, _128bit);
    check::<AsconXof128>("Ascon-XOF128", ASCON_XOF128_NAME, _128bit);
    check::<AsconCXof128>("Ascon-CXOF128", ASCON_CXOF128_NAME, _128bit);
}
