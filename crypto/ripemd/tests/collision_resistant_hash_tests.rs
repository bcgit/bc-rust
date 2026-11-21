//! No RIPEMD function carries `CollisionResistantHash`, so none can produce a signature except
//! as `hazmat::WithoutCollisionResistance<H>`, which is the function in everything else.

use bouncycastle_core::hazmat::WithoutCollisionResistance;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, AlgorithmOID, HashAlgParams, HashOneShot};
use bouncycastle_core_test_framework::assert_not_collision_resistant_hash;
use bouncycastle_ripemd::{RIPEMD128, RIPEMD160, RIPEMD256, RIPEMD320};

#[test]
fn no_ripemd_function_carries_the_marker() {
    assert_not_collision_resistant_hash!(RIPEMD128);
    assert_not_collision_resistant_hash!(RIPEMD160);
    assert_not_collision_resistant_hash!(RIPEMD256);
    assert_not_collision_resistant_hash!(RIPEMD320);
}

fn carries_the_marker<H: bouncycastle_core::traits::CollisionResistantHash>() {}

fn the_wrapper_is<H: HashOneShot + HashAlgParams>() {
    carries_the_marker::<WithoutCollisionResistance<H>>();
    assert_eq!(<WithoutCollisionResistance<H> as Algorithm>::ALG_NAME, H::ALG_NAME);
    assert_eq!(
        <WithoutCollisionResistance<H> as Algorithm>::MAX_SECURITY_STRENGTH,
        SecurityStrength::None
    );
    assert_eq!(<WithoutCollisionResistance<H> as HashAlgParams>::OUTPUT_LEN, H::OUTPUT_LEN);
    assert_eq!(<WithoutCollisionResistance<H> as HashAlgParams>::BLOCK_LEN, H::BLOCK_LEN);
    assert_eq!(WithoutCollisionResistance::<H>::hash(b"abc"), H::hash(b"abc"));
}

#[test]
fn the_hazmat_wrapper_is_the_function_with_the_marker() {
    the_wrapper_is::<RIPEMD128>();
    the_wrapper_is::<RIPEMD160>();
    the_wrapper_is::<RIPEMD256>();
    the_wrapper_is::<RIPEMD320>();
    assert_eq!(<WithoutCollisionResistance<RIPEMD160> as AlgorithmOID>::OID, RIPEMD160::OID);
    assert_eq!(
        <WithoutCollisionResistance<RIPEMD160> as AlgorithmOID>::OID_DER,
        RIPEMD160::OID_DER
    );
}
