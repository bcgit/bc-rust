//! Which SHA-3 types carry `CollisionResistantHash`, the marker a signature's hash needs: SHA-3,
//! and SHAKE as a fixed-length digest. The SP 800-185 functions take their parameters and
//! output length at run time and do not.

use bouncycastle_core_test_framework::assert_not_collision_resistant_hash;
use bouncycastle_core_test_framework::hash::test_collision_resistant_hash;
use bouncycastle_digest::sha3::kmac::{KMACXOF128, KMACXOF256};
use bouncycastle_digest::sha3::parallelhash::{
    ParallelHash128, ParallelHash256, ParallelHashXOF128, ParallelHashXOF256,
};
use bouncycastle_digest::sha3::tuplehash::{
    TupleHash128, TupleHash256, TupleHashXOF128, TupleHashXOF256,
};
use bouncycastle_digest::sha3::{
    CSHAKE128, CSHAKE256, SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256,
};

#[test]
fn sha3_and_shake_carry_the_marker() {
    test_collision_resistant_hash::<SHA3_224>();
    test_collision_resistant_hash::<SHA3_256>();
    test_collision_resistant_hash::<SHA3_384>();
    test_collision_resistant_hash::<SHA3_512>();
    test_collision_resistant_hash::<SHAKE128>();
    test_collision_resistant_hash::<SHAKE256>();
}

#[test]
fn the_parameterised_functions_do_not() {
    assert_not_collision_resistant_hash!(CSHAKE128);
    assert_not_collision_resistant_hash!(CSHAKE256);
    assert_not_collision_resistant_hash!(KMACXOF128);
    assert_not_collision_resistant_hash!(KMACXOF256);
    assert_not_collision_resistant_hash!(TupleHash128);
    assert_not_collision_resistant_hash!(TupleHash256);
    assert_not_collision_resistant_hash!(TupleHashXOF128);
    assert_not_collision_resistant_hash!(TupleHashXOF256);
    assert_not_collision_resistant_hash!(ParallelHash128);
    assert_not_collision_resistant_hash!(ParallelHash256);
    assert_not_collision_resistant_hash!(ParallelHashXOF128);
    assert_not_collision_resistant_hash!(ParallelHashXOF256);
}
