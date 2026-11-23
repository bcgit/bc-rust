//! Which SHA-2 types carry `CollisionResistantHash`, the marker a signature's hash needs.

use bouncycastle_core_test_framework::assert_not_collision_resistant_hash;
use bouncycastle_core_test_framework::hash::test_collision_resistant_hash;
use bouncycastle_digest::sha2::{SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256, SHA512t};

#[test]
fn the_named_hashes_carry_the_marker() {
    test_collision_resistant_hash::<SHA224>();
    test_collision_resistant_hash::<SHA256>();
    test_collision_resistant_hash::<SHA384>();
    test_collision_resistant_hash::<SHA512>();
    test_collision_resistant_hash::<SHA512_224>();
    test_collision_resistant_hash::<SHA512_256>();
}

/// SHA-512/t carries the marker where it reports a strength, from 224 bits up, and not below.
#[test]
fn sha512t_carries_the_marker_from_224_bits_up() {
    test_collision_resistant_hash::<SHA512t<232>>();
    test_collision_resistant_hash::<SHA512t<376>>();
    test_collision_resistant_hash::<SHA512t<392>>();
    test_collision_resistant_hash::<SHA512t<504>>();
    assert_not_collision_resistant_hash!(SHA512t<216>);
    assert_not_collision_resistant_hash!(SHA512t<160>);
    assert_not_collision_resistant_hash!(SHA512t<96>);
    assert_not_collision_resistant_hash!(SHA512t<8>);
}
