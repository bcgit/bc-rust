//! Which SHA-2 types carry `CollisionResistantHash`, the marker a signature's hash needs.

use bouncycastle_core_test_framework::assert_not_collision_resistant_hash;
use bouncycastle_core_test_framework::hash::test_collision_resistant_hash;
use bouncycastle_sha2::{SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256, SHA512t};

#[test]
fn the_named_hashes_carry_the_marker() {
    test_collision_resistant_hash::<SHA224>();
    test_collision_resistant_hash::<SHA256>();
    test_collision_resistant_hash::<SHA384>();
    test_collision_resistant_hash::<SHA512>();
    test_collision_resistant_hash::<SHA512_224>();
    test_collision_resistant_hash::<SHA512_256>();
}

/// The marker is not generic over `t`: a short truncation reports no strength and has none.
#[test]
fn another_truncation_does_not() {
    assert_not_collision_resistant_hash!(SHA512t<96>);
    assert_not_collision_resistant_hash!(SHA512t<160>);
}
