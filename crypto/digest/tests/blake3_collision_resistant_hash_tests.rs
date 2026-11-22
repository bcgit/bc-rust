//! BLAKE3 in `hash` mode carries `CollisionResistantHash`, the marker a signature's hash needs;
//! `derive_key` mode, whose function depends on its context string, does not.

use bouncycastle_core_test_framework::assert_not_collision_resistant_hash;
use bouncycastle_core_test_framework::hash::test_collision_resistant_hash;
use bouncycastle_digest::blake3::{BLAKE3, BLAKE3DeriveKey};

#[test]
fn the_hash_carries_the_marker() {
    test_collision_resistant_hash::<BLAKE3>();
}

#[test]
fn derive_key_does_not() {
    assert_not_collision_resistant_hash!(BLAKE3DeriveKey);
}
