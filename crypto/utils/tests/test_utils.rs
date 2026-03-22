use bouncycastle_core_interface::key_material::KeyType;
use bouncycastle_utils::{max, min};

#[test]
fn test_max_min() {
    // Test with numbers
    assert_eq!(*max(&0_i32, &35_i32), 35_i32);
    assert_eq!(*max(&0_i32, &-35_i32), 0_i32);
    assert_eq!(*max(&1_i32, &1_i32), 1_i32);
    assert_eq!(*min(&0_i32, &35_i32), 0_i32);
    assert_eq!(*min(&0_i32, &-35_i32), -35_i32);

    // Test with Strings
    assert_eq!(*max(&"abc", &"def"), "def");
    assert_eq!(*min(&"abc", &"def"), "abc");

    // Test with KeyMaterial KeyTypes
    assert_eq!(
        *max(&KeyType::BytesLowEntropy, &KeyType::BytesFullEntropy),
        KeyType::BytesFullEntropy
    );
}
