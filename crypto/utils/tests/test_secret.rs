
#[cfg(test)]
mod test_secret {
    // The crate is `#![no_std]`; the test harness links `std`, but its prelude (and `format!`) is
    // not in scope automatically. Bring it in explicitly for these tests.
    extern crate std;
    use std::format;
    
    use bouncycastle_utils::Secret;

    #[test]
    fn new_and_default_are_zeroed() {
        let s = Secret::<u32>::new();
        assert_eq!(*s, 0);

        let d: Secret<u64> = Secret::default();
        assert_eq!(*d, 0);

        let arr = Secret::<[u8; 4]>::new();
        assert_eq!(*arr, [0u8; 4]);
    }

    #[test]
    fn fill_in_place_via_deref_mut() {
        let mut s = Secret::<u16>::new();
        assert_eq!(*s, 0u16);
        *s = 0xABCD;
        assert_eq!(*s, 0xABCD);
    }

    #[test]
    fn array_is_transparent() {
        let mut key = Secret::<[u8; 4]>::new();
        *key = [1u8, 2, 3, 4];
        assert_eq!(key[0], 1);
        assert_eq!(key[3], 4);
        assert_eq!(key.len(), 4);
        assert_eq!(key.iter().copied().sum::<u8>(), 10);
    }

    #[test]
    fn default_supports_arrays_larger_than_32() {
        // `[u8; 64]: Default` does NOT exist (Default is capped at N <= 32), but `ZeroInit` does,
        // so this must compile and produce a zeroed buffer, really just to prove that we can do
        // something that Default can't.
        let big = Secret::<[u8; 64]>::new();
        assert_eq!(big.len(), 64);
        assert!(big.iter().all(|&b| b == 0));
    }

    #[test]
    fn explicit_zeroize_scrubs_scalar() {
        let mut s = Secret::<u64>::new();
        *s = 0xDEAD_BEEF_DEAD_BEEF;
        s.zeroize();
        assert_eq!(*s, 0);
    }

    #[test]
    fn explicit_zeroize_scrubs_array() {
        let mut key = Secret::<[u8; 16]>::new();
        *key = [0xFFu8; 16];
        key.zeroize();
        assert_eq!(*key, [0u8; 16]);
    }

    #[test]
    fn clone_duplicates_value() {
        let mut a = Secret::<u32>::new();
        *a = 42;
        let mut b = a.clone();
        *b += 1;
        assert_eq!(*a, 42);
        assert_eq!(*b, 43);
    }

    #[test]
    fn debug_and_display_are_redacted() {
        let mut s = Secret::<u32>::new();
        *s = 0x4141_4141; // would render as "AAAA" if leaked
        let dbg = format!("{s:?}");
        let disp = format!("{s}");
        assert!(dbg.contains("redacted"));
        assert!(disp.contains("redacted"));
        // The secret value must not appear in either rendering.
        assert!(!dbg.contains("1094795585")); // 0x41414141
        assert!(!disp.contains("1094795585"));
    }

    #[test]
    fn drop_does_not_panic() {
        let mut s = Secret::<[u8; 32]>::new();
        *s = [7u8; 32];
        drop(s);
    }
}
