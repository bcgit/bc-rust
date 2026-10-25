#[cfg(test)]
mod test_secret {
    // The crate is `#![no_std]`; the test harness links `std`, but its prelude (and `format!`) is
    // not in scope automatically. Bring it in explicitly for these tests.
    extern crate std;

    use std::fmt;
    use std::fmt::Formatter;
    use std::format;

    use bouncycastle_utils::ct::Condition;
    use bouncycastle_utils::secret::{Secret, ZeroizablePrimitive};

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

    /// Wrapping something in Secret will mask the type's native Debug / Display
    #[test]
    fn debug_and_display_are_redacted() {
        // Redacts basic types
        // would render as "AAAA" if leaked
        let i = 0x4141_4141i32;
        assert_eq!(format!("{i}"), "1094795585");
        assert_eq!(format!("{i:?}"), "1094795585");

        let mut s = Secret::<i32>::new();
        *s = 0x4141_4141;
        assert_eq!(*s, 0x4141_4141);
        let dbg = format!("{s:?}");
        let disp = format!("{s}");
        assert!(dbg.contains("redacted"));
        assert!(disp.contains("redacted"));
        // The secret value must not appear in either rendering.
        assert!(!dbg.contains("1094795585")); // 0x41414141
        assert!(!disp.contains("1094795585"));

        // Same for arrays
        let a = [0x0, 0x1, 0x2, 0x3];
        // [u8] does not impl Display, but it does impl Debug
        assert_eq!(format!("{a:?}"), "[0, 1, 2, 3]");

        let mut sa = Secret::<[u8; 4]>::new();
        *sa = [0x0, 0x1, 0x2, 0x3];
        assert_eq!(*sa, [0x0, 0x1, 0x2, 0x3]);
        assert!(format!("{sa:?}").contains("redacted"));
        assert!(!format!("{sa:?}").contains("0, 1, 2, 3"));

        // Same for custom types
        #[derive(Copy, Clone)]
        struct Thing {
            value: i32,
        }
        // Debug and Display that dump the inner value.
        impl fmt::Debug for Thing {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(f, "Thing {}", self.value)
            }
        }
        impl fmt::Display for Thing {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(f, "Thing {}", self.value)
            }
        }

        // So that it's valid for Secret<T: ZeroizablePrimitive>
        impl ZeroizablePrimitive for Thing {
            const ZEROED: Self = Self { value: 0 };
            fn ct_eq(&self, other: &Self) -> Condition<u32> {
                self.value.ct_eq(&other.value)
            }
        }

        // Thing can be debugged and displayed with the inner value
        let non_secret_thing = Thing { value: 42 };
        assert_eq!(format!("{}", non_secret_thing), "Thing 42");
        assert_eq!(format!("{:?}", non_secret_thing), "Thing 42");

        // But a Secret<Thing> cannot
        let mut secret_thing = Secret::<Thing>::new();
        secret_thing.value = 42;

        assert!(format!("{}", secret_thing).contains("<redacted>"));
        assert!(!format!("{}", secret_thing).contains("42"));

        assert!(format!("{:?}", secret_thing).contains("<redacted>"));
        assert!(!format!("{:?}", secret_thing).contains("42"));

        // Equality goes through Thing's `ct_eq`.
        let mut same_thing = Secret::<Thing>::new();
        same_thing.value = 42;
        assert!(secret_thing == same_thing);
        same_thing.value = 41;
        assert!(secret_thing != same_thing);

        // still behaves properly after zeroization
        secret_thing.zeroize();
        assert_eq!(secret_thing.value, 0i32);

        assert!(format!("{}", secret_thing).contains("<redacted>"));
        assert!(!format!("{}", secret_thing).contains("0"));

        assert!(format!("{:?}", secret_thing).contains("<redacted>"));
        assert!(!format!("{:?}", secret_thing).contains("0"));

        secret_thing.value = 43;
        assert_eq!(secret_thing.value, 43i32);

        assert!(format!("{}", secret_thing).contains("<redacted>"));
        assert!(!format!("{}", secret_thing).contains("43"));

        assert!(format!("{:?}", secret_thing).contains("<redacted>"));
        assert!(!format!("{:?}", secret_thing).contains("43"));
    }

    #[test]
    fn drop_does_not_panic() {
        let mut s = Secret::<[u8; 32]>::new();
        *s = [7u8; 32];
        drop(s);
    }

    #[test]
    fn eq() {
        // Scalars: equal and unequal.
        let mut a = Secret::<u64>::new();
        *a = 0xDEAD_BEEF;
        let mut b = Secret::<u64>::new();
        *b = 0xDEAD_BEEF;
        let mut c = Secret::<u64>::new();
        *c = 0xFEED_FACE;
        assert_eq!(a, b);
        assert_ne!(a, c);

        // Two freshly-zeroed secrets are equal.
        assert_eq!(Secret::<u32>::new(), Secret::<u32>::new());

        // Arrays: equal, and differing in a single byte.
        let mut k1 = Secret::<[u8; 16]>::new();
        *k1 = [0x42u8; 16];
        let mut k2 = Secret::<[u8; 16]>::new();
        *k2 = [0x42u8; 16];
        assert_eq!(k1, k2);

        k2[15] = 0x43; // flip only the last byte
        assert_ne!(k1, k2);

        k2[15] = 0x42;
        k2[0] = 0x43; // flip only the first byte
        assert_ne!(k1, k2);
    }

    /// `Secret`s holding `a` and `b`, compared.
    fn secrets_equal<T: ZeroizablePrimitive>(a: T, b: T) -> bool {
        let mut sa = Secret::<T>::new();
        *sa = a;
        let mut sb = Secret::<T>::new();
        *sb = b;
        sa == sb
    }

    /// Every integer width compares its whole value: a difference in only the lowest or only the
    /// highest bit is seen.
    #[test]
    fn eq_every_integer_width() {
        assert!(secrets_equal(0xA5u8, 0xA5));
        assert!(!secrets_equal(0xA5u8, 0xA4));
        assert!(!secrets_equal(0x25u8, 0xA5));
        assert!(secrets_equal(0xA5A5u16, 0xA5A5));
        assert!(!secrets_equal(0xA5A5u16, 0xA5A4));
        assert!(!secrets_equal(0x25A5u16, 0xA5A5));
        assert!(secrets_equal(0xA5A5_A5A5u32, 0xA5A5_A5A5));
        assert!(!secrets_equal(0xA5A5_A5A5u32, 0xA5A5_A5A4));
        assert!(!secrets_equal(0x25A5_A5A5u32, 0xA5A5_A5A5));
        assert!(secrets_equal(u64::MAX, u64::MAX));
        assert!(!secrets_equal(u64::MAX, u64::MAX - 1));
        assert!(!secrets_equal(u64::MAX >> 1, u64::MAX));
        assert!(secrets_equal(u128::MAX, u128::MAX));
        assert!(!secrets_equal(u128::MAX, u128::MAX - 1));
        assert!(!secrets_equal(u128::MAX >> 1, u128::MAX));
        assert!(secrets_equal(usize::MAX, usize::MAX));
        assert!(!secrets_equal(usize::MAX, usize::MAX - 1));
        assert!(!secrets_equal(usize::MAX >> 1, usize::MAX));
        assert!(secrets_equal(-1i8, -1));
        assert!(!secrets_equal(-1i8, -2));
        assert!(!secrets_equal(i8::MAX, -1));
        assert!(secrets_equal(-1i16, -1));
        assert!(!secrets_equal(-1i16, -2));
        assert!(!secrets_equal(i16::MAX, -1));
        assert!(secrets_equal(-1i32, -1));
        assert!(!secrets_equal(-1i32, -2));
        assert!(!secrets_equal(i32::MAX, -1));
        assert!(secrets_equal(-1i64, -1));
        assert!(!secrets_equal(-1i64, -2));
        assert!(!secrets_equal(i64::MAX, -1));
        assert!(secrets_equal(-1i128, -1));
        assert!(!secrets_equal(-1i128, -2));
        assert!(!secrets_equal(i128::MAX, -1));
        assert!(secrets_equal(-1isize, -1));
        assert!(!secrets_equal(-1isize, -2));
        assert!(!secrets_equal(isize::MAX, -1));
    }

    #[test]
    fn eq_bool_and_char() {
        assert!(secrets_equal(true, true));
        assert!(secrets_equal(false, false));
        assert!(!secrets_equal(true, false));
        assert!(secrets_equal('é', 'é'));
        assert!(!secrets_equal('é', 'e'));
        // Differ only above the low byte.
        assert!(!secrets_equal('\u{0141}', '\u{0041}'));
    }

    /// An array compares every element: a difference in only the first or only the last element is
    /// seen, which an early return on the first element or a loop that stops short would miss.
    #[test]
    fn eq_arrays_visit_every_element() {
        let base = [0x1111_2222_3333_4444u64; 4];
        assert!(secrets_equal(base, base));
        let mut first = base;
        first[0] ^= 1 << 63;
        assert!(!secrets_equal(base, first));
        let mut last = base;
        last[3] ^= 1;
        assert!(!secrets_equal(base, last));

        // Nested arrays recurse through the element type's `ct_eq`.
        let nested = [[0x5Au8; 3]; 2];
        assert!(secrets_equal(nested, nested));
        let mut nested_last = nested;
        nested_last[1][2] = 0x5B;
        assert!(!secrets_equal(nested, nested_last));

        // The empty array is equal to itself.
        assert!(secrets_equal([0u32; 0], [0u32; 0]));
    }

    /// `ct_eq` itself returns the all-ones mask for equal values and the zero mask otherwise.
    #[test]
    fn ct_eq_mask_values() {
        assert!([1u32, 2, 3].ct_eq(&[1, 2, 3]).to_bool());
        assert!(![1u32, 2, 3].ct_eq(&[1, 2, 4]).to_bool());
        assert!(7u16.ct_eq(&7).to_bool());
        assert!(!7u16.ct_eq(&8).to_bool());
    }

    /// The Secret wrapper does not add any memory overhead.
    #[test]
    fn no_size_inflation() {
        assert_eq!(size_of::<i32>(), size_of::<Secret<i32>>());
        assert_eq!(size_of::<[u8; 32]>(), size_of::<Secret<[u8; 32]>>());
    }
}
