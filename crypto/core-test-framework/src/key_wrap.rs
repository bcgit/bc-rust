//! Generic behaviour tests for a key-wrap key object, through the [`KeyWrappingKey`] /
//! [`KeyUnwrappingKey`] roles and the [`KeyWrapper`] / [`KeyUnwrapper`] workers it hands out.
//! The key-type and strength policy of the construction is `TestFrameworkFromKeyMaterial`'s.

use crate::DUMMY_SEED;
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::{FromKeyMaterial, KeyUnwrappingKey, KeyWrappingKey};
use bouncycastle_core::traits::{KeyUnwrapper, KeyWrapper};
use bouncycastle_utils::secret::Secret;

/// Size of the scratch buffers used for the variable-length APIs.
const BUF_LEN: usize = 1024;

/// Instance of the test framework.
pub struct TestFrameworkKeyWrap {
    // Put any config options here
}

impl Default for TestFrameworkKeyWrap {
    fn default() -> Self {
        Self::new()
    }
}

impl TestFrameworkKeyWrap {
    /// Create a new instance of the test framework.
    pub fn new() -> Self {
        Self {}
    }

    /// The key from `KEK_LEN` bytes of the dummy seed starting at `offset`, tagged as a cipher key.
    fn key<const KEK_LEN: usize, K: FromKeyMaterial<KEK_LEN>>(offset: usize) -> K {
        let kek = KeyMaterial::<KEK_LEN>::from_bytes_as_type(
            &DUMMY_SEED[offset..offset + KEK_LEN],
            KeyType::SymmetricCipherKey,
        )
        .unwrap();
        K::from_key_material(&kek).expect("a cipher key of the key's own length")
    }

    /// Every member of the two roles and the two worker traits for one valid `(KEY_LEN, CT_LEN)`
    /// pair, including the error conditions common to all key-wrap algorithms. This gives good
    /// baseline test coverage, but is not a substitute for known-answer tests; see
    /// [`TestFrameworkKeyWrap::test_kat`].
    pub fn test<const KEK_LEN: usize, const KEY_LEN: usize, const CT_LEN: usize, K>(&self)
    where
        K: FromKeyMaterial<KEK_LEN> + KeyWrappingKey<KEK_LEN> + KeyUnwrappingKey<KEK_LEN>,
    {
        assert!(CT_LEN <= BUF_LEN, "test buffers are too small");

        let kek: K = Self::key(0);
        let key: [u8; KEY_LEN] = DUMMY_SEED[100..100 + KEY_LEN].try_into().unwrap();

        /* Length helpers, on the key and on the workers */

        assert_eq!(kek.wrap_out_len(KEY_LEN), CT_LEN);
        assert_eq!(kek.create_wrapper().wrap_out_len(KEY_LEN), CT_LEN);
        let max_pt_len = kek.unwrap_out_max_len(CT_LEN);
        assert_eq!(kek.create_unwrapper().unwrap_out_max_len(CT_LEN), max_pt_len);
        assert!(max_pt_len >= KEY_LEN, "unwrap_out_max_len is not an upper bound");
        assert!(max_pt_len < CT_LEN, "a key-wrap ciphertext is longer than its plaintext");
        // documented as saturating, and as never panicking
        assert_eq!(kek.unwrap_out_max_len(0), 0);
        let _ = kek.unwrap_out_max_len(usize::MAX);
        let _ = kek.wrap_out_len(usize::MAX);
        // one semiblock: half the block cipher's block length
        let semiblock_len = CT_LEN - max_pt_len;

        /* Fixed-length API */

        let ct = kek.wrap_key::<KEY_LEN, CT_LEN>(&key).unwrap();

        // wrap_key() and wrap_key_out() agree, on the key and on the worker
        let mut ct_out = [0u8; CT_LEN];
        let bytes_written = kek.wrap_key_out(&key, &mut ct_out).unwrap();
        assert_eq!(bytes_written, CT_LEN);
        assert_eq!(ct, ct_out);
        assert_eq!(kek.create_wrapper().wrap_key::<KEY_LEN, CT_LEN>(&key).unwrap(), ct);
        ct_out.fill(0);
        assert_eq!(kek.create_wrapper().wrap_key_out(&key, &mut ct_out).unwrap(), CT_LEN);
        assert_eq!(ct, ct_out);

        // key wrapping is deterministic
        assert_eq!(ct, kek.wrap_key::<KEY_LEN, CT_LEN>(&key).unwrap());

        // round trip through unwrap_key() and unwrap_key_out(), on the key and on the worker
        let recovered: Secret<[u8; KEY_LEN]> = kek.unwrap_key(&ct).unwrap();
        assert_eq!(*recovered, key);
        let recovered: Secret<[u8; KEY_LEN]> = kek.create_unwrapper().unwrap_key(&ct).unwrap();
        assert_eq!(*recovered, key);

        let mut recovered_out = Secret::<[u8; KEY_LEN]>::new();
        let bytes_written = kek.unwrap_key_out(&ct, &mut recovered_out).unwrap();
        assert_eq!(bytes_written, KEY_LEN);
        assert_eq!(*recovered_out, key);
        recovered_out.zeroize();
        let bytes_written = kek.create_unwrapper().unwrap_key_out(&ct, &mut recovered_out).unwrap();
        assert_eq!(bytes_written, KEY_LEN);
        assert_eq!(*recovered_out, key);

        /* Variable-length API agrees with the fixed-length API */

        let mut buf = [0u8; BUF_LEN];
        let bytes_written = kek.wrap_out(&key, &mut buf[..CT_LEN]).unwrap();
        assert_eq!(bytes_written, CT_LEN);
        assert_eq!(&buf[..CT_LEN], &ct);
        buf.fill(0);
        assert_eq!(kek.create_wrapper().wrap_out(&key, &mut buf[..CT_LEN]).unwrap(), CT_LEN);
        assert_eq!(&buf[..CT_LEN], &ct);

        // a larger buffer than needed is fine
        let bytes_written = kek.wrap_out(&key, &mut buf).unwrap();
        assert_eq!(bytes_written, CT_LEN);

        let mut pt = [0u8; BUF_LEN];
        let bytes_written = kek.unwrap_out(&ct, &mut pt[..max_pt_len]).unwrap();
        assert_eq!(bytes_written, KEY_LEN);
        assert_eq!(&pt[..KEY_LEN], &key);
        pt.fill(0);
        assert_eq!(kek.create_unwrapper().unwrap_out(&ct, &mut pt[..max_pt_len]).unwrap(), KEY_LEN);
        assert_eq!(&pt[..KEY_LEN], &key);

        // several workers in flight from one key, and the key unchanged by use
        let a = kek.create_wrapper();
        let b = kek.create_unwrapper();
        assert_eq!(a.wrap_key::<KEY_LEN, CT_LEN>(&key).unwrap(), ct);
        assert_eq!(*b.unwrap_key::<KEY_LEN, CT_LEN>(&ct).unwrap(), key);
        assert_eq!(a.wrap_key::<KEY_LEN, CT_LEN>(&key).unwrap(), ct);
        assert_eq!(kek.wrap_key::<KEY_LEN, CT_LEN>(&key).unwrap(), ct);

        /* Error case: output buffers too small */

        match kek.wrap_out(&key, &mut buf[..CT_LEN - 1]) {
            Err(SymmetricCipherError::OutputBufferTooSmall(required)) => {
                assert_eq!(required, CT_LEN)
            }
            _ => panic!("Should have rejected a ciphertext buffer that is too small"),
        }
        // checked before any work is done, so it is the upper bound that is enforced, even when
        // the actual plaintext would have fit
        match kek.unwrap_out(&ct, &mut pt[..max_pt_len - 1]) {
            Err(SymmetricCipherError::OutputBufferTooSmall(required)) => {
                assert_eq!(required, max_pt_len)
            }
            _ => panic!("Should have rejected a plaintext buffer that is too small"),
        }

        /* Error case: input lengths the algorithm is not defined on */

        // Every key-wrap algorithm in SP 800-38F (Table 1) needs at least one octet of plaintext
        // and a ciphertext of at least two semiblocks that is a whole number of semiblocks.
        // Empty inputs also catch implementations that subtract before checking the length.
        match kek.wrap_out(&[], &mut buf) {
            Err(SymmetricCipherError::InvalidInputLength(_)) => { /* good */ }
            _ => panic!("Should have rejected an empty plaintext"),
        }
        for bad_ct_len in [0, semiblock_len, CT_LEN - 1] {
            match kek.unwrap_out(&ct[..bad_ct_len], &mut pt) {
                Err(SymmetricCipherError::InvalidInputLength(_)) => { /* good */ }
                _ => panic!("Should have rejected a ciphertext of {bad_ct_len} bytes"),
            }
        }

        /* Error case: modified ciphertext */

        // Key wrap is authenticated, so unlike an unauthenticated cipher, a modified ciphertext
        // must always fail to unwrap, and always with DecryptionFailed.
        for i in [0, CT_LEN / 2, CT_LEN - 1] {
            let mut bad_ct = ct;
            bad_ct[i] ^= 0x01;

            match kek.unwrap_key::<KEY_LEN, CT_LEN>(&bad_ct) {
                Err(SymmetricCipherError::DecryptionFailed) => { /* good */ }
                _ => panic!("Should have failed to unwrap a ciphertext modified at byte {i}"),
            }

            // on failure the plaintext buffer is zeroized, not left holding partial output
            pt.fill(0xFF);
            match kek.unwrap_out(&bad_ct, &mut pt) {
                Err(SymmetricCipherError::DecryptionFailed) => { /* good */ }
                _ => panic!("Should have failed to unwrap a ciphertext modified at byte {i}"),
            }
            assert!(pt.iter().all(|b| *b == 0), "plaintext buffer was not zeroized on error");
            let mut out = Secret::<[u8; KEY_LEN]>::new();
            out.fill(0xFF);
            assert!(kek.unwrap_key_out(&bad_ct, &mut out).is_err());
            assert!(out.iter().all(|b| *b == 0), "the Secret was not zeroized on error");
        }

        /* Error case: wrong KEK */

        let wrong_kek: K = Self::key(1);
        match wrong_kek.unwrap_key::<KEY_LEN, CT_LEN>(&ct) {
            Err(SymmetricCipherError::DecryptionFailed) => { /* good */ }
            _ => panic!("Should have failed to unwrap under the wrong KEK"),
        }
        assert_ne!(
            wrong_kek.wrap_key::<KEY_LEN, CT_LEN>(&key).unwrap(),
            ct,
            "two KEKs must not wrap to the same ciphertext"
        );
    }

    /// Known-answer test: checks that wrapping `key` under `kek` gives `expected_ct` through both
    /// the fixed-length and variable-length APIs, and that unwrapping `expected_ct` gives back `key`.
    /// Test vectors must come from the specification or its official companion files, for example
    /// RFC 3394 Section 4 or RFC 5649 Section 6.
    pub fn test_kat<const KEK_LEN: usize, const KEY_LEN: usize, const CT_LEN: usize, K>(
        &self,
        kek: &[u8; KEK_LEN],
        key: &[u8; KEY_LEN],
        expected_ct: &[u8; CT_LEN],
    ) where
        K: FromKeyMaterial<KEK_LEN> + KeyWrappingKey<KEK_LEN> + KeyUnwrappingKey<KEK_LEN>,
    {
        let kek =
            KeyMaterial::<KEK_LEN>::from_bytes_as_type(kek, KeyType::SymmetricCipherKey).unwrap();
        let kek = K::from_key_material(&kek).expect("the vector's KEK");

        let ct = kek.wrap_key::<KEY_LEN, CT_LEN>(key).unwrap();
        assert_eq!(&ct, expected_ct);

        let recovered: Secret<[u8; KEY_LEN]> = kek.unwrap_key(expected_ct).unwrap();
        assert_eq!(&*recovered, key);

        let mut buf = [0u8; BUF_LEN];
        let bytes_written = kek.wrap_out(key, &mut buf).unwrap();
        assert_eq!(&buf[..bytes_written], expected_ct);

        let bytes_written = kek.unwrap_out(expected_ct, &mut buf).unwrap();
        assert_eq!(&buf[..bytes_written], key);
    }
}

#[cfg(test)]
mod tests {
    //! Exercises the framework itself against a mock key and worker, so that the framework is known
    //! to compile and pass before any real key-wrap algorithm exists.

    use super::*;
    use bouncycastle_core::errors::KeyMaterialError;
    use bouncycastle_core::key_material::KeyMaterialTrait;
    use bouncycastle_core::security_strength::SecurityStrength;
    use bouncycastle_core::traits::Algorithm;

    const MOCK_KEK_LEN: usize = 16;
    const MOCK_SEMIBLOCK_LEN: usize = 8;

    /// NOT CRYPTOGRAPHY. A key whose worker has the same length behaviour as KWP (SP 800-38F,
    /// Sec. 6.3) and satisfies the documented contract of the key-wrap traits. It builds
    /// `S = [len(P)]32 || checksum32(kek || P) || P || zero padding` to a multiple of 8 bytes, and
    /// XORs `S` with the repeated KEK.
    struct MockKeyWrapKey {
        kek: [u8; MOCK_KEK_LEN],
    }

    /// The worker: the KEK bytes, borrowed.
    struct MockKeyWrap<'k> {
        kek: &'k [u8; MOCK_KEK_LEN],
    }

    impl Algorithm for MockKeyWrap<'_> {
        const ALG_NAME: &'static str = "MockKeyWrap-NOT-CRYPTOGRAPHY";
        const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
    }

    impl FromKeyMaterial<MOCK_KEK_LEN> for MockKeyWrapKey {
        const KEY_TYPE: KeyType = KeyType::SymmetricCipherKey;

        fn from_key_material(
            kek: &KeyMaterial<MOCK_KEK_LEN>,
        ) -> Result<Self, SymmetricCipherError> {
            if kek.key_type() != KeyType::SymmetricCipherKey {
                Err(KeyMaterialError::InvalidKeyType("KEK must be a SymmetricCipherKey"))?
            }
            if kek.security_strength() < MockKeyWrap::MAX_SECURITY_STRENGTH {
                Err(KeyMaterialError::SecurityStrength("KEK is weaker than the algorithm"))?
            }
            Ok(Self { kek: kek.ref_to_bytes().try_into().unwrap() })
        }
    }

    impl KeyWrappingKey<MOCK_KEK_LEN> for MockKeyWrapKey {
        type Wrapper<'k> = MockKeyWrap<'k>;

        fn create_wrapper<'k>(&'k self) -> Self::Wrapper<'k> {
            MockKeyWrap { kek: &self.kek }
        }
    }

    impl KeyUnwrappingKey<MOCK_KEK_LEN> for MockKeyWrapKey {
        type Unwrapper<'k> = MockKeyWrap<'k>;

        fn create_unwrapper<'k>(&'k self) -> Self::Unwrapper<'k> {
            MockKeyWrap { kek: &self.kek }
        }
    }

    /// 32-bit FNV-1a over `kek || pt`.
    fn checksum(kek: &[u8], pt: &[u8]) -> [u8; 4] {
        let mut hash: u32 = 0x811c9dc5;
        for b in kek.iter().chain(pt.iter()) {
            hash ^= *b as u32;
            hash = hash.wrapping_mul(0x01000193);
        }
        hash.to_be_bytes()
    }

    fn xor_with_kek(kek: &[u8], data: &mut [u8]) {
        for (i, b) in data.iter_mut().enumerate() {
            *b ^= kek[i % kek.len()];
        }
    }

    impl KeyWrapper for MockKeyWrap<'_> {
        fn wrap_key_out<const KEY_LEN: usize, const CT_LEN: usize>(
            &self,
            key: &[u8; KEY_LEN],
            ciphertext: &mut [u8; CT_LEN],
        ) -> Result<usize, SymmetricCipherError> {
            const {
                assert!(
                    KEY_LEN >= 1
                        && CT_LEN
                            == KEY_LEN.div_ceil(MOCK_SEMIBLOCK_LEN) * MOCK_SEMIBLOCK_LEN
                                + MOCK_SEMIBLOCK_LEN
                )
            };
            self.wrap_out(key, ciphertext)
        }

        fn wrap_out_len(&self, plaintext_len: usize) -> usize {
            plaintext_len
                .div_ceil(MOCK_SEMIBLOCK_LEN)
                .saturating_mul(MOCK_SEMIBLOCK_LEN)
                .saturating_add(MOCK_SEMIBLOCK_LEN)
        }

        fn wrap_out(
            &self,
            plaintext: &[u8],
            ciphertext: &mut [u8],
        ) -> Result<usize, SymmetricCipherError> {
            let ct_len = self.wrap_out_len(plaintext.len());
            if ciphertext.len() < ct_len {
                return Err(SymmetricCipherError::OutputBufferTooSmall(ct_len));
            }
            if plaintext.is_empty() || plaintext.len() > u32::MAX as usize {
                return Err(SymmetricCipherError::InvalidInputLength("plaintext length"));
            }
            let s = &mut ciphertext[..ct_len];
            s.fill(0);
            s[..4].copy_from_slice(&(plaintext.len() as u32).to_be_bytes());
            s[4..8].copy_from_slice(&checksum(self.kek, plaintext));
            s[8..8 + plaintext.len()].copy_from_slice(plaintext);
            xor_with_kek(self.kek, s);
            Ok(ct_len)
        }
    }

    impl KeyUnwrapper for MockKeyWrap<'_> {
        fn unwrap_key_out<const KEY_LEN: usize, const CT_LEN: usize>(
            &self,
            ciphertext: &[u8; CT_LEN],
            key: &mut Secret<[u8; KEY_LEN]>,
        ) -> Result<usize, SymmetricCipherError> {
            const {
                assert!(
                    KEY_LEN >= 1
                        && CT_LEN
                            == KEY_LEN.div_ceil(MOCK_SEMIBLOCK_LEN) * MOCK_SEMIBLOCK_LEN
                                + MOCK_SEMIBLOCK_LEN
                )
            };
            // The padded plaintext is up to 7 bytes longer than KEY_LEN, so unwrap into a
            // scratch Secret sized for it, then check that the recovered length is KEY_LEN.
            let mut scratch = Secret::<[u8; BUF_LEN]>::new();
            let result = self.unwrap_out(ciphertext, &mut scratch[..]);
            match result {
                Ok(pt_len) if pt_len == KEY_LEN => {
                    key.copy_from_slice(&scratch[..KEY_LEN]);
                    Ok(KEY_LEN)
                }
                Ok(_) => {
                    key.zeroize();
                    Err(SymmetricCipherError::DecryptionFailed)
                }
                Err(e) => {
                    key.zeroize();
                    Err(e)
                }
            }
        }

        fn unwrap_out_max_len(&self, ciphertext_len: usize) -> usize {
            ciphertext_len.saturating_sub(MOCK_SEMIBLOCK_LEN)
        }

        fn unwrap_out(
            &self,
            ciphertext: &[u8],
            plaintext: &mut [u8],
        ) -> Result<usize, SymmetricCipherError> {
            let max_pt_len = self.unwrap_out_max_len(ciphertext.len());
            if plaintext.len() < max_pt_len {
                return Err(SymmetricCipherError::OutputBufferTooSmall(max_pt_len));
            }
            plaintext.fill(0);
            if ciphertext.len() < 2 * MOCK_SEMIBLOCK_LEN
                || !ciphertext.len().is_multiple_of(MOCK_SEMIBLOCK_LEN)
            {
                return Err(SymmetricCipherError::InvalidInputLength("ciphertext length"));
            }
            let kek = self.kek;

            // Decrypt the header, and the padded plaintext straight into the caller's buffer.
            let mut header = [0u8; MOCK_SEMIBLOCK_LEN];
            header.copy_from_slice(&ciphertext[..MOCK_SEMIBLOCK_LEN]);
            xor_with_kek(kek, &mut header);
            let padded = &mut plaintext[..max_pt_len];
            padded.copy_from_slice(&ciphertext[MOCK_SEMIBLOCK_LEN..]);
            for (i, b) in padded.iter_mut().enumerate() {
                *b ^= kek[(i + MOCK_SEMIBLOCK_LEN) % kek.len()];
            }

            // As KWP-AD: every check fails with the same error.
            let pt_len = u32::from_be_bytes(header[..4].try_into().unwrap()) as usize;
            let ok = pt_len <= max_pt_len
                && max_pt_len - pt_len < MOCK_SEMIBLOCK_LEN
                && padded[pt_len..].iter().all(|b| *b == 0)
                && checksum(kek, &padded[..pt_len]) == header[4..];
            if !ok {
                plaintext.fill(0);
                return Err(SymmetricCipherError::DecryptionFailed);
            }
            Ok(pt_len)
        }
    }

    #[test]
    fn framework_passes_against_mock() {
        let tf = TestFrameworkKeyWrap::new();
        // a whole number of semiblocks, one that needs padding, and the shortest possible
        tf.test::<MOCK_KEK_LEN, 16, 24, MockKeyWrapKey>();
        tf.test::<MOCK_KEK_LEN, 13, 24, MockKeyWrapKey>();
        tf.test::<MOCK_KEK_LEN, 1, 16, MockKeyWrapKey>();
    }

    /// Only checks the plumbing of test_kat(): the "expected" value is generated by the mock itself.
    /// Real implementations must use vectors from the specification.
    #[test]
    fn kat_plumbing_against_mock() {
        let kek: [u8; MOCK_KEK_LEN] = DUMMY_SEED[..MOCK_KEK_LEN].try_into().unwrap();
        let key = [0x42u8; 4];
        let kek_material =
            KeyMaterial::<MOCK_KEK_LEN>::from_bytes_as_type(&kek, KeyType::SymmetricCipherKey)
                .unwrap();
        let expected: [u8; 16] =
            MockKeyWrapKey::from_key_material(&kek_material).unwrap().wrap_key(&key).unwrap();
        TestFrameworkKeyWrap::new()
            .test_kat::<MOCK_KEK_LEN, 4, 16, MockKeyWrapKey>(&kek, &key, &expected);
    }
}
