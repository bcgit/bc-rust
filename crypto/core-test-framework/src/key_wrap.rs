//! Generic behaviour tests for the key-wrap traits [`KeyWrapper`] and [`KeyUnwrapper`].

use crate::DUMMY_SEED;
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::key_material::{
    KeyMaterial, KeyMaterialTrait, KeyType, do_hazardous_operations,
};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{KeyUnwrapper, KeyWrapper};
use bouncycastle_utils::secret::Secret;

/// Size of the scratch buffers used for the variable-length APIs.
const BUF_LEN: usize = 1024;

/// Instance of the test framework.
pub struct TestFrameworkKeyWrap {
    // Put any config options here
}

impl TestFrameworkKeyWrap {
    /// Create a new instance of the test framework.
    pub fn new() -> Self {
        Self {}
    }

    /// Test all the members of traits [`KeyWrapper`] and [`KeyUnwrapper`] for one valid
    /// `(KEY_LEN, CT_LEN)` pair, including the error conditions common to all key-wrap algorithms.
    /// This gives good baseline test coverage, but is not a substitute for known-answer tests; see
    /// [`TestFrameworkKeyWrap::test_kat`].
    pub fn test<
        const KEK_LEN: usize,
        const KEY_LEN: usize,
        const CT_LEN: usize,
        W: KeyWrapper<KEK_LEN> + KeyUnwrapper<KEK_LEN>,
    >(
        &self,
    ) {
        assert!(CT_LEN <= BUF_LEN, "test buffers are too small");

        let kek = KeyMaterial::<KEK_LEN>::from_bytes_as_type(
            &DUMMY_SEED[..KEK_LEN],
            KeyType::SymmetricCipherKey,
        )
        .unwrap();
        let key: [u8; KEY_LEN] = DUMMY_SEED[100..100 + KEY_LEN].try_into().unwrap();

        /* Length helpers */

        assert_eq!(W::wrap_out_len(KEY_LEN), CT_LEN);
        let max_pt_len = W::unwrap_out_max_len(CT_LEN);
        assert!(max_pt_len >= KEY_LEN, "unwrap_out_max_len is not an upper bound");
        assert!(max_pt_len < CT_LEN, "a key-wrap ciphertext is longer than its plaintext");
        // documented as saturating, and as never panicking
        assert_eq!(W::unwrap_out_max_len(0), 0);
        let _ = W::unwrap_out_max_len(usize::MAX);
        let _ = W::wrap_out_len(usize::MAX);
        // one semiblock: half the block cipher's block length
        let semiblock_len = CT_LEN - max_pt_len;

        /* Fixed-length API */

        let ct = W::wrap_key::<KEY_LEN, CT_LEN>(&kek, &key).unwrap();

        // wrap_key() and wrap_key_out() agree
        let mut ct_out = [0u8; CT_LEN];
        let bytes_written = W::wrap_key_out(&kek, &key, &mut ct_out).unwrap();
        assert_eq!(bytes_written, CT_LEN);
        assert_eq!(ct, ct_out);

        // key wrapping is deterministic
        assert_eq!(ct, W::wrap_key::<KEY_LEN, CT_LEN>(&kek, &key).unwrap());

        // round trip through unwrap_key() and unwrap_key_out()
        let recovered: Secret<[u8; KEY_LEN]> = W::unwrap_key(&kek, &ct).unwrap();
        assert_eq!(*recovered, key);

        let mut recovered_out = Secret::<[u8; KEY_LEN]>::new();
        let bytes_written = W::unwrap_key_out(&kek, &ct, &mut recovered_out).unwrap();
        assert_eq!(bytes_written, KEY_LEN);
        assert_eq!(*recovered_out, key);

        /* Variable-length API agrees with the fixed-length API */

        let mut buf = [0u8; BUF_LEN];
        let bytes_written = W::wrap_out(&kek, &key, &mut buf[..CT_LEN]).unwrap();
        assert_eq!(bytes_written, CT_LEN);
        assert_eq!(&buf[..CT_LEN], &ct);

        // a larger buffer than needed is fine
        let bytes_written = W::wrap_out(&kek, &key, &mut buf).unwrap();
        assert_eq!(bytes_written, CT_LEN);

        let mut pt = [0u8; BUF_LEN];
        let bytes_written = W::unwrap_out(&kek, &ct, &mut pt[..max_pt_len]).unwrap();
        assert_eq!(bytes_written, KEY_LEN);
        assert_eq!(&pt[..KEY_LEN], &key);

        /* Error case: output buffers too small */

        match W::wrap_out(&kek, &key, &mut buf[..CT_LEN - 1]) {
            Err(SymmetricCipherError::OutputBufferTooSmall(required)) => {
                assert_eq!(required, CT_LEN)
            }
            _ => panic!("Should have rejected a ciphertext buffer that is too small"),
        }
        // checked before any work is done, so it is the upper bound that is enforced, even when
        // the actual plaintext would have fit
        match W::unwrap_out(&kek, &ct, &mut pt[..max_pt_len - 1]) {
            Err(SymmetricCipherError::OutputBufferTooSmall(required)) => {
                assert_eq!(required, max_pt_len)
            }
            _ => panic!("Should have rejected a plaintext buffer that is too small"),
        }

        /* Error case: input lengths the algorithm is not defined on */

        // Every key-wrap algorithm in SP 800-38F (Table 1) needs at least one octet of plaintext
        // and a ciphertext of at least two semiblocks that is a whole number of semiblocks.
        // Empty inputs also catch implementations that subtract before checking the length.
        match W::wrap_out(&kek, &[], &mut buf) {
            Err(SymmetricCipherError::InvalidInputLength(_)) => { /* good */ }
            _ => panic!("Should have rejected an empty plaintext"),
        }
        for bad_ct_len in [0, semiblock_len, CT_LEN - 1] {
            match W::unwrap_out(&kek, &ct[..bad_ct_len], &mut pt) {
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

            match W::unwrap_key::<KEY_LEN, CT_LEN>(&kek, &bad_ct) {
                Err(SymmetricCipherError::DecryptionFailed) => { /* good */ }
                _ => panic!("Should have failed to unwrap a ciphertext modified at byte {i}"),
            }

            // on failure the plaintext buffer is zeroized, not left holding partial output
            pt.fill(0xFF);
            match W::unwrap_out(&kek, &bad_ct, &mut pt) {
                Err(SymmetricCipherError::DecryptionFailed) => { /* good */ }
                _ => panic!("Should have failed to unwrap a ciphertext modified at byte {i}"),
            }
            assert!(pt.iter().all(|b| *b == 0), "plaintext buffer was not zeroized on error");
        }

        /* Error case: wrong KEK */

        let wrong_kek = KeyMaterial::<KEK_LEN>::from_bytes_as_type(
            &DUMMY_SEED[1..KEK_LEN + 1],
            KeyType::SymmetricCipherKey,
        )
        .unwrap();
        match W::unwrap_key::<KEY_LEN, CT_LEN>(&wrong_kek, &ct) {
            Err(SymmetricCipherError::DecryptionFailed) => { /* good */ }
            _ => panic!("Should have failed to unwrap under the wrong KEK"),
        }

        /* Error case: KEK of the wrong type */

        let mac_key =
            KeyMaterial::<KEK_LEN>::from_bytes_as_type(&DUMMY_SEED[..KEK_LEN], KeyType::MACKey)
                .unwrap();
        match W::wrap_key::<KEY_LEN, CT_LEN>(&mac_key, &key) {
            Err(SymmetricCipherError::KeyMaterialError(_)) => { /* good */ }
            _ => panic!("Should have rejected a KEK that is not a SymmetricCipherKey"),
        }
        match W::wrap_out(&mac_key, &key, &mut buf) {
            Err(SymmetricCipherError::KeyMaterialError(_)) => { /* good */ }
            _ => panic!("Should have rejected a KEK that is not a SymmetricCipherKey"),
        }
        match W::unwrap_key::<KEY_LEN, CT_LEN>(&mac_key, &ct) {
            Err(SymmetricCipherError::KeyMaterialError(_)) => { /* good */ }
            _ => panic!("Should have rejected a KEK that is not a SymmetricCipherKey"),
        }
        match W::unwrap_out(&mac_key, &ct, &mut pt) {
            Err(SymmetricCipherError::KeyMaterialError(_)) => { /* good */ }
            _ => panic!("Should have rejected a KEK that is not a SymmetricCipherKey"),
        }

        /* Error case: KEK security strength too weak for the algorithm */

        let mut kek = kek;
        let security_strengths = [
            SecurityStrength::None,
            SecurityStrength::_112bit,
            SecurityStrength::_128bit,
            SecurityStrength::_192bit,
            SecurityStrength::_256bit,
        ];
        for ss in security_strengths.iter() {
            // `set_security_strength` enforces its key-length guard even inside a
            // do_hazardous_operations() closure, so skip the strengths this KEK cannot carry,
            // as the symmetric cipher frameworks do.
            if ss > &SecurityStrength::from_bytes(KEK_LEN) {
                continue;
            }
            do_hazardous_operations(&mut kek, |kek| kek.set_security_strength(*ss)).unwrap();

            let strong_enough = ss >= &W::MAX_SECURITY_STRENGTH;
            match W::wrap_key::<KEY_LEN, CT_LEN>(&kek, &key) {
                Ok(_) => assert!(
                    strong_enough,
                    "Should not have accepted a KEK weaker than the algorithm"
                ),
                Err(SymmetricCipherError::KeyMaterialError(_)) => {
                    assert!(!strong_enough, "Should have accepted a strong enough KEK")
                }
                _ => panic!("Unexpected error"),
            }
            match W::unwrap_key::<KEY_LEN, CT_LEN>(&kek, &ct) {
                Ok(_) => assert!(
                    strong_enough,
                    "Should not have accepted a KEK weaker than the algorithm"
                ),
                Err(SymmetricCipherError::KeyMaterialError(_)) => {
                    assert!(!strong_enough, "Should have accepted a strong enough KEK")
                }
                _ => panic!("Unexpected error"),
            }
        }
    }

    /// Known-answer test: checks that wrapping `key` under `kek` gives `expected_ct` through both
    /// the fixed-length and variable-length APIs, and that unwrapping `expected_ct` gives back `key`.
    /// Test vectors must come from the specification or its official companion files, for example
    /// RFC 3394 Section 4 or RFC 5649 Section 6.
    pub fn test_kat<
        const KEK_LEN: usize,
        const KEY_LEN: usize,
        const CT_LEN: usize,
        W: KeyWrapper<KEK_LEN> + KeyUnwrapper<KEK_LEN>,
    >(
        &self,
        kek: &[u8; KEK_LEN],
        key: &[u8; KEY_LEN],
        expected_ct: &[u8; CT_LEN],
    ) {
        let kek =
            KeyMaterial::<KEK_LEN>::from_bytes_as_type(kek, KeyType::SymmetricCipherKey).unwrap();

        let ct = W::wrap_key::<KEY_LEN, CT_LEN>(&kek, key).unwrap();
        assert_eq!(&ct, expected_ct);

        let recovered: Secret<[u8; KEY_LEN]> = W::unwrap_key(&kek, expected_ct).unwrap();
        assert_eq!(&*recovered, key);

        let mut buf = [0u8; BUF_LEN];
        let bytes_written = W::wrap_out(&kek, key, &mut buf).unwrap();
        assert_eq!(&buf[..bytes_written], expected_ct);

        let bytes_written = W::unwrap_out(&kek, expected_ct, &mut buf).unwrap();
        assert_eq!(&buf[..bytes_written], key);
    }
}

#[cfg(test)]
mod tests {
    //! Exercises the framework itself against a mock implementation, so that the framework is known
    //! to compile and pass before any real key-wrap algorithm exists.

    use super::*;
    use bouncycastle_core::errors::KeyMaterialError;
    use bouncycastle_core::traits::Algorithm;

    /// NOT CRYPTOGRAPHY. A stand-in with the same length behaviour as KWP (SP 800-38F, Sec. 6.3),
    /// which satisfies the documented contract of the key-wrap traits. It builds
    /// `S = [len(P)]32 || checksum32(kek || P) || P || zero padding` to a multiple of 8 bytes, and
    /// XORs `S` with the repeated KEK.
    struct MockKeyWrap;

    const MOCK_KEK_LEN: usize = 16;
    const MOCK_SEMIBLOCK_LEN: usize = 8;

    impl Algorithm for MockKeyWrap {
        const ALG_NAME: &'static str = "MockKeyWrap-NOT-CRYPTOGRAPHY";
        const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
    }

    fn check_kek(kek: &KeyMaterial<MOCK_KEK_LEN>) -> Result<(), SymmetricCipherError> {
        if kek.key_type() != KeyType::SymmetricCipherKey {
            Err(KeyMaterialError::InvalidKeyType("KEK must be a SymmetricCipherKey"))?
        }
        if kek.security_strength() < MockKeyWrap::MAX_SECURITY_STRENGTH {
            Err(KeyMaterialError::SecurityStrength("KEK is weaker than the algorithm"))?
        }
        Ok(())
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

    impl KeyWrapper<MOCK_KEK_LEN> for MockKeyWrap {
        fn wrap_key_out<const KEY_LEN: usize, const CT_LEN: usize>(
            kek: &KeyMaterial<MOCK_KEK_LEN>,
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
            Self::wrap_out(kek, key, ciphertext)
        }

        fn wrap_out_len(plaintext_len: usize) -> usize {
            plaintext_len
                .div_ceil(MOCK_SEMIBLOCK_LEN)
                .saturating_mul(MOCK_SEMIBLOCK_LEN)
                .saturating_add(MOCK_SEMIBLOCK_LEN)
        }

        fn wrap_out(
            kek: &KeyMaterial<MOCK_KEK_LEN>,
            plaintext: &[u8],
            ciphertext: &mut [u8],
        ) -> Result<usize, SymmetricCipherError> {
            let ct_len = Self::wrap_out_len(plaintext.len());
            if ciphertext.len() < ct_len {
                return Err(SymmetricCipherError::OutputBufferTooSmall(ct_len));
            }
            check_kek(kek)?;
            if plaintext.is_empty() || plaintext.len() > u32::MAX as usize {
                return Err(SymmetricCipherError::InvalidInputLength("plaintext length"));
            }
            let kek = kek.ref_to_bytes();
            let s = &mut ciphertext[..ct_len];
            s.fill(0);
            s[..4].copy_from_slice(&(plaintext.len() as u32).to_be_bytes());
            s[4..8].copy_from_slice(&checksum(kek, plaintext));
            s[8..8 + plaintext.len()].copy_from_slice(plaintext);
            xor_with_kek(kek, s);
            Ok(ct_len)
        }
    }

    impl KeyUnwrapper<MOCK_KEK_LEN> for MockKeyWrap {
        fn unwrap_key_out<const KEY_LEN: usize, const CT_LEN: usize>(
            kek: &KeyMaterial<MOCK_KEK_LEN>,
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
            let pt_len = Self::unwrap_out(kek, ciphertext, &mut scratch[..])?;
            if pt_len != KEY_LEN {
                return Err(SymmetricCipherError::DecryptionFailed);
            }
            key.copy_from_slice(&scratch[..KEY_LEN]);
            Ok(KEY_LEN)
        }

        fn unwrap_out_max_len(ciphertext_len: usize) -> usize {
            ciphertext_len.saturating_sub(MOCK_SEMIBLOCK_LEN)
        }

        fn unwrap_out(
            kek: &KeyMaterial<MOCK_KEK_LEN>,
            ciphertext: &[u8],
            plaintext: &mut [u8],
        ) -> Result<usize, SymmetricCipherError> {
            let max_pt_len = Self::unwrap_out_max_len(ciphertext.len());
            if plaintext.len() < max_pt_len {
                return Err(SymmetricCipherError::OutputBufferTooSmall(max_pt_len));
            }
            plaintext.fill(0);
            check_kek(kek)?;
            if ciphertext.len() < 2 * MOCK_SEMIBLOCK_LEN
                || !ciphertext.len().is_multiple_of(MOCK_SEMIBLOCK_LEN)
            {
                return Err(SymmetricCipherError::InvalidInputLength("ciphertext length"));
            }
            let kek = kek.ref_to_bytes();

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
        tf.test::<MOCK_KEK_LEN, 16, 24, MockKeyWrap>();
        tf.test::<MOCK_KEK_LEN, 13, 24, MockKeyWrap>();
        tf.test::<MOCK_KEK_LEN, 1, 16, MockKeyWrap>();
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
        let expected: [u8; 16] = MockKeyWrap::wrap_key(&kek_material, &key).unwrap();
        TestFrameworkKeyWrap::new()
            .test_kat::<MOCK_KEK_LEN, 4, 16, MockKeyWrap>(&kek, &key, &expected);
    }
}
