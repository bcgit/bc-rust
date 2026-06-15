use bouncycastle_core::errors::AeadError;
use bouncycastle_core::traits::AeadCipher;

/// Shared conformance tests for implementations of the [AeadCipher] trait.
///
/// Because [AeadCipher] does not define a constructor (construction is implementation-specific, and
/// depends on a key/nonce/associated-data context), callers supply two factory closures that each
/// build a fresh cipher: one configured for encryption and one for decryption, both over the *same*
/// key/nonce/associated-data.
pub struct TestFrameworkAead {
    // Put any config options here.
}

impl TestFrameworkAead {
    pub fn new() -> Self {
        Self {}
    }

    /// Exercise the core behaviours of an [AeadCipher] implementation:
    /// encrypt→decrypt round-trip, ciphertext length, byte-at-a-time vs one-shot equivalence, and
    /// rejection of a tampered tag. `new_enc`/`new_dec` must each build a fresh cipher over the same
    /// key/nonce/associated-data.
    pub fn test_aead<C, FE, FD>(&self, new_enc: FE, new_dec: FD, plaintext: &[u8])
    where
        C: AeadCipher,
        FE: Fn() -> C,
        FD: Fn() -> C,
    {
        const TAG_LEN: usize = 16;

        // A fresh encryptor has not computed a tag yet.
        assert_eq!(new_enc().get_mac(), [0u8; TAG_LEN]);

        // --- Encrypt (one-shot) ---
        let mut enc = new_enc();
        let mut ct = vec![0u8; enc.get_output_size(plaintext.len())];
        let n1 = enc.process_bytes(plaintext, &mut ct);
        let n2 = enc.do_final(&mut ct[n1..]).expect("encryption do_final should succeed");
        ct.truncate(n1 + n2);
        assert_eq!(ct.len(), plaintext.len() + TAG_LEN, "ciphertext = plaintext || 16-byte tag");

        // --- Decrypt round-trip ---
        let mut dec = new_dec();
        let mut pt = vec![0u8; dec.get_output_size(ct.len())];
        let m1 = dec.process_bytes(&ct, &mut pt);
        let m2 = dec.do_final(&mut pt[m1..]).expect("decryption do_final should succeed");
        pt.truncate(m1 + m2);
        assert_eq!(pt, plaintext, "round-trip plaintext must match");

        // --- Byte-at-a-time encryption must equal one-shot encryption ---
        let mut enc_chunked = new_enc();
        let mut ct2 = vec![0u8; enc_chunked.get_output_size(plaintext.len())];
        let mut wrote = 0;
        for &b in plaintext {
            wrote += enc_chunked.process_byte(b, &mut ct2[wrote..]);
        }
        wrote += enc_chunked.do_final(&mut ct2[wrote..]).expect("chunked encryption do_final");
        ct2.truncate(wrote);
        assert_eq!(ct2, ct, "byte-at-a-time encryption must match one-shot");

        // --- Tampering with the tag must fail authentication ---
        let mut tampered = ct.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        let mut dec_bad = new_dec();
        let mut pt_bad = vec![0u8; tampered.len()];
        let k1 = dec_bad.process_bytes(&tampered, &mut pt_bad);
        match dec_bad.do_final(&mut pt_bad[k1..]) {
            Err(AeadError::AuthenticationFailed) => { /* expected */ }
            other => panic!("tampered ciphertext should fail authentication, got {other:?}"),
        }
    }
}

impl Default for TestFrameworkAead {
    fn default() -> Self {
        Self::new()
    }
}
