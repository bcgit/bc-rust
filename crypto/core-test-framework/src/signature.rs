use crate::DUMMY_SEED_1024;
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{
    Hash, PHSignature, Signature, SignaturePrivateKey, SignaturePublicKey,
};

pub struct TestFrameworkSignature {
    // Put any config options here
    /// Should the test framework expect that repeated calls to sign() will produce the same signature?
    alg_is_deterministic: bool,

    /// Does the signature algorithm use the provided context parameter? (false means that it is expected to ignore it)
    alg_accepts_ctx: bool,
}

impl TestFrameworkSignature {
    pub fn new(alg_is_deterministic: bool, alg_accepts_ctx: bool) -> Self {
        Self { alg_is_deterministic, alg_accepts_ctx }
    }

    /// Test all the members of trait Hash against the given input-output pair.
    /// This gives good baseline test coverage, but is not exhaustive.
    pub fn test_signature<
        PK: SignaturePublicKey<PK_LEN>,
        SK: SignaturePrivateKey<SK_LEN>,
        SigAlg: Signature<PK, SK, PK_LEN, SK_LEN, SIG_LEN>,
        const PK_LEN: usize,
        const SK_LEN: usize,
        const SIG_LEN: usize,
    >(
        &self,
        run_full_bitflipping_tests: bool,
    ) {
        let msg = b"The quick brown fox jumped over the lazy dog";

        // Basic test
        let (pk, sk) = SigAlg::keygen().unwrap();
        let sig_val = SigAlg::sign(&sk, msg, None).unwrap();
        SigAlg::verify(&pk, msg, None, &sig_val).unwrap();

        // Test non-determinism
        if !self.alg_is_deterministic {
            let sig1 = SigAlg::sign(&sk, msg, None).unwrap();
            let sig2 = SigAlg::sign(&sk, msg, None).unwrap();
            assert_ne!(sig1, sig2);
        }

        // uses ctx
        // success case
        let sig = SigAlg::sign(&sk, msg, Some(b"test with ctx")).unwrap();
        SigAlg::verify(&pk, msg, Some(b"test with ctx"), &sig).unwrap();

        // but it had better produce something different
        if !self.alg_accepts_ctx {
            let sig1 = SigAlg::sign(&sk, msg, None).unwrap();
            let sig2 = SigAlg::sign(&sk, msg, Some(&[0u8; 1])).unwrap();
            assert_ne!(sig1, sig2);
        }

        // Test that verification fails for broken signature value
        let (pk, sk) = SigAlg::keygen().unwrap();
        let sig_val = SigAlg::sign(&sk, msg, None).unwrap();

        // spot-check
        let mut sig_val_copy = sig_val.clone();
        sig_val_copy[8] ^= 0x0F;
        // should throw an Err
        match SigAlg::verify(&pk, msg, None, &sig_val_copy) {
            Err(SignatureError::SignatureVerificationFailed) => (),
            _ => panic!("This should have thrown an error but it didn't."),
        }

        // test flipping every bit ... this will take some time to run
        if run_full_bitflipping_tests {
            for i in 0..sig_val.len() {
                for j in 0..8 {
                    let mut sig_val_copy = sig_val.clone();
                    sig_val_copy[i] ^= 1 << j;

                    // should throw an Err
                    match SigAlg::verify(&pk, msg, None, &sig_val_copy) {
                        Err(SignatureError::SignatureVerificationFailed) => (),
                        _ => panic!(
                            "This should have thrown an error but it didn't when byte {i} bit {j} of the signature was flipped"
                        ),
                    }
                }
            }
        }

        // test the sign_out interface
        // fn sign_out(sk: &SK, msg: &[u8], ctx: &[u8], output: &mut [u8]) -> Result<usize, SignatureError>;

        // Success case
        let mut output = [0u8; SIG_LEN];
        let bytes_written = SigAlg::sign_out(&sk, msg, None, &mut output).unwrap();
        assert_eq!(bytes_written, SIG_LEN);
        SigAlg::verify(&pk, msg, None, &sig_val).unwrap();

        // test with a large message
        let sig = SigAlg::sign(&sk, DUMMY_SEED_1024, None).unwrap();
        SigAlg::verify(&pk, DUMMY_SEED_1024, None, &sig).unwrap();

        // Test the streaming signing API
        // fn sign_init(&mut self, sk: &SK) -> Result<(), SignatureError>;
        // fn sign_update(&mut self, msg_chunk: &[u8]);
        // fn sign_final(&mut self, msg_chunk: &[u8], ctx: &[u8]) -> Result<Vec<u8>, SignatureError>;
        // fn sign_final_out(&mut self, msg_chunk: &[u8], ctx: &[u8], output: &mut [u8]) -> Result<(), SignatureError>;

        // First, test the streaming API with one call to .sign_update
        let mut s = SigAlg::sign_init(&sk, Some(b"streaming API")).unwrap();
        s.sign_update(DUMMY_SEED_1024);
        let sig_val = s.sign_final().unwrap();
        SigAlg::verify(&pk, DUMMY_SEED_1024, Some(b"streaming API"), &sig_val).unwrap();

        // Then with the message broken into chunks
        let mut s = SigAlg::sign_init(&sk, Some(b"streaming API chunked")).unwrap();
        for msg_chunk in DUMMY_SEED_1024.chunks(100) {
            s.sign_update(msg_chunk);
        }
        let sig_val = s.sign_final().unwrap();
        SigAlg::verify(&pk, DUMMY_SEED_1024, Some(b"streaming API chunked"), &sig_val).unwrap();

        // Test the streaming verification API
        // one-shot
        let sig = SigAlg::sign(&sk, DUMMY_SEED_1024, Some(b"streaming API")).unwrap();
        let mut v = SigAlg::verify_init(&pk, Some(b"streaming API")).unwrap();
        v.verify_update(DUMMY_SEED_1024);
        v.verify_final(&sig).unwrap();

        // chunked
        let sig = SigAlg::sign(&sk, DUMMY_SEED_1024, Some(b"streaming API")).unwrap();
        let mut v = SigAlg::verify_init(&pk, Some(b"streaming API")).unwrap();
        for msg_chunk in DUMMY_SEED_1024.chunks(100) {
            v.verify_update(msg_chunk);
        }
        v.verify_final(&sig).unwrap();

        // failure case for streaming verify
        let sig = SigAlg::sign(&sk, DUMMY_SEED_1024, Some(b"streaming API")).unwrap();
        let mut v = SigAlg::verify_init(&pk, Some(b"streaming API")).unwrap();
        v.verify_update(b"this is the wrong message");
        match v.verify_final(&sig) {
            Err(SignatureError::SignatureVerificationFailed) => (),
            _ => panic!("This should have thrown an error but it didn't."),
        }

        // test sign_out version of streaming API
        let mut s = SigAlg::sign_init(&sk, Some(b"streaming API")).unwrap();
        s.sign_update(DUMMY_SEED_1024);
        let mut sig_val = [0u8; SIG_LEN];
        let bytes_written = s.sign_final_out(&mut sig_val).unwrap();
        assert_eq!(bytes_written, SIG_LEN);
        SigAlg::verify(&pk, DUMMY_SEED_1024, Some(b"streaming API"), &sig_val).unwrap();

        // the ::verify API should accept a sig value that's too long and just ignore the extra bytes
        let mut sig_val_too_long = vec![1u8; SIG_LEN + 2];
        sig_val_too_long[..SIG_LEN].copy_from_slice(&sig_val);
        SigAlg::verify(&pk, DUMMY_SEED_1024, Some(b"streaming API"), &sig_val).unwrap();
    }

    /// Test all the members of trait Hash against the given input-output pair.
    /// This gives good baseline test coverage, but is not exhaustive.
    pub fn test_ph_signature<
        PK: SignaturePublicKey<PK_LEN>,
        SK: SignaturePrivateKey<SK_LEN>,
        SigAlg: PHSignature<PK, SK, PK_LEN, SK_LEN, SIG_LEN, PH_LEN>,
        HASH: Hash + Default,
        const PK_LEN: usize,
        const SK_LEN: usize,
        const SIG_LEN: usize,
        const PH_LEN: usize,
    >(
        &self,
        run_full_bitflipping_tests: bool,
    ) {
        let msg = b"The quick brown fox jumped over the lazy dog";

        // Basic test
        let (pk, sk) = SigAlg::keygen().unwrap();
        let sig_val = SigAlg::sign(&sk, msg, None).unwrap();
        SigAlg::verify(&pk, msg, None, &sig_val).unwrap();

        // Test non-determinism
        if !self.alg_is_deterministic {
            let sig1 = SigAlg::sign(&sk, msg, None).unwrap();
            let sig2 = SigAlg::sign(&sk, msg, None).unwrap();
            assert_ne!(sig1, sig2);
        }

        // uses ctx
        // success case
        let sig = SigAlg::sign(&sk, msg, Some(b"test with ctx")).unwrap();
        SigAlg::verify(&pk, msg, Some(b"test with ctx"), &sig).unwrap();

        // but it had better produce something different
        if !self.alg_accepts_ctx {
            let sig1 = SigAlg::sign(&sk, msg, None).unwrap();
            let sig2 = SigAlg::sign(&sk, msg, Some(&[0u8; 1])).unwrap();
            assert_ne!(sig1, sig2);
        }

        // Test that verification fails for broken signature value
        let (pk, sk) = SigAlg::keygen().unwrap();
        let sig_val = SigAlg::sign(&sk, msg, None).unwrap();

        // spot-check
        let mut sig_val_copy = sig_val.clone();
        sig_val_copy[8] ^= 0x0F;
        // should throw an Err
        match SigAlg::verify(&pk, msg, None, &sig_val_copy) {
            Err(SignatureError::SignatureVerificationFailed) => (),
            _ => panic!("This should have thrown an error but it didn't."),
        }

        // test flipping every bit ... this will take some time to run
        if run_full_bitflipping_tests {
            for i in 0..sig_val.len() {
                for j in 0..8 {
                    let mut sig_val_copy = sig_val.clone();
                    sig_val_copy[i] ^= 1 << j;

                    // should throw an Err
                    match SigAlg::verify(&pk, msg, None, &sig_val_copy) {
                        Err(SignatureError::SignatureVerificationFailed) => (),
                        _ => panic!(
                            "This should have thrown an error but it didn't when byte {i} bit {j} of the signature was flipped"
                        ),
                    }
                }
            }
        }

        // test the sign_out interface
        // fn sign_out(sk: &SK, msg: &[u8], ctx: &[u8], output: &mut [u8]) -> Result<usize, SignatureError>;

        // Success case
        let mut output = [0u8; SIG_LEN];
        let bytes_written = SigAlg::sign_out(&sk, msg, None, &mut output).unwrap();
        assert_eq!(bytes_written, SIG_LEN);
        SigAlg::verify(&pk, msg, None, &sig_val).unwrap();

        // test with a large message
        let sig = SigAlg::sign(&sk, DUMMY_SEED_1024, None).unwrap();
        SigAlg::verify(&pk, DUMMY_SEED_1024, None, &sig).unwrap();

        // the ::verify API should not accept a sig value that's too
        let mut sig_val_too_long = vec![1u8; SIG_LEN + 2];
        sig_val_too_long[..SIG_LEN].copy_from_slice(&sig);
        match SigAlg::verify(&pk, DUMMY_SEED_1024, None, &sig_val_too_long) {
            Err(SignatureError::LengthError(_)) => (),
            _ => panic!("Unexpected error"),
        }

        // sign_ph
        let (pk, sk) = SigAlg::keygen().unwrap();
        let mut ph = [0u8; PH_LEN];
        HASH::default().hash_out(msg, &mut ph);
        let sig_val = SigAlg::sign_ph(&sk, &ph, None).unwrap();
        SigAlg::verify(&pk, msg, None, &sig_val).unwrap();
        SigAlg::verify_ph(&pk, &ph, None, &sig_val).unwrap();

        // sign_ph_out
        let (pk, sk) = SigAlg::keygen().unwrap();
        let mut ph = [0u8; PH_LEN];
        HASH::default().hash_out(msg, &mut ph);
        let mut sig_val = [0u8; SIG_LEN];
        let bytes_written = SigAlg::sign_ph_out(&sk, &ph, None, &mut sig_val).unwrap();
        assert_eq!(bytes_written, SIG_LEN);
        SigAlg::verify_ph(&pk, &ph, None, &sig_val).unwrap();
        SigAlg::verify(&pk, msg, None, &sig_val).unwrap();
    }
}

pub struct TestFrameworkSignatureKeys {}

impl TestFrameworkSignatureKeys {
    pub fn new() -> Self {
        Self {}
    }

    pub fn test_keys<
        PK: SignaturePublicKey<PK_LEN>,
        SK: SignaturePrivateKey<SK_LEN>,
        SigAlg: Signature<PK, SK, PK_LEN, SK_LEN, SIG_LEN>,
        const PK_LEN: usize,
        const SK_LEN: usize,
        const SIG_LEN: usize,
    >(
        &self,
    ) {
        self.test_boundary_conditions::<PK, SK, SigAlg, PK_LEN, SK_LEN, SIG_LEN>();
    }

    /// Tests the correct behaviour on buffers too large / too small.
    fn test_boundary_conditions<
        PK: SignaturePublicKey<PK_LEN>,
        SK: SignaturePrivateKey<SK_LEN>,
        SigAlg: Signature<PK, SK, PK_LEN, SK_LEN, SIG_LEN>,
        const PK_LEN: usize,
        const SK_LEN: usize,
        const SIG_LEN: usize,
    >(
        &self,
    ) {
        let (pk, sk) = SigAlg::keygen().unwrap();

        let pk_bytes = pk.encode();
        assert_eq!(pk_bytes.len(), PK_LEN);
        // too short
        match PK::from_bytes(&pk_bytes[..PK_LEN - 1]) {
            Err(SignatureError::DecodingError(_)) => { /* good */ }
            _ => panic!("Should have failed"),
        }
        // too long
        let mut bytes_too_long: Vec<u8> = Vec::with_capacity(PK_LEN + 1);
        bytes_too_long.append(&mut Vec::from(&pk_bytes[..PK_LEN]));
        bytes_too_long.push(0xFF);
        match PK::from_bytes(&bytes_too_long) {
            Err(SignatureError::DecodingError(_)) => { /* good */ }
            _ => panic!("Should have failed"),
        }

        let sk_bytes = sk.encode();
        assert_eq!(sk_bytes.len(), SK_LEN);
        // too short
        match SK::from_bytes(&sk_bytes[..SK_LEN - 1]) {
            Err(SignatureError::DecodingError(_)) => { /* good */ }
            _ => panic!("Should have failed"),
        }
        // too long
        let mut bytes_too_long: Vec<u8> = Vec::with_capacity(SK_LEN + 1);
        bytes_too_long.append(&mut Vec::from(&sk_bytes[..SK_LEN]));
        bytes_too_long.push(0xFF);
        match SK::from_bytes(&bytes_too_long) {
            Err(SignatureError::DecodingError(_)) => { /* good */ }
            _ => panic!("Should have failed"),
        }
    }
}
