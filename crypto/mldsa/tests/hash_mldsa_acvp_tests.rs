//! NIST ACVP known-answer tests for HashML-DSA: `ML-DSA-sigGen-preHash.txt` and
//! `ML-DSA-sigVer-preHash.txt`, which pair each of twelve hashes with each parameter set.
//!
//! A pairing whose hash is weaker than the parameter set runs through `hazmat::AnyStrength`,
//! after a check that the bare hash is refused. A pairing FIPS 204 Section 5.4 allows runs both
//! ways, so the wrapper is also held to the known answers where it is not needed.
//!
//! Vectors are read from the bc-test-data repo (https://github.com/bcgit/bc-test-data), which must be
//! cloned alongside this repo at "../bc-test-data", under `pqc/crypto/mldsa/`. If it is not
//! present the tests print a warning and pass vacuously.

use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::hazmat::FixedSeedRNG;
use bouncycastle_core::signature_key::{
    DeterministicPreHashSigningKey, PreHash, PreHashAlgorithm, PreHashSigningKey,
    PreHashVerifyingKey,
};
use bouncycastle_core::traits::{
    Algorithm, CollisionResistantHash, HashOneShot, PrivateKey, PublicKey, SignatureSigner,
    SignatureVerifier,
};
use bouncycastle_core_test_framework::test_data_loaders::bc_test_data;
use bouncycastle_hex as hex;
use bouncycastle_mldsa::hazmat::AnyStrength;
use bouncycastle_mldsa::{
    MLDSA, MLDSA44_PK_LEN, MLDSA44_SIG_LEN, MLDSA44_SK_LEN, MLDSA44Params, MLDSA65_PK_LEN,
    MLDSA65_SIG_LEN, MLDSA65_SK_LEN, MLDSA65Params, MLDSA87_PK_LEN, MLDSA87_SIG_LEN,
    MLDSA87_SK_LEN, MLDSA87Params, MLDSAPrivateKey, MLDSAPrivateKeyTrait, MLDSAPublicKey,
    PrivateKeyLen, PublicKeyLen, SignatureLen,
};
use bouncycastle_sha2::{SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256};
use bouncycastle_sha3::{SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256};
use std::collections::BTreeMap;

const TEST_DATA_DIR: &str = "pqc/crypto/mldsa";

/// The `hashAlg` values of the files, each of which occurs with each parameter set.
const HASH_ALGS: [&str; 12] = [
    "SHA2-224", "SHA2-256", "SHA2-384", "SHA2-512", "SHA2-512/224", "SHA2-512/256", "SHA3-224",
    "SHA3-256", "SHA3-384", "SHA3-512", "SHAKE-128", "SHAKE-256",
];
const PARAMETER_SETS: [&str; 3] = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"];

/// One `key = value` record of a vector file.
struct Record(BTreeMap<String, String>);

impl Record {
    fn str(&self, field: &str) -> &str {
        self.0.get(field).unwrap_or_else(|| panic!("a record has no {field}: {:?}", self.0.keys()))
    }

    fn hex(&self, field: &str) -> Vec<u8> {
        hex::decode(self.str(field))
            .unwrap_or_else(|_| panic!("tcId {}: bad hex in {field}", self.str("tcId")))
    }

    fn flag(&self, field: &str) -> bool {
        self.str(field).parse().unwrap_or_else(|_| panic!("tcId {}: {field}", self.str("tcId")))
    }

    fn pairing(&self) -> String {
        format!("{} with {}", self.str("parameterSet"), self.str("hashAlg"))
    }

    fn id(&self) -> String {
        format!("tcId {} ({})", self.str("tcId"), self.pairing())
    }
}

/// Records are separated by blank lines; `#` starts a comment. A value may be empty (`context`).
fn parse(contents: &str) -> Vec<Record> {
    let mut records = Vec::new();
    let mut fields = BTreeMap::new();
    for line in contents.lines().chain([""]) {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if line.is_empty() {
            if !fields.is_empty() {
                records.push(Record(core::mem::take(&mut fields)));
            }
            continue;
        }
        let (tag, value) = line.split_once('=').unwrap_or_else(|| panic!("not a field: {line}"));
        let repeated = fields.insert(tag.trim().to_string(), value.trim().to_string());
        assert!(repeated.is_none(), "{tag} occurs twice in one record");
    }
    records
}

/// How the records of one file were run, per pairing.
#[derive(Default)]
struct Tally {
    /// Records run through `AnyStrength<H>`: all of them.
    wrapped: usize,
    /// Records also run with the bare hash, which the pairing allows.
    bare: usize,
    /// Records whose bare hash was refused as too weak.
    refused: usize,
}

type Tallies = BTreeMap<String, Tally>;

/// Every pairing occurs, every record ran through the wrapper, and each ran or was refused with
/// the bare hash; `weak` is the number of records with a pairing FIPS 204 Section 5.4 rules out.
fn check_tallies(file: &str, tallies: &Tallies, records: usize, weak: usize) {
    println!("{file}: {records} records");
    println!("  {:<28} {:>7} {:>5} {:>8}", "pairing", "wrapped", "bare", "refused");
    for (pairing, t) in tallies {
        println!("  {pairing:<28} {:>7} {:>5} {:>8}", t.wrapped, t.bare, t.refused);
    }
    for set in PARAMETER_SETS {
        for hash in HASH_ALGS {
            assert!(tallies.contains_key(&format!("{set} with {hash}")), "no {set} with {hash}");
        }
    }
    assert_eq!(tallies.len(), PARAMETER_SETS.len() * HASH_ALGS.len());
    let total = |f: fn(&Tally) -> usize| tallies.values().map(f).sum::<usize>();
    println!(
        "  total: {} wrapped, {} bare, {} refused bare",
        total(|t| t.wrapped),
        total(|t| t.bare),
        total(|t| t.refused)
    );
    assert_eq!(total(|t| t.wrapped), records);
    assert_eq!(total(|t| t.refused), weak);
    assert_eq!(total(|t| t.bare), records - weak);
}

/* sigGen */

/// Signs the record's message with a HashML-DSA key pair, by the one-shots over the digest and
/// the message and by the streaming signer, and checks each against the record's signature,
/// which must then verify.
fn sign_as<A, PK, SK, const SIG_LEN: usize>(rec: &Record, pk: &PK, sk: &SK)
where
    A: PreHashAlgorithm,
    A::Hash: CollisionResistantHash,
    PK: PreHashVerifyingKey<A, SIG_LEN>,
    SK: PreHashSigningKey<A, SIG_LEN> + DeterministicPreHashSigningKey<A, SIG_LEN>,
{
    let (msg, ctx, expected) = (rec.hex("message"), rec.hex("context"), rec.hex("signature"));
    let ctx = Some(ctx.as_slice());
    let ph = A::Hash::hash(&msg);

    let (over_digest, over_message, streamed) = if rec.flag("deterministic") {
        let mut signer = sk.create_signer_deterministic(ctx).unwrap();
        signer.do_update(&msg);
        (
            sk.sign_ph_deterministic(&ph, ctx).unwrap(),
            sk.sign_deterministic(&msg, ctx).unwrap(),
            signer.do_final().unwrap(),
        )
    } else {
        // The hedged variant draws rnd, 32 bytes, from the RNG: the record's `rnd`.
        let rnd = rec.hex("rnd");
        let mut signer = sk.create_signer(&mut FixedSeedRNG::new(&rnd), ctx).unwrap();
        signer.do_update(&msg);
        (
            sk.sign_ph(&mut FixedSeedRNG::new(&rnd), &ph, ctx).unwrap(),
            sk.sign(&mut FixedSeedRNG::new(&rnd), &msg, ctx).unwrap(),
            signer.do_final().unwrap(),
        )
    };
    assert_eq!(over_digest.as_slice(), expected, "sigGen {}: one-shot over the digest", rec.id());
    assert_eq!(over_message.as_slice(), expected, "sigGen {}: one-shot", rec.id());
    assert_eq!(streamed.as_slice(), expected, "sigGen {}: streaming", rec.id());

    pk.verify_ph(&ph, ctx, &expected)
        .unwrap_or_else(|e| panic!("sigGen {}: verify_ph: {e:?}", rec.id()));
    let mut verifier = pk.create_verifier(ctx).unwrap();
    verifier.do_update(&msg);
    verifier
        .do_verify_final(&expected)
        .unwrap_or_else(|e| panic!("sigGen {}: streaming verify: {e:?}", rec.id()));
}

/// The key over the bare hash refuses at each signing entry point.
fn sign_is_refused<A, SK, const SIG_LEN: usize>(rec: &Record, sk: &SK)
where
    A: PreHashAlgorithm,
    A::Hash: CollisionResistantHash,
    SK: PreHashSigningKey<A, SIG_LEN> + DeterministicPreHashSigningKey<A, SIG_LEN>,
{
    let msg = rec.hex("message");
    let ph = A::Hash::hash(&msg);
    let mut rng = FixedSeedRNG::new([0u8; 32]);
    let too_weak = Err(SignatureError::PreHashTooWeak);
    assert_eq!(sk.sign_ph_deterministic(&ph, None), too_weak, "sigGen {}", rec.id());
    assert_eq!(sk.sign_ph(&mut rng, &ph, None), too_weak, "sigGen {}", rec.id());
    assert_eq!(sk.sign_deterministic(&msg, None), too_weak, "sigGen {}", rec.id());
    assert_eq!(sk.sign(&mut rng, &msg, None), too_weak, "sigGen {}", rec.id());
    assert!(
        matches!(sk.create_signer_deterministic(None), Err(SignatureError::PreHashTooWeak)),
        "sigGen {}",
        rec.id()
    );
    assert!(
        matches!(sk.create_signer(&mut rng, None), Err(SignatureError::PreHashTooWeak)),
        "sigGen {}",
        rec.id()
    );
}

/// One record under the hash `H`: through `AnyStrength`, and with the bare hash, which signs or
/// is refused as FIPS 204 Section 5.4 has it for the parameter set `P`.
fn sig_gen_with<P, H, const SIG_LEN: usize>(
    rec: &Record,
    pk: &MLDSAPublicKey<P>,
    sk: &MLDSAPrivateKey<P>,
    tally: &mut Tally,
) where
    P: SignatureLen<SIG_LEN>,
    H: PreHash + CollisionResistantHash,
{
    sign_as(rec, &pk.as_prehash::<AnyStrength<H>>(), &sk.as_prehash::<AnyStrength<H>>());
    tally.wrapped += 1;
    if H::MAX_SECURITY_STRENGTH < MLDSA::<P>::MAX_SECURITY_STRENGTH {
        sign_is_refused(rec, &sk.as_prehash::<H>());
        tally.refused += 1;
    } else {
        sign_as(rec, &pk.as_prehash::<H>(), &sk.as_prehash::<H>());
        tally.bare += 1;
    }
}

/// One record under the parameter set `P`, by its `hashAlg`.
fn sig_gen<P, const SK_LEN: usize, const SIG_LEN: usize>(rec: &Record, tally: &mut Tally)
where
    P: PrivateKeyLen<SK_LEN> + SignatureLen<SIG_LEN>,
{
    let sk = MLDSAPrivateKey::<P>::from_bytes(&rec.hex("sk")).unwrap();
    let pk = sk.derive_pk();
    match rec.str("hashAlg") {
        "SHA2-224" => sig_gen_with::<P, SHA224, SIG_LEN>(rec, &pk, &sk, tally),
        "SHA2-256" => sig_gen_with::<P, SHA256, SIG_LEN>(rec, &pk, &sk, tally),
        "SHA2-384" => sig_gen_with::<P, SHA384, SIG_LEN>(rec, &pk, &sk, tally),
        "SHA2-512" => sig_gen_with::<P, SHA512, SIG_LEN>(rec, &pk, &sk, tally),
        "SHA2-512/224" => sig_gen_with::<P, SHA512_224, SIG_LEN>(rec, &pk, &sk, tally),
        "SHA2-512/256" => sig_gen_with::<P, SHA512_256, SIG_LEN>(rec, &pk, &sk, tally),
        "SHA3-224" => sig_gen_with::<P, SHA3_224, SIG_LEN>(rec, &pk, &sk, tally),
        "SHA3-256" => sig_gen_with::<P, SHA3_256, SIG_LEN>(rec, &pk, &sk, tally),
        "SHA3-384" => sig_gen_with::<P, SHA3_384, SIG_LEN>(rec, &pk, &sk, tally),
        "SHA3-512" => sig_gen_with::<P, SHA3_512, SIG_LEN>(rec, &pk, &sk, tally),
        "SHAKE-128" => sig_gen_with::<P, SHAKE128, SIG_LEN>(rec, &pk, &sk, tally),
        "SHAKE-256" => sig_gen_with::<P, SHAKE256, SIG_LEN>(rec, &pk, &sk, tally),
        other => panic!("sigGen {}: unknown hashAlg {other}", rec.id()),
    }
}

#[test]
#[allow(non_snake_case)]
fn ML_DSA_sigGen_preHash() {
    let file = "ML-DSA-sigGen-preHash.txt";
    let Some(contents) = bc_test_data(TEST_DATA_DIR, file) else { return };
    let records = parse(&contents);
    assert_eq!(records.len(), 90, "{file} has 90 records");

    let mut tallies = Tallies::new();
    for rec in &records {
        let tally = tallies.entry(rec.pairing()).or_default();
        match rec.str("parameterSet") {
            "ML-DSA-44" => sig_gen::<MLDSA44Params, MLDSA44_SK_LEN, MLDSA44_SIG_LEN>(rec, tally),
            "ML-DSA-65" => sig_gen::<MLDSA65Params, MLDSA65_SK_LEN, MLDSA65_SIG_LEN>(rec, tally),
            "ML-DSA-87" => sig_gen::<MLDSA87Params, MLDSA87_SK_LEN, MLDSA87_SIG_LEN>(rec, tally),
            other => panic!("sigGen {}: unknown parameterSet {other}", rec.id()),
        }
    }
    // 44 of the 90 records pair a hash with a parameter set stronger than it.
    check_tallies(file, &tallies, 90, 44);
}

/* sigVer */

/// Verifies the record's signature with a HashML-DSA public key, by the one-shots over the
/// digest and the message and by the streaming verifier, and checks each against `testPassed`.
fn verify_as<A, PK, const SIG_LEN: usize>(rec: &Record, pk: &PK)
where
    A: PreHashAlgorithm,
    PK: PreHashVerifyingKey<A, SIG_LEN>,
{
    let (msg, ctx, sig) = (rec.hex("message"), rec.hex("context"), rec.hex("signature"));
    let ctx = Some(ctx.as_slice());
    let expected = if rec.flag("testPassed") {
        Ok(())
    } else {
        Err(SignatureError::SignatureVerificationFailed)
    };

    assert_eq!(pk.verify_ph(&A::Hash::hash(&msg), ctx, &sig), expected, "sigVer {}", rec.id());
    assert_eq!(pk.verify(&msg, ctx, &sig), expected, "sigVer {}: one-shot", rec.id());
    let mut verifier = pk.create_verifier(ctx).unwrap();
    verifier.do_update(&msg);
    assert_eq!(verifier.do_verify_final(&sig), expected, "sigVer {}: streaming", rec.id());
}

/// The key over the bare hash refuses at each verifying entry point, whatever the signature.
fn verify_is_refused<A, PK, const SIG_LEN: usize>(rec: &Record, pk: &PK)
where
    A: PreHashAlgorithm,
    PK: PreHashVerifyingKey<A, SIG_LEN>,
{
    let (msg, sig) = (rec.hex("message"), rec.hex("signature"));
    let too_weak = Err(SignatureError::PreHashTooWeak);
    assert_eq!(pk.verify_ph(&A::Hash::hash(&msg), None, &sig), too_weak, "sigVer {}", rec.id());
    assert_eq!(pk.verify(&msg, None, &sig), too_weak, "sigVer {}", rec.id());
    assert!(
        matches!(pk.create_verifier(None), Err(SignatureError::PreHashTooWeak)),
        "sigVer {}",
        rec.id()
    );
}

/// One record under the hash `H`; see [`sig_gen_with`].
fn sig_ver_with<P, H, const SIG_LEN: usize>(rec: &Record, pk: &MLDSAPublicKey<P>, tally: &mut Tally)
where
    P: SignatureLen<SIG_LEN>,
    H: PreHash,
{
    verify_as(rec, &pk.as_prehash::<AnyStrength<H>>());
    tally.wrapped += 1;
    if H::MAX_SECURITY_STRENGTH < MLDSA::<P>::MAX_SECURITY_STRENGTH {
        verify_is_refused(rec, &pk.as_prehash::<H>());
        tally.refused += 1;
    } else {
        verify_as(rec, &pk.as_prehash::<H>());
        tally.bare += 1;
    }
}

/// One record under the parameter set `P`, by its `hashAlg`.
fn sig_ver<P, const PK_LEN: usize, const SIG_LEN: usize>(rec: &Record, tally: &mut Tally)
where
    P: PublicKeyLen<PK_LEN> + SignatureLen<SIG_LEN>,
{
    let pk = MLDSAPublicKey::<P>::from_bytes(&rec.hex("pk")).unwrap();
    match rec.str("hashAlg") {
        "SHA2-224" => sig_ver_with::<P, SHA224, SIG_LEN>(rec, &pk, tally),
        "SHA2-256" => sig_ver_with::<P, SHA256, SIG_LEN>(rec, &pk, tally),
        "SHA2-384" => sig_ver_with::<P, SHA384, SIG_LEN>(rec, &pk, tally),
        "SHA2-512" => sig_ver_with::<P, SHA512, SIG_LEN>(rec, &pk, tally),
        "SHA2-512/224" => sig_ver_with::<P, SHA512_224, SIG_LEN>(rec, &pk, tally),
        "SHA2-512/256" => sig_ver_with::<P, SHA512_256, SIG_LEN>(rec, &pk, tally),
        "SHA3-224" => sig_ver_with::<P, SHA3_224, SIG_LEN>(rec, &pk, tally),
        "SHA3-256" => sig_ver_with::<P, SHA3_256, SIG_LEN>(rec, &pk, tally),
        "SHA3-384" => sig_ver_with::<P, SHA3_384, SIG_LEN>(rec, &pk, tally),
        "SHA3-512" => sig_ver_with::<P, SHA3_512, SIG_LEN>(rec, &pk, tally),
        "SHAKE-128" => sig_ver_with::<P, SHAKE128, SIG_LEN>(rec, &pk, tally),
        "SHAKE-256" => sig_ver_with::<P, SHAKE256, SIG_LEN>(rec, &pk, tally),
        other => panic!("sigVer {}: unknown hashAlg {other}", rec.id()),
    }
}

#[test]
#[allow(non_snake_case)]
fn ML_DSA_sigVer_preHash() {
    let file = "ML-DSA-sigVer-preHash.txt";
    let Some(contents) = bc_test_data(TEST_DATA_DIR, file) else { return };
    let records = parse(&contents);
    assert_eq!(records.len(), 45, "{file} has 45 records");
    assert_eq!(records.iter().filter(|rec| rec.flag("testPassed")).count(), 9);

    let mut tallies = Tallies::new();
    for rec in &records {
        let tally = tallies.entry(rec.pairing()).or_default();
        match rec.str("parameterSet") {
            "ML-DSA-44" => sig_ver::<MLDSA44Params, MLDSA44_PK_LEN, MLDSA44_SIG_LEN>(rec, tally),
            "ML-DSA-65" => sig_ver::<MLDSA65Params, MLDSA65_PK_LEN, MLDSA65_SIG_LEN>(rec, tally),
            "ML-DSA-87" => sig_ver::<MLDSA87Params, MLDSA87_PK_LEN, MLDSA87_SIG_LEN>(rec, tally),
            other => panic!("sigVer {}: unknown parameterSet {other}", rec.id()),
        }
    }
    // 23 of the 45 records pair a hash with a parameter set stronger than it.
    check_tallies(file, &tallies, 45, 23);
}
