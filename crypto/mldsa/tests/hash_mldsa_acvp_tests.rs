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
use bouncycastle_core::signature_key::{
    DeterministicPreHashSigningKey, PreHash, PreHashSigningKey, PreHashVerifyingKey,
    SignatureAlgorithm,
};
use bouncycastle_core::traits::{PrivateKey, PublicKey, SignatureSigner, SignatureVerifier};
use bouncycastle_core_test_framework::test_data_loaders::bc_test_data;
use bouncycastle_hex as hex;
use bouncycastle_mldsa::hazmat::AnyStrength;
use bouncycastle_mldsa::{
    MLDSA44, MLDSA44_PK_LEN, MLDSA44_SIG_LEN, MLDSA44_SK_LEN, MLDSA44PrivateKey, MLDSA44PublicKey,
    MLDSA65, MLDSA65_PK_LEN, MLDSA65_SIG_LEN, MLDSA65_SK_LEN, MLDSA65PrivateKey, MLDSA65PublicKey,
    MLDSA87, MLDSA87_PK_LEN, MLDSA87_SIG_LEN, MLDSA87_SK_LEN, MLDSA87PrivateKey, MLDSA87PublicKey,
    MLDSAPrivateKeyTrait,
};
use bouncycastle_rng::FixedSeedRNG;
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

/// Signs the record's message with the pre-hash `H`, by the one-shot over the digest and by the
/// streaming signer over the message, and checks both against the record's signature, which
/// must then verify.
fn sign_as<A, PK, SK, H, const SIG_LEN: usize>(rec: &Record, pk: &PK, sk: &SK)
where
    A: SignatureAlgorithm,
    PK: PreHashVerifyingKey<A, SIG_LEN>,
    SK: PreHashSigningKey<A, SIG_LEN> + DeterministicPreHashSigningKey<A, SIG_LEN>,
    H: PreHash,
{
    let (msg, ctx, expected) = (rec.hex("message"), rec.hex("context"), rec.hex("signature"));
    let ctx = Some(ctx.as_slice());
    let ph = H::hash(&msg);

    let (one_shot, streamed) = if rec.flag("deterministic") {
        let mut signer = sk.create_ph_signer_deterministic::<H>(ctx).unwrap();
        signer.do_update(&msg);
        (sk.sign_ph_deterministic::<H>(&ph, ctx).unwrap(), signer.do_final().unwrap())
    } else {
        // The hedged variant draws rnd, 32 bytes, from the RNG: the record's `rnd`.
        let rnd = rec.hex("rnd");
        let mut signer = sk.create_ph_signer::<H>(&mut FixedSeedRNG::new(&rnd), ctx).unwrap();
        signer.do_update(&msg);
        (
            sk.sign_ph::<H>(&mut FixedSeedRNG::new(&rnd), &ph, ctx).unwrap(),
            signer.do_final().unwrap(),
        )
    };
    assert_eq!(one_shot.as_slice(), expected, "sigGen {}: one-shot", rec.id());
    assert_eq!(streamed.as_slice(), expected, "sigGen {}: streaming", rec.id());

    pk.verify_ph::<H>(&ph, ctx, &expected)
        .unwrap_or_else(|e| panic!("sigGen {}: verify_ph: {e:?}", rec.id()));
    let mut verifier = pk.create_ph_verifier::<H>(ctx).unwrap();
    verifier.do_update(&msg);
    verifier
        .do_verify_final(&expected)
        .unwrap_or_else(|e| panic!("sigGen {}: streaming verify: {e:?}", rec.id()));
}

/// The bare hash is refused at each signing entry point.
fn sign_is_refused<A, SK, H, const SIG_LEN: usize>(rec: &Record, sk: &SK)
where
    A: SignatureAlgorithm,
    SK: PreHashSigningKey<A, SIG_LEN> + DeterministicPreHashSigningKey<A, SIG_LEN>,
    H: PreHash,
{
    let ph = H::hash(&rec.hex("message"));
    let mut rng = FixedSeedRNG::new([0u8; 32]);
    let too_weak = Err(SignatureError::PreHashTooWeak);
    assert_eq!(sk.sign_ph_deterministic::<H>(&ph, None), too_weak, "sigGen {}", rec.id());
    assert_eq!(sk.sign_ph::<H>(&mut rng, &ph, None), too_weak, "sigGen {}", rec.id());
    assert!(
        matches!(sk.create_ph_signer_deterministic::<H>(None), Err(SignatureError::PreHashTooWeak)),
        "sigGen {}",
        rec.id()
    );
    assert!(
        matches!(sk.create_ph_signer::<H>(&mut rng, None), Err(SignatureError::PreHashTooWeak)),
        "sigGen {}",
        rec.id()
    );
}

fn sig_gen_with<A, PK, SK, H, const SK_LEN: usize, const SIG_LEN: usize>(
    rec: &Record,
    pk_of: fn(&SK) -> PK,
    tally: &mut Tally,
) where
    A: SignatureAlgorithm,
    PK: PreHashVerifyingKey<A, SIG_LEN>,
    SK: PrivateKey<SK_LEN>
        + PreHashSigningKey<A, SIG_LEN>
        + DeterministicPreHashSigningKey<A, SIG_LEN>,
    H: PreHash,
{
    let sk = SK::from_bytes(&rec.hex("sk")).unwrap();
    let pk = pk_of(&sk);

    sign_as::<A, PK, SK, AnyStrength<H>, SIG_LEN>(rec, &pk, &sk);
    tally.wrapped += 1;
    if H::MAX_SECURITY_STRENGTH < A::MAX_SECURITY_STRENGTH {
        sign_is_refused::<A, SK, H, SIG_LEN>(rec, &sk);
        tally.refused += 1;
    } else {
        sign_as::<A, PK, SK, H, SIG_LEN>(rec, &pk, &sk);
        tally.bare += 1;
    }
}

fn sig_gen<A, PK, SK, const SK_LEN: usize, const SIG_LEN: usize>(
    rec: &Record,
    pk_of: fn(&SK) -> PK,
    tally: &mut Tally,
) where
    A: SignatureAlgorithm,
    PK: PreHashVerifyingKey<A, SIG_LEN>,
    SK: PrivateKey<SK_LEN>
        + PreHashSigningKey<A, SIG_LEN>
        + DeterministicPreHashSigningKey<A, SIG_LEN>,
{
    match rec.str("hashAlg") {
        "SHA2-224" => sig_gen_with::<A, PK, SK, SHA224, SK_LEN, SIG_LEN>(rec, pk_of, tally),
        "SHA2-256" => sig_gen_with::<A, PK, SK, SHA256, SK_LEN, SIG_LEN>(rec, pk_of, tally),
        "SHA2-384" => sig_gen_with::<A, PK, SK, SHA384, SK_LEN, SIG_LEN>(rec, pk_of, tally),
        "SHA2-512" => sig_gen_with::<A, PK, SK, SHA512, SK_LEN, SIG_LEN>(rec, pk_of, tally),
        "SHA2-512/224" => sig_gen_with::<A, PK, SK, SHA512_224, SK_LEN, SIG_LEN>(rec, pk_of, tally),
        "SHA2-512/256" => sig_gen_with::<A, PK, SK, SHA512_256, SK_LEN, SIG_LEN>(rec, pk_of, tally),
        "SHA3-224" => sig_gen_with::<A, PK, SK, SHA3_224, SK_LEN, SIG_LEN>(rec, pk_of, tally),
        "SHA3-256" => sig_gen_with::<A, PK, SK, SHA3_256, SK_LEN, SIG_LEN>(rec, pk_of, tally),
        "SHA3-384" => sig_gen_with::<A, PK, SK, SHA3_384, SK_LEN, SIG_LEN>(rec, pk_of, tally),
        "SHA3-512" => sig_gen_with::<A, PK, SK, SHA3_512, SK_LEN, SIG_LEN>(rec, pk_of, tally),
        "SHAKE-128" => sig_gen_with::<A, PK, SK, SHAKE128, SK_LEN, SIG_LEN>(rec, pk_of, tally),
        "SHAKE-256" => sig_gen_with::<A, PK, SK, SHAKE256, SK_LEN, SIG_LEN>(rec, pk_of, tally),
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
            "ML-DSA-44" => sig_gen::<
                MLDSA44,
                MLDSA44PublicKey,
                MLDSA44PrivateKey,
                MLDSA44_SK_LEN,
                MLDSA44_SIG_LEN,
            >(rec, |sk| sk.derive_pk(), tally),
            "ML-DSA-65" => sig_gen::<
                MLDSA65,
                MLDSA65PublicKey,
                MLDSA65PrivateKey,
                MLDSA65_SK_LEN,
                MLDSA65_SIG_LEN,
            >(rec, |sk| sk.derive_pk(), tally),
            "ML-DSA-87" => sig_gen::<
                MLDSA87,
                MLDSA87PublicKey,
                MLDSA87PrivateKey,
                MLDSA87_SK_LEN,
                MLDSA87_SIG_LEN,
            >(rec, |sk| sk.derive_pk(), tally),
            other => panic!("sigGen {}: unknown parameterSet {other}", rec.id()),
        }
    }
    // 44 of the 90 records pair a hash with a parameter set stronger than it.
    check_tallies(file, &tallies, 90, 44);
}

/* sigVer */

/// Verifies the record's signature with the pre-hash `H`, by the one-shot over the digest and
/// by the streaming verifier over the message, and checks both against `testPassed`.
fn verify_as<A, PK, H, const SIG_LEN: usize>(rec: &Record, pk: &PK)
where
    A: SignatureAlgorithm,
    PK: PreHashVerifyingKey<A, SIG_LEN>,
    H: PreHash,
{
    let (msg, ctx, sig) = (rec.hex("message"), rec.hex("context"), rec.hex("signature"));
    let ctx = Some(ctx.as_slice());
    let expected = if rec.flag("testPassed") {
        Ok(())
    } else {
        Err(SignatureError::SignatureVerificationFailed)
    };

    assert_eq!(pk.verify_ph::<H>(&H::hash(&msg), ctx, &sig), expected, "sigVer {}", rec.id());
    let mut verifier = pk.create_ph_verifier::<H>(ctx).unwrap();
    verifier.do_update(&msg);
    assert_eq!(verifier.do_verify_final(&sig), expected, "sigVer {}: streaming", rec.id());
}

fn sig_ver_with<A, PK, H, const PK_LEN: usize, const SIG_LEN: usize>(
    rec: &Record,
    tally: &mut Tally,
) where
    A: SignatureAlgorithm,
    PK: PublicKey<PK_LEN> + PreHashVerifyingKey<A, SIG_LEN>,
    H: PreHash,
{
    let pk = PK::from_bytes(&rec.hex("pk")).unwrap();

    verify_as::<A, PK, AnyStrength<H>, SIG_LEN>(rec, &pk);
    tally.wrapped += 1;
    if H::MAX_SECURITY_STRENGTH < A::MAX_SECURITY_STRENGTH {
        // The bare hash is refused at each verifying entry point, whatever the signature.
        let (ph, sig) = (H::hash(&rec.hex("message")), rec.hex("signature"));
        let too_weak = Err(SignatureError::PreHashTooWeak);
        assert_eq!(pk.verify_ph::<H>(&ph, None, &sig), too_weak, "sigVer {}", rec.id());
        assert!(
            matches!(pk.create_ph_verifier::<H>(None), Err(SignatureError::PreHashTooWeak)),
            "sigVer {}",
            rec.id()
        );
        tally.refused += 1;
    } else {
        verify_as::<A, PK, H, SIG_LEN>(rec, &pk);
        tally.bare += 1;
    }
}

fn sig_ver<A, PK, const PK_LEN: usize, const SIG_LEN: usize>(rec: &Record, tally: &mut Tally)
where
    A: SignatureAlgorithm,
    PK: PublicKey<PK_LEN> + PreHashVerifyingKey<A, SIG_LEN>,
{
    match rec.str("hashAlg") {
        "SHA2-224" => sig_ver_with::<A, PK, SHA224, PK_LEN, SIG_LEN>(rec, tally),
        "SHA2-256" => sig_ver_with::<A, PK, SHA256, PK_LEN, SIG_LEN>(rec, tally),
        "SHA2-384" => sig_ver_with::<A, PK, SHA384, PK_LEN, SIG_LEN>(rec, tally),
        "SHA2-512" => sig_ver_with::<A, PK, SHA512, PK_LEN, SIG_LEN>(rec, tally),
        "SHA2-512/224" => sig_ver_with::<A, PK, SHA512_224, PK_LEN, SIG_LEN>(rec, tally),
        "SHA2-512/256" => sig_ver_with::<A, PK, SHA512_256, PK_LEN, SIG_LEN>(rec, tally),
        "SHA3-224" => sig_ver_with::<A, PK, SHA3_224, PK_LEN, SIG_LEN>(rec, tally),
        "SHA3-256" => sig_ver_with::<A, PK, SHA3_256, PK_LEN, SIG_LEN>(rec, tally),
        "SHA3-384" => sig_ver_with::<A, PK, SHA3_384, PK_LEN, SIG_LEN>(rec, tally),
        "SHA3-512" => sig_ver_with::<A, PK, SHA3_512, PK_LEN, SIG_LEN>(rec, tally),
        "SHAKE-128" => sig_ver_with::<A, PK, SHAKE128, PK_LEN, SIG_LEN>(rec, tally),
        "SHAKE-256" => sig_ver_with::<A, PK, SHAKE256, PK_LEN, SIG_LEN>(rec, tally),
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
            "ML-DSA-44" => {
                sig_ver::<MLDSA44, MLDSA44PublicKey, MLDSA44_PK_LEN, MLDSA44_SIG_LEN>(rec, tally)
            }
            "ML-DSA-65" => {
                sig_ver::<MLDSA65, MLDSA65PublicKey, MLDSA65_PK_LEN, MLDSA65_SIG_LEN>(rec, tally)
            }
            "ML-DSA-87" => {
                sig_ver::<MLDSA87, MLDSA87PublicKey, MLDSA87_PK_LEN, MLDSA87_SIG_LEN>(rec, tally)
            }
            other => panic!("sigVer {}: unknown parameterSet {other}", rec.id()),
        }
    }
    // 23 of the 45 records pair a hash with a parameter set stronger than it.
    check_tallies(file, &tallies, 45, 23);
}
