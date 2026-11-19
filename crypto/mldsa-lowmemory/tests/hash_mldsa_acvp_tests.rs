//! NIST ACVP known-answer tests for HashML-DSA: `ML-DSA-sigGen-preHash.txt` and
//! `ML-DSA-sigVer-preHash.txt`, which pair each of twelve hashes with each parameter set.
//!
//! A pairing whose hash is weaker than the parameter set runs through `hazmat::AnyStrength`,
//! after a check that the bare hash is refused. A pairing FIPS 204 Section 5.4 allows runs both
//! ways, so the wrapper is also held to the known answers where it is not needed.
//!
//! The sigGen file gives each signing key only as the expanded private key, which this crate's
//! seed-only keys cannot be built from, so its signatures are not regenerated here; the full
//! `mldsa` crate's copy of this test does that. Each one is verified here instead, under the
//! public key the full crate derives from the record's private key.
//!
//! Vectors are read from the bc-test-data repo (https://github.com/bcgit/bc-test-data), which must be
//! cloned alongside this repo at "../bc-test-data", under `pqc/crypto/mldsa/`. If it is not
//! present the tests print a warning and pass vacuously.

use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::signature_key::{PreHash, PreHashVerifyingKey, SignatureAlgorithm};
use bouncycastle_core::traits::{PrivateKey, PublicKey, SignatureVerifier};
use bouncycastle_core_test_framework::test_data_loaders::bc_test_data;
use bouncycastle_hex as hex;
use bouncycastle_mldsa::MLDSAPrivateKeyTrait;
use bouncycastle_mldsa_lowmemory::hazmat::AnyStrength;
use bouncycastle_mldsa_lowmemory::{
    MLDSA44, MLDSA44_PK_LEN, MLDSA44_SIG_LEN, MLDSA44PublicKey, MLDSA65, MLDSA65_PK_LEN,
    MLDSA65_SIG_LEN, MLDSA65PublicKey, MLDSA87, MLDSA87_PK_LEN, MLDSA87_SIG_LEN, MLDSA87PublicKey,
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

/// Verifies the record's signature with the pre-hash `H`, by the one-shot over the digest and
/// by the streaming verifier over the message, and checks that both find it valid or not as `valid` says.
fn verify_as<A, PK, H, const SIG_LEN: usize>(rec: &Record, pk: &PK, valid: bool)
where
    A: SignatureAlgorithm,
    PK: PreHashVerifyingKey<A, SIG_LEN>,
    H: PreHash,
{
    let (msg, ctx, sig) = (rec.hex("message"), rec.hex("context"), rec.hex("signature"));
    let ctx = Some(ctx.as_slice());
    let expected = || if valid { Ok(()) } else { Err(SignatureError::SignatureVerificationFailed) };
    assert_eq!(pk.verify_ph::<H>(&H::hash(&msg), ctx, &sig), expected(), "{}", rec.id());
    let mut verifier = pk.create_ph_verifier::<H>(ctx).unwrap();
    verifier.do_update(&msg);
    assert_eq!(verifier.do_verify_final(&sig), expected(), "{}: streaming", rec.id());
}

fn verify_with<A, PK, H, const PK_LEN: usize, const SIG_LEN: usize>(
    rec: &Record,
    pk: &[u8],
    valid: bool,
    tally: &mut Tally,
) where
    A: SignatureAlgorithm,
    PK: PublicKey<PK_LEN> + PreHashVerifyingKey<A, SIG_LEN>,
    H: PreHash,
{
    let pk = PK::from_bytes(pk).unwrap();

    verify_as::<A, PK, AnyStrength<H>, SIG_LEN>(rec, &pk, valid);
    tally.wrapped += 1;
    if H::MAX_SECURITY_STRENGTH < A::MAX_SECURITY_STRENGTH {
        // The bare hash is refused at each verifying entry point, whatever the signature.
        let (ph, sig) = (H::hash(&rec.hex("message")), rec.hex("signature"));
        let too_weak = Err(SignatureError::PreHashTooWeak);
        assert_eq!(pk.verify_ph::<H>(&ph, None, &sig), too_weak, "{}", rec.id());
        assert!(
            matches!(pk.create_ph_verifier::<H>(None), Err(SignatureError::PreHashTooWeak)),
            "{}",
            rec.id()
        );
        tally.refused += 1;
    } else {
        verify_as::<A, PK, H, SIG_LEN>(rec, &pk, valid);
        tally.bare += 1;
    }
}

fn verify<A, PK, const PK_LEN: usize, const SIG_LEN: usize>(
    rec: &Record,
    pk: &[u8],
    valid: bool,
    tally: &mut Tally,
) where
    A: SignatureAlgorithm,
    PK: PublicKey<PK_LEN> + PreHashVerifyingKey<A, SIG_LEN>,
{
    match rec.str("hashAlg") {
        "SHA2-224" => verify_with::<A, PK, SHA224, PK_LEN, SIG_LEN>(rec, pk, valid, tally),
        "SHA2-256" => verify_with::<A, PK, SHA256, PK_LEN, SIG_LEN>(rec, pk, valid, tally),
        "SHA2-384" => verify_with::<A, PK, SHA384, PK_LEN, SIG_LEN>(rec, pk, valid, tally),
        "SHA2-512" => verify_with::<A, PK, SHA512, PK_LEN, SIG_LEN>(rec, pk, valid, tally),
        "SHA2-512/224" => verify_with::<A, PK, SHA512_224, PK_LEN, SIG_LEN>(rec, pk, valid, tally),
        "SHA2-512/256" => verify_with::<A, PK, SHA512_256, PK_LEN, SIG_LEN>(rec, pk, valid, tally),
        "SHA3-224" => verify_with::<A, PK, SHA3_224, PK_LEN, SIG_LEN>(rec, pk, valid, tally),
        "SHA3-256" => verify_with::<A, PK, SHA3_256, PK_LEN, SIG_LEN>(rec, pk, valid, tally),
        "SHA3-384" => verify_with::<A, PK, SHA3_384, PK_LEN, SIG_LEN>(rec, pk, valid, tally),
        "SHA3-512" => verify_with::<A, PK, SHA3_512, PK_LEN, SIG_LEN>(rec, pk, valid, tally),
        "SHAKE-128" => verify_with::<A, PK, SHAKE128, PK_LEN, SIG_LEN>(rec, pk, valid, tally),
        "SHAKE-256" => verify_with::<A, PK, SHAKE256, PK_LEN, SIG_LEN>(rec, pk, valid, tally),
        other => panic!("{}: unknown hashAlg {other}", rec.id()),
    }
}

/// Each sigGen record's signature verifies; see the module docs for why none is regenerated.
#[test]
#[allow(non_snake_case)]
fn ML_DSA_sigGen_preHash_verifies() {
    let file = "ML-DSA-sigGen-preHash.txt";
    let Some(contents) = bc_test_data(TEST_DATA_DIR, file) else { return };
    let records = parse(&contents);
    assert_eq!(records.len(), 90, "{file} has 90 records");

    let mut tallies = Tallies::new();
    for rec in &records {
        let tally = tallies.entry(rec.pairing()).or_default();
        let sk = rec.hex("sk");
        match rec.str("parameterSet") {
            "ML-DSA-44" => {
                let pk =
                    bouncycastle_mldsa::MLDSA44PrivateKey::from_bytes(&sk).unwrap().derive_pk();
                verify::<MLDSA44, MLDSA44PublicKey, MLDSA44_PK_LEN, MLDSA44_SIG_LEN>(
                    rec,
                    &PublicKey::<MLDSA44_PK_LEN>::encode(&pk),
                    true,
                    tally,
                )
            }
            "ML-DSA-65" => {
                let pk =
                    bouncycastle_mldsa::MLDSA65PrivateKey::from_bytes(&sk).unwrap().derive_pk();
                verify::<MLDSA65, MLDSA65PublicKey, MLDSA65_PK_LEN, MLDSA65_SIG_LEN>(
                    rec,
                    &PublicKey::<MLDSA65_PK_LEN>::encode(&pk),
                    true,
                    tally,
                )
            }
            "ML-DSA-87" => {
                let pk =
                    bouncycastle_mldsa::MLDSA87PrivateKey::from_bytes(&sk).unwrap().derive_pk();
                verify::<MLDSA87, MLDSA87PublicKey, MLDSA87_PK_LEN, MLDSA87_SIG_LEN>(
                    rec,
                    &PublicKey::<MLDSA87_PK_LEN>::encode(&pk),
                    true,
                    tally,
                )
            }
            other => panic!("{}: unknown parameterSet {other}", rec.id()),
        }
    }
    // 44 of the 90 records pair a hash with a parameter set stronger than it.
    check_tallies(file, &tallies, 90, 44);
    println!("{file}: 90 records verified, 0 signed: the keys are given in expanded form only");
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
        let pk = rec.hex("pk");
        let valid = rec.flag("testPassed");
        match rec.str("parameterSet") {
            "ML-DSA-44" => verify::<MLDSA44, MLDSA44PublicKey, MLDSA44_PK_LEN, MLDSA44_SIG_LEN>(
                rec, &pk, valid, tally,
            ),
            "ML-DSA-65" => verify::<MLDSA65, MLDSA65PublicKey, MLDSA65_PK_LEN, MLDSA65_SIG_LEN>(
                rec, &pk, valid, tally,
            ),
            "ML-DSA-87" => verify::<MLDSA87, MLDSA87PublicKey, MLDSA87_PK_LEN, MLDSA87_SIG_LEN>(
                rec, &pk, valid, tally,
            ),
            other => panic!("{}: unknown parameterSet {other}", rec.id()),
        }
    }
    // 23 of the 45 records pair a hash with a parameter set stronger than it.
    check_tallies(file, &tallies, 45, 23);
}
