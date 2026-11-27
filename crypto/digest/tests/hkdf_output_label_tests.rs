//! How HKDF types what it derives: by the `KDF` trait's rule, `hazmat::label_kdf_output`, over
//! the keys it credits, which are the IKMs given as keys and a salt typed `MACKey`, seeded at
//! half a hash output of credited bytes and capped at the strength that many bytes hold.
//!
//! The first test runs every path over every hash the library names an HKDF for against the
//! shared function. The rest spell out, as literal values, the cases where HKDF's label is not
//! what the shared function gives a KDF that passes it the derivation's keys alone.

use bouncycastle_core::hazmat::{do_hazardous_operations, label_kdf_output};
use bouncycastle_core::key_material::{
    KeyMaterial, KeyMaterial0, KeyMaterial256, KeyMaterial512, KeyMaterialTrait, KeyType,
};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, KDF};
use bouncycastle_core_test_framework::DUMMY_SEED;
use bouncycastle_digest::hkdf::{HKDF, HKDFParams};
use bouncycastle_digest::ripemd::RIPEMD160;
use bouncycastle_digest::sha2::{SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256};
use bouncycastle_digest::sha3::{SHA3_224, SHA3_256, SHA3_384, SHA3_512};
use bouncycastle_digest::sm3::SM3;

type Label = (KeyType, SecurityStrength);
const UNKNOWN: Label = (KeyType::Unknown, SecurityStrength::None);

fn random(strength: SecurityStrength) -> Label {
    (KeyType::CryptographicRandom, strength)
}

fn label_of(key: &(impl KeyMaterialTrait + ?Sized)) -> Label {
    (key.key_type(), key.security_strength())
}

/// `len` bytes typed `key_type`, at the strength the length gives.
fn key(len: usize, key_type: KeyType) -> KeyMaterial<128> {
    KeyMaterial::from_bytes_as_type(&DUMMY_SEED[..len], key_type).unwrap()
}

/// As [`key`], at `strength`.
fn key_at(len: usize, key_type: KeyType, strength: SecurityStrength) -> KeyMaterial<128> {
    let mut k = key(len, key_type);
    do_hazardous_operations(&mut k, |k| k.set_security_strength(strength)).unwrap();
    k
}

/// What `hazmat::label_kdf_output` gives `len` bytes derived from `keys` by a KDF over `H`
/// with HKDF's two parameters: seeded at `OUTPUT_LEN / 2` credited bytes, capped at the
/// strength `OUTPUT_LEN / 2` bytes hold.
fn shared_rule<H: HKDFParams>(keys: &[&dyn KeyMaterialTrait], len: usize) -> Label {
    let mut dkm = KeyMaterial::<128>::new();
    label_kdf_output(
        keys,
        len,
        H::OUTPUT_LEN / 2,
        SecurityStrength::from_bytes(H::OUTPUT_LEN / 2),
        &mut dkm,
    )
    .unwrap();
    label_of(&dkm)
}

/// The keys HKDF credits: the salt when it is typed `MACKey`, then the IKMs.
fn credited_keys<'a>(
    salt: &'a dyn KeyMaterialTrait,
    ikms: &[&'a dyn KeyMaterialTrait],
) -> Vec<&'a dyn KeyMaterialTrait> {
    let mut keys = Vec::new();
    if salt.key_type() == KeyType::MACKey {
        keys.push(salt);
    }
    keys.extend_from_slice(ikms);
    keys
}

const LENS: [usize; 8] = [1, 13, 14, 16, 24, 32, 64, 100];

/// Every path of `HKDF<H>` against the shared function, over salts and IKMs of every kind.
fn check_against_the_shared_rule<H: HKDFParams>() {
    let name = H::HKDF_ALG_NAME;
    let h = H::OUTPUT_LEN;

    let absent = KeyMaterial0::new();
    let salts: [(&str, &dyn KeyMaterialTrait); 7] = [
        ("absent", &absent),
        ("public 32", &key(32, KeyType::CryptographicRandom)),
        ("seed 32", &key(32, KeyType::Seed)),
        ("secret 8", &key(8, KeyType::MACKey)),
        ("secret 14", &key(14, KeyType::MACKey)),
        ("secret 32", &key(32, KeyType::MACKey)),
        ("secret 64", &key(64, KeyType::MACKey)),
    ];
    let zeroized = KeyMaterial256::new();
    let unknown = key(32, KeyType::Unknown);
    let r6 = key(6, KeyType::CryptographicRandom);
    let r9 = key(9, KeyType::CryptographicRandom);
    let r10 = key(10, KeyType::CryptographicRandom);
    let r13 = key(13, KeyType::CryptographicRandom);
    let r14 = key(14, KeyType::CryptographicRandom);
    let r15 = key(15, KeyType::CryptographicRandom);
    let r16 = key(16, KeyType::CryptographicRandom);
    let r23 = key(23, KeyType::CryptographicRandom);
    let r24 = key(24, KeyType::CryptographicRandom);
    let r31 = key(31, KeyType::CryptographicRandom);
    let r32 = key(32, KeyType::CryptographicRandom);
    let r64 = key(64, KeyType::CryptographicRandom);
    let seed32 = key(32, KeyType::Seed);
    let cipher32 = key(32, KeyType::SymmetricCipherKey);
    let z_unstated = key(32, KeyType::SharedSecret);
    let z128 = key_at(32, KeyType::SharedSecret, SecurityStrength::_128bit);
    let r32_at_112 = key_at(32, KeyType::CryptographicRandom, SecurityStrength::_112bit);
    let r32_at_none = key_at(32, KeyType::CryptographicRandom, SecurityStrength::None);
    let ikm_sets: [(&str, Vec<&dyn KeyMaterialTrait>); 23] = [
        ("zeroized", vec![&zeroized]),
        ("unknown 32", vec![&unknown]),
        ("random 6", vec![&r6]),
        ("random 9", vec![&r9]),
        ("random 10", vec![&r10]),
        ("random 13", vec![&r13]),
        ("random 14", vec![&r14]),
        ("random 15", vec![&r15]),
        ("random 16", vec![&r16]),
        ("random 23", vec![&r23]),
        ("random 24", vec![&r24]),
        ("random 31", vec![&r31]),
        ("random 32", vec![&r32]),
        ("random 64", vec![&r64]),
        ("seed 32", vec![&seed32]),
        ("cipher key 32", vec![&cipher32]),
        ("shared secret 32, unstated", vec![&z_unstated]),
        ("shared secret 32 at 128", vec![&z128]),
        ("random 32 at 112", vec![&r32_at_112]),
        ("random 32 at none", vec![&r32_at_none]),
        ("random 14 + 14", vec![&r14, &r14]),
        ("random 16 + unknown 32 + 16", vec![&r16, &unknown, &r16]),
        ("shared secret 32 at 128 + random 64", vec![&z128, &r64]),
    ];

    for (salt_name, salt) in salts {
        for (ikm_name, ikms) in &ikm_sets {
            let case = format!("{name}, salt {salt_name}, IKM {ikm_name}");
            let keys = credited_keys(salt, ikms);

            // HKDF-Extract through the streaming API: the PRK is HashLen bytes from the keys.
            let mut hkdf = HKDF::<H>::new();
            hkdf.do_extract_init(salt).unwrap();
            for ikm in ikms {
                hkdf.do_extract_update_key(*ikm).unwrap();
            }
            let prk = hkdf.do_extract_final().unwrap();
            assert_eq!(label_of(&prk), shared_rule::<H>(&keys, h), "extract: {case}");

            // The one-shot extract takes one IKM.
            if let [ikm] = ikms[..] {
                let one_shot = HKDF::<H>::extract(salt, ikm).unwrap();
                assert_eq!(label_of(&one_shot), label_of(&prk), "extract one-shot: {case}");
            }

            for len in LENS {
                let case = format!("{case}, L {len}");
                let mut okm = KeyMaterial::<128>::new();

                // HKDF-Expand alone: the PRK is its one key.
                assert_eq!(HKDF::<H>::expand_out(&prk, b"info", len, &mut okm).unwrap(), len);
                assert_eq!(label_of(&okm), shared_rule::<H>(&[&prk], len), "expand: {case}");

                // Extract-then-expand as one derivation: the keys that went in label the output.
                if let [ikm] = ikms[..] {
                    HKDF::<H>::extract_and_expand_out(salt, ikm, b"info", len, &mut okm).unwrap();
                    assert_eq!(
                        label_of(&okm),
                        shared_rule::<H>(&keys, len),
                        "extract_and_expand_out: {case}"
                    );
                }
                let instance = HKDF::<H>::new_with_salt(salt).unwrap();
                instance.derive_key_from_multiple_out(ikms, b"info", len, &mut okm).unwrap();
                assert_eq!(label_of(&okm), shared_rule::<H>(&keys, len), "KDF trait: {case}");
                if let [ikm] = ikms[..] {
                    instance.derive_key_out(ikm, b"info", len, &mut okm).unwrap();
                    assert_eq!(label_of(&okm), shared_rule::<H>(&keys, len), "derive_key: {case}");
                }
                if salt.key_len() == 0 {
                    HKDF::<H>::new()
                        .derive_key_from_multiple_out(ikms, b"info", len, &mut okm)
                        .unwrap();
                    assert_eq!(
                        label_of(&okm),
                        shared_rule::<H>(&keys, len),
                        "KDF trait, HKDF::new(): {case}"
                    );
                }
            }
        }
    }
}

#[test]
fn every_path_labels_by_the_shared_rule_over_the_keys_hkdf_credits() {
    check_against_the_shared_rule::<SHA224>();
    check_against_the_shared_rule::<SHA256>();
    check_against_the_shared_rule::<SHA384>();
    check_against_the_shared_rule::<SHA512>();
    check_against_the_shared_rule::<SHA512_224>();
    check_against_the_shared_rule::<SHA512_256>();
    check_against_the_shared_rule::<SHA3_224>();
    check_against_the_shared_rule::<SHA3_256>();
    check_against_the_shared_rule::<SHA3_384>();
    check_against_the_shared_rule::<SHA3_512>();
    check_against_the_shared_rule::<SM3>();
    check_against_the_shared_rule::<RIPEMD160>();
}

/// The cap HKDF passes the rule, the strength half a hash output of bytes holds, is the
/// strength each of the library's hashes claims, which is what the Concat and X9.63 KDFs pass:
/// the two differ only for a hash defined elsewhere that claims otherwise.
#[test]
fn the_cap_is_the_strength_the_library_hashes_claim() {
    fn check<H: HKDFParams>(expected: SecurityStrength) {
        assert_eq!(SecurityStrength::from_bytes(H::OUTPUT_LEN / 2), expected, "{}", H::ALG_NAME);
        assert_eq!(H::MAX_SECURITY_STRENGTH, expected, "{}", H::ALG_NAME);
        assert_eq!(HKDF::<H>::MAX_SECURITY_STRENGTH, expected, "{}", H::ALG_NAME);
    }
    check::<SHA224>(SecurityStrength::_112bit);
    check::<SHA256>(SecurityStrength::_128bit);
    check::<SHA384>(SecurityStrength::_192bit);
    check::<SHA512>(SecurityStrength::_256bit);
    check::<SHA512_224>(SecurityStrength::_112bit);
    check::<SHA512_256>(SecurityStrength::_128bit);
    check::<SHA3_224>(SecurityStrength::_112bit);
    check::<SHA3_256>(SecurityStrength::_128bit);
    check::<SHA3_384>(SecurityStrength::_192bit);
    check::<SHA3_512>(SecurityStrength::_256bit);
    check::<SM3>(SecurityStrength::_128bit);
    check::<RIPEMD160>(SecurityStrength::None);
}

/// A salt typed `MACKey` is credited as a key, where the shared rule over the derivation's
/// keys alone, as every other KDF applies it, credits only the IKM: with a secret 32-byte salt
/// and an IKM that credits nothing the output is `CryptographicRandom`, and with the same
/// bytes typed as a public salt it is `Unknown`, which is what the keys alone give either way.
#[test]
fn a_secret_salt_is_credited_and_a_public_one_is_not() {
    let secret = key(32, KeyType::MACKey);
    let public = key(32, KeyType::CryptographicRandom);
    let unknown = key(32, KeyType::Unknown);
    let short = key(8, KeyType::CryptographicRandom);
    let mut okm = KeyMaterial512::new();

    for ikm in [&unknown as &dyn KeyMaterialTrait, &short, &KeyMaterial0::new()] {
        assert_eq!(shared_rule::<SHA256>(&[ikm], 32), UNKNOWN, "the IKM alone");
        assert_eq!(shared_rule::<SHA512>(&[ikm], 32), UNKNOWN, "the IKM alone");

        // HKDF-SHA256: 32 secret bytes at 256 bits, capped at SHA-256's 128.
        let prk = HKDF::<SHA256>::extract(&secret, ikm).unwrap();
        assert_eq!(label_of(&prk), random(SecurityStrength::_128bit));
        HKDF::<SHA256>::extract_and_expand_out(&secret, ikm, b"", 32, &mut okm).unwrap();
        assert_eq!(label_of(&okm), random(SecurityStrength::_128bit));
        let instance = HKDF::<SHA256>::new_with_salt(&secret).unwrap();
        instance.derive_key_out(ikm, b"", 32, &mut okm).unwrap();
        assert_eq!(label_of(&okm), random(SecurityStrength::_128bit));

        // HKDF-SHA512: the same salt seeds it (32 = 64 / 2) and keeps its 256 bits.
        let prk = HKDF::<SHA512>::extract(&secret, ikm).unwrap();
        assert_eq!(label_of(&prk), random(SecurityStrength::_256bit));
        HKDF::<SHA512>::extract_and_expand_out(&secret, ikm, b"", 32, &mut okm).unwrap();
        assert_eq!(label_of(&okm), random(SecurityStrength::_256bit));

        // The same bytes as a public salt credit nothing.
        let prk = HKDF::<SHA256>::extract(&public, ikm).unwrap();
        assert_eq!(label_of(&prk), UNKNOWN);
        HKDF::<SHA256>::extract_and_expand_out(&public, ikm, b"", 32, &mut okm).unwrap();
        assert_eq!(label_of(&okm), UNKNOWN);
        let instance = HKDF::<SHA256>::new_with_salt(&public).unwrap();
        instance.derive_key_out(ikm, b"", 32, &mut okm).unwrap();
        assert_eq!(label_of(&okm), UNKNOWN);
    }

    // A secret salt and an IKM add up: 8 + 8 credit nothing (neither carries a strength),
    // 14 + 14 seed HKDF-SHA256 at 112 bits and do not seed HKDF-SHA512, whose bar is 32.
    let salt14 = key(14, KeyType::MACKey);
    let ikm14 = key(14, KeyType::CryptographicRandom);
    assert_eq!(shared_rule::<SHA256>(&[&ikm14], 32), UNKNOWN, "the IKM alone");
    let prk = HKDF::<SHA256>::extract(&salt14, &ikm14).unwrap();
    assert_eq!(label_of(&prk), random(SecurityStrength::_112bit));
    HKDF::<SHA256>::extract_and_expand_out(&salt14, &ikm14, b"", 32, &mut okm).unwrap();
    assert_eq!(label_of(&okm), random(SecurityStrength::_112bit));
    HKDF::<SHA512>::extract_and_expand_out(&salt14, &ikm14, b"", 32, &mut okm).unwrap();
    assert_eq!(label_of(&okm), UNKNOWN);
    let salt8 = key(8, KeyType::MACKey);
    HKDF::<SHA256>::extract_and_expand_out(&salt8, &short, b"", 32, &mut okm).unwrap();
    assert_eq!(label_of(&okm), UNKNOWN);
}

/// The seeding bar is half a hash output of credited bytes, on both sides, for each output
/// length: one 32-byte key (a KEM's shared secret) seeds every hash, at no more than the hash's
/// strength.
#[test]
fn the_seeding_bar_is_half_a_hash_output() {
    fn check<H: HKDFParams>(bar: usize, cap: SecurityStrength) {
        let name = H::HKDF_ALG_NAME;
        assert_eq!(H::OUTPUT_LEN / 2, bar, "{name}");
        let mut okm = KeyMaterial512::new();
        let none = KeyMaterial0::new();
        // Below the bar. A key under 14 bytes has no strength and credits nothing, so RIPEMD-160's
        // bar of 10 is met only by a key that clears it.
        let below = key(bar - 1, KeyType::CryptographicRandom);
        HKDF::<H>::extract_and_expand_out(&none, &below, b"", 32, &mut okm).unwrap();
        assert_eq!(label_of(&okm), UNKNOWN, "{name}, {} bytes", bar - 1);
        assert_eq!(label_of(&HKDF::<H>::extract(&none, &below).unwrap()), UNKNOWN, "{name}");

        let at_len = if bar < 14 { 14 } else { bar };
        let at = key(at_len, KeyType::CryptographicRandom);
        let strength =
            *[at.security_strength(), cap].iter().min_by(|a, b| a.partial_cmp(b).unwrap()).unwrap();
        HKDF::<H>::extract_and_expand_out(&none, &at, b"", 32, &mut okm).unwrap();
        assert_eq!(label_of(&okm), random(strength), "{name}, {at_len} bytes");
        assert_eq!(label_of(&HKDF::<H>::extract(&none, &at).unwrap()), random(strength), "{name}");

        // 32 bytes at 256 bits seed every hash; the label is the hash's cap.
        let secret32 = key(32, KeyType::CryptographicRandom);
        HKDF::<H>::extract_and_expand_out(&none, &secret32, b"", 32, &mut okm).unwrap();
        assert_eq!(label_of(&okm), random(cap), "{name}, 32 bytes");
        HKDF::<H>::new().derive_key_out(&secret32, b"", 32, &mut okm).unwrap();
        assert_eq!(label_of(&okm), random(cap), "{name}, 32 bytes, KDF trait");
    }
    check::<RIPEMD160>(10, SecurityStrength::None);
    check::<SHA224>(14, SecurityStrength::_112bit);
    check::<SHA512_224>(14, SecurityStrength::_112bit);
    check::<SHA3_224>(14, SecurityStrength::_112bit);
    check::<SHA256>(16, SecurityStrength::_128bit);
    check::<SHA512_256>(16, SecurityStrength::_128bit);
    check::<SHA3_256>(16, SecurityStrength::_128bit);
    check::<SM3>(16, SecurityStrength::_128bit);
    check::<SHA384>(24, SecurityStrength::_192bit);
    check::<SHA3_384>(24, SecurityStrength::_192bit);
    check::<SHA512>(32, SecurityStrength::_256bit);
    check::<SHA3_512>(32, SecurityStrength::_256bit);
}

/// HKDF over RIPEMD-160, a hash that claims no strength: a seeded derivation is
/// `CryptographicRandom` with no strength by every path that has the keys, as the shared rule
/// gives a function with a cap of none. A PRK carries that label as its type alone, so
/// `expand_out` handed it back, like any key with no strength, credits nothing; a PRK the
/// caller types with a strength is credited.
#[test]
fn ripemd160_labels_a_seeded_derivation_random_with_no_strength() {
    let none = KeyMaterial0::new();
    let secret = key(32, KeyType::CryptographicRandom);
    let mut okm = KeyMaterial512::new();

    let prk = HKDF::<RIPEMD160>::extract(&none, &secret).unwrap();
    assert_eq!(prk.key_len(), 20);
    assert_eq!(label_of(&prk), random(SecurityStrength::None));

    HKDF::<RIPEMD160>::extract_and_expand_out(&none, &secret, b"", 32, &mut okm).unwrap();
    assert_eq!(label_of(&okm), random(SecurityStrength::None));
    HKDF::<RIPEMD160>::new().derive_key_out(&secret, b"", 32, &mut okm).unwrap();
    assert_eq!(label_of(&okm), random(SecurityStrength::None));
    let keys: [&dyn KeyMaterialTrait; 2] = [&secret, &secret];
    HKDF::<RIPEMD160>::new().derive_key_from_multiple_out(&keys, b"", 32, &mut okm).unwrap();
    assert_eq!(label_of(&okm), random(SecurityStrength::None));
    // A secret salt seeds it alone.
    let salt = key(32, KeyType::MACKey);
    let instance = HKDF::<RIPEMD160>::new_with_salt(&salt).unwrap();
    instance.derive_key_out(&none, b"", 32, &mut okm).unwrap();
    assert_eq!(label_of(&okm), random(SecurityStrength::None));

    // The two steps by hand: the PRK has no strength, so the expansion credits nothing.
    HKDF::<RIPEMD160>::expand_out(&prk, b"", 32, &mut okm).unwrap();
    assert_eq!(label_of(&okm), UNKNOWN);
    // A PRK from elsewhere with a strength is credited, at the hash's cap of none.
    let typed_prk = key(20, KeyType::MACKey);
    assert_eq!(typed_prk.security_strength(), SecurityStrength::_128bit);
    HKDF::<RIPEMD160>::expand_out(&typed_prk, b"", 32, &mut okm).unwrap();
    assert_eq!(label_of(&okm), random(SecurityStrength::None));

    // Unseeded, by every path.
    let unknown = key(32, KeyType::Unknown);
    assert_eq!(label_of(&HKDF::<RIPEMD160>::extract(&none, &unknown).unwrap()), UNKNOWN);
    HKDF::<RIPEMD160>::extract_and_expand_out(&none, &unknown, b"", 32, &mut okm).unwrap();
    assert_eq!(label_of(&okm), UNKNOWN);
    HKDF::<RIPEMD160>::new().derive_key_out(&unknown, b"", 32, &mut okm).unwrap();
    assert_eq!(label_of(&okm), UNKNOWN);
}

/// For every hash with a strength, the two steps by hand give the label the one derivation
/// does: the PRK's type and strength carry it.
#[test]
fn the_two_steps_by_hand_label_as_the_one_derivation_does() {
    fn check<H: HKDFParams>() {
        let salt = key(32, KeyType::MACKey);
        let absent = KeyMaterial0::new();
        for ikm in [key(32, KeyType::CryptographicRandom), key(8, KeyType::CryptographicRandom)] {
            for len in LENS {
                let mut one = KeyMaterial::<128>::new();
                HKDF::<H>::extract_and_expand_out(&absent, &ikm, b"i", len, &mut one).unwrap();
                let prk = HKDF::<H>::extract(&absent, &ikm).unwrap();
                let mut two = KeyMaterial::<128>::new();
                HKDF::<H>::expand_out(&prk, b"i", len, &mut two).unwrap();
                assert_eq!(label_of(&one), label_of(&two), "{}, L {len}", H::HKDF_ALG_NAME);
                assert_eq!(one.ref_to_bytes(), two.ref_to_bytes());

                HKDF::<H>::extract_and_expand_out(&salt, &ikm, b"i", len, &mut one).unwrap();
                let prk = HKDF::<H>::extract(&salt, &ikm).unwrap();
                HKDF::<H>::expand_out(&prk, b"i", len, &mut two).unwrap();
                assert_eq!(label_of(&one), label_of(&two), "{}, L {len}", H::HKDF_ALG_NAME);
                assert_eq!(one.ref_to_bytes(), two.ref_to_bytes());
            }
        }
    }
    check::<SHA224>();
    check::<SHA256>();
    check::<SHA384>();
    check::<SHA512>();
    check::<SHA512_224>();
    check::<SHA512_256>();
    check::<SHA3_224>();
    check::<SHA3_256>();
    check::<SHA3_384>();
    check::<SHA3_512>();
    check::<SM3>();
}

/// The streaming extract's account: each key returns the bytes it credits, `get_entropy` is
/// their sum, and `is_fully_seeded` turns at half a hash output, 16 bytes for SHA-256 and 32
/// for SHA-512.
#[test]
fn the_streaming_extract_counts_what_it_credits() {
    let none = KeyMaterial0::new();
    let r8 = key(8, KeyType::CryptographicRandom);
    let r14 = key(14, KeyType::CryptographicRandom);
    let r16 = key(16, KeyType::CryptographicRandom);

    let mut hkdf = HKDF::<SHA256>::new();
    assert_eq!(hkdf.do_extract_init(&none).unwrap(), 0);
    // 8 bytes are 64 bits, below the 112 a key needs to carry a strength.
    assert_eq!(r8.security_strength(), SecurityStrength::None);
    assert_eq!(hkdf.do_extract_update_key(&r8).unwrap(), 0);
    assert_eq!((hkdf.get_entropy(), hkdf.is_fully_seeded()), (0, false));
    assert_eq!(hkdf.do_extract_update_key(&r14).unwrap(), 14);
    assert_eq!((hkdf.get_entropy(), hkdf.is_fully_seeded()), (14, false));
    assert_eq!(hkdf.do_extract_update_key(&r14).unwrap(), 14);
    assert_eq!((hkdf.get_entropy(), hkdf.is_fully_seeded()), (28, true));
    assert_eq!(label_of(&hkdf.do_extract_final().unwrap()), random(SecurityStrength::_112bit));

    let mut hkdf = HKDF::<SHA256>::new();
    hkdf.do_extract_init(&none).unwrap();
    hkdf.do_extract_update_key(&r16).unwrap();
    assert_eq!((hkdf.get_entropy(), hkdf.is_fully_seeded()), (16, true));

    let mut hkdf = HKDF::<SHA512>::new();
    hkdf.do_extract_init(&none).unwrap();
    hkdf.do_extract_update_key(&r16).unwrap();
    assert_eq!((hkdf.get_entropy(), hkdf.is_fully_seeded()), (16, false));
    hkdf.do_extract_update_key(&r16).unwrap();
    assert_eq!((hkdf.get_entropy(), hkdf.is_fully_seeded()), (32, true));
    // Bytes given as bytes credit nothing.
    assert_eq!(hkdf.do_extract_update_bytes(&[0x5A; 64]).unwrap(), 0);
    assert_eq!(hkdf.get_entropy(), 32);
    assert_eq!(label_of(&hkdf.do_extract_final().unwrap()), random(SecurityStrength::_128bit));
}
