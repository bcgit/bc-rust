//! The `*_from_hash` entry points take the message hash, and for RSASSA-PSS the salt, as
//! slices, so their lengths are the caller's to get wrong. A hash that is not one output of
//! the algorithm's hash, or a salt that is not the algorithm's salt length, is an error in
//! every build profile: no signature over a `DigestInfo` that no hash produces, and no panic.
//! These tests are meant to be run with `--release` as well as without.

use bouncycastle_core::errors::{RNGError, SignatureError};
use bouncycastle_core::hex::decode as hex_decode;
use bouncycastle_core::key_material::KeyMaterialTrait;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{HashOneShot, RNG};
use bouncycastle_digest::sha2::{SHA256, SHA512};
use bouncycastle_modexp::rsa::RSA2048;
use bouncycastle_modexp::rsa::keys::{RsaPrivateComponents, RsaPublicComponents};
use bouncycastle_modexp::rsa::modexp::{MontgomeryContext, mod_pow_public_exponent};
use bouncycastle_modexp::rsa::rsassa::{
    self, RsaDeterministicSignatureAlgorithm, RsaRandomizedSignatureAlgorithm,
    RsaSignatureAlgorithm,
};
use bouncycastle_modexp::rsa::rsassa_pkcs1_v1_5::RSASSA_PKCS1_v1_5;
use bouncycastle_modexp::rsa::rsassa_pss::{Mgf1, NoSalt, RSASSA_PSS};
use bouncycastle_modexp::rsa::size::RsaSize;

// A genuine RSA-2048 key: the first SHA-256 group of Wycheproof's
// `rsa_pkcs1_2048_sig_gen_test.json` (`tests/rsa_2048_pkcs1_v1_5_tests.rs` has the provenance).
const P: [u64; 16] = [
    0x0ea36cfb3a5b18f1, 0x48a6e65332119129, 0x110ad9e7b48a1c93, 0x569156b90113e2e9,
    0xe79813a575cfad9c, 0x69d659d143ec6f17, 0xe81e6bab5ddaa783, 0xbff1c5b80a69f788,
    0x978f6c35814f50ee, 0xe6a289ad4cfbf78f, 0x34d5681e5809d415, 0xbb028bda42eeb5d2,
    0x41c56e4de086b0d5, 0x58b8d1e24f3b55d0, 0xfb5248247d98cb7d, 0xdc431050f782e894,
];
const Q: [u64; 16] = [
    0x669f140cfbc20f25, 0xb97bb03677207d95, 0xfd4e06f3ed7299d4, 0x160f90536abc9492,
    0xf5b131f39098f7bc, 0xae8d72c57088d7ab, 0x89b94fbde542aba9, 0x3d3f9880ec47d5e0,
    0x1378a6868af3b7a0, 0x5544070beb057c94, 0x16611debc472fac4, 0xe500ffb79f5b8868,
    0x308a5e32196603b2, 0xea5fb19eb4eabc38, 0x122273ae3222b598, 0xbd1a81e7977f9898,
];
const D_P: [u64; 16] = [
    0x209f33f09515d7c1, 0xb4a9b37656917205, 0x276933bb07e4efb9, 0x8c14019808e00414,
    0x289f96da220711e5, 0xfbbd2923d31532fe, 0xc06b414e61c0e1e7, 0x4c23c4588488961d,
    0x4dc48ae34514759c, 0x9c786961ae3e2c35, 0x497e8d9c650688e0, 0x18bf08472612dbe5,
    0x8885fb161870ee12, 0xf21d7c1479d99d47, 0x9121d91952ffd1c7, 0xa94b528b28f29159,
];
const D_Q: [u64; 16] = [
    0xf7597ffb68011d8d, 0x7b3cc538c4bab8c9, 0xa8fa480a81a925af, 0x6d6ede7251a383bf,
    0x8a63f788ce3a0f85, 0x0b920502eb478bc9, 0x7e37e755edfe70d9, 0x9cf9948422a16555,
    0x0d6d9ea1f2ef71fd, 0xf7efa32ea0cb6e00, 0x0629b114ca7f780f, 0xcf51176359654348,
    0x540cdcbd4ad35435, 0x31c02ff1a2bc437c, 0xff2503df78bafed5, 0x3af0e72a933aef09,
];
const Q_INV: [u64; 16] = [
    0x552fe4bfce945f7b, 0x67e50c999c67247b, 0xfb54ef17be3b2853, 0x241f5921b5ad3983,
    0x02de5eccd143cf31, 0x74e45f6fcc60f216, 0xafa5428a74f12708, 0x88d42294b6a2759b,
    0xe923e1097c0c562f, 0xc968b48a91c38b5b, 0x933e85179c0320b0, 0x7993d0445f758d51,
    0x9bfc042ee0924b1b, 0x41f956d90fa8a793, 0xee7a87b6483a66ee, 0x2640fbfbcfefb163,
];

type V15 = RSASSA_PKCS1_v1_5<RSA2048, SHA256>;
type Pss = RSASSA_PSS<RSA2048, SHA256>;
type PssSalt20 = RSASSA_PSS<RSA2048, SHA512, Mgf1<SHA256, 20>>;
type PssNoSalt = RSASSA_PSS<RSA2048, SHA256, NoSalt<SHA256>>;

const HASH_LEN: SignatureError =
    SignatureError::LengthError("the message hash must be the hash's output length");
const SALT_LEN: SignatureError =
    SignatureError::LengthError("the salt must be the parameters' salt length");

fn key_pair() -> (RsaPublicComponents<RSA2048>, RsaPrivateComponents<RSA2048>) {
    let sk =
        RsaPrivateComponents::<RSA2048>::from_crt_components(&P, &Q, &D_P, &D_Q, &Q_INV, 0x10001)
            .unwrap();
    (RsaPublicComponents::<RSA2048>::new(sk.n(), sk.e()).unwrap(), sk)
}

/// Hash lengths that are not SHA-256's 32: none, SHA-1's 20, one short, one long, SHA-512's.
const WRONG_HASH_LENS: [usize; 5] = [0, 20, 31, 33, 64];

/// An RNG that counts its draws and otherwise fills with a constant.
struct Counting(usize);

impl RNG for Counting {
    fn add_seed_keymaterial(&mut self, _: &dyn KeyMaterialTrait) -> Result<(), RNGError> {
        Err(RNGError::GenericError("not seedable"))
    }
    fn next_int(&mut self) -> Result<u32, RNGError> {
        Err(RNGError::GenericError("not used"))
    }
    fn next_bytes_out(&mut self, out: &mut [u8]) -> Result<usize, RNGError> {
        self.0 += 1;
        out.fill(0x5A);
        Ok(out.len())
    }
    fn fill_keymaterial_out(&mut self, _: &mut dyn KeyMaterialTrait) -> Result<usize, RNGError> {
        Err(RNGError::GenericError("not used"))
    }
    fn security_strength(&self) -> SecurityStrength {
        SecurityStrength::_256bit
    }
}

#[test]
fn pkcs1_v1_5_from_hash_refuses_a_hash_of_the_wrong_length() {
    let (pk, sk) = key_pair();
    let (pk, sk) = (pk.key::<V15>(), sk.key::<V15>());
    let digest = [0x11u8; 64];
    let good = rsassa::sign_from_hash_deterministic(&sk, &digest[..32]).unwrap();
    rsassa::verify_from_hash(&pk, &digest[..32], &good).unwrap();

    for len in WRONG_HASH_LENS {
        assert_eq!(
            rsassa::sign_from_hash_deterministic(&sk, &digest[..len]),
            Err(HASH_LEN),
            "{len}"
        );
        assert_eq!(rsassa::verify_from_hash(&pk, &digest[..len], &good), Err(HASH_LEN), "{len}");
        // The scheme's own encoding and verification, which the functions above go through.
        assert_eq!(V15::emsa_encode::<256>(&digest[..len]), Err(HASH_LEN), "{len}");
    }
}

/// What a release build used to sign for a 20-byte "SHA-256 hash": a `DigestInfo` naming
/// SHA-256 over a 20-byte OCTET STRING. Made here by hand, with its signature under the test
/// key by Python 3.12 (`pow(em, d, n)`), which exponentiation by `e` takes back to the
/// structure: a well-formed signature of it, and not accepted for those 20 bytes, by
/// `verify_from_hash`, which reports the length, or by the scheme's decoding.
#[test]
fn pkcs1_v1_5_does_not_verify_a_digest_info_over_a_short_hash() {
    let (pk, _) = key_pair();
    let short = [0x11u8; 20];
    // RFC 8017 Section 9.2 note 1's SHA-256 prefix with its two lengths cut from 0x31 and 0x20
    // to 0x25 and 0x14, then the 20 bytes.
    let mut t = vec![
        0x30, 0x25, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x14,
    ];
    t.extend_from_slice(&short);
    let mut em = [0xFFu8; 256];
    em[0] = 0x00;
    em[1] = 0x01;
    em[256 - t.len() - 1] = 0x00;
    em[256 - t.len()..].copy_from_slice(&t);

    let signature: [u8; 256] = hex_decode(concat!(
        "01060f84ad7e852a590229460ecedaf84de77c0f1d050a8d0b880db39aabf17e07ab11e726141b00",
        "2e1c8f7efae8c57adfbfca4ba027a25706e61e407f0e623d87207f09e30f3c4eba05f2ce1fba2631",
        "9b4f57072f8a7393092a9c1fe82f467dcd8f29ea2adc9209932847dbabf0faf43eb81ccedc75a194",
        "6bf69f5986120ed0e080fce97b030aa874fd4be4755f035cb784f938d978b65779207b80eebf3bcb",
        "05dbb114a0a57c3395f38de2f25d2a4e18ba34b9d841566b5ebcc77f7e4e0902e67c20374e6d188d",
        "ccfc30c5a9b7349dbca0bc45363d9d5d55dcfdfd20b8b9c172b2068d8d2db6252d7e072d7e347417",
        "a0e41df4927f2b8b65c9b414cfc38398",
    ))
    .unwrap()
    .try_into()
    .unwrap();
    assert_eq!(
        mod_pow_public_exponent::<32, 64, 65>(
            &RSA2048::limbs_from_be_bytes(&signature),
            pk.e(),
            &MontgomeryContext::<32>::for_public_modulus(pk.n()).unwrap()
        ),
        RSA2048::limbs_from_be_bytes(&em)
    );

    assert_eq!(rsassa::verify_from_hash(&pk.key::<V15>(), &short, &signature), Err(HASH_LEN));
    assert!(!V15::emsa_verify::<256>(&short, &em));
    // The same structure over a real hash length is what verification is for.
    let digest = [0x11u8; 32];
    let em = V15::emsa_encode::<256>(&digest).unwrap();
    assert!(V15::emsa_verify::<256>(&digest, &em));
}

#[test]
fn pss_from_hash_refuses_a_hash_of_the_wrong_length() {
    let (pk, sk) = key_pair();
    let digest = [0x11u8; 64];
    let salt = [0x42u8; 32];
    let (pk_pss, sk_pss) = (pk.key::<Pss>(), sk.key::<Pss>());
    let good = rsassa::sign_from_hash_with_salt(&sk_pss, &digest[..32], &salt).unwrap();
    rsassa::verify_from_hash(&pk_pss, &digest[..32], &good).unwrap();

    for len in WRONG_HASH_LENS {
        let h = &digest[..len];
        assert_eq!(rsassa::sign_from_hash_with_salt(&sk_pss, h, &salt), Err(HASH_LEN), "{len}");
        assert_eq!(rsassa::verify_from_hash(&pk_pss, h, &good), Err(HASH_LEN), "{len}");
        // Nothing is drawn for a hash that will be refused.
        let mut rng = Counting(0);
        assert_eq!(rsassa::sign_from_hash(&sk_pss, h, &mut rng), Err(HASH_LEN), "{len}");
        assert_eq!(rng.0, 0, "{len}");
        assert_eq!(Pss::emsa_encode::<256>(h, &salt), Err(HASH_LEN), "{len}");
        assert!(!Pss::emsa_verify::<256>(h, &[0u8; 256]), "{len}");
    }
    let mut rng = Counting(0);
    let drawn = rsassa::sign_from_hash(&sk_pss, &digest[..32], &mut rng).unwrap();
    assert_eq!(rng.0, 1);
    rsassa::verify_from_hash(&pk_pss, &digest[..32], &drawn).unwrap();

    // Unsalted PSS is the deterministic entry point.
    let (pk_ns, sk_ns) = (pk.key::<PssNoSalt>(), sk.key::<PssNoSalt>());
    let good = rsassa::sign_from_hash_deterministic(&sk_ns, &digest[..32]).unwrap();
    rsassa::verify_from_hash(&pk_ns, &digest[..32], &good).unwrap();
    for len in WRONG_HASH_LENS {
        let h = &digest[..len];
        assert_eq!(rsassa::sign_from_hash_deterministic(&sk_ns, h), Err(HASH_LEN), "{len}");
        assert_eq!(rsassa::verify_from_hash(&pk_ns, h, &good), Err(HASH_LEN), "{len}");
        assert_eq!(PssNoSalt::emsa_encode::<256>(h), Err(HASH_LEN), "{len}");
    }
}

#[test]
fn pss_from_hash_refuses_a_salt_of_the_wrong_length() {
    let (pk, sk) = key_pair();
    let salt = [0x42u8; 64];

    // The conventional parameters: the salt is one SHA-256 output.
    let sk_pss = sk.key::<Pss>();
    let digest = [0x11u8; 32];
    for len in [0, 20, 31, 33, 64] {
        assert_eq!(
            rsassa::sign_from_hash_with_salt(&sk_pss, &digest, &salt[..len]),
            Err(SALT_LEN),
            "{len}"
        );
        assert_eq!(Pss::emsa_encode::<256>(&digest, &salt[..len]), Err(SALT_LEN), "{len}");
    }

    // Spelled parameters: SHA-512 with a 20-byte salt. The hash is 64 bytes and the salt 20,
    // and neither length stands in for the other.
    assert_eq!(<PssSalt20 as RsaRandomizedSignatureAlgorithm>::SALT_LEN, 20);
    let (pk_20, sk_20) = (pk.key::<PssSalt20>(), sk.key::<PssSalt20>());
    let mut digest = [0u8; 64];
    SHA512::hash_out(b"the message", &mut digest);
    let good = rsassa::sign_from_hash_with_salt(&sk_20, &digest, &salt[..20]).unwrap();
    rsassa::verify_from_hash(&pk_20, &digest, &good).unwrap();
    for len in [0, 19, 21, 32, 64] {
        assert_eq!(
            rsassa::sign_from_hash_with_salt(&sk_20, &digest, &salt[..len]),
            Err(SALT_LEN),
            "{len}"
        );
    }
    assert_eq!(rsassa::sign_from_hash_with_salt(&sk_20, &digest[..20], &salt[..20]), Err(HASH_LEN));
    assert_eq!(rsassa::verify_from_hash(&pk_20, &digest[..32], &good), Err(HASH_LEN));
}

/// RFC 8017 Section 9.1.1 step 3: "If emLen < hLen + sLen + 2, output "encoding error" and
/// stop." RSA-1024 with SHA-512 and its 64-byte salt needs 130 bytes of a 128-byte modulus.
/// No key signs at RSA-1024, but the pairing can be named and its encoding called through
/// the algorithm traits: an error, and from the verification (Section 9.1.2 step 3,
/// "inconsistent") a refusal, in every build. The next size up has the room.
#[test]
fn pss_encoding_refuses_a_modulus_too_short_for_the_hash_and_salt() {
    use bouncycastle_modexp::rsa::{RSA1024, RSA1536};
    type Short = RSASSA_PSS<RSA1024, SHA512>;
    type Unsalted = RSASSA_PSS<RSA1024, SHA512, NoSalt<SHA512>>;
    type Fits = RSASSA_PSS<RSA1536, SHA512>;
    let too_short =
        || SignatureError::EncodingError("the modulus is too short for this hash and salt length");
    let (digest, salt) = ([0x11u8; 64], [0x42u8; 64]);

    assert_eq!(Short::emsa_encode::<128>(&digest, &salt), Err(too_short()));
    assert!(!Short::emsa_verify::<128>(&digest, &[0u8; 128]));
    let mut em = [0u8; 128];
    em[127] = 0xbc;
    assert!(!Short::emsa_verify::<128>(&digest, &em));

    // Without a salt the same hash fits (66 of 128 bytes), and with one at RSA-1536 too.
    let em = Unsalted::emsa_encode::<128>(&digest).unwrap();
    assert!(Unsalted::emsa_verify::<128>(&digest, &em));
    let em = Fits::emsa_encode::<192>(&digest, &salt).unwrap();
    assert!(Fits::emsa_verify::<192>(&digest, &em));

    // The boundary itself: a 62-byte salt makes hLen + sLen + 2 exactly emLen, which fits, and
    // one byte more does not.
    type Exact = RSASSA_PSS<RSA1024, SHA512, Mgf1<SHA512, 62>>;
    type OneOver = RSASSA_PSS<RSA1024, SHA512, Mgf1<SHA512, 63>>;
    let em = Exact::emsa_encode::<128>(&digest, &[0x42u8; 62]).unwrap();
    assert!(Exact::emsa_verify::<128>(&digest, &em));
    assert_eq!(OneOver::emsa_encode::<128>(&digest, &[0x42u8; 63]), Err(too_short()));
}
