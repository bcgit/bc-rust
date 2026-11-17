//! DHKEM(P-384, HKDF-SHA384) (RFC 9180, `kem_id` 0x0011) against BC Java.
//!
//! RFC 9180 defines this KEM (Section 7.1, Table 2) but publishes no vectors for it: neither
//! Appendix A nor the machine-readable set it cites has `kem_id` 17. These four sets were
//! produced by BC Java 1.84 (`bcprov-jdk18on-1.84`, `org.bouncycastle.crypto.hpke.DHKEM`) with a
//! small driver that first ran BC Java over the RFC's own P-256 and P-521 vectors (32 sets,
//! all matching), so the two implementations are shown to agree where the RFC can arbitrate
//! before they are compared where it cannot. They are a cross-check between implementations,
//! not a specification's answers.
//!
//! The keying material is `ikmR[i] = (0x10 * set + i) mod 256` and
//! `ikmE[i] = (0xA5 + 7 * set + 3 * i) mod 256`, 48 bytes each; `enc` and `shared_secret` are
//! BC Java's `Encap(pkR)` under the ephemeral key `DeriveKeyPair(ikmE)`.

use bouncycastle_core::kem_key::DecapsulatingKey;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{PrivateKey, PublicKey};
use bouncycastle_ec::P384;
use bouncycastle_eccdh::dhkem::derive_key_pair;
use bouncycastle_eccdh::keys::ECCDHPrivateKey;
use bouncycastle_hex as hex;

struct Vector {
    ikm_r: &'static str,
    ikm_e: &'static str,
    sk_rm: &'static str,
    sk_em: &'static str,
    pk_rm: &'static str,
    pk_em: &'static str,
    enc: &'static str,
    shared_secret: &'static str,
}

const VECTORS: [Vector; 4] = [
    Vector {
        ikm_r: concat!(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "202122232425262728292a2b2c2d2e2f",
        ),
        ikm_e: concat!(
            "a5a8abaeb1b4b7babdc0c3c6c9cccfd2d5d8dbdee1e4e7eaedf0f3f6f9fcff02",
            "05080b0e1114171a1d202326292c2f32",
        ),
        sk_rm: concat!(
            "98c0889aab5610522699abe5970b7b7132022094127060b928018fb3c0e2aaae",
            "9da72e0c9cf8f909d91c1e1e58f7454a",
        ),
        sk_em: concat!(
            "4898fd003ba5a27412ade8bf543f1e6a734fd31216e5344d12c9798d41cf2800",
            "24d8e0df896e983bbe34310ea71b58cc",
        ),
        pk_rm: concat!(
            "04986dc0a7d2b37e3b222ea7d25a32fc290c88c50b6a0acfdecadb83a285f19a",
            "3ef0dbceeeecf54a9e7e02e4fb2c7bc075c24ba4c069bb3466ba3d35b29783bb",
            "51c74aa60ecfadacb1f4446327b36272176c58d687e5318e5537176f37cc8468",
            "23",
        ),
        pk_em: concat!(
            "047f2b47b78f647740f77394b77592b926821fde59d0d600abdea0d03c6ff682",
            "85f9615eaab384fc97f9eb64e7bc27c36a22c75955cebbd637b4970810fbfa33",
            "e90c150c6d1f6724d2e0563e3e5622bb0c1519757e6b9cfdec607d2037c6c18a",
            "be",
        ),
        enc: concat!(
            "047f2b47b78f647740f77394b77592b926821fde59d0d600abdea0d03c6ff682",
            "85f9615eaab384fc97f9eb64e7bc27c36a22c75955cebbd637b4970810fbfa33",
            "e90c150c6d1f6724d2e0563e3e5622bb0c1519757e6b9cfdec607d2037c6c18a",
            "be",
        ),
        shared_secret: concat!(
            "81e02447bd2be2d8d7174bd37f8429cc982e5a11c22e92fd43f6bf0645960636",
            "40be3396e2a69c56604bad06fc28a4c3",
        ),
    },
    Vector {
        ikm_r: concat!(
            "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
            "303132333435363738393a3b3c3d3e3f",
        ),
        ikm_e: concat!(
            "acafb2b5b8bbbec1c4c7cacdd0d3d6d9dcdfe2e5e8ebeef1f4f7fafd00030609",
            "0c0f1215181b1e2124272a2d30333639",
        ),
        sk_rm: concat!(
            "07533659a577085dfcc27fe94ff34d69758c0a863f1e5cdcfad8862023b2feba",
            "d12fcd7daefc9091c801fac030207964",
        ),
        sk_em: concat!(
            "420f9e547948f2b8dff62b4b508a42290c49cc3b6af0311960492030e9bf89ec",
            "ac49f59c3b6d99f606ab1ec4e5d05805",
        ),
        pk_rm: concat!(
            "047286f352579d02eb3ebe7b9282e7281fdd38b19eee094cbbd4d5c050785a87",
            "d7fa0dfc436f5518aa43b4a6422ddf0b2c4038a71ec990b99ebdd77117163bca",
            "83d0ac4f291d24ad129ef628f5bff6c49a73b7d9e6c0e8491c310e23685c7c5e",
            "d0",
        ),
        pk_em: concat!(
            "04cc624656fa5c186c024c733c55885f1776a30f236852572526c249076c8ba5",
            "d7a7907a87367bc2bcadb488f871d9f3f112cec946ab88739782a83eb5990a2c",
            "501043adb647ee081973a9315def2c83a8f836f40f99f4a35c9647cc60e5f7a2",
            "02",
        ),
        enc: concat!(
            "04cc624656fa5c186c024c733c55885f1776a30f236852572526c249076c8ba5",
            "d7a7907a87367bc2bcadb488f871d9f3f112cec946ab88739782a83eb5990a2c",
            "501043adb647ee081973a9315def2c83a8f836f40f99f4a35c9647cc60e5f7a2",
            "02",
        ),
        shared_secret: concat!(
            "6a29024bd404d3f9547d6cdfeb54525fc08da1faa883bb6be75da1de909bef32",
            "8eb3282f72217d6b753bc2e67e70f8bb",
        ),
    },
    Vector {
        ikm_r: concat!(
            "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
            "404142434445464748494a4b4c4d4e4f",
        ),
        ikm_e: concat!(
            "b3b6b9bcbfc2c5c8cbced1d4d7dadde0e3e6e9eceff2f5f8fbfe0104070a0d10",
            "1316191c1f2225282b2e3134373a3d40",
        ),
        sk_rm: concat!(
            "ba1ddfa9c6f3fc5a6732b25ce1ebbff59edc5cbfe5405639e10a1ecc89a90740",
            "e7876c89584972b3a41ba4dd0cc48cdb",
        ),
        sk_em: concat!(
            "e57dcb1fd76e9460a748ca294fdd8961c851e882a726dab8c6529bd76e4057b0",
            "226c91b5bfd81860854ebf84a6b9da30",
        ),
        pk_rm: concat!(
            "048704cd2566fbbb51bbb0085eaf98a5bc5bba8745466a80b8c36572652ff1dd",
            "9d4fbd87022e3e321b81798a0b5a3b77d5bd5eb19238420c51373f65c3e260b2",
            "06c0d4b806cf83279b27b349a116358beeaea1cc128ffd69ae53172c00a1fa1a",
            "2f",
        ),
        pk_em: concat!(
            "0444eb5d0821edd29680302c3040055a26e8d88c441b0c1e2c8f5e31ad2a0a90",
            "9f564c7ee73c51e5c47c9b85bfed9d148be621dca2b5af34cd95a602288ce98d",
            "e2c3e15272c62e81ad31924d0e4939e936c2f6bc044fcc5895bd5a8a3c3bd339",
            "88",
        ),
        enc: concat!(
            "0444eb5d0821edd29680302c3040055a26e8d88c441b0c1e2c8f5e31ad2a0a90",
            "9f564c7ee73c51e5c47c9b85bfed9d148be621dca2b5af34cd95a602288ce98d",
            "e2c3e15272c62e81ad31924d0e4939e936c2f6bc044fcc5895bd5a8a3c3bd339",
            "88",
        ),
        shared_secret: concat!(
            "f9ef4a264e1bff97665d7612017a3ab10219b0c1436376a2f27d2575808c14f9",
            "c19ea5ec3bd77cfd7389bf9b0c0290d6",
        ),
    },
    Vector {
        ikm_r: concat!(
            "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
            "505152535455565758595a5b5c5d5e5f",
        ),
        ikm_e: concat!(
            "babdc0c3c6c9cccfd2d5d8dbdee1e4e7eaedf0f3f6f9fcff0205080b0e111417",
            "1a1d202326292c2f3235383b3e414447",
        ),
        sk_rm: concat!(
            "f75cf38de0e4d9c0e7300f015a489277523039eecdbd9783f1225f1f8a595d92",
            "84763f708d2253617835c39438325080",
        ),
        sk_em: concat!(
            "d2cf09e656775f00ed91619799edc6ebcf3912d2ec68d4fe910c8b1e93586e01",
            "a79062290eb0473dc433c0c2188eb0d1",
        ),
        pk_rm: concat!(
            "04508ad7a0bf66da82742955a74ed6bdb89a0f523415cb37e17cc61085ada994",
            "f32727cf95ffc2e1a986446c0e476f884a4a366b3b0f4b45d83d4edc9901b452",
            "033957f97bc39bac9b1b216ff36571f63d59ba29aa68f3abc2b6aef8314e272a",
            "9c",
        ),
        pk_em: concat!(
            "04edaee62df6ecc6ddbbab8dfa978368608fb250acf5670b2663acf3f482c93f",
            "a70d2c6487f22f4daf0d9787fd979ba3b591bbd6e3894ba39d0891c91252c044",
            "ac22329bf7c3c169f9072507f79c4023f7ca83464e15ef964febf6b850aea19d",
            "e1",
        ),
        enc: concat!(
            "04edaee62df6ecc6ddbbab8dfa978368608fb250acf5670b2663acf3f482c93f",
            "a70d2c6487f22f4daf0d9787fd979ba3b591bbd6e3894ba39d0891c91252c044",
            "ac22329bf7c3c169f9072507f79c4023f7ca83464e15ef964febf6b850aea19d",
            "e1",
        ),
        shared_secret: concat!(
            "ad562c04b5d3024b1b5dce2e67a4d892ff074086a85abfbb030702af7de0015a",
            "a73635d3bfae9ddb4c3c38e98489f507",
        ),
    },
];

fn seed(hex_str: &str) -> KeyMaterial<128> {
    KeyMaterial::<128>::from_bytes_as_type(&hex::decode(hex_str).unwrap(), KeyType::Seed).unwrap()
}

/// `DeriveKeyPair` agrees with BC Java for the recipient's and the ephemeral keying material.
#[test]
fn derive_key_pair_agrees_with_bc_java() {
    for (i, v) in VECTORS.iter().enumerate() {
        let (pk_r, sk_r) = derive_key_pair::<P384>(&seed(v.ikm_r)).unwrap();
        assert_eq!(hex::encode(sk_r.encode()), v.sk_rm, "set {i} skRm");
        assert_eq!(hex::encode(pk_r.encode()), v.pk_rm, "set {i} pkRm");
        let (pk_e, sk_e) = derive_key_pair::<P384>(&seed(v.ikm_e)).unwrap();
        assert_eq!(hex::encode(sk_e.encode()), v.sk_em, "set {i} skEm");
        assert_eq!(hex::encode(pk_e.encode()), v.pk_em, "set {i} pkEm");
    }
}

/// `Decap` of BC Java's `enc` under the recipient's key gives BC Java's shared secret.
#[test]
fn decaps_agrees_with_bc_java() {
    for (i, v) in VECTORS.iter().enumerate() {
        let sk_r = ECCDHPrivateKey::<P384>::from_bytes(&hex::decode(v.sk_rm).unwrap()).unwrap();
        let enc: [u8; 97] = hex::decode(v.enc).unwrap().try_into().unwrap();
        let ss = sk_r.decaps(&enc, ()).unwrap();
        assert_eq!(hex::encode(ss.ref_to_bytes()), v.shared_secret, "set {i} shared_secret");
        assert_eq!(v.enc, v.pk_em, "set {i}: enc is the ephemeral public key");
    }
}
