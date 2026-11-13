//! NIST CAVP "ECC CDH Primitive (SP800-56A Section 5.7.1.2)" vectors, CAVS 14.1 (2012-11-19),
//! `bc-test-data/crypto/cavp/KAS_ECC_CDH_PrimitiveTest.txt`, section `[P-256]`: the own
//! private key `dIUT` must derive the own public key `QIUT`, and its agreement with the peer key
//! `QCAVS` must give `ZIUT`. See `cavp_common` for the parser and why a missing checkout fails.

mod cavp_common;

use bouncycastle_core::agreement_key::AgreementKey;
use bouncycastle_core::key_material::KeyMaterialTrait;
use bouncycastle_core::traits::{KeyAgreementPrivateKey, KeyAgreementPublicKey};
use bouncycastle_ec::P256;
use bouncycastle_ec::curve::Curve;
use bouncycastle_eccdh::keys::{ECCDHPrivateKey, ECCDHPublicKey};
use bouncycastle_eccdh::keys_common::DerivePublicKey;
use cavp_common::{get_test_data, hex_field, parse_records, uncompressed_pk};

const SECTION: &str = "P-256";
/// The width of a coordinate in this section: `ceil(log2 p / 8)` bytes.
const FIELD_WIDTH: usize = 32;

#[test]
fn cavp_ecc_cdh_primitive() {
    let content = get_test_data("KAS_ECC_CDH_PrimitiveTest.txt");
    let records: Vec<_> = parse_records(&content)
        .into_iter()
        .filter(|r| r.section == SECTION && r.fields.contains_key("ZIUT"))
        .collect();
    assert_eq!(records.len(), 25, "the P-256 section has 25 records");

    for record in &records {
        let count = &record.fields["COUNT"];
        let peer = uncompressed_pk(
            &hex_field(&record.fields, "QCAVSx", FIELD_WIDTH),
            &hex_field(&record.fields, "QCAVSy", FIELD_WIDTH),
        );
        let own = uncompressed_pk(
            &hex_field(&record.fields, "QIUTx", FIELD_WIDTH),
            &hex_field(&record.fields, "QIUTy", FIELD_WIDTH),
        );
        let d = hex_field(&record.fields, "dIUT", P256::SCALAR_LEN);
        let z_expected = hex_field(&record.fields, "ZIUT", P256::FE_LEN);

        let peer_pk = ECCDHPublicKey::<P256>::from_bytes(&peer)
            .unwrap_or_else(|e| panic!("COUNT {count}: QCAVS {e:?}"));
        let own_pk = ECCDHPublicKey::<P256>::from_bytes(&own)
            .unwrap_or_else(|e| panic!("COUNT {count}: QIUT {e:?}"));
        let sk = ECCDHPrivateKey::<P256>::from_bytes(&d)
            .unwrap_or_else(|e| panic!("COUNT {count}: dIUT {e:?}"));
        assert_eq!(sk.derive_pk(), own_pk, "COUNT {count}: [dIUT]G must be QIUT");

        let z = sk.agree(&peer_pk, ()).unwrap_or_else(|e| panic!("COUNT {count}: agree {e:?}"));
        assert_eq!(z.ref_to_bytes(), z_expected.as_slice(), "COUNT {count}: ZIUT");
    }
}
