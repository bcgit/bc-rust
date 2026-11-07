//! RFC 7027 Appendix A.3 (512-bit curve, brainpoolP512r1): party A's and B's private keys and
//! public keys and the shared secret's x-coordinate `x_Z`, which is `Z`. Both public keys must
//! derive from their private keys, and the agreement must give `x_Z` from either side.

use bouncycastle_core::agreement_key::AgreementKey;
use bouncycastle_core::key_material::KeyMaterialTrait;
use bouncycastle_core::traits::{KeyAgreementPrivateKey, KeyAgreementPublicKey};
use bouncycastle_eccdh::keys_bp512r1::{ECCDHBp512r1PrivateKey, ECCDHBp512r1PublicKey};
use bouncycastle_eccdh::keys_common::DerivePublicKey;
use bouncycastle_hex::decode as hex_decode;

const D_A: &str = "16302FF0DBBB5A8D733DAB7141C1B45ACBC8715939677F6A56850A38BD87BD59B09E80279609FF333EB9D4C061231FB26F92EEB04982A5F1D1764CAD57665422";
const X_QA: &str = "0A420517E406AAC0ACDCE90FCD71487718D3B953EFD7FBEC5F7F27E28C6149999397E91E029E06457DB2D3E640668B392C2A7E737A7F0BF04436D11640FD09FD";
const Y_QA: &str = "72E6882E8DB28AAD36237CD25D580DB23783961C8DC52DFA2EC138AD472A0FCEF3887CF62B623B2A87DE5C588301EA3E5FC269B373B60724F5E82A6AD147FDE7";
const D_B: &str = "230E18E1BCC88A362FA54E4EA3902009292F7F8033624FD471B5D8ACE49D12CFABBC19963DAB8E2F1EBA00BFFB29E4D72D13F2224562F405CB80503666B25429";
const X_QB: &str = "9D45F66DE5D67E2E6DB6E93A59CE0BB48106097FF78A081DE781CDB31FCE8CCBAAEA8DD4320C4119F1E9CD437A2EAB3731FA9668AB268D871DEDA55A5473199F";
const Y_QB: &str = "2FDC313095BCDD5FB3A91636F07A959C8E86B5636A1E930E8396049CB481961D365CC11453A06C719835475B12CB52FC3C383BCE35E27EF194512B71876285FA";
const X_Z: &str = "A7927098655F1F9976FA50A9D566865DC530331846381C87256BAF3226244B76D36403C024D7BBF0AA0803EAFF405D3D24F11A9B5C0BEF679FE1454B21C4CD1F";

fn pk(x: &str, y: &str) -> ECCDHBp512r1PublicKey {
    let encoded = [&[0x04u8][..], &hex_decode(x).unwrap(), &hex_decode(y).unwrap()].concat();
    ECCDHBp512r1PublicKey::from_bytes(&encoded).unwrap()
}

#[test]
fn rfc7027_appendix_a_3() {
    let sk_a = ECCDHBp512r1PrivateKey::from_bytes(&hex_decode(D_A).unwrap()).unwrap();
    let sk_b = ECCDHBp512r1PrivateKey::from_bytes(&hex_decode(D_B).unwrap()).unwrap();
    let pk_a = pk(X_QA, Y_QA);
    let pk_b = pk(X_QB, Y_QB);
    assert_eq!(sk_a.derive_pk(), pk_a, "Q_A = [d_A]G");
    assert_eq!(sk_b.derive_pk(), pk_b, "Q_B = [d_B]G");

    let x_z = hex_decode(X_Z).unwrap();
    assert_eq!(sk_a.agree(&pk_b, ()).unwrap().ref_to_bytes(), x_z.as_slice(), "x_Z from A");
    assert_eq!(sk_b.agree(&pk_a, ()).unwrap().ref_to_bytes(), x_z.as_slice(), "x_Z from B");
}
