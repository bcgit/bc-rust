//! RFC 7027 Appendix A.2 (384-bit curve, brainpoolP384r1): party A's and B's private keys and
//! public keys and the shared secret's x-coordinate `x_Z`, which is `Z`. Both public keys must
//! derive from their private keys, and the agreement must give `x_Z` from either side.

use bouncycastle_core::agreement_key::AgreementKey;
use bouncycastle_core::key_material::KeyMaterialTrait;
use bouncycastle_core::traits::{KeyAgreementPrivateKey, KeyAgreementPublicKey};
use bouncycastle_eccdh::keys_bp384r1::{ECCDHBp384r1PrivateKey, ECCDHBp384r1PublicKey};
use bouncycastle_eccdh::keys_common::DerivePublicKey;
use bouncycastle_hex::decode as hex_decode;

const D_A: &str = "1E20F5E048A5886F1F157C74E91BDE2B98C8B52D58E5003D57053FC4B0BD65D6F15EB5D1EE1610DF870795143627D042";
const X_QA: &str = "68B665DD91C195800650CDD363C625F4E742E8134667B767B1B476793588F885AB698C852D4A6E77A252D6380FCAF068";
const Y_QA: &str = "55BC91A39C9EC01DEE36017B7D673A931236D2F1F5C83942D049E3FA20607493E0D038FF2FD30C2AB67D15C85F7FAA59";
const D_B: &str = "032640BC6003C59260F7250C3DB58CE647F98E1260ACCE4ACDA3DD869F74E01F8BA5E0324309DB6A9831497ABAC96670";
const X_QB: &str = "4D44326F269A597A5B58BBA565DA5556ED7FD9A8A9EB76C25F46DB69D19DC8CE6AD18E404B15738B2086DF37E71D1EB4";
const Y_QB: &str = "62D692136DE56CBE93BF5FA3188EF58BC8A3A0EC6C1E151A21038A42E9185329B5B275903D192F8D4E1F32FE9CC78C48";
const X_Z: &str = "0BD9D3A7EA0B3D519D09D8E48D0785FB744A6B355E6304BC51C229FBBCE239BBADF6403715C35D4FB2A5444F575D4F42";

fn pk(x: &str, y: &str) -> ECCDHBp384r1PublicKey {
    let encoded = [&[0x04u8][..], &hex_decode(x).unwrap(), &hex_decode(y).unwrap()].concat();
    ECCDHBp384r1PublicKey::from_bytes(&encoded).unwrap()
}

#[test]
fn rfc7027_appendix_a_2() {
    let sk_a = ECCDHBp384r1PrivateKey::from_bytes(&hex_decode(D_A).unwrap()).unwrap();
    let sk_b = ECCDHBp384r1PrivateKey::from_bytes(&hex_decode(D_B).unwrap()).unwrap();
    let pk_a = pk(X_QA, Y_QA);
    let pk_b = pk(X_QB, Y_QB);
    assert_eq!(sk_a.derive_pk(), pk_a, "Q_A = [d_A]G");
    assert_eq!(sk_b.derive_pk(), pk_b, "Q_B = [d_B]G");

    let x_z = hex_decode(X_Z).unwrap();
    assert_eq!(sk_a.agree(&pk_b, ()).unwrap().ref_to_bytes(), x_z.as_slice(), "x_Z from A");
    assert_eq!(sk_b.agree(&pk_a, ()).unwrap().ref_to_bytes(), x_z.as_slice(), "x_Z from B");
}
