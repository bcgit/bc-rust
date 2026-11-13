//! RFC 7027 Appendix A.1 (256-bit curve, brainpoolP256r1): party A's and B's private keys and
//! public keys and the shared secret's x-coordinate `x_Z`, which is `Z`. Both public keys must
//! derive from their private keys, and the agreement must give `x_Z` from either side.

use bouncycastle_core::agreement_key::AgreementKey;
use bouncycastle_core::key_material::KeyMaterialTrait;
use bouncycastle_core::traits::{KeyAgreementPrivateKey, KeyAgreementPublicKey};
use bouncycastle_ec::Bp256r1;
use bouncycastle_eccdh::keys::{ECCDHPrivateKey, ECCDHPublicKey};
use bouncycastle_eccdh::keys_common::DerivePublicKey;
use bouncycastle_hex::decode as hex_decode;

const D_A: &str = "81DB1EE100150FF2EA338D708271BE38300CB54241D79950F77B063039804F1D";
const X_QA: &str = "44106E913F92BC02A1705D9953A8414DB95E1AAA49E81D9E85F929A8E3100BE5";
const Y_QA: &str = "8AB4846F11CACCB73CE49CBDD120F5A900A69FD32C272223F789EF10EB089BDC";
const D_B: &str = "55E40BC41E37E3E2AD25C3C6654511FFA8474A91A0032087593852D3E7D76BD3";
const X_QB: &str = "8D2D688C6CF93E1160AD04CC4429117DC2C41825E1E9FCA0ADDD34E6F1B39F7B";
const Y_QB: &str = "990C57520812BE512641E47034832106BC7D3E8DD0E4C7F1136D7006547CEC6A";
const X_Z: &str = "89AFC39D41D3B327814B80940B042590F96556EC91E6AE7939BCE31F3A18BF2B";

fn pk(x: &str, y: &str) -> ECCDHPublicKey<Bp256r1> {
    let encoded = [&[0x04u8][..], &hex_decode(x).unwrap(), &hex_decode(y).unwrap()].concat();
    ECCDHPublicKey::<Bp256r1>::from_bytes(&encoded).unwrap()
}

#[test]
fn rfc7027_appendix_a_1() {
    let sk_a = ECCDHPrivateKey::<Bp256r1>::from_bytes(&hex_decode(D_A).unwrap()).unwrap();
    let sk_b = ECCDHPrivateKey::<Bp256r1>::from_bytes(&hex_decode(D_B).unwrap()).unwrap();
    let pk_a = pk(X_QA, Y_QA);
    let pk_b = pk(X_QB, Y_QB);
    assert_eq!(sk_a.derive_pk(), pk_a, "Q_A = [d_A]G");
    assert_eq!(sk_b.derive_pk(), pk_b, "Q_B = [d_B]G");

    let x_z = hex_decode(X_Z).unwrap();
    assert_eq!(sk_a.agree(&pk_b, ()).unwrap().ref_to_bytes(), x_z.as_slice(), "x_Z from A");
    assert_eq!(sk_b.agree(&pk_a, ()).unwrap().ref_to_bytes(), x_z.as_slice(), "x_Z from B");
}
