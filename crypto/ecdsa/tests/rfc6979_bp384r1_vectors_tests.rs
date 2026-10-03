//! Cross-check against an independent Python implementation of RFC 6979 §3.2 (using Python's own
//! `hmac`/`hashlib`, not derived from this crate) for brainpoolP384r1/SHA-384: RFC 6979 has no
//! official Appendix A.2.x vectors for brainpool curves; five independently-generated `(d, msg)`
//! pairs (empty, short ASCII, longer ASCII, all-zero, all-`0xff`), each with the deterministic
//! `k`, the resulting `(r, s)`, and `Q = [d]G` computed via the standard affine group law (general
//! `a`), `random.seed 1234567`.

use bouncycastle_core::traits::Hash;
use bouncycastle_core::traits::{
    SignaturePrivateKey, SignaturePublicKey, SignatureVerifier, Signer,
};
use bouncycastle_ec::bp384r1_comb::comb_multiply_base_point;
use bouncycastle_ec::bp384r1_scalar::Bp384r1Scalar;
use bouncycastle_ecdsa::ecdsa_bp384r1::ECDSABp384r1;
use bouncycastle_ecdsa::keys_bp384r1::{ECDSABp384r1PrivateKey, ECDSABp384r1PublicKey};
use bouncycastle_ecdsa::rfc6979_bp384r1::generate_k;
use bouncycastle_hex::decode as hex_decode;
use bouncycastle_sha2::SHA384;

struct Vector {
    d: &'static str,
    msg: &'static [u8],
    k: &'static str,
    r: &'static str,
    s: &'static str,
    ux: &'static str,
    uy: &'static str,
}

const CASE_0: Vector = Vector {
    d: "0A3ECED49C8BE3E693AF8A68F77282BD1201AF823A0A4FE05170CFF294DC13FC115AC6CB3C58FD846EC5C07FF6908E54",
    msg: b"",
    k: "3FC56705D95B3FEE45DD25E9B16F5A1BCB7769D0AA8782A1F6A40ECC1913ABB96F1868AD0EE9391884B159B491B4FF53",
    r: "26B68E91F47AF625048D8B83AAE51A225E8EF081DB72DB2DE9794BF363C0FC8057319941DD127664E7876D4013A6148F",
    s: "2E86B247F68E070380656BAAFDEC7C4F14063241642A158FB6E002D7D86FA990574AB86A8C3CCE3B05D642DD35BE1787",
    ux: "320C24C58062BC08BB59C576C8261D873B1BC8D2B7458A85C3734565B8D9CA289692E2AFE3633EB1C3A2D900813AEAA6",
    uy: "503CA7DC163064CBFA64790AAFBE97D325B874DAB95D23AFA699CC00B3B8BB54E9BCC637713AF9E829D87878D27FA8A2",
};

const CASE_1: Vector = Vector {
    d: "8BE822EDD22F87F9914BFAF280DD7C1531A01101800F36D7D7F978F0A674894EAF61ACFE376CEAE9AE8692ADE621E465",
    msg: b"sample",
    k: "3C7FA6ED4AAF3AAD9E43F4CE4358455015E8E9B33E169BFB59CCEF92DA47D304A238B94617732DC27BA29E14E3C296AE",
    r: "0E3EB847856EDDBBA79B6A794E7C47CF2017FB55F82D12CEC8E8205CFB51B7F2925906CBD527AC1DD9283167E7E5D098",
    s: "6F2E40C4E636F0FC6A55DC74AADC68D2C1E264C27948FA3BAE84943A67CC231AA7B0B0F3CC83C2C26BE2B0BF79415D10",
    ux: "758855E97E1648F5FA81A6F3A4B987C1E043F428502954D30DB662E25BEC4A228E29CA78370F5B2EE1AC2DB4A853C157",
    uy: "4AD9E8AECBB17CD175381EBF72F9933D9CDB9CDEF87641A480AF3A76225BDF38C87170F0CFAF6D1F1BC1E57FBAD061A1",
};

const CASE_2: Vector = Vector {
    d: "59D4756A0A10302D86464ED67338BD3217BAA6642A507BD5336ED46492D516FEE5A381A0C9D32A03D4CCAF167412C30D",
    msg: b"test message for RFC 6979 brainpoolP384r1 cross-check",
    k: "16C5B418941903EEB9BCB368EF69803B46147902C83FE09972FFFC7D6C4C34F91B88A752CB31461A3B32D938ED365D31",
    r: "39FD12109FD43E281557AA9A72C53644878349ACFD4014C09952AD23C7646D9FE38EB91AF48E3FE9E56BBE1C1B26C0E9",
    s: "69AE82BD7A4DA2CD3486309D7544A665478EF93DC6B93A93611BCED16513AAC25AF1B79B99C1A3D2FCA7E11523640DA0",
    ux: "7831F05270F3A9B5EBFFF2003DD13C3CDDCB67348265B73AF054F9AD46FC4D7EB134AAED3E78F1F126C9D6B0AC8CE09D",
    uy: "78795C35667B76A614646A8F7187B29153A13DDF2CFABB29FCAC838103FD649A84335F4E3A5C6B915DF7F8189A2E496A",
};

const CASE_3: Vector = Vector {
    d: "3BFDEAFDE8ED1C92C83FC7A3FB856FE01E484B7A312A44DD6494CF57049E427467DFEBC315C77C8AF429FCF59430B282",
    msg: &[0u8; 32],
    k: "80B3FC797B1EEB3B7B012691E4BF25B5A139C609A8F67A6FAAFB3E7DCE8F6B2ECCE425A4A05511D8ECD61D6A9AADF7D2",
    r: "3149C49F6FF4515C00EDB3592F1139374B107E0592121AAFA3D4C159C04F00759BD648BD27B2BCDF737FC20D734C4862",
    s: "80AF76FE73606B75DDE71E8FFA388BBE4FAEDB122D583DFB3571004C137BCAE440FA197D9FF91A0A351103A0D2956ACC",
    ux: "239CF75A0C6291C46835846A3D634EB8682E9D70D443358F9D6EB7BBA08E5AA8B63937F56A7423BE76F566335B1E7DFE",
    uy: "776FB4EA44FE91B2CD416CA75D3F115D0B044826D949E129F7A5B5008C6CB069925D86B6EEBD5EDCF813AC2B5D417305",
};

const CASE_4: Vector = Vector {
    d: "3AC2CE16303249B912258C63556A44E17CEE4B4D567578F26A89C3FC0098EFE577CBF8FCAC22AAE164F74D7169CEB006",
    msg: &[0xffu8; 10],
    k: "866B6A38D026D864CD5B3FF749B271D081AF3E6C3B53ACE0899006B722E30781C7258A734209E1C1C88451D73F431E29",
    r: "41801494B55EE535AB19F416992D044A6E7F9272BACB9C898297F580BA8D23F261CD75936A2B283DFBD4C694EFEE4A42",
    s: "0A13D21EBBB985D37F28921C8DA8DF207E8D7914062FCC4376CEEB85338BE6C661EBA26615CA8B3FF2CB620EFED64E44",
    ux: "2123645AD346A966820312FC832DBAD86A20C249819121BCADBD17C1A18DE49605EBF74AEAA128C6E03F4CB48744983E",
    uy: "64DE68D75FA78C5E6F9B37E297163E77EFFABB263D957D5C017EAF2AD4F9F9567664BB1E701959E6302BE803300CE40F",
};

const CASES: [&Vector; 5] = [&CASE_0, &CASE_1, &CASE_2, &CASE_3, &CASE_4];

fn bytes48(hex: &str) -> [u8; 48] {
    hex_decode(hex).unwrap().try_into().unwrap()
}

fn public_key_for(v: &Vector) -> ECDSABp384r1PublicKey {
    let mut uncompressed = [0u8; 97];
    uncompressed[0] = 0x04;
    uncompressed[1..49].copy_from_slice(&bytes48(v.ux));
    uncompressed[49..97].copy_from_slice(&bytes48(v.uy));
    ECDSABp384r1PublicKey::from_bytes(&uncompressed).unwrap()
}

#[test]
fn public_key_matches_vectors() {
    for v in CASES {
        let d = Bp384r1Scalar::from_be_bytes(&bytes48(v.d));
        let q = comb_multiply_base_point(&d);
        let (x, y) = q.to_affine().unwrap();
        assert_eq!(
            x.to_limbs(),
            bouncycastle_ec::bp384r1_sec1::limbs_from_be_bytes(&bytes48(v.ux)),
            "Qx for d = {}",
            v.d
        );
        assert_eq!(
            y.to_limbs(),
            bouncycastle_ec::bp384r1_sec1::limbs_from_be_bytes(&bytes48(v.uy)),
            "Qy for d = {}",
            v.d
        );
    }
}

#[test]
fn generate_k_matches_vectors() {
    for v in CASES {
        let d = Bp384r1Scalar::from_be_bytes(&bytes48(v.d));
        let h: [u8; 48] = SHA384::default().hash(v.msg)[..48].try_into().unwrap();
        let k = generate_k(&d, &h);
        assert_eq!(k, Bp384r1Scalar::from_be_bytes(&bytes48(v.k)), "k for message {:?}", v.msg);
    }
}

#[test]
fn deterministic_sign_matches_vectors() {
    for v in CASES {
        let sk = ECDSABp384r1PrivateKey::from_bytes(&bytes48(v.d)).unwrap();
        let sig = ECDSABp384r1::sign(&sk, v.msg, None).unwrap();
        let mut expected = [0u8; 96];
        expected[..48].copy_from_slice(&bytes48(v.r));
        expected[48..].copy_from_slice(&bytes48(v.s));
        assert_eq!(sig, expected, "signature for message {:?}", v.msg);
    }
}

#[test]
fn deterministic_signature_verifies() {
    for v in CASES {
        let sk = ECDSABp384r1PrivateKey::from_bytes(&bytes48(v.d)).unwrap();
        let pk = public_key_for(v);
        let sig = ECDSABp384r1::sign(&sk, v.msg, None).unwrap();
        ECDSABp384r1::verify(&pk, v.msg, None, &sig).unwrap();
    }
}
