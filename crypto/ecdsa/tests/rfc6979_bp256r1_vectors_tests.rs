//! Cross-check against an independent Python implementation of RFC 6979 §3.2 (using Python's own
//! `hmac`/`hashlib`, not derived from this crate) for brainpoolP256r1/SHA-256: RFC 6979 has no
//! official Appendix A.2.x vectors for brainpool curves (its appendix only covers the NIST curves
//! P-192 through P-521), so this is the closest equivalent -- five independently-generated `(d,
//! msg)` pairs (empty, short ASCII, longer ASCII, all-zero, all-`0xff`), each with the
//! deterministic `k`, the resulting `(r, s)`, and `Q = [d]G` computed via the standard affine
//! group law (general `a`), `random.seed 1234567`.
//!
//! On this curve the §3.2 step h.3 rejection loop runs on a third of real messages (see
//! `rfc6979_bp256r1`'s module docs), and these vectors pin it deliberately: CASE_0 rejects one
//! candidate before its `k`, and a sixth pair, CASE_5, is chosen so that five in a row are
//! rejected, exercising the `K = HMAC_K(V || 0x00)` re-key five times. Every vector, including
//! both rejecting ones, is additionally reproduced by python-ecdsa 0.19.2 (its own pure-Python
//! RFC 6979) and by OpenSSL 4.0.2's deterministic ECDSA (through the cryptography 50.0.1
//! bindings), which also anchors the curve constants a second way.

use bouncycastle_core::traits::Hash;
use bouncycastle_core::traits::{
    SignaturePrivateKey, SignaturePublicKey, SignatureVerifier, Signer,
};
use bouncycastle_ec::bp256r1_comb::comb_multiply_base_point;
use bouncycastle_ec::bp256r1_scalar::Bp256r1Scalar;
use bouncycastle_ecdsa::ecdsa_bp256r1::ECDetDSABp256r1;
use bouncycastle_ecdsa::keys_bp256r1::{ECDSABp256r1PrivateKey, ECDSABp256r1PublicKey};
use bouncycastle_ecdsa::rfc6979_bp256r1::generate_k;
use bouncycastle_hex::decode as hex_decode;
use bouncycastle_sha2::SHA256;

struct Vector {
    d: &'static str,
    msg: &'static [u8],
    k: &'static str,
    r: &'static str,
    s: &'static str,
    ux: &'static str,
    uy: &'static str,
}

// The first h.3 candidate for this (d, msg) is >= n: the accepted k is the second, after one
// re-key of the HMAC chain.
const CASE_0: Vector = Vector {
    d: "1201AF823A0A4FE05170CFF294DC13FC115AC6CB3C58FD846EC5C07FF6908E54",
    msg: b"",
    k: "A0E19EABA085BB08D16F30C7AE971295A949C8B000453F712784363710FDC060",
    r: "0B8F953A8F0D6D91DAB6A4A6457FA641FDD10C96E94086CCB62D8513F24D69C7",
    s: "60819F11F5A7D66CF4E6F762682C9DF73013B97343260D38E25E66ABCBF1448C",
    ux: "A6A0C25545FABE99A6DA940773677938492C2763EC54A5146654D5E4BCA7685D",
    uy: "41BA5253532155D7F7F80D8103CA988A60D17407E97D7A778A737535ADFF0773",
};

const CASE_1: Vector = Vector {
    d: "7E7B91BCA9655DC7AA94AFFD753150AEAF395DDF588590D1CB31A5A541346EC1",
    msg: b"sample",
    k: "7D360D0B1F5B42A6B50D004C76B5715BDD3DFD4CE084CBC77CEDA0014C4F750A",
    r: "116AD2387430F54440072A9403C76E9AFA5525A3268174A55CB246E94782A595",
    s: "2F09D7DD0AFEF60D74CBD16CC7DD19D8DCBB2EDEF81B7A11A21965C46193CBB2",
    ux: "4ECD080482532BFC1F6C5DDFBE0F445BCBC3C40E64794FF51ADF8E3205145F04",
    uy: "0AE02177241814BF08BC717B94C73ECC26849951F3F22DF8C29DD52B1781B41C",
};

const CASE_2: Vector = Vector {
    d: "31A01101800F36D7D7F978F0A674894EAF61ACFE376CEAE9AE8692ADE621E465",
    msg: b"test message for RFC 6979 brainpoolP256r1 cross-check",
    k: "2B7CFCFDB9BD902E6CB97EEEE4B66DF58C299A876CA17EDDF07DF61A7C15B471",
    r: "A374D349024E2B2829ECC45A3D7882F28A1CB70A99151CEBDAC98AF701A84A1E",
    s: "89968BA364EE210AA894C67C848B67C78162DA25F20FDFC3F883088169FF90D4",
    ux: "845B89330FE2D4A0DD98C53051E662897C6DEAA47DC984DFFD3681437891CCE6",
    uy: "1BFD2C17D33734CA963DA3A21C8FB2BB02CC8412B860F2CB75B1C04F538C5288",
};

const CASE_3: Vector = Vector {
    d: "330EC367DE3D130E41B64A8D9CA805E18BE822EDD22F87F9914BFAF280DD7C16",
    msg: &[0u8; 32],
    k: "08C64809010AFC34B047B996465699C164FBA094BB1A36ABA4A23D3362DFEC98",
    r: "55558146F7D5CF164C97475C004BE0C2A4E6EB69EA0F140239D360869B88DBD5",
    s: "87F099C25E243DA8B4C0162D2729169A681962DE7FA3AA078463B733A518D729",
    ux: "7AE313447CF7324732217CFA91F5E11A4CB24449C45BCE6642925A5E238CA222",
    uy: "108EC1D7914D723E30D1CA6F65756350476C31703D6D3F07FC848F98BD325906",
};

const CASE_4: Vector = Vector {
    d: "A67E90EC30BC65D57594E68E791FA9ADF8E3DD706ECB52454C5082AF09E88A09",
    msg: &[0xffu8; 10],
    k: "65C065EB328E8D876D31F307C44647ABCFE66291FD28244A9024B38D3E1B482E",
    r: "388B00024108BE9D41B90930E18AE68F05C3CC6F3E318410E3887DD4BE841F5C",
    s: "216DCA2EB91D9D919EE961A5A9C840DDFA64D06CC52815C72D2740E2581CF60B",
    ux: "767C8507AA96B62B2028B9203DD7554274D10444AB32769666695FBADFFF26AB",
    uy: "62F10FDBD0CDE940DD72CEBD0A3C8FB1D734ECB5C6B287CDEB2E50CA650D67C2",
};

// Pins the h.3 continue-chain deliberately: five candidates in a row are >= n, so the accepted k
// follows five `K = HMAC_K(V || 0x00)` re-keys. d is SHA-512("bc-rust brainpoolP256r1 h.3
// rejection pin") reduced into [1, n-1]; the message index is the first to reach five rejections.
const CASE_5: Vector = Vector {
    d: "07C1C10F28FB620F5ABFC2231E5CF77931E282BFCC735F96DE13FDCCFB51F95E",
    msg: b"brainpoolP256r1 rejection test 363",
    k: "753584443CB1744D143C4E19D1DE051F2DB89DEA3F208C1089EFAF093C459CA9",
    r: "2228C1F981B3F9514F15D1D2CFFCF96E5F6C93ABF5208872611B5A69E3B6CC2D",
    s: "64B2088C315AB6158001B09B6F15EC2FE314F1B5CA971E92453A1FCDF414D472",
    ux: "8CBDEA6139F062041BDF604D0C80750AC944D23BFD5406A1EFA70A5FC19B290C",
    uy: "46A4AE6AA2E4182CC865D49169994AD26DA55207D4E517DC68780EC25A263DC1",
};

const CASES: [&Vector; 6] = [&CASE_0, &CASE_1, &CASE_2, &CASE_3, &CASE_4, &CASE_5];

fn bytes32(hex: &str) -> [u8; 32] {
    hex_decode(hex).unwrap().try_into().unwrap()
}

fn public_key_for(v: &Vector) -> ECDSABp256r1PublicKey {
    let mut uncompressed = [0u8; 65];
    uncompressed[0] = 0x04;
    uncompressed[1..33].copy_from_slice(&bytes32(v.ux));
    uncompressed[33..65].copy_from_slice(&bytes32(v.uy));
    ECDSABp256r1PublicKey::from_bytes(&uncompressed).unwrap()
}

#[test]
fn public_key_matches_vectors() {
    for v in CASES {
        let d = Bp256r1Scalar::from_be_bytes(&bytes32(v.d));
        let q = comb_multiply_base_point(&d);
        let (x, y) = q.to_affine().unwrap();
        assert_eq!(
            x.to_limbs(),
            bouncycastle_ec::bp256r1_sec1::limbs_from_be_bytes(&bytes32(v.ux)),
            "Qx for d = {}",
            v.d
        );
        assert_eq!(
            y.to_limbs(),
            bouncycastle_ec::bp256r1_sec1::limbs_from_be_bytes(&bytes32(v.uy)),
            "Qy for d = {}",
            v.d
        );
    }
}

#[test]
fn generate_k_matches_vectors() {
    for v in CASES {
        let d = Bp256r1Scalar::from_be_bytes(&bytes32(v.d));
        let h: [u8; 32] = SHA256::default().hash(v.msg)[..32].try_into().unwrap();
        let k = generate_k(&d, &h);
        assert_eq!(k, Bp256r1Scalar::from_be_bytes(&bytes32(v.k)), "k for message {:?}", v.msg);
    }
}

#[test]
fn deterministic_sign_matches_vectors() {
    for v in CASES {
        let sk = ECDSABp256r1PrivateKey::from_bytes(&bytes32(v.d)).unwrap();
        let sig = ECDetDSABp256r1::sign(&sk, v.msg, None).unwrap();
        let mut expected = [0u8; 64];
        expected[..32].copy_from_slice(&bytes32(v.r));
        expected[32..].copy_from_slice(&bytes32(v.s));
        assert_eq!(sig, expected, "signature for message {:?}", v.msg);
    }
}

#[test]
fn deterministic_signature_verifies() {
    for v in CASES {
        let sk = ECDSABp256r1PrivateKey::from_bytes(&bytes32(v.d)).unwrap();
        let pk = public_key_for(v);
        let sig = ECDetDSABp256r1::sign(&sk, v.msg, None).unwrap();
        ECDetDSABp256r1::verify(&pk, v.msg, None, &sig).unwrap();
    }
}
