//! RFC 8032 Section 7.1 (Ed25519, all five vectors) and Section 7.3 (Ed25519ph), through the
//! public API: private key to public key, signing and verification.
//!
//! The tables were lifted from the text of the RFC by script, not typed.

use bouncycastle_core::signature_key::{
    DeterministicOneShotSigningKey, DeterministicSigningKey, OneShotVerifyingKey, VerifyingKey,
};
use bouncycastle_core::traits::{PrivateKey, PublicKey, SignatureSigner, SignatureVerifier};
use bouncycastle_ed::ed25519::{Ed25519PrivateKey, Ed25519PublicKey, keypair_consistency_check};

// (test name, secret key, public key, message, signature)
const RFC8032_ED25519: &[(&str, &str, &str, &str, &str)] = &[
    (
        "1",
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        concat!(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bac",
            "c61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
    ),
    (
        "2",
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        concat!(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e",
            "458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
    ),
    (
        "3",
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        concat!(
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290",
            "ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        ),
    ),
    (
        "1024",
        "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
        "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
        concat!(
            "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12",
            "ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe57",
            "38829adb26c81b37c93a1b270b20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338b",
            "bd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe",
            "ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e06203b33890cc9b8",
            "32f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc10",
            "3b6621fcde2beca1231d206be6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53",
            "f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2",
            "d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6",
            "079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c65adb7553",
            "878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2",
            "cf65bd92dd597b0707e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba",
            "b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae078",
            "4504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8",
            "fcffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301",
            "651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8",
            "ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd9",
            "04b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7",
            "984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a",
            "3ca8e1b939ae49e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3",
            "2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a4",
            "3dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041",
            "e989f7914f90cc2c7fff357876e506b50d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d9",
            "0d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d",
            "b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef",
            "68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0",
        ),
        concat!(
            "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f45",
            "28ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03",
        ),
    ),
    (
        "SHA(abc)",
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        concat!(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a8",
            "36ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        ),
        concat!(
            "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ec",
            "fdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
        ),
    ),
];

// (test name, secret key, public key, message, signature)
const RFC8032_ED25519PH: &[(&str, &str, &str, &str, &str)] = &[(
    "abc",
    "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
    "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
    "616263",
    concat!(
        "98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae4131f85042463c2a35",
        "5a2003d062adf5aaa10b8c61e636062aaad11c2a26083406",
    ),
)];

fn bytes(hex: &str) -> Vec<u8> {
    bouncycastle_hex::decode(hex).unwrap()
}

/// The key pair of a vector: the private key decoded, its public key compared with the
/// vector's, and the vector's public key decoded on its own.
fn key_pair(name: &str, sk: &str, pk: &str) -> (Ed25519PublicKey, Ed25519PrivateKey) {
    let sk = Ed25519PrivateKey::from_bytes(&bytes(sk)).unwrap();
    assert_eq!(sk.pk().unwrap().encode().as_slice(), bytes(pk), "{name}: public key");
    let pk = Ed25519PublicKey::from_bytes(&bytes(pk)).unwrap();
    assert_eq!(pk, sk.pk().unwrap(), "{name}");
    keypair_consistency_check(&pk, &sk).unwrap();
    (pk, sk)
}

#[test]
fn rfc_8032_section_7_1_ed25519() {
    assert_eq!(RFC8032_ED25519.len(), 5);
    assert_eq!(bytes(RFC8032_ED25519[3].3).len(), 1023);
    for (name, sk, pk, msg, sig) in RFC8032_ED25519 {
        let (pk, sk) = key_pair(name, sk, pk);
        let (msg, sig) = (bytes(msg), bytes(sig));

        let signed = sk.sign_deterministic(&msg, None).unwrap();
        assert_eq!(signed.as_slice(), sig, "{name}: signature");
        pk.verify(&msg, None, &sig).unwrap();
        // It is not an Ed25519ph signature.
        assert!(pk.as_prehash().verify(&msg, None, &sig).is_err());
    }
}

#[test]
fn rfc_8032_section_7_3_ed25519ph() {
    assert_eq!(RFC8032_ED25519PH.len(), 1);
    for (name, sk, pk, msg, sig) in RFC8032_ED25519PH {
        let (pk, sk) = key_pair(name, sk, pk);
        let (msg, sig) = (bytes(msg), bytes(sig));

        // The vector has no context: none, and the empty one.
        for ctx in [None, Some(&[][..])] {
            let signed = sk.as_prehash().sign_deterministic(&msg, ctx).unwrap();
            assert_eq!(signed.as_slice(), sig, "{name}: signature");
            pk.as_prehash().verify(&msg, ctx, &sig).unwrap();
        }

        // Streamed an octet at a time.
        let mut signer = sk.as_prehash().create_signer_deterministic(None).unwrap();
        let mut verifier = pk.as_prehash().create_verifier(None).unwrap();
        for octet in msg.chunks(1) {
            signer.do_update(octet);
            verifier.do_update(octet);
        }
        assert_eq!(signer.do_final().unwrap().as_slice(), sig, "{name}: streamed");
        verifier.do_verify_final(&sig).unwrap();

        // It is not an Ed25519 signature.
        assert!(pk.verify(&msg, None, &sig).is_err());
    }
}
