//! HPKE known answers for what RFC 9180 defines but publishes no vectors for: DHKEM(P-384,
//! HKDF-SHA384) as the KEM (`kem_id` 0x0011) and HKDF-SHA384 as the KDF (`kdf_id` 0x0002).
//! Neither Appendix A nor the `[TestVectors]` file it cites has either.
//!
//! The six sets below are BC Java 1.84's (`org.bouncycastle.crypto.hpke.HPKE`), as the sender,
//! from a driver that first reproduced the RFC's vectors with BC Java: the 96 entries of
//! `kem_id` 16, 18 and 32 as the recipient (18504 encryptions, 288 exports) and the Base ones as
//! the sender under the vector's ephemeral key (4626 encryptions). This crate is the recipient
//! of each set. The suites are P-384 with HKDF-SHA384 and AES-256-GCM (Base, and Auth), with
//! ChaCha20Poly1305 (PSK) and with AES-128-GCM (AuthPSK), X25519 with HKDF-SHA384 and
//! AES-128-GCM (Base), and P-521 with HKDF-SHA384, export-only (PSK). The 80-byte export is
//! HKDF-SHA384's two-block expand.

use bouncycastle_aes::{AES128Key, AES256Key};
use bouncycastle_cipher::modes::GCM;
use bouncycastle_core::hex;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{PrivateKey, PublicKey};
use bouncycastle_digest::sha2::SHA384;
use bouncycastle_ec::{P384, P521};
use bouncycastle_eccdh::keys::{ECCDHPrivateKey, ECCDHPublicKey};
use bouncycastle_ed::x25519::{X25519PrivateKey, X25519PublicKey};
use bouncycastle_hybrid::hpke::{
    ExportOnly, HpkeAead, HpkeAuthRecipient, HpkeCipher, HpkeContext, HpkeParams, HpkeRecipient,
    Psk, Recipient,
};
use bouncycastle_symmetric::chacha20_poly1305_aead::ChaCha20Poly1305Key;
use std::collections::HashMap;

/// The sets, separated by blank lines, as the driver printed them.
const SETS: &str = "\
kem_id = 17
kdf_id = 2
aead_id = 2
mode = 0
skRm = b0f2570f2b2b695106a7d8cd975adf7152ccfc26dbef1507f9b858895e70ebf0a5461e2701f29d33457d1d6a0975e053
pkRm = 0471e37149b174e718adf02124514d4965d0a6243866933e4a28220afed5ef839f4470d156e3feafd7d9a476731a101df37517c594aa20625c0f11e89f3f9282097b4c36d43e74074d7d2bf5667fe241f4418e1d6573bede276f94ace703f7bd4e
enc = 04ab0839a77608065dbf856f500a265ccab4bd2c652e064208e672398a2ae84ed5c74f2ad0f4fccd26c8d93b8c4a1bad12477f8e1249a98c5931e5200080f3267a1762080b2dcbe3a82e21b0ddcc97b5a701a097d653cd12e848f789c73e02f1dd
info = 1152e5de439a308c85b11fc745456e35eab40aec
aad0 = 9cf75e1c907845
pt0 = a1d1cbcfb020a4a7fbaebd877c208993979360339d9ebcd56319bc8eaf
ct0 = 0bfd60a524b85f2cfc13ebc0626f47baaa26dfd66df8bed63850819ca4a2e505ceed4c563bd0d1f5e79c149abd
aad1 = e989782951c5cfaa
pt1 = f22d16185108b13be33ad5e6721faa54db6be2b61a907ca36ee96007b7f2106b33bb858d7b8dfe63b85d35e8ea
ct1 = 73d53b0d5aa9b13ff356a54f5a8178a2edf976f363806672a44742083dc328769df6b9295caf88f26465a1750ed58eb0fab26f2e80da11c7897c46d9a4
aad2 = 39c1723f874e7f8dd2
pt2 = 5924361f97179fc0ce6860bff2c82d69056264205c7a098b1fb4081ec3b68ca2b10daa5295cf1c136ce3f7fc6a779fa56f360dc3ce8b560186f3fb7723
ct2 = 901ec4a750ebf9779f2f87a5ca7d334b915e2492acd99624c032e49e202712c25c2c03406287f64fc0159839dcfabf84eb3afd207101d650067a468c3d3c1f1e78ef9497c933a5ebcb00f4249e
exporter_context = 15d62c19f2e3fb0fd853b8
exported32 = 3389c412ee506477cac088f663bf60b86f90f3f7e7fff47e5626ec00f3fa2215
exported80 = 57274fcd49611567d86466978ced4f8d3493e2f333477dd97b50cae4d896550952244bec682f27ff5dd4279f62635efe70469a206403c2728785c17e272ab46b5a53c82f5400b16d2003a7e06fe4a53a

kem_id = 17
kdf_id = 2
aead_id = 3
mode = 1
skRm = 1ee4a14ddbef4d6c5da4655eb3a009d6e10a468e1b2511f7aeced29a557acb6d3e6c6ee41e74b00a88a542b5006fe092
pkRm = 042f3a1683236f4edc45a57d5860955a7ff67a4d331696367f5fb11f8429d4c530d4b01a552dfa7e45d652db601170f14c357da1cdc9ddbf74bb51f0b98a783a39fbc50e4dba95c60187d6195e2891f86536c19f71131fe96fe442c6bc3818de69
enc = 04efad3256e6412e8a8de29e63263c6e08b0d239cca517c9638ad3d64ad4ffd5bd079855ce73d494ec4298d032e0b6dada059b782507dd6d3d62511fcef2659123dad4f0c43ec4df7b44e240ba7d602380454d596053c2b89a77343fdfe74a94b1
info = 57230bcac0572fe5f957b10e392c560f0e7bfc14
psk = 46a818ffb4ad789a515d5077eddcc3d3e57f02aeda5bed0ad5400fd5b825d20c
psk_id = 14a15341f1b815953b0b08
aad0 = 0673cc32e846d1
pt0 = f5c85705f5f77f4eadea7f02a2ff84a15c6679b1f8ddbbc8bae1e11886
ct0 = 02f48efcd00ffd4efeb2013d08f2e4bef8f95d2575d2a98d1d1262d0289b5ba9953ab45ade53759cd751662a66
aad1 = d49f233879d2eb9e
pt1 = 5b9813c23735a1606adf56b87577c064e48ef88b7d1fb8c2127b09e514331f78e832be690fd3456d36a969eb9b
ct1 = 49eace98574bc013e54f2d564766f53c19243110c70a1e67e616d54f54cc805698b120e71220b3bbf9a68f1939c43d8d4f3e043fb4a525d01f9725e48a
aad2 = c638c5db700ee1155d
pt2 = 878279595e7242442945ecb71abe24e884a25e73e73f59e338129f7a319d298eb2f937e47eb74fbba3a92aac4b53c27755763dffd7bd7a4137e2b1ee87
ct2 = 7a4b0c462cb84792bc77f053439a0bfc437723595dda4539c0248b12b1971676c1a3c273d36be568d26faee7d5c7cebff9215cea195cac49e58a2275387a461ae47316a0cda565943807f9c687
exporter_context = 4ad08f4fd1c7557216c7e8
exported32 = 66e450f5ab0a3ed72310486097c849a08704202b061779cdb0ca3d5bce4ab920
exported80 = fdb7fd1698ecfe3c54c16fa958a4a885ae36dd49b26ea88700c16e06211d5e7e36c6631fa18d71617e2ea937c785be4031b3aa0327eee5ff764c2eb6019a6b7e737c881efa2a51cd97ec8df73290d5d5

kem_id = 32
kdf_id = 2
aead_id = 1
mode = 0
skRm = 50af821fc8293217ff78381191bdd20f9e6d9cb4e8ef0cbb500158a364f80c55
pkRm = 67d82507a12e4d8cfc1f124fe8e9d675590c537400120575961a56112c8e4403
enc = f2cef189d1de6a26bed116a9b584a5b72404eee76b344719ea605962e7645721
info = 9d456b31e93e3c9a76029f819e2c9ac5401b67cd
aad0 = c09efd017c70cf
pt0 = 7f1799b6a059f59cbd1925c84aeeec363cb7e1d3ecc254cb67487b176f
ct0 = 1fb2e838c42e14bb77e397873f8b9322e6c149d69186f609746ca6569ba861158995eeb089c50c68646bea6651
aad1 = 4cdd1258a8365181
pt1 = db301b9bac5e99e57331b0fcb666a63652df34c44406959303ad7b42b0e84ca9b53de1b6ee6c2ef5e096ebf3da
ct1 = 4cecc80c3c3c57ec8ec0eee7ceb40b69e55928f9c9a8c3e04c6bc1f89a4cd013ca444e6489da58177eca96745b5cab4bd3d61364e952acc459c1966fe8
aad2 = ed12a2d604343a419c
pt2 = 9b0f82dd576dd9f7009b751e52ccbd8aaf2515e940888f3e6756f8e1acbcea655ac216160bd3d94ed25514486a8c58125945a142f18c4451f6db629edd
ct2 = 6e0425bcba279fbf4e795fe03c54ecd08f979947403395ad61f5a6b59bffde0c39d15e51bfffc3185cfbc6691f1c2fc878c15b51c34ef538aade1e6e5ebf8d19c1d454b33116b0f0a48af42a0e
exporter_context = 30173c9787821a8c4f5729
exported32 = c9aea56c8db40f87b0f930b7635cf291323aac1cc23454319d6debba5a683cfa
exported80 = 3e51b90ea407bc0e1dc05af02b8f351a66e3d2b6614e43004861cb0bdb49d876c55a866f6e293f08a8d277d04384d697d885f429ede9a96fe19f95ebf88883d8677b437d44a1478d3085de61517b78b3

kem_id = 18
kdf_id = 2
aead_id = 65535
mode = 1
skRm = 0141cdf9f4e82bd117f68ce37061098057911746ee8ee2271dffd49574e465fa54dd2e08e1d932dc1dd4bc3a106470b5e9719fc46354f208db03e33a2a98e053f104
pkRm = 040045e440f37da99968b4760f9e3124823fade582dd0bbb168353381ccaa222ad1e2f15f6b14f04cb0043f8b5c125fc64deec7ec2841a59b5ade24271ecec1384ec7d00f3ded08d93b161750763e58f7c8d61f05ef474c2876cbc0067b064b96b244b1c7c32e6ef62bea058c6601f869031b6af34976beda16fc2176df7b2d61cab71e8b3
enc = 040072049ebe1dc3c5d813dfeea4a21882f192ee5c9f283f0de9428ab3821fdc999ee38fe90cb52239e2c24809f712ac9ed182c069e30f09bc48b925c214e0e1ec9a4500fd2871feb57f5b8756743746d87daddb929e60ed2c6874fe78f3e9f5949a80b1dec50d83f9c9287602fa9fb6298ee057262af5506e0c89485e4ce064f34cac5c37
info = ca51ed5e538b8539d0c51d4d6fa1f457b87edbe4
psk = c0c8f30fc16c39d2853b14b116d1ed39f497bf5bf8f02c417c3edb4840765b2c
psk_id = d6922367fe9cc0048bbcd9
exporter_context = 1daed9f4967a163b223b13
exported32 = 179306f836f4216c5fde57e862a87b1059d39b3b1274ed817d62e759c509a017
exported80 = cefa515d10e4b32beaf83c247ab50dc0d42ff07bc94a9d5279a618bf40881d0c00609e337a22638596ec2ac7241686767258171bb9e08a4f8048ba160c3d1b9472f1d2c4c974bf5a32b64bb805fd8b8e

kem_id = 17
kdf_id = 2
aead_id = 2
mode = 2
skRm = 95551e86ef074d61ac6248bed7cf681166a8bd3bef9be45618a430a69aa3708ccd1055d1d08f704ec0830fa41b637c44
pkRm = 04e685c05eef0b4750caed57bbf5a1d153eecff469fefaa38628d40d2bfb5b4c665379c350f4b5549649657846bc03c10c63b2491cc9373b9aca4d3bffe87d7b577a88c0156f60f6c960cb50a615edf04d29ee51ce0e558b93aac34fa7b0884786
enc = 04ead1458799854c339601a4fb3f42266e4f26fc8d694cf11e55562f7bc1f24fb786b9d7095eaee6749152551d764729abfc5ecba124676d1aa40be1a94f8df377aafb140a23568346941a4d1424035cb766bb1db0e3555f14912c5eb530eec44d
info = 6ca01bb50ee2c746a2077c790dc902947d21e71c
pkSm = 04c047739a6290d5115debb2aeb7d023b0cebdae0aa8ec49488c2e00e2f8e0ef92d8afe996598f3db416a7c24c956e0b9252dbc4714bc44ebaf44d21b6205fe003c7de56d92bc8ca886ff7337bb027d3499c5611916de7cf632be4e5dd93331874
aad0 = 63da1d633dacda
pt0 = a2f6b8b0871630e250c260ca1f649b09899f5978a36f59570ab420130e
ct0 = 44d550a1060a7da9fe8ce5ceebf850b1db8f7766a4dad4bb0d957d20d0c0dd5ed412dded37755c5d10f41aed61
aad1 = 195fce1bc26d2a4c
pt1 = 9f3ee70b8467a9df72dc17cf7080da06f146838c940baa16c6a12ef13b7bd6a3477e3f1e2c2d94a926c95b9dd1
ct1 = 53cc6d3170917070dc098400a281f3dfe6cb5787b4c2cfcdb187c83737a56bec057b85ff0dc45ef157593caa8e0dbb013f92768b8b22dbfb4fc0d71843
aad2 = 15d0c7f6ebc3bd0be3
pt2 = 7c182c5b7dc95a62e2694d79b581ec84a5b7b7d93eaa170e7100ee8e1130fc7c43d176e6182eab6b8f0900c2be267e66c50e744775abaa1c6bd33fcc08
ct2 = 7bf891d0ebb14a05ab21bdb93f7c7f5d4c54815c8171ac46088d0aa49815bc3df99f2d4aa271d836062497e5a95301d1af6237388d4defd5d418062387591c7baed7bdf78bfdc020e90b46cbab
exporter_context = 4026736f890a3a600adc50
exported32 = 56ba7c24eba5a446773fe2b28f80714168ee706a426b973a4352f1aae459ce52
exported80 = 8968dedf842b1b69a93193f65ad3a0a50af973880a4ac00cc074e173e833a77903906e380105aa9c023f708330304e4a166a22ca6590ce4aed323dc2a9801bd45e95f03ab927b70c0cbc5e3490f4ca52

kem_id = 17
kdf_id = 2
aead_id = 1
mode = 3
skRm = 71a3a40e630c76057242758151413d5394a7b802831af85b71dcd28e1a57eb110c9a7a8e77d12ad026cec3b8bb932007
pkRm = 041d0109c980536080dae6ff52488613f793fa67b0fdc77a8c7104e80d8801bfd55bfa8b955b9797629453c4c8845bf50904f00e55bf8405301931ed15600eaa90ddcb6892b39db04a18765fd71c34ac612de5d6baa20df36797c9fc19e724a551
enc = 044c2c1902e926db8e6611fdcd0642098b9f3b649e46331d854c1d8432b5b0db33ad6bd4e35e1b92f6a24ad3b13f9be6dce239055d82d81d010057643d6696ae3d8c0c3c6d5247a77a58f134e687134df1943d3dd2ccd3391a54f0fbdc392f8d4c
info = ed5b313226071e21f3554a9ad42e8b9eca69cd34
pkSm = 04713c55bb8b4abd4bcbaf556902a48481ef9735f993a0dada615ca2473be077d18a0402bb623c6b498b73e7bfe71eee42cfdfc763b454aee30b5c986f311edc0b15c67934d4a0c02fc15ba569ea6ddc0f704772e18d6c46ba38fd85cded1a46c7
psk = ecb00296b83400e9b2af76f45aab65224625995652afc1ae82e31ce0aaf06415
psk_id = ff1a700b5d22820372d2f2
aad0 = 74dee4ea116db1
pt0 = e7e07fbb69f318f3247722043ed2ec2da9663448c3cc4d6bd45d511382
ct0 = d6407a88550a1ddb5f0edb688af7f38e82a05f97a0900fc1bd220269939ba9cb9fca8800446259106c51954646
aad1 = bc2c8854b312c6a3
pt1 = 80218c6206cc07f32b995610ed096b85da9ac9c480fd890633917f6ff1a0df9de7effb970ded3582a385295e05
ct1 = 787dc72af0476563c448c3a3e874c40c6bf0f5d3efbf3cd59e30147dd22637c561196849cb17bc42ef76a1bfc5fc7aa13d9fe794d8bf5b953e24f8c7c7
aad2 = 9459650c5fdc634fe4
pt2 = 299ee5c4a1a1e3e568d99e3c49ac483b14b699704347015424789c05363c8e27f1d4a5ad56335ea5833af931190620472ca5507b4a385bf17980714369
ct2 = 7b40680d1810e7a48f46ad9cfe969ea889487f7b0f8e061c90a1283ca1435ca4a7a099c37db909fe63e47c75b28ceba328e7cd27490520204ac529cb172d1cde8367dec1e753829e5762f2289f
exporter_context = 7a9ff095c3587d494c06a6
exported32 = 4e16ea40657991183d46924abbc28086b40a3ab6267b33405e6b986c892e1832
exported80 = e45855b6dab946d9f05d41de2207ed2a87200029ed87c556af488bbf8818e89281baeaf9fb5508fed0aa4f4e86129a6f0634b668b8ebdea51c87cce6d634d3f9654144bf6f0bc42467148721b456fb67
";

fn sets() -> Vec<HashMap<&'static str, Vec<u8>>> {
    SETS.split("\n\n")
        .map(|set| {
            set.lines()
                .map(|line| {
                    let (name, value) = line.split_once(" = ").expect("name = value");
                    // The four identifiers are decimal; they are matched as text below.
                    let value = if name.ends_with("_id") && name != "psk_id" || name == "mode" {
                        value.as_bytes().to_vec()
                    } else {
                        hex::decode(value).expect("hex")
                    };
                    (name, value)
                })
                .collect()
        })
        .collect()
}

/// The recipient's context for `set`, over the KDF HKDF-SHA384 and the AEAD `A`; an
/// authenticated set carries the sender's public key.
fn recipient<SK, PK, A, const N_SK: usize, const N_ENC: usize, const N_SECRET: usize>(
    set: &HashMap<&str, Vec<u8>>,
) -> HpkeContext<Recipient, SHA384, A>
where
    SK: PrivateKey<N_SK>
        + HpkeRecipient<N_ENC, N_SECRET>
        + HpkeAuthRecipient<N_ENC, N_SECRET, SenderPublicKey = PK>,
    PK: PublicKey<N_ENC>,
    A: HpkeAead,
{
    let sk = SK::from_bytes(&set["skRm"]).unwrap();
    let enc: [u8; N_ENC] = set["enc"].clone().try_into().unwrap();
    let psk = set
        .get("psk")
        .map(|psk| KeyMaterial::<64>::from_bytes_as_type(psk, KeyType::MACKey).unwrap());
    let mut params = HpkeParams::<SHA384, A>::new(&set["info"]);
    if let Some(psk) = &psk {
        params = params.with_psk(Psk::new(psk, &set["psk_id"]).unwrap());
    }
    match set.get("pkSm") {
        None => sk.setup_recipient(&enc, params).unwrap(),
        Some(pk_s) => {
            sk.setup_auth_recipient(&enc, &PK::from_bytes(pk_s).unwrap(), params).unwrap()
        }
    }
}

/// The set's three messages open in order, and its two exports match.
fn check_cipher<A: HpkeCipher>(
    mut context: HpkeContext<Recipient, SHA384, A>,
    set: &HashMap<&str, Vec<u8>>,
) {
    for i in 0..3 {
        let ct = &set[format!("ct{i}").as_str()];
        let mut pt = vec![0u8; ct.len()];
        let n = context.open_out(&set[format!("aad{i}").as_str()], ct, &mut pt).unwrap();
        assert_eq!(&pt[..n], set[format!("pt{i}").as_str()].as_slice(), "message {i}");
    }
    check_exports(context, set);
}

fn check_exports<A: HpkeAead>(
    context: HpkeContext<Recipient, SHA384, A>,
    set: &HashMap<&str, Vec<u8>>,
) {
    let mut out = KeyMaterial::<32>::new();
    context.export_out(&set["exporter_context"], &mut out);
    assert_eq!(out.ref_to_bytes(), set["exported32"].as_slice());
    let mut out = KeyMaterial::<80>::new();
    context.export_out(&set["exporter_context"], &mut out);
    assert_eq!(out.ref_to_bytes(), set["exported80"].as_slice());
}

#[test]
fn bc_java_sets_for_p384_and_hkdf_sha384() {
    let sets = sets();
    assert_eq!(sets.len(), 6);
    for set in &sets {
        let id = |name: &str| core::str::from_utf8(&set[name]).unwrap();
        type P384Sk = ECCDHPrivateKey<P384>;
        type P384Pk = ECCDHPublicKey<P384>;
        match (id("kem_id"), id("kdf_id"), id("aead_id"), id("mode")) {
            ("17", "2", "2", "0" | "2") => {
                check_cipher(recipient::<P384Sk, P384Pk, AES256Key<GCM>, 48, 97, 48>(set), set)
            }
            ("17", "2", "3", "1") => {
                check_cipher(recipient::<P384Sk, P384Pk, ChaCha20Poly1305Key, 48, 97, 48>(set), set)
            }
            ("17", "2", "1", "3") => {
                check_cipher(recipient::<P384Sk, P384Pk, AES128Key<GCM>, 48, 97, 48>(set), set)
            }
            ("32", "2", "1", "0") => check_cipher(
                recipient::<X25519PrivateKey, X25519PublicKey, AES128Key<GCM>, 32, 32, 32>(set),
                set,
            ),
            ("18", "2", "65535", "1") => check_exports(
                recipient::<ECCDHPrivateKey<P521>, ECCDHPublicKey<P521>, ExportOnly, 66, 133, 64>(
                    set,
                ),
                set,
            ),
            suite => panic!("an unexpected suite among the sets: {suite:?}"),
        }
    }
}
