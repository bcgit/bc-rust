//! XTS-AES-128 and XTS-AES-256 against NIST's ACVP sample vectors.
//!
//! The vectors are copied from the `internalProjection.json` of `ACVP-AES-XTS-1.0` and
//! `ACVP-AES-XTS-2.0` in NIST's ACVP-Server repository (`gen-val/json-files`, commit `975de31e`),
//! whose expected values come from NIST's reference implementation; each was also reproduced with
//! OpenSSL when it was copied. bc-test-data has no AES-XTS set, so a subset is embedded here:
//! every whole-byte `ACVP-AES-XTS-2.0` vector of at most 128 bytes -- ciphertext stealing with
//! tails of most lengths, both directions and both tweak modes -- and the shortest of 129 to 700
//! bytes for each key size, direction and tweak mode that has one. (An ACVP data unit can be any
//! number of bits; this API takes whole bytes.)
//!
//! Each vector is checked in both directions, whichever one it was generated for. A vector of
//! tweak mode "number" gives the data unit's sequence number as well as the tweak, and the check
//! confirms that the tweak is the number's 128-bit little-endian encoding before using it.

use bouncycastle_aes::hazmat::{AES128Internal, AES256Internal};
use bouncycastle_cipher::modes::XTSKey;
use bouncycastle_core::hazmat::BlockPermutation;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::FromKeyMaterial;
use bouncycastle_hex as hex;

/// One ACVP test case, as hex.
struct Vector {
    /// The revision, `tgId` and `tcId` it was copied from.
    source: &'static str,
    key: &'static str,
    /// The 128-bit tweak value, `tweakValue`.
    tweak: &'static str,
    /// `sequenceNumber`, for tweak mode "number".
    sequence_number: Option<u128>,
    pt: &'static str,
    ct: &'static str,
}

/// Checks `v` through `XTSKey<P, N>` under its `KEY_LEN`-byte key, in both directions.
fn check<P, const KEY_LEN: usize, const N: usize>(v: &Vector)
where
    P: BlockPermutation<16>,
    XTSKey<P, N>: FromKeyMaterial<KEY_LEN>,
{
    let material = KeyMaterial::<KEY_LEN>::from_bytes_as_type(
        &hex::decode(v.key).unwrap(),
        KeyType::SymmetricCipherKey,
    )
    .unwrap();
    let key = XTSKey::<P, N>::from_key_material(&material)
        .unwrap_or_else(|e| panic!("{}: the key is refused: {e:?}", v.source));

    let tweak: [u8; 16] = hex::decode(v.tweak).unwrap().try_into().unwrap();
    if let Some(n) = v.sequence_number {
        assert_eq!(n.to_le_bytes(), tweak, "{}: the tweak is the sequence number, LE", v.source);
    }
    let pt: [u8; N] = hex::decode(v.pt).unwrap().try_into().expect("an N-byte plaintext");
    let ct: [u8; N] = hex::decode(v.ct).unwrap().try_into().expect("an N-byte ciphertext");

    let mut data_unit = pt;
    assert_eq!(key.encrypt_inplace(&tweak, &mut data_unit), N, "{}", v.source);
    assert_eq!(data_unit, ct, "{}: encryption", v.source);

    let mut data_unit = ct;
    assert_eq!(key.decrypt_inplace(&tweak, &mut data_unit), N, "{}", v.source);
    assert_eq!(data_unit, pt, "{}: decryption", v.source);
}

#[test]
fn acvp_xts_aes_128() {
    check::<AES128Internal, 32, 16>(&V2_TG1_TC4);
    check::<AES128Internal, 32, 16>(&V2_TG3_TC131);
    check::<AES128Internal, 32, 16>(&V2_TG9_TC444);
    check::<AES128Internal, 32, 16>(&V2_TG11_TC535);
    check::<AES128Internal, 32, 23>(&V2_TG3_TC125);
    check::<AES128Internal, 32, 29>(&V2_TG11_TC503);
    check::<AES128Internal, 32, 46>(&V2_TG11_TC516);
    check::<AES128Internal, 32, 48>(&V2_TG3_TC139);
    check::<AES128Internal, 32, 56>(&V2_TG3_TC101);
    check::<AES128Internal, 32, 62>(&V2_TG1_TC13);
    check::<AES128Internal, 32, 64>(&V2_TG1_TC38);
    check::<AES128Internal, 32, 75>(&V2_TG11_TC525);
    check::<AES128Internal, 32, 86>(&V2_TG1_TC36);
    check::<AES128Internal, 32, 92>(&V2_TG11_TC502);
    check::<AES128Internal, 32, 93>(&V2_TG11_TC548);
    check::<AES128Internal, 32, 94>(&V2_TG3_TC144);
    check::<AES128Internal, 32, 94>(&V2_TG9_TC412);
    check::<AES128Internal, 32, 100>(&V2_TG9_TC433);
    check::<AES128Internal, 32, 100>(&V2_TG11_TC508);
    check::<AES128Internal, 32, 119>(&V2_TG9_TC441);
    check::<AES128Internal, 32, 126>(&V2_TG3_TC127);
    check::<AES128Internal, 32, 262>(&V2_TG1_TC18);
}

#[test]
fn acvp_xts_aes_256() {
    check::<AES256Internal, 64, 320>(&V1_TG11_TC101);
    check::<AES256Internal, 64, 559>(&V1_TG18_TC171);
    check::<AES256Internal, 64, 16>(&V2_TG5_TC233);
    check::<AES256Internal, 64, 16>(&V2_TG7_TC319);
    check::<AES256Internal, 64, 16>(&V2_TG13_TC642);
    check::<AES256Internal, 64, 16>(&V2_TG15_TC719);
    check::<AES256Internal, 64, 21>(&V2_TG15_TC702);
    check::<AES256Internal, 64, 27>(&V2_TG5_TC237);
    check::<AES256Internal, 64, 31>(&V2_TG15_TC737);
    check::<AES256Internal, 64, 46>(&V2_TG13_TC603);
    check::<AES256Internal, 64, 57>(&V2_TG13_TC640);
    check::<AES256Internal, 64, 59>(&V2_TG13_TC649);
    check::<AES256Internal, 64, 77>(&V2_TG5_TC230);
    check::<AES256Internal, 64, 78>(&V2_TG15_TC717);
    check::<AES256Internal, 64, 84>(&V2_TG13_TC641);
    check::<AES256Internal, 64, 86>(&V2_TG13_TC644);
    check::<AES256Internal, 64, 92>(&V2_TG15_TC712);
    check::<AES256Internal, 64, 94>(&V2_TG7_TC305);
    check::<AES256Internal, 64, 308>(&V2_TG13_TC646);
}

// ---- the vectors ----

/// ACVP-AES-XTS-2.0 tgId 1 tcId 4: AES-128, encrypt, tweakMode hex, 16 bytes.
const V2_TG1_TC4: Vector = Vector {
    source: "ACVP-AES-XTS-2.0 tgId 1 tcId 4",
    key: "8acb99d1d215612314d6b262147343f23f1b1e8f34f1dcbd6d57200fae54e8c4",
    tweak: "bf0d3404d7bce2b4132d02e90a256ebf",
    sequence_number: None,
    pt: "ea29098cb827a1de9d69f5b47a500c34",
    ct: "7a4cc60de7997471aab765348f08d935",
};

/// ACVP-AES-XTS-2.0 tgId 3 tcId 131: AES-128, encrypt, tweakMode number, 16 bytes.
const V2_TG3_TC131: Vector = Vector {
    source: "ACVP-AES-XTS-2.0 tgId 3 tcId 131",
    key: "852d1f431ecedb3434b856b664b97a319fb70ae546b0a8b359edcc7b00fa0b45",
    tweak: "4d000000000000000000000000000000",
    sequence_number: Some(77),
    pt: "0625bd766ef28555c68ac0a200347f55",
    ct: "3ae27f24b6c9ebf7b13d9709c18d1769",
};

/// ACVP-AES-XTS-2.0 tgId 9 tcId 444: AES-128, decrypt, tweakMode hex, 16 bytes.
const V2_TG9_TC444: Vector = Vector {
    source: "ACVP-AES-XTS-2.0 tgId 9 tcId 444",
    key: "ad17809726942ffde1060dd99de05415906c3ea6647ae52d8dbea10238341580",
    tweak: "7daa90322aa35fd658cd72f818159f2b",
    sequence_number: None,
    pt: "a5fdabb4e63926bf33bebfc73e01c05b",
    ct: "dc6929d5f7a1c1bb50f5ad10d0ed94fa",
};

/// ACVP-AES-XTS-2.0 tgId 11 tcId 535: AES-128, decrypt, tweakMode number, 16 bytes.
const V2_TG11_TC535: Vector = Vector {
    source: "ACVP-AES-XTS-2.0 tgId 11 tcId 535",
    key: "6aa59d12e31dc3850e22d0ea0641f47478779bd5b8f0dc4b0a0e49e05e7ac055",
    tweak: "a9000000000000000000000000000000",
    sequence_number: Some(169),
    pt: "8732826aad287e864070694a0af4255a",
    ct: "1242abfca4a5041936ea5a55c810c7e2",
};

/// ACVP-AES-XTS-2.0 tgId 3 tcId 125: AES-128, encrypt, tweakMode number, 23 bytes (b = 7).
const V2_TG3_TC125: Vector = Vector {
    source: "ACVP-AES-XTS-2.0 tgId 3 tcId 125",
    key: "c3d3dc0b7a345ccfe48b232075e47299ebf11e5c40e1bfe42acf96e1840b7353",
    tweak: "ca000000000000000000000000000000",
    sequence_number: Some(202),
    pt: "eafdbd330511baa1c912ea24b7b1303507ab3aabe6621c",
    ct: "b0c68b8a8c230a35676338546d361e15178b8cc3426e31",
};

/// ACVP-AES-XTS-2.0 tgId 11 tcId 503: AES-128, decrypt, tweakMode number, 29 bytes (b = 13).
const V2_TG11_TC503: Vector = Vector {
    source: "ACVP-AES-XTS-2.0 tgId 11 tcId 503",
    key: "0e00f2017e1fba4bd287e57b95d197e57bd0e7253be250b31380426cdd19dde5",
    tweak: "d0000000000000000000000000000000",
    sequence_number: Some(208),
    pt: "0df94f3f3eb892dbfad8fa149d5e275af6e81e0f9578861668354385a6",
    ct: "7b3af90fb25385a545804d183a624931d1b02aeb5654f2070fa55503c5",
};

/// ACVP-AES-XTS-2.0 tgId 11 tcId 516: AES-128, decrypt, tweakMode number, 46 bytes (b = 14).
const V2_TG11_TC516: Vector = Vector {
    source: "ACVP-AES-XTS-2.0 tgId 11 tcId 516",
    key: "8e52f6fd062d7c3dca35e3959e0b1d397af6ceedcc8a833c807a6da14c108e8f",
    tweak: "5c000000000000000000000000000000",
    sequence_number: Some(92),
    pt: "\
        72bbecdcac5b9913780ac9d439bbdbc46367f61cb3d6f0b0dcb100a2e33a4189ff812cccb7af572d0b183752\
        9f79",
    ct: "\
        18aea17a4d782407848151529c59fa54a35a413fa9b9352fcd43752a3400bf1c8780ee9860c094bc3577a702\
        ba50",
};

/// ACVP-AES-XTS-2.0 tgId 3 tcId 139: AES-128, encrypt, tweakMode number, 48 bytes.
const V2_TG3_TC139: Vector = Vector {
    source: "ACVP-AES-XTS-2.0 tgId 3 tcId 139",
    key: "b45cf630863a2e65ca84e55e4cdd7d14c3ca25f86a4aed34fd35cee38c859aeb",
    tweak: "5f000000000000000000000000000000",
    sequence_number: Some(95),
    pt: "\
        b6c799f91fc6c3b84092b1993f28f5ca743f7577b69a464d5516f74af26ef87b1e258641a8f2533941dc93b0\
        97424bf4",
    ct: "\
        d892c20885d33a10ad528b4a6022ce5d60b7ce3e77a99bd21bd267d7a6da43123e4ea8f10ebed953c4c735dd\
        5b1ee7b7",
};

/// ACVP-AES-XTS-2.0 tgId 3 tcId 101: AES-128, encrypt, tweakMode number, 56 bytes (b = 8).
const V2_TG3_TC101: Vector = Vector {
    source: "ACVP-AES-XTS-2.0 tgId 3 tcId 101",
    key: "4d283fa6573813ebbb3e2ecc03013416972c53c40249fbb4fc582e0005fe58bb",
    tweak: "f5000000000000000000000000000000",
    sequence_number: Some(245),
    pt: "\
        2dc07c5d016cdfaf10dd3698a0583d659e897452b3e314c985401336e824c9f2d6ce254066d2a00b7f06a716\
        1280f50f8f1725cef02e8a52",
    ct: "\
        b80a9187ab9638477dfb6a4c4a759b361cb2b496e9ea882d684cf9d231e43d37e91f5fba1798f84b45ba9c85\
        61e71be17cbe3465b72ec3b7",
};

/// ACVP-AES-XTS-2.0 tgId 1 tcId 13: AES-128, encrypt, tweakMode hex, 62 bytes (b = 14).
const V2_TG1_TC13: Vector = Vector {
    source: "ACVP-AES-XTS-2.0 tgId 1 tcId 13",
    key: "6fa0ae27860cb658b40a3d95666954442e418ee3e4565657dd08edc69e20e5d2",
    tweak: "c7c71ac8a3f858145b9ba0e658491af7",
    sequence_number: None,
    pt: "\
        316f416dd8828155aafe1efa50361d48613e073e1b4b66b00d86a908626157d3058dcb83b1b6833580aa2f4a\
        0663de87115027f5f4eb60fcf2f2235bb801",
    ct: "\
        74fccb3c6fa20bae9d1fba9525519a5aebb0bd4f2803a40c4ec0d80fbe3d5ecf53ea3d8c7456d23b4fd7772c\
        4bc44b06c0c7a533e53747a4cb94927d4572",
};

/// ACVP-AES-XTS-2.0 tgId 1 tcId 38: AES-128, encrypt, tweakMode hex, 64 bytes.
const V2_TG1_TC38: Vector = Vector {
    source: "ACVP-AES-XTS-2.0 tgId 1 tcId 38",
    key: "4e202f28cdc52b4652cb8a58aa7333ce3a64d343098f278d7e88125b58605d7e",
    tweak: "530d55c0b4d4a7c7041a5cc2af8ceae9",
    sequence_number: None,
    pt: "\
        d01a71806151bb27515e4fdc62264f1675b5220c0bbb03bfa1917989ed7ca5a2a8ec7ffa8aa8835c71deff0c\
        4ec81ef812ffd8fe02056b5014fb29e5ae2d0650",
    ct: "\
        dd50d20ed7b5d4a9083d0b8410aa8392f627a41a765c7436bf3cce3feede6a4e0c2ea4053701f532d43ac7e6\
        04703f13d7cc2b9258eb1db12ab6e29ba5cd7fd8",
};

/// ACVP-AES-XTS-2.0 tgId 11 tcId 525: AES-128, decrypt, tweakMode number, 75 bytes (b = 11).
const V2_TG11_TC525: Vector = Vector {
    source: "ACVP-AES-XTS-2.0 tgId 11 tcId 525",
    key: "88cfdd08e11ea2981cd342080a7770300effbd1e0b2738562f060bffacbd9af7",
    tweak: "d8000000000000000000000000000000",
    sequence_number: Some(216),
    pt: "\
        42e0b4f015fdb8e0c9f1339a5ec6c940cb3e4f84088e2d05e966d457e3eb7bd96dce0ff96b4c0e9aeb3cbf00\
        35c0c66b3b2ba29d0a7ba98c8ef9cdadbc04f558368d2bfed49fc7af696b8b",
    ct: "\
        103672952d6947df8aee1cf3779a536ce5620efe4f9e01fa650b7129fd2c8638c7b9a25de456921dfe0cbc0c\
        219d61a12f092b33f661b0b29357ebc08645eb46fb3e91d83b827611950460",
};

/// ACVP-AES-XTS-2.0 tgId 1 tcId 36: AES-128, encrypt, tweakMode hex, 86 bytes (b = 6).
const V2_TG1_TC36: Vector = Vector {
    source: "ACVP-AES-XTS-2.0 tgId 1 tcId 36",
    key: "a1e04e9180658a01af0882bf5319a88a097e43aa00c9140abbebade5fe63eea8",
    tweak: "4fdb844b178e00df69c41096b076b231",
    sequence_number: None,
    pt: "\
        90b44113367f8b928685152b98bccb17a90efa9f1e42e5e3f385100cf71087c4331a7b1f305299031e61ede6\
        ad088fcbf7a4f5852722c30cd37265cf82aaf4736cc2332888c3bb9f9321c2e14eb856595592b6eb83f3",
    ct: "\
        1561acd6c5f0052a9241049416bebf907971c31c6724b2891495b03d93f308a4e37406db648469eff0bd1a4b\
        f0b6ea66781e5b513e942b7d259742c0692b21feb025affeb65230fdaca4f3ad4bba7ef53ff198adfe5b",
};

/// ACVP-AES-XTS-2.0 tgId 11 tcId 502: AES-128, decrypt, tweakMode number, 92 bytes (b = 12).
const V2_TG11_TC502: Vector = Vector {
    source: "ACVP-AES-XTS-2.0 tgId 11 tcId 502",
    key: "0692f81900c50b2171aa24a718b8cc0e29d723c7e9d0b0c7ca490b0abba4eaa7",
    tweak: "cc000000000000000000000000000000",
    sequence_number: Some(204),
    pt: "\
        7d4230b7fae49be48c71a98bbb2224b44650d0492739a200f0dd1ad71f18636c5cbcf35075f5d16f61a39e69\
        2e5eaf82cfce4b62245b2289112947380bc64e3c687901dabb2a99973bbdef14549b31f9c43b5d13f03dfc0a\
        fc17c675",
    ct: "\
        8c010cb5f0f4dec68df4b6bffe9d5dbb08fca75bd7fe411248e80dde8c9816286922457674d50bd032fbc52b\
        e2f9b0d72897a2d2cd54c9d177808afbc411c1532099b8ae758653abce74afa1d0b993d3e4d1f04deb37c221\
        d1bafcc7",
};

/// ACVP-AES-XTS-2.0 tgId 11 tcId 548: AES-128, decrypt, tweakMode number, 93 bytes (b = 13).
const V2_TG11_TC548: Vector = Vector {
    source: "ACVP-AES-XTS-2.0 tgId 11 tcId 548",
    key: "d169f425fb98179f9b6a0c72ee490c36f9ba04a5cc59fc71f292e2ebeea3e60d",
    tweak: "f5000000000000000000000000000000",
    sequence_number: Some(245),
    pt: "\
        32c873f28118bd7141869f15dd1632cb2b9916e508230dd8ede7928b78aaa92d4c7a49492f8d442f881d6b5c\
        b8b439157a1481ca12b14e1732ee1f7b4ae94a599c7662d5b1093aa53a9b0a1185164ff87ed47f2cd35c710a\
        45e7948af6",
    ct: "\
        2c6926de92a4c7e0b6d91ac808618808c2b0f6133da310f74886c9c378cd79b63215d47751cee7f0ce4149dc\
        5044f8bc555ab8675a182300e077ad79949621ffb66b0c011ede637b18512c60a4f06ef5005e599acd2f213f\
        16f255b549",
};

/// ACVP-AES-XTS-2.0 tgId 3 tcId 144: AES-128, encrypt, tweakMode number, 94 bytes (b = 14).
const V2_TG3_TC144: Vector = Vector {
    source: "ACVP-AES-XTS-2.0 tgId 3 tcId 144",
    key: "02f67f1a707e9ccb6208263996a6a3f2ede1d9357cb1d71fe1e9a0930a7838dc",
    tweak: "0a000000000000000000000000000000",
    sequence_number: Some(10),
    pt: "\
        54bdbf9e132107e5cab8e3cff0f327fa64f235f9bbdb41c194933b7863668446d8172dbea007e422da9410bd\
        726cb21d6104f98ebe11f3817b5fa6f844e279db76563ca21188fe5d80f30aaf5cbc203a8c805add42fb9c14\
        ba3e469e6565",
    ct: "\
        37ca552b306aa35d80756b6ab82e5cd3fb72df960e939629eaf6c3465515a1093d6c387b7e3b7aaf37554bff\
        c2aceac8b56d58f302e304e2d0db471733cdbb25911b8f405f50bb114dc29da2638b52ab51d45f013298901f\
        3cf2a3b580f4",
};

/// ACVP-AES-XTS-2.0 tgId 9 tcId 412: AES-128, decrypt, tweakMode hex, 94 bytes (b = 14).
const V2_TG9_TC412: Vector = Vector {
    source: "ACVP-AES-XTS-2.0 tgId 9 tcId 412",
    key: "274976d0a13779af9de7d91b0c3b56b15be1d2b9771a75850eaa595b732c4e97",
    tweak: "f2fc1bf4ee74720ecab2a2e114a777ff",
    sequence_number: None,
    pt: "\
        55a9ab8095e2025e007c5229ab6c3c6ac2a4a87558a82e54531f383a67260dac51d5a4d1a0165ea9a9325fb5\
        98415e3ac9bb86e1cf030439de3342dd211311390ee92f482ba03b64610d5d69fbd173356db3b01a6a16d7f6\
        0f0ccd6b2151",
    ct: "\
        562c4483eaf6a0c4b6920f63fa80b8240d160d623ecd2b6bcd61c642fb3042ac4ad39bc55f63c768441187a3\
        8642e6d5ec558bb6d8996bf1f1a3e7b15ee4d63d3595a6e155a57998cce6fbaabe1d0eb4132527d26d7842f1\
        b4f06bd9fc93",
};

/// ACVP-AES-XTS-2.0 tgId 9 tcId 433: AES-128, decrypt, tweakMode hex, 100 bytes (b = 4).
const V2_TG9_TC433: Vector = Vector {
    source: "ACVP-AES-XTS-2.0 tgId 9 tcId 433",
    key: "38a415450a8a52b171ac7a571eb9f8abd96ef5d3f59558c296817d018349fea5",
    tweak: "6cc3a5fc6c25df36fc5adb6bc4714b2a",
    sequence_number: None,
    pt: "\
        c96a17bd3e6c0fc9443c9c3e3ddae29b32ca140236e34b1b544c593fa1c82d4d44f644a639a8a9d4a2f0ffcd\
        338ca2257cadd6415133e491ba116bf7e3d2fc662e3c3cebc7aa8a2722d16cec871af01c3fbe37420438cafd\
        607a66b5581065819949fc74",
    ct: "\
        31a976845781c861969b91c5e776b7795c5eb4c2177cd3af296cc6d2ece94d037261cdd533540a8d310c4fc9\
        45812e5d5469ebd04c7006fe7fa9d9610ff96de665d64716d30ce3472f01331d7b525902cdd6cc5acfb2d9b9\
        77a1e2169c398f642acb1c9e",
};

/// ACVP-AES-XTS-2.0 tgId 11 tcId 508: AES-128, decrypt, tweakMode number, 100 bytes (b = 4).
const V2_TG11_TC508: Vector = Vector {
    source: "ACVP-AES-XTS-2.0 tgId 11 tcId 508",
    key: "c0c85a32988822fd2f146178cf21c0b417c198f35e621835085e182b0fe9a7c8",
    tweak: "49000000000000000000000000000000",
    sequence_number: Some(73),
    pt: "\
        01c97075dbca87fdd44086eea98060f526fe7962895cf954e33307fb7813b704dedd05bccb2b98449d52557c\
        0d709fdcbbdbce58d313c9c1fe3263a05118cb5a4c9956023e05e26055f37d90c3a54e59a8d1a47488134b2b\
        1e97012ce8cadc0d3a0ae2a9",
    ct: "\
        b59cf115c0f380ca04a27d29a58157095721a40fbd5f74b1dd1b251952269fac3e07fa272b17d5bcd05653d2\
        14f6502e776b52ae95e5cfb0c31c2c96af512057749120f5b0cf75a9d03af58c0f38ce0ab1d56a737e133e5e\
        fcaaf6a0c1a5f7c6e3630be3",
};

/// ACVP-AES-XTS-2.0 tgId 9 tcId 441: AES-128, decrypt, tweakMode hex, 119 bytes (b = 7).
const V2_TG9_TC441: Vector = Vector {
    source: "ACVP-AES-XTS-2.0 tgId 9 tcId 441",
    key: "05b104202f78cb71331bfccefb9bce77977f6bfce3d01e4e167f001fe2c82250",
    tweak: "eddca8e9cae2487d4fcc200e6491a790",
    sequence_number: None,
    pt: "\
        cb872fb2d7596de44cb51bd3d6269d58772c09bd3ce0d294d344f39e9353da555f8d8e4433226c12650a231e\
        d7bfe482ee8c1c3a38ab6394541234edd27e54aab13156d5bee738d2c7cd1c2b362040fe2a94e5912459ec4b\
        33bc40d320e6a002f0ce816dd1d0cf8281b4c2b102b54e53e3dc11c6b9f384",
    ct: "\
        0cee96da18921858d88cbae9315efd4feb02d687e1b37e9c8c1cb248d1a3fded042d2df8ebb97a6d074caf62\
        6caa6bc8c7d1c2dfb5277e39e6829492ff1fa588ee27949d27c520ade18caf5fec641e21afb267772cec1598\
        ca54bd0c675cf9b6ac9cc78bcc1a7a2f48efcbcbc0498ea48efceef9d55125",
};

/// ACVP-AES-XTS-2.0 tgId 3 tcId 127: AES-128, encrypt, tweakMode number, 126 bytes (b = 14).
const V2_TG3_TC127: Vector = Vector {
    source: "ACVP-AES-XTS-2.0 tgId 3 tcId 127",
    key: "4c819dce0edea0af7ca2cadc18a6d1213d4d7120ffd01e84114fd2d438678cd9",
    tweak: "9a000000000000000000000000000000",
    sequence_number: Some(154),
    pt: "\
        94bc929bca0e94c32e603538e39d37aa91d00007cc09dfde1d67dca2a2cf0fb1daae7a4f5162f13e553e2ade\
        af3beceef275a3481967870e0be3febc4ce902583ee474d08b291f3418196e5418eac21b24288ca4284e964f\
        7e067870960a58c39342c9715711177e19cb97afb60615845495c7a4ad959b0755cbe1a3a739",
    ct: "\
        6456c9ebb196d4bb0a5a1e65c2c9cba208a726ac47365bac7a1fc0bd37d93b667b401ae6abc40b7a6d91be06\
        bf60ba51abb2f398ea93f19e60eec3456b74ee996ded4162525aa14a7962e482eaf80edbe75d2d7b1297be9e\
        83845d288c6c549675c73bb2f9e1a2b54bdedae3297680189d339926e99884f7b653e72482cb",
};

/// ACVP-AES-XTS-2.0 tgId 1 tcId 18: AES-128, encrypt, tweakMode hex, 262 bytes (b = 6).
const V2_TG1_TC18: Vector = Vector {
    source: "ACVP-AES-XTS-2.0 tgId 1 tcId 18",
    key: "a961fa246936e474bd453ad6d21affa859dae7322bcad53030e82d5506610f54",
    tweak: "e2bcc8951a6d4ba8001676fd052998da",
    sequence_number: None,
    pt: "\
        1910d9ac563533caeef460ef9d7b902d6b7d5f157eb2eb820d50599d01d3681e34d85263486b25b8ef66e416\
        4de3808a852e286f7f442d6b7321177ced2330d30aaed21e05165c94ecde5aab1e5ea425cc47c031a773cc07\
        f65779a400129649110374f2084cd1465fcfe24c4c23c3edc6188e846d41d77fa0db6ad75cbc64cf2aa6cee2\
        4b6a3d5bcc2e737ef26ce3612fd66065e2c1f0e0e5c05c46a79e74d34dd4b82f84f3c3277d71465e22bc3ffd\
        211275d08fb2a4e3d653d50f91bacc128c953a326a0473a5a6f01786a4c734bbd0ee0174b0006888062334f8\
        996a1794f8ea25567710ec228626d1f83aab060b4c6e79a94fc4fdb1ecb2425627facc78e85232abd280",
    ct: "\
        52c66c83c4701ac5209861cfb07a978115fafbfc66da33b683fd4560d952dac3dd566efae5d8573b5692820d\
        e4999a0210f9ba4efc843d9cd8f91da5ced139e3d6b83fc4656ab80242926cfca430210139b3872e47a00529\
        cf5801f9258f4eec7dc786d816df6f935216678b00af9d775a15a8d0c198366406bc19a3414426457a8b7c3a\
        77cf5db5f4ccb412524832056dda2e2a17b7da298763752c1765397779e94e306399b6af55ef90ea61f94a02\
        b8f226a57ed869722a24a37625de01ee9c20de72adee49520bb443537c392a8d75d5a5a63477b4fc25376d8c\
        aaffea407af287ff0affb1f63bb569bcbb312ba2e1b7aed532f81e0fd045a4b0849dae7c0266bf91416d",
};

/// ACVP-AES-XTS-1.0 tgId 11 tcId 101: AES-256, encrypt, tweakMode hex, 320 bytes.
const V1_TG11_TC101: Vector = Vector {
    source: "ACVP-AES-XTS-1.0 tgId 11 tcId 101",
    key: "\
        2ba2f3f25c0819edb749996effc95a8cd5c4c70b353f1bcad9903dea946b8720650863b3fba7eeda72e09ba4\
        8b1ef7beba8c8464187b408e56ee9a4be38bce52",
    tweak: "1366aa5b88c0456680cff819ddf81537",
    sequence_number: None,
    pt: "\
        ee258cf68714185a28df8675cd71b973db207662be7545f1ffebc8140217baf85669164591d2df30ee43da5e\
        6c3f7a1e039c629d8424bb046a1ec86644079d033ef3b54890bc103dbefa867979b00fc7520c1b9f1af8eb0b\
        b1a602a20f9d2b75bc540e7c07cc2b1e3c7c96702f6caa6cc0d8046f7d5a574d70bc14bbdb4dba546bb5e624\
        1cd0a0567c99fa72455cc7c561ddefcaf2962ba3782b4da722a7b737eedcccf7320b4ab0a2f706a8fdd078bd\
        6337629384a93137ad18306780424d8341f842be192bfcc471747323ced8bca892ceea702af92f319ae6222f\
        d0bb24161ad580ba790b8b4da88d8db3dacb1dd0480022a5586858c2b2bbc9a579a452fe274defeca804a9b5\
        7343d983bbe1ed638b9cd422b94c640ac129be22c0ff9181104895c72fa96c1c22dcf1bc721aec71de89a40a\
        266347bd151e951520cb9165",
    ct: "\
        5181e91d815a44163a8ca2f12dd6a5b51a82eeed30c9665d5d8cc7e3e3359e2534461f5b9bee4a9836647dae\
        81bac117e8c8aebe0a31864e3b9df05f34de5bac15aeb162d8cb77eb2d893de06edfd064e258d36e113226bb\
        01c26ce532ef82bb2f0506b7797aa5a4b1ccbd0713964ce74868728cc42da69b74914ecd4775e01dad6d5d66\
        cde80f91db57894cc280be52ffe79725afdc7fcd5a4c26fc22bfa2c7bd5f367389e31285dd3137e94885e714\
        f988bef70ec4cf2022c2320fe9e527cbbb8abc0612e1c8fda67d6f208449a23ee2860f31fd7b6f36521537e0\
        f08dddb766314d400d616ea2f6721a70201cf5a85b7a3b69c462057398cebdcce5e7308fb322d2c4ae9bf966\
        2941f53d787c6e093106cad99554773f9db9a7ce3e6a15eccc1667fa64425357c6fd5b72d086dca76722c312\
        cdc823d08f653a0d1a7a5427",
};

/// ACVP-AES-XTS-1.0 tgId 18 tcId 171: AES-256, encrypt, tweakMode number, 559 bytes (b = 15).
const V1_TG18_TC171: Vector = Vector {
    source: "ACVP-AES-XTS-1.0 tgId 18 tcId 171",
    key: "\
        4553964ee112435943a1dfddb0db6dfedfbcaae3765036dd86ffb11969d501df2381b7ab692e365fc2e609a8\
        b6556189e592f9443a9114fcffff7d1771063f4c",
    tweak: "46000000000000000000000000000000",
    sequence_number: Some(70),
    pt: "\
        4a953211645291d801e4758b4d35dc0317231fa9224b7555921bfefa063843377156de935878ac053c1b90af\
        e7a718fdf98350b43db0a328288a891057cdf391945c326533d68667d75d59c6749ee01c2c56c7facad794a3\
        bc1169dfdf836295e2054dc8c34553c17d1a8cd254603a926a6894ba63d596e124f6ab86980481642fae27ae\
        304a84c1102ad061b9b899689801e361e8924409b37e13480764ec4d7b468aeec9d2944eca7d4da7df4a6037\
        3eb3ea8452fdaaba9cf081c5994f3f5dd2afab19f0d81b8286365f934de1f93543ac9746c2befc27607bc6e5\
        551a8429109a88d87fa3e4d6faad424e250a3663d5d6df1d784ff85b872bbdd4ae1630c885849d8344ce0b23\
        ca1096ba1984531d5075fb85e309adae1ecda78bc6aee690675bd3782886d8d05bc32726fd17282eb7848395\
        a7972458fdc60a1c9f67e6f13794d241b20aa2d30aa21d0862ab7429e946f2ad9f1e25399d8583ca5ae37378\
        cb89d172401175a93122b3ccd1c2de809065ff12e0b17b0906125327b4d3f6be6eeeca402b058ee959d25e1a\
        272b4cf0ad379e50a1e16795c9fd77cefbce7c903ddbf71eb38bb82eb5a1f4474744067de14ff63063339a66\
        0d7dcbe433438b4d1aa65f2ea82d40a36801843b48741395e1aa12871c97369d0aa04bf32f21303add3dbc5b\
        d9e828f4d612c79ad1a4075870fb05647e688ad7013916d12216b6309c55df50cd8490e70e90efa76e38d620\
        726d09e552cc8fbd8d8adf6acf3785c5b936d2a7c579c67ae057300d251861",
    ct: "\
        795d9ef272b0b923cdfca4fbc4457ec624875688a120b498ad62b1a337354895165b910ad5f2e119e601acde\
        bc9984b8f7cc0f1e7590144b64a3dd48e7d154df06355905e6ce778dd946c6e4e428c846870b8dfc5bda1f13\
        675cd69568a81003e7b3802f6b1b447dfc81a24b5bb42a7ab695052e8992695d3da3125412ea58ae90cb4b01\
        6d2646017dbefaa96f1c45e9fd63958387e0a56f47a86fdd2bdcbf59e3aaf35633186aa99273234a78a80821\
        4f471eab9012b48c034694ce4d8f00743e7bea666fc7e0c86c29dc888083d1bd9dcdc4dcdb457d032a894460\
        2e62b50e8f696a329537ed113cdbbcb4c298f31a1a0df8f4d84aca643fb7ba98f430bf226e7587d69e0e8522\
        fc3da498d0eb382aca86741861654954178b20469230d1ea63a9434a4688c36fb83c63833431be2847ddfeec\
        0b907fb4d4bfe640d5d5e0457a2f3e701cd79b2e6081520fbdbf44c91a57a5179801861550e6a4f90d01b5a6\
        6b05c73d3af0f990124525f59d6742c54d27841ee0fcf2ff3d57825d4c32ec52cf909c36ab26f60b79650eeb\
        b75b3bcc4f5e55bad56b117224daaf2e2184183016eff3a4e311f90e1b4ba68cde1a3d7ed702c55d38ae5a7b\
        6f4b5b80b19ed457ec64967d277ebc927404ceb03b909c9fc3a4d2f6d5ea2c13492fb64cbac155923b4f7bd6\
        6c8774e08cbd23777c48a5bb457b01ddf194feda4e2ca5d1e34ae7d48b94184e42e6028368064e8e0f20fd34\
        980b5b06748ae66dd9d4634c5174c07deef68b7aa08e22f7fe090f48b05d7d",
};

/// ACVP-AES-XTS-2.0 tgId 5 tcId 233: AES-256, encrypt, tweakMode hex, 16 bytes.
const V2_TG5_TC233: Vector = Vector {
    source: "ACVP-AES-XTS-2.0 tgId 5 tcId 233",
    key: "\
        9d9674635844373fbac65ea8fefccf4bedb7b1845c89dc1b28b343fdcd5df7af1c0a96edeead069c6666b741\
        153fa3f367ad7538f9615c348462115fe09da571",
    tweak: "eae1092e65f917efaf69e01740494551",
    sequence_number: None,
    pt: "0873e8a1ef36f962efaae5b9bd617d39",
    ct: "6ea0f22583c4c6397adcaf702a08c27d",
};

/// ACVP-AES-XTS-2.0 tgId 7 tcId 319: AES-256, encrypt, tweakMode number, 16 bytes.
const V2_TG7_TC319: Vector = Vector {
    source: "ACVP-AES-XTS-2.0 tgId 7 tcId 319",
    key: "\
        95f8cac93590607136175e70d8fa55465a1edaa5e128c31f17821fb29cdd5d218d8e637502eec9e88acb1b28\
        8727561ce79b01bf11efbef86dccb7fe78ea3c52",
    tweak: "f9000000000000000000000000000000",
    sequence_number: Some(249),
    pt: "40e5982e173de25bdeec94a02130ebcf",
    ct: "4b9c0a90753d611c4df75991c4d4abc8",
};

/// ACVP-AES-XTS-2.0 tgId 13 tcId 642: AES-256, decrypt, tweakMode hex, 16 bytes.
const V2_TG13_TC642: Vector = Vector {
    source: "ACVP-AES-XTS-2.0 tgId 13 tcId 642",
    key: "\
        074beb63ea25525f509e04562158a49f1c5de35dd0b32528de9673f9d8b2c1e799c852ee2ce4a5487e49822f\
        e803860ed6eb5cc61ddc965a3a18478f6ed1a8d2",
    tweak: "642178ce09bf25ef9bdc12a9043643cd",
    sequence_number: None,
    pt: "bc564ad27849d52c0fe571248907f6d8",
    ct: "ceec59a7677a8a78230139670e604025",
};

/// ACVP-AES-XTS-2.0 tgId 15 tcId 719: AES-256, decrypt, tweakMode number, 16 bytes.
const V2_TG15_TC719: Vector = Vector {
    source: "ACVP-AES-XTS-2.0 tgId 15 tcId 719",
    key: "\
        530d1742668119cf2be522a070fca1262dc0a85543440998fa1abe81d5f16f522cc220cd9e7cffba88ebb933\
        2aa42e9a8a6d8a2af9639a73dab5bf663ca1bae5",
    tweak: "b7000000000000000000000000000000",
    sequence_number: Some(183),
    pt: "39a576b8e051682d9bb974522bc8173f",
    ct: "184c449f962b94b8eba1b8ddb7e44db9",
};

/// ACVP-AES-XTS-2.0 tgId 15 tcId 702: AES-256, decrypt, tweakMode number, 21 bytes (b = 5).
const V2_TG15_TC702: Vector = Vector {
    source: "ACVP-AES-XTS-2.0 tgId 15 tcId 702",
    key: "\
        6838b46d0a41d3468520baef2f28dacd770a7f2e2a53328345bcd010d40799bb1e2ed2e127c0cb999f4d4946\
        d1026fa90b9344d11d59223b1adc2dd6db7394ce",
    tweak: "2f000000000000000000000000000000",
    sequence_number: Some(47),
    pt: "dd3870cb70e39e96f1b70404030dabfe2d1a54cc89",
    ct: "678cf29fd1e660bcdc9d874c8e4c5f7292ab8368d5",
};

/// ACVP-AES-XTS-2.0 tgId 5 tcId 237: AES-256, encrypt, tweakMode hex, 27 bytes (b = 11).
const V2_TG5_TC237: Vector = Vector {
    source: "ACVP-AES-XTS-2.0 tgId 5 tcId 237",
    key: "\
        dcf8c5f5ac2ff90719df2dcbbee159c53c44e80bcfa95c718c659c4e8f6fc0a4c85a9e3c16527e66bdd924c1\
        3ec8314987f0f3e89089007b34dc472b95b7e03e",
    tweak: "7eb2097b64cc3bccad39608427ecc1a5",
    sequence_number: None,
    pt: "a06b93f02ae1b52f2d7995d024914dd490320670ad610f5b4bc91e",
    ct: "87e96fcd94d73ba5e2cfe45a96be469c2a13ce2f621cd76fc1c875",
};

/// ACVP-AES-XTS-2.0 tgId 15 tcId 737: AES-256, decrypt, tweakMode number, 31 bytes (b = 15).
const V2_TG15_TC737: Vector = Vector {
    source: "ACVP-AES-XTS-2.0 tgId 15 tcId 737",
    key: "\
        a373bfc7b1697d90e3338fa4eda3a6b47333e128afd5ab041deec226c678a02a1595a2c29ffcc534dea529d5\
        e0fc611c77825ae6127a9146365fc3779d5b350c",
    tweak: "f6000000000000000000000000000000",
    sequence_number: Some(246),
    pt: "a6f75098bd821c44d18a6e5870a7133b15800c27d6d2c7450309e80d07d586",
    ct: "0870a04fbf1d37cd1af4a2411be163e1655f82fc85a99ab6e462e0d6c9df28",
};

/// ACVP-AES-XTS-2.0 tgId 13 tcId 603: AES-256, decrypt, tweakMode hex, 46 bytes (b = 14).
const V2_TG13_TC603: Vector = Vector {
    source: "ACVP-AES-XTS-2.0 tgId 13 tcId 603",
    key: "\
        fe08576b2820261bb57ee5164416885f9b154ba446ec82e129345825e30721c87a13ac02fde62cd5d7a34433\
        e5eb021be485ea54422113aa0b545154f5fdbef9",
    tweak: "89325d57b103c2cdc2bfa2e3327aa6ff",
    sequence_number: None,
    pt: "\
        c1355ee7100214f1bf77a1d8d1b0c2229ec647806e7d8004cca909350315a03d7d62b84dba97cda22359554b\
        744b",
    ct: "\
        b2ca0147326de586698dc559978e367b894e23a101d3937c5ade6fe36c96629cfddbc21b668b690827ec27d5\
        9d6e",
};

/// ACVP-AES-XTS-2.0 tgId 13 tcId 640: AES-256, decrypt, tweakMode hex, 57 bytes (b = 9).
const V2_TG13_TC640: Vector = Vector {
    source: "ACVP-AES-XTS-2.0 tgId 13 tcId 640",
    key: "\
        f222058080b731845a6a64ceead954d05a85635ade124a235ab389f42daa124fc56edc769a372f57ef9f4ea2\
        9273ed82310d96db7c0101cf999fb8b00f2123a9",
    tweak: "f395c13b586f1939f93ce0ecc82d3b93",
    sequence_number: None,
    pt: "\
        c6d43c791a16be5294d948d5a5ec94ef81e69f75cbfa2ce03db3f47689d8b1a370f71bc63f072491f1d96323\
        d10d6da674d967a6f172b2ae99",
    ct: "\
        0cf742d85c85def160e05bdfe2e3c31263981651531f46074638fc782890374a7f30865586511b475eeafac3\
        0848089618e140466ca3da934c",
};

/// ACVP-AES-XTS-2.0 tgId 13 tcId 649: AES-256, decrypt, tweakMode hex, 59 bytes (b = 11).
const V2_TG13_TC649: Vector = Vector {
    source: "ACVP-AES-XTS-2.0 tgId 13 tcId 649",
    key: "\
        3a8c5ecf475e3dc20da414c965824312224d946aeee4ed9d9db450ba24747d44930b61cb9d2aa1676059a578\
        2994a7d5415ca6b742aefa9b58fcf9e8c69d1cb2",
    tweak: "d2f56bc08a8cf7f2858737313afd1bee",
    sequence_number: None,
    pt: "\
        b3d431bbcc8538abcd33ea5a7c5166b360f21beefc3f4800c25ca803a453f493ae941f279aad1033adf64893\
        80eb31f7287e0e38d72e510006871a",
    ct: "\
        1c3e5d0c58856fc805d719e8804699969d175741269983f017ba510cf3a63f794225bec32b44ec999dcd51c6\
        9e1256a909ec8f05175ed8db018850",
};

/// ACVP-AES-XTS-2.0 tgId 5 tcId 230: AES-256, encrypt, tweakMode hex, 77 bytes (b = 13).
const V2_TG5_TC230: Vector = Vector {
    source: "ACVP-AES-XTS-2.0 tgId 5 tcId 230",
    key: "\
        a0e54b4453a9c9d7740a8a88f4f72fb3a76f16d078197a1c69e5f69e68a710fb3555068bfe708ee35224f8cd\
        c5b238823a2b239e5cd6a0a6704ab4e18c1cfc6d",
    tweak: "cc82acdf52a949538b9cc27c8e61a04a",
    sequence_number: None,
    pt: "\
        d7503a2c796adeca0e73a619c0ea661dc683ba6414e74c708280f6dd3a9c56f83db8b82cd0fe06f5903786a8\
        4722276627ef7de3153a258f7c0b2a7f606e02941ced3ce7518d0d4466cf9f3a77",
    ct: "\
        31611d514838ab07ce6167149db16a0bca816ed32c55c5311f6d9a3b7913243b334e01d9ac661f48d0379f64\
        1a0dcc2f8cb8c9442f2adfda7912cb4b5ba32563834821ad807a0bca4afc26e353",
};

/// ACVP-AES-XTS-2.0 tgId 15 tcId 717: AES-256, decrypt, tweakMode number, 78 bytes (b = 14).
const V2_TG15_TC717: Vector = Vector {
    source: "ACVP-AES-XTS-2.0 tgId 15 tcId 717",
    key: "\
        dc8b232a4635ce86276464428f2b0038bc149a74304ae557a3f63da68af81f37d57c1940be983288e3f6b482\
        a795aa04719b0a65484d0af6cbe2c279beb17ddb",
    tweak: "65000000000000000000000000000000",
    sequence_number: Some(101),
    pt: "\
        f1dbec7f644d96647c88b946c4fa3ae44dbcb07c721783992239d316a5fbf12338d0b2f89baf3626a9c4425a\
        3a03aacfb1e1c81c80f232aa8976fbbf4d9c41520e2441b2f32f57da1549ae46713f",
    ct: "\
        e70bd73a2f71d4c67ae2c23b40b139656ffb5807d40643adb749b1925fac6ba531f533e0fb1affc9a2de6b8c\
        fbc1407d7422252956aed11aecd3552f3b76a5e56ebdfc802ead889525afb6a52030",
};

/// ACVP-AES-XTS-2.0 tgId 13 tcId 641: AES-256, decrypt, tweakMode hex, 84 bytes (b = 4).
const V2_TG13_TC641: Vector = Vector {
    source: "ACVP-AES-XTS-2.0 tgId 13 tcId 641",
    key: "\
        34dc22fc6047a40f4ac0e6efe354128997a28b3b5c0ef60d1cc34c63003f97c1a176a8fd6be17e7801e44ba8\
        68c6e7b4d09cba9730d928dcd98edddebfa6f495",
    tweak: "ecc6873db15aaa23686c9c7bff6f38b1",
    sequence_number: None,
    pt: "\
        0d93588848314be196d4a7394e7299cee4419b799b9b583c19824321fbb4072cb491362fd6c2f6690b741dba\
        d20966058133b0ac8e2eb815322ecf88994e62df4112cfccd861c1a945ea313e498bfa7293a32fcf",
    ct: "\
        684fb6ca08e2265239bc1584ebd09cfaa20b0af4d500105741b1e09233b8341669377904c189c0da91909741\
        31698eb9211196f3bd5dcde1537754c8bdb8e2d1fe46ee798abd0c38ffc852a2e264ce957a9d4a16",
};

/// ACVP-AES-XTS-2.0 tgId 13 tcId 644: AES-256, decrypt, tweakMode hex, 86 bytes (b = 6).
const V2_TG13_TC644: Vector = Vector {
    source: "ACVP-AES-XTS-2.0 tgId 13 tcId 644",
    key: "\
        ec6cbedc8a6a66d571d880d5aa99d8052b933193e8d65b8c5888556856ced10f9ab2d48a796204780da64583\
        e5f5c27db783383615d43bc0f7383f8ee3737bb7",
    tweak: "4779bd6f28599c39274f2c6964063988",
    sequence_number: None,
    pt: "\
        fde1ef403f19c49f43760d342435f6ff3534c87b7c1d8b940b253fe7b6d3008ccc3da904f72f3d35cfcd149a\
        e052781d213c0e196e7081f805b36495d10ff4976b2fc4c3e4294d84c95f16ad692ff3dc1f27077c852d",
    ct: "\
        5b65ca6c16908863c94767239652c4971738dcd2852d74651eea1b01c5cdc075c9dcd5a98cd9b69455bd648a\
        395aab1239045ca4e94593310f5746cc25dd202dd2a17d4265fd9c73dcc517195f84bc65b740dee6fb92",
};

/// ACVP-AES-XTS-2.0 tgId 15 tcId 712: AES-256, decrypt, tweakMode number, 92 bytes (b = 12).
const V2_TG15_TC712: Vector = Vector {
    source: "ACVP-AES-XTS-2.0 tgId 15 tcId 712",
    key: "\
        93fe122fd121d1450133086e9bb229381f572f6055127af61efa212973edf3f6b96ece04bd6b0df9a0bb25f6\
        9dad503d323ad83a0118826103cf9ade1b720127",
    tweak: "2a000000000000000000000000000000",
    sequence_number: Some(42),
    pt: "\
        1292b98c98225013261708d38b99df9bece6132393a522216235061d2fc95b9cdc331a66f5b681e53bb634a2\
        a9c44379e7d4658a90ea9c267b92fca5f52b6506c9db44827de72cb5764eada1a1f79d8a83da435a52766e88\
        b22a22da",
    ct: "\
        2aa51cebef5c72f7923178d8737dc5b9d93c9c74141d9cd55abe612f629f2b199399746366297aceaeed589e\
        eedc2064fffd7d468c94c19e0983156a2a20e4ead066b494e2c5b656832808d6bba5596f298b504689fb8048\
        2e56281d",
};

/// ACVP-AES-XTS-2.0 tgId 7 tcId 305: AES-256, encrypt, tweakMode number, 94 bytes (b = 14).
const V2_TG7_TC305: Vector = Vector {
    source: "ACVP-AES-XTS-2.0 tgId 7 tcId 305",
    key: "\
        51c5973bdea6ffe02ab15c3d6b07ce940f8337d9f3662fefed7f07b283b7d8de95c52fb67847180624bed57d\
        dec5b9f5d7e2c2c84c5b24807c0f82f6ac239fff",
    tweak: "36000000000000000000000000000000",
    sequence_number: Some(54),
    pt: "\
        2e3b0325fda676d24b833518e7acfe7076b4d522b7071a98ea2c5def19648a59d6bc29dd352faaad0579d066\
        f30facd9fe9c5a367c75bc58193855a7537c4b1cea28279486fd0cd1eb5298736033d13fd3b06b65807482fe\
        50afdb420195",
    ct: "\
        01331145cb441fb40ef1d6d5669ff934e5427645704a1d5a20947c2de257b9c2e0064902e5912f15aa0b2b1a\
        e973a337be3b765d253c0ffc47169d37fb143812f1ae419ff4eb010e6d05f184041430439022be3c7a5e8234\
        47adf700fec0",
};

/// ACVP-AES-XTS-2.0 tgId 13 tcId 646: AES-256, decrypt, tweakMode hex, 308 bytes (b = 4).
const V2_TG13_TC646: Vector = Vector {
    source: "ACVP-AES-XTS-2.0 tgId 13 tcId 646",
    key: "\
        6737c853f8522ef9313f5917151392568f1c63917c6e655baf09694ea6906ce89e2042d9f165e3d274a50ff5\
        37a0f63710bf3052fdab8caa10bab9dc25a29f41",
    tweak: "6fe228a190dbf0edcec119a0e5140c6c",
    sequence_number: None,
    pt: "\
        69befc6730eb06f8078b01d610187e4e14bb1be0c9344a43dd1521240c8cd5d8da51cca4a870aac8661a590f\
        b917d66bc8cbe8a17a057939a3a8ac4f2858923be2f58214373654848812fb95dbc783483e48ccb2d6c25019\
        37c7ef9b400da671aaac08f7e03b4bc323f34c1a1151c92d424bf0fa3abad868525454358303e3be4e53554b\
        d1edc2449eab840b1ed40dffe0d18e76daca0f45b598a7f29a9c450f4bfb97f4cbdd68cd92497bf15615f145\
        08b14d0cb9c2c1d778e8292af6e77d0074d291c24665b6cb56dd5af714543f83d7800249c9a096fb540cd296\
        bf8613de6c00e85b28cb0e8302612a7fbadc28e2d88f485f2578aa687db095523e1c960d7d4b30c0070cac7c\
        7427c2318c14c7a9aa92158ca68047f0f9b844043f9bd5173691f9e0b3b8260bd8164656a3d64ca3833c34c1",
    ct: "\
        3590b70b4aa216c06e603d0918751568e58ff145d1a278562c8d7b08265233b1af286b4d09dbc6010502f476\
        02b9388cc2df2e59544e69a1ddc0e711a41bc363d63fc25102d84814e845943a445617149f2023e9b50af071\
        796e2551efae47993d38cc19cdd7ace5c9e46344c0e2100212d7c0ecb4009ca3589028afbd11f84b8a541d54\
        5829eb5f0cd7ea52ad4802a11de263e8fad2ed5b8d2442b837b9bcb336118dc2842ee576c0bbbea25b29c79b\
        495f687ac52f5c1817a2823d9fab1acb79467b75e44b01865d291857eb05fd0f62e264518436fab286720d85\
        b442a0d812aaa758382a7eadb1edb1c0e1e38a2427378040842d75219fb4a062f8b2730ee9f93b762a2446e2\
        22e87ff957996626d4063728508ad24e20d17d7f0da19630e60959470a5f2b5f5fd0ca567b95f21c33ad038f",
};
