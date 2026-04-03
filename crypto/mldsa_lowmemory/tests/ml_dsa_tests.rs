/// This performs tests using the public interfaces of the crate.
#[cfg(test)]
mod mldsa_tests {
    use bouncycastle_core_interface::errors::SignatureError;
    use bouncycastle_core_interface::key_material::{KeyMaterial256, KeyType};
    use bouncycastle_core_interface::traits::{KeyMaterial, Signature, SignaturePrivateKey, SignaturePublicKey, RNG};
    use bouncycastle_core_test_framework::DUMMY_SEED_1024;
    use bouncycastle_core_test_framework::signature::*;
    use bouncycastle_hex as hex;
    use bouncycastle_mldsa_lowmemory::{MLDSA44PrivateKey, MLDSA44PublicKey, MLDSA65PrivateKey, MLDSA65PublicKey, MLDSA87PrivateKey, MLDSA87PublicKey, MuBuilder, MLDSA44, MLDSA65, MLDSA87, TR_LEN};
    use bouncycastle_mldsa_lowmemory::{MLDSA44_PK_LEN, MLDSA44_SIG_LEN, MLDSA65_PK_LEN, MLDSA65_SIG_LEN, MLDSA87_SIG_LEN, MLDSA87_PK_LEN};
    use bouncycastle_mldsa_lowmemory::{MLDSATrait, MLDSAPublicKeyTrait, MLDSAPrivateKeyTrait};
    use crate::{MLDSA44_KAT1, MLDSA65_KAT1, MLDSA87_KAT1};

    #[test]
    fn test_framework_signature() {
        let tf = TestFrameworkSignature::new(false, true);

        tf.test_signature::<MLDSA44PublicKey, MLDSA44PrivateKey, MLDSA44, MLDSA44_SIG_LEN>(false);
        tf.test_signature::<MLDSA65PublicKey, MLDSA65PrivateKey, MLDSA65, MLDSA65_SIG_LEN>(false);
        tf.test_signature::<MLDSA87PublicKey, MLDSA87PrivateKey, MLDSA87, MLDSA87_SIG_LEN>(false);
    }

    /// This runs the full bitflipping tests and takes several minutes.
    /// I'm leaving this commented out, but feel free to un-comment it and run it.
    // #[test]
    // fn test_framework_signature_extensive() {
    //
    //     let tf = TestFrameworkSignature::new(false, true);
    //
    //     tf.test_signature::<MLDSA44PublicKey, MLDSA44PrivateKey, MLDSA44, MLDSA44_SIG_LEN>(true);
    //
    //     tf.test_signature::<MLDSA65PublicKey, MLDSA65PrivateKey, MLDSA65, MLDSA65_SIG_LEN>(true);
    //
    //     tf.test_signature::<MLDSA87PublicKey, MLDSA87PrivateKey, MLDSA87, MLDSA87_SIG_LEN>(true);
    //
    // }

    #[test]
    fn rfc9881_keygen() {
        // note: same seed for MLDSA44, MLDSA65, MLDSA87
        let seed = KeyMaterial256::from_bytes_as_type(
            &hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap(),
            KeyType::Seed,
        ).unwrap();


        /* MLDSA44 */
       let expected_pk_bytes: [u8; MLDSA44_PK_LEN] = hex::decode("d7b2b47254aae0db45e7930d4a98d2c97d8f1397d1789dafa17024b316e9bec94fc9946d42f19b79a7413bbaa33e7149cb42ed5115693ac041facb988adeb5fe0e1d8631184995b592c397d2294e2e14f90aa414ba3826899ac43f4cccacbc26e9a832b95118d5cb433cbef9660b00138e0817f61e762ca274c36ad554eb22aac1162e4ab01acba1e38c4efd8f80b65b333d0f72e55dfe71ce9c1ebb9889e7c56106c0fd73803a2aecfeafded7aa3cb2ceda54d12bd8cd36a78cf975943b47abd25e880ac452e5742ed1e8d1a82afa86e590c758c15ae4d2840d92bca1a5090f40496597fca7d8b9513f1a1bda6e950aaa98de467507d4a4f5a4f0599216582c3572f62eda8905ab3581670c4a02777a33e0ca7295fd8f4ff6d1a0a3a7683d65f5f5f7fc60da023e826c5f92144c02f7d1ba1075987553ea9367fcd76d990b7fa99cd45afdb8836d43e459f5187df058479709a01ea6835935fa70460990cd3dc1ba401ba94bab1dde41ac67ab3319dcaca06048d4c4eef27ee13a9c17d0538f430f2d642dc2415660de78877d8d8abc72523978c042e4285f4319846c44126242976844c10e556ba215b5a719e59d0c6b2a96d39859071fdcc2cde7524a7bedae54e85b318e854e8fe2b2f3edfac9719128270aafd1e5044c3a4fdafd9ff31f90784b8e8e4596144a0daf586511d3d9962b9ea95af197b4e5fc60f2b1ed15de3a5bef5f89bdc79d91051d9b2816e74fa54531efdc1cbe74d448857f476bcd58f21c0b653b3b76a4e076a6559a302718555cc63f74859aabab925f023861ca8cd0f7badb2871f67d55326d7451135ad45f4a1ba69118fbb2c8a30eec9392ef3f977066c9add5c710cc647b1514d217d958c7017c3e90fd20c04e674b90486e9370a31a001d32f473979e4906749e7e477fa0b74508f8a5f2378312b83c25bd388ca0b0fff7478baf42b71667edaac97c46b129643e586e5b055a0c211946d4f36e675bed5860fa042a315d9826164d6a9237c35a5fbf495490a5bd4df248b95c4aae7784b605673166ac4245b5b4b082a09e9323e62f2078c5b76783446defd736ad3a3702d49b089844900a61833397bc4419b30d7a97a0b387c1911474c4d41b53e32a977acb6f0ea75db65bb39e59e701e76957def6f2d44559c31a77122b5204e3b5c219f1688b14ed0bc0b801b3e6e82dcd43e9c0e9f41744cd9815bd1bc8820d8bb123f04facd1b1b685dd5a2b1b8dbbf3ed933670f095a180b4f192d08b10b8fabbdfcc2b24518e32eea0a5e0c904ca844780083f3b0cd2d0b8b6af67bc355b9494025dc7b0a78fa80e3a2dbfeb51328851d6078198e9493651ae787ec0251f922ba30e9f51df62a6d72784cf3dd205393176dfa324a512bd94970a36dd34a514a86791f0eb36f0145b09ab64651b4a0313b299611a2a1c48891627598768a3114060ba4443486df51522a1ce88b30985c216f8e6ed178dd567b304a0d4cafba882a28342f17a9aa26ae58db630083d2c358fdf566c3f5d62a428567bc9ea8ce95caa0f35474b0bfa8f339a250ab4dfcf2083be8eefbc1055e18fe15370eecb260566d83ff06b211aaec43ca29b54ccd00f8815a2465ef0b46515cc7e41f3124f09efff739309ab58b29a1459a00bce5038e938c9678f72eb0e4ee5fdaae66d9f8573fc97fc42b4959f4bf8b61d78433e86b0335d6e9191c4d8bf487b3905c108cfd6ac24b0ceb7dcb7cf51f84d0ed687b95eaeb1c533c06f0d97023d92a70825837b59ba6cb7d4e56b0a87c203862ae8f315ba5925e8edefa679369a2202766151f16a965f9f81ece76cc070b55869e4db9784cf05c830b3242c8312").unwrap()
                                                        .try_into().unwrap();

        // Decode and re-encode the pk, make sure you get the same thing
        let decoded_pk = MLDSA44PublicKey::from_bytes(&expected_pk_bytes).unwrap();
        let pk_bytes = decoded_pk.pk_encode();
        assert_eq!(pk_bytes.len(), expected_pk_bytes.len());
        assert_eq!(pk_bytes, expected_pk_bytes.as_slice());

        // run keygen from seed
        let (derived_pk, derived_sk) = MLDSA44::keygen_from_seed(&seed).unwrap();
        let sk_bytes = derived_sk.sk_encode();
        assert_eq!(&sk_bytes, &*hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap());

        assert_eq!(derived_pk.pk_encode(), expected_pk_bytes.as_slice());
        // also test the `impl Eq`
        assert_eq!(derived_pk, decoded_pk);

        // consistency check between returned pk and sk.get_public_key()
        assert_eq!(derived_pk, derived_sk.derive_pk());

        MLDSA44::keygen_from_seed_and_encoded(&seed, &sk_bytes).unwrap();

        let mut wrong_sk_bytes = sk_bytes.clone();
        wrong_sk_bytes[4..8].copy_from_slice(&[0u8, 0u8, 0u8, 0u8]);
        match MLDSA44::keygen_from_seed_and_encoded(&seed, &wrong_sk_bytes) {
            Err(SignatureError::KeyGenError(_)) => {/* good */ },
            _ => panic!("sk_from_seed_and_encoded should fail with InvalidSignature"),
        }



        /* MLDSA65 */
        let expected_pk_bytes: [u8; MLDSA65_PK_LEN] = hex::decode("48683d91978e31eb3dddb8b0473482d2b88a5f625949fd8f58a561e696bd4c27d05b38dbb2edf01e664efd81be1ea893688ce68aa2d51c5958f8bbc6eb4e89ee67d2c0320954d57212cac7229ff1d6eaf03928bd51511f8d88d847736c7de2730d5978e5410713160978867711bf5539a0bfc4c350c2be572baf0ee2e2fb16ccfea08028d99ac49aebb75937ddce111cdab62fff3cea8ba2233d1e56fbc5c5a1e726de63fadd2af016b119177fa3d971a2d9277173fce55b67745af0b7c21d597dbeb93e6a32f341c49a5a8be9e825088d1f2aa45155d6c8ae15367e4eb003b8fdf7851071949739f9fff09023eaf45104d2a84a45906eed4671a44dc28d27987bb55df69e9e8561f61a80a72699503865fed9b7ee72a8e17a19c408144f4b29afef7031c3a6d8571610b42c9f421245a88f197e16812b031159b65b9687e5b3e934c5225ae98a79ba73d2b399d73510effad19e53b8450f0ba8fce1012fd98d260a74aaaa13fae249a006b1c34f5ba0b882f26378222fb36f2283c243f0ffeb5f1bb414a0a70d55e3d40a56b6cbc88ae1f03b7b2882d98deea28e145c9dedfd8eaf1cef2ed94a8b050f8964f46d1ea0d0c2a43e0dda6182adbf4f6ed175b6742257859bf22f3a417ecf1f9d89317b5e539d587af16b9e1313e04514ffa64ba8b3ff2b8321f8811cb3fb022c8f644e70a4b80a2fbfee604abb7379091ea8e6c5c74dfc0283666b40c0793870028204a136bf5da9568eb798d349038bdb0c11e03445e7847cb5069c75cf28ac601c7799d958210ddbcb226e51afef9f1de47b073873d6d3f97456bede085082e74a298b2cd48f4b3093155f366c8fa601c6af858dfa32c08491b2a29887f90335949a5d6edaa679882a3a95d6bf6d970a221f4b9d3d8cbf384af81aac95e2b3294e04789ac83727a5dc04559f96af41d8a053516feeeebc52746eb6ab2819e09108710d835f011fa63065872ad334d5cdffb2b2310507e92fc993ae317da97f4f309cdaf0f67ed99d90215576083849f953b246d7fedb3fdb67679850a5ad404e64147fb7cf4f6aeddd05afb4b834968d1fe88014960dce5d942236526e12a478d69e5fbe6970310b308c06845018cfc7b2ab430a13a6b1ac7bb02cccbb3d911ac2f11068613fbe029bfdce02cf5cd38950ed72c83944edfbc75615af87f864c051f3c55456c5412863a40c06d1dab562bdff0571b8d3c3917bbd300880bba5e998239b95fa91b7d6416d4f398b3adbcd30983ed3592b4d9ef7d4236fd00f50d98aa53a235ac4172720f77d96172672980cfe8ff7a5a702783edc2ba31b2259015a112fc7f468a9c2f9464039002d30ef678b4cb798bc116216bf7a9a7c18ba03b7b58fd07515d3115049d3614be7a07e744300750df1d2c58753389059eafc3d785ccdd31c07648bedc03a5c3b8ad46d064d59c13d57374729fc4e295362e2a5191204530428bc1522afa28ff5fe1655e304ca5bc8c27ad0e0c6a39dd4df28956c14b38cc93682cefe402bbd5e82d29c464e44eb5d37b48fc568dfe0cc6e8e16baea05e5135590f19294e73e8367b0216dbb815030b9de55913f08039c42351c59e5515dd5af8e089a15e625e8f6dee639386c46497d7a263288774de581a7de9629b41b4424141f978fb8331208efdec3c6e0de39bc57063f3dcd6c470373c08891ea29cbc7cc6d6483b8889083ace86aa7b51b1c2cfe6e2ad18d97ce36fbc56ea42fae97e6a7ac114864478c366df1ebb1e7b11a9098504fd5975bdf1f49dc70002b63c1739a9d263fbad4073f6a9f6c2b8af4b4c332a103a0cffa5deeb2d062ca3c215fd360026be7c5164f4a4424ef74948804d66f46487732c8202c795478647b4ea71d627c086024cca354a41f0877b38f19b3774ad2095c8da53b069e21c76ae2d2007e16719ed40080d334f7da52e9f5a5990439caf083a95b833f02ad10a08c1a6d0f260c007285bd4a2f47703a5aef465287d253b18ac22514316210ff566814b10f87a293d6f199d3c3959990d0c1268b4f50d5f9fcefbbf237bd0c28b80182d6659741f14f10bfbb21bba12ab620aa2396f56c0686b4ea9017990224216b2fe8ad76c4a9148eef9a86a3635a6aa77bc1dcfb6fba59a77dfda9b7530dc0ca8648c8d973738e01bab8f08b4905e84aa4641bd602410cd97520265f2f231f2b35e15eb2fa04d2bd94d5a77abaf1e0e161010a990087f5b46ea988b2bc0512fda0fa923dadd6c45c5301d09483673265b5ab2e10f4ba520f6bbad564a5c3d5e27bdb080f7d20e13296a3181954c39c649c943ebe17df5c1f7aae0a8fe126c477585a5d4d648a0d008b6af5e8cd31be69a9296d4f3fd25ed86f221e4b93f65f5929967533624b9235750c30707550b58536d109a7131c5a5bbe4a5715567c12534aec7660761eebb9fae2891c774589b80e566ad557ddef7367196b7227ea9870ef09ddfec79d6b9319a6879b5205d76bf7aba5acf33afb59d17fc54e68383d6be5a08e9b66da53dcde008bb294b8582bd132cdcc49959fdbc21e52721880c8ad0352c79f03a43bbd84c4cdfdc6c529005e1e7cd9a349a7168a35569ba5dea818968d5a91466bd6e64e20bf62417198afc4e81c28dd77ed4028232398b52fbde86bc84f475b9016710ce2aabc11a06b4dbac901ec16cf365ca3f2d53813948a693a0f93e79c46ca5d5a6dca3d28ca50ad18bd13fca55059dd9b185f79f9c47196a4e81b2104bc460a051e02f2e8444f").unwrap()
                                                        .try_into().unwrap();

        // Decode and re-encode the pk, make sure you get the same thing
        let expected_pk = MLDSA65PublicKey::from_bytes(&expected_pk_bytes).unwrap();
        let pk_bytes = expected_pk.encode();
        assert_eq!(pk_bytes.len(), expected_pk_bytes.len());
        assert_eq!(pk_bytes, expected_pk_bytes.as_slice());


        // run keygen from seed
        let (derived_pk, derived_sk) = MLDSA65::keygen_from_seed(&seed).unwrap();
        let sk_bytes = derived_sk.sk_encode();
        assert_eq!(&sk_bytes, &*hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap());


        assert_eq!(derived_pk.pk_encode(), expected_pk_bytes.as_slice());
        // also test the `impl Eq`
        assert_eq!(derived_pk, expected_pk);

        // consistency check between returned pk and sk.get_public_key()
        assert_eq!(derived_pk, derived_sk.derive_pk());

        MLDSA65::keygen_from_seed_and_encoded(&seed, &sk_bytes).unwrap();

        let mut wrong_sk_bytes = sk_bytes.clone();
        wrong_sk_bytes[4..8].copy_from_slice(&[0u8, 0u8, 0u8, 0u8]);
        match MLDSA65::keygen_from_seed_and_encoded(&seed, &wrong_sk_bytes) {
            Err(SignatureError::KeyGenError(_)) => {/* good */ },
            _ => panic!("sk_from_seed_and_encoded should fail with InvalidSignature"),
        }



        /* MLDSA87 */
        let expected_pk_bytes: [u8; MLDSA87_PK_LEN] = hex::decode("9792bcec2f2430686a82fccf3c2f5ff665e771d7ab41b90258cfa7e90ec97124a73b323b9ba21ab64d767c433f5a521effe18f86e46a188952c4467e048b729e7fc4d115e7e48da1896d5fe119b10dcddef62cb307954074b42336e52836de61da941f8d37ea68ac8106fabe19070679af6008537120f70793b8ea9cc0e6e7b7b4c9a5c7421c60f24451ba1e933db1a2ee16c79559f21b3d1b8305850aa42afbb13f1f4d5b9f4835f9d87dfceb162d0ef4a7fdc4cba1743cd1c87bb4967da16cc8764b6569df8ee5bdcbffe9a4e05748e6fdf225af9e4eeb7773b62e8f85f9b56b548945551844fbd89806a4ac369bed2d256100f688a6ad5e0a709826dc4449e91e23c5506e642361ef5a313712f79bc4b3186861ca85a4bab17e7f943d1b8a333aa3ae7ce16b440d6018f9e04daf5725c7f1a93fad1a5a27b67895bd249aa91685de20af32c8b7e268c7f96877d0c85001135a4f0a8f1b8264fa6ebe5a349d8aecad1a16299ccf2fd9c7b85bace2ced3aa1276ba61ee78ed7e5ca5b67cdd458a9354030e6abbbabf56a0a2316fec9dba83b51d42fd3167f1e0f90855d5c66509b210265dc1e54ec44b43ba7cf9aef118b44d80912ce75166a6651e116cebe49229a7062c09931f71abd2293f76f7efc3215ba97800037e58e470bdbbb43c1b0439eaf79c54d93b44aac9efe9fbe151874cfb2a64cbee28cc4c0fe7775e5d870f1c02e5b2e3c5004c995f24c9b779cb753a277d0e71fd425eb6bc2ca56ce129db51f70740f31e63976b50c7312e9797d78c5b1ac24a5fa347cc916e0a83f5c3b675cd30b81e3fa10b93444e07397571cce98b28da51db9056bc728c5b0b1181e2fbd387b4c79ab1a5fefece37167af772ddad14eb4c3982da5a59d0e9eb173ec6315091170027a3ab5ef6aa129cb8585727b9358a28501d713a72f3f1db31714286f9b6408013af06045d75592fc0b7dd47c73ed9c75b11e9d7c69f7cadfc3280a9062c5273c43be1c34f87448864cea7b5c97d6d32f59bd5f25384653bb5c4faa45bea8b89402843e645b6b9269e2bd988ddacb033328ffb060450f7df080053e6969b251e875ecec32cfc592840d69ab69a75e06b379c535d95266b082f4f09c93162b33b0d9f7307a4eaaa52104437fed66f8ee3eabbd45d67b25a8133f496468b52baffdbfad93eef1a9818b5e42ec722788a3d8d3529fc777d2ba570801dfae01ec88302837c1fb9e0355727645ee1046c3f915f6ae82dad4fb6b0356a46518ffc834155c3b4fe6dafa6cc8a5ccf53c73a0849d8d44f7dcf72754e70e1b7dfb447bb4ef49d1a718f6171bbce200950e0ce926106b151a3e871d5ce49731bd6650a9b0ca972da1c5f136d44820ea6383c08f3b384cf2338e789c513f618cc5694a6f0cee104511e1ed7c5f23a1ebfd8a0db8424553240156dbf622831b0c643d1c551b6f3f7a98d29b85c2de05a65fa615eee16495bd90737672115b53e91c5d90028cf3f1a93953a153de53b44084e9ccff6b736693926daefebb2d77aa5ad689b92f31686669df16d1715cc58f7a2cfb72dd1a51e92f825993a74022be7e9eb6054654457094d14928f20215e7b222ac56b51adbec8d8bdb6983979a7e3a21b44b5d1518ca97d0b5195f51ed6a24350c89747e1edea51b448e3e9147054ce927873c90db394d86888e07dff177593d6f79e152302204aeb03be2386af3e24078bd028b1689f5e147c9f452c8ceb02ec59cc9db63a03576ceeafe98239023897da0236630a53c0de7f435a19869792fab36e7b9e635760f09069e6432e700035ac2a02879fff0a1e1bec522047193d94eb5df1efd53eea1144ca78940852f5ec9727904b366ede4f5e2d331fad5fc282ea2c47e923142771c3dd75a87357487def99e5f18e9d9ed623c175d02888c51f82c07a80d54716b3c3c2bdbe2e9f0a9bbaaebeb4d52936876406f5c00e8e4bbd0a5ec05797e6207c5ab6c88f1a688421bd05a114f4d7de2ac241fa0e8bedff47f762ddcbeaa91004f8d31e85095c81054994ad3826e344ba96040810fc0b2ad1de48cfade002c62e5a49a0731ab38344bc1636df16bf607d56855e56d684003c718e4bad9e5a099979fcddeeb1c4a7776cd37a3417cb0e184e29ef9bc0e87475ba663be09e00ab562eb7c0f7165f969a9b42414198ccf1bff2a2c8d689a414ece7662927665689e94db961ebaec5615cbc1a7895c6851ac961432ff1118d4607d32ef9dc732d51333be4b4d0e30ddea784eca8be47e741be9c19631dc470a52ef4dc13a4f3633fd434d787c170977b417df598e1d0dde506bb71d6f0bc17ec70e3b03cdc1965cb36993f633b0472e50d0923ac6c66fdf1d3e6459cc121f0f5f94d09e9dbcf5d690e23233838a0bacb7c638d1b2650a4308cd171b6855126d1da672a6ed85a8d78c286fb56f4ab3d21497528045c63262c8a42af2f9802c53b7bb8be28e78fe0b5ce45fbb7a1af1a3b28a8d94b7890e3c882e39bc98e9f0ad76025bf0dd2f00298e7141a226b3d7cee414f604d1e0ba54d11d5fe58bccea6ad77ad2e8c1caacf32459014b7b91001b1efa8ad172a523fb8e365b577121bf9fd88a2c60c21e821d7b6acb47a5a995e40caced5c223b8fe6de5e18e9d2e5893aefebb7aae7ff1a146260e2f110e939528213a0025a38ec79aabc861b25ebc509a4674c132aaacb7e0146f14efd11cfcaf4caa4f775a716ce325e0a435a4d349d720bcf137450afc45046fc1a1f83a9d329777a7084e4aadae7122ce97005930528eb3c7f7f1129b372887a371155a3ba201a25cbf1dcb64e7cdee092c3141fb5550fe3d0dd82e870e578b2b46500818113b8f6569773c677385b69a42b77dcba7acffd95fd4452e23aaa1d37e1da2151ea658d40a3596b27ac9f8129dc6cf0643772624b59f4f461230df471ca26087c3942d5c6687df6082835935a3f87cb762b0c3b1d0dda4a6533965bef1b7b8292e254c014d090fed857c44c1839c694c0a64e3fad90a11f534722b6ee1574f2e149d55d744de4887024e08511431c062750e16c74ab9f3242f2db3ffb12a8d6107faa229d6f6373b07f36d3932b3bdb04c19dd64eadd7f93c3c564c358a1c81dcf1c9c31e5b06568f97544c17dc15698c5cb38983a9afc42783faa773a52c9d8260690be9e3156aa5bc1509dea3f69587695cd6ff172ba83e6a6d8a7d6bbebbbcda3672731983f89bc5831dc37c3f3c5c56facc697f3cb20bd5dbadbd702e54844ac2f626901fe159db93dfd4773d8fe73562b846c1fc856d1802762840ebc72d7988bde75cbca70d319d32ce0cc0253bb2ad455723ee0c7f4736ce6e6665c5aca32a481c53839bc259167b013d0423395eeb9aaaee3206149a7d550d67fc5fdfe4a8a5c35d2510b664379ab8f72855a2af47abce2a632048eaf89e5cb4a88debc53a595103acce4f1cff18acff07afe1eb5716aa1e40b63134c3a3ae9579fa87f515be093c2d29db6d6b65c93661e00636b592704d093cc6716c2342eb1853d48c85c63ac8a2854462c7b77e7e3bd1eac5bca28ffaa00b5d349f8a547ad875b96a8c2b2910c9301309a3f9138a5693111f55b3c009ca947c39dfc82d98eb1caa4a9cbe885f786fa86e55be062222f8ba90a974073326b31212aece0a34a60").unwrap()
                                                        .try_into().unwrap();

        // Decode and re-encode the pk, make sure you get the same thing
        let expected_pk = MLDSA87PublicKey::from_bytes(&expected_pk_bytes).unwrap();
        let pk_bytes = expected_pk.encode();
        assert_eq!(pk_bytes.len(), expected_pk_bytes.len());
        assert_eq!(pk_bytes, expected_pk_bytes.as_slice());


        // run keygen from seed
        let (derived_pk, derived_sk) = MLDSA87::keygen_from_seed(&seed).unwrap();
        let sk_bytes = derived_sk.sk_encode();
        assert_eq!(&sk_bytes, &*hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap());


        assert_eq!(derived_pk.pk_encode(), expected_pk_bytes.as_slice());
        // also test the `impl Eq`
        assert_eq!(derived_pk, expected_pk);

        // consistency check between returned pk and sk.get_public_key()
        assert_eq!(derived_pk, derived_sk.derive_pk());

        MLDSA87::keygen_from_seed_and_encoded(&seed, &sk_bytes).unwrap();

        let mut wrong_sk_bytes = sk_bytes.clone();
        wrong_sk_bytes[4..8].copy_from_slice(&[0u8, 0u8, 0u8, 0u8]);
        match MLDSA87::keygen_from_seed_and_encoded(&seed, &wrong_sk_bytes) {
            Err(SignatureError::KeyGenError(_)) => {/* good */ },
            _ => panic!("sk_from_seed_and_encoded should fail with InvalidSignature"),
        }
    }

    #[test]
    fn keygen_error_cases() {
        /*
            Testing this condition:
                if !(seed.key_type() == KeyType::Seed || seed.key_type() == KeyType::BytesFullEntropy)
            || seed.key_len() != 32
         */
        // success case KeyType: seed
        let mut seed = KeyMaterial256::from_bytes_as_type(
            &hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap(),
            KeyType::Seed,
        ).unwrap();
        /* MLDSA44 */
        let expected_pk_bytes: [u8; MLDSA44_PK_LEN] = hex::decode("d7b2b47254aae0db45e7930d4a98d2c97d8f1397d1789dafa17024b316e9bec94fc9946d42f19b79a7413bbaa33e7149cb42ed5115693ac041facb988adeb5fe0e1d8631184995b592c397d2294e2e14f90aa414ba3826899ac43f4cccacbc26e9a832b95118d5cb433cbef9660b00138e0817f61e762ca274c36ad554eb22aac1162e4ab01acba1e38c4efd8f80b65b333d0f72e55dfe71ce9c1ebb9889e7c56106c0fd73803a2aecfeafded7aa3cb2ceda54d12bd8cd36a78cf975943b47abd25e880ac452e5742ed1e8d1a82afa86e590c758c15ae4d2840d92bca1a5090f40496597fca7d8b9513f1a1bda6e950aaa98de467507d4a4f5a4f0599216582c3572f62eda8905ab3581670c4a02777a33e0ca7295fd8f4ff6d1a0a3a7683d65f5f5f7fc60da023e826c5f92144c02f7d1ba1075987553ea9367fcd76d990b7fa99cd45afdb8836d43e459f5187df058479709a01ea6835935fa70460990cd3dc1ba401ba94bab1dde41ac67ab3319dcaca06048d4c4eef27ee13a9c17d0538f430f2d642dc2415660de78877d8d8abc72523978c042e4285f4319846c44126242976844c10e556ba215b5a719e59d0c6b2a96d39859071fdcc2cde7524a7bedae54e85b318e854e8fe2b2f3edfac9719128270aafd1e5044c3a4fdafd9ff31f90784b8e8e4596144a0daf586511d3d9962b9ea95af197b4e5fc60f2b1ed15de3a5bef5f89bdc79d91051d9b2816e74fa54531efdc1cbe74d448857f476bcd58f21c0b653b3b76a4e076a6559a302718555cc63f74859aabab925f023861ca8cd0f7badb2871f67d55326d7451135ad45f4a1ba69118fbb2c8a30eec9392ef3f977066c9add5c710cc647b1514d217d958c7017c3e90fd20c04e674b90486e9370a31a001d32f473979e4906749e7e477fa0b74508f8a5f2378312b83c25bd388ca0b0fff7478baf42b71667edaac97c46b129643e586e5b055a0c211946d4f36e675bed5860fa042a315d9826164d6a9237c35a5fbf495490a5bd4df248b95c4aae7784b605673166ac4245b5b4b082a09e9323e62f2078c5b76783446defd736ad3a3702d49b089844900a61833397bc4419b30d7a97a0b387c1911474c4d41b53e32a977acb6f0ea75db65bb39e59e701e76957def6f2d44559c31a77122b5204e3b5c219f1688b14ed0bc0b801b3e6e82dcd43e9c0e9f41744cd9815bd1bc8820d8bb123f04facd1b1b685dd5a2b1b8dbbf3ed933670f095a180b4f192d08b10b8fabbdfcc2b24518e32eea0a5e0c904ca844780083f3b0cd2d0b8b6af67bc355b9494025dc7b0a78fa80e3a2dbfeb51328851d6078198e9493651ae787ec0251f922ba30e9f51df62a6d72784cf3dd205393176dfa324a512bd94970a36dd34a514a86791f0eb36f0145b09ab64651b4a0313b299611a2a1c48891627598768a3114060ba4443486df51522a1ce88b30985c216f8e6ed178dd567b304a0d4cafba882a28342f17a9aa26ae58db630083d2c358fdf566c3f5d62a428567bc9ea8ce95caa0f35474b0bfa8f339a250ab4dfcf2083be8eefbc1055e18fe15370eecb260566d83ff06b211aaec43ca29b54ccd00f8815a2465ef0b46515cc7e41f3124f09efff739309ab58b29a1459a00bce5038e938c9678f72eb0e4ee5fdaae66d9f8573fc97fc42b4959f4bf8b61d78433e86b0335d6e9191c4d8bf487b3905c108cfd6ac24b0ceb7dcb7cf51f84d0ed687b95eaeb1c533c06f0d97023d92a70825837b59ba6cb7d4e56b0a87c203862ae8f315ba5925e8edefa679369a2202766151f16a965f9f81ece76cc070b55869e4db9784cf05c830b3242c8312").unwrap()
            .try_into().unwrap();
        let (derived_pk, _derived_sk) = MLDSA44::keygen_from_seed(&seed).unwrap();
        assert_eq!(derived_pk.pk_encode(), expected_pk_bytes.as_slice());

        // success case KeyType: BytesFullEntropy
        seed.allow_hazardous_operations();
        seed.set_key_type(KeyType::BytesFullEntropy).unwrap();
        _ = MLDSA44::keygen_from_seed(&seed).unwrap();


        // Failure case: key type != Seed || BytesFullEntropy
        let mac_seed = KeyMaterial256::from_bytes_as_type(
            &hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap(),
            KeyType::MACKey,
        ).unwrap();

        match MLDSA44::keygen_from_seed(&mac_seed) {
            Err(SignatureError::KeyGenError(_)) => { /* good */ },
            _ => panic!("expected KeyGenError"),
        }

        // Failure case: key is undersized
        let seed = KeyMaterial256::from_bytes_as_type(
            &hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718").unwrap(),
            KeyType::Seed,
        ).unwrap();
        assert_eq!(seed.key_len(), 25);

        match MLDSA44::keygen_from_seed(&seed) {
            Err(SignatureError::KeyGenError(_)) => { /* good */ },
            _ => panic!("expected KeyGenError"),
        }
    }

    #[test]
    fn deterministic_sign() {
        // at least one test each of signing with a deterministic signing nonce
        // We support setting the signing nonce (rnd) via two interfaces: external mu, and streaming API.

        // ML-DSA-44

        let sk = MLDSA44PrivateKey::from_bytes(&hex::decode(MLDSA44_KAT1.sk).unwrap()).unwrap();
        let rnd = if !MLDSA44_KAT1.deterministic {
                let mut rnd = [0u8; 32];
                bouncycastle_rng::DefaultRNG::default().next_bytes_out(&mut rnd).unwrap();
                rnd
            } else { [0u8; 32] };

        let mu = MLDSA44::compute_mu_from_sk(&sk,&hex::decode(MLDSA44_KAT1.message).unwrap(), Some(&hex::decode(MLDSA44_KAT1.ctx).unwrap())).unwrap();
        let sig = MLDSA44::sign_mu_deterministic(&sk, &mu, rnd).unwrap();
        assert_eq!(&sig, &*hex::decode(MLDSA44_KAT1.signature).unwrap());
        MLDSA44::verify(&sk.derive_pk(), &hex::decode(MLDSA44_KAT1.message).unwrap(), Some(&hex::decode(MLDSA44_KAT1.ctx).unwrap()), &sig).unwrap();

        // test the streaming API on the same value
        let mut s = MLDSA44::sign_init(&sk, Some(&hex::decode(MLDSA44_KAT1.ctx).unwrap())).unwrap();
        s.set_signer_rnd(rnd);
        s.sign_update(&hex::decode(MLDSA44_KAT1.message).unwrap());
        let sig = s.sign_final().unwrap();
        assert_eq!(&sig, &hex::decode(MLDSA44_KAT1.signature).unwrap());

        // Then with the message broken into chunks
        let mut s = MLDSA44::sign_init(&sk, Some(b"streaming API chunked")).unwrap();
        s.set_signer_rnd(rnd);
        for msg_chunk in DUMMY_SEED_1024.chunks(100) {
            s.sign_update(msg_chunk);
        }
        let sig_val = s.sign_final().unwrap();
        MLDSA44::verify(&sk.derive_pk(), DUMMY_SEED_1024, Some(b"streaming API chunked"), &sig_val).unwrap();



        // ML-DSA-65

        let sk = MLDSA65PrivateKey::from_bytes(&hex::decode(MLDSA65_KAT1.sk).unwrap()).unwrap();
        let rnd = if !MLDSA65_KAT1.deterministic {
            let mut rnd = [0u8; 32];
            bouncycastle_rng::DefaultRNG::default().next_bytes_out(&mut rnd).unwrap();
            rnd
        } else { [0u8; 32] };

        let mu = MLDSA65::compute_mu_from_sk(&sk, &hex::decode(MLDSA65_KAT1.message).unwrap(), Some(&hex::decode(MLDSA65_KAT1.ctx).unwrap())).unwrap();
        let sig = MLDSA65::sign_mu_deterministic(&sk, &mu, rnd).unwrap();
        assert_eq!(&sig, &*hex::decode(MLDSA65_KAT1.signature).unwrap());

        MLDSA65::verify(
            &sk.derive_pk(), &*hex::decode(MLDSA65_KAT1.message).unwrap(), Some(&hex::decode(MLDSA65_KAT1.ctx).unwrap()), &sig).unwrap();

        // test the streaming API on the same value
        let mut s = MLDSA65::sign_init(&sk, Some(&hex::decode(MLDSA65_KAT1.ctx).unwrap())).unwrap();
        s.set_signer_rnd(rnd);
        s.sign_update(&hex::decode(MLDSA65_KAT1.message).unwrap());
        let sig = s.sign_final().unwrap();
        assert_eq!(&sig, &hex::decode(MLDSA65_KAT1.signature).unwrap());



        // ML-DSA-87

        let sk = MLDSA87PrivateKey::from_bytes(&hex::decode(MLDSA87_KAT1.sk).unwrap()).unwrap();
        let rnd = if !MLDSA65_KAT1.deterministic {
            let mut rnd = [0u8; 32];
            bouncycastle_rng::DefaultRNG::default().next_bytes_out(&mut rnd).unwrap();
            rnd
        } else { [0u8; 32] };

        let mu = MLDSA87::compute_mu_from_sk(&sk, &hex::decode(MLDSA87_KAT1.message).unwrap(), Some(&hex::decode(MLDSA87_KAT1.ctx).unwrap())).unwrap();
        let sig = MLDSA87::sign_mu_deterministic(&sk, &mu, rnd).unwrap();
        assert_eq!(&sig, &*hex::decode(MLDSA87_KAT1.signature).unwrap());

        MLDSA87::verify(&sk.derive_pk(), &*hex::decode(MLDSA87_KAT1.message).unwrap(), Some(&hex::decode(MLDSA87_KAT1.ctx).unwrap()), &sig).unwrap();

        // test the streaming API on the same value
        let mut s = MLDSA87::sign_init(&sk, Some(&hex::decode(MLDSA87_KAT1.ctx).unwrap())).unwrap();
        s.set_signer_rnd(rnd);
        s.sign_update(&hex::decode(MLDSA87_KAT1.message).unwrap());
        let sig = s.sign_final().unwrap();
        assert_eq!(&sig, &hex::decode(MLDSA87_KAT1.signature).unwrap());
    }

    #[test]
    fn test_sign_mu_deterministic_from_seed_out() {
        // I don't have a KAT, so I'll test against the regular implementation

        // ML-DSA-44

        let seed = KeyMaterial256::from_bytes_as_type(
            &hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap(),
            KeyType::Seed,
        ).unwrap();

        let rnd = if !MLDSA44_KAT1.deterministic {
            let mut rnd = [0u8; 32];
            bouncycastle_rng::DefaultRNG::default().next_bytes_out(&mut rnd).unwrap();
            rnd
        } else { [0u8; 32] };

        let tr: [u8; TR_LEN];
        {
            let (_, sk) = MLDSA44::keygen_from_seed(&seed).unwrap();
            tr = sk.tr().clone();
        }

        // BEGIN expected values
        let (_, expected_sk) = MLDSA44::keygen_from_seed(&seed).unwrap();
        let expected_mu = MLDSA44::compute_mu_from_sk(&expected_sk,
                                                      &hex::decode(MLDSA44_KAT1.message).unwrap(),
                                                      Some(&hex::decode(MLDSA44_KAT1.ctx).unwrap())).unwrap();
        let mut expected_sig = [0u8; MLDSA44_SIG_LEN];
        let bytes_written = MLDSA44::sign_mu_deterministic_out(&expected_sk, &expected_mu, rnd, &mut expected_sig).unwrap();
        assert_eq!(bytes_written, MLDSA44_SIG_LEN);
        // END expected values

        let mu = MLDSA44::compute_mu_from_tr(&tr, &hex::decode(MLDSA44_KAT1.message).unwrap(), Some(&hex::decode(MLDSA44_KAT1.ctx).unwrap())).unwrap();
        assert_eq!(&expected_mu, &mu);
        let mut sig = [0u8; MLDSA44_SIG_LEN];
        let bytes_written = MLDSA44::sign_mu_deterministic_from_seed_out(&seed, &mu, rnd, &mut sig).unwrap();
        assert_eq!(bytes_written, MLDSA44_SIG_LEN);
        assert_eq!(&sig, &expected_sig);

        let (pk, _) = MLDSA44::keygen_from_seed(&seed).unwrap();
        MLDSA44::verify(&pk, &hex::decode(MLDSA44_KAT1.message).unwrap(), Some(&hex::decode(MLDSA44_KAT1.ctx).unwrap()), &sig).unwrap();


        // test the streaming API on the same value

        let mut s = MLDSA44::sign_init_from_seed(&seed, Some(&hex::decode(MLDSA44_KAT1.ctx).unwrap())).unwrap();
        s.set_signer_rnd(rnd);
        s.sign_update(&hex::decode(MLDSA44_KAT1.message).unwrap());
        let sig = s.sign_final().unwrap();
        assert_eq!(&sig, &expected_sig);



        // while we're at it, test the streaming verifier cause I'm not sure where else this is being tested.

        let mut v = MLDSA44::verify_init(&pk, Some(&hex::decode(MLDSA44_KAT1.ctx).unwrap())).unwrap();
        v.verify_update(&hex::decode(MLDSA44_KAT1.message).unwrap());
        v.verify_final(&expected_sig).unwrap();
    }

    #[test]
    fn test_boundary_conditions() {
        let msg = b"The quick brown fox jumped over the lazy dog";

        // ctx too long
        // this is common to all parameter sets, so I'll just test MLDSA44
        let (_pk, sk) = MLDSA44::keygen().unwrap();
        let too_long_ctx = [1u8; 256];
        match MLDSA44::sign_init(&sk, Some(&too_long_ctx)) {
            Err(SignatureError::LengthError(_)) => { /* good */ },
            _ => panic!("Expected error for ctx too long"),
        }

        // test various things that are shorter / longer than required

        // sign_out

        // MLDSA44
        let (_pk, sk) = MLDSA44::keygen().unwrap();
        let mut out_too_short = [1u8; MLDSA44_SIG_LEN -1];
        match MLDSA44::sign_out(&sk, msg, None, &mut out_too_short) {
            Err(SignatureError::LengthError(_)) => { /* good */ },
            _ => panic!("Expected error for out_too_short"),
        }

        let mut s = MLDSA44::sign_init(&sk, None).unwrap();
        s.sign_update(msg);
        match s.sign_final_out(&mut out_too_short) {
            Err(SignatureError::LengthError(_)) => { /* good */ },
            _ => panic!("Expected error for out_too_short"),
        }


        // too long is fine; it should just write to the beginning
        let mut out_too_long = [1u8; MLDSA44_SIG_LEN + 2];
        let bytes_written = MLDSA44::sign_out(&sk, msg, None, &mut out_too_long).unwrap();
        assert_eq!(bytes_written, MLDSA44_SIG_LEN);
        assert_eq!(&out_too_long[MLDSA44_SIG_LEN..], &[1,1]);

        let mut s = MLDSA44::sign_init(&sk, None).unwrap();
        s.sign_update(msg);
        let bytes_written = s.sign_final_out(&mut out_too_long).unwrap();
        assert_eq!(bytes_written, MLDSA44_SIG_LEN);
        assert_eq!(&out_too_long[MLDSA44_SIG_LEN..], &[1,1]);


        // MLDSA65
        let (_pk, sk) = MLDSA65::keygen().unwrap();
        let mut out_too_short = [1u8; MLDSA65_SIG_LEN -1];
        match MLDSA65::sign_out(&sk, msg, None, &mut out_too_short) {
            Err(SignatureError::LengthError(_)) => { /* good */ },
            _ => panic!("Expected error for out_too_short"),
        }

        let mut s = MLDSA65::sign_init(&sk, None).unwrap();
        s.sign_update(msg);
        match s.sign_final_out(&mut out_too_short) {
            Err(SignatureError::LengthError(_)) => { /* good */ },
            _ => panic!("Expected error for out_too_short"),
        }

        // too long is fine; it should just write to the beginning
        let mut out_too_long = [1u8; MLDSA65_SIG_LEN + 2];
        let bytes_written = MLDSA65::sign_out(&sk, msg, None, &mut out_too_long).unwrap();
        assert_eq!(bytes_written, MLDSA65_SIG_LEN);
        assert_eq!(&out_too_long[MLDSA65_SIG_LEN..], &[1,1]);

        let mut s = MLDSA65::sign_init(&sk, None).unwrap();
        s.sign_update(msg);
        let bytes_written = s.sign_final_out(&mut out_too_long).unwrap();
        assert_eq!(bytes_written, MLDSA65_SIG_LEN);
        assert_eq!(&out_too_long[MLDSA65_SIG_LEN..], &[1,1]);


        // MLDSA87
        let (_pk, sk) = MLDSA87::keygen().unwrap();
        let mut out_too_short = [1u8; MLDSA87_SIG_LEN -1];
        match MLDSA87::sign_out(&sk, msg, None, &mut out_too_short) {
            Err(SignatureError::LengthError(_)) => { /* good */ },
            _ => panic!("Expected error for out_too_short"),
        }

        let mut s = MLDSA87::sign_init(&sk, None).unwrap();
        s.sign_update(msg);
        match s.sign_final_out(&mut out_too_short) {
            Err(SignatureError::LengthError(_)) => { /* good */ },
            _ => panic!("Expected error for out_too_short"),
        }

        // too long is fine; it should just write to the beginning
        let mut out_too_long = [1u8; MLDSA87_SIG_LEN + 2];
        let bytes_written = MLDSA87::sign_out(&sk, msg, None, &mut out_too_long).unwrap();
        assert_eq!(bytes_written, MLDSA87_SIG_LEN);
        assert_eq!(&out_too_long[MLDSA87_SIG_LEN..], &[1,1]);

        let mut s = MLDSA87::sign_init(&sk, None).unwrap();
        s.sign_update(msg);
        let bytes_written = s.sign_final_out(&mut out_too_long).unwrap();
        assert_eq!(bytes_written, MLDSA87_SIG_LEN);
        assert_eq!(&out_too_long[MLDSA87_SIG_LEN..], &[1,1]);


        // sig too long / too short

        // MLDSA44
        let (pk, sk) = MLDSA44::keygen().unwrap();
        let sig = MLDSA44::sign(&sk, msg, None).unwrap();
        // too short
        match MLDSA44::verify(&pk, msg, None, &sig[..MLDSA44_SIG_LEN-1]) {
            Err(SignatureError::LengthError(_)) => { /* good */ },
            _ => panic!("Expected error for sig too short"),
        }
        // too long
        let mut sig_too_long = sig.clone();
        sig_too_long.append(&mut vec![1u8, 0u8]);
        match MLDSA44::verify(&pk, msg, None, &sig_too_long) {
            Err(SignatureError::LengthError(_)) => { /* good */ },
            _ => panic!("Expected error for sig too short"),
        }

        // MLDSA65
        let (pk, sk) = MLDSA65::keygen().unwrap();
        let sig = MLDSA65::sign(&sk, msg, None).unwrap();
        // too short
        match MLDSA65::verify(&pk, msg, None, &sig[..MLDSA65_SIG_LEN-1]) {
            Err(SignatureError::LengthError(_)) => { /* good */ },
            _ => panic!("Expected error for sig too short"),
        }
        // too long
        let mut sig_too_long = sig.clone();
        sig_too_long.append(&mut vec![0u8, 0u8]);
        match MLDSA65::verify(&pk, msg, None, &sig_too_long) {
            Err(SignatureError::LengthError(_)) => { /* good */ },
            _ => panic!("Expected error for sig too short"),
        }

        // MLDSA87
        let (pk, sk) = MLDSA87::keygen().unwrap();
        let sig = MLDSA87::sign(&sk, msg, None).unwrap();
        // too short
        match MLDSA87::verify(&pk, msg, None, &sig[..MLDSA44_SIG_LEN-1]) {
            Err(SignatureError::LengthError(_)) => { /* good */ },
            _ => panic!("Expected error for sig too short"),
        }
        // too long
        let mut sig_too_long = sig.clone();
        sig_too_long.append(&mut vec![0u8, 0u8]);
        match MLDSA87::verify(&pk, msg, None, &sig_too_long) {
            Err(SignatureError::LengthError(_)) => { /* good */ },
            _ => panic!("Expected error for sig too short"),
        }
    }

    #[test]
    fn sig_val_z_too_big() {
        // This signature value was manually generated in the debugger to have a z containing several
        // coefficients of (1<<17) -1, which are just below GAMMA1, and in aggregate should cause check_norm() to fail.
        // ... a condition that generally does not show up with well-behaved inputs.

        let busted_sig = hex::decode("cb8f8b46d73e7c273500555acbe0e7cf1da54d950675248e11bff5940b45f52f010004001000000682ff854d13b45dd7a148636d330453ecaecc627c0a1b417aa5c52cdbb614aeaa3e73f19a59686151872cab71fe793a217ecad4c7a0504a6bbd2585dcb4fc756ebf43242d933c5d90f940d96c74a2a0817e14b5d5563c1f42cd7ac23d18276a301acd91ce752843982ebea23b1c0a7319adcb6ded96d6db10b80067d20b2cce31ea5ff1dbd2bf0b9d29e2db5f9bd547e9f75d00e7db6f2071b5d4f3cb9137df6924ba5e2e203b000802ee2bd34f933e352a54325804ff0b5c43deae326e7e6af0afcff83c2b4ced702a5e2f2fe57a2aad9223a96aa1b54e422aa2ad23a75ce489bf4232b92cb4ddbae6f9f1c0a7d3472e26b7423caf59c919c916e08fc50981c153ea9daa956afdd0a8d980cbb709082c8fcec7f55cef10f1e2d641b667f4aa54be817c26ed446bf58ebbe4b0a98175e469d6231c73d798e761190018a9340d463c09e525d17ab29b50031cc46f625f20ddffbacee4833cf652f6733c5ab1c3c0554fe916652e3a5b88e634213f7fa34ce2c8cfea0e49eed17ada23844c061846f962410b43d1facd60d5e3a667871f7c10d922ba44b7ed153d9b9337d07e14338e8dcae3371c84483a65b5889591c226aa04f4f22965b0762e0cd98396fe6aa0a5aa902f70f93bf9a816dc686ac6cf055d7acb7a994cb1613fc1a8473fde6d39beabcf302eded80ea213f980bd28df6e5837de4b8afbb685b74a1e9cf4f9fc51639b057e73b68d11d72d15e8c81762e3ebf085cf058e132d1edcf170915509a3a58bc2e3184629b0cfe17b452537421532d6bd7d78237b8cb83811d3f823e150144d102f86418ab8cefb2c4c6a7510f1a34e1d2f9cee9209fb8f62c04975086767bfae2644f0e514e0b973ed6547deee0b8cf0a5d21865b4c41bf7acf05ad8f14103dc599aa9d068d777b047850ff42328de052300588bab7264fa885e981b1afce0b48e756db8589625d6294732c44a51aa4a8d4f5c5572bc3c08a3d18c0d7f9d2291af6ee2f3bb552b22acf3466f75886a77701cc0efa1adbc5258dc7e9463db16983e4e7bf2cf66bd3770ea2ca0a33e3c4515b1865f9bd5057c8a810062a7c61f9c1e73b0c53fb1a29b306ae719ad7602c49dde36909e152e106d248be1df684c4a56355a69277255e646d5c1bc6fea212e19da26caaddae09c63587ca4bc496de9369e22eb270a96706d3d4b3caabb271bea66027739fad15bd5d91108944b7533daa77f5eb3cf87eaaba8a8eb7e1aa234eccb2fda84ba55027bb96b024a8a81afbe46b3334376f5f9f8efbce6530ada96980b2c9938858ec99fce960eae548e84bfccf400209fdca72fdcc8a72cc497ef4f247056f7cd008bf2299a6e3d5bcccc7055abbf7a8585bdde15028815cfee54e7a74a88c09af785d1b8885c090e59ea312f2aabffaceb8f77eb62e122ca5b74cf906ff7bb393f7d5801332aa0edc72a9a264b413405edf3b80c6e2dd410f0ab0ddca75d04cccdef4c76df60482e83e45a4306f7b67028d4ac0a99d75dacd0d78c4056814f1e3624219dc46832ebf66d6520316a7a552d12752e991a0217e119662d21ead999271c74a6cb168af99dd0a63412882be744f409d08c0ace64b60a647326f88262bd6a1c19187ad9ff420e56fd0242c4c8e3dc097e1313047d618b29336c36571b0bf2840da2d8d9d021c271532f475c07b5dfd74754a3b4a2b22035b3575d4a4836c784f24b228be567f30994b71be1c355644edb72dea9458848f91da920c3c45c187121431684e261af26671387a109b1938e14257a646902be53d5bd9a26696c7ef48e194135c6bdf97df5a98e87a77df89150b2906b50d332cd79389710fcd0c57c982ed51d510ca44de02d4acc9ad0fd9e4491fc9727ea26691b2f742c96bf0b0c88c1d844102e2d90d744fa91cd6d01a2123b8e6e0f2f40ab68149d7fc00fcce3ef590152722b4d47bf8f291491e8ebf6efdde2d1992ce9b754aea6ef9ee019afeddf619aed86757c50b5b85bf8c44eaab670f4f018bcde75f7dcead0a1ff234d6e717f057a9a372ba998915c4cac6b8c4d568b414c8c0be19afbb8a40092c686eeb57a899b3f67d1e1d6ae326f1f5fc5e8e3b203e041807462c7f171f49841835c20f32fadca7b3ee944c814ef61796083b88994948967f5422c51df776d0957011d2ed0569d8e7b28ebe02b4e38f52d00330b79850d6fcba7c598e40ab93e12ab3b7c2f46f88b56b5d83f828871d94ff0e2d60b549c7e7b2cfc5f1a960fd7afcc46ce5f058f1e05a872c38495cb3490a365135a26515cf2cc453f9e71a0c3d233fc6e6d0dbe152f7f34add23fa5b101e02fd83c5fdfe1a66754cc7a4748abbfbb96c7762153c33bad113e3720861fe1accea673c334c915036794a8341d47bae11fc9a2a9effdb54c904b9e9fc9a1cef369ad4d04c51b97ef8820c8bc3343c33ab85c6f040a46210b7a72c76b639702620731fa002460fb781b5a663ec200ab82626d4b085e3348ba5d42f83f743fbaf59f009b960d40c3978bedc8b2f6701619a6f79a82b4c27604d28e6b1413742aa35e981e9b6eb3ecac3c013506209bda49a7d5f4667e45d57b311f476617706b415baf0964fe531fd38cd200450007f3aad73141732d6c0ffde482e36cbc47aebec1ec036069020df695fa9a43ad5711ecb9b54b358991640a8090093ecd7f9448ec08c8250d27a45595d2e7a1c012e07c632083af08995fc211eb55d04f9bc787d4d604de5b797b64a4918e9d93f3cd84690f99b93194da46bad979e5cbf5146cedcbb43e931da298b708fde037a4057a7178d66bfa3ad2fedd06c646cfc128496e8d9f3d439421cf0a6199b5d6614a7a06a1369384cccae710f3dcdf8f1d52cf7bd5b7fed962c1646e372dd2b00ee98d286c61f10ffe4d7ec8300202ceae605c64ff085a9adc1031798c5ecd9a747dee38fc64f43883db58572d57fd56c94b27d1a97b15f93daa73a5931a72dcf59d6ba2a5bfceeb8814963c0e953491be65175c7248dd7a3c1486d9713b636cdde8b36cab2dc6773a671d637a739feaed54d8c43742cab579896914770d5f14141eca519adc3556dfc08ca9720045cc0679999e864b19d9cca01ca6fc1f0536ccd7ed3d4a7e2d911346d66d648ea0d2a8d9da8097fa0ac9f239d5a566dd88164ae8c2a18612c47f72dfa73f8166550e516a7656329fcddc63b258de992e4bc918401e91257e6852e9f1c64eddc0ba3e724f4a6c7e0ef80a26eb38501908191a292a314344626f718ca1b4c9dce9f828687197a5b0bdf9112f345f70798dc5e4121d283b6f728fa3adb0c4f9000000000000000000000000000000000000000000000000000000000000000000001119222e").unwrap();

        let msg = b"The quick brown fox jumped over the lazy dog";

        let seed = KeyMaterial256::from_bytes_as_type(
            &hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap(),
            KeyType::Seed,
        ).unwrap();

        let (pk, _sk) = MLDSA44::keygen_from_seed(&seed).unwrap();

        // BEGIN GENERATE BUSTED SIG
        // let (_pk, sk) = MLDSA44::keygen_from_seed(&seed).unwrap();
        // let busted_sig = MLDSA44::sign(&sk, msg, None).unwrap();
        // // ^^ debug this with a breakpoint in aux_functions::sig_encode
        // // ^^ and go muck with the z coeffs
        // println!("{:?}", hex::encode(busted_sig.as_slice()));
        // END GENERATE BUSTED SIG

        match MLDSA44::verify(&pk, msg, None, busted_sig.as_slice().try_into().unwrap()) {
            Err(SignatureError::SignatureVerificationFailed) => (),
            _ => panic!("Expected verification to fail due to busted signature"),
        }
    }

    /// Tests that no private data is displayed
    #[test]
    fn test_display() {
        // Objects within the ML-DSA implementation that (could) contain private data,
        // and therefore should be protected against accidental crash dumps:
        //  * Polynomial -- this is pub(crate) so can't test it from here, see polynomial.rs::test_display()
        //  * MLDSAPrivateKey -- see ml_dsa_key_tests.rs::test_display()
        
        // In addition, [u8] intermediate values within ml_dsa.rs::keygen_internal() 
        // and ml_dsa.rs::sign_mu_deterministic_out() are zeroized after their last use.
        
        // So in fact, nothing to test here
    }

    #[test]
    fn keypair_consistency_check() {
        // this is common to all parameter sets, so I'll just test MLDSA44
        let (pk, sk) = MLDSA44::keygen().unwrap();

        // success case
        MLDSA44::keypair_consistency_check(&pk, &sk).unwrap();

        // failure case: different but valid key
        let (pk2, sk2) = MLDSA44::keygen().unwrap();
        match MLDSA44::keypair_consistency_check(&pk, &sk2) {
            Err(SignatureError::ConsistencyCheckFailed()) => { /* good */ },
            _ => panic!("Expected error for different key"),
        };
        match MLDSA44::keypair_consistency_check(&pk2, &sk) {
            Err(SignatureError::ConsistencyCheckFailed()) => { /* good */ },
            _ => panic!("Expected error for different key"),
        };

        // failure case: flip some bits
        let mut pk_bytes = pk.encode();
        pk_bytes[17] ^= 0x01;
        let pk2 = MLDSA44PublicKey::from_bytes(&pk_bytes).unwrap();
        match MLDSA44::keypair_consistency_check(&pk2, &sk) {
            Err(SignatureError::ConsistencyCheckFailed()) => { /* good */ },
            _ => panic!("Expected error for different key"),
        };

        let mut sk_bytes = sk.encode();
        sk_bytes[17] ^= 0x01;
        let sk2 = MLDSA44PrivateKey::from_bytes(&sk_bytes).unwrap();
        match MLDSA44::keypair_consistency_check(&pk, &sk2) {
            Err(SignatureError::ConsistencyCheckFailed()) => { /* good */ },
            _ => panic!("Expected error for different key"),
        };
    }

    #[test]
    fn compute_mu() {
        let msg = b"The quick brown fox jumped over the lazy dog";

        let (pk, sk) = MLDSA44::keygen().unwrap();

        let mu1 = MLDSA44::compute_mu_from_sk(&sk, msg, None).unwrap();
        let mu2 = MLDSA44::compute_mu_from_pk(&pk, msg, None).unwrap();
        let mu3 = MLDSA44::compute_mu_from_tr(&pk.compute_tr(), msg, None).unwrap();
        assert_eq!(mu1, mu2);
        assert_eq!(mu2, mu3);

        let mu4 = MuBuilder::compute_mu(&pk.compute_tr(), msg, None).unwrap();
        assert_eq!(mu1, mu4);

        let mut mb = MuBuilder::do_init(&pk.compute_tr(), None).unwrap();
        mb.do_update(msg);
        let mu5 = mb.do_final();
        assert_eq!(mu1, mu5);

        let mut mb = MuBuilder::do_init(&pk.compute_tr(), None).unwrap();
        mb.do_update(b"The quick brown fox ");
        mb.do_update(b"jumped over the lazy dog");
        let mu6 = mb.do_final();
        assert_eq!(mu1, mu6);
    }

    #[test]
    fn external_mu() {
        let msg = b"The quick brown fox jumped over the lazy dog";

        let (pk, sk) = MLDSA44::keygen().unwrap();

        let mu = MuBuilder::compute_mu(&pk.compute_tr(), msg, None).unwrap();


        let sig = MLDSA44::sign_mu(&sk, &mu).unwrap();
        MLDSA44::verify(&pk, msg, None, &sig).unwrap();

        let mut sig_buf = [1u8; MLDSA44_SIG_LEN];
        MLDSA44::sign_mu_out(&sk, &mu, &mut sig_buf).unwrap();
        MLDSA44::verify(&pk, msg, None, &sig_buf).unwrap();

        let sig = MLDSA44::sign_mu_deterministic(&sk, &mu, [0u8; 32]).unwrap();
        MLDSA44::verify(&pk, msg, None, &sig).unwrap();

        MLDSA44::sign_mu_deterministic_out(&sk, &mu, [1u8; 32], &mut sig_buf).unwrap();
        MLDSA44::verify(&pk, msg, None, &sig_buf).unwrap();
    }
}

struct Kat {
    _parameter_set: &'static str,
    deterministic: bool,
    sk: &'static str,
    message: &'static str,
    ctx: &'static str,
    signature: &'static str,
}

// generated by hand against bc-java
// This is almost tgId=1, tcId=1 from https://raw.githubusercontent.com/bcgit/bc-test-data/refs/heads/main/pqc/crypto/mldsa/ML-DSA-sigGen.txt
// except I added an empty ctx instead of testing sign_internal directly and re-ran the signature value against bc-java
const MLDSA44_KAT1: Kat = Kat {
    _parameter_set: "ML-DSA-44",
    deterministic: true,
    sk: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    message: "BE2E693BBF71C271A5AB6B2AC0CD1EE8BAA143B4D65E131C",
    ctx: "",
    signature: "b81e096e85567fd09d555774afc606ae1951429ea1b43bc45c98df6310f24cb81af58143a0c32294b0c2e09fdba17e72f845491e47c08c47d10550fe441f66bf48d18fbb5ea30bb7f3a8972f930dcb4442cd8394711e415ba65b1b5efd5c0c040dd17ab79584b8d130eb46d6766f918b05c6e09157c72d2b9554ecb5eb5b9cb0848fc2c16629558ae4fb71ee88c0a45b134b66a676e99c70375f770f8ee37dd9bf6082d75d2ffc0e94a6915649cdf0f76638000783b263ad71f71d5a38a589efde0e9919ab76fd950b678236b9d50651db8711c26bbcf1b99fe5a2e4f48c0f41f7bd8b654edc3e9da18b867f03104a13cd8d137e3471c9dd7cf2ab0a5b9154e0f933627cb153a37b430ed7748d924a14e50a609ce48fe1c360017fb72c820482b816d3a1cc06905003418e234e36a592bb02bcd2549311cd2658ebd31290eff7af81df4a6d31ee1423712acdd006e35d6801f90a07f109cf83d5318aa2e7e4e7d5c7d3b537293cb334054bf8ae4a2cc579b9898bf15b03884339dee7f2d9512531b610b3195b76d7b9b3256e88b36a67c316c236860bf2e044ba7a5063172cd282feceff292d7bc967f93499f71d6ba05c3dd6b11bcf30f0e93145065da0691edace80c6e98eb58a8ef71e2efe3b5d419d3cca385c4aaf8f35c3a4b0f374d962bff9850a8454137eaf93524f3de66aa0cd9dd2013f9a071ec668e0d77efb185d57faac28ce7ea0f50624d75200e28c8de77854b8f10197a6f0cc0ad6d07607d7fa7794a445443a46f7c647f9556e68ec66100d7ed885bd139b39f5b504fd6ecd29c544d962b94b21bf81dae5dbee60718c7b01318ba0d82af0f36188a556ea3140407b5e8c2dcf8cfff7572566150a15bde39e546f34d0721373c5b745c298cc0381101bdb0a652ac27bea90faa9cfd38c44539d58cb5ed863cb097f5508f51a020db28e99306d3e92333baf24d06e08b56fc8d007ce56236659ded6a0e43ff5f3e631427338d2da2e6e540292de3c30940999363340c1e6fddc907a8a0a2123777b532d8ac955d08588da2453908508d55404e73ce6d8dcdc17f94c691d1588f006a2045610ea57ab2cbb519fcf38da7a5a9f7459c4ca0d41683622a5c8b122309880ea4eba537c47a6b4788dd046bdf92b43e25d287320f739fb0dd8f7d97feca2d121529e93b82f336aef09b8fbf89445597c2823a531b6ab91bb1eed579ba94a1bf9d4bfc65836379983b8c5e298fd7f7d7fb827b802e5b3b0e3ccd8c51ae6b0fbf6ceb6f97abd76607f6911163225f156248d392af26af46d261db85f7996414f6c291cf15c59e45661ddaaa24f92cb48a0b2da5d862b266d6d0ec390b445da9e16bd5330ab48e2b4289ecc93d984ff426eb17d34162c314a99499863c8e78dbb802b0c5fa06a27e12d9741432d91bbb6fa9339dae46189d165e6dff8aa6382d0b66195333aa3b945e7b2b26be2fa899949429663b77d8897e685794683cbbf2a7d113bf5950675439e335f0a8df0e02b4730c0d3632aea985649712a27b7d492b21628fc3c3111ee3497aefd8f17aca5854a612f2e2b3ff30ffe708f616fb65ce49c85bac292874972ff2997e633a8bc39b1ef487ff6331d306aece4542df2b6d918513d611a50d6cb4a8086a009e909aa444f1d37fcd03526d6ba42ead0a2d4cb83197683b45a5626ba9fa2ec1fc24bbb4e4ab21a33355eef8c54ba5d82b72e5602bc72b020d0c8feb4d0b1518842fadffaa2e7fde8300e198cf7afeff1901a91f2b9d78671374eace911d333a91ad2ed5f6a932d5859e2acb1a09eeeab17af3d868a7d246f9cd73466a49ac5751af61fc4140b8ab1ffb60c794c10c8b07c2dae98425e04465a927fe4e88cadc0929e2a768174be133214b4b46141e1e3d8e9ed48f631e24e3efc276c35d35d20fe144e7124c7ac1772aa1a967b0af5526291d56c0dd404ad92265ab281483d6c39123f104c910b2217af79b9e9bdbf9b2561f304f51b6f406d482c069dda85a15b86d927c7c9a1de1a1036730315fc662ddd8754abd437192d240602fcfa366bd4c80acb931ae8b4775c2a2c3158471b773f5f36dd588937ba08f30b3e232a909e0d309c31510898229d5f533c72d57ded1e61c3c2815d373e2cc9dc41ab937056bce8f61373b502e480b7975b02a203b34fc57923075b1ac3df70a036ea30bd6db11ab0e58d447bb21f21cf88195427fca127ae10290b85cdab50038389786c20ea6b3a6c12920fd546de742f68ecf2965c1f7b01ca361da14a6799c7de0410a250bb62ddf26b0514405f6ef7721b29fc8b1f751453c7629ccdbc40c71a22e5e3948dfd09071711043dc9e483a34c31dbedc55be19ffce85a5055062bbbfe9608b93faabe8fee086832de8ca6b9f4aad3df54a8914b2bc37229ff49e3bf014d758d6cfd5e6665286e0e120ef9322dcbbb40fe2831b73cf59612b13fa62e62ed8419a4323c9ca406eb1d7110726d3e4e3825b3b5e50f72c7fbe92d154184e5403895ee9c23173a98816c13a4726859898485a1b8f36c29b2e5951499d722575dbf80775cfeab321f6967569022452394abd2c6e9f8ee2fd70a8b9fab3bf281abe6717c2fed16472167766af0ebc92b99ebb89649aa35e744bb9249a44b2c12cd50fe3e6e4274c7047967ba777e7e0aa7c600d2131cd5d536cf8e7834d0d93d8ae028b19d015a1bc5ba5dbb1031e1e2f25ad29fbdc42569ed4554aae8efde1543de9eff9cd04146f0e315869722dac4ad06663c154890f8dddb4075bf7268626a86dfd42cf43d9681cf399fd2cda03e2696ddbb713bd27b1c16193908898a04db43e960536755c0d9ccbaec637c0d8d6462474a11267291d863cf29fc09dd549307305e20e7acb1c63de3378aa74cf08807472f45f20013c0275d0003bcda5cce48d8f52304970f34498b567da4409b71725772bdead54f9a9e907c9b0d989599f6d0ceccea03559f56aa18a5084ada636989e80763b986a3837d360b75b644e9a80174aee3abbaf2483b3e1945f02e1f3567ed1f60f2b2a3b62ae0d6997ef62024b63639f1b63a84560ded1cb35e449f87229f535534c6a403bcee4aa402b98f3cc15dd3c833d9a05c108febceb0de6280af073ca03bfc6f7b99896bad33a580c8c74cac28fc50e4da4e0f3ba173e122c66f95827b1e343488f5387ac4615a196bcbfbbcda0f78aeff9dbcd6d6217ebedf12f75d6c22ec2d846322fc50e9d6a061b46e1be96b45e806f646399c6973a94241f7aff272c8c08c38002071e58ff05e2368a52c71e3013d06efecb566474657616465787e879fbac0cdd7e90f101c474a89939b9dabacb6c6d1132048536086878898b2b5b6cff80f383a4248658c8d98a9cdddee000000000000000000000000000000000000000000000000000e1c2a37",
};

// This is almost tgId=1, tcId=1 from https://raw.githubusercontent.com/bcgit/bc-test-data/refs/heads/main/pqc/crypto/mldsa/ML-DSA-sigGen.txt
// except I added an empty ctx instead of testing sign_internal directly
// except I added an empty ctx instead of testing sign_internal directly and re-ran the signature value against bc-java
const MLDSA65_KAT1: Kat = Kat {
    _parameter_set: "ML-DSA-65",
    deterministic: true,
    sk: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00",
    message: "F7DB318231EFC5250F7AB18DEBC0340C53",
    ctx: "",
    signature: "7c8bf133e9d1373235f1fa3602be8d20505104c417105f612e6ac620f87e2343c45994fe4cd8f8f1354e6009e1e329dd972c1164520d4f21a7547a9696ca3d1eae8c1ddfc2ee756bff0dc31d95a9d39d90bc785769dd314ec227b55769c4796ddd00083d98dd9d7cad97083edc991dec8ae191d899a16c67ca65ef694921b924721ac1a763ab7fb607d1e434f41e3fd2b4cd8e39082a722acfca32f753fd576546fb3323cc18a6b8a441a8ad1f10f234a766ceaa3246d4e422915ccbefd6fca64b60d503d713480d0dece9ad7d93c56e2713620787813d7d14fc06a9a24a3ef4106e3075ab8f3acb30da128776cc9d98368bad562aecee44b7202daa11dd2a839386a15744cb8ff8bd5d9a71d862a729a86d1a3863a4d05bfd050cebb152728ad303e476fcd5b1e1603ec4f501635b750c92d9095ff0f0872c0c4ff8a5c476dc0d1252af6ead3fada16de77b887ab2cfb42885ef0af0d66e4e32fb255b34bcda02265c3d630c1baae069c0d61641abfb59fe50a146ddc082ceb2383368edb90708e74e4989f715dbb667efd4326e18efa563eafdb9b07f19ee13b242027473032da29b964496b2643adf94c9901cc846bd9a22d670523dd80ed1f9eea1fb6fc516b45ac937ade32ee739836c4a1520394cf012d1f38c4770c992675a367efa89c8d6cd66f6715412cb0e2e73bf00db2330a76d4e2468f5b18e73c416b12f986e2d2b76a088a42d9f5d1f1a1cdccbc593c203e62aa11febe7815d50e42f7d211c1f4a192ac27ca23f7b0b2cacd315380b190d36a52833b250856f40bdd5bf5265dbbf43488576131e2707272f32d7b7b11c91e6dfff4b28a8ccea14e6794a144d62a7562f563332691eee2123ac736798105a4066e7cfc6fdfe411b35b9a42d507b3d628c53d6d8ceca360c4c97d4a69b4537ec0e1335f7b03761c412da57f28421fa8eac4d43b4258270399554c0a3b94521c9d43ecb15f75acbc26620f57204108604d9eef0f833d329b911a87a3ff64083845810404c5f6559503f8336ffed042f9fcb50f9379a1c736ead4cad92b13eed19aeecda1b3da2ffe879f580a0e1db9e6fb3dfae6eacfff7a200d70295c781e237d2eabbb5caa02a742daa8429afe451b3447163822928c0445a35b714a19057aa5f2c19015bcfea3a829e890c49053b50c9a1851ba409b4212cb65130763dc576de1c74929b761e5deb6532a5b2d2ef01f58f7d29943c8fdc1e9003edd75647f0f244f81a69f0331324dc137ec4570e742f3d92a46267e8775c530893253693a324440f882a2d5010992b1ccf5469ca5dbbe59c7d06a5659ce1360e5b25c93142590afaf6e3604b796de9bd2a995e1255cbe4b3fae1547b2d07ed08eefc55656d0cf03e366152b6230b7647c334fe5679f821edbb5499462180585888c0b1ecd8f55bea2a3faf819701725b4ecdc7ad208913b57c2fc93c6303f15c1c997d7f063f71084d1b20d12a2a73ba2acd47ca12bdac2b668bfa4da38adb2148a75a8dd8331642db1648a628c403a519caebfb2dce4345bbfbcdec2a8d2505091f20d5b996a3b49979bbbc72e9b4c260af554dded8eb3cdac15439bc0442120335ebb3059c8e0cd7b4422780e515c706d773126d3c1990194f80a35f4d4f0ea6b728b0fb1779df4aacedab6cf4ce5fa07c30d65d1df611b6c92a093e4e6a7c3e901403b3877dc80e10580849a14508d141705f251c39e01f5a82b488de06a445716d3ef677c44a5771abff063bcd56f08afc5eed37db0a58eefaf4a21913a9cd32635995e3dbeaeb7aad09447ad6935b523e5b52eb8c6df5103958b624282f933ae6cce7173e440a823047d06074367fd2d3dd874e6d2134bef9b397d8a4a7a78f7d65540eb0444e4d7240cbde6147960985a9a89adb4538ce2cfe0d09fb5b87f2776b422b397ec459b86b7714242a94104a7e20d184cb3aee49345435c7de4babbfa8d48a8da2b2b8e262e787655034ff2878e90a85765d6b4f1156a68f26b70497d93938e9cd44b52a22e1b2333bc5a7061a6c6b9112be516e80c5fd8cc75b7c69adcc0a67e917b868b010d71b22d992664f716a64656b94e578866d972cb1ef1aba767eb6e9138ce138b2fb52edcd3cd4b70f18eb9dc3bd1311e149db677d78441cd7de9acce04009d63bd0051baf1ea8bd47e009cba83b6ad08b54467fc675f03fc502df3f3bb558c8bf3e0855a892825ebc3a0eff081b7a800b6f89e5b55446ff9afaa96fe967f59ed1afc560fe8388fb1e73829de5a38a1bad0dab5b844e99e9bd5fb5067050f0ddb57d567e7fca87b59fccaaaa9ad0ad687b083add39f456e77ee00d25ecb67e2336cc915c17bc50fd1435f099633a3771810a0ac0a9f02ed57334ee6f5f8bc99e14282c8104324e0bcc93183803aa30e24410d0475139119ff7453e8dd5db49bb33c1d83d894fe9bc0235223d566d4ca1b232326fb2d2cb994588fdb00b9a15d3692dad7a7191d5e93fd0edf0f73027aae76311b35e5ff487c37b329730bceee0f348982884409ef6c41d85d9b08e73b4056c159ed509f99cdad435b93d079df463cfee11fc25d5709264cd0cb764e020067ebbac3f16c00ac038eba776bc5ede1d96a8e28ae3dc33d8cf7c74c10172bd1ef96f089f11510795c3071b511c9aa7d71401a3f25e6cf0736d701d62a44bae6c84d25dbd487794783cce286960dc58e8b5b386ec11c49a986aebd599882d3956344b0d6bd793464ea2af20d79b66a18c1aacdb03a980b15e2b91c842aac41c3c95a1d5e88f8497c94144cab7473a136ea4b4d6fc5586395c1581e19125001049bd137e16183adf98241bef207097842185204193e1dbca9e8454a6d2d3c7cac267ce9ff2abb0864378296c578f4f49b830b4e48bc5dca8a823fd1592e05295fdde53c30f2dbc878d316e1332e92d82c7dd10a5e4b8154257a216f19869ba66da56966fef97ca49e41d1b346f9653e002a62750b8760a2640d6aff21caf57f8794ef959efceffc4ad4e53e2e09613ef0dcaefe630cd2501de62d65fc3fdb5568b8373e782ef4f876da9fab513d695cf324249fd6d2080200d039c4996fa62c7a3703b2725c0c54447ff8dc47ea875f0270ae8c900bf2ac32b86ca91540aa3b59f2a3c9f780b0f50c440e61b6781f16826767641049ea3f4c70eb3e5ab13936f3a501cb8909e6ffa25a4cbe42fa8c6691333adf46477bba3e0af0dc6d0389883f3e9f764e3418a5fa8ca11da24f640e38bb9b62017732dbdcf4dbf262d9be5dc2eb4e2d2645e4e8f59bca3db108672b9c8f33d47dbff755e2ea6a9f79d96a3228972ca45b7a4cf99fd02bcb4857a529d90b37743a97173c940444a4c74edeab33cf4045ec0c8fd0fdde4861f6706fb58483960fbb75fce1ecff890986a8488ab34f43a528d93b65fd839063ff85961ea21b211eb937e71f3f8d192ae794b15c3391f4751238396982acbc1776b8bce572bfa3b919fbac229c6d395a6d5352e470b5103948d11a167ee921af402f2fc453c25ec232a3157d0bf1b5822ab751c8a4cd60ec4d0f1690b9c8196739537c146e120e822e334903a7509d232fa462cfe9af018b175d484a8404f20a855d52f64e8ba11691c89ab63ee1f409aef036c048d165e8b9083cc42efaeaaaefad79a9b05a007982f664cdfbea191f7cec4d9c4f5f97e9cd809b1ed084d3ccfbf323c4fae45fc19b8472fc186da8ce7f9b4f32151be0dff2f29ee4b9fb8f297cb320cbbe519e2e91f7c3fd920dd427e7b7882b0e0d8176f192b916e0019abc55715d5b77ad9b9b17fa38d9ba78c38e95169bc5fabeee2f1f8ad4f834e0a19159b6f5d538606faae53817a912b12f356cfdf2b91df0817e27f10da74cc4366e100f35e5c1b4384e42dceca600d771fe5accce796fcd3bc950d9741473a8d6ea172debab3a75d95992f22cb540336b01c4a7ad5972debedf8bac9e34379972f2b80af7d870b096ad05cd4a5f006bc5816ece674f75088f8c5df543433724d7f57d868ba820576e9efea7e019728ed54bec5578e6ccad58905b2a0327d071a8065d7539bbd41b0c25445a7b4ff97ab5ac7ae9ef14b417216367bbec33ba76aeed5735b32463d1fa0b4ec1ddf86f3b24ed2ff4e7602967cfcfdd314747ba01bc522f7f0585c67775a513e64cedd145de0093ef9cdd9137ca397cb187fb5dfb26a120f65ad1e1376ce760ddb65d4e54cf5fa301b166d26253cebe08dfa5416c3df31b4e15669da870a5c5091e834757200f74ebdff05693258c98e3248667646f8e8395aa68e667ec31fa40554a34cb64976678e29fe036ff9d6019774700de214709213f9f5ee986054e249a5be3373400d911dc64128c072bad2ed84bcf3ee67fcea0837934171362b69dc697fe21602f5dfd47eb87658bdce859160c120df5fc3cb501d412ec3879612b15108936d2b7f4c5e11ab8a42b4e0e3118bfd9d0c4069fda0eb2a0a8639a0dd8fa7b2d9330e93fe374259e6a59e94bb5c2f439eb6ef9ea05fe15754ea983d769fac709d6a8f18a1ce47d02d6f0bc7afe67c54c4923d24b94686f6c7727a98f5496bc0b78d0d1199af7db4ff80db465de414a9c2ddee313c53727daed1e00143548f9da5b3e40b85d5f2088efbfd537abacee1000000000000000000000000000000000000000000050d15191d22",
};

// generated by hand against bc-java
// This is almost tgId=1, tcId=1 from https://raw.githubusercontent.com/bcgit/bc-test-data/refs/heads/main/pqc/crypto/mldsa/ML-DSA-sigGen.txt
// except I added an empty ctx instead of testing sign_internal directly and re-ran the signature value against bc-java
const MLDSA87_KAT1: Kat = Kat {
    _parameter_set: "ML-DSA-87",
    deterministic: true,
    sk: "02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0001",
    message: "3F8599C466713387354B419392EFED39A9D76C0B5E45E079B3DB",
    ctx: "",
    signature: "541deb5ddb0e92ae138afd5e86f1989633e8f078bcf8218cf2bb75cd248b289d5297b7fec27bb45e59a26e85dda77cf0fbcccf5cf262856203453305327554fcf6dfb293a0c58d4f45a0c79c9fa2c0297744e18a554237dc6ccbabb581470311a3f7cf89ad2ff13dc9c4e88aa31a6571fbaacac7133d89624ff7e5ef43d51cf7bd1b826d82fd6dd66bc9f42d651ea3903e686d30816f808cab060aa452d41b39a4f31b9f0f643942d98390cd445ed85305ed16900cc3baf8a3632878e2343cac3469b8ffc4c94031618f3822eb478aae832c0473860fe3fd55dcdcadb65f9696f820e8cd9f63cb5715cd6b6c52d545beb6843fbc75a8cdce07bdfbfb548d749e76b6e557fbe12c781a19eb75c4568b83318f119cff2461beda087e5f7c1adf09d3b267ef24f07093abc365508c9f3dc5be04c8ece633fbaf57931b10886f1497a29cb8e46fe438cb59413fb374ee1e324cf00d89e4500ac4c0274978e1d757b2ab071c61c739afeabe207da69d041245d286293fe3a3fa41593d4b3f98a30c8660a005c487e9c86faf6a29955f7bac1654b34f8688211ca6060dd4f380d5af3f412ba8d0260c2f772c2d17db2629b0a2adcd4112d403df99391ef15bb99a577d20a69590284cf6e0be1794fc246a29d6c15c21a484aedc6f52987579a14bcfea14a030c2646131527b2aa4e8b17c1b5e91fe8ae4655e6d40d9898ef2b8b17a37cca3a6d73cac55247e2ac09d12644095a2dc89047e5f110aa0eb4b47a9f6bdf017cc671d82d9199f300a6a91aa9396053450e6e07bfc9248f8a7b65f02daddc03c91a68167b622f44dbe744baf9f768255c816862d990fa53237f8d7ec495bc0ba1e72a90b83c565101ea538dfc4804e72bf6f9dc05eb35a7b2f04067d8be00041526f46d8251542e97e9d403816c96e17fc647db3bf1c00880855caaf857d8a9ae76dae309486b4aa96d47fb15ef645fe1ca8a4e52dd567610c2a8aa04ddc948a14628b0a652ae5c0b4621cc59df503fa2cae7a3b5433bb1837767e6809291cc3b8b09c60064ca512fefc3e52b62881c40c6e655a7dcd8528a41f7c42ad6b63b2cf7da1fa274474f01bea6a2d0832c2c74e758f0061f3ec15513fdd559e6b5173662a648bf0ca9054edace5d97c434032729d82ab910382131fe267df78ee02cfef45edf0c9ca1b090e122011f10953021be469d0e62e1629ccbed6706124b6276b2ea77082be43a84f7e73c0e92fae90ced3c057f0acf35bd5e2bbe20f2e6459f00fe80efdb35d41c5644816220bb39309cb7c1923b2f609e245e43ee5291dbf58cd24e443c05576cefa5cc774d93b5a62c3aeb9e2c2452e1a2c0b949fc02a36d62020049d62a03ee5aa8305b7cca9fbd21c94c7fac58602872ba9a26f8ec23a1ec102528fe6c0e82339ce37173fc3ffcaafe537f41ec8eec089e06d9e49c40fd9163589a95ca74d2ccd4650ec971bcd9678ce2f7df94f74c745ec6e4377340079fd670ede55d1d5131bb7b5c4b64903c0e4865e3d43003612b602d5f5947471d009b687d910dcf7f2e807e8acb56af5d6bfcfdf5bfbea1dc4f860a4d4deaecb305e3e32cb66816394a9b9fdb5fde03b926cb50788a704ef8bbc919464b2bfe28b34ebfb7cfb44f9040daba70ee4163b52c4e2144d435d1fc29718aefc27bd82966fc65cc058df4385635df809d91e58e147914bb694426d08f71721a4b65c2cc6180425b224d0924c2c8f6514544ebe11141715ab08ef48e4bebd90d57b158d79359d598b1687df8754a4a821384d425c60767da977afc87b304f6651553a2d0fb01909f7715034924393408bffe8095b8d27eb8cd181adef31e38aaec72168ac1942502b492957191327692dc56d78706802b229d9d9e9ec82816c7047f9458972c1a24b55587d19225cca849295ca8d07d8d5000aa2c5c1bc1e2f39f2d6fdd0ba95d5f6239b36cc86b4cfd62d44bf9d299fc1ec13cd748dca123c94f0be8a6ce2899e8e84d9b5289a2bf0ad1f69645af3385c250029a9d1eaeeee1f22dacde920f8f66237dae504d4c0c42fd92c3eeaf8169e97b238aec66326d71a2374ba42083fd4b09708f0cf493748ef03efb5962685a50693a34be57e3c1d036ba9630a7f564260fd1a6852c2e883a9e0554aee9d23ee4cf2ed53a6998a2e0d731ebb847b1294c1d8067296fd03bdafc4f875cc60581baf81e9f1dfcfc4922acc1673c7896e8fc5f16bff3a6d5a83348fbfff1d90e9d14fae4024a58cf71803da38fffdcb5ed86a8cb91d8480b09f813c651773fc09ec86dd8fbad25ff1a5a7773664c3b8584892f562f77076d46ccd7bba39f4b9e5a00b6af1f10f5b870ff1f2ac686e6cc720e50942d8dd7099742a523dca21208d5d21b8527831c2a3a780ab18168f2e5ef43c7dc514ea719dd70c1bc3c1aba4839bf4ef55af560fea35dc94a4052d7bc8b68da81e3ea636ec210a4c3271d0aacb5913d2fcf87bad72820faf4fbb0d09724247446a97f8386c19a75cd9d29d4b0ab9f03f7c70a3406c2bdbb312666dc91efd420445a469466c2a2024bc1eb51e16b23bd075e8733eec07e64c7264ef497cbad5166eff63e2024b1205da225821482e30631abb401b5f0374c5ed7062be3326be8d77ceb29358b224b1d36d7825ad9d54a28ca66c64ff560af353413956837086dca174da510e5c529f5f0fd525eec5cf7240479850bd5618040f4ae961dc9a0b11b7b0afd530dbdec922a6ef500d83c0d1849055eea0eafe3832e58c7a92cddc495596ba5223820055fa76b690b84733c26f92784921180e64a8139ba12f4621255debfaaced0c1ec350bfd3560f76c4bc9b40ddcfd8b23f98c92b7c7f1ce1a1aed811a05eef9602a8abbd3009340788230fad7ffd56af02b0a4f60eef9afe84825f6c7f9f9fc4c7385e4de6da903c5f5bbc55894d2f2bcc0908c3d42a400dc6e8a5f34c291ec388f705eb31a186d85b3c91baec79eef0edcc4c1cbc97e7fd6307f865c36f9b5cc608ed7c5d022dd7a4e1f61cbf78dd2c129d41f0e9ee867d87bde240c37eba47a579576dd9489ae43ed23461b1e6043e29baaaca561dc80f97b26e4b308a4c8c9f9fb34cc19fd087a4e1ac83d677087a1d9a672eda63a0699ba3635707bdc6238515e82eae01e18c431d5763ce30d9cdb560e0325557908dcbb016461d92f48cc1260562a66ec2ac2033f45b96d859e0b4249fba2f8a4193c85009c9eef7de6064fcdf613361814d0c5b228d6cef300c4a0d85d68e559a6a080697ce216de5e6925a2eb8e5f5879f352618c686ca66d81e867925cf181284053916cc51f94272122d29062d30c0652d16f6d95575d92c95eccbef8f2d8e2b3b38864c3bcbd0de7f68ae991a72120bebf34821bfefa13e3bec1c1d3528dbab24a5ffeaae5c9499596e47e1f8b47f15e4faed41094eea13b3b661fc61e2521fd2970c691c661c471da9aa65cd768acaa14f5ba93dd966541f5d01f8970a39497e2b6c7d3dddb1188c3525a9d711efb622503356ee3f80238f01bfc165cb26bfed9a15c343354adfc2591d2fe8275aebf93f201463a9f7b5543e8430cffd57e84d22baf5c471f0efb76ebee62272cb27da66833a78f00a36c3c4b35d69bbeb9d69cfff27e66fa16b843293ef9009142c3469abba381fe7aac9e75aab955ff912e9a767f46f68f4a26f8c0a8439040187409e75e9e509796a67025053179913c729c7fcc27bf270a4957b0cf979f2be75bd1c11e5a474f2b7f5ba78ccb9898b5b99cc42f73c2179e43188c47a3d5e84aa75783e9db05ffc49ac190ed840217c34173ce90def9c84aa1c055f8617ccb54f2029c0705b8010a943df665f39e0e5430ba1a4b20b0ed4f92913ecf2530387921ee206262a2c49d20e0f027459b54a123bf1d3ab06e9237262566cb9b1f2b6bc85f4e6105d180e4cfa7b6e0c8209590c9ce5dab89867e538a4b8c1060f3364cb6337a6b5d4d75feb88134a1e3a19571e882d549b38ad6d6ba769ad4bedb041e744ff8bf2afafce2d64d73461388998073ced7af23787d99c650fa17683c26c89cb408fca9ec3a67261118297b67116a26af94afc5866ac292cc315f13085e233c1eb6d5522f30d4e1e5d9480bd15c5ec9cc302c7789d57f51874f8dc7a79c007fa2de15d8eacc8696e5d35d4a65d10840e95594dd655a7c51c80942d956dada91d01efe3acd736fa56431958578d0c443e66c7519dfba2e7847338cffa0bc947df28f5b2628116c7d6808217e98d78fc00d43f2b6b0a20c722362b5c02ea840fd19d9ca10f7f6cbf36369e80d16f2dd310e7c5e3d43cd8d9214bae2761a5e77e73f4c626ee807bab14c17e68315241bf6e632b546729d9b7d6d589dbf56306afc2980f0cb932ea0a5abd8a992b43cfabee2cff1d94935b8213d4aeb6c7416e1768d148376996e0dd17284935eab9645fe4ef638e2d041044d5a19fd35ec084a838b54e5fe7c63afb800fc043a666e020dece7fee30f5d1ce51e0a6fba97745d28efedc1a4ca20cdc1c65b21472456522e7069a52579fa71ca3866d24dc5abea774c737e05b3cf00cf6e171f8740da20b4c04d17de786534f78bf22fb66879cbd8b507fa953f74bcca3473e1d837ff4079699ae810b555460a4ff3896c7d5e234417c9f4555325a4f2b968e7e1c5fb425571486d07e80ea23a4858bfdee29ccb301456484f29a3c86946866166357bd9225ddf715a0030ee384c9617935fda2ce99928644dab3dbd5ca48108ce00a3ee8eddcfda8fd93200ee6c7a162ca0f400a40d9b3a82fdd117880b53986ae7e75ecc0a4cdbc867d88d3785c290628509ab671f670c8ff79d748f5e5ecad187b53aaea14c75979a3023013a8678ec4c94a4a8467e8ad8e87087a7f321d1574ccfda16f98434f639d9b2a5f1cd600eb7790343feaf262c7750a7bb5539ceaa82d06ee8617e224a7313b8b343ede0fa660e8b3cb7153ae582df86c13b22fbaa09f01c02061685d729c52a1ce778b7bfe167a80d70ecd91fba455a1766ba7709ef293c3cb51372ba33a624ebf490cf52f46f49e71cfa38602201a9f2671d723ca79f5e267c9ec12f34ce7f382f7726070f02bf330961e587fef4bb3f985df8228ed4ec95a0e9dc45ae394dd4de1f526c28c025d1de1f2e606722298c3103f716cf38343527520bf17e3383d4961179de7b28db5e25f90e83e5cd8a33146480eb9762b58405d326f44de501465aed7ce1f97b2bc8f5c1cb4c206b0f7a2f79f7806b5af2a4de009114541d6404fab70100b75ceb0deaaede4a260582a32a52400436ece37e1c85d4563a192d7d35a9a39fa3a0494805f4020f429f89e90e547a5d62a59ea1220bfbf4189f8a2d6cf00a4daae88708f0352c7627aa2a82f87da376c3435567b8c707c4540ae79d344101b5d38c36a35c34e8766ad30e44e45bbe98bccb7725ce095b10a749964e41e6d21e4de19cef1a0b27bb7b1c528c59170d5ab20ab8b73ab97611543f42806ec13a8b3d0543069bee738dc9ee796eb776ee7bbf2677d44798938f9cfc2fa7322d82f36a1c0cbca0f20641dc86f02d7f6a0fc0cdea441419083f621a253a3b58b50a3ac876b272cea21a7acd7648d356e720e39a0dc3a4a95201033eba587337c961700c1f4cc72d0edd38b5fac1c30c33881030c2d4805d8316d6693a3f61c4401604e0aa83be5d4b0585d9d2cb94dbcf95ae4a6a6262ff968df9a20ca00f0315e7742d6c66ce361f00f1e6e46270c08f499e81edc28d4e555add5f7c1b7c9dc5426e327fa50a272e39a88ce4a64add93c639f37ef9d9f35ff3d2c9b9edf8ab6cc2d1fc20b903dabe4d07641df5acbbc5a702c2a78b74f7b6879e3852cfa7fc801705814418afddef12cb1c18550cda8ed00a878e803478db2576491d0c6be1451433f5c526eba05c67026e6613269e9f879d388a0470ab81ecbf4c5cb7493647d077eff273c15375c32d12301b9fac37e1f5be7adce8107efd9edc9c6c2ff7a53005a0f96d26b9d59fc6d61bcef7ed509bf1f7b1ca297bbba020a67e41a3fb11ff1dbda68028ceed966ebd7d8afff42dc65f80ce63d14cd599f2c71e6ee86053ed6fe10722f727575b692f86ba4bb7f247ce4afc67aafa5a4949fd9c29f0bdacab2ce7c3c74714ff34c5b47b37e991a5f317863b4a4c279f3145eb3488a1daeca03fecc66fbcdf44770851b281fa91358bca53c7cf948b79d456459bc08c43eac0d12d75e0d94a79bfed8605befad8628573d4c647a5cc824bf3901153d34cff9d1d23da7bfaa482f76031a5cff7159bf0a9906d9166a5287e6234040ea27279a24238af98d0f90b869151a1eadd9016204fb18cf03b08aab2e9a680988e39e4240d4f7c86a24c08d2bfc75287ea9b20906f0a4e7577da2c78f73402a7c20bbf48c7d85291548a7b212b5dfc09381b75b607a9b9da0b3bcc2070d2d98f21d4a7881060e20466d902f444f707f8799afb3c6f631747abdc4e2f01584a5a7d8dd343b3cabbabbe3eb0000000000000000000000000000000000000000080d111722292f37",
};

// struct NistRng {
//     _seed: String,
// }
//
// impl NistRng {
//     pub(crate) fn new(seed: &str) -> Self {
//         Self { _seed: seed.to_string() }
//     }
// }
//
//
// #[test]
// fn generate_key_pair() {
//     let random = TestRng::new();
//     let kpg = MlDsaKeyPairGenerator::init(Box::new(random), new_ml_dsa_44());
//     assert!(kpg.generate_key_pair().is_ok());
// }
//
// #[test]
// fn test_key_encoding() {
//     let random = NistRng::new(
//         "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1",
//     );
//     let kpg = MlDsaKeyPairGenerator::init(Box::new(random), new_ml_dsa_44());
//     let result = kpg.generate_key_pair();
//     assert!(result.is_ok(), "ML-DSA-44 key generation failed");
//     let kp = result.unwrap();
//
//     let expected_pub_key = hex::decode("1C0EE1111B08003F28E65E8B3BDEB037CF8F221DFCDAF5950EDB38D506D85BEF6177E3DE0D4F1EF5847735947B56D08E841DB2444FA2B729ADEB1417CA7ADF42A1490C5A097F002760C1FC419BE8325AAD0197C52CED80D3DF18E7774265B289912CECA1BE3A90D8A4FDE65C84C610864E47DEECAE3EEA4430B9909559408D11A6ABDB7DB9336DF7F96EAB4864A6579791265FA56C348CB7D2DDC90E133A95C3F6B13601429F5408BD999AA479C1018159550EC55A113C493BE648F4E036DD4F8C809E036B4FBB918C2C484AD8E1747AE05585AB433FDF461AF03C25A773700721AA05F7379FE7F5ED96175D4021076E7F52B60308EFF5D42BA6E093B3D0815EB3496646E49230A9B35C8D41900C2BB8D3B446A23127F7E096D85A1C794AD4C89277904FC6BFEC57B1CDD80DF9955030FDCA741AFBDAC827B13CCD5403588AF4644003C2265DFA4D419DBCCD2064892386518BE9D51C16498275EBECF5CDC7A820F2C29314AC4A6F08B2252AD3CFB199AA42FE0B4FB571975C1020D949E194EE1EAD937BFB550BB3BA8E357A029C29F077554602E1CA2F2289CB9169941C3AAFDB8E58C7F2AC77291FB4147C65F6B031D3EBA42F2ACFD9448A5BC22B476E07CCCEDA2306C554EC9B7AB655F1D7318C2B7E67D5F69BEDF56000FDA98986B5AB1B3A22D8DFD6681697B23A55C96E8710F3F98C044FB15F606313EE56C0F1F5CA0F512E08484FCB358E6E528FFA89F8A866CCFF3C0C5813147EC59AF0470C4AAD0141D34F101DA2E5E1BD52D0D4C9B13B3E3D87D1586105796754E7978CA1C68A7D85DF112B7AB921B359A9F03CBD27A7EAC87A9A80B0B26B4C9657ED85AD7FA2616AB345EB8226F69FC0F48183FF574BCD767B5676413ADB12EA2150A0E97683EE54243C25B7EA8A718606F86993D8D0DACE834ED341EEB724FE3D5FF0BC8B8A7B8104BA269D34133A4CF8300A2D688496B59B6FCBC61AE96062EA1D8E5B410C5671F424417ED693329CD983001FFCD10023D598859FB7AD5FD263547117100690C6CE7438956E6CC57F1B5DE53BB0DC72CE9B6DEAA85789599A70F0051F1A0E25E86D888B00DF36BDBC93EF7217C45ACE11C0790D70E9953E5B417BA2FD9A4CAF82F1FCE6F45F53E215B8355EF61D891DF1C794231C162DD24164B534A9D48467CDC323624C2F95D4402FF9D66AB1191A8124144AFA35D4E31DC86CAA797C31F68B85854CD959C4FAC5EC53B3B56D374B888A9E979A6576B6345EC8522C9606990281BF3EF7C5945D10FD21A2A1D2E5404C5CF21220641391B98BCF825398305B56E58B611FE5253203E3DF0D22466A73B3F0FBE43B9A62928091898B8A0E5B269DB586B0E4DDEF50D682A12D2C1BE824149AA254C6381BB412D77C3F9AA902B688C81715A59C839558556D35ED4FC83B4AB18181F40F73DCD76860D8D8BF94520237C2AC0E463BA09E3C9782380DC07FE4FCBA340CC2003439FD2314610638070D6C9EEA0A70BAE83B5D5D3C5D3FDE26DD01606C8C520158E7E5104020F248CEAA666457C10AEBF068F8A3BD5CE7B52C6AF0ABD5944AF1AD4752C9113976083C03B6C34E1D47ED69644CAD782C2F7D05F8A148961D965FA2E1723A8DDEBC22A90CD783DD1F4DB38FB9AE5A6714B3D946781643D317B7DD79381CF789A9588BB3E193B92A0B60D6B07D047F6984B0609EC57543C394CA8D5E5BCC2A731A79618BD1E2E0DA8704AF98F20F5F8F5452DDF646B95B341DD7F0D2CC1FA15BD9895CD5B65AA1CB94B5E2E788FDA9825B656639193D98328154A4F2C35495A38B6EA0D2FFAAA35DF92C203C7F31CBBCA7BD03C3C2302190CECD161FD49237E4F839E3F3").expect("pk couldn't be read");
//     let expected_priv_key = hex::decode("1C0EE1111B08003F28E65E8B3BDEB037CF8F221DFCDAF5950EDB38D506D85BEF394D1695059DFF40AE256C5D5EDABFB69F5F40F37A588F50532CA408A8168AB187D0AD11522110931494BF2CAEAE36979711BC585B32F08C78496F379D604D5321C8C62B59EDC23AE1FC7742135918E01B02E411630E26E675400D5AD2C776FCC0A6711A966C11312AD9A821D8086542A600A4B42C1940720242628106210A43852331709308108B188C022492C1B28412C4218B042181C8610248059C9201C0348819326C582046891868A2C28D82346A1C094200A28CE3A6491C112CC24812E0902191985062C084622451CA062C64240E1BB3312496854B4606DB2668C38268441046C9B6211404811445502442084422710B92459AA0811A91709C241003957004C504C82692D29200C0B260C0A26809190AA2300E188969E0008DD84862DA14712018051907440412409B1240118010D142819928508B1091022464A0206D1246211C838C1B4769010690CC062481846920982C24120521B15041360298446ED1A63111056AD3A840CAA84C62B00003134A53344614194004C54CE306695AB08961168ECB10808B168ED990640B94602483851AB30454262251B8251C424A0B814842C4445A102023808409B7254CC64814854D19380E601651D8326A0A918908C170E0964D18468C01328D91C4054A0061230868A2104210A8611306218A248E620689C9B24508278451200D980466DC42054424852426282221612016090BA62C0A1144E0928158480D422210A006098B246E81288CC0248090308D8436404CA68450042494B68DA2926D18B344A00085E3B805140504A4C290842281C3262D0B2066CC903198382810166CC13445C0102224C688034632D840901C20680415289A188144988D9C206E9C302CC1B820614221080310A0C28C58128553204C0330814CA48D44C08D51404C1CA72C440865A03840DA20808106858C260DE2A88C9C4411594228C42604441426A1426408C0851101869B483199B20C80464459A88C0042089882900AB54562244812960544124600C88813A061E1284D0AB9914B962099B84400314E98128500B60183A00D14150E1881101901224A06681A498DE1A28411C63121262591A06D030524A1B6089444724334125BB42041B650D0888D0B074D1C94644C208E8B8808E0300944200549864D03134E19C9840937611A43684A80900204311C1742184080C8308EE1A241C33404A3282251247188D6FEF46712CA182872AB2919678AFF9D94E743E063A39E0C35CAF72A7F2EDA28E65858520D5D8467DE747CF340653B52C268F55413F5ADDC7D49011EC33EDD537423A84288869337AEA0781A124269071451722DB3BB8F2CE5B1552F83D2AF07F25613918A9F4E6F1257603888E589308CA5F95F07143D23BAAE17520B36B6E0E94FAF6845EB2131AEC383E63BC8644EE5F1ACCBA82F9211E57AFCBF509C1131A37466BC91B357DCBBBC14CCC319C4CC6AC75FCDC82C6596D07770C8277AD370B192A0B4E05F812E0E265D2912AA29F03FC9F72DFA69C9B1291A3FC583642B235F6991A954788347F60A0328C48ECEE51BA02DFF323ABD911667CB14549B618F1C5D250CAC9E35E071601992FBEC0BAE6F74213081404744D12F2A0E04BDB265E0924CADA40D1FA1F38ACA4606BFD4575712B8260A456FDDEEEFE7CA259BCDA97B9B939A5FD2889C9B49FB7D4E3553DEA61B3339BD0E6B16BF3BB227103BF9202E72DC502E28F7CE1559A4631F372520324E4EBA07545F78BF4D94B0E5B8BF51B8F176533D5CFEA5232F283A47605FA65DDB17C891C251011C4E98EEB6EB00CB65BA31C8F025C87A9FE02DBC10C5D83A065EBA5D7B2A19D5A1CB2C160AE166E867F2AF8C7D49D63FB83A614957FC0A3B5A5C74990E9A2B02120C7E6DE37E155FB472F50F0A45E47CF5F9D7A4C82982C9DC86AE877C3FD1885943E439FB003C7A9A42F71B4FF6F0A28B140CBDBA6E71B13AC31B23DE9EAB7837E15A69F833EB7B56A71D8BC2CAF1F2A31C345BD5F46EE013A7C689372337191DAA800C0AC6C46C9FF688B1A01347F257C474AA3D97C1D63A8C00E0A37B681673F57C1C9C8FCCD46F174C74A29D84CEB71F7E6B2F8CD2B089ED43F7C96DAE81A223418C20B16F1DF3D1A978AE28F6DF35EC559D04D20EC74B224AEA31A289B015B069E9CBBBF7CF6DE94CFB2A96E4AE3462C96003CDDA87DB561AF2CE3C0BA1D90413FDCE3CCF4390C02C1CB9F654F4820EC33015457D4A629FBF39419CAB7642D6885E103FCE0D4206CCE7C12C6FC44FA33AD0864C3371A7CBE820E3B371B656A38F2E7FF18FE4A50C8AB3F85D783FB57835CED8490B84EE0D99AF0D64C483CEB6366FF54F8AC8A40DB1AFA573A4FB326C74F0236ECEF3DA7120665CCE05DD654B5071723A8348E7CD7793513819B61CB64E1328E8B22E7664BD6B41B5710D19EA8809D4450850E907DFC4D0B75F588CECE962E9E0937CE1402446A4D2891A46E6617FB29D4FCD712606F7819ECA60F7E0D5B19E7FFB57C73C16FFEEB90038410CB9FCBB5E9D51EB3EB6297E9FF6AB7088FE2D9B237BC24CF7F8290118A5E0E00A0B903FB6375C848176CD0A8C8875CC59199CDA11A87A78F65CC404330B087571FD0633E27129FDAB5A8A1F793E52412B0083FD5C74DB3CF60C2543CE7C91B2800E40203F8D99FE5FDE5B108E7EDC80EBB9BB34986EC5C5A8F580E75752907FF0F294C866C2CF1F362E840B6881BD43219201781C63B0039A95BCFB4A0FECE569DF00523CE9C084B022B3B022242E28419796ACF0A0C995F948DBFFFD30D77ED105A3C9943C406B305BC81A6A248A291548F2A67F438D966A57D53F4B7BE15354E581BE16F7AD64D164E85787DF5849C810AFC28D06482F441B5FDE3DB2ED36DD25AA6664D4D43FFA32EDA25689C9F4A5D514FC66231C5401520922524438EF1DC78D693C9718DEBBD243312674C899F18910E389C8EBE505824BCC42CD4A9ACE193768220219011F3B1F335427BFF9E8BDED5C08711A09C2B71CB964C56A8393BFD2B56E9B6B2F513E682587DC1B8ED196066326871025628036700063176D345DE384E182D6C417A32AB11095EF59BB4D171B9CF81D17AC42664DED933CCB722C69857FFC53C8E7F2474B0CB2DFF2DDC8A5C601C84A701981199BCCF74112A6EC062C4FEB601A028AF01032ADB6BD15D4C2B9550AA850AD62CCC3A3665D5212B12E0FD5C5326A1E5EB1F10D557D94605E8E3F356E08FF7FD884ED3C4205463594C9AF2F39E4B1274695234B54EECED93F460EDF1A13C2CB4B17D322F6F79FE16F0357C1C4739863E796791F8647FABF730AB00E0DA509706D94571740F61F7BAF366D2774C9B5B8C61DD6BE9819A6028B264BB2E4AEA54B56D4ECAB5B528CE0C0C0CCDB73023352CB00445BAB6F7467B4644D4361C464FAC6B5B137D32391021B475FCB5F31774FD8ECABDF65475F25574C65559CB331F41C0F498B74DD941C344C50D8E64F9578714A32561FAACEAF78148E6DA4B566826925714B17108AFDD546385A3CD454D5CAA16960916282A47C4315CE236BD9E3255C604EBDC39772DB5CE0B236").expect("sk couldn't be read");
//     assert_eq!(expected_pub_key, kp.public.get_encoded(), "Public key does not match");
//     assert_eq!(expected_priv_key, kp.private.get_encoded(), "Private key does not match");
//
//     let pub_key =
//         MlDsaPublicKeyParameters::init_from_encoding(new_ml_dsa_44(), expected_pub_key.as_slice());
//     assert_eq!(pub_key.t1(), kp.public.t1(), "Public key parameter t1 does not match");
//     assert_eq!(pub_key.rho(), kp.public.rho(), "Public key parameter rho does not match");
//
//     let priv_key_result = MlDsaPrivateKeyParameters::init_from_encoding(
//         new_ml_dsa_44(),
//         expected_priv_key.as_slice(),
//         Some(pub_key),
//     );
//     assert!(priv_key_result.is_ok(), "Private key generation from encoding failed");
//     let priv_key = priv_key_result.unwrap();
//     assert_eq!(priv_key.rho(), kp.private.rho(), "Private key parameter rho does not match");
//     assert_eq!(priv_key.k(), kp.private.k(), "Private key parameter k does not match");
//     assert_eq!(priv_key.tr(), kp.private.tr(), "Private key parameter tr does not match");
//     assert_eq!(priv_key.s1(), kp.private.s1(), "Private key parameter s1 does not match");
//     assert_eq!(priv_key.s2(), kp.private.s2(), "Private key parameter s2 does not match");
//     assert_eq!(priv_key.t0(), kp.private.t0(), "Private key parameter t0 does not match");
//     assert_eq!(priv_key.t1(), kp.private.t1(), "Private key parameter t1 does not match");
// }
//
// #[test]
// fn run_kat() {
//     println!("{}", "ML-DSA-44");
//     run_test_vectors(read_test_vectors("tests/data/PQCsignKAT_ml_dsa_44.rsp"), new_ml_dsa_44());
//     println!("{}", "ML-DSA-65");
//     run_test_vectors(read_test_vectors("tests/data/PQCsignKAT_ml_dsa_65.rsp"), new_ml_dsa_65());
//     println!("{}", "ML-DSA-87");
//     run_test_vectors(read_test_vectors("tests/data/PQCsignKAT_ml_dsa_87.rsp"), new_ml_dsa_87());
// }
//
// fn run_test_vectors(test_vectors: HashMap<String, TestCase>, parameters: MlDsaParameters) {
//     for (count, tc) in test_vectors {
//         //println!("count {}", count); // HashMaps are not ordered in Rust, i.e. test cases are in arbitrary order
//
//         //
//         // Generate keys and test.
//         //
//         let random = NistRng::new(tc.seed.as_str());
//         let kpg = MlDsaKeyPairGenerator::init(Box::new(random), parameters);
//         let kp = match kpg.generate_key_pair() {
//             Ok(kp) => kp,
//             Err(error) => panic!("{}", error.to_string()),
//         };
//
//         assert_eq!(tc.sk, kp.private.get_encoded(), "count {} private key does not match", count);
//         assert_eq!(tc.pk, kp.public.get_encoded(), "count {} public key does not match", count);
//
//         //
//         // Signature test
//         //
//         let signer = match MlDsaSigner::init(true, Box::new(kp.private), None) {
//             Ok(signer) => signer,
//             Err(error) => panic!("count {} {}", count, error.to_string()),
//         };
//         let mut sig_generated = match signer.generate_signature(&tc.msg) {
//             Ok(sig) => sig,
//             Err(error) => panic!("count {} {}", count, error.to_string()),
//         };
//         let mut sig_attached = sig_generated.clone();
//         sig_attached.append(&mut tc.msg.to_vec());
//
//         assert_eq!(sig_attached, tc.sm, "count {} signature does not match", count);
//
//         //
//         // Verify
//         //
//         let verifier = match MlDsaSigner::init(false, Box::new(kp.public), None) {
//             Ok(verifier) => verifier,
//             Err(error) => panic!("count {} {}", count, error.to_string()),
//         };
//         let vrfyrespass = match verifier.verify_signature(&tc.msg, sig_generated.as_slice()) {
//             Ok(ver) => ver,
//             Err(error) => panic!("count {} {}", count, error.to_string()),
//         };
//         sig_generated[3] = sig_generated[3].wrapping_add(1);
//         let vrfyresfail = match verifier.verify_signature(&tc.msg, sig_generated.as_slice()) {
//             Ok(ver) => ver,
//             Err(error) => panic!("count {} {}", count, error.to_string()),
//         };
//
//         assert!(vrfyrespass, "count {} verify failed", count);
//         assert!(!vrfyresfail, "count {} verify for bad signature didn't fail", count);
//     }
// }
//
// fn get_seed_buf() -> HashMap<&'static str, &'static str> {
//     HashMap::from([
//         (
//             "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1",
//             "7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2D",
//         ),
//         (
//             "64335BF29E5DE62842C941766BA129B0643B5E7121CA26CFC190EC7DC3543830557FDD5C03CF123A456D48EFEA43C868",
//             "4B622DE1350119C45A9F2E2EF3DC5DF50A759D138CDFBD64C81CC7CC2F513345",
//         ),
//         (
//             "BFF58FDA9DB4C2D8BD02E4647868D4A2FA12500A65CA4C9F918B505707FA775951018D9149C97D443EA16B07DD68435B",
//             "1D836E889E46259BCD1CCD2B369583C5B47CFBB919EC2B72C280247CB15A5569",
//         ),
//         (
//             "58C094D217BC13EDFDBEA57EDBF3A536F8F69FED1D54648CE3D0CCB4847A5C9917C2E2BC4D5F620E937F0D329FCF8A16",
//             "539577CB7F2088FBEDFF1B53F235D607321857DB32BBA645F8DF3A89DD426552",
//         ),
//         (
//             "F1902A7815F37BC7F5802D8CBCE5B48D82EB85691718062BFB84D8C06AA41D6E9039B0A107245DAFA4EC109A57332914",
//             "2CA59C6CF33C53803749F69EF5ABFA9482FCEE7EFD87FBF17135ECC3FF3FD7F7",
//         ),
//         (
//             "75224ECC026C18159FF92256844D0ADF953F0A4DD8D74D4EBF1DC5EE8F5630B011A447FD4DC34A2404D620CA0E1F273E",
//             "E17E72290E49A44C9C534F211195257CF13B0D45405782CEDA2D7F982A551721",
//         ),
//         (
//             "447F03C8CD27EDAA1FA0436DA492812F57AC946479A9F1F90EC4F5E913A05F8AB0DD7645026A96510F6D40AF05D85B07",
//             "3B7388E675DE5C59A78AF095481C7DD999C6EEA898595B1E7DCDA7EDC3A2C25C",
//         ),
//         (
//             "8C151C556DA912A82DEB32144C8A8C9090CFAF5C12AB822AC3C72618837A41C2453B715EEFF3724CAFE69B1ADCAE9DDA",
//             "DC9F40CABE2E8E4F3D1538FBC1ADA27B61B99081455AB0C4C41B5B3DA8101000",
//         ),
//         (
//             "9B42F41492530EAC81992F17613EFDF155F407D7E67F18AE193EDCE714D65D1031E7AD10839AAB46D0850EAF5997AB4D",
//             "1DADE637AE98C393260F5BBBE288373100DD7AF37EBA913C528D2B7B998767CB",
//         ),
//         (
//             "11134936880F5A11ED3504CF7B273E55A351FCCB10943BBBD186623EE6C7A13A6565C3080D1F536BFDB018F99C4E46CD",
//             "8866693CEE12B909E32A0C64381796633666417E1246B51A2643564B464B4113",
//         ),
//         (
//             "98DDA6B97E89A479D5EE214E660DD6B5D8F6CC638A1CD4F462A0EC545F5B0B0A1A403AADF566F7B1C0C5FFCA29B36FCB",
//             "D6DAD5B2746422F4487B72536D70DF88AF4B2F9040AA45999F8D7784EF696DA0",
//         ),
//         (
//             "D34A0AAD27ECAD31A5E08E9A2D7901A9B85F864D9B1B46F40CDCA0B3615B2CBA04EF82AD7BD8CF627C3E861477030BE2",
//             "68E7818F33B97BA6166768C395BD010CEF7BCE9995891D164303B53C1123A991",
//         ),
//         (
//             "4FDA9FB6929E3F391901D69FA0AA2F25A9657D249A620F1B9E305A5965676BA76794CAD3355EB632579C3958CA7D443D",
//             "35B153A7706109D4A13D7C4B26AA5B56D9E3FAC53B47E91B0C10BD4E0EAAFC19",
//         ),
//         (
//             "B0E6A23FAB10A7A333E3720BE00D31507917F39C5EFE1C98CA18BEB5C3101FB4479B478A1558C4C00398C55C9822FC44",
//             "0E1A1634FB2396E187CD8980EF29663C42DC3EF963CCD491F817A84283A11FA0",
//         ),
//         (
//             "0A98A2BD2B9FF42CFC18D3396BAD052E1D0F3372854DA69A318B142F7A1AAC609C3861263BD8FB0549DA7266784DB8B4",
//             "B0BFA060F1C1A70F1AC55E321E6186A6613605DD732574B5FE6E14F0FF6F7A82",
//         ),
//         (
//             "9887F1FD854241A301EE0120645CD8E119B43F7BEE11F77A835E9ADF518C3A51CB76D86653FBE73AA716264C146797EE",
//             "A33BC0A7A08C13C0D4C1174DDD886AAC4C5666E1F4831F006C9519D36B2CE882",
//         ),
//         (
//             "5B485527C3B9A5E5B7579950049CD357975D4BCFEF83FE33C087ACBFCC10A0BE4225E7F8A5F77203B5FC7C0B5FC0E78B",
//             "C7E33FA5329142B668CCDDE1057EB7A8619397537F2B4C6D6755B3B9FF936441",
//         ),
//         (
//             "327CE565CFF6CD9A25EDD84F482FA0758B78CBC246567DAE98B818314AE28CD438E339043EB3FF16E1C2B4B104A717B8",
//             "7611B5B7D4195D5F8B97244B6811748EFEA929EA272E66435A36D0BD16E3BF21",
//         ),
//         (
//             "790FC03F956D1301A735504075B67A05944A762E0A4BDA77BB8C036C5CF911E2B561EC1CA6AA355D5CEC919AED42A1D2",
//             "5A1E3E05C72CEF1A73EF98840DA035E4FD2552912DB8DAE28A79011DE4BBC1A4",
//         ),
//         (
//             "716354F7DEAE272CD26929C0932CA257AED1DD23D67260726B5213D82E61466FA99BB6A7D81DEE9D0EBE03DEEE4DBFC7",
//             "8F3920A235EEC3659CFCFE62931474204EAE264959702F901D461B66D9BB563D",
//         ),
//         (
//             "A32E6FF879EC8866A5F5E4F6318DA8FE6743812ED2CF5FB94F5C3AA3EDF953CBC32665810B71B2CFEBF343A571CBC570",
//             "0B2B3EB50681403A0B9A99B25041A489C6D45D2A49DE0EC83E1FD10922ABE2D5",
//         ),
//         (
//             "5A64401EF8E63AEE18E8CC0162845DC7AF388230E86728ECB330007F2546F949764273EA05B397FE71F567E1527FA445",
//             "8217D32CD15658D39CDCA92C41B59F5780869A68838A3579DEA48B5E3EA768AA",
//         ),
//         (
//             "3222E4B55D6767E300FDE03DB3D8227E19FB8B08EA9B923FEDE18D699DC3694EFFA7C4DAE2AF57E4A0162B7C564199BD",
//             "CC625322C9D52898E7F60AE47BC2847E20F3722794DE41E30FDB20CA1A093208",
//         ),
//         (
//             "F41B3C6225245C06455272A6A073F363E5F19F09A0B146AFCDFC2B3B0EA64BAA3F90359F32B2D1017608B03064E90AB2",
//             "950226D6AB0B774C5F439AFCFD0113B5DBF5905960C445F5E6E03E5D5C687A9A",
//         ),
//         (
//             "A08AD391E0FC57A83B74CA8CF44DB67F8178262ED9B20AA0163CDD8274AC2BE05F558B112B094244370C1AAAB75077E6",
//             "A6B534767A6D839FD19075AE0BA10147C46862BF7BBCBE83F2B72F72F1368A1F",
//         ),
//         (
//             "6E0A8EF5156D693FD0140BC4A31084E79773A83F42C8D133AC8A9D62DE3CD74511F893DCB26041E6B35E2B175408FCE7",
//             "103164ED522DF0DB131C15E139C0F83D9B1B7A1B6ECF7F89A5248CAD7E68DE8C",
//         ),
//         (
//             "49CC05312D1DBE216FF03B60575017A6A1464C06D2C5A4A6F973AD9F275F7C66163A29A803BE759B117043862D277C27",
//             "BC962D978F38881085C1B813BC90EEE44AD9E7651681C20BA46402F557C454DE",
//         ),
//         (
//             "C33EE43A9CBB4347BFAF71147B7FBDD88D212462CB06FBE695A35402C503CD15732B7D0E8BF829A555B9167BCFA2F2BF",
//             "C3DE54854A4060EA09ED92A363F71C7863EBA64195E9AC79E7AD7EB6A183CFAC",
//         ),
//         (
//             "19CB4BE2332F7FF0C078BC001FAB3C5FD8569A76EBCE373D1ED4FC8EB5D744C6464E2B5EECB9EE836CD5D87BEDA78BA7",
//             "828B9804524BDD17D0EB387368B01B0E95B4960057ED63FC2289D858201E207E",
//         ),
//         (
//             "6BD93FD13C0299B3EC7403638673F3DBC449F3A617B691DDF73C072B62BF028913375D7460BED2CF9FDCA517690CBAC3",
//             "4A84CA5C3954FAAFA11AE87FCBE701EBB5AFBCC5F8ECAE7786D10821E01ADA5A",
//         ),
//         (
//             "1787C82DA9F2E6CA9ACF7D6CCA70116A1724902C81EDC1439F332C74807AF2BCCCCDC7AC1788BA798520B2999F39DC3B",
//             "3E74AE2B1D49EE6F149076F0BAE2D26A5CADFD5DE7BEF66DFCAE6B588A1F4067",
//         ),
//         (
//             "9E6E12F025B2A57B0F5A3A9FA70396FC332E1802608E5CA07CC4FBA922F1FE5DEA6721B96F1BA2BFB97825A19F08FF2F",
//             "39550BD2782D66FA95380F5F101D827377B11410F8BF3BCCFBE0E504FC09AE38",
//         ),
//         (
//             "569B8B9BDB707B19CD6F9BEB29F304D603C1509B9CF25987C280C342E870B1E13EFC7DD7E41DC85BF4F42D0493B84B0F",
//             "B18F0FDF9DC4F514107F88CC43FB29190608EBC5A2CD00B49FE20631761038DF",
//         ),
//         (
//             "F32C3715B0BA8C1D0BD59F0645E9697DFCF9AEAF761A71ECDF9672215B9F138C0502D7214F6B1BB4D6612432F9FBED5E",
//             "D4FA14DA39548392300A41BE413EBD53BD7BCBD045B4D3C8CA44ABC9599E269D",
//         ),
//         (
//             "B0C7530A52AC9F561C2C14548D3A5F5053396B738EA1C7A5190F5AB01C9C38719C4DBE856E42D37A114FA24FD5DF5081",
//             "C796FD12D1FEB1DF46B162C38292684C09059E4463CB95DBDBF498A4DD4F7F00",
//         ),
//         (
//             "B2FD7BFAAFB667C9DABE5915C3BC271EF41F18588666A6F4990C09D098E62DB590110DF6A56F08C5E0DE65B00F91D60F",
//             "A18A366A5ECACAE4732DC9E954333EAD153203013BAC4E3C50BEE15269F983FB",
//         ),
//         (
//             "C08E846A8E039C8655651919A8433D475F494899FB617DC3B4715DEF0C992C195CE38158B7FF40E0684B30FD7E623265",
//             "585E714D565AA66078BC2B12699F1E86C6FF30A1ABC8CBD19563BCDDD2F1F6D2",
//         ),
//         (
//             "1D9C060EA0408A068BD982D9694D39D02BA5A473378F6F9F09349F686566F331E767263FAFF5DC0E823BB6F648843876",
//             "662CF70D3D5E95A9C6A33BD7C6ABF0E8CD23AB2D2D9420878C4835DE14A6C606",
//         ),
//         (
//             "A4563D09AD21D3916BF4636301F2E64183A8F003DA186753D7F2DC3BE0089BA09C62B8A52B72C2C8451213606801FB29",
//             "1924A71628292AA3D2D34EA72E2BFC2520864205F54EC6F19F7714733AA34CC9",
//         ),
//         (
//             "811A8A2ED2917CC616FAF246C5F9BB902E5FBF5430AB078AD6CE871CF8C160512A748216EFAB3A4CE1271AAFEA12C11B",
//             "EF7BA21809AE7E0BC3230B6061C5FEE206D805572CF1345198E1EF22A8FE7322",
//         ),
//         (
//             "41CC9DB2E90239AB5158A2628E7478D0B3512FDF84CD27A4CA5FE3119A455C22045F198C3C5C39F491FB975BD1CFF7F8",
//             "CB0B305FB54E1CB23B63EC1F6F4689137E5048D095FB3EADC854C852CA86BE93",
//         ),
//         (
//             "1C13369824A3FDD41B1065E17297574715D9BD9CE5BB733D36D22C31B62BB1033989A604D78BFB1A0746BD4A2271FC0C",
//             "F92FFA3A36F43F9177763AD320FD651D9357C6D99F09549FE6AF12943B58BE90",
//         ),
//         (
//             "7AD6C7DF00C9E52A75290D28DA946305D83CCF6DE2515C19A8E26850C34C8C2E545E2E32108F13B9C97F87AB68D10131",
//             "5D3CCE926A795ABC5F6632CABFF8BF66275DCC7E4A4AB3B8399D23E62A28BD16",
//         ),
//         (
//             "38FFDE9B60DEDB5BBFAD6C52AA02EF6D49369BF276C99E588D796A4F260E0FF0A65C96C35863BAACFFD9B212EC305E7F",
//             "BA2386BA92AA89049C64ECFE60FDDBE136815D3874527414B63ED32215F2E06F",
//         ),
//         (
//             "ACC98B16DCC9A50EF57F332D66255CA56C2BB679CAE705B4297F1418DA845861448DA6CC5CC458DE6C6E96128EEB2898",
//             "B4E1AF25E8DC6934BA391A89984A358702BDD36838BABEBD982638703F20EEF8",
//         ),
//         (
//             "8BEA4E384E73C7E0B47381B3063334291A0F06D28DB61B5BF65B01D0A747722E0AA62B81AD46C00C8A5C31494E513836",
//             "A62875A3A6D305E120DC7975962552126CD844554857C2943872A4E524A6EEB5",
//         ),
//         (
//             "CFA713E4A63A6FFBA43BFB898956DC400507F68AD164C3D24A67B5F8D7548C9DB44DAA43E5E4A0990325A4233089318A",
//             "76AE71DED1F9E73AF77A2FEAE4EEF80F87414DFB7580FB4AE0325BFF20D74A5D",
//         ),
//         (
//             "1F3193EBC58EF65E9E396D69220ADB8ADC729BB388A72CEC9028A094F1CBDED21CFB0C41356AF31E0CF66A3B0D843666",
//             "A8F65BE046001A6814F537915BE3F03F3670E1169E4AAA6D7E726174ACAEC77C",
//         ),
//         (
//             "CF5A04DDB5EBC45328F703D486D24443A7692D65AA55F054E3078DB76A7939590A3F35CF1A21E82A845445DD1B64A85A",
//             "802E08C14F6E3446BBF7F4666C8DDF7755DC718C3E02B7865FF33E9D8290ABEC",
//         ),
//         (
//             "8C3D2FBBE0D39E293AF2D2CC5A9BEDEAAE3752DFD19CDC1E186D41E717A0412AA429CBDF005445AFDE684656B5D17690",
//             "23D7A85A824DF3D904A511281A973C979F67F5BFAF3AB0546E85D0597F91120F",
//         ),
//         (
//             "C10427EF0B26328163F85D45E22EC5215415326F013FF31EDD58BD3E97B1A72FF07D275D4C1B517F4661B0638F75640C",
//             "771CBB7C9FBD9FC5DB93E3E4DE6C034E58BE9BADE93748C42297142124696234",
//         ),
//         (
//             "4B6B73E042CE76DBE39535E45D3BB2F3B9F8B2BDA170E76CC88666844703E32B2367460A0F6A0A2E3F4E7A6CD32BE998",
//             "FA812D8CC3A9631A0239474EB93AD3A2A3480F2D973D3324228EF92A3B043163",
//         ),
//         (
//             "3D4607399F6FCBE074FD2BEAB1A7571239D6BE6308617866B65B892EE65399E14DC7FA612CDBC5F7E23116FA86C3133D",
//             "C660B84D558A7E6B4EAC47C7B62135668E0EF0FBF74D514EAA3D0D428014282A",
//         ),
//         (
//             "7031BA806F4D8BC28529163B239E0EE836871C51D2D62B601B71D6F2B69B203C81440F8FFC09C3AAD94DB1D880160671",
//             "929F309AB3F90CDD9C21EB77A7CA762CA3AFCACBFE3E67B056290835694BA3D8",
//         ),
//         (
//             "C8671A5D752CC6DDF075C899797603A625C142485EAC3D57CAF14F2244D7F84D116B28F959912A758E519D588A6A07EB",
//             "DAE1EBA78AD1568590348088AAE88C1ABEB59626EF65991CD76AB81198E52837",
//         ),
//         (
//             "D780D7688AF364949A196657A066BD48FFA8DC45B4885279B6DEF362E5957F398CDCE1D20FC3F8F63A275C325FCCE654",
//             "15ED428927A7EB0C7C2DC7A98CFBB77BDD773FA8747B8232A6EC4B87CD7DBCE1",
//         ),
//         (
//             "36AB8588F5233D15674677535A682382C29968FF824031AF646F58FCAF0E83C1C486B1E75479149FD6F4D9E8397CAF73",
//             "BA7E359B1F669783521AD35EDABE97141A816C2FABF0AD0E001E21F73CCF7736",
//         ),
//         (
//             "4E94DD734A371A7C6AD4A567038CF93BAACE2B9D30F3862198DC55D2F21F8FDC9A7AE5DCA1541712179E3AB1FFA3F792",
//             "9DAEF95C8D5A61D3A3A267FEFB9F37D6E677D7BA26A3A5BFDBDA8C281BE89CCB",
//         ),
//         (
//             "D9281003AC5F7673E0E9A7BC29C4ED75E6B0F228DF49D11A2599BFF2DA9E887163BB26DBA4F071FBCE02891540EC6F1C",
//             "0531B4105CB209585F9FBC29CAA57E64C2D40F0829931A42CAF7701717D9096E",
//         ),
//         (
//             "750A74866BE8DF4E60BC14BF36E6D83ABF6DCBB86792D125CF0980007C5435F40F87BA96498A88252D9C5C6710807652",
//             "7F8515AA82DBC9EC8CF1DED5AB58EC0D08CF686E25A8C01FB1109A3C68D19E48",
//         ),
//         (
//             "A832D4AAE8076C4EFE8319A74CE315928AB765BB629075254CBC63EAAE691C220F4B5E1839E9A99D8747AACD7C2F1EE3",
//             "5AF3838060E0F83352A75A0EC4ACE2CE8BA119BF89F34CB4D6B8E27007CAE7FB",
//         ),
//         (
//             "09B8441F47235EFC82D71933A0037FA4F69124C3BAD4EF6A3A7178B417A3FDA874081B7EEFD7EF1BF234C752458FBBAD",
//             "B323D48B567F7EFFFFD47A7C9ABF0ADD5F11141737A8AF62B56E042EE498AD6E",
//         ),
//         (
//             "D2629CEEAE5C95D3C34C1FFCC2338B4A97782BDFCD39111E18540B69DB035B352D012857111F816F03550BFE5F56ABEE",
//             "C1CF3107EA9B283419E27DC563ECCE950BEA78C048A3F49FB42128819959E51C",
//         ),
//         (
//             "EAA4FB8EF0290A499A1D92EE398A8D7E71CD3CBF01A36750DA4B7EFF175DA26D17AC4ECE49A84C88D1D2C2493563C26D",
//             "A50FC40F0D9EFA5D254943DC599F7DCC2F6D197A4D2666D5D69CFACCDA560817",
//         ),
//         (
//             "5909111F333F3E939105DFF8532548927EBF289F31A72F4C1B0C66816D8B68F64622F36A9BC85E63601BEE8EE7CB3DC5",
//             "4C0F0EF1CA8073A562D5414584EDF268913D53D5FB39FA639E02E900891EA82C",
//         ),
//         (
//             "238461A224ABEECCF709AB6CACF4EDD372D45E5F4274095273A49AFE614F2BF713134ABF68B4DD058E6D7B612C3658C3",
//             "5BA8AD9B66C93CDE7E7E616A97FED8AA91BC7235FB4DB086CB4021877780C6B4",
//         ),
//         (
//             "83C653708FAF3E5F6FBC9DFBE6FB5E83E572A7688645D75D2C4835B28695DEA4BD7093740D0FF43237354EAD1C978BC2",
//             "25D957B9BF68326D2EFEC93DA464F43E3DF16DD6571CEB1AB68BD58E87734A51",
//         ),
//         (
//             "BC81485EE93AAD8B464B5199FFEF9FEFC06EA97645BDFE0B4E915B812E606A77F93917ED925E882161CBB909747AC4C8",
//             "24F0CD3B05D964F82D3702BF0A613139808D49283286294BE57E13A983C3C961",
//         ),
//         (
//             "DE9E2742591A5AF6A6153DA85A510C39FD31A2ACD8A8511F190A9A5E5753E63D9801A8019508E67DEB1E9219CC18BA3A",
//             "5EF2732B63A1CBD2CC239EA6FED62F7FEB3102715A5BAFD8C83AAC33702FACCF",
//         ),
//         (
//             "272E459EAB6A0BDF720E4C5B79E641C95BAB66C3CEE261D0E3596BB04D232ACE0A1CE24BACCAAE9037665A962C711B08",
//             "6A27B1666AB6FC4483D14CF84EDE49FEDFE05BB24E008AE8A01C52D83B8D40FE",
//         ),
//         (
//             "DCC58DFC13B035323ED44BE50A7096F697C9C143518FED50A59181160960203831A9904847BA20B85E99FFA63E4AB0B2",
//             "2A855572E7E2ADD2888022BDB585B61577A75A31AA8ACEDE59ACB27EEB2936AE",
//         ),
//         (
//             "270BEDAA7BCD43990FD8B4F44FFB63A3AE8E991BB2BF84DA7BC2CCD1A079C579AEBE2082ACBAB7FF286DE795F31973B4",
//             "7967E9DE70A7F95E69371F812C2FBF932CEC07AB4C235AE9E8A6799F3F537D36",
//         ),
//         (
//             "F151196F55A9ED88F1663AF6BD24B2CB9DCAF3C9B313CD8F0A27639D3CDAE72EA90D60ED5C7C6AB697A06185E5A2E215",
//             "5ABA340A8E541568FBEF49E77F94CFB4B3A5E9CF14C6755CE6412CF86CF62898",
//         ),
//         (
//             "C7ECD1EC1A3D83F5116C0AA4345FB3ADB4D9F81BD79896BC4932EE2F9D2D1F179BAF7A002D88F4F69071A7931E7F7FAE",
//             "DF4853F482CC1D0B3A2D71E9EACA064E57C5D100DF79BD004BA81B43EACEC401",
//         ),
//         (
//             "5DE03CAB3CBD81B8805A17E0FFC2105C3BCDC8D782EAAB161A15AAA543FED59353C1FBE03E7F36B955FC51C9B30F0C93",
//             "95DA16B844BAF559C2CD6E68B237614BB9927D90811106347B5849FEE2F48640",
//         ),
//         (
//             "63742CEFAE9868C3C0B31DDE0F9D378FD5D71BE7CC3F0B6ECD393DB55FB043CF00264852C45D1836CC12B9C872A20251",
//             "F258FF1178CC42A3CEBE238C8418B4974812A05F43B8FA95639CC46BC0738BC5",
//         ),
//         (
//             "B887F07DB5358C3FDC2402947BBC87ABD064B02A859FE8DB37B5BCBB916020443DABA5534A0778FD0B1C05EF3ABE6269",
//             "5EFBBBE99CF5C2B6830FB8E990250BE308E662200526889EA973C8D33823EC19",
//         ),
//         (
//             "D08A139CC7147ECAF4B1D1E434EB2EFA2B2607B0033D8BA989133E496DC9F3654944C7AF91CBB79866443E8C4E8217ED",
//             "47A048D8799784F6EC385EB984E70C62CE7C8A107232871B69B99F7BF4C3DBB5",
//         ),
//         (
//             "A315BCF0E6835892ADFA07C034BFCD39F80B62925A95490B20170BD29378E11559C7F1CD296377FF1E01284EC727FFCD",
//             "1D9E243A35118BC7C50A50746E1CF19C9FC310C7D54181FB95F44753EAB1B94A",
//         ),
//         (
//             "8B47E0EBE786914C9A52D547106CEB4A3D3DE938B3244E02E5F9660954C4C95A23F2476FCCB487673AAD0513820905DF",
//             "0A46FDA6BA71125F3415E8BB6C2D8C00601107FA563E7F6386486A88F87701FB",
//         ),
//         (
//             "07CD8F8AB7CD12EA7CC94103B8623D6F0FEA2BAFD2325BF6089DF5351BDBB9A94525C3C6B72D3820F2E4D5F9E7C849F8",
//             "5229DFE11090EFFBE94EE161054CD5FF58B31E23F567B282DB42EB1FE42E44AA",
//         ),
//         (
//             "3D598F7C498D8A1095C40945975380554BEF6142578638A7627E2C0A21C59C579F8E8CDA309348FC54C764C899FB93E9",
//             "18AA77795AA6D7ADE8B6CDCED81A1959A8329677F042283DC8CA71E13EB3ADEE",
//         ),
//         (
//             "6CDB757AD36DF99E52F535C2680431D5FF36C812D8EA19399F666F2FDD66D3A842A7A5AE1038359AB618FA58A0A6E840",
//             "4B2D6EC32BE9C5D8FA11F3FC0008F4F26B945064D98362AD912F452692AC383D",
//         ),
//         (
//             "A97269579EB70D268C58D94FF744329B197F722A8A407B788510DDCACA34C8CD4C72FFC14B76300C86AEA1E4CFA66BA4",
//             "196B8144DFBFB47EC01E96A6B8443211D6C9C4AA7853A8131B5218349BD6D953",
//         ),
//         (
//             "483A81716F91A43ACA6764C4BD2A57C9156B762E9174EA49730A6BEB9CB19A0B3755E37BA47EC524BBE2FA25B9FEF687",
//             "C171793029D0CBAF8D2661A823243AD50D67F2619533180F25B50C94B1310389",
//         ),
//         (
//             "30F0E117513AAF27AB2516BCEADD1188B4BBDE76E57DFAF43CBF2D70723D941E8F875C5EBF02BD7D67AE81ABCC54440A",
//             "615FA91F3D206B908649399F216950EC7B2420EB04AEC6ABFCB7B4528E8E33E6",
//         ),
//         (
//             "070FFB907EE8AB7152A9D380DEA2C4C4796780FCFD80906C5E489B917A45D5E7EDFE6F37C4420E5480E8BB599FE36451",
//             "626C19B8553B2D9E5A47A758615D80B15BE11FD016D3A1962D8DE58ED5CA2219",
//         ),
//         (
//             "EDBCC4F6AD0F30066947D678A368B960CCD164889D77730516B444ED2DF10B49C101902F5FA227377C3163A0045B34E4",
//             "B0D4BA39ADB4E8712B3A3E6495ABA2F04A29E45C68671A960BC0D8D89900C97E",
//         ),
//         (
//             "DEEE61A2FAC04E4D6B7A250124DFD91518D9B90A71FA02665E3088760BF69CB3CD7B6977F860A7026819D178623C9676",
//             "E04328A783C10DACD96702D2E726BB11CE4ECC571564CE7CB10722D1C98C2842",
//         ),
//         (
//             "DAB6C05E29342106CC34769BF419ADCC88010C05B57E673A503E63AE7A4EE55B72AB2CA86C4EF57FC8C02D2E0C8694A1",
//             "CEE2E53099D8CB576F8F76C5C155470F87A6EC5F7D73256A0A2AEE62CBC53597",
//         ),
//         (
//             "0CAF47BD9AABD7D09FFAD404449BBAB2E1D48E80AC78550831A365BED8765420DBBE9A566EFDF20D4E5233D7848582E4",
//             "02D9755C369932E7F99A2E1614B03E2C86D713563785965E008BA987A6C89F49",
//         ),
//         (
//             "9564E88F336C091EAD50C893F3EAA8351FA388682F433F7A72A34731020B9C96DFCF75EF5EAE47E12684AFA51EFB49B7",
//             "2B2BF7CBB0957A86BBEC97001B60C7C6AD98A56E94542FF561F78FED211DA755",
//         ),
//         (
//             "4D0788DE958A707899D5DCC02F756A10DEA2EFE0214F5E01B3281DF4E013CA75523ECEC64723D6C8BEC0B92C4F821D8F",
//             "049569CC5FB969C6EEBB8AEA1AF1FCAF46F8A9E6CD6C796FC7193592BCA9CF23",
//         ),
//         (
//             "55A9C7A0B49706090BC0702ECFC070AB060427FFC820C3FE05B499B59AEB125F2DB4787A5910B88C6F8FAF0A69BE0AE5",
//             "9D89B9A327DF0D341CD2968BA9218BBC3E934502CD88919D8BB16DD3D39FEBF7",
//         ),
//         (
//             "CEECCCD3F7BB922650E3F6E8F20C47AF17C1C1053EA8FE08226F167D67C3B0781BD774C4C7AAD23C6AB0B9F3E3F96F97",
//             "4544C2F21054605B0EEE46F62A87DFCBC3BFEC473B9850886266F478BF9E33D7",
//         ),
//         (
//             "2489C04BA57D149A60F446670C13C29998B52F3BAD548A751D7134B694DB25ABFA034FB4BA45E105AE27D575CBD02B99",
//             "D9931E321732BD82EC9CA1DF12BA48549BFC7D3E76A404B71892F4198777FFBB",
//         ),
//         (
//             "26CF860726D4DFA38AE07399838BB336F1BEE59E9F23AE4C81E73D49964997EF21CB5F5412F9A70A1EC39FC6228C36CA",
//             "F838451E4A5929B8BAE9084B40B1DC0EDFB76A9354BF27F981960C88B0BA3A11",
//         ),
//         (
//             "13F1F446D9AA5AC853278BF74C9E6447A6CE4294C037867F43DF554370EE261D05C7260EEBF46D6694D0850B8343FBE5",
//             "8E4334B2589D0CAECF0FD9BA584EA26A4123D4543A8A0FE126D4A7E07F6067AF",
//         ),
//         (
//             "6F6E47E8336ADEE99B2C52CF2DC8D461E0A54C3DF2F08199A9F0816AF8455381054CE47A7766726D3AFC2E2F2BEAF8E8",
//             "37519A02E8021F2257259C0D2E499AF3533C8ED8DD5BF7751CCE920D79B518FA",
//         ),
//         (
//             "CB2E6226615393FC3BD4AB3A412AAA030AAD40E8648EE6B56D2C1591D8B97915D88F2D22F7221377B4B04CF2AE9ECC4E",
//             "690482BFF6C1D0BA6C071DD395ADF69E55E1BFC4E0992A8650FFB5E60A02B172",
//         ),
//     ])
// }
//
// struct TestCase {
//     seed: String,
//     mlen: i32,
//     msg: Vec<u8>,
//     pk: Vec<u8>,
//     sk: Vec<u8>,
//     smlen: i32,
//     sm: Vec<u8>,
// }
//
// fn read_test_vectors(path: &str) -> HashMap<String, TestCase> {
//     let mut test_vectors: HashMap<String, TestCase> = HashMap::new();
//     let string_content: Vec<String> =
//         fs::read_to_string(path).unwrap().lines().map(String::from).collect();
//
//     let mut i = 0;
//     while i < string_content.len() {
//         if string_content[i].starts_with("count = ") {
//             let count = string_content[i].split(" = ").collect::<Vec<&str>>()[1].to_string();
//             let seed = string_content[i + 1].split(" = ").collect::<Vec<&str>>()[1].to_string();
//             let mlen = string_content[i + 2].split(" = ").collect::<Vec<&str>>()[1]
//                 .parse::<i32>()
//                 .unwrap();
//             let msg = hex::decode(string_content[i + 3].split(" = ").collect::<Vec<&str>>()[1])
//                 .expect("msg couldn't be read");
//             let pk = hex::decode(string_content[i + 4].split(" = ").collect::<Vec<&str>>()[1])
//                 .expect("pk couldn't be read");
//             let sk = hex::decode(string_content[i + 5].split(" = ").collect::<Vec<&str>>()[1])
//                 .expect("sk couldn't be read");
//             let smlen = string_content[i + 6].split(" = ").collect::<Vec<&str>>()[1]
//                 .parse::<i32>()
//                 .unwrap();
//             let sm = hex::decode(string_content[i + 7].split(" = ").collect::<Vec<&str>>()[1])
//                 .expect("sm couldn't be read");
//             let v = TestCase { seed, mlen, msg, pk, sk, smlen, sm };
//             test_vectors.insert(count, v);
//             i += 7;
//         }
//         i += 1;
//     }
//
//     test_vectors
// }
