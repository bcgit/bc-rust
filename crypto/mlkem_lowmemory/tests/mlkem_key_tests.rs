#[cfg(test)]
mod mlkem_key_tests {
    use bouncycastle_core::key_material::{KeyMaterial512, KeyMaterialTrait, KeyType};
    use bouncycastle_core::traits::{KEM, KEMPrivateKey, KEMPublicKey, SecurityStrength};
    use bouncycastle_hex as hex;
    use bouncycastle_mlkem_lowmemory::mlkem::MLKEM512_FULL_SK_LEN;
    use bouncycastle_mlkem_lowmemory::{
        MLKEM_SS_LEN, MLKEM512_CT_LEN, MLKEM512_PK_LEN, MLKEM512_SK_LEN, MLKEM768_CT_LEN,
        MLKEM768_PK_LEN, MLKEM768_SK_LEN, MLKEM1024_CT_LEN, MLKEM1024_PK_LEN, MLKEM1024_SK_LEN,
    };
    use bouncycastle_mlkem_lowmemory::{MLKEM512, MLKEM768, MLKEM1024};
    use bouncycastle_mlkem_lowmemory::{
        MLKEM512PrivateKey, MLKEM512PublicKey, MLKEM768PrivateKey, MLKEM768PublicKey,
        MLKEM1024PrivateKey, MLKEM1024PublicKey,
    };
    use bouncycastle_mlkem_lowmemory::{MLKEMPrivateKeyTrait, MLKEMPublicKeyTrait, MLKEMTrait};

    #[test]
    fn core_framework_tests() {
        use bouncycastle_core_test_framework::kem::TestFrameworkKEMKeys;
        let tf = TestFrameworkKEMKeys::new();

        tf.test_keys::<MLKEM512PublicKey, MLKEM512PrivateKey, MLKEM512, MLKEM512_PK_LEN, MLKEM512_SK_LEN, MLKEM512_CT_LEN, MLKEM_SS_LEN>();
        tf.test_keys::<MLKEM768PublicKey, MLKEM768PrivateKey, MLKEM768, MLKEM768_PK_LEN, MLKEM768_SK_LEN, MLKEM768_CT_LEN, MLKEM_SS_LEN>();
        tf.test_keys::<MLKEM1024PublicKey, MLKEM1024PrivateKey, MLKEM1024, MLKEM1024_PK_LEN, MLKEM1024_SK_LEN, MLKEM1024_CT_LEN, MLKEM_SS_LEN>();
    }

    #[test]
    fn pk_from_sk() {

        /* MLDSA44 */
        let seed_bytes: [u8; MLKEM512_SK_LEN] = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f").unwrap().try_into().unwrap();
        let expected_sk_bytes: [u8; MLKEM512_FULL_SK_LEN] = hex::decode("70554fd436344f2785b1b3b1bac184b6679003336c26f15a7de878c4825c6be03f3c4a480f75b7486aad31d3a00518623fd207ab528dd62721495835ae0062c367b74a71baf10aad0e8a2902076be31348beb15ccc0957cdebb4aff226756bbc601b6568ab784acbaeb34702f0f86a26202118b22b23f83558776c79c14dba983379c803e0dcc3160a11757030e69c6919798d81eb698a9a4483a99e5a5cb2c31c9a661799f3cc89c790706ea041629045d42a83aed88860e394c69187e2105d28cc14ec393592d67dd00aa43fe8b4eae4414002866b5c713c6a8d7d16cf78b819d6f12e9e5a74233908f0b15e3c4ba8329c5cdda55c84928e3aa8063e5aa9676403f91735b11010c7f593091364dc86445bc804840a9a21724212469f8a7b0ce0ac698eb86cad39a7f4824d9a5163aac21ee6808b053c8a3facb0b6744b5262bbcb26a43f664c8732b64cfc7acf099605f41c796060976ac433833fe00343fb1828300a424741116e4b45bb276ea81129a0db4c6e60bce611101e8c625474925e0222679308a3e7708d1972a7b423eb232851c36d2ed53d3ed3bb7500637061a5dc2292fa1c466c07354683328bec2c1ed2cb5c99b78eca0969038cf7c34dd118724e31cae086206b34302b520f5d177aded5b3cce02acce808ea26bcc072625fdb93f17458a5fc1d4da394380a1f57e9cc66109438a075f0d2813fcc4a199cc76db3823f270b0061594192940411a37ffbafae2c150165cec5c6bf73c595fb92cd15312607da070778652bd9944bc48bc7d1a534338bad0bad6656c5d502ce7850ab1587244eeb58f439ab5e08574a718c8aac3d77c798bba1542733be73448f23fb70c0e5353a27c88322c5218493afbb38086434d6d60a56ba887dd498c3ab26a0870993815aa6a40975f218adca1582d64ffc8652fbb3a9a6fbc304f91945fa4aaef2878fd715df70113d2379f44886f812c83ff2b719a69e1ec74ae4b15accd3aed5a53ce76a7b0982471633b973cb40a1a0015d0a424fa11a479c023017436d2a2900e993eb5a0a067400c7f4aadf201fc4fa31264a63bae95cc8d65c3995815e597d104355cf29aa5333c93251869d5bcdbe487124f602b8b6a66c16c4761648ad765cf5d8006b515e905a7f0ac076b0c62efa328153e7ca5701699f1305f1e6bc6f90b0e49b693512b6ce992a8b8016ddfc1a662c7e3f9619cbd869dd771af30896ccd5918ac6cb77466c5e779996d67ff9aabc97503f2c7b7e2d000d86450fb1807ca4cabda465825a31c789a1b7a491ab3872765d320d0b71920fa213c94093416b83b8124e69f65e62cb5000dcc37aa9a0fff73970c4772f357d24189ca6f5305568c0e2376a3762a68c605e563c5d209572e0fc7532ca294729535567b5fc413c5e8792d2464536cc808f98add74664f141566f9016a90a541829a98a0464ce41a8bb44c2d4fa3c2c209460728ef14a1a7c4c9b98d12203b4cc3529160a9ab2d7838f7ff6b53ae05aa31a7d646b7afa6c45932526a3c3755619be994c211c2a31c05b3447836cb2150be1829dae6b04c5535cff546e392ba797411720f924f490a5ac5495f21356d550b782a64c1688b6b655bcc7842197a434c2f6563b5b7f09a78bcc488232783561d16f4cbab6755400050781570c66604b817ad1252294736e8b01861a4b5a74519b8b6fe51489a5072392e587626c713776575d33806a1c8e2732af97c2680f51666331c4eb8bbc0431c4f96832daf1b3c45528fba153f6c78b1c198702947ccd337727a46fb53ba11de5cb4191346859516cb6ad72400f3cf209b236aef35a580ac87eb3e30fafd66973ca8a7dd2675af41f7a17b61433cd1af80f7708869f665488497980b1ac10a0cdcb636a00ed8681b35e429124ca80350725b85f83a5eac3a4a3cc1600903e65293560b9b336e5af0d529dac1a048119302cb7a9bcc110b94851bf02117f199dc485a852b7473f09b831a6831d5b54c0b790d225cf6bb92d9462a26cdb33dda5123c7aaf0e26a0b83655eea28bf3a8074725018fd6bae4b601cf61baab71a7a3d35197a343e74b4a272c125d540896426d85b7958d3b38a6ba987ec37225c7b44cdb12dde4539b4ab082363683f04bf7a09cc5c41dfe830a1b162e0b324334362f084a14467723344badd000f8d8c537c48f998f05307cebd1ede0b81c3bc59a065a1b6d63b26c82f101ff648063b376e2bb6c5b7455f655a50c2feadade150efa0e0e6f365aea202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f").unwrap()
            .try_into().unwrap();
        let expected_pk_bytes: [u8; MLKEM512_PK_LEN] = hex::decode("3995815e597d104355cf29aa5333c93251869d5bcdbe487124f602b8b6a66c16c4761648ad765cf5d8006b515e905a7f0ac076b0c62efa328153e7ca5701699f1305f1e6bc6f90b0e49b693512b6ce992a8b8016ddfc1a662c7e3f9619cbd869dd771af30896ccd5918ac6cb77466c5e779996d67ff9aabc97503f2c7b7e2d000d86450fb1807ca4cabda465825a31c789a1b7a491ab3872765d320d0b71920fa213c94093416b83b8124e69f65e62cb5000dcc37aa9a0fff73970c4772f357d24189ca6f5305568c0e2376a3762a68c605e563c5d209572e0fc7532ca294729535567b5fc413c5e8792d2464536cc808f98add74664f141566f9016a90a541829a98a0464ce41a8bb44c2d4fa3c2c209460728ef14a1a7c4c9b98d12203b4cc3529160a9ab2d7838f7ff6b53ae05aa31a7d646b7afa6c45932526a3c3755619be994c211c2a31c05b3447836cb2150be1829dae6b04c5535cff546e392ba797411720f924f490a5ac5495f21356d550b782a64c1688b6b655bcc7842197a434c2f6563b5b7f09a78bcc488232783561d16f4cbab6755400050781570c66604b817ad1252294736e8b01861a4b5a74519b8b6fe51489a5072392e587626c713776575d33806a1c8e2732af97c2680f51666331c4eb8bbc0431c4f96832daf1b3c45528fba153f6c78b1c198702947ccd337727a46fb53ba11de5cb4191346859516cb6ad72400f3cf209b236aef35a580ac87eb3e30fafd66973ca8a7dd2675af41f7a17b61433cd1af80f7708869f665488497980b1ac10a0cdcb636a00ed8681b35e429124ca80350725b85f83a5eac3a4a3cc1600903e65293560b9b336e5af0d529dac1a048119302cb7a9bcc110b94851bf02117f199dc485a852b7473f09b831a6831d5b54c0b790d225cf6bb92d9462a26cdb33dda5123c7aaf0e26a0b83655eea28bf3a8074725018fd6bae4b601cf61baab71a7a3d35197a343e74b4a272c125d540896426d85b7958d3b38a6ba987ec37225c7b44cdb12dde4539b4ab082363683f04bf7a09cc5c41dfe830a1b162e0b324334362f084a14467723344badd000f8d8c537c48f998f05307cebd1ede0b81c3bc59a065a1b6d63b26c").unwrap()
            .try_into().unwrap();

        // Decode and re-encode the sk, make sure you get the same thing
        let sk = MLKEM512PrivateKey::from_bytes(&seed_bytes).unwrap();
        let sk_bytes = sk.encode();
        assert_eq!(sk_bytes.len(), seed_bytes.len());

        assert_eq!(sk_bytes.len(), seed_bytes.len());
        assert_eq!(sk_bytes, seed_bytes.as_slice());

        // Also test the export to fully expanded sk
        assert_eq!(&sk.encode_full_sk(), &expected_sk_bytes);


        // Decode and re-encode the pk, make sure you get the same thing
        let decoded_pk = MLKEM512PublicKey::from_bytes(&expected_pk_bytes).unwrap();
        let pk_bytes = decoded_pk.encode();
        assert_eq!(pk_bytes.len(), expected_pk_bytes.len());
        assert_eq!(pk_bytes, expected_pk_bytes.as_slice());

        // test re-deriving pk from sk;
        assert_eq!(sk.pk(), decoded_pk);
    }
    #[test]
    fn test_ek_hash() {
        // three separate tests here:
        // 1) does it calculate H(ek) properly from a public key?
        // 2) does it calculate H(ek) properly from a private key?
        // 3) does it reject a private key if the H(ek) is wrong?

        let seed = KeyMaterial512::from_bytes_as_type(
            &hex::decode(
                "000102030405060708090a0b0c0d0e0f
                101112131415161718191a1b1c1d1e1f
                202122232425262728292a2b2c2d2e2f
                303132333435363738393a3b3c3d3e3f",
            ).unwrap(),
            KeyType::Seed,
        ).unwrap();
        let (_pk, mut sk) = MLKEM512::keygen_from_seed(&seed).unwrap();

        let expected_pk_bytes: [u8; MLKEM512_PK_LEN] = hex::decode("3995815e597d104355cf29aa5333c93251869d5bcdbe487124f602b8b6a66c16c4761648ad765cf5d8006b515e905a7f0ac076b0c62efa328153e7ca5701699f1305f1e6bc6f90b0e49b693512b6ce992a8b8016ddfc1a662c7e3f9619cbd869dd771af30896ccd5918ac6cb77466c5e779996d67ff9aabc97503f2c7b7e2d000d86450fb1807ca4cabda465825a31c789a1b7a491ab3872765d320d0b71920fa213c94093416b83b8124e69f65e62cb5000dcc37aa9a0fff73970c4772f357d24189ca6f5305568c0e2376a3762a68c605e563c5d209572e0fc7532ca294729535567b5fc413c5e8792d2464536cc808f98add74664f141566f9016a90a541829a98a0464ce41a8bb44c2d4fa3c2c209460728ef14a1a7c4c9b98d12203b4cc3529160a9ab2d7838f7ff6b53ae05aa31a7d646b7afa6c45932526a3c3755619be994c211c2a31c05b3447836cb2150be1829dae6b04c5535cff546e392ba797411720f924f490a5ac5495f21356d550b782a64c1688b6b655bcc7842197a434c2f6563b5b7f09a78bcc488232783561d16f4cbab6755400050781570c66604b817ad1252294736e8b01861a4b5a74519b8b6fe51489a5072392e587626c713776575d33806a1c8e2732af97c2680f51666331c4eb8bbc0431c4f96832daf1b3c45528fba153f6c78b1c198702947ccd337727a46fb53ba11de5cb4191346859516cb6ad72400f3cf209b236aef35a580ac87eb3e30fafd66973ca8a7dd2675af41f7a17b61433cd1af80f7708869f665488497980b1ac10a0cdcb636a00ed8681b35e429124ca80350725b85f83a5eac3a4a3cc1600903e65293560b9b336e5af0d529dac1a048119302cb7a9bcc110b94851bf02117f199dc485a852b7473f09b831a6831d5b54c0b790d225cf6bb92d9462a26cdb33dda5123c7aaf0e26a0b83655eea28bf3a8074725018fd6bae4b601cf61baab71a7a3d35197a343e74b4a272c125d540896426d85b7958d3b38a6ba987ec37225c7b44cdb12dde4539b4ab082363683f04bf7a09cc5c41dfe830a1b162e0b324334362f084a14467723344badd000f8d8c537c48f998f05307cebd1ede0b81c3bc59a065a1b6d63b26c").unwrap()
            .try_into().unwrap();
        let pk = MLKEM512PublicKey::from_bytes(&expected_pk_bytes).unwrap();

        // generation of KAT
        // let h_ek = pk.compute_hash();
        // println!("H(ek) for public key: {}", hex::encode(h_ek));
        let expected_h_ek: [u8; 32] =
            hex::decode("82f101ff648063b376e2bb6c5b7455f655a50c2feadade150efa0e0e6f365aea")
                .unwrap().try_into().unwrap();

        assert_eq!(pk.compute_hash(), expected_h_ek);
        assert_eq!(sk.pk_hash(), &expected_h_ek);
    }

    #[test]
    fn encode_decode() {
        let seed = KeyMaterial512::from_bytes_as_type(
            &hex::decode(
                "000102030405060708090a0b0c0d0e0f
                101112131415161718191a1b1c1d1e1f
                202122232425262728292a2b2c2d2e2f
                303132333435363738393a3b3c3d3e3f",
            ).unwrap(),
            KeyType::Seed,
        ).unwrap();

        let (pk1, sk1) = MLKEM512::keygen_from_seed(&seed).unwrap();
        let pk1_bytes = pk1.encode();
        let sk1_bytes = sk1.encode();

        let (pk2, sk2) = MLKEM512::keygen_from_seed(&seed).unwrap();
        let pk2_bytes = pk2.encode();
        assert_eq!(pk2_bytes.len(), MLKEM512_PK_LEN);
        assert_eq!(pk1_bytes, pk2_bytes);

        let sk2_bytes = sk2.encode();
        assert_eq!(sk2_bytes.len(), MLKEM512_SK_LEN);
        assert_eq!(sk1_bytes, sk2_bytes);
    }

    #[test]
    fn seed() {
        let seed = KeyMaterial512::from_bytes_as_type(
            &hex::decode(
                "000102030405060708090a0b0c0d0e0f
                101112131415161718191a1b1c1d1e1f
                202122232425262728292a2b2c2d2e2f
                303132333435363738393a3b3c3d3e3f",
            ).unwrap(),
            KeyType::Seed,
        ).unwrap();

        let (_pk, sk) = MLKEM512::keygen_from_seed(&seed).unwrap();

        assert!(sk.seed().is_some());
        assert_eq!(sk.seed().as_ref().unwrap(), &seed);

        // When you pop the seed out, its SecurityStrength will match the ML-DSA algorithm
        let (_pk, sk) = MLKEM512::keygen_from_seed(&seed).unwrap();
        assert_eq!(sk.seed().unwrap().security_strength(), SecurityStrength::_128bit);

        let (_pk, sk) = MLKEM768::keygen_from_seed(&seed).unwrap();
        assert_eq!(sk.seed().unwrap().security_strength(), SecurityStrength::_192bit);

        let (_pk, sk) = MLKEM1024::keygen_from_seed(&seed).unwrap();
        assert_eq!(sk.seed().unwrap().security_strength(), SecurityStrength::_256bit);
    }

    #[test]
    fn test_eq() {

        // MLKEM512

        let (pk, sk) = MLKEM512::keygen().unwrap();

        // basic equality checks
        assert_eq!(pk, pk);
        assert_eq!(pk, pk.clone());
        assert_eq!(pk, MLKEM512PublicKey::from_bytes(&pk.encode()).unwrap());

        assert_eq!(sk, sk);
        assert_eq!(sk, sk.clone());
        assert_eq!(sk, MLKEM512PrivateKey::from_bytes(&sk.encode()).unwrap());

        // inequality checks
        let mut bytes = pk.encode();
        bytes[17] ^= 0x01;
        assert_ne!(pk, MLKEM512PublicKey::from_bytes(&bytes).unwrap());

        let mut bytes = sk.encode();
        bytes[17] ^= 0x01;
        assert_ne!(sk, MLKEM512PrivateKey::from_bytes(&bytes).unwrap());


        // MLKEM768

        let (pk, sk) = MLKEM768::keygen().unwrap();

        // basic equality checks
        assert_eq!(pk, pk);
        assert_eq!(pk, pk.clone());
        assert_eq!(pk, MLKEM768PublicKey::from_bytes(&pk.encode()).unwrap());

        assert_eq!(sk, sk);
        assert_eq!(sk, sk.clone());
        assert_eq!(sk, MLKEM768PrivateKey::from_bytes(&sk.encode()).unwrap());

        // inequality checks
        let mut bytes = pk.encode();
        bytes[17] ^= 0x01;
        assert_ne!(pk, MLKEM768PublicKey::from_bytes(&bytes).unwrap());

        let mut bytes = sk.encode();
        bytes[17] ^= 0x01;
        assert_ne!(sk, MLKEM768PrivateKey::from_bytes(&bytes).unwrap());


        // MLKEM1024

        let (pk, sk) = MLKEM1024::keygen().unwrap();

        // basic equality checks
        assert_eq!(pk, pk);
        assert_eq!(pk, pk.clone());
        assert_eq!(pk, MLKEM1024PublicKey::from_bytes(&pk.encode()).unwrap());

        assert_eq!(sk, sk);
        assert_eq!(sk, sk.clone());
        assert_eq!(sk, MLKEM1024PrivateKey::from_bytes(&sk.encode()).unwrap());

        // inequality checks
        let mut bytes = pk.encode();
        bytes[17] ^= 0x01;
        assert_ne!(pk, MLKEM1024PublicKey::from_bytes(&bytes).unwrap());

        let mut bytes = sk.encode();
        bytes[17] ^= 0x01;
        assert_ne!(sk, MLKEM1024PrivateKey::from_bytes(&bytes).unwrap());
    }

    /// Tests that no private data is displayed
    #[test]
    fn test_display() {
        let (pk512, sk512) = MLKEM512::keygen().unwrap();
        let (pk768, sk768) = MLKEM768::keygen().unwrap();
        let (pk1024, sk1024) = MLKEM1024::keygen().unwrap();


        /*** MLDSAPublicKey ***/
        // fmt

        let pk_str = format!("{}", pk512);
        assert!(pk_str.contains("MLKEMPublicKey { alg: ML-KEM-512, pub_key_hash:"));

        let pk_str = format!("{}", pk768);
        assert!(pk_str.contains("MLKEMPublicKey { alg: ML-KEM-768, pub_key_hash:"));

        let pk_str = format!("{}", pk1024);
        assert!(pk_str.contains("MLKEMPublicKey { alg: ML-KEM-1024, pub_key_hash:"));

        // debug
        let pk_str = format!("{:?}", pk512);
        assert!(pk_str.contains("MLKEMPublicKey { alg: ML-KEM-512, pub_key_hash:"));

        let pk_str = format!("{:?}", pk768);
        assert!(pk_str.contains("MLKEMPublicKey { alg: ML-KEM-768, pub_key_hash:"));

        let pk_str = format!("{:?}", pk1024);
        assert!(pk_str.contains("MLKEMPublicKey { alg: ML-KEM-1024, pub_key_hash:"));



        /*** MLDSAPrivateKey ***/
        // fmt
        let sk_str = format!("{}", sk512);
        assert!(sk_str.contains("MLKEMSeedPrivateKey { alg: ML-KEM-512, pub_key_hash:"));

        let sk_str = format!("{}", sk768);
        assert!(sk_str.contains("MLKEMSeedPrivateKey { alg: ML-KEM-768, pub_key_hash:"));

        let sk_str = format!("{}", sk1024);
        assert!(sk_str.contains("MLKEMSeedPrivateKey { alg: ML-KEM-1024, pub_key_hash:"));

        // debug
        let sk_str = format!("{:?}", sk512);
        assert!(sk_str.contains("MLKEMSeedPrivateKey { alg: ML-KEM-512, pub_key_hash:"));

        let sk_str = format!("{:?}", sk768);
        assert!(sk_str.contains("MLKEMSeedPrivateKey { alg: ML-KEM-768, pub_key_hash:"));

        let sk_str = format!("{:?}", sk1024);
        assert!(sk_str.contains("MLKEMSeedPrivateKey { alg: ML-KEM-1024, pub_key_hash:"));
    }
}
