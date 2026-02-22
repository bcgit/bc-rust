//! todo -- docs -- turn this back on:
// #![warn(missing_docs)]

#![allow(unused_variables)] // todo - remove
#![allow(dead_code)] // todo - remove
#![allow(private_interfaces)] // todo debugging -- remove

#![forbid(unsafe_code)]
#![allow(incomplete_features)] // needed because currently generic_const_exprs is experimental
#![feature(generic_const_exprs)]
#![feature(int_roundings)]

// These are because I'm matching variable names exactly against FIPS 204, for example both 'K' and 'k',
// or 'A' and 'a' are used and have specific meanings.
// But need to tell the rust linter to not care.
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

mod mldsa;
mod mldsa_keys;
mod polynomial;
mod aux_functions;
mod matrix;


/*** Exported types ***/
use bouncycastle_core_interface::key_material::{KeyMaterial256, KeyType};
pub use mldsa::MLDSA;
pub use mldsa_keys::MLDSAPublicKey;
use crate::mldsa_keys::MLDSAPrivateKey;

/*** String constants ***/
pub const ML_DSA_44_NAME: &str = "ML-DSA-44";
pub const ML_DSA_65_NAME: &str = "ML-DSA-65";
pub const ML_DSA_87_NAME: &str = "ML-DSA-87";

/*** pub types ***/
pub type MLDSA44 = MLDSA<MLDSA44_k, MLDSA44_l, 2, MLDSA44_PK_LEN, MLDSA44_SK_LEN, MLDSA44_SIG_LEN, MLDSA44Params>;
pub type MLDSA44PublicKey = MLDSAPublicKey<MLDSA44_k, MLDSA44_PK_LEN>;
pub type MLDSA44PrivateKey = MLDSAPrivateKey<MLDSA44_k, MLDSA44_l, 2, MLDSA44_SK_LEN, MLDSA44_PK_LEN>;


pub type MLDSA65 = MLDSA<MLDSA65_k, MLDSA65_l, 4, MLDSA65_PK_LEN, MLDSA65_SK_LEN, MLDSA65_SIG_LEN, MLDSA65Params>;
pub type MLDSA65PublicKey = MLDSAPublicKey<MLDSA65_k, MLDSA65_PK_LEN>;
pub type MLDSA65PrivateKey = MLDSAPrivateKey<MLDSA65_k, MLDSA65_l, 4, MLDSA65_SK_LEN, MLDSA65_PK_LEN>;

pub type MLDSA87 = MLDSA<MLDSA87_k, MLDSA87_l, 2, MLDSA87_PK_LEN, MLDSA87_SK_LEN, MLDSA87_SIG_LEN, MLDSA87Params>;
pub type MLDSA87PublicKey = MLDSAPublicKey<MLDSA87_k, MLDSA87_PK_LEN>;
pub type MLDSA87PrivateKey = MLDSAPrivateKey<MLDSA87_k, MLDSA87_l, 2, MLDSA87_SK_LEN, MLDSA87_PK_LEN>;


/*** Constants ***/
// The way the constants are defined is a bit weird, so let me explain:
// We have three sets of constants:
//   * Constants for sizing arrays, which are used in type definitions, these include the sizes of
//     the vectors and matrices k and l, and the byte sizes of the public key, private key, and signature.
//     These are defined as global constants because the rust compiler seems to need them that way to be
//     usable in a typedef.
//   * Computational values that are fixed across parameter sets. These are defined as global constants.
//   * Computational values that vary by parameter set. These are defined in an instance of the MLDSAParams trait.

/*** Size values ***/
const MLDSA44_k: usize = 4;
const MLDSA44_l: usize = 4;
// const MLDSA44_ETA: usize = 2;
const MLDSA44_ETA_PACK_LEN: usize = 32*3;
const MLDSA44_PK_LEN: usize = 1312;
const MLDSA44_SK_LEN: usize = 2560;
const MLDSA44_SIG_LEN: usize = 2420;

const MLDSA65_k: usize = 6;
const MLDSA65_l: usize = 5;
// const MLDSA65_ETA: usize = 4;
const MLDSA65_ETA_PACK_LEN: usize = 32*4;
const MLDSA65_PK_LEN: usize = 1952;
const MLDSA65_SK_LEN: usize = 4032;
const MLDSA65_SIG_LEN: usize = 3309;

const MLDSA87_k: usize = 8;
const MLDSA87_l: usize = 7;
// const MLDSA87_ETA: usize = 2;
const MLDSA87_ETA_PACK_LEN: usize = 32*3;
const MLDSA87_PK_LEN: usize = 2592;
const MLDSA87_SK_LEN: usize = 4896;
const MLDSA87_SIG_LEN: usize = 4627;


/*** Internal fixed ML-DSA constants ***/
pub(crate) const N: usize = 256;
pub(crate) const q: i32 = 8380417;
pub(crate) const q_inv: i32 = 58728449; // Q ^ (-1) mod 2 ^32
pub(crate) const d: i32 = 13;
pub(crate) const ROOT_OF_UNITY: i32 = 1753;
pub(crate) const SEED_LEN: usize = 32;
pub(crate) const CRH_LEN: usize = 64;
pub(crate) const RND_LEN: usize = 32;
pub(crate) const TR_LEN: usize = 64;
pub(crate) const POLY_T1PACKED_LEN: usize = 320;
pub(crate) const POLY_T0PACKED_LEN: usize = 416;


/*** Param traits ***/

// TODO: remove the constants from the trait that are also defined above

/// Private trait on purpose so that only the NIST-approved params can be used.
/// Values taken directly from FIPS 204 Table 1 and Table 2
#[allow(private_bounds)]
trait MLDSAParams {
    // from FIPS 204 Table 1
    // q, zeta, d defined as global constants since they do not vary by parameter set
    const TAU: i32;
    const GAMMA1: i32;
    const GAMMA2: i32;
    const k: usize;
    const l: usize;
    const ETA: i32;
    const BETA: i32; // tau * eta
    const OMEGA: i32;

    // from FIPS 204 Table 2
    const SK_LEN: usize;
    const PK_LEN: usize;
    const SIG_LEN: usize;

    // useful derived values
    // const ALG: MldsaAlg;
    const C_TILDE: usize;
    const POLY_VEC_H_PACKED_LEN: usize;
    const POLY_Z_PACKED_LEN: usize;
    const POLY_W1_PACKED_LEN: usize;
    const POLY_ETA_PACKED_LEN: usize;
    const POLY_UNIFORM_GAMMA1_N_LEN: usize;
}

pub struct MLDSA44Params;

impl MLDSAParams for MLDSA44Params {
    const TAU: i32 = 39;
    const GAMMA1: i32 = 1 << 17;
    const GAMMA2: i32 = (q - 1) / 88;
    const k: usize = 4;
    const l: usize = 4;
    const ETA: i32 = 2;
    const BETA: i32 = 78;
    const OMEGA: i32 = 80;
    const SK_LEN: usize = 2560;
    const PK_LEN: usize = 1312;
    const SIG_LEN: usize = 2420;
    // const ALG: MldsaAlg = MldsaAlg::MlDsa44;
    const C_TILDE: usize = 32;
    const POLY_VEC_H_PACKED_LEN: usize = 0; // todo -- compute
    const POLY_Z_PACKED_LEN: usize = 576;
    const POLY_W1_PACKED_LEN: usize = 192;
    const POLY_ETA_PACKED_LEN: usize = 96;
    const POLY_UNIFORM_GAMMA1_N_LEN: usize = 0; // todo -- compute: 576usize.div_ceil(symmetric.stream_256_block_bytes)
}

pub struct MLDSA65Params;

impl MLDSAParams for MLDSA65Params {
    const TAU: i32 = 49;
    const GAMMA1: i32 = 1 << 19;
    const GAMMA2: i32 = (q - 1) / 32;
    const k: usize = 6;
    const l: usize = 5;
    const ETA: i32 = 4;
    const BETA: i32 = 196;
    const OMEGA: i32 = 55;
    const SK_LEN: usize = 4032;
    const PK_LEN: usize = 1952;
    const SIG_LEN: usize = 3309;
    // const ALG: MldsaAlg = MldsaAlg::MlDsa65;
    const C_TILDE: usize = 48;
    const POLY_VEC_H_PACKED_LEN: usize = 0; // todo -- compute
    const POLY_Z_PACKED_LEN: usize = 640;
    const POLY_W1_PACKED_LEN: usize = 128;
    const POLY_ETA_PACKED_LEN: usize = 128;
    const POLY_UNIFORM_GAMMA1_N_LEN: usize = 0; // todo -- compute: 640usize.div_ceil(symmetric.stream_256_block_bytes)
}

pub struct MLDSA87Params;

impl MLDSAParams for MLDSA87Params {
    const TAU: i32 = 60;
    const GAMMA1: i32 = 1 << 19;
    const GAMMA2: i32 = (q - 1) / 32;
    const k: usize = 8;
    const l: usize = 7;
    const ETA: i32 = 2;
    const BETA: i32 = 120;
    const OMEGA: i32 = 75;
    const SK_LEN: usize = 4896;
    const PK_LEN: usize = 2592;
    const SIG_LEN: usize = 4627;
    // const ALG: MldsaAlg = MldsaAlg::MlDsa87;
    const C_TILDE: usize = 64;
    const POLY_VEC_H_PACKED_LEN: usize = 0; // todo -- compute
    const POLY_Z_PACKED_LEN: usize = 640;
    const POLY_W1_PACKED_LEN: usize = 128;
    const POLY_ETA_PACKED_LEN: usize = 96;
    const POLY_UNIFORM_GAMMA1_N_LEN: usize = 0; // todo -- compute: 640usize.div_ceil(symmetric.stream_256_block_bytes)
}

// todo -- impl bouncycastle_core_interface::traits::Algorithm with the security strengths from Table 1



// todo -- DEBUG delete this
#[test]
fn rfc9881_test_vectors() {
    use bouncycastle_hex as hex;
    use bouncycastle_core_interface::traits::{SignaturePublicKey, SignaturePrivateKey};

    // note: same seed for MLDSA44, MLDSA65, MLDSA87
    let seed = KeyMaterial256::from_bytes_as_type(
        &hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap(),
        KeyType::Seed,
    ).unwrap();


    /* MLDSA44 */
    let expected_sk_bytes = hex::decode("d7b2b47254aae0db45e7930d4a98d2c97d8f1397d1789dafa17024b316e9bec939ce0f7f77f8db5644dcda366bfe4734bd95f435ff9a613aa54aa41c2c694c04329a07b1fabb48f52a309f11a1898f848e2322ffe623ec810db3bee33685854a88269da320d5120bfcfe89a18e30f7114d83aa404a646b6c997389860d12522ee0006e2384819186619b260d118664d4a62822184482402898146148a6614c4248a19208c2382951244808a125c2083108c47120140914836c18a78084106ec9c07022b56408b0610c070498124451886959004622932041062e42b64c01164914284c41a85180460a5116515a0820022244dc9849d13251e13065d3c08592a85112a1640039220946621cc70cd9086dd0062652408580443091062c50c80924c5841a966d4a982c99066da4443220a7645a326e11b57020926124138e04852c0a4872c8a051d3082a99208058242024074e59148810a46460c06de0b28d1b1909203422c024410943710a212061a2015222521b80809a340013934dd3322922170a9892691a14512027219cc02062a2814818691a854d8344695b2041031242cb184601a90d0c023183b0215a224ac89205d9906904306a4b064ad2b2011c404081423252327254a6405a18100c321292c2805212625c82280bb46c03428d53100c14010ee1365288842491020a63462620062911c228d0204802b36ca236095a8648cbb4618b4662c440821a890910024d24b24520122524c90588288cc9c04d5948220a276ec134644c90605b445082864943880443b28c603080a2882d84a46d8ca629d0c68442064689885100a98d01498de4380da4068dd3947142b26c1a84611ba32842b42808a0711ac531e0a04c013765242862142890091061d940221b3360090292d02481200408491844a3222d5c8844149808a446610195640b390a0c9450ca406ad2b220c0380182308e13b908918084148829c0189112350da02422e20406d9c2850428121cc989180272d24029c20812d8062a9994719bb8682384291a2289144511dc82445096450c4484c0b2049aa60543862c44326e88442120a84c9a3070e3b82d63268803254903438c48a809ca147253344e1243081ba704593022d99480e234228142129c302a9434266104452426281346094a326d11280918b82562281113410d41b21190844c8b1212a2c688c9c030220606d2188e848630904452128831d9207113c52843060e033060cca6845826524c88011ef72562c85ffa43acfa49217f2b172d7bbc14620e6d980a71aabbdf0c45e9a206ecb1423fee15decc17601300149d9223cd6e6c6e1fa8e41fc7c64938ab68905fd3dcda50d87082e7d0d71d1bc9b2b84c85523ca8fe6cad294adf83be15b108ff721d0cc87bc3dd3a7590184b0e845663a91fc9e1c3c53a61d867420b04f092355753bc65a06368fd41295fd09924132c6f91f67964c142674a725c343914c4cecf58c074bcaf4558c97bf7911e07aa6d0938f2ee2bb3c1a8c595d635e84342fdea01dc24b211ad2fc281cf77e59110c7abc54bf0c86d480b9be276471dc9d603cee98cfdab3e9fcfb703793560549ea4450fa7b33fb9169c44b4d25fb9c457f49791cd3da03eac96095813c105132ccda4e63e49228cd23d8a1f37856f142d93b90db09f82af89258c63aab8047a80c036c9357ea2046f8dc6354f0c5295f342bb417d3cfeb0b1fd33622c29e14cbbd92e1363c65ebd4504b7512329b9670e32e1b2c67a54e7f1a55f8b9f9ea04e8ca3a705e62a3c5e637374afb7aeb6ddea612cde28f01a202d7aa4e34722d27dd3f9b89894d019fd5d4d7119efe3723bba104cb8bb0981e074de3afe200daaaead826cc45f244dbf431afab34efbdf782474d2fd57118f646214934ed99cba3b003e8d67a3836f6f19fc41910ce5163ee3ae99eb84d514eb761e63684ea56f9791d2dd4aac6e6168b948c817f75a222acb0e8cdc03cc4afe8f67157e1a363b7faeff9f172b98913677c5a1dd085e9ee4c22052c1af58193116673dcd3bfc5f34b855dcc6c77885649e9e71f43d4aea0f4b72ca7eda0578ba13d31a658d2d060a9a66ff69ed1be7997a2fb1d2723d38f9bfabe18f8e7b3cda906e4e9b5e942c8eaeb296070ebfd364947a940cc978bed66b37749e6d5dcd7be8c494440e2b84cecfefb98c0bedfb3c41e3359d2cd7197fbe720c48aa6c6b6465c1ee63e3569c2adc744491370b7f7826fe0b77a1d19d64101d032b918106b42d2ef73747e5601fe4ba50f23ede521f031a817d15294a43722e8378784b6db0cf1ba9e8ae911d9201b9ce9cc3019c6f5c27cb98da26144b64225a7c932b30f761e78a2d59a1d8b83ec6344a2f6dd47e765706d00bf4a79a6a926c3ba91d812c8f2c797ab1796709e5d16856778293529f0286d015c3b5399619642a333e9e593d6e3f5353994208e9e6a332851d7f652522a928b917e27e2d6d42137dfe2ebfa6fb1c67b26c0254528685f7ebdbe315a68eaa2da769e8a9f42d3e60007c71330926b2c0012d83ead4e4fd1ed872ccd1972201d2b027f3545ac2d30cd78bc1d740feccbc6fc2a0446c6e30eac51f5a69098aa2d447f2085b4e4e4b92ccc26921d2de478518cd090ce267aea2d27ada57fd88b4976d89fb843cdccf49a76ca2679e6801bfa7fb031896fb50629704b9923936bb5dd385311121cadfb11995e59b73034cf67ed03ab813867648d025828087e949a9afd16b95d72d99b1edca257aac132ffb7a0709aed5a9c0ff05fb0f2bbf28409eed7b5f5801be964ced019e1cb7851d3851f10290674e19ffb008b301c4acf641a2bb14216e1d69cabf52b5ef227496b0f30799a855d117fad3744a6fa33503ea798b52ddd7ee5426609dbfcd3f0c13b164d6c051f7ed4a119719a712e388d328402081ff1354b554d2c237afed3b151c4ba8e9f4bdeb8499a3066e26bbc69e8af089dec71731d1dc529eab17ef7374734c0fe475494c83836bdd34a03b9bc89914716061bfb98ec6e61c3ed4438edcaf25243c647086b9ea7018b0d9a8a0b00cecb00abde2498d69c2336101a772cbe4f571523f51bd05882cdf358b849cc140aa1faf22423a12851ce0e33fd48975a4959fa5c5fe418c93908191ab6e741b77bfe02cbd698ee795c466d615619e6441382c6eac01834ee9ab73cea80bbe235c78da91bd79b6f82f899785d68700d393e675c2224d6b7a1ad21320495679adaed70167b50866713a53109db7b6f7d81304ecdfd83b319b1ef248306b45ad29e7ddcc863dac56048b5d69ea175011f7614c00a86a863cde1872a8932878b9ac7e1ac5bda4997b72064f0cd75f4c814e034de11acb9013cf7ea926b4e7eaace070c7ba2188efad2e431e1223d45dd05c4d8403c2e45cee6413ecbe7527e873e455c4e610a61839aacc0bd56d2483e78f298b66a478eb2f558cbafca86be847baeb02c5b216c8cd88fea4df249b09e670a20703abac24b0a91abc4a5646601442ba10becfd30993880051d07f56a05a9379e7a8e6befee3f22faa106398f7706006e42e9be1ef89d25c272f11a95095c587d713732284de9dbd3c7217b0689e21d8eb0ff69668").unwrap();
    let expected_pk_bytes = hex::decode("d7b2b47254aae0db45e7930d4a98d2c97d8f1397d1789dafa17024b316e9bec94fc9946d42f19b79a7413bbaa33e7149cb42ed5115693ac041facb988adeb5fe0e1d8631184995b592c397d2294e2e14f90aa414ba3826899ac43f4cccacbc26e9a832b95118d5cb433cbef9660b00138e0817f61e762ca274c36ad554eb22aac1162e4ab01acba1e38c4efd8f80b65b333d0f72e55dfe71ce9c1ebb9889e7c56106c0fd73803a2aecfeafded7aa3cb2ceda54d12bd8cd36a78cf975943b47abd25e880ac452e5742ed1e8d1a82afa86e590c758c15ae4d2840d92bca1a5090f40496597fca7d8b9513f1a1bda6e950aaa98de467507d4a4f5a4f0599216582c3572f62eda8905ab3581670c4a02777a33e0ca7295fd8f4ff6d1a0a3a7683d65f5f5f7fc60da023e826c5f92144c02f7d1ba1075987553ea9367fcd76d990b7fa99cd45afdb8836d43e459f5187df058479709a01ea6835935fa70460990cd3dc1ba401ba94bab1dde41ac67ab3319dcaca06048d4c4eef27ee13a9c17d0538f430f2d642dc2415660de78877d8d8abc72523978c042e4285f4319846c44126242976844c10e556ba215b5a719e59d0c6b2a96d39859071fdcc2cde7524a7bedae54e85b318e854e8fe2b2f3edfac9719128270aafd1e5044c3a4fdafd9ff31f90784b8e8e4596144a0daf586511d3d9962b9ea95af197b4e5fc60f2b1ed15de3a5bef5f89bdc79d91051d9b2816e74fa54531efdc1cbe74d448857f476bcd58f21c0b653b3b76a4e076a6559a302718555cc63f74859aabab925f023861ca8cd0f7badb2871f67d55326d7451135ad45f4a1ba69118fbb2c8a30eec9392ef3f977066c9add5c710cc647b1514d217d958c7017c3e90fd20c04e674b90486e9370a31a001d32f473979e4906749e7e477fa0b74508f8a5f2378312b83c25bd388ca0b0fff7478baf42b71667edaac97c46b129643e586e5b055a0c211946d4f36e675bed5860fa042a315d9826164d6a9237c35a5fbf495490a5bd4df248b95c4aae7784b605673166ac4245b5b4b082a09e9323e62f2078c5b76783446defd736ad3a3702d49b089844900a61833397bc4419b30d7a97a0b387c1911474c4d41b53e32a977acb6f0ea75db65bb39e59e701e76957def6f2d44559c31a77122b5204e3b5c219f1688b14ed0bc0b801b3e6e82dcd43e9c0e9f41744cd9815bd1bc8820d8bb123f04facd1b1b685dd5a2b1b8dbbf3ed933670f095a180b4f192d08b10b8fabbdfcc2b24518e32eea0a5e0c904ca844780083f3b0cd2d0b8b6af67bc355b9494025dc7b0a78fa80e3a2dbfeb51328851d6078198e9493651ae787ec0251f922ba30e9f51df62a6d72784cf3dd205393176dfa324a512bd94970a36dd34a514a86791f0eb36f0145b09ab64651b4a0313b299611a2a1c48891627598768a3114060ba4443486df51522a1ce88b30985c216f8e6ed178dd567b304a0d4cafba882a28342f17a9aa26ae58db630083d2c358fdf566c3f5d62a428567bc9ea8ce95caa0f35474b0bfa8f339a250ab4dfcf2083be8eefbc1055e18fe15370eecb260566d83ff06b211aaec43ca29b54ccd00f8815a2465ef0b46515cc7e41f3124f09efff739309ab58b29a1459a00bce5038e938c9678f72eb0e4ee5fdaae66d9f8573fc97fc42b4959f4bf8b61d78433e86b0335d6e9191c4d8bf487b3905c108cfd6ac24b0ceb7dcb7cf51f84d0ed687b95eaeb1c533c06f0d97023d92a70825837b59ba6cb7d4e56b0a87c203862ae8f315ba5925e8edefa679369a2202766151f16a965f9f81ece76cc070b55869e4db9784cf05c830b3242c8312").unwrap();

    // Decode and re-encode the sk, make sure you get the same thing
    let expected_sk = MLDSA44PrivateKey::from_bytes(&expected_sk_bytes).unwrap();
    let sk_bytes = expected_sk.sk_encode();
    assert_eq!(sk_bytes.len(), expected_sk_bytes.len());
    assert_eq!(sk_bytes, expected_sk_bytes.as_slice());


    // Decode and re-encode the pk, make sure you get the same thing
    let expected_pk = MLDSA44PublicKey::from_bytes(&expected_pk_bytes).unwrap();
    let pk_bytes = expected_pk.pk_encode();
    assert_eq!(pk_bytes.len(), expected_pk_bytes.len());
    assert_eq!(pk_bytes, expected_pk_bytes.as_slice());


    // run keygen from seed
    let (derived_pk, derived_sk) = MLDSA44::keygen_from_seed(&seed).unwrap();
    let sk_bytes = derived_sk.sk_encode();

    if derived_sk.rho == expected_sk.rho { println!("rho matches") } else { println!("rho does not match") }
    if derived_sk.K == expected_sk.K { println!("K matches") } else { println!("K does not match") }
    if derived_sk.s1.vec[0] == expected_sk.s1.vec[0] { println!("s1[0] matches") } else { println!("s1[0] does not match") }
    if derived_sk.s2.vec[0] == expected_sk.s2.vec[0] { println!("s2[0] matches") } else { println!("s2[0] does not match") }
    if derived_sk.t0.vec[0] == expected_sk.t0.vec[0] { println!("t0[0] matches") }
    else {
        println!("t0[0] does not match:") ;
        println!("derived: {:?}", derived_sk.t0.vec[0]);
        println!("expectd: {:?}", expected_sk.t0.vec[0]);
    }
}