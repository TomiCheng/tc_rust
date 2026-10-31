//! `X931Signer`：Bouncy Castle `X931SignerTest` 的往返與三組向量（SHA-1、SHA-224，含以無 CRT
//! 的私鑰簽章）、隱含結尾、BC 的結尾表，以及錯誤。

use num_traits::Num;
use tc_bigint::PaddedBigUint;
use tc_keccak::Sha3Digest;
use tc_rsa::{RsaEngine, RsaKey, RsaKeyOwned, RsaPrivateCrtKeyOwned};
use tc_rsa_signer::{X931Signer, X931SignerError, iso_trailers};
use tc_sha::{Sha1Digest, Sha224Digest, Sha256Digest, Sha512tDigest};
use tc_signer::{Signer, SignerInit};

const N: &str = "8012a1ed8f41bd483fb6d3c82f6eb231cfec5be750c569296e3d8ae16daf0fdd329625b0c328214da3ba97e27c3a5d171224b520783fee989a0e568ef1ca4c8aef43b491e335788da3d3bb9e98b34a59f440c0ea06f71cb8ed53ef016f599f58cfb28cac5c3c3b858f012d8c694f1e0d55abe080f4735c31228d9f6fad5baaad";
const E: &str = "11";
const D: &str = "f11403a10da8ebd34ac18ea5feee7c99ffdb07591082a7d584379c02b058965513ed741f8d78b728bbb9965f07f563ef313609a687ffdf3d5e391b676cc817996d7789c01edbcf1f4d30401f79d721c8ec2347c3d87632b73694cb2ad665109e89921e108a1ad7a5930ee1f2995949bd6e2777fa59a2ab8dc5c16f87a1ff3f1";
const P: &str = "9f52b724d55be00bff5b3b441b45c19185060777cdcb41ab3cf028f75ae8b6ed2050f39e6c030aa0252101fd5f5e17ed43cba2408386e01aefa3a70d76f53a21";
const Q: &str = "cdc97c3efd74d2790376de49c4b33ed5b1c7fb522e2d101c5b64ba1b528b3797764bf91526daee5573c04386287996f36f5b4683714e10f2e1db35222856d70d";
const DP: &str = "257cdfcc6e6ff87b4b24866a60c51e7c97c52eef033ee24668b0fa948ddc6746da6d667fa0f1a825ae621e95f8525ffb977b353c5b2ecb51a1cc274e7657d171";
const DQ: &str = "60d749870ddc9f4801a1598c205459cdf94f0cdb610625b2fdd50c4917c90b1a198d29ebd60cac6472b4d47b5e5756183467303ddaf78f815b39fae2e5ce8351";
const QINV: &str = "2edd20ef0aec36c431b83741f2afeb1fc7d215e0573062ed088a9f39e7358fb14422e600fc00a24438179076b45a037b9cb5d28c7a32eb7d300b94e8abcbef52";
const TEST1_N: &str = "c9be1b28f8caccca65d86cc3c9bbcc13eccc059df3b80bd2292b811eff3aa0dd75e1e85c333b8e3fa9bed53bb20f5359ff4e6900c5e9a388e3a4772a583a79e2299c76582c2b27694b65e9ba22e66bfb817f8b70b22206d7d8ae488c86dbb7137c26d5eff9b33c90e6cee640630313b7a715802e15142fef498c404a8de19674974785f0f852e2d470fe85a2e54ffca9f5851f672b71df691785a5cdabe8f14aa628942147de7593b2cf962414a5b59c632c4e14f1768c0ab2e9250824beea60a3529f11bf5e070ce90a47686eb0be1086fb21f0827f55295b4a48307db0b048c05a4aec3f488c576ca6f1879d354224c7e84cbcd8e76dd217a3de54dba73c35";
const TEST1_E: &str = "e75b1b";
const TEST1_MSG: &str = "5bb0d1c0ef9b5c7af2477fe08d45523d3842a4b2db943f7033126c2a7829bacb3d2cfc6497ec91688189e81b7f8742488224ba320ce983ce9480722f2cc5bc42611f00bb6311884f660ccc244788378673532edb05284fd92e83f6f6dab406209032e6af9a33c998677933e32d6fb95fd27408940d7728f9c9c40267ca1d20ce";
const TEST1_SIG: &str = "0fe8bb8e3109a1eb7489ef35bf4c1a0780071da789c8bd226a4170538eafefdd30b732d628f0e87a0b9450051feae9754d4fb61f57862d10f0bacc4f660d13281d0cd1141c006ade5186ff7d961a4c6cd0a4b352fc1295c5afd088f80ac1f8e192ef116a010a442655fe8ff5eeacea15807906fb0f0dfa86e680d4c005872357f7ece9aa4e20b15d5f709b30f08648ecaa34f2fbf54eb6b414fa2ff6f87561f70163235e69ccb4ac82a2e46d3be214cc2ef5263b569b2d8fd839b21a9e102665105ea762bda25bb446cfd831487a6b846100dee113ae95ae64f4af22c428c87bab809541c962bb3a56d4c86588e0af4ebc7fcc66dadced311051356d3ea745f7";
const TEST2_N: &str = "b746ba6c3c0be64bbe33aa55b2929b0af4e86d773d44bfe5914db9287788c4663984b61a418d2eecca30d752ff6b620a07ec72eeb2b422d2429da352407b99982800b9dd7697be6a7b1baa98ca5f4fc2fe33400f20b9dba337ac25c987804165d4a6e0ee4d18eabd6de5abdfe578cae6713ff91d16c80a5bb20217fe614d9509e75a43e1825327b9da8f0a9f6eeaa1c04b69fb4bacc073569fff4ab491becbe6d0441d437fc3fa823239c4a0f75321666b68dd3f66e2dd394089a15bcc288a68a4eb0a48e17d639743b9dea0a91cc35820544732aff253f8ca9967c609dc01c2f8cd0313a7a91cfa94ff74289a1d2b6f19d1811f4b9a65f4cce9e5759b4cc64f";
const TEST2_E: &str = "dcbbdb";
const TEST2_MSG: &str = "a5d3c8a060f897bbbc20ae0955052f37fbc70986b6e11c65075c9f457142bfa93856897c69020aa81a91b5e4f39e05cdeecc63395ab849c8262ca8bc5c96870aecb8edb0aba0024a9bdb71e06de6100344e5c318bc979ef32b8a49a8278ba99d4861bce42ebbc5c8c666aaa6cac39aff8779f2cae367620f9edd4cb1d80b6c8c";
const TEST2_SIG: &str = "39fbbd1804c689a533b0043f84da0f06081038c0fbf31e443e46a05e58f50de5198bbca40522afefaba3aed7082a6cb93b1da39f1f5a42246bf64930781948d300549bef0f8d554ecfca60a1b1ecba95a7014ee4545ad4f0c4e3a31942c6738b4ccd6244b6a21267dadf0826a5f713f13b1f5a9ab8501d957a26d4948278ac67851071a315674bdab173bfef2c2690c8373da6bf3d69f30c0e5da8883de872f59521b40793854085641adf98d13db991c5d0a8aaa0222934fa33332e90ef0b954e195cb267d6ffb36c96e14d1ec7b915a87598b4461a3146566354dc2ae748c84ee0cd46543b53ebff8cdf47725b280a1f799fb6ebb4a31ad2bdd5178250f83a";
const TEST3_N: &str = "dcb5686a3d2063a3f9cf7b9b32d2d3765b4c449b09b4960245a9111cd3b0cbd3260496885b8e1fa5db33b03efcc759d9c1afe29d93c6faebc7e0efada334b5b9a29655e2da2c8f11103d8203be311feab7ae88e9f1b2ec7d8fc655d77202b1681dd9717ec0f525b35584987e19539635a1ed23ca482a00149c609a23dc1645fd";
const TEST3_E: &str = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000dc9f7";
const TEST3_D: &str = "189d6345099098992e0c9ca5f281e1338092342fa0acc85cc2a111f30f9bd2fb4753cd1a48ef0ddca9bf1af33ec76fb2e23a9fb4896c26f2235b516f7c05ef7ae81e70f4b491a5fedba9b935e9c76d761a813ce7776ff8a1e5efe1166ff2eca26aa900da88c908d51af9de26977fe39719cc781df32216fa41b838f0c63803c3";
const TEST3_MSG: &str = "911475c6e210ef4ac65b6fe8d2bfe5e01b959771b137c4ef69b88716e0d2ff9ebc1fad0f358c1dd7d50cc99a7b893ac9a6207076f08d8467d9e48c69c683bfe64a44dabaa3f7c243880f6ab7229bf7bb587822314fc5de5131983bfb2eef8b4bc1eac36f353724b567cd1ae8cddd64ddb7057549d5c81ad5fa3b5e751f00abf5";
const TEST3_SIG: &str = "02c50ec0ac8a7f38ef5630c396964d6a6daaa7e3083ab5b57fa2a2632f3b70e2e85c8456cd774d45d7e44fcb063f0f04fff9f1e3adfda11272535a92cb59320b190b5ee4261f23d6ceaa925df3a7bfa42e26bf61ea9645d9d64b3c90a820802768a6e209c9f83705375a3867afccc037e8242a98fa4c3db6b2d9877754d47289";

const MESSAGE: &[u8] = &[1, 6, 3, 32, 7, 43, 2, 5, 7, 78, 4, 23];

fn int(hex: &str) -> PaddedBigUint {
    PaddedBigUint::from_str_radix(hex, 16).unwrap()
}

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn public_key(n: &str, e: &str) -> RsaKey {
    RsaKeyOwned::new(false, int(n), int(e)).into()
}

fn crt_key() -> RsaKey {
    RsaPrivateCrtKeyOwned::new(
        int(N),
        int(E),
        int(D),
        int(P),
        int(Q),
        int(DP),
        int(DQ),
        int(QINV),
    )
    .into()
}

fn sign<S: Signer + SignerInit<RsaKey>>(mut signer: S, key: &RsaKey, message: &[u8]) -> Vec<u8>
where
    <S as Signer>::Error: core::fmt::Debug,
    <S as SignerInit<RsaKey>>::Error: core::fmt::Debug,
{
    signer.init(key).unwrap();
    signer.update(message).unwrap();
    let mut signature = vec![0; signer.max_signature_size()];
    let length = signer.generate_signature(&mut signature).unwrap();
    signature.truncate(length);
    signature
}

fn verify<S: Signer + SignerInit<RsaKey>>(
    mut signer: S,
    key: &RsaKey,
    message: &[u8],
    signature: &[u8],
) -> bool
where
    <S as Signer>::Error: core::fmt::Debug,
    <S as SignerInit<RsaKey>>::Error: core::fmt::Debug,
{
    signer.init(key).unwrap();
    signer.update(message).unwrap();
    signer.verify_signature(signature).unwrap()
}

#[test]
fn a_crt_key_signs_and_its_public_key_verifies() {
    let signer = || X931Signer::new(RsaEngine::new(), Sha1Digest::default());
    let signature = sign(signer(), &crt_key(), MESSAGE);
    assert_eq!(signature.len(), 128);
    assert!(verify(signer(), &public_key(N, E), MESSAGE, &signature));
    assert!(!verify(
        signer(),
        &public_key(N, E),
        &MESSAGE[1..],
        &signature
    ));
}

#[test]
fn the_three_vectors_of_bouncy_castle_verify_and_the_third_signs() {
    let sha1 = || X931Signer::new(RsaEngine::new(), Sha1Digest::default());
    assert!(verify(
        sha1(),
        &public_key(TEST1_N, TEST1_E),
        &bytes(TEST1_MSG),
        &bytes(TEST1_SIG)
    ));
    assert!(verify(
        X931Signer::new(RsaEngine::new(), Sha224Digest::default()),
        &public_key(TEST2_N, TEST2_E),
        &bytes(TEST2_MSG),
        &bytes(TEST2_SIG)
    ));

    let private_key: RsaKey = RsaKeyOwned::new(true, int(TEST3_N), int(TEST3_D)).into();
    let signature = sign(sha1(), &private_key, &bytes(TEST3_MSG));
    assert_eq!(signature, bytes(TEST3_SIG));
    assert!(verify(
        sha1(),
        &public_key(TEST3_N, TEST3_E),
        &bytes(TEST3_MSG),
        &signature
    ));
}

#[test]
fn an_implicit_trailer_does_not_verify_as_an_explicit_one() {
    let implicit = || X931Signer::implicit(RsaEngine::new(), Sha256Digest::default());
    let explicit = || X931Signer::new(RsaEngine::new(), Sha256Digest::default());
    let signature = sign(implicit(), &crt_key(), MESSAGE);
    assert!(verify(implicit(), &public_key(N, E), MESSAGE, &signature));
    assert!(!verify(explicit(), &public_key(N, E), MESSAGE, &signature));
}

#[test]
fn the_trailer_table_follows_bouncy_castle() {
    assert_eq!(iso_trailers::trailer("SHA-1"), Some(0x33CC));
    assert_eq!(iso_trailers::trailer("sha-512/256"), Some(0x40CC));
    assert_eq!(iso_trailers::trailer("Whirlpool"), Some(0x37CC));
    assert_eq!(iso_trailers::trailer("SHA3-256"), None);
    let signature = sign(
        X931Signer::new(RsaEngine::new(), Sha512tDigest::new(224)),
        &crt_key(),
        MESSAGE,
    );
    assert!(verify(
        X931Signer::new(RsaEngine::new(), Sha512tDigest::new(224)),
        &public_key(N, E),
        MESSAGE,
        &signature
    ));
}

#[test]
fn errors_are_reported() {
    let mut signer = X931Signer::new(RsaEngine::new(), Sha1Digest::default());
    assert_eq!(signer.update(b"x"), Err(X931SignerError::NotInitialized));
    signer.init(&public_key(N, E)).unwrap();
    assert_eq!(
        signer.generate_signature(&mut [0; 128]),
        Err(X931SignerError::NotForSigning)
    );
    signer.init(&crt_key()).unwrap();
    assert_eq!(
        signer.verify_signature(&[0; 128]),
        Err(X931SignerError::NotForVerifying)
    );

    // SHA3 沒有 ISO/IEC 10118 代號，只能用隱含結尾。
    let mut sha3 = X931Signer::new(RsaEngine::new(), Sha3Digest::new(256));
    assert!(matches!(
        sha3.init(&crt_key()),
        Err(X931SignerError::NoTrailer)
    ));
    let mut sha3 = X931Signer::implicit(RsaEngine::new(), Sha3Digest::new(256));
    assert!(sha3.init(&crt_key()).is_ok());

    let mut verifier = X931Signer::new(RsaEngine::new(), Sha1Digest::default());
    verifier.init(&public_key(N, E)).unwrap();
    assert!(!verifier.verify_signature(&[0xff; 128]).unwrap());
}
