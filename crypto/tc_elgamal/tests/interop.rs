//! 與 Bouncy Castle 互通：固定私鑰 x，BC 的 `ElGamalEngine` 與
//! `Pkcs1Encoding(ElGamalEngine)` 加密的密文，這裡解密要得到原文。BC 的密文由隨機的 k
//! 產生，所以只能驗證解密方向。

mod common;

use common::{big, decode, from_hex, group14};
use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection};
use tc_asym_encoding::Pkcs1Encoding;
use tc_bigint::BigUint;
use tc_elgamal::{ElGamalEngine, ElGamalPrivateKey};
use tc_modular::{ModPow, NonZero};

const X: &str = "5f3c2a91e8d74b06a1c9e3f27d8b4a65c0f19e2d73a8b5c4e6f0123456789abc";
const Y: &str = "25fbdf291faed488902301e698c905f867a83f908498933fa7ba5efa499f1deb\
    5005730995746fc875409e785a997f44f368d487be6b2530b90792e4248bb82e\
    4c5427d2a07f944fc534df285e0a1db0f39b7f78cf5c055e139bfc1d8dd40b48\
    369a2d4b59a15a1afcf9a51912252631a174a24318fe9ae46137bcc17277a860\
    3fcdb02bd596a442300f2f13951a3b5b84c736c2b9f9fa8b054fc5b12b68b74b\
    bf1ef8bfb495fc234fa4ad328cb6817ebd7717136dc9656f22a073c75a0ea0cf\
    14cc79a502666c6d50352134a3fd94ac09560d1a58ba6e44e28cac6356e8144e\
    7e7fa51adc5983c2dd84f791fc27ecb417f95fa4a4ed3d8dbb3bc5a47607bb5b";
const MESSAGE: &[u8] = b"ElGamal from Bouncy Castle";

fn private_key() -> ElGamalPrivateKey {
    ElGamalPrivateKey::new(from_hex(X), group14())
}

#[test]
fn the_public_value_matches_bouncy_castle() {
    let p = NonZero::new(big(group14().p())).unwrap();
    let y = BigUint::from(2u8).mod_pow(&big(&from_hex(X)), &p);
    assert_eq!(y, big(&from_hex(Y)));
}

#[test]
fn a_raw_ciphertext_from_bouncy_castle_decrypts_to_its_message() {
    let ciphertext = decode(
        "2de6d42700a97000392fe5219e4ff5ae70b671600db0ae0b0101ea4d46864ac4\
        16ef6b81d033a3f58f860b60bb27b1b7109ab6e1221114685bd2dbbfc5f6e32a\
        24602145f0efc9739a42fbca2ec226078a71fb3e3ded8cab5e9711d92ee169bf\
        e7af460a963e64edb34b4e3d12ce8455eeb4a4e27180596ae010f05bd9235a86\
        2e12aa3f3e186dc0fb6de4c85e9d9a82fe777b330c8f78d2d36096cfb1583fdc\
        28fb4f4f82e47fb6ed78aca3e892a63901971409a8dae441ec663c315f38022d\
        a622f6aa854c5a9eb5ff1c4b4f623c8c82c966d4776c6c28622a2641a6ffe1ef\
        e44917b816bb72dfb21b5fdf210ea1e62a7204eb650cd85f021fbacb4d383404\
        59d8001d07da073601714ef53701139a5e60db4572a38068928172086d27f7ba\
        3351dc6dab4c22c0e8f0bd0414e24c6cf0577f799e9c218fb8fc4eaed44fc7d5\
        721d123b35aa67df7aa0394af6a547dac055ffa190b9b7226591d7c97c7b7649\
        264e516919963b891807dd8afbce0388336a3361060e6a63c723beec685d3e6c\
        a0bc364542967a38f868bbf8c781883a6bb0abc996a5b23a73d935175ebc356a\
        4a0acefc3fb811dcdd9d23661d0c201bbd56c8856ee72721108b55203c3bbc69\
        5d638a9f33630b63fd2cc260d4ae0f81c4f40b4a916be5ee4feabc8ffd9cbe8d\
        e1e5ec8cd308bd2dcfede08b5cd895a83a815facf4388f574300326e2ad63a5b",
    );
    let mut engine = ElGamalEngine::new(rand::rng());
    engine
        .init(CipherDirection::Decrypt, &private_key())
        .unwrap();
    let mut output = vec![0; engine.output_block_size()];
    let length = engine.process_block(&ciphertext, &mut output).unwrap();
    assert_eq!(length, 256);
    assert!(output[..length - MESSAGE.len()].iter().all(|&b| b == 0));
    assert_eq!(&output[length - MESSAGE.len()..length], MESSAGE);
}

#[test]
fn a_pkcs1_ciphertext_from_bouncy_castle_decrypts_through_the_encoding() {
    let ciphertext = decode(
        "3c6b6096192157eadf98cc2824ba5690b7f76e9e374cd09464e3dc1e94b51fa9\
        f28a9b36f373fb655e548637d6bf85ac6b1d3add6cb73301ff16daaf8d0bf479\
        906454fae38c2974a1147c0a682c6560a3e8a89491ab77c0e7efafa133ef262d\
        98e49025b6cb6f7edb57439079f85c393b92fa67ecc658856dd859fa2b85bc2c\
        1ea54e83294d417e63d40e241b2d645df1982db11e6cd2ede987cf561625a43a\
        2dd7a5959c1ec5edd895cd64f23788c4b0f9413dc810ddbe973f89fd2b2bc2eb\
        2292aa51c5c86a1e0943f476a7da3aba0f178deceb03ba136336d29953de39cb\
        e23b1db0ce80d9502ef703fce1356d2e7d0a9c0ab5eb383a9f9ec79ebb9c6d10\
        518487b6a9d856b8ee1f84f0d387eba266a22e9b50a7cdee11015239ecb705a2\
        45a054c5e64e7528e205aa769e95791b44c6d44014b2b6cf72cf3e8f028761b8\
        84fd3a1ea2e36e35c47633ae076fb382eae675b90570cbd372f02321b875b5bd\
        546097f9a7a71c718bc1824c50597aba5c16f3ef8833a0b5e7c268434eb462f5\
        5f67564d14cf9a4f65b64291764111db1b85d61323633b22fa73a78d4c137f14\
        9918f0ceb797e756907e721300cbec2f26782f3d16c56b68aaaf98a13ba82a8e\
        9c649e6bf5745c4f80181415d29bf2d2baa8dcf6622618c514377e6d20ed37b9\
        788babf6443a5078c0d3faf5605c46a1b27f6b4c943eb0704f31c2592bc5699f",
    );
    let mut encoding = Pkcs1Encoding::from_parts(ElGamalEngine::new(rand::rng()), rand::rng());
    encoding
        .init(CipherDirection::Decrypt, &private_key())
        .unwrap();
    let mut output = vec![0; encoding.output_block_size()];
    let length = encoding.process_block(&ciphertext, &mut output).unwrap();
    assert_eq!(&output[..length], MESSAGE);
}
