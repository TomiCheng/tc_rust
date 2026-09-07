extern crate std;

use core::convert::Infallible;
use std::vec;
use std::vec::Vec;

use rand_core::{TryCryptoRng, TryRng};
use tc_bigint::BigUint;
use tc_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection};

use super::RsaBlindedEngine;
use crate::{RsaError, RsaKeyParameters, RsaPrivateCrtKeyParameters};

struct SequenceRng(u8);

impl TryRng for SequenceRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0_u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0_u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
        output.fill(self.0);
        self.0 = self.0.wrapping_add(1);
        Ok(())
    }
}

impl TryCryptoRng for SequenceRng {}

fn bigint(value: &str) -> BigUint {
    BigUint::from_str_radix(value, 16).unwrap()
}

#[allow(clippy::chunks_exact_to_as_chunks)]
fn hex_bytes(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digits = core::str::from_utf8(pair).unwrap();
            u8::from_str_radix(digits, 16).unwrap()
        })
        .collect()
}

fn key_1024() -> [BigUint; 8] {
    // Bouncy Castle 的 PKCS #1 v2.1 RSA-PSS 範例 1，使用公開的 1024 位元測試金鑰。
    // https://github.com/bcgit/bc-csharp/blob/master/crypto/test/src/crypto/test/PSSTest.cs
    [
        bigint(
            "a56e4a0e701017589a5187dc7ea841d156f2ec0e36ad52a44dfeb1e61f7ad991d8c51056ffedb162b4c0f283a12a88a394dff526ab7291cbb307ceabfce0b1dfd5cd9508096d5b2b8b6df5d671ef6377c0921cb23c270a70e2598e6ff89d19f105acc2d3f0cb35f29280e1386b6f64c4ef22e1e1f20d0ce8cffb2249bd9a2137",
        ),
        bigint("010001"),
        bigint(
            "33a5042a90b27d4f5451ca9bbbd0b44771a101af884340aef9885f2a4bbe92e894a724ac3c568c8f97853ad07c0266c8c6a3ca0929f1e8f11231884429fc4d9ae55fee896a10ce707c3ed7e734e44727a39574501a532683109c2abacaba283c31b4bd2f53c3ee37e352cee34f9e503bd80c0622ad79c6dcee883547c6a3b325",
        ),
        bigint(
            "e7e8942720a877517273a356053ea2a1bc0c94aa72d55c6e86296b2dfc967948c0a72cbccca7eacb35706e09a1df55a1535bd9b3cc34160b3b6dcd3eda8e6443",
        ),
        bigint(
            "b69dca1cf7d4d7ec81e75b90fcca874abcde123fd2700180aa90479b6e48de8d67ed24f9f19d85ba275874f542cd20dc723e6963364a1f9425452b269a6799fd",
        ),
        bigint(
            "28fa13938655be1f8a159cbaca5a72ea190c30089e19cd274a556f36c4f6e19f554b34c077790427bbdd8dd3ede2448328f385d81b30e8e43b2fffa027861979",
        ),
        bigint(
            "1a8b38f398fa712049898d7fb79ee0a77668791299cdfa09efc0e507acb21ed74301ef5bfd48be455eaeb6e1678255827580a8e4e8e14151d1510a82a3f2e729",
        ),
        bigint(
            "27156aba4126d24a81f3a528cbfb27f56886f840a9f6e86e17a44b94fe9319584b8e22fdde1e5a2e3bd8aa5ba8d8584194eb2190acf832b847f13a3d24a79f4d",
        ),
    ]
}

fn key_2048() -> [BigUint; 8] {
    // C2SP Wycheproof rsa_pkcs1_2048_test.json 第一組金鑰的 JWK 參數。
    // https://github.com/C2SP/wycheproof/blob/main/testvectors_v1/rsa_pkcs1_2048_test.json
    [
        bigint(
            "b3510a2bcd4ce644c5b594ae5059e12b2f054b658d5da5959a2fdf1871b808bc3df3e628d2792e51aad5c124b43bda453dca5cde4bcf28e7bd4effba0cb4b742bbb6d5a013cb63d1aa3a89e02627ef5398b52c0cfd97d208abeb8d7c9bce0bbeb019a86ddb589beb29a5b74bf861075c677c81d430f030c265247af9d3c9140ccb65309d07e0adc1efd15cf17e7b055d7da3868e4648cc3a180f0ee7f8e1e7b18098a3391b4ce7161e98d57af8a947e201a463e2d6bbca8059e5706e9dfed8f4856465ffa712ed1aa18e888d12dc6aa09ce95ecfca83cc5b0b15db09c8647f5d524c0f2e7620a3416b9623cadc0f097af573261c98c8400aa12af38e43cad84d",
        ),
        bigint("010001"),
        bigint(
            "1a502d0eea6c7b69e21d5839101f705456ed0ef852fb47fe21071f54c5f33c8ceb066c62d727e32d26c58137329f89d3195325b795264c195d85472f7507dbd0961d2951f935a26b34f0ac24d15490e1128a9b7138915bc7dbfa8fe396357131c543ae9c98507368d9ceb08c1c6198a3eda7aea185a0e976cd42c22d00f003d9f19d96ea4c9afcbfe1441ccc802cfb0689f59d804c6a4e4f404c15174745ed6cb8bc88ef0b33ba0d2a80e35e43bc90f350052e72016e75b00d357a381c9c0d467069ca660887c987766349fcc43460b4aa516bce079edd87ba164307b752c277ed9528ad3ba0bf1877349ed3b7966a6c240110409bf4d0fade0c68fdadd847fd",
        ),
        bigint(
            "ec125cf37e310a2ff46263b9b2e0629d6390005ec88913d4fb71bd4dd856124498aaeba983d7ba2bd942e64d223feb7a23af4d605efeea6bd70d39afe99d35a3aa15e74a1768778093be0edd4a8d09b2def6dc9b67ff85764625c2e19236db4c401ce30a2572d3ecb4f969b7ad19c522c02d774465676e1a3776c54d6248348b",
        ),
        bigint(
            "c2742abcd9897bd4b0b671f973fc82a8f84abf5705ff88dd41948623afe9dca60dc6543390767feaebeb539576ee8bfa61b5fcbca94a7cef75a09150c540fa9694dd8004ad23718c889049219369c99f4458d4afc148f6f07df87324a96d9cf7b385dd8622414a1832f9f29446f050c2d5a6407649dc41ab70e23b3dcc22c987",
        ),
        bigint(
            "96a9798d250263400bb6277342881627e07cecdf91187b01b89ff47314188a7c20fb24800156d2c85d5666e8df6ceff9f9804ddfad80ff5767de56ecc029c72bf6c717df9f64daafc29acf9dc7908f9a0ad67e20e8949936ccba18d021a2c4febb04349a2b2047c4901385b6e5d0c691d118b33f81802b32ac272ef09e42fad5",
        ),
        bigint(
            "0554f41b0b87f68a45722b3be0cf4ab1e165034c1a91002ab8f29e9ef9e2dab6fee7b2455bafb42037e9d2f7e533f348a147412fd72080be7c2633f5d802c91c39e6bcece3e675e59995033c55737020dad9e8b30d04b828adfb9304ad54a11a35a4f50709876ac5b118236ba76a4d7c9a291dd9607b169de1d182385691999f",
        ),
        bigint(
            "1c640189d9bfe8c623833210a76c420c6f44e5d760e259916cec2ae2b156456960fd95e2747660c389562250f055049cfab7e5c3039549384a7a2aaeb1c824d3af709482a8cf9b587022a00b1f0722db50f33cb26dc20dd2245d5265df61ee2983c938c2167dcee121fc4b4479c237e728cf633ab60a8c0ecd04fce7e3baa559",
        ),
    ]
}

fn crt_params(values: &[BigUint; 8]) -> RsaPrivateCrtKeyParameters<'_> {
    RsaPrivateCrtKeyParameters::new(
        &values[0], &values[1], &values[2], &values[3], &values[4], &values[5], &values[6],
        &values[7],
    )
    .unwrap()
}

fn raw_private(values: &[BigUint; 8], input: &[u8]) -> Result<Vec<u8>, RsaError> {
    let mut engine =
        RsaBlindedEngine::new(SequenceRng(0), CipherDirection::Decrypt, crt_params(values))?;
    let mut output = vec![0_u8; values[0].byte_length()];
    let length = engine.process_block(input, &mut output)?;
    output.truncate(length);
    Ok(output)
}

#[test]
fn published_1024_and_2048_keys_match_fixed_raw_outputs() {
    let key = key_1024();
    let expected = hex_bytes(
        "34d69b59851d5808df4a31190f07cbec1a49416fb60329aebdc7d0bd310183d54a1de34b24dfb602740514eed04d9686247ff1650543f24eac91b744f98f6b054d1caa00d9b296a424f576e1a047bc5f9dec27404043c4677a24a5a17fadde03769ab884fd348b62816669b1b4ef7ca5438f90be00857e34d9b933f73ac0991b",
    );
    assert_eq!(raw_private(&key, &[2]).unwrap(), expected);

    let key = key_2048();
    let expected = hex_bytes(
        "214e2267e82ffe9c70c8fc4daa32ce7c7487f4d9dccaa8dfef3ec0965805d5d79c8f0564853af8bb8c99c07e2632cf1c5fa5b26537e6d7d31c648ec58cd60b8acb2ce7cfd63713af4cde37e1ab7ad8baf6c0f991f6ca68f0d39347e2bece16050e5fbae8e4aa448686b5e0cc1fc42b12c41a1066d2af5dd85ab464025c66eb0a5a0fa4e5f5608e3836e0330ffbf9bb58f858972d992558df4e524cd1a60835ac1953a968bc83ab136bf610c1d5221234f341458524c408fbb28fa4843f5e1e815f68507be966fa9118023d312ed58fb0ca3ec421c0dcba276df1738f5707e4459cbc00535b447c5ad0524d19fa58389d82998fc8956e97b0820c1cbba834c0ca",
    );
    assert_eq!(raw_private(&key, &[2]).unwrap(), expected);
}

#[test]
fn crt_matches_non_crt_and_blinding_does_not_change_the_result() {
    let values = key_1024();
    let private = RsaKeyParameters::new(true, &values[0], &values[2]).unwrap();
    let mut plain_engine =
        RsaBlindedEngine::new(SequenceRng(0), CipherDirection::Decrypt, private).unwrap();
    let mut crt_engine = RsaBlindedEngine::new(
        SequenceRng(0),
        CipherDirection::Decrypt,
        crt_params(&values),
    )
    .unwrap();
    let mut plain = vec![0_u8; 128];
    let mut first = vec![0_u8; 128];
    let mut second = vec![0_u8; 128];

    let plain_len = plain_engine.process_block(&[2], &mut plain).unwrap();
    let first_len = crt_engine.process_block(&[2], &mut first).unwrap();
    let second_len = crt_engine.process_block(&[2], &mut second).unwrap();
    assert_eq!(&first[..first_len], &plain[..plain_len]);
    assert_eq!(&second[..second_len], &plain[..plain_len]);
}

#[test]
fn raw_round_trip_covers_low_high_and_arbitrary_messages() {
    let values = key_1024();
    let public = RsaKeyParameters::new(false, &values[0], &values[1]).unwrap();
    let mut encryptor =
        RsaBlindedEngine::new(SequenceRng(0), CipherDirection::Encrypt, public).unwrap();
    let mut decryptor = RsaBlindedEngine::new(
        SequenceRng(0),
        CipherDirection::Decrypt,
        crt_params(&values),
    )
    .unwrap();
    let messages = [
        BigUint::from(2_u8),
        &values[0] - BigUint::from(2_u8),
        bigint("0123456789abcdef0123456789abcdef"),
    ];

    for message in messages {
        let encoded = message.to_be_bytes();
        let mut ciphertext = vec![0_u8; encryptor.output_block_size()];
        let ciphertext_len = encryptor.process_block(&encoded, &mut ciphertext).unwrap();
        let mut recovered = vec![0_u8; values[0].byte_length()];
        let recovered_len = decryptor
            .process_block(&ciphertext[..ciphertext_len], &mut recovered)
            .unwrap();
        assert_eq!(&recovered[..recovered_len], encoded);
    }
}

fn uneven_key(dp: &BigUint) -> [BigUint; 8] {
    [
        BigUint::from(4087_u16),
        BigUint::from(7_u8),
        BigUint::from(2263_u16),
        BigUint::from(67_u8),
        BigUint::from(61_u8),
        dp.clone(),
        BigUint::from(43_u8),
        BigUint::from(11_u8),
    ]
}

#[test]
fn unequal_factor_width_selects_from_the_larger_factor_and_computes_correctly() {
    let dp = BigUint::from(19_u8);
    let values = uneven_key(&dp);
    assert_eq!(values[3].bits(), values[4].bits() + 1);

    let private = RsaKeyParameters::new(true, &values[0], &values[2]).unwrap();
    let mut plain =
        RsaBlindedEngine::new(SequenceRng(0), CipherDirection::Decrypt, private).unwrap();
    let mut crt = RsaBlindedEngine::new(
        SequenceRng(0),
        CipherDirection::Decrypt,
        crt_params(&values),
    )
    .unwrap();
    assert_eq!(crt.core.bucket_bits(), 1024);

    let mut plain_output = [0_u8; 128];
    let mut crt_output = [0_u8; 128];
    let plain_len = plain.process_block(&[42], &mut plain_output).unwrap();
    let crt_len = crt.process_block(&[42], &mut crt_output).unwrap();
    assert_eq!(&crt_output[..crt_len], &plain_output[..plain_len]);
}

#[test]
fn lenstra_check_rejects_a_one_bit_crt_exponent_fault() {
    let bad_dp = BigUint::from(19_u8).flip_bit(1);
    let values = uneven_key(&bad_dp);
    let mut engine = RsaBlindedEngine::new(
        SequenceRng(0),
        CipherDirection::Decrypt,
        crt_params(&values),
    )
    .unwrap();

    assert_eq!(
        engine.process_block(&[42], &mut [0_u8; 128]),
        Err(RsaError::FaultyDecryptionOrSigning)
    );
}

#[test]
fn block_sizes_boundaries_output_buffer_and_trait_reinitialization_are_checked() {
    let modulus = BigUint::from(4087_u16);
    let exponent = BigUint::from(7_u8);
    let public = RsaKeyParameters::new(false, &modulus, &exponent).unwrap();
    let mut engine =
        RsaBlindedEngine::new(SequenceRng(0), CipherDirection::Encrypt, public).unwrap();

    assert_eq!(engine.input_block_size(), 1);
    assert_eq!(engine.output_block_size(), 2);
    assert_eq!(
        engine.process_block(&[1], &mut [0_u8; 2]),
        Err(RsaError::InputTooSmall)
    );
    assert_eq!(
        engine.process_block(
            &(modulus.clone() - BigUint::from(1_u8)).to_be_bytes(),
            &mut [0_u8; 2]
        ),
        Err(RsaError::InputTooLarge)
    );
    assert_eq!(
        engine.process_block(&[0, 0, 2], &mut [0_u8; 2]),
        Err(RsaError::InputTooLarge)
    );
    assert_eq!(
        engine.process_block(&[2], &mut [0_u8; 1]),
        Err(RsaError::OutputTooShort)
    );

    AsymmetricBlockCipherInit::init(&mut engine, CipherDirection::Decrypt, &public).unwrap();
    assert_eq!(engine.input_block_size(), 2);
    assert_eq!(engine.output_block_size(), 1);
}

#[test]
fn invalid_key_values_preserve_the_public_error_contract() {
    let zero = BigUint::default();
    let even = BigUint::from(4_u8);
    let odd = BigUint::from(3_u8);

    assert_eq!(
        RsaKeyParameters::new(false, &zero, &odd),
        Err(RsaError::InvalidModulus)
    );
    assert_eq!(
        RsaKeyParameters::new(false, &even, &odd),
        Err(RsaError::EvenModulus)
    );
    assert_eq!(
        RsaKeyParameters::new(false, &odd, &zero),
        Err(RsaError::InvalidExponent)
    );
    assert_eq!(
        RsaKeyParameters::new(false, &odd, &even),
        Err(RsaError::EvenPublicExponent)
    );
}
