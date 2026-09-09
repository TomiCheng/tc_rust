//! 比較新的 `Padded` 引擎與既有的固定寬度、堆後端。

use tc_cipher::{AsymmetricBlockCipher, CipherDirection};
use tc_rsa::{
    HeapRsaCoreEngine, HeapRsaCrtCoreEngine, PaddedRsaCoreEngine, PaddedRsaCrtCoreEngine,
    Rsa2048Core, Rsa2048CrtCore, RsaCrt, RsaCrtInit, RsaError, RsaInit, RsaKeyRef,
    RsaPrivateCrtKeyRef,
};

/// 以指定引擎跑一次區塊運算，回傳實際輸出。
fn run(engine: &mut impl AsymmetricBlockCipher<Error = RsaError>, input: &[u8]) -> Vec<u8> {
    let mut output = [0_u8; 256];
    let len = engine.process_block(input, &mut output).unwrap();
    output[..len].to_vec()
}

#[test]
fn the_padded_public_engine_agrees_with_both_existing_backends() {
    let values = key_2048();
    let public_key = RsaKeyRef::new(false, &values[0], &values[1]);

    let mut padded = PaddedRsaCoreEngine::default();
    let mut fixed = Rsa2048Core::default();
    let mut heap = HeapRsaCoreEngine::default();
    padded.init(CipherDirection::Encrypt, &public_key).unwrap();
    fixed.init(CipherDirection::Encrypt, &public_key).unwrap();
    heap.init(CipherDirection::Encrypt, &public_key).unwrap();

    for input in [vec![2_u8], vec![0xAB, 0xCD, 0xEF], vec![7_u8; 128]] {
        let expected = run(&mut fixed, &input);
        assert_eq!(run(&mut padded, &input), expected);
        assert_eq!(run(&mut heap, &input), expected);
    }
}

#[test]
fn the_padded_private_engine_agrees_with_both_existing_backends() {
    let values = key_2048();
    let private_key = RsaKeyRef::new(true, &values[0], &values[2]);

    let mut padded = PaddedRsaCoreEngine::default();
    let mut fixed = Rsa2048Core::default();
    let mut heap = HeapRsaCoreEngine::default();
    padded.init(CipherDirection::Decrypt, &private_key).unwrap();
    fixed.init(CipherDirection::Decrypt, &private_key).unwrap();
    heap.init(CipherDirection::Decrypt, &private_key).unwrap();

    let input = vec![2_u8];
    let expected = run(&mut fixed, &input);
    assert_eq!(run(&mut padded, &input), expected);
    assert_eq!(run(&mut heap, &input), expected);
}

#[test]
fn the_padded_crt_engine_agrees_with_both_existing_backends() {
    let values = key_2048();
    let crt_key = RsaPrivateCrtKeyRef::new(
        &values[0], &values[1], &values[2], &values[3], &values[4], &values[5], &values[6],
        &values[7],
    );

    let mut padded = PaddedRsaCrtCoreEngine::default();
    let mut fixed = Rsa2048CrtCore::default();
    let mut heap = HeapRsaCrtCoreEngine::default();
    RsaCrtInit::init(&mut padded, CipherDirection::Decrypt, &crt_key).unwrap();
    RsaCrtInit::init(&mut fixed, CipherDirection::Decrypt, &crt_key).unwrap();
    RsaCrtInit::init(&mut heap, CipherDirection::Decrypt, &crt_key).unwrap();

    let input = vec![2_u8];
    let expected = run(&mut fixed, &input);
    assert_eq!(run(&mut padded, &input), expected);
    assert_eq!(run(&mut heap, &input), expected);
}

#[test]
fn a_public_encryption_round_trips_through_the_padded_crt_engine() {
    let values = key_2048();
    let public_key = RsaKeyRef::new(false, &values[0], &values[1]);
    let crt_key = RsaPrivateCrtKeyRef::new(
        &values[0], &values[1], &values[2], &values[3], &values[4], &values[5], &values[6],
        &values[7],
    );

    let mut encrypt = PaddedRsaCoreEngine::default();
    let mut decrypt = PaddedRsaCrtCoreEngine::default();
    encrypt.init(CipherDirection::Encrypt, &public_key).unwrap();
    RsaCrtInit::init(&mut decrypt, CipherDirection::Decrypt, &crt_key).unwrap();

    let message = vec![0x2A_u8, 0x13, 0x99];
    let ciphertext = run(&mut encrypt, &message);
    assert_eq!(ciphertext.len(), 256);
    assert_eq!(run(&mut decrypt, &ciphertext), message);
}

#[test]
fn blinding_does_not_change_the_result() {
    use tc_rsa::Rsa;

    let values = key_2048();
    let crt_key = RsaPrivateCrtKeyRef::new(
        &values[0], &values[1], &values[2], &values[3], &values[4], &values[5], &values[6],
        &values[7],
    );

    let mut engine = PaddedRsaCrtCoreEngine::default();
    RsaCrtInit::init(&mut engine, CipherDirection::Decrypt, &crt_key).unwrap();

    let input = engine.convert_input(&[2_u8]).unwrap();
    let plain = engine.process_int(&input).unwrap();

    let mut rng = ExampleRng(0x9d1e_4c07_5ab3_268f);
    for round in 0..8 {
        let blinded = engine.process_int_blinded(&input, &mut rng).unwrap();
        assert_eq!(blinded, plain, "round {round}");
    }
}

#[test]
fn an_uninitialised_engine_reports_no_key() {
    use tc_rsa::Rsa;

    let mut core = PaddedRsaCoreEngine::default();
    assert_eq!(core.input_block_size(), 0);
    assert_eq!(core.output_block_size(), 0);
    assert!(matches!(
        core.process_block(&[2], &mut [0; 256]),
        Err(RsaError::NotInitialized)
    ));
    assert!(matches!(
        core.convert_input(&[2]),
        Err(RsaError::NotInitialized)
    ));

    let mut crt = PaddedRsaCrtCoreEngine::default();
    assert_eq!(crt.input_block_size(), 0);
    assert!(matches!(
        crt.process_block(&[2], &mut [0; 256]),
        Err(RsaError::NotInitialized)
    ));
}

#[test]
fn degenerate_inputs_are_rejected() {
    use tc_rsa::Rsa;

    let values = key_2048();
    let public_key = RsaKeyRef::new(false, &values[0], &values[1]);
    let mut engine = PaddedRsaCoreEngine::default();
    engine.init(CipherDirection::Encrypt, &public_key).unwrap();

    assert!(matches!(
        engine.convert_input(&[0]),
        Err(RsaError::InputTooSmall)
    ));
    assert!(matches!(
        engine.convert_input(&[1]),
        Err(RsaError::InputTooSmall)
    ));
    // n 本身與 n-1 都要擋掉。
    assert!(matches!(
        engine.convert_input(&values[0]),
        Err(RsaError::InputTooLarge)
    ));
    let mut modulus_minus_one = values[0].clone();
    let last = modulus_minus_one.len() - 1;
    modulus_minus_one[last] -= 1;
    assert!(matches!(
        engine.convert_input(&modulus_minus_one),
        Err(RsaError::InputTooLarge)
    ));
}

#[test]
fn key_material_is_erased_when_the_engine_is_dropped() {
    fn has_drop_policy<T: tc_bigint::ZeroizeOnDrop>(_: &T) {}
    has_drop_policy(&PaddedRsaCoreEngine::default());
    has_drop_policy(&PaddedRsaCrtCoreEngine::default());
}

/// 固定種子的 xorshift，測試需要可重現。
struct ExampleRng(u64);

impl rand_core::TryRng for ExampleRng {
    type Error = rand_core::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.try_next_u64()? as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        Ok(self.0)
    }

    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in output.chunks_mut(8) {
            let bytes = self.try_next_u64()?.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }
}

impl rand_core::TryCryptoRng for ExampleRng {}

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

fn key_2048() -> [Vec<u8>; 8] {
    // C2SP Wycheproof rsa_pkcs1_2048_test.json 第一組金鑰的 JWK 參數。
    // https://github.com/C2SP/wycheproof/blob/main/testvectors_v1/rsa_pkcs1_2048_test.json
    [
        hex_bytes(
            "b3510a2bcd4ce644c5b594ae5059e12b2f054b658d5da5959a2fdf1871b808bc3df3e628d2792e51aad5c124b43bda453dca5cde4bcf28e7bd4effba0cb4b742bbb6d5a013cb63d1aa3a89e02627ef5398b52c0cfd97d208abeb8d7c9bce0bbeb019a86ddb589beb29a5b74bf861075c677c81d430f030c265247af9d3c9140ccb65309d07e0adc1efd15cf17e7b055d7da3868e4648cc3a180f0ee7f8e1e7b18098a3391b4ce7161e98d57af8a947e201a463e2d6bbca8059e5706e9dfed8f4856465ffa712ed1aa18e888d12dc6aa09ce95ecfca83cc5b0b15db09c8647f5d524c0f2e7620a3416b9623cadc0f097af573261c98c8400aa12af38e43cad84d",
        ),
        hex_bytes("010001"),
        hex_bytes(
            "1a502d0eea6c7b69e21d5839101f705456ed0ef852fb47fe21071f54c5f33c8ceb066c62d727e32d26c58137329f89d3195325b795264c195d85472f7507dbd0961d2951f935a26b34f0ac24d15490e1128a9b7138915bc7dbfa8fe396357131c543ae9c98507368d9ceb08c1c6198a3eda7aea185a0e976cd42c22d00f003d9f19d96ea4c9afcbfe1441ccc802cfb0689f59d804c6a4e4f404c15174745ed6cb8bc88ef0b33ba0d2a80e35e43bc90f350052e72016e75b00d357a381c9c0d467069ca660887c987766349fcc43460b4aa516bce079edd87ba164307b752c277ed9528ad3ba0bf1877349ed3b7966a6c240110409bf4d0fade0c68fdadd847fd",
        ),
        hex_bytes(
            "ec125cf37e310a2ff46263b9b2e0629d6390005ec88913d4fb71bd4dd856124498aaeba983d7ba2bd942e64d223feb7a23af4d605efeea6bd70d39afe99d35a3aa15e74a1768778093be0edd4a8d09b2def6dc9b67ff85764625c2e19236db4c401ce30a2572d3ecb4f969b7ad19c522c02d774465676e1a3776c54d6248348b",
        ),
        hex_bytes(
            "c2742abcd9897bd4b0b671f973fc82a8f84abf5705ff88dd41948623afe9dca60dc6543390767feaebeb539576ee8bfa61b5fcbca94a7cef75a09150c540fa9694dd8004ad23718c889049219369c99f4458d4afc148f6f07df87324a96d9cf7b385dd8622414a1832f9f29446f050c2d5a6407649dc41ab70e23b3dcc22c987",
        ),
        hex_bytes(
            "96a9798d250263400bb6277342881627e07cecdf91187b01b89ff47314188a7c20fb24800156d2c85d5666e8df6ceff9f9804ddfad80ff5767de56ecc029c72bf6c717df9f64daafc29acf9dc7908f9a0ad67e20e8949936ccba18d021a2c4febb04349a2b2047c4901385b6e5d0c691d118b33f81802b32ac272ef09e42fad5",
        ),
        hex_bytes(
            "0554f41b0b87f68a45722b3be0cf4ab1e165034c1a91002ab8f29e9ef9e2dab6fee7b2455bafb42037e9d2f7e533f348a147412fd72080be7c2633f5d802c91c39e6bcece3e675e59995033c55737020dad9e8b30d04b828adfb9304ad54a11a35a4f50709876ac5b118236ba76a4d7c9a291dd9607b169de1d182385691999f",
        ),
        hex_bytes(
            "1c640189d9bfe8c623833210a76c420c6f44e5d760e259916cec2ae2b156456960fd95e2747660c389562250f055049cfab7e5c3039549384a7a2aaeb1c824d3af709482a8cf9b587022a00b1f0722db50f33cb26dc20dd2245d5265df61ee2983c938c2167dcee121fc4b4479c237e728cf633ab60a8c0ecd04fce7e3baa559",
        ),
    ]
}
