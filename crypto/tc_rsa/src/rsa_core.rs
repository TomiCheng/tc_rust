//! RSA 核心運算的後端實作。

use tc_bigint::limbs_for_bits;

use crate::{RsaError, RsaKeyParams};

mod fixed;
mod heap;

pub use fixed::FixedRsaCoreEngine;
pub use heap::HeapRsaCoreEngine;

/// 大端序位元組所代表的位元長度；全零（含空切片）回 0。
pub(crate) fn bit_length(bytes: &[u8]) -> usize {
    let mut rest = bytes.iter().skip_while(|byte| **byte == 0);
    match rest.next() {
        None => 0,
        Some(top) => (8 - top.leading_zeros() as usize) + rest.count() * 8,
    }
}

/// 位元組是否代表零；空切片視為零。
pub(crate) fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

/// 位元組代表的整數是否為奇數；空切片是零，因此為偶數。
pub(crate) fn is_odd(bytes: &[u8]) -> bool {
    bytes.last().is_some_and(|byte| byte & 1 == 1)
}

/// 檢查金鑰參數的位元組是否構成可用的 RSA 金鑰，通過則回傳模數的位元長度。
///
/// 只做位元組層次的判斷：模數非零且為奇數、指數非零且為奇數。是否放得進
/// `FixedBigUint<N>` 由後續轉換負責，質因數篩選與模數合成性檢查則待
/// `tc_bigint` 質數模組整合後補上。
///
/// 這些檢查原本在 `RsaKeyRef::new` 做；照專案慣例，參數型別只是位元組容器，
/// 有效性一律在 `init` 判定。
/// 檢查金鑰參數的位元組是否構成可用的 RSA 金鑰，通過則回傳模數的位元長度。
///
/// 只做位元組層次的判斷：模數非零且為奇數、指數非零且為奇數。是否放得進
/// `FixedBigUint<N>` 由後續轉換負責，質因數篩選與模數合成性檢查則待
/// `tc_bigint` 質數模組整合後補上。
///
/// 這些檢查原本在 `RsaKeyRef::new` 做；照專案慣例，參數型別只是位元組容器，
/// 有效性一律在 `init` 判定。
pub(crate) fn validate<K: RsaKeyParams + ?Sized>(key: &K) -> Result<usize, RsaError> {
    let modulus = key.modulus();
    if is_zero(modulus) {
        return Err(RsaError::InvalidModulus);
    }
    if !is_odd(modulus) {
        return Err(RsaError::EvenModulus);
    }

    let exponent = key.exponent();
    let is_private = key.is_private_key();
    if is_zero(exponent) {
        return Err(if is_private {
            RsaError::InvalidPrivateExponent
        } else {
            RsaError::InvalidExponent
        });
    }
    if !is_odd(exponent) {
        // 私鑰的 d 必為奇數：e 為奇數且 d*e ≡ 1 (mod λ(n))，λ(n) 為偶數。
        return Err(if is_private {
            RsaError::InvalidPrivateExponent
        } else {
            RsaError::EvenPublicExponent
        });
    }

    Ok(bit_length(modulus))
}

/// 模數上限 1024 位元的核心。
pub type Rsa1024Core = FixedRsaCoreEngine<{ limbs_for_bits(1024) }>;

/// 模數上限 2048 位元的核心。
pub type Rsa2048Core = FixedRsaCoreEngine<{ limbs_for_bits(2048) }>;

/// 模數上限 3072 位元的核心。
pub type Rsa3072Core = FixedRsaCoreEngine<{ limbs_for_bits(3072) }>;

/// 模數上限 4096 位元的核心。
pub type Rsa4096Core = FixedRsaCoreEngine<{ limbs_for_bits(4096) }>;

#[cfg(test)]
mod tests {
    use tc_cipher::CipherDirection;

    use super::fixed::FixedRsaCoreEngine;
    use super::heap::HeapRsaCoreEngine;
    use super::validate;
    use super::{bit_length, is_odd, is_zero};
    use alloc::vec;
    use alloc::vec::Vec;

    use crate::RsaBlindedEngine;
    use crate::rsa_crt::{FixedRsaCrtCoreEngine, HeapRsaCrtCoreEngine};
    use crate::{Rsa1024Core, Rsa1024CrtCore, Rsa2048Core, Rsa2048CrtCore};
    use crate::{RsaCrt, RsaCrtInit, RsaKeyOwned, RsaPrivateCrtKeyOwned, RsaPrivateCrtKeyRef};
    use core::convert::Infallible;

    use rand_core::{TryCryptoRng, TryRng};

    use crate::RsaError;

    /// 決定性的測試亂數來源；盲化只要求可用，不要求隨機品質。
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
            for byte in output {
                self.0 = self.0.wrapping_add(1);
                *byte = self.0;
            }
            Ok(())
        }
    }

    impl TryCryptoRng for SequenceRng {}

    use tc_cipher::AsymmetricBlockCipher;

    use crate::{Rsa, RsaInit, RsaKeyRef as Key};

    #[test]
    fn bit_length_ignores_leading_zeros() {
        assert_eq!(bit_length(&[]), 0);
        assert_eq!(bit_length(&[0, 0, 0]), 0);
        assert_eq!(bit_length(&[1]), 1);
        assert_eq!(bit_length(&[0xff]), 8);
        assert_eq!(bit_length(&[0x00, 0x05]), bit_length(&[0x05]));
        assert_eq!(bit_length(&[0x01, 0x00]), 9);
        assert_eq!(bit_length(&[0x00, 0x80, 0x00]), 16);
    }

    #[test]
    fn zero_and_parity_follow_the_byte_contract() {
        assert!(is_zero(&[]));
        assert!(is_zero(&[0, 0]));
        assert!(!is_zero(&[0, 1]));

        assert!(!is_odd(&[]));
        assert!(!is_odd(&[0]));
        assert!(is_odd(&[3]));
        assert!(!is_odd(&[0xff, 0x02]));
        assert!(is_odd(&[0x00, 0x01]));
    }

    /// 一組最小的合法值：模數 4087 = 0x0ff7，公開指數 7。
    const MODULUS: [u8; 2] = [0x0f, 0xf7];
    const EXPONENT: [u8; 1] = [7];

    #[test]
    fn accepts_odd_modulus_with_odd_exponent() {
        assert_eq!(validate(&Key::new(false, &MODULUS, &EXPONENT)), Ok(12));
        assert_eq!(validate(&Key::new(true, &MODULUS, &EXPONENT)), Ok(12));
    }

    #[test]
    fn leading_zeros_do_not_change_the_verdict() {
        let padded = [0x00, 0x00, 0x0f, 0xf7];
        assert_eq!(validate(&Key::new(false, &padded, &[0x00, 0x07])), Ok(12));
    }

    #[test]
    fn rejects_a_zero_or_even_modulus() {
        assert_eq!(
            validate(&Key::new(false, &[], &EXPONENT)),
            Err(RsaError::InvalidModulus)
        );
        assert_eq!(
            validate(&Key::new(false, &[0, 0], &EXPONENT)),
            Err(RsaError::InvalidModulus)
        );
        assert_eq!(
            validate(&Key::new(false, &[0x0f, 0xf6], &EXPONENT)),
            Err(RsaError::EvenModulus)
        );
    }

    #[test]
    fn exponent_errors_depend_on_whether_the_key_is_private() {
        assert_eq!(
            validate(&Key::new(false, &MODULUS, &[0])),
            Err(RsaError::InvalidExponent)
        );
        assert_eq!(
            validate(&Key::new(true, &MODULUS, &[0])),
            Err(RsaError::InvalidPrivateExponent)
        );
        assert_eq!(
            validate(&Key::new(false, &MODULUS, &[4])),
            Err(RsaError::EvenPublicExponent)
        );
        assert_eq!(
            validate(&Key::new(true, &MODULUS, &[4])),
            Err(RsaError::InvalidPrivateExponent)
        );
    }

    /// 以 4087 = 0x0ff7 為模數建一個單 limb 的核心。
    fn engine(direction: CipherDirection) -> FixedRsaCoreEngine<1> {
        fixed_engine(direction, &Key::new(false, &MODULUS, &EXPONENT))
    }

    /// 以 `Default` 建立再 `init`，這是引擎唯一的金鑰入口。
    fn fixed_engine(direction: CipherDirection, key: &Key<'_>) -> FixedRsaCoreEngine<1> {
        let mut engine = FixedRsaCoreEngine::<1>::default();
        engine.init(direction, key).unwrap();
        engine
    }

    fn heap_engine(direction: CipherDirection, key: &Key<'_>) -> HeapRsaCoreEngine {
        let mut engine = HeapRsaCoreEngine::default();
        engine.init(direction, key).unwrap();
        engine
    }

    fn heap_error(key: &Key<'_>) -> Option<RsaError> {
        let mut engine = HeapRsaCoreEngine::default();
        RsaInit::init(&mut engine, CipherDirection::Encrypt, key).err()
    }

    #[test]
    fn convert_input_rejects_the_trivial_and_out_of_range_values() {
        let engine = engine(CipherDirection::Encrypt);

        assert_eq!(engine.convert_input(&[0]), Err(RsaError::InputTooSmall));
        assert_eq!(engine.convert_input(&[1]), Err(RsaError::InputTooSmall));
        assert_eq!(
            engine.convert_input(&[0x0f, 0xf6]),
            Err(RsaError::InputTooLarge)
        );
        assert_eq!(
            engine.convert_input(&[0x0f, 0xf7]),
            Err(RsaError::InputTooLarge)
        );
        assert!(engine.convert_input(&[2]).is_ok());
    }

    #[test]
    fn convert_output_pads_when_encrypting_and_trims_when_decrypting() {
        let value = engine(CipherDirection::Encrypt)
            .convert_input(&[2])
            .unwrap();

        let mut buffer = [0xaa_u8; 4];
        assert_eq!(
            engine(CipherDirection::Encrypt).convert_output(&value, &mut buffer),
            Ok(2)
        );
        assert_eq!(buffer[..2], [0x00, 0x02]);

        let mut buffer = [0xaa_u8; 4];
        assert_eq!(
            engine(CipherDirection::Decrypt).convert_output(&value, &mut buffer),
            Ok(1)
        );
        assert_eq!(buffer[0], 0x02);
    }

    #[test]
    fn convert_output_reports_a_short_buffer() {
        let value = engine(CipherDirection::Encrypt)
            .convert_input(&[2])
            .unwrap();

        assert_eq!(
            engine(CipherDirection::Encrypt).convert_output(&value, &mut [0_u8; 1]),
            Err(RsaError::OutputTooShort)
        );
    }

    #[test]
    fn public_and_private_exponents_round_trip() {
        // 4087 = 61 * 67，λ(4087) = lcm(60, 66) = 660，7 * 2263 ≡ 1 (mod 660)。
        const PRIVATE_EXPONENT: [u8; 2] = [0x08, 0xd7];

        let mut public = fixed_engine(
            CipherDirection::Encrypt,
            &Key::new(false, &MODULUS, &EXPONENT),
        );
        let mut private = fixed_engine(
            CipherDirection::Decrypt,
            &Key::new(true, &MODULUS, &PRIVATE_EXPONENT),
        );

        for message in [&[2_u8][..], &[42][..], &[0x0f, 0xf5][..]] {
            let plain = public.convert_input(message).unwrap();
            let cipher = public.process_int(&plain).unwrap();
            let recovered = private.process_int(&cipher).unwrap();
            assert_eq!(recovered, plain);

            let mut output = [0_u8; 2];
            let length = private.convert_output(&recovered, &mut output).unwrap();
            assert_eq!(&output[..length], message);
        }
    }

    #[test]
    fn the_heap_backend_matches_the_fixed_backend() {
        const PRIVATE_EXPONENT: [u8; 2] = [0x08, 0xd7];

        let mut fixed_public = fixed_engine(
            CipherDirection::Encrypt,
            &Key::new(false, &MODULUS, &EXPONENT),
        );
        let mut heap_public = heap_engine(
            CipherDirection::Encrypt,
            &Key::new(false, &MODULUS, &EXPONENT),
        );
        let mut heap_private = heap_engine(
            CipherDirection::Decrypt,
            &Key::new(true, &MODULUS, &PRIVATE_EXPONENT),
        );

        assert_eq!(
            heap_public.input_block_size(),
            fixed_public.input_block_size()
        );
        assert_eq!(
            heap_public.output_block_size(),
            fixed_public.output_block_size()
        );

        for message in [&[2_u8][..], &[42][..], &[0x0f, 0xf5][..]] {
            let mut from_fixed = [0_u8; 2];
            let plain = fixed_public.convert_input(message).unwrap();
            let cipher = fixed_public.process_int(&plain).unwrap();
            let fixed_len = fixed_public
                .convert_output(&cipher, &mut from_fixed)
                .unwrap();

            let mut from_heap = [0_u8; 2];
            let plain = heap_public.convert_input(message).unwrap();
            let cipher = heap_public.process_int(&plain).unwrap();
            let heap_len = heap_public.convert_output(&cipher, &mut from_heap).unwrap();

            assert_eq!(&from_heap[..heap_len], &from_fixed[..fixed_len]);

            let mut recovered = [0_u8; 2];
            let cipher = heap_private.convert_input(&from_heap[..heap_len]).unwrap();
            let plain = heap_private.process_int(&cipher).unwrap();
            let length = heap_private.convert_output(&plain, &mut recovered).unwrap();
            assert_eq!(&recovered[..length], message);
        }
    }

    #[test]
    fn the_heap_backend_shares_the_key_validation() {
        assert_eq!(
            heap_error(&Key::new(false, &[0x0f, 0xf6], &EXPONENT)),
            Some(RsaError::EvenModulus)
        );
        assert_eq!(
            heap_error(&Key::new(false, &MODULUS, &[4])),
            Some(RsaError::EvenPublicExponent)
        );
    }

    #[test]
    fn an_uninitialised_engine_reports_no_capacity() {
        let fixed = FixedRsaCoreEngine::<1>::default();
        let heap = HeapRsaCoreEngine::default();

        assert_eq!(fixed.input_block_size(), 0);
        assert_eq!(fixed.output_block_size(), 0);
        assert_eq!(fixed.convert_input(&[2]), Err(RsaError::NotInitialized));
        assert_eq!(heap.input_block_size(), 0);
        assert_eq!(heap.output_block_size(), 0);
        assert_eq!(heap.convert_input(&[2]), Err(RsaError::NotInitialized));
    }

    #[test]
    fn a_failed_init_leaves_the_previous_key_in_place() {
        let mut engine = fixed_engine(
            CipherDirection::Encrypt,
            &Key::new(false, &MODULUS, &EXPONENT),
        );
        let before = engine.input_block_size();

        assert_eq!(
            RsaInit::init(
                &mut engine,
                CipherDirection::Decrypt,
                &Key::new(false, &[0x0f, 0xf6], &EXPONENT)
            ),
            Err(RsaError::EvenModulus)
        );
        assert_eq!(engine.input_block_size(), before);
    }

    /// 4087 = 61 * 67 的完整 CRT 私鑰：e=7、d=2263、dp=19、dq=43、qInv=11。
    fn crt_key() -> RsaPrivateCrtKeyRef<'static> {
        const PRIVATE_EXPONENT: [u8; 2] = [0x08, 0xd7];
        RsaPrivateCrtKeyRef::new(
            &MODULUS,
            &EXPONENT,
            &PRIVATE_EXPONENT,
            &[67],
            &[61],
            &[19],
            &[43],
            &[11],
        )
    }

    fn crt_engine() -> FixedRsaCrtCoreEngine<2, 1> {
        let mut engine = FixedRsaCrtCoreEngine::<2, 1>::default();
        engine.init(CipherDirection::Decrypt, &crt_key()).unwrap();
        engine
    }

    #[test]
    fn the_crt_backend_matches_the_plain_private_exponent() {
        const PRIVATE_EXPONENT: [u8; 2] = [0x08, 0xd7];

        let mut plain = fixed_engine(
            CipherDirection::Decrypt,
            &Key::new(true, &MODULUS, &PRIVATE_EXPONENT),
        );
        let mut crt = crt_engine();
        let mut rng = SequenceRng(0);

        for message in [&[2_u8][..], &[42][..], &[0x0f, 0xf5][..]] {
            // 兩個引擎的整數寬度不同（1 vs 2 limb），所以比對輸出位元組。
            let mut expected = [0_u8; 2];
            let value = plain.convert_input(message).unwrap();
            let result = plain.process_int(&value).unwrap();
            let expected_len = plain.convert_output(&result, &mut expected).unwrap();

            let value = crt.convert_input(message).unwrap();

            let mut plain_crt = [0_u8; 2];
            let result = crt.process_int(&value).unwrap();
            let length = crt.convert_output(&result, &mut plain_crt).unwrap();
            assert_eq!(&plain_crt[..length], &expected[..expected_len]);

            let mut blinded = [0_u8; 2];
            let result = crt.process_int_blinded(&value, &mut rng).unwrap();
            let length = crt.convert_output(&result, &mut blinded).unwrap();
            assert_eq!(&blinded[..length], &expected[..expected_len]);
        }
    }

    #[test]
    fn the_crt_backend_rejects_a_faulty_exponent() {
        const PRIVATE_EXPONENT: [u8; 2] = [0x08, 0xd7];
        // dp 從 19 翻成 17，單邊的 CRT 結果就會錯，必須被 Lenstra 檢查擋下。
        let key = RsaPrivateCrtKeyRef::new(
            &MODULUS,
            &EXPONENT,
            &PRIVATE_EXPONENT,
            &[67],
            &[61],
            &[17],
            &[43],
            &[11],
        );
        let mut engine = FixedRsaCrtCoreEngine::<2, 1>::default();
        engine.init(CipherDirection::Decrypt, &key).unwrap();

        let value = engine.convert_input(&[42]).unwrap();
        assert_eq!(
            engine.process_int(&value),
            Err(RsaError::FaultyDecryptionOrSigning)
        );
    }

    #[test]
    fn an_uninitialised_crt_engine_reports_no_capacity() {
        let engine = FixedRsaCrtCoreEngine::<2, 1>::default();

        assert_eq!(engine.input_block_size(), 0);
        assert_eq!(engine.output_block_size(), 0);
        assert_eq!(engine.convert_input(&[2]), Err(RsaError::NotInitialized));
    }

    fn heap_crt_engine() -> HeapRsaCrtCoreEngine {
        let mut engine = HeapRsaCrtCoreEngine::default();
        engine.init(CipherDirection::Decrypt, &crt_key()).unwrap();
        engine
    }

    #[test]
    fn the_heap_crt_backend_matches_the_fixed_crt_backend() {
        for direction in [CipherDirection::Encrypt, CipherDirection::Decrypt] {
            let mut fixed = FixedRsaCrtCoreEngine::<2, 1>::default();
            let mut heap = HeapRsaCrtCoreEngine::default();
            fixed.init(direction, &crt_key()).unwrap();
            heap.init(direction, &crt_key()).unwrap();
            assert_eq!(heap.input_block_size(), fixed.input_block_size());
            assert_eq!(heap.output_block_size(), fixed.output_block_size());

            for message in [&[2_u8][..], &[42][..], &[0x0f, 0xf5][..]] {
                // 兩個後端的整數型別不同，所以比對轉換後的輸出位元組。
                let value = fixed.convert_input(message).unwrap();
                let result = fixed.process_int(&value).unwrap();
                let mut expected = [0_u8; 2];
                let expected_len = fixed.convert_output(&result, &mut expected).unwrap();

                let value = heap.convert_input(message).unwrap();
                let result = heap.process_int(&value).unwrap();
                let mut output = [0_u8; 2];
                let length = heap.convert_output(&result, &mut output).unwrap();
                assert_eq!(&output[..length], &expected[..expected_len]);
            }
        }
    }

    #[test]
    fn heap_crt_blinding_does_not_change_the_result() {
        let mut engine = heap_crt_engine();
        let mut rng = SequenceRng(0);

        for message in [&[2_u8][..], &[42][..], &[0x0f, 0xf5][..]] {
            let input = engine.convert_input(message).unwrap();
            let expected = engine.process_int(&input).unwrap();
            let first = engine.process_int_blinded(&input, &mut rng).unwrap();
            let second = engine.process_int_blinded(&input, &mut rng).unwrap();
            assert_eq!(first, expected);
            assert_eq!(second, expected);
        }
        // 確認盲化路徑確實使用了呼叫端的亂數來源。
        assert_ne!(rng.0, 0);
    }

    #[test]
    fn the_heap_crt_backend_rejects_a_faulty_exponent() {
        let valid = crt_key();
        // dp 從 19 翻成 17，兩條運算路徑都必須被 Lenstra 檢查擋下。
        let key = RsaPrivateCrtKeyRef::new(
            &MODULUS,
            &EXPONENT,
            valid.private_exponent(),
            valid.p(),
            valid.q(),
            &[17],
            valid.dq(),
            valid.q_inv(),
        );
        let mut engine = HeapRsaCrtCoreEngine::default();
        engine.init(CipherDirection::Decrypt, &key).unwrap();

        let input = engine.convert_input(&[42]).unwrap();
        assert_eq!(
            engine.process_int(&input),
            Err(RsaError::FaultyDecryptionOrSigning)
        );
        assert_eq!(
            engine.process_int_blinded(&input, &mut SequenceRng(0)),
            Err(RsaError::FaultyDecryptionOrSigning)
        );
    }

    #[test]
    fn an_uninitialised_heap_crt_engine_reports_no_capacity() {
        let mut engine = HeapRsaCrtCoreEngine::default();
        let input = tc_bigint::BigUint::from(2_u8);

        assert_eq!(engine.input_block_size(), 0);
        assert_eq!(engine.output_block_size(), 0);
        assert_eq!(engine.convert_input(&[2]), Err(RsaError::NotInitialized));
        assert_eq!(engine.process_int(&input), Err(RsaError::NotInitialized));
        assert_eq!(
            engine.process_int_blinded(&input, &mut SequenceRng(0)),
            Err(RsaError::NotInitialized)
        );
        assert_eq!(
            engine.convert_output(&input, &mut [0; 2]),
            Err(RsaError::NotInitialized)
        );
    }

    #[test]
    fn heap_crt_recombination_reduces_m_q_before_unsigned_subtraction() {
        let valid = crt_key();
        // 交換 p、q 與 dp、dq，新的 qInv 是 67^-1 mod 61 = 51。
        let key = RsaPrivateCrtKeyRef::new(
            &MODULUS,
            &EXPONENT,
            valid.private_exponent(),
            valid.q(),
            valid.p(),
            valid.dq(),
            valid.dp(),
            &[51],
        );
        let mut heap = HeapRsaCrtCoreEngine::default();
        heap.init(CipherDirection::Decrypt, &key).unwrap();
        let mut fixed = crt_engine();

        // 輸入 6 時 m_p=2、m_q=65；只加一次 p=61 仍會下溢，必須先算 m_q mod p。
        let input = heap.convert_input(&[6]).unwrap();
        let result = heap.process_int(&input).unwrap();
        let mut output = [0_u8; 2];
        let length = heap.convert_output(&result, &mut output).unwrap();
        let input = fixed.convert_input(&[6]).unwrap();
        let result = fixed.process_int(&input).unwrap();
        let mut expected = [0_u8; 2];
        let expected_len = fixed.convert_output(&result, &mut expected).unwrap();
        assert_eq!(&output[..length], &expected[..expected_len]);
    }

    #[test]
    fn crt_backends_share_validation_and_failed_init_preserves_the_heap_state() {
        let key = crt_key();
        let mut heap = heap_crt_engine();
        let input = heap.convert_input(&[42]).unwrap();
        let expected = heap.process_int(&input).unwrap();

        for (index, value, error) in [
            (0, &[][..], RsaError::InvalidModulus),
            (0, &[4][..], RsaError::EvenModulus),
            (1, &[][..], RsaError::InvalidExponent),
            (1, &[4][..], RsaError::EvenPublicExponent),
            (2, &[][..], RsaError::InvalidPrivateExponent),
            (2, &[4][..], RsaError::InvalidPrivateExponent),
            (3, &[][..], RsaError::InvalidP),
            (3, &[4][..], RsaError::InvalidP),
            (4, &[][..], RsaError::InvalidQ),
            (4, &[4][..], RsaError::InvalidQ),
            (5, &[][..], RsaError::InvalidDp),
            (6, &[][..], RsaError::InvalidDq),
            (7, &[][..], RsaError::InvalidQInv),
        ] {
            let mut fields = [
                key.modulus(),
                key.public_exponent(),
                key.private_exponent(),
                key.p(),
                key.q(),
                key.dp(),
                key.dq(),
                key.q_inv(),
            ];
            fields[index] = value;
            let invalid = RsaPrivateCrtKeyRef::new(
                fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[6],
                fields[7],
            );
            let mut fixed = crt_engine();
            assert_eq!(fixed.init(CipherDirection::Encrypt, &invalid), Err(error));
            assert_eq!(heap.init(CipherDirection::Encrypt, &invalid), Err(error));
            assert_eq!(heap.input_block_size(), 2);
            assert_eq!(heap.output_block_size(), 1);
            assert_eq!(heap.process_int(&input).unwrap(), expected);
        }
    }

    #[test]
    fn owned_clones_keep_their_fields_after_the_original_is_dropped() {
        fn has_drop_policy<T: tc_bigint::ZeroizeOnDrop>(_: &T) {}

        let owned = RsaKeyOwned::new(false, MODULUS.to_vec(), EXPONENT.to_vec());
        has_drop_policy(&owned);
        let cloned = owned.clone();
        drop(owned);
        let borrowed = cloned.as_key_ref();
        assert!(!borrowed.is_private());
        assert_eq!(borrowed.modulus(), MODULUS);
        assert_eq!(borrowed.exponent(), EXPONENT);

        let key = crt_key();
        let owned = RsaPrivateCrtKeyOwned::new(
            key.modulus().to_vec(),
            key.public_exponent().to_vec(),
            key.private_exponent().to_vec(),
            key.p().to_vec(),
            key.q().to_vec(),
            key.dp().to_vec(),
            key.dq().to_vec(),
            key.q_inv().to_vec(),
        );
        has_drop_policy(&owned);
        let cloned = owned.clone();
        drop(owned);
        let borrowed = cloned.as_key_ref();
        // 比較測試向量的各個欄位，不為金鑰容器重新定義相等語意。
        for (actual, expected) in [
            (borrowed.modulus(), key.modulus()),
            (borrowed.public_exponent(), key.public_exponent()),
            (borrowed.private_exponent(), key.private_exponent()),
            (borrowed.p(), key.p()),
            (borrowed.q(), key.q()),
            (borrowed.dp(), key.dp()),
            (borrowed.dq(), key.dq()),
            (borrowed.q_inv(), key.q_inv()),
        ] {
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn heap_clones_survive_reinitialization_and_drop_of_the_original() {
        let key = crt_key();
        let private = Key::new(true, key.modulus(), key.private_exponent());
        let public = Key::new(false, &MODULUS, &EXPONENT);
        let mut plain = HeapRsaCoreEngine::default();
        plain.init(CipherDirection::Decrypt, &private).unwrap();
        let input = plain.convert_input(&[2]).unwrap();
        let expected = plain.process_int(&input).unwrap();
        let mut plain_clone = plain.clone();

        plain.init(CipherDirection::Encrypt, &public).unwrap();
        assert_eq!(
            plain.process_int(&input).unwrap(),
            tc_bigint::BigUint::from(128_u8)
        );
        drop(plain);
        assert_eq!(plain_clone.process_int(&input).unwrap(), expected);

        let mut crt = HeapRsaCrtCoreEngine::default();
        crt.init(CipherDirection::Decrypt, &key).unwrap();
        let mut crt_clone = crt.clone();
        crt.init(CipherDirection::Encrypt, &key).unwrap();
        assert_eq!(crt.output_block_size(), 2);
        assert_eq!(crt.process_int(&input).unwrap(), expected);
        drop(crt);
        assert_eq!(crt_clone.output_block_size(), 1);
        assert_eq!(crt_clone.process_int(&input).unwrap(), expected);
        assert_eq!(
            crt_clone
                .process_int_blinded(&input, &mut SequenceRng(0))
                .unwrap(),
            expected
        );
    }

    #[test]
    fn owned_parameters_behave_like_the_borrowed_ones() {
        let owned = RsaKeyOwned::new(false, MODULUS.to_vec(), EXPONENT.to_vec());
        assert_eq!(validate(&owned), validate(&owned.as_key_ref()));

        let mut from_owned = FixedRsaCoreEngine::<1>::default();
        from_owned.init(CipherDirection::Encrypt, &owned).unwrap();
        let borrowed = fixed_engine(
            CipherDirection::Encrypt,
            &Key::new(false, &MODULUS, &EXPONENT),
        );

        let value = from_owned.convert_input(&[42]).unwrap();
        assert_eq!(
            from_owned.process_int(&value).unwrap(),
            borrowed.clone().process_int(&value).unwrap()
        );
    }

    #[test]
    fn owned_crt_parameters_drive_the_crt_engine() {
        let owned = RsaPrivateCrtKeyOwned::new(
            MODULUS.to_vec(),
            EXPONENT.to_vec(),
            vec![0x08, 0xd7],
            vec![67],
            vec![61],
            vec![19],
            vec![43],
            vec![11],
        );

        let mut engine = FixedRsaCrtCoreEngine::<2, 1>::default();
        engine.init(CipherDirection::Decrypt, &owned).unwrap();
        let mut expected = crt_engine();

        let value = engine.convert_input(&[42]).unwrap();
        assert_eq!(
            engine.process_int(&value).unwrap(),
            expected.process_int(&value).unwrap()
        );
    }

    #[test]
    fn the_byte_interface_matches_the_three_step_path() {
        let public = Key::new(false, &MODULUS, &EXPONENT);
        let message = &[42_u8][..];

        let mut fixed = fixed_engine(CipherDirection::Encrypt, &public);
        let mut heap = heap_engine(CipherDirection::Encrypt, &public);
        let mut fixed_crt = crt_engine();
        let mut heap_crt = heap_crt_engine();

        let mut expected = [0_u8; 2];
        let value = fixed.convert_input(message).unwrap();
        let result = fixed.process_int(&value).unwrap();
        let expected_len = fixed.convert_output(&result, &mut expected).unwrap();

        for (name, actual) in [
            ("fixed", {
                let mut buffer = [0_u8; 2];
                let length =
                    AsymmetricBlockCipher::process_block(&mut fixed, message, &mut buffer).unwrap();
                (buffer, length)
            }),
            ("heap", {
                let mut buffer = [0_u8; 2];
                let length =
                    AsymmetricBlockCipher::process_block(&mut heap, message, &mut buffer).unwrap();
                (buffer, length)
            }),
        ] {
            assert_eq!(&actual.0[..actual.1], &expected[..expected_len], "{name}");
        }

        // 兩個 CRT 引擎是解密方向，對同一密文的位元組介面結果也要一致。
        let mut ciphertext = [0_u8; 2];
        let cipher_len =
            AsymmetricBlockCipher::process_block(&mut fixed, message, &mut ciphertext).unwrap();

        let mut from_fixed_crt = [0_u8; 2];
        let fixed_crt_len = AsymmetricBlockCipher::process_block(
            &mut fixed_crt,
            &ciphertext[..cipher_len],
            &mut from_fixed_crt,
        )
        .unwrap();
        let mut from_heap_crt = [0_u8; 2];
        let heap_crt_len = AsymmetricBlockCipher::process_block(
            &mut heap_crt,
            &ciphertext[..cipher_len],
            &mut from_heap_crt,
        )
        .unwrap();

        assert_eq!(&from_fixed_crt[..fixed_crt_len], message);
        assert_eq!(&from_heap_crt[..heap_crt_len], message);
    }

    #[test]
    fn the_byte_interface_passes_errors_through() {
        let mut engine = fixed_engine(
            CipherDirection::Encrypt,
            &Key::new(false, &MODULUS, &EXPONENT),
        );

        assert_eq!(
            AsymmetricBlockCipher::process_block(&mut engine, &[1], &mut [0_u8; 2]),
            Err(RsaError::InputTooSmall)
        );
        assert_eq!(
            AsymmetricBlockCipher::process_block(&mut engine, &[42], &mut [0_u8; 1]),
            Err(RsaError::OutputTooShort)
        );

        let mut empty = FixedRsaCoreEngine::<1>::default();
        assert_eq!(
            AsymmetricBlockCipher::process_block(&mut empty, &[42], &mut [0_u8; 2]),
            Err(RsaError::NotInitialized)
        );
        assert_eq!(AsymmetricBlockCipher::input_block_size(&empty), 0);
    }

    #[test]
    fn the_blinded_engine_matches_the_unblinded_crt_path() {
        let mut engine: RsaBlindedEngine<FixedRsaCrtCoreEngine<2, 1>, _> =
            RsaBlindedEngine::new(SequenceRng(0));
        engine.init(CipherDirection::Decrypt, &crt_key()).unwrap();
        let mut reference = crt_engine();

        let mut public = fixed_engine(
            CipherDirection::Encrypt,
            &Key::new(false, &MODULUS, &EXPONENT),
        );

        for message in [&[2_u8][..], &[42][..], &[0x0f, 0xf5][..]] {
            let mut ciphertext = [0_u8; 2];
            let cipher_len =
                AsymmetricBlockCipher::process_block(&mut public, message, &mut ciphertext)
                    .unwrap();

            let mut expected = [0_u8; 2];
            let value = reference.convert_input(&ciphertext[..cipher_len]).unwrap();
            let result = reference.process_int(&value).unwrap();
            let expected_len = reference.convert_output(&result, &mut expected).unwrap();

            let mut recovered = [0_u8; 2];
            let length = AsymmetricBlockCipher::process_block(
                &mut engine,
                &ciphertext[..cipher_len],
                &mut recovered,
            )
            .unwrap();

            assert_eq!(&recovered[..length], &expected[..expected_len]);
            assert_eq!(&recovered[..length], message);
        }

        // 門面只是轉發，區塊大小要跟被包的核心一致。
        assert_eq!(
            AsymmetricBlockCipher::input_block_size(&engine),
            AsymmetricBlockCipher::input_block_size(&reference)
        );
        assert_eq!(
            AsymmetricBlockCipher::output_block_size(&engine),
            AsymmetricBlockCipher::output_block_size(&reference)
        );
    }

    #[test]
    fn the_blinded_engine_wraps_a_heap_core_too() {
        let mut engine: RsaBlindedEngine<HeapRsaCrtCoreEngine, _> =
            RsaBlindedEngine::new(SequenceRng(0));
        engine.init(CipherDirection::Decrypt, &crt_key()).unwrap();

        let mut public = fixed_engine(
            CipherDirection::Encrypt,
            &Key::new(false, &MODULUS, &EXPONENT),
        );
        let mut ciphertext = [0_u8; 2];
        let cipher_len =
            AsymmetricBlockCipher::process_block(&mut public, &[42], &mut ciphertext).unwrap();

        let mut recovered = [0_u8; 2];
        let length = AsymmetricBlockCipher::process_block(
            &mut engine,
            &ciphertext[..cipher_len],
            &mut recovered,
        )
        .unwrap();
        assert_eq!(&recovered[..length], &[42]);
    }

    #[test]
    fn an_uninitialised_blinded_engine_reports_no_capacity() {
        let mut engine: RsaBlindedEngine<FixedRsaCrtCoreEngine<2, 1>, _> =
            RsaBlindedEngine::new(SequenceRng(0));

        assert_eq!(AsymmetricBlockCipher::input_block_size(&engine), 0);
        assert_eq!(AsymmetricBlockCipher::output_block_size(&engine), 0);
        assert_eq!(
            AsymmetricBlockCipher::process_block(&mut engine, &[42], &mut [0_u8; 2]),
            Err(RsaError::NotInitialized)
        );
    }

    fn published_crt_key(values: &[Vec<u8>; 8]) -> RsaPrivateCrtKeyRef<'_> {
        RsaPrivateCrtKeyRef::new(
            &values[0], &values[1], &values[2], &values[3], &values[4], &values[5], &values[6],
            &values[7],
        )
    }

    /// 直接驗證位元組入口，預期值來自舊版保留的公開向量，不由待測引擎計算。
    fn assert_published_raw_output(
        engine: &mut impl AsymmetricBlockCipher<Error = RsaError>,
        modulus_len: usize,
        expected: &str,
    ) {
        let mut output = vec![0_u8; modulus_len];
        let length = AsymmetricBlockCipher::process_block(engine, &[2], &mut output).unwrap();
        assert_eq!(&output[..length], hex_bytes(expected));
    }

    #[test]
    fn published_1024_and_2048_keys_match_fixed_crt_raw_outputs() {
        let values = key_1024();
        let mut engine = Rsa1024CrtCore::default();
        engine
            .init(CipherDirection::Decrypt, &published_crt_key(&values))
            .unwrap();
        assert_published_raw_output(&mut engine, values[0].len(), EXPECTED_1024);

        let values = key_2048();
        let mut engine = Rsa2048CrtCore::default();
        engine
            .init(CipherDirection::Decrypt, &published_crt_key(&values))
            .unwrap();
        assert_published_raw_output(&mut engine, values[0].len(), EXPECTED_2048);
    }

    #[test]
    fn published_1024_and_2048_keys_match_heap_crt_raw_outputs() {
        for (values, expected) in [(key_1024(), EXPECTED_1024), (key_2048(), EXPECTED_2048)] {
            let mut engine = HeapRsaCrtCoreEngine::default();
            engine
                .init(CipherDirection::Decrypt, &published_crt_key(&values))
                .unwrap();
            assert_published_raw_output(&mut engine, values[0].len(), expected);
        }
    }

    #[test]
    fn published_2048_key_blinding_preserves_the_raw_output() {
        let values = key_2048();
        let mut engine: RsaBlindedEngine<Rsa2048CrtCore, _> = RsaBlindedEngine::new(SequenceRng(0));
        engine
            .init(CipherDirection::Decrypt, &published_crt_key(&values))
            .unwrap();

        for _ in 0..2 {
            assert_published_raw_output(&mut engine, values[0].len(), EXPECTED_2048);
        }
    }

    fn assert_published_round_trip(
        public: &mut impl AsymmetricBlockCipher<Error = RsaError>,
        private: &mut impl AsymmetricBlockCipher<Error = RsaError>,
        modulus: &[u8],
    ) {
        let high = tc_bigint::BigUint::from_be_bytes(modulus) - tc_bigint::BigUint::from(2_u8);
        let messages = [
            vec![2_u8],
            high.to_be_bytes(),
            hex_bytes("0123456789abcdef0123456789abcdef"),
        ];

        for message in messages {
            let mut ciphertext = vec![0_u8; public.output_block_size()];
            let cipher_len =
                AsymmetricBlockCipher::process_block(public, &message, &mut ciphertext).unwrap();
            // n - 2 的最短表示法仍可能佔滿模數寬度，解密緩衝區依模數長度配置。
            let mut recovered = vec![0_u8; modulus.len()];
            let recovered_len = AsymmetricBlockCipher::process_block(
                private,
                &ciphertext[..cipher_len],
                &mut recovered,
            )
            .unwrap();
            assert_eq!(&recovered[..recovered_len], message);
        }
    }

    #[test]
    fn published_keys_round_trip_low_high_and_arbitrary_messages_at_both_widths() {
        let values = key_1024();
        let mut public = Rsa1024Core::default();
        public
            .init(
                CipherDirection::Encrypt,
                &Key::new(false, &values[0], &values[1]),
            )
            .unwrap();
        let mut private = Rsa1024CrtCore::default();
        private
            .init(CipherDirection::Decrypt, &published_crt_key(&values))
            .unwrap();
        assert_published_round_trip(&mut public, &mut private, &values[0]);

        let values = key_2048();
        let mut public = Rsa2048Core::default();
        public
            .init(
                CipherDirection::Encrypt,
                &Key::new(false, &values[0], &values[1]),
            )
            .unwrap();
        let mut private = Rsa2048CrtCore::default();
        private
            .init(CipherDirection::Decrypt, &published_crt_key(&values))
            .unwrap();
        assert_published_round_trip(&mut public, &mut private, &values[0]);
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

    fn key_1024() -> [Vec<u8>; 8] {
        // Bouncy Castle 的 PKCS #1 v2.1 RSA-PSS 範例 1，使用公開的 1024 位元測試金鑰。
        // https://github.com/bcgit/bc-csharp/blob/master/crypto/test/src/crypto/test/PSSTest.cs
        [
            hex_bytes(
                "a56e4a0e701017589a5187dc7ea841d156f2ec0e36ad52a44dfeb1e61f7ad991d8c51056ffedb162b4c0f283a12a88a394dff526ab7291cbb307ceabfce0b1dfd5cd9508096d5b2b8b6df5d671ef6377c0921cb23c270a70e2598e6ff89d19f105acc2d3f0cb35f29280e1386b6f64c4ef22e1e1f20d0ce8cffb2249bd9a2137",
            ),
            hex_bytes("010001"),
            hex_bytes(
                "33a5042a90b27d4f5451ca9bbbd0b44771a101af884340aef9885f2a4bbe92e894a724ac3c568c8f97853ad07c0266c8c6a3ca0929f1e8f11231884429fc4d9ae55fee896a10ce707c3ed7e734e44727a39574501a532683109c2abacaba283c31b4bd2f53c3ee37e352cee34f9e503bd80c0622ad79c6dcee883547c6a3b325",
            ),
            hex_bytes(
                "e7e8942720a877517273a356053ea2a1bc0c94aa72d55c6e86296b2dfc967948c0a72cbccca7eacb35706e09a1df55a1535bd9b3cc34160b3b6dcd3eda8e6443",
            ),
            hex_bytes(
                "b69dca1cf7d4d7ec81e75b90fcca874abcde123fd2700180aa90479b6e48de8d67ed24f9f19d85ba275874f542cd20dc723e6963364a1f9425452b269a6799fd",
            ),
            hex_bytes(
                "28fa13938655be1f8a159cbaca5a72ea190c30089e19cd274a556f36c4f6e19f554b34c077790427bbdd8dd3ede2448328f385d81b30e8e43b2fffa027861979",
            ),
            hex_bytes(
                "1a8b38f398fa712049898d7fb79ee0a77668791299cdfa09efc0e507acb21ed74301ef5bfd48be455eaeb6e1678255827580a8e4e8e14151d1510a82a3f2e729",
            ),
            hex_bytes(
                "27156aba4126d24a81f3a528cbfb27f56886f840a9f6e86e17a44b94fe9319584b8e22fdde1e5a2e3bd8aa5ba8d8584194eb2190acf832b847f13a3d24a79f4d",
            ),
        ]
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

    const EXPECTED_1024: &str = "34d69b59851d5808df4a31190f07cbec1a49416fb60329aebdc7d0bd310183d54a1de34b24dfb602740514eed04d9686247ff1650543f24eac91b744f98f6b054d1caa00d9b296a424f576e1a047bc5f9dec27404043c4677a24a5a17fadde03769ab884fd348b62816669b1b4ef7ca5438f90be00857e34d9b933f73ac0991b";

    const EXPECTED_2048: &str = "214e2267e82ffe9c70c8fc4daa32ce7c7487f4d9dccaa8dfef3ec0965805d5d79c8f0564853af8bb8c99c07e2632cf1c5fa5b26537e6d7d31c648ec58cd60b8acb2ce7cfd63713af4cde37e1ab7ad8baf6c0f991f6ca68f0d39347e2bece16050e5fbae8e4aa448686b5e0cc1fc42b12c41a1066d2af5dd85ab464025c66eb0a5a0fa4e5f5608e3836e0330ffbf9bb58f858972d992558df4e524cd1a60835ac1953a968bc83ab136bf610c1d5221234f341458524c408fbb28fa4843f5e1e815f68507be966fa9118023d312ed58fb0ca3ec421c0dcba276df1738f5707e4459cbc00535b447c5ad0524d19fa58389d82998fc8956e97b0820c1cbba834c0ca";
}
