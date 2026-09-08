//! 固定寬度、無 alloc 的 RSA 核心。

use tc_bigint::modular::{FixedMontyForm, FixedMontyParams};
use tc_bigint::{FixedBigUint, Odd};
use tc_cipher::CipherDirection;

use crate::rsa_core::{bit_length, is_odd, is_zero};
use crate::{Rsa, RsaError, RsaInit, RsaKeyParams};

/// 固定 `N` 個 limb 寬的 RSA 核心；`N` 由呼叫端決定，crate 本身沒有模數上限。
#[derive(Clone, Copy)]
pub struct FixedRsaCoreEngine<const N: usize> {
    modulus: FixedBigUint<N>,
    exponent: FixedBigUint<N>,
    params_n: FixedMontyParams<N>,
    is_private: bool,
    bit_size: usize,
    direction: CipherDirection,
}

impl<const N: usize> FixedRsaCoreEngine<N> {
    /// 以已驗證的金鑰建立核心。
    ///
    /// 沒有未初始化的狀態：拿得到引擎就表示金鑰已通過檢查且放得進 `N` 個 limb。
    pub fn new<K: RsaKeyParams + ?Sized>(
        direction: CipherDirection,
        key: &K,
    ) -> Result<Self, RsaError> {
        let bit_size = validate(key)?;
        let modulus = fixed(key.modulus(), RsaError::InvalidModulus)?;
        let is_private = key.is_private_key();
        let exponent = fixed(
            key.exponent(),
            if is_private {
                RsaError::InvalidPrivateExponent
            } else {
                RsaError::InvalidExponent
            },
        )?;
        let params_n = FixedMontyParams::new(Odd::new(modulus).ok_or(RsaError::EvenModulus)?);

        Ok(Self {
            modulus,
            exponent,
            params_n,
            is_private,
            bit_size,
            direction,
        })
    }
}

impl<K: RsaKeyParams + ?Sized, const N: usize> RsaInit<K> for FixedRsaCoreEngine<N> {
    type Error = RsaError;

    fn init(&mut self, direction: CipherDirection, parameters: &K) -> Result<(), Self::Error> {
        *self = Self::new(direction, parameters)?;
        Ok(())
    }
}

impl<const N: usize> Rsa for FixedRsaCoreEngine<N> {
    type RsaBigInt = FixedBigUint<N>;
    type Error = RsaError;

    fn input_block_size(&self) -> usize {
        match self.direction {
            CipherDirection::Encrypt => self.bit_size.saturating_sub(1) / 8,
            CipherDirection::Decrypt => self.bit_size.div_ceil(8),
        }
    }

    fn output_block_size(&self) -> usize {
        match self.direction {
            CipherDirection::Encrypt => self.bit_size.div_ceil(8),
            CipherDirection::Decrypt => self.bit_size.saturating_sub(1) / 8,
        }
    }

    fn convert_input(&self, input: &[u8]) -> Result<Self::RsaBigInt, Self::Error> {
        let input = fixed(input, RsaError::InputTooLarge)?;
        // 0、1 與 n-1 的模冪結果等於自身，帶不出資訊；一律當成無效輸入擋掉。
        if input <= FixedBigUint::from(1_u8) {
            return Err(RsaError::InputTooSmall);
        }
        if input >= self.modulus - FixedBigUint::from(1_u8) {
            return Err(RsaError::InputTooLarge);
        }
        Ok(input)
    }

    fn process_block(&mut self, input: &Self::RsaBigInt) -> Result<Self::RsaBigInt, Self::Error> {
        // 私鑰指數是秘密，走固定排程；公鑰的 e 是公開值，用變動時間版本比較快。
        // 兩條分支不可合併成一條。
        let result = if self.is_private {
            FixedMontyForm::new_ct(input, self.params_n)
                .pow_ct(&self.exponent)
                .retrieve()
        } else {
            FixedMontyForm::new(input, self.params_n)
                .pow(&self.exponent)
                .retrieve()
        };
        Ok(result)
    }

    fn convert_output(
        &self,
        result: &Self::RsaBigInt,
        output: &mut [u8],
    ) -> Result<usize, Self::Error> {
        let result_len = result.byte_length_unsigned();
        // 加密輸出固定補到模數長度；解密輸出用最短表示法，與 Bouncy Castle 一致。
        let output_len = match self.direction {
            CipherDirection::Encrypt => self.bit_size.div_ceil(8),
            CipherDirection::Decrypt => result_len,
        };
        if output.len() < output_len || result_len > output_len {
            return Err(RsaError::OutputTooShort);
        }

        output[..output_len].fill(0);
        result
            .write_unsigned_be_bytes(&mut output[output_len - result_len..output_len])
            .map_err(|_| RsaError::OutputTooShort)?;
        Ok(output_len)
    }
}

/// 檢查金鑰參數的位元組是否構成可用的 RSA 金鑰，通過則回傳模數的位元長度。
///
/// 只做位元組層次的判斷：模數非零且為奇數、指數非零且為奇數。是否放得進
/// `FixedBigUint<N>` 由後續轉換負責，質因數篩選與模數合成性檢查則待
/// `tc_bigint` 質數模組整合後補上。
///
/// 這些檢查原本在 `RsaKeyRef::new` 做；照專案慣例，參數型別只是位元組容器，
/// 有效性一律在 `init` 判定。
/// 把大端序位元組轉成固定寬度整數；放不進 `N` 個 limb 時回傳指定的錯誤。
fn fixed<const N: usize>(value: &[u8], error: RsaError) -> Result<FixedBigUint<N>, RsaError> {
    FixedBigUint::from_be_bytes(value).map_err(|_| error)
}

pub(super) fn validate<K: RsaKeyParams + ?Sized>(key: &K) -> Result<usize, RsaError> {
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
