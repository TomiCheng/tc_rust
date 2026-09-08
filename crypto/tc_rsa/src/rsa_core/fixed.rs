//! 固定寬度、無 alloc 的 RSA 核心。

use tc_bigint::modular::{FixedMontyForm, FixedMontyParams};
use tc_bigint::{FixedBigUint, Odd};
use tc_cipher::CipherDirection;

use crate::rsa_core::validate;
use crate::{Rsa, RsaError, RsaInit, RsaKeyParams};

/// 固定 `N` 個 limb 寬的 RSA 核心；`N` 由呼叫端決定，crate 本身沒有模數上限。
///
/// 以 [`Default`] 建立的引擎尚未持有金鑰，運算方法會回
/// [`RsaError::NotInitialized`]，區塊大小則為 `0`；呼叫
/// [`RsaInit::init`](crate::RsaInit::init) 之後才可用。
#[derive(Clone, Copy, Default)]
pub struct FixedRsaCoreEngine<const N: usize> {
    inner: Option<Inner<N>>,
}

/// 初始化後才存在的狀態。
#[derive(Clone, Copy)]
struct Inner<const N: usize> {
    modulus: FixedBigUint<N>,
    exponent: FixedBigUint<N>,
    params_n: FixedMontyParams<N>,
    is_private: bool,
    bit_size: usize,
    direction: CipherDirection,
}

impl<const N: usize> Inner<N> {
    fn new<K: RsaKeyParams + ?Sized>(
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

impl<const N: usize> FixedRsaCoreEngine<N> {
    /// 取得初始化後的狀態，未初始化時回 [`RsaError::NotInitialized`]。
    fn inner(&self) -> Result<&Inner<N>, RsaError> {
        self.inner.as_ref().ok_or(RsaError::NotInitialized)
    }
}

impl<K: RsaKeyParams + ?Sized, const N: usize> RsaInit<K> for FixedRsaCoreEngine<N> {
    type Error = RsaError;

    fn init(&mut self, direction: CipherDirection, parameters: &K) -> Result<(), Self::Error> {
        // 先建好再寫回，失敗時引擎維持原狀，不會留下半初始化的金鑰。
        let inner = Inner::new(direction, parameters)?;
        self.inner = Some(inner);
        Ok(())
    }
}

impl<const N: usize> Rsa for FixedRsaCoreEngine<N> {
    type RsaBigInt = FixedBigUint<N>;
    type Error = RsaError;

    fn input_block_size(&self) -> usize {
        self.inner.map_or(0, |inner| match inner.direction {
            CipherDirection::Encrypt => inner.bit_size.saturating_sub(1) / 8,
            CipherDirection::Decrypt => inner.bit_size.div_ceil(8),
        })
    }

    fn output_block_size(&self) -> usize {
        self.inner.map_or(0, |inner| match inner.direction {
            CipherDirection::Encrypt => inner.bit_size.div_ceil(8),
            CipherDirection::Decrypt => inner.bit_size.saturating_sub(1) / 8,
        })
    }

    fn convert_input(&self, input: &[u8]) -> Result<Self::RsaBigInt, Self::Error> {
        let inner = self.inner()?;
        let input = fixed(input, RsaError::InputTooLarge)?;
        // 0、1 與 n-1 的模冪結果等於自身，帶不出資訊；一律當成無效輸入擋掉。
        if input <= FixedBigUint::from(1_u8) {
            return Err(RsaError::InputTooSmall);
        }
        if input >= inner.modulus - FixedBigUint::from(1_u8) {
            return Err(RsaError::InputTooLarge);
        }
        Ok(input)
    }

    fn process_block(&mut self, input: &Self::RsaBigInt) -> Result<Self::RsaBigInt, Self::Error> {
        // 私鑰指數是秘密，走固定排程；公鑰的 e 是公開值，用變動時間版本比較快。
        // 兩條分支不可合併成一條。
        let inner = self.inner()?;
        let result = if inner.is_private {
            FixedMontyForm::new_ct(input, inner.params_n)
                .pow_ct(&inner.exponent)
                .retrieve()
        } else {
            FixedMontyForm::new(input, inner.params_n)
                .pow(&inner.exponent)
                .retrieve()
        };
        Ok(result)
    }

    fn convert_output(
        &self,
        result: &Self::RsaBigInt,
        output: &mut [u8],
    ) -> Result<usize, Self::Error> {
        let inner = self.inner()?;
        let result_len = result.byte_length_unsigned();
        // 加密輸出固定補到模數長度；解密輸出用最短表示法，與 Bouncy Castle 一致。
        let output_len = match inner.direction {
            CipherDirection::Encrypt => inner.bit_size.div_ceil(8),
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

/// 把大端序位元組轉成固定寬度整數；放不進 `N` 個 limb 時回傳指定的錯誤。
fn fixed<const N: usize>(value: &[u8], error: RsaError) -> Result<FixedBigUint<N>, RsaError> {
    FixedBigUint::from_be_bytes(value).map_err(|_| error)
}
