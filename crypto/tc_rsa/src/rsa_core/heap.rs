//! 以堆配置的 RSA 核心；模數寬度在執行期決定。

use tc_bigint::BigUint;
use tc_cipher::CipherDirection;

use crate::rsa_core::validate;
use crate::{Rsa, RsaError, RsaInit, RsaKeyParams};

/// 寬度不設限的 RSA 核心。
///
/// 相對於 [`FixedRsaCoreEngine`](crate::FixedRsaCoreEngine)，這個版本不需要在
/// 編譯期知道模數大小，適合寬度只有執行期才確定的場合，例如解析任意來源的
/// 憑證或 PKCS#8 金鑰。
///
/// # 不保證常數時間
///
/// 底層的 [`BigUint`] 是長度隨數值變動的堆配置整數，`mod_pow` 也沒有固定排程，
/// 而且秘密材料會留在無法歸零的堆緩衝區裡。私鑰運算若暴露在遠端計時之下，
/// 請改用固定寬度版本。
#[derive(Clone, Debug)]
pub struct HeapRsaCoreEngine {
    modulus: BigUint,
    exponent: BigUint,
    is_private: bool,
    bit_size: usize,
    direction: CipherDirection,
}

impl HeapRsaCoreEngine {
    /// 以已驗證的金鑰建立核心。
    pub fn new<K: RsaKeyParams + ?Sized>(
        direction: CipherDirection,
        key: &K,
    ) -> Result<Self, RsaError> {
        let bit_size = validate(key)?;

        Ok(Self {
            modulus: BigUint::from_be_bytes(key.modulus()),
            exponent: BigUint::from_be_bytes(key.exponent()),
            is_private: key.is_private_key(),
            bit_size,
            direction,
        })
    }
}

impl<K: RsaKeyParams + ?Sized> RsaInit<K> for HeapRsaCoreEngine {
    type Error = RsaError;

    fn init(&mut self, direction: CipherDirection, parameters: &K) -> Result<(), Self::Error> {
        *self = Self::new(direction, parameters)?;
        Ok(())
    }
}

impl Rsa for HeapRsaCoreEngine {
    type RsaBigInt = BigUint;
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
        let input = BigUint::from_be_bytes(input);
        // 0、1 與 n-1 的模冪結果等於自身，帶不出資訊；一律當成無效輸入擋掉。
        if input <= BigUint::from(1_u8) {
            return Err(RsaError::InputTooSmall);
        }
        if input >= &self.modulus - BigUint::from(1_u8) {
            return Err(RsaError::InputTooLarge);
        }
        Ok(input)
    }

    fn process_block(&mut self, input: &Self::RsaBigInt) -> Result<Self::RsaBigInt, Self::Error> {
        // `mod_pow` 是變動時間；私鑰在這個後端沒有排程保護，見型別文件。
        let _ = self.is_private;
        Ok(input.mod_pow(&self.exponent, &self.modulus))
    }

    fn convert_output(
        &self,
        result: &Self::RsaBigInt,
        output: &mut [u8],
    ) -> Result<usize, Self::Error> {
        let bytes = result.to_be_bytes();
        let result_len = bytes.len();
        // 加密輸出固定補到模數長度；解密輸出用最短表示法，與 Bouncy Castle 一致。
        let output_len = match self.direction {
            CipherDirection::Encrypt => self.bit_size.div_ceil(8),
            CipherDirection::Decrypt => result_len,
        };
        if output.len() < output_len || result_len > output_len {
            return Err(RsaError::OutputTooShort);
        }

        output[..output_len].fill(0);
        output[output_len - result_len..output_len].copy_from_slice(&bytes);
        Ok(output_len)
    }
}
