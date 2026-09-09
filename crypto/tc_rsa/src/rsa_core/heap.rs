//! 以堆配置的 RSA 核心；模數寬度在執行期決定。

use tc_bigint::{BigUint, Zeroize, ZeroizeOnDrop};
use tc_cipher::{AsymmetricBlockCipher, CipherDirection};

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
/// 私鑰運算若暴露在遠端計時之下，
/// 請改用固定寬度版本。
/// 以 [`Default`] 建立的引擎尚未持有金鑰，運算方法會回
/// [`RsaError::NotInitialized`]，區塊大小則為 `0`。
///
/// # 記憶體清除
///
/// 狀態在引擎 drop 或成功重新初始化時，會清除所有整數欄位目前有效的 limb。
/// 初始化失敗仍保留原狀態。清除不涵蓋 spare capacity、先前重配置的舊緩衝、
/// 其他副本或運算中間值，也不改變這個後端的計時性質。
#[derive(Clone, Debug, Default)]
pub struct HeapRsaCoreEngine {
    inner: Option<Inner>,
}

/// 初始化後才存在的狀態。
#[derive(Clone, Debug)]
struct Inner {
    modulus: BigUint,
    exponent: BigUint,
    is_private: bool,
    bit_size: usize,
    direction: CipherDirection,
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.modulus.zeroize();
        self.exponent.zeroize();
    }
}

impl ZeroizeOnDrop for Inner {}

impl Inner {
    fn new<K: RsaKeyParams + ?Sized>(
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

impl HeapRsaCoreEngine {
    /// 取得初始化後的狀態，未初始化時回 [`RsaError::NotInitialized`]。
    fn inner(&self) -> Result<&Inner, RsaError> {
        self.inner.as_ref().ok_or(RsaError::NotInitialized)
    }
}

impl<K: RsaKeyParams + ?Sized> RsaInit<K> for HeapRsaCoreEngine {
    type Error = RsaError;

    fn init(&mut self, direction: CipherDirection, parameters: &K) -> Result<(), Self::Error> {
        // 先建好再寫回，失敗時引擎維持原狀，不會留下半初始化的金鑰。
        let inner = Inner::new(direction, parameters)?;
        self.inner = Some(inner);
        Ok(())
    }
}

impl AsymmetricBlockCipher for HeapRsaCoreEngine {
    type Error = RsaError;

    fn input_block_size(&self) -> usize {
        self.inner
            .as_ref()
            .map_or(0, |inner| match inner.direction {
                CipherDirection::Encrypt => inner.bit_size.saturating_sub(1) / 8,
                CipherDirection::Decrypt => inner.bit_size.div_ceil(8),
            })
    }

    fn output_block_size(&self) -> usize {
        self.inner
            .as_ref()
            .map_or(0, |inner| match inner.direction {
                CipherDirection::Encrypt => inner.bit_size.div_ceil(8),
                CipherDirection::Decrypt => inner.bit_size.saturating_sub(1) / 8,
            })
    }

    /// 位元組層的單一區塊運算：轉換輸入、做原始 RSA、寫回輸出。
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        let value = self.convert_input(input)?;
        let result = self.process_int(&value)?;
        self.convert_output(&result, output)
    }
}

impl Rsa for HeapRsaCoreEngine {
    type RsaBigInt = BigUint;

    fn convert_input(&self, input: &[u8]) -> Result<Self::RsaBigInt, Self::Error> {
        let inner = self.inner()?;
        let input = BigUint::from_be_bytes(input);
        // 0、1 與 n-1 的模冪結果等於自身，帶不出資訊；一律當成無效輸入擋掉。
        if input <= BigUint::from(1_u8) {
            return Err(RsaError::InputTooSmall);
        }
        if input >= &inner.modulus - BigUint::from(1_u8) {
            return Err(RsaError::InputTooLarge);
        }
        Ok(input)
    }

    fn process_int(&mut self, input: &Self::RsaBigInt) -> Result<Self::RsaBigInt, Self::Error> {
        // `mod_pow` 是變動時間；私鑰在這個後端沒有排程保護，見型別文件。
        let inner = self.inner()?;
        let _ = inner.is_private;
        Ok(input.mod_pow(&inner.exponent, &inner.modulus))
    }

    fn convert_output(
        &self,
        result: &Self::RsaBigInt,
        output: &mut [u8],
    ) -> Result<usize, Self::Error> {
        let inner = self.inner()?;
        let bytes = result.to_be_bytes();
        let result_len = bytes.len();
        // 加密輸出固定補到模數長度；解密輸出用最短表示法，與 Bouncy Castle 一致。
        let output_len = match inner.direction {
            CipherDirection::Encrypt => inner.bit_size.div_ceil(8),
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
