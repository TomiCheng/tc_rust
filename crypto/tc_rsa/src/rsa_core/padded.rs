//! 寬度由金鑰決定的 RSA 核心。

use tc_bigint::modular::{PaddedMontyForm, PaddedMontyParams};
use tc_bigint::{Odd, PaddedBigUint, limbs_for_bits};
use tc_cipher::{AsymmetricBlockCipher, CipherDirection};

use crate::rsa_core::validate;
use crate::{Rsa, RsaError, RsaInit, RsaKeyParams};

/// 模數寬度在 [`RsaInit::init`] 時由金鑰決定的 RSA 核心。
///
/// 與 [`crate::FixedRsaCoreEngine`] 的差別只有兩點：寬度不是型別參數，
/// 以及金鑰材料離開作用域時會自動清除 —— 後者是 `Fixed` 版為了保持 `Copy`
/// 而放棄的能力。
///
/// 以 [`Default`] 建立的引擎尚未持有金鑰，運算方法會回
/// [`RsaError::NotInitialized`]，區塊大小則為 `0`。
#[derive(Default)]
pub struct PaddedRsaCoreEngine {
    inner: Option<Inner>,
}

/// 初始化後才存在的狀態。
struct Inner {
    modulus_minus_one: PaddedBigUint,
    exponent: PaddedBigUint,
    params_n: PaddedMontyParams,
    is_private: bool,
    bit_size: usize,
    direction: CipherDirection,
}

impl Inner {
    fn new<K: RsaKeyParams + ?Sized>(
        direction: CipherDirection,
        key: &K,
    ) -> Result<Self, RsaError> {
        let bit_size = validate(key)?;
        let width = limbs_for_bits(bit_size);

        let modulus = padded(key.modulus(), width, RsaError::InvalidModulus)?;
        let is_private = key.is_private_key();
        let exponent = padded(
            key.exponent(),
            width,
            if is_private {
                RsaError::InvalidPrivateExponent
            } else {
                RsaError::InvalidExponent
            },
        )?;

        let one = padded(&[1], width, RsaError::InvalidModulus)?;
        let (modulus_minus_one, borrow) = modulus.sub(&one);
        if borrow {
            return Err(RsaError::InvalidModulus);
        }

        let params_n = PaddedMontyParams::new(Odd::new(modulus).ok_or(RsaError::EvenModulus)?);

        Ok(Self {
            modulus_minus_one,
            exponent,
            params_n,
            is_private,
            bit_size,
            direction,
        })
    }
}

/// 所有金鑰材料都存在 [`PaddedBigUint`] 裡，離開作用域時自動清除。
impl tc_bigint::ZeroizeOnDrop for PaddedRsaCoreEngine {}

impl PaddedRsaCoreEngine {
    /// 取得初始化後的狀態，未初始化時回 [`RsaError::NotInitialized`]。
    fn inner(&self) -> Result<&Inner, RsaError> {
        self.inner.as_ref().ok_or(RsaError::NotInitialized)
    }
}

impl<K: RsaKeyParams + ?Sized> RsaInit<K> for PaddedRsaCoreEngine {
    type Error = RsaError;

    fn init(&mut self, direction: CipherDirection, parameters: &K) -> Result<(), Self::Error> {
        // 先建好再寫回，失敗時引擎維持原狀，不會留下半初始化的金鑰。
        let inner = Inner::new(direction, parameters)?;
        self.inner = Some(inner);
        Ok(())
    }
}

impl AsymmetricBlockCipher for PaddedRsaCoreEngine {
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

impl Rsa for PaddedRsaCoreEngine {
    type RsaBigInt = PaddedBigUint;

    fn convert_input(&self, input: &[u8]) -> Result<Self::RsaBigInt, Self::Error> {
        let inner = self.inner()?;
        let width = inner.params_n.len();
        let input = padded(input, width, RsaError::InputTooLarge)?;

        // 0、1 與 n-1 的模冪結果等於自身，帶不出資訊；一律當成無效輸入擋掉。
        if input <= padded(&[1], width, RsaError::InputTooSmall)? {
            return Err(RsaError::InputTooSmall);
        }
        if input >= inner.modulus_minus_one {
            return Err(RsaError::InputTooLarge);
        }
        Ok(input)
    }

    fn process_int(&mut self, input: &Self::RsaBigInt) -> Result<Self::RsaBigInt, Self::Error> {
        // 公鑰路徑上沒有秘密，連進入 Montgomery 域都用變動時間的除法約簡；
        // 私鑰路徑則兩步都走固定排程。兩條分支不可合併成一條。
        let inner = self.inner()?;
        let result = if inner.is_private {
            PaddedMontyForm::new_ct(input, inner.params_n.clone()).pow_ct(&inner.exponent)
        } else {
            PaddedMontyForm::new(input, inner.params_n.clone()).pow(&inner.exponent)
        };
        Ok(result.retrieve())
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
            .write_be_bytes(&mut output[output_len - result_len..output_len])
            .map_err(|_| RsaError::OutputTooShort)?;
        Ok(output_len)
    }
}

/// 把大端序位元組轉成 `width` 個 limb 寬的整數；放不下時回傳指定的錯誤。
pub(crate) fn padded(
    value: &[u8],
    width: usize,
    error: RsaError,
) -> Result<PaddedBigUint, RsaError> {
    PaddedBigUint::from_be_bytes(value, width).map_err(|_| error)
}
