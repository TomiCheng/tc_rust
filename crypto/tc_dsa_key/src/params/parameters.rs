use crate::{DsaError, DsaValidationParameters};
use tc_bigint::PaddedBigUint;

// BC `DsaMaxSize` 的預設值。
const MAX_MODULUS_BITS: u32 = 16384;

/// BC 的 `DsaParameters`：模數 p、子群階 q、q 階的生成元 g，以及選填的驗證資料。
///
/// 只是容器，建構時不檢查；[`validate`](Self::validate) 由產生器與簽章的 `init` 呼叫。
/// 比較相等時只看 p、q、g，同 BC。
#[derive(Clone, Debug)]
pub struct DsaParameters {
    p: PaddedBigUint,
    q: PaddedBigUint,
    g: PaddedBigUint,
    validation: Option<DsaValidationParameters>,
}

impl DsaParameters {
    /// p、q 與 g。常數時間。
    pub fn new(p: PaddedBigUint, q: PaddedBigUint, g: PaddedBigUint) -> Self {
        Self {
            p,
            q,
            g,
            validation: None,
        }
    }

    /// 設定驗證資料。常數時間。
    pub fn with_validation(mut self, validation: DsaValidationParameters) -> Self {
        self.validation = Some(validation);
        self
    }

    /// 模數 p。常數時間。
    pub fn p(&self) -> &PaddedBigUint {
        &self.p
    }

    /// 子群階 q。常數時間。
    pub fn q(&self) -> &PaddedBigUint {
        &self.q
    }

    /// 生成元 g。常數時間。
    pub fn g(&self) -> &PaddedBigUint {
        &self.g
    }

    /// 驗證資料。常數時間。
    pub fn validation(&self) -> Option<&DsaValidationParameters> {
        self.validation.as_ref()
    }

    /// p 至多 16384 位元（最先檢查，同 BC 在取冪前擋下過大的模數）、是大於 2 的奇數，q 是
    /// 大於 2 且小於 p 的奇數，g 在 `[2, p − 1]`；BC 只在公鑰檢查 p 的上限，其餘是
    /// Montgomery 運算的前提。變動時間：只能用於公開值，參數是公開的。
    pub fn validate(&self) -> Result<(), DsaError> {
        if self.p.bits() > MAX_MODULUS_BITS {
            return Err(DsaError::ModulusTooLarge);
        }
        let two = PaddedBigUint::from(2u8);
        if !self.p.bit(0) || self.p <= two {
            return Err(DsaError::InvalidModulus);
        }
        if !self.q.bit(0) || self.q <= two || self.q >= self.p {
            return Err(DsaError::InvalidOrder);
        }
        if self.g < two || self.g >= self.p {
            return Err(DsaError::InvalidGenerator);
        }
        Ok(())
    }
}

impl PartialEq for DsaParameters {
    /// 比較 p、q、g。變動時間：只能用於公開值。
    fn eq(&self, other: &Self) -> bool {
        self.p == other.p && self.q == other.q && self.g == other.g
    }
}

impl Eq for DsaParameters {}
