use crate::{DhError, DhValidationParameters};
use tc_bigint::PaddedBigUint;

// BC 的 `DefaultMinimumLength`：沒指定 m 時私鑰至少的位元數。
const DEFAULT_MINIMUM_LENGTH: u32 = 160;

/// BC 的 `DHParameters`：模數 p、生成元 g，以及選填的子群階 q、私鑰位元數的下限 m 與
/// 指定長度 l、餘因子 j、產生 p 時的驗證資料。
///
/// 只是容器，建構時不檢查；[`validate`](Self::validate) 做 BC 建構子的檢查，由產生器的
/// `init` 與使用參數的運算呼叫。比較相等時只看 p、g、q，同 BC。
#[derive(Clone, Debug)]
pub struct DhParameters {
    p: PaddedBigUint,
    g: PaddedBigUint,
    q: Option<PaddedBigUint>,
    m: Option<u32>,
    l: u32,
    j: Option<PaddedBigUint>,
    validation: Option<DhValidationParameters>,
}

impl DhParameters {
    /// 只有 p 與 g 的參數。常數時間。
    pub fn new(p: PaddedBigUint, g: PaddedBigUint) -> Self {
        Self {
            p,
            g,
            q: None,
            m: None,
            l: 0,
            j: None,
            validation: None,
        }
    }

    /// 設定子群階 q。常數時間。
    pub fn with_q(mut self, q: PaddedBigUint) -> Self {
        self.q = Some(q);
        self
    }

    /// 設定私鑰位元數的下限 m。常數時間。
    pub fn with_m(mut self, m: u32) -> Self {
        self.m = Some(m);
        self
    }

    /// 設定私鑰的位元數 l；0 表示不指定。常數時間。
    pub fn with_l(mut self, l: u32) -> Self {
        self.l = l;
        self
    }

    /// 設定餘因子 j。常數時間。
    pub fn with_j(mut self, j: PaddedBigUint) -> Self {
        self.j = Some(j);
        self
    }

    /// 設定產生 p 時的驗證資料。常數時間。
    pub fn with_validation(mut self, validation: DhValidationParameters) -> Self {
        self.validation = Some(validation);
        self
    }

    /// 模數 p。常數時間。
    pub fn p(&self) -> &PaddedBigUint {
        &self.p
    }

    /// 生成元 g。常數時間。
    pub fn g(&self) -> &PaddedBigUint {
        &self.g
    }

    /// 子群階 q。常數時間。
    pub fn q(&self) -> Option<&PaddedBigUint> {
        self.q.as_ref()
    }

    /// 私鑰位元數的下限 m；沒設定時同 BC 的 `GetDefaultMParam`：l 為 0 時是 160，否則是
    /// l 與 160 中較小者。常數時間。
    pub fn m(&self) -> u32 {
        self.m.unwrap_or(match self.l {
            0 => DEFAULT_MINIMUM_LENGTH,
            l => l.min(DEFAULT_MINIMUM_LENGTH),
        })
    }

    /// 私鑰的位元數 l；0 表示不指定。常數時間。
    pub fn l(&self) -> u32 {
        self.l
    }

    /// 餘因子 j。常數時間。
    pub fn j(&self) -> Option<&PaddedBigUint> {
        self.j.as_ref()
    }

    /// 產生 p 時的驗證資料。常數時間。
    pub fn validation(&self) -> Option<&DhValidationParameters> {
        self.validation.as_ref()
    }

    /// BC `DHParameters` 建構子的檢查：p 是大於 2 的奇數，g 在 `[2, p - 2]`，q 的位元數
    /// 小於 p 的，m 小於 p 的位元數，l 有設定時小於 p 的位元數且不小於 m，j 至少是 2。
    /// 不檢查 p、q 是否為質數，同 BC。變動時間：參數是公開值。
    pub fn validate(&self) -> Result<(), DhError> {
        let two = PaddedBigUint::from(2u8);
        if !self.p.bit(0) || self.p <= two {
            return Err(DhError::InvalidModulus);
        }
        if self.g < two || self.g > &self.p - 2u32 {
            return Err(DhError::InvalidGenerator);
        }
        let p_bits = self.p.bits();
        if self.q.as_ref().is_some_and(|q| q.bits() >= p_bits) {
            return Err(DhError::InvalidSubgroupOrder);
        }
        let m = self.m();
        if m >= p_bits || (self.l != 0 && (self.l >= p_bits || self.l < m)) {
            return Err(DhError::InvalidPrivateValueLength);
        }
        if self.j.as_ref().is_some_and(|j| *j < two) {
            return Err(DhError::InvalidCofactor);
        }
        Ok(())
    }
}

impl PartialEq for DhParameters {
    /// 只比較 p、g、q，同 BC 的 `Equals`。變動時間：參數是公開值。
    fn eq(&self, other: &Self) -> bool {
        self.p == other.p && self.g == other.g && self.q == other.q
    }
}

impl Eq for DhParameters {}
