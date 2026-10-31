use crate::{Gost3410Error, Gost3410ValidationParameters};
use tc_bigint::PaddedBigUint;

/// BC 的 `Gost3410Parameters`：模數 p、子群階 q、q 階的生成元 a，以及選填的驗證資料。
///
/// 只是容器，建構時不檢查；[`validate`](Self::validate) 由產生器與簽章的 `init` 呼叫。
/// 比較相等時只看 p、q、a，同 BC。
#[derive(Clone, Debug)]
pub struct Gost3410Parameters {
    p: PaddedBigUint,
    q: PaddedBigUint,
    a: PaddedBigUint,
    validation: Option<Gost3410ValidationParameters>,
}

impl Gost3410Parameters {
    /// p、q 與 a。常數時間。
    pub fn new(p: PaddedBigUint, q: PaddedBigUint, a: PaddedBigUint) -> Self {
        Self {
            p,
            q,
            a,
            validation: None,
        }
    }

    /// 設定驗證資料。常數時間。
    pub fn with_validation(mut self, validation: Gost3410ValidationParameters) -> Self {
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

    /// 生成元 a。常數時間。
    pub fn a(&self) -> &PaddedBigUint {
        &self.a
    }

    /// 驗證資料。常數時間。
    pub fn validation(&self) -> Option<&Gost3410ValidationParameters> {
        self.validation.as_ref()
    }

    /// p 與 q 是大於 2 的奇數、q 小於 p、a 在 `[2, p − 1]`；BC 不檢查，這裡是 Montgomery
    /// 運算的前提。變動時間：只能用於公開值，參數是公開的。
    pub fn validate(&self) -> Result<(), Gost3410Error> {
        let two = PaddedBigUint::from(2u8);
        if !self.p.bit(0) || self.p <= two {
            return Err(Gost3410Error::InvalidModulus);
        }
        if !self.q.bit(0) || self.q <= two || self.q >= self.p {
            return Err(Gost3410Error::InvalidOrder);
        }
        if self.a < two || self.a >= self.p {
            return Err(Gost3410Error::InvalidGenerator);
        }
        Ok(())
    }
}

impl PartialEq for Gost3410Parameters {
    /// 比較 p、q、a。變動時間：只能用於公開值。
    fn eq(&self, other: &Self) -> bool {
        self.p == other.p && self.q == other.q && self.a == other.a
    }
}

impl Eq for Gost3410Parameters {}
