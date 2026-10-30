use crate::ElGamalError;
use tc_bigint::PaddedBigUint;
use tc_dh_key::DhParameters;

/// BC 的 `ElGamalParameters`：模數 p、生成元 g，以及私鑰的位元數 l（0 表示不指定）。
///
/// 只是容器，建構時不檢查；[`validate`](Self::validate) 由產生器與引擎的 `init` 呼叫。
/// 比較相等時看 p、g、l，同 BC。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElGamalParameters {
    p: PaddedBigUint,
    g: PaddedBigUint,
    l: u32,
}

impl ElGamalParameters {
    /// 不指定私鑰長度的參數。常數時間。
    pub fn new(p: PaddedBigUint, g: PaddedBigUint) -> Self {
        Self { p, g, l: 0 }
    }

    /// 設定私鑰的位元數 l。常數時間。
    pub fn with_l(mut self, l: u32) -> Self {
        self.l = l;
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

    /// 私鑰的位元數 l；0 表示不指定。常數時間。
    pub fn l(&self) -> u32 {
        self.l
    }

    /// 檢查 p 是大於 2 的奇數、g 在 `[2, p - 2]`、l 小於 p 的位元數。BC 的
    /// `ElGamalParameters` 不檢查，而是在產生金鑰時交給 `DHParameters` 檢查，這裡做的是
    /// 同一組檢查。變動時間：參數是公開值。
    pub fn validate(&self) -> Result<(), ElGamalError> {
        Ok(self.to_dh().validate()?)
    }

    /// BC `ElGamalKeyPairGenerator` 轉出的 DH 參數：沒有 q，m = 0，l 照設定。常數時間。
    pub(crate) fn to_dh(&self) -> DhParameters {
        DhParameters::new(self.p.clone(), self.g.clone())
            .with_m(0)
            .with_l(self.l)
    }
}
