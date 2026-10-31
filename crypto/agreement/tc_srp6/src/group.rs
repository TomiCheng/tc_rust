use crate::Srp6Error;
use tc_bigint::PaddedBigUint;
use tc_modular::{Odd, PaddedMontyParams};

/// BC 的 `Srp6GroupParameters`：安全質數 N 與生成元 g。只是容器，client、server 與驗證值
/// 產生器的 `init` 才檢查。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Srp6GroupParameters {
    n: PaddedBigUint,
    g: PaddedBigUint,
}

impl Srp6GroupParameters {
    /// 以 N 與 g 組成的群組。常數時間。
    pub fn new(n: PaddedBigUint, g: PaddedBigUint) -> Self {
        Self { n, g }
    }

    /// 安全質數 N。常數時間。
    pub fn n(&self) -> &PaddedBigUint {
        &self.n
    }

    /// 生成元 g。常數時間。
    pub fn g(&self) -> &PaddedBigUint {
        &self.g
    }
}

/// `init` 檢查過的群組，並為 N 建好 Montgomery 參數。
pub(crate) struct Group {
    pub(crate) n: PaddedBigUint,
    pub(crate) g: PaddedBigUint,
    pub(crate) monty: PaddedMontyParams,
}

impl Group {
    /// 檢查 N 是大於 3 的奇數、g 在 `[2, N - 2]`；BC 不檢查，但 Montgomery 運算需要 N 為
    /// 奇數，g 落在範圍外時 g 的冪也沒有意義。變動時間：只依公開的群組分支。
    pub(crate) fn new(params: &Srp6GroupParameters) -> Result<Self, Srp6Error> {
        let n = params.n();
        let g = params.g();
        if n.bits() < 3 || *g < PaddedBigUint::from(2u8) || *g > n - 2u32 {
            return Err(Srp6Error::InvalidGroup);
        }
        let odd = Odd::new(n.clone()).ok_or(Srp6Error::InvalidGroup)?;
        Ok(Self {
            n: n.clone(),
            g: g.clone(),
            monty: PaddedMontyParams::new(odd),
        })
    }
}
