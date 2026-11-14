use crate::DhParameters;

/// BC 的 `DHKeyGenerationParameters`，不含亂數來源：亂數來源在產生器建構時給。
#[derive(Clone, Debug)]
pub struct DhKeyGenerationParams {
    pub(crate) params: DhParameters,
}

impl DhKeyGenerationParams {
    /// 包起參數；參數在產生器 `init` 時檢查。常數時間。
    pub fn new(params: DhParameters) -> Self {
        Self { params }
    }

    /// 參數。常數時間。
    pub fn params(&self) -> &DhParameters {
        &self.params
    }

    /// BC 的 `GetStrength`：l 有設定時是 l，否則是 p 的位元數。常數時間。
    pub fn strength(&self) -> u32 {
        match self.params.l() {
            0 => self.params.p().bits(),
            l => l,
        }
    }
}
