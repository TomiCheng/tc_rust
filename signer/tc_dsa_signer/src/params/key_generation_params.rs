use crate::DsaParameters;

/// BC 的 `DsaKeyGenerationParameters`，不含亂數來源：亂數來源在產生器建構時給。
#[derive(Clone)]
pub struct DsaKeyGenerationParams {
    pub(crate) params: DsaParameters,
}

impl DsaKeyGenerationParams {
    /// 包起參數；參數在產生器 `init` 時檢查。常數時間。
    pub fn new(params: DsaParameters) -> Self {
        Self { params }
    }

    /// 參數。常數時間。
    pub fn params(&self) -> &DsaParameters {
        &self.params
    }

    /// BC 的 `Strength`：p 的位元數減 1。常數時間。
    pub fn strength(&self) -> u32 {
        self.params.p().bits().saturating_sub(1)
    }
}
