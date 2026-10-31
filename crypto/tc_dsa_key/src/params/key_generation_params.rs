use crate::DsaParameters;
use rand_core::CryptoRng;

/// BC 的 `DsaKeyGenerationParameters`：參數與亂數來源。
pub struct DsaKeyGenerationParams<'a> {
    pub(crate) params: DsaParameters,
    pub(crate) rng: &'a mut dyn CryptoRng,
}

impl<'a> DsaKeyGenerationParams<'a> {
    /// 包起參數與亂數來源；參數在產生器 `init` 時檢查。常數時間。
    pub fn new(params: DsaParameters, rng: &'a mut dyn CryptoRng) -> Self {
        Self { params, rng }
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
