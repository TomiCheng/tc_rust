use crate::DhParameters;
use rand_core::CryptoRng;

/// BC 的 `DHKeyGenerationParameters`：參數與亂數來源。
pub struct DhKeyGenerationParams<'a> {
    pub(crate) params: DhParameters,
    pub(crate) rng: &'a mut dyn CryptoRng,
}

impl<'a> DhKeyGenerationParams<'a> {
    /// 包起參數與亂數來源；參數在產生器 `init` 時檢查。常數時間。
    pub fn new(params: DhParameters, rng: &'a mut dyn CryptoRng) -> Self {
        Self { params, rng }
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
