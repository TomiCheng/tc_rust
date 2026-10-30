use crate::ElGamalParameters;
use rand_core::CryptoRng;

/// BC 的 `ElGamalKeyGenerationParameters`：參數與亂數來源。
pub struct ElGamalKeyGenerationParams<'a> {
    pub(crate) params: ElGamalParameters,
    pub(crate) rng: &'a mut dyn CryptoRng,
}

impl<'a> ElGamalKeyGenerationParams<'a> {
    /// 包起參數與亂數來源；參數在產生器 `init` 時檢查。常數時間。
    pub fn new(params: ElGamalParameters, rng: &'a mut dyn CryptoRng) -> Self {
        Self { params, rng }
    }

    /// 參數。常數時間。
    pub fn params(&self) -> &ElGamalParameters {
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
