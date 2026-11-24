use crate::{ElGamalError, ElGamalParameters};
use rand_core::CryptoRng;
use tc_dh_key::{DhGroupGenerationParams, DhGroupGenerator};

/// BC 的 `ElGamalParametersGenerator`，命名照 `DhGroupGenerator`：與 DH 相同的安全質數 p，
/// g = 2，只留下 p 與 g。產生很慢，2048 位元可能要數十秒到數分鐘。
pub struct ElGamalGroupGenerator<R> {
    inner: DhGroupGenerator<R>,
}

impl<R> ElGamalGroupGenerator<R> {
    /// 從 `rng` 取亂數、尚未 `init` 的產生器。常數時間。
    pub fn new(rng: R) -> Self {
        Self {
            inner: DhGroupGenerator::new(rng),
        }
    }

    /// BC 的 `Init`：設定 p 的位元數與質數檢定的 certainty。p 少於 64 位元或 certainty 為 0
    /// 時回傳錯誤。常數時間。
    pub fn init(&mut self, params: &DhGroupGenerationParams) -> Result<(), ElGamalError> {
        Ok(self.inner.init(params)?)
    }
}

impl<R: CryptoRng> ElGamalGroupGenerator<R> {
    /// BC 的 `GenerateParameters`：安全質數 p ≡ 7 (mod 8) 與 g = 2。變動時間：產生的是
    /// 公開值。
    pub fn generate_group(&mut self) -> Result<ElGamalParameters, ElGamalError> {
        let group = self.inner.generate_group()?;
        Ok(ElGamalParameters::new(group.p().clone(), group.g().clone()))
    }
}
