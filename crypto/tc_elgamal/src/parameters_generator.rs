use crate::{ElGamalError, ElGamalParameters};
use rand_core::CryptoRng;
use tc_dh_key::DhParametersGenerator;

/// BC 的 `ElGamalParametersGenerator`：與 DH 相同的安全質數 p，g = 2，只留下 p 與 g。
/// 產生很慢，2048 位元可能要數十秒到數分鐘。
pub struct ElGamalParametersGenerator<'a> {
    inner: DhParametersGenerator<'a>,
}

impl<'a> ElGamalParametersGenerator<'a> {
    /// 尚未 `init` 的產生器。常數時間。
    pub fn new() -> Self {
        Self {
            inner: DhParametersGenerator::new(),
        }
    }

    /// 設定 p 的位元數、質數檢定的 certainty 與亂數來源（BC 的 `Init`）。p 少於 64 位元或
    /// certainty 為 0 時回傳錯誤。常數時間。
    pub fn init(
        &mut self,
        size: u32,
        certainty: u32,
        rng: &'a mut dyn CryptoRng,
    ) -> Result<(), ElGamalError> {
        Ok(self.inner.init(size, certainty, rng)?)
    }

    /// BC 的 `GenerateParameters`：安全質數 p ≡ 7 (mod 8) 與 g = 2。變動時間：產生的是
    /// 公開值。
    pub fn generate_parameters(&mut self) -> Result<ElGamalParameters, ElGamalError> {
        let dh = self.inner.generate_parameters()?;
        Ok(ElGamalParameters::new(dh.p().clone(), dh.g().clone()))
    }
}

impl Default for ElGamalParametersGenerator<'_> {
    fn default() -> Self {
        Self::new()
    }
}
