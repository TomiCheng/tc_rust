use crate::Gost3410Parameters;
use rand_core::CryptoRng;

/// BC 的 `Gost3410KeyGenerationParameters`：參數與亂數來源。BC 也能以 CryptoPro 的參數集
/// OID 查參數，這裡沒有那張表。
pub struct Gost3410KeyGenerationParams<'a> {
    pub(crate) params: Gost3410Parameters,
    pub(crate) rng: &'a mut dyn CryptoRng,
}

impl<'a> Gost3410KeyGenerationParams<'a> {
    /// 包起參數與亂數來源；參數在產生器 `init` 時檢查。常數時間。
    pub fn new(params: Gost3410Parameters, rng: &'a mut dyn CryptoRng) -> Self {
        Self { params, rng }
    }

    /// 參數。常數時間。
    pub fn params(&self) -> &Gost3410Parameters {
        &self.params
    }

    /// BC 的 `Strength`：p 的位元數減 1。常數時間。
    pub fn strength(&self) -> u32 {
        self.params.p().bits().saturating_sub(1)
    }
}
