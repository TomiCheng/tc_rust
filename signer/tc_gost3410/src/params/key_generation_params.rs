use crate::Gost3410Parameters;

/// BC 的 `Gost3410KeyGenerationParameters`，不含亂數來源：亂數來源在產生器建構時給。BC 也能以 CryptoPro 的參數集
/// OID 查參數，這裡沒有那張表。
#[derive(Clone)]
pub struct Gost3410KeyGenerationParams {
    pub(crate) params: Gost3410Parameters,
}

impl Gost3410KeyGenerationParams {
    /// 包起參數；參數在產生器 `init` 時檢查。常數時間。
    pub fn new(params: Gost3410Parameters) -> Self {
        Self { params }
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
