// BC `RsaKeyPairGenerator` 慣用的預設值：2048 位元、certainty 100。
const DEFAULT_SIZE: u32 = 2048;
const DEFAULT_CERTAINTY: u32 = 100;

/// BC `DHParametersGenerator.Init` 的 size 與 certainty，不含亂數來源：亂數來源在產生器
/// 建構時給。BC 沒有預設值，這裡預設 2048 位元、certainty 100；不檢查，由產生器的 `init`
/// 判定。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DhGroupGenerationParams {
    size: u32,
    certainty: u32,
}

impl DhGroupGenerationParams {
    /// 預設值：p 為 2048 位元，質數檢定到 certainty 100。常數時間。
    pub const fn new() -> Self {
        Self {
            size: DEFAULT_SIZE,
            certainty: DEFAULT_CERTAINTY,
        }
    }

    /// 設定 p 的位元數。常數時間。
    pub const fn with_size(mut self, size: u32) -> Self {
        self.size = size;
        self
    }

    /// 設定質數檢定的 certainty：誤判的機率不超過 2^-certainty。常數時間。
    pub const fn with_certainty(mut self, certainty: u32) -> Self {
        self.certainty = certainty;
        self
    }

    /// p 的位元數。常數時間。
    pub const fn size(&self) -> u32 {
        self.size
    }

    /// 質數檢定的 certainty。常數時間。
    pub const fn certainty(&self) -> u32 {
        self.certainty
    }
}

impl Default for DhGroupGenerationParams {
    /// 同 [`new`](Self::new)。常數時間。
    fn default() -> Self {
        Self::new()
    }
}
