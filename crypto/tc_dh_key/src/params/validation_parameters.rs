use alloc::vec::Vec;

/// BC 的 `DHValidationParameters`：產生 p 時用的種子與計數，供 X9.42 驗證參數來源。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DhValidationParameters {
    seed: Vec<u8>,
    counter: u32,
}

impl DhValidationParameters {
    /// 包起種子與計數，不檢查。常數時間。
    pub fn new(seed: Vec<u8>, counter: u32) -> Self {
        Self { seed, counter }
    }

    /// 種子。常數時間。
    pub fn seed(&self) -> &[u8] {
        &self.seed
    }

    /// 計數。常數時間。
    pub fn counter(&self) -> u32 {
        self.counter
    }
}
