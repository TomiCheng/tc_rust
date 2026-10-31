use alloc::vec::Vec;

/// BC 的 `DsaValidationParameters`：產生 p、q 的 seed 與計數，FIPS 186-3 可驗證地產生 g 時
/// 另有用途索引。比較相等時只看 seed 與計數，同 BC。
#[derive(Clone, Debug)]
pub struct DsaValidationParameters {
    seed: Vec<u8>,
    counter: u32,
    usage_index: Option<u8>,
}

impl DsaValidationParameters {
    /// seed 與計數，沒有用途索引。常數時間。
    pub fn new(seed: Vec<u8>, counter: u32) -> Self {
        Self {
            seed,
            counter,
            usage_index: None,
        }
    }

    /// 設定用途索引。常數時間。
    pub fn with_usage_index(mut self, usage_index: u8) -> Self {
        self.usage_index = Some(usage_index);
        self
    }

    /// seed。常數時間。
    pub fn seed(&self) -> &[u8] {
        &self.seed
    }

    /// 計數。常數時間。
    pub fn counter(&self) -> u32 {
        self.counter
    }

    /// 用途索引；沒有時為 `None`，即 BC 的 −1。常數時間。
    pub fn usage_index(&self) -> Option<u8> {
        self.usage_index
    }
}

impl PartialEq for DsaValidationParameters {
    /// 比較 seed 與計數。變動時間：只能用於公開值。
    fn eq(&self, other: &Self) -> bool {
        self.counter == other.counter && self.seed == other.seed
    }
}

impl Eq for DsaValidationParameters {}
