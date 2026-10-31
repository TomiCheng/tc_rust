use alloc::vec::Vec;

/// BC 的 `ParametersWithUkm`：底層協商的私鑰參數，加上寄件人的 UKM（user keying
/// material），寫進 KDF 的 `entityUInfo`。只是容器，`init` 才使用。
#[derive(Clone)]
pub struct UkmParams<P> {
    params: P,
    ukm: Vec<u8>,
}

impl<P> UkmParams<P> {
    /// 沒有 UKM 的參數，同 BC 不包 `ParametersWithUkm` 時。常數時間。
    pub fn new(params: P) -> Self {
        Self {
            params,
            ukm: Vec::new(),
        }
    }

    /// 設定 UKM；空的代表沒有。常數時間。
    pub fn with_ukm(mut self, ukm: Vec<u8>) -> Self {
        self.ukm = ukm;
        self
    }

    /// 底層協商的私鑰參數。常數時間。
    pub fn params(&self) -> &P {
        &self.params
    }

    /// UKM。常數時間。
    pub fn ukm(&self) -> &[u8] {
        &self.ukm
    }
}
