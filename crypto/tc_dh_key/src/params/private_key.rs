use crate::DhParameters;
use tc_bigint::PaddedBigUint;
use tc_zeroize::Zeroize;

/// BC 的 `DHPrivateKeyParameters`：私鑰 x 與它的參數；drop 時清除 x。BC 也不檢查 x。
///
/// 沒有 `Debug` 與 `PartialEq`，以免印出或以變動時間比較 x。
#[derive(Clone)]
pub struct DhPrivateKey {
    x: PaddedBigUint,
    params: DhParameters,
}

impl DhPrivateKey {
    /// 包起 x 與參數，不檢查。常數時間。
    pub fn new(x: PaddedBigUint, params: DhParameters) -> Self {
        Self { x, params }
    }

    /// 私鑰 x。常數時間。
    pub fn x(&self) -> &PaddedBigUint {
        &self.x
    }

    /// 參數。常數時間。
    pub fn params(&self) -> &DhParameters {
        &self.params
    }
}

impl Drop for DhPrivateKey {
    /// 清除 x。常數時間。
    fn drop(&mut self) {
        self.x.zeroize();
    }
}
