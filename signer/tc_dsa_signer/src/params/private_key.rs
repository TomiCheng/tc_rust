use crate::{DsaError, DsaParameters};
use tc_asym_cipher::AsymmetricKeyParams;
use tc_bigint::PaddedBigUint;
use tc_zeroize::Zeroize;

/// BC 的 `DsaPrivateKeyParameters`：私鑰 x 與它的參數；drop 時清除 x。只是容器，
/// [`validate`](Self::validate) 檢查範圍；BC 不檢查。
///
/// 沒有 `Debug` 與 `PartialEq`，以免印出或以變動時間比較 x。
#[derive(Clone)]
pub struct DsaPrivateKey {
    x: PaddedBigUint,
    params: DsaParameters,
}

impl DsaPrivateKey {
    /// 包起 x 與參數，不檢查。常數時間。
    pub fn new(x: PaddedBigUint, params: DsaParameters) -> Self {
        Self { x, params }
    }

    /// 私鑰 x。常數時間。
    pub fn x(&self) -> &PaddedBigUint {
        &self.x
    }

    /// 參數。常數時間。
    pub fn params(&self) -> &DsaParameters {
        &self.params
    }

    /// 參數合格，且 x 在 `[1, q − 1]`。對 x 是常數時間：只透露是否通過；參數只依公開值
    /// 檢查。
    pub fn validate(&self) -> Result<(), DsaError> {
        self.params.validate()?;
        if self.x < PaddedBigUint::from(1u8) || &self.x >= self.params.q() {
            return Err(DsaError::InvalidPrivateKey);
        }
        Ok(())
    }
}

impl AsymmetricKeyParams for DsaPrivateKey {
    /// 私鑰。常數時間。
    fn is_private_key(&self) -> bool {
        true
    }
}

impl Drop for DsaPrivateKey {
    /// 清除 x。常數時間。
    fn drop(&mut self) {
        self.x.zeroize();
    }
}
