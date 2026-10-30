use crate::ElGamalParameters;
use tc_asym_cipher::AsymmetricKeyParams;
use tc_bigint::PaddedBigUint;
use tc_zeroize::Zeroize;

/// BC 的 `ElGamalPrivateKeyParameters`：私鑰 x 與它的參數；drop 時清除 x。只是容器，
/// 建構時不檢查，引擎解密的 `init` 才檢查。
///
/// 沒有 `Debug` 與 `PartialEq`，以免印出或以變動時間比較 x。
#[derive(Clone)]
pub struct ElGamalPrivateKey {
    x: PaddedBigUint,
    params: ElGamalParameters,
}

impl ElGamalPrivateKey {
    /// 包起 x 與參數，不檢查。常數時間。
    pub fn new(x: PaddedBigUint, params: ElGamalParameters) -> Self {
        Self { x, params }
    }

    /// 私鑰 x。常數時間。
    pub fn x(&self) -> &PaddedBigUint {
        &self.x
    }

    /// 參數。常數時間。
    pub fn params(&self) -> &ElGamalParameters {
        &self.params
    }
}

impl AsymmetricKeyParams for ElGamalPrivateKey {
    /// 私鑰。常數時間。
    fn is_private_key(&self) -> bool {
        true
    }
}

impl Drop for ElGamalPrivateKey {
    /// 清除 x。常數時間。
    fn drop(&mut self) {
        self.x.zeroize();
    }
}
