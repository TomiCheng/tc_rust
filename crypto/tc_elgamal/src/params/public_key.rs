use crate::ElGamalParameters;
use tc_asym_cipher::AsymmetricKeyParams;
use tc_bigint::PaddedBigUint;

/// BC 的 `ElGamalPublicKeyParameters`：公開值 y = g^x mod p 與它的參數。只是容器，建構時
/// 不檢查，引擎加密的 `init` 才檢查。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElGamalPublicKey {
    y: PaddedBigUint,
    params: ElGamalParameters,
}

impl ElGamalPublicKey {
    /// 包起 y 與參數，不檢查。常數時間。
    pub fn new(y: PaddedBigUint, params: ElGamalParameters) -> Self {
        Self { y, params }
    }

    /// 公開值 y。常數時間。
    pub fn y(&self) -> &PaddedBigUint {
        &self.y
    }

    /// 參數。常數時間。
    pub fn params(&self) -> &ElGamalParameters {
        &self.params
    }
}

impl AsymmetricKeyParams for ElGamalPublicKey {
    /// 公鑰。常數時間。
    fn is_private_key(&self) -> bool {
        false
    }
}
